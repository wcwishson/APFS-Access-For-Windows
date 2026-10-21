#include "ApfsVerifier.h"
#include "ApfsFusionEmptyWriteback.h"

#include "AppleTransactionCommit.h"
#include "AppleReadOnlyRetention.h"
#include "AppleReadOnlyRecordGraph.h"
#include "ApfsReadOnlyMetadataAdmission.h"
#include "AppleVolumeTransaction.h"
#include "ApfsSharedSpace.h"
#include "NativeApfsReader.h"
#include "ApfsFusionReadSession.h"
#include "ApfsFusionSpaceman.h"
#include "SnapshotPlanningSource.h"
#include "ApfsVerifierEncryptedSource.h"
#include "ApfsProfileHistory.h"
#include "ApfsProfileSnapshotGraph.h"
#include "ApfsFusionSnapshotCatalog.h"
#include "ApfsEncryptedSnapshotReadContext.h"
#include "FusionPlanningParser.h"
#include "ProfileRetentionContinuity.h"

#include <algorithm>
#include <set>
#include <stdexcept>
#include <tuple>

namespace apfsaccess::catalog
{
namespace
{
using namespace apfsaccess::rw;

bool UuidValid(const std::string& value)
{
    return value.size() == 32 && value != std::string(32, '0') &&
        std::all_of(value.begin(), value.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        });
}

// I/O failure is observed at the source boundary, never inferred from parser
// strings. Sticky failure prevents checkpoint-ring scanning from hiding a read
// failure with a later parse result. This adapter has no write surface.
class VerificationSource final : public RandomAccessSource
{
public:
    VerificationSource(const RandomAccessSource& source, const VerificationScope& scope,
        const std::function<bool()>& within_deadline)
        : source_(source), budget_(source.ReadBudget()), within_deadline_(within_deadline)
    {
        if (!budget_) budget_ = std::make_shared<ApfsReadBudget>(scope.max_reads,
            scope.max_read_bytes, scope.max_records, scope.max_record_bytes);
        else budget_->LimitRemainingTo(scope.max_reads, scope.max_read_bytes,
            scope.max_records, scope.max_record_bytes);
    }
    std::uint64_t SizeBytes() const override { return source_.SizeBytes(); }
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override { return budget_; }
    bool WithinDeadline() const
    {
        if (budget_->Failed()) return false;
        try
        {
            if (!within_deadline_ || within_deadline_()) return !budget_->Failed();
        }
        catch (...) { return budget_->Refuse("VerifierDeadlineCallbackFailed"); }
        return budget_->Refuse("VerifierDeadlineExceeded");
    }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override
    {
        out.clear();
        if (io_failed || bounds_failed || !WithinDeadline()) return false;
        if (offset > SizeBytes() || size > SizeBytes() - offset)
        { bounds_failed = true; failed_offset = offset; return false; }
        if (!source_.ReadBudget() && !budget_->Read(size)) return false;
        ++reads;
        bytes += size;
        if (!source_.Read(offset, size, out) || out.size() != size)
        {
            out.clear();
            if (!budget_->Failed()) { io_failed = true; failed_offset = offset; }
            return false;
        }
        return true;
    }
    mutable std::uint64_t reads = 0, bytes = 0, failed_offset = 0;
    mutable bool io_failed = false, bounds_failed = false;
private:
    const RandomAccessSource& source_;
    std::shared_ptr<ApfsReadBudget> budget_;
    const std::function<bool()>& within_deadline_;
};

bool Contains(const std::string& text, const char* part) { return text.find(part) != std::string::npos; }

VerificationCode Classify(const std::string& error, VerificationCode fallback)
{
    if (Contains(error, "Checksum") || Contains(error, "checksum")) return VerificationCode::ChecksumMismatch;
    if (Contains(error, "Budget") || Contains(error, "AllocationFailed")) return VerificationCode::BudgetExceeded;
    if (Contains(error, "Tier2Unsupported")) return VerificationCode::FusionUnsupported;
    if (Contains(error, "Encrypted") || Contains(error, "EncryptionUnsupported")) return VerificationCode::CryptoUnsupported;
    if (Contains(error, "Unsupported") || Contains(error, "Unproven")) return VerificationCode::UnsupportedFeature;
    if (Contains(error, "Spaceman")) return VerificationCode::SpacemanInconsistent;
    if (Contains(error, "CatalogBtreeRouting") || error == "CatalogBtreeLeafKeyOrder") return VerificationCode::TreeOrderInconsistent;
    if (Contains(error, "CatalogBtree")) return VerificationCode::StructuralInconsistency;
    if (Contains(error, "ExactGenerationUnavailable")) return VerificationCode::CheckpointUnavailable;
    if (error == "ApplePayloadMetadataOverlap") return VerificationCode::PayloadMetadataOverlap;
    if (error == "ApplePayloadNotAllocated") return VerificationCode::PayloadAllocationInconsistent;
    return fallback;
}

VerificationCoverage& Coverage(VerificationReport& report, VerificationCheck check)
{
    return *std::find_if(report.coverage.begin(), report.coverage.end(),
        [check](const auto& entry) { return entry.check == check; });
}

void Finish(VerificationReport& report)
{
    // Canonical order is independent of hash-map iteration in reused validators.
    std::sort(report.findings.begin(), report.findings.end(), [](const auto& a, const auto& b) {
        return std::tie(a.check, a.code, a.volume_oid, a.object_id, a.physical_block,
            a.checkpoint_xid, a.failed_source_offset_bytes, a.severity, a.detail) <
            std::tie(b.check, b.code, b.volume_oid, b.object_id, b.physical_block,
                b.checkpoint_xid, b.failed_source_offset_bytes, b.severity, b.detail);
    });
    auto& plan = report.repair;
    plan.source_identity = report.requested_scope.source_identity;
    plan.requested_identity = report.requested_scope.exact;
    plan.observed_identity = report.selected;
    plan.findings = report.findings;
    plan.refusal = report.outcome == VerificationOutcome::Complete
        ? ApfsRepairRefusal::NoIndependentReconstructionEvidence
        : ApfsRepairRefusal::VerificationNotComplete;
    auto& id = plan.plan_id;
    id = report.requested_scope.account_retained_ownership ? "apfs-verifier-refusal-ownership-v1|" :
        report.requested_scope.retained_from_xid ? "apfs-verifier-refusal-history-v1|" :
        (report.requested_scope.observe_payload_content
            ? "apfs-verifier-refusal-v2|" : "apfs-verifier-refusal-v1|");
    const auto field = [&](const std::string& value) { id += std::to_string(value.size()) + ":" + value; };
    const auto number = [&](auto value) { field(std::to_string(static_cast<std::uint64_t>(value))); };
    const auto optional = [&](const std::optional<std::uint64_t>& value) {
        field(value ? std::to_string(*value) : "unknown");
    };
    const auto exact = [&](const ApfsSnapshotScope& scope) {
        number(scope.store_offset_bytes); number(scope.store_size_bytes);
        field(scope.container_uuid_hex); field(scope.volume_uuid_hex);
        number(scope.volume_oid); number(scope.checkpoint_xid);
    };
    field(plan.source_identity); exact(plan.requested_identity);
    number(report.selected.has_value());
    if (report.selected)
    {
        exact(report.selected->exact);
        number(report.selected->checkpoint_physical_block);
        number(report.selected->volume_superblock_physical_block);
        number(report.selected->volume_superblock_xid);
        number(report.selected->root_oid); number(report.selected->root_physical_block);
    }
    const auto& scope = report.requested_scope;
    number(scope.max_reads); number(scope.max_read_bytes); number(scope.max_records); number(scope.max_record_bytes);
    number(scope.require_whole_volume); number(scope.require_payload_content_hashes);
    if (scope.account_retained_ownership) number(scope.account_retained_ownership);
    if (scope.retained_from_xid) number(*scope.retained_from_xid);
    if (scope.observe_payload_content || scope.retained_from_xid)
    {
        number(scope.observe_payload_content);
        if (scope.observe_payload_content)
        { number(scope.max_payload_logical_bytes); number(scope.max_payload_entries); }
    }
    number(report.outcome); number(plan.refusal); number(report.findings.size());
    for (const auto& finding : report.findings)
    {
        number(finding.check); number(finding.code); number(finding.severity);
        optional(finding.volume_oid); optional(finding.object_id);
        optional(finding.physical_block); optional(finding.checkpoint_xid);
        optional(finding.failed_source_offset_bytes); field(finding.detail);
    }
    number(report.coverage.size());
    for (const auto& coverage : report.coverage)
    { number(coverage.check); number(coverage.implemented); number(coverage.required); number(coverage.state); }
}

// Compare the authoritative comparator's sorted copy to the actual leaf walk.
// Sorting must never conceal damage. Routing is separately checked during the walk.
bool CheckOrder(const RandomAccessSource& source, const std::vector<BtreeRecord>& records,
    AppleBtreeKeyOrder order, std::string& error)
{
    for (const auto& record : records)
        if (!source.ReadBudget()->Materialize(1, sizeof(BtreeRecord) + record.key.size() + record.value.size()))
        { error = source.ReadBudget()->Failure(); return false; }
    auto sorted = records;
    if (!SortAppleBtreeRecords(sorted, order, error)) return false;
    for (std::size_t i = 0; i < records.size(); ++i)
        if (records[i].key != sorted[i].key)
        { error = "VerifierLeafKeyOrderInconsistent"; return false; }
    return true;
}

// Numeric orders are the exact unsigned tuples used by SortAppleBtreeRecords.
// FS names/hash collisions use that authoritative comparator directly: never
// normalize names, compare UTF-16, include name lengths, or sort raw LE headers.
BtreeRoutingPolicy Routing(const RandomAccessSource& source, AppleBtreeKeyOrder order)
{
    return {[&source, order](const auto& left, const auto& right, std::string& error) -> std::optional<int> {
        if (order == AppleBtreeKeyOrder::ObjectMap || order == AppleBtreeKeyOrder::SpacemanFreeQueue ||
            order == AppleBtreeKeyOrder::PhysicalExtent || order == AppleBtreeKeyOrder::SnapshotObjectMap)
        {
            const bool pair = order == AppleBtreeKeyOrder::ObjectMap || order == AppleBtreeKeyOrder::SpacemanFreeQueue;
            if (left.size() != (pair ? 16u : 8u) || right.size() != left.size())
            { error = "VerifierRoutingNumericKeyInvalid"; return std::nullopt; }
            const auto a = std::make_pair(ReadU64LE(left, 0).value(), pair ? ReadU64LE(left, 8).value() : 0);
            const auto b = std::make_pair(ReadU64LE(right, 0).value(), pair ? ReadU64LE(right, 8).value() : 0);
            if (order == AppleBtreeKeyOrder::SpacemanFreeQueue && (!a.first || !a.second || !b.first || !b.second))
            { error = "VerifierRoutingQueueKeyInvalid"; return std::nullopt; }
            return a == b ? 0 : a < b ? -1 : 1;
        }
        if (!source.ReadBudget()->Materialize(0, 2 * sizeof(BtreeRecord) + left.size() + right.size()))
        { error = source.ReadBudget()->Failure(); return std::nullopt; }
        std::vector<BtreeRecord> keys{{left, {}}, {right, {}}};
        if (!SortAppleBtreeRecords(keys, order, error))
        {
            if (error != "AppleBtreeDuplicateKey") return std::nullopt;
            error.clear(); return 0;
        }
        return keys.front().key == left ? -1 : 1;
    }};
}

bool CheckSnapshotMetadataOwners(const AppleCheckpointView& checkpoint,
    std::vector<AppleSnapshotMetadataClaim>& owners,
    std::optional<AppleSnapshotMetadataClaim>& bad, std::string& error, const ApfsFusionStore* fusion = nullptr)
{
    const auto& nx = checkpoint.container.superblock;
    const auto bounded = [&](const auto& owner) {
        if (!owner.block_count) return false;
        if (!fusion) return owner.physical_block < nx.block_count && owner.block_count <= nx.block_count - owner.physical_block;
        FusionRoute route;
        return nx.block_size && owner.block_count <= UINT64_MAX / nx.block_size &&
            fusion->MapPhysical(owner.physical_block, 0, owner.block_count * nx.block_size, route, error);
    };
    for (const auto& owner : owners)
        if (!owner.object_id || !owner.object_xid || !owner.map_oid ||
            !owner.view_xid || owner.view_xid > nx.xid ||
            !owner.selection_xid || owner.selection_xid > nx.xid ||
            owner.object_xid > owner.selection_xid ||
            !bounded(owner) ||
            (owner.mapping_xid && (owner.object_xid > *owner.mapping_xid ||
                *owner.mapping_xid > owner.selection_xid)))
        { bad = owner; error = "VerifierSnapshotMetadataOwnerIdentityInvalid"; return false; }
    std::sort(owners.begin(), owners.end(), [](const auto& a, const auto& b) {
        return std::tie(a.physical_block, a.block_count, a.volume_oid, a.object_id,
            a.object_xid, a.type, a.subtype, a.metadata_class, a.map_oid, a.view_xid,
            a.selection_xid, a.mapping_xid) <
            std::tie(b.physical_block, b.block_count, b.volume_oid, b.object_id,
            b.object_xid, b.type, b.subtype, b.metadata_class, b.map_oid, b.view_xid,
            b.selection_xid, b.mapping_xid);
    });
    for (std::size_t i = 1; i < owners.size(); ++i)
    {
        const auto& a = owners[i-1]; const auto& b = owners[i];
        if (b.physical_block >= a.physical_block + a.block_count) continue;
        // Resolver context may differ, but the authenticated immutable object,
        // physical interval, owner domain and semantic class must be identical.
        if (std::tie(a.physical_block,a.block_count,a.volume_oid,a.object_id,
                a.object_xid,a.type,a.subtype,a.metadata_class) ==
            std::tie(b.physical_block,b.block_count,b.volume_oid,b.object_id,
                b.object_xid,b.type,b.subtype,b.metadata_class)) continue;
        bad = b;
        error = "VerifierSnapshotMetadataOwnerConflict:otherVolumeOid=" + std::to_string(a.volume_oid) +
            ":otherObjectId=" + std::to_string(a.object_id) + ":mapOid=" + std::to_string(b.map_oid) +
            ":viewXid=" + std::to_string(b.view_xid) +
            ":class=" + std::to_string(static_cast<unsigned>(b.metadata_class));
        return false;
    }
    return true;
}

// One interval per object/tree node or physical extent, never a byte/block
// array proportional to payload length. Domain zero is container metadata.
// Tree ownership is its volume and root identity; distinct current trees may
// not alias even when their node headers happen to be individually valid.
struct CurrentOwner
{
    std::uint64_t begin, end, volume, object;
    std::uint32_t type, subtype;
    bool tree;
};

bool AddCurrentOwner(const RandomAccessSource& source, const AppleCheckpointView& checkpoint,
    std::vector<CurrentOwner>& owners, std::uint64_t first, std::uint64_t count,
    std::uint64_t volume, const AppleObjectLocation& object, bool tree, std::string& error,
    const ApfsFusionStore* fusion = nullptr)
{
    FusionRoute route;
    const auto bs = checkpoint.container.superblock.block_size;
    if (!count || (fusion ? (!bs || count > UINT64_MAX / bs || !fusion->MapPhysical(first, 0, count * bs, route, error)) :
        (first >= checkpoint.container.superblock.block_count || count > checkpoint.container.superblock.block_count - first)))
    { error = "VerifierCurrentOwnerRangeInvalid"; return false; }
    if (!source.ReadBudget()->Materialize(1, sizeof(CurrentOwner)))
    { error = source.ReadBudget()->Failure(); return false; }
    owners.push_back({first, first + count, volume, object.object_id, object.type, object.subtype, tree});
    return true;
}

bool CheckCurrentOwners(const RandomAccessSource& source, const AppleCheckpointView& checkpoint,
    std::vector<CurrentOwner>& owners, const std::vector<ApplePhysicalExtentRecord>& payload,
    std::optional<std::uint64_t>& volume, std::optional<std::uint64_t>& object,
    std::optional<std::uint64_t>& block, VerificationCode& code, std::string& error,
    const ApfsFusionStore* fusion = nullptr)
{
    const auto& nx = checkpoint.container.superblock;
    const auto append = [&](const AppleObjectLocation& item, std::uint64_t domain = 0) {
        if (!item.size_bytes || item.size_bytes % nx.block_size)
        { error = "VerifierCurrentOwnerSizeInvalid"; return false; }
        return AddCurrentOwner(source, checkpoint, owners, item.physical_block,
            item.size_bytes / nx.block_size, domain, item, false, error, fusion);
    };
    if (!append(checkpoint.container_object_map.object) || !append(checkpoint.spaceman.object)) return false;
    for (const auto& v : checkpoint.volumes)
        if (!append(v.superblock_object, v.superblock.object_id) ||
            !append(v.object_map.object, v.superblock.object_id)) return false;
    // Checkpoint mappings are additional references to the same ephemeral
    // object, not additional owners. Admit only an exact known-object match.
    for (const auto& m : checkpoint.container.mappings)
    {
        const auto matches = [&](const AppleObjectLocation& item) {
            return m.file_system_oid == 0 && m.object_id == item.object_id &&
                m.physical_block == item.physical_block && m.size_bytes == item.size_bytes &&
                m.type == item.type && m.subtype == item.subtype;
        };
        if (matches(checkpoint.spaceman.object)) continue;
        bool known = false;
        for (const auto& q : checkpoint.spaceman.free_queues)
            if (q.tree_oid && matches(q.root)) { known = true; break; }
        if (!known && !append({m.object_id, nx.xid, m.physical_block, m.type, m.subtype, m.size_bytes}, m.file_system_oid))
            return false;
    }
    for (const auto& device : checkpoint.spaceman.devices)
    {
        for (const auto& cab : device.cabs) if (!append(cab.object)) return false;
        for (const auto& cib : device.cibs) if (!append(cib.object)) return false;
    }
    // Bitmap ownership uses its allocator index, not its physical address.
    // Two chunk descriptors naming one bitmap must remain two claims.
    for (std::size_t i = 0; i < checkpoint.spaceman.chunks.size(); ++i)
    {
        const auto& chunk = checkpoint.spaceman.chunks[i];
        if (chunk.bitmap_block && !append({i + 1, nx.xid, chunk.bitmap_block,
            kObjectTypeSpacemanBitmap, 0, nx.block_size})) return false;
    }
    const auto& bitmaps = checkpoint.spaceman.internal_pool.active_bitmaps;
    for (std::size_t i = 0; i < bitmaps.size(); ++i)
        if (!append({i + 1, nx.xid, bitmaps[i].physical_block,
            kObjectTypeSpacemanBitmap, 1, nx.block_size})) return false;
    const auto raw = [&](std::uint64_t at, std::uint32_t type) {
        return append({at, nx.xid, at, type, 0, nx.block_size});
    };
    if (!raw(0, kNxSuperblockObjectType) ||
        !raw(checkpoint.container.superblock_physical_block, kNxSuperblockObjectType)) return false;
    for (const auto at : checkpoint.container.checkpoint_map_blocks)
        if (!raw(at, kObjectTypeCheckpointMap)) return false;
    std::sort(owners.begin(), owners.end(), [](const auto& a, const auto& b) {
        return std::tie(a.begin, a.end, a.volume, a.object, a.type, a.subtype, a.tree) <
            std::tie(b.begin, b.end, b.volume, b.object, b.type, b.subtype, b.tree);
    });
    for (std::size_t i = 1; i < owners.size(); ++i)
        if (owners[i].begin < owners[i-1].end)
        {
            const auto& a = owners[i-1]; const auto& b = owners[i];
            // Repeated references to an identical current tree are harmless.
            if (std::tie(a.begin,a.end,a.volume,a.object,a.type,a.subtype,a.tree) ==
                std::tie(b.begin,b.end,b.volume,b.object,b.type,b.subtype,b.tree)) continue;
            volume = b.volume ? std::optional{b.volume} : std::nullopt;
            object = b.object; block = b.begin; code = VerificationCode::MetadataOwnerConflict;
            error = "VerifierMetadataOwnerConflict:otherVolumeOid=" + std::to_string(a.volume) +
                ":otherObjectId=" + std::to_string(a.object); return false;
        }
    // The payload graph already normalizes clone references into unique
    // physical intervals. This check never charges clone multiplicity as space.
    for (const auto& extent : payload)
    {
        const auto at = std::lower_bound(owners.begin(), owners.end(), extent.physical_block,
            [](const auto& owner, std::uint64_t value) { return owner.end <= value; });
        if (at != owners.end() && at->begin < extent.physical_block + extent.block_count)
        {
            block = (std::max)(at->begin, extent.physical_block); object = at->object;
            volume = at->volume ? std::optional{at->volume} : std::nullopt;
            code = VerificationCode::PayloadMetadataOverlap;
            error = "ApplePayloadMetadataOverlap"; return false;
        }
    }
    object.reset(); block.reset(); volume.reset(); return true;
}

// Reconcile bitmap allocations against bounded interval unions. Reservations
// explain main-pool allocation only; the internal pool gets a separate census
// against its active bitmap so reserving the pool cannot conceal its orphans.
bool ObserveAllocationCensus(const RandomAccessSource& source, const AppleCheckpointView& checkpoint,
    const std::vector<CurrentOwner>& owners, const std::vector<ApplePhysicalExtentRecord>& payload,
    VerificationAllocationCensus& census, const std::function<bool()>& within_deadline, std::string& error,
    const VerificationRetainedOwnership* retained = nullptr)
{
    using Range = VerificationBlockRange;
    std::vector<Range> main, internal;
    const auto add = [&](auto& ranges, std::uint64_t first, std::uint64_t count) {
        if (!within_deadline()) { error = source.ReadBudget()->Failure(); return false; }
        if (!count) return true;
        if (!source.ReadBudget()->Materialize(1, sizeof(Range)))
        { error = source.ReadBudget()->Failure(); return false; }
        ranges.push_back({first, count}); return true;
    };
    std::uint64_t end = 0;
    for (const auto& owner : owners)
    {
        const auto begin = (std::max)(owner.begin, end);
        if (owner.end > begin) census.current_metadata_blocks += owner.end - begin;
        end = owner.end;
        if (!add(main, owner.begin, owner.end - owner.begin) ||
            !add(internal, owner.begin, owner.end - owner.begin)) return false;
    }
    for (const auto& extent : payload)
    {
        census.current_payload_blocks += extent.block_count;
        if (!add(main, extent.physical_block, extent.block_count)) return false;
    }
    if (retained)
    {
        for (const auto& range : retained->metadata_ranges)
            if (!add(main, range.physical_block, range.block_count) ||
                !add(internal, range.physical_block, range.block_count)) return false;
        for (const auto& range : retained->payload_ranges)
            if (!add(main, range.physical_block, range.block_count)) return false;
    }
    for (const auto& queue : checkpoint.spaceman.free_queues)
        for (const auto& entry : queue.entries)
            if (!add(main, entry.physical_block, entry.block_count) ||
                !add(internal, entry.physical_block, entry.block_count)) return false;
    const auto& nx = checkpoint.container.superblock;
    const auto& pool = checkpoint.spaceman.internal_pool;
    if (!add(main, nx.xp_desc_base_block, nx.xp_desc_block_count) ||
        !add(main, nx.xp_data_base_block, nx.xp_data_block_count) ||
        !add(main, pool.base_block, pool.block_count) ||
        !add(main, pool.bitmap_base_block, pool.bitmap_block_count)) return false;
    const auto merge = [](auto& ranges) {
        std::sort(ranges.begin(), ranges.end(), [](const auto& a, const auto& b) {
            return std::tie(a.physical_block, a.block_count) < std::tie(b.physical_block, b.block_count);
        });
        std::size_t out = 0;
        for (const auto range : ranges)
        {
            if (out && range.physical_block <= ranges[out-1].physical_block + ranges[out-1].block_count)
                ranges[out-1].block_count = (std::max)(ranges[out-1].physical_block + ranges[out-1].block_count,
                    range.physical_block + range.block_count) - ranges[out-1].physical_block;
            else ranges[out++] = range;
        }
        ranges.resize(out);
    };
    merge(main); merge(internal);
    const auto scan = [&](const auto& bytes, std::uint64_t first, std::uint64_t count,
                          const auto& known, auto& unknown, std::uint64_t& total) {
        if (count > bytes.size() * 8ull)
        { error = "VerifierCensusBitmapCoverageMissing"; return false; }
        auto at = std::lower_bound(known.begin(), known.end(), first,
            [](const auto& r, std::uint64_t value) { return r.physical_block + r.block_count <= value; });
        for (std::uint64_t bit = 0; bit < count;)
        {
            if ((bit & 4095) == 0 && !within_deadline())
            { error = source.ReadBudget()->Failure(); return false; }
            const auto block = first + bit;
            while (at != known.end() && at->physical_block + at->block_count <= block) ++at;
            if (at != known.end() && at->physical_block <= block)
            { bit += (std::min)(count - bit, at->physical_block + at->block_count - block); continue; }
            if (bit % 8 == 0 && count - bit >= 8 && bytes[bit / 8] == std::byte{0})
            { bit += 8; continue; }
            if ((std::to_integer<unsigned>(bytes[bit / 8]) & (1u << (bit % 8))) != 0)
            {
                ++total;
                if (!unknown.empty() && unknown.back().physical_block + unknown.back().block_count == block)
                    ++unknown.back().block_count;
                else if (!add(unknown, block, 1)) return false;
            }
            ++bit;
        }
        return true;
    };
    for (const auto& chunk : checkpoint.spaceman.chunks)
    {
        if (!within_deadline()) { error = source.ReadBudget()->Failure(); return false; }
        // The canonical spaceman reader authenticates bitmap_block == 0 as
        // an entirely free chunk (free_count == block_count). There are no
        // allocated bits to attribute, and no bitmap bytes to scan.
        if (!chunk.bitmap_block) continue;
        if (!scan(chunk.allocation_bitmap, chunk.start_block, chunk.block_count,
            main, census.unattributed_main_ranges, census.unattributed_main_blocks)) return false;
    }
    const auto capacity = 8ull * nx.block_size;
    for (std::size_t i = 0; i < pool.active_bitmaps.size(); ++i)
    {
        if (!within_deadline()) { error = source.ReadBudget()->Failure(); return false; }
        const auto offset = i * capacity;
        if (offset >= pool.block_count) break;
        if (!scan(pool.active_bitmaps[i].bytes, pool.base_block + offset,
            (std::min)(capacity, pool.block_count - offset), internal,
            census.unattributed_internal_ranges, census.unattributed_internal_blocks)) return false;
    }
    return true;
}

// Uses already authenticated checkpoint/allocator views and visited tree blocks.
// This proves allocation of current reachable metadata, not an orphan census.
bool CheckMetadataAllocation(const RandomAccessSource& source, const AppleCheckpointView& checkpoint,
    std::vector<std::uint64_t>& blocks, std::optional<std::uint64_t>& bad_block, std::string& error)
{
    const auto& nx = checkpoint.container.superblock;
    const auto& sm = checkpoint.spaceman;
    const auto& pool = sm.internal_pool;
    const auto append = [&](std::uint64_t first, std::uint64_t count) {
        if (!count || first >= nx.block_count || count > nx.block_count - first)
        { error = "VerifierMetadataRangeInvalid"; bad_block = first; return false; }
        if (!source.ReadBudget()->Materialize(0, count * sizeof(std::uint64_t)))
        { error = source.ReadBudget()->Failure(); return false; }
        for (std::uint64_t i = 0; i < count; ++i) blocks.push_back(first + i);
        return true;
    };
    const auto object = [&](const AppleObjectLocation& item) {
        if (!item.size_bytes || item.size_bytes % nx.block_size)
        { error = "VerifierMetadataObjectSizeInvalid"; return false; }
        return append(item.physical_block, item.size_bytes / nx.block_size);
    };
    if (!append(0, 1) || !append(checkpoint.container.superblock_physical_block, 1) ||
        !object(checkpoint.container_object_map.object) || !object(sm.object)) return false;
    for (const auto block : checkpoint.container.checkpoint_map_blocks) if (!append(block, 1)) return false;
    for (const auto& mapping : checkpoint.container.mappings)
    {
        if (!mapping.size_bytes || mapping.size_bytes % nx.block_size)
        { error = "VerifierMetadataMappingSizeInvalid"; return false; }
        if (!append(mapping.physical_block, mapping.size_bytes / nx.block_size)) return false;
    }
    for (const auto& volume : checkpoint.volumes)
        if (!object(volume.superblock_object) || !object(volume.object_map.object)) return false;
    for (const auto& device : sm.devices)
    {
        for (const auto& cab : device.cabs) if (!object(cab.object)) return false;
        for (const auto& cib : device.cibs) if (!object(cib.object)) return false;
    }
    for (const auto& chunk : sm.chunks) if (chunk.bitmap_block && !append(chunk.bitmap_block, 1)) return false;
    for (const auto& bitmap : pool.active_bitmaps) if (!append(bitmap.physical_block, 1)) return false;
    std::sort(blocks.begin(), blocks.end());
    blocks.erase(std::unique(blocks.begin(), blocks.end()), blocks.end());
    const auto bit = [](const auto& bytes, std::uint64_t index) {
        return index / 8 < bytes.size() && (std::to_integer<unsigned>(bytes[index / 8]) & (1u << (index % 8))) != 0;
    };
    std::vector<std::pair<std::uint64_t, std::uint64_t>> queued;
    for (const auto& queue : sm.free_queues)
    {
        if (!source.ReadBudget()->Materialize(0, queue.entries.size() * sizeof(queued.front())))
        { error = source.ReadBudget()->Failure(); return false; }
        for (const auto& entry : queue.entries) queued.emplace_back(entry.physical_block, entry.physical_block + entry.block_count);
    }
    std::sort(queued.begin(), queued.end());
    for (const auto block : blocks)
    {
        bad_block = block;
        const auto chunk = std::lower_bound(sm.chunks.begin(), sm.chunks.end(), block,
            [](const auto& item, std::uint64_t value) { return item.start_block + item.block_count <= value; });
        if (chunk == sm.chunks.end() || block < chunk->start_block || !bit(chunk->allocation_bitmap, block - chunk->start_block))
        { error = "VerifierMetadataMainAllocationBitClear"; return false; }
        const bool internal = block >= pool.base_block && block - pool.base_block < pool.block_count;
        if (internal)
        {
            const auto relative = block - pool.base_block;
            const auto capacity = 8ull * nx.block_size;
            const auto index = relative / capacity;
            if (index >= pool.active_bitmaps.size() || !bit(pool.active_bitmaps[index].bytes, relative % capacity))
            { error = "VerifierMetadataInternalAllocationBitClear"; return false; }
        }
        const auto retirement = std::lower_bound(queued.begin(), queued.end(), block,
            [](const auto& range, std::uint64_t value) { return range.second <= value; });
        if (retirement != queued.end() && retirement->first <= block)
        { error = "VerifierCurrentMetadataQueuedForFree"; return false; }
    }
    bad_block.reset(); return true;
}

// Allocation is checked against the selected allocator. Signed snapshot layers
// are resolved separately below; historical views never count as clone uses.
bool CheckReachableAllocation(const RandomAccessSource& source, const AppleCheckpointView& checkpoint,
    const AppleVolumeCheckpointView& volume, const AppleSnapshotTreeRecords& trees,
    const std::vector<std::uint64_t>& dependencies,
    std::optional<std::uint64_t>& bad_block, VerificationCode& code, std::string& error,
    std::shared_ptr<const NativeApfsVolumeProjection>* namespace_projection = nullptr, bool observational = false)
{
    const auto& nx = checkpoint.container.superblock;
    code = VerificationCode::MetadataAllocationInconsistent;
    const auto size = trees.filesystem_blocks.size() + trees.extentref_blocks.size() + dependencies.size() + 1;
    if (!source.ReadBudget()->Materialize(size, size * sizeof(std::uint64_t)))
    { error = source.ReadBudget()->Failure(); return false; }
    std::vector<std::uint64_t> metadata = trees.filesystem_blocks;
    metadata.insert(metadata.end(), trees.extentref_blocks.begin(), trees.extentref_blocks.end());
    metadata.insert(metadata.end(), dependencies.begin(), dependencies.end());
    metadata.push_back(volume.superblock_object.physical_block);
    if (!CheckMetadataAllocation(source, checkpoint, metadata, bad_block, error)) return false;
    code = VerificationCode::NamespaceOrLinkInconsistent;
    if (namespace_projection)
    {
        NativeApfsVolumeProjection projection;
        const auto project = observational ? NativeApfsReader::TryProjectObservationalFileSystemRecords : NativeApfsReader::TryProjectOrdinaryFileSystemRecords;
        if (!project(trees.filesystem, nx,
            volume.superblock, source.ReadBudget(), projection, error)) return false;
        if (!source.ReadBudget()->Materialize(1, sizeof(NativeApfsVolumeProjection) + 64))
        { error = source.ReadBudget()->Failure(); return false; }
        *namespace_projection = std::make_shared<const NativeApfsVolumeProjection>(std::move(projection));
    }
    else {
        const auto validate = observational ? NativeApfsReader::ValidateObservationalFileSystemRecords : NativeApfsReader::ValidateOrdinaryFileSystemRecords;
        if (!validate(trees.filesystem, nx, volume.superblock, source.ReadBudget(), error)) return false;
    }
    using Interval = std::pair<std::uint64_t, std::uint64_t>;
    std::vector<Interval> queued;
    for (const auto& queue : checkpoint.spaceman.free_queues)
    {
        if (!source.ReadBudget()->Materialize(queue.entries.size(), queue.entries.size() * sizeof(Interval)))
        { error = source.ReadBudget()->Failure(); return false; }
        for (const auto& entry : queue.entries) queued.emplace_back(entry.physical_block, entry.physical_block + entry.block_count);
    }
    std::sort(queued.begin(), queued.end());
    const auto& pool = checkpoint.spaceman.internal_pool;
    for (const auto& record : trees.filesystem)
    {
        if (ReadU64LE(record.key, 0).value_or(0) >> 60 != 8) continue;
        AppleFileExtentRecord extent;
        code = VerificationCode::ExtentReferenceInconsistent;
        if (!DecodeAppleFileExtentRecord(record, nx.block_size, extent, error)) return false;
        if (extent.crypto_id) { error = "VerifierSnapshotEncryptedExtentUnsupported"; return false; }
        if (!extent.physical_block) continue; // Canonically decoded sparse hole.
        const auto begin = extent.physical_block;
        const auto count = extent.length_bytes / nx.block_size;
        bad_block = begin;
        if (!count || begin >= nx.block_count || count > nx.block_count - begin)
        { error = "VerifierSnapshotPayloadRangeInvalid"; return false; }
        const auto end = begin + count;
        const auto intersects = [&](std::uint64_t first, std::uint64_t length) {
            return length && first < end && (first >= begin || begin - first < length);
        };
        const auto found = std::lower_bound(metadata.begin(), metadata.end(), begin);
        if ((found != metadata.end() && *found < end) ||
            intersects(nx.xp_desc_base_block, nx.xp_desc_block_count) ||
            intersects(nx.xp_data_base_block, nx.xp_data_block_count) ||
            intersects(pool.base_block, pool.block_count) ||
            intersects(pool.bitmap_base_block, pool.bitmap_block_count))
        { code = VerificationCode::PayloadMetadataOverlap; error = "ApplePayloadMetadataOverlap"; return false; }
        code = VerificationCode::PayloadAllocationInconsistent;
        const auto retirement = std::lower_bound(queued.begin(), queued.end(), begin,
            [](const auto& interval, std::uint64_t value) { return interval.second <= value; });
        if (retirement != queued.end() && retirement->first < end)
        { error = "VerifierSnapshotPayloadQueuedForFree"; return false; }
        auto cursor = begin;
        while (cursor < end)
        {
            const auto chunk = std::lower_bound(checkpoint.spaceman.chunks.begin(), checkpoint.spaceman.chunks.end(), cursor,
                [](const auto& item, std::uint64_t value) { return item.start_block + item.block_count <= value; });
            if (chunk == checkpoint.spaceman.chunks.end() || cursor < chunk->start_block)
            { bad_block = cursor; error = "VerifierSnapshotPayloadAllocationMissing"; return false; }
            const auto stop = (std::min)(end, chunk->start_block + chunk->block_count);
            while (cursor < stop)
            {
                const auto bit = cursor - chunk->start_block;
                if (bit / 8 >= chunk->allocation_bitmap.size() ||
                    (std::to_integer<unsigned>(chunk->allocation_bitmap[bit / 8]) & (1u << (bit % 8))) == 0)
                { bad_block = cursor; error = "VerifierSnapshotPayloadNotAllocated"; return false; }
                // Constant scratch even for multi-gigabyte contiguous extents.
                if (bit % 8 == 0 && stop - cursor >= 8 && chunk->allocation_bitmap[bit / 8] == std::byte{0xff}) cursor += 8;
                else ++cursor;
            }
        }
    }
    bad_block.reset(); return true;
}

bool ResolveVerifierReferenceLayer(const RandomAccessSource& source, const AppleCheckpointView& checkpoint,
    const std::vector<ApplePhysicalExtentRecord>& prior, const std::vector<ApplePhysicalExtentRecord>& historical,
    const AppleSnapshotTreeRecords& trees, std::vector<ApplePhysicalExtentRecord>& resolved, std::string& error, bool observational)
{
    // Same interval-work envelope as the canonical snapshot projection resolver.
    // The final live layer consumes this allowance too; never reset it per view.
    for (const auto count : {prior.size(), historical.size(), trees.filesystem.size(), trees.extentref.size()})
    {
        if (count > UINT64_MAX / 2048ull)
        {
            (void)source.ReadBudget()->Refuse("VerifierSnapshotReferenceSizeOverflow");
            error = source.ReadBudget()->Failure(); return false;
        }
        if (!source.ReadBudget()->Materialize(count, count * 2048ull))
        { error = source.ReadBudget()->Failure(); return false; }
    }
    const auto& nx = checkpoint.container.superblock;
    const auto resolve = observational ? ResolveAppleReadOnlySnapshotExtentLayer : ResolveAppleSnapshotExtentLayer;
    return resolve(prior, historical, trees.filesystem, trees.extentref,
        nx.block_size, nx.block_count, resolved, error);
}

bool ReadTree(const RandomAccessSource& source, const AppleCheckpointView& checkpoint,
    const AppleVolumeCheckpointView& volume, const AppleObjectLocation& root,
    std::vector<BtreeRecord>& records, AppleBtreeKeyOrder order,
    std::vector<std::uint64_t>& visited, std::string& error)
{
    BtreeReadPolicy policy;
    policy.visited_physical_blocks = &visited;
    policy.include_ghost_records = order == AppleBtreeKeyOrder::SpacemanFreeQueue;
    policy.enforce_object_identity = true;
    policy.require_complete_traversal = true;
    policy.reject_unsupported_flags = true;
    policy.root_object_id = root.object_id;
    policy.storage_type = root.type;
    policy.subtype = root.subtype;
    policy.ephemeral_checkpoint = &checkpoint.container;
    const bool physical = (root.type & kObjectStorageTypeMask) == kObjectPhysical;
    if (!physical && (root.type & kObjectStorageTypeMask) != kObjectEphemeral)
    {
        policy.virtual_child_resolver = [&](std::uint64_t oid, std::string& detail)
            -> std::optional<BtreeVirtualChildMapping> {
            const auto mapped = ResolveOmapValue(source, checkpoint.container.superblock.block_size,
                volume.object_map.object.object_id, oid, checkpoint.container.superblock.xid, detail);
            if (!mapped) return std::nullopt;
            if (mapped->flags != 0 || mapped->size != checkpoint.container.superblock.block_size)
            { detail = "VerifierVirtualMappingUnsupported"; return std::nullopt; }
            return BtreeVirtualChildMapping{mapped->physical_block, mapped->xid};
        };
    }
    return ReadBtreeLeafRecords(source, checkpoint.container.superblock.block_size,
        root.physical_block, physical, volume.object_map.object.object_id,
        checkpoint.container.superblock.xid, policy, Routing(source, order), records, error);
}

bool CheckVirtualRoot(const RandomAccessSource& source, const AppleCheckpointView& checkpoint,
    const AppleObjectLocation& root, std::uint64_t omap_oid, std::string& error)
{
    const auto mapping = ResolveOmapValue(source, checkpoint.container.superblock.block_size,
        omap_oid, root.object_id, checkpoint.container.superblock.xid, error);
    if (!mapping) return false;
    if (mapping->flags != 0 || mapping->size != checkpoint.container.superblock.block_size)
    { error = "VerifierRootMappingFlagsOrSizeUnsupported"; return false; }
    if (root.xid == 0 || root.xid > mapping->xid || root.physical_block != mapping->physical_block ||
        root.size_bytes != mapping->size)
    { error = "VerifierRootMappingIdentityInconsistent"; return false; }
    return true;
}

bool ChargeHistory(const RandomAccessSource& source, std::uint64_t count,
    std::uint64_t bytes_each, std::string& error)
{
    const auto budget = source.ReadBudget();
    if (bytes_each && count > UINT64_MAX / bytes_each)
        (void)budget->Refuse("VerifierHistorySizeOverflow");
    if (budget->Failed() || !budget->Materialize(count, count * bytes_each))
    { error = budget->Failure(); return false; }
    return true;
}

bool NormalizeProtectedRanges(std::vector<VerificationBlockRange>& ranges,
    std::uint64_t container_blocks, std::string& error)
{
    for (const auto& range : ranges)
        if (!range.block_count || range.physical_block >= container_blocks ||
            range.block_count > container_blocks - range.physical_block)
        { error = "VerifierHistoryProtectedRangeInvalid"; return false; }
    std::sort(ranges.begin(), ranges.end(), [](const auto& a, const auto& b) {
        return std::tie(a.physical_block, a.block_count) < std::tie(b.physical_block, b.block_count);
    });
    std::size_t kept = 0;
    for (const auto range : ranges)
    {
        if (kept && range.physical_block <= ranges[kept - 1].physical_block + ranges[kept - 1].block_count)
        {
            auto& previous = ranges[kept - 1];
            previous.block_count = (std::max)(previous.physical_block + previous.block_count,
                range.physical_block + range.block_count) - previous.physical_block;
        }
        else ranges[kept++] = range;
    }
    ranges.resize(kept);
    return true;
}

bool VerifyRequestedHistory(const RandomAccessSource& source, const AppleCheckpointView& checkpoint,
    const VerifiedCheckpointIdentity& endpoint, std::uint64_t from,
    RequestedHistoryVerification& output, std::string& error, bool read_only)
{
    output = {};
    std::vector<AppleRecoveryCheckpointView> history;
    if (!ChargeHistory(source, 1, sizeof(std::uint64_t), error)) return false;
    const std::vector<std::uint64_t> requested{from};
    // The snapshot-aware entry point authenticates the latest endpoint, hidden
    // OMAP/descriptor owners, each next_xid and allocator/queue continuity.
    if (!(read_only ? LoadAppleReadOnlySnapshotRecoveryCheckpoints(source, checkpoint, requested, history, error) :
        LoadAppleSnapshotRecoveryCheckpoints(source, checkpoint, requested, history, error))) return false;
    const auto& nx = checkpoint.container.superblock;
    std::sort(history.begin(), history.end(), [](const auto& a, const auto& b) {
        return a.checkpoint.container.superblock.xid < b.checkpoint.container.superblock.xid;
    });
    if (history.empty() || history.size() >= UINT64_MAX ||
        !ChargeHistory(source, 1, sizeof(RequestedHistoryVerification) +
            endpoint.exact.container_uuid_hex.size() + endpoint.exact.volume_uuid_hex.size(), error) ||
        !ChargeHistory(source, history.size() + 1, sizeof(std::uint64_t), error) ||
        !ChargeHistory(source, history.size(), sizeof(VerificationProtectedCheckpoint), error))
    {
        if (error.empty()) error = "VerifierHistoryChainUnavailable";
        return false;
    }
    RequestedHistoryVerification result;
    result.from_xid = from;
    result.endpoint = endpoint;
    result.chain_xids.reserve(history.size() + 1);
    result.checkpoints.reserve(history.size());
    auto expected = from;
    for (const auto& retained : history)
    {
        const auto& old = retained.checkpoint;
        const auto& old_nx = old.container.superblock;
        if (old_nx.xid != expected || old_nx.xid >= nx.xid ||
            old_nx.next_xid <= old_nx.xid || old_nx.next_xid > nx.xid)
        { error = "VerifierHistoryChainUnavailable"; return false; }
        if (old_nx.uuid_hex != nx.uuid_hex || old_nx.block_size != nx.block_size ||
            old_nx.block_count != nx.block_count)
        { error = "VerifierHistoryIdentityMismatch"; return false; }
        if (old_nx.incompatible_features & 0x100)
        { error = "VerifierHistoryFusionUnsupported"; return false; }
        if ((old_nx.features & ~kNxKnownOptionalFeaturesMask) || old_nx.readonly_features ||
            (old_nx.incompatible_features & ~kNxSupportedIncompatibleFeaturesMask))
        { error = "VerifierHistoryContainerFeaturesUnsupported"; return false; }
        const auto selected = std::find_if(old.volumes.begin(), old.volumes.end(), [&](const auto& volume) {
            return volume.superblock.object_id == endpoint.exact.volume_oid;
        });
        if (selected == old.volumes.end() || selected->superblock.uuid_hex != endpoint.exact.volume_uuid_hex ||
            std::count_if(old.volumes.begin(), old.volumes.end(), [&](const auto& volume) {
                return volume.superblock.uuid_hex == endpoint.exact.volume_uuid_hex;
            }) != 1)
        { error = "VerifierHistoryIdentityMismatch"; return false; }
        for (const auto& volume : old.volumes)
        {
            if (volume.superblock.fs_flags != kFsFlagUnencrypted)
            { error = "VerifierHistoryEncryptionUnsupported"; return false; }
            if ((volume.superblock.features & ~kVolumeKnownOptionalFeaturesMask) ||
                !CheckAppleVolumeWriteFeatures(old_nx, volume.superblock, error))
            { error = "VerifierHistoryVolumeFeaturesUnsupported:" + error; return false; }
        }
        VerificationProtectedCheckpoint protected_checkpoint;
        protected_checkpoint.checkpoint_xid = old_nx.xid;
        if (!ChargeHistory(source, retained.metadata_blocks.size(), sizeof(VerificationBlockRange), error) ||
            !ChargeHistory(source, retained.payload_extents.size(), sizeof(VerificationBlockRange), error)) return false;
        protected_checkpoint.metadata_ranges.reserve(retained.metadata_blocks.size());
        protected_checkpoint.payload_ranges.reserve(retained.payload_extents.size());
        for (const auto block : retained.metadata_blocks)
            protected_checkpoint.metadata_ranges.push_back({block, 1});
        // Recovery output is physical protection geometry. Its placeholder
        // owner/refcount fields supply no historical logical ownership evidence.
        for (const auto& extent : retained.payload_extents)
            protected_checkpoint.payload_ranges.push_back({extent.physical_block, extent.block_count});
        if (!NormalizeProtectedRanges(protected_checkpoint.metadata_ranges, nx.block_count, error) ||
            !NormalizeProtectedRanges(protected_checkpoint.payload_ranges, nx.block_count, error)) return false;
        if (protected_checkpoint.metadata_ranges.empty())
        { error = "VerifierHistoryMetadataUnavailable"; return false; }
        std::size_t m = 0, p = 0;
        while (m < protected_checkpoint.metadata_ranges.size() && p < protected_checkpoint.payload_ranges.size())
        {
            const auto& metadata = protected_checkpoint.metadata_ranges[m];
            const auto& payload = protected_checkpoint.payload_ranges[p];
            if (metadata.physical_block + metadata.block_count <= payload.physical_block) ++m;
            else if (payload.physical_block + payload.block_count <= metadata.physical_block) ++p;
            else { error = "VerifierHistoryPayloadMetadataOverlap"; return false; }
        }
        result.chain_xids.push_back(old_nx.xid);
        result.checkpoints.push_back(std::move(protected_checkpoint));
        expected = old_nx.next_xid;
    }
    if (expected != nx.xid) { error = "VerifierHistoryChainUnavailable"; return false; }
    result.chain_xids.push_back(nx.xid);
    output = std::move(result);
    return true;
}

VerificationCode HistoryFailureCode(const std::string& error)
{
    if (error == "AppleSnapshotRetirementEndpointUnproven" ||
        error == "AppleCheckpointRetentionIdentityMismatch" || error == "VerifierHistoryIdentityMismatch")
        return VerificationCode::IdentityMismatch;
    if (error == "AppleCheckpointRetentionUnavailable" ||
        error == "AppleCheckpointRetentionContinuityUnavailable" || error == "VerifierHistoryChainUnavailable")
        return VerificationCode::CheckpointUnavailable;
    if (error == "VerifierHistoryFusionUnsupported") return VerificationCode::FusionUnsupported;
    // A recovery helper's diagnostic does not identify a current-volume
    // counter, owner or allocator defect. Keep those findings on check 22.
    const auto code = Classify(error, VerificationCode::StructuralInconsistency);
    switch (code)
    {
    case VerificationCode::ChecksumMismatch:
    case VerificationCode::BudgetExceeded:
    case VerificationCode::CheckpointUnavailable:
    case VerificationCode::UnsupportedFeature:
    case VerificationCode::CryptoUnsupported:
    case VerificationCode::FusionUnsupported:
        return code;
    default:
        return VerificationCode::StructuralInconsistency;
    }
}

using OwnershipRanges = std::vector<VerificationBlockRange>;

bool OwnershipAppend(const RandomAccessSource& source, OwnershipRanges& ranges,
    std::uint64_t block, std::uint64_t count, std::string& error)
{
    if (!count) return true;
    if (!ChargeHistory(source, 1, sizeof(VerificationBlockRange), error)) return false;
    ranges.push_back({block, count});
    return true;
}

std::uint64_t RangeCount(const OwnershipRanges& ranges)
{
    std::uint64_t count = 0;
    for (const auto& r : ranges) count += r.block_count;
    return count;
}

std::uint64_t ExclusiveRangeCount(const OwnershipRanges& ranges, const OwnershipRanges& live)
{
    std::uint64_t count = 0;
    std::size_t index = 0;
    for (const auto& r : ranges)
    {
        auto at = r.physical_block;
        const auto end = at + r.block_count;
        while (index < live.size() && live[index].physical_block + live[index].block_count <= at) ++index;
        for (auto i = index; i < live.size() && live[i].physical_block < end; ++i)
        {
            if (live[i].physical_block > at) count += live[i].physical_block - at;
            at = (std::max)(at, (std::min)(end, live[i].physical_block + live[i].block_count));
            if (at == end) break;
        }
        count += end - at;
    }
    return count;
}

// Enumerate candidates with the canonical NX decoder, then require exact
// canonical checkpoint selection and recovery closure for every generation.
// A stale, damaged or reclaimed candidate prevents exhaustive certification.
bool EnumerateRetainedDescriptorXids(const RandomAccessSource& source, const NxSuperblock& nx,
    const std::function<bool()>& allowed, std::vector<std::uint64_t>& xids,
    std::optional<std::uint64_t>& bad_block, std::optional<std::uint64_t>& bad_xid, std::string& error)
{
    xids.clear();
    if (!nx.xp_desc_block_count || nx.xp_desc_noncontiguous || nx.xp_data_noncontiguous)
    { error = "VerifierRetainedDescriptorGeometryUnsupported"; return false; }
    for (std::uint64_t i = 0; i < nx.xp_desc_block_count; ++i)
    {
        if (!allowed()) { error = source.ReadBudget()->Failure(); return false; }
        const auto at = nx.xp_desc_base_block + i;
        bad_block = at;
        bad_xid.reset();
        std::vector<std::byte> bytes;
        if (!ChargeHistory(source, 1, sizeof(NxSuperblock) + nx.block_size, error)) return false;
        if (!source.Read(at * nx.block_size, nx.block_size, bytes))
        { error = "VerifierRetainedDescriptorReadFailure"; return false; }
        const auto candidate = ParseNxSuperblock(bytes);
        if (!candidate)
        {
            // Header type is damage evidence, never a substitute for canonical
            // NX decoding. Corrupt magic must not erase a retained generation.
            if (ReadU32LE(bytes, 0x20).value_or(0) == kNxsbMagic ||
                (ReadU32LE(bytes, 0x18).value_or(0) & kObjectTypeMask) == kNxSuperblockObjectType)
            {
                const auto header_xid = ReadU64LE(bytes, 0x10);
                if (header_xid && *header_xid) bad_xid = header_xid;
                error = VerifyObjectChecksum(bytes, nx.block_size)
                    ? "VerifierRetainedDescriptorStructureInvalid" : "VerifierRetainedDescriptorChecksumInvalid";
                return false;
            }
            continue;
        }
        bad_xid = candidate->xid;
        if (candidate->uuid_hex != nx.uuid_hex || candidate->block_size != nx.block_size ||
            candidate->block_count != nx.block_count || candidate->xid > nx.xid ||
            ((nx.incompatible_features & kNxIncompatFusion) && candidate->fusion_uuid != nx.fusion_uuid))
        { error = "VerifierHistoryIdentityMismatch"; return false; }
        if (!ChargeHistory(source, 1, sizeof(std::uint64_t), error)) return false;
        xids.push_back(candidate->xid);
    }
    std::sort(xids.begin(), xids.end());
    if (xids.empty() || xids.back() != nx.xid ||
        std::adjacent_find(xids.begin(), xids.end()) != xids.end())
    { error = "VerifierRetainedDescriptorSetAmbiguous"; return false; }
    return true;
}

bool AccountRetainedOwnership(const RandomAccessSource& source, const AppleCheckpointView& checkpoint,
    const std::vector<CurrentOwner>& current_owners,
    const std::function<bool()>& allowed, VerificationRetainedOwnership& result,
    VerificationCheck& phase, std::optional<std::uint64_t>& bad_block,
    std::optional<std::uint64_t>& bad_xid, std::string& error, bool read_only)
{
    const auto& nx = checkpoint.container.superblock;
    phase = VerificationCheck::HistoricalReachability;
    std::vector<std::uint64_t> xids;
    if (!EnumerateRetainedDescriptorXids(source, nx, allowed, xids, bad_block, bad_xid, error)) return false;
    // This entry point authenticates the exact latest endpoint and its complete
    // hidden OMAP graph even when xids contains only the current generation.
    std::vector<AppleRecoveryCheckpointView> history;
    if (!(read_only ? LoadAppleReadOnlySnapshotRecoveryCheckpoints(source, checkpoint, xids, history, error) :
        LoadAppleSnapshotRecoveryCheckpoints(source, checkpoint, xids, history, error))) return false;
    if (history.size() + 1 != xids.size())
    { error = "VerifierHistoryChainUnavailable"; return false; }
    std::sort(history.begin(), history.end(), [](const auto& a, const auto& b) {
        return a.checkpoint.container.superblock.xid < b.checkpoint.container.superblock.xid;
    });
    std::vector<std::uint64_t> metadata;
    std::vector<ApplePhysicalExtentRecord> payload;
    if (!(read_only ? LoadAppleReadOnlySnapshotCheckpointOwners(source, checkpoint, metadata, payload, error) :
        LoadAppleSnapshotCheckpointOwners(source, checkpoint, metadata, payload, error))) return false;
    const auto append = [&](const auto& blocks, const auto& extents) {
        for (const auto block : blocks)
            if (!OwnershipAppend(source, result.metadata_ranges, block, 1, error)) return false;
        for (const auto& extent : extents)
            if (!OwnershipAppend(source, result.payload_ranges, extent.physical_block, extent.block_count, error)) return false;
        return true;
    };
    if (!append(metadata, payload)) return false;
    // The recovery closure protects mutation dependencies. The allocation
    // census also owns the anchor, checkpoint maps and current allocator roots.
    for (const auto& owner : current_owners)
        if (!OwnershipAppend(source, result.metadata_ranges, owner.begin, owner.end - owner.begin, error)) return false;
    for (std::size_t i = 0; i < history.size(); ++i)
    {
        if (!allowed()) { error = source.ReadBudget()->Failure(); return false; }
        const auto& old = history[i].checkpoint;
        const auto& old_nx = old.container.superblock;
        bad_xid = old_nx.xid;
        if (old_nx.xid != xids[i] || old_nx.next_xid != xids[i + 1])
        { error = "VerifierHistoryChainUnavailable"; return false; }
        if (old_nx.features & ~kNxKnownOptionalFeaturesMask || old_nx.readonly_features ||
            old_nx.incompatible_features & ~kNxSupportedIncompatibleFeaturesMask)
        { error = "VerifierHistoryContainerFeaturesUnsupported"; return false; }
        for (const auto& volume : old.volumes)
        {
            if (volume.superblock.fs_flags != kFsFlagUnencrypted)
            { error = "VerifierHistoryEncryptionUnsupported"; return false; }
            if (volume.superblock.features & ~kVolumeKnownOptionalFeaturesMask ||
                !CheckAppleVolumeWriteFeatures(old_nx, volume.superblock, error))
            { error = "VerifierHistoryVolumeFeaturesUnsupported:" + error; return false; }
        }
        if (!append(history[i].metadata_blocks, history[i].payload_extents)) return false;
    }
    bad_xid.reset(); bad_block.reset();
    if (!NormalizeProtectedRanges(result.metadata_ranges, nx.block_count, error) ||
        !NormalizeProtectedRanges(result.payload_ranges, nx.block_count, error)) return false;
    std::size_t m = 0, p = 0;
    while (m < result.metadata_ranges.size() && p < result.payload_ranges.size())
    {
        if (!allowed()) { error = source.ReadBudget()->Failure(); return false; }
        const auto& a = result.metadata_ranges[m]; const auto& b = result.payload_ranges[p];
        if (a.physical_block + a.block_count <= b.physical_block) ++m;
        else if (b.physical_block + b.block_count <= a.physical_block) ++p;
        else
        {
            bad_block = (std::max)(a.physical_block, b.physical_block);
            error = "VerifierRetainedPayloadMetadataConflict"; return false;
        }
    }
    result.checkpoint_xids = std::move(xids);
    phase = VerificationCheck::CompleteAllocationAccounting;
    return true;
}

// Classify allocated bits, not address-space lengths. Reservations are charged
// after owners, queues after reservations, so each allocated bit is counted once.
bool PartitionRetainedAllocation(const RandomAccessSource& source, const AppleCheckpointView& checkpoint,
    const std::function<bool()>& allowed, VerificationRetainedOwnership& result, std::string& error)
{
    const auto& nx = checkpoint.container.superblock;
    const auto& pool = checkpoint.spaceman.internal_pool;
    OwnershipRanges owned, reserved, queued;
    for (const auto* ranges : {&result.metadata_ranges, &result.payload_ranges})
        for (const auto& r : *ranges)
            if (!OwnershipAppend(source, owned, r.physical_block, r.block_count, error)) return false;
    for (const auto& r : {VerificationBlockRange{nx.xp_desc_base_block, nx.xp_desc_block_count},
        {nx.xp_data_base_block, nx.xp_data_block_count}, {pool.base_block, pool.block_count},
        {pool.bitmap_base_block, pool.bitmap_block_count}})
        if (!OwnershipAppend(source, reserved, r.physical_block, r.block_count, error)) return false;
    for (const auto& queue : checkpoint.spaceman.free_queues)
        for (const auto& entry : queue.entries)
            if (!OwnershipAppend(source, queued, entry.physical_block, entry.block_count, error)) return false;
    for (auto* ranges : {&owned, &reserved, &queued})
        if (!NormalizeProtectedRanges(*ranges, nx.block_count, error)) return false;
    const auto scan = [&](const auto& bytes, std::uint64_t first, std::uint64_t count, bool internal) {
        if (count > bytes.size() * 8ull) { error = "VerifierCensusBitmapCoverageMissing"; return false; }
        std::size_t o = 0, r = 0, q = 0;
        const auto contains = [](const auto& ranges, auto& index, std::uint64_t block) {
            while (index < ranges.size() && ranges[index].physical_block + ranges[index].block_count <= block) ++index;
            return index < ranges.size() && ranges[index].physical_block <= block;
        };
        for (std::uint64_t bit = 0; bit < count; ++bit)
        {
            if ((bit & 4095) == 0 && !allowed()) { error = source.ReadBudget()->Failure(); return false; }
            if (bit % 8 == 0 && count - bit >= 8 && bytes[bit / 8] == std::byte{0}) { bit += 7; continue; }
            if (!(std::to_integer<unsigned>(bytes[bit / 8]) & (1u << (bit % 8)))) continue;
            const auto block = first + bit;
            ++(internal ? result.allocated_internal_blocks : result.allocated_main_blocks);
            if (contains(owned, o, block)) ++(internal ? result.owned_internal_blocks : result.owned_main_blocks);
            else if (!internal && contains(reserved, r, block)) ++result.reserved_main_blocks;
            else if (contains(queued, q, block)) ++(internal ? result.deferred_internal_blocks : result.deferred_main_blocks);
            else { error = "VerifierRetainedPartitionUnattributed:block=" + std::to_string(block); return false; }
        }
        return true;
    };
    for (const auto& chunk : checkpoint.spaceman.chunks)
        if (chunk.bitmap_block && !scan(chunk.allocation_bitmap, chunk.start_block, chunk.block_count, false)) return false;
    const auto capacity = 8ull * nx.block_size;
    for (std::size_t i = 0; i < pool.active_bitmaps.size() && i * capacity < pool.block_count; ++i)
        if (!scan(pool.active_bitmaps[i].bytes, pool.base_block + i * capacity,
            (std::min)(capacity, pool.block_count - i * capacity), true)) return false;
    return true;
}
}

VerificationReport ApfsVerifier::Verify(const RandomAccessSource& source, const VerificationScope& scope)
{
    return Verify(source, scope, [] { return true; });
}

static VerificationReport VerifyWithAdmission(const RandomAccessSource& source, const VerificationScope& scope,
    const std::function<bool()>& within_deadline, bool read_only)
{
    VerificationReport report;
    report.requested_scope = scope;
    const auto add = [&](VerificationCheck check, bool implemented, bool required, const char* detail) {
        report.coverage.push_back({check, implemented, required, VerificationCheckState::Unproven, detail});
    };
    add(VerificationCheck::ExactSelection, true, true, "Exact container/volume UUID, OID, XID and store window; source identity is caller supplied");
    add(VerificationCheck::OrdinaryFeatures, true, true, "Single-store ordinary unencrypted current volume and dependency roots");
    add(VerificationCheck::SpacemanGraph, true, true, "Authoritative spaceman bitmap, pool, free queue and counter consistency");
    add(VerificationCheck::SnapshotInventory, true, true, "Authoritative ordinary snapshot inventories for all volumes; complete historical accounting remains unproven");
    add(VerificationCheck::MetadataTreeWalk, true, true, "All current FS/extentref, snapshot inventory, OMAP including snapshot-index, and free-queue trees: checksum, identity, bounds, cycles, counts");
    add(VerificationCheck::LeafKeyOrder, true, true, "All current FS/extentref, snapshot inventory, OMAP including snapshot-index, and free-queue leaf order and duplicate keys");
    add(VerificationCheck::NamespaceLinksAndStreams, true, true, "All current volumes strict namespace/links/streams; only admitted inode/xattr flags, base directory records and name/dstream/sparse inode xfields");
    add(VerificationCheck::PayloadReferences, true, true, "All current volumes normalized live physical intervals and reference multiplicity; canonical signed snapshot-layer resolution bound to reread live records where needed; no payload reads");
    add(VerificationCheck::PayloadAllocatorOwnership, true, true, "All current payload allocated, nonqueued, outside current container metadata and reserved ranges");
    add(VerificationCheck::SharedSpaceAndQuota, true, true, "Container shared counters/reserves and each volume allocated count versus configured quota");
    add(VerificationCheck::InternalSeparatorRouting, true, true, "All current trees: exact comparator order, separator equals child minimum, exclusive upper ranges at every level");
    add(VerificationCheck::MetadataAllocatorOwnership, true, true, "Current reachable trees, objects, checkpoint mappings and allocator metadata: main/internal bits set, no deferred-free entry");
    add(VerificationCheck::CrossVolumePayloadOwnership, true, true, "All admitted current peer volumes: independently validated physical payload intervals do not overlap");
    add(VerificationCheck::CurrentOwnershipCensus, true, true, read_only ?
        "Current object/tree physical ownership intervals are disjoint; APSB logical allocation charges are not derived or compared; exhaustive allocated-bit/orphan proof requires CompleteAllocationAccounting" :
        "Current object/tree ownership intervals are disjoint; APSB allocation is at least current unique metadata plus payload; overstatements and orphan ownership remain unproven");
    add(VerificationCheck::SnapshotReachableAllocation, true, true, "Exact catalog dependency nodes with authenticated volume, map, object OID/XID, selection version, physical range and metadata class; conflicting owners rejected, immutable same-volume sharing permitted; current allocation and no deferred free or payload-versus-metadata overlap; canonical NEW/UPDATE payload coverage through final live view; all-peer alias and allocator recheck; full retained-checkpoint continuity/accounting unproven");
    add(VerificationCheck::CompleteAllocationAccounting, scope.account_retained_ownership,
        scope.require_whole_volume || scope.account_retained_ownership, scope.account_retained_ownership
        ? "Every allocated main/internal bit attributed once to canonical graph ownership, main reservations or deferred retirement; no orphan bits; APSB logical charges and purgeability are separate"
        : "Orphan allocations, retained ownership of every allocated block, and APSB totals versus full ownership are unproven");
    add(VerificationCheck::HistoricalReachability, scope.account_retained_ownership,
        scope.require_whole_volume || scope.account_retained_ownership, scope.account_retained_ownership
        ? "Every descriptor-ring NXSB and exact successor chain to latest; canonical complete hidden OMAP/snapshot closure and allocator/queue continuity; stale/reclaimed generations refuse certification"
        : "Full retained-checkpoint continuity and ownership of unselected historical OMAP targets are unproven");
    add(VerificationCheck::PayloadContentHashes, false, scope.require_payload_content_hashes || scope.require_whole_volume,
        scope.observe_payload_content ? "Independent expected payload comparison is not supplied" : "Payload bytes are not read or hashed");
    add(VerificationCheck::Crypto, false, false, "Encrypted volumes/keybags are unsupported");
    add(VerificationCheck::Fusion, false, false, "Fusion/multiple physical stores are unsupported");
    Coverage(report, VerificationCheck::Crypto).state = VerificationCheckState::Unsupported;
    Coverage(report, VerificationCheck::Fusion).state = VerificationCheckState::Unsupported;
    if (scope.observe_payload_content)
    {
        add(VerificationCheck::CurrentPayloadObservation, true, true,
            "Selected admitted current regular-file/xattr logical bytes; observed SHA256 with expected comparison NotSupplied");
        report.payload_inventory.emplace();
        report.payload_inventory->outcome = payload::Outcome::Incomplete;
        report.payload_inventory->reason = payload::Reason::AdmissionNotComplete;
    }
    if (scope.retained_from_xid)
        add(VerificationCheck::RequestedHistoryOwnership, true, true,
            "Protected metadata/payload ranges and allocation, retirement-queue and bitmap continuity for the explicit retained-XID chain to this exact latest endpoint; hidden descriptor closure included; not exhaustive history, orphan accounting, logical reference counts or write authority");

    VerificationCheck active = VerificationCheck::ExactSelection;
    std::optional<std::uint64_t> affected_volume, affected_object, affected_block;
    std::optional<std::uint64_t> affected_xid;
    std::optional<std::uint64_t> affected_failed_offset;
    std::unique_ptr<VerificationSource> bounded;
    const auto fail = [&](VerificationCode code, std::string detail, bool refused = false) {
        if (bounded && bounded->io_failed) { code = VerificationCode::ReadFailure; refused = false; }
        else if (bounded && bounded->ReadBudget()->Failed())
        { code = VerificationCode::BudgetExceeded; detail = bounded->ReadBudget()->Failure(); refused = false; }
        else if (bounded && bounded->bounds_failed) { code = VerificationCode::StructuralInconsistency; refused = false; }
        if (code == VerificationCode::UnsupportedFeature || code == VerificationCode::CryptoUnsupported ||
            code == VerificationCode::FusionUnsupported) refused = true;
        if (code == VerificationCode::SpacemanInconsistent) active = VerificationCheck::SpacemanGraph;
        if (code == VerificationCode::FusionUnsupported) active = VerificationCheck::Fusion;
        if (code == VerificationCode::CryptoUnsupported) active = VerificationCheck::Crypto;
        auto& coverage = Coverage(report, active);
        coverage.state = refused ? VerificationCheckState::Unsupported :
            (code == VerificationCode::ReadFailure || code == VerificationCode::BudgetExceeded ||
                code == VerificationCode::CheckpointUnavailable ? VerificationCheckState::Unproven : VerificationCheckState::Inconsistent);
        report.findings.push_back({code, refused ? VerificationSeverity::Warning : VerificationSeverity::Error,
            active, affected_volume, affected_object, affected_block,
            affected_xid ? affected_xid : (scope.exact.checkpoint_xid ? std::optional{scope.exact.checkpoint_xid} : std::nullopt),
            bounded && bounded->io_failed ? std::optional{bounded->failed_offset} : affected_failed_offset, std::move(detail)});
        report.outcome = refused ? VerificationOutcome::Refused : VerificationOutcome::Incomplete;
    };
    const auto failed = [&](const std::string& error, VerificationCode fallback) {
        fail(Classify(error, fallback), error);
    };
    try
    {
        const auto run = [&]() {
            const auto& exact = scope.exact;
            if (scope.source_identity.empty() || scope.source_identity.size() > 1024 ||
                !UuidValid(exact.container_uuid_hex) || !UuidValid(exact.volume_uuid_hex) ||
                !exact.volume_oid || !exact.checkpoint_xid || !exact.store_size_bytes ||
                exact.store_offset_bytes > source.SizeBytes() ||
                exact.store_size_bytes > source.SizeBytes() - exact.store_offset_bytes ||
                !scope.max_reads || !scope.max_read_bytes || !scope.max_records || !scope.max_record_bytes ||
                (scope.observe_payload_content && (!within_deadline ||
                    scope.max_payload_logical_bytes != payload::MaxLogicalBytes || scope.max_payload_entries != payload::MaxEntries)))
            { fail(VerificationCode::InvalidScope, "VerifierScopeInvalid", true); return; }
            if (scope.retained_from_xid && (!*scope.retained_from_xid || *scope.retained_from_xid >= exact.checkpoint_xid))
            {
                active = VerificationCheck::RequestedHistoryOwnership;
                fail(VerificationCode::InvalidScope, "VerifierRetainedFromXidInvalid", true); return;
            }
            bounded = std::make_unique<VerificationSource>(source, scope, within_deadline);
            report.read_budget = bounded->ReadBudget();
            const auto work_allowed = [&] { return bounded->WithinDeadline(); };
            const auto deadline_failed = [&] {
                if (work_allowed()) return false;
                fail(VerificationCode::BudgetExceeded, bounded->ReadBudget()->Failure()); return true;
            };
            if (deadline_failed()) return;
            if (report.payload_inventory) report.payload_inventory->sharedBudget = report.read_budget;
            OffsetRandomAccessSource store(bounded.get(), exact.store_offset_bytes, exact.store_size_bytes);
            std::string error;
            const auto checkpoint = LoadAppleCheckpointView(store, 0, store.SizeBytes(), error, exact.checkpoint_xid);
            if (!checkpoint || bounded->io_failed || bounded->ReadBudget()->Failed())
            { failed(error, VerificationCode::StructuralInconsistency); return; }
            if (deadline_failed()) return;
            const auto& nx = checkpoint->container.superblock;
            const auto selected = std::find_if(checkpoint->volumes.begin(), checkpoint->volumes.end(),
                [&](const auto& volume) { return volume.superblock.object_id == exact.volume_oid; });
            if (nx.uuid_hex != exact.container_uuid_hex || nx.xid != exact.checkpoint_xid ||
                selected == checkpoint->volumes.end() || selected->superblock.uuid_hex != exact.volume_uuid_hex ||
                std::count_if(checkpoint->volumes.begin(), checkpoint->volumes.end(), [&](const auto& volume) {
                    return volume.superblock.uuid_hex == exact.volume_uuid_hex; }) != 1)
            { fail(VerificationCode::IdentityMismatch, "VerifierExactIdentityMismatch", true); return; }
            if (nx.block_size == 0 || nx.block_count > UINT64_MAX / nx.block_size ||
                nx.block_count * nx.block_size != exact.store_size_bytes || exact.store_offset_bytes % nx.block_size)
            { fail(VerificationCode::InvalidScope, "VerifierStoreWindowMustEqualContainerGeometry", true); return; }
            report.selected = VerifiedCheckpointIdentity{exact, checkpoint->container.superblock_physical_block,
                selected->superblock_object.physical_block, selected->superblock.xid,
                selected->root_tree.object_id, selected->root_tree.physical_block};
            Coverage(report, active).state = VerificationCheckState::Verified;
            Coverage(report, VerificationCheck::SpacemanGraph).state = VerificationCheckState::Verified;
            active = VerificationCheck::OrdinaryFeatures;
            if (nx.incompatible_features & 0x100)
            { fail(VerificationCode::FusionUnsupported, "VerifierFusionUnsupported", true); return; }
            if ((nx.features & ~kNxKnownOptionalFeaturesMask) || nx.readonly_features ||
                (nx.incompatible_features & ~kNxSupportedIncompatibleFeaturesMask))
            { fail(VerificationCode::UnsupportedFeature, "VerifierContainerFeaturesUnsupported", true); return; }
            for (const auto& volume : checkpoint->volumes)
            {
                if (deadline_failed()) return;
                affected_volume = volume.superblock.object_id;
                if (volume.superblock.fs_flags != kFsFlagUnencrypted)
                { fail(VerificationCode::CryptoUnsupported, "VerifierEncryptionOrFsFlagsUnsupported", true); return; }
                if ((volume.superblock.features & ~kVolumeKnownOptionalFeaturesMask) ||
                    !CheckAppleVolumeWriteFeatures(nx, volume.superblock, error))
                { fail(VerificationCode::UnsupportedFeature, "VerifierOrdinaryVolumeFeaturesUnsupported:" + error, true); return; }
            }
            Coverage(report, active).state = VerificationCheckState::Verified;
            bool has_snapshots = false;
            const bool capture_snapshot_owners = std::any_of(checkpoint->volumes.begin(), checkpoint->volumes.end(),
                [](const auto& volume) { return volume.object_map.snapshot_tree_oid != 0; });
            std::vector<AppleSnapshotMetadataClaim> snapshot_owners;
            std::vector<VerificationSnapshotPayloadUsage> snapshot_usage;
            struct SnapshotLiveGraph
            {
                std::uint64_t volume_oid;
                std::vector<BtreeRecord> filesystem, extentrefs;
                std::vector<ApplePhysicalExtentRecord> physical;
                std::shared_ptr<const NativeApfsVolumeProjection> namespace_projection;
            };
            std::vector<SnapshotLiveGraph> snapshot_live;
            bool snapshot_ownership_verified = false;
            active = VerificationCheck::SnapshotInventory;
            for (const auto& volume : checkpoint->volumes)
            {
                affected_volume = volume.superblock.object_id;
                // Authoritative checkpoint resolution bounds headers by NX XID.
                // Also bind each virtual root to its selected OMAP version.
                active = VerificationCheck::MetadataTreeWalk;
                affected_object = volume.superblock_object.object_id;
                affected_block = volume.superblock_object.physical_block;
                if (!CheckVirtualRoot(store, *checkpoint, volume.superblock_object,
                    checkpoint->container_object_map.object.object_id, error))
                { failed(error, VerificationCode::StructuralInconsistency); return; }
                for (const auto* root : {&volume.root_tree,
                    volume.extentref_tree ? &*volume.extentref_tree : nullptr,
                    volume.snapshot_metadata_tree ? &*volume.snapshot_metadata_tree : nullptr})
                    if (root && (root->type & kObjectStorageTypeMask) == 0)
                    {
                        affected_object = root->object_id; affected_block = root->physical_block;
                        if (!CheckVirtualRoot(store, *checkpoint, *root, volume.object_map.object.object_id, error))
                        { failed(error, VerificationCode::StructuralInconsistency); return; }
                    }
                affected_object.reset(); affected_block.reset();
                active = VerificationCheck::SnapshotInventory;
                AppleSnapshotCatalogRecords catalog;
                std::vector<AppleSnapshotMetadataClaim> volume_owners;
                if (!(capture_snapshot_owners ? (read_only ?
                    LoadAppleReadOnlySnapshotCatalog(store, *checkpoint, *affected_volume, catalog, volume_owners, error) :
                    LoadAppleSnapshotCatalog(store, *checkpoint, *affected_volume, catalog, volume_owners, error)) : (read_only ?
                    LoadAppleReadOnlySnapshotCatalog(store, *checkpoint, *affected_volume, catalog, error) :
                    LoadAppleSnapshotCatalog(store, *checkpoint, *affected_volume, catalog, error))))
                { failed(error, VerificationCode::SnapshotCoverageUnavailable); return; }
                if (capture_snapshot_owners)
                {
                    std::vector<std::uint64_t> attributed;
                    if (!store.ReadBudget()->Materialize(0, volume_owners.size() * sizeof(std::uint64_t)) ||
                        !store.ReadBudget()->Materialize(volume_owners.size(),
                            volume_owners.size() * sizeof(AppleSnapshotMetadataClaim)))
                    { failed(store.ReadBudget()->Failure(), VerificationCode::BudgetExceeded); return; }
                    for (const auto& owner : volume_owners) attributed.push_back(owner.physical_block);
                    std::sort(attributed.begin(), attributed.end());
                    attributed.erase(std::unique(attributed.begin(), attributed.end()), attributed.end());
                    if (attributed != catalog.metadata_blocks)
                    { fail(VerificationCode::StructuralInconsistency, "VerifierSnapshotMetadataOwnerCoverageIncomplete"); return; }
                    snapshot_owners.insert(snapshot_owners.end(), volume_owners.begin(), volume_owners.end());
                }
                const auto& snapshots = catalog.inventory;
                if (catalog.snapshots.size() != snapshots.size())
                { fail(VerificationCode::StructuralInconsistency, "VerifierSnapshotCatalogCountMismatch"); return; }
                has_snapshots = has_snapshots || !snapshots.empty();
                if (scope.account_retained_ownership)
                {
                    if (!ChargeHistory(store, 1, sizeof(VerificationSnapshotPayloadUsage), error))
                    { failed(error, VerificationCode::BudgetExceeded); return; }
                    snapshot_usage.push_back({volume.superblock.object_id});
                }
                std::vector<ApplePhysicalExtentRecord> prior, historical;
                for (std::size_t index = 0; index < snapshots.size(); ++index)
                {
                    const auto& snapshot = snapshots[index];
                    active = VerificationCheck::SnapshotReachableAllocation;
                    affected_xid = snapshot.xid;
                    affected_object = snapshot.volume.superblock_object.object_id;
                    affected_block = snapshot.volume.superblock_object.physical_block;
                    const auto& trees = catalog.snapshots[index];
                    VerificationCode snapshot_code = VerificationCode::StructuralInconsistency;
                    if (!CheckReachableAllocation(store, *checkpoint, snapshot.volume, trees, catalog.metadata_blocks,
                        affected_block, snapshot_code, error, nullptr, read_only))
                    { affected_object.reset(); failed(error, snapshot_code); return; }
                    affected_object = snapshot.volume.extentref_tree->object_id;
                    affected_block = snapshot.volume.extentref_tree->physical_block;
                    std::vector<ApplePhysicalExtentRecord> resolved;
                    if (!ResolveVerifierReferenceLayer(store, *checkpoint, prior, historical, trees, resolved, error, read_only))
                    { failed(error, VerificationCode::ExtentReferenceInconsistent); return; }
                    historical.insert(historical.end(), resolved.begin(), resolved.end());
                    prior = std::move(resolved);
                    affected_xid.reset(); affected_object.reset(); affected_block.reset();
                }
                if (!snapshots.empty())
                {
                    active = VerificationCheck::SnapshotReachableAllocation;
                    affected_xid = nx.xid;
                    affected_object = volume.superblock_object.object_id;
                    affected_block = volume.superblock_object.physical_block;
                    VerificationCode live_code = VerificationCode::StructuralInconsistency;
                    std::shared_ptr<const NativeApfsVolumeProjection> namespace_projection;
                    if (!CheckReachableAllocation(store, *checkpoint, volume, catalog.live, catalog.metadata_blocks,
                        affected_block, live_code, error, scope.observe_payload_content &&
                            volume.superblock.object_id == exact.volume_oid ? &namespace_projection : nullptr, read_only))
                    { affected_object.reset(); failed(error, live_code); return; }
                    affected_object = volume.extentref_tree->object_id;
                    affected_block = volume.extentref_tree->physical_block;
                    std::vector<ApplePhysicalExtentRecord> live;
                    if (!ResolveVerifierReferenceLayer(store, *checkpoint, prior, historical, catalog.live, live, error, read_only))
                    { failed(error, VerificationCode::ExtentReferenceInconsistent); return; }
                    if (scope.account_retained_ownership)
                    {
                        OwnershipRanges retained_ranges, live_ranges;
                        for (const auto& extent : historical)
                            if (!OwnershipAppend(store, retained_ranges, extent.physical_block, extent.block_count, error))
                            { failed(error, VerificationCode::BudgetExceeded); return; }
                        for (const auto& extent : live)
                            if (!OwnershipAppend(store, live_ranges, extent.physical_block, extent.block_count, error))
                            { failed(error, VerificationCode::BudgetExceeded); return; }
                        if (!NormalizeProtectedRanges(retained_ranges, nx.block_count, error) ||
                            !NormalizeProtectedRanges(live_ranges, nx.block_count, error))
                        { failed(error, VerificationCode::StructuralInconsistency); return; }
                        auto& usage = snapshot_usage.back();
                        usage.referenced_blocks = RangeCount(retained_ranges);
                        usage.exclusive_blocks = ExclusiveRangeCount(retained_ranges, live_ranges);
                        usage.referenced_bytes = usage.referenced_blocks * nx.block_size;
                        usage.exclusive_bytes = usage.exclusive_blocks * nx.block_size;
                    }
                    if (!store.ReadBudget()->Materialize(1, sizeof(SnapshotLiveGraph)))
                    { failed(store.ReadBudget()->Failure(), VerificationCode::BudgetExceeded); return; }
                    snapshot_live.push_back({volume.superblock.object_id, std::move(catalog.live.filesystem),
                        std::move(catalog.live.extentref), std::move(live), std::move(namespace_projection)});
                    affected_xid.reset(); affected_object.reset(); affected_block.reset();
                }
            }
            Coverage(report, VerificationCheck::SnapshotInventory).state = VerificationCheckState::Verified;
            if (has_snapshots)
            {
                // Reuse the canonical read-only retained-owner census for the
                // all-peer alias proof and final allocator currency check.
                active = VerificationCheck::SnapshotReachableAllocation;
                affected_volume.reset();
                AppleSnapshotRetentionView retained;
                if (!(read_only ? LoadAppleReadOnlySnapshotRetention(store, *checkpoint, retained, error) :
                    LoadAppleSnapshotRetention(store, *checkpoint, retained, error)))
                {
                    auto code = VerificationCode::StructuralInconsistency;
                    if (error == "AppleSnapshotRetentionCrossVolumePayloadOverlap") code = VerificationCode::CrossVolumePayloadOverlap;
                    else if (error == "AppleSnapshotRetentionPayloadMetadataOverlap") code = VerificationCode::PayloadMetadataOverlap;
                    else if (error == "AppleSnapshotRetentionMetadataNotOwned") code = VerificationCode::MetadataAllocationInconsistent;
                    else if (error == "AppleSnapshotRetentionPayloadNotOwned") code = VerificationCode::PayloadAllocationInconsistent;
                    else if (error == "AppleVolumePhysicalExtentOwnerMismatch" ||
                        error == "AppleVolumePhysicalExtentRefcountMismatch" ||
                        error == "AppleVolumePhysicalExtentCoverageIncomplete")
                        code = VerificationCode::ExtentReferenceInconsistent;
                    failed(error, code); return;
                }
                std::optional<AppleSnapshotMetadataClaim> bad_owner;
                if (!CheckSnapshotMetadataOwners(*checkpoint, snapshot_owners, bad_owner, error))
                {
                    if (bad_owner)
                    {
                        affected_volume = bad_owner->volume_oid ? std::optional{bad_owner->volume_oid} : std::nullopt;
                        affected_object = bad_owner->object_id; affected_block = bad_owner->physical_block;
                        affected_xid = bad_owner->object_xid;
                    }
                    failed(error, VerificationCode::MetadataOwnerConflict); return;
                }
                snapshot_ownership_verified = true;
            }
            Coverage(report, VerificationCheck::SnapshotReachableAllocation).state = VerificationCheckState::Verified;
            if (has_snapshots && scope.require_whole_volume && !scope.retained_from_xid && !scope.account_retained_ownership)
            {
                active = VerificationCheck::HistoricalReachability;
                affected_volume.reset();
                fail(VerificationCode::SnapshotAccountingUnsupported, "VerifierSnapshotReachableBlocksCheckedButHistoricalReferenceOwnershipUnproven", true);
                return;
            }
            std::vector<CurrentOwner> current_owners;
            std::vector<std::uint64_t> metadata_blocks;
            std::vector<BtreeRecord> map_records;
            const auto walk = [&](const AppleVolumeCheckpointView& volume, const AppleObjectLocation& root,
                std::vector<BtreeRecord>& records, AppleBtreeKeyOrder order, bool container_tree = false) {
                active = VerificationCheck::MetadataTreeWalk;
                affected_volume = volume.superblock.object_id;
                affected_object = root.object_id; affected_block = root.physical_block;
                std::vector<std::uint64_t> visited;
                if (!ReadTree(store, *checkpoint, volume, root, records, order, visited, error))
                {
                    if (Contains(error, "Routing")) active = VerificationCheck::InternalSeparatorRouting;
                    else if (error == "CatalogBtreeLeafKeyOrder") active = VerificationCheck::LeafKeyOrder;
                    failed(error, VerificationCode::StructuralInconsistency); return false;
                }
                if (!CheckOrder(store, records, order, error))
                { active = VerificationCheck::LeafKeyOrder; failed(error, VerificationCode::TreeOrderInconsistent); return false; }
                if (!store.ReadBudget()->Materialize(0, visited.size() * sizeof(std::uint64_t)))
                { failed(store.ReadBudget()->Failure(), VerificationCode::BudgetExceeded); return false; }
                for (const auto block : visited)
                    if (!AddCurrentOwner(store, *checkpoint, current_owners, block, 1,
                        container_tree ? 0 : volume.superblock.object_id, root, true, error))
                    { failed(error, VerificationCode::StructuralInconsistency); return false; }
                metadata_blocks.insert(metadata_blocks.end(), visited.begin(), visited.end());
                return true;
            };
            if (!walk(*selected, checkpoint->container_object_map.tree, map_records, AppleBtreeKeyOrder::ObjectMap, true)) return;
            for (const auto& queue : checkpoint->spaceman.free_queues)
                if (queue.tree_oid && !walk(*selected, queue.root, map_records, AppleBtreeKeyOrder::SpacemanFreeQueue, true)) return;
            struct OwnedExtent { ApplePhysicalExtentRecord extent; std::uint64_t volume_oid; };
            std::vector<OwnedExtent> owned;
            std::vector<ApplePhysicalExtentRecord> physical;
            std::uint64_t selected_records = 0, selected_extents = 0;
            for (const auto& volume : checkpoint->volumes)
            {
                if (!walk(volume, volume.object_map.tree, map_records, AppleBtreeKeyOrder::ObjectMap)) return;
                if (volume.object_map.snapshot_tree_oid)
                {
                    const auto root = std::find_if(snapshot_owners.begin(), snapshot_owners.end(), [&](const auto& owner) {
                        return owner.volume_oid == volume.superblock.object_id && owner.view_xid == nx.xid &&
                            owner.metadata_class == AppleSnapshotMetadataClass::OmapSnapshotNode &&
                            owner.object_id == volume.object_map.snapshot_tree_oid &&
                            owner.physical_block == volume.object_map.snapshot_tree_oid;
                    });
                    if (root == snapshot_owners.end())
                    { fail(VerificationCode::StructuralInconsistency, "VerifierCurrentSnapshotIndexOwnerMissing"); return; }
                    AppleObjectLocation location{root->object_id, root->object_xid, root->physical_block,
                        root->type, root->subtype, nx.block_size};
                    if (!walk(volume, location, map_records, AppleBtreeKeyOrder::SnapshotObjectMap)) return;
                }
                const auto fs_order = ApfsNamePolicy::FromIncompatibleFeatures(volume.superblock.incompatible_features).UsesHashedDirectoryKeys()
                    ? AppleBtreeKeyOrder::FileSystemHashedDirectory : AppleBtreeKeyOrder::FileSystemCaseSensitive;
                if (volume.snapshot_metadata_tree &&
                    !walk(volume, *volume.snapshot_metadata_tree, map_records, AppleBtreeKeyOrder::FileSystemCaseSensitive)) return;
                std::vector<BtreeRecord> filesystem, extentrefs;
                if (!walk(volume, volume.root_tree, filesystem, fs_order)) return;
                if (!volume.extentref_tree)
                { fail(VerificationCode::UnsupportedFeature, "VerifierExtentrefCoverageMissing", true); return; }
                if (!walk(volume, *volume.extentref_tree, extentrefs, AppleBtreeKeyOrder::PhysicalExtent)) return;
                active = VerificationCheck::PayloadReferences;
                for (const auto* records : {&filesystem, &extentrefs})
                    for (const auto& record : *records)
                    {
                        // The self-comparison extent graph retains scalar uses,
                        // pointers, range/event vectors and fixed-size indexes.
                        // Encoded extents are not copied. Variable inode/xattr
                        // codecs still need the larger envelope; namespace
                        // projection separately charges its own decoded objects.
                        const auto kind = ReadU64LE(record.key, 0).value_or(0) >> 60;
                        const auto bytes = records == &extentrefs || kind == 8 ? 512ull :
                            (kind == 3 || kind == 4 ?
                                8192 + 32ull * (record.key.size() + record.value.size()) : 0ull);
                        if (!store.ReadBudget()->Materialize(1, bytes))
                        { failed(store.ReadBudget()->Failure(), VerificationCode::BudgetExceeded); return; }
                    }
                std::vector<ApplePhysicalExtentRecord> volume_physical;
                const auto resolved_live = std::find_if(snapshot_live.begin(), snapshot_live.end(),
                    [&](const auto& graph) { return graph.volume_oid == volume.superblock.object_id; });
                if (resolved_live != snapshot_live.end())
                {
                    const auto same = [](const auto& left, const auto& right) {
                        return left.size() == right.size() && std::equal(left.begin(), left.end(), right.begin(),
                            [](const auto& a, const auto& b) { return a.key == b.key && a.value == b.value; });
                    };
                    if (!same(filesystem, resolved_live->filesystem) || !same(extentrefs, resolved_live->extentrefs))
                    { fail(VerificationCode::IdentityMismatch, "VerifierCurrentSnapshotLiveRecordsChanged"); return; }
                    volume_physical = std::move(resolved_live->physical);
                }
                else if (!(read_only ? ValidateAppleReadOnlyPayloadExtentGraph : ValidateApplePayloadExtentGraph)(filesystem, extentrefs, nx.block_size, nx.block_count, volume_physical, error))
                { failed(error, VerificationCode::ExtentReferenceInconsistent); return; }
                active = VerificationCheck::NamespaceLinksAndStreams;
                if (scope.observe_payload_content && volume.superblock.object_id == exact.volume_oid)
                {
                    if (resolved_live != snapshot_live.end())
                        report.payload_projection = std::move(resolved_live->namespace_projection);
                    else
                    {
                        NativeApfsVolumeProjection projection;
                        if (!(read_only ? NativeApfsReader::TryProjectObservationalFileSystemRecords : NativeApfsReader::TryProjectOrdinaryFileSystemRecords)(filesystem, nx, volume.superblock,
                            store.ReadBudget(), projection, error))
                        { failed(error, VerificationCode::NamespaceOrLinkInconsistent); return; }
                        if (!store.ReadBudget()->Materialize(1, sizeof(NativeApfsVolumeProjection) + 64))
                        { failed(store.ReadBudget()->Failure(), VerificationCode::BudgetExceeded); return; }
                        report.payload_projection = std::make_shared<const NativeApfsVolumeProjection>(std::move(projection));
                    }
                }
                // Reuse only the owned live view proved in this invocation and
                // bound above to every reread FS and extentref key/value byte.
                else if (resolved_live == snapshot_live.end() &&
                    !(read_only ? NativeApfsReader::ValidateObservationalFileSystemRecords : NativeApfsReader::ValidateOrdinaryFileSystemRecords)(filesystem, nx, volume.superblock, store.ReadBudget(), error))
                { failed(error, VerificationCode::NamespaceOrLinkInconsistent); return; }
                if (!store.ReadBudget()->Materialize(0, volume_physical.size() * (sizeof(OwnedExtent) + sizeof(ApplePhysicalExtentRecord))))
                { failed(store.ReadBudget()->Failure(), VerificationCode::BudgetExceeded); return; }
                for (const auto& extent : volume_physical) owned.push_back({extent, volume.superblock.object_id});
                physical.insert(physical.end(), volume_physical.begin(), volume_physical.end());
                if (volume.superblock.object_id == exact.volume_oid)
                { selected_records = filesystem.size(); selected_extents = volume_physical.size(); }
            }
            for (const auto check : {VerificationCheck::MetadataTreeWalk, VerificationCheck::LeafKeyOrder,
                VerificationCheck::InternalSeparatorRouting, VerificationCheck::PayloadReferences, VerificationCheck::NamespaceLinksAndStreams})
                Coverage(report, check).state = VerificationCheckState::Verified;
            active = VerificationCheck::CrossVolumePayloadOwnership;
            affected_object.reset(); affected_block.reset();
            std::sort(owned.begin(), owned.end(), [](const auto& a, const auto& b) {
                return std::tie(a.extent.physical_block, a.volume_oid) < std::tie(b.extent.physical_block, b.volume_oid);
            });
            for (std::size_t i = 1; i < owned.size(); ++i)
                if (owned[i].extent.physical_block < owned[i-1].extent.physical_block + owned[i-1].extent.block_count)
                {
                    affected_volume = owned[i].volume_oid; affected_block = owned[i].extent.physical_block;
                    fail(VerificationCode::CrossVolumePayloadOverlap, "VerifierCrossVolumePayloadOverlap:otherVolumeOid=" +
                        std::to_string(owned[i-1].volume_oid)); return;
                }
            Coverage(report, active).state = VerificationCheckState::Verified;
            active = VerificationCheck::CurrentOwnershipCensus;
            VerificationCode owner_code = VerificationCode::StructuralInconsistency;
            if (deadline_failed()) return;
            if (!CheckCurrentOwners(store, *checkpoint, current_owners, physical,
                affected_volume, affected_object, affected_block, owner_code, error))
            { failed(error, owner_code); return; }
            for (const auto& volume : checkpoint->volumes)
            {
                if (deadline_failed()) return;
                std::uint64_t count = 0, end = 0;
                for (const auto& owner : current_owners)
                    if (owner.volume == volume.superblock.object_id)
                    {
                        const auto start = (std::max)(owner.begin, end);
                        if (owner.end > start) count += owner.end - start;
                        end = owner.end;
                    }
                for (const auto& extent : owned)
                    if (extent.volume_oid == volume.superblock.object_id) count += extent.extent.block_count;
                if (!read_only && volume.superblock.space.allocated_block_count < count)
                {
                    affected_volume = volume.superblock.object_id;
                    fail(VerificationCode::AllocatedCountUnderstated, "VerifierAllocatedCountBelowCurrentOwnership:reachable=" +
                        std::to_string(count) + ":declared=" + std::to_string(volume.superblock.space.allocated_block_count)); return;
                }
            }
            Coverage(report, active).state = VerificationCheckState::Verified;
            active = VerificationCheck::MetadataAllocatorOwnership;
            affected_volume.reset();
            if (!CheckMetadataAllocation(store, *checkpoint, metadata_blocks, affected_block, error))
            { failed(error, VerificationCode::MetadataAllocationInconsistent); return; }
            Coverage(report, active).state = VerificationCheckState::Verified;
            active = VerificationCheck::PayloadAllocatorOwnership;
            // The canonical retained census checks every peer's resolved live
            // payload against selected allocator/metadata/reserved ranges and
            // rechecks allocator currency. Its live raw records are bound above.
            // The ordinary helper intentionally rejects snapshots, so retain it
            // only on the snapshot-free path, never as a signed-layer parser.
            if (!(has_snapshots ? snapshot_ownership_verified :
                ValidateAppleCheckpointPayloadOwnership(store, *checkpoint, physical, error)))
            { failed(error, VerificationCode::PayloadAllocationInconsistent); return; }
            Coverage(report, active).state = VerificationCheckState::Verified;
            VerificationAllocationCensus census;
            active = VerificationCheck::CurrentOwnershipCensus;
            if (!ObserveAllocationCensus(store, *checkpoint, current_owners, physical, census, work_allowed, error))
            { failed(error, VerificationCode::StructuralInconsistency); return; }
            active = VerificationCheck::SharedSpaceAndQuota;
            ApfsSharedSpaceProjection space;
            if (!TryProjectAppleSharedSpace(*checkpoint, space, error))
            { affected_volume.reset(); failed(error, VerificationCode::QuotaOrReserveInconsistent); return; }
            for (const auto& volume : checkpoint->volumes)
                if (volume.superblock.space.quota_block_count &&
                    volume.superblock.space.allocated_block_count > volume.superblock.space.quota_block_count)
                {
                    affected_volume = volume.superblock.object_id;
                    fail(VerificationCode::QuotaOrReserveInconsistent, "VerifierAllocatedBlocksExceedQuota"); return;
                }
            Coverage(report, active).state = VerificationCheckState::Verified;
            affected_volume = exact.volume_oid;
            if (scope.observe_payload_content)
            {
                active = VerificationCheck::CurrentPayloadObservation;
                affected_object.reset(); affected_block.reset();
                if (!report.payload_projection)
                { fail(VerificationCode::StructuralInconsistency, "VerifierSelectedProjectionMissing"); return; }
                // Source-free ordinary extents are STORE-relative. The adapter
                // supplies the parent base once and inherits the exact allowance.
                report.payload_inventory = payload::ObserveCurrentPayload({*report.payload_projection,
                    store, {0, store.SizeBytes()}, store.ReadBudget(), within_deadline});
                const auto& observed = *report.payload_inventory;
                if (!observed.exactComplete())
                {
                    affected_object = observed.failedInodeOid;
                    if (observed.reason == payload::Reason::SourceReadFailure && observed.failedSourceOffset)
                    {
                        if (*observed.failedSourceOffset > UINT64_MAX - exact.store_offset_bytes)
                        { fail(VerificationCode::StructuralInconsistency, "VerifierPayloadFailureOffsetOverflow"); return; }
                        affected_failed_offset = exact.store_offset_bytes + *observed.failedSourceOffset;
                    }
                    VerificationCode code = VerificationCode::StructuralInconsistency;
                    switch (observed.reason)
                    {
                    case payload::Reason::LogicalLimit: case payload::Reason::EntryLimit:
                    case payload::Reason::SharedBudget: case payload::Reason::Deadline:
                    case payload::Reason::AllocationFailure: code = VerificationCode::BudgetExceeded; break;
                    case payload::Reason::SourceReadFailure: code = VerificationCode::ReadFailure; break;
                    case payload::Reason::UnsupportedRepresentation: case payload::Reason::HashProviderUnavailable:
                    case payload::Reason::HashProviderFailure: case payload::Reason::CallbackFailure:
                        code = VerificationCode::UnsupportedFeature; break;
                    default: break;
                    }
                    fail(code, "VerifierCurrentPayload:" + std::string(payload::Name(observed.reason)));
                    return;
                }
                Coverage(report, active).state = VerificationCheckState::Verified;
            }
            std::optional<RequestedHistoryVerification> requested_history;
            if (scope.retained_from_xid)
            {
                active = VerificationCheck::RequestedHistoryOwnership;
                affected_volume.reset(); affected_object.reset(); affected_block.reset(); affected_xid.reset();
                RequestedHistoryVerification history;
                if (!VerifyRequestedHistory(store, *checkpoint, *report.selected, *scope.retained_from_xid, history, error, read_only) ||
                    bounded->io_failed || bounded->bounds_failed || bounded->ReadBudget()->Failed())
                {
                    const auto code = HistoryFailureCode(error);
                    fail(code, error, code == VerificationCode::IdentityMismatch); return;
                }
                requested_history = std::move(history);
            }
            std::optional<VerificationRetainedOwnership> retained_ownership;
            if (scope.account_retained_ownership)
            {
                affected_volume.reset(); affected_object.reset(); affected_block.reset(); affected_xid.reset();
                VerificationRetainedOwnership ownership;
                if (!AccountRetainedOwnership(store, *checkpoint, current_owners, work_allowed, ownership,
                    active, affected_block, affected_xid, error, read_only))
                {
                    fail(error == "VerifierRetainedPayloadMetadataConflict" ? VerificationCode::RetainedOwnershipConflict
                        : HistoryFailureCode(error), error); return;
                }
                Coverage(report, VerificationCheck::HistoricalReachability).state = VerificationCheckState::Verified;
                census = {};
                if (!ObserveAllocationCensus(store, *checkpoint, current_owners, physical, census,
                    work_allowed, error, &ownership))
                { failed(error, VerificationCode::StructuralInconsistency); return; }
                if (census.unattributed_main_blocks || census.unattributed_internal_blocks)
                {
                    affected_block = census.unattributed_main_ranges.empty()
                        ? census.unattributed_internal_ranges.front().physical_block
                        : census.unattributed_main_ranges.front().physical_block;
                    fail(VerificationCode::OrphanAllocation, "VerifierOrphanAllocation:main=" +
                        std::to_string(census.unattributed_main_blocks) + ":internal=" +
                        std::to_string(census.unattributed_internal_blocks)); return;
                }
                if (!PartitionRetainedAllocation(store, *checkpoint, work_allowed, ownership, error))
                { failed(error, VerificationCode::StructuralInconsistency); return; }
                std::sort(snapshot_usage.begin(), snapshot_usage.end(), [](const auto& a, const auto& b) {
                    return a.volume_oid < b.volume_oid;
                });
                ownership.snapshot_payload_usage = std::move(snapshot_usage);
                retained_ownership = std::move(ownership);
                Coverage(report, VerificationCheck::CompleteAllocationAccounting).state = VerificationCheckState::Verified;
            }
            for (const auto& coverage : report.coverage)
                if (coverage.required && coverage.state != VerificationCheckState::Verified)
                {
                    if (coverage.check == VerificationCheck::RequestedHistoryOwnership && requested_history) continue;
                    active = coverage.check;
                    fail(VerificationCode::CoverageMissing, coverage.scope_detail);
                    Coverage(report, active).state = VerificationCheckState::Unproven;
                    return;
                }
            if (deadline_failed()) return;
            report.allocation_census = std::move(census);
            report.allocation_census->block_size_bytes = checkpoint->container.superblock.block_size;
            report.allocation_census->container_block_count = checkpoint->container.superblock.block_count;
            report.covered_filesystem_records = selected_records;
            report.covered_physical_extents = selected_extents;
            report.requested_history = std::move(requested_history);
            report.retained_ownership = std::move(retained_ownership);
            if (report.requested_history)
                Coverage(report, VerificationCheck::RequestedHistoryOwnership).state = VerificationCheckState::Verified;
            report.outcome = VerificationOutcome::Complete;
        };
        run();
    }
    catch (const std::bad_alloc&) { fail(VerificationCode::BudgetExceeded, "VerifierAllocationFailed"); }
    catch (const std::length_error&) { fail(VerificationCode::BudgetExceeded, "VerifierAllocationFailed"); }
    if (scope.retained_from_xid && report.outcome != VerificationOutcome::Complete)
    {
        report.requested_history.reset(); report.allocation_census.reset();
        report.covered_filesystem_records = 0; report.covered_physical_extents = 0;
    }
    if (bounded) { report.source_reads = bounded->reads; report.source_read_bytes = bounded->bytes; }
    // On admission refusal no aliases or payload backing escape as an admitted view.
    if (report.payload_inventory && report.payload_inventory->reason == payload::Reason::AdmissionNotComplete)
        report.payload_projection.reset();
    Finish(report);
    return report;
}

VerificationReport ApfsVerifier::Verify(const RandomAccessSource& source, const VerificationScope& scope,
    const std::function<bool()>& within_deadline)
{
    return VerifyWithAdmission(source, scope, within_deadline, false);
}

VerificationReport ApfsVerifier::VerifyReadOnly(const RandomAccessSource& source, const VerificationScope& scope)
{
    return VerifyReadOnly(source, scope, [] { return true; });
}

VerificationReport ApfsVerifier::VerifyReadOnly(const RandomAccessSource& source, const VerificationScope& scope,
    const std::function<bool()>& within_deadline)
{
    return VerifyWithAdmission(source, scope, within_deadline, true);
}

CurrentProfileVerificationReport ApfsVerifier::VerifyEncryptedCurrent(const ApfsVerifierEncryptedSource& source,
    ApfsEncryptedReadSession& session, const VerificationScope& scope, const std::function<bool()>& within_deadline)
{
    CurrentProfileVerificationReport out;
    out.profile = CurrentVerificationProfile::EncryptedOneKeyGenerationZero;
    out.requested_scope = scope; out.read_budget = source.ReadBudget();
    auto active = VerificationCheck::ExactSelection;
    std::optional<std::uint64_t> block;
    const auto add = [&](VerificationCheck check, const char* detail) {
        out.coverage.push_back({check, true, true, VerificationCheckState::Unproven, detail});
    };
    add(active, "Exact original cumulative source, container-relative window, single selected volume and current checkpoint");
    add(VerificationCheck::Crypto, "Session-minted current software ONEKEY generation-zero metadata decryption; no key export or authenticated file-content claim");
    add(VerificationCheck::OrdinaryFeatures, "Canonical admitted ONEKEY current profile, without snapshots, rolling state or separate extent trees");
    add(VerificationCheck::SpacemanGraph, "Canonical complete current single-store allocator graph");
    add(VerificationCheck::MetadataTreeWalk, "Canonical complete encrypted FS walk plus all current plain OMAP/extentref/empty snapshot trees");
    add(VerificationCheck::LeafKeyOrder, "Canonical complete record order and duplicate checks on fresh current trees");
    add(VerificationCheck::NamespaceLinksAndStreams, "Source-bound canonical encrypted session namespace, links, supported file/xattr streams");
    add(VerificationCheck::PayloadReferences, "Canonical generation-zero encrypted extent codec and complete current NEW reference multiplicity");
    add(VerificationCheck::MetadataAllocatorOwnership, "All completed canonical FS metadata-read dependency blocks and plain current metadata allocated and nonqueued");
    add(VerificationCheck::PayloadAllocatorOwnership, "Current payload allocated, nonqueued and separate from all current metadata dependencies/reservations");
    add(VerificationCheck::InternalSeparatorRouting, "Canonical context binds the APSB name-policy comparator; complete internal separator minima and exclusive upper ranges");
    out.coverage.push_back({VerificationCheck::HistoricalReachability, false, false, VerificationCheckState::NotRequested,
        "Historical keybag eras, retained/snapshot closure and exhaustive allocated-bit/orphan accounting are outside this current profile"});
    const auto fail = [&](VerificationCode code, std::string detail, bool refused = false) {
        if (out.read_budget && out.read_budget->Failed())
        { code = VerificationCode::BudgetExceeded; detail = out.read_budget->Failure(); refused = false; }
        out.outcome = refused ? VerificationOutcome::Refused : VerificationOutcome::Incomplete;
        for (auto& row : out.coverage) if (row.check == active)
            row.state = refused ? VerificationCheckState::Unsupported : VerificationCheckState::Inconsistent;
        out.findings.push_back({code, refused ? VerificationSeverity::Warning : VerificationSeverity::Error,
            active, scope.exact.volume_oid, {}, block, scope.exact.checkpoint_xid, {}, std::move(detail)});
    };
    const auto failed = [&](const std::string& error, VerificationCode fallback) {
        // Context binding/lifecycle/integrity failures are failures of the
        // admitted operation, not unsupported encryption feature promotion.
        auto code = Classify(error, fallback);
        if (Contains(error, "OriginalSourceMismatch") || Contains(error, "SelectionBindingMismatch") ||
            Contains(error, "GeometryOrCheckpointMismatch") || Contains(error, "SourceBindingMismatch"))
        { fail(VerificationCode::IdentityMismatch, error, true); return; }
        if (code == VerificationCode::CryptoUnsupported && error.find("Unsupported") == std::string::npos) code = fallback;
        fail(code, error, code == VerificationCode::UnsupportedFeature || code == VerificationCode::CryptoUnsupported);
    };
    const auto before = out.read_budget->Consumed();
    struct Records
    {
        std::vector<BtreeRecord> values;
        ~Records() { for (auto& r : values) { SecureZeroMemory(r.key.data(), r.key.size()); SecureZeroMemory(r.value.data(), r.value.size()); } }
    };
    const auto check_encrypted_order = [&](const std::vector<BtreeRecord>& records,
        AppleBtreeKeyOrder order, std::string& error) {
        Records sorted;
        for (const auto& r : records)
        {
            if (!out.read_budget->Materialize(1, 2 * sizeof(BtreeRecord) + r.key.size() + r.value.size()))
            { error = out.read_budget->Failure(); return false; }
            // Guard each half-built deep copy as well as the completed vector.
            Records one; one.values.emplace_back();
            one.values.front().key = r.key; one.values.front().value = r.value;
            sorted.values.push_back(std::move(one.values.front()));
        }
        if (!SortAppleBtreeRecords(sorted.values, order, error)) return false;
        for (std::size_t i = 0; i < records.size(); ++i)
            if (records[i].key != sorted.values[i].key)
            { error = "VerifierEncryptedLeafKeyOrderInconsistent"; return false; }
        return true;
    };
    try
    {
        const auto run = [&] {
            const auto& exact = scope.exact;
            if (scope.source_identity.empty() || scope.source_identity.size() > 1024 || !UuidValid(exact.container_uuid_hex) ||
                !UuidValid(exact.volume_uuid_hex) || !exact.volume_oid || !exact.checkpoint_xid ||
                exact.store_offset_bytes || exact.store_size_bytes != source.SizeBytes() || !within_deadline ||
                !scope.max_reads || !scope.max_read_bytes || !scope.max_records || !scope.max_record_bytes ||
                scope.require_whole_volume || scope.require_payload_content_hashes || scope.observe_payload_content ||
                scope.account_retained_ownership || scope.retained_from_xid)
            { fail(VerificationCode::InvalidScope, "VerifierEncryptedCurrentScopeInvalid", true); return; }
            if (scope.source_identity != source.SourceIdentity())
            { fail(VerificationCode::IdentityMismatch, "VerifierEncryptedSourceIdentityMismatch", true); return; }
            out.read_budget->LimitRemainingTo(scope.max_reads, scope.max_read_bytes, scope.max_records, scope.max_record_bytes);
            const auto allowed = [&] {
                if (!source.CheckDeadline()) return false;
                try { if (within_deadline()) return true; }
                catch (...) { return out.read_budget->Refuse("VerifierEncryptedDeadlineCallbackFailed"); }
                return out.read_budget->Refuse("VerifierEncryptedDeadlineExceeded");
            };
            if (!allowed()) { fail(VerificationCode::BudgetExceeded, out.read_budget->Failure()); return; }
            active = VerificationCheck::Crypto;
            EncryptedReadError read_error;
            auto context = session.CreateMetadataReadContext(read_error);
            if (!context) { fail(VerificationCode::ReadFailure, "VerifierEncryptedContextUnavailable:" + std::to_string(static_cast<unsigned>(read_error))); return; }
            std::string error;
            auto cp = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error, *context, exact.checkpoint_xid);
            if (!cp) { failed(error, VerificationCode::StructuralInconsistency); return; }
            const auto& nx = cp->container.superblock;
            active = VerificationCheck::ExactSelection;
            if (nx.uuid_hex != exact.container_uuid_hex || nx.xid != exact.checkpoint_xid || cp->volumes.size() != 1 ||
                cp->volumes.front().superblock.object_id != exact.volume_oid || cp->volumes.front().superblock.uuid_hex != exact.volume_uuid_hex)
            { fail(VerificationCode::IdentityMismatch, "VerifierEncryptedCurrentSelectionMismatch", true); return; }
            const auto& v = cp->volumes.front();
            out.selected = VerifiedCheckpointIdentity{exact, cp->container.superblock_physical_block,
                v.superblock_object.physical_block, v.superblock.xid, v.root_tree.object_id, v.root_tree.physical_block};
            out.stores.push_back({scope.source_identity, 0, source.SizeBytes()});
            active = VerificationCheck::OrdinaryFeatures;
            std::vector<std::byte> apsb;
            if (!source.Read(v.superblock_object.physical_block * nx.block_size, nx.block_size, apsb))
            { fail(VerificationCode::ReadFailure, "VerifierEncryptedApsbReadFailure"); return; }
            if ((nx.features & ~kNxKnownOptionalFeaturesMask) || nx.readonly_features ||
                (nx.incompatible_features & ~kNxSupportedIncompatibleFeaturesMask) || v.superblock.fs_flags != kFsFlagOneKey ||
                (v.superblock.features & ~kVolumeKnownOptionalFeaturesMask) || v.superblock.readonly_features ||
                (v.superblock.incompatible_features & ~kVolumeSupportedIncompatibleFeaturesMask) || !v.extentref_tree ||
                v.object_map.snapshot_tree_oid || cp->container_object_map.snapshot_tree_oid ||
                ReadU64LE(apsb, 0xD8).value_or(~0ull) || ReadU64LE(apsb, 0xA0).value_or(~0ull) ||
                ReadU64LE(apsb, 0xA8).value_or(~0ull) || ReadU64LE(apsb, 0x3D0).value_or(~0ull) ||
                ReadU64LE(apsb, 0x3E8).value_or(~0ull) || !CheckAppleReadOnlyOneKeyInactiveTreeDefaults(apsb, v.superblock, error))
            { fail(VerificationCode::CryptoUnsupported, "VerifierEncryptedCurrentProfileUnsupported:" + error, true); return; }
            Records fs, refs;
            std::vector<std::uint64_t> metadata;
            active = VerificationCheck::MetadataTreeWalk;
            if (!source.BeginMetadataReads(nx.block_size)) { fail(VerificationCode::BudgetExceeded, out.read_budget->Failure()); return; }
            bool read = false;
            try { read = ReadAppleVolumeFileSystemRecords(source, cp->container, v, fs.values, error, *context); }
            catch (...) { source.EndMetadataReads(metadata); throw; }
            source.EndMetadataReads(metadata);
            if (!read) { failed(error, VerificationCode::StructuralInconsistency); return; }
            if (metadata.empty()) { fail(VerificationCode::CoverageMissing, "VerifierEncryptedCanonicalReadFootprintMissing"); return; }
            active = VerificationCheck::Crypto;
            UnlockError keybag_error;
            std::uint64_t container_bag_block = 0, volume_bag_block = 0;
            const auto bags = InspectPasswordKeybagMetadataAtCheckpoint(source, exact.volume_oid,
                KeybagLength::IncludesHeader, nx.xid, keybag_error, container_bag_block, volume_bag_block);
            if (!bags || bags->selection.checkpoint_xid != nx.xid || bags->selection.volume_oid != exact.volume_oid)
            { fail(VerificationCode::StructuralInconsistency, "VerifierEncryptedCurrentKeybagMetadataInvalid:" + std::to_string(static_cast<unsigned>(keybag_error))); return; }
            if (!out.read_budget->Materialize(2, 2 * sizeof(std::uint64_t))) { fail(VerificationCode::BudgetExceeded, out.read_budget->Failure()); return; }
            metadata.push_back(container_bag_block); metadata.push_back(volume_bag_block);
            const auto order = ApfsNamePolicy::FromIncompatibleFeatures(v.superblock.incompatible_features).UsesHashedDirectoryKeys()
                ? AppleBtreeKeyOrder::FileSystemHashedDirectory : AppleBtreeKeyOrder::FileSystemCaseSensitive;
            active = VerificationCheck::LeafKeyOrder;
            if (!check_encrypted_order(fs.values, order, error)) { failed(error, VerificationCode::TreeOrderInconsistent); return; }
            const auto tree = [&](const AppleObjectLocation& root, AppleBtreeKeyOrder key_order, std::vector<BtreeRecord>& records) {
                std::vector<std::uint64_t> visited;
                if (!ReadTree(source, *cp, v, root, records, key_order, visited, error) || !CheckOrder(source, records, key_order, error)) return false;
                if (!out.read_budget->Materialize(visited.size(), visited.size() * sizeof(std::uint64_t))) { error = out.read_budget->Failure(); return false; }
                metadata.insert(metadata.end(), visited.begin(), visited.end()); return true;
            };
            if (!tree(*v.extentref_tree, AppleBtreeKeyOrder::PhysicalExtent, refs.values)) { failed(error, VerificationCode::StructuralInconsistency); return; }
            for (const auto* map : std::array<const AppleOmapView*, 2>{&cp->container_object_map, &v.object_map})
            {
                Records records;
                if (!tree(map->tree, AppleBtreeKeyOrder::ObjectMap, records.values)) { failed(error, VerificationCode::StructuralInconsistency); return; }
            }
            if (v.snapshot_metadata_tree)
            {
                Records records;
                if (!tree(*v.snapshot_metadata_tree, AppleBtreeKeyOrder::Lexicographic, records.values)) { failed(error, VerificationCode::StructuralInconsistency); return; }
                if (!records.values.empty()) { fail(VerificationCode::UnsupportedFeature, "VerifierEncryptedSnapshotsUnsupported", true); return; }
            }
            active = VerificationCheck::NamespaceLinksAndStreams;
            EncryptedNamespaceInfo names;
            if (session.GetNamespaceInfo(names) != EncryptedReadError::None || !names.root_inode_id)
            { fail(VerificationCode::UnsupportedFeature, "VerifierEncryptedNamespaceUnavailable", true); return; }
            active = VerificationCheck::PayloadReferences;
            std::vector<ApplePhysicalExtentRecord> physical;
            if (!ValidateAppleEncryptedPayloadExtentGraph(fs.values, refs.values, nx.block_size, nx.block_count, physical, error))
            { failed(error, VerificationCode::ExtentReferenceInconsistent); return; }
            active = VerificationCheck::MetadataAllocatorOwnership;
            if (!CheckMetadataAllocation(source, *cp, metadata, block, error)) { failed(error, VerificationCode::MetadataAllocationInconsistent); return; }
            active = VerificationCheck::PayloadAllocatorOwnership;
            const auto& pool = cp->spaceman.internal_pool;
            for (const auto& e : physical)
            {
                block = e.physical_block;
                const auto end = e.physical_block + e.block_count;
                const auto hit = [&](std::uint64_t first, std::uint64_t count) { return count && first < end && e.physical_block < first + count; };
                const auto m = std::lower_bound(metadata.begin(), metadata.end(), e.physical_block);
                if ((m != metadata.end() && *m < end) || hit(0, 1) || hit(nx.xp_desc_base_block, nx.xp_desc_block_count) ||
                    hit(nx.xp_data_base_block, nx.xp_data_block_count) || hit(pool.base_block, pool.block_count) || hit(pool.bitmap_base_block, pool.bitmap_block_count))
                { fail(VerificationCode::PayloadMetadataOverlap, "VerifierEncryptedPayloadMetadataOverlap"); return; }
                for (const auto& queue : cp->spaceman.free_queues)
                {
                    if (!out.read_budget->Materialize(queue.entries.size(), 0)) { fail(VerificationCode::BudgetExceeded, out.read_budget->Failure()); return; }
                    for (const auto& entry : queue.entries)
                        if (hit(entry.physical_block, entry.block_count)) { fail(VerificationCode::PayloadAllocationInconsistent, "VerifierEncryptedPayloadQueued"); return; }
                }
                for (auto cursor = e.physical_block; cursor < end;)
                {
                    if (!allowed() || !out.read_budget->Materialize(1, 0)) { fail(VerificationCode::BudgetExceeded, out.read_budget->Failure()); return; }
                    const auto c = std::find_if(cp->spaceman.chunks.begin(), cp->spaceman.chunks.end(), [&](const auto& item) {
                        return item.device_index == 0 && cursor >= item.start_block && cursor - item.start_block < item.block_count;
                    });
                    if (c == cp->spaceman.chunks.end()) { fail(VerificationCode::PayloadAllocationInconsistent, "VerifierEncryptedPayloadChunkMissing"); return; }
                    const auto stop = (std::min)(end, c->start_block + c->block_count);
                    if (!out.read_budget->Materialize(stop - cursor, 0)) { fail(VerificationCode::BudgetExceeded, out.read_budget->Failure()); return; }
                    for (; cursor < stop; ++cursor)
                    {
                        const auto bit = cursor - c->start_block;
                        if (bit / 8 >= c->allocation_bitmap.size() || !(std::to_integer<unsigned>(c->allocation_bitmap[bit / 8]) & (1u << (bit % 8))))
                        { block = cursor; fail(VerificationCode::PayloadAllocationInconsistent, "VerifierEncryptedPayloadNotAllocated"); return; }
                        if ((bit & 4095) == 0 && !allowed()) { fail(VerificationCode::BudgetExceeded, out.read_budget->Failure()); return; }
                    }
                }
            }
            // Re-enter the same revocable canonical context before publication.
            Records rechecked;
            if (!ReadAppleVolumeFileSystemRecords(source, cp->container, v, rechecked.values, error, *context) || !allowed())
            { failed(error, VerificationCode::ReadFailure); return; }
            if (fs.values.size() != rechecked.values.size() || !std::equal(fs.values.begin(), fs.values.end(), rechecked.values.begin(),
                [](const auto& a, const auto& b) { return a.key == b.key && a.value == b.value; }))
            { fail(VerificationCode::StructuralInconsistency, "VerifierEncryptedCurrentRecordsChanged"); return; }
            for (auto& row : out.coverage) if (row.required) row.state = VerificationCheckState::Verified;
            out.allocation_unit_bytes = nx.block_size;
            out.covered_volume_count = 1; out.covered_filesystem_records = fs.values.size();
            out.covered_physical_extents = physical.size(); out.current_metadata_blocks = metadata.size();
            out.outcome = VerificationOutcome::Complete;
        };
        run();
    }
    catch (const std::bad_alloc&) { fail(VerificationCode::BudgetExceeded, "VerifierEncryptedAllocationFailed"); }
    catch (const std::length_error&) { fail(VerificationCode::BudgetExceeded, "VerifierEncryptedAllocationFailed"); }
    catch (...) { fail(VerificationCode::ReadFailure, "VerifierEncryptedContextCallbackFailed"); }
    const auto after = out.read_budget->Consumed();
    out.source_reads = after.reads - before.reads; out.source_read_bytes = after.read_bytes - before.read_bytes;
    return out;
}

namespace
{
CurrentProfileVerificationReport VerifyFusionCheckpointGraph(const ApfsFusionStore& source,
    const VerificationScope& scope, const std::array<std::string, 2>& member_store_ids,
    const std::function<bool()>& within_deadline, const ContainerCheckpointView* retained = nullptr,
    RetainedProfileCheckpointGraph* graph = nullptr)
{
    CurrentProfileVerificationReport out;
    out.requested_scope = scope;
    out.read_budget = source.ReadBudget();
    auto active = VerificationCheck::ExactSelection;
    std::optional<std::uint64_t> volume, object, block;
    const auto add = [&](VerificationCheck check, const char* detail) {
        out.coverage.push_back({check, true, true, VerificationCheckState::Unproven, detail});
    };
    add(active, "Exact held main/tier2 member IDs, windows, container, volume and current checkpoint");
    add(VerificationCheck::Fusion, "Canonical clean-cache paired-store binding, both member leases rechecked");
    add(VerificationCheck::OrdinaryFeatures, "All current peer volumes: canonical supported unencrypted Fusion feature profile");
    add(VerificationCheck::SpacemanGraph, "Canonical device-indexed CIB/CAB/chunk bitmaps, internal pool and all three free queues");
    add(VerificationCheck::MetadataTreeWalk, "All current peer APSB/OMAP/FS/extentref trees; no snapshot or hidden historical graph claim");
    add(VerificationCheck::LeafKeyOrder, "Canonical comparator order and duplicate rejection for every walked current tree");
    add(VerificationCheck::InternalSeparatorRouting, "Canonical complete traversal with exact separator and exclusive upper-range checks");
    add(VerificationCheck::NamespaceLinksAndStreams, "Canonical Fusion namespace, links, file/xattr streams and exact member extent routing");
    add(VerificationCheck::PayloadReferences, "Complete canonical current NEW physical extent/reference multiplicity for every peer");
    add(VerificationCheck::MetadataAllocatorOwnership, "Every current object/tree node allocated in its canonical device/internal pool and not retired");
    add(VerificationCheck::PayloadAllocatorOwnership, "Every payload block allocated in its exact member, outside reserved areas and retirement queues");
    add(VerificationCheck::CrossVolumePayloadOwnership, "Current peer payload disjointness and metadata/payload separation");
    out.coverage.push_back({VerificationCheck::HistoricalReachability, false, false, VerificationCheckState::NotRequested,
        "Retained checkpoints, hidden historical versions and exhaustive allocated-bit/orphan accounting are outside this current profile"});
    const auto verified = [&](VerificationCheck check) {
        for (auto& row : out.coverage) if (row.check == check) row.state = VerificationCheckState::Verified;
    };
    const auto fail = [&](VerificationCode code, std::string detail, bool refused = false) {
        if (out.read_budget && out.read_budget->Failed())
        { code = VerificationCode::BudgetExceeded; detail = out.read_budget->Failure(); refused = false; }
        out.outcome = refused ? VerificationOutcome::Refused : VerificationOutcome::Incomplete;
        for (auto& row : out.coverage) if (row.check == active)
            row.state = refused ? VerificationCheckState::Unsupported : VerificationCheckState::Inconsistent;
        out.findings.push_back({code, refused ? VerificationSeverity::Warning : VerificationSeverity::Error,
            active, volume, object, block, scope.exact.checkpoint_xid, {}, std::move(detail)});
    };
    const auto failed = [&](const std::string& error, VerificationCode fallback) {
        const auto code = Classify(error, fallback);
        fail(code, error, code == VerificationCode::UnsupportedFeature || code == VerificationCode::FusionUnsupported ||
            code == VerificationCode::CryptoUnsupported);
    };
    const auto before = out.read_budget ? out.read_budget->Consumed() : ApfsReadBudget::Consumption{};
    try
    {
        const auto run = [&] {
            const auto& exact = scope.exact;
            if (!out.read_budget || scope.source_identity.empty() || scope.source_identity.size() > 1024 ||
                !UuidValid(exact.container_uuid_hex) || !UuidValid(exact.volume_uuid_hex) || !exact.volume_oid ||
                !exact.checkpoint_xid || !within_deadline || !scope.max_reads || !scope.max_read_bytes ||
                !scope.max_records || !scope.max_record_bytes || scope.require_whole_volume ||
                scope.require_payload_content_hashes || scope.observe_payload_content ||
                scope.account_retained_ownership || scope.retained_from_xid)
            { fail(VerificationCode::InvalidScope, "VerifierFusionCurrentScopeInvalid", true); return; }
            out.read_budget->LimitRemainingTo(scope.max_reads, scope.max_read_bytes, scope.max_records, scope.max_record_bytes);
            VerificationSource bounded(source, scope, within_deadline);
            SnapshotPlanningSource observed(bounded);
            std::string error;
            if (!bounded.WithinDeadline()) { fail(VerificationCode::BudgetExceeded, out.read_budget->Failure()); return; }
            if (!source.CheckAvailable(error)) { fail(VerificationCode::ReadFailure, error); return; }
            const auto& container = retained ? *retained : source.Checkpoint();
            const auto& nx = container.superblock;
            const auto& main = source.Binding(FusionMemberRole::Main);
            if (nx.uuid_hex != exact.container_uuid_hex || nx.xid != exact.checkpoint_xid ||
                exact.store_offset_bytes != main.store_offset || exact.store_size_bytes != main.store_size ||
                member_store_ids[0] != source.Members()[0].stable_store_id ||
                member_store_ids[1] != source.Members()[1].stable_store_id)
            { fail(VerificationCode::IdentityMismatch, "VerifierFusionExactBindingMismatch", true); return; }
            for (const auto role : {FusionMemberRole::Main, FusionMemberRole::Tier2})
            {
                const auto& binding = source.Binding(role);
                out.stores.push_back({binding.stable_store_id, binding.store_offset, binding.store_size});
            }
            verified(VerificationCheck::Fusion);
            if (retained)
            {
                auto exact_retained = LoadContainerCheckpointView(observed, 0, source.CapacityBytes(), error, nx.xid);
                if (!exact_retained || exact_retained->superblock_bytes != container.superblock_bytes)
                { failed(error.empty() ? "VerifierFusionRetainedCheckpointChanged" : error, VerificationCode::StructuralInconsistency); return; }
            }
            auto read = LoadAppleReadOnlyVolumeView(observed, container, error);
            if (!read) { failed(error, VerificationCode::StructuralInconsistency); return; }
            AppleCheckpointView cp;
            cp.container = std::move(read->container); cp.container_object_map = std::move(read->container_object_map);
            cp.volumes = std::move(read->volumes);
            const auto selected = std::find_if(cp.volumes.begin(), cp.volumes.end(), [&](const auto& v) {
                return v.superblock.object_id == exact.volume_oid && v.superblock.uuid_hex == exact.volume_uuid_hex;
            });
            if (selected == cp.volumes.end() || std::count_if(cp.volumes.begin(), cp.volumes.end(), [&](const auto& v) {
                    return v.superblock.uuid_hex == exact.volume_uuid_hex; }) != 1)
            { fail(VerificationCode::IdentityMismatch, "VerifierFusionSelectedVolumeMismatch", true); return; }
            out.selected = VerifiedCheckpointIdentity{exact, cp.container.superblock_physical_block,
                selected->superblock_object.physical_block, selected->superblock.xid,
                selected->root_tree.object_id, selected->root_tree.physical_block};
            verified(active);
            active = VerificationCheck::SpacemanGraph;
            if (!(retained ? LoadFusionPlanningAllocation(source, observed, cp.container, cp.spaceman, error) :
                LoadFusionSpacemanAllocationView(source, cp.spaceman, error)))
            { failed(error, VerificationCode::SpacemanInconsistent); return; }
            verified(active);
            const auto tier = kFusionTier2ByteAddress / nx.block_size;
            const auto reserved = [&](std::uint64_t begin, std::uint64_t count) {
                const auto hit = [&](std::uint64_t first, std::uint64_t length) {
                    return length && first < begin + count && begin < first + length;
                };
                const auto& ip = cp.spaceman.internal_pool;
                return hit(0, 1) || hit(tier, 1) || hit(nx.xp_desc_base_block, nx.xp_desc_block_count) ||
                    hit(nx.xp_data_base_block, nx.xp_data_block_count) || hit(nx.fusion_middle_tree_oid, 1) ||
                    hit(nx.fusion_writeback_start, nx.fusion_writeback_blocks) ||
                    hit(ip.base_block, ip.block_count) || hit(ip.bitmap_base_block, ip.bitmap_block_count);
            };
            const auto owned = [&](std::uint64_t first, std::uint64_t count) {
                block = first;
                FusionRoute route;
                if (!count || count > UINT64_MAX / nx.block_size ||
                    !source.MapPhysical(first, 0, count * nx.block_size, route, error)) return false;
                for (const auto& queue : cp.spaceman.free_queues)
                {
                    if (!out.read_budget->Materialize(queue.entries.size(), 0)) { error = out.read_budget->Failure(); return false; }
                    for (const auto& e : queue.entries)
                        if (e.physical_block < first + count && first < e.physical_block + e.block_count)
                        { error = "VerifierFusionOwnerQueued"; return false; }
                }
                const auto device = route.role == FusionMemberRole::Tier2 ? 1u : 0u;
                auto cursor = first - (device ? tier : 0);
                const auto end = cursor + count;
                while (cursor < end)
                {
                    if (!bounded.WithinDeadline() || !out.read_budget->Materialize(1, 0))
                    { error = out.read_budget->Failure(); return false; }
                    const auto found = std::find_if(cp.spaceman.chunks.begin(), cp.spaceman.chunks.end(), [&](const auto& c) {
                        return c.device_index == device && cursor >= c.start_block && cursor - c.start_block < c.block_count;
                    });
                    if (found == cp.spaceman.chunks.end()) { error = "VerifierFusionOwnerChunkMissing"; return false; }
                    const auto stop = (std::min)(end, found->start_block + found->block_count);
                    if (!out.read_budget->Materialize(stop - cursor, 0)) { error = out.read_budget->Failure(); return false; }
                    for (; cursor < stop; ++cursor)
                    {
                        const auto bit = cursor - found->start_block;
                        if (bit / 8 >= found->allocation_bitmap.size() ||
                            !(std::to_integer<unsigned>(found->allocation_bitmap[bit / 8]) & (1u << (bit % 8))))
                        { block = cursor + (device ? tier : 0); error = "VerifierFusionOwnerNotAllocated"; return false; }
                        if ((bit & 4095) == 0 && !bounded.WithinDeadline()) { error = out.read_budget->Failure(); return false; }
                    }
                }
                return true;
            };
            std::set<std::uint64_t> metadata;
            std::vector<ApplePhysicalExtentRecord> payload;
            const auto meta = [&](std::uint64_t b) {
                active = VerificationCheck::MetadataAllocatorOwnership;
                if (!out.read_budget->Materialize(1, sizeof(std::uint64_t) + 64)) { error = out.read_budget->Failure(); return false; }
                if (!metadata.insert(b).second) { block = b; error = "VerifierFusionMetadataOwnerAlias"; return false; }
                if (reserved(b, 1)) { block = b; error = "VerifierFusionMetadataReservedCollision"; return false; }
                return owned(b, 1);
            };
            const auto tree = [&](const AppleVolumeCheckpointView& v, const AppleObjectLocation& root, AppleBtreeKeyOrder order,
                std::vector<BtreeRecord>& records) {
                active = VerificationCheck::MetadataTreeWalk; object = root.object_id; block = root.physical_block;
                std::vector<std::uint64_t> visited;
                if (!ReadTree(observed, cp, v, root, records, order, visited, error) || !CheckOrder(observed, records, order, error)) return false;
                for (const auto b : visited) if (!meta(b)) return false;
                return true;
            };
            const auto map = [&](const AppleVolumeCheckpointView& v, const AppleOmapView& omap, std::uint32_t flags) {
                active = VerificationCheck::MetadataTreeWalk;
                std::vector<std::byte> bytes;
                if (!observed.Read(omap.object.physical_block * nx.block_size, nx.block_size, bytes))
                { error = "VerifierFusionOmapReadFailure"; return false; }
                if (omap.flags != flags || omap.snapshot_tree_oid || ReadU32LE(bytes, 0x24).value_or(~0u) ||
                    ReadU64LE(bytes, 0x40).value_or(~0ull) || ReadU64LE(bytes, 0x48).value_or(~0ull) || ReadU64LE(bytes, 0x50).value_or(~0ull))
                { error = "VerifierFusionOmapHistoryUnsupported"; return false; }
                std::vector<BtreeRecord> records;
                return meta(omap.object.physical_block) && tree(v, omap.tree, AppleBtreeKeyOrder::ObjectMap, records);
            };
            if (!map(*selected, cp.container_object_map, 1)) { failed(error, VerificationCode::MetadataAllocationInconsistent); return; }
            std::uint64_t records_count = 0, extent_count = 0;
            for (const auto& v : cp.volumes)
            {
                volume = v.superblock.object_id; active = VerificationCheck::OrdinaryFeatures;
                if (!CheckAppleVolumeWriteFeatures(nx, v.superblock, error, true)) { failed(error, VerificationCode::UnsupportedFeature); return; }
                std::vector<std::byte> apsb;
                if (!observed.Read(v.superblock_object.physical_block * nx.block_size, nx.block_size, apsb))
                { fail(VerificationCode::ReadFailure, "VerifierFusionApsbReadFailure"); return; }
                if (!v.extentref_tree || v.snapshot_metadata_tree || v.file_extent_tree ||
                    ReadU64LE(apsb, 0xD8).value_or(~0ull) || ReadU64LE(apsb, 0xA0).value_or(~0ull) ||
                    ReadU64LE(apsb, 0xA8).value_or(~0ull) || ReadU64LE(apsb, 0x3E8).value_or(~0ull))
                { fail(VerificationCode::UnsupportedFeature, "VerifierFusionSnapshotOrVolumeStateUnsupported", true); return; }
                if (!meta(v.superblock_object.physical_block) || !map(v, v.object_map, 0))
                { failed(error, VerificationCode::MetadataAllocationInconsistent); return; }
                std::vector<BtreeRecord> fs, refs;
                const auto order = ApfsNamePolicy::FromIncompatibleFeatures(v.superblock.incompatible_features).UsesHashedDirectoryKeys()
                    ? AppleBtreeKeyOrder::FileSystemHashedDirectory : AppleBtreeKeyOrder::FileSystemCaseSensitive;
                if (!tree(v, v.root_tree, order, fs) || !tree(v, *v.extentref_tree, AppleBtreeKeyOrder::PhysicalExtent, refs))
                { failed(error, VerificationCode::StructuralInconsistency); return; }
                active = VerificationCheck::NamespaceLinksAndStreams;
                if (!ApfsFusionReadSession::ValidatePlanningRecords(source, nx, v.superblock, fs, error))
                { failed(error, VerificationCode::NamespaceOrLinkInconsistent); return; }
                active = VerificationCheck::PayloadReferences;
                std::vector<ApplePhysicalExtentRecord> extents;
                // The canonical validator uses this argument only as an address
                // bound. The encoded gap is separately rejected by MapPhysical.
                if (!ValidateApplePayloadExtentGraph(fs, refs, nx.block_size, source.SizeBytes() / nx.block_size, extents, error))
                { failed(error, VerificationCode::ExtentReferenceInconsistent); return; }
                for (const auto& e : extents)
                {
                    active = VerificationCheck::PayloadAllocatorOwnership;
                    if (reserved(e.physical_block, e.block_count) || !owned(e.physical_block, e.block_count))
                    { if (error.empty()) error = "VerifierFusionPayloadReservedCollision"; failed(error, VerificationCode::PayloadAllocationInconsistent); return; }
                    if (!out.read_budget->Materialize(1, sizeof(e))) { fail(VerificationCode::BudgetExceeded, out.read_budget->Failure()); return; }
                    payload.push_back(e);
                }
                records_count += fs.size(); extent_count += extents.size();
            }
            active = VerificationCheck::CrossVolumePayloadOwnership;
            std::sort(payload.begin(), payload.end(), [](const auto& a, const auto& b) { return a.physical_block < b.physical_block; });
            std::uint64_t end = 0;
            for (const auto& e : payload)
            {
                block = e.physical_block;
                const auto m = metadata.lower_bound(e.physical_block);
                if (e.physical_block < end)
                { fail(VerificationCode::CrossVolumePayloadOverlap, "VerifierFusionCrossVolumePayloadOverlap"); return; }
                if (m != metadata.end() && *m < e.physical_block + e.block_count)
                { fail(VerificationCode::PayloadMetadataOverlap, "VerifierFusionPayloadMetadataOverlap"); return; }
                end = e.physical_block + e.block_count;
            }
            if (!observed.VerifyUnchanged(error) || !source.CheckAvailable(error) || !bounded.WithinDeadline())
            { failed(error, VerificationCode::ReadFailure); return; }
            if (graph)
            {
                RetainedProfileCheckpointGraph result; result.checkpoint_xid = nx.xid;
                if (!out.read_budget->Materialize(metadata.size() + payload.size(),
                    (metadata.size() + payload.size()) * sizeof(VerificationBlockRange)))
                { fail(VerificationCode::BudgetExceeded, out.read_budget->Failure()); return; }
                for (const auto b : metadata) result.metadata_ranges.push_back({b, 1});
                for (const auto& e : payload) result.payload_ranges.push_back({e.physical_block, e.block_count});
                if (!NormalizeProtectedRanges(result.metadata_ranges, source.SizeBytes() / nx.block_size, error) ||
                    !NormalizeProtectedRanges(result.payload_ranges, source.SizeBytes() / nx.block_size, error))
                { failed(error, VerificationCode::StructuralInconsistency); return; }
                *graph = std::move(result);
            }
            for (auto& row : out.coverage) if (row.required) row.state = VerificationCheckState::Verified;
            out.allocation_unit_bytes = nx.block_size;
            out.covered_volume_count = cp.volumes.size(); out.covered_filesystem_records = records_count;
            out.covered_physical_extents = extent_count; out.current_metadata_blocks = metadata.size();
            out.outcome = VerificationOutcome::Complete;
        };
        run();
    }
    catch (const std::bad_alloc&) { fail(VerificationCode::BudgetExceeded, "VerifierFusionAllocationFailed"); }
    catch (const std::length_error&) { fail(VerificationCode::BudgetExceeded, "VerifierFusionAllocationFailed"); }
    if (out.read_budget)
    {
        const auto after = out.read_budget->Consumed();
        out.source_reads = after.reads - before.reads; out.source_read_bytes = after.read_bytes - before.read_bytes;
    }
    return out;
}
}

CurrentProfileVerificationReport ApfsVerifier::VerifyFusionCurrent(const ApfsFusionStore& source,
    const VerificationScope& scope, const std::array<std::string, 2>& member_store_ids,
    const std::function<bool()>& within_deadline)
{
    return VerifyFusionCheckpointGraph(source, scope, member_store_ids, within_deadline);
}

RetainedProfileHistoryReport VerifyFusionRetainedHistory(const ApfsFusionStore& source,
    const VerificationScope& scope, const std::array<std::string, 2>& members, std::uint64_t from,
    const std::function<bool()>& within_deadline)
{
    RetainedProfileHistoryReport out;
    out.endpoint_scope = scope; out.from_xid = from; out.read_budget = source.ReadBudget();
    const auto before = out.read_budget ? out.read_budget->Consumed() : ApfsReadBudget::Consumption{};
    std::optional<std::uint64_t> bad_block, bad_xid;
    const auto fail = [&](VerificationCode code, std::string error, bool refused = false) {
        if (out.read_budget && out.read_budget->Failed())
        { code = VerificationCode::BudgetExceeded; error = out.read_budget->Failure(); refused = false; }
        out.outcome = refused ? VerificationOutcome::Refused : VerificationOutcome::Incomplete;
        out.chain_xids.clear(); out.checkpoints.clear();
        out.selected.reset(); out.allocation_unit_bytes = 0; out.historical_namespace_verified.reset(); out.stores.clear();
        out.findings.push_back({code, refused ? VerificationSeverity::Warning : VerificationSeverity::Error,
            VerificationCheck::RequestedHistoryOwnership, scope.exact.volume_oid, {}, bad_block, bad_xid, {}, std::move(error)});
    };
    try
    {
        const auto run = [&] {
            if (!from || from >= scope.exact.checkpoint_xid || !out.read_budget)
            { fail(VerificationCode::InvalidScope, "VerifierFusionRetainedScopeInvalid", true); return; }
            const auto current = ApfsVerifier::VerifyFusionCurrent(source, scope, members, within_deadline);
            if (current.outcome != VerificationOutcome::Complete)
            {
                out.outcome = current.outcome; out.findings = current.findings; return;
            }
            VerificationSource bounded(source, scope, within_deadline);
            SnapshotPlanningSource observed(bounded);
            const auto& latest = source.Checkpoint().superblock;
            std::string error;
            const auto allowed = [&] { return bounded.WithinDeadline(); };
            const auto failed = [&](const std::string& detail) {
                const auto code = HistoryFailureCode(detail);
                fail(code, detail, code == VerificationCode::UnsupportedFeature ||
                    code == VerificationCode::FusionUnsupported || code == VerificationCode::CryptoUnsupported);
            };
            std::vector<std::uint64_t> xids;
            if (!EnumerateRetainedDescriptorXids(observed, latest, allowed, xids, bad_block, bad_xid, error))
            { failed(error); return; }
            const auto begin = std::lower_bound(xids.begin(), xids.end(), from);
            if (begin == xids.end() || *begin != from)
            { fail(VerificationCode::CheckpointUnavailable, "VerifierHistoryChainUnavailable"); return; }
            xids.erase(xids.begin(), begin);
            std::vector<RetainedProfileCheckpointGraph> graphs;
            std::vector<AppleRecoveryCheckpointView> continuity;
            OwnershipRanges protected_metadata, protected_payload;
            for (std::size_t i = 0; i < xids.size(); ++i)
            {
                bad_xid = xids[i]; bad_block.reset();
                if (!allowed()) { failed(out.read_budget->Failure()); return; }
                auto cp = LoadContainerCheckpointView(observed, 0, source.CapacityBytes(), error, xids[i]);
                if (!cp) { failed(error); return; }
                if ((i + 1 < xids.size() && cp->superblock.next_xid != xids[i + 1]) ||
                    (i + 1 == xids.size() && cp->superblock_bytes != source.Checkpoint().superblock_bytes))
                { fail(VerificationCode::CheckpointUnavailable, "VerifierHistoryChainUnavailable"); return; }
                auto selected_scope = scope; selected_scope.exact.checkpoint_xid = xids[i];
                RetainedProfileCheckpointGraph graph;
                auto report = VerifyFusionCheckpointGraph(source, selected_scope, members, within_deadline, &*cp, &graph);
                if (report.outcome != VerificationOutcome::Complete)
                { out.outcome = report.outcome; out.findings = std::move(report.findings); return; }
                for (const auto& r : graph.metadata_ranges)
                    if (!OwnershipAppend(observed, protected_metadata, r.physical_block, r.block_count, error)) { failed(error); return; }
                for (const auto& r : graph.payload_ranges)
                    if (!OwnershipAppend(observed, protected_payload, r.physical_block, r.block_count, error)) { failed(error); return; }
                if (!NormalizeProtectedRanges(protected_metadata, source.SizeBytes() / latest.block_size, error) ||
                    !NormalizeProtectedRanges(protected_payload, source.SizeBytes() / latest.block_size, error)) { failed(error); return; }
                AppleSpacemanView allocation;
                if (!LoadFusionPlanningAllocation(source, observed, *cp, allocation, error)) { failed(error); return; }
                if (!continuity.empty())
                {
                    const auto& a = continuity.front().checkpoint.spaceman.internal_pool;
                    const auto& b = allocation.internal_pool;
                    if (a.base_block != b.base_block || a.block_count != b.block_count || a.bitmap_base_block != b.bitmap_base_block ||
                        a.bitmap_size_blocks != b.bitmap_size_blocks || a.bitmap_block_count != b.bitmap_block_count)
                    { fail(VerificationCode::IdentityMismatch, "AppleCheckpointRetentionIdentityMismatch"); return; }
                }
                if (!out.read_budget->Materialize(1, sizeof(graph) + sizeof(AppleRecoveryCheckpointView)) ||
                    !out.read_budget->Materialize(RangeCount(graph.metadata_ranges), RangeCount(graph.metadata_ranges) * sizeof(std::uint64_t)) ||
                    !out.read_budget->Materialize(graph.payload_ranges.size(), graph.payload_ranges.size() * sizeof(ApplePhysicalExtentRecord)))
                { failed(out.read_budget->Failure()); return; }
                AppleRecoveryCheckpointView state;
                state.checkpoint.container = std::move(*cp); state.checkpoint.spaceman = std::move(allocation);
                for (const auto& r : graph.metadata_ranges)
                    for (auto b = r.physical_block; b < r.physical_block + r.block_count; ++b) state.metadata_blocks.push_back(b);
                for (const auto& r : graph.payload_ranges)
                    state.payload_extents.push_back({r.physical_block, r.block_count, kApplePhysicalExtentKindNew, 0, 0});
                continuity.push_back(std::move(state));
                graphs.push_back(std::move(graph));
            }
            for (std::size_t i = 0; i + 1 < continuity.size(); ++i)
            {
                bad_xid = continuity[i].checkpoint.container.superblock.xid;
                if (!allowed() || !VerifyProfileRecoveryContinuity(observed, continuity[i], continuity,
                    continuity.back().checkpoint, true, error))
                { failed(error); return; }
            }
            for (const auto& m : protected_metadata) for (const auto& p : protected_payload)
            {
                if (!allowed() || !out.read_budget->Materialize(1, 0)) { failed(out.read_budget->Failure()); return; }
                if (m.physical_block < p.physical_block + p.block_count && p.physical_block < m.physical_block + m.block_count)
                { bad_block = (std::max)(m.physical_block, p.physical_block); fail(VerificationCode::PayloadMetadataOverlap, "VerifierRetainedPayloadMetadataConflict"); return; }
            }
            if (!observed.VerifyUnchanged(error) || !source.CheckAvailable(error) || !allowed()) { failed(error); return; }
            out.stores = current.stores; out.chain_xids = std::move(xids); out.checkpoints = std::move(graphs);
            out.selected = current.selected; out.allocation_unit_bytes = current.allocation_unit_bytes;
            out.historical_namespace_verified = true;
            out.outcome = VerificationOutcome::Complete;
        };
        run();
    }
    catch (const std::bad_alloc&) { fail(VerificationCode::BudgetExceeded, "VerifierFusionRetainedAllocationFailed"); }
    catch (...) { fail(VerificationCode::ReadFailure, "VerifierFusionRetainedReadFailure"); }
    if (out.read_budget)
    {
        const auto after = out.read_budget->Consumed();
        out.source_reads = after.reads - before.reads; out.source_read_bytes = after.read_bytes - before.read_bytes;
    }
    return out;
}

RetainedProfileHistoryReport VerifyEncryptedRetainedHistory(const ApfsVerifierEncryptedSource& source,
    ApfsEncryptedReadSession& session, const VerificationScope& scope, std::uint64_t from,
    const std::function<bool()>& within_deadline)
{
    RetainedProfileHistoryReport out; out.profile = CurrentVerificationProfile::EncryptedOneKeyGenerationZero;
    out.endpoint_scope = scope; out.from_xid = from; out.read_budget = source.ReadBudget();
    const auto before = out.read_budget->Consumed();
    std::optional<std::uint64_t> bad_block, bad_xid;
    const auto fail = [&](VerificationCode code, std::string detail, bool refused = false) {
        if (out.read_budget->Failed()) { code = VerificationCode::BudgetExceeded; detail = out.read_budget->Failure(); refused = false; }
        out.chain_xids.clear(); out.checkpoints.clear(); out.historical_namespace_verified.reset();
        out.selected.reset(); out.allocation_unit_bytes = 0; out.stores.clear();
        out.outcome = refused ? VerificationOutcome::Refused : VerificationOutcome::Incomplete;
        out.findings.push_back({code, refused ? VerificationSeverity::Warning : VerificationSeverity::Error,
            VerificationCheck::RequestedHistoryOwnership, scope.exact.volume_oid, {}, bad_block, bad_xid, {}, std::move(detail)});
    };
    const auto failed = [&](const std::string& detail) {
        const auto code = HistoryFailureCode(detail);
        fail(code, detail, code == VerificationCode::UnsupportedFeature || code == VerificationCode::CryptoUnsupported);
    };
    struct Records
    {
        std::vector<BtreeRecord> values;
        ~Records() { for (auto& r : values) { SecureZeroMemory(r.key.data(), r.key.size()); SecureZeroMemory(r.value.data(), r.value.size()); } }
    };
    try
    {
        const auto run = [&] {
            if (!from || from >= scope.exact.checkpoint_xid)
            { fail(VerificationCode::InvalidScope, "VerifierEncryptedRetainedScopeInvalid", true); return; }
            const auto current = ApfsVerifier::VerifyEncryptedCurrent(source, session, scope, within_deadline);
            if (current.outcome != VerificationOutcome::Complete)
            { out.outcome = current.outcome; out.findings = current.findings; return; }
            const auto allowed = [&] {
                if (!source.CheckDeadline()) return false;
                try { if (within_deadline()) return true; } catch (...) { return out.read_budget->Refuse("VerifierEncryptedHistoryDeadlineCallbackFailed"); }
                return out.read_budget->Refuse("VerifierEncryptedHistoryDeadlineExceeded");
            };
            SnapshotPlanningSource observed(source);
            std::string error;
            auto latest = LoadContainerCheckpointView(observed, 0, source.SizeBytes(), error, scope.exact.checkpoint_xid);
            if (!latest) { failed(error); return; }
            std::vector<std::uint64_t> xids;
            if (!EnumerateRetainedDescriptorXids(observed, latest->superblock, allowed, xids, bad_block, bad_xid, error))
            { failed(error); return; }
            const auto begin = std::lower_bound(xids.begin(), xids.end(), from);
            if (begin == xids.end() || *begin != from)
            { fail(VerificationCode::CheckpointUnavailable, "VerifierHistoryChainUnavailable"); return; }
            xids.erase(xids.begin(), begin);
            std::vector<RetainedProfileCheckpointGraph> graphs;
            std::vector<AppleRecoveryCheckpointView> states;
            OwnershipRanges metadata_union, payload_union;
            for (std::size_t i = 0; i < xids.size(); ++i)
            {
                bad_xid = xids[i]; bad_block.reset();
                if (!allowed()) { failed(out.read_budget->Failure()); return; }
                EncryptedReadError ce;
                auto context = i + 1 == xids.size() ? session.CreateMetadataReadContext(ce) :
                    session.CreateRetainedVerificationContext(xids[i], error);
                if (!context)
                { fail(VerificationCode::CryptoUnsupported, error.empty() ? "VerifierEncryptedRetainedContextUnavailable" : error, true); return; }
                auto cp = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error, *context, xids[i]);
                if (!cp) { failed(error); return; }
                const auto& nx = cp->container.superblock;
                if (nx.uuid_hex != scope.exact.container_uuid_hex || cp->volumes.size() != 1 ||
                    cp->volumes.front().superblock.object_id != scope.exact.volume_oid ||
                    cp->volumes.front().superblock.uuid_hex != scope.exact.volume_uuid_hex ||
                    (i + 1 < xids.size() && nx.next_xid != xids[i + 1]) ||
                    (i + 1 == xids.size() && cp->container.superblock_bytes != latest->superblock_bytes))
                { fail(VerificationCode::IdentityMismatch, "VerifierEncryptedRetainedSelectionMismatch"); return; }
                const auto& v = cp->volumes.front();
                std::vector<std::byte> apsb;
                if (!observed.Read(v.superblock_object.physical_block * nx.block_size, nx.block_size, apsb))
                { fail(VerificationCode::ReadFailure, "VerifierEncryptedRetainedApsbReadFailure"); return; }
                if (!v.extentref_tree || v.object_map.snapshot_tree_oid || cp->container_object_map.snapshot_tree_oid ||
                    ReadU64LE(apsb,0xD8).value_or(~0ull) || ReadU64LE(apsb,0xA0).value_or(~0ull) ||
                    ReadU64LE(apsb,0xA8).value_or(~0ull) || ReadU64LE(apsb,0x3D0).value_or(~0ull) || ReadU64LE(apsb,0x3E8).value_or(~0ull) ||
                    !CheckAppleReadOnlyOneKeyInactiveTreeDefaults(apsb,v.superblock,error))
                { fail(VerificationCode::UnsupportedFeature, "VerifierEncryptedRetainedProfileUnsupported:"+error, true); return; }
                Records fs, refs;
                std::vector<std::uint64_t> metadata;
                if (!source.BeginMetadataReads(nx.block_size)) { failed(out.read_budget->Failure()); return; }
                bool read = false;
                try { read = ReadAppleVolumeFileSystemRecords(source,cp->container,v,fs.values,error,*context); }
                catch (...) { source.EndMetadataReads(metadata); throw; }
                source.EndMetadataReads(metadata);
                if (!read || metadata.empty()) { failed(error.empty() ? "VerifierEncryptedRetainedMetadataMissing" : error); return; }
                if (i + 1 < xids.size())
                {
                    EncryptedNamespaceInfo names;
                    const auto status = session.ValidateRetainedNamespace(*context, names, error);
                    if (status != EncryptedReadError::None)
                    {
                        const auto unsupported = status == EncryptedReadError::UnsupportedEncryptionLayout ||
                            status == EncryptedReadError::NamespaceUnavailable;
                        const auto code = unsupported ? VerificationCode::UnsupportedFeature :
                            status == EncryptedReadError::ResourceLimit ? VerificationCode::BudgetExceeded :
                            status == EncryptedReadError::SourceIdentityMismatch ? VerificationCode::IdentityMismatch :
                            status == EncryptedReadError::MetadataIntegrityFailure ? VerificationCode::NamespaceOrLinkInconsistent :
                            VerificationCode::ReadFailure;
                        fail(code, error, unsupported); return;
                    }
                }
                const auto tree = [&](const AppleObjectLocation& root, AppleBtreeKeyOrder order, std::vector<BtreeRecord>& records) {
                    std::vector<std::uint64_t> blocks;
                    if (!ReadTree(observed,*cp,v,root,records,order,blocks,error) || !CheckOrder(observed,records,order,error)) return false;
                    if (!ChargeHistory(observed,blocks.size(),sizeof(std::uint64_t),error)) return false;
                    metadata.insert(metadata.end(),blocks.begin(),blocks.end()); return true;
                };
                if (!tree(*v.extentref_tree,AppleBtreeKeyOrder::PhysicalExtent,refs.values)) { failed(error); return; }
                for (const auto* map : std::array<const AppleOmapView*, 2>{&cp->container_object_map, &v.object_map})
                {
                    Records records;
                    if (!tree(map->tree,AppleBtreeKeyOrder::ObjectMap,records.values)) { failed(error); return; }
                    if (!ChargeHistory(observed,1,sizeof(std::uint64_t),error)) { failed(error); return; }
                    metadata.push_back(map->object.physical_block);
                }
                if (v.snapshot_metadata_tree)
                {
                    Records records;
                    if (!tree(*v.snapshot_metadata_tree,AppleBtreeKeyOrder::Lexicographic,records.values)) { failed(error); return; }
                    if (!records.values.empty()) { fail(VerificationCode::UnsupportedFeature,"VerifierEncryptedRetainedSnapshotsUnsupported",true); return; }
                }
                UnlockError ke; std::uint64_t container_bag=0, volume_bag=0;
                auto bags = InspectPasswordKeybagMetadataAtCheckpoint(source,scope.exact.volume_oid,KeybagLength::IncludesHeader,
                    nx.xid,ke,container_bag,volume_bag);
                if (!bags) { fail(VerificationCode::StructuralInconsistency,"VerifierEncryptedRetainedKeybagMetadataInvalid"); return; }
                if (!ChargeHistory(observed,2,sizeof(std::uint64_t),error)) { failed(error); return; }
                metadata.push_back(container_bag); metadata.push_back(volume_bag);
                std::vector<ApplePhysicalExtentRecord> payload;
                if (!ChargeHistory(observed,fs.values.size()+refs.values.size(),256+2*sizeof(ApplePhysicalExtentRecord),error) ||
                    !ValidateAppleEncryptedPayloadExtentGraph(fs.values,refs.values,nx.block_size,nx.block_count,payload,error) ||
                    !CheckMetadataAllocation(observed,*cp,metadata,bad_block,error)) { failed(error); return; }
                RetainedProfileCheckpointGraph graph; graph.checkpoint_xid=nx.xid;
                for (const auto b : metadata)
                    if (!OwnershipAppend(observed,graph.metadata_ranges,b,1,error)) { failed(error); return; }
                for (const auto& e : payload)
                    if (!OwnershipAppend(observed,graph.payload_ranges,e.physical_block,e.block_count,error)) { failed(error); return; }
                if (!NormalizeProtectedRanges(graph.metadata_ranges,nx.block_count,error) ||
                    !NormalizeProtectedRanges(graph.payload_ranges,nx.block_count,error)) { failed(error); return; }
                for (const auto& r : graph.metadata_ranges)
                    if (!OwnershipAppend(observed,metadata_union,r.physical_block,r.block_count,error)) { failed(error); return; }
                for (const auto& r : graph.payload_ranges)
                    if (!OwnershipAppend(observed,payload_union,r.physical_block,r.block_count,error)) { failed(error); return; }
                if (!out.read_budget->Materialize(2,sizeof(graph)+sizeof(AppleRecoveryCheckpointView))) { failed(out.read_budget->Failure()); return; }
                AppleRecoveryCheckpointView state; state.checkpoint=std::move(*cp);
                state.metadata_blocks=std::move(metadata); state.payload_extents=std::move(payload);
                states.push_back(std::move(state)); graphs.push_back(std::move(graph));
            }
            for (std::size_t i=0; i+1<states.size(); ++i)
            {
                bad_xid=states[i].checkpoint.container.superblock.xid;
                const auto& a=states[i].checkpoint.spaceman.internal_pool; const auto& b=states.back().checkpoint.spaceman.internal_pool;
                if (a.base_block!=b.base_block || a.block_count!=b.block_count || a.bitmap_base_block!=b.bitmap_base_block ||
                    a.bitmap_size_blocks!=b.bitmap_size_blocks || a.bitmap_block_count!=b.bitmap_block_count)
                { fail(VerificationCode::IdentityMismatch,"AppleCheckpointRetentionIdentityMismatch"); return; }
                if (!allowed() || !VerifyProfileRecoveryContinuity(observed,states[i],states,states.back().checkpoint,false,error))
                { failed(error); return; }
            }
            if (!NormalizeProtectedRanges(metadata_union,source.SizeBytes()/latest->superblock.block_size,error) ||
                !NormalizeProtectedRanges(payload_union,source.SizeBytes()/latest->superblock.block_size,error)) { failed(error); return; }
            for (const auto& m : metadata_union) for (const auto& p : payload_union)
            {
                if (!allowed() || !out.read_budget->Materialize(1,0)) { failed(out.read_budget->Failure()); return; }
                if (m.physical_block<p.physical_block+p.block_count && p.physical_block<m.physical_block+m.block_count)
                { fail(VerificationCode::PayloadMetadataOverlap,"VerifierRetainedPayloadMetadataConflict"); return; }
            }
            auto recheck=session.CreateRetainedVerificationContext(from,error);
            if (!recheck || !LoadAppleCheckpointView(source,0,source.SizeBytes(),error,*recheck,from) ||
                !observed.VerifyUnchanged(error) || !allowed()) { failed(error); return; }
            out.stores=current.stores; out.chain_xids=std::move(xids); out.checkpoints=std::move(graphs);
            out.selected=current.selected; out.allocation_unit_bytes=current.allocation_unit_bytes;
            out.historical_namespace_verified=true;
            out.outcome=VerificationOutcome::Complete;
        };
        run();
    }
    catch (const std::bad_alloc&) { fail(VerificationCode::BudgetExceeded,"VerifierEncryptedRetainedAllocationFailed"); }
    catch (...) { fail(VerificationCode::ReadFailure,"VerifierEncryptedRetainedReadFailure"); }
    const auto after=out.read_budget->Consumed();
    out.source_reads=after.reads-before.reads; out.source_read_bytes=after.read_bytes-before.read_bytes;
    return out;
}
#include "ProfileSnapshotGraphVerifier.inc"
}
