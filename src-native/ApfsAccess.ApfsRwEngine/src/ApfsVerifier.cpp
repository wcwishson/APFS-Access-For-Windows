#include "ApfsVerifier.h"

#include "AppleTransactionCommit.h"
#include "AppleVolumeTransaction.h"
#include "ApfsSharedSpace.h"
#include "NativeApfsReader.h"

#include <algorithm>
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
    VerificationSource(const RandomAccessSource& source, const VerificationScope& scope)
        : source_(source), budget_(source.ReadBudget())
    {
        if (!budget_) budget_ = std::make_shared<ApfsReadBudget>(scope.max_reads,
            scope.max_read_bytes, scope.max_records, scope.max_record_bytes);
        else budget_->LimitRemainingTo(scope.max_reads, scope.max_read_bytes,
            scope.max_records, scope.max_record_bytes);
    }
    std::uint64_t SizeBytes() const override { return source_.SizeBytes(); }
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override { return budget_; }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override
    {
        out.clear();
        if (io_failed || bounds_failed || budget_->Failed()) return false;
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
    id = "apfs-verifier-refusal-v1|";
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
            order == AppleBtreeKeyOrder::PhysicalExtent)
        {
            const bool pair = order != AppleBtreeKeyOrder::PhysicalExtent;
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
}

VerificationReport ApfsVerifier::Verify(const RandomAccessSource& source, const VerificationScope& scope)
{
    VerificationReport report;
    report.requested_scope = scope;
    const auto add = [&](VerificationCheck check, bool implemented, bool required, const char* detail) {
        report.coverage.push_back({check, implemented, required, VerificationCheckState::Unproven, detail});
    };
    add(VerificationCheck::ExactSelection, true, true, "Exact container/volume UUID, OID, XID and store window; source identity is caller supplied");
    add(VerificationCheck::OrdinaryFeatures, true, true, "Single-store ordinary unencrypted current volume and dependency roots");
    add(VerificationCheck::SpacemanGraph, true, true, "Authoritative spaceman bitmap, pool, free queue and counter consistency");
    add(VerificationCheck::SnapshotInventory, true, true, "Authoritative inventory for all volumes; nonempty snapshot accounting refused");
    add(VerificationCheck::MetadataTreeWalk, true, true, "All current FS/extentref, empty snapshot, OMAP and free-queue trees: checksum, identity, bounds, cycles, counts");
    add(VerificationCheck::LeafKeyOrder, true, true, "All current FS/extentref, empty snapshot, OMAP and free-queue leaf order and duplicate keys");
    add(VerificationCheck::NamespaceLinksAndStreams, true, true, "All current volumes strict namespace/links/streams; only admitted inode/xattr flags, base directory records and name/dstream/sparse inode xfields");
    add(VerificationCheck::PayloadReferences, true, true, "All current volumes KIND_NEW physical intervals and reference multiplicity; no payload reads");
    add(VerificationCheck::PayloadAllocatorOwnership, true, true, "All current payload allocated, nonqueued, outside current container metadata and reserved ranges");
    add(VerificationCheck::SharedSpaceAndQuota, true, true, "Container shared counters/reserves and each volume allocated count versus configured quota");
    add(VerificationCheck::InternalSeparatorRouting, true, true, "All current trees: exact comparator order, separator equals child minimum, exclusive upper ranges at every level");
    add(VerificationCheck::MetadataAllocatorOwnership, true, true, "Current reachable trees, objects, checkpoint mappings and allocator metadata: main/internal bits set, no deferred-free entry");
    add(VerificationCheck::CrossVolumePayloadOwnership, true, true, "All admitted snapshot-free volumes: independently validated physical payload intervals do not overlap");
    add(VerificationCheck::CompleteAllocationAccounting, false, scope.require_whole_volume, "Orphan allocations, ownership of every allocated block, metadata aliasing and APSB totals versus full ownership are unproven");
    add(VerificationCheck::HistoricalReachability, false, scope.require_whole_volume, "Historical/checkpoint-retention and nonempty snapshot ownership are unproven");
    add(VerificationCheck::PayloadContentHashes, false, scope.require_payload_content_hashes || scope.require_whole_volume, "Payload bytes are not read or hashed");
    add(VerificationCheck::Crypto, false, false, "Encrypted volumes/keybags are unsupported");
    add(VerificationCheck::Fusion, false, false, "Fusion/multiple physical stores are unsupported");
    Coverage(report, VerificationCheck::Crypto).state = VerificationCheckState::Unsupported;
    Coverage(report, VerificationCheck::Fusion).state = VerificationCheckState::Unsupported;

    VerificationCheck active = VerificationCheck::ExactSelection;
    std::optional<std::uint64_t> affected_volume, affected_object, affected_block;
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
            scope.exact.checkpoint_xid ? std::optional{scope.exact.checkpoint_xid} : std::nullopt,
            bounded && bounded->io_failed ? std::optional{bounded->failed_offset} : std::nullopt, std::move(detail)});
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
                !scope.max_reads || !scope.max_read_bytes || !scope.max_records || !scope.max_record_bytes)
            { fail(VerificationCode::InvalidScope, "VerifierScopeInvalid", true); return; }
            bounded = std::make_unique<VerificationSource>(source, scope);
            OffsetRandomAccessSource store(bounded.get(), exact.store_offset_bytes, exact.store_size_bytes);
            std::string error;
            const auto checkpoint = LoadAppleCheckpointView(store, 0, store.SizeBytes(), error, exact.checkpoint_xid);
            if (!checkpoint || bounded->io_failed || bounded->ReadBudget()->Failed())
            { failed(error, VerificationCode::StructuralInconsistency); return; }
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
                affected_volume = volume.superblock.object_id;
                if (volume.superblock.fs_flags != kFsFlagUnencrypted)
                { fail(VerificationCode::CryptoUnsupported, "VerifierEncryptionOrFsFlagsUnsupported", true); return; }
                if ((volume.superblock.features & ~kVolumeKnownOptionalFeaturesMask) ||
                    !CheckAppleVolumeWriteFeatures(nx, volume.superblock, error))
                { fail(VerificationCode::UnsupportedFeature, "VerifierOrdinaryVolumeFeaturesUnsupported:" + error, true); return; }
            }
            Coverage(report, active).state = VerificationCheckState::Verified;
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
                std::vector<AppleSnapshotRecord> snapshots;
                if (!LoadAppleSnapshotRecords(store, *checkpoint, *affected_volume, snapshots, error))
                { failed(error, VerificationCode::SnapshotCoverageUnavailable); return; }
                if (!snapshots.empty())
                { fail(VerificationCode::SnapshotAccountingUnsupported, "VerifierNonemptySnapshotOwnershipUnsupported", true); return; }
            }
            Coverage(report, active).state = VerificationCheckState::Verified;
            std::vector<std::uint64_t> metadata_blocks;
            std::vector<BtreeRecord> map_records;
            const auto walk = [&](const AppleVolumeCheckpointView& volume, const AppleObjectLocation& root,
                std::vector<BtreeRecord>& records, AppleBtreeKeyOrder order) {
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
                metadata_blocks.insert(metadata_blocks.end(), visited.begin(), visited.end());
                return true;
            };
            if (!walk(*selected, checkpoint->container_object_map.tree, map_records, AppleBtreeKeyOrder::ObjectMap)) return;
            for (const auto& queue : checkpoint->spaceman.free_queues)
                if (queue.tree_oid && !walk(*selected, queue.root, map_records, AppleBtreeKeyOrder::SpacemanFreeQueue)) return;
            struct OwnedExtent { ApplePhysicalExtentRecord extent; std::uint64_t volume_oid; };
            std::vector<OwnedExtent> owned;
            std::vector<ApplePhysicalExtentRecord> physical;
            std::uint64_t selected_records = 0, selected_extents = 0;
            for (const auto& volume : checkpoint->volumes)
            {
                if (!walk(volume, volume.object_map.tree, map_records, AppleBtreeKeyOrder::ObjectMap)) return;
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
                        if (!store.ReadBudget()->Materialize(1, 8192 + 32ull * (record.key.size() + record.value.size())))
                        { failed(store.ReadBudget()->Failure(), VerificationCode::BudgetExceeded); return; }
                std::vector<ApplePhysicalExtentRecord> volume_physical;
                if (!ValidateApplePayloadExtentGraph(filesystem, extentrefs, nx.block_size, nx.block_count, volume_physical, error))
                { failed(error, VerificationCode::ExtentReferenceInconsistent); return; }
                active = VerificationCheck::NamespaceLinksAndStreams;
                if (!NativeApfsReader::ValidateOrdinaryFileSystemRecords(filesystem, nx, volume.superblock, store.ReadBudget(), error))
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
            active = VerificationCheck::MetadataAllocatorOwnership;
            affected_volume.reset();
            if (!CheckMetadataAllocation(store, *checkpoint, metadata_blocks, affected_block, error))
            { failed(error, VerificationCode::MetadataAllocationInconsistent); return; }
            Coverage(report, active).state = VerificationCheckState::Verified;
            active = VerificationCheck::PayloadAllocatorOwnership;
            if (!ValidateAppleCheckpointPayloadOwnership(store, *checkpoint, physical, error))
            { failed(error, VerificationCode::PayloadAllocationInconsistent); return; }
            Coverage(report, active).state = VerificationCheckState::Verified;
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
            for (const auto& coverage : report.coverage)
                if (coverage.required && coverage.state != VerificationCheckState::Verified)
                {
                    active = coverage.check;
                    fail(VerificationCode::CoverageMissing, coverage.scope_detail);
                    Coverage(report, active).state = VerificationCheckState::Unproven;
                    return;
                }
            report.covered_filesystem_records = selected_records;
            report.covered_physical_extents = selected_extents;
            report.outcome = VerificationOutcome::Complete;
        };
        run();
    }
    catch (const std::bad_alloc&) { fail(VerificationCode::BudgetExceeded, "VerifierAllocationFailed"); }
    catch (const std::length_error&) { fail(VerificationCode::BudgetExceeded, "VerifierAllocationFailed"); }
    if (bounded) { report.source_reads = bounded->reads; report.source_read_bytes = bounded->bytes; }
    Finish(report);
    return report;
}
}
