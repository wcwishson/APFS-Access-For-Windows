#pragma once

#include "ApfsSnapshotStore.h"
#include "CurrentPayloadObservation.h"
#include <array>

namespace apfsaccess::catalog
{
// Numeric values are stable report-schema identifiers, not parser error text.
enum class VerificationOutcome : std::uint8_t { Complete = 1, Incomplete = 2, Refused = 3 };
enum class VerificationSeverity : std::uint8_t { Information = 1, Warning = 2, Error = 3 };
enum class VerificationCode : std::uint16_t
{
    InvalidScope = 1, IdentityMismatch = 2, ReadFailure = 3, BudgetExceeded = 4,
    CheckpointUnavailable = 5, ChecksumMismatch = 6, StructuralInconsistency = 7,
    UnsupportedFeature = 8, TreeOrderInconsistent = 9, NamespaceOrLinkInconsistent = 10,
    ExtentReferenceInconsistent = 11, PayloadMetadataOverlap = 12,
    PayloadAllocationInconsistent = 13, SpacemanInconsistent = 14,
    QuotaOrReserveInconsistent = 15, SnapshotCoverageUnavailable = 16,
    SnapshotAccountingUnsupported = 17, CoverageMissing = 18,
    CryptoUnsupported = 19, FusionUnsupported = 20,
    MetadataAllocationInconsistent = 21, CrossVolumePayloadOverlap = 22,
    MetadataOwnerConflict = 23, AllocatedCountUnderstated = 24,
    VolumeFileCountInconsistent = 25, OrphanAllocation = 26,
    RetainedOwnershipConflict = 27
};
enum class VerificationCheck : std::uint8_t
{
    ExactSelection = 1, OrdinaryFeatures = 2, SpacemanGraph = 3,
    SnapshotInventory = 4, MetadataTreeWalk = 5, LeafKeyOrder = 6,
    NamespaceLinksAndStreams = 7, PayloadReferences = 8, PayloadAllocatorOwnership = 9,
    SharedSpaceAndQuota = 10, InternalSeparatorRouting = 11,
    CompleteAllocationAccounting = 12, HistoricalReachability = 13,
    PayloadContentHashes = 14, Crypto = 15, Fusion = 16,
    MetadataAllocatorOwnership = 17, CrossVolumePayloadOwnership = 18,
    CurrentOwnershipCensus = 19, SnapshotReachableAllocation = 20,
    CurrentPayloadObservation = 21, RequestedHistoryOwnership = 22
};
enum class VerificationCheckState : std::uint8_t
{ Unproven = 1, Verified = 2, Inconsistent = 3, Unsupported = 4, NotRequested = 5 };

struct VerificationScope
{
    // Caller-held source identity (for example a stable image/file ID). This is
    // a binding label, not a device identity authenticated by this byte interface.
    std::string source_identity;
    ApfsSnapshotScope exact;
    std::uint64_t max_reads = 65536;
    std::uint64_t max_read_bytes = 256ull * 1024 * 1024;
    std::uint64_t max_records = 1000000;
    std::uint64_t max_record_bytes = 256ull * 1024 * 1024;
    // The implementation can complete the covered current-metadata subset.
    // Requesting either broader scope always yields explicit missing coverage.
    bool require_whole_volume = false;
    bool require_payload_content_hashes = false;
    // Current-byte observations supply no independent expected-content authority.
    // False preserves the existing metadata-only coverage/wire/plan contract.
    bool observe_payload_content = false;
    std::uint64_t max_payload_logical_bytes = payload::MaxLogicalBytes;
    std::uint64_t max_payload_entries = payload::MaxEntries;
    // Opt-in protected ownership from this retained XID to the exact latest
    // endpoint. Requires 0 < from < endpoint; does not enumerate all history.
    std::optional<std::uint64_t> retained_from_xid;
    // Exhaustive physical accounting for every descriptor-ring generation and
    // canonical hidden OMAP/snapshot owner. Requires an exact latest endpoint.
    // Does not supply expected content hashes or Apple purgeability policy.
    bool account_retained_ownership = false;
};

struct VerificationFinding
{
    VerificationCode code = VerificationCode::StructuralInconsistency;
    VerificationSeverity severity = VerificationSeverity::Error;
    VerificationCheck check = VerificationCheck::ExactSelection;
    std::optional<std::uint64_t> volume_oid;
    std::optional<std::uint64_t> object_id;
    std::optional<std::uint64_t> physical_block; // store-relative root/check context, not necessarily the damaged child
    std::optional<std::uint64_t> checkpoint_xid;
    std::optional<std::uint64_t> failed_source_offset_bytes; // exact backing I/O failure, source relative
    // Diagnostic context only; callers switch on code/check, never this text.
    std::string detail;
    bool operator==(const VerificationFinding&) const = default;
};

struct VerificationCoverage
{
    VerificationCheck check;
    bool implemented;
    bool required;
    VerificationCheckState state;
    std::string scope_detail;
    bool operator==(const VerificationCoverage&) const = default;
};

struct VerifiedCheckpointIdentity
{
    ApfsSnapshotScope exact;
    std::uint64_t checkpoint_physical_block = 0;
    std::uint64_t volume_superblock_physical_block = 0;
    std::uint64_t volume_superblock_xid = 0;
    std::uint64_t root_oid = 0;
    std::uint64_t root_physical_block = 0;
    bool operator==(const VerifiedCheckpointIdentity&) const = default;
};

enum class ApfsRepairRefusal : std::uint8_t
{ NoIndependentReconstructionEvidence = 1, VerificationNotComplete = 2 };

// A deterministic, identity/finding-bound refusal, deliberately with no write
// actions or apply API. The plan ID is a canonical serialization, NOT a content
// hash, authorization token, or repair capability. Task 10 repair remains open.
struct ApfsRepairPlan
{
    std::string plan_id;
    std::string source_identity;
    ApfsSnapshotScope requested_identity;
    std::optional<VerifiedCheckpointIdentity> observed_identity;
    std::vector<VerificationFinding> findings;
    ApfsRepairRefusal refusal = ApfsRepairRefusal::VerificationNotComplete;
    bool operator==(const ApfsRepairPlan&) const = default;
};

struct VerificationBlockRange
{
    std::uint64_t physical_block = 0, block_count = 0;
    bool operator==(const VerificationBlockRange&) const = default;
};

// Container-relative protected ranges, not logical refcounts, volume charges
// or reclaim candidates. Sharing between checkpoints is intentionally retained.
struct VerificationProtectedCheckpoint
{
    std::uint64_t checkpoint_xid = 0;
    std::vector<VerificationBlockRange> metadata_ranges, payload_ranges;
    bool operator==(const VerificationProtectedCheckpoint&) const = default;
};

struct RequestedHistoryVerification
{
    std::uint64_t from_xid = 0;
    VerifiedCheckpointIdentity endpoint;
    std::vector<std::uint64_t> chain_xids; // Includes the current endpoint.
    std::vector<VerificationProtectedCheckpoint> checkpoints; // Excludes it.
    bool operator==(const RequestedHistoryVerification&) const = default;
};

// Observations for the selected live graph, including its OMAP snapshot index.
// Retained snapshot objects are not counted once per historical view here.
// These observations are not reclaim candidates.
// Unattributed allocations may belong to retained checkpoints/OMAP versions.
// Even zero unattributed ranges does not establish historical ownership.
struct VerificationAllocationCensus
{
    // Authenticated container geometry; all ranges use container-relative blocks.
    std::uint64_t block_size_bytes = 0, container_block_count = 0;
    std::uint64_t current_metadata_blocks = 0, current_payload_blocks = 0;
    std::uint64_t unattributed_main_blocks = 0, unattributed_internal_blocks = 0;
    std::vector<VerificationBlockRange> unattributed_main_ranges;
    std::vector<VerificationBlockRange> unattributed_internal_ranges;
    bool operator==(const VerificationAllocationCensus&) const = default;
};

struct VerificationSnapshotPayloadUsage
{
    std::uint64_t volume_oid = 0;
    // Unique physical payload referenced by the current snapshot inventory.
    // Exclusive means absent from that volume's live payload, not reclaimable:
    // retained checkpoints and hidden OMAP descriptors can still protect it.
    std::uint64_t referenced_blocks = 0, exclusive_blocks = 0;
    std::uint64_t referenced_bytes = 0, exclusive_bytes = 0;
    bool operator==(const VerificationSnapshotPayloadUsage&) const = default;
};

struct VerificationRetainedOwnership
{
    std::vector<std::uint64_t> checkpoint_xids; // Exhaustive descriptor NXSB set.
    // Canonical complete current/snapshot/hidden-OMAP and retained graph union.
    std::vector<VerificationBlockRange> metadata_ranges, payload_ranges;
    // Disjoint allocator partition, independently for main and internal pools.
    std::uint64_t allocated_main_blocks = 0, allocated_internal_blocks = 0;
    std::uint64_t owned_main_blocks = 0, owned_internal_blocks = 0;
    std::uint64_t reserved_main_blocks = 0, deferred_main_blocks = 0, deferred_internal_blocks = 0;
    std::vector<VerificationSnapshotPayloadUsage> snapshot_payload_usage;
    // Total snapshot metadata charges and purgeability require further Apple
    // accounting/policy evidence. Payload observations cannot establish them.
    std::optional<std::uint64_t> snapshot_total_bytes, purgeable_bytes;
    bool operator==(const VerificationRetainedOwnership&) const = default;
};

struct VerificationReport
{
    VerificationScope requested_scope;
    VerificationOutcome outcome = VerificationOutcome::Incomplete;
    std::optional<VerifiedCheckpointIdentity> selected;
    std::vector<VerificationFinding> findings;
    std::vector<VerificationCoverage> coverage;
    std::uint64_t source_reads = 0; // includes failed backing read attempts
    std::uint64_t source_read_bytes = 0;
    // Published only after every covered check succeeds; zero on late failure.
    std::uint64_t covered_filesystem_records = 0;
    std::uint64_t covered_physical_extents = 0;
    // Published with the completed current subset only, cleared on any failure.
    std::optional<VerificationAllocationCensus> allocation_census;
    // Published only when the entire requested verification completes.
    std::optional<RequestedHistoryVerification> requested_history;
    bool whole_volume_verified = false;
    bool payload_content_hashes_verified = false;
    std::optional<payload::Result> payload_inventory;
    // Owns the admitted alias/extent backing for the inventory's borrowed span.
    std::shared_ptr<const rw::NativeApfsVolumeProjection> payload_projection;
    // Exact operation allowance; serialization must not install a replacement.
    std::shared_ptr<ApfsReadBudget> read_budget;
    ApfsRepairPlan repair;
    // Published only after all requested checks succeed, with no orphan bits.
    std::optional<VerificationRetainedOwnership> retained_ownership;
};

class ApfsFusionStore;
class ImmutableEncryptedReadSource;
class ApfsEncryptedReadSession;
class ApfsVerifierEncryptedSource;

enum class CurrentVerificationProfile : std::uint8_t
{ FusionCleanCache = 1, EncryptedOneKeyGenerationZero = 2 };

struct VerificationStoreBinding
{
    std::string store_id;
    std::uint64_t offset_bytes = 0, size_bytes = 0;
};

// Separate result contract: never serialize as legacy single-store verification.
// Complete covers the stated current graph only; no retained/orphan, content
// expectation, repair, allocation-charge or purgeability authority is supplied.
struct CurrentProfileVerificationReport
{
    CurrentVerificationProfile profile = CurrentVerificationProfile::FusionCleanCache;
    VerificationScope requested_scope;
    VerificationOutcome outcome = VerificationOutcome::Incomplete;
    std::optional<VerifiedCheckpointIdentity> selected;
    std::vector<VerificationStoreBinding> stores;
    std::vector<VerificationFinding> findings;
    std::vector<VerificationCoverage> coverage;
    std::uint32_t allocation_unit_bytes = 0;
    std::uint64_t covered_volume_count = 0, covered_filesystem_records = 0;
    // Unique current object/tree dependency blocks; no logical allocation charge.
    std::uint64_t covered_physical_extents = 0, current_metadata_blocks = 0;
    std::uint64_t source_reads = 0, source_read_bytes = 0;
    std::shared_ptr<ApfsReadBudget> read_budget;
    std::optional<std::uint64_t> snapshot_allocation_charge_bytes, apple_purgeable_bytes, reclaimable_bytes;
};

class ApfsVerifier final
{
public:
    // No handles are opened. Caller must hold a stable, single-store image
    // source throughout this call. The byte interface cannot prove immutability
    // or file/device kind. Exact XID only: never selects an older checkpoint.
    // Scope limits are enforced even when source has its own stricter sticky
    // budget (monotonically tightened, never reset). Complete means the
    // explicitly covered subset, NOT volume health.
    [[nodiscard]] static VerificationReport Verify(
        const RandomAccessSource& source, const VerificationScope& scope);
    // Retained callers pass their existing cooperative deadline. Checked before
    // source reads, during allocation scans, at phase boundaries and for every
    // payload chunk, including holes/embedded data with no backing I/O.
    [[nodiscard]] static VerificationReport Verify(
        const RandomAccessSource& source, const VerificationScope& scope,
        const std::function<bool()>& within_deadline);
    // Explicit observational inactive-tree profile. Existing Verify stays
    // strict. No mutation/repair authority or wider feature mask is granted.
    [[nodiscard]] static VerificationReport VerifyReadOnly(
        const RandomAccessSource& source, const VerificationScope& scope);
    [[nodiscard]] static VerificationReport VerifyReadOnly(
        const RandomAccessSource& source, const VerificationScope& scope,
        const std::function<bool()>& within_deadline);
    // Explicit paired-store current graph. exact.store_* identifies the main
    // window; member IDs are supplied in main/tier2 order and compared exactly.
    // Uses the already held canonical binding; opens no path or write handle.
    [[nodiscard]] static CurrentProfileVerificationReport VerifyFusionCurrent(
        const ApfsFusionStore& source, const VerificationScope& scope,
        const std::array<std::string, 2>& member_store_ids,
        const std::function<bool()>& within_deadline);
    // Separately unlocked cumulative observational source only. Existing host
    // sessions cannot be rebound or silently reuse a fresh per-call allowance.
    [[nodiscard]] static CurrentProfileVerificationReport VerifyEncryptedCurrent(
        const ApfsVerifierEncryptedSource& source, ApfsEncryptedReadSession& session,
        const VerificationScope& scope, const std::function<bool()>& within_deadline);
};
}
