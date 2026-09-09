#pragma once

#include "ApfsSnapshotStore.h"

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
    MetadataAllocationInconsistent = 21, CrossVolumePayloadOverlap = 22
};
enum class VerificationCheck : std::uint8_t
{
    ExactSelection = 1, OrdinaryFeatures = 2, SpacemanGraph = 3,
    SnapshotInventory = 4, MetadataTreeWalk = 5, LeafKeyOrder = 6,
    NamespaceLinksAndStreams = 7, PayloadReferences = 8, PayloadAllocatorOwnership = 9,
    SharedSpaceAndQuota = 10, InternalSeparatorRouting = 11,
    CompleteAllocationAccounting = 12, HistoricalReachability = 13,
    PayloadContentHashes = 14, Crypto = 15, Fusion = 16,
    MetadataAllocatorOwnership = 17, CrossVolumePayloadOwnership = 18
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
    bool whole_volume_verified = false;
    bool payload_content_hashes_verified = false;
    ApfsRepairPlan repair;
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
};
}
