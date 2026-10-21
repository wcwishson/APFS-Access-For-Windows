#pragma once

#include "ApfsVerifier.h"
#include "ApfsSpaceAccounting.h"
#include "ApfsProfileHistory.h"
#include "ApfsProfileSnapshotGraph.h"
#include <span>
#include <string_view>

namespace apfsaccess::catalog
{
inline constexpr std::size_t MaxImageVerificationJsonBytes = 64ull * 1024 * 1024 - 2;
inline constexpr unsigned RetainedAccountingImageVerificationVersion = 4;
inline constexpr unsigned SnapshotSpaceAttributionVersion = 1;
inline constexpr unsigned SnapshotAllocationCountersVersion = 1;
inline constexpr unsigned CurrentProfileVerificationVersion = 1;
inline constexpr unsigned RetainedProfileVerificationVersion = 1;
inline constexpr unsigned VisibleSnapshotProfileVerificationVersion = 1;
inline constexpr unsigned MarkedReferenceSpaceVersion = 1;
inline constexpr std::size_t MaxSnapshotSpaceAttributionJsonBytes = MaxImageVerificationJsonBytes;

// Pure serialization; the caller owns the stable image lease and path label.
// Metadata-only requests retain image v2. Observation requests emit image v3.
// Explicit retained accounting emits image v4: requestedScope gains
// accountRetainedOwnership and the root gains retainedOwnership (null on
// incomplete/refused verification). Optional pin/observation fields are emitted
// only when requested. Older strict parsers must reject v4, never reinterpret it.
// Snapshot usage is physical payload only; total/purgeable remain null.
// Charges the report's exact allowance before allocation. An exhausted budget,
// expired deadline or response overflow returns no JSON, never a partial report.
// The transport caller must publish its existing bounded failure in that case.
[[nodiscard]] bool SerializeImageVerificationReport(const VerificationReport& report,
    std::string_view image_path, const std::function<bool()>& within_deadline,
    std::size_t max_output_bytes, std::string& output, payload::Reason& failure);

// Explicit requested-history transport. It conveys no repair plan or whole
// allocation/volume assurance and cannot be emitted through the legacy codec.
// Accounting requests/results are refused here; use the explicit image v4 path.
[[nodiscard]] bool SerializeProtectedHistoryVerificationReport(const VerificationReport& report,
    std::string_view image_path, const std::function<bool()>& within_deadline,
    std::size_t max_output_bytes, std::string& output, payload::Reason& failure);

// Separate apfs-access-snapshot-space-attribution v1 document. Complete admitted
// result only; never a payload-only snapshot-space or verifier v2/v3/v4 document.
// expected_scope binds the caller-held source label and all exact selectors.
// No source kind, lease, total charge, purgeability or release authority is
// inferred here. Labels must be valid UTF-8, non-NUL and at most 65535 bytes.
// The result's exact sticky allowance covers validation and both encoding
// passes. Refusal, deadline, allocation or output limit clears the entire JSON.
[[nodiscard]] bool SerializeSnapshotSpaceAttribution(
    const std::optional<ApfsSnapshotSpaceAttribution>& result,
    const VerificationScope& expected_scope, std::string_view image_path,
    const std::function<bool()>& within_deadline, std::size_t max_output_bytes,
    std::string& output, payload::Reason& failure);

// Separate observed descriptor counters, never deletion savings or a sum of
// snapshot charges. Complete canonical read-only admission is required. Each
// amount is apfs_fs_alloc_count at the exact descriptor XID, which can postdate
// the snapshot XID. All independent Apple policy/charge amounts remain null.
[[nodiscard]] bool SerializeSnapshotAllocationCounters(
    const std::optional<ApfsSnapshotAllocationCounters>& result,
    const VerificationScope& expected_scope, std::string_view image_path,
    const std::function<bool()>& within_deadline, std::size_t max_output_bytes,
    std::string& output, payload::Reason& failure);

// Distinct apfs-access-marked-reference-space v1. Requires the complete
// namespace/directory7/allocation subset; exact marked-file physical ranges
// include external xattrs. Literal private-stream records remain separate.
// No hidden owners, retained NX history, OS policy or release permission.
[[nodiscard]] bool SerializeMarkedReferenceSpace(
    const std::optional<ApfsMarkedReferenceSpaceObservation>& result,
    const VerificationScope& expected_scope, std::string_view image_path,
    const std::function<bool()>& within_deadline, std::size_t max_output_bytes,
    std::string& output, payload::Reason& failure);

[[nodiscard]] bool SerializeMarkedOwnerSpaceAttribution(
    const std::optional<ApfsMarkedOwnerSpaceAttribution>& result, const VerificationScope& expected_scope,
    std::optional<std::uint64_t> expected_from_xid, std::string_view image_path,
    const std::function<bool()>& within_deadline, std::size_t max_output_bytes,
    std::string& output, payload::Reason& failure);

// Separate apfs-access-current-profile-verification v1. Exact independent
// expected profile/scope/member bindings; labels are display-only. Fusion
// windows are member-image-relative; encrypted windows are container-relative.
// Typed incomplete/refused reports carry null counts. Sticky budget/deadline
// failure produces no document; transport must use its bounded failure route.
// No lease, original image offset, history, Apple charge or repair authority.
[[nodiscard]] bool SerializeCurrentProfileVerificationReport(
    const CurrentProfileVerificationReport& report, CurrentVerificationProfile expected_profile,
    const VerificationScope& expected_scope, std::span<const VerificationStoreBinding> expected_stores,
    std::span<const std::string> source_labels, const std::function<bool()>& within_deadline,
    std::size_t max_output_bytes, std::string& output, payload::Reason& failure);

// Distinct apfs-access-retained-profile-verification v1; never the current v1
// or ordinary image codec. Exact explicit from-XID through endpoint, finite
// namespace/physical continuity only. Incomplete/refused results have no graph,
// selected identity or namespace success. No hidden-owner/orphan completeness
// or Apple charge authority. Shares the same bounded response behavior.
[[nodiscard]] bool SerializeRetainedProfileVerificationReport(
    const RetainedProfileHistoryReport& report, CurrentVerificationProfile expected_profile,
    const VerificationScope& expected_scope, std::uint64_t expected_from_xid,
    std::span<const VerificationStoreBinding> expected_stores,
    std::span<const std::string> source_labels, const std::function<bool()>& within_deadline,
    std::size_t max_output_bytes, std::string& output, payload::Reason& failure);

// Distinct finite visible-inventory graph/attribution v1, including nonempty
// encrypted/Fusion snapshot inventories. from_xid is an explicit parent-chain
// request, not an exhaustive history promise. Complete reports rederive bounded
// physical set attribution from the canonical graph. Incomplete/refused reports
// publish null graph/attribution/selected. No hidden-owner/orphan, Apple charge,
// purgeability or guaranteed deletion savings is asserted by this document.
[[nodiscard]] bool SerializeVisibleSnapshotProfileVerificationReport(
    const ProfileSnapshotGraphReport& report, CurrentVerificationProfile expected_profile,
    const VerificationScope& expected_scope, std::optional<std::uint64_t> expected_from_xid,
    std::span<const VerificationStoreBinding> expected_stores,
    std::span<const std::string> source_labels, const std::function<bool()>& within_deadline,
    std::size_t max_output_bytes, std::string& output, payload::Reason& failure);
}
