#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

// Offline bounded RCT2 (APSB regular-file count) repair operation.
// Single invocation drives exactly one prepare/display/confirm/apply/verify
// pipeline in-process: the confirmation token never leaves the process, so
// no secret crosses argv, environment, logs, or evidence files.
//
// Contracts (mirroring ApfsCountRepairPlan, enforced structurally):
// - explicit confirmation: --confirm plus an exact --expected-count intent;
//   without both the tool only displays the prepared plan (dry run).
// - exact identity: image/container/volume/XID/store-window selectors; the
//   live image identity is re-verified after open and bound into the plan.
// - fresh witness + preimage validation, XID/generation binding, WAL identity
//   bound to this volume+checkpoint, post-publication verification.
// - fresh journal only: --journal must not exist (foreign journals are never
//   adopted); the tool creates and owns it for this run.
// - ambiguity fails closed: snapshots present, concurrent owner, torn
//   inputs, Fusion/encrypted/whole-volume/payload-hash shapes all refuse
//   with bytes provably unchanged.
// - single horizon: prepare and apply share one process lifetime, inside the
//   plan's 5-minute expiry by construction.
//
// Exit codes mirror ApfsObserver verify: 0 repaired (or healthy no-op),
// 3 needs-confirmation / incomplete, 4 refused (bytes unchanged), 2 invalid
// arguments, 5 operational failure. stdout (or --out) carries exactly one
// JSON document on the "apfs-access-repair" version-1 contract.
// --approval-mode exact-source-v1 selects additive report version 2. Its
// source.identity/source.sha256 and existing scope/plan.expectedCount are
// public review evidence. Confirmed fresh apply must return that evidence;
// hashing, scope checks, planning and apply share the exact exclusive lease.
// Original accepted repair journals retain their engine-validated replay path.
struct VolumeRepairToolOptions
{
    std::string image;
    std::string container_uuid;
    std::string volume_uuid;
    std::uint64_t volume_oid = 0;
    std::uint64_t checkpoint_xid = 0;
    std::uint64_t store_offset_bytes = 0;
    std::uint64_t store_size_bytes = 0;
    std::uint64_t expected_count = 0; // operator intent; 0 = unstated
    std::string journal_path;
    std::string evidence_dir;
    std::string out_path; // empty = stdout
    bool confirm = false;
    // Opt-in v2 public approval, distinct from the engine's one-use token.
    // Dry runs return the held file identity and complete image SHA-256.
    // Fresh confirmed apply requires both, plus the exact existing scope/count.
    bool exact_source_approval = false;
    std::string approved_source_identity;
    std::string approved_source_sha256;
    // Test-only interruption hook (accepts "before-apple-publish"); honored
    // only when APFS_REPAIR_TEST_HOOKS=1, otherwise rejected as unknown.
    std::string test_abort_stage;
};

struct VolumeRepairToolResult
{
    int exit_code = 5;
    std::string json;
};

// Never throws: all failures return an exit code plus a JSON error document.
VolumeRepairToolResult RunVolumeRepair(const VolumeRepairToolOptions& options);
// Parses argv (program name excluded); usage errors throw ToolArgumentError.
VolumeRepairToolOptions ParseVolumeRepairArguments(const std::vector<std::string>& argv);

class ToolArgumentError : public std::invalid_argument
{
public:
    explicit ToolArgumentError(const std::string& message) : std::invalid_argument(message) {}
};

std::string VolumeRepairUsage();
