#pragma once

#include "AppleVolumeTransaction.h"
#include "VolumeKeeperHistory.h"
#include <filesystem>
#include <map>
#include <vector>

namespace apfsaccess::rw
{
enum class VolumeManagementOperation : std::uint8_t { Create = 1, Delete = 2 };
enum class VolumeManagementOutcome : std::uint8_t
{ Prepared = 1, Committed = 2, Cancelled = 3, Refused = 4, RecoveryRequired = 5 };

struct VolumeManagementRequest
{
    VolumeManagementOperation operation = VolumeManagementOperation::Create;
    std::filesystem::path image;
    // Runtime-owned, durable directory. All callers for an image MUST use the
    // same directory, including after restart. The keeper derives its filename.
    // Do not accept this value from managed clients or choose a temporary root.
    // Missing/unavailable roots fail closed; migration requires drained intent.
    std::filesystem::path journal_directory;
    std::uint64_t offset_bytes = 0;
    std::string container_uuid, volume_uuid;
    // Create requires the exact nx_next_oid; delete requires an existing OID.
    std::uint64_t volume_oid = 0, checkpoint_xid = 0;
    std::map<std::uint64_t, std::filesystem::path> sibling_wals;
    std::string name_utf8;
    std::uint64_t quota_blocks = 0, reserve_blocks = 0;
    bool case_sensitive = false;
    // Trusted runtime roots, independently rechecked natively; not serialized
    // into the original request and never a transferable history assertion.
    VolumeKeeperHistoryContext history_context;
};

struct VolumeManagementResult
{
    VolumeManagementOutcome outcome = VolumeManagementOutcome::Refused;
    std::string error, confirmation_token, source_identity;
    std::filesystem::path journal_path;
    std::uint64_t pre_xid = 0, post_xid = 0, block_size = 0;
    std::uint64_t free_blocks_before = 0, free_blocks_after = 0;
    std::uint64_t allocated_blocks = 0, deferred_blocks = 0, expires_unix_seconds = 0;
};

struct VolumeManagementObservationRequest
{
    std::filesystem::path image;
    std::uint64_t offset_bytes = 0;
};
struct VolumeManagementObservedVolume
{
    std::string volume_uuid;
    std::uint64_t oid = 0;
};
struct VolumeManagementObservation
{
    bool complete = false;
    std::string error, source_identity, container_uuid;
    std::uint64_t store_size_bytes = 0, checkpoint_xid = 0, block_size = 0, next_oid = 0;
    std::vector<VolumeManagementObservedVolume> volumes;
};

// Held ordinary read-only image, strict native checkpoint and geometry only.
// No WAL/journal observations or creation. Trusted service launch metadata
// supplies the keeper's complete original WAL paths separately.
VolumeManagementObservation ObserveVolumeManagement(const VolumeManagementObservationRequest&);
std::string VolumeManagementObservationJson(const VolumeManagementObservationRequest&,
    const VolumeManagementObservation&);
// Pure encoding of existing managed partitionless recovery identity material.
// This grants no ownership authority. Census separately proves bare image
// scope under its held source lease; nonzero/GPT offsets remain refused.
std::string DerivePartitionlessVolumeRecoveryIdentity(std::string_view container_uuid,
    std::uint64_t volume_oid);

// Offline regular-image keeper, bounded to 256 MiB of store-relative input.
// Prepare verifies and durably stores a private VMT1 plan without image writes.
// It refuses existing unfinished intent. The random confirmation is single-use;
// stale, expired, wrong-confirmation and cancel attempts consume prepared intent.
// Exclusive image and complete clean sibling WAL leases are held through apply.
// This does not mount a volume or use the APFSRW scaffold/coordinator.
VolumeManagementResult PrepareVolumeCreate(const VolumeManagementRequest&);
VolumeManagementResult PrepareVolumeDelete(const VolumeManagementRequest&);
VolumeManagementResult ApplyVolumeManagement(const VolumeManagementRequest&,
    std::string_view confirmation, const AppleCheckpointStageHook& interrupt = {});
VolumeManagementResult CancelVolumeManagement(const VolumeManagementRequest&,
    std::string_view confirmation);
// Exact original request/root required. Unaccepted prepared and cancelled
// intent returns Cancelled only with unchanged preimage and original WAL census.
// Accepted intent still requires deterministic forward recovery.
VolumeManagementResult RecoverVolumeManagement(const VolumeManagementRequest&,
    const AppleCheckpointStageHook& interrupt = {});

// Separate typed VMT2 authority over the caller's retained physical window.
// The initial topology profile retains the existing 256 MiB planner bound;
// peers can be created before a later independently admitted window growth.
// image is the exact held instance ID and offset_bytes the bound store base.
// Complete original sibling WALs and trusted history roots remain mandatory.
VolumeManagementResult PrepareVolumePhysicalCreate(const std::shared_ptr<VolumePhysicalSource>&,
    const VolumeManagementRequest&);
VolumeManagementResult PrepareVolumePhysicalDelete(const std::shared_ptr<VolumePhysicalSource>&,
    const VolumeManagementRequest&);
VolumeManagementResult ApplyVolumePhysicalManagement(const std::shared_ptr<VolumePhysicalSource>&,
    const VolumeManagementRequest&, std::string_view confirmation, const AppleCheckpointStageHook& = {});
VolumeManagementResult CancelVolumePhysicalManagement(const std::shared_ptr<VolumePhysicalSource>&,
    const VolumeManagementRequest&, std::string_view confirmation);
VolumeManagementResult RecoverVolumePhysicalManagement(const std::shared_ptr<VolumePhysicalSource>&,
    const VolumeManagementRequest&, const AppleCheckpointStageHook& = {});

// One JSON document per invocation, schemaVersion 1. Identity/count uint64s are
// decimal strings (lossless in managed/JavaScript consumers). No token on apply.
std::string VolumeManagementJson(const VolumeManagementRequest&, const VolumeManagementResult&);
}
