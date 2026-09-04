#pragma once

// One safe RW owner per APFS container: a single raw-device lease, one
// container identity/checkpoint, one commit serializer, and one extent ledger
// shared by every mounted volume in the container, while each volume keeps an
// independent MetadataStore session (namespace, WAL/status/recovery identity,
// mount state). C++17-clean: FsHost builds at C++17.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "ApfsContainerCatalog.h"
#include "MetadataStore.h"

namespace apfsaccess::rw
{
class BlockDevice;
} // namespace apfsaccess::rw

namespace apfsaccess::catalog
{

struct ContainerVolumeSession
{
    std::uint64_t volume_object_id = 0;
    std::string container_uuid_hex; // must match the opened container
    std::string mount_point; // opaque routing label, UTF-8
    bool requested_write = false;
    std::string recovery_identity; // opaque per-volume identity, may be empty
    // Selects CommitCanonicalTransaction inside Commit (FsHost canonical
    // gate); false uses CommitTransaction. Mount loads canonical state.
    bool use_canonical_transaction = false;
    // FsHost supplies the same metadata policy used by the legacy path.
    // The coordinator overwrites device and selected-volume identity fields.
    apfsaccess::rw::MetadataStore::VolumeContext metadata_context;
};

struct ContainerCommitResult
{
    bool committed = false;
    std::string error;
    std::uint64_t checkpoint_xid = 0;
    // Mirrors the session store outcome so hosts keep their bookkeeping
    // (timeouts, perf, recovery latching) identical to direct commits.
    int commit_status_code = static_cast<int>(
        apfsaccess::rw::MetadataStore::CommitStatus::NotReady);
    std::string commit_stage;
    std::uint64_t committed_xid = 0;
    std::wstring commit_recovery_reason;
    bool commit_recovery_required = false;
    std::vector<apfsaccess::rw::MetadataStore::PayloadIdentity>
        staged_identities;
};

using ContainerPrepublicationHook = std::function<bool(
    const std::vector<apfsaccess::rw::MetadataStore::MutationRequest>&,
    const std::vector<apfsaccess::rw::MetadataStore::PayloadIdentity>&,
    std::string& out_error)>;

struct ContainerShutdownResult
{
    bool clean = false;
    std::string error;
};

struct ManifestVolumeEntry
{
    std::uint64_t object_id = 0;
    std::string container_uuid_hex;
    std::string name_utf8;
    std::string mount_point;
    bool requested_write = false;
    std::string recovery_identity;
};

struct ContainerManifest
{
    std::string container_uuid_hex;
    std::string manifest_sha256;
    std::string device_path;
    std::uint64_t device_offset_bytes = 0;
    std::vector<ManifestVolumeEntry> volumes;
};

// Protected session manifest: checksum-covered JSON (see format comment on
// ParseContainerManifest). Rejects symlinks, schema violations, container
// mismatches, and unknown/duplicate volume OIDs.
[[nodiscard]] bool ParseContainerManifest(
    const std::string& manifest_path,
    ContainerManifest& out_manifest,
    std::string& out_error);

class ContainerMountCoordinator
{
public:
    // Opens one raw lease on (device_path, device_offset) and loads the
    // catalog, requiring exactly one container. Fails closed otherwise.
    [[nodiscard]] static std::unique_ptr<ContainerMountCoordinator> Open(
        const std::string& device_path,
        std::uint64_t device_offset_bytes,
        std::string& out_error,
        CatalogLoadPolicy catalog_load_policy = CatalogLoadPolicy::StrictApple,
        bool require_writable_lease = false);

    ContainerMountCoordinator(const ContainerMountCoordinator&) = delete;
    ContainerMountCoordinator& operator=(const ContainerMountCoordinator&) = delete;
    ~ContainerMountCoordinator();

    // Mounts one volume session (reader projection via catalog, container-
    // qualified). Fails closed on unknown OIDs, container mismatch, and
    // duplicate mounts. Sibling sessions are untouched.
    [[nodiscard]] bool MountVolume(
        const ContainerVolumeSession& session, std::string& out_error);
    // Unmounts one session without touching siblings or shared state.
    // Unknown OIDs fail closed.
    [[nodiscard]] bool UnmountVolume(std::uint64_t volume_object_id, std::string& out_error);

    // Serializes one commit for the given mounted volume: stages the
    // mutations, commits the session store (canonical transaction when the
    // session requested it), records allocation ranges in the shared ledger
    // (overlap fails closed into recovery-required), and advances the
    // container xid. An empty batch
    // commits whatever the session holds (usually NothingToCommit).
    // Rejected once draining starts.
    [[nodiscard]] ContainerCommitResult Commit(
        std::uint64_t volume_object_id,
        const std::vector<apfsaccess::rw::MetadataStore::MutationRequest>&
            mutations,
        const ContainerPrepublicationHook& prepublication_hook = {});

    // Re-syncs the container checkpoint from a mounted session (hosts call
    // this after startup replay, which commits directly while sessions mount
    // sequentially). Fails closed on unknown volumes.
    [[nodiscard]] bool RefreshCheckpointFromSession(
        std::uint64_t volume_object_id, std::string& out_error);

    // Rejects new work, drains in-flight commits, destroys sessions, and
    // drops the raw lease. Bounded by timeout.
    [[nodiscard]] ContainerShutdownResult DrainAndStop(std::chrono::milliseconds timeout);

    [[nodiscard]] std::uint64_t OwnerProcessId() const noexcept;
    [[nodiscard]] bool RawLeaseHeld() const noexcept;
    [[nodiscard]] std::size_t MountedVolumeCount() const;
    [[nodiscard]] std::uint64_t CheckpointXid() const noexcept;
    [[nodiscard]] const std::string& ContainerUuidHex() const noexcept;
    [[nodiscard]] const apfsaccess::rw::BlockDevice& Device() const noexcept;
    // Non-owning session lookup for host provider wiring and read models.
    // Valid only while the volume stays mounted; commits must go through
    // Commit (direct session commits bypass serialization and the ledger).
    [[nodiscard]] apfsaccess::rw::MetadataStore* FindSessionStore(
        std::uint64_t volume_object_id) noexcept;
    [[nodiscard]] bool IsRecoveryRequired() const noexcept;
    [[nodiscard]] std::optional<std::uint64_t> RecoveryVolumeObjectId() const noexcept;
    [[nodiscard]] std::string RecoveryReason() const;
    [[nodiscard]] std::uint64_t MaxObservedCommitConcurrency() const noexcept;

    struct ExtentRange
    {
        std::uint64_t address = 0;
        std::uint64_t bytes = 0;
    };

    // Pure overlap predicate behind the shared extent ledger (public for
    // unit coverage; the recording path stays inside Commit).
    [[nodiscard]] static bool RangesOverlap(
        const ExtentRange& left, const ExtentRange& right) noexcept;
    [[nodiscard]] static bool ApplyExtentDelta(
        std::vector<ExtentRange>& ledger,
        const std::vector<ExtentRange>& allocations,
        const std::vector<ExtentRange>& deallocations,
        std::string& out_error);

private:
    ContainerMountCoordinator() = default;

    struct SessionState;

    bool ReloadSessionForCommitNoLock(
        SessionState& session, std::string& out_error);
    bool RecordCommitRangesNoLock(
        const std::vector<ExtentRange>& allocations,
        const std::vector<ExtentRange>& deallocations,
        std::string& out_error);

    std::shared_ptr<apfsaccess::rw::BlockDevice> device_;
    bool writable_lease_required_ = false;
    CatalogLoadPolicy catalog_load_policy_ = CatalogLoadPolicy::StrictApple;
    std::uint64_t device_offset_bytes_ = 0;
    std::string container_uuid_hex_;
    std::vector<std::uint64_t> container_volume_oids_;
    std::atomic<std::uint64_t> checkpoint_xid_{0};
    std::uint64_t owner_process_id_ = 0;
    mutable std::mutex mutex_;
    std::timed_mutex commit_mutex_;
    bool draining_ = false;
    bool recovery_required_ = false;
    std::optional<std::uint64_t> recovery_volume_object_id_;
    std::string recovery_reason_;
    std::vector<std::unique_ptr<SessionState>> sessions_;
    std::vector<ExtentRange> committed_ranges_;
    std::atomic<std::uint64_t> in_flight_commits_{0};
    std::atomic<std::uint64_t> max_commit_concurrency_{0};
};

} // namespace apfsaccess::catalog
