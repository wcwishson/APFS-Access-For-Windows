#pragma once

// Define APFSACCESS_COORDINATOR_SHARED_SPACE_ONLY before including this header
// in a C++17 read-model translation unit. It exposes an opaque coordinator and
// the copied snapshot lookup without the engine's C++20 MetadataStore headers.
// Use a separate translation unit for the full lifecycle/mutation interface.
#include <cstdint>
#include <optional>
#include <string_view>

namespace apfsaccess::catalog
{
class ContainerMountCoordinator;

// A copied observation of one volume's share of a single durable container
// checkpoint. Total is the container total; available includes the selected
// volume's quota and sibling reserves. Never sum sibling available values.
struct ContainerVolumeSpaceSnapshot
{
    std::uint64_t volume_object_id = 0;
    std::uint64_t checkpoint_xid = 0;
    std::uint64_t total_bytes = 0;
    std::uint64_t available_bytes = 0;
    std::uint32_t allocation_unit_bytes = 0;
};

// C++17 opaque-owner facade for LookupSharedSpace below. Null owner/unknown
// identity returns nullopt. Caller must retain the owner's lifetime. No locks
// on coordinator/session state, allocation, or I/O; a bounded copied result.
[[nodiscard]] std::optional<ContainerVolumeSpaceSnapshot> LookupContainerSharedSpace(
    const ContainerMountCoordinator* coordinator, std::string_view container_uuid_hex,
    std::uint64_t volume_object_id) noexcept;
} // namespace apfsaccess::catalog

#if !defined(APFSACCESS_COORDINATOR_SHARED_SPACE_ONLY)

// One safe RW owner per APFS container: a single raw-device lease, one
// container identity/checkpoint, one commit serializer, and one extent ledger
// shared by every mounted volume in the container, while each volume keeps an
// independent MetadataStore session (namespace, WAL/status/recovery identity,
// mount state). Full engine policy types currently require C++20; the snapshot
// facade above and its shared_ptr atomic publication use C++17 facilities.

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "ApfsContainerCatalog.h"
#include "MetadataStore.h"

namespace apfsaccess::rw
{
class BlockDevice;
class RawSnapshotRuntimeRecoveryToken;
struct RawSnapshotRuntimeAccess;
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

// Capture only request selectors, never inline or deferred payload bytes.
struct ContainerMutationStagingFailure
{
    std::size_t mutation_index = 0;
    apfsaccess::rw::MetadataStore::MutationOperation operation{};
    std::wstring path;
    std::wstring secondary_path;
    std::uint64_t offset = 0;
    std::uint64_t length = 0;
    std::wstring reason;
};

struct ContainerCommitResult
{
    // Publication occurred (or NothingToCommit). A postpublication verifier
    // failure keeps this true, with InvariantFailed and recovery required;
    // callers must check status/recovery before acknowledging durable work.
    bool committed = false;
    // WAL acceptance completed, but APFS checkpoint publication was deliberately
    // deferred until the close/quiet boundary. This is success for the
    // acceptance phase only; callers must not treat it as published data.
    bool accepted_without_publication = false;
    std::string error;
    std::uint64_t checkpoint_xid = 0;
    // Mirrors the session store outcome so hosts keep their bookkeeping
    // (timeouts, perf, recovery latching) identical to direct commits.
    int commit_status_code = static_cast<int>(
        apfsaccess::rw::MetadataStore::CommitStatus::NotReady);
    std::string commit_stage;
    // Latest committed XID observed by the store; NothingToCommit can report
    // the existing checkpoint here. Only CommitStatus::Committed proves a
    // new publication (or an explicit postpublication-verifier failure).
    std::uint64_t committed_xid = 0;
    std::wstring commit_recovery_reason;
    bool commit_recovery_required = false;
    // Positive evidence for this attempt only: publication/binding never ran,
    // and the selected native store was untouched and clean or successfully
    // reloaded after refusal. False includes unknown phase and failed rollback.
    // Never set for accepted replay or a failure after the prepublication hook,
    // even when commit reports no device I/O. Older WAL/census debt is unchanged.
    bool clean_prepublication_refusal = false;
    // Preserve the staging failure separately from the legacy commit status;
    // phase-aware callers can identify capacity refusal without parsing text.
    std::optional<apfsaccess::rw::MetadataStore::MutationStatus> mutation_staging_status;
    // First refused staged request, copied before rollback/reload. Admission
    // and hook failures have no staging-failure packet.
    std::optional<ContainerMutationStagingFailure> mutation_staging_failure;
    std::vector<apfsaccess::rw::MetadataStore::PayloadIdentity>
    staged_identities;
};

// Always-on, in-memory counters for completed coordinator scopes. Successes
// exclude NothingToCommit; failures include admission rejection and exceptions.
// Microseconds use steady_clock. Commit total = wait + hold; reload time is
// nested within hold (except recovery refresh), so do not add it to commit time.
// Reloads exclude mount preparation and MetadataStore's post-publication load.
struct ContainerCommitDiagnostics
{
    std::uint64_t commit_attempts = 0;
    std::uint64_t commit_successes = 0;
    std::uint64_t commit_noops = 0;
    std::uint64_t commit_deferred_acceptances = 0;
    std::uint64_t commit_failures = 0;
    std::string last_failure_stage;
    std::string last_failure_detail;
    std::uint64_t commit_total_us = 0;
    std::uint64_t commit_max_us = 0;
    std::uint64_t commit_wait_total_us = 0;
    std::uint64_t commit_hold_total_us = 0;
    std::uint64_t reload_attempts = 0;
    std::uint64_t reload_failures = 0;
    // Counted when the owner-local generation and store state epoch prove
    // that a precommit reload can be safely reused after a successful
    // publication. Rollback and recovery repair reloads remain conservative.
    std::uint64_t reload_reuses = 0;
    std::uint64_t reload_total_us = 0;
    std::uint64_t reload_max_us = 0;
    std::uint64_t precommit_reload_attempts = 0;
    std::uint64_t rollback_reload_attempts = 0;
    std::uint64_t recovery_reload_attempts = 0;
};

struct VolumeCheckpointPins
{
    std::uint64_t volume_object_id = 0;
    std::vector<std::uint64_t> required_checkpoint_xids;
    bool unapplied_accepted_work = false;
};

// Delete requests carry the unlink outcome captured by the selected session's
// staging pass. The hook persists it with the matching identity before publish
// and returns that volume's refreshed accepted-WAL checkpoint pins.
using ContainerPrepublicationHook = std::function<bool(
    const std::vector<apfsaccess::rw::MetadataStore::MutationRequest>&,
    const std::vector<apfsaccess::rw::MetadataStore::PayloadIdentity>&,
    std::uint64_t preimage_checkpoint_xid,
    std::vector<std::uint64_t>& out_required_checkpoint_xids,
    std::string& out_error)>;

using ContainerMutationStagingHook = std::function<bool(
    std::size_t mutation_index,
    const apfsaccess::rw::MetadataStore::MutationRequest&,
    const apfsaccess::rw::MetadataStore::PayloadIdentity&,
    std::string& out_error)>;

// Read-only request builder, invoked once while Commit owns the container,
// after admission/census/reload and before any staging. The vector is a local
// copy of Commit's input; replace/extend it with the exact source request and
// ensuing same-owner mutations (e.g. CRW1, content times, write). Return true
// with an empty error only for a complete batch. No staging, store/device
// writes, WAL acceptance, coordinator reentry, or retained store/vector
// references are allowed. The host must also hold its exclusive metadata/read
// gate. This grants no independently writable session.
// Bounds apply only when this optional builder is present; ordinary Commit
// callers retain their existing limits. A new Commit must rebuild evidence;
// the internal no-I/O retention retry keeps this exact staged batch.
inline constexpr std::size_t ContainerPreparedMutationLimit = 3;
inline constexpr std::size_t ContainerPreparedInlineByteLimit = 17u << 20;
inline constexpr std::size_t ContainerPreparedPathCharLimit = 32768;
using ContainerMutationPreparationHook = std::function<bool(
    const apfsaccess::rw::MetadataStore& live_store,
    std::vector<apfsaccess::rw::MetadataStore::MutationRequest>& requests,
    std::string& out_error)>;

// Optional read-only verification of the immediate published native image.
// Runs at most once, only after Committed and the store's publication/reload,
// under commit_mutex_ (which also protects session/store lifetime), after
// checkpoint/ledger accounting and before resolving accepted work. No sibling
// can publish until it returns. The host retains its metadata/read gate and
// may acquire its transaction mutex here to verify accepted WAL evidence.
// No coordinator reentry, staging, pin cleanup, WAL durability marking, or
// retained store references. True requires an empty error. False/throw/error
// preserves publication and accepted census, latches container recovery, and
// returns committed=true, InvariantFailed, stage "postpublication-verifier".
// There is no rollback reload, second publication, or retry after this hook.
using ContainerPostpublicationVerifierHook = std::function<bool(
    const apfsaccess::rw::MetadataStore& live_store,
    std::uint64_t committed_xid,
    std::string& out_error)>;

// Runs at most once under the container commit lock after no-I/O retention
// pressure. True means the returned census is authoritative (not necessarily
// changed) and out_error is empty. May release only this volume's durably cleaned
// WAL pins; must not reenter the coordinator or discard the pending source.
// False can follow irreversible journal cleanup: keep conservative pins and
// fail closed; do not roll back durable cleanup or retry publication.
using ContainerRetentionCleanupHook = std::function<bool(
    std::vector<std::uint64_t>& out_required_checkpoint_xids,
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
    bool initially_active = true;
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

// A retained reader owns the same device lease and a checkpoint pin. Keep this
// object alive for every read; a copied descriptor alone owns no storage.
// The coordinator must also remain alive. Destruction and successful drain close
// readers before releasing history. Drain retains ownership on timeout.
class SnapshotRuntimeReader final {
public:
    SnapshotRuntimeReader()=default;
    SnapshotRuntimeReader(const SnapshotRuntimeReader&)=delete;
    SnapshotRuntimeReader& operator=(const SnapshotRuntimeReader&)=delete;
    const apfsaccess::rw::NativeApfsSnapshotProjection& Projection() const { return *projection_; }
    bool Read(std::uint64_t inode,std::uint64_t offset,std::size_t size,std::vector<std::byte>& out) const;
private:
    friend class ContainerMountCoordinator;
    mutable std::timed_mutex read_mutex_;
    mutable bool closed_=true;
    void Close() const {
        std::lock_guard<std::timed_mutex> lock(read_mutex_);closed_=true;device_.reset();
    }
    bool CloseUntil(std::chrono::steady_clock::time_point deadline) const {
        std::unique_lock<std::timed_mutex> lock(read_mutex_,std::defer_lock);
        if(!lock.try_lock_until(deadline))return false;
        closed_=true;device_.reset();return true;
    }
    mutable std::shared_ptr<apfsaccess::rw::BlockDevice> device_;
    std::shared_ptr<const apfsaccess::rw::NativeApfsSnapshotProjection> projection_;
    std::uint64_t checkpoint_=0,volume_=0;
};
class ContainerMountCoordinator
{
public:
    // Opens one raw lease on (device_path, device_offset) and loads the
    // catalog, requiring exactly one container. Fails closed otherwise.
    // When admit_raw_device_writer is set, a non-regular source may be
    // promoted to a deny-write bound writer (GPT/APFS binding, container
    // clamp, NXSB revalidation) instead of failing the writable lease.
    // Default-closed; test-only overrides never enable this path.
    [[nodiscard]] static std::unique_ptr<ContainerMountCoordinator> Open(
        const std::string& device_path,
        std::uint64_t device_offset_bytes,
        std::string& out_error,
        CatalogLoadPolicy catalog_load_policy = CatalogLoadPolicy::StrictApple,
        bool require_writable_lease = false,
        bool require_checkpoint_census = false,
        bool exclusive_management_image = false,
        bool admit_raw_device_writer = false);

    // Uses the command's retained exclusive ordinary-image object, never a new path open.
    [[nodiscard]] static std::unique_ptr<ContainerMountCoordinator> OpenRepairImage(
        std::shared_ptr<apfsaccess::rw::BlockDevice> image, std::string& error);
    std::vector<std::uint64_t> SnapshotRuntimeCheckpointPins() const;
    std::shared_ptr<const SnapshotRuntimeReader> AcquireSnapshotReader(const ApfsSnapshotIdentity&,std::string&);
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

    // Required mode stays closed until one atomic census represents every
    // catalog volume, including read-only and currently unmounted volumes.
    [[nodiscard]] bool CheckpointCensusRequired() const noexcept;
    // Copies the exact per-volume pins and unresolved acceptance flags under
    // commit ownership, including after recovery is latched. Do not call from
    // a Commit hook, which already owns that lock.
    [[nodiscard]] std::vector<VolumeCheckpointPins> CheckpointCensusSnapshot() const;
    [[nodiscard]] bool InitializeRequiredCheckpointCensus(
        const std::vector<VolumeCheckpointPins>& volume_pins,
        std::string& out_error);
    // Replaces one volume's pins only after its durable cleanup has authorized
    // release. Pin state is catalog-owned and survives session unmount.
    [[nodiscard]] bool UpdateRequiredCheckpointXids(
        std::uint64_t volume_object_id,
        const std::vector<std::uint64_t>& required_checkpoint_xids,
        std::string& out_error,
        bool unapplied_accepted_work = false);

    // Serializes one commit for the given mounted volume: stages the
    // mutations, commits the session store (canonical transaction when the
    // session requested it), records allocation ranges in the shared ledger
    // (overlap fails closed into recovery-required), and advances the
    // container xid. Without a preparation builder, an empty batch
    // commits whatever the session holds (usually NothingToCommit).
    // Rejected once draining starts. Unresolved accepted work blocks ordinary
    // publication. A host-validated replay may cross unresolved siblings only
    // when the selected volume's census entry is also unresolved; every
    // sibling pin remains retained until its own durable cleanup update.
    [[nodiscard]] ContainerCommitResult Commit(
        std::uint64_t volume_object_id,
        const std::vector<apfsaccess::rw::MetadataStore::MutationRequest>&
            mutations,
        const ContainerPrepublicationHook& prepublication_hook = {},
        const ContainerMutationStagingHook& mutation_staging_hook = {},
        const ContainerRetentionCleanupHook& retention_cleanup_hook = {},
        bool accepted_replay = false,
        std::optional<std::uint64_t> expected_replay_preimage = std::nullopt,
        const ContainerMutationPreparationHook& mutation_preparation_hook = {},
        const ContainerPostpublicationVerifierHook& postpublication_verifier_hook = {},
        bool retain_accepted_owner_until_cleanup = false,
        bool defer_publication = false);

    // Refreshes the borrowed store before startup recovery examines retained
    // history. Pending mutations are refused rather than discarded.
    [[nodiscard]] bool RefreshSessionForRecovery(std::uint64_t volume_object_id,
        std::string& out_error);

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
    // One immutable snapshot load and a bounded identity/volume lookup. No
    // metadata, state or commit locks, device I/O, or allocation. UUID must be
    // exactly 32 hex characters (either case). Nullopt means unknown, including
    // legacy fixtures, invalid identity, invalidation and drain. Covers catalog
    // volumes, even before mount. A concurrent commit may expose a complete
    // prior durable observation or unknown; its completion updates all siblings.
    // The caller must keep this coordinator alive throughout the call.
    [[nodiscard]] std::optional<ContainerVolumeSpaceSnapshot> LookupSharedSpace(
        std::string_view container_uuid_hex, std::uint64_t volume_object_id) const noexcept;
    [[nodiscard]] const std::string& ContainerUuidHex() const noexcept;
    [[nodiscard]] const apfsaccess::rw::BlockDevice& Device() const noexcept;
    // Non-owning session lookup for host provider wiring and read models.
    // Valid only while the volume stays mounted; commits must go through
    // Commit (direct session commits bypass serialization and the ledger).
    [[nodiscard]] apfsaccess::rw::MetadataStore* FindSessionStore(
        std::uint64_t volume_object_id) noexcept;
    // Owner-derived canonical journal identity for a mounted session:
    // "apfs-vol:<container_uuid_hex>:<volume_object_id>", built only from the
    // loaded container UUID and the catalog-resolved OID. False when unmounted.
    // Maintenance must prove ownership against this identity, never against a
    // caller-supplied string.
    [[nodiscard]] bool SessionCanonicalJournalIdentity(
        std::uint64_t volume_object_id, std::string& out_identity) const;
    // Original recovery storage identity from MountVolume, never from a
    // mutable journal configuration or caller-supplied receipt.
    [[nodiscard]] bool SessionRecoveryIdentity(
        std::uint64_t volume_object_id, std::string& out_identity) const;
    // Read-only callback under the same serializer as publication/unmount.
    // Requires a clean complete census and an already-current canonical store.
    // Callback must not reenter the coordinator or retain store references.
    [[nodiscard]] bool InspectCurrentSession(std::uint64_t volume_object_id,
        const std::function<bool(const apfsaccess::rw::MetadataStore&, std::string&)>& inspect,
        std::string& out_error, bool accepted_replay = false);
    // Read-only verification may inspect the newest published checkpoint while
    // a clean sibling's namespace remains lazily loaded at an older checkpoint.
    // Every session must be clean, canonical and on this retained device; the
    // latest view must resolve the selected volume's unchanged UUID/OID. The
    // callback may only read the source under the caller's full host gates. It
    // grants no mutation/repair authority and must not retain either reference.
    [[nodiscard]] bool InspectPublishedCheckpointForVerification(std::uint64_t volume_object_id,
        const std::function<bool(const apfsaccess::rw::MetadataStore&,
            const AppleCheckpointView&, std::string&)>& inspect, std::string& out_error);
    [[nodiscard]] std::weak_ptr<const std::uint8_t> LifetimeToken() const noexcept { return lifetime_token_; }
    [[nodiscard]] bool IsRecoveryRequired() const noexcept;
    [[nodiscard]] std::optional<std::uint64_t> RecoveryVolumeObjectId() const noexcept;
    [[nodiscard]] std::string RecoveryReason() const;
    [[nodiscard]] std::uint64_t MaxObservedCommitConcurrency() const noexcept;

    // Cumulative over this coordinator's lifetime, including unmount/remount
    // and drain. Nullopt selects container totals (including unknown-OID
    // rejections); a catalog OID selects that volume, unknown OIDs return zero.
    // Takes only the short state mutex, so status readers and commit hooks can
    // sample without waiting for device I/O. An active scope appears on exit;
    // use quiescent before/after samples for exact cross-counter deltas.
    [[nodiscard]] ContainerCommitDiagnostics DiagnosticsSnapshot(
        std::optional<std::uint64_t> volume_object_id = std::nullopt) const;

    // Atomic counters only; no device I/O or commit-lock acquisition. The state
    // lock protects the device lifetime against concurrent drain.
    [[nodiscard]] std::string DevicePerformanceJson() const;

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
    friend struct apfsaccess::rw::RawSnapshotRuntimeAccess;
    friend struct RawSnapshotRuntimeRecoveryTestPeer;
    struct RawSnapshotPeerObservation {
        std::uint64_t oid = 0;
        apfsaccess::rw::MetadataStore* store = nullptr;
        std::string canonical_identity;
        std::string recovery_identity;
        VolumeCheckpointPins census;
        bool canonical_writer = false;
    };
    std::vector<RawSnapshotPeerObservation> ObserveRawSnapshotPeersNoLock() const;
    bool ReloadRawSnapshotRecoveryNoLock(std::uint64_t, std::string&);
    void AccountRawSnapshotRecoveryNoLock(std::uint64_t);
    ContainerCommitResult CommitRawSnapshot(std::uint64_t,
        const std::vector<apfsaccess::rw::MetadataStore::MutationRequest>&,
        const ContainerPrepublicationHook&, const ContainerMutationPreparationHook&,
        const ContainerPostpublicationVerifierHook&,
        const std::shared_ptr<const apfsaccess::rw::RawSnapshotRuntimeRecoveryToken>&);
    ContainerCommitResult CommitNoLock(std::uint64_t,
        const std::vector<apfsaccess::rw::MetadataStore::MutationRequest>&,
        const ContainerPrepublicationHook&, const ContainerMutationStagingHook&,
        const ContainerRetentionCleanupHook&, bool, std::optional<std::uint64_t>,
        const ContainerMutationPreparationHook&, const ContainerPostpublicationVerifierHook&,
        bool, bool,
        const std::shared_ptr<const apfsaccess::rw::RawSnapshotRuntimeRecoveryToken>& candidate = {},
        const std::shared_ptr<const apfsaccess::rw::RawSnapshotRuntimeRecoveryToken>& recovery = {},
        std::chrono::steady_clock::time_point started = std::chrono::steady_clock::now());
    std::shared_ptr<const apfsaccess::rw::RawSnapshotRuntimeRecoveryToken> raw_snapshot_recovery_;
    std::string raw_snapshot_recovery_reason_;
    static std::unique_ptr<ContainerMountCoordinator> OpenHeldImage(
        std::shared_ptr<apfsaccess::rw::BlockDevice>, std::uint64_t, std::string&,
        CatalogLoadPolicy, bool, bool);
    ContainerMountCoordinator() = default;

    struct SessionState;
    struct ScopedCommitDiagnostics;
    struct ScopedReloadDiagnostics;
    enum class ReloadReason { BeforeCommit, Rollback, Recovery };

    // Writers own commit_mutex_ (or are constructing Open). The only reader
    // surface copies primitive values. C++17 shared_ptr atomic free functions
    // protect pointer publication; no coordinator lock is acquired by readers.
    void InvalidateSharedSpaceNoLock() noexcept;
    void PublishSharedSpaceNoLock(const AppleCheckpointView* checkpoint,
        bool freshly_loaded) noexcept;
    std::shared_ptr<const ApfsSharedSpaceProjection> shared_space_snapshot_;
    std::uint64_t shared_space_high_water_xid_ = 0;
    bool shared_space_invalidated_ = true;
    // Drain sets this before waiting for commit ownership. In-flight publishers
    // cannot revive observations after shutdown, including a timed-out drain.
    std::atomic<bool> shared_space_stopped_{false};

    bool ReloadSessionForCommitNoLock(
        SessionState& session, std::string& out_error,
        ReloadReason reason = ReloadReason::Rollback);
    [[nodiscard]] ContainerCommitDiagnostics* FindVolumeDiagnosticsNoLock(
        std::uint64_t volume_object_id) noexcept;
    bool RecordCommitRangesNoLock(
        const std::vector<ExtentRange>& allocations,
        const std::vector<ExtentRange>& deallocations,
        std::string& out_error);
    [[nodiscard]] VolumeCheckpointPins* FindVolumeCheckpointPinsNoLock(
        std::uint64_t volume_object_id) noexcept;
    [[nodiscard]] const VolumeCheckpointPins* FindVolumeCheckpointPinsNoLock(
        std::uint64_t volume_object_id) const noexcept;
    [[nodiscard]] std::vector<std::uint64_t>
        RequiredCheckpointXidUnionNoLock() const;

    std::vector<std::weak_ptr<const SnapshotRuntimeReader>> snapshot_readers_;
    std::shared_ptr<apfsaccess::rw::BlockDevice> device_;
    const std::shared_ptr<const std::uint8_t> lifetime_token_ = std::make_shared<const std::uint8_t>(0);
    bool writable_lease_required_ = false;
    CatalogLoadPolicy catalog_load_policy_ = CatalogLoadPolicy::StrictApple;
    std::uint64_t device_offset_bytes_ = 0;
    std::string container_uuid_hex_;
    std::vector<std::uint64_t> container_volume_oids_;
    bool require_checkpoint_census_ = false;
    bool checkpoint_census_initialized_ = true;
    std::vector<VolumeCheckpointPins> volume_checkpoint_pins_;
    std::atomic<std::uint64_t> checkpoint_xid_{0};
    // Owner-local publication generation for bounded prepared-session reuse.
    // A sibling publication advances it and invalidates every other session.
    std::uint64_t commit_generation_ = 0;
    std::uint64_t owner_process_id_ = 0;
    mutable std::mutex mutex_;
    mutable std::timed_mutex commit_mutex_;
    bool draining_ = false;
    bool recovery_required_ = false;
    std::optional<std::uint64_t> recovery_volume_object_id_;
    std::string recovery_reason_;
    std::vector<std::unique_ptr<SessionState>> sessions_;
    // Fixed catalog-sized storage: recording a scope never allocates.
    struct VolumeDiagnostics
    {
        std::uint64_t volume_object_id = 0;
        ContainerCommitDiagnostics counters;
    };
    ContainerCommitDiagnostics diagnostics_;
    std::vector<VolumeDiagnostics> volume_diagnostics_;
    std::vector<ExtentRange> committed_ranges_;
    std::atomic<std::uint64_t> in_flight_commits_{0};
    std::atomic<std::uint64_t> max_commit_concurrency_{0};
};

} // namespace apfsaccess::catalog

#endif // !APFSACCESS_COORDINATOR_SHARED_SPACE_ONLY
