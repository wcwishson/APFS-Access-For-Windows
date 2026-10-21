#pragma once
#include "NativeSnapshotIntent.h"
#include "TransactionManager.h"
#include <memory>
#include <span>
#include <functional>

namespace apfsaccess::catalog { class ContainerMountCoordinator; }
namespace apfsaccess::rw {
class MetadataStore;
struct RawSnapshotRuntimeAccess;

struct RawSnapshotRuntimePeerOwner {
    std::uint64_t volume_oid = 0;
    MetadataStore* store = nullptr;
    TransactionManager* journal = nullptr;
    std::wstring journal_path;
};

// Only the capture factories can create this proof. The host retains the
// coordinator and every original peer and holds their metadata/journal gates
// during capture, inspection, preparation, apply, replay and completion verification.
class RawSnapshotRuntimeAuthority final {
public:
    RawSnapshotRuntimeAuthority(const RawSnapshotRuntimeAuthority&) = delete;
    RawSnapshotRuntimeAuthority& operator=(const RawSnapshotRuntimeAuthority&) = delete;
private:
    friend struct RawSnapshotRuntimeAccess;
    struct State;
    explicit RawSnapshotRuntimeAuthority(std::shared_ptr<const State> state) : state_(std::move(state)) {}
    std::shared_ptr<const State> state_;
};

bool CaptureRawSnapshotRuntimeAuthority(catalog::ContainerMountCoordinator&,
    std::span<const RawSnapshotRuntimePeerOwner>, const RawHardwareQualification&,
    std::shared_ptr<const RawSnapshotRuntimeAuthority>&, std::string&);

// Engine restart admission after the host has fenced and authenticated startup
// evidence. Re-reads the original existing WAL under its live owner and matches
// the complete transaction. This does not implement the host's pre-seed fence:
// SetJournalPath can already have repaired a torn tail before this call.
bool CaptureRawSnapshotRuntimeRestartAuthority(catalog::ContainerMountCoordinator&,
    std::span<const RawSnapshotRuntimePeerOwner>, const RawHardwareQualification&,
    const TransactionManager::AcceptedTransaction&,
    std::shared_ptr<const RawSnapshotRuntimeAuthority>&, std::string&);

struct RawSnapshotRuntimeReplayParameters {
    std::shared_ptr<const RawSnapshotRuntimeAuthority> authority;
    std::uint64_t accepted_sequence = 0;
};

// Minted only by real runtime acceptance or the engine's authenticated fresh
// restart admission. Serialized caller fields cannot create it. Publication
// recovery returns this token while the selected completion latch stays set.
class RawSnapshotRuntimeRecoveryToken final {
public:
    RawSnapshotRuntimeRecoveryToken(const RawSnapshotRuntimeRecoveryToken&) = delete;
    RawSnapshotRuntimeRecoveryToken& operator=(const RawSnapshotRuntimeRecoveryToken&) = delete;
private:
    friend struct RawSnapshotRuntimeAccess;
    friend class catalog::ContainerMountCoordinator;
    bool AcceptanceStarted() const noexcept;
    void CaptureSelectedState(const MetadataStore&) const noexcept;
    bool CaptureVerifiedPublication(const MetadataStore&) const noexcept;
    struct State;
    explicit RawSnapshotRuntimeRecoveryToken(std::shared_ptr<State> state) : state_(std::move(state)) {}
    std::shared_ptr<State> state_;
};

// Runs under the original coordinator serializer and all host peer gates.
// Called after APFS durability, before WAL cleanup. The host completes its
// selected spool/marker work idempotently and keeps user writes disabled.
// No coordinator reentry. False/throw retains the latch and permits a retry
// with the same token; it never republishes the snapshot.
// The hook must not append or compact any original peer WAL; only the engine's
// exact selected durability/cleanup records may extend the captured history.
using RawSnapshotRuntimeCompletionHook = std::function<bool(std::string&)>;

// Preflight only: acquires coordinator lookups/census and must never be called
// from a Commit hook. Locked runtime checks use captured original peers instead.
bool VerifyRawSnapshotRuntimeAuthority(const std::shared_ptr<const RawSnapshotRuntimeAuthority>&,
    catalog::ContainerMountCoordinator&, const NativeSnapshotIntent&, std::string&);
}
