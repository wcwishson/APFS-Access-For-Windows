#pragma once
#include "VolumeKeeperAdmission.h"
#include <memory>
#include <functional>
#include <array>

namespace apfsaccess::catalog { class RandomAccessSource; }

namespace apfsaccess::rw
{
class VolumePhysicalSource;
struct VolumeKeeperHistoryContext
{
    std::filesystem::path spool_root, recovery_root;
};
// A hash-checked namespace tuple only classifies storage. It grants no source,
// WAL cleanliness, retirement, or publication authority.
std::array<std::byte, 42> BuildVolumeKeeperNamespaceMaterial(std::string_view container_uuid,
    std::uint64_t oid, const RawSnapshotBinding* physical = nullptr);
void PersistVolumeKeeperNamespaceWitness(const std::filesystem::path& trusted_root,
    std::span<const std::byte> material);
struct VolumeKeeperHeldWal
{
    std::filesystem::path path;
    void* handle = nullptr;
};
std::string VolumeKeeperWalFileIdentity(const VolumeKeeperHeldWal&);

// Called only before native acceptance, with the keeper's source and complete
// original WAL leases still held. Never called by completed/accepted recovery.
void PersistVolumeKeeperHistoryProof(const std::filesystem::path& journal,
    std::span<const std::byte> prepared_frame, std::string_view held_identity,
    const std::vector<VolumeKeeperHeldWal>& original_wals,
    const std::function<bool(std::string_view)>& stage_hook = {});
// Replay only verifies and flushes an existing original certificate. It must
// never create replacement authorization from the currently opened WALs.
void ConfirmVolumeKeeperHistoryProof(const std::filesystem::path& journal,
    std::span<const std::byte> accepted_frame, std::string_view held_identity,
    const std::vector<VolumeKeeperHeldWal>& original_wals);

class VolumeKeeperHistoryLease final
{
public:
    struct Impl;
    explicit VolumeKeeperHistoryLease(std::unique_ptr<Impl>);
    ~VolumeKeeperHistoryLease();
    VolumeKeeperHistoryLease(const VolumeKeeperHistoryLease&) = delete;
    VolumeKeeperHistoryLease& operator=(const VolumeKeeperHistoryLease&) = delete;
    std::uint64_t CheckpointXid() const;
    const std::vector<VolumeKeeperHistoryMember>& Members() const;
    std::uint64_t MarkerCheckpointXid(const VolumeKeeperHistoryMember&) const;
private:
    std::unique_ptr<Impl> impl_;
};

// All values come from the actual keeper's exclusive source and journal handles.
// current_wals are hints matched to the verified native checkpoint. Borrowed WAL
// fences must retain their keeper leases until this lease is destroyed.
std::unique_ptr<VolumeKeeperHistoryLease> AcquireVolumeKeeperHistory(
    std::string_view held_identity, std::span<const std::byte> current_image,
    const std::filesystem::path& trusted_root,
    const std::vector<VolumeKeeperHistoryMember>& current_wals,
    const std::vector<VolumeKeeperHeldWal>& borrowed_wals = {},
    const std::filesystem::path& held_journal = {}, std::span<const std::byte> held_journal_bytes = {},
    const VolumeKeeperHistoryContext& context = {}, bool require_terminal = false, bool detached_observation = false);
// Source overload retains the caller's exact held image/window. It performs the
// same topology, complete journal history and original WAL proof checks.
std::unique_ptr<VolumeKeeperHistoryLease> AcquireVolumeKeeperHistory(
    std::string_view held_identity, const catalog::RandomAccessSource& current_image,
    const std::filesystem::path& trusted_root,
    const std::vector<VolumeKeeperHistoryMember>& current_wals,
    const std::vector<VolumeKeeperHeldWal>& borrowed_wals = {},
    const std::filesystem::path& held_journal = {}, std::span<const std::byte> held_journal_bytes = {},
    const VolumeKeeperHistoryContext& context = {}, bool require_terminal = false, bool detached_observation = false);
// This fence authorizes no APFS publication and exposes no continuation proof.
// Unaccepted cancellation can retain sibling WAL debt without consuming it.
class VolumeKeeperCancellationFence final
{
public:
    explicit VolumeKeeperCancellationFence(std::unique_ptr<VolumeKeeperHistoryLease> fence) : fence_(std::move(fence)) {}
private:
    std::unique_ptr<VolumeKeeperHistoryLease> fence_;
};
std::unique_ptr<VolumeKeeperCancellationFence> AcquireVolumeKeeperCancellationMarkers(
    std::string_view held_identity, std::span<const std::byte> current_image,
    const std::filesystem::path& held_journal, std::span<const std::byte> held_journal_bytes,
    const VolumeKeeperHistoryContext& context);
std::unique_ptr<VolumeKeeperCancellationFence> AcquireVolumeKeeperCancellationMarkers(
    std::string_view held_identity, const catalog::RandomAccessSource& current_image,
    const std::filesystem::path& held_journal, std::span<const std::byte> held_journal_bytes,
    const VolumeKeeperHistoryContext& context);
// The separate held capability supplies physical authority, including when the
// source argument is an immutable original reconstructed during recovery.
std::unique_ptr<VolumeKeeperHistoryLease> AcquireVolumeKeeperPhysicalHistory(
    const std::shared_ptr<VolumePhysicalSource>&, const catalog::RandomAccessSource& current,
    const std::filesystem::path& trusted_root,
    const std::vector<VolumeKeeperHistoryMember>& current_wals,
    const std::vector<VolumeKeeperHeldWal>& borrowed_wals = {},
    const std::filesystem::path& held_journal = {}, std::span<const std::byte> held_journal_bytes = {},
    const VolumeKeeperHistoryContext& context = {}, bool require_terminal = false);
std::unique_ptr<VolumeKeeperCancellationFence> AcquireVolumeKeeperPhysicalCancellationMarkers(
    const std::shared_ptr<VolumePhysicalSource>&, const catalog::RandomAccessSource& current,
    const std::filesystem::path& held_journal, std::span<const std::byte> held_journal_bytes,
    const VolumeKeeperHistoryContext& context);
std::string ObserveVolumeKeeperHistoryJson(const std::filesystem::path& image,
    const std::filesystem::path& trusted_root, const VolumeKeeperHistoryContext& context, bool& admitted);
class VolumePhysicalGeometrySource;
std::unique_ptr<VolumeKeeperHistoryLease> AcquireVolumeKeeperGeometryHistory(
    const std::shared_ptr<VolumePhysicalGeometrySource>&, const catalog::RandomAccessSource& current,
    const std::filesystem::path& trusted_root, const std::vector<VolumeKeeperHistoryMember>& current_wals,
    const std::vector<VolumeKeeperHeldWal>& borrowed_wals = {}, const std::filesystem::path& held_journal = {},
    std::span<const std::byte> held_journal_bytes = {}, const VolumeKeeperHistoryContext& context = {}, bool require_terminal = false);
std::unique_ptr<VolumeKeeperCancellationFence> AcquireVolumeKeeperGeometryCancellationMarkers(
    const std::shared_ptr<VolumePhysicalGeometrySource>&, const catalog::RandomAccessSource& current,
    const std::filesystem::path& journal, std::span<const std::byte> frame, const VolumeKeeperHistoryContext& context);
}
