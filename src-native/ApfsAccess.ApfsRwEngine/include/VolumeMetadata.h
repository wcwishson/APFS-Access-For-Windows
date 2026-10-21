#pragma once
#include "NativeVolumeRename.h"
#include "AppleVolumeTransaction.h"
#include "ContainerMountCoordinator.h"
#include "TransactionManager.h"

namespace apfsaccess::rw
{
// Caller holds its exclusive metadata/read gate for planning and application.
// The coordinator remains the only serialization and device publication owner.
struct VolumeRenamePlan
{
    MetadataStore::MutationRequest request;
    const catalog::ContainerMountCoordinator* owner = nullptr;
    std::chrono::steady_clock::time_point expires;
    bool consumed = false;
    // Native fault tests only. Returning true interrupts this exact boundary.
    std::function<bool(std::string_view)> fault_hook_for_tests;
    VolumeRenamePlan() = default;
    VolumeRenamePlan(const VolumeRenamePlan&) = delete;
    VolumeRenamePlan& operator=(const VolumeRenamePlan&) = delete;
private:
    friend struct VolumeMetadataPlanAccess;
    std::vector<std::byte> sealed_payload_;
    const MetadataStore* sealed_store_ = nullptr;
};

bool PrepareVolumeRename(catalog::ContainerMountCoordinator& owner, std::uint64_t oid,
    std::string_view label, VolumeRenamePlan& out, std::string& error);
bool ValidateVolumeRenameMutation(const MetadataStore& store,
    const MetadataStore::MutationRequest& request, std::string& error);
bool PlanVolumeRenameCheckpoint(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const NativeVolumeRename& rename,
    const std::vector<std::uint64_t>& pins, AppleVolumeTransactionPlan& out, std::string& error);
bool VolumeRenameFromWal(const WriteAheadLog::Record& record, MetadataStore::MutationRequest& out);
bool VerifyPublishedVolumeRename(const MetadataStore& store,
    const NativeVolumeRename& rename, std::string& error);

// Consumes the plan on every attempt. WAL acceptance occurs only in the
// coordinator's prepublication hook, after staging/capacity admission. Success
// requires canonical publication, retained-history verification and durable WAL
// finalization. Failures never change the caller's display label.
// Optional diagnostics only. Observer must not block, allocate, throw, acquire
// filesystem/coordinator locks, or do I/O; it cannot alter the commit outcome.
struct VolumeRenameObserver
{
    void* context = nullptr;
    void (*stage)(void*, const char*) noexcept = nullptr;
    void Mark(const char* name) const noexcept { if (stage) stage(context, name); }
};
catalog::ContainerCommitResult ApplyVolumeRename(catalog::ContainerMountCoordinator& owner,
    TransactionManager& journal, VolumeRenamePlan& plan, VolumeRenameObserver observer = {});
// nullopt means this WAL contains no volume rename. An isolated accepted rename
// is replayed through the same coordinator, or verified in retained history.
std::optional<bool> ReplayVolumeRename(catalog::ContainerMountCoordinator& owner,
    TransactionManager& journal, std::uint64_t oid, std::string& error);
// Operation 20: one atomic pair, measured in the container's allocation blocks.
// Image-only, snapshot-free current ownership census; zero clears each limit.
using VolumeQuotaReservePlan = VolumeRenamePlan;
bool PrepareVolumeQuotaReserve(catalog::ContainerMountCoordinator& owner, std::uint64_t oid,
    std::uint64_t quota_blocks, std::uint64_t reserve_blocks, VolumeQuotaReservePlan& out, std::string& error);
catalog::ContainerCommitResult ApplyVolumeQuotaReserve(catalog::ContainerMountCoordinator& owner,
    TransactionManager& journal, VolumeQuotaReservePlan& plan);
std::optional<bool> ReplayVolumeQuotaReserve(catalog::ContainerMountCoordinator& owner,
    TransactionManager& journal, std::uint64_t oid, std::string& error);

// Internal shared metadata dispatch, always through the canonical transaction.
bool ValidateVolumeMetadataMutation(const MetadataStore& store, const MetadataStore::MutationRequest& request, std::string& error);
bool PlanVolumeMetadataCheckpoint(const catalog::RandomAccessSource& source, const catalog::AppleCheckpointView& checkpoint,
    const NativeVolumeRename& intent, const std::vector<std::uint64_t>& pins, AppleVolumeTransactionPlan& out, std::string& error);

}
