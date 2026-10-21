#pragma once
#include "NativeSnapshotIntent.h"
#include "VolumeMetadata.h"
#include "RawSnapshotRuntimeAuthority.h"
namespace apfsaccess::rw {
// Prepare follows the existing metadata-owner gate contract: the caller holds
// its exclusive metadata gate while reading a session. Apply revalidates under
// the coordinator lock; a stale plan never grants acceptance or publication.
struct SnapshotRuntimePlan {
    MetadataStore::MutationRequest request;
    const catalog::ContainerMountCoordinator* owner = nullptr;
    std::shared_ptr<const RawSnapshotRuntimeAuthority> raw_authority;
    bool consumed = false;
    SnapshotRuntimePlan()=default;
    SnapshotRuntimePlan(const SnapshotRuntimePlan&)=delete;
    SnapshotRuntimePlan& operator=(const SnapshotRuntimePlan&)=delete;
};
bool PrepareSnapshotCreate(catalog::ContainerMountCoordinator&, std::uint64_t oid, std::string_view name,
    std::uint64_t time_ns, std::uint64_t inum, SnapshotRuntimePlan&, std::string&);
bool PrepareSnapshotDelete(catalog::ContainerMountCoordinator&, const catalog::ApfsSnapshotIdentity&,
    std::uint64_t time_ns, SnapshotRuntimePlan&, std::string&);
bool PrepareSnapshotCreate(catalog::ContainerMountCoordinator&, std::uint64_t oid, std::string_view name,
    std::uint64_t time_ns, std::uint64_t inum, const std::shared_ptr<const RawSnapshotRuntimeAuthority>&,
    SnapshotRuntimePlan&, std::string&);
bool PrepareSnapshotDelete(catalog::ContainerMountCoordinator&, const catalog::ApfsSnapshotIdentity&,
    std::uint64_t time_ns, const std::shared_ptr<const RawSnapshotRuntimeAuthority>&,
    SnapshotRuntimePlan&, std::string&);
// Pure clean-owner inspection under the coordinator serializer. Caller holds
// all original peer gates. Stale mounted state is refused without refreshing.
// Outputs are empty on refusal; inventory is enumerated only when requested.
bool InspectRawSnapshotRuntimeAuthority(const std::shared_ptr<const RawSnapshotRuntimeAuthority>&,
    catalog::ContainerMountCoordinator&,std::uint64_t selected_oid,catalog::ApfsSnapshotScope&,
    std::vector<catalog::ApfsSnapshotInfo>* inventory,std::string&);
// Same strict inspection, with a clean selected-store reload only when the
// original cohort already holds the exact published checkpoint found on disk.
// Caller holds all original peer gates. Never reloads retained/restart debt,
// accepts an unknown disk generation, or changes source/WAL/census state.
bool RefreshAndInspectRawSnapshotRuntimeAuthority(const std::shared_ptr<const RawSnapshotRuntimeAuthority>&,
    catalog::ContainerMountCoordinator&,std::uint64_t selected_oid,catalog::ApfsSnapshotScope&,
    std::vector<catalog::ApfsSnapshotInfo>* inventory,std::string&);
// Owner-bound maintenance gate. Verifies, without mutating anything, that the
// volume is mounted on this coordinator, the owner is ready, and the supplied
// transaction owner actually owns the journal at journal_path under the
// owner-derived canonical identity ("apfs-vol:<container>:<oid>") with a clean
// journal (Idle, no pending mutations, valid recovery, no accepted debt).
// Caller-supplied WAL paths, registry mappings, substitute clean journals and
// synthetic sidecars never satisfy this gate by assertion: path, identity and
// the live writer lease must all agree. False carries durable refusal
// evidence; nothing is mutated.
bool VerifySnapshotMaintenanceOwner(catalog::ContainerMountCoordinator&, std::uint64_t oid,
    TransactionManager&, const std::wstring& journal_path, std::string&);
// Ownership half of the maintenance gate for recovery: same mounted session,
// canonical identity and live-lease proof, but accepted debt is expected (it
// is the operation being recovered), so journal cleanliness is NOT required.
// ReplaySnapshot itself validates the debt content before touching anything.
bool VerifySnapshotRecoveryOwner(catalog::ContainerMountCoordinator&, std::uint64_t oid,
    TransactionManager&, const std::wstring& journal_path, std::string&);
// Journal currency against the mounted session. Pins must chain at or below
// the session checkpoint (never ahead). With strict_substitution_check, a
// journal with no durable history is refused on an image that already carries
// snapshot history: a substituted clean journal cannot authenticate itself.
// Session-owned journals pass false (the host established the file and
// startup recovery reconciled markers). Pure verification; nothing mutated.
bool VerifySnapshotJournalCurrency(catalog::ContainerMountCoordinator&, std::uint64_t oid,
    TransactionManager&, std::string&);
bool VerifySnapshotJournalCurrency(catalog::ContainerMountCoordinator&, std::uint64_t oid,
    TransactionManager&, bool strict_substitution_check, std::string&);
bool ValidateSnapshotMutation(const MetadataStore&,const MetadataStore::MutationRequest&,std::string&);
bool PlanSnapshotRuntimeCheckpoint(const catalog::RandomAccessSource&,const catalog::AppleCheckpointView&,
    const NativeSnapshotIntent&,const std::vector<std::uint64_t>& pins,AppleVolumeTransactionPlan&,std::string&);
// The source-only overload remains SNP1-only. This overload constructs the
// actual bounded device source from the enrolled store for authenticated SNP2.
bool PlanSnapshotRuntimeCheckpoint(const MetadataStore&,const catalog::AppleCheckpointView&,
    const NativeSnapshotIntent&,const std::vector<std::uint64_t>& pins,AppleVolumeTransactionPlan&,std::string&);
bool VerifyPublishedSnapshot(const MetadataStore&,const NativeSnapshotIntent&,std::string&);
catalog::ContainerCommitResult ApplySnapshot(catalog::ContainerMountCoordinator&,TransactionManager&,SnapshotRuntimePlan&);
// Raw admission requires a nonempty host completion hook. Publication retains
// the exact typed owner until host completion and final cleanup proof succeed.
// The no-hook overload refuses raw before acceptance; SNP1 behavior is unchanged.
catalog::ContainerCommitResult ApplySnapshot(catalog::ContainerMountCoordinator&,TransactionManager&,SnapshotRuntimePlan&,
    const RawSnapshotRuntimeCompletionHook&);
std::optional<bool> ReplaySnapshot(catalog::ContainerMountCoordinator&,TransactionManager&,std::uint64_t oid,std::string&);
std::optional<bool> ReplaySnapshot(catalog::ContainerMountCoordinator&,TransactionManager&,std::uint64_t oid,
    const RawSnapshotRuntimeReplayParameters&,std::string&);
// Selected retained-owner debt only. Authenticates the original held WAL and
// failure receipt, reloads under serialization, then replays P or proves P+1.
// Success does not admit generic writes: completion still owns the latch.
// Pure admission uses the same source/receipt proof without reload, grants,
// latch changes, durability marking or pin updates. Caller holds all peer gates.
bool AdmitRetainedRawSnapshotRecovery(catalog::ContainerMountCoordinator&,TransactionManager&,std::uint64_t oid,
    const RawSnapshotRuntimeReplayParameters&,std::string&);
// Fresh restart authority must contain the complete factory-authenticated held
// receipt. Admit is pure; Recover registers typed debt before reload/replay.
// Success returns a completion token with the latch and pins still held.
bool AdmitRawSnapshotRestartRecovery(catalog::ContainerMountCoordinator&,TransactionManager&,std::uint64_t oid,
    const RawSnapshotRuntimeReplayParameters&,std::string&);
bool RecoverRawSnapshotRestart(catalog::ContainerMountCoordinator&,TransactionManager&,std::uint64_t oid,
    const RawSnapshotRuntimeReplayParameters&,
    std::shared_ptr<const RawSnapshotRuntimeRecoveryToken>& completion,std::string&);
bool RecoverRetainedRawSnapshot(catalog::ContainerMountCoordinator&,TransactionManager&,std::uint64_t oid,
    const RawSnapshotRuntimeReplayParameters&,
    std::shared_ptr<const RawSnapshotRuntimeRecoveryToken>& completion,std::string&);
bool CompleteRetainedRawSnapshotRecovery(catalog::ContainerMountCoordinator&,
    const std::shared_ptr<const RawSnapshotRuntimeRecoveryToken>&,
    const RawSnapshotRuntimeCompletionHook&,std::string&);
// Explicit live profile: returns complete NEW reference records only after the
// same bounded historical census and chronological reference resolution.
bool LoadSnapshotRuntimeLiveReferences(const catalog::RandomAccessSource&,const catalog::AppleCheckpointView&,
    std::uint64_t oid,std::vector<catalog::BtreeRecord>&,std::string&);
}
