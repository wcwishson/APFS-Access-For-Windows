#include "VolumeManagementTestFixture.h"
#include "../src/VolumeManagementInternal.h"
#include "BlockDevice.h"
#include "TransactionManager.h"
#include <iostream>

using namespace apfsaccess::volume_management_test;
namespace
{
unsigned checks = 0, cases = 0;
std::filesystem::path root;
void Check(bool value, const std::string& why) { ++checks; if (!value) throw std::runtime_error(why); }
void Pass(const std::string& name) { ++cases; std::cout << "PASS " << name << std::endl; }
VolumeManagementRequest Setup(std::string name, bool create, const Bytes& bytes = Fixture())
{
    const auto dir = root / name; Check(!std::filesystem::exists(dir), "test directory must be fresh");
    std::filesystem::create_directories(dir); const auto r = Request(dir, create, bytes); Save(r.image, bytes);
    for (const auto& [oid, wal] : r.sibling_wals) Save(wal, {});
    return r;
}
VolumeManagementResult Prepare(const VolumeManagementRequest& r)
{ return r.operation == VolumeManagementOperation::Create ? PrepareVolumeCreate(r) : PrepareVolumeDelete(r); }
void Success(bool create)
{
    const auto r = Setup(create ? "create" : "delete", create); const auto original = Read(r.image);
    const auto p = Prepare(r); Check(p.outcome == VolumeManagementOutcome::Prepared, "prepare: " + p.error);
    Check(Read(r.image) == original, "dry-run is image-byte-identical");
    Check(p.confirmation_token.size() == 64 && p.pre_xid == r.checkpoint_xid && p.post_xid > p.pre_xid, "bound plan identity");
    Check(Prepare(r).outcome == VolumeManagementOutcome::Refused, "unfinished plan cannot be replaced");
    const auto done = ApplyVolumeManagement(r, p.confirmation_token);
    Check(done.outcome == VolumeManagementOutcome::Committed, "commit: " + done.error);
    const auto bytes = Read(r.image); const auto cp = Checkpoint(bytes);
    Check(cp.container.superblock.xid == p.post_xid && cp.volumes.size() == (create ? 3 : 1), "published topology");
    std::string e; VectorRandomAccessSource source(bytes);
    Check(apfsaccess::rw::volume_management::VerifyTopology(source, cp, e), "independent post-verification: " + e);
    Check(std::equal(original.begin() + 208 * 4096, original.begin() + 209 * 4096, bytes.begin() + 208 * 4096), "sibling payload unchanged");
    const auto old = LoadAppleCheckpointView(source, 0, source.SizeBytes(), e, r.checkpoint_xid);
    Check(!!old && old->volumes.size() == 2, "old checkpoint remains recoverable");
    Check(ApplyVolumeManagement(r, p.confirmation_token).outcome == VolumeManagementOutcome::Refused, "single use confirmation");
    Check(RecoverVolumeManagement(r).outcome == VolumeManagementOutcome::Committed, "idempotent verified recovery receipt");
    if (!create) {
        Check(p.deferred_blocks == 7, "delete queues six metadata blocks and one payload block");
        bool queued = false;
        for (const auto& q : cp.spaceman.free_queues) for (const auto& rec : q.entries)
            if (rec.physical_block <= 200 && 200 - rec.physical_block < rec.block_count) queued = true;
        Check(queued, "deleted payload retirement is deferred");
        Check(bytes[200 * 4096] == std::byte{0x41}, "retained payload bytes untouched");
    }
    Pass(create ? "create genuine APSB/OMAP/root/extentref publication" : "delete populated volume with deferred ownership release");
}
void Confirmations()
{
    for (bool cancel : {false, true}) {
        auto r = Setup(cancel ? "cancel" : "wrong-confirm", true); const auto before = Read(r.image); const auto p = Prepare(r);
        Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
        const auto result = cancel ? CancelVolumeManagement(r, p.confirmation_token) : ApplyVolumeManagement(r, "wrong");
        Check(result.outcome == (cancel ? VolumeManagementOutcome::Cancelled : VolumeManagementOutcome::Refused), "cancel/wrong token outcome");
        Check(Read(r.image) == before && ApplyVolumeManagement(r, p.confirmation_token).outcome == VolumeManagementOutcome::Refused,
            "cancel/wrong token consumes plan without image changes");
    }
    auto r = Setup("stale", true); const auto p = Prepare(r); Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
    auto changed = Read(r.image); changed.back() ^= std::byte{1}; Save(r.image, changed);
    Check(ApplyVolumeManagement(r, p.confirmation_token).error == "VolumeManagementStalePreimage", "stale source veto");
    Check(Read(r.image) == changed && ApplyVolumeManagement(r, p.confirmation_token).outcome == VolumeManagementOutcome::Refused, "stale consumes token");
    Pass("cancel wrong confirmation and stale preimage");
}
void Refusals()
{
    unsigned n = 0;
    const auto test = [&](const std::function<void(VolumeManagementRequest&)>& alter, bool create = true) {
        auto r = Setup("refusal-" + std::to_string(n++), create); const auto before = Read(r.image); alter(r);
        const auto p = Prepare(r); Check(p.outcome == VolumeManagementOutcome::Refused && !p.error.empty(), "expected typed refusal");
        Check(Read(r.image) == before, "refusal leaves bytes intact");
    };
    test([](auto& r) { r.volume_oid = 0; }); test([](auto& r) { ++r.checkpoint_xid; });
    test([](auto& r) { r.container_uuid[0] = 'f'; }); test([](auto& r) { r.volume_uuid = std::string(32, '0'); });
    test([](auto& r) { r.volume_uuid[0] = 'e'; }, false);
    test([](auto& r) { r.sibling_wals.erase(102); });
    test([](auto& r) { r.sibling_wals[102] = r.sibling_wals[101]; });
    test([](auto& r) { r.quota_blocks = 1; r.reserve_blocks = 0; });
    test([](auto& r) { r.reserve_blocks = 500; r.quota_blocks = 501; });
    test([](auto& r) { r.name_utf8 = std::string(1, char(0xff)); });
    auto r = Setup("space", true, Fixture(true, 1)); const auto p = Prepare(r);
    Check(p.outcome == VolumeManagementOutcome::Refused, "insufficient allocator capacity");
    auto busy = Setup("busy", true); std::string e;
    auto device = BlockDevice::OpenExclusiveManagementImage(busy.image.wstring(), 0, e); Check(!!device, e);
    Check(Prepare(busy).outcome == VolumeManagementOutcome::Refused, "busy image refused");
    Pass("identity capacity malformed names census and busy image refusal");
}
void Interruptions()
{
    const std::vector<std::string> stages = {"after-volume-management-accept", "before-apple-device-write",
        "before-apple-prepublication-flush", "before-apple-checkpoint-switch", "before-apple-final-flush", "before-volume-management-complete"};
    for (bool create : {true, false}) for (std::size_t i = 0; i < stages.size(); ++i) {
        auto r = Setup(std::string(create ? "create-interrupt-" : "delete-interrupt-") + std::to_string(i), create);
        const auto p = Prepare(r); Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
        bool hit = false;
        const auto interrupted = ApplyVolumeManagement(r, p.confirmation_token, [&](auto stage) {
            if (stage == stages[i]) { hit = true; return false; } return true;
        });
        Check(hit && interrupted.outcome == VolumeManagementOutcome::RecoveryRequired, "interrupt accepted durable stage: " + interrupted.error);
        Check(ApplyVolumeManagement(r, p.confirmation_token).outcome == VolumeManagementOutcome::Refused, "accepted token cannot apply twice");
        const auto recovered = RecoverVolumeManagement(r);
        Check(recovered.outcome == VolumeManagementOutcome::Committed, "fresh-lease recovery: " + recovered.error);
        Check(Checkpoint(Read(r.image)).container.superblock.xid == p.post_xid, "one exact generation after replay");
        Check(RecoverVolumeManagement(r).outcome == VolumeManagementOutcome::Committed, "recovery idempotence");
    }
    auto r = Setup("cancel-before-accept", true); const auto before = Read(r.image); const auto p = Prepare(r);
    const auto cancelled = ApplyVolumeManagement(r, p.confirmation_token, [](auto stage) { return stage != "before-volume-management-accept"; });
    Check(cancelled.outcome == VolumeManagementOutcome::Cancelled && Read(r.image) == before, "cancel at acceptance boundary is byte-identical");
    Pass("both operations recover at every publication barrier");
}
void WalAndSnapshotOwners()
{
    for (bool create : {true, false}) {
        auto r = Setup(create ? "create-wal-pin" : "delete-wal-pin", create);
        const auto before = Read(r.image);
        {
            TransactionManager journal(L"Strict"); journal.SetJournalPath(r.sibling_wals.at(102).wstring());
            const auto identity = "apfs-vol:" + r.container_uuid + ":102";
            journal.SetVolumeIdentity(std::wstring(identity.begin(), identity.end()));
            TransactionManager::MutationIntent intent; intent.kind = TransactionManager::MutationKind::CreateFile;
            intent.path = L"\\pending.txt"; intent.object_id = 400; intent.generation = r.checkpoint_xid + 1;
            Check(journal.Begin() && journal.RecordMutation(intent) && journal.Accept(r.checkpoint_xid), "genuine accepted sibling WAL");
        }
        const auto refusal = Prepare(r);
        Check(refusal.outcome == VolumeManagementOutcome::Refused && refusal.error == "VolumeManagementWalDebtOrRecoveryPins",
            "accepted sibling checkpoint pin veto: " + refusal.error);
        Check(Read(r.image) == before, "WAL pin refusal is byte-identical");
    }
    auto image = Fixture(); const auto cp = Checkpoint(image); VectorRandomAccessSource source(image);
    AppleSnapshotCreateRequest request; request.volume_object_id = 101; request.name_utf8 = "retained";
    request.creation_time_ns = 1700000000000000000ull; request.snapshot_inum = 600;
    AppleSnapshotCreatePlan snapshot; std::string e;
    Check(PlanAppleSnapshotCreate(source, cp, request, snapshot, e), "actual snapshot fixture transaction: " + e);
    const auto write = [&](const auto& w) { std::copy(w.bytes.begin(), w.bytes.end(), image.begin() + w.physical_block * 4096); };
    for (const auto& w : snapshot.commit.publication.before_superblock_writes) write(w);
    write(snapshot.commit.publication.superblock_write);
    const auto with_snapshot = Checkpoint(image);
    VectorRandomAccessSource snapshot_source(image); AppleSnapshotRetentionView retention;
    Check(LoadAppleSnapshotRetention(snapshot_source, with_snapshot, retention, e) && retention.identities.size() == 1,
        "independently proven snapshot owner: " + e);
    for (bool create : {true, false}) {
        auto r = Setup(create ? "create-snapshot-owner" : "delete-snapshot-owner", create, image);
        Check(Prepare(r).outcome == VolumeManagementOutcome::Refused && Read(r.image) == image, "snapshot owner cannot be reclaimed");
    }
    auto r = Setup("wal-owner-busy", true); const auto before = Read(r.image);
    TransactionManager owner(L"Strict"); owner.SetJournalPath(r.sibling_wals.at(101).wstring());
    const auto identity = "apfs-vol:" + r.container_uuid + ":101"; owner.SetVolumeIdentity(std::wstring(identity.begin(), identity.end()));
    Check(owner.AcquireJournalOwnership(e), e);
    Check(Prepare(r).outcome == VolumeManagementOutcome::Refused && Read(r.image) == before, "busy sibling journal identity refuses");
    Pass("real accepted WAL pins snapshot ownership and busy sibling lease");
}
void TornWritesAndReceipts()
{
    for (bool create : {true, false}) {
        auto r = Setup(create ? "create-torn-checkpoint" : "delete-torn-checkpoint", create); const auto before = Read(r.image);
        apfsaccess::rw::volume_management::TopologyPlan topology; std::string e; VectorRandomAccessSource original(before);
        Check(apfsaccess::rw::volume_management::PlanTopology(original, r, topology, e), e);
        const auto p = Prepare(r); Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
        const auto result = ApplyVolumeManagement(r, p.confirmation_token, [](auto stage) { return stage != "before-apple-checkpoint-switch"; });
        Check(result.outcome == VolumeManagementOutcome::RecoveryRequired, result.error);
        auto torn = Read(r.image); const auto& nx = topology.publication.superblock_write;
        std::copy_n(nx.bytes.begin(), 2111, torn.begin() + nx.physical_block * 4096);
        // Also model a torn previously staged allocator-owned metadata block.
        const auto at = topology.publication.before_superblock_writes.front().physical_block * 4096;
        std::fill_n(torn.begin() + at + 100, 777, std::byte{0x55}); Save(r.image, torn);
        Check(RecoverVolumeManagement(r).outcome == VolumeManagementOutcome::Committed, "redo repairs only authorized torn destinations");
        const auto recovered = Read(r.image); Check(Checkpoint(recovered).container.superblock.xid == p.post_xid, "torn switch recovered exact generation");
        const auto current_request = Request(r.image.parent_path(), true, recovered);
        const auto next = PrepareVolumeCreate(current_request);
        // A second create must use a distinct UUID. This also checks that a
        // completed journal can be archived before a new plan is admitted.
        if (create) Check(next.outcome == VolumeManagementOutcome::Refused, "duplicate UUID after real create");
        else Check(next.outcome == VolumeManagementOutcome::Prepared, "new plan after recovered delete: " + next.error);
    }
    for (bool completed : {false, true}) {
        auto r = Setup(completed ? "torn-complete-receipt" : "torn-accept-receipt", true); const auto before = Read(r.image);
        const auto p = Prepare(r); Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
        const auto result = ApplyVolumeManagement(r, p.confirmation_token, [&](auto stage) {
            return completed || stage != "after-volume-management-accept";
        });
        Check(result.outcome == (completed ? VolumeManagementOutcome::Committed : VolumeManagementOutcome::RecoveryRequired), result.error);
        auto receipt = Read(p.journal_path); receipt.resize(receipt.size() - 9); Save(p.journal_path, receipt);
        const auto recovered = RecoverVolumeManagement(r);
        Check(recovered.outcome == (completed ? VolumeManagementOutcome::Committed : VolumeManagementOutcome::Cancelled),
            "partial journal receipt recovery: " + recovered.error);
        if (!completed) Check(Read(r.image) == before, "incomplete acceptance never authorizes image writes");
    }
    auto r = Setup("recovery-unrelated-corruption", false); const auto p = Prepare(r);
    Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
    Check(ApplyVolumeManagement(r, p.confirmation_token, [](auto stage) { return stage != "after-volume-management-accept"; }).outcome ==
        VolumeManagementOutcome::RecoveryRequired, "accepted recovery fixture");
    auto changed = Read(r.image); changed[208 * 4096] ^= std::byte{1}; Save(r.image, changed);
    const auto veto = RecoverVolumeManagement(r);
    Check(veto.outcome == VolumeManagementOutcome::RecoveryRequired && veto.error == "VolumeManagementRecoveryUnrelatedBytesChanged" &&
        Read(r.image) == changed, "recovery cannot overwrite a changed sibling payload");
    Pass("torn checkpoint allocator blocks receipts and foreign-change veto");
}
void JournalAndBindingChanges()
{
    auto r = Setup("grown-image-binding", true); const auto p = Prepare(r);
    Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
    auto bytes = Read(r.image); bytes.resize(bytes.size() + 4096); Save(r.image, bytes);
    Check(Prepare(r).error == "VolumeManagementUnfinishedJournal", "file growth does not hide pending journal locator");
    Check(ApplyVolumeManagement(r, p.confirmation_token).error == "VolumeManagementJournalBindingMismatch", "file size is exact identity");
    Check(Read(r.image) == bytes, "wrong-capacity image never written");
    r = Setup("altered-request", true); const auto original = Read(r.image); const auto plan = Prepare(r);
    Check(plan.outcome == VolumeManagementOutcome::Prepared, plan.error);
    auto changed = r; changed.name_utf8 = "tampered";
    Check(ApplyVolumeManagement(changed, plan.confirmation_token).error == "VolumeManagementJournalBindingMismatch", "mutation values bound");
    changed = r; changed.sibling_wals.at(102) = r.journal_directory / "other.wal";
    Check(ApplyVolumeManagement(changed, plan.confirmation_token).error == "VolumeManagementJournalBindingMismatch", "WAL paths bound");
    Check(Read(r.image) == original, "tampering is byte-identical");
    auto journal = Read(plan.journal_path); journal[100] ^= std::byte{1}; Save(plan.journal_path, journal);
    Check(ApplyVolumeManagement(r, plan.confirmation_token).error == "VolumeManagementJournalChecksumInvalid", "journal checksum enforced");
    Check(Read(r.image) == original, "malformed journal cannot authorize writes");
    r = Setup("conflicting-published-checkpoint", false); const auto before = Read(r.image);
    const auto prepared = Prepare(r); Check(prepared.outcome == VolumeManagementOutcome::Prepared, prepared.error);
    Check(ApplyVolumeManagement(r, prepared.confirmation_token, [](auto stage) { return stage != "before-apple-checkpoint-switch"; }).outcome ==
        VolumeManagementOutcome::RecoveryRequired, "conflicting checkpoint fixture accepted");
    apfsaccess::rw::volume_management::TopologyPlan topology; std::string e; VectorRandomAccessSource source(before);
    Check(apfsaccess::rw::volume_management::PlanTopology(source, r, topology, e), e);
    auto nx = topology.publication.superblock_write.bytes; PutU64LE(nx, 0x10, prepared.post_xid + 1); PutU64LE(nx, 0x60, prepared.post_xid + 2);
    FletcherForBlock(nx, 4096); auto conflict = Read(r.image);
    std::copy(nx.begin(), nx.end(), conflict.begin() + topology.publication.superblock_write.physical_block * 4096); Save(r.image, conflict);
    const auto refused = RecoverVolumeManagement(r);
    Check(refused.outcome == VolumeManagementOutcome::RecoveryRequired && refused.error == "VolumeManagementRecoveryConflictingCheckpoint" &&
        Read(r.image) == conflict, "recovery cannot replace a different valid published generation");
    Pass("capacity mutation WAL-path journal-tamper and conflicting-generation binding");
}
void CompactionEvidence()
{
    for (bool create : {true, false}) {
        auto r = Setup(create ? "create-compaction-evidence" : "delete-compaction-evidence", create);
        const auto before = Read(r.image);
        const auto p = Prepare(r); Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
        auto receipt = r.sibling_wals.at(102); receipt += L".compact.intent";
        const Bytes evidence{std::byte{1}, std::byte{2}}; Save(receipt, evidence);
        const auto refused = ApplyVolumeManagement(r, p.confirmation_token);
        Check(refused.outcome == VolumeManagementOutcome::Refused && refused.error == "VolumeManagementWalCompactionEvidence",
            "sibling compaction evidence vetoes acceptance: " + refused.error);
        Check(Read(receipt) == evidence && Read(r.image) == before, "compaction evidence and source retained");
        Check(CancelVolumeManagement(r, p.confirmation_token).outcome == VolumeManagementOutcome::Cancelled,
            "unaccepted plan remains cancellable with sibling debt");
    }
    Pass("sibling compaction evidence refuses before acceptance");
}
void LongArchivePath()
{
    auto r = Setup("archive-path", true);
    auto directory = r.journal_directory.wstring();
    const auto target = (std::max<std::size_t>)(directory.size() + 8, 180);
    directory += L"\\" + std::wstring(target - directory.size() - 1, L'a');
    r.journal_directory = directory;
    std::filesystem::create_directories(r.journal_directory);
    const auto prepared = Prepare(r);
    Check(prepared.outcome == VolumeManagementOutcome::Prepared, prepared.error);
    const auto archive = prepared.journal_path.wstring() + L"." +
        std::wstring(prepared.confirmation_token.begin(), prepared.confirmation_token.end()) + L".completed";
    Check(archive.size() > MAX_PATH, "completed archive exceeds legacy path limit");
    Check(CancelVolumeManagement(r, prepared.confirmation_token).outcome == VolumeManagementOutcome::Cancelled,
        "cancel first long-path plan");
    const auto replacement = Prepare(r);
    Check(replacement.outcome == VolumeManagementOutcome::Prepared, "new plan archives long completed path: " + replacement.error);
    const auto extended = L"\\\\?\\" + archive;
    Check(GetFileAttributesW(extended.c_str()) != INVALID_FILE_ATTRIBUTES, "completed evidence is retained at long archive path");
    Check(CancelVolumeManagement(r, replacement.confirmation_token).outcome == VolumeManagementOutcome::Cancelled,
        "cancel replacement plan");
    Pass("completed journal archive supports long paths");
}
}
int wmain(int argc, wchar_t** argv)
{
    try {
        Check(argc == 2, "usage: VolumeManagementTests absolute-fresh-evidence-directory"); root = argv[1];
        std::filesystem::create_directories(root);
        Success(true); Success(false); Confirmations(); Refusals(); Interruptions(); WalAndSnapshotOwners(); TornWritesAndReceipts(); JournalAndBindingChanges(); CompactionEvidence(); LongArchivePath();
        std::cout << "PASS cases=" << cases << " checks=" << checks << '\n'; return 0;
    } catch (const std::exception& e) { std::cerr << "FAIL checks=" << checks << " " << e.what() << '\n'; return 1; }
}
