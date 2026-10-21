#include "VolumeManagementTestFixture.h"
#include "BlockDevice.h"
#include "TransactionManager.h"
#include <bcrypt.h>
#include <iostream>
#undef CreateFile

using namespace apfsaccess::volume_management_test;
namespace
{
unsigned checks = 0, groups = 0;
std::filesystem::path root;
void Check(bool value, const std::string& why) { ++checks; if (!value) throw std::runtime_error(why); }
void Pass(const char* name) { ++groups; std::cout << "PASS " << name << '\n'; }
std::filesystem::path ExtendedFixturePath(std::filesystem::path path)
{
    path.make_preferred(); return std::filesystem::path(L"\\\\?\\" + path.wstring());
}
Bytes IsolatedFixture()
{
    auto bytes = Fixture(); std::array<std::byte, 16> uuid{};
    Check(BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(uuid.data()), static_cast<ULONG>(uuid.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0, "unique fixture container identity");
    for (std::size_t at = 0; at < bytes.size(); at += 4096) {
        Bytes nx(bytes.begin() + at, bytes.begin() + at + 4096);
        if (!ParseNxSuperblock(nx)) continue;
        std::copy(uuid.begin(), uuid.end(), nx.begin() + 0x48); FletcherForBlock(nx, 4096);
        std::copy(nx.begin(), nx.end(), bytes.begin() + at);
    }
    return bytes;
}
VolumeManagementRequest Setup(const std::string& name, bool create)
{
    const auto dir = root / name; Check(!std::filesystem::exists(dir), "fresh fixture required");
    std::filesystem::create_directories(dir);
    const auto bytes = IsolatedFixture(); const auto r = Request(dir, create, bytes); Save(r.image, bytes); return r;
}
VolumeManagementResult Prepare(const VolumeManagementRequest& r)
{ return r.operation == VolumeManagementOperation::Create ? PrepareVolumeCreate(r) : PrepareVolumeDelete(r); }
using Files = std::map<std::filesystem::path, Bytes>;
Files Snapshot(const std::filesystem::path& directory)
{
    Files files;
    for (const auto& item : std::filesystem::recursive_directory_iterator(directory))
        files.emplace(item.path(), item.is_regular_file() ? Read(item.path()) : Bytes{});
    return files;
}
void Cancelled(const VolumeManagementRequest& r, const VolumeManagementResult& result)
{
    Check(result.outcome == VolumeManagementOutcome::Cancelled && result.error.empty(), "proved cancellation: " + result.error);
    Check(result.source_identity.size() == 80 && !result.journal_path.empty() && result.confirmation_token.empty(), "exact cancellation identity");
    Check(result.pre_xid == r.checkpoint_xid && result.post_xid == result.pre_xid && result.block_size == 4096 &&
        result.free_blocks_after == result.free_blocks_before && result.allocated_blocks == 0 && result.deferred_blocks == 0,
        "cancelled recovery reports actual unchanged checkpoint and allocation");
}
void LostResponses()
{
    for (bool create : {true, false}) {
        auto r = Setup(create ? "prepared-create" : "prepared-delete", create);
        ProvisionOriginalWals(r);
        const auto before = Read(r.image);
        const auto p = Prepare(r); Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
        const auto journal = Read(p.journal_path);
        Cancelled(r, RecoverVolumeManagement(r));
        Check(Read(r.image) == before && Read(p.journal_path).size() == journal.size() + 40, "only cancellation receipt appended");
        const auto terminal = Snapshot(r.journal_directory);
        Cancelled(r, RecoverVolumeManagement(r));
        Check(Snapshot(r.journal_directory) == terminal, "cancelled recovery is completely read-only and idempotent");
        Check(ApplyVolumeManagement(r, p.confirmation_token).error == "VolumeManagementConfirmationConsumed", "lost prepare token cannot apply");
        const auto next = Prepare(r); Check(next.outcome == VolumeManagementOutcome::Prepared, "archive cancelled and prepare anew: " + next.error);
        Check(CancelVolumeManagement(r, next.confirmation_token).outcome == VolumeManagementOutcome::Cancelled, "cancel response fixture");
        const auto cancelled = Snapshot(r.journal_directory);
        Cancelled(r, RecoverVolumeManagement(r));
        Check(Read(r.image) == before && Snapshot(r.journal_directory) == cancelled, "lost cancel response reconciles without file changes");
    }
    Pass("lost prepare/cancel responses for create and delete");
}
void ScopeAndSourceGuards()
{
    for (bool terminal : {false, true}) {
        auto r = Setup(terminal ? "cancelled-guards" : "prepared-guards", true);
        ProvisionOriginalWals(r);
        const auto before = Read(r.image);
        const auto p = Prepare(r); Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
        if (terminal) Check(CancelVolumeManagement(r, p.confirmation_token).outcome == VolumeManagementOutcome::Cancelled, "cancel guard fixture");
        const auto journal = Read(p.journal_path);
        auto wrong = r; ++wrong.checkpoint_xid;
        Check(RecoverVolumeManagement(wrong).error == "VolumeManagementJournalBindingMismatch", "wrong original XID refused");
        wrong = r; wrong.sibling_wals.erase(102);
        Check(RecoverVolumeManagement(wrong).error == "VolumeManagementJournalBindingMismatch", "incomplete original census refused");
        wrong = r; wrong.sibling_wals.at(102) = wrong.sibling_wals.at(101);
        Check(RecoverVolumeManagement(wrong).error == "VolumeManagementJournalBindingMismatch", "duplicate substituted WAL path refused");
        wrong = r; wrong.journal_directory /= "missing";
        Check(RecoverVolumeManagement(wrong).error == "VolumeManagementJournalDirectoryMissing", "stable missing root never recreated");
        Check(Read(p.journal_path) == journal && Read(r.image) == before, "request refusals retain all evidence");
        auto changed = before; changed[208 * 4096] ^= std::byte{1}; Save(r.image, changed);
        Check(RecoverVolumeManagement(r).error == "VolumeManagementUnacceptedImageChanged", "changed sibling payload blocks cancellation proof");
        Check(Read(p.journal_path) == journal && Read(r.image) == changed, "stale source refusal is non-mutating");
        Save(r.image, before); auto corrupt = journal; corrupt[100] ^= std::byte{1}; Save(p.journal_path, corrupt);
        Check(RecoverVolumeManagement(r).error == "VolumeManagementJournalChecksumInvalid", "cancelled/prepared journal corruption remains refused");
        Check(Read(p.journal_path) == corrupt && Read(r.image) == before, "journal corruption evidence retained");
    }
    Pass("prepared/cancelled exact request preimage corruption and root guards");
}
void WalGuards()
{
    for (bool terminal : {false, true}) {
        auto r = Setup(terminal ? "cancelled-wal-debt" : "prepared-wal-debt", false);
        ProvisionOriginalWals(r);
        const auto before = Read(r.image);
        const auto p = Prepare(r); Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
        if (terminal) Check(CancelVolumeManagement(r, p.confirmation_token).outcome == VolumeManagementOutcome::Cancelled, "cancel WAL fixture");
        const auto journal = Read(p.journal_path);
        {
            TransactionManager tx(L"Strict"); tx.SetJournalPath(r.sibling_wals.at(102).wstring());
            const auto id = "apfs-vol:" + r.container_uuid + ":102"; tx.SetVolumeIdentity(std::wstring(id.begin(), id.end()));
            TransactionManager::MutationIntent intent; intent.kind = TransactionManager::MutationKind::CreateFile;
            intent.path = L"\\accepted.txt"; intent.object_id = 400; intent.generation = r.checkpoint_xid + 1;
            Check(tx.Begin() && tx.RecordMutation(intent) && tx.Accept(r.checkpoint_xid), "real accepted sibling debt");
        }
        const auto debt = Read(r.sibling_wals.at(102));
        Check(RecoverVolumeManagement(r).error == "VolumeManagementWalDebtOrRecoveryPins", "existing accepted WAL prevents cancellation proof");
        Check(Read(r.image) == before && Read(p.journal_path) == journal && Read(r.sibling_wals.at(102)) == debt, "unknown debt retained exactly");
    }
    auto r = Setup("stale-clean-wal", true); ProvisionOriginalWals(r); const auto p = Prepare(r);
    Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
    const auto before = Snapshot(r.journal_directory);
    Save(r.sibling_wals.at(102), Bytes{std::byte{0x7f}});
    const auto changed = Snapshot(r.journal_directory);
    const auto refusal = RecoverVolumeManagement(r);
    Check(refusal.outcome == VolumeManagementOutcome::Refused && !refusal.error.empty(), "torn changed WAL cannot prove original clean census");
    Check(Snapshot(r.journal_directory) == changed && before != changed, "WAL refusal does not consume prepared receipt");
    Pass("accepted sibling debt and torn stale WAL guards");
}
void AcceptedRecovery()
{
    for (bool create : {true, false}) {
        auto r = Setup(create ? "accepted-create" : "accepted-delete", create);
        ProvisionOriginalWals(r);
        const auto p = Prepare(r); Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
        const auto interrupted = ApplyVolumeManagement(r, p.confirmation_token,
            [](auto stage) { return stage != "after-volume-management-accept"; });
        Check(interrupted.outcome == VolumeManagementOutcome::RecoveryRequired, "accepted interruption still owns forward recovery");
        const auto recovered = RecoverVolumeManagement(r);
        Check(recovered.outcome == VolumeManagementOutcome::Committed && recovered.post_xid > r.checkpoint_xid, "accepted forward recovery still commits");
        Check(Checkpoint(Read(r.image)).container.superblock.xid == recovered.post_xid, "independent fresh checkpoint load");
        const auto final = Snapshot(r.journal_directory);
        Check(RecoverVolumeManagement(r).outcome == VolumeManagementOutcome::Committed && Snapshot(r.journal_directory) == final,
            "completed forward recovery remains idempotent");
    }
    Pass("accepted forward recovery remains deterministic");
}
void AbortedWal(const std::filesystem::path& path, const std::string& identity)
{
    TransactionManager tx(L"Strict"); tx.SetJournalPath(path.wstring()); tx.SetVolumeIdentity(std::wstring(identity.begin(), identity.end()));
    TransactionManager::MutationIntent intent; intent.kind = TransactionManager::MutationKind::CreateFile;
    intent.path = L"\\aborted.txt"; intent.object_id = 400; intent.generation = 8;
    Check(tx.Begin() && tx.RecordMutation(intent) && tx.FlushPreparedRecords() && tx.Abort(), "actual native aborted WAL history");
}
void ProductionPaths(VolumeManagementRequest& r)
{
    for (auto& [id, path] : r.sibling_wals) {
        const auto identity = DerivePartitionlessVolumeRecoveryIdentity(r.container_uuid, id);
        const auto session = r.journal_directory / ("apfs_recovery_v1_" + identity.substr(17));
        std::filesystem::create_directories(session); path = session / "write-ahead.wal";
    }
    ProvisionOriginalWals(r, true);
}
void ProductionWalIdentities()
{
    Check(DerivePartitionlessVolumeRecoveryIdentity("11001100110044008800110011001100", 101) ==
        "apfs-recovery-v1-9fwLlNVjvMZQaZyYZrnqMl8E3Z7lZlnUnjbMIfi7eT0", "independent .NET 42-byte identity vector");
    for (bool production : {true, false}) for (bool create : {true, false}) {
        auto r = Setup(std::string(production ? "production-" : "canonical-") + (create ? "create" : "delete"), create);
        if (production) ProductionPaths(r);
        else ProvisionOriginalWals(r);
        const auto image = Read(r.image); const auto before = Snapshot(r.journal_directory);
        for (const auto& [id, path] : r.sibling_wals) {
            const auto expected = production ? DerivePartitionlessVolumeRecoveryIdentity(r.container_uuid, id) :
                "apfs-vol:" + r.container_uuid + ":" + std::to_string(id);
            const auto wal = WriteAheadLog::ReadAll(path, expected);
            Check(wal.status == WriteAheadLog::ReadStatus::Ok && !wal.records.empty(), "nonempty WAL has exact proved runtime identity");
        }
        const auto p = Prepare(r); Check(p.outcome == VolumeManagementOutcome::Prepared, "production/canonical prepare: " + p.error);
        Check(Read(r.image) == image, "production preview never writes image");
        unsigned fenced = 0;
        const auto committed = ApplyVolumeManagement(r, p.confirmation_token, [&](auto stage) {
            if (stage == "after-volume-management-accept") for (const auto& [id, path] : r.sibling_wals) {
                for (const auto& identity : {"apfs-vol:" + r.container_uuid + ":" + std::to_string(id),
                    DerivePartitionlessVolumeRecoveryIdentity(r.container_uuid, id)}) {
                    WriteAheadLog contender({path, identity}); Check(!contender.AcquireWriterLeaseOnly(), "both known alternate writers remain excluded"); ++fenced;
                }
            }
            return true;
        });
        Check(committed.outcome == VolumeManagementOutcome::Committed && fenced == 4, "both identity leases held through real publication: " + committed.error);
        Check(RecoverVolumeManagement(r).outcome == VolumeManagementOutcome::Committed, "production identity forward recovery remains idempotent");
        for (const auto& [id, path] : r.sibling_wals) Check(Read(path) == before.at(path), "original production WAL bytes remain unchanged");
    }
    for (bool create : {true, false}) {
        auto r = Setup(create ? "prod-cli-create" : "prod-cli-delete", create); ProductionPaths(r);
        const auto p = Prepare(r); Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
        const auto cancelled = RecoverVolumeManagement(r); Cancelled(r, cancelled);
        std::ofstream original(r.journal_directory / "original-request.json"); original << VolumeManagementJson(r, cancelled) << '\n';
        Check(!!original, "persist original scope for independent real executable production test");
    }
    Pass("proved production recovery identities and both known writer leases");
}
void ProductionWalRefusals()
{
    for (const auto& owner_kind : {"production", "canonical"}) {
        auto r = Setup(std::string("busy-empty-") + owner_kind, true);
        for (const auto& [id, path] : r.sibling_wals) {
            WriteAheadLog original({path, "apfs-vol:" + r.container_uuid + ":" + std::to_string(id)});
            Check(original.AcquireExclusiveWriterLease() && std::filesystem::file_size(path) == 0, "native empty original WAL fixture");
        }
        const auto p = Prepare(r);
        Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
        const auto before = Snapshot(r.journal_directory);
        const auto identity = std::string(owner_kind) == "production" ? DerivePartitionlessVolumeRecoveryIdentity(r.container_uuid, 102) :
            "apfs-vol:" + r.container_uuid + ":102";
        {
            WriteAheadLog owner({r.sibling_wals.at(102), identity}); Check(owner.AcquireWriterLeaseOnly(), "known writer-only owner fixture");
            Check(RecoverVolumeManagement(r).error == "VolumeManagementWalBusy" && Snapshot(r.journal_directory) == before,
                "empty WAL cannot bypass either original ownership lease");
        }
        Cancelled(r, RecoverVolumeManagement(r));
    }
    {
        auto r = Setup("production-debt", false); ProductionPaths(r);
        const auto p = Prepare(r); Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
        const auto journal = Read(p.journal_path); const auto image = Read(r.image);
        {
            TransactionManager tx(L"Strict"); tx.SetJournalPath(r.sibling_wals.at(102).wstring());
            const auto identity = DerivePartitionlessVolumeRecoveryIdentity(r.container_uuid, 102);
            tx.SetVolumeIdentity(std::wstring(identity.begin(), identity.end()));
            TransactionManager::MutationIntent intent; intent.kind = TransactionManager::MutationKind::CreateFile;
            intent.path = L"\\accepted-production.txt"; intent.object_id = 401; intent.generation = 8;
            Check(tx.Begin() && tx.RecordMutation(intent) && tx.Accept(r.checkpoint_xid), "genuine production-identity accepted debt");
        }
        const auto debt = Read(r.sibling_wals.at(102));
        Check(RecoverVolumeManagement(r).error == "VolumeManagementWalDebtOrRecoveryPins", "proved production identity never relaxes accepted debt");
        Check(Read(p.journal_path) == journal && Read(r.image) == image && Read(r.sibling_wals.at(102)) == debt, "production debt and intent retained exactly");
    }
    for (bool mixed : {false, true}) {
        auto r = Setup(mixed ? "mixed-known-identities" : "legacy-unknown-identity", true);
        ProvisionOriginalWal(r, 101);
        const auto production = DerivePartitionlessVolumeRecoveryIdentity(r.container_uuid, 102);
        const auto canonical = "apfs-vol:" + r.container_uuid + ":102";
        if (mixed) {
            AbortedWal(r.sibling_wals.at(102), production);
            const auto other = r.journal_directory / "other.wal"; AbortedWal(other, canonical);
            auto bytes = Read(r.sibling_wals.at(102)); const auto alternate = Read(other);
            bytes.insert(bytes.end(), alternate.begin(), alternate.end()); Save(r.sibling_wals.at(102), bytes);
        } else AbortedWal(r.sibling_wals.at(102), "device=D:\\old-image.apfs|offset=0|volume=Legacy|serial=1");
        const auto before = Snapshot(r.journal_directory);
        const auto refused = Prepare(r);
        Check(refused.outcome == VolumeManagementOutcome::Refused && refused.error ==
            (mixed ? "VolumeManagementWalMixedIdentities" : "VolumeManagementWalIdentityUnproven"), "mixed/legacy identities remain refused: " + refused.error);
        Check(Read(r.image) == before.at(r.image) && Read(r.sibling_wals.at(102)) == before.at(r.sibling_wals.at(102)), "unknown WAL evidence remains byte-identical");
    }
    {
        auto r = Setup("nonzero-production-scope", true); auto bytes = Bytes(4096, std::byte{0x55}); const auto image = Read(r.image);
        bytes.insert(bytes.end(), image.begin(), image.end()); Save(r.image, bytes); r.offset_bytes = 4096;
        const auto before = Snapshot(r.journal_directory); const auto refused = Prepare(r);
        Check(refused.outcome == VolumeManagementOutcome::Refused && refused.error == "VolumeManagementProductionWalScopeUnproven" &&
            Snapshot(r.journal_directory) == before, "unproved nonzero/GPT recovery ownership refuses before WAL creation");
    }
    Pass("production accepted debt empty-owner mixed legacy and offset guards");
}
void LongCompactionCensus()
{
    auto r = Setup("long-compaction", true);
    constexpr std::size_t wal_length = MAX_PATH - 1;
    const std::wstring leaf = L"write-ahead.wal";
    const auto base_length = r.journal_directory.wstring().size() + leaf.size() + 2;
    Check(base_length < wal_length && wal_length - base_length <= 255, "bounded long-path fixture directory");
    const auto directory = r.journal_directory / std::wstring(wal_length - base_length, L'p');
    std::filesystem::create_directory(directory);
    auto& wal = r.sibling_wals.at(101); wal = directory / leaf;
    ProvisionOriginalWal(r, 101, true);
    ProvisionOriginalWal(r, 102);
    Check(wal.wstring().size() == wal_length && wal.wstring().size() + 9 >= MAX_PATH,
        "existing WAL fits MAX_PATH while compaction enumeration exceeds it");
    const auto image = Read(r.image), wal_bytes = Read(wal);
    const auto p = Prepare(r);
    Check(p.outcome == VolumeManagementOutcome::Prepared, "long absent compaction census: " + p.error);
    const auto journal = Read(p.journal_path);
    for (const auto suffix : {L".compact.intent", L".compact.intent.completed", L".compact.previous"}) {
        const std::filesystem::path evidence(wal.wstring() + suffix);
        const auto extended = ExtendedFixturePath(evidence);
        const Bytes retained{std::byte{0x43}, std::byte{0x50}, std::byte{0x49}};
        Save(extended, retained);
        const auto refused = RecoverVolumeManagement(r);
        Check(refused.outcome == VolumeManagementOutcome::Refused && refused.error == "VolumeManagementWalCompactionEvidence",
            "long-path compaction receipt or predecessor stays refused: " + refused.error);
        Check(Read(r.image) == image && Read(wal) == wal_bytes && Read(p.journal_path) == journal && Read(extended) == retained,
            "long-path compaction refusal retains image original WAL prepared journal and evidence");
        Check(std::filesystem::remove(extended), "remove only the test-created compaction evidence");
    }
    Cancelled(r, RecoverVolumeManagement(r));
    Check(Read(r.image) == image && Read(wal) == wal_bytes, "long-path proven cancellation never mutates image or WAL");
    Pass("MAX_PATH compaction census absence and retained evidence refusal");
}
void MissingWalDirectory()
{
    auto r = Setup("missing-wal-dir", true);
    const auto directory = r.journal_directory / "original-wal-directory";
    std::filesystem::create_directory(directory); r.sibling_wals.at(102) = directory / "write-ahead.wal";
    ProvisionOriginalWals(r);
    const auto p = Prepare(r); Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
    const auto image = Read(r.image), journal = Read(p.journal_path);
    Check(std::filesystem::remove(r.sibling_wals.at(102)) && std::filesystem::remove(directory), "remove only original test WAL directory");
    for (const auto& result : {RecoverVolumeManagement(r), Prepare(r)})
        Check(result.outcome == VolumeManagementOutcome::Refused && result.error == "VolumeManagementWalDirectoryMissing",
            "missing original WAL directory remains refused: " + result.error);
    Check(Read(r.image) == image && Read(p.journal_path) == journal && !std::filesystem::exists(directory),
        "missing directory refusal retains image and prepared intent without recreating a WAL namespace");
    Pass("missing original WAL directory refusal retains prepared intent");
}
void ReadOnlyObservation()
{
    const auto r = Setup("observe", true); const auto bytes = Read(r.image); const auto cp = Checkpoint(bytes);
    const VolumeManagementObservationRequest request{r.image, 0};
    const auto before = Snapshot(r.journal_directory); const auto observed = ObserveVolumeManagement(request);
    Check(observed.complete && observed.error.empty(), "complete native image topology observation: " + observed.error);
    Check(observed.container_uuid == cp.container.superblock.uuid_hex && observed.next_oid == cp.container.superblock.next_oid &&
        observed.checkpoint_xid == cp.container.superblock.xid && observed.block_size == 4096 && observed.store_size_bytes == bytes.size(),
        "native parser reports exact held checkpoint NextOID UUID and store geometry");
    std::string e; auto keeper = BlockDevice::OpenExclusiveManagementImage(r.image.wstring(), 0, e); std::string identity;
    Check(keeper && keeper->QueryRegularImageIdentity(identity) && identity == observed.source_identity, "same opaque keeper image identity");
    keeper.reset(); Check(observed.volumes.size() == cp.volumes.size() && Snapshot(r.journal_directory) == before, "complete topology creates no WAL journal or registry");
    for (std::size_t i = 0; i < cp.volumes.size(); ++i)
        Check(observed.volumes[i].volume_uuid == cp.volumes[i].superblock.uuid_hex && observed.volumes[i].oid == cp.volumes[i].superblock.object_id,
            "each original sibling UUID/OID comes from the exact native checkpoint");
    const auto json = VolumeManagementObservationJson(request, observed);
    Check(json.find("\"nextOid\":\"" + std::to_string(cp.container.superblock.next_oid) + "\"") != std::string::npos &&
        json.find("\"readOnly\":true") != std::string::npos && json.find("walPath") == std::string::npos &&
        json.find("siblingWals") == std::string::npos && json.find("spoolRoot") == std::string::npos, "decimal-string topology-only JSON contract");
    for (const auto& dir : {"guessed-session", "duplicate-session"}) {
        const auto session = r.journal_directory / dir; std::filesystem::create_directory(session); Save(session / "write-ahead.wal", {});
    }
    const auto guessed = Snapshot(r.journal_directory);
    Check(VolumeManagementObservationJson(request, ObserveVolumeManagement(request)) == json &&
        Snapshot(r.journal_directory) == guessed, "native observation does not infer WAL authority from duplicate session paths");
    Save(r.journal_directory / "duplicate-session" / "write-ahead.wal", Bytes{std::byte{1}, std::byte{2}});
    const auto debt = Snapshot(r.journal_directory);
    Check(VolumeManagementObservationJson(request, ObserveVolumeManagement(request)) == json && Snapshot(r.journal_directory) == debt,
        "native topology does not consume or export unknown retained WAL debt");
    Pass("strict read-only native topology with complete sibling UUID/OID census");
}
void ObservationSources()
{
    auto r = Setup("observation-sources", true); const auto bytes = Read(r.image);
    VolumeManagementObservationRequest request{r.image, 0};
    auto bad = request; bad.image = LR"(\\.\PhysicalDrive2)";
    Check(ObserveVolumeManagement(bad).error == "VolumeManagementAbsoluteLocalPathRequired", "physical device refused before open");
    bad = request; bad.offset_bytes = 1;
    Check(ObserveVolumeManagement(bad).error == "VolumeManagementOffsetUnaligned", "unaligned store offset refused");
    const auto linked = r.journal_directory / "hardlink.apfs";
    Check(CreateHardLinkW(linked.c_str(), r.image.c_str(), nullptr) != FALSE, "hardlink fixture");
    Check(ObserveVolumeManagement(request).error == "VolumeManagementObservationImageNotOrdinary", "hardlink source cannot gain observation authority");
    std::filesystem::remove(linked);
    auto padded = bytes; padded.resize(bytes.size() + 4096); Save(r.image, padded);
    Check(!ObserveVolumeManagement(request).complete, "store geometry cannot include trailing unowned bytes");
    Save(r.image, bytes);
    auto prefixed = Bytes(4096, std::byte{0x5a}); prefixed.insert(prefixed.end(), bytes.begin(), bytes.end()); Save(r.image, prefixed);
    request.offset_bytes = 4096; const auto observed = ObserveVolumeManagement(request);
    Check(observed.next_oid == Checkpoint(bytes).container.superblock.next_oid && observed.store_size_bytes == bytes.size(), "explicit offset uses exact store window");
    std::string e; auto keeper = BlockDevice::OpenExclusiveManagementImage(r.image.wstring(), 4096, e); std::string identity;
    Check(keeper && keeper->QueryRegularImageIdentity(identity) && identity == observed.source_identity, "offset-bound held identity matches keeper");
    keeper.reset(); Check(Read(r.image) == prefixed, "prefix and image remain byte-identical");
    std::filesystem::resize_file(r.image, 256ull * 1024 * 1024 + 8192);
    Check(ObserveVolumeManagement(request).error == "VolumeManagementBoundedImageSizeExceeded", "over-bound store window refused");
    Pass("physical hardlink offset geometry and size refusal");
}
}
int wmain(int argc, wchar_t** argv)
{
    try {
        Check(argc == 2, "fresh D: evidence root required"); root = argv[1];
        Check(root.is_absolute() && root.root_name() == L"D:" && !std::filesystem::exists(root), "fresh private D: test root");
        std::filesystem::create_directories(root);
        LostResponses(); ScopeAndSourceGuards(); WalGuards(); AcceptedRecovery(); ProductionWalIdentities(); ProductionWalRefusals();
        LongCompactionCensus();
        MissingWalDirectory();
        ReadOnlyObservation(); ObservationSources();
        std::cout << "PASS groups=" << groups << " checks=" << checks << '\n'; return 0;
    } catch (const std::exception& ex) { std::cerr << "FAIL checks=" << checks << " " << ex.what() << '\n'; return 1; }
}
