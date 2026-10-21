#include "VolumeResizeFixture.h"
#include "VolumeManagement.h"
#include "VolumeKeeperWal.h"
#include "../src/VolumeResizeInternal.h"
#include "BlockDevice.h"
#include "AppleVolumeTransaction.h"
#include "InodeMetadataPatch.h"
#include "ApfsExtendedRecordCodec.h"
#include <bcrypt.h>
#include <iostream>
#undef CreateFile
#undef CreateDirectory

namespace fixture = apfsaccess::volume_image_test;
using namespace apfsaccess::catalog;
using namespace apfsaccess::rw;
using Bytes = std::vector<std::byte>;

namespace
{
unsigned checks = 0;
void Check(bool value, const std::string& error)
{ ++checks; if (!value) throw std::runtime_error(error); }

std::filesystem::path Wal(const VolumeKeeperHistoryContext& context, const std::string& container, std::uint64_t oid)
{ return context.spool_root / ("apfs_recovery_v1_" + DerivePartitionlessVolumeRecoveryIdentity(container, oid).substr(17)) / "write-ahead.wal"; }
std::filesystem::path Marker(const VolumeKeeperHistoryContext& context, const std::string& container, std::uint64_t oid)
{ return context.recovery_root / ("apfs_recovery_v1_" + DerivePartitionlessVolumeRecoveryIdentity(container, oid).substr(17) + "_Native.state"); }
void MarkerBytes(const std::filesystem::path& path, const std::string& text)
{ fixture::Save(path, Bytes(reinterpret_cast<const std::byte*>(text.data()), reinterpret_cast<const std::byte*>(text.data() + text.size()))); }
void Mark(const VolumeKeeperHistoryContext& context, const std::string& container, std::uint64_t oid, std::uint64_t xid)
{ MarkerBytes(Marker(context, container, oid), "dirty=0\nlastCommitXid=" + std::to_string(xid) + "\n"); }
void Production(VolumeImageRequest& request, const std::filesystem::path& root, bool create_destination = true)
{
    request.history_context = {root / "spool", root / "recovery"};
    std::filesystem::create_directories(request.history_context.spool_root);
    std::filesystem::create_directories(request.history_context.recovery_root);
    for (auto& [oid, path] : request.sibling_wals) {
        path = Wal(request.history_context, request.container_uuid, oid); std::filesystem::create_directories(path.parent_path());
    }
    request.new_volume_wal = Wal(request.history_context, request.new_container_uuid, 1024);
    if (create_destination) std::filesystem::create_directories(request.new_volume_wal.parent_path());
}
std::filesystem::path Proof(const std::filesystem::path& journal, const std::string& identity)
{
    const auto binding = DecodeVolumeKeeperHistoryBinding(fixture::Read(journal), journal, journal.parent_path(), identity);
    return journal.parent_path() / ("wal-history-" + binding.frame_digest + ".vkh1");
}
std::string FileId(const std::filesystem::path& path)
{
    const auto h = CreateFileW(fixture::FixtureIoPath(path).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    Check(h != INVALID_HANDLE_VALUE, "fault fixture file ID: " + std::to_string(GetLastError()));
    const auto id = VolumeKeeperWalFileIdentity({path, h}); CloseHandle(h); return id;
}
std::map<std::filesystem::path, Bytes> Evidence(const std::filesystem::path& root)
{
    std::map<std::filesystem::path, Bytes> result;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(root))
        if (entry.is_regular_file() && !entry.path().filename().string().ends_with(".hashes.tsv")) result.emplace(entry.path(), fixture::Read(entry.path()));
    return result;
}
void SaveHashes(const std::filesystem::path& root, const char* label)
{
    std::string rows;
    for (const auto& [path, bytes] : Evidence(root)) {
        BCRYPT_ALG_HANDLE alg{}; std::array<unsigned char, 32> digest{};
        Check(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0, "evidence digest algorithm");
        const auto status = BCryptHash(alg, nullptr, 0, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())),
            static_cast<ULONG>(bytes.size()), digest.data(), 32);
        BCryptCloseAlgorithmProvider(alg, 0); Check(status >= 0, "evidence digest");
        const char hex[] = "0123456789abcdef";
        for (const auto b : digest) { rows += hex[b >> 4]; rows += hex[b & 15]; }
        const auto name = path.lexically_relative(root).generic_u8string();
        rows += '\t'; rows.append(reinterpret_cast<const char*>(name.data()), name.size()); rows += '\n';
    }
    MarkerBytes(root / (std::string(label) + ".hashes.tsv"), rows);
}
void ForgeProofId(const std::filesystem::path& path, const std::string& old_id, const std::string& new_id)
{
    auto bytes = fixture::Read(path);
    const auto old = std::span(reinterpret_cast<const std::byte*>(old_id.data()), old_id.size());
    auto found = std::search(bytes.begin(), bytes.end(), old.begin(), old.end());
    Check(found != bytes.end(), "original proof ID located");
    std::memcpy(&*found, new_id.data(), new_id.size());
    std::array<unsigned char, 32> hash{}; BCRYPT_ALG_HANDLE alg{};
    Check(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0, "forged proof checksum algorithm");
    const auto status = BCryptHash(alg, nullptr, 0, reinterpret_cast<PUCHAR>(bytes.data() + 80), static_cast<ULONG>(bytes.size() - 80), hash.data(), 32);
    BCryptCloseAlgorithmProvider(alg, 0); Check(status >= 0, "forged proof checksum");
    const char digits[] = "0123456789abcdef";
    for (std::size_t i = 0; i < hash.size(); ++i) { bytes[16 + i * 2] = std::byte(digits[hash[i] >> 4]); bytes[17 + i * 2] = std::byte(digits[hash[i] & 15]); }
    fixture::Save(path, bytes);
}

VolumeManagementRequest NextCreate(const std::filesystem::path& image, const std::filesystem::path& root, const VolumeKeeperHistoryContext& context)
{
    const auto cp = fixture::Checkpoint(fixture::Read(image)); VolumeManagementRequest next;
    next.operation = VolumeManagementOperation::Create; next.image = image; next.journal_directory = root;
    next.history_context = context; next.container_uuid = cp.container.superblock.uuid_hex;
    next.volume_oid = cp.container.superblock.next_oid; next.checkpoint_xid = cp.container.superblock.xid;
    next.volume_uuid = "123456781234423482341234567890ab"; next.name_utf8 = "Next generation";
    for (const auto& v : cp.volumes) next.sibling_wals[v.superblock.object_id] = Wal(context, next.container_uuid, v.superblock.object_id);
    return next;
}
std::uint64_t PublishTimestamp(const std::filesystem::path&, const std::filesystem::path&, std::uint64_t, bool canonical = false);

void NextPlan(const std::filesystem::path& image, const std::filesystem::path& root, const VolumeKeeperHistoryContext& context,
    const std::filesystem::path& original_journal, const Bytes& original_bytes)
{
    const auto before = fixture::Read(image); const auto next = NextCreate(image, root, context);
    auto prepared = PrepareVolumeCreate(next);
    Check(prepared.outcome == VolumeManagementOutcome::Prepared, "next plan preserves retired history: " + prepared.error);
    const auto cancelled = CancelVolumeManagement(next, prepared.confirmation_token);
    Check(cancelled.outcome == VolumeManagementOutcome::Cancelled, "next plan cancels under retained real roots");
    Check(fixture::Read(image) == before, "next prepare preserves image");
    bool retained = false;
    for (const auto& e : std::filesystem::directory_iterator(root))
        if (e.path().filename().wstring().starts_with(original_journal.filename().wstring()) && e.is_regular_file())
            retained |= fixture::Read(e.path()) == original_bytes;
    Check(retained, "original journal bytes retained by existing native archive lifecycle");
    prepared = PrepareVolumeCreate(next);
    Check(prepared.outcome == VolumeManagementOutcome::Prepared, "next plan after cancellation: " + prepared.error);
    const auto committed = ApplyVolumeManagement(next, prepared.confirmation_token);
    Check(committed.outcome == VolumeManagementOutcome::Committed, "next create commits with complete original history: " + committed.error);
    const auto wal = Wal(context, next.container_uuid, next.volume_oid); std::filesystem::create_directories(wal.parent_path());
    const auto xid = PublishTimestamp(image, wal, next.volume_oid);
    Mark(context, next.container_uuid, next.volume_oid, xid);
    const auto recovered = RecoverVolumeManagement(next);
    Check(recovered.outcome == VolumeManagementOutcome::Committed, "create terminal continuation after real child WAL: " + recovered.error);
}

std::uint64_t PublishTimestamp(const std::filesystem::path& image,
    const std::filesystem::path& wal, std::uint64_t oid, bool canonical)
{
    std::string error;
    auto device = BlockDevice::OpenExclusiveManagementImage(image.wstring(), 0, error);
    Check(!!device, error);
    Bytes bytes;
    Check(device->Read(0, static_cast<std::size_t>(device->GetGeometry().total_bytes), bytes), "read held source");
    const auto cp = fixture::Checkpoint(bytes);
    const auto volume = std::find_if(cp.volumes.begin(), cp.volumes.end(),
        [&](const auto& v) { return v.superblock.object_id == oid; });
    Check(volume != cp.volumes.end(), "exact native member");
    VectorRandomAccessSource source(bytes);
    std::vector<BtreeRecord> records;
    Check(ReadBtreeLeafRecords(source, 4096, volume->root_tree.physical_block,
        (volume->root_tree.type & kObjectStorageTypeMask) == kObjectPhysical,
        volume->superblock.omap_oid, cp.container.superblock.xid, records, error), error);
    bool updated = false;
    const auto stamp = 1700000000000000000ull + cp.container.superblock.xid * 100;
    for (auto& record : records) {
        AppleInodeRecord inode;
        if (ApfsExtendedRecordCodec::DecodeInode(record, inode, error) && inode.object_id == 2) {
            inode.modification_time = stamp;
            Check(EncodeAppleInodeRecord(inode, record, error), error);
            updated = true;
        }
    }
    Check(updated, "existing root inode timestamp changed");
    AppleVolumeTransactionRequest request;
    request.volume_object_id = oid;
    request.filesystem_records = std::move(records);
    AppleVolumeTransactionPlan plan;
    Check(PlanAppleVolumeTransaction(source, cp, request, plan, error), "timestamp planning: " + error);
    TransactionManager writer(L"Strict");
    const auto identity = canonical ? "apfs-vol:" + cp.container.superblock.uuid_hex + ":" + std::to_string(oid) :
        DerivePartitionlessVolumeRecoveryIdentity(cp.container.superblock.uuid_hex, oid);
    writer.SetJournalPath(wal.wstring());
    writer.SetVolumeIdentity(std::wstring(identity.begin(), identity.end()));
    TransactionManager::MutationIntent intent;
    intent.kind = TransactionManager::MutationKind::SetInodeMetadata;
    intent.path = L"\\";
    intent.object_id = 2;
    intent.generation = plan.commit.publication.transaction_xid;
    InodeMetadataPatch patch;
    patch.mask = InodeMetadataPatch::ModificationTime;
    patch.modification_time_utc = InodeMetadataPatch::UnixEpochTicks + stamp / 100;
    Check(EncodeInodeMetadataPatch(patch, intent.inline_payload), "valid native inode metadata patch");
    intent.length = intent.inline_payload.size();
    intent.payload_length = intent.inline_payload.size();
    BCRYPT_ALG_HANDLE algorithm{};
    Check(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0, "native patch hash algorithm");
    const auto hash_status = BCryptHash(algorithm, nullptr, 0, reinterpret_cast<PUCHAR>(intent.inline_payload.data()),
        static_cast<ULONG>(intent.inline_payload.size()), intent.payload_checksum.data(), static_cast<ULONG>(intent.payload_checksum.size()));
    BCryptCloseAlgorithmProvider(algorithm, 0);
    Check(hash_status >= 0, "native patch SHA256");
    Check(writer.Begin(), "real native WAL begin");
    Check(writer.RecordMutation(intent), "real native WAL metadata intent");
    Check(writer.Accept(cp.container.superblock.xid), "real native WAL acceptance");
    const auto accepted = writer.Watermarks().accepted_sequence;
    Check(accepted != 0, "nonempty native accepted WAL");
    Check(ExecuteAppleCheckpointPublication(*device, plan.commit.publication, error), "timestamp publication: " + error);
    Check(writer.MarkApfsDurableThrough(accepted) && writer.MarkCleanedThrough(accepted), "native durable CLEAN boundary");
    Bytes after;
    Check(device->Read(0, bytes.size(), after), "readback native publication");
    const auto current = fixture::Checkpoint(after);
    Check(current.container.superblock.xid == cp.container.superblock.xid + 1, "one genuine later native generation");
    return current.container.superblock.xid;
}

void SeedOriginals(const std::filesystem::path& image, const std::map<std::uint64_t, std::filesystem::path>& wals)
{
    for (const auto& [oid, wal] : wals) {
        PublishTimestamp(image, wal, oid);
        Check(std::filesystem::file_size(wal) != 0, "original native WAL is not manufactured empty");
    }
}
void SiblingDebt(const VolumeImageRequest& r)
{
    const auto oid = r.sibling_wals.begin()->first;
    const auto id = DerivePartitionlessVolumeRecoveryIdentity(r.container_uuid, oid);
    TransactionManager tx(L"Strict"); tx.SetJournalPath(r.sibling_wals.at(oid).wstring()); tx.SetVolumeIdentity(std::wstring(id.begin(), id.end()));
    TransactionManager::MutationIntent intent; intent.kind = TransactionManager::MutationKind::CreateDirectory;
    intent.path = L"\\retained-debt"; intent.object_id = 4000; intent.generation = 1;
    Check(tx.Begin() && tx.RecordMutation(intent) && tx.Accept(r.checkpoint_xid), "real accepted sibling WAL debt");
}

void PreacceptHookCancellation(const std::filesystem::path& root, bool format)
{
    std::filesystem::create_directories(root);
    const auto seed = fixture::Fixture();
    auto r = fixture::Request(root, VolumeImageOperation::Format, seed);
    Production(r, root);
    fixture::Save(r.image, seed);
    SeedOriginals(r.image, r.sibling_wals);
    r.checkpoint_xid = fixture::Checkpoint(fixture::Read(r.image)).container.superblock.xid;
    for (const auto& [oid, path] : r.sibling_wals) Mark(r.history_context, r.container_uuid, oid, r.checkpoint_xid);
    VolumeManagementRequest m;
    m.operation = VolumeManagementOperation::Delete; m.image = r.image; m.journal_directory = root;
    m.container_uuid = r.container_uuid; m.volume_uuid = r.volume_uuid; m.volume_oid = r.volume_oid;
    m.checkpoint_xid = r.checkpoint_xid; m.sibling_wals = r.sibling_wals; m.history_context = r.history_context;
    std::filesystem::path journal;
    std::string identity, token;
    if (format) {
        const auto p = PrepareVolumeFormat(r);
        Check(p.outcome == VolumeImageOutcome::Prepared, "hook fixture format Prepare: " + p.error);
        journal = p.journal; identity = p.source_identity; token = p.token;
    } else {
        const auto p = PrepareVolumeDelete(m);
        Check(p.outcome == VolumeManagementOutcome::Prepared, "hook fixture delete Prepare: " + p.error);
        journal = p.journal_path; identity = p.source_identity; token = p.confirmation_token;
    }
    const auto proof = Proof(journal, identity);
    Check(!std::filesystem::exists(proof), "prepared hook fixture has no history proof");
    const auto marker_oid = r.sibling_wals.begin()->first;
    const auto stage = format ? "before-image-accept" : "before-volume-management-accept";
    unsigned hits = 0;
    const AppleCheckpointStageHook hook = [&](std::string_view at) {
        if (at != stage) return true;
        ++hits; return false;
    };
    Mark(r.history_context, r.container_uuid, marker_oid, r.checkpoint_xid + 1);
    const auto ahead = Evidence(root);
    SaveHashes(root, "hook-ahead-before");
    std::string refusal_json, error;
    bool refused = false;
    if (format) {
        const auto result = ApplyVolumeFormat(r, token, hook);
        refusal_json = VolumeImageJson(r, result); error = result.error;
        refused = result.outcome == VolumeImageOutcome::Refused;
    } else {
        const auto result = ApplyVolumeManagement(m, token, hook);
        refusal_json = VolumeManagementJson(m, result); error = result.error;
        refused = result.outcome == VolumeManagementOutcome::Refused;
    }
    SaveHashes(root, "hook-ahead-after");
    const bool unchanged = Evidence(root) == ahead;
    MarkerBytes(root / "hook-ahead-result.json", refusal_json);
    Check(hits == 1, "actual preacceptance cancellation hook invoked once");
    Check(refused && error == "KeeperHistoryMarkerCheckpointUnproved", "hook ahead marker refuses before receipt: " + refusal_json);
    Check(unchanged, "hook refusal preserves entire image/WAL/marker/journal artifact set");
    Check(!std::filesystem::exists(proof), "hook refusal cannot mint history proof");
    Check(DecodeVolumeKeeperHistoryBinding(fixture::Read(journal), journal, root, identity).state ==
        VolumeKeeperJournalState::Prepared, "hook refusal leaves exact Prepared native frame");
    std::cout << "REFUSED " << (format ? "VIF" : "VMT") << " hook-ahead " << error << '\n';

    Mark(r.history_context, r.container_uuid, marker_oid, r.checkpoint_xid);
    const auto valid = Evidence(root);
    SaveHashes(root, "hook-valid-before");
    hits = 0;
    std::string cancelled_json;
    bool cancelled = false;
    if (format) {
        const auto result = ApplyVolumeFormat(r, token, hook);
        cancelled_json = VolumeImageJson(r, result);
        cancelled = result.outcome == VolumeImageOutcome::Cancelled && result.error.empty();
    } else {
        const auto result = ApplyVolumeManagement(m, token, hook);
        cancelled_json = VolumeManagementJson(m, result);
        cancelled = result.outcome == VolumeManagementOutcome::Cancelled && result.error.empty();
    }
    SaveHashes(root, "hook-valid-after");
    const auto after = Evidence(root);
    MarkerBytes(root / "hook-valid-result.json", cancelled_json);
    Check(hits == 1 && cancelled, "valid marker retains preacceptance hook cancellation: " + cancelled_json);
    Check(after.size() == valid.size(), "hook cancellation creates no extra evidence");
    for (const auto& [path, bytes] : valid)
        Check(path == journal || (after.contains(path) && after.at(path) == bytes), "only original cancellation receipt may change");
    Check(after.at(journal) != valid.at(journal), "valid hook appends native cancellation receipt");
    Check(DecodeVolumeKeeperHistoryBinding(after.at(journal), journal, root, identity).state ==
        VolumeKeeperJournalState::Cancelled, "native decoder proves Cancelled without Accepted receipt");
    Check(!std::filesystem::exists(proof), "valid hook cancellation creates no history proof");
    std::cout << "CANCELLED " << (format ? "VIF" : "VMT") << " hook-valid image/WAL unchanged, proof absent\n";
}

bool Delete(const std::filesystem::path& root, const std::string& scenario = {})
{
    const bool vif_prepare = scenario.starts_with("vif-");
    const auto attack = vif_prepare ? scenario.substr(4) : scenario;
    std::filesystem::create_directories(root);
    const auto seed = fixture::Fixture();
    auto image_request = fixture::Request(root, VolumeImageOperation::Format, seed);
    Production(image_request, root);
    fixture::Save(image_request.image, seed);
    SeedOriginals(image_request.image, image_request.sibling_wals);
    const auto cp = fixture::Checkpoint(fixture::Read(image_request.image));
    VolumeManagementRequest request;
    request.operation = VolumeManagementOperation::Delete;
    request.image = image_request.image;
    request.journal_directory = root;
    request.container_uuid = cp.container.superblock.uuid_hex;
    request.volume_oid = cp.volumes.front().superblock.object_id;
    request.volume_uuid = cp.volumes.front().superblock.uuid_hex;
    request.checkpoint_xid = cp.container.superblock.xid;
    request.sibling_wals = image_request.sibling_wals;
    request.history_context = image_request.history_context;
    for (const auto& [oid, path] : request.sibling_wals) Mark(request.history_context, request.container_uuid, oid, request.checkpoint_xid);
    const auto original_image = fixture::Read(request.image);
    if (attack == "incomplete-census") {
        request.sibling_wals.erase(request.sibling_wals.begin());
        const auto result = PrepareVolumeDelete(request);
        Check(result.outcome == VolumeManagementOutcome::Refused && result.error.find("Wal") != std::string::npos,
            "incomplete original census refuses: " + result.error);
        Check(fixture::Read(request.image) == original_image, "incomplete census preserves source"); return true;
    }
    if (attack == "missing-prepare") {
        const auto path = request.sibling_wals.begin()->second;
        Check(MoveFileExW(path.c_str(), (root / "original.wal").c_str(), MOVEFILE_WRITE_THROUGH), "retain missing prepare original");
        const auto evidence = Evidence(root);
        SaveHashes(root, "missing-before");
        const auto result = PrepareVolumeDelete(request);
        SaveHashes(root, "missing-after");
        Check(result.outcome == VolumeManagementOutcome::Refused, "missing current Prepare refused");
        Check(!std::filesystem::exists(path) && Evidence(root) == evidence, "Prepare continued absence and all artifacts unchanged");
        std::cout << "REFUSED missing-prepare " << result.error << '\n'; return true;
    }
    const auto prepared = PrepareVolumeDelete(request);
    Check(prepared.outcome == VolumeManagementOutcome::Prepared, "delete prepare: " + prepared.error);
    if (attack == "missing-apply" || attack == "missing-recover") {
        const auto path = request.sibling_wals.begin()->second;
        Check(MoveFileExW(path.c_str(), (root / "original.wal").c_str(), MOVEFILE_WRITE_THROUGH), "retain missing unaccepted original");
        const auto evidence = Evidence(root);
        SaveHashes(root, "missing-before");
        const auto result = attack == "missing-apply" ? ApplyVolumeManagement(request, prepared.confirmation_token) : RecoverVolumeManagement(request);
        SaveHashes(root, "missing-after");
        Check(result.outcome == VolumeManagementOutcome::Refused, "missing current unaccepted operation refused: " + result.error);
        Check(!std::filesystem::exists(path) && Evidence(root) == evidence, "unaccepted continued absence and all artifacts unchanged");
        std::cout << "REFUSED " << attack << " " << result.error << '\n'; return true;
    }
    const bool proof_retry = attack == "proof-file-flush" || attack == "proof-directory-flush";
    const bool damaged_proof = attack == "partial-proof-retry" || attack == "mismatch-proof-retry";
    if (proof_retry || damaged_proof) {
        const auto stage = attack == "proof-file-flush" ? "before-history-proof-file-flush" : "before-history-proof-directory-flush";
        const auto journal = fixture::Read(prepared.journal_path);
        const auto proof = Proof(prepared.journal_path, prepared.source_identity);
        Bytes original;
        for (unsigned attempt = 0; attempt < 2; ++attempt) {
            unsigned hits = 0;
            const auto failed = ApplyVolumeManagement(request, prepared.confirmation_token, [&](std::string_view at) {
                if (at == stage) { ++hits; return false; } return true;
            });
            Check(hits == 1 && failed.outcome == VolumeManagementOutcome::Refused, "proof barrier refuses every retry: " + failed.error);
            Check(fixture::Read(request.image) == original_image && fixture::Read(prepared.journal_path) == journal, "failed barrier stays unaccepted");
            Check(std::filesystem::exists(proof), "complete readable proof survived failed barrier");
            if (!attempt) original = fixture::Read(proof);
            Check(fixture::Read(proof) == original, "retry keeps immutable proof bytes");
        }
        if (damaged_proof) {
            auto damaged = original;
            if (attack == "partial-proof-retry") damaged.resize(damaged.size() / 2);
            else damaged.back() ^= std::byte{1};
            fixture::Save(root / "original-proof.bin", original); fixture::Save(proof, damaged);
            const auto before = Evidence(root); SaveHashes(root, "proof-before");
            const auto refused = ApplyVolumeManagement(request, prepared.confirmation_token);
            SaveHashes(root, "proof-after");
            Check(refused.outcome == VolumeManagementOutcome::Refused && refused.error == "KeeperHistoryExistingProofChanged", "partial/mismatched proof is never repaired");
            Check(Evidence(root) == before, "partial/mismatched proof refusal preserves complete artifact set");
            std::cout << "REFUSED " << attack << " " << refused.error << '\n'; return true;
        }
        std::cout << "RETRY " << attack << " twice refused before acceptance\n";
    }
    auto committed = ApplyVolumeManagement(request, prepared.confirmation_token, [&](std::string_view stage) {
        return attack != "accepted-crash" || stage != "after-volume-management-accept";
    });
    if (attack == "accepted-crash") {
        Check(committed.outcome == VolumeManagementOutcome::RecoveryRequired, "accepted interruption is recoverable");
        Check(std::filesystem::exists(Proof(committed.journal_path, committed.source_identity)), "individual identity proof durable before acceptance");
        committed = RecoverVolumeManagement(request);
    }
    Check(committed.outcome == VolumeManagementOutcome::Committed, "delete commit: " + committed.error);
    const auto immediate = RecoverVolumeManagement(request);
    Check(immediate.outcome == VolumeManagementOutcome::Committed, "delete original immediate recovery: " + immediate.error);
    const auto retired_before = fixture::Read(request.sibling_wals.at(request.volume_oid));
    const auto journal_before = fixture::Read(committed.journal_path);
    const auto survivor = fixture::Checkpoint(fixture::Read(request.image)).volumes.front().superblock.object_id;
    const auto later_xid = PublishTimestamp(request.image, request.sibling_wals.at(survivor), survivor);
    Mark(request.history_context, request.container_uuid, survivor, later_xid);
    bool observed = false;
    const auto observation = ObserveVolumeKeeperHistoryJson(request.image, root, request.history_context, observed);
    Check(observed, "detached clean observation before subsequent fault: " + observation);
    const auto retired = request.sibling_wals.at(request.volume_oid), current_wal = request.sibling_wals.at(survivor);
    std::unique_ptr<WriteAheadLog> contended;
    HANDLE held_fence = INVALID_HANDLE_VALUE;
    const auto preserve = [&](const std::filesystem::path& p) {
        std::filesystem::create_directories(root / "preserved"); fixture::Save(root / "preserved" / p.filename(), fixture::Read(p));
    };
    if (attack.starts_with("dirty-") || attack.starts_with("accepted-") && attack != "accepted-crash" || attack.starts_with("checkpointed-")) {
        const auto oid = attack.ends_with("retired") ? request.volume_oid : survivor;
        const auto path = request.sibling_wals.at(oid); preserve(path);
        const auto id = DerivePartitionlessVolumeRecoveryIdentity(request.container_uuid, oid);
        TransactionManager tx(L"Strict"); tx.SetJournalPath(path.wstring()); tx.SetVolumeIdentity(std::wstring(id.begin(), id.end()));
        Check(tx.Begin(), "fault injection native begin");
        TransactionManager::MutationIntent intent; intent.kind = TransactionManager::MutationKind::CreateDirectory;
        intent.path = L"\\unfinished"; intent.object_id = 4000; intent.generation = 1;
        Check(tx.RecordMutation(intent), "fault injection native prepared record");
        Check(tx.FlushPreparedRecords(), "fault injection durable unaccepted native record");
        if (attack.starts_with("accepted-")) Check(tx.Accept(later_xid), "valid accepted debt with original pin");
        if (attack.starts_with("checkpointed-")) Check(tx.Commit(later_xid), "valid checkpointed debt past cleanup");
        const auto records = WriteAheadLog::ReadAll(path, id);
        Check(records.status == WriteAheadLog::ReadStatus::Ok && !records.recovered_torn_tail, "native decoder validates complete WAL frames");
        Check(std::any_of(records.records.begin(), records.records.end(), [](const auto& r) {
            return r.operation == WriteAheadLog::OperationKind::CreateDirectory && r.object_id == 4000 &&
                r.state == WriteAheadLog::RecordState::Prepared && r.path_utf8 == "\\unfinished";
        }), "valid native object identity and unaccepted mutation recorded");
    } else if (attack == "foreign") {
        preserve(retired); fixture::Save(retired, fixture::Read(current_wal));
    } else if (attack == "replaced" || attack == "forged-file-id") {
        const auto replacement = root / "replacement.wal", backup = root / "preserved-original.wal";
        const auto original_id = FileId(retired);
        fixture::Save(replacement, fixture::Read(retired));
        Check(ReplaceFileW(retired.c_str(), replacement.c_str(), backup.c_str(), 0, nullptr, nullptr), "private replacement preserves original file as backup");
        if (attack == "forged-file-id") {
            const auto proof = Proof(committed.journal_path, committed.source_identity); preserve(proof);
            ForgeProofId(proof, original_id, FileId(retired));
            MarkerBytes(root / "request.json", VolumeManagementJson(request, committed));
        }
    } else if (attack == "missing") {
        Check(MoveFileExW(retired.c_str(), (root / "preserved-original.wal").c_str(), MOVEFILE_WRITE_THROUGH),
            "isolated missing-path fault retains original native WAL file");
    } else if (attack == "alias") {
        Check(CreateHardLinkW((root / "alias.wal").c_str(), retired.c_str(), nullptr), "private second WAL link");
    } else if (attack == "bad-proof") {
        const auto proof = Proof(committed.journal_path, committed.source_identity); preserve(proof);
        auto b = fixture::Read(proof); b.back() ^= std::byte{1}; fixture::Save(proof, b);
    } else if (attack == "missing-proof") {
        const auto proof = Proof(committed.journal_path, committed.source_identity);
        Check(MoveFileExW(proof.c_str(), (root / "preserved-proof.bin").c_str(), MOVEFILE_WRITE_THROUGH), "preserve missing proof original");
    } else if (attack == "proof-journal-binding" || attack == "proof-source-binding") {
        const auto proof = Proof(committed.journal_path, committed.source_identity); preserve(proof);
        const auto b = DecodeVolumeKeeperHistoryBinding(fixture::Read(committed.journal_path), committed.journal_path, root, committed.source_identity);
        const auto old = attack == "proof-journal-binding" ? b.frame_digest : b.source_identity;
        auto changed = old; changed[0] = changed[0] == '1' ? '2' : '1'; ForgeProofId(proof, old, changed);
    } else if (attack == "proof-alias") {
        const auto proof = Proof(committed.journal_path, committed.source_identity);
        Check(CreateHardLinkW((root / "alias-proof.bin").c_str(), proof.c_str(), nullptr), "private proof alias");
    } else if (attack == "lease-busy") {
        contended = std::make_unique<WriteAheadLog>(WriteAheadLog::Options{retired, DerivePartitionlessVolumeRecoveryIdentity(request.container_uuid, request.volume_oid)});
        Check(contended->AcquireWriterLeaseOnly(), "actual competing retired writer lease held");
    } else if (attack == "fence-busy") {
        held_fence = CreateFileW(retired.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        Check(held_fence != INVALID_HANDLE_VALUE, "actual competing file fence held");
    } else if (attack == "forged-terminal") {
        preserve(committed.journal_path); auto b = fixture::Read(committed.journal_path); b.back() ^= std::byte{1}; fixture::Save(committed.journal_path, b);
    } else if (attack == "oid-reuse") {
        preserve(request.image); auto bytes = fixture::Read(request.image); const auto current = fixture::Checkpoint(bytes);
        const auto at = current.volumes.front().superblock_object.physical_block * 4096;
        Bytes block(bytes.begin() + at, bytes.begin() + at + 4096); block[0xf0] ^= std::byte{1};
        apfsaccess::testfixture::FletcherForBlock(block, 4096); std::copy(block.begin(), block.end(), bytes.begin() + at);
        fixture::Save(request.image, bytes);
        const auto changed = fixture::Checkpoint(bytes);
        Check(changed.container.superblock.xid == later_xid && changed.volumes.front().superblock.object_id == survivor &&
            changed.volumes.front().superblock.uuid_hex != current.volumes.front().superblock.uuid_hex, "valid current OID with different UUID");
    } else if (attack == "marker-ahead") {
        preserve(Marker(request.history_context, request.container_uuid, survivor)); Mark(request.history_context, request.container_uuid, survivor, later_xid + 1);
    } else if (attack == "retired-marker-ahead") {
        preserve(Marker(request.history_context, request.container_uuid, request.volume_oid)); Mark(request.history_context, request.container_uuid, request.volume_oid, later_xid);
    } else if (attack == "marker-noncanonical") {
        const auto marker = Marker(request.history_context, request.container_uuid, survivor); preserve(marker);
        MarkerBytes(marker, "dirty=0\nlastCommitXid=011\n");
    } else if (attack == "unknown-spool") {
        MarkerBytes(current_wal.parent_path() / "unknown.evidence", "preserve unknown evidence");
    } else if (attack == "compact-retired" || attack == "compact-current") {
        MarkerBytes((attack.ends_with("retired") ? retired : current_wal).wstring() + L".compact.pending", "retained compaction evidence");
    }
    const auto evidence_wal = attack == "missing" ? root / "preserved-original.wal" : retired;
    if (vif_prepare) {
        const auto before = fixture::Read(request.image);
        auto next = fixture::Request(root, VolumeImageOperation::Grow, before); next.history_context = request.history_context;
        for (auto& [oid, wal] : next.sibling_wals) wal = Wal(next.history_context, next.container_uuid, oid);
        const auto evidence = Evidence(root);
        SaveHashes(root, "vif-prepare-before");
        const auto refused = PrepareVolumeResize(next);
        SaveHashes(root, "vif-prepare-after");
        Check(refused.outcome == VolumeImageOutcome::Refused && !refused.error.empty(), "VIF Prepare actual held history refusal: " + refused.error);
        Check(fixture::Read(request.image) == before, "VIF Prepare preserves current source");
        for (const auto& [path, bytes] : evidence) Check(fixture::Read(path) == bytes, "VIF Prepare preserves original evidence");
        const auto binding = DecodeVolumeKeeperHistoryBinding(fixture::Read(refused.journal), refused.journal, root, refused.source_identity);
        Check(binding.state == VolumeKeeperJournalState::Prepared, "failed VIF Prepare leaves valid unaccepted native frame");
        if (attack == "missing") Check(MoveFileExW((root / "preserved-original.wal").c_str(), retired.c_str(), MOVEFILE_WRITE_THROUGH), "restore same private original file identity");
        else if (attack == "replaced") {
            Check(MoveFileExW(retired.c_str(), (root / "rejected-replacement.wal").c_str(), MOVEFILE_WRITE_THROUGH), "retain rejected replacement");
            Check(MoveFileExW((root / "preserved-original.wal").c_str(), retired.c_str(), MOVEFILE_WRITE_THROUGH), "restore same private original WAL");
        } else if (attack == "alias") Check(DeleteFileW((root / "alias.wal").c_str()), "remove private extra alias only");
        else if (attack == "dirty-retired") fixture::Save(retired, retired_before);
        const auto recovered = RecoverVolumeResize(next);
        Check(recovered.outcome == VolumeImageOutcome::Cancelled && fixture::Read(request.image) == before, "refused Prepare recovers after original evidence restored: " + recovered.error);
        std::cout << "REFUSED " << scenario << " " << refused.error << " then original unaccepted recovery cancelled\n";
        return true;
    }
    const auto before = fixture::Read(request.image), wal_before = attack == "fence-busy" ? retired_before : fixture::Read(evidence_wal), terminal_before = fixture::Read(committed.journal_path);
    if (attack != "fence-busy") SaveHashes(root, "recovery-before");
    const auto recovered = RecoverVolumeManagement(request);
    if (held_fence != INVALID_HANDLE_VALUE) CloseHandle(held_fence);
    contended.reset();
    SaveHashes(root, "recovery-after");
    Check(fixture::Read(request.image) == before && fixture::Read(committed.journal_path) == terminal_before &&
        fixture::Read(evidence_wal) == wal_before, "delete recovery never changes supplied evidence");
    if (!attack.empty() && attack != "accepted-crash" && !proof_retry) {
        Check(recovered.outcome != VolumeManagementOutcome::Committed && !recovered.error.empty(), "refuse " + attack);
        if (attack == "oid-reuse") Check(recovered.error == "KeeperHistoryCurrentTopologyMismatchOrOidReuse", "OID reuse exact native refusal: " + recovered.error);
        if (attack == "forged-terminal") Check(recovered.error.find("Checksum") != std::string::npos, "forged receipt checksum refusal: " + recovered.error);
        if (attack == "forged-file-id") Check(recovered.error == "KeeperHistoryOriginalFileIdentityCensusUnproved", "forged ID cannot match original journal census: " + recovered.error);
        if (attack == "missing") Check(!std::filesystem::exists(retired), "missing original WAL remains missing; native creates no empty replacement");
        if (attack == "missing-proof") Check(!std::filesystem::exists(Proof(committed.journal_path, committed.source_identity)), "missing completed proof stays missing");
        if (attack == "proof-journal-binding" || attack == "proof-source-binding") Check(recovered.error == "KeeperHistoryProofJournalBindingMismatch", "exact original proof cross-binding refuses");
        if (attack == "lease-busy") Check(recovered.error == "KeeperHistoryWalBusy", "actual writer lease prevents detached authority transfer");
        std::cout << "REFUSED " << attack << " " << recovered.error << '\n'; return true;
    }
    Check(wal_before == retired_before && terminal_before == journal_before, "all original retired bytes preserved");
    std::cout << "DELETE pre=" << request.checkpoint_xid << " post=" << committed.post_xid << " current=" << later_xid
        << " committed=" << (recovered.outcome == VolumeManagementOutcome::Committed)
        << " error=" << recovered.error << '\n';
    Check(recovered.outcome == VolumeManagementOutcome::Committed, "delete completed continuation");
    NextPlan(request.image, root, request.history_context, committed.journal_path, journal_before);
    Check(fixture::Read(retired) == retired_before, "next operation preserves original retired WAL");
    return true;
}

bool Format(const std::filesystem::path& root, const std::string& attack = {})
{
    std::filesystem::create_directories(root);
    const auto seed = fixture::Fixture();
    auto request = fixture::Request(root, VolumeImageOperation::Format, seed);
    Production(request, root);
    fixture::Save(request.image, seed);
    SeedOriginals(request.image, request.sibling_wals);
    request.checkpoint_xid = fixture::Checkpoint(fixture::Read(request.image)).container.superblock.xid;
    for (const auto& [oid, path] : request.sibling_wals) Mark(request.history_context, request.container_uuid, oid, request.checkpoint_xid);
    const auto prepared = PrepareVolumeFormat(request);
    Check(prepared.outcome == VolumeImageOutcome::Prepared, "format prepare: " + prepared.error);
    if (!attack.empty()) {
        const auto stage = attack == "proof-file-flush" ? "before-history-proof-file-flush" : "before-history-proof-directory-flush";
        const auto source = fixture::Read(request.image), journal = fixture::Read(prepared.journal);
        const auto proof = Proof(prepared.journal, prepared.source_identity); Bytes first;
        for (unsigned attempt = 0; attempt < 2; ++attempt) {
            unsigned hits = 0;
            const auto failed = ApplyVolumeFormat(request, prepared.token, [&](std::string_view at) {
                if (at == stage) { ++hits; return false; } return true;
            });
            Check(hits == 1 && failed.outcome == VolumeImageOutcome::Refused, "format proof retry refuses before acceptance: " + failed.error);
            Check(fixture::Read(request.image) == source && fixture::Read(prepared.journal) == journal, "format proof failure preserves original generation");
            if (!attempt) first = fixture::Read(proof);
            Check(fixture::Read(proof) == first, "format proof immutable retry");
        }
        std::cout << "FORMAT RETRY " << attack << " twice refused before acceptance\n";
    }
    const auto committed = ApplyVolumeFormat(request, prepared.token);
    Check(committed.outcome == VolumeImageOutcome::Committed, "format commit: " + committed.error);
    const auto immediate = RecoverVolumeFormat(request);
    Check(immediate.outcome == VolumeImageOutcome::Committed, "format original immediate recovery: " + immediate.error);
    const auto journal_before = fixture::Read(committed.journal);
    std::map<std::uint64_t, Bytes> originals;
    for (const auto& [oid, path] : request.sibling_wals) originals[oid] = fixture::Read(path);
    const auto later_xid = PublishTimestamp(request.image, request.new_volume_wal, 1024);
    Mark(request.history_context, request.new_container_uuid, 1024, later_xid);
    const auto before = fixture::Read(request.image);
    SaveHashes(root, "recovery-before");
    const auto recovered = RecoverVolumeFormat(request);
    SaveHashes(root, "recovery-after");
    Check(fixture::Read(request.image) == before && fixture::Read(committed.journal) == journal_before, "format recovery preserves image and original journal");
    for (const auto& [oid, path] : request.sibling_wals)
        Check(fixture::Read(path) == originals.at(oid), "format preserves every original retired WAL");
    std::cout << "FORMAT pre=" << request.checkpoint_xid << " post=" << committed.post_xid << " current=" << later_xid
        << " committed=" << (recovered.outcome == VolumeImageOutcome::Committed)
        << " error=" << recovered.error << '\n';
    Check(recovered.outcome == VolumeImageOutcome::Committed, "format completed continuation");
    Check(ReadU32LE(fixture::Checkpoint(before).container.superblock_bytes, 0xb4) ==
        ReadU32LE(fixture::Checkpoint(seed).container.superblock_bytes, 0xb4), "format preserves original slot budget for next create");
    NextPlan(request.image, root, request.history_context, committed.journal, journal_before);
    const auto next_image = fixture::Read(request.image);
    auto next = fixture::Request(root, VolumeImageOperation::Grow, next_image);
    next.history_context = request.history_context;
    for (auto& [oid, path] : next.sibling_wals) path = Wal(request.history_context, next.container_uuid, oid);
    const auto next_plan = PrepareVolumeResize(next);
    Check(next_plan.outcome == VolumeImageOutcome::Prepared, "format next growth plan: " + next_plan.error);
    const auto grown = ApplyVolumeResize(next, next_plan.token);
    Check(grown.outcome == VolumeImageOutcome::Committed, "format next growth commit with original WALs: " + grown.error);
    std::cout << "FORMAT next create/cancel and growth committed with preserved original storage\n";
    for (const auto& [oid, path] : request.sibling_wals) Check(fixture::Read(path) == originals.at(oid), "next growth preserves original format WALs");
    return true;
}

Bytes IndependentFixture()
{
    auto bytes = fixture::Fixture(); std::array<std::byte, 16> uuid{};
    Check(BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(uuid.data()), static_cast<ULONG>(uuid.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0, "independent ordinary fixture identity");
    for (std::size_t at = 0; at < bytes.size(); at += 4096) {
        Bytes nx(bytes.begin() + at, bytes.begin() + at + 4096);
        if (!ParseNxSuperblock(nx)) continue;
        std::copy(uuid.begin(), uuid.end(), nx.begin() + 0x48);
        apfsaccess::testfixture::FletcherForBlock(nx, 4096); std::copy(nx.begin(), nx.end(), bytes.begin() + at);
    }
    return bytes;
}
Bytes BitmapSignatureFixture(bool apsb)
{
    using namespace apfsaccess::testfixture;
    const auto seed = IndependentFixture(); const auto base = fixture::Checkpoint(seed);
    VectorRandomAccessSource source(seed); std::string error;
    BuilderStore spec; spec.authoritative_checkpoint = true; spec.block_count = apsb ? 2048 : 1024;
    spec.authoritative_checkpoint_ring_blocks = 32; spec.authoritative_internal_pool_blocks = 64;
    spec.uuid_hex = base.container.superblock.uuid_hex; spec.volumes.clear();
    for (const auto& member : base.volumes) {
        BuilderVolume v; v.oid = member.superblock.object_id; v.uuid_hex = member.superblock.uuid_hex; v.incompat = 0;
        Check(ReadBtreeLeafRecords(source, 4096, member.root_tree.physical_block, false,
            member.superblock.omap_oid, base.container.superblock.xid, v.filesystem_records, error), error);
        Check(ReadBtreeLeafRecords(source, 4096, member.extentref_tree->physical_block, true,
            0, base.container.superblock.xid, v.extentref_records, error), error);
        v.additional_file_system_allocated_blocks = 1; spec.volumes.push_back(v);
    }
    for (const auto block : {240ull, 248ull})
        spec.authoritative_seeded_main_blocks.emplace_back(block, Bytes(seed.begin() + block * 4096, seed.begin() + (block + 1) * 4096));
    auto& v = spec.volumes.front(); BtreeRecord record;
    AppleInodeRecord inode; inode.object_id = inode.private_id = 31; inode.parent_id = 2; inode.mode = 0100644;
    inode.children_or_links = 1; inode.uncompressed_size = 4 * 4096;
    AppleExtendedField stream{8, 0, Bytes(40)}; PutU64LE(stream.data, 0, 4 * 4096); PutU64LE(stream.data, 8, 4 * 4096);
    inode.extended_fields.push_back(stream);
    Check(EncodeAppleInodeRecord(inode, record, error), error); v.filesystem_records.push_back(record);
    AppleDirectoryRecord entry; entry.parent_id = 2; entry.file_id = 31; entry.name_utf8 = "bitmap-signature.bin"; entry.flags = 8;
    Check(EncodeAppleDirectoryRecord(entry, record, error), error); v.filesystem_records.push_back(record);
    Check(EncodeAppleDataStreamIdRecord({31, 1}, record, error), error); v.filesystem_records.push_back(record);
    const std::array<std::uint64_t, 4> blocks{192, apsb ? 194ull : 193ull, 195, apsb ? 1728ull : 288ull};
    for (unsigned i = 0; i < blocks.size(); ++i) {
        Check(EncodeAppleFileExtentRecord({31, i * 4096ull, 4096, blocks[i], 0, 4096}, record, error), error);
        v.filesystem_records.push_back(record);
        Check(EncodeApplePhysicalExtentRecord({blocks[i], 1, 1, 31, 1}, record, error), error); v.extentref_records.push_back(record);
        spec.authoritative_seeded_main_blocks.emplace_back(blocks[i], Bytes(4096, std::byte(0x81 + i)));
    }
    for (auto& r : v.filesystem_records) {
        if (ReadU64LE(r.key, 0).value_or(0) != ((3ull << 60) | 2)) continue;
        AppleInodeRecord root; Check(ApfsExtendedRecordCodec::DecodeInode(r, root, error), error); root.children_or_links = 2;
        Check(EncodeAppleInodeRecord(root, r, error), error);
    }
    v.additional_file_system_allocated_blocks += blocks.size();
    Check(SortAppleBtreeRecords(v.filesystem_records, AppleBtreeKeyOrder::FileSystemCaseSensitive, error), error);
    Check(SortAppleBtreeRecords(v.extentref_records, AppleBtreeKeyOrder::PhysicalExtent, error), error);
    auto bytes = BuildStoreImage(spec);
    const auto put = [&](std::uint64_t block, const Bytes& data) { std::copy(data.begin(), data.end(), bytes.begin() + block * 4096); };
    for (std::size_t at = 0; at < bytes.size(); at += 4096) {
        Bytes nx(bytes.begin() + at, bytes.begin() + at + 4096); if (!ParseNxSuperblock(nx)) continue;
        PutU32LE(nx, 0xb4, 100); FletcherForBlock(nx, 4096); put(at / 4096, nx);
    }
    for (unsigned i = 0; i < 2; ++i) {
        const auto block = kFirstVolumeBlock + i; Bytes sb(bytes.begin() + block * 4096, bytes.begin() + (block + 1) * 4096);
        PutU64LE(sb, 0xb8, i == 0 ? 2 : 1); PutU64LE(sb, 0xc0, 1); PutU32LE(sb, 0x24, i);
        FletcherForBlock(sb, 4096); put(block, sb);
    }
    // Use the established resize fixture's versioned spaceman layout; all
    // allocation bits and counts above come from the authoritative encoder.
    const auto cp = fixture::Checkpoint(bytes); auto sm = cp.spaceman.bytes;
    const auto cib = ReadU64LE(sm, cp.spaceman.devices[0].address_offset).value();
    const auto xid = ReadU64LE(sm, ReadU32LE(sm, 0x144).value()).value();
    const auto index = ReadU16LE(sm, ReadU32LE(sm, 0x148).value()).value();
    const auto links_at = ReadU32LE(sm, 0x14c).value(); std::array<std::uint16_t, 16> links{};
    for (unsigned i = 0; i < links.size(); ++i) links[i] = ReadU16LE(sm, links_at + i * 2).value();
    std::fill(sm.begin() + 0x158, sm.end(), std::byte{});
    PutU32LE(sm, 0x50, 0xa00); PutU32LE(sm, 0x90, 1); PutU64LE(sm, 0xc0, 0);
    PutU32LE(sm, 0x144, 0xa08); PutU32LE(sm, 0x148, 0xa10); PutU32LE(sm, 0x14c, 0xa20);
    PutU32LE(sm, 0x150, 1); PutU32LE(sm, 0x154, 4096); PutU64LE(sm, 0xa00, cib); PutU64LE(sm, 0xa08, xid); PutU16LE(sm, 0xa10, index);
    for (unsigned i = 0; i < links.size(); ++i) PutU16LE(sm, 0xa20 + i * 2, links[i]);
    FletcherForBlock(sm, 4096); put(cp.spaceman.object.physical_block, sm);
    return bytes;
}
void BitmapOriginalHistory(const std::filesystem::path& root, bool apsb)
{
    std::filesystem::create_directories(root);
    const auto original = BitmapSignatureFixture(apsb); const auto cp = fixture::Checkpoint(original);
    apfsaccess::rw::volume_image::Verify(original, cp); ++checks;
    VectorRandomAccessSource source(original); std::string error; AppleSnapshotRetentionView snapshots;
    Check(LoadAppleSnapshotRetention(source, cp, snapshots, error) && snapshots.identities.empty(), "real snapshot-free bitmap fixture: " + error);
    std::vector<std::uint64_t> metadata; std::vector<ApplePhysicalExtentRecord> payload;
    Check(LoadAppleSnapshotCheckpointOwners(source, cp, metadata, payload, error) && !metadata.empty(), "complete bitmap fixture owners: " + error);
    std::uint64_t payload_blocks = 0; for (const auto& x : payload) payload_blocks += x.block_count;
    Check(payload_blocks == 6, "all six ordinary payload blocks have authoritative owners");
    const auto& chunk = cp.spaceman.chunks.front(); std::uint64_t allocated = 0;
    for (std::uint64_t i = 0; i < chunk.block_count; ++i) allocated += apfsaccess::rw::volume_image::Bit(chunk.allocation_bitmap, i);
    Check(chunk.free_count == chunk.block_count - allocated && cp.spaceman.devices[0].free_count == chunk.free_count,
        "bitmap, chunk and device allocation counts agree");
    Check(std::find(metadata.begin(), metadata.end(), chunk.bitmap_block) != metadata.end(), "headerless bitmap belongs to complete metadata census");
    const auto type = ReadU32LE(chunk.allocation_bitmap, 0x18).value() & kObjectTypeMask;
    Check(type == (apsb ? kObjectTypeFs : kObjectTypeOmap) &&
        (apsb ? ReadU64LE(chunk.allocation_bitmap, 0xd8).value() : ReadU32LE(chunk.allocation_bitmap, 0x24).value()) != 0,
        "ordinary owned allocation bits mimic nonzero APSB/OMAP snapshot fields");
    std::cout << "BITMAP VALID kind=" << (apsb ? "apsb" : "omap") << " blocks=" << chunk.block_count
        << " metadata=" << metadata.size() << " payloadBlocks=" << payload_blocks << " allocated=" << allocated
        << " free=" << chunk.free_count << " bitmap=" << chunk.bitmap_block << " fakeType=" << type << std::endl;
    auto r = fixture::Request(root, apsb ? VolumeImageOperation::Shrink : VolumeImageOperation::Grow, original);
    fixture::Save(r.image, original); for (const auto& [oid, path] : r.sibling_wals) fixture::Save(path, {});
    fixture::Save(root / "original.bin", original);
    const auto wal_ids = [&]() { std::map<std::filesystem::path, std::string> ids; for (const auto& [oid, path] : r.sibling_wals) ids[path] = FileId(path); return ids; }();
    Check(InspectVolumeKeeperImage(r.image, 0, root).admitted, "initial bitmap image admits");
    const auto p = PrepareVolumeResize(r);
    MarkerBytes(root / "prepare.json", VolumeImageJson(r, p));
    Check(fixture::Read(r.image) == original, "prepare preserves valid original bytes");
    if (p.outcome != VolumeImageOutcome::Prepared) {
        const auto stranded = fixture::Read(p.journal); std::string decode_error;
        try { (void)DecodeVolumeKeeperHistoryBinding(stranded, p.journal, root, p.source_identity); }
        catch (const std::exception& ex) { decode_error = ex.what(); }
        const auto admission = InspectVolumeKeeperImage(r.image, 0, root);
        const auto recover = RecoverVolumeResize(r);
        Check(fixture::Read(r.image) == original && fixture::Read(p.journal) == stranded, "failed original recovery preserves stranded evidence");
        std::cout << "BITMAP RED prepare=" << p.error << " decode=" << decode_error << " admission=" << admission.error
            << " recover=" << recover.error << " journalUnchanged=1" << std::endl;
    }
    Check(p.outcome == VolumeImageOutcome::Prepared, "snapshot-free bitmap Prepare must succeed: " + p.error);
    const auto decode = [&](const std::filesystem::path& path, VolumeKeeperJournalState state) {
        const auto bytes = fixture::Read(path); const auto body = ReadU64LE(bytes, 8).value();
        Check(body >= original.size() && std::equal(original.begin(), original.end(), bytes.begin() + 48 + body - original.size()), "embedded original bytes remain exact");
        const auto b = DecodeVolumeKeeperHistoryBinding(bytes, path, root, p.source_identity);
        Check(b.state == state && b.pre_xid == r.checkpoint_xid && b.post_xid == p.post_xid && b.before.size() == 2 &&
            b.source_identity == p.source_identity, "shared decoder retains exact original binding");
    };
    decode(p.journal, VolumeKeeperJournalState::Prepared);
    const auto blocked = InspectVolumeKeeperImage(r.image, 0, root);
    Check(!blocked.admitted && blocked.error == "VolumeKeeperAdmissionBlocked:vif1:prepared", "valid prepared frame is debt, not invalid history");
    Check(CancelVolumeResize(r, p.token).outcome == VolumeImageOutcome::Cancelled, "bitmap original cancels normally");
    decode(p.journal, VolumeKeeperJournalState::Cancelled); const auto cancelled = fixture::Read(p.journal);
    Check(RecoverVolumeResize(r).outcome == VolumeImageOutcome::Cancelled && fixture::Read(p.journal) == cancelled &&
        fixture::Read(r.image) == original && InspectVolumeKeeperImage(r.image, 0, root).admitted, "cancelled original recovery repeats with no stranded journal");
    const auto q = PrepareVolumeResize(r); Check(q.outcome == VolumeImageOutcome::Prepared, "next prepare archives cancelled bitmap original: " + q.error);
    auto archive = p.journal; archive += "." + p.token + ".completed";
    Check(fixture::Read(archive) == cancelled, "archive preserves exact cancelled frame"); decode(archive, VolumeKeeperJournalState::Cancelled);
    const auto unaccepted = ApplyVolumeResize(r, q.token, [](auto stage) { return stage != "before-image-accept"; });
    Check(unaccepted.outcome == VolumeImageOutcome::Cancelled && fixture::Read(r.image) == original, "preaccept interruption cancels bitmap original");
    const auto lost = PrepareVolumeResize(r); Check(lost.outcome == VolumeImageOutcome::Prepared, "lost-reply original prepare: " + lost.error);
    Check(RecoverVolumeResize(r).outcome == VolumeImageOutcome::Cancelled && fixture::Read(r.image) == original,
        "prepared original recovers to cancellation without token");
    const auto accepted = PrepareVolumeResize(r); Check(accepted.outcome == VolumeImageOutcome::Prepared, "accepted bitmap original prepare: " + accepted.error);
    const std::string stage = apsb ? "after-image-truncate" : "after-image-grow";
    const auto interrupted = ApplyVolumeResize(r, accepted.token, [&](auto at) { return at != stage; });
    Check(interrupted.outcome == VolumeImageOutcome::RecoveryRequired && interrupted.error == "VolumeImageInterrupted:" + stage,
        "actual bitmap resize interruption: " + interrupted.error);
    decode(accepted.journal, apsb ? VolumeKeeperJournalState::AnchorDurable : VolumeKeeperJournalState::Accepted);
    Check(!InspectVolumeKeeperImage(r.image, 0, root).admitted, "accepted bitmap resize retains owning debt");
    const auto recovered = RecoverVolumeResize(r); Check(recovered.outcome == VolumeImageOutcome::Committed, "bitmap original recovery commits: " + recovered.error);
    const auto post = fixture::Read(r.image); const auto after = fixture::Checkpoint(post);
    Check(post.size() == r.target_bytes && after.container.superblock.xid == accepted.post_xid, "actual requested geometry and checkpoint published");
    apfsaccess::rw::volume_image::Verify(post, after); ++checks;
    std::size_t metadata_comparisons = 0;
    for (const auto block : metadata) if (block != 0) {
        Check(std::equal(original.begin() + block * 4096, original.begin() + (block + 1) * 4096, post.begin() + block * 4096), "complete original metadata preserved");
        ++metadata_comparisons;
    }
    for (const auto& x : payload)
        Check(std::equal(original.begin() + x.physical_block * 4096, original.begin() + (x.physical_block + x.block_count) * 4096,
            post.begin() + x.physical_block * 4096), "every original owned payload byte preserved");
    decode(accepted.journal, VolumeKeeperJournalState::Completed); const auto terminal = fixture::Read(accepted.journal);
    Check(RecoverVolumeResize(r).outcome == VolumeImageOutcome::Committed && fixture::Read(r.image) == post &&
        fixture::Read(accepted.journal) == terminal && InspectVolumeKeeperImage(r.image, 0, root).admitted,
        "completed bitmap original recovery repeats and all canonical/archive frames admit");
    for (const auto& [oid, path] : r.sibling_wals)
        Check(fixture::Read(path).empty() && FileId(path) == wal_ids.at(path), "all sibling WAL bytes and file IDs preserved");
    std::cout << "BITMAP GREEN kind=" << (apsb ? "apsb" : "omap") << " prepares=4 cancellations=3 acceptedRecoveries=1"
        << " metadataComparisons=" << metadata_comparisons << " payloadBytes=" << payload_blocks * 4096 << std::endl;
}
VolumeImageRequest CurrentResize(const std::filesystem::path& root, const VolumeKeeperHistoryContext& context,
    VolumeImageOperation op)
{
    auto r = fixture::Request(root, op, fixture::Read(root / "image.apfs")); r.history_context = context;
    for (auto& [oid, path] : r.sibling_wals) path = Wal(context, r.container_uuid, oid);
    return r;
}
VolumeManagementRequest CurrentManagement(const std::filesystem::path& root, const VolumeKeeperHistoryContext& context, bool create)
{
    auto r = NextCreate(root / "image.apfs", root, context);
    if (!create) {
        const auto cp = fixture::Checkpoint(fixture::Read(r.image));
        r.operation = VolumeManagementOperation::Delete; r.name_utf8.clear();
        r.volume_oid = cp.volumes.back().superblock.object_id; r.volume_uuid = cp.volumes.back().superblock.uuid_hex;
    }
    return r;
}
void CheckStorage(const std::filesystem::path& root, const std::map<std::filesystem::path, Bytes>& original,
    const std::map<std::filesystem::path, std::string>& ids)
{
    for (const auto& [path, bytes] : original)
        Check(fixture::Read(path) == bytes && FileId(path) == ids.at(path), "original WAL/marker/proof bytes and file identity: " + path.string());
}
void PopulateFormattedVolume(const std::filesystem::path& image, const std::filesystem::path& wal)
{
    std::string error; auto device = BlockDevice::OpenExclusiveManagementImage(image.wstring(), 0, error); Check(!!device, error);
    Bytes bytes; Check(device->Read(0, static_cast<std::size_t>(device->GetGeometry().total_bytes), bytes), "formatted source read");
    const auto cp = fixture::Checkpoint(bytes); Check(cp.volumes.size() == 1, "one real formatted volume");
    const auto& v = cp.volumes.front(); VectorRandomAccessSource source(bytes); AppleVolumeTransactionRequest r;
    r.volume_object_id = v.superblock.object_id; r.file_count_delta = 1;
    Check(ReadBtreeLeafRecords(source, 4096, v.root_tree.physical_block, false, v.superblock.omap_oid,
        cp.container.superblock.xid, r.filesystem_records, error), error);
    bool root = false;
    for (auto& record : r.filesystem_records) {
        AppleInodeRecord inode;
        if (!ApfsExtendedRecordCodec::DecodeInode(record, inode, error) || inode.object_id != 2) continue;
        Check(inode.children_or_links == 1, "formatted root retains its private directory"); ++inode.children_or_links;
        Check(EncodeAppleInodeRecord(inode, record, error), error); root = true;
    }
    Check(root, "formatted root found");
    AppleInodeRecord file; file.object_id = file.private_id = 30; file.parent_id = 2; file.mode = 0100644;
    file.children_or_links = 1; file.uncompressed_size = 4096; BtreeRecord record;
    AppleExtendedField stream{8, 0, Bytes(40)};
    apfsaccess::testfixture::PutU64LE(stream.data, 0, 4096); apfsaccess::testfixture::PutU64LE(stream.data, 8, 4096);
    file.extended_fields.push_back(stream);
    Check(EncodeAppleInodeRecord(file, record, error), error); r.filesystem_records.push_back(record);
    AppleDirectoryRecord entry; entry.parent_id = 2; entry.file_id = 30; entry.flags = 8; entry.name_utf8 = "owned.bin";
    Check(EncodeAppleDirectoryRecord(entry, ApfsNamePolicy::FromIncompatibleFeatures(v.superblock.incompatible_features), record, error), error);
    r.filesystem_records.push_back(record);
    AppleVolumeDataWrite data; data.file_private_id = 30; data.bytes.assign(4096, std::byte{0x79}); r.data_writes.push_back(data);
    AppleVolumeTransactionPlan plan; Check(PlanAppleVolumeTransaction(source, cp, r, plan, error), "formatted payload plan: " + error);
    TransactionManager tx(L"Strict"); tx.SetJournalPath(wal.wstring());
    const auto id = DerivePartitionlessVolumeRecoveryIdentity(cp.container.superblock.uuid_hex, r.volume_object_id);
    tx.SetVolumeIdentity(std::wstring(id.begin(), id.end()));
    TransactionManager::MutationIntent intent; intent.kind = TransactionManager::MutationKind::CreateFile;
    intent.path = L"\\owned.bin"; intent.object_id = 30; intent.generation = plan.commit.publication.transaction_xid;
    Check(tx.Begin() && tx.RecordMutation(intent), "formatted real file creation intent");
    intent.kind = TransactionManager::MutationKind::Write; intent.length = intent.payload_length = data.bytes.size(); intent.inline_payload = data.bytes;
    BCRYPT_ALG_HANDLE algorithm{};
    Check(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0, "formatted payload digest provider");
    const auto status = BCryptHash(algorithm, nullptr, 0, reinterpret_cast<PUCHAR>(intent.inline_payload.data()),
        static_cast<ULONG>(intent.inline_payload.size()), intent.payload_checksum.data(), static_cast<ULONG>(intent.payload_checksum.size()));
    BCryptCloseAlgorithmProvider(algorithm, 0); Check(status >= 0, "formatted payload digest");
    Check(tx.RecordMutation(intent) && tx.Accept(cp.container.superblock.xid), "formatted real data acceptance");
    const auto accepted = tx.Watermarks().accepted_sequence;
    Check(accepted != 0 && ExecuteAppleCheckpointPublication(*device, plan.commit.publication, error), "formatted payload publication: " + error);
    Check(tx.MarkApfsDurableThrough(accepted) && tx.MarkCleanedThrough(accepted), "formatted payload genuine CLEAN boundary");
    Bytes after; Check(device->Read(0, bytes.size(), after), "formatted payload readback");
    apfsaccess::rw::volume_image::Verify(after, fixture::Checkpoint(after)); ++checks;
}
void ManagementResizeHistory(const std::filesystem::path& root, bool format_only = false)
{
    unsigned cases = 0, compared_operations = 0;
    for (const std::string profile : {"empty", "aborted-production", "aborted-canonical", "cleaned-production",
        "cleaned-canonical", "cancelled", "completed-delete", "completed-format"}) for (const bool shrink_first : {false, true}) {
        if (format_only && profile != "completed-format") continue;
        const auto dir = root / ("case-" + std::to_string(++cases)); std::filesystem::create_directories(dir);
        fixture::Save(dir / "image.apfs", IndependentFixture());
        const VolumeKeeperHistoryContext context{dir / "spool", dir / "recovery"};
        std::filesystem::create_directories(context.spool_root); std::filesystem::create_directories(context.recovery_root);
        auto seed = CurrentResize(dir, context, VolumeImageOperation::Grow);
        for (const auto& [oid, path] : seed.sibling_wals) {
            std::filesystem::create_directories(path.parent_path()); fixture::Save(path, {});
            if (profile.starts_with("aborted")) {
                const auto id = profile.ends_with("canonical") ? "apfs-vol:" + seed.container_uuid + ":" + std::to_string(oid) :
                    DerivePartitionlessVolumeRecoveryIdentity(seed.container_uuid, oid);
                TransactionManager tx(L"Strict"); tx.SetJournalPath(path.wstring()); tx.SetVolumeIdentity(std::wstring(id.begin(), id.end()));
                TransactionManager::MutationIntent intent; intent.kind = TransactionManager::MutationKind::CreateFile;
                intent.path = L"\\aborted-original"; intent.object_id = 900; intent.generation = seed.checkpoint_xid + 1;
                Check(tx.Begin() && tx.RecordMutation(intent) && tx.FlushPreparedRecords() && tx.Abort(), "native original Abort history");
            } else if (profile != "empty") PublishTimestamp(seed.image, path, oid, profile == "cleaned-canonical");
        }
        seed = CurrentResize(dir, context, VolumeImageOperation::Grow);
        for (const auto& [oid, path] : seed.sibling_wals) Mark(context, seed.container_uuid, oid, seed.checkpoint_xid);
        if (profile == "cancelled") {
            const auto m = CurrentManagement(dir, context, true); const auto p = PrepareVolumeCreate(m);
            Check(p.outcome == VolumeManagementOutcome::Prepared, "cancelled original VMT prepare: " + p.error);
            Check(RecoverVolumeManagement(m).outcome == VolumeManagementOutcome::Cancelled, "unaccepted original VMT recovery");
            const auto q = PrepareVolumeResize(seed); Check(q.outcome == VolumeImageOutcome::Prepared, q.error);
            Check(RecoverVolumeResize(seed).outcome == VolumeImageOutcome::Cancelled, "unaccepted original VIF recovery");
        } else if (profile == "completed-delete") {
            const auto m = CurrentManagement(dir, context, false); const auto p = PrepareVolumeDelete(m);
            Check(p.outcome == VolumeManagementOutcome::Prepared, p.error);
            const auto done = ApplyVolumeManagement(m, p.confirmation_token);
            Check(done.outcome == VolumeManagementOutcome::Committed, "original terminal delete: " + done.error);
        } else if (profile == "completed-format") {
            auto format = CurrentResize(dir, context, VolumeImageOperation::Format);
            format.new_container_uuid = format.container_uuid;
            format.new_container_uuid[0] = format.new_container_uuid[0] == 'a' ? 'b' : 'a';
            Production(format, dir); const auto p = PrepareVolumeFormat(format);
            Check(p.outcome == VolumeImageOutcome::Prepared, "original format prepare: " + p.error);
            const auto done = ApplyVolumeFormat(format, p.token);
            Check(done.outcome == VolumeImageOutcome::Committed, "original terminal format: " + done.error);
            PopulateFormattedVolume(seed.image, format.new_volume_wal);
            const auto populated = fixture::Checkpoint(fixture::Read(seed.image));
            Mark(context, populated.container.superblock.uuid_hex, 1024, populated.container.superblock.xid);
            if (shrink_first) {
                // The formatter deliberately places its bootstrap at the old tail.
                // Grow a real free suffix before exercising supported shrink.
                const auto before = Evidence(dir); std::map<std::filesystem::path, std::string> before_ids;
                for (const auto& [path, bytes] : before) before_ids.emplace(path, FileId(path));
                const auto shrink = CurrentResize(dir, context, VolumeImageOperation::Shrink);
                const auto refused = PrepareVolumeResize(shrink);
                Check(refused.outcome == VolumeImageOutcome::Refused && refused.error == "VolumeResizeReservedRegionWouldBeTruncated",
                    "allocated/reserved format tail still refuses: " + refused.error);
                const auto after = Evidence(dir); Check(after.size() == before.size(), "refused shrink creates/removes no evidence");
                for (const auto& [path, bytes] : before) {
                    const auto original = std::find_if(after.begin(), after.end(), [&](const auto& entry) {
                        return entry.second == bytes && FileId(entry.first) == before_ids.at(path);
                    });
                    Check(original != after.end(), "refused shrink preserves exact source/WAL/marker/proof and archives original terminal frame");
                }
                const auto grow = CurrentResize(dir, context, VolumeImageOperation::Grow); const auto q = PrepareVolumeResize(grow);
                Check(q.outcome == VolumeImageOutcome::Prepared, "format free-suffix grow plan: " + q.error);
                const auto partial = ApplyVolumeResize(grow, q.token, [](std::string_view at) { return at != "after-image-grow"; });
                Check(partial.outcome == VolumeImageOutcome::RecoveryRequired, "format free-suffix owner interrupted");
                const auto recovered = RecoverVolumeResize(grow);
                Check(recovered.outcome == VolumeImageOutcome::Committed && fixture::Read(seed.image).size() == grow.target_bytes,
                    "format free-suffix grow recovered: " + recovered.error);
            }
        }
        std::map<std::string, VolumeKeeperHistoryBinding> chains;
        const auto chain = [&]() {
            const auto inspection = InspectVolumeKeeperImage(seed.image, 0, dir);
            Check(inspection.admitted, "complete keeper admission: " + inspection.error);
            std::map<std::string, VolumeKeeperHistoryBinding> now;
            for (const auto& evidence : inspection.journals) {
                if (evidence.state == VolumeKeeperJournalState::Missing) continue;
                const auto b = DecodeVolumeKeeperHistoryBinding(fixture::Read(evidence.path), evidence.path, dir, inspection.source_identity);
                Check(b.state == VolumeKeeperJournalState::Completed || b.state == VolumeKeeperJournalState::Cancelled,
                    "every original canonical/archive receipt is terminal"); now.emplace(b.token, b);
            }
            for (const auto& [token, old] : chains)
                Check(now.contains(token) && now.at(token).frame_digest == old.frame_digest && now.at(token).state == old.state &&
                    now.at(token).source_identity == old.source_identity && now.at(token).pre_xid == old.pre_xid && now.at(token).post_xid == old.post_xid,
                    "complete immutable original keeper/checkpoint chain");
            chains = std::move(now); return inspection.source_identity;
        };
        const auto identity = chain();
        for (unsigned step = 0; step < 4; ++step) {
            const auto before = fixture::Read(seed.image); const auto cp = fixture::Checkpoint(before);
            std::map<std::filesystem::path, Bytes> storage; std::map<std::filesystem::path, std::string> ids;
            for (const auto& [path, bytes] : Evidence(dir)) if (path.extension() == ".wal" || path.extension() == ".state" || path.extension() == ".vkh1") {
                storage.emplace(path, bytes); ids.emplace(path, FileId(path));
            }
            VectorRandomAccessSource source(before); std::string error;
            std::vector<std::uint64_t> metadata; std::vector<ApplePhysicalExtentRecord> payload;
            Check(LoadAppleSnapshotCheckpointOwners(source, cp, metadata, payload, error), "complete current owner census: " + error);
            Check(!metadata.empty() && !payload.empty(), "nonempty current metadata and payload census before every matrix operation");
            for (const auto& v : cp.volumes)
                Check(std::find(metadata.begin(), metadata.end(), v.superblock_object.physical_block) != metadata.end(), "census contains every current sibling APSB");
            std::uint64_t expected_payload_blocks = profile == "completed-format" || profile == "completed-delete" ? 1 : 2;
            std::uint64_t payload_blocks = 0;
            for (const auto& x : payload) payload_blocks += x.block_count;
            Check(payload_blocks == expected_payload_blocks, "census contains exact populated fixture payload blocks");
            const bool management = step % 2 == 0, create = step == 0;
            const auto m = CurrentManagement(dir, context, create);
            auto resize = CurrentResize(dir, context, (step == 1 ? shrink_first : !shrink_first) ? VolumeImageOperation::Shrink : VolumeImageOperation::Grow);
            std::uint64_t post_xid{};
            if (management) {
                const auto p = create ? PrepareVolumeCreate(m) : PrepareVolumeDelete(m);
                Check(p.outcome == VolumeManagementOutcome::Prepared && p.pre_xid == cp.container.superblock.xid &&
                    p.source_identity.substr(0, 64) == identity.substr(0, 64), "exact create/delete plan: " + p.error);
                const auto stage = shrink_first ? "before-volume-management-complete" : "after-volume-management-accept";
                unsigned hits = 0;
                const auto partial = ApplyVolumeManagement(m, p.confirmation_token, [&](std::string_view at) {
                    if (at != stage) return true;
                    std::string busy; Check(!BlockDevice::OpenExclusiveManagementImage(m.image.wstring(), 0, busy), "actual source lease retained through management publication");
                    ++hits; return false;
                });
                Check(hits == 1 && partial.outcome == VolumeManagementOutcome::RecoveryRequired, "accepted management interruption: " + partial.error);
                const auto blocked = InspectVolumeKeeperImage(seed.image, 0, dir);
                Check(!blocked.admitted && blocked.error == "VolumeKeeperAdmissionBlocked:vmt1:accepted", "pending owner blocks cross-family admission");
                const auto recovered = RecoverVolumeManagement(m);
                Check(recovered.outcome == VolumeManagementOutcome::Committed && recovered.post_xid == p.post_xid,
                    "positive create/delete owner recovery: " + recovered.error); post_xid = recovered.post_xid;
                const auto committed = fixture::Read(seed.image);
                Check(RecoverVolumeManagement(m).outcome == VolumeManagementOutcome::Committed && fixture::Read(seed.image) == committed,
                    "idempotent management recovery preserves every source byte");
            } else {
                const auto p = PrepareVolumeResize(resize);
                Check(p.outcome == VolumeImageOutcome::Prepared && p.pre_xid == cp.container.superblock.xid &&
                    p.source_identity.substr(0, 64) == identity.substr(0, 64), "exact bounded grow/shrink plan: " + p.error);
                const auto stage = resize.operation == VolumeImageOperation::Grow ? "after-image-grow" : "after-image-truncate";
                unsigned hits = 0;
                const auto partial = ApplyVolumeResize(resize, p.token, [&](std::string_view at) {
                    if (at != stage) return true;
                    std::string busy; Check(!BlockDevice::OpenExclusiveManagementImage(resize.image.wstring(), 0, busy), "actual source lease retained through resize publication");
                    ++hits; return false;
                });
                Check(hits == 1 && partial.outcome == VolumeImageOutcome::RecoveryRequired, "accepted resize interruption: " + partial.error);
                Check(!InspectVolumeKeeperImage(seed.image, 0, dir).admitted, "pending resize owner blocks admission");
                const auto recovered = RecoverVolumeResize(resize);
                Check(recovered.outcome == VolumeImageOutcome::Committed && recovered.post_xid == p.post_xid,
                    "positive grow/shrink owner recovery: " + recovered.error); post_xid = recovered.post_xid;
                const auto committed = fixture::Read(seed.image);
                Check(RecoverVolumeResize(resize).outcome == VolumeImageOutcome::Committed && fixture::Read(seed.image) == committed,
                    "idempotent resize recovery preserves every source byte");
            }
            const auto after = fixture::Read(seed.image); const auto post = fixture::Checkpoint(after);
            apfsaccess::rw::volume_image::Verify(after, post); ++checks;
            Check(post.container.superblock.uuid_hex == cp.container.superblock.uuid_hex && post.container.superblock.xid == post_xid &&
                post_xid == cp.container.superblock.next_xid && after.size() == (management ? before.size() : resize.target_bytes) &&
                post.container.superblock.block_count * 4096 == after.size(), "exact checkpoint/container/capacity after reopen");
            Check(post.volumes.size() == cp.volumes.size() + (management && create ? 1 : 0) - (management && !create ? 1 : 0), "exact topology after reopen");
            if (!management) {
                VectorRandomAccessSource live(after);
                Check(!LoadAppleCheckpointView(live, 0, after.size(), error, cp.container.superblock.xid),
                    "old geometry is not a selectable old-XID checkpoint in the resized live source");
                const auto selection_error = error; error.clear();
                std::vector<AppleRecoveryCheckpointView> old_live;
                const auto loaded = LoadAppleSnapshotRecoveryCheckpoints(live, post, {cp.container.superblock.xid}, old_live, error);
                Check(!loaded && old_live.empty() && error == "AppleCheckpointRetentionUnavailable",
                    "old-XID live recovery must refuse after a geometry change: " + error);
                std::cout << "LIVE_OLD_XID_REFUSED pre=" << cp.container.superblock.xid << " post=" << post_xid
                    << " selection=" << selection_error << " recovery=" << error << std::endl;
            }
            if (management) {
                const auto selected = std::find_if(post.volumes.begin(), post.volumes.end(), [&](const auto& v) { return v.superblock.object_id == m.volume_oid; });
                Check(create ? selected != post.volumes.end() && selected->superblock.uuid_hex == m.volume_uuid &&
                    selected->superblock.name_utf8 == m.name_utf8 : selected == post.volumes.end(), "exact requested create/delete member after reopen");
            }
            for (const auto& old : cp.volumes) {
                if (management && !create && old.superblock.object_id == m.volume_oid) continue;
                const auto found = std::find_if(post.volumes.begin(), post.volumes.end(), [&](const auto& v) { return v.superblock.object_id == old.superblock.object_id; });
                Check(found != post.volumes.end() && found->superblock.uuid_hex == old.superblock.uuid_hex &&
                    found->superblock_object.physical_block == old.superblock_object.physical_block, "every surviving sibling exact identity and APSB");
            }
            std::size_t metadata_comparisons = 0; std::uint64_t payload_bytes = 0;
            for (const auto block : metadata) if (block) {
                Check(block < after.size() / 4096 && std::equal(before.begin() + block * 4096, before.begin() + (block + 1) * 4096,
                    after.begin() + block * 4096), "complete current owner metadata byte identity");
                ++metadata_comparisons;
            }
            for (const auto& extent : payload) {
                Check(extent.physical_block + extent.block_count <= after.size() / 4096 &&
                    std::equal(before.begin() + extent.physical_block * 4096, before.begin() + (extent.physical_block + extent.block_count) * 4096,
                        after.begin() + extent.physical_block * 4096), "complete current owner payload content identity");
                payload_bytes += extent.block_count * 4096;
            }
            Check(metadata_comparisons > 0 && metadata_comparisons == std::count_if(metadata.begin(), metadata.end(), [](auto b) { return b != 0; }) &&
                payload_bytes == expected_payload_blocks * 4096, "all census comparisons executed with nonzero metadata and exact payload bytes");
            ++compared_operations;
            CheckStorage(dir, storage, ids); Check(chain().substr(0, 64) == identity.substr(0, 64), "same original source file/offset throughout history");
            if (management && create) {
                const auto wal = Wal(context, m.container_uuid, m.volume_oid); std::filesystem::create_directories(wal.parent_path());
                Check(!std::filesystem::exists(wal), "new volume starts with its own absent WAL"); fixture::Save(wal, {});
                Mark(context, m.container_uuid, m.volume_oid, post_xid);
            }
            std::cout << "CLOSURE profile=" << profile << " shrinkFirst=" << shrink_first << " step=" << step << " pre=" << cp.container.superblock.xid
                << " post=" << post_xid << " bytes=" << after.size() << " chains=" << chains.size()
                << " metadataComparisons=" << metadata_comparisons << " payloadBytes=" << payload_bytes << std::endl;
        }
        SaveHashes(dir, "closure-final");
    }
    Check(cases == (format_only ? 2u : 16u) && compared_operations == (format_only ? 8u : 64u),
        "every requested operation executed complete owner byte comparisons");
    std::cout << "MANAGEMENT RESIZE HISTORY GREEN cases=" << cases << " comparedOperations=" << compared_operations << '\n';
}

void ManagedFixture(const std::filesystem::path& root, std::wstring_view mode)
{
    if (mode == L"--managed-seed") {
        std::filesystem::create_directories(root);
        Check(!std::filesystem::exists(root / "source.apfs"), "fresh managed seed");
        fixture::Save(root / "source.apfs", fixture::Fixture()); return;
    }
    Check(mode == L"--managed-prepare-delete" || mode == L"--managed-prepare-format" || mode == L"--managed-debt", "known managed fixture mode");
    auto r = fixture::Request(root, VolumeImageOperation::Format, fixture::Read(root / "image.apfs"));
    Production(r, root, mode == L"--managed-prepare-format");
    if (mode == L"--managed-debt") { SiblingDebt(r); return; }
    SeedOriginals(r.image, r.sibling_wals);
    r.checkpoint_xid = fixture::Checkpoint(fixture::Read(r.image)).container.superblock.xid;
    for (const auto& [oid, path] : r.sibling_wals) Mark(r.history_context, r.container_uuid, oid, r.checkpoint_xid);
    if (mode == L"--managed-prepare-format") {
        const auto p = PrepareVolumeFormat(r);
        Check(p.outcome == VolumeImageOutcome::Prepared, "managed fixture format Prepare: " + p.error);
        MarkerBytes(root / "request.json", VolumeImageJson(r, p));
    } else {
        VolumeManagementRequest m; m.operation = VolumeManagementOperation::Delete; m.image = r.image; m.journal_directory = root;
        m.container_uuid = r.container_uuid; m.volume_uuid = r.volume_uuid; m.volume_oid = r.volume_oid;
        m.checkpoint_xid = r.checkpoint_xid; m.sibling_wals = r.sibling_wals; m.history_context = r.history_context;
        const auto p = PrepareVolumeDelete(m);
        Check(p.outcome == VolumeManagementOutcome::Prepared, "managed fixture delete Prepare: " + p.error);
        MarkerBytes(root / "request.json", VolumeManagementJson(m, p));
    }
}
}

int wmain(int argc, wchar_t** argv)
{
    try {
        Check(argc == 2 || argc == 3, "absolute fresh D: evidence root required");
        const std::filesystem::path root(argv[1]);
        Check(root.is_absolute() && root.root_name() == L"D:", "absolute D: root required");
        if (argc == 3 && std::wstring_view(argv[2]).starts_with(L"--managed-")) {
            ManagedFixture(root, argv[2]); return 0;
        }
        Check(!std::filesystem::exists(root), "fresh D: root required");
        if (argc == 3) {
            const std::wstring_view mode(argv[2]);
            if (mode == L"--bitmap-originals-only" || mode == L"--bitmap-omap-only" || mode == L"--bitmap-apsb-only") {
                if (mode != L"--bitmap-apsb-only") BitmapOriginalHistory(root / "omap", false);
                if (mode != L"--bitmap-omap-only") BitmapOriginalHistory(root / "apsb", true);
                std::cout << "CHECKS " << checks << "\nBITMAP ORIGINAL HISTORY GREEN\n"; return 0;
            }
            if (mode == L"--management-resize-only" || mode == L"--format-history-only") {
                ManagementResizeHistory(root, mode == L"--format-history-only"); std::cout << "CHECKS " << checks << '\n'; return 0;
            }
            if (mode == L"--preaccept-hook-delete" || mode == L"--preaccept-hook-format") {
                try {
                    PreacceptHookCancellation(root, mode == L"--preaccept-hook-format");
                    std::cout << "CHECKS " << checks << "\nHOOK CANCELLATION GREEN\n"; return 0;
                } catch (const std::exception& ex) {
                    std::cerr << "FOCUSED_FAILURE " << ex.what() << '\n'; return 1;
                }
            }
            Check(std::wstring_view(argv[2]) == L"--format-next-plan-only", "known focused selector");
            Check(Format(root / "format"), "format next stage"); std::cout << "CHECKS " << checks << '\n'; return 0;
        }
        const bool deletion = Delete(root / "delete");
        const bool format = Format(root / "format");
        unsigned scenario_index = 0;
        std::string scenario_paths;
        const auto scenario_path = [&](const std::string& name) {
            // Keep native WAL paths below MAX_PATH under the CTest evidence root.
            const auto leaf = "case-" + std::to_string(++scenario_index);
            scenario_paths += leaf + '\t' + name + '\n';
            MarkerBytes(root / "scenario-paths.tsv", scenario_paths);
            return root / leaf;
        };
        for (const auto* attack : {"accepted-crash", "incomplete-census", "dirty-retired", "dirty-current", "foreign", "replaced", "forged-file-id", "missing", "alias", "bad-proof", "forged-terminal",
            "oid-reuse", "marker-ahead", "retired-marker-ahead", "marker-noncanonical", "unknown-spool", "missing-prepare", "missing-apply", "missing-recover",
            "proof-file-flush", "proof-directory-flush", "accepted-retired", "accepted-current", "checkpointed-retired", "checkpointed-current",
            "compact-retired", "compact-current", "vif-missing", "vif-replaced", "vif-alias", "vif-dirty-retired",
            "missing-proof", "proof-journal-binding", "proof-source-binding", "proof-alias", "lease-busy", "fence-busy",
            "partial-proof-retry", "mismatch-proof-retry"}) Delete(scenario_path(attack), attack);
        for (const auto* attack : {"proof-file-flush", "proof-directory-flush"}) Format(scenario_path(std::string("format-") + attack), attack);
        std::cout << "CHECKS " << checks << '\n';
        std::cout << "CONTINUATION " << (deletion && format ? "GREEN" : "RED") << '\n';
        return deletion && format ? 0 : 1;
    } catch (const std::exception& ex) {
        std::cerr << "SETUP_FAILURE " << ex.what() << '\n';
        return 2;
    }
}
