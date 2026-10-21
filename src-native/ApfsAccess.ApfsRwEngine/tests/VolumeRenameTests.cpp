#define APPLE_CLONE_TEST_HELPERS_ONLY
#include "AppleCloneCowTests.cpp"
#include "MetadataStore.h"
#include "NativeVolumeRename.h"
#ifndef BASELINE_RED
#include "VolumeMetadata.h"
#endif
#include <filesystem>
#include <bcrypt.h>

namespace
{
using Store = MetadataStore;
void SaveImage(const std::filesystem::path& path, const std::vector<std::byte>& bytes)
{
    std::ofstream file(path, std::ios::binary);
    file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    Check(!!file, "save image");
}
std::vector<std::byte> ReadImage(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    std::vector<char> raw((std::istreambuf_iterator<char>(file)), {});
    std::vector<std::byte> bytes(raw.size());
    memcpy(bytes.data(), raw.data(), raw.size()); return bytes;
}
BuilderStore RenameSpec()
{
    auto spec = CloneSpec(1);
    auto sibling = spec.volumes[0]; sibling.oid = 102; sibling.name = "Data";
    sibling.reserve_block_count = 16; sibling.quota_block_count = 128;
    for (auto& record : sibling.filesystem_records)
        if (Type(record) == 8) PutU64LE(record.value, 8, 144);
    PutU64LE(sibling.extentref_records[0].key, 0, (2ull << 60) | 144);
    for (unsigned i = 0; i != 4; ++i)
        spec.authoritative_seeded_main_blocks.push_back({144 + i, std::vector<std::byte>(kBlockSize, std::byte(90 + i))});
    spec.volumes.push_back(sibling);
    spec.volumes[0].reserve_block_count = 12; spec.volumes[0].quota_block_count = 128;
    return spec;
}
NativeVolumeRename Proof(const Fixture& fixture, const std::string& label)
{
    NativeVolumeRename rename;
    const auto& cp = fixture.checkpoint; const auto& v = cp.volumes[0];
    rename.checkpoint = cp.container.superblock.xid; rename.volume = v.superblock.object_id;
    rename.container_uuid = cp.container.superblock.uuid_hex; rename.volume_uuid = v.superblock.uuid_hex;
    rename.old_label = v.superblock.name_utf8; rename.new_label = label;
    auto at = fixture.image.begin() + v.superblock_object.physical_block * kBlockSize;
    rename.superblock.assign(at, at + kBlockSize); return rename;
}
Store::MutationRequest Mutation(const NativeVolumeRename& rename)
{
    Store::MutationRequest request;
    request.operation = static_cast<Store::MutationOperation>(17); request.path = L"\\";
    request.object_id = rename.volume; request.generation = rename.checkpoint + 1;
    request.inline_payload = EncodeNativeVolumeRename(rename); request.length = request.inline_payload.size();
    return request;
}
void BaselineAdmission()
{
    Fixture fixture(RenameSpec()); const auto path = std::filesystem::absolute("admission.apfs"); SaveImage(path, fixture.image);
    Store::VolumeContext context; context.device_path = path.wstring(); context.volume_object_id = 101;
    context.container_uuid_hex = fixture.checkpoint.container.superblock.uuid_hex;
    context.volume_uuid_hex = fixture.checkpoint.volumes[0].superblock.uuid_hex;
    context.allow_legacy_scaffold_for_fixtures = false;
    Store store(context); Check(store.PrepareNativeWritePath(), "baseline native reader opens");
    Check(store.StageMutation(Mutation(Proof(fixture, "Renamed"))) == Store::MutationStatus::Applied,
        "RED/GREEN: valid native volume rename stages instead of unsupported");
}
#ifndef BASELINE_RED
using Tx = TransactionManager;
using Owner = ContainerMountCoordinator;
std::unique_ptr<Owner> OpenOwner(const std::filesystem::path& path, Tx* journal = nullptr)
{
    std::string error;
    auto owner = Owner::Open(path.string(), 0, error, CatalogLoadPolicy::StrictApple, true, true);
    Check(!!owner, "open canonical image owner: " + error);
    std::vector<VolumeCheckpointPins> census;
    for (std::uint64_t oid : {101, 102})
    {
        ContainerVolumeSession session; session.volume_object_id = oid;
        session.container_uuid_hex = owner->ContainerUuidHex(); session.requested_write = true;
        session.use_canonical_transaction = true; session.recovery_identity = "unchanged-owner-" + std::to_string(oid);
        session.metadata_context.allow_legacy_scaffold_for_fixtures = false;
        Check(owner->MountVolume(session, error), "mount native image session: " + error);
        VolumeCheckpointPins pins; pins.volume_object_id = oid;
        if (oid == 101 && journal)
        {
            Check(journal->LoadRequiredCheckpointXidsSinceCleanup(pins.required_checkpoint_xids, &error), "load canonical recovery pins: " + error);
            pins.unapplied_accepted_work = journal->HasUnappliedAcceptedWork();
        }
        census.push_back(pins);
    }
    Check(owner->InitializeRequiredCheckpointCensus(census, error), "initialize complete two-volume census: " + error);
    return owner;
}
void Configure(Tx& journal, const std::filesystem::path& path)
{
    journal.SetJournalPath(std::filesystem::absolute(path).wstring());
    journal.SetVolumeIdentity(L"apfs-vol:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:101");
}
void CheckSuccess(const ContainerCommitResult& result)
{
    Check(result.committed && !result.commit_recovery_required &&
        result.commit_status_code == static_cast<int>(Store::CommitStatus::Committed),
        "durable rename succeeds: " + result.error + " stage=" + result.commit_stage);
}
void Observe(const std::filesystem::path& path, const Fixture& original, const std::string& label)
{
    auto bytes = ReadImage(path); VectorRandomAccessSource source(bytes); std::string error;
    ApfsContainerCatalog catalog;
    Check(ApfsContainerCatalog::TryLoadImage(source, "rename-fixture", path.string(), catalog, error, CatalogLoadPolicy::StrictApple),
        "fresh strict catalog loads: " + error);
    ResolvedMountVolume selected, sibling;
    Check(catalog.TryResolveVolume(original.checkpoint.container.superblock.uuid_hex, 101, selected, error) &&
        selected.name_utf8 == label && selected.volume_uuid_hex == original.checkpoint.volumes[0].superblock.uuid_hex,
        "fresh catalog observes label and exact UUID/OID");
    Check(catalog.TryResolveVolume(original.checkpoint.container.superblock.uuid_hex, 102, sibling, error) &&
        sibling.name_utf8 == "Data" && sibling.volume_uuid_hex == original.checkpoint.volumes[1].superblock.uuid_hex,
        "same-name sibling UUID/OID and label unchanged");
    const auto cp = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    Check(!!cp, "fresh checkpoint and checksums valid");
    for (unsigned v = 0; v != 2; ++v)
    {
        const auto& before = original.checkpoint.volumes[v]; const auto& after = cp->volumes[v];
        Check(before.superblock.object_id == after.superblock.object_id && before.superblock.uuid_hex == after.superblock.uuid_hex &&
            before.superblock.role_raw == after.superblock.role_raw &&
            before.superblock.space.reserve_block_count == after.superblock.space.reserve_block_count &&
            before.superblock.space.quota_block_count == after.superblock.space.quota_block_count &&
            before.superblock.next_object_id == after.superblock.next_object_id,
            "volume identities, role, quota/reserve and next inode identity preserved");
        const auto payload = v ? 144 : 128;
        Check(std::equal(bytes.begin() + payload * kBlockSize, bytes.begin() + (payload + 4) * kBlockSize,
            original.image.begin() + payload * kBlockSize), "selected/sibling payload bytes unchanged");
        if (v) Check(std::equal(bytes.begin() + after.superblock_object.physical_block * kBlockSize,
            bytes.begin() + (after.superblock_object.physical_block + 1) * kBlockSize,
            original.image.begin() + before.superblock_object.physical_block * kBlockSize), "sibling APSB byte-for-byte unchanged");
    }
    auto owner = OpenOwner(path);
    for (std::uint64_t oid : {101, 102})
    {
        auto* store = owner->FindSessionStore(oid);
        const auto inode = store->LookupCommittedInodeByPath(L"\\clone0");
        Check(inode && inode->object_id == 17 && inode->owner == 501 && inode->group == 20 && inode->mode == 0100640,
            "fresh remount reads stable inode identity and permissions");
        std::vector<std::byte> payload;
        Check(store->ReadCommittedFileRange(L"\\clone0", 0, 4 * kBlockSize, payload), "fresh reader reads full payload");
        const auto offset = oid == 101 ? 128 : 144;
        Check(std::equal(payload.begin(), payload.end(), original.image.begin() + offset * kBlockSize), "fresh reader bytes match source");
    }
}
void SuccessCases()
{
    unsigned number = 0;
    for (const std::string label : {std::string("Renamed"), std::string("研究资料 🚀 café"), std::string(255, 'x')})
    {
        const auto stem = "success-" + std::to_string(number++); Fixture fixture(RenameSpec());
        const auto path = std::filesystem::absolute(stem + ".apfs"); SaveImage(path, fixture.image);
        {
            Tx journal(L"Strict"); Configure(journal, stem + ".wal"); auto owner = OpenOwner(path);
            VolumeRenamePlan plan; std::string error;
            Check(PrepareVolumeRename(*owner, 101, label, plan, error), "prepare label: " + error);
            Check(ReadImage(path) == fixture.image && journal.Watermarks().accepted_sequence == 0, "planning is read-only");
            bool acceptance_saw_old = false;
            journal.SetJournalFaultInjectionHook([&](std::string_view stage) {
                if (stage == "durable-flush" && !acceptance_saw_old) {
                    Check(ReadImage(path) == fixture.image, "prepublication acceptance sees intact old checkpoint"); acceptance_saw_old = true;
                } return false;
            });
            const auto inode = owner->FindSessionStore(101)->LookupCommittedInodeByPath(L"\\clone0");
            const auto result = ApplyVolumeRename(*owner, journal, plan); CheckSuccess(result);
            Check(acceptance_saw_old && result.checkpoint_xid > fixture.checkpoint.container.superblock.xid,
                "rename advances container XID after durable acceptance");
            const auto after = owner->FindSessionStore(101)->LookupCommittedInodeByPath(L"\\clone0");
            // The existing reader reports the selected APSB XID as the read
            // generation of every inode. It advances at a checkpoint; native
            // inode/private IDs and the actual inode records must stay intact.
            Check(inode && after && inode->object_id == after->object_id && inode->private_id == after->private_id,
                "rename preserves native inode/private identities");
            Check(!ApplyVolumeRename(*owner, journal, plan).committed, "consumed plan cannot execute again");
            Check(journal.Watermarks().accepted_sequence == journal.Watermarks().cleanup_sequence &&
                !journal.HasUnappliedAcceptedWork(), "canonical durable and cleanup watermarks finalized");
        }
        Observe(path, fixture, label);
    }
}
void InvalidCases()
{
    Fixture fixture(RenameSpec()); auto path = std::filesystem::absolute("invalid.apfs"); SaveImage(path, fixture.image);
    auto owner = OpenOwner(path); Tx journal(L"Strict"); Configure(journal, "invalid.wal");
    for (const auto& label : std::vector<std::string>{"", std::string(256, 'x'), std::string("a\0b", 3),
        "\xc0\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80", "\xe2\x82", "\x80", "\xf0\x80\x80\xaf", "Data"})
    {
        VolumeRenamePlan plan; std::string error;
        Check(!PrepareVolumeRename(*owner, 101, label, plan, error), "invalid/no-op label rejected before mutation");
        Check(ReadImage(path) == fixture.image && owner->FindSessionStore(101)->PendingMutationCount() == 0 &&
            journal.Watermarks().accepted_sequence == 0, "invalid label changes neither image nor journal");
    }
    auto proof = Proof(fixture, "New"); auto bytes = EncodeNativeVolumeRename(proof); NativeVolumeRename decoded;
    Check(DecodeNativeVolumeRename(bytes, decoded), "VRN1 round trip");
    bytes[0] ^= std::byte{1}; Check(!DecodeNativeVolumeRename(bytes, decoded), "unknown VRN payload version rejected");
    bytes = EncodeNativeVolumeRename(proof); bytes.push_back(std::byte{});
    Check(!DecodeNativeVolumeRename(bytes, decoded), "trailing payload bytes rejected");
    auto request = Mutation(proof); request.object_id = 102; std::string error;
    Check(!ValidateVolumeRenameMutation(*owner->FindSessionStore(101), request, error), "wrong OID rejected");
    proof.container_uuid = std::string(32, 'b'); request = Mutation(proof);
    Check(!ValidateVolumeRenameMutation(*owner->FindSessionStore(101), request, error), "wrong container UUID rejected");
    proof = Proof(fixture, "New"); proof.volume_uuid = std::string(32, 'c'); request = Mutation(proof);
    Check(!ValidateVolumeRenameMutation(*owner->FindSessionStore(101), request, error), "wrong volume UUID rejected");
}
void StaleAndBusy()
{
    Fixture fixture(RenameSpec()); auto path = std::filesystem::absolute("stale.apfs"); SaveImage(path, fixture.image);
    auto owner = OpenOwner(path); Tx journal(L"Strict"); Configure(journal, "stale.wal"); std::string error;
    VolumeRenamePlan stale, current;
    Check(PrepareVolumeRename(*owner, 101, "Stale", stale, error) && PrepareVolumeRename(*owner, 101, "Current", current, error), "capture two plans");
    CheckSuccess(ApplyVolumeRename(*owner, journal, current)); const auto image = ReadImage(path);
    Check(!ApplyVolumeRename(*owner, journal, stale).committed && ReadImage(path) == image, "stale checkpoint refuses without writes");
    VolumeRenamePlan busy;
    Check(PrepareVolumeRename(*owner, 101, "Busy", busy, error), "prepare before conflicting owner appears");
    Check(owner->UpdateRequiredCheckpointXids(102, {owner->CheckpointXid()}, error, true), "register sibling recovery owner");
    const auto refused = ApplyVolumeRename(*owner, journal, busy);
    Check(!refused.committed && ReadImage(path) == image, "active sibling recovery owner invalidates plan");
    Check(owner->CheckpointCensusSnapshot()[1].unapplied_accepted_work, "refusal preserves sibling recovery owner");
}
void WrongOwnerConsumesPlan()
{
    Fixture fixture(RenameSpec());
    const auto path = std::filesystem::absolute("wrong-owner.apfs"); SaveImage(path, fixture.image);
    const auto other_path = std::filesystem::absolute("other-owner.apfs"); SaveImage(other_path, fixture.image);
    auto owner = OpenOwner(path), other = OpenOwner(other_path);
    Tx journal(L"Strict"); Configure(journal, "single-use.wal"); std::string error;
    VolumeRenamePlan plan;
    Check(PrepareVolumeRename(*owner, 101, "SingleUse", plan, error), "prepare single-use plan");
    Check(!ApplyVolumeRename(*other, journal, plan).committed, "wrong coordinator refuses plan");
    Check(!ApplyVolumeRename(*owner, journal, plan).committed && ReadImage(path) == fixture.image &&
        journal.Watermarks().accepted_sequence == 0, "every attempt consumes plan, including wrong-owner refusal");
}
void RetainedRenameHistory()
{
    for (const std::uint64_t subsequent : {0ull, 101ull, 102ull})
    {
        Fixture fixture(RenameSpec());
        const auto stem = "retained-" + std::to_string(subsequent);
        const auto path = std::filesystem::absolute(stem + ".apfs"); SaveImage(path, fixture.image);
        const auto wal = std::filesystem::absolute(stem + ".wal");
        std::vector<std::byte> accepted_preimage;
        {
            Tx journal(L"Strict"); Configure(journal, wal); auto owner = OpenOwner(path);
            VolumeRenamePlan plan; std::string error;
            Check(PrepareVolumeRename(*owner, 101, "First", plan, error), "prepare retained-history rename");
            journal.SetJournalFaultInjectionHook([&](std::string_view stage) {
                if (stage == "durable-flush" && accepted_preimage.empty()) accepted_preimage = ReadImage(wal);
                return false;
            });
            CheckSuccess(ApplyVolumeRename(*owner, journal, plan));
            Check(!accepted_preimage.empty(), "freeze actual accepted WAL before its finalization");
            // Model a retained accepted journal whose cleanup was not observed.
            // Keep both proof boundaries through the later canonical commit.
            Check(owner->UpdateRequiredCheckpointXids(subsequent == 101 ? 102 : 101, {fixture.checkpoint.container.superblock.xid,
                owner->CheckpointXid()}, error, false), "pin original and first publication checkpoints");
            if (subsequent)
            {
                // Release the original journal lease before opening another
                // history owner with this fixture's fixed volume identity.
                journal.SetJournalPath(L"");
                Tx later(L"Strict"); Configure(later, stem + "-later.wal");
                for (unsigned i = 0; i != 2; ++i)
                {
                    Check(owner->RefreshSessionForRecovery(subsequent, error), "refresh later selected or sibling session");
                    VolumeRenamePlan next;
                    Check(PrepareVolumeRename(*owner, subsequent, "Later" + std::to_string(i), next, error), "prepare later selected or sibling rename");
                    CheckSuccess(ApplyVolumeRename(*owner, later, next));
                }
            }
        }
        SaveImage(wal, accepted_preimage);
        const auto before_replay = ReadImage(path);
        {
            Tx journal(L"Strict"); Configure(journal, wal); auto owner = OpenOwner(path, &journal);
            std::string error;
            const auto replay = ReplayVolumeRename(*owner, journal, 101, error);
            Check(replay.value_or(false), "verify first rename with subsequent OID " +
                std::to_string(subsequent) + ": " + error);
            Check(ReadImage(path) == before_replay && !journal.HasUnappliedAcceptedWork() &&
                journal.Watermarks().cleanup_sequence > 0, "historical verification cleans only WAL without rewriting later image");
        }
    }
}
void CodecAndSnapshot()
{
    Fixture fixture(RenameSpec()); auto proof = Proof(fixture, "New");
    WriteAheadLog::Record record;
    record.volume_identity = "codec"; record.transaction_id = record.sequence = 1;
    record.operation = WriteAheadLog::OperationKind::RenameVolume; record.path_utf8 = "\\";
    record.object_id = proof.volume; record.parent_object_id = proof.checkpoint + 1;
    record.inline_payload = EncodeNativeVolumeRename(proof); record.payload_length = record.inline_payload.size();
    const auto hash = [](auto& r) {
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        Check(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0, "codec hash provider");
        const auto status = BCryptHash(algorithm, nullptr, 0, reinterpret_cast<PUCHAR>(r.inline_payload.data()),
            static_cast<ULONG>(r.inline_payload.size()), r.payload_sha256.data(), 32);
        BCryptCloseAlgorithmProvider(algorithm, 0); Check(status >= 0, "codec hash");
    };
    hash(record);
    Check(WriteAheadLog::VolumeRenameIsConsistent(record) && !WriteAheadLog::EncodeForTest(record, 2).empty(), "rename uses existing v2 envelope");
    for (std::uint16_t version : {1, 3, 99})
        Check(WriteAheadLog::EncodeForTest(record, version).empty(), "rename rejects old/incompatible/unknown envelope version");
    const auto bytes = WriteAheadLog::EncodeForTest(record);
    { std::ofstream out("rename-codec.wal", std::ios::binary); out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size()); }
    const auto read = WriteAheadLog::ReadAll("rename-codec.wal", "codec");
    Store::MutationRequest request;
    Check(read.status == WriteAheadLog::ReadStatus::Ok && read.records.size() == 1 && VolumeRenameFromWal(read.records[0], request),
        "typed rename survives actual WAL encode/read/decode");
    auto bad = record; bad.inline_payload[0] ^= std::byte{1}; hash(bad);
    Check(!WriteAheadLog::VolumeRenameIsConsistent(bad) && WriteAheadLog::EncodeForTest(bad).empty(),
        "unknown typed payload version rejected even with fresh matching digest");
    bad = record; ++bad.parent_object_id;
    Check(!WriteAheadLog::VolumeRenameIsConsistent(bad), "WAL generation must match bound checkpoint");
    Tx journal(L"Strict"); Configure(journal, "wrong-xid.wal");
    Tx::MutationIntent intent; intent.kind = Tx::MutationKind::RenameVolume; intent.path = L"\\";
    intent.object_id = record.object_id; intent.generation = record.parent_object_id;
    intent.inline_payload = record.inline_payload; intent.length = intent.payload_length = record.inline_payload.size();
    intent.payload_checksum = record.payload_sha256;
    Check(journal.Begin() && journal.RecordMutation(intent) && !journal.Accept(proof.checkpoint + 1),
        "transaction cannot durably accept a different preimage checkpoint");
    std::string error;
    VolumeRenamePlan plan;
    const auto path = std::filesystem::absolute("snapshot-refusal.apfs");
    SetApsbCounter(fixture, 0, 0xd8, 1);
    const auto rename = Proof(fixture, "SnapshotRefused");
    AppleVolumeTransactionPlan planned; VectorRandomAccessSource source(fixture.image);
    Check(!PlanVolumeRenameCheckpoint(source, fixture.checkpoint, rename, {rename.checkpoint}, planned, error) &&
        error == "VolumeRenameSnapshotsUnsupported", "rename profile explicitly preserves snapshot unsupported admission");
    SaveImage(path, fixture.image);
    const auto before = ReadImage(path);
    Check(before == fixture.image && planned.commit.publication.before_superblock_writes.empty(), "snapshot refusal produces no publishable plan");
}
void Capacity()
{
    auto spec = RenameSpec(); spec.authoritative_main_free_blocks = 5;
    for (auto& volume : spec.volumes) volume.reserve_block_count = 0;
    Fixture fixture(spec); auto path = std::filesystem::absolute("capacity.apfs"); SaveImage(path, fixture.image);
    auto owner = OpenOwner(path); Tx journal(L"Strict"); Configure(journal, "capacity.wal"); std::string error;
    VolumeRenamePlan plan; Check(PrepareVolumeRename(*owner, 101, "Full", plan, error), "capacity plan has valid identity");
    NativeVolumeRename rename; Check(DecodeNativeVolumeRename(plan.request.inline_payload, rename), "capacity proof decodes");
    AppleVolumeTransactionPlan preview; VectorRandomAccessSource source(fixture.image);
    const bool fits = PlanVolumeRenameCheckpoint(source, fixture.checkpoint, rename, {rename.checkpoint}, preview, error);
    std::cout << "capacity preview: " << fits << " " << error << "\n";
    const auto result = ApplyVolumeRename(*owner, journal, plan);
    Check(!result.committed && result.commit_status_code == static_cast<int>(Store::CommitStatus::CapacityBlocked) &&
        result.clean_prepublication_refusal, "capacity refused before acceptance: " + result.error);
    Check(ReadImage(path) == fixture.image && journal.Watermarks().accepted_sequence == 0, "capacity refusal writes neither image nor accepted WAL");
}
void Faults()
{
    const std::vector<std::string> modes = {"write-fail", "write-torn", "flush", "acceptance", "switch", "final-flush"};
    for (const auto& mode : modes)
    {
        const auto stem = "fault-" + mode; Fixture fixture(RenameSpec());
        auto path = std::filesystem::absolute(stem + ".apfs"); SaveImage(path, fixture.image);
        {
            Tx journal(L"Strict"); Configure(journal, stem + ".wal"); auto owner = OpenOwner(path);
            VolumeRenamePlan plan; std::string error;
            Check(PrepareVolumeRename(*owner, 101, "Recovered", plan, error), "fault case plans");
            if (mode == "acceptance") journal.SetJournalFaultInjectionHook([](std::string_view stage) { return stage == "durable-flush"; });
            if (mode == "write-fail") SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_WRITE", L"fail");
            if (mode == "write-torn") SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_WRITE", L"first-half");
            if (mode == "flush") SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_FLUSH", L"1");
            if (mode == "switch" || mode == "final-flush") owner->FindSessionStore(101)->SetCommitStageHook([&](std::string_view stage) {
                if (mode == "final-flush" && stage == "before-apple-final-flush") SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_FLUSH", L"1");
                return mode != "switch" || stage != "before-apple-checkpoint-switch";
            });
            const auto result = ApplyVolumeRename(*owner, journal, plan);
            SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_WRITE", nullptr); SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_FLUSH", nullptr);
            Check(result.commit_recovery_required && result.commit_status_code != static_cast<int>(Store::CommitStatus::Committed),
                "injected " + mode + " is never acknowledged");
            Check(journal.Watermarks().apfs_durable_sequence == 0 && journal.Watermarks().cleanup_sequence == 0,
                "injected fault keeps canonical accepted evidence");
        }
        auto bytes = ReadImage(path); VectorRandomAccessSource source(bytes); std::string error;
        const auto old_or_new = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        Check(old_or_new && (old_or_new->volumes[0].superblock.name_utf8 == "Data" || old_or_new->volumes[0].superblock.name_utf8 == "Recovered"),
            "fault leaves valid old-or-new canonical checkpoint: " + error);
        {
            Tx journal(L"Strict"); Configure(journal, stem + ".wal"); auto owner = OpenOwner(path, &journal);
            const auto result = ReplayVolumeRename(*owner, journal, 101, error);
            Check(result.value_or(false), "restart canonical replay recovers " + mode + ": " + error);
            Check(!journal.HasUnappliedAcceptedWork() && journal.Watermarks().cleanup_sequence > 0, "replay finalizes existing canonical journal");
            Check(!ReplayVolumeRename(*owner, journal, 101, error).has_value(), "second replay is empty, not a second rename");
        }
        Observe(path, fixture, "Recovered");
    }
}
#endif
}
#ifndef VOLUME_RENAME_TEST_HELPERS_ONLY
int main(int argc, char** argv)
{
    try
    {
        if (argc < 2 || argc > 3) throw std::runtime_error("usage: VolumeRenameTests <D:\\fresh-evidence-directory> [single-use]");
        const auto run = std::filesystem::path(argv[1]) / ("run-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64()));
        std::filesystem::create_directories(run); std::filesystem::current_path(run);
        std::cout << "Evidence: " << run.string() << "\n";
        if (argc == 3)
        {
#ifndef BASELINE_RED
            if (std::string_view(argv[2]) == "history") RetainedRenameHistory();
            else WrongOwnerConsumesPlan();
#endif
        }
        else
        {
        BaselineAdmission();
#ifndef BASELINE_RED
        SuccessCases(); InvalidCases(); StaleAndBusy(); WrongOwnerConsumesPlan(); RetainedRenameHistory(); CodecAndSnapshot(); Capacity(); Faults();
#endif
        }
        std::cout << "PASS volume rename " << checks << " checks\n"; return 0;
    }
    catch (const std::exception& error) { std::cerr << "FAIL after " << checks << " checks: " << error.what() << "\n"; return 1; }
}
#endif
