#define SNAPSHOT_RUNTIME_TEST_HELPERS_ONLY
#include "SnapshotRuntimeTests.cpp"
#include "ApfsRepair.h"
#include "MutationCompactor.h"

namespace {
void FreshRepair(const std::filesystem::path& path) {
    auto spec = RuntimeSpec();
    std::string error;
    for (auto& volume : spec.volumes)
        Check(SortAppleBtreeRecords(volume.filesystem_records, AppleBtreeKeyOrder::FileSystemHashedDirectory, error),
            "sort complete ordinary repair census: " + error);
    Fresh(path, spec);
}
void DamageCount(const std::filesystem::path& path) {
    auto image = Bytes(path);
    VectorRandomAccessSource source(image);
    std::string error;
    const auto checkpoint = LoadAppleCheckpointView(source, 0, image.size(), error);
    Check(!!checkpoint, "load count damage preimage: " + error);
    const auto block = checkpoint->volumes[0].superblock_object.physical_block;
    std::vector<std::byte> apsb(image.begin() + block * kBlockSize, image.begin() + (block + 1) * kBlockSize);
    PutU64LE(apsb, 0xb8, 99);
    Check(FinalizeAppleObjectChecksum(apsb, error), "checksum typed count damage");
    std::copy(apsb.begin(), apsb.end(), image.begin() + block * kBlockSize);
    Save(path, image);
}
void RepairThenSnapshot() {
    FreshRepair("transition.apfs"); DamageCount("transition.apfs");
    {
        Tx journal(L"Strict"); Configure(journal, "transition.wal");
        auto owner = Open("transition.apfs", journal);
        const auto original = LiveBytes(*owner, L"\\clone0");
        ApfsCountRepairPlan repair; std::string error;
        const bool prepared = PrepareApfsCountRepair(*owner, 101, repair, error);
        Check(prepared, "repair with runtime admission enabled: " + error);
        Success(ApplyApfsCountRepair(*owner, journal, repair, repair.ConfirmationToken()));
        Check(!journal.HasUnappliedAcceptedWork(), "repair cleans its accepted owner");
        Create(*owner, journal, "after-repair");
        Observe(*owner, 0, original, {std::byte{1}, std::byte{2}, std::byte{3}});
    }
    // Change only the selected current APSB count in a closed private image.
    // Runtime admission is explicitly enabled on reopen; repair must still refuse.
    DamageCount("transition.apfs");
    Tx journal(L"Strict"); Configure(journal, "transition.wal");
    auto owner = Open("transition.apfs", journal); std::string error;
    const auto id = List(*owner).at(0).identity;
    auto reader = owner->AcquireSnapshotReader(id, error);
    Check(!!reader, "reader acquired on snapshot-bearing image: " + error);
    std::vector<std::byte> before, after;
    Check(reader->Read(17, 0, 4 * kBlockSize, before), "historical payload before repair refusal");
    const auto image = Bytes("transition.apfs"), wal = Bytes("transition.wal");
    ApfsCountRepairPlan refused;
    Check(!PrepareApfsCountRepair(*owner, 101, refused, error), "snapshot-bearing repair stays refused with runtime enabled");
    Check(Bytes("transition.apfs") == image && Bytes("transition.wal") == wal, "refusal preserves complete image and journal bytes");
    Check(reader->Read(17, 0, 4 * kBlockSize, after) && before == after, "repair refusal preserves reader and payload pin");
    Check(owner->DrainAndStop(std::chrono::seconds(2)).clean, "union coordinator drains snapshot reader");
    Check(!reader->Read(17, 0, 4 * kBlockSize, after) && after.empty(), "drained reader no longer accesses image");
}
void AcceptedRepairBlocksSnapshot() {
    FreshRepair("accepted-repair.apfs"); DamageCount("accepted-repair.apfs");
    {
        Tx journal(L"Strict"); Configure(journal, "accepted-repair.wal");
        auto owner = Open("accepted-repair.apfs", journal); std::string error;
        ApfsCountRepairPlan repair;
        Check(PrepareApfsCountRepair(*owner, 101, repair, error), "prepare interrupted repair: " + error);
        owner->FindSessionStore(101)->SetCommitStageHook([](std::string_view stage) { return stage != "before-apple-publish"; });
        const auto result = ApplyApfsCountRepair(*owner, journal, repair, repair.ConfirmationToken());
        Check(result.commit_recovery_required && journal.HasUnappliedAcceptedWork(), "interrupted repair retains accepted owner");
    }
    Tx journal(L"Strict"); Configure(journal, "accepted-repair.wal");
    auto owner = Open("accepted-repair.apfs", journal); std::string error;
    const auto image = Bytes("accepted-repair.apfs"), wal = Bytes("accepted-repair.wal");
    SnapshotRuntimePlan snapshot;
    Check(!PrepareSnapshotCreate(*owner, 101, "blocked", 1, 0, snapshot, error) &&
        error == "SnapshotRuntimeAcceptedOwnerConflict", "accepted RCT2 excludes new snapshot work");
    Check(Bytes("accepted-repair.apfs") == image && Bytes("accepted-repair.wal") == wal, "snapshot refusal retains accepted RCT2 bytes");
    const auto replay = ReplayApfsCountRepair(*owner, journal, 101, error);
    Check(replay.value_or(false), "union runtime replays accepted repair: " + error);
    Create(*owner, journal, "after-recovery");
}
void AcceptedSnapshotBlocksRepair() {
    FreshRepair("accepted-snapshot.apfs"); DamageCount("accepted-snapshot.apfs");
    {
        Tx journal(L"Strict"); Configure(journal, "accepted-snapshot.wal");
        auto owner = Open("accepted-snapshot.apfs", journal); std::string error;
        SnapshotRuntimePlan snapshot;
        Check(PrepareSnapshotCreate(*owner, 101, "retained", 1, 0, snapshot, error), "prepare interrupted snapshot: " + error);
        owner->FindSessionStore(101)->SetCommitStageHook([](std::string_view stage) { return stage != "before-apple-publish"; });
        const auto result = ApplySnapshot(*owner, journal, snapshot);
        Check(result.commit_recovery_required && journal.HasUnappliedAcceptedWork(), "interrupted snapshot retains accepted owner");
    }
    Tx journal(L"Strict"); Configure(journal, "accepted-snapshot.wal");
    auto owner = Open("accepted-snapshot.apfs", journal); std::string error;
    const auto image = Bytes("accepted-snapshot.apfs"), wal = Bytes("accepted-snapshot.wal");
    ApfsCountRepairPlan repair;
    Check(!PrepareApfsCountRepair(*owner, 101, repair, error) && error == "InspectionAcceptedOwnerConflict",
        "accepted snapshot excludes repair preparation: " + error);
    Check(Bytes("accepted-snapshot.apfs") == image && Bytes("accepted-snapshot.wal") == wal &&
        journal.HasUnappliedAcceptedWork(), "repair refusal conserves accepted snapshot evidence");
    const auto replay = ReplaySnapshot(*owner, journal, 101, error);
    Check(replay.value_or(false), "union runtime replays accepted snapshot: " + error);
    Check(List(*owner).size() == 1, "accepted snapshot remains visible after recovery");
}
void WireAndCompaction() {
    FreshRepair("wire-union.apfs"); DamageCount("wire-union.apfs");
    Tx journal(L"Strict"); Configure(journal, "wire-union.wal");
    auto owner = Open("wire-union.apfs", journal); std::string error;
    ApfsCountRepairPlan repair;
    Check(PrepareApfsCountRepair(*owner, 101, repair, error), "wire repair prepares: " + error);
    const auto& proof = repair.Evidence();
    WriteAheadLog::Record record;
    record.operation = WriteAheadLog::OperationKind::RepairVolumeFileCount;
    record.volume_identity = CountRepairJournalIdentity(proof); record.path_utf8 = "\\";
    record.object_id = proof.volume; record.parent_object_id = proof.checkpoint + 1;
    record.transaction_id = 1; record.sequence = 1;
    record.inline_payload = EncodeNativeCountRepair(proof); record.payload_length = record.inline_payload.size();
    HashPayload(record.inline_payload, record.payload_sha256);
    Check(!WriteAheadLog::EncodeForTest(record, 2).empty(), "RCT2 uses existing v2 WAL envelope");
    for (const auto opcode : {18, 19, 20, 25}) {
        auto bad = record; bad.operation = static_cast<WriteAheadLog::OperationKind>(opcode);
        Check(WriteAheadLog::EncodeForTest(bad).empty(), "repair payload cannot cross snapshot or reserved opcode");
    }
    auto legacy = record; legacy.inline_payload[3] = std::byte{0x31}; HashPayload(legacy.inline_payload, legacy.payload_sha256);
    Check(WriteAheadLog::EncodeForTest(legacy).empty(), "rehashed RCT1 remains fail-closed");
    auto zero = proof; zero.volume = 0;
    auto bad = record; bad.object_id = 0; bad.volume_identity = CountRepairJournalIdentity(zero);
    bad.inline_payload = EncodeNativeCountRepair(zero); HashPayload(bad.inline_payload, bad.payload_sha256);
    Check(WriteAheadLog::EncodeForTest(bad).empty(), "zero repair OID stays refused");
    using Kind = MutationCompactor::MutationKind;
    static_assert(static_cast<unsigned>(Kind::CreateSnapshot) == 18 && static_cast<unsigned>(Kind::DeleteSnapshot) == 19 &&
        static_cast<unsigned>(Kind::RepairVolumeFileCount) == 24);
    for (const auto kind : {Kind::CreateSnapshot, Kind::DeleteSnapshot, Kind::RepairVolumeFileCount}) {
        const auto summary = MutationCompactor::Summarize({{Kind::Write, L"\\file", L"", 4},
            {kind, L"\\", L"", 0}, {Kind::Write, L"\\file", L"", 8}});
        Check(summary.compacted_mutation_count == 3 && summary.payload_paths.size() == 1,
            "snapshot/repair barrier preserves ordered writes and excludes invented metadata payload");
    }
}
}
int main() {
    try {
        const auto root = std::filesystem::current_path(); unsigned ordinal = 0;
        const auto run = [&](auto test) { const auto path = root / std::to_string(++ordinal);
            std::filesystem::create_directory(path); std::filesystem::current_path(path); test(); std::filesystem::current_path(root); };
        run(RepairThenSnapshot); run(AcceptedRepairBlocksSnapshot); run(AcceptedSnapshotBlocksRepair); run(WireAndCompaction);
        std::cout << "SnapshotRepairIntegrationTests: " << checks << " checks, 0 failures\n"; return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL after " << checks << " checks: " << error.what() << '\n'; return 1; }
}
