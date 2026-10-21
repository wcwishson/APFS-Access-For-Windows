#define VOLUME_RENAME_TEST_HELPERS_ONLY
#include "VolumeRenameTests.cpp"
#include "ApfsRepair.h"
#include <thread>
#include <future>

namespace
{
unsigned repair_cases = 0;
void Passed(const std::string& name) { ++repair_cases; std::cout << "PASS " << name << '\n'; }
Fixture Oracle(bool aliases = false, unsigned alias_drec_fault = 0)
{
    auto spec = RenameSpec();
    // Allocated but unattributed bytes are never a repair free-space source.
    spec.authoritative_seeded_main_blocks.push_back({200, std::vector<std::byte>(kBlockSize, std::byte{0xa6})});
    for (auto& volume : spec.volumes) {
        std::string why;
        for (auto& record : volume.filesystem_records) if (Type(record) == 3) {
            AppleInodeRecord inode;
            Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, why), "oracle inode decode");
            for (auto& field : inode.extended_fields) field.flags = 0;
            Check(EncodeAppleInodeRecord(inode, record, why), "oracle supported ordinary inode fields");
        }
        if (aliases && volume.oid == 101) {
            const auto attach_sibling = [&](AppleDirectoryRecord& entry, std::uint64_t id) {
                if (alias_drec_fault == 1) return;
                AppleExtendedField sibling{1, 0, std::vector<std::byte>(8)};
                PutU64LE(sibling.data, 0, alias_drec_fault == 2 ? (id == 700 ? 701 : 700) : id);
                entry.extended_fields.push_back(std::move(sibling));
            };
            std::string original_name;
            for (auto& record : volume.filesystem_records) {
                if (Type(record) == 3) {
                    AppleInodeRecord inode;
                    Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, why), "alias inode decode");
                    inode.children_or_links = 2;
                    Check(EncodeAppleInodeRecord(inode, record, why), "alias inode link and root child counts");
                }
                if (Type(record) == 9) {
                    AppleDirectoryRecord drec;
                    Check(ApfsExtendedRecordCodec::DecodeDirectory(record, ApfsNamePolicy::FromIncompatibleFeatures(9), drec, why), "alias original name");
                    original_name = drec.name_utf8;
                    attach_sibling(drec, 700);
                    Check(EncodeAppleDirectoryRecord(drec, ApfsNamePolicy::FromIncompatibleFeatures(9), record, why), "alias original sibling directory entry");
                }
            }
            apfsaccess::catalog::BtreeRecord encoded;
            AppleDirectoryRecord alias;
            alias.parent_id = 2; alias.file_id = 17; alias.flags = 8; alias.name_utf8 = "alias";
            attach_sibling(alias, 701);
            Check(EncodeAppleDirectoryRecord(alias, ApfsNamePolicy::FromIncompatibleFeatures(9), encoded, why), "alias directory entry");
            volume.filesystem_records.push_back(encoded);
            for (const auto& [name, id] : std::vector<std::pair<std::string, std::uint64_t>>{{original_name,700},{"alias",701}}) {
                Check(EncodeAppleSiblingLinkRecord({17,id,2,name}, encoded, why), "alias sibling link");
                volume.filesystem_records.push_back(encoded);
                Check(EncodeAppleSiblingMapRecord({id,17}, encoded, why), "alias sibling map");
                volume.filesystem_records.push_back(encoded);
            }
        }
        Check(SortAppleBtreeRecords(volume.filesystem_records, AppleBtreeKeyOrder::FileSystemHashedDirectory, why), "oracle APFS key ordering: " + why);
    }
    Fixture fixture(spec);
    // The strict snapshot inventory reader admits ordinary manually managed
    // OMAPs. The older transaction fixture omits this header feature.
    auto at = fixture.image.begin() + 2 * kBlockSize;
    std::vector<std::byte> omap(at, at + kBlockSize);
    PutU32LE(omap, 0x20, 1); std::string error;
    Check(FinalizeAppleObjectChecksum(omap, error), "oracle OMAP checksum");
    std::copy(omap.begin(), omap.end(), at); fixture.Reload();
    // Independent fixture truth: each volume contains exactly one regular
    // inode, one root directory, one drec and its data/xattr records.
    SetApsbCounter(fixture, 0, 0xb8, 1);
    SetApsbCounter(fixture, 1, 0xb8, 1);
    return fixture;
}
void ObserveRepair(const std::filesystem::path& path, const Fixture& oracle)
{
    auto bytes = ReadImage(path); VectorRandomAccessSource source(bytes); std::string error;
    const auto cp = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    Check(cp && cp->volumes[0].superblock.file_count == 1, "pristine oracle file count restored: " + error);
    VerificationScope scope;
    scope.source_identity = "independent-oracle-read";
    scope.exact = {0, bytes.size(), cp->container.superblock.uuid_hex, cp->volumes[0].superblock.uuid_hex,
        101, cp->container.superblock.xid};
    const auto report = ApfsVerifier::Verify(source, scope);
    Check(report.outcome == VerificationOutcome::Complete && report.findings.empty(), "fresh second current-subset verification");
    Fixture after = oracle; after.image = bytes; after.checkpoint = *cp;
    const auto before_records = ReadTree(oracle), after_records = ReadTree(after);
    Check(before_records.size() == after_records.size(), "oracle record cardinality unchanged");
    for (std::size_t i = 0; i < before_records.size(); ++i)
        Check(before_records[i].key == after_records[i].key && before_records[i].value == after_records[i].value,
            "every original inode, directory, xattr and extent record preserved exactly");
    Observe(path, oracle, "Data");
    Check(std::equal(bytes.begin() + 200 * kBlockSize, bytes.begin() + 201 * kBlockSize,
        oracle.image.begin() + 200 * kBlockSize), "unattributed allocation bytes preserved");
    for (const auto& old_chunk : oracle.checkpoint.spaceman.chunks) {
        const auto it = std::find_if(cp->spaceman.chunks.begin(), cp->spaceman.chunks.end(), [&](const auto& chunk) {
            return chunk.start_block == old_chunk.start_block && chunk.block_count == old_chunk.block_count;
        });
        Check(it != cp->spaceman.chunks.end(), "allocator chunk geometry preserved");
        Check(old_chunk.allocation_bitmap.size() == it->allocation_bitmap.size() &&
            std::equal(old_chunk.allocation_bitmap.begin(), old_chunk.allocation_bitmap.end(), it->allocation_bitmap.begin(),
                [](std::byte old_byte, std::byte new_byte) { return (old_byte & new_byte) == old_byte; }),
            "every prior main-pool allocated bit remains allocated");
    }
}
void RepairSuccess()
{
    for (const auto damaged_count : {0ull, 2ull, 1000000ull, UINT64_MAX}) {
        auto oracle = Oracle(), damaged = oracle;
        SetApsbCounter(damaged, 0, 0xb8, damaged_count);
        const auto stem = "repair-" + std::to_string(damaged_count);
        const auto path = std::filesystem::absolute(stem + ".apfs"); SaveImage(path, damaged.image);
        SaveImage(stem + "-pristine.apfs", oracle.image);
        {
            Tx journal(L"Strict"); Configure(journal, stem + ".wal"); auto owner = OpenOwner(path);
            ApfsCountRepairPlan plan; std::string error;
            const bool prepared = PrepareApfsCountRepair(*owner, 101, plan, error);
            Check(prepared, "prepare count repair: " + error);
            Check(plan.Evidence().expected_count == 1 && plan.Finding().code == VerificationCode::VolumeFileCountInconsistent,
                "typed independent count finding");
            Check(ReadImage(path) == damaged.image && !journal.Watermarks().accepted_sequence, "prepare changes no image or WAL bytes");
            const auto result = ApplyApfsCountRepair(*owner, journal, plan, plan.ConfirmationToken());
            CheckSuccess(result);
            Check(!ApplyApfsCountRepair(*owner, journal, plan, plan.ConfirmationToken()).committed, "capability is one-use");
            ApfsCountRepairPlan noop;
            Check(!PrepareApfsCountRepair(*owner, 101, noop, error) && error == "CountRepairNoFinding", "no-op is explicit refusal");
            Check(!journal.HasUnappliedAcceptedWork() && journal.Watermarks().cleanup_sequence > 0, "only verified repair cleans accepted ownership");
        }
        ObserveRepair(path, oracle); Passed(stem);
    }
}
void RepairRefusals()
{
    auto damaged = Oracle(); SetApsbCounter(damaged, 0, 0xb8, 99);
    const auto path = std::filesystem::absolute("refusal.apfs"); SaveImage(path, damaged.image);
    const auto other_path = std::filesystem::absolute("refusal-other.apfs"); SaveImage(other_path, damaged.image);
    auto owner = OpenOwner(path), other = OpenOwner(other_path); Tx journal(L"Strict"); Configure(journal, "refusal.wal");
    std::string error;
    for (const bool wrong_owner : {false, true}) {
        ApfsCountRepairPlan plan;
        Check(PrepareApfsCountRepair(*owner, 101, plan, error), "prepare refusal: " + error);
        const auto result = ApplyApfsCountRepair(wrong_owner ? *other : *owner, journal, plan,
            wrong_owner ? plan.ConfirmationToken() : "wrong-token");
        Check(!result.committed && !ApplyApfsCountRepair(*owner, journal, plan, plan.ConfirmationToken()).committed,
            "wrong owner/token consumes capability");
        Check(ReadImage(path) == damaged.image && !journal.Watermarks().accepted_sequence, "refusal is byte-identical and unaccepted");
        Passed(wrong_owner ? "wrong owner" : "wrong confirmation");
    }
    ApfsCountRepairPlan stale, current;
    Check(PrepareApfsCountRepair(*owner, 101, stale, error) && PrepareApfsCountRepair(*owner, 101, current, error), "two exact preimages");
    CheckSuccess(ApplyApfsCountRepair(*owner, journal, current, current.ConfirmationToken()));
    const auto after = ReadImage(path);
    Check(!ApplyApfsCountRepair(*owner, journal, stale, stale.ConfirmationToken()).committed && ReadImage(path) == after,
        "stale plan writes nothing"); Passed("stale XID");
    auto proof = stale.Evidence(); ++proof.expected_count;
    VectorRandomAccessSource source(damaged.image); AppleVolumeTransactionPlan planned;
    Check(!PlanCountRepairCheckpoint(source, damaged.checkpoint, proof, {proof.checkpoint}, planned, error) &&
        planned.commit.publication.before_superblock_writes.empty(), "caller-chosen replacement count refused"); Passed("forged count");
    proof = stale.Evidence(); proof.graph_sha256[0] = proof.graph_sha256[0] == '0' ? '1' : '0';
    Check(!PlanCountRepairCheckpoint(source, damaged.checkpoint, proof, {proof.checkpoint}, planned, error), "changed graph proof refuses");
    Passed("changed graph preimage");
    proof = stale.Evidence(); ++proof.volume;
    Check(!PlanCountRepairCheckpoint(source, damaged.checkpoint, proof, {proof.checkpoint}, planned, error), "wrong volume OID refuses");
    Passed("wrong volume identity");
}
void RepairFaults()
{
    for (const std::string mode : {"write-fail", "write-torn", "flush", "acceptance", "switch", "final-flush", "after-publish", "finalization", "cleanup-finalization", "cleanup-marker-lost"}) {
        auto oracle = Oracle(), damaged = oracle; SetApsbCounter(damaged, 0, 0xb8, 99);
        const auto stem = "repair-fault-" + mode, path = std::filesystem::absolute(stem + ".apfs").string();
        SaveImage(path, damaged.image);
        std::vector<std::byte> durable_prefix;
        const bool cleanup_fault = mode == "cleanup-finalization" || mode == "cleanup-marker-lost";
        {
            Tx journal(L"Strict"); Configure(journal, stem + ".wal"); auto owner = OpenOwner(path);
            ApfsCountRepairPlan plan; std::string error;
            Check(PrepareApfsCountRepair(*owner, 101, plan, error), "fault preflight: " + error);
            if (mode == "acceptance") journal.SetJournalFaultInjectionHook([](std::string_view stage) { return stage == "durable-flush"; });
            unsigned journal_flushes = 0;
            if (mode == "finalization" || cleanup_fault) journal.SetJournalFaultInjectionHook([&](std::string_view stage) {
                if (stage != "durable-flush") return false;
                ++journal_flushes;
                if (cleanup_fault && journal_flushes == 2) durable_prefix = ReadImage(stem + ".wal");
                return journal_flushes >= (cleanup_fault ? 3u : 2u);
            });
            if (mode == "after-publish") owner->FindSessionStore(101)->SetCommitStageHook([](std::string_view stage) {
                return stage != "after-apple-publish";
            });
            if (mode == "write-fail") SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_WRITE", L"fail");
            if (mode == "write-torn") SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_WRITE", L"first-half");
            if (mode == "flush") SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_FLUSH", L"1");
            if (mode == "switch" || mode == "final-flush") owner->FindSessionStore(101)->SetCommitStageHook([&](std::string_view stage) {
                if (mode == "final-flush" && stage == "before-apple-final-flush") SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_FLUSH", L"1");
                return mode != "switch" || stage != "before-apple-checkpoint-switch";
            });
            const auto result = ApplyApfsCountRepair(*owner, journal, plan, plan.ConfirmationToken());
            SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_WRITE", nullptr); SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_FLUSH", nullptr);
            Check(result.commit_recovery_required && result.commit_status_code != static_cast<int>(Store::CommitStatus::Committed),
                "fault never acknowledged: " + mode + " " + result.error);
            Check((cleanup_fault ? journal.Watermarks().apfs_durable_sequence > 0 : !journal.Watermarks().apfs_durable_sequence) && !journal.Watermarks().cleanup_sequence,
                "accepted evidence not cleaned on fault");
            const auto pins = owner->CheckpointCensusSnapshot();
            Check(pins[0].unapplied_accepted_work && !pins[0].required_checkpoint_xids.empty(), "accepted owner and old checkpoint remain pinned");
        }
        if (mode == "cleanup-marker-lost") {
            Check(!durable_prefix.empty(), "capture durable prefix before uncertain cleanup marker");
            SaveImage(stem + "-visible-cleanup.wal", ReadImage(stem + ".wal"));
            SaveImage(stem + ".wal", durable_prefix); // Model loss of only the unflushed marker.
        }
        auto bytes = ReadImage(path); VectorRandomAccessSource source(bytes); std::string error;
        const auto cp = LoadAppleCheckpointView(source, 0, bytes.size(), error);
        Check(cp && (cp->volumes[0].superblock.file_count == 99 || cp->volumes[0].superblock.file_count == 1), "valid old-or-new count after fault");
        {
            Tx journal(L"Strict"); Configure(journal, stem + ".wal"); auto owner = OpenOwner(path, &journal);
            const auto result = ReplayApfsCountRepair(*owner, journal, 101, error);
            Check(mode == "cleanup-finalization"
                    ? !result.has_value() && cp->volumes[0].superblock.file_count == 1 && error.empty()
                    : result.value_or(false),
                "restart proves repaired state whether uncertain cleanup marker survived or was lost: " + mode + " " + error);
            Check(!journal.HasUnappliedAcceptedWork() && journal.Watermarks().cleanup_sequence > 0, "replay cleans accepted evidence only after verification");
            Check(!ReplayApfsCountRepair(*owner, journal, 101, error).has_value(), "second replay is empty, not repair success");
        }
        ObserveRepair(path, oracle); Passed(mode);
    }
}
void RepairAdditionalGates()
{
    auto damaged = Oracle(); SetApsbCounter(damaged, 0, 0xb8, 99);
    const auto path = std::filesystem::absolute("additional.apfs"); SaveImage(path, damaged.image);
    auto owner = OpenOwner(path); Tx journal(L"Strict"); Configure(journal, "additional.wal"); std::string error;
    ApfsCountRepairPlan expired;
    Check(PrepareApfsCountRepair(*owner, 101, expired, error, std::chrono::milliseconds(1)), "short expiry prepares");
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    Check(!ApplyApfsCountRepair(*owner, journal, expired, expired.ConfirmationToken()).committed && ReadImage(path) == damaged.image,
        "expired plan changes no bytes"); Passed("expiry");
    ApfsCountRepairPlan busy;
    Check(PrepareApfsCountRepair(*owner, 101, busy, error), "prepare before sibling debt");
    Check(owner->UpdateRequiredCheckpointXids(102, {owner->CheckpointXid()}, error, true), "establish sibling accepted owner");
    Check(!ApplyApfsCountRepair(*owner, journal, busy, busy.ConfirmationToken()).committed && ReadImage(path) == damaged.image,
        "sibling accepted owner blocks repair");
    Check(owner->CheckpointCensusSnapshot()[1].unapplied_accepted_work, "sibling ownership retained");
    Check(owner->UpdateRequiredCheckpointXids(102, {}, error, false), "remove test-only sibling debt"); Passed("sibling debt");
    ApfsCountRepairPlan changed;
    Check(PrepareApfsCountRepair(*owner, 101, changed, error), "prepare changed bytes");
    const auto block = damaged.checkpoint.volumes[1].superblock_object.physical_block;
    std::vector<std::byte> sibling(damaged.image.begin() + block * kBlockSize, damaged.image.begin() + (block + 1) * kBlockSize);
    PutU64LE(sibling, 0xb8, 2); Check(FinalizeAppleObjectChecksum(sibling, error), "same-XID sibling mutation checksum");
    Check(const_cast<BlockDevice&>(owner->Device()).Write(block * kBlockSize, sibling), "inject native sibling change on held image");
    const auto modified = ReadImage(path);
    Check(!ApplyApfsCountRepair(*owner, journal, changed, changed.ConfirmationToken()).committed && ReadImage(path) == modified &&
        !journal.Watermarks().accepted_sequence, "same-XID changed sibling bytes invalidate prepared witness"); Passed("changed sibling bytes");
    owner.reset();
    SaveImage(path, damaged.image); owner = OpenOwner(path);
    ApfsCountRepairPlan payload_changed;
    Check(PrepareApfsCountRepair(*owner, 101, payload_changed, error), "prepare payload preimage");
    std::vector<std::byte> payload(kBlockSize, std::byte{0x39});
    Check(const_cast<BlockDevice&>(owner->Device()).Write(128 * kBlockSize, payload), "inject changed payload bytes");
    const auto changed_payload = ReadImage(path);
    Check(!ApplyApfsCountRepair(*owner, journal, payload_changed, payload_changed.ConfirmationToken()).committed &&
        ReadImage(path) == changed_payload && !journal.Watermarks().accepted_sequence, "changed payload refuses before acceptance");
    Passed("changed payload bytes");
    owner.reset(); SaveImage(path, damaged.image); owner = OpenOwner(path);
    ApfsCountRepairPlan concurrent;
    Check(PrepareApfsCountRepair(*owner, 101, concurrent, error), "prepare concurrent consumption");
    ContainerCommitResult first, second;
    std::thread a([&] { first = ApplyApfsCountRepair(*owner, journal, concurrent, concurrent.ConfirmationToken()); });
    std::thread b([&] { second = ApplyApfsCountRepair(*owner, journal, concurrent, concurrent.ConfirmationToken()); });
    a.join(); b.join();
    Check(first.committed != second.committed, "exactly one concurrent capability consumer publishes");
    CheckSuccess(first.committed ? first : second); Passed("concurrent one-use");
    owner.reset(); SaveImage(path, damaged.image); owner = OpenOwner(path);
    ApfsCountRepairPlan left, right;
    Check(PrepareApfsCountRepair(*owner, 101, left, error) && PrepareApfsCountRepair(*owner, 101, right, error),
        "prepare two independent capabilities for one source and WAL");
    first = {}; second = {};
    std::thread c([&] { first = ApplyApfsCountRepair(*owner, journal, left, left.ConfirmationToken()); });
    std::thread d([&] { second = ApplyApfsCountRepair(*owner, journal, right, right.ConfirmationToken()); });
    c.join(); d.join();
    Check(first.committed != second.committed, "different plans sharing one WAL have exactly one publisher");
    CheckSuccess(first.committed ? first : second); Passed("distinct-plan serialized journal admission");
}
void RepairCorruptionRefusals()
{
    auto damaged = Oracle(); SetApsbCounter(damaged, 0, 0xb8, 99);
    const auto path = std::filesystem::absolute("corruption.apfs"); SaveImage(path, damaged.image);
    auto owner = OpenOwner(path); ApfsCountRepairPlan plan; std::string error;
    Check(PrepareApfsCountRepair(*owner, 101, plan, error), "corruption proof source");
    const auto proof = plan.Evidence(); owner.reset();
    for (const std::string kind : {"checksum", "link", "snapshot", "encrypted"}) {
        auto corrupt = damaged;
        if (kind == "checksum") corrupt.image[corrupt.checkpoint.volumes[0].root_tree.physical_block * kBlockSize + 80] ^= std::byte{1};
        else if (kind == "snapshot") SetApsbCounter(corrupt, 0, 0xd8, 1);
        else if (kind == "encrypted") SetApsbCounter(corrupt, 0, 0x108, 0);
        else {
            auto records = ReadTree(corrupt);
            for (auto& record : records) if (Type(record) == 3 && Id(record) == 17) PutU32LE(record.value, 56, 7);
            const auto& root = corrupt.checkpoint.volumes[0].root_tree;
            std::vector<std::vector<std::byte>> keys, values;
            for (const auto& record : records) { keys.push_back(record.key); values.push_back(record.value); }
            auto tree = BuildRawLeafNode(keys, values, root.xid, kBlockSize, 0, root.object_id, root.type, root.subtype);
            std::copy(tree.begin(), tree.end(), corrupt.image.begin() + root.physical_block * kBlockSize);
        }
        VectorRandomAccessSource source(corrupt.image); AppleVolumeTransactionPlan publication;
        const auto before = corrupt.image;
        Check(!PlanCountRepairCheckpoint(source, corrupt.checkpoint, proof, {proof.checkpoint}, publication, error) &&
            publication.commit.publication.before_superblock_writes.empty() && corrupt.image == before,
            "corruption never waived: " + kind); Passed(kind + " refusal");
    }
}
void RepairSiblingMetadataRecovery()
{
    auto damaged = Oracle(); SetApsbCounter(damaged, 0, 0xb8, 99);
    const auto path = std::filesystem::absolute("sibling-inline.apfs"); SaveImage(path, damaged.image);
    std::string error;
    {
        auto owner = OpenOwner(path); Tx journal(L"Strict"); Configure(journal, "sibling-inline.wal");
        ApfsCountRepairPlan plan; Check(PrepareApfsCountRepair(*owner, 101, plan, error), "sibling inline prepares");
        owner->FindSessionStore(101)->SetCommitStageHook([](std::string_view stage) { return stage != "before-apple-publish"; });
        const auto result = ApplyApfsCountRepair(*owner, journal, plan, plan.ConfirmationToken());
        std::cerr << "[DIAG] sibling original acceptance committed=" << result.committed << " recovery=" << result.commit_recovery_required
            << " stage=" << result.commit_stage << " error=" << result.error << " accepted=" << journal.Watermarks().accepted_sequence << '\n';
        Check(!result.committed && result.commit_recovery_required && journal.HasUnappliedAcceptedWork() &&
            ReadImage(path) == damaged.image, "accept original graph without publication");
    }
    const auto block = damaged.checkpoint.volumes[1].root_tree.physical_block;
    std::vector<std::byte> leaf(damaged.image.begin() + block*kBlockSize, damaged.image.begin() + (block+1)*kBlockSize);
    const auto value = HexToBytes("cafebabe012345");
    const auto at = std::search(leaf.begin(), leaf.end(), value.begin(), value.end());
    Check(at != leaf.end(), "locate original sibling inline user xattr");
    *(at + value.size() - 1) ^= std::byte{1};
    Check(FinalizeAppleObjectChecksum(leaf, error), "checksum-valid sibling inline change");
    std::copy(leaf.begin(), leaf.end(), damaged.image.begin() + block*kBlockSize);
    SaveImage(path, damaged.image);
    auto owner = OpenOwner(path); Tx journal(L"Strict"); Configure(journal, "sibling-inline.wal");
    // The changed graph is individually valid; only the accepted proof can
    // establish that this is no longer the admitted source.
    VectorRandomAccessSource source(damaged.image); VerificationScope scope;
    scope.source_identity = "changed-inline-control";
    scope.exact = {0, damaged.image.size(), damaged.checkpoint.container.superblock.uuid_hex,
        damaged.checkpoint.volumes[0].superblock.uuid_hex, 101, damaged.checkpoint.container.superblock.xid};
    const auto verified = ApfsVerifier::Verify(source, scope);
    Check(verified.outcome == VerificationOutcome::Complete && verified.findings.empty(),
        "changed sibling metadata remains a valid ordinary graph");
    const auto result = ReplayApfsCountRepair(*owner, journal, 101, error);
    std::cerr << "[DIAG] sibling inline replay result=" << (result.has_value() ? (*result ? "true" : "false") : "none") << " error=" << error << '\n';
    Check(result.has_value() && !*result && journal.HasUnappliedAcceptedWork() && ReadImage(path) == damaged.image,
        "accepted repair refuses changed sibling inline metadata without publication or WAL cleanup");
    Passed("accepted sibling inline metadata proof");
}
void RepairAliasCount()
{
    auto oracle = Oracle(true), damaged = oracle; SetApsbCounter(damaged, 0, 0xb8, 2);
    const auto path = std::filesystem::absolute("aliases.apfs"); SaveImage(path, damaged.image);
    auto owner = OpenOwner(path); Tx journal(L"Strict"); Configure(journal, "aliases.wal");
    ApfsCountRepairPlan plan; std::string error;
    const bool prepared = PrepareApfsCountRepair(*owner, 101, plan, error);
    Check(prepared, "aliases prepare: " + error);
    Check(plan.Evidence().expected_count == 1, "two names count as exactly one regular inode");
    CheckSuccess(ApplyApfsCountRepair(*owner, journal, plan, plan.ConfirmationToken()));
    ObserveRepair(path, oracle); Passed("alias count and records preserved");
    for (const auto fault : {1u, 2u}) {
        auto malformed = Oracle(true, fault); SetApsbCounter(malformed, 0, 0xb8, 2);
        const auto bad_path = std::filesystem::absolute("aliases-drec-" + std::to_string(fault) + ".apfs");
        SaveImage(bad_path, malformed.image);
        auto bad_owner = OpenOwner(bad_path); ApfsCountRepairPlan rejected; error.clear();
        const bool admitted = PrepareApfsCountRepair(*bad_owner, 101, rejected, error);
        Check(!admitted && error.starts_with("CountRepairIndependentCurrentGraphNotVerified"),
            "alias directory sibling ownership refuses repair preparation: " + error);
        Check(ReadImage(bad_path) == malformed.image && !bad_owner->IsRecoveryRequired(),
            "malformed alias ownership preserves all image bytes without recovery debt");
        Passed(fault == 1 ? "missing directory sibling IDs refuse repair" : "exchanged directory sibling IDs refuse repair");
    }
}
void RepairJournalIdentity()
{
    for (const std::wstring identity : {L"apfs-vol:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:102",
            L"apfs-vol:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:101", L"arbitrary-owner"}) {
        auto damaged = Oracle(); SetApsbCounter(damaged, 0, 0xb8, 99);
        const auto stem = "journal-identity-" + std::to_string(repair_cases);
        const auto path = std::filesystem::absolute(stem + ".apfs"); SaveImage(path, damaged.image);
        auto owner = OpenOwner(path); Tx journal(L"Strict"); Configure(journal, stem + ".wal");
        journal.SetVolumeIdentity(identity);
        ApfsCountRepairPlan plan; std::string error;
        Check(PrepareApfsCountRepair(*owner, 101, plan, error), "journal mismatch prepares exact source");
        const auto result = ApplyApfsCountRepair(*owner, journal, plan, plan.ConfirmationToken());
        Check(!result.committed && !result.commit_recovery_required && !journal.Watermarks().accepted_sequence &&
            journal.PendingMutationCount() == 0 && ReadImage(path) == damaged.image,
            "foreign outer journal identity refuses before acceptance without image changes");
        Check(!ApplyApfsCountRepair(*owner, journal, plan, plan.ConfirmationToken()).committed,
            "journal mismatch consumes confirmation");
        Passed("journal identity refusal");
    }
}
void RepairRetainedHistory()
{
    auto damaged = Oracle(); SetApsbCounter(damaged, 0, 0xb8, 99);
    const auto path = std::filesystem::absolute("history.apfs"), wal = std::filesystem::absolute("history.wal");
    SaveImage(path, damaged.image); std::vector<std::byte> accepted;
    {
        Tx journal(L"Strict"); Configure(journal, wal); auto owner = OpenOwner(path); std::string error;
        ApfsCountRepairPlan plan; Check(PrepareApfsCountRepair(*owner, 101, plan, error), "history repair prepares");
        journal.SetJournalFaultInjectionHook([&](std::string_view stage) {
            if (stage == "durable-flush" && accepted.empty()) accepted = ReadImage(wal);
            return false;
        });
        CheckSuccess(ApplyApfsCountRepair(*owner, journal, plan, plan.ConfirmationToken()));
        Check(!accepted.empty(), "capture real accepted opcode-24 WAL before cleanup");
        Check(owner->UpdateRequiredCheckpointXids(101, {damaged.checkpoint.container.superblock.xid, owner->CheckpointXid()}, error, false),
            "retain accepted history for restart scenario");
        Check(owner->RefreshSessionForRecovery(102, error), "refresh sibling at repaired checkpoint");
        Tx later(L"Strict");
        later.SetVolumeIdentity(L"apfs-vol:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:102");
        later.SetJournalPath(std::filesystem::absolute("history-later.wal").wstring());
        VolumeRenamePlan rename;
        Check(PrepareVolumeRename(*owner, 102, "Later", rename, error), "later canonical sibling transaction prepares");
        CheckSuccess(ApplyVolumeRename(*owner, later, rename));
    }
    SaveImage(wal, accepted);
    const auto current = ReadImage(path);
    const auto other = std::filesystem::absolute("history-copy.apfs"); SaveImage(other, current);
    {
        Tx journal(L"Strict"); Configure(journal, wal); auto owner = OpenOwner(other, &journal); std::string error;
        const auto result = ReplayApfsCountRepair(*owner, journal, 101, error);
        Check(result.has_value() && !*result && error == "CountRepairReplayIdentityInvalid" && ReadImage(other) == current,
            "byte-identical replacement image cannot inherit accepted ownership");
        Check(journal.HasUnappliedAcceptedWork(), "wrong-source replay retains canonical accepted WAL"); Passed("restart file identity");
    }
    {
        Tx journal(L"Strict"); Configure(journal, wal); auto owner = OpenOwner(path, &journal); std::string error;
        std::vector<Tx::AcceptedTransaction> retained;
        Check(journal.LoadAcceptedTransactionsSinceCleanup(retained) && retained.size() == 1,
            "read real accepted repair for independent WAL envelope checks");
        auto record = retained[0].mutations[0];
        auto legacy = record.inline_payload;
        legacy[3] = std::byte{0x31}; NativeCountRepair old_proof;
        Check(!DecodeNativeCountRepair(legacy, old_proof), "RCT1 cannot masquerade as the complete sibling-record proof");
        Check(WriteAheadLog::CountRepairIsConsistent(record), "canonical repair envelope remains valid");
        record.volume_identity = "apfs-vol:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:102";
        Check(!WriteAheadLog::CountRepairIsConsistent(record) && !WriteAheadLog::InlinePayloadIsConsistent(record),
            "foreign WAL envelope cannot route a valid repair payload");
        bool entered = false;
        Check(!owner->InspectCurrentSession(101, [&](const Store&, std::string&) { entered = true; return true; }, error) && !entered,
            "ordinary inspection cannot cross unresolved accepted ownership");
        std::future<bool> competitor;
        Check(owner->InspectCurrentSession(101, [&](const Store&, std::string&) {
            std::promise<void> started; auto ready = started.get_future();
            competitor = std::async(std::launch::async, [&, signal = std::move(started)]() mutable {
                signal.set_value(); std::string why;
                return owner->UpdateRequiredCheckpointXids(102, {}, why);
            });
            ready.wait();
            Check(competitor.wait_for(std::chrono::milliseconds(30)) == std::future_status::timeout,
                "recovery inspection owns serializer against sibling updates");
            return true;
        }, error, true), "accepted owner can inspect its exact current session: " + error);
        Check(competitor.get(), "sibling resumes after recovery inspection");
        error.clear();
        const auto result = ReplayApfsCountRepair(*owner, journal, 101, error);
        Check(result.value_or(false), "retained repair with later sibling commit: " + error);
        Check(ReadImage(path) == current && !journal.HasUnappliedAcceptedWork(), "historical recovery verifies without APFS rewrites");
        Passed("retained history after sibling commit");
    }
}
}
int main(int argc, char** argv)
{
    try {
        if (argc != 2) throw std::runtime_error("usage: ApfsRepairTests EVIDENCE_DIRECTORY");
        const auto run = std::filesystem::absolute(argv[1]) / ("run-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64()));
        std::filesystem::create_directories(run); std::filesystem::current_path(run);
        RepairSiblingMetadataRecovery(); RepairAliasCount(); RepairJournalIdentity(); RepairSuccess(); RepairRefusals(); RepairFaults(); RepairAdditionalGates(); RepairCorruptionRefusals(); RepairRetainedHistory();
        std::cout << "PASS bounded repair " << repair_cases << " cases " << checks << " checks\n"; return 0;
    } catch (const std::exception& error) {
        SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_WRITE", nullptr); SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_FLUSH", nullptr);
        std::cerr << "FAIL after " << repair_cases << " cases " << checks << " checks: " << error.what() << '\n'; return 1;
    }
}
