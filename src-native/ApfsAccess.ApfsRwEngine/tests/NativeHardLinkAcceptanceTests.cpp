#include <windows.h>
#undef CreateFile
#undef CreateDirectory
#define APPLE_CLONE_TEST_HELPERS_ONLY
#include "AppleCloneCowTests.cpp"
#include "MetadataStore.h"
#include "NativeHardLink.h"
#include "TransactionManager.h"
#include <filesystem>

namespace {
using Store = MetadataStore;
using Journal = TransactionManager;

BuilderStore HardLinkSpec(unsigned files) {
    Check(files == 1, "single-leaf seed fixture is bounded to one file");
    auto spec = CloneSpec(files);
    auto& records = spec.volumes.front().filesystem_records;
    std::erase_if(records, [](const auto& record) { return Type(record) == 4 && Id(record) == 17; });
    return spec;
}

Fixture HardLinkFixture(unsigned files) {
    Fixture fixture(HardLinkSpec(1));
    if (files == 1) return fixture;
    Check(files == 100, "bounded large native cohort");
    AppleVolumeTransactionRequest request; request.volume_object_id = 101;
    request.file_count_delta = files - 1; request.filesystem_records = ReadTree(fixture);
    AppleInodeRecord source; std::string error;
    for (auto& record : request.filesystem_records) {
        if (Type(record) == 3 && Id(record) == 17)
            Check(ApfsExtendedRecordCodec::DecodeInode(record, source, error), "decode canonical clone seed:" + error);
        if (Type(record) == 3 && Id(record) == 2) {
            AppleInodeRecord root; Check(ApfsExtendedRecordCodec::DecodeInode(record, root, error), error);
            root.children_or_links = files; Check(EncodeAppleInodeRecord(root, record, error), error);
        }
    }
    Check(source.object_id == 17, "canonical source inode exists");
    const auto first = fixture.checkpoint.volumes.front().superblock.next_object_id;
    for (unsigned n = 1; n < files; ++n) {
        const auto target = first + n - 1;
        auto inode = source; inode.object_id = inode.private_id = target; inode.children_or_links = 1;
        apfsaccess::catalog::BtreeRecord record; Check(EncodeAppleInodeRecord(inode, record, error), error);
        request.filesystem_records.push_back(record);
        AppleDirectoryRecord directory; directory.parent_id = 2; directory.file_id = target;
        directory.flags = 8; directory.name_utf8 = "clone" + std::to_string(n);
        Check(EncodeAppleDirectoryRecord(directory, ApfsNamePolicy::FromIncompatibleFeatures(kIncompatCaseInsensitive), record, error), error);
        request.filesystem_records.push_back(record); request.clones.push_back({17, target});
    }
    const auto plan = PlanClone(fixture, request); Publish(fixture, plan);
    const auto root = fixture.checkpoint.volumes.front().root_tree.physical_block;
    Check(ReadU16LE(std::span(fixture.image).subspan(root * 4096, 4096), 0x22).value_or(0) > 0,
        "large source was actually serialized as a multi-node canonical tree");
    return fixture;
}

void SaveImage(const std::filesystem::path& path, const std::vector<std::byte>& bytes) {
    Check(!std::filesystem::exists(path), "hard-link fixture must be fresh");
    std::ofstream output(path, std::ios::binary);
    output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    Check(!!output, "save hard-link source image");
}

Store::VolumeContext HardLinkContext(const std::filesystem::path& path) {
    Store::VolumeContext context;
    context.device_path = std::filesystem::absolute(path).wstring();
    context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    return context;
}

void OpenJournal(Journal& journal, const std::filesystem::path& path, const Fixture& source) {
    std::string error;
    const auto canonical = std::string("apfs-vol:") + source.checkpoint.container.superblock.uuid_hex + ":101";
    const auto identity = std::wstring(canonical.begin(), canonical.end());
    Check(journal.OpenStartupJournal(std::filesystem::absolute(path).wstring(), identity, error),
        "open original hard-link journal: " + error);
    if (!std::filesystem::exists(path))
        Check(journal.MaterializeAbsentStartupJournal(error), "materialize original journal: " + error);
    Check(journal.EnrollCanonicalJournalIdentity(identity), "enroll exact canonical journal identity");
}

void ProofCodec() {
    NativeHardLinkProof proof;
    proof.container_uuid = std::string(32, '1'); proof.volume_uuid = std::string(32, '2');
    proof.volume_oid = 101; proof.checkpoint = proof.source_generation = 4; proof.source_inode = 17;
    proof.original_parent = proof.destination_parent = 2;
    proof.original_name = "source"; proof.destination_name = "alias";
    proof.first_sibling = 1000; proof.next_object_id = 1007; proof.timestamp_ns = 1234;
    proof.incompatible_features = kIncompatCaseInsensitive;
    proof.block_size = 4096; proof.block_count = 512; proof.image_size = 4096 * 512;
    proof.image_creation_time = 7; proof.image_file_id.fill(std::byte{1});
    proof.before_sha.fill(1); proof.after_sha.fill(2); proof.references_sha.fill(3);
    proof.payload_sha.fill(4); proof.publication_sha.fill(5);
    proof.preimages.push_back({});
    auto encoded = EncodeNativeHardLink(proof);
    Check(!encoded.empty(), "multi-node publication proof permits additional allocated child object IDs");
    NativeHardLinkProof decoded;
    Check(DecodeNativeHardLink(encoded, decoded) && decoded == proof, "exact multi-node proof roundtrip");
    auto v2=proof;v2.version=2;const auto legacy_encoding=EncodeNativeHardLink(v2);
    Check(!legacy_encoding.empty()&&DecodeNativeHardLink(legacy_encoding,decoded)&&decoded==v2,"accepted NHL2 framing remains readable");
    auto mismatched=legacy_encoding;mismatched[3]=std::byte{'3'};
    Check(!DecodeNativeHardLink(mismatched,decoded)&&decoded.volume_oid==0,"proof magic and version must agree");
    auto wrong = proof; wrong.next_object_id = proof.first_sibling;
    Check(EncodeNativeHardLink(wrong).empty(), "new sibling ID must be below next object ID");
    wrong = proof; wrong.next_object_id = 0x0fffffffffffffffULL;
    Check(EncodeNativeHardLink(wrong).empty(), "reserved object ID ceiling refuses");
    encoded.push_back(std::byte{0});
    Check(!DecodeNativeHardLink(encoded, decoded) && decoded.volume_oid == 0, "trailing proof bytes clear output");
    wrong = proof; wrong.preimages.clear(); Check(EncodeNativeHardLink(wrong).empty(), "proof requires original physical census");
    wrong = proof; wrong.preimages.push_back({}); Check(EncodeNativeHardLink(wrong).empty(), "duplicate physical preimages refuse");
    wrong = proof; wrong.preimages.front().physical_block = proof.block_count;
    Check(EncodeNativeHardLink(wrong).empty(), "out-of-source preimage refuses");
    wrong = proof; wrong.preimages.resize(MaxNativeHardLinkPreimageBlocks + 1);
    Check(EncodeNativeHardLink(wrong).empty(), "bounded original physical census");
    wrong = proof; wrong.preimages.clear();
    for (std::uint64_t n = 0; n < MaxNativeHardLinkPreimageBlocks; ++n) {
        NativeHardLinkPreimage preimage; preimage.physical_block = n; preimage.bytes.fill(std::byte(n & 255));
        wrong.preimages.push_back(preimage);
    }
    auto full = EncodeNativeHardLink(wrong);
    Check(!full.empty() && full.size() <= WriteAheadLog::MaxInlinePayloadBytes && DecodeNativeHardLink(full, decoded) && decoded == wrong,
        "maximum bounded census fits existing inline policy");
    full.resize(MaxNativeHardLinkProofBytes + 1);
    Check(!DecodeNativeHardLink(full, decoded) && decoded.preimages.empty(), "over-budget proof clears output");
    auto legacy = EncodeNativeHardLink(proof); legacy[3] = std::byte{'1'}; legacy[4] = std::byte{1};
    Check(!DecodeNativeHardLink(legacy, decoded) && decoded.preimages.empty(), "historical NHL1 is explicitly unsupported");
    WriteAheadLog::Record record;
    record.operation = WriteAheadLog::OperationKind::HardLink; record.object_id = proof.source_inode;
    record.parent_object_id = proof.checkpoint; record.sequence = record.transaction_id = 1;
    record.path_utf8 = "\\alias"; record.secondary_path_utf8 = "\\source"; record.volume_identity = "native-test";
    record.inline_payload = EncodeNativeHardLink(proof);
    record.logical_length = record.payload_length = record.inline_payload.size();
    Check(NativeHardLinkHash(record.inline_payload, record.payload_sha256) && WriteAheadLog::NativeHardLinkIsConsistent(record),
        "registered versioned exact inline mapping");
    for (unsigned n = 0; n < 9; ++n) {
        auto bad = record;
        switch (n) {
        case 0: bad.payload_spool_id = 1; break;
        case 1: --bad.logical_length; break;
        case 2: bad.flags = 4; break;
        case 3: bad.payload_offset = 1; break;
        case 4: ++bad.parent_object_id; break;
        case 5: bad.secondary_path_utf8 = bad.path_utf8; break;
        case 6: bad.path_utf8 = "\xc0\xaf"; break;
        case 7: bad.payload_sha256[0] ^= 1; break;
        case 8: bad.state = WriteAheadLog::RecordState::Accepted; break;
        }
        Check(!WriteAheadLog::NativeHardLinkIsConsistent(bad) && WriteAheadLog::EncodeForTest(bad).empty(),
            "malformed typed WAL fields refuse encoding");
    }
}

std::vector<std::byte> FileBytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    Check(!!input, "open preserved evidence"); const auto size = input.tellg();
    Check(size >= 0 && size <= (8 << 20), "bounded regular evidence");
    std::vector<std::byte> bytes(static_cast<std::size_t>(size)); input.seekg(0);
    input.read(reinterpret_cast<char*>(bytes.data()), bytes.size()); Check(!!input, "read complete evidence"); return bytes;
}

std::vector<std::byte> ImageBytes(const BlockDevice& device) {
    const auto size = device.GetGeometry().total_bytes;
    Check(size && size <= (8 << 20), "bounded held regular image");
    std::vector<std::byte> bytes;
    Check(device.ReadForVerification(0, static_cast<std::size_t>(size), bytes) && bytes.size() == size, "exact held image evidence");
    return bytes;
}

void OriginalAdmissionControls(const WriteAheadLog::Record& accepted, const std::string& stem) {
    NativeHardLinkProof proof; Check(DecodeNativeHardLink(accepted.inline_payload, proof), "real original admission proof");
    for (unsigned mode = 0; mode < 3; ++mode) {
        const auto path = std::filesystem::absolute(stem + "-admission-" + std::to_string(mode) + ".wal");
        Journal journal(L"Strict"); std::string error;
        const auto volume = accepted.volume_identity + ":admission-" + std::to_string(mode);
        const std::wstring identity(volume.begin(), volume.end());
        Check(journal.OpenStartupJournal(path.wstring(), identity, error) && journal.MaterializeAbsentStartupJournal(error), "fresh admission control");
        Journal::MutationIntent intent; intent.kind = Journal::MutationKind::HardLink;
        intent.path.assign(accepted.path_utf8.begin(), accepted.path_utf8.end());
        intent.secondary_path.assign(accepted.secondary_path_utf8.begin(), accepted.secondary_path_utf8.end());
        intent.object_id = accepted.object_id; intent.generation = accepted.parent_object_id;
        intent.length = intent.payload_length = accepted.payload_length; intent.inline_payload = accepted.inline_payload;
        intent.payload_checksum = accepted.payload_sha256;
        const auto before = FileBytes(path);
        Check(journal.Begin() && journal.RecordMutation(intent) && !journal.FlushPreparedRecords() && FileBytes(path) == before,
            "typed proof cannot partially flush before its bound terminal");
        if (mode == 2) {
            Journal::MutationIntent extra; extra.kind = Journal::MutationKind::CreateFile;
            extra.object_id = 9999; extra.path = L"\\extra";
            Check(journal.RecordMutation(extra), "mixed buffered batch control");
        }
        const auto ok = journal.Accept(proof.checkpoint + (mode == 0 ? 1 : 0));
        Check(ok == (mode == 1), "acceptance binds one original proof to its exact preimage XID");
        if (mode != 1) Check(!journal.Watermarks().accepted_sequence && FileBytes(path) == before,
            "preimage/mixed-batch refusal persists no acceptance bytes");
        else {
            auto read = WriteAheadLog::ReadAll(path, volume);
            Check(read.status == WriteAheadLog::ReadStatus::Ok && read.records.size() == 2, "exact original proof and acceptance retained");
            ++read.records.back().object_id;
            const auto wrong = std::filesystem::path(stem + "-wrong-preimage.wal");
            std::ofstream output(wrong, std::ios::binary);
            for (const auto& row : read.records) {
                const auto bytes = WriteAheadLog::EncodeForTest(row); Check(!bytes.empty(), "CRC-valid wrong-preimage framing");
                output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
            }
            output.close(); const auto damaged = FileBytes(wrong);
            journal.SetJournalPath(L""); Journal reopened(L"Strict");
            Check(!reopened.OpenStartupJournal(std::filesystem::absolute(wrong).wstring(), identity, error) && FileBytes(wrong) == damaged,
                "semantic replay rejects wrong accepted preimage without repair");
        }
    }
}

void RefusalCases() {
    for (unsigned kind = 0; kind < 8; ++kind) {
        Fixture fixture(HardLinkSpec(1));
        const auto stem = "refuse-" + std::to_string(kind);
        const auto image = std::filesystem::path(stem + ".apfs"), wal = std::filesystem::path(stem + ".wal");
        SaveImage(image, fixture.image); auto context = HardLinkContext(image); std::string error;
        auto lease = BlockDevice::OpenExclusiveManagementImage(context.device_path, 0, error);
        Check(!!lease, "exclusive refusal lease:" + error); Store store(context, lease);
        Check(store.PrepareNativeWritePath(), "refusal source opens");
        Journal journal(L"Strict");
        if (kind == 6) journal.SetJournalMaxBytesForTest(1024);
        if (kind == 0) {
            Check(journal.OpenStartupJournal(std::filesystem::absolute(wal).wstring(), L"wrong-canonical-jid", error) &&
                journal.MaterializeAbsentStartupJournal(error) && journal.EnrollCanonicalJournalIdentity(L"wrong-canonical-jid"), "foreign original identity fixture");
        } else OpenJournal(journal, wal, fixture);
        const auto before = ImageBytes(*lease), original_wal = FileBytes(wal);
        Store::HardLinkReceipt receipt;
        if (kind < 3) {
            const auto target = kind == 1 ? L"\\CLONE0" : kind == 2 ? L"\\clone0" : L"\\alias";
            Check(store.AcceptNativeHardLink(journal, L"\\clone0", target, 123456789, receipt, error) == Store::HardLinkAcceptance::Refused,
                "foreign journal or existing alias refuses before acceptance:" + error);
            Check(journal.CurrentState() == Journal::State::Idle && !journal.Watermarks().accepted_sequence &&
                ImageBytes(*lease) == before && FileBytes(wal) == original_wal, "preacceptance refusal preserves image/original bytes");
            continue;
        }
        if (kind == 6) {
            Check(store.AcceptNativeHardLink(journal, L"\\clone0", L"\\alias", 123456789, receipt, error) != Store::HardLinkAcceptance::Accepted,
                "bounded original capacity cannot accept an oversized proof batch");
            const auto read = WriteAheadLog::ReadAll(wal, TransactionManager::WideToUtf8(journal.ConfiguredVolumeIdentity()));
            Check(ImageBytes(*lease) == before && read.status == WriteAheadLog::ReadStatus::Ok &&
                !journal.Watermarks().accepted_sequence &&
                std::all_of(read.records.begin(), read.records.end(), [](const auto& row) {
                    return row.operation == WriteAheadLog::OperationKind::CompactionIndex;
                }), "capacity refusal changes no image and retains only ordinary compaction metadata without acceptance");
            continue;
        }
        Check(store.AcceptNativeHardLink(journal, L"\\clone0", L"\\alias", 123456789, receipt, error) == Store::HardLinkAcceptance::Accepted,
            "real accepted proof for negative recovery:" + error);
        if (kind == 3) {
            std::vector<Journal::AcceptedTransaction> batches;
            Check(journal.LoadAcceptedTransactionsSinceCleanup(batches, &error) && batches.size() == 1, "actual original admission controls source");
            OriginalAdmissionControls(batches.front().mutations.front(), stem);
            journal.SetJournalFaultInjectionHook([](auto stage) { return stage == "durable-flush"; });
            Check(store.PublishOrRecoverNativeHardLink(journal, error) == Store::HardLinkPublication::RecoveryRequired && ImageBytes(*lease) == before,
                "original barrier failure cannot publish an image byte");
            continue;
        }
        if (kind == 7) {
            auto read = WriteAheadLog::ReadAll(wal, TransactionManager::WideToUtf8(journal.ConfiguredVolumeIdentity()));
            Check(read.status == WriteAheadLog::ReadStatus::Ok && read.records.size() == 2, "actual accepted proof for changed commitment");
            NativeHardLinkProof changed; Check(DecodeNativeHardLink(read.records.front().inline_payload, changed), "decode exact accepted proof");
            changed.publication_sha[0] ^= 1; auto& row = read.records.front(); row.inline_payload = EncodeNativeHardLink(changed);
            Check(!row.inline_payload.empty() && NativeHardLinkHash(row.inline_payload, row.payload_sha256), "self-consistent changed original commitment");
            const auto wrong = std::filesystem::path(stem + "-wrong-proof.wal"); std::ofstream output(wrong, std::ios::binary);
            for (const auto& r : read.records) { const auto bytes = WriteAheadLog::EncodeForTest(r); Check(!bytes.empty(), "changed proof framing");
                output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size()); }
            output.close(); const auto evidence = FileBytes(wrong);
            const auto identity=journal.ConfiguredVolumeIdentity(),enrolled=journal.EnrolledCanonicalJournalIdentity();
            journal.SetJournalPath(L""); Journal modified(L"Strict");
            Check(modified.OpenStartupJournal(std::filesystem::absolute(wrong).wstring(), identity, error) &&
                modified.EnrollCanonicalJournalIdentity(enrolled), "framing-valid changed commitment original");
            Store recovered(context, lease); Check(recovered.PrepareNativeWritePath(), "wrong-proof owner opens unchanged original image");
            Check(recovered.PublishOrRecoverNativeHardLink(modified, error) == Store::HardLinkPublication::Refused &&
                ImageBytes(*lease) == before && FileBytes(wrong) == evidence && !modified.Watermarks().cleanup_sequence,
                "full canonical replan rejects changed publication commitment with no writes:" + error);
            continue;
        }
        store.SetCommitStageHook([](std::string_view stage) { return stage != "before-apple-final-flush"; });
        Check(store.PublishOrRecoverNativeHardLink(journal, error) == Store::HardLinkPublication::RecoveryRequired,
            "real post-switch cut before physical evidence mutation:" + error);
        std::vector<Journal::AcceptedTransaction> pending;
        Check(journal.LoadAcceptedTransactionsSinceCleanup(pending, &error) && pending.size() == 1, "original proof retained after cut");
        NativeHardLinkProof proof;
        Check(DecodeNativeHardLink(pending.front().mutations.front().inline_payload, proof), "actual accepted NHL2 proof");
        const auto old_root = fixture.checkpoint.volumes.front().root_tree.physical_block;
        const auto current = [&] { std::vector<std::byte> bytes; Check(lease->ReadForVerification(0, 4096 * 512, bytes), "read actual switched image");
            VectorRandomAccessSource source(bytes); return LoadAppleCheckpointView(source, 0, source.SizeBytes(), error); }();
        Check(!!current, "actual published checkpoint selection");
        const auto block = kind == 4 ? old_root : current->volumes.front().root_tree.physical_block;
        Check(std::any_of(proof.preimages.begin(), proof.preimages.end(), [&](const auto& p) { return p.physical_block == block; }),
            "mutated guard/destination is committed in original census");
        Store recovered(context, lease); Check(recovered.PrepareNativeWritePath(), "fresh owner loaded before physical guard drift");
        std::vector<std::byte> bytes; Check(lease->ReadForVerification(block * 4096, 4096, bytes), "read selected guard/destination");
        bytes[0] ^= std::byte{1}; Check(lease->Write(block * 4096, bytes) && lease->Flush(), "actual private guard/destination corruption");
        const auto damaged = ImageBytes(*lease), wal_before = FileBytes(wal);
        Check(recovered.PublishOrRecoverNativeHardLink(journal, error) == Store::HardLinkPublication::Refused,
            "corrupt guard or planned postimage cannot earn durable completion:" + error);
        Check(ImageBytes(*lease) == damaged && FileBytes(wal) == wal_before && journal.Watermarks().cleanup_sequence < receipt.sequence,
            "corrupt physical evidence preserves all bytes and accepted debt");
    }
}

void AcceptanceRecovery(unsigned files, const std::string& cut) {
    std::cout << "BEGIN hard-link files=" << files << " cut=" << cut << '\n' << std::flush;
    auto fixture = HardLinkFixture(files);
    const auto name = "hardlink-" + std::to_string(files) + "-" + (cut.empty() ? "clean" : cut);
    const auto image = std::filesystem::path(name + ".apfs");
    const auto wal = std::filesystem::path(name + ".wal");
    SaveImage(image, fixture.image);
    auto context = HardLinkContext(image);
    const auto original = Payload(fixture, 17);
    std::uint64_t accepted = 0, checkpoint = 0;
    {
        std::string lease_error;
        auto lease = BlockDevice::OpenExclusiveManagementImage(context.device_path, 0, lease_error);
        Check(!!lease, "exclusive hard-link image lease: " + lease_error);
        Store store(context, lease);
        Check(store.PrepareNativeWritePath(), "hard-link source opens");
        Journal journal(L"Strict"); OpenJournal(journal, wal, fixture);
        Store::HardLinkReceipt receipt; std::string error;
        const auto outcome = store.AcceptNativeHardLink(journal, L"\\clone0", L"\\alias", 123456789, receipt, error);
        Check(outcome == Store::HardLinkAcceptance::Accepted, "durable original accepts hard link: " + error);
        std::cout << "ACCEPTED files=" << files << " cut=" << cut << '\n' << std::flush;
        accepted = receipt.sequence; checkpoint = receipt.checkpoint;
        Check(receipt.source == 17 && accepted != 0 && checkpoint == *store.CheckpointXid(), "receipt binds source and checkpoint");
        Check(!store.LookupWorkingInodeByPath(L"\\alias") && !store.LookupCommittedInodeByPath(L"\\alias"),
            "acceptance does not expose unpublished alias");
        Check(journal.Watermarks().accepted_sequence == accepted && journal.Watermarks().cleanup_sequence < accepted,
            "original accepted debt remains before publication");
        if (!cut.empty()) store.SetCommitStageHook([&](std::string_view stage) { return stage != cut; });
        const auto publication = store.PublishOrRecoverNativeHardLink(journal, error);
        std::cout << "PUBLICATION files=" << files << " cut=" << cut << " result=" << static_cast<int>(publication) << " detail=" << error << '\n' << std::flush;
        if (cut.empty()) {
            Check(publication == Store::HardLinkPublication::Published, "hard-link publication succeeds: " + error);
            Check(journal.Watermarks().cleanup_sequence == accepted, "clean publication settles original debt");
        } else {
            Check(publication == Store::HardLinkPublication::RecoveryRequired, "interrupted publication retains recovery: " + error);
            Check(journal.Watermarks().cleanup_sequence < accepted, "interrupted publication cannot mark cleaned");
        }
    }
    {
        std::string lease_error;
        auto lease = BlockDevice::OpenExclusiveManagementImage(context.device_path, 0, lease_error);
        Check(!!lease, "fresh exclusive hard-link image lease: " + lease_error);
        Store recovered(context, lease);
        Check(recovered.PrepareNativeWritePath(), "fresh owner opens hard-link image");
        std::cout << "REOPENED files=" << files << " cut=" << cut << '\n' << std::flush;
        Journal journal(L"Strict"); OpenJournal(journal, wal, fixture);
        if (!cut.empty()) {
            std::string error;
            const auto publication = recovered.PublishOrRecoverNativeHardLink(journal, error);
            const auto expected = cut == "before-apple-final-flush" ? Store::HardLinkPublication::AlreadyPublished :
                Store::HardLinkPublication::Published;
            Check(publication == expected, "fresh original owner recovers exact hard-link boundary: " + error);
        }
        const auto a = recovered.LookupCommittedInodeByPath(L"\\clone0");
        const auto b = recovered.LookupCommittedInodeByPath(L"\\alias");
        Check(a && b && a->object_id == 17 && b->object_id == 17 && a->link_count == 2 && b->link_count == 2,
            "both durable names share one inode with two links");
        std::vector<std::byte> bytes;
        Check(recovered.ReadCommittedFileRange(L"\\alias", 0, original.size(), bytes) && bytes == original,
            "alias payload remains byte-exact");
        if (files > 1) Check(recovered.ReadCommittedFileRange(L"\\clone1", 0, original.size(), bytes) && bytes == original,
            "independent clone peer is unchanged");
        Check(journal.Watermarks().accepted_sequence == accepted && journal.Watermarks().apfs_durable_sequence == accepted &&
            journal.Watermarks().cleanup_sequence == accepted, "fresh owner observes exact settled watermarks");
        Check(recovered.CheckpointXid() == fixture.checkpoint.container.superblock.next_xid, "recovery publishes exact planned transaction XID once");
    }
    std::cout << "PASS hard-link files=" << files << " cut=" << cut << '\n' << std::flush;
}
}

#ifndef NATIVE_HARD_LINK_TEST_HELPERS_ONLY
int main(int argc, char** argv) {
    try {
        const auto mode = argc > 2 ? std::string(argv[2]) : argc > 1 ? std::string(argv[1]) : std::string("all");
        if (argc > 1 && std::string(argv[1]).rfind("--", 0) != 0) {
            const auto root = std::filesystem::absolute(argv[1]);
            Check(root.wstring().substr(0, 3) == L"D:\\" && !std::filesystem::exists(root),
                "fresh explicit D: test root required");
            Check(std::filesystem::create_directories(root), "create fresh hard-link evidence root");
            std::filesystem::current_path(root);
        }
        if (std::filesystem::current_path().wstring().substr(0, 3) != L"D:\\")
            throw std::runtime_error("hard-link file tests require a fresh D: evidence directory");
        ProofCodec();
        if (mode != "--codec")
            for (unsigned files : {1u, 100u}) if (mode != "--large" || files == 100)
                for (const auto& cut : {std::string{}, std::string("before-apple-checkpoint-switch"),
                    std::string("before-apple-final-flush")}) AcceptanceRecovery(files, cut);
        if (mode != "--codec" && mode != "--large") RefusalCases();
        std::cout << "PASS hard-link acceptance " << checks << " checks\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << "\n";
        return 1;
    }
}
#endif
