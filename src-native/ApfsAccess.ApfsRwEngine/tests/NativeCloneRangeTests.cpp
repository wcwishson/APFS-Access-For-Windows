#define NATIVE_HARD_LINK_TEST_HELPERS_ONLY
#include "NativeHardLinkAcceptanceTests.cpp"
#include "NativeCloneRange.h"

namespace
{
BuilderStore RangeSpec(bool sparse = false)
{
    auto spec = CloneSpec(3); auto& volume = spec.volumes.front(); std::string error;
    volume.additional_file_system_allocated_blocks = 8;
    for (auto& record : volume.filesystem_records) {
        if (Type(record) == 8 && Id(record) == 18) PutU64LE(record.value, 8, 140);
        if (sparse && Type(record) == 3 && (Id(record) == 17 || Id(record) == 18)) {
            AppleInodeRecord inode; Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), error);
            inode.internal_flags |= kAppleInodeSparseFlag;
            AppleExtendedField field{kAppleInodeSparseBytesField, 0, std::vector<std::byte>(8)};
            if (Id(record) == 17) { PutU64LE(inode.extended_fields.front().data, 8, 3 * 4096); PutU64LE(field.data, 0, 4096); }
            inode.extended_fields.push_back(field); Check(EncodeAppleInodeRecord(inode, record, error), error);
        }
    }
    auto encode_extent = [&](std::uint64_t logical, std::uint64_t length, std::uint64_t physical) {
        apfsaccess::catalog::BtreeRecord record; Check(EncodeAppleFileExtentRecord({17, logical, length, physical, 0, 4096}, record, error), error);
        volume.filesystem_records.push_back(record);
    };
    if (sparse) {
        std::erase_if(volume.filesystem_records, [](const auto& r) { return Type(r) == 8 && Id(r) == 17; });
        encode_extent(0, 4096, 128); encode_extent(8192, 8192, 130);
    }
    volume.extentref_records.clear();
    const auto reference = [&](std::uint64_t at, std::uint64_t count, std::uint64_t owner, std::int32_t refs) {
        apfsaccess::catalog::BtreeRecord record; Check(EncodeApplePhysicalExtentRecord({at, count, kApplePhysicalExtentKindNew, owner, refs}, record, error), error);
        volume.extentref_records.push_back(record);
    };
    if (sparse) { reference(128, 1, 17, 2); reference(129, 1, 19, 1); reference(130, 2, 17, 2); }
    else reference(128, 4, 17, 2);
    reference(140, 4, 18, 1);
    for (unsigned n = 0; n < 4; ++n) spec.authoritative_seeded_main_blocks.push_back({140 + n, std::vector<std::byte>(4096, std::byte(0x91 + n))});
    return spec;
}
NativeCloneRangeRequest RangeRequest()
{ return {0, 4096, 8192, 123456789}; }
AppleVolumeTransactionPlan RangePlan(Fixture& fixture, const NativeCloneRangeRequest& request, NativeCloneRangeState& before)
{
    VectorRandomAccessSource source(fixture.image); AppleVolumeTransactionPlan plan; std::string error;
    const bool ok = PlanNativeCloneRangeTransaction(source, fixture.checkpoint, 101, 17, 18, request, before, plan, error);
    Check(ok, "typed range plan: " + error); return plan;
}
void CowOne(Fixture& fixture, std::uint64_t inode, std::uint64_t logical, std::byte value)
{
    AppleVolumeTransactionRequest request; request.volume_object_id = 101; std::string error;
    unsigned removed = 0;
    for (auto record : ReadTree(fixture)) {
        if (Type(record) != 8 || Id(record) != inode) { request.filesystem_records.push_back(std::move(record)); continue; }
        AppleFileExtentRecord extent; Check(DecodeAppleFileExtentRecord(record, 4096, extent, error), error);
        const auto end = extent.logical_address + extent.length_bytes;
        if (logical < extent.logical_address || logical >= end) { request.filesystem_records.push_back(std::move(record)); continue; }
        Check(extent.physical_block != 0, "COW replaces actual shared payload");
        request.released_data_blocks.push_back({extent.physical_block + (logical - extent.logical_address) / 4096, 1}); ++removed;
        const auto retain = [&](std::uint64_t lo, std::uint64_t hi) {
            if (lo == hi) return;
            auto part = extent; part.logical_address = lo; part.length_bytes = hi - lo;
            part.physical_block += (lo - extent.logical_address) / 4096;
            apfsaccess::catalog::BtreeRecord encoded; Check(EncodeAppleFileExtentRecord(part, encoded, error), error); request.filesystem_records.push_back(std::move(encoded));
        };
        retain(extent.logical_address, logical); retain(logical + 4096, end);
    }
    Check(removed == 1, "exactly one original range relinquished for COW");
    request.data_writes.push_back({inode, logical, 0, std::vector<std::byte>(4096, value)});
    const auto plan = PlanClone(fixture, request); Check(plan.payload_blocks.size() == 1, "post-range write allocates one private COW block");
    Publish(fixture, plan); CheckGraph(fixture);
}
void PlannerCases()
{
    Fixture fixture(RangeSpec()); const auto source = Payload(fixture, 17), peer = Payload(fixture, 19), target = Payload(fixture, 18);
    auto expected = target; std::copy_n(source.begin(), 8192, expected.begin() + 4096);
    NativeCloneRangeState before; const auto plan = RangePlan(fixture, RangeRequest(), before);
    Check(plan.payload_blocks.empty(), "range cloning allocates no payload and performs no byte-copy write");
    Check(NativeHardLinkWritesExcludePayload(plan.commit.publication, before.source.payload, 512), "every planned write excludes all original payload blocks");
    Check(Deferred(plan, 141) && Deferred(plan, 142) && !Deferred(plan, 140) && !Deferred(plan, 143) && !Deferred(plan, 128),
        "only exact zero-reference destination interval is deferred");
    Publish(fixture, plan); CheckGraph(fixture);
    Check(Payload(fixture, 17) == source && Payload(fixture, 19) == peer && Payload(fixture, 18) == expected,
        "different source/target offsets preserve source, clone peer and destination prefix/suffix");
    bool shared = false; std::string error;
    for (const auto& record : ReadTree(fixture, true)) {
        ApplePhysicalExtentRecord extent; Check(DecodeApplePhysicalExtentRecord(record, extent, error), error);
        if (extent.physical_block == 128) { Check(extent.block_count == 2 && extent.reference_count == 3, "two exact source blocks gain target references"); shared = true; }
    }
    Check(shared, "real shared physical-reference interval exists after publication");
    CowOne(fixture, 18, 4096, std::byte{0x33}); std::fill_n(expected.begin() + 4096, 4096, std::byte{0x33});
    Check(Payload(fixture, 17) == source && Payload(fixture, 19) == peer && Payload(fixture, 18) == expected, "target COW isolates both clone peers");
    CowOne(fixture, 17, 4096, std::byte{0x44}); auto changed_source = source; std::fill_n(changed_source.begin() + 4096, 4096, std::byte{0x44});
    Check(Payload(fixture, 17) == changed_source && Payload(fixture, 19) == peer && Payload(fixture, 18) == expected, "source COW preserves target and third inode");

    Fixture sparse(RangeSpec(true)); const auto sparse_source = Payload(sparse, 17), sparse_target = Payload(sparse, 18);
    auto sparse_expected = sparse_target; std::copy_n(sparse_source.begin(), 12288, sparse_expected.begin());
    NativeCloneRangeRequest operation{0, 0, 12288, 123456790}; const auto sparse_plan = RangePlan(sparse, operation, before);
    Publish(sparse, sparse_plan); CheckGraph(sparse);
    VectorRandomAccessSource sparse_input(sparse.image); NativeSparseState sparse_after;
    Check(ReadNativeSparseStateV2(sparse_input, sparse.checkpoint, 101, 18, sparse_after, error) && sparse_after.sparse && sparse_after.allocated == 12288,
        "sparse source holes replace target allocations with exact sparse-byte accounting");
    Check(Payload(sparse, 18) == sparse_expected && Payload(sparse, 17) == sparse_source, "sparse clone retains holes and exact source mapping");
    for (unsigned fault = 0; fault < 10; ++fault) {
        Fixture negative(RangeSpec()); VectorRandomAccessSource input(negative.image); auto bad = RangeRequest();
        std::uint64_t source_id = 17, target_id = 18;
        switch (fault) {
        case 0: bad.length = 0; break;
        case 1: bad.source_offset = 1; break;
        case 2: bad.target_offset = 1; break;
        case 3: bad.length = 4097; break;
        case 4: bad.length = 1ull << 32; break;
        case 5: bad.source_offset = UINT64_MAX; break;
        case 6: bad.source_offset = 12288; break;
        case 7: bad.target_offset = 12288; break;
        case 8: source_id = target_id; break;
        case 9: bad.timestamp_ns = 0; break;
        }
        AppleVolumeTransactionPlan refused; const auto original = negative.image;
        Check(!PlanNativeCloneRangeTransaction(input, negative.checkpoint, 101, source_id, target_id, bad, before, refused, error) &&
            refused.commit.publication.before_superblock_writes.empty() && negative.image == original, "bounded range/identity failure changes no image and publishes no plan");
    }
    std::cout << "PASS canonical range/refcount/sparse and bidirectional COW\n";
}
NativeCloneRangeOpenEntry Entry(const Store& store, const std::wstring& path)
{
    const auto inode = store.LookupCommittedInodeByPath(path);
    const auto link = store.LookupCommittedDirectoryLinkByPath(path);
    Check(inode && link, "actual committed open entry exists");
    return {inode->object_id, inode->xid, link->parent_object_id, link->sibling_id, link->entry_name_utf8};
}
Store::CloneRangeAcceptance AcceptRange(Store& store, Journal& journal, Store::CloneRangeReceipt& receipt, std::string& error)
{
    auto outcome = Store::CloneRangeAcceptance::Refused;
    const auto source = Entry(store, L"\\clone0"), target = Entry(store, L"\\clone1");
    const auto borrowed = store.WithNativeCloneRangeSession(source, target, [&](const auto& session, std::string& detail) {
        outcome = store.AcceptNativeCloneRange(journal, session, RangeRequest(), receipt, detail);
        return outcome == Store::CloneRangeAcceptance::Accepted;
    }, error);
    Check(borrowed == (outcome == Store::CloneRangeAcceptance::Accepted), "synchronous session outcome agrees with durable acceptance");
    return outcome;
}
void OriginalControls(const WriteAheadLog::Record& record)
{
    NativeCloneRangeProof proof, decoded;
    Check(DecodeNativeCloneRange(record.inline_payload, proof) && EncodeNativeCloneRange(proof) == record.inline_payload,
        "real original has one exact canonical bounded encoding");
    for (const auto size : {std::size_t{0}, std::size_t{1}, std::size_t{8}, std::size_t{16}, record.inline_payload.size() - 1})
        Check(!DecodeNativeCloneRange(std::span(record.inline_payload).first(size), decoded) && !decoded.volume_oid,
            "truncated original proof clears all output");
    auto bytes = record.inline_payload; bytes.push_back(std::byte{});
    Check(!DecodeNativeCloneRange(bytes, decoded), "trailing original bytes refuse");
    auto changed = proof; changed.preimages.push_back(changed.preimages.back());
    Check(EncodeNativeCloneRange(changed).empty(), "duplicate original physical evidence refuses");
    changed = proof; changed.preimages.front().physical_block = 1;
    Check(EncodeNativeCloneRange(changed).empty(), "block-zero original authority is mandatory");
    changed = proof; changed.preimages.resize(NativeCloneRangeMaxPreimages + 1);
    Check(EncodeNativeCloneRange(changed).empty(), "original physical evidence is bounded before encoding");
    for (unsigned fault = 0; fault < 10; ++fault) {
        auto bad = record;
        switch (fault) {
        case 0: bad.flags = 4; break;
        case 1: ++bad.logical_length; break;
        case 2: ++bad.payload_length; break;
        case 3: ++bad.parent_object_id; break;
        case 4: ++bad.object_id; break;
        case 5: bad.path_utf8 = bad.secondary_path_utf8; break;
        case 6: bad.secondary_path_utf8 = "\xc0\xaf"; break;
        case 7: bad.payload_spool_id = bad.sequence; break;
        case 8: bad.payload_sha256[0] ^= 1; break;
        case 9: bad.state = WriteAheadLog::RecordState::Accepted; break;
        }
        Check(!WriteAheadLog::NativeCloneRangeIsConsistent(bad) && WriteAheadLog::EncodeForTest(bad).empty(),
            "typed original identity/hash/UTF8/state fields refuse encoding");
    }
    for (unsigned mode = 0; mode < 3; ++mode) {
        const auto path = std::filesystem::absolute("range-admission-" + std::to_string(mode) + ".wal");
        Journal journal(L"Strict"); std::string error;
        Check(journal.OpenStartupJournal(path.wstring(), L"range-admission", error) && journal.MaterializeAbsentStartupJournal(error), "fresh original admission control");
        Journal::MutationIntent intent; intent.kind = Journal::MutationKind::CloneRange;
        intent.path.assign(record.path_utf8.begin(), record.path_utf8.end()); intent.secondary_path.assign(record.secondary_path_utf8.begin(), record.secondary_path_utf8.end());
        intent.object_id = record.object_id; intent.generation = record.parent_object_id; intent.length = intent.payload_length = record.payload_length;
        intent.inline_payload = record.inline_payload; intent.payload_checksum = record.payload_sha256;
        const auto prior = FileBytes(path);
        Check(journal.Begin() && journal.RecordMutation(intent) && !journal.FlushPreparedRecords() && FileBytes(path) == prior,
            "clone range proof cannot flush without its exact original acceptance boundary");
        if (mode == 2) { Journal::MutationIntent extra; extra.kind = Journal::MutationKind::CreateFile; extra.object_id = 999; extra.path = L"\\extra";
            Check(journal.RecordMutation(extra), "buffered mixed original control"); }
        Check(journal.Accept(proof.checkpoint + (mode == 0 ? 1 : 0)) == (mode == 1), "one complete original binds the exact preimage checkpoint");
        if (mode != 1) Check(FileBytes(path) == prior && !journal.Watermarks().accepted_sequence, "wrong preimage or mixed original refuses before append");
    }
}
void FileCase(const std::string& cut, unsigned fault = 0, bool misuse = false)
{
    Fixture fixture(RangeSpec()); auto expected = Payload(fixture, 18); const auto source = Payload(fixture, 17), peer = Payload(fixture, 19);
    std::copy_n(source.begin(), 8192, expected.begin() + 4096);
    const auto stem = std::string("range-") + (cut.empty() ? "clean" : cut) + "-" + std::to_string(fault);
    const auto image = std::filesystem::path(stem + ".apfs"), wal = std::filesystem::path(stem + ".wal");
    SaveImage(image, fixture.image); const auto context = HardLinkContext(image); std::uint64_t sequence = 0;
    {
        std::string error; auto device = BlockDevice::OpenExclusiveManagementImage(context.device_path, 0, error);
        Check(!!device, "actual range exclusive file lease"); Store store(context, device);
        Check(store.PrepareNativeWritePath(), "actual range ordinary owner opens"); Journal journal(L"Strict"); OpenJournal(journal, wal, fixture);
        const auto unchanged = ImageBytes(*device), journal_before = FileBytes(wal);
        auto stale = Entry(store, L"\\clone0"); ++stale.generation;
        Check(!store.WithNativeCloneRangeSession(stale, Entry(store, L"\\clone1"), [](const auto&, auto&) { return true; }, error) &&
            ImageBytes(*device) == unchanged && FileBytes(wal) == journal_before, "stale actual source open refuses before acceptance/image changes");
        if (misuse) {
            auto target = Entry(store, L"\\clone1"); ++target.sibling_id;
            Check(!store.WithNativeCloneRangeSession(Entry(store, L"\\clone0"), target, [](const auto&, auto&) { return true; }, error),
                "wrong actual target alias binding refuses before borrowing a session");
            Store foreign(context, device); Check(foreign.PrepareNativeWritePath(), "second model over same held source for owner-identity control");
            bool called = false;
            Check(!store.WithNativeCloneRangeSession(Entry(store, L"\\clone0"), Entry(store, L"\\clone1"), [&](const auto& session, auto& detail) {
                Store::CloneRangeReceipt refused; called = true;
                Check(foreign.AcceptNativeCloneRange(journal, session, RangeRequest(), refused, detail) == Store::CloneRangeAcceptance::Refused && !refused.sequence,
                    "foreign MetadataStore cannot consume another owner's opaque session"); return false;
            }, error) && called, "foreign session control entered actual owner callback");
            journal.SetJournalMaxBytesForTest(128); Store::CloneRangeReceipt refused;
            Check(AcceptRange(store, journal, refused, error) == Store::CloneRangeAcceptance::Refused && journal.CurrentState() == Journal::State::Idle &&
                ImageBytes(*device) == unchanged && FileBytes(wal) == journal_before && !journal.Watermarks().accepted_sequence,
                "exact proof plus marker capacity refuses before Begin, WAL append or image writes");
            journal.SetJournalMaxBytesForTest(64ull << 20);
        }
        Store::CloneRangeReceipt receipt;
        Check(AcceptRange(store, journal, receipt, error) == Store::CloneRangeAcceptance::Accepted, "actual original accepts typed range:" + error);
        sequence = receipt.sequence;
        Check(receipt.source_inode == 17 && receipt.target_inode == 18 && sequence && ImageBytes(*device) == unchanged,
            "acceptance binds both inodes and changes no target bytes");
        std::vector<Journal::AcceptedTransaction> batches;
        Check(journal.LoadAcceptedTransactionsSinceCleanup(batches, &error) && batches.size() == 1 && batches.front().mutations.size() == 1,
            "actual full original range evidence is readable");
        NativeCloneRangeProof proof;
        Check(DecodeNativeCloneRange(batches.front().mutations.front().inline_payload, proof), "actual bounded original proof decodes");
        if (cut.empty() && !fault && !misuse) OriginalControls(batches.front().mutations.front());
        if (fault == 3) {
            const auto identity = journal.ConfiguredVolumeIdentity(), enrolled = journal.EnrolledCanonicalJournalIdentity();
            auto read = WriteAheadLog::ReadAll(wal, Journal::WideToUtf8(identity));
            Check(read.status == WriteAheadLog::ReadStatus::Ok && read.records.size() == 2, "read actual accepted original to form self-consistent tamper control");
            proof.publication_sha[0] ^= 1; auto& row = read.records.front(); row.inline_payload = EncodeNativeCloneRange(proof);
            Check(!row.inline_payload.empty() && NativeHardLinkHash(row.inline_payload, row.payload_sha256), "changed original has valid typed framing and recalculated checksum");
            const auto wrong = std::filesystem::path(stem + "-wrong-original.wal"); std::ofstream output(wrong, std::ios::binary);
            for (const auto& entry : read.records) { const auto bytes = WriteAheadLog::EncodeForTest(entry); Check(!bytes.empty(), "CRC-valid changed original");
                output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size()); }
            output.close(); const auto damaged = FileBytes(wrong); journal.SetJournalPath(L""); Journal altered(L"Strict");
            Check(altered.OpenStartupJournal(std::filesystem::absolute(wrong).wstring(), identity, error) && altered.EnrollCanonicalJournalIdentity(enrolled),
                "framing-valid changed original opens for exact reconstruction control");
            Check(store.PublishOrRecoverNativeCloneRange(altered, error) == Store::CloneRangePublication::RecoveryRequired &&
                ImageBytes(*device) == unchanged && FileBytes(wrong) == damaged && !altered.Watermarks().cleanup_sequence,
                "complete original reconstruction rejects modified commitment without target writes or evidence repair");
        }
        if (fault == 4) {
            const auto guard = fixture.checkpoint.volumes.front().root_tree.physical_block;
            Check(std::any_of(proof.preimages.begin(), proof.preimages.end(), [&](const auto& pre) { return pre.physical_block == guard; }), "exact original contains old FS guard");
            std::vector<std::byte> changed; Check(device->ReadForVerification(guard * 4096, 4096, changed), "read held source guard");
            changed[0] ^= std::byte{1}; Check(device->Write(guard * 4096, changed) && device->Flush(), "persist actual private source guard corruption");
            const auto damaged = ImageBytes(*device), original = FileBytes(wal);
            Check(store.PublishOrRecoverNativeCloneRange(journal, error) == Store::CloneRangePublication::RecoveryRequired &&
                ImageBytes(*device) == damaged && FileBytes(wal) == original && !journal.Watermarks().cleanup_sequence,
                "changed original source guard refuses and preserves every byte plus accepted debt");
            std::cout << "PASS range source guard tamper refusal\n"; return;
        }
        if (fault == 3) { std::cout << "PASS range original body tamper refusal\n"; }
        else {
        if (fault == 1) journal.SetJournalFaultInjectionHook([](auto stage) { return stage == "durable-flush"; });
        if (!cut.empty()) store.SetCommitStageHook([&](auto stage) { return stage != cut; });
        const auto publication = store.PublishOrRecoverNativeCloneRange(journal, error);
        Check(publication == (cut.empty() && !fault ? Store::CloneRangePublication::Published : Store::CloneRangePublication::RecoveryRequired),
            "actual publication/cut result:" + error);
        if (fault == 1) Check(ImageBytes(*device) == unchanged, "original flush failure precedes every target write");
        if (fault == 2) {
            NativeCloneRangeState before; auto plan = RangePlan(fixture, RangeRequest(), before);
            const auto block = plan.commit.publication.before_superblock_writes.front().physical_block;
            std::vector<std::byte> bytes; Check(device->ReadForVerification(block * 4096, 4096, bytes), "read actual pre-switch destination");
            std::fill_n(bytes.begin(), 73, std::byte{0x87});
            Check(device->Write(block * 4096, bytes) && device->Flush(), "persist short torn private COW destination before checkpoint switch");
        }
        if (!cut.empty() || fault) Check(journal.Watermarks().cleanup_sequence < sequence, "cut cannot claim settled original");
        }
    }
    {
        std::string error; auto device = BlockDevice::OpenExclusiveManagementImage(context.device_path, 0, error);
        Check(!!device, "fresh exclusive range owner"); Store recovered(context, device);
        Check(recovered.PrepareNativeWritePath(), "fresh range owner loads actual canonical selection"); Journal journal(L"Strict"); OpenJournal(journal, wal, fixture);
        if (!cut.empty() || fault) {
            const auto outcome = recovered.PublishOrRecoverNativeCloneRange(journal, error);
            Check(outcome == (cut == "before-apple-final-flush" || cut == "before-native-clone-range-cleaned" ?
                Store::CloneRangePublication::AlreadyPublished : Store::CloneRangePublication::Published), "fresh full original range recovery:" + error);
        }
        std::vector<std::byte> bytes;
        Check(recovered.ReadCommittedFileRange(L"\\clone0", 0, source.size(), bytes) && bytes == source, "fresh range source data exact");
        Check(recovered.ReadCommittedFileRange(L"\\clone1", 0, expected.size(), bytes) && bytes == expected, "fresh range destination prefix/shared/suffix exact");
        Check(recovered.ReadCommittedFileRange(L"\\clone2", 0, peer.size(), bytes) && bytes == peer, "fresh range third clone peer exact");
        const auto marks = journal.Watermarks();
        Check(marks.accepted_sequence == sequence && marks.apfs_durable_sequence == sequence && marks.cleanup_sequence == sequence, "actual original settles exact accepted/durable/cleaned boundary");
    }
    std::cout << "PASS range original/cut=" << cut << " fault=" << fault << '\n' << std::flush;
}
}
int main(int argc, char** argv)
{
    try {
        Check(argc == 2 || (argc == 3 && std::string_view(argv[2]) == "--misuse"), "fresh absolute fixed D evidence root required"); const auto root = std::filesystem::path(argv[1]);
        Check(root.is_absolute() && root.wstring().starts_with(L"D:\\") && !std::filesystem::exists(root), "fresh D root required");
        for (auto at = root.parent_path(); !at.empty();) {
            const auto attributes = GetFileAttributesW(at.c_str());
            Check(attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() == ERROR_PATH_NOT_FOUND || GetLastError() == ERROR_FILE_NOT_FOUND :
                (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0, "no reparse path escape");
            const auto parent = at.parent_path(); if (parent == at) break; at = parent;
        }
        Check(std::filesystem::create_directories(root), "create fresh private range evidence"); std::filesystem::current_path(root);
        if (argc == 3) { FileCase("", 0, true); FileCase("", 3); FileCase("", 4); }
        else {
            PlannerCases(); SharedCowCases(); UnlinkAndTruncateCases();
            FileCase(""); FileCase("before-apple-checkpoint-switch"); FileCase("before-apple-final-flush");
            FileCase("before-native-clone-range-cleaned"); FileCase("", 1); FileCase("before-apple-checkpoint-switch", 2);
        }
        std::cout << "PASS native clone-range " << checks << " checks\n"; return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL native clone-range: " << error.what() << '\n'; return 1; }
}
