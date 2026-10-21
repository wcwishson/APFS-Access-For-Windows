#pragma once

// Include after the canonical mount-context fixtures in FsHostSemanticsTests.cpp.
namespace RetainedGenerationPressureTests
{
using Store = apfsaccess::rw::MetadataStore;
using Tx = apfsaccess::rw::TransactionManager;
using Spool = apfsaccess::rw::PayloadSpool;
using Wal = apfsaccess::rw::WriteAheadLog;
constexpr std::uint64_t Block = 4096;

struct Batch
{
    std::wstring path;
    std::vector<std::byte> payload;
    Store::PayloadIdentity identity;
    Spool::AppendResult reference;
    std::uint64_t preimage = 0, accepted = 0;
};

bool Accept(MountContext& c, Batch& batch, bool create)
{
    batch.preimage = c.metadata_store->CheckpointXid().value_or(0);
    if (!Require(c.tx_manager->Begin(), "W09 begin accepted batch")) return false;
    Tx::MutationIntent intent;
    intent.path = batch.path;
    Store::MutationRequest request;
    request.path = batch.path;
    if (create)
    {
        request.operation = Store::MutationOperation::CreateFile;
        const auto status = c.metadata_store->StageMutation(request, &batch.identity);
        if (!Require(status == Store::MutationStatus::Applied, "W09 stage new file")) return false;
        intent.kind = Tx::MutationKind::CreateFile;
        intent.object_id = batch.identity.object_id; intent.generation = batch.identity.generation;
        if (!Require(c.tx_manager->RecordMutation(intent), "W09 record new file")) return false;
    }
    request.operation = Store::MutationOperation::Write; request.length = batch.payload.size();
    if (!Require(c.metadata_store->StageMutation(request, &batch.identity) == Store::MutationStatus::Applied,
            "W09 stage payload write")) return false;
    intent.kind = Tx::MutationKind::Write;
    intent.object_id = batch.identity.object_id; intent.generation = batch.identity.generation;
    intent.wal_sequence = c.tx_manager->NextMutationSequence();
    if (!c.payload_spool->Append({c.payload_spool_volume_identity, intent.object_id, intent.generation,
            0, intent.wal_sequence, batch.payload}, &batch.reference)) return Require(false, "W09 append original spool");
    intent.length = intent.payload_length = batch.reference.payload_length;
    intent.payload_spool_offset = batch.reference.spool_offset;
    intent.payload_checksum = batch.reference.payload_sha256;
    c.pending_native_writes = true;
    if (!Require(c.tx_manager->RecordMutation(intent), "W09 record payload reference") ||
        !Require(c.payload_spool->FlushDirtyState(), "W09 make original spool durable") ||
        !Require(AcceptMutationJournalForDeferredCommitBestEffort(&c, L"W09PressureAccept", &batch.accepted),
            "W09 accept original source checkpoint")) return false;
    return true;
}

bool CheckReference(MountContext& c, const Batch& batch)
{
    Spool::PersistedRangeReference reference{c.payload_spool_volume_identity,
        batch.identity.object_id, batch.identity.generation, 0, batch.reference.payload_length,
        batch.reference.spool_offset, batch.reference.wal_sequence, batch.reference.payload_sha256};
    std::vector<std::byte> bytes;
    std::vector<Tx::AcceptedTransaction> transactions;
    if (!c.tx_manager->LoadAcceptedTransactionsSinceCleanup(transactions)) return false;
    const auto transaction = std::find_if(transactions.begin(), transactions.end(), [&](const auto& tx) {
        return tx.accepted_sequence == batch.accepted;
    });
    if (transaction == transactions.end()) return false;
    const auto write = std::find_if(transaction->mutations.begin(), transaction->mutations.end(), [](const auto& m) {
        return m.operation == Wal::OperationKind::Write;
    });
    return Require(transaction->preimage_checkpoint_xid == batch.preimage && write != transaction->mutations.end() &&
        write->object_id == reference.object_id && write->parent_object_id == reference.generation &&
        write->sequence == reference.wal_sequence && write->payload_offset == reference.spool_offset &&
        write->payload_length == reference.payload_length && write->payload_sha256 == reference.payload_sha256 &&
        write->inline_payload.empty() && c.payload_spool->ReadPersistedRange(reference, bytes) && bytes == batch.payload,
        "W09 original WAL generation, sequence, immutable spool offset and SHA256 remain exact");
}

bool CheckFile(Store& store, const Batch& batch)
{
    const auto inode = store.LookupCommittedInodeByPath(batch.path);
    std::vector<std::byte> bytes;
    return Require(inode && inode->object_id == batch.identity.object_id &&
        inode->private_id == batch.identity.object_id &&
        inode->logical_size == batch.payload.size() &&
        store.ReadCommittedFileRange(batch.path, 0, batch.payload.size() + 1, bytes) && bytes == batch.payload,
        "W09 canonical payload, EOF and inode identity match the accepted batch");
}

bool CheckHistory(const std::filesystem::path& image, const std::vector<std::byte>& original,
    std::uint64_t preimage, bool capture, std::vector<std::uint64_t>& protected_blocks)
{
    using namespace apfsaccess::catalog;
    using namespace apfsaccess::rw;
    HeldFileSource source(image.string());
    std::string error;
    const auto current = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    std::vector<AppleRecoveryCheckpointView> history;
    if (!Require(current && LoadAppleRecoveryCheckpoints(source, *current, {preimage}, history, error) && !history.empty(),
            ("W09 authoritative retained ownership and queue continuity: " + error).c_str())) return false;
    const auto old = std::find_if(history.begin(), history.end(), [&](const auto& h) {
        return h.checkpoint.container.superblock.xid == preimage;
    });
    if (!Require(old != history.end() && !old->payload_extents.empty(),
            "W09 historical payload ownership is nonempty")) return false;
    if (capture)
    {
        protected_blocks = old->metadata_blocks;
        for (const auto& extent : old->payload_extents)
            for (std::uint64_t i = 0; i < extent.block_count; ++i) protected_blocks.push_back(extent.physical_block + i);
    }
    for (const auto block : protected_blocks)
    {
        std::vector<std::byte> bytes;
        if (!Require(block < original.size() / Block && source.Read(block * Block, Block, bytes) &&
                std::equal(bytes.begin(), bytes.end(), original.begin() + block * Block),
                "W09 all retained metadata and payload blocks remain byte-identical")) return false;
    }
    return true;
}

bool Reopen(DirectorySymlinkFixture& fixture, bool exclusive, HANDLE& borrowed_source)
{
    auto& old = *fixture.context;
    const auto args = old.args;
    const auto root = old.session_root;
    const auto cache = old.cache_root;
    StopDeferredCommitWorker(&old);
    fixture.context.reset();
    fixture.context = std::make_unique<MountContext>();
    auto& c = *fixture.context;
    c.args = args; c.native_write_enabled = true;
    c.session_root = root; c.cache_root = cache; c.recovery_marker_file = root / "recovery.marker";
    borrowed_source = INVALID_HANDLE_VALUE;
    if (exclusive)
    {
        // Ownership transfers to BlockDevice. The borrowed value is used only
        // for an actual post-bootstrap fault, without a third duplicate handle.
        const auto handle = CreateFileW(fixture.image.path.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (!Require(handle != INVALID_HANDLE_VALUE, "W09 sole-owner image opens before metadata bootstrap")) return false;
        std::string error;
        auto device = apfsaccess::rw::BlockDevice::AdoptExclusiveRepairImage(fixture.image.path.wstring(), handle, error);
        if (!Require(device && device->CaptureExclusiveWriteSourceObservation().has_value(),
                "W09 real sole-owner handle pair qualifies without extra handles")) return false;
        borrowed_source = handle;
        c.owned_metadata_store = std::make_unique<Store>(fixture.volume, std::move(device));
    }
    else c.owned_metadata_store = std::make_unique<Store>(fixture.volume);
    c.metadata_store = c.owned_metadata_store.get();
    c.tx_manager = std::make_unique<Tx>(L"Conservative");
    c.tx_journal_file = root / "accepted.wal";
    std::string journal_error;
    if (!Require(c.tx_manager->OpenStartupJournal(c.tx_journal_file.wstring(),
            L"directory-symlink-volume", journal_error),
            ("W09 original startup journal preserves evidence: " + journal_error).c_str())) return false;
    c.payload_spool_volume_identity = "directory-symlink-volume";
    c.payload_spool = std::make_unique<Spool>(Spool::Options{
        root / "payload-spool", c.payload_spool_volume_identity, 1024 * 1024});
    c.metadata_store->SetFilePayloadProvider([&c](const auto& path, auto size) {
        return LoadHydratedPayloadForPath(&c, path, size, false);
    });
    c.metadata_store->SetFilePayloadRangeProvider([&c](const auto& path, auto identity, auto offset, auto destination) {
        return ReadHydratedPayloadRangeForPath(&c, path, identity, offset, destination);
    });
    return c.metadata_store->PrepareNativeWritePath();
}

// Dedicated private runner entry point; no FsHost process or mounted volume.
bool RunGeneralized(const std::string& fault = {}, bool partial_tail = false)
{
    using Operation = Store::MutationOperation;
    using Patch = apfsaccess::rw::InodeMetadataPatch;
    DirectorySymlinkFixture fixture(false);
    auto spec = TwoProjectableVolumeStore();
    spec.volumes.resize(1); spec.authoritative_checkpoint = true; spec.dual_checkpoint = false; spec.xid = 20;
    spec.block_count = 512; spec.authoritative_checkpoint_ring_blocks = 32;
    spec.authoritative_internal_pool_blocks = 64; spec.authoritative_main_free_blocks = 180;
    if (!Require(WriteFileBytes(fixture.image.path, apfsaccess::testfixture::BuildStoreImage(spec)) &&
            fixture.Initialize(false), "W09 mixed canonical ordinary image initializes")) return false;
    auto& c = *fixture.context;
    c.args.write_require_canonical_commit = true; c.args.write_max_dirty_transactions = 64;
    std::map<std::uint64_t, std::vector<std::byte>> contents;
    c.metadata_store->SetFilePayloadRangeProvider([&](const auto& path, auto identity, auto offset, auto destination) {
        const auto inode = c.metadata_store->LookupWorkingInodeByPath(path);
        const auto found = contents.find(identity.object_id);
        if (!inode || inode->object_id != identity.object_id || inode->xid != identity.generation ||
            found == contents.end() || offset > found->second.size() || destination.size() > found->second.size() - offset) return false;
        std::copy_n(found->second.begin() + offset, destination.size(), destination.begin());
        return true;
    });
    Batch bystander{L"\\bystander", BuildPatternPayloadForTest(3 * Block + 17, 0x35)};
    Batch target{L"\\target", BuildPatternPayloadForTest(3 * Block + 29, 0x57)};
    for (auto* seed : {&bystander, &target})
    {
        if (!Accept(c, *seed, true)) return false;
        contents[seed->identity.object_id] = seed->payload;
        if (!Require(NT_SUCCESS(CommitNativeMutationsBestEffort(&c, L"W09MixedSeed")) &&
                FinalizeMutationJournalBestEffort(&c, L"W09MixedSeed"), "W09 mixed seeds publish and clean")) return false;
    }
    const auto original = ReadFileBytes(fixture.image.path);
    const auto source_xid = c.metadata_store->CheckpointXid().value_or(0);
    auto old_snapshot = std::make_unique<Store>(fixture.volume);
    if (!Require(old_snapshot->PrepareNativeWritePath(), "W09 mixed old checkpoint reader captures original view")) return false;
    std::vector<std::uint64_t> protected_blocks, accepted;
    std::vector<std::vector<std::byte>> original_journal_prefixes;
    Spool::AppendResult tail_reference;
    Store::PayloadIdentity tail_identity;
    unsigned batch_index = 0;
    const auto stage = [&](Store::MutationRequest request, const std::vector<std::byte>& payload = {}) {
        Store::PayloadIdentity identity;
        std::optional<apfsaccess::rw::UnlinkOutcome> unlink;
        const auto status = c.metadata_store->StageMutation(request, &identity, &unlink);
        if (!Require(status == Store::MutationStatus::Applied, "W09 mixed original mutation stages")) return false;
        const auto kind = ManifestJournalKindForOperation(request.operation);
        if (!kind) return false;
        Tx::MutationIntent intent;
        intent.kind = *kind; intent.path = request.path; intent.secondary_path = request.secondary_path;
        intent.offset = request.offset; intent.length = request.length; intent.timestamp_utc = request.timestamp_utc;
        intent.replace_if_exists = request.replace_if_exists;
        intent.object_id = identity.object_id; intent.generation = identity.generation;
        intent.unlink_outcome = unlink;
        if (request.operation == Operation::CreateFile) contents[identity.object_id].clear();
        if (request.operation == Operation::Write || request.operation == Operation::SetFileSize)
        {
            const auto inode = c.metadata_store->LookupWorkingInodeByPath(request.path);
            if (!inode) return false;
            auto& expected = contents.at(identity.object_id);
            expected.resize(static_cast<std::size_t>(inode->logical_size), std::byte{0});
            if (request.operation == Operation::Write)
            {
                if (payload.size() != request.length) return false;
                std::copy(payload.begin(), payload.end(), expected.begin() + request.offset);
                intent.wal_sequence = c.tx_manager->NextMutationSequence();
                Spool::AppendResult reference;
                if (!c.payload_spool->Append({c.payload_spool_volume_identity, identity.object_id, identity.generation,
                        request.offset, intent.wal_sequence, payload}, &reference)) return false;
                intent.payload_spool_offset = reference.spool_offset; intent.payload_length = reference.payload_length;
                intent.payload_checksum = reference.payload_sha256;
                if (batch_index == 3) { tail_reference = reference; tail_identity = identity; }
            }
        }
        if (request.operation == Operation::SetInodeMetadata)
        {
            c.pending_native_writes = true;
            return Require(RecordMutationBestEffort(&c, *kind, request.path, L"", 0,
                request.length, false, 0, 0, &identity, nullptr, request.inline_payload),
                "W09 mixed metadata uses the production checksum-bound WAL recording helper");
        }
        if (fault == "misbound-metadata" && batch_index == 0 && request.operation == Operation::SetBasicInfo)
            intent.object_id = bystander.identity.object_id;
        if (fault == "misbound-unlink" && batch_index == 1 && unlink)
            ++intent.unlink_outcome->parent_object_id;
        c.pending_native_writes = true;
        return Require(c.tx_manager->RecordMutation(intent), "W09 mixed original WAL records mutation and immutable payload reference");
    };
    const auto request = [](Operation op, const std::wstring& path, std::uint64_t length = 0,
            std::uint64_t offset = 0, const std::wstring& secondary = L"") {
        Store::MutationRequest value;
        value.operation = op; value.path = path; value.length = length; value.offset = offset; value.secondary_path = secondary;
        return value;
    };
    const auto timestamp = [&](const std::wstring& path, std::uint64_t value) {
        auto change = request(Operation::SetBasicInfo, path); change.timestamp_utc = value;
        return stage(change);
    };
    const auto metadata = [&](const std::wstring& path, std::uint64_t time) {
        Patch patch;
        patch.mask = Patch::Owner | Patch::Group | Patch::Mode | Patch::CreateTime |
            Patch::ModificationTime | Patch::ChangeTime | Patch::AccessTime;
        patch.owner = 501; patch.group = 20; patch.mode = 0640;
        patch.create_time_utc = time; patch.modification_time_utc = time + 1;
        patch.change_time_utc = time + 2; patch.access_time_utc = time + 3;
        auto change = request(Operation::SetInodeMetadata, path);
        if (!apfsaccess::rw::EncodeInodeMetadataPatch(patch, change.inline_payload)) return false;
        change.length = change.inline_payload.size();
        return stage(change);
    };
    const auto accept = [&]() {
        std::uint64_t sequence = 0;
        if (!c.payload_spool->FlushDirtyState() ||
            !AcceptMutationJournalForDeferredCommitBestEffort(&c, L"W09MixedAccept", &sequence)) return false;
        accepted.push_back(sequence);
        original_journal_prefixes.push_back(ReadFileBytes(c.session_root / "accepted.wal"));
        return true;
    };
    const auto publish = [&]() {
        const auto status = CommitNativeMutationsBestEffort(&c, L"W09MixedPublish");
        std::fwprintf(stderr, L"[W09-mixed] batch=%u status=%lx xid=%llu detail=%ls\n", batch_index,
            static_cast<unsigned long>(status), c.metadata_store->CheckpointXid().value_or(0),
            c.metadata_store->LastCommitFailureDetail().c_str());
        return Require(NT_SUCCESS(status), "W09 mixed accepted batch publishes without a durability receipt") &&
            CheckHistory(fixture.image.path, original, source_xid, protected_blocks.empty(), protected_blocks) &&
            CheckFile(*old_snapshot, target) && CheckFile(*old_snapshot, bystander) && CheckFile(*c.metadata_store, bystander);
    };
    if (!c.tx_manager->Begin() ||
        !stage(request(Operation::Write, target.path, 37, Block - 6), BuildPatternPayloadForTest(37, 0xa1)) ||
        !stage(request(Operation::Write, target.path, 11, Block + 4), BuildPatternPayloadForTest(11, 0xb2)) ||
        !timestamp(target.path, 133700000000000111ULL) ||
        !stage(request(Operation::CreateDirectory, L"\\work")) ||
        !stage(request(Operation::CreateFile, L"\\work\\new")) ||
        !stage(request(Operation::Write, L"\\work\\new", 207), BuildPatternPayloadForTest(207, 0xc3)) ||
        !metadata(L"\\work\\new", 133700000000000222ULL) ||
        !stage(request(Operation::Rename, target.path, 0, 0, L"\\work\\moved")) || !accept()) return false;
    if (fault == "unlogged-metadata")
    {
        auto extra = request(Operation::SetBasicInfo, L"\\work\\moved"); extra.timestamp_utc = 133700000000009999ULL;
        if (c.metadata_store->StageMutation(extra) != Store::MutationStatus::Applied) return false;
    }
    if (fault == "unlogged-payload") contents.at(target.identity.object_id).at(Block + 20) ^= std::byte{1};
    if (!publish()) return false;
    ++batch_index;
    if (!c.tx_manager->Begin() ||
        !stage(request(Operation::SetFileSize, L"\\work\\moved", Block + 3)) ||
        !stage(request(Operation::SetFileSize, L"\\work\\moved", 2 * Block + 37)) ||
        !stage(request(Operation::Write, L"\\work\\moved", 19, 2 * Block + 42), BuildPatternPayloadForTest(19, 0xd4)) ||
        !timestamp(L"\\work\\moved", 133700000000000333ULL) ||
        !stage(request(Operation::Delete, L"\\work\\new")) ||
        !stage(request(Operation::CreateFile, L"\\spare")) ||
        !stage(request(Operation::CreateDirectory, L"\\vacant")) ||
        !stage(request(Operation::CreateFile, L"\\final")) ||
        !stage(request(Operation::Write, L"\\final", 9), BuildPatternPayloadForTest(9, 0xf6)) || !accept() || !publish()) return false;
    const auto& resized = contents.at(target.identity.object_id);
    if (!Require(resized.size() == 2 * Block + 61 &&
            std::all_of(resized.begin() + Block + 3, resized.begin() + 2 * Block + 42,
                [](auto byte) { return byte == std::byte{0}; }),
            "W09 shrink then extension erases old tail and zeroes the write gap")) return false;
    ++batch_index;
    auto replacement = request(Operation::Rename, L"\\archive\\moved", 0, 0, L"\\final");
    replacement.replace_if_exists = true;
    if (!c.tx_manager->Begin() ||
        !stage(request(Operation::Rename, L"\\work", 0, 0, L"\\archive")) ||
        !stage(replacement) ||
        !stage(request(Operation::Delete, L"\\spare")) || !stage(request(Operation::Delete, L"\\vacant")) ||
        !metadata(L"\\final", 133700000000000444ULL) || !accept() || !publish()) return false;
    ++batch_index;
    auto tail = partial_tail ? resized : BuildPatternPayloadForTest(resized.size(), 0xe5);
    const auto fragment = BuildPatternPayloadForTest(43, 0xe5);
    const auto tail_offset = partial_tail ? Block - 7 : 0;
    if (partial_tail) std::copy(fragment.begin(), fragment.end(), tail.begin() + tail_offset);
    const auto& tail_write = partial_tail ? fragment : tail;
    if (!c.tx_manager->Begin() || !stage(request(Operation::Write, L"\\final", tail_write.size(), tail_offset), tail_write) ||
        !timestamp(L"\\final", 133700000000000555ULL) || !accept()) return false;

    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    const auto spool = ReadFileBytes(c.payload_spool->SpoolFilePath());
    for (const auto& prefix : original_journal_prefixes)
        if (!Require(prefix.size() <= wal.size() && std::equal(prefix.begin(), prefix.end(), wal.begin()),
                "W09 every accepted original WAL prefix remains byte-identical")) return false;
    std::filesystem::path evidence;
    if (const auto* destination = std::getenv("APFSACCESS_W09_EVIDENCE"))
    {
        evidence = std::filesystem::path(destination) /
            (fault.empty() ? partial_tail ? "mixed-partial-tail-positive" : "mixed-positive" : "mixed-" + fault);
        if (!WriteFileBytes(evidence / "original.img", original) ||
            !WriteFileBytes(evidence / "published.img", ReadFileBytes(fixture.image.path)) ||
            !WriteFileBytes(evidence / "accepted.wal", wal) || !WriteFileBytes(evidence / "payload-spool.bin", spool) ||
            !WriteFileBytes(evidence / "payload-spool.idx", ReadFileBytes(c.session_root / "payload-spool" / "payload-spool.idx")) ||
            !WriteFileBytes(evidence / "final-expected.bin", tail) ||
            !WriteFileBytes(evidence / "bystander-expected.bin", bystander.payload)) return false;
    }
    old_snapshot.reset();
    HANDLE borrowed = INVALID_HANDLE_VALUE;
    if (!Reopen(fixture, true, borrowed)) return false;
    auto& r = *fixture.context;
    const auto image_bytes = [&]() {
        std::vector<std::byte> bytes;
        if (!r.metadata_store->Device().ReadForVerification(0,
                static_cast<std::size_t>(spec.block_count * Block), bytes)) bytes.clear();
        return bytes;
    };
    if (fault == "corrupt-tail")
    {
        r.payload_spool.reset();
        auto corrupted = spool;
        corrupted.at(static_cast<std::size_t>(tail_reference.spool_offset)) ^= std::byte{1};
        if (!WriteFileBytes(r.session_root / "payload-spool" / "payload-spool.bin", corrupted)) return false;
        r.payload_spool = std::make_unique<Spool>(Spool::Options{
            r.session_root / "payload-spool", r.payload_spool_volume_identity, 1024 * 1024});
    }
    const auto before = image_bytes();
    const auto spool_before = ReadFileBytes(r.payload_spool->SpoolFilePath());
    const auto index = ReadFileBytes(r.session_root / "payload-spool" / "payload-spool.idx");
    const auto marks = r.tx_manager->Watermarks();
    std::vector<std::uint64_t> sequences{UINT64_MAX};
    std::string error;
    const bool proven = r.metadata_store->ProveRetainedAcceptedPrefix(*r.tx_manager, *r.payload_spool,
        r.tx_journal_file, r.payload_spool_volume_identity, sequences, error);
    std::fprintf(stderr, "[W09-mixed] fault=%s proof=%d sequences=%zu error=%s\n", fault.c_str(), proven, sequences.size(), error.c_str());
    if (!Require(!before.empty() && before == image_bytes() && wal == ReadFileBytes(r.tx_journal_file) &&
            spool_before == ReadFileBytes(r.payload_spool->SpoolFilePath()) &&
            index == ReadFileBytes(r.session_root / "payload-spool" / "payload-spool.idx") &&
            marks.accepted_sequence == r.tx_manager->Watermarks().accepted_sequence &&
            marks.apfs_durable_sequence == r.tx_manager->Watermarks().apfs_durable_sequence &&
            marks.cleanup_sequence == r.tx_manager->Watermarks().cleanup_sequence && CheckFile(*r.metadata_store, bystander),
            "W09 mixed proof preserves exact complete image, original WAL/spool/index and every watermark")) return false;
    if (!evidence.empty() && (!WriteFileBytes(evidence / "after-proof.img", image_bytes()) ||
            !WriteFileBytes(evidence / "after-proof.wal", ReadFileBytes(r.tx_journal_file)) ||
            !WriteFileBytes(evidence / "after-proof-spool.bin", ReadFileBytes(r.payload_spool->SpoolFilePath())))) return false;
    if (!fault.empty())
    {
        const auto expected = fault == "corrupt-tail" ? "RetainedAcceptedOriginalPayloadInvalid" :
            fault == "misbound-metadata" || fault == "misbound-unlink" ? "RetainedAcceptedOriginalStageMismatch" :
            "RetainedAcceptedPublicationReadbackMismatch";
        if (!Require(!proven && sequences.empty() && error == expected,
                "W09 mixed corrupt, misbound and unlogged semantics cannot certify even a valid earlier prefix")) return false;
        unsigned publications = 0;
        r.metadata_store->SetCommitStageHook([&](std::string_view stage_name) {
            if (stage_name == "before-apple-publish") ++publications;
            return true;
        });
        const auto replayed = ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(r);
        if (!Require(!replayed && publications == 0 && !r.runtime_recovery_reason.empty() &&
                before == image_bytes() && wal == ReadFileBytes(r.tx_journal_file) &&
                spool_before == ReadFileBytes(r.payload_spool->SpoolFilePath()) &&
                index == ReadFileBytes(r.session_root / "payload-spool" / "payload-spool.idx") &&
                marks.accepted_sequence == r.tx_manager->Watermarks().accepted_sequence &&
                marks.apfs_durable_sequence == r.tx_manager->Watermarks().apfs_durable_sequence &&
                marks.cleanup_sequence == r.tx_manager->Watermarks().cleanup_sequence,
                "W09 mixed startup refuses the original invalid batch without publication or evidence retirement")) return false;
        if (!evidence.empty() && (!WriteFileBytes(evidence / "after-refused-replay.img", image_bytes()) ||
                !WriteFileBytes(evidence / "after-refused-replay.wal", ReadFileBytes(r.tx_journal_file)) ||
                !WriteFileBytes(evidence / "after-refused-replay-spool.bin", ReadFileBytes(r.payload_spool->SpoolFilePath())))) return false;
        return true;
    }
    const std::vector<std::uint64_t> expected(accepted.begin(), accepted.end() - 1);
    if (!Require(proven && sequences == expected && expected.size() == 3,
            "W09 mixed full publication-byte proof certifies exactly three original accepted checkpoints")) return false;
    unsigned publications = 0;
    r.metadata_store->SetCommitStageHook([&](std::string_view stage_name) {
        if (stage_name == "before-apple-publish") ++publications;
        return true;
    });
    const auto replayed = ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(r);
    std::fwprintf(stderr, L"[W09-mixed] replay=%d publications=%u reason=%ls\n", replayed, publications, r.runtime_recovery_reason.c_str());
    Batch final{L"\\final", tail, tail_identity};
    const auto final_inode = r.metadata_store->LookupCommittedInodeByPath(final.path);
    if (!Require(replayed && publications == 1 && r.tx_manager->Watermarks().accepted_sequence == accepted.back() &&
            r.tx_manager->Watermarks().apfs_durable_sequence == accepted.back() &&
            r.tx_manager->Watermarks().cleanup_sequence == accepted.back() && final_inode &&
            final_inode->modification_time_utc == 133700000000000555ULL && final_inode->owner == 501 &&
            final_inode->group == 20 && (final_inode->mode & 07777) == 0640 &&
            !r.metadata_store->LookupCommittedInodeByPath(L"\\spare") &&
            !r.metadata_store->LookupCommittedInodeByPath(L"\\vacant") &&
            !r.metadata_store->LookupCommittedInodeByPath(L"\\archive\\new") &&
            r.metadata_store->LookupCommittedInodeByPath(L"\\archive"),
            "W09 mixed recovery marks only the proven prefix then publishes the original tail once") ||
        !CheckFile(*r.metadata_store, final) || !CheckFile(*r.metadata_store, bystander)) return false;
    const auto stable = image_bytes();
    if (!Require(ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(r) && publications == 1 && stable == image_bytes(),
            "W09 mixed repeated recovery performs no publication or image change")) return false;
    if (!evidence.empty() && (!WriteFileBytes(evidence / "recovered.img", stable) ||
            !WriteFileBytes(evidence / "recovered.wal", ReadFileBytes(r.tx_journal_file)))) return false;
    r.owned_metadata_store.reset(); r.metadata_store = nullptr;
    Store fresh(fixture.volume);
    return Require(fresh.PrepareNativeWritePath(), "W09 mixed independent canonical reopen") &&
        CheckFile(fresh, final) && CheckFile(fresh, bystander);
}

bool Run(bool corrupt_spool = false, bool missing_receipt = false, unsigned history_fault = 0,
    bool unrecorded_timestamp = false, bool mutable_source = false)
{
    DirectorySymlinkFixture fixture(false);
    auto spec = TwoProjectableVolumeStore();
    spec.volumes.resize(1); spec.authoritative_checkpoint = true; spec.dual_checkpoint = false; spec.xid = 20;
    spec.block_count = 256; spec.authoritative_checkpoint_ring_blocks = 16;
    spec.authoritative_internal_pool_blocks = 32; spec.authoritative_main_free_blocks = 80;
    if (!Require(WriteFileBytes(fixture.image.path, apfsaccess::testfixture::BuildStoreImage(spec)) &&
            fixture.Initialize(false), "W09 canonical low-space mount context initializes")) return false;
    auto& c = *fixture.context;
    c.args.write_require_canonical_commit = true;
    c.args.write_max_dirty_transactions = 64;
    c.metadata_store->SetFilePayloadRangeProvider([&c](const auto&, auto identity, auto offset, auto destination) {
        std::size_t covered = 0;
        return c.payload_spool->ReadFullyCoveredRange({c.payload_spool_volume_identity, identity.object_id,
            identity.generation, offset, destination}, covered) && covered == destination.size();
    });
    Batch bystander{L"\\bystander", BuildPatternPayloadForTest(3 * Block + 17, 0x35)};
    Batch target{L"\\target", BuildPatternPayloadForTest(4 * Block + 29, 0x57)};
    const auto publish_clean = [&](Batch& batch) {
        if (!Accept(c, batch, true)) return false;
        const auto status = CommitNativeMutationsBestEffort(&c, L"W09Seed");
        std::fwprintf(stderr, L"[W09] seed=%ls status=%lx stage=%hs reason=%ls detail=%ls\n", batch.path.c_str(),
            static_cast<unsigned long>(status), c.metadata_store->LastCommitStage().c_str(),
            c.metadata_store->LastCommitFailureReason().c_str(), c.metadata_store->LastCommitFailureDetail().c_str());
        return NT_SUCCESS(status) && FinalizeMutationJournalBestEffort(&c, L"W09Seed");
    };
    if (!Require(publish_clean(bystander) && publish_clean(target), "W09 real accepted seed files publish and clean")) return false;
    // Move the next data publication to the end so the retained batch crosses zero.
    for (unsigned i = 0; i < 5 && c.metadata_store->AuthoritativeAppleCheckpointView()->container.superblock.xp_data_next < 13; ++i)
    {
        Batch warm{L"\\warm-" + std::to_wstring(i), BuildPatternPayloadForTest(7, 0x62)};
        if (!Require(publish_clean(warm), "W09 clean warmup positions the genuine checkpoint ring")) return false;
    }
    const auto original = ReadFileBytes(fixture.image.path);
    const auto source_xid = c.metadata_store->CheckpointXid().value_or(0);
    const auto data_next = c.metadata_store->AuthoritativeAppleCheckpointView()->container.superblock.xp_data_next;
    const auto desc_next = c.metadata_store->AuthoritativeAppleCheckpointView()->container.superblock.xp_desc_next;
    auto retained = std::make_unique<Store>(fixture.volume);
    if (!Require(retained->PrepareNativeWritePath(), "W09 retained canonical reader pins the original payload plan")) return false;
    Batch changed{target.path, BuildPatternPayloadForTest(target.payload.size(), 0xa7)};
    if (!Accept(c, changed, false)) return false;
    if (unrecorded_timestamp)
    {
        Store::MutationRequest extra;
        extra.operation = Store::MutationOperation::SetBasicInfo;
        extra.path = changed.path;
        extra.timestamp_utc = 133700000000000000ULL;
        if (!Require(c.metadata_store->StageMutation(extra) == Store::MutationStatus::Applied,
                "W09 negative publishes extra timestamp semantics absent from the original WAL")) return false;
    }
    if (!Require(NT_SUCCESS(CommitNativeMutationsBestEffort(&c, L"W09Wrap")),
            "W09 accepted overwrite publishes with its original preimage retained")) return false;
    if (!missing_receipt && !Require(c.tx_manager->MarkApfsDurableThrough(changed.accepted),
            "W09 persist the verified publication receipt while retaining its original journal and pin")) return false;
    bool data_wrapped = c.metadata_store->AuthoritativeAppleCheckpointView()->container.superblock.xp_data_next < data_next;
    bool desc_wrapped = c.metadata_store->AuthoritativeAppleCheckpointView()->container.superblock.xp_desc_next < desc_next;
    std::vector<std::uint64_t> protected_blocks;
    if (!CheckHistory(fixture.image.path, original, source_xid, true, protected_blocks) ||
        !CheckReference(c, changed) || !CheckFile(*retained, target) || !CheckFile(*c.metadata_store, bystander)) return false;

    // Exercise real allocation pressure before accepting any additional bytes.
    const auto before_full = ReadFileBytes(fixture.image.path);
    const auto wal_before_full = ReadFileBytes(c.session_root / "accepted.wal");
    const auto spool_before_full = ReadFileBytes(c.payload_spool->SpoolFilePath());
    const auto marks_before_full = c.tx_manager->Watermarks();
    const auto free = c.metadata_store->FreeSizeBytes().value_or(UINT64_MAX);
    const auto request = NativeCallbackRequest(Store::MutationOperation::SetFileSize, target.path, free / Block * Block);
    const auto full = PreflightDirectCallback(&c, std::span(&request, 1));
    std::fprintf(stderr, "[W09] capacity-admission=%lx free-blocks=%llu\n", static_cast<unsigned long>(full), free / Block);
    if (!Require(free < 80 * Block && full == STATUS_DISK_FULL &&
            ReadFileBytes(fixture.image.path) == before_full && ReadFileBytes(c.session_root / "accepted.wal") == wal_before_full &&
            ReadFileBytes(c.payload_spool->SpoolFilePath()) == spool_before_full &&
            c.tx_manager->Watermarks().accepted_sequence == marks_before_full.accepted_sequence &&
            c.tx_manager->Watermarks().cleanup_sequence == marks_before_full.cleanup_sequence &&
            c.native_write_enabled && !c.write_degraded && !c.recovery_active,
            "W09 low-space mounted admission refuses without changing retained WAL, spool, image or admission")) return false;

    std::vector<Batch> batches{changed};
    bool blocked = false;
    for (unsigned i = 0; i < 8; ++i)
    {
        Batch next{L"\\pending-" + std::to_wstring(i), BuildPatternPayloadForTest(Block + 31, 0x71 + i)};
        if (!Require(Accept(c, next, true), "W09 later accepted generation retains its own payload reference")) return false;
        const auto before = ReadFileBytes(fixture.image.path);
        const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
        const auto spool = ReadFileBytes(c.payload_spool->SpoolFilePath());
        const auto marks = c.tx_manager->Watermarks();
        const auto previous = c.metadata_store->AuthoritativeAppleCheckpointView()->container.superblock;
        const auto result = CommitNativeMutationsBestEffort(&c, L"W09PinnedPressure");
        std::fwprintf(stderr, L"[W09] next=%u status=%lx xid=%llu free=%llu detail=%ls\n", i,
            static_cast<unsigned long>(result), c.metadata_store->CheckpointXid().value_or(0),
            c.metadata_store->FreeSizeBytes().value_or(0) / Block, c.metadata_store->LastCommitFailureDetail().c_str());
        batches.push_back(next);
        if (result == STATUS_MEDIA_WRITE_PROTECTED)
        {
            blocked = true;
            const auto after = c.tx_manager->Watermarks();
            std::fwprintf(stderr, L"[W09] retained image=%d wal=%d spool=%d pending=%zu debt=%d marks=%llu/%llu/%llu->%llu/%llu/%llu stage=%hs reason=%ls runtime=%ls action=%ls enabled=%d degraded=%d recovery=%d\n",
                before == ReadFileBytes(fixture.image.path), wal == ReadFileBytes(c.session_root / "accepted.wal"),
                spool == ReadFileBytes(c.payload_spool->SpoolFilePath()), c.metadata_store->PendingMutationCount(),
                c.tx_manager->HasUnappliedAcceptedWork(), marks.accepted_sequence, marks.apfs_durable_sequence,
                marks.cleanup_sequence, after.accepted_sequence, after.apfs_durable_sequence, after.cleanup_sequence,
                c.metadata_store->LastCommitStage().c_str(), c.metadata_store->LastCommitFailureReason().c_str(),
                c.runtime_recovery_reason.c_str(), c.runtime_last_recovery_action.c_str(),
                c.native_write_enabled.load(), c.write_degraded.load(), c.recovery_active.load());
            if (!Require(before == ReadFileBytes(fixture.image.path) && wal == ReadFileBytes(c.session_root / "accepted.wal") &&
                    spool == ReadFileBytes(c.payload_spool->SpoolFilePath()) &&
                    c.metadata_store->PendingMutationCount() != 0 && c.tx_manager->HasUnappliedAcceptedWork() &&
                    c.tx_manager->Watermarks().accepted_sequence == marks.accepted_sequence &&
                    c.tx_manager->Watermarks().apfs_durable_sequence == marks.apfs_durable_sequence &&
                    c.tx_manager->Watermarks().cleanup_sequence == marks.cleanup_sequence &&
                    c.metadata_store->LastCommitStage() == "apple-plan-retention-blocked" &&
                    c.metadata_store->LastCommitFailureReason() == L"CheckpointRetentionExhausted" &&
                    c.runtime_recovery_reason == L"CommitCapacityFailureWithJournalDebt" &&
                    c.runtime_last_recovery_action == L"DowngradedAfterCapacityFailureWithJournalDebt" &&
                    !c.native_write_enabled && c.write_degraded && c.recovery_active,
                    "W09 accepted pinned-capacity debt latches recovery before image I/O and preserves original evidence")) return false;
            if (!Require(CommitNativeMutationsBestEffort(&c, L"W09LatchedRetry") == STATUS_MEDIA_WRITE_PROTECTED &&
                    before == ReadFileBytes(fixture.image.path) && wal == ReadFileBytes(c.session_root / "accepted.wal") &&
                    spool == ReadFileBytes(c.payload_spool->SpoolFilePath()) &&
                    c.metadata_store->PendingMutationCount() != 0 && c.tx_manager->HasUnappliedAcceptedWork() &&
                    c.tx_manager->Watermarks().accepted_sequence == marks.accepted_sequence &&
                    c.tx_manager->Watermarks().apfs_durable_sequence == marks.apfs_durable_sequence &&
                    c.tx_manager->Watermarks().cleanup_sequence == marks.cleanup_sequence,
                    "W09 same-owner retry cannot clear accepted retention debt or advance its receipts")) return false;
            break;
        }
        if (!Require(NT_SUCCESS(result), "W09 publication succeeds or retains accepted capacity debt")) return false;
        if (!missing_receipt && !Require(c.tx_manager->MarkApfsDurableThrough(next.accepted),
                "W09 published prefix has an actual durable receipt without cleanup")) return false;
        const auto& current = c.metadata_store->AuthoritativeAppleCheckpointView()->container.superblock;
        data_wrapped |= current.xp_data_next < previous.xp_data_next;
        desc_wrapped |= current.xp_desc_next < previous.xp_desc_next;
        if (!CheckHistory(fixture.image.path, original, source_xid, false, protected_blocks)) return false;
    }
    std::fprintf(stderr, "[W09] data-wrap=%d descriptor-wrap=%d batches=%zu protected-blocks=%zu\n",
        data_wrapped, desc_wrapped, batches.size(), protected_blocks.size());
    if (!Require(blocked && data_wrapped && desc_wrapped, "W09 both genuine checkpoint rings wrap under retained payload pins")) return false;
    for (const auto& batch : batches) if (!CheckReference(c, batch)) return false;
    const auto pending = batches.back();
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    const auto spool = ReadFileBytes(c.payload_spool->SpoolFilePath());
    std::filesystem::path evidence;
    if (const auto* destination = std::getenv("APFSACCESS_W09_EVIDENCE"))
    {
        evidence = std::filesystem::path(destination) / (mutable_source ? "mutable-source" : unrecorded_timestamp ? "unrecorded-timestamp" :
            history_fault == 1 ? "history-missing" :
            history_fault == 2 ? "history-misbound" : history_fault == 3 ? "history-corrupt" :
            missing_receipt ? "missing-receipt" : corrupt_spool ? "corrupt-spool" : "recovery");
        if (!WriteFileBytes(evidence / "original.img", original) ||
            !WriteFileBytes(evidence / "before-replay.img", ReadFileBytes(fixture.image.path)) ||
            !WriteFileBytes(evidence / "accepted.wal", wal) ||
            !WriteFileBytes(evidence / "payload-spool.bin", spool) ||
            !WriteFileBytes(evidence / "payload-spool.idx", ReadFileBytes(c.session_root / "payload-spool" / "payload-spool.idx")) ||
            !WriteFileBytes(evidence / "pending-expected.bin", pending.payload) ||
            !WriteFileBytes(evidence / "bystander-expected.bin", bystander.payload) ||
            !WriteFileBytes(evidence / "target-expected.bin", changed.payload)) return false;
    }
    retained.reset();
    HANDLE borrowed_source = INVALID_HANDLE_VALUE;
    const bool exclusive = missing_receipt && !mutable_source;
    if (!Reopen(fixture, exclusive, borrowed_source)) return false;
    auto& r = *fixture.context;
    class HeldVerificationSource final : public apfsaccess::catalog::RandomAccessSource
    {
    public:
        explicit HeldVerificationSource(const apfsaccess::rw::BlockDevice& device) : device_(device) {}
        std::uint64_t SizeBytes() const override { return device_.GetGeometry().total_bytes; }
        bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& bytes) const override
        {
            bytes.clear();
            if (offset > SizeBytes() || size > SizeBytes() - offset) return false;
            if (!size) return true;
            const auto aligned = offset - offset % Block;
            const auto prefix = static_cast<std::size_t>(offset - aligned);
            const auto length = (prefix + size + Block - 1) / Block * Block;
            if (!device_.ReadForVerification(aligned, length, bytes)) return false;
            if (prefix) bytes.erase(bytes.begin(), bytes.begin() + prefix);
            bytes.resize(size);
            return true;
        }
    private:
        const apfsaccess::rw::BlockDevice& device_;
    } held_source(r.metadata_store->Device());
    const auto read_image = [&]() {
        std::vector<std::byte> bytes;
        if (!held_source.Read(0, static_cast<std::size_t>(held_source.SizeBytes()), bytes)) bytes.clear();
        return bytes;
    };
    const auto peers_refused = [&]() {
        bool refused = true;
        for (const auto access : {DWORD(GENERIC_WRITE), DWORD(DELETE)})
        {
            const auto peer = CreateFileW(fixture.image.path.c_str(), access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            const auto error = GetLastError();
            if (peer != INVALID_HANDLE_VALUE) CloseHandle(peer);
            refused &= peer == INVALID_HANDLE_VALUE && error == ERROR_SHARING_VIOLATION;
        }
        return refused;
    };
    if (!Require(read_image().size() == spec.block_count * Block &&
            (!exclusive || peers_refused()), "W09 held readback works and exclusive lease refuses external write/delete opens")) return false;
    if (!Require(wal == ReadFileBytes(r.session_root / "accepted.wal") && spool == ReadFileBytes(r.payload_spool->SpoolFilePath()),
            "W09 fresh owner reopens original WAL and spool without rewriting evidence")) return false;
    if (mutable_source)
    {
        const auto image = read_image();
        const auto index = ReadFileBytes(r.session_root / "payload-spool" / "payload-spool.idx");
        const auto marks = r.tx_manager->Watermarks();
        std::vector<std::uint64_t> applied{UINT64_MAX};
        std::string error;
        const bool proof = r.metadata_store->ProveRetainedAcceptedPrefix(*r.tx_manager, *r.payload_spool,
            r.tx_journal_file, r.payload_spool_volume_identity, applied, error);
        const bool replay = ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(r);
        std::fprintf(stderr, "[W09] mutable-owner proof=%d replay=%d detail=%s\n", proof, replay, error.c_str());
        return Require(!proof && applied.empty() && error == "RetainedAcceptedSourceNotExclusive" && !replay &&
            image == read_image() && wal == ReadFileBytes(r.tx_journal_file) &&
            spool == ReadFileBytes(r.payload_spool->SpoolFilePath()) &&
            index == ReadFileBytes(r.session_root / "payload-spool" / "payload-spool.idx") &&
            marks.accepted_sequence == r.tx_manager->Watermarks().accepted_sequence &&
            marks.apfs_durable_sequence == r.tx_manager->Watermarks().apfs_durable_sequence &&
            marks.cleanup_sequence == r.tx_manager->Watermarks().cleanup_sequence,
            "W09 unsupported mutable ordinary owner refuses with original evidence and watermarks intact");
    }
    if (history_fault || unrecorded_timestamp)
    {
        if (history_fault)
        {
            std::string error;
            const auto historical = apfsaccess::catalog::LoadAppleCheckpointView(held_source, 0, held_source.SizeBytes(), error, source_xid);
            if (!Require(historical.has_value(), "W09 negative starts with the real retained historical owner")) return false;
            auto faulted = read_image();
            const auto block = history_fault == 3 ? historical->volumes.front().root_tree.physical_block :
                historical->container.superblock_physical_block;
            const auto at = static_cast<std::size_t>(block * Block);
            std::vector<std::byte> cached;
            if (!Require(r.metadata_store->Device().Read(at, Block, cached) && cached.size() == Block,
                    "W09 prime the original historical block in the general cache")) return false;
            if (history_fault == 1) std::fill_n(faulted.begin() + at, Block, std::byte{0});
            else if (history_fault == 2)
            {
                std::vector<std::byte> nx(faulted.begin() + at, faulted.begin() + at + Block);
                nx[0x48] ^= std::byte{1};
                apfsaccess::testfixture::FletcherForBlock(nx, Block);
                std::copy(nx.begin(), nx.end(), faulted.begin() + at);
            }
            else faulted.at(at + 0x30) ^= std::byte{1};
            OVERLAPPED write{};
            write.Offset = static_cast<DWORD>(at); write.OffsetHigh = static_cast<DWORD>(std::uint64_t(at) >> 32);
            DWORD written = 0;
            const auto started = WriteFile(borrowed_source, faulted.data() + at, static_cast<DWORD>(Block), &written, &write);
            const auto completed = started || (GetLastError() == ERROR_IO_PENDING &&
                GetOverlappedResult(borrowed_source, &write, &written, TRUE));
            if (!Require(completed && written == Block && FlushFileBuffers(borrowed_source) && read_image() == faulted,
                    "W09 actual post-bootstrap held-handle corruption is flushed and independently reread")) return false;
            std::vector<std::byte> general_read;
            const auto cache_enabled = std::getenv("APFSACCESS_EXPERIMENTAL_BLOCK_READ_CACHE");
            if (!Require(r.metadata_store->Device().Read(at, Block, general_read) &&
                    (!cache_enabled || std::string(cache_enabled) != "1" || general_read == cached),
                    "W09 cache-enabled negative retains demonstrably stale historical bytes")) return false;
            std::fprintf(stderr, "[W09] actual-fault block=%llu xid=%llu stale-cache=%d authority=%d\n",
                block, source_xid, general_read == cached,
                r.metadata_store->Device().CaptureExclusiveWriteSourceObservation().has_value());
            if (!evidence.empty() && !WriteFileBytes(evidence / "faulted.img", faulted)) return false;
        }
        const auto image = read_image();
        const auto index = ReadFileBytes(r.session_root / "payload-spool" / "payload-spool.idx");
        const auto marks = r.tx_manager->Watermarks();
        if (unrecorded_timestamp || history_fault)
        {
            std::vector<std::uint64_t> applied{UINT64_MAX};
            std::string error;
            if (!Require(!r.metadata_store->ProveRetainedAcceptedPrefix(*r.tx_manager, *r.payload_spool,
                    r.tx_journal_file, r.payload_spool_volume_identity, applied, error) && applied.empty() &&
                    error == (unrecorded_timestamp ? "RetainedAcceptedPublicationReadbackMismatch" : "RetainedAcceptedHistoryUnavailable"),
                    "W09 real data faults refuse canonical proof despite exclusive authority and cached old bytes")) return false;
            std::fprintf(stderr, "[W09] negative-proof=0 detail=%s\n", error.c_str());
        }
        const auto replayed = ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(r);
        std::fwprintf(stderr, L"[W09] history-fault=%u replay=%d reason=%ls\n", history_fault, replayed, r.runtime_recovery_reason.c_str());
        const auto after = r.tx_manager->Watermarks();
        std::fprintf(stderr, "[W09] negative-watermarks before=%llu/%llu/%llu after=%llu/%llu/%llu\n",
            marks.accepted_sequence, marks.apfs_durable_sequence, marks.cleanup_sequence,
            after.accepted_sequence, after.apfs_durable_sequence, after.cleanup_sequence);
        if (!evidence.empty() && (!WriteFileBytes(evidence / "after-refusal.img", read_image()) ||
                !WriteFileBytes(evidence / "after-refusal.wal", ReadFileBytes(r.tx_journal_file)) ||
                !WriteFileBytes(evidence / "after-refusal-spool.bin", ReadFileBytes(r.payload_spool->SpoolFilePath())))) return false;
        return Require(!replayed && r.runtime_recovery_reason == L"AcceptedReplayPreimageCheckpointMismatch" &&
            image == read_image() && wal == ReadFileBytes(r.session_root / "accepted.wal") &&
            spool == ReadFileBytes(r.payload_spool->SpoolFilePath()) &&
            index == ReadFileBytes(r.session_root / "payload-spool" / "payload-spool.idx") &&
            r.tx_manager->Watermarks().accepted_sequence == marks.accepted_sequence &&
            r.tx_manager->Watermarks().apfs_durable_sequence == marks.apfs_durable_sequence &&
            r.tx_manager->Watermarks().cleanup_sequence == marks.cleanup_sequence && r.tx_manager->HasUnappliedAcceptedWork() &&
            !r.metadata_store->PendingMutationCount() && CheckFile(*r.metadata_store, bystander),
            "W09 missing, misbound or corrupt history refuses without rebasing identities, writes or cleanup");
    }
    if (missing_receipt)
    {
        const auto image = read_image();
        const auto index = ReadFileBytes(r.session_root / "payload-spool" / "payload-spool.idx");
        const auto marks = r.tx_manager->Watermarks();
        std::vector<std::uint64_t> applied, expected;
        for (std::size_t i = 0; i + 1 < batches.size(); ++i) expected.push_back(batches[i].accepted);
        std::string error;
        const auto proven = r.metadata_store->ProveRetainedAcceptedPrefix(*r.tx_manager, *r.payload_spool,
            r.tx_journal_file, r.payload_spool_volume_identity, applied, error);
        std::fprintf(stderr, "[W09] original-prefix-proof=%d batches=%zu detail=%s\n", proven, applied.size(), error.c_str());
        if (!Require(proven && applied == expected && expected.size() == 4 && image == read_image() &&
                wal == ReadFileBytes(r.session_root / "accepted.wal") && spool == ReadFileBytes(r.payload_spool->SpoolFilePath()) &&
                index == ReadFileBytes(r.session_root / "payload-spool" / "payload-spool.idx") &&
                r.tx_manager->Watermarks().apfs_durable_sequence == marks.apfs_durable_sequence &&
                r.tx_manager->Watermarks().cleanup_sequence == marks.cleanup_sequence,
                "W09 exact original accepted sequences earn a read-only canonical publication proof")) return false;
        for (const auto& batch : batches) if (!CheckReference(r, batch)) return false;
    }
    if (corrupt_spool)
    {
        r.payload_spool.reset();
        auto corrupted = spool;
        corrupted.at(static_cast<std::size_t>(pending.reference.spool_offset)) ^= std::byte{1};
        if (!WriteFileBytes(r.session_root / "payload-spool" / "payload-spool.bin", corrupted)) return false;
        r.payload_spool = std::make_unique<Spool>(Spool::Options{
            r.session_root / "payload-spool", r.payload_spool_volume_identity, 1024 * 1024});
        const auto image = read_image();
        const auto marks = r.tx_manager->Watermarks();
        if (!evidence.empty() && !WriteFileBytes(evidence / "corrupted-spool.bin", corrupted)) return false;
        if (missing_receipt)
        {
            std::vector<std::uint64_t> applied{UINT64_MAX};
            std::string error;
            if (!Require(!r.metadata_store->ProveRetainedAcceptedPrefix(*r.tx_manager, *r.payload_spool,
                    r.tx_journal_file, r.payload_spool_volume_identity, applied, error) && applied.empty() &&
                    error == "RetainedAcceptedOriginalPayloadInvalid" &&
                    image == read_image() &&
                    wal == ReadFileBytes(r.session_root / "accepted.wal") &&
                    corrupted == ReadFileBytes(r.payload_spool->SpoolFilePath()) &&
                    r.tx_manager->Watermarks().apfs_durable_sequence == marks.apfs_durable_sequence &&
                    r.tx_manager->Watermarks().cleanup_sequence == marks.cleanup_sequence,
                    "W09 corrupt pending tail cannot return even the valid prefix proof or advance receipts")) return false;
        }
        return Require(!ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(r) &&
            (r.runtime_recovery_reason == L"AcceptedWritePayloadIndexRebuildFailed" ||
                r.runtime_recovery_reason == L"AcceptedWriteReplayPayloadMismatch") &&
            image == read_image() && wal == ReadFileBytes(r.session_root / "accepted.wal") &&
            corrupted == ReadFileBytes(r.payload_spool->SpoolFilePath()) &&
            r.tx_manager->Watermarks().apfs_durable_sequence == marks.apfs_durable_sequence &&
            r.tx_manager->Watermarks().cleanup_sequence == marks.cleanup_sequence && r.tx_manager->HasUnappliedAcceptedWork() &&
            !r.metadata_store->PendingMutationCount() && CheckFile(*r.metadata_store, bystander),
            "W09 damaged original spool refuses certification without image writes, cleanup or invented progress");
    }
    unsigned publications = 0;
    unsigned receipt_checks = 0;
    bool lease_held_at_receipt = true;
    if (exclusive) r.tx_manager->SetJournalFaultInjectionHook([&](std::string_view stage) {
        if (stage == "durable-flush" && publications == 0)
        {
            ++receipt_checks;
            lease_held_at_receipt &= peers_refused() &&
                r.metadata_store->Device().CaptureExclusiveWriteSourceObservation().has_value();
        }
        return false;
    });
    r.metadata_store->SetCommitStageHook([&](std::string_view stage) {
        if (stage == "before-apple-publish") ++publications;
        return true;
    });
    const auto before_replay_xid = r.metadata_store->CheckpointXid().value_or(0);
    const auto replayed = ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(r);
    std::fwprintf(stderr, L"[W09] replay=%d publications=%u reason=%ls\n", replayed, publications, r.runtime_recovery_reason.c_str());
    std::fprintf(stderr, "[W09] receipt-lease checks=%u held=%d\n", receipt_checks, lease_held_at_receipt);
    r.tx_manager->SetJournalFaultInjectionHook({});
    if (!Require(replayed && publications == 1 && (!exclusive || (receipt_checks && lease_held_at_receipt && peers_refused())) &&
            r.metadata_store->CheckpointXid() == before_replay_xid + 1 &&
            r.tx_manager->Watermarks().accepted_sequence == pending.accepted &&
            r.tx_manager->Watermarks().apfs_durable_sequence == pending.accepted &&
            r.tx_manager->Watermarks().cleanup_sequence == pending.accepted && !r.tx_manager->HasUnappliedAcceptedWork(),
            "W09 recovery proves the published prefix and replays only the original pending generation once")) return false;
    for (const auto& batch : batches) if (!CheckFile(*r.metadata_store, batch)) return false;
    if (!CheckFile(*r.metadata_store, bystander)) return false;
    const auto stable = read_image();
    if (!evidence.empty() && (!WriteFileBytes(evidence / "recovered.img", stable) ||
            !WriteFileBytes(evidence / "recovered.wal", ReadFileBytes(r.session_root / "accepted.wal")))) return false;
    if (!Require(ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(r) && stable == read_image() &&
            r.metadata_store->VerifyIntegrity() && r.metadata_store->IsProductionCanonicalPathActive() &&
            !r.metadata_store->IsFixtureLegacyFallbackActive() && !r.metadata_store->UsesScaffoldCommitBlob(),
            "W09 repeated replay is byte-idempotent on the canonical Apple path")) return false;
    r.owned_metadata_store.reset();
    r.metadata_store = nullptr;
    borrowed_source = INVALID_HANDLE_VALUE;
    Store fresh(fixture.volume);
    return Require(fresh.PrepareNativeWritePath(), "W09 independent canonical reopen") &&
        CheckFile(fresh, pending) && CheckFile(fresh, changed) && CheckFile(fresh, bystander);
}
}
