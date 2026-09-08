#pragma once

bool TestNativeCompressionWriteCallbacks(bool interrupted = false)
{
    using Store = apfsaccess::rw::MetadataStore;
    using Tx = apfsaccess::rw::TransactionManager;
    if (!CompressionReplay222ScratchReady()) return false;
    bool passed = true;
    for (const auto type : {1u, 3u, 4u})
    for (unsigned variant = 0; variant < (interrupted ? 4u : 2u); ++variant)
    {
        const bool archive_refusal = !interrupted && variant == 1;
        HostCompressionRewrite211Fixture fixture;
        if (!Require(fixture.Initialize(type, false, false, false, archive_refusal),
                "foreground rewrite fixture initializes")) return false;
        auto& c = *fixture.fixture.context;
        c.args.write_recovery_policy = interrupted && (variant & 1) ? L"BestEffort" : L"FailClosed";
        auto fs = BuildFileSystem(&c);
        const auto initial = c.metadata_store->LookupCommittedInodeByPath(L"\\compressed");
        std::vector<std::byte> expected;
        if (!Require(initial && c.metadata_store->ReadCommittedFileRange(L"\\compressed", 0,
                fixture.eof, expected), "capture complete original compressed bytes")) return false;
        FSP_FSCTL_FILE_INFO info{};
        PVOID writer = nullptr, reader = nullptr, unrelated = nullptr;
        ScopeExit close{[&] {
            if (writer) CB_Close(&fs, writer);
            if (reader) CB_Close(&fs, reader);
            if (unrelated) CB_Close(&fs, unrelated);
        }};
        if (!Require(CB_Open(&fs, const_cast<PWSTR>(L"\\alias"), FILE_OPEN << 24,
                GENERIC_READ | GENERIC_WRITE | FILE_WRITE_ATTRIBUTES, &writer, &info) == STATUS_SUCCESS &&
                CB_Open(&fs, const_cast<PWSTR>(L"\\compressed"), FILE_OPEN << 24,
                    GENERIC_READ, &reader, &info) == STATUS_SUCCESS,
                "compressed owner opens for editing and alias reads through normal callbacks")) return false;
        if (archive_refusal)
        {
            // Imported metadata is genuinely archive-clear on disk. Live
            // timestamp updates of compressed content are a separate feature.
            std::optional<UINT32> attributes;
            if (!Require(ReadWindowsAttributes(c.metadata_store->LookupCommittedExtendedAttribute(
                    initial->object_id, kWindowsAttributesName), attributes) && attributes &&
                    !(*attributes & FILE_ATTRIBUTE_ARCHIVE) &&
                    c.metadata_store->LookupCommittedExtendedAttribute(initial->object_id, "com.apple.decmpfs") &&
                    CanOpenNativeCompressionRewrite(&c, static_cast<OpenContext*>(writer)->node),
                    "archive-clear owner still passes compression-source admission")) return false;
            c.args.write_max_dirty_transactions = 64;
            if (!Require(CB_Create(&fs, const_cast<PWSTR>(L"\\unrelated-pending"), FILE_NON_DIRECTORY_FILE,
                    GENERIC_READ | GENERIC_WRITE, FILE_ATTRIBUTE_ARCHIVE, nullptr, 0, &unrelated, &info) == STATUS_SUCCESS &&
                    c.metadata_store->PendingMutationCount() != 0 && c.tx_manager->PendingMutationCount() != 0 &&
                    !c.metadata_store->LookupCommittedInodeByPath(L"\\unrelated-pending") &&
                    CanOpenNativeCompressionRewrite(&c, static_cast<OpenContext*>(writer)->node),
                    "unrelated real file creation remains pending before refused compressed write")) return false;
            const auto xid = c.metadata_store->CheckpointXid();
            const auto marks = c.tx_manager->Watermarks();
            const auto pending = c.metadata_store->PendingMutationCount();
            const auto journal_pending = c.tx_manager->PendingMutationCount();
            const auto next_sequence = c.tx_manager->NextMutationSequence();
            const auto state = c.tx_manager->CurrentState();
            const auto pending_writes = c.pending_native_writes.load();
            const auto working = c.metadata_store->LookupWorkingInodeByPath(L"\\unrelated-pending");
            const auto image = ReadFileBytes(fixture.fixture.image.path);
            const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
            const auto marker = ReadFileBytes(c.recovery_marker_file);
            const auto spool = c.payload_spool->SnapshotCounters();
            std::byte refused{'R'};
            ULONG refused_done = 999;
            const auto refused_status = CB_Write(&fs, writer, &refused, 1, 1, FALSE, FALSE, &refused_done, &info);
            const auto after = c.tx_manager->Watermarks();
            const auto after_spool = c.payload_spool->SnapshotCounters();
            const auto after_working = c.metadata_store->LookupWorkingInodeByPath(L"\\unrelated-pending");
            if (!Require(refused_status == STATUS_NOT_SUPPORTED && refused_done == 0 &&
                    xid == c.metadata_store->CheckpointXid() && image == ReadFileBytes(fixture.fixture.image.path) &&
                    wal == ReadFileBytes(c.session_root / "accepted.wal") && marker == ReadFileBytes(c.recovery_marker_file) &&
                    marks.accepted_sequence == after.accepted_sequence &&
                    marks.apfs_durable_sequence == after.apfs_durable_sequence && marks.cleanup_sequence == after.cleanup_sequence &&
                    pending == c.metadata_store->PendingMutationCount() && journal_pending == c.tx_manager->PendingMutationCount() &&
                    next_sequence == c.tx_manager->NextMutationSequence() && state == c.tx_manager->CurrentState() &&
                    pending_writes == c.pending_native_writes.load() && working && after_working &&
                    working->object_id == after_working->object_id && working->xid == after_working->xid &&
                    !c.metadata_store->LookupCommittedInodeByPath(L"\\unrelated-pending") &&
                    spool.spool_bytes == after_spool.spool_bytes && spool.dirty_range_count == after_spool.dirty_range_count &&
                    !c.recovery_active && !c.write_degraded,
                    "archive refusal changes no checkpoint, WAL, watermarks, spool or unrelated pending mutation")) return false;
            continue;
        }
        unsigned publication_attempts = 0;
        bool transition_checked = false;
        const bool proof_refusal = interrupted && variant >= 2;
        ScopeExit clear_hook{[&] {
            c.metadata_store->SetCommitStageHook({});
            g_compressed_after_publication_hook = {};
            g_compressed_refuse_publication_proof = false;
        }};
        g_compressed_refuse_publication_proof = proof_refusal;
        if (!interrupted)
        {
            // Even a same-size preexisting cache cannot become a new alias's
            // data source between native publication and materialization.
            const auto cache = HydrationPath(&c, *static_cast<OpenContext*>(writer)->node);
            std::filesystem::create_directories(cache.parent_path());
            if (!WriteFileBytes(cache, std::vector<std::byte>(expected.size(), std::byte{'Q'}))) return false;
            g_compressed_after_publication_hook = [&](MountContext*) {
                PVOID alias = nullptr, root = nullptr;
                FSP_FSCTL_FILE_INFO observed{};
                const auto status = CB_Open(&fs, const_cast<PWSTR>(L"\\compressed"), FILE_OPEN << 24,
                    GENERIC_READ, &alias, &observed);
                const auto root_status = CB_Open(&fs, const_cast<PWSTR>(L"\\"), FILE_DIRECTORY_FILE,
                    FILE_READ_ATTRIBUTES, &root, &observed);
                transition_checked = status == STATUS_DEVICE_BUSY && !alias && root_status == STATUS_SUCCESS;
                if (alias) CB_Close(&fs, alias);
                if (root) CB_Close(&fs, root);
            };
        }
        if (interrupted && !proof_refusal)
            c.metadata_store->SetCommitStageHook([&](std::string_view stage) {
                if (stage != "after-apple-publish") return true;
                ++publication_attempts;
                return false;
            });
        std::byte value{'Z'};
        ULONG done = 999;
        const auto status = CB_Write(&fs, writer, &value, 1, 1, FALSE, FALSE, &done, &info);
        expected[1] = value;
        if (interrupted)
        {
            const auto marks = c.tx_manager->Watermarks();
            if (!Require(publication_attempts == (proof_refusal ? 0u : 1u) && !NT_SUCCESS(status) && done == 0 &&
                marks.accepted_sequence > marks.apfs_durable_sequence &&
                marks.accepted_sequence > marks.cleanup_sequence && c.pending_native_writes &&
                c.recovery_active && ((variant & 1) || c.write_degraded),
                "interrupted foreground conversion keeps accepted recovery evidence under each policy")) return false;
            const auto spool = c.payload_spool->SnapshotCounters();
            const auto spool_bytes = ReadFileBytes(c.payload_spool->SpoolFilePath());
            const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
            std::vector<std::uint64_t> pins;
            if (!Require(!wal.empty() && !spool_bytes.empty() && spool.dirty_range_count != 0 && spool.spool_bytes != 0 &&
                    c.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(pins) && !pins.empty(),
                    "interruption leaves real accepted WAL, spool bytes and checkpoint pins")) return false;
            c.metadata_store->SetCommitStageHook({});
            g_compressed_refuse_publication_proof = false;
            const auto retained = [&](const char* phase) {
                const auto after = c.tx_manager->Watermarks();
                const auto after_spool = c.payload_spool->SnapshotCounters();
                std::vector<std::uint64_t> after_pins;
                std::vector<Tx::AcceptedTransaction> batches;
                return Require(after.accepted_sequence == marks.accepted_sequence &&
                    after.apfs_durable_sequence == marks.apfs_durable_sequence && after.cleanup_sequence == marks.cleanup_sequence &&
                    after_spool.dirty_range_count == spool.dirty_range_count && after_spool.spool_bytes == spool.spool_bytes &&
                    spool_bytes == ReadFileBytes(c.payload_spool->SpoolFilePath()) &&
                    wal == ReadFileBytes(c.session_root / "accepted.wal") &&
                    c.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(after_pins) && after_pins == pins &&
                    c.tx_manager->LoadAcceptedTransactionsSinceCleanup(batches) && !batches.empty() &&
                    c.recovery_active && c.pending_native_writes &&
                    std::filesystem::exists(c.recovery_marker_file) && !ReadFileBytes(c.recovery_marker_file).empty(), phase);
            };
            // Flush may be a no-op once FailClosed disables mutations. Exercise
            // the direct drain and finalizer too, with the injection removed.
            (void)CB_Flush(&fs, writer, &info);
            passed &= retained("Flush retains interrupted compression evidence and every cleanup watermark");
            const auto drain = CommitNativeMutationsOnFlushBestEffort(&c);
            passed &= Require(!NT_SUCCESS(drain), "explicit Flush drain refuses unresolved compression publication");
            passed &= retained("explicit drain retains interrupted compression evidence and watermarks");
            const auto finalized = FinalizeMutationJournalBestEffort(&c, L"CompressionInterruptedFinalize");
            passed &= Require(!finalized, "finalization refuses unresolved compression publication");
            passed &= retained("finalization retains interrupted compression evidence and watermarks");
            // Close before shutdown so ScopeExit cannot publish after the final
            // retention assertion. The fixture's unmounted fs remains null;
            // production shutdown runs its real drain without WinFsp teardown.
            CB_Close(&fs, writer); writer = nullptr;
            CB_Close(&fs, reader); reader = nullptr;
            passed &= retained("closing aliases retains interrupted compression evidence and watermarks");
            if (!Require(c.fs == nullptr, "shutdown fixture has no mounted WinFsp filesystem")) return false;
            const auto shutdown = RunFsHostShutdownDrain(fixture.fixture.context);
            passed &= Require(shutdown == 10 || shutdown == 11,
                "normal shutdown reports unresolved native publication or journal finalization");
            passed &= retained("normal shutdown retains interrupted compression WAL, spool, marker, pins and watermarks");
        }
        else
        {
            if (!Require(status == STATUS_SUCCESS && done == 1 && !c.write_degraded && transition_checked,
                    "one-byte callback edit publishes and verifies the full conversion")) return false;
            const auto first_marks = c.tx_manager->Watermarks();
            if (!Require(first_marks.accepted_sequence != 0 &&
                    first_marks.accepted_sequence == first_marks.apfs_durable_sequence &&
                    first_marks.accepted_sequence == first_marks.cleanup_sequence,
                    "first conversion completes publication proof and cleanup before the second write")) return false;
            std::vector<std::byte> actual(expected.size());
            if (!Require(CB_Read(&fs, reader, actual.data(), 0, static_cast<ULONG>(actual.size()), &done) == STATUS_SUCCESS &&
                    done == actual.size() && actual == expected,
                    "already-open alias sees all original bytes and the accepted edit")) return false;
            // Keep both metadata-only opens alive across conversion. In
            // particular, never reopen the writer before its ordinary write.
            value = std::byte{'Y'};
            done = 999;
            if (!Require(CB_Write(&fs, writer, &value, fixture.eof - 1, 1, FALSE, FALSE, &done, &info) == STATUS_SUCCESS &&
                    done == 1, "same still-open writer performs a second bounded write with alias reader open")) return false;
            expected.back() = value;
            for (const auto handle : {writer, reader})
            {
                actual.assign(expected.size(), std::byte{0});
                if (!Require(CB_Read(&fs, handle, actual.data(), 0, static_cast<ULONG>(actual.size()), &done) == STATUS_SUCCESS &&
                        done == actual.size() && actual == expected,
                        "both still-open aliases see both edits and every untouched original byte")) return false;
            }
            if (!Require(CB_Flush(&fs, writer, &info) == STATUS_SUCCESS,
                    "second bounded write drains through the normal writer Flush")) return false;
            const auto marks = c.tx_manager->Watermarks();
            if (!Require(marks.accepted_sequence > first_marks.accepted_sequence && marks.accepted_sequence == marks.apfs_durable_sequence &&
                    marks.accepted_sequence == marks.cleanup_sequence,
                    "foreground callback finishes publication proof before journal cleanup")) return false;
        }
        Store fresh(fixture.fixture.volume);
        std::vector<std::byte> actual;
        if (!Require(fresh.PrepareNativeWritePath(), "independent native reload prepares")) return false;
        for (const auto path : {L"\\alias", L"\\compressed"})
            if (!Require(fresh.ReadCommittedFileRange(path, 0, expected.size(), actual) && actual == expected,
                    "independent native reload reads every accepted edit through both aliases")) return false;
        const auto after = fresh.LookupCommittedInodeByPath(L"\\compressed");
        if (!Require(after && after->object_id == initial->object_id && after->mode == initial->mode &&
                after->owner == initial->owner && after->group == initial->group &&
                after->create_time_utc == initial->create_time_utc && after->access_time_utc == initial->access_time_utc &&
                !(after->bsd_flags & apfsaccess::rw::kAppleBsdCompressedFlag) &&
                !fresh.LookupCommittedExtendedAttribute(initial->object_id, "com.apple.decmpfs"),
                "native conversion preserves Mac permissions and identity")) return false;
        const auto retained_fork = fresh.LookupCommittedExtendedAttribute(initial->object_id, "com.apple.ResourceFork");
        if (!Require(retained_fork.has_value() == (type != 4),
                "independent resource forks survive; only compression-owned forks retire")) return false;
    }
    return passed;
}
