#pragma once

// Reopen the actual failed callback's accepted WAL and spool using the same
// bootstrap sequence as NativeCompressionRestartTests.h, without runtime guards
// inherited from its original context. The caller has already closed aliases.
bool HostCompressionWriteRecoverAccepted(HostCompressionRewrite211Fixture& fixture,
    const std::vector<std::byte>& expected, bool already_published = true)
{
    using Store = apfsaccess::rw::MetadataStore;
    using Tx = apfsaccess::rw::TransactionManager;
    using Spool = apfsaccess::rw::PayloadSpool;
    auto& original = *fixture.fixture.context;
    const auto marks = original.tx_manager->Watermarks();
    const auto image = ReadFileBytes(fixture.fixture.image.path);
    const auto wal_path = original.session_root / "accepted.wal";
    const auto spool_path = original.payload_spool->SpoolFilePath();
    const auto wal_bytes = ReadFileBytes(wal_path);
    const auto spool_bytes = ReadFileBytes(spool_path);
    auto recovered = std::make_unique<MountContext>();
    recovered->args = original.args;
    recovered->args.write_crash_replay_mode = L"ReplayIfSafe";
    recovered->session_root = original.session_root;
    recovered->cache_root = original.cache_root;
    recovered->recovery_marker_file = original.recovery_marker_file;
    ResetRecoveryMarkerCache(&original);
    fixture.fixture.context.reset();
    fixture.fixture.context = std::move(recovered);
    auto& c = *fixture.fixture.context;
    c.native_write_enabled = true;
    SeedRoot(c);
    std::array<std::byte, 16> security{};
    SeedSecurity(c, security);
    const auto startup = LoadRecoveryMarkerAtStartup(c);
    if (!Require(startup.load_status == RecoveryMarkerLoadStatus::Loaded && startup.state.dirty &&
            startup.action == LoadedRecoveryMarkerAction::ReplayIfSafe && c.native_write_enabled &&
            c.compression_verification_pending.load() == 0 && !HasBlockedRecoveryEvidence(c),
            "modern callback recovery starts fresh from the persisted dirty marker")) return false;
    c.tx_journal_file = wal_path;
    c.tx_manager = std::make_unique<Tx>(L"Conservative");
    c.tx_manager->SetVolumeIdentity(L"directory-symlink-volume");
    c.tx_manager->SetJournalPath(wal_path.wstring());
    bool wal_pending = c.tx_manager->HasUnappliedAcceptedWork();
    if (!Require(wal_pending && ArmRecoveryMarkerForPendingWriteAheadLog(c, wal_pending),
            "modern restart rediscovers real accepted callback WAL")) return false;
    c.payload_spool_volume_identity = "directory-symlink-volume";
    c.payload_spool = std::make_unique<Spool>(Spool::Options{
        spool_path.parent_path(), c.payload_spool_volume_identity, 1024 * 1024});
    bool spool_pending = c.payload_spool->RecoveryRequired();
    c.owned_metadata_store = std::make_unique<Store>(fixture.fixture.volume);
    c.metadata_store = c.owned_metadata_store.get();
    // Match startup before replay: journal payloads are materialized into the
    // new session's hydration store, then read through these production helpers.
    c.metadata_store->SetFilePayloadProvider([&c](const std::wstring& path, std::uint64_t size) {
        return LoadHydratedPayloadForPath(&c, path, size, false);
    });
    c.metadata_store->SetFilePayloadRangeProvider([&c](const std::wstring& path,
        Store::PayloadIdentity identity, std::uint64_t offset, std::span<std::byte> bytes) {
        return ReadHydratedPayloadRangeForPath(&c, path, identity, offset, bytes);
    });
    std::vector<Tx::AcceptedTransaction> batches;
    if (!Require(c.metadata_store->PrepareNativeWritePath() && c.metadata_store->IsCanonicalCommitReady() &&
            c.tx_manager->RecoveryStateValid() && spool_pending &&
            c.tx_manager->LoadUnappliedAcceptedTransactions(batches) && batches.size() == 1 &&
            batches.front().accepted_sequence == marks.accepted_sequence &&
            wal_bytes == ReadFileBytes(wal_path) && spool_bytes == ReadFileBytes(spool_path) &&
            apfsaccess::fshost::NativeCompressionReplay::Verify(*c.metadata_store, *c.tx_manager,
                marks.accepted_sequence, c.payload_spool.get(), c.payload_spool_volume_identity) ==
                (already_published ? apfsaccess::fshost::NativeCompressionReplay::Result::Verified :
                    apfsaccess::fshost::NativeCompressionReplay::Result::HistoryUnsupported) &&
            c.metadata_store->CheckpointXid() == batches.front().preimage_checkpoint_xid + (already_published ? 1 : 0),
            "fresh recovery distinguishes the original preimage from a proven published conversion")) return false;
    const auto expected_checkpoint = batches.front().preimage_checkpoint_xid + 1;
    c.runtime_last_commit_xid = ResolveCleanRecoveryCheckpointXid(*c.metadata_store);
    if (!Require(ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(c),
            "production bootstrap recovers the real interrupted modern callback")) return false;
    wal_pending = false;
    spool_pending = c.payload_spool->RecoveryRequired();
    ReconcilePayloadSpoolRecoveryAfterMetadataBootstrap(c, spool_pending);
    ReconcileWriteAheadLogRecoveryAfterMetadataBootstrap(c, wal_pending);
    const auto after = c.tx_manager->Watermarks();
    const auto spool = c.payload_spool->SnapshotCounters();
    std::vector<std::uint64_t> pins;
    RecoveryMarkerState marker{};
    if (!Require(after.accepted_sequence == marks.accepted_sequence &&
            after.apfs_durable_sequence == marks.accepted_sequence && after.cleanup_sequence == marks.accepted_sequence &&
            c.tx_manager->CanClearRecoveryState() && c.tx_manager->LoadAcceptedTransactionsSinceCleanup(batches) && batches.empty() &&
            c.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(pins) && pins.empty() &&
            spool.spool_bytes == 0 && spool.dirty_range_count == 0 && ReadFileBytes(spool_path).empty() &&
            !c.payload_spool->RecoveryRequired() && TryLoadRecoveryMarkerState(c.recovery_marker_file, marker) && !marker.dirty &&
            !c.recovery_active && !c.pending_native_writes && !c.write_degraded && IsMutationWriteEnabled(&c) &&
            c.metadata_store->CheckpointXid() == expected_checkpoint &&
            (already_published ? image == ReadFileBytes(fixture.fixture.image.path) :
                image != ReadFileBytes(fixture.fixture.image.path)) && MergeCommittedInodeStateIntoNodeIndex(&c),
            "verified modern recovery publishes only when needed and cleans WAL debt, spool and pins")) return false;
    auto fs = BuildFileSystem(&c);
    for (const auto path : {L"\\compressed", L"\\alias"})
    {
        PVOID reader = nullptr;
        FSP_FSCTL_FILE_INFO info{};
        ScopeExit close{[&] { if (reader) CB_Close(&fs, reader); }};
        std::vector<std::byte> actual(expected.size(), std::byte{0xa6});
        ULONG done = 999;
        if (!Require(CB_Open(&fs, const_cast<PWSTR>(path), FILE_OPEN << 24, GENERIC_READ, &reader, &info) == STATUS_SUCCESS &&
                reader && CB_Read(&fs, reader, actual.data(), 0, static_cast<ULONG>(actual.size()), &done) == STATUS_SUCCESS &&
                done == actual.size() && actual == expected && CB_Flush(&fs, reader, &info) == STATUS_SUCCESS,
                "fresh recovered callbacks read all independently expected bytes through both aliases")) return false;
    }
    return true;
}

bool TestNativeCompressionWriteCallbacks(bool interrupted = false, unsigned only_type = 0)
{
    using Store = apfsaccess::rw::MetadataStore;
    using Tx = apfsaccess::rw::TransactionManager;
    if (!CompressionReplay222ScratchReady()) return false;
    bool passed = true;
    for (const auto type : only_type ? std::vector<unsigned>{only_type} : std::vector<unsigned>{1u, 3u, 4u})
    for (unsigned variant = 0; variant < (interrupted ? 4u : 2u); ++variant)
    {
        const bool archive_refusal = !interrupted && variant == 1;
        HostCompressionRewrite211Fixture fixture;
        const bool modern = type >= 7 && type <= 14;
        if (!Require(fixture.Initialize(type, false, false, modern, archive_refusal),
                "foreground rewrite fixture initializes")) return false;
        auto& c = *fixture.fixture.context;
        c.args.write_recovery_policy = interrupted && (variant & 1) ? L"BestEffort" : L"FailClosed";
        auto fs = BuildFileSystem(&c);
        const auto initial = c.metadata_store->LookupCommittedInodeByPath(L"\\compressed");
        std::vector<std::byte> expected;
        if (!Require(initial && c.metadata_store->ReadCommittedFileRange(L"\\compressed", 0,
                fixture.eof, expected) && expected == fixture.expected_source,
                "complete original compressed bytes match an independent expected vector")) return false;
        const auto finder = c.metadata_store->LookupCommittedExtendedAttribute(initial->object_id, "com.apple.FinderInfo");
        const auto mac_security = c.metadata_store->LookupCommittedExtendedAttribute(initial->object_id, kAppleSecurityName);
        const auto independent_fork = c.metadata_store->LookupCommittedExtendedAttribute(initial->object_id, "com.apple.ResourceFork");
        const auto source_image = ReadFileBytes(fixture.fixture.image.path);
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
            if (!Require(refused_status == STATUS_NOT_SUPPORTED && refused_done == 0 && refused == std::byte{'R'} &&
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
            if (fixture.fixture.context->metadata_store) fixture.fixture.context->metadata_store->SetCommitStageHook({});
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
        if (!Require(retained_fork.has_value() == !fixture.UsesResourceFork(type),
                "independent resource forks survive; only compression-owned forks retire")) return false;
        const auto same_attribute = [](const auto& before, const auto& after) {
            return before.has_value() == after.has_value() &&
                (!before || (before->flags == after->flags && before->data == after->data));
        };
        const auto published_image = ReadFileBytes(fixture.fixture.image.path);
        if (!Require(same_attribute(finder, fresh.LookupCommittedExtendedAttribute(initial->object_id, "com.apple.FinderInfo")) &&
                same_attribute(mac_security, fresh.LookupCommittedExtendedAttribute(initial->object_id, kAppleSecurityName)) &&
                (fixture.UsesResourceFork(type) || same_attribute(independent_fork, retained_fork)) &&
                (!modern || (source_image.size() >= 104 * 4096 && published_image.size() >= 104 * 4096 &&
                    std::equal(source_image.begin() + 103 * 4096, source_image.begin() + 104 * 4096,
                        published_image.begin() + 103 * 4096))),
                "conversion preserves Finder/security metadata and external Finder source block 103 exactly")) return false;
        std::array<std::byte, 32> finder_bytes{};
        std::size_t read = 0;
        if (!Require(fresh.ReadCommittedExtendedAttributeRange(initial->object_id, "com.apple.FinderInfo", 0, finder_bytes, read) &&
                read == finder_bytes.size() && std::all_of(finder_bytes.begin(), finder_bytes.end(),
                    [](auto byte) { return byte == std::byte{0x46}; }),
                "preserved embedded or external FinderInfo remains readable byte for byte")) return false;
        if (!fixture.UsesResourceFork(type))
        {
            std::array<std::byte, 3> fork_bytes{};
            if (!Require(fresh.ReadCommittedExtendedAttributeRange(initial->object_id, "com.apple.ResourceFork", 0, fork_bytes, read) &&
                    read == fork_bytes.size() && fork_bytes == std::array<std::byte, 3>{std::byte{0x46}, std::byte{0x00}, std::byte{0x80}},
                    "independent opaque Mac resource bytes survive inline conversion exactly")) return false;
        }
        if (interrupted && modern && !HostCompressionWriteRecoverAccepted(fixture, expected)) return false;
    }
    return passed;
}
