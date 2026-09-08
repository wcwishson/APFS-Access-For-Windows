#pragma once
// Include after NativeCompressionReplayTests.h. All fixtures are regular files
// under the runner's D: TEMP/TMP; no mounted filesystem or worker is started.

bool TestNativeCompressionRestart256(bool tamper)
{
    using F = HostCompressionReplay222Fixture;
    using Tx = F::Tx;
    using Store = F::Store;
    using Spool = apfsaccess::rw::PayloadSpool;
    if (!CompressionReplay222ScratchReady()) return false;
    bool passed = true;
    for (const auto type : {1u, 3u, 4u})
    for (const auto policy : {L"FailClosed", L"BestEffort"})
    {
        std::wcerr << L"[INFO] compression restart 256: type=" << type
            << L" policy=" << policy << L" tamper=" << tamper << L'\n';
        F fixture;
        if (!Require(fixture.Initialize(type, true) && fixture.Publish(),
                "restart fixture accepts external WAL/spool writes and actually publishes conversion")) return false;
        auto& original = *fixture.owned.fixture.context;
        original.args.write_recovery_policy = policy;
        original.args.write_crash_replay_mode = L"ReplayIfSafe";
        original.runtime_last_commit_xid = original.metadata_store->CheckpointXid();
        if (!Require(fixture.Verify(*original.metadata_store) == F::Replay::Result::Verified &&
                ArmRecoveryMarkerForPendingWriteAheadLog(original, true),
                "original published conversion is valid and retains a real dirty recovery marker")) return false;

        const auto marks = original.tx_manager->Watermarks();
        const auto spool = original.payload_spool->SnapshotCounters();
        const auto wal_path = original.session_root / "accepted.wal";
        const auto spool_path = original.payload_spool->SpoolFilePath();
        const auto index_path = spool_path.parent_path() / "payload-spool.idx";
        const auto marker_path = original.recovery_marker_file;
        const auto wal_bytes = ReadFileBytes(wal_path);
        const auto spool_bytes = ReadFileBytes(spool_path);
        const auto index_bytes = ReadFileBytes(index_path);
        const auto marker_bytes = ReadFileBytes(marker_path);
        std::vector<std::uint64_t> pins;
        if (!Require(marks.accepted_sequence == fixture.sequence &&
                marks.accepted_sequence > marks.apfs_durable_sequence &&
                marks.accepted_sequence > marks.cleanup_sequence &&
                original.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(pins) &&
                pins == std::vector<std::uint64_t>{fixture.preimage} &&
                !wal_bytes.empty() && !spool_bytes.empty() && !index_bytes.empty() && !marker_bytes.empty() &&
                spool.dirty_range_count != 0 && spool.spool_bytes != 0,
                "restart begins with uncleaned accepted WAL, spool/index, preimage pin and marker")) return false;

        auto image = ReadFileBytes(fixture.owned.fixture.image.path);
        if (tamper)
        {
            // Locate the actual published default-data extent through the
            // native projection. Offset zero is untouched by every WAL write.
            apfsaccess::rw::NativeApfsVolumeProjection projection;
            std::wstring error;
            const auto inode = original.metadata_store->LookupCommittedInodeByPath(L"\\compressed");
            if (!Require(inode && apfsaccess::rw::NativeApfsReader::TryLoadVolumeProjection(
                    original.metadata_store->Device(), fixture.owned.fixture.volume.volume_object_id,
                    projection, error), "published conversion projects through NativeApfsReader")) return false;
            const auto found = projection.read_extents_by_inode.find(inode->object_id);
            if (!Require(found != projection.read_extents_by_inode.end() && !found->second.empty() &&
                    found->second.front().logical_offset == 0 && found->second.front().physical_address != 0 &&
                    found->second.front().physical_address < image.size(),
                    "published ordinary data has a bounded first physical extent")) return false;
            image[static_cast<std::size_t>(found->second.front().physical_address)] ^= std::byte{1};
        }

        // Allocate while the original still exists, then destroy the entire
        // original context (including its journal lease) before reopening any
        // image, WAL or spool. Copy paths/options only, never runtime guards.
        auto recovered = std::make_unique<MountContext>();
        recovered->args = original.args;
        recovered->session_root = original.session_root;
        recovered->cache_root = original.cache_root;
        recovered->recovery_marker_file = marker_path;
        ResetRecoveryMarkerCache(&original);
        fixture.owned.fixture.context.reset();
        fixture.owned.fixture.context = std::move(recovered);
        auto& c = *fixture.owned.fixture.context;
        if (tamper && !Require(WriteFileBytes(fixture.owned.fixture.image.path, image),
                "tamper only the published payload after releasing original device and journal handles")) return false;
        c.native_write_enabled = true;
        SeedRoot(c);
        std::array<std::byte, 16> security{};
        SeedSecurity(c, security);
        const auto startup = LoadRecoveryMarkerAtStartup(c);
        if (!Require(startup.load_status == RecoveryMarkerLoadStatus::Loaded && startup.state.dirty &&
                startup.action == LoadedRecoveryMarkerAction::ReplayIfSafe && c.native_write_enabled &&
                c.compression_verification_pending.load() == 0 && !c.unjournaled_native_mutation.load() &&
                !HasBlockedRecoveryEvidence(c),
                "new context admits production replay with no inherited compression/identity barrier")) return false;
        c.tx_journal_file = wal_path;
        c.tx_manager = std::make_unique<Tx>(L"Conservative");
        c.tx_manager->SetVolumeIdentity(L"directory-symlink-volume");
        c.tx_manager->SetJournalPath(wal_path.wstring());
        const auto reopened_marks = c.tx_manager->Watermarks();
        bool wal_pending = !c.tx_manager->RecoveryStateValid() || c.tx_manager->HasUnappliedAcceptedWork() ||
            reopened_marks.cleanup_sequence < reopened_marks.apfs_durable_sequence;
        if (!Require(wal_pending && ArmRecoveryMarkerForPendingWriteAheadLog(c, wal_pending),
                "fresh WAL startup discovers and arms pending accepted recovery")) return false;
        c.payload_spool_volume_identity = "directory-symlink-volume";
        c.payload_spool = std::make_unique<Spool>(Spool::Options{
            spool_path.parent_path(), c.payload_spool_volume_identity, 1024 * 1024});
        bool spool_pending = c.payload_spool->RecoveryRequired();
        c.owned_metadata_store = std::make_unique<Store>(fixture.owned.fixture.volume);
        c.metadata_store = c.owned_metadata_store.get();
        std::vector<Tx::AcceptedTransaction> accepted;
        if (!Require(c.metadata_store->PrepareNativeWritePath() &&
                c.metadata_store->IsCanonicalCommitReady() && !c.metadata_store->IsRecoveryRequired() &&
                c.metadata_store->PendingMutationCount() == 0 &&
                c.metadata_store->CheckpointXid() == fixture.preimage + 1 &&
                c.tx_manager->RecoveryStateValid() && c.tx_manager->CurrentState() == Tx::State::Idle &&
                c.tx_manager->LoadUnappliedAcceptedTransactions(accepted) && accepted.size() == 1 &&
                accepted.front().accepted_sequence == fixture.sequence &&
                accepted.front().preimage_checkpoint_xid == fixture.preimage && spool_pending,
                "fresh canonical metadata, accepted WAL and persisted spool load without structural damage")) return false;
        c.runtime_last_commit_xid = ResolveCleanRecoveryCheckpointXid(*c.metadata_store);

        const auto retained = [&](const char* phase) {
            const auto after = c.tx_manager->Watermarks();
            const auto after_spool = c.payload_spool->SnapshotCounters();
            std::vector<std::uint64_t> after_pins;
            std::vector<Tx::AcceptedTransaction> batches;
            RecoveryMarkerState marker{};
            return Require(after.accepted_sequence == marks.accepted_sequence &&
                after.apfs_durable_sequence == marks.apfs_durable_sequence &&
                after.cleanup_sequence == marks.cleanup_sequence &&
                c.tx_manager->RecoveryStateValid() &&
                c.tx_manager->LoadAcceptedTransactionsSinceCleanup(batches) && batches.size() == 1 &&
                batches.front().accepted_sequence == fixture.sequence &&
                c.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(after_pins) && after_pins == pins &&
                after_spool.spool_bytes == spool.spool_bytes && after_spool.dirty_range_count == spool.dirty_range_count &&
                wal_bytes == ReadFileBytes(wal_path) && spool_bytes == ReadFileBytes(spool_path) &&
                index_bytes == ReadFileBytes(index_path) && marker_bytes == ReadFileBytes(marker_path) &&
                TryLoadRecoveryMarkerState(marker_path, marker) && marker.dirty &&
                image == ReadFileBytes(fixture.owned.fixture.image.path) &&
                c.metadata_store->CheckpointXid() == fixture.preimage + 1 &&
                c.metadata_store->PendingMutationCount() == 0, phase);
        };
        if (!retained("fresh reopening preserves every accepted/durable/cleanup mark and evidence byte")) return false;
        std::vector<std::byte> expected = fixture.expected, content;
        if (tamper) expected.front() ^= std::byte{1};
        if (!Require(c.metadata_store->ReadCommittedFileRange(L"\\compressed", 0, expected.size(), content) &&
                content == expected && content[1] == std::byte{'Z'} && content.back() == std::byte{'Y'} &&
                F::Replay::Verify(*c.metadata_store, *c.tx_manager, fixture.sequence,
                    c.payload_spool.get(), c.payload_spool_volume_identity) ==
                    (tamper ? F::Replay::Result::ContentMismatch : F::Replay::Result::Verified),
                "fresh proof checks genuine published bytes, including the untouched byte and accepted edits")) return false;

        // Mirror the production bootstrap caller: replay first, update pending
        // flags only on success, then reconcile spool followed by WAL.
        const bool replayed = c.native_write_enabled && ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(c);
        if (tamper && !Require(!replayed &&
                c.runtime_recovery_reason == L"AcceptedReplayPreimageCheckpointMismatch",
                "production bootstrap reaches real publication-proof refusal, not a spool/structure error")) return false;
        if (replayed)
        {
            wal_pending = false;
            spool_pending = c.payload_spool->RecoveryRequired();
        }
        ReconcilePayloadSpoolRecoveryAfterMetadataBootstrap(c, spool_pending);
        ReconcileWriteAheadLogRecoveryAfterMetadataBootstrap(c, wal_pending);
        if (!Require(replayed == !tamper, "production bootstrap accepts only the unmodified publication")) return false;
        if (!Require(MergeCommittedInodeStateIntoNodeIndex(&c), "fresh callback namespace loads committed aliases")) return false;
        auto fs = BuildFileSystem(&c);
        PVOID reader = nullptr;
        FSP_FSCTL_FILE_INFO info{};
        ScopeExit close{[&] { if (reader) CB_Close(&fs, reader); }};
        if (!Require(CB_Open(&fs, const_cast<PWSTR>(L"\\alias"), FILE_OPEN << 24,
                GENERIC_READ, &reader, &info) == STATUS_SUCCESS && reader,
                "fresh recovered context opens the surviving alias through callbacks")) return false;
        if (tamper)
        {
            const auto blocked = [&](const char* phase) {
                return retained(phase) && Require(c.write_degraded && c.recovery_active && c.pending_native_writes &&
                    !c.native_write_enabled && !c.overlay_write_enabled && !IsMutationWriteEnabled(&c) &&
                    RequiresNativeApfsCheckpoint(&c) && c.compression_verification_pending.load() == 0,
                    "both policies block publication using recovered WAL debt, without a foreground OID guard");
            };
            passed &= blocked("failed bootstrap retains exact WAL, spool/index, pins, marker and watermarks");
            std::byte byte{'Q'};
            ULONG done = 999;
            passed &= Require(CB_Write(&fs, reader, &byte, 1, 1, FALSE, FALSE, &done, &info) ==
                    STATUS_MEDIA_WRITE_PROTECTED && done == 0,
                    "subsequent Write is blocked by volume admission before per-handle access checks");
            PVOID writer = nullptr;
            const auto open_status = CB_Open(&fs, const_cast<PWSTR>(L"\\compressed"), FILE_OPEN << 24,
                GENERIC_READ | GENERIC_WRITE, &writer, &info);
            if (writer) CB_Close(&fs, writer);
            passed &= Require(open_status == STATUS_MEDIA_WRITE_PROTECTED && !writer,
                "subsequent writable Open is disabled under both recovery policies");
            passed &= blocked("refused writes preserve all restart evidence");
            (void)CB_Flush(&fs, reader, &info);
            (void)CB_Flush(&fs, nullptr, nullptr);
            passed &= blocked("file and volume Flush preserve all restart evidence");
            passed &= Require(CommitNativeMutationsOnFlushBestEffort(&c) == STATUS_MEDIA_WRITE_PROTECTED &&
                    CommitNativeMutationsBestEffort(&c, L"CompressionRestart256") == STATUS_MEDIA_WRITE_PROTECTED,
                    "ordinary native drains cannot convert NothingToCommit into publication authority");
            passed &= blocked("native drains preserve all restart evidence");
            passed &= Require(!FinalizeMutationJournalBestEffort(&c, L"CompressionRestart256"),
                "ordinary finalization refuses unproven accepted restart work");
            passed &= blocked("finalization preserves all restart evidence");
            CB_Close(&fs, reader); reader = nullptr;
            passed &= blocked("normal Close preserves all restart evidence");
            if (!Require(c.fs == nullptr && ShouldRunNativeShutdownFinalDrain(c),
                    "unmounted test context enters the production shutdown drain")) return false;
            passed &= Require(RunFsHostShutdownDrain(fixture.owned.fixture.context) == 10,
                "normal shutdown reports native drain failure for refused restart publication");
            passed &= blocked("normal shutdown preserves exact accepted/durable/cleanup marks and recovery evidence");
        }
        else
        {
            const auto clean = [&]() {
                const auto after = c.tx_manager->Watermarks();
                const auto after_spool = c.payload_spool->SnapshotCounters();
                std::vector<std::uint64_t> after_pins;
                std::vector<Tx::AcceptedTransaction> batches;
                RecoveryMarkerState marker{};
                return Require(after.accepted_sequence == marks.accepted_sequence &&
                    after.apfs_durable_sequence == marks.accepted_sequence && after.cleanup_sequence == marks.accepted_sequence &&
                    c.tx_manager->CanClearRecoveryState() &&
                    c.tx_manager->LoadAcceptedTransactionsSinceCleanup(batches) && batches.empty() &&
                    c.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(after_pins) && after_pins.empty() &&
                    after_spool.spool_bytes == 0 && after_spool.dirty_range_count == 0 &&
                    ReadFileBytes(spool_path).empty() && !c.payload_spool->RecoveryRequired() &&
                    TryLoadRecoveryMarkerState(marker_path, marker) && !marker.dirty &&
                    !c.recovery_active && !c.pending_native_writes && !c.write_degraded &&
                    c.native_write_enabled && IsMutationWriteEnabled(&c) &&
                    image == ReadFileBytes(fixture.owned.fixture.image.path),
                    "verified fresh recovery retires evidence and pins, converges marks and preserves native writes");
            };
            passed &= clean();
            content.assign(expected.size(), std::byte{});
            ULONG done = 0;
            passed &= Require(CB_Read(&fs, reader, content.data(), 0, static_cast<ULONG>(content.size()), &done) ==
                    STATUS_SUCCESS && done == content.size() && content == expected &&
                    CB_Flush(&fs, reader, &info) == STATUS_SUCCESS &&
                    CommitNativeMutationsOnFlushBestEffort(&c) == STATUS_SUCCESS &&
                    FinalizeMutationJournalBestEffort(&c, L"CompressionRestart256Success"),
                    "genuine fresh recovery supports alias reads, Flush, native drain and finalization");
            CB_Close(&fs, reader); reader = nullptr;
            if (!Require(c.fs == nullptr, "success control has no mounted filesystem")) return false;
            passed &= Require(RunFsHostShutdownDrain(fixture.owned.fixture.context) == 0,
                "genuine fresh recovery completes normal shutdown successfully");
            passed &= clean();
        }
    }
    return passed;
}
