#pragma once

bool TestDeferredManifestTimestamps(const std::string& boundary)
{
    using Store = apfsaccess::rw::MetadataStore;
    using Tx = apfsaccess::rw::TransactionManager;
    using Wal = apfsaccess::rw::WriteAheadLog;
    std::array<wchar_t, 32> previous{};
    const auto previous_size = GetEnvironmentVariableW(L"APFSACCESS_DEFER_CLOSE_COMMITS",
        previous.data(), static_cast<DWORD>(previous.size()));
    SetEnvironmentVariableW(L"APFSACCESS_DEFER_CLOSE_COMMITS", L"1");
    ScopeExit restore{[&] { SetEnvironmentVariableW(L"APFSACCESS_DEFER_CLOSE_COMMITS",
        previous_size ? previous.data() : nullptr); }};
    DirectorySymlinkFixture fixture(true);
    if (!fixture.Initialize(true, boundary == "replay")) return false;
    auto& c = *fixture.context;
    c.args.write_max_dirty_transactions = 128;
    auto fs = BuildFileSystem(&c);
    PVOID handle = nullptr, reader = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    const auto path = L"\\timestamps.bin";
    if (!Require(CB_Create(&fs, const_cast<PWSTR>(path), FILE_NON_DIRECTORY_FILE,
            FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES, FILE_ATTRIBUTE_ARCHIVE,
            nullptr, 0, &handle, &info) == STATUS_SUCCESS,
            "timestamps: initial inode is published")) return false;
    ScopeExit close{[&] {
        c.tx_manager->SetJournalFaultInjectionHook({});
        c.metadata_store->SetCommitStageHook({});
        if (reader) CB_Close(&fs, reader);
        if (handle) CB_Close(&fs, handle);
    }};
    auto* open = static_cast<OpenContext*>(handle);
    const auto node = open->node;
    const auto preimage = c.metadata_store->CheckpointXid().value_or(0);
    const auto old_inode = c.metadata_store->LookupCommittedInodeByPath(path);
    auto payload = BuildPatternPayloadForTest(16384, 0x62);
    ULONG written = 0;
    if (!Require(CB_Write(&fs, handle, payload.data(), 0, static_cast<ULONG>(payload.size()),
            FALSE, FALSE, &written, &info) == STATUS_SUCCESS && written == payload.size() &&
            c.tx_manager->HasUnappliedAcceptedWork() && c.metadata_store->CheckpointXid() == preimage,
            "timestamps: real Write is accepted without publication")) return false;
    const auto before = c.tx_manager->Watermarks();
    const auto flushes = c.tx_manager->DeferredWalGroupFlushCount();
    const auto original_times = VisibleInodeTimes(*node);
    const auto changed = original_times.modification_time_utc + 10000000;
    auto expected_times = original_times;
    expected_times.modification_time_utc = changed;
    unsigned publications = 0, wal_flushes = 0;
    c.metadata_store->SetCommitStageHook([&](std::string_view stage) {
        if (stage == "before-apple-publish") ++publications;
        return true;
    });
    c.tx_manager->SetJournalFaultInjectionHook([&](std::string_view stage) {
        if (stage != "durable-flush") return false;
        ++wal_flushes;
        if (boundary == "snapshot-during-ack" && old_inode)
        {
            std::lock_guard<std::mutex> lock(c.mutex);
            ApplyCommittedInodeMetadataToNode(&c, *old_inode, node->timestamp, node, FILE_ATTRIBUTE_ARCHIVE);
        }
        return boundary == "wal-failure";
    });
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    const auto set_times = [&] {
        status = CB_SetBasicInfo(&fs, handle, INVALID_FILE_ATTRIBUTES, 0, 0, changed, 0, &info);
    };
    if (boundary == "snapshot")
    {
        std::shared_ptr<Node> root;
        {
            std::lock_guard<std::mutex> lock(c.mutex);
            root = TryGetNodeLockedNormalized(&c, L"\\");
        }
        if (!Require(root && c.namespace_checkpoint_xid == preimage,
                "timestamps: directory snapshot starts at the accepted write preimage")) return false;
        c.test_before_namespace_snapshot_apply = set_times;
        if (!Require(MergeCommittedDirectoryChildrenIntoNodeIndex(&c, root),
                "timestamps: apply same-checkpoint snapshot captured before SetBasicInfo")) return false;
    }
    else set_times();
    c.tx_manager->SetJournalFaultInjectionHook({});
    if (boundary == "count" || boundary == "baseline-count")
    {
        const bool baseline = boundary == "baseline-count";
        const auto after_basic = publications;
        CB_Cleanup(&fs, handle, const_cast<PWSTR>(path), FspCleanupSetLastWriteTime | FspCleanupSetChangeTime);
        const auto after_cleanup = publications;
        const auto visible = VisibleInodeTimes(*node);
        const auto flush_status = CB_Flush(&fs, handle, &info);
        const auto committed = c.metadata_store->LookupCommittedInodeByPath(path);
        std::vector<std::byte> bytes;
        const auto final = c.tx_manager->Watermarks();
        std::cerr << "[timestamp-count] baseline=" << baseline << " create=1 write=0 basic=" << after_basic
            << " cleanup=" << after_cleanup - after_basic << " terminal=" << publications - after_cleanup
            << " total=" << publications + 1 << '\n';
        return Require(status == STATUS_SUCCESS && flush_status == STATUS_SUCCESS &&
                after_basic == (baseline ? 1u : 0u) && after_cleanup == (baseline ? 2u : 0u) &&
                publications == (baseline ? 2u : 1u) && committed &&
                committed->modification_time_utc == visible.modification_time_utc &&
                committed->change_time_utc == visible.change_time_utc &&
                c.metadata_store->ReadCommittedFileRange(path, 0, payload.size(), bytes) && bytes == payload &&
                final.accepted_sequence == final.cleanup_sequence && c.native_write_enabled && !c.recovery_active,
                "timestamps: identical copy callback sequence preserves bytes/times with measured publications");
    }
    if (boundary == "wal-failure")
        return Require(!NT_SUCCESS(status) && wal_flushes != 0 && publications == 0 &&
                c.metadata_store->CheckpointXid() == preimage &&
                VisibleInodeTimes(*node) == original_times && !c.native_write_enabled &&
                c.tx_manager->Watermarks().cleanup_sequence <= before.apfs_durable_sequence &&
                c.metadata_store->PendingMutationCount() != 0,
                "timestamps: failed durable acknowledgement retains debt and exposes no new times");

    const auto accepted = c.tx_manager->Watermarks();
    if (!Require(status == STATUS_SUCCESS && publications == 0 &&
            accepted.accepted_sequence > before.accepted_sequence &&
            accepted.apfs_durable_sequence == before.apfs_durable_sequence &&
            c.tx_manager->DeferredWalGroupFlushCount() > flushes && wal_flushes != 0 &&
            node->times_generation > preimage && node->file_size == payload.size() &&
            VisibleInodeTimes(*node) == expected_times,
            "timestamps: callback waits for durable WAL, propagates generation, and retains visible EOF")) return false;
    std::vector<Tx::AcceptedTransaction> transactions;
    std::string error;
    if (!Require(c.tx_manager->LoadUnappliedAcceptedTransactions(transactions, &error) &&
            !transactions.empty(), "timestamps: accepted WAL is readable")) return false;
    const auto& last = transactions.back();
    apfsaccess::rw::InodeMetadataPatch patch;
    if (!Require(last.preimage_checkpoint_xid == preimage && last.mutations.size() == 1 &&
            last.mutations[0].operation == Wal::OperationKind::SetInodeMetadata &&
            last.mutations[0].object_id == node->object_id &&
            last.mutations[0].parent_object_id == node->times_generation &&
            apfsaccess::rw::DecodeInodeMetadataPatch(last.mutations[0].inline_payload, patch) &&
            patch.mask == apfsaccess::rw::InodeMetadataPatch::ModificationTime &&
            patch.modification_time_utc == changed,
            "timestamps: WAL binds the exact inode, staged generation, source checkpoint, and patch")) return false;
    if (!Require(CB_Open(&fs, const_cast<PWSTR>(path), FILE_NON_DIRECTORY_FILE,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES, &reader, &info) == STATUS_SUCCESS &&
            info.FileSize == payload.size() && info.LastWriteTime == changed &&
            info.CreationTime == expected_times.create_time_utc &&
            info.ChangeTime == expected_times.change_time_utc &&
            info.LastAccessTime == expected_times.access_time_utc,
            "timestamps: another handle observes pending EOF and timestamps")) return false;
    std::vector<std::byte> observed(payload.size());
    ULONG read = 0;
    if (!Require(CB_Read(&fs, reader, observed.data(), 0, static_cast<ULONG>(observed.size()), &read) ==
            STATUS_SUCCESS && read == payload.size() && observed == payload,
            "timestamps: another handle reads accepted payload before publication")) return false;
    CB_Close(&fs, reader);
    reader = nullptr;

    CB_Cleanup(&fs, handle, const_cast<PWSTR>(path), FspCleanupSetLastWriteTime | FspCleanupSetChangeTime);
    const auto cleanup_times = VisibleInodeTimes(*node);
    if (!Require(publications == 0 && c.metadata_store->CheckpointXid() == preimage &&
            c.tx_manager->Watermarks().accepted_sequence > accepted.accepted_sequence && open->cleanup_seen,
            "timestamps: writer Cleanup continues accepted Write without publication")) return false;
    if (boundary == "close")
    {
        CB_Close(&fs, handle);
        handle = nullptr;
    }
    else if (boundary == "shutdown")
    {
        if (!Require(BeginMutationShutdownDrain(&c) && StopDeferredCommitWorker(&c) &&
                DrainNativeMutationsByPolicy(&c, L"Shutdown") == STATUS_SUCCESS &&
                FinalizeMutationJournalBestEffort(&c, L"Shutdown"),
                "timestamps: quit drain publishes accepted write and cleanup metadata")) return false;
    }
    else if (boundary == "replay")
    {
        // Discard the unpublished store and reopen this fixture's journal/spool.
        c.container_session_contexts = {&c};
        if (!Require(c.metadata_store->PrepareNativeWritePath(),
                "timestamps: replay bootstrap discards volatile staging")) return false;
        c.tx_manager.reset();
        c.tx_manager = std::make_unique<Tx>(L"Conservative");
        if (!Require(c.tx_manager->OpenStartupJournal((c.session_root / "accepted.wal").wstring(),
                L"directory-symlink-volume", error), "timestamps: reopen accepted fixture WAL")) return false;
        c.payload_spool.reset();
        c.payload_spool = std::make_unique<apfsaccess::rw::PayloadSpool>(apfsaccess::rw::PayloadSpool::Options{
            c.session_root / "payload-spool", c.payload_spool_volume_identity, 1024 * 1024});
        if (!ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(c))
        {
            std::wcerr << L"[timestamps replay] reason=" << c.runtime_recovery_reason
                << L" action=" << c.runtime_last_recovery_action << '\n';
            return Require(false, "timestamps: replay reconstructs Write and both timestamp continuations");
        }
    }
    else if (!Require(CB_Flush(&fs, handle, &info) == STATUS_SUCCESS,
            "timestamps: Flush publishes accepted write and cleanup metadata")) return false;
    const auto committed = c.metadata_store->LookupCommittedInodeByPath(path);
    std::vector<std::byte> bytes;
    const auto final = c.tx_manager->Watermarks();
    if (!Require(publications == 1 && committed && committed->logical_size == payload.size() &&
            committed->create_time_utc == cleanup_times.create_time_utc &&
            committed->modification_time_utc == cleanup_times.modification_time_utc &&
            committed->change_time_utc == cleanup_times.change_time_utc &&
            committed->access_time_utc == cleanup_times.access_time_utc &&
            c.metadata_store->ReadCommittedFileRange(path, 0, payload.size(), bytes) && bytes == payload &&
            final.accepted_sequence == final.apfs_durable_sequence && final.apfs_durable_sequence == final.cleanup_sequence &&
            c.metadata_store->PendingMutationCount() == 0 && ManifestQueuedRequestCount(&c) == 0 &&
            c.native_write_enabled && !c.write_degraded && !c.recovery_active,
            "timestamps: one terminal publication commits exact payload/times and cleans WAL debt")) return false;
    if (boundary == "replay")
    {
        const auto image = ReadFileBytes(fixture.image.path);
        return Require(ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(c) && publications == 1 &&
                image == ReadFileBytes(fixture.image.path),
                "timestamps: repeated startup replay is idempotent");
    }
    return true;
}

bool TestDeferredManifestTimestampFallback(const std::string& kind)
{
    using Store = apfsaccess::rw::MetadataStore;
    using Operation = Store::MutationOperation;
    SetEnvironmentVariableW(L"APFSACCESS_DEFER_CLOSE_COMMITS", L"1");
    ScopeExit restore{[] { SetEnvironmentVariableW(L"APFSACCESS_DEFER_CLOSE_COMMITS", nullptr); }};
    DirectorySymlinkFixture fixture(true);
    if (!fixture.Initialize(true)) return false;
    auto& c = *fixture.context;
    c.args.write_max_dirty_transactions = 128;
    auto fs = BuildFileSystem(&c);
    PVOID handle = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    const auto path = L"\\fallback.bin";
    if (!Require(CB_Create(&fs, const_cast<PWSTR>(path), FILE_NON_DIRECTORY_FILE,
            FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES, FILE_ATTRIBUTE_ARCHIVE,
            nullptr, 0, &handle, &info) == STATUS_SUCCESS, "timestamp fallback: create")) return false;
    ScopeExit close{[&] { CB_Close(&fs, handle); }};
    Store::MutationRequest extra;
    extra.path = path;
    if (kind == "create") { extra.operation = Operation::CreateFile; extra.path = L"\\other.bin"; }
    else if (kind == "resize") { extra.operation = Operation::SetFileSize; extra.length = 4096; }
    else if (kind == "allocation") { extra.operation = Operation::SetAllocationSize; extra.length = 4096; }
    else if (kind == "xattr")
    {
        extra.operation = Operation::SetExtendedAttribute;
        extra.secondary_path = L"user.timestamp-test";
        extra.inline_payload = {std::byte{7}, std::byte{8}};
        extra.length = extra.inline_payload.size();
    }
    else if (kind == "security")
    {
        extra.operation = Operation::SetInodeMetadata;
        apfsaccess::rw::InodeMetadataPatch patch;
        patch.mask = apfsaccess::rw::InodeMetadataPatch::Mode;
        patch.mode = 0600;
        if (!apfsaccess::rw::EncodeInodeMetadataPatch(patch, extra.inline_payload)) return false;
        extra.length = extra.inline_payload.size();
    }
    const bool no_write = kind == "no-write";
    const bool attributes = kind == "attributes";
    if (!no_write)
    {
        if (!attributes) EnqueueManifestRequest(&c, extra);
        Store::MutationRequest write;
        write.operation = Operation::Write; write.path = path; write.length = 4096;
        std::vector<std::byte> bytes(4096, std::byte{0x71});
        EnqueueManifestRequest(&c, write);
        if (!Require(AcceptQueuedManifestWritesWithWalBestEffort(&c, path, 0, bytes.data(),
                static_cast<std::uint32_t>(bytes.size()), L"TimestampFallbackSeed") == ManifestWriteBatchResult::Accepted,
                "timestamp fallback: real accepted mixed batch")) return false;
        if (!attributes && !Require(!c.metadata_store->PendingWriteTimestampIdentity(path,
                static_cast<OpenContext*>(handle)->node->object_id),
                "timestamp fallback: pending create/resize/security/xattr cannot continue")) return false;
    }
    const auto before = c.metadata_store->CheckpointXid();
    const auto count = fixture.coordinator->DiagnosticsSnapshot(101).commit_deferred_acceptances;
    const auto requested = ToFileTimeValue(UtcNow()) + 10000000;
    if (!Require(CB_SetBasicInfo(&fs, handle, attributes ? FILE_ATTRIBUTE_HIDDEN : INVALID_FILE_ATTRIBUTES,
            0, 0, requested, 0, &info) == STATUS_SUCCESS,
            "timestamp fallback: original synchronous callback succeeds")) return false;
    const auto inode = c.metadata_store->LookupCommittedInodeByPath(path);
    const auto marks = c.tx_manager->Watermarks();
    return Require(c.metadata_store->CheckpointXid() > before && inode && inode->modification_time_utc == requested &&
            fixture.coordinator->DiagnosticsSnapshot(101).commit_deferred_acceptances == count &&
            marks.accepted_sequence == marks.cleanup_sequence && c.metadata_store->PendingMutationCount() == 0,
            "timestamp fallback: publishes completely instead of widening eligibility");
}
