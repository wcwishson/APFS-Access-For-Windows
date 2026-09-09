#pragma once

bool TestDirectNativeStartupTopology()
{
    for (const bool single_volume : {false, true})
    {
        DirectorySymlinkFixture fixture(false);
        auto spec = TwoProjectableVolumeStore();
        if (single_volume) spec.volumes.resize(1);
        spec.authoritative_checkpoint = true;
        spec.authoritative_checkpoint_ring_blocks = 16;
        spec.authoritative_internal_pool_blocks = 16;
        if (!Require(WriteFileBytes(fixture.image.path, apfsaccess::testfixture::BuildStoreImage(spec)),
                "startup topology image is created")) return false;
        auto& c = *fixture.context;
        fixture.volume.device_path = fixture.image.path.wstring();
        fixture.volume.volume_object_id = 101;
        fixture.volume.allow_legacy_scaffold_for_fixtures = false;
        c.owned_metadata_store = std::make_unique<DirectorySymlinkFixture::Store>(fixture.volume);
        c.metadata_store = c.owned_metadata_store.get();
        c.native_write_enabled = true;
        if (!Require(c.metadata_store->PrepareNativeWritePath(), "strict startup view is prepared")) return false;
        const auto before = ReadFileBytes(fixture.image.path);
        const auto admitted = ValidateDirectNativeStartup(c);
        if (!Require(admitted == single_volume && c.native_write_enabled == single_volume &&
                c.write_degraded != single_volume && !c.mount_ready && !c.fs &&
                !c.metadata_store->PendingMutationCount() && before == ReadFileBytes(fixture.image.path),
                "direct startup rejects sibling topology before provider or mutation")) return false;
        if (!single_volume && !Require(c.runtime_recovery_reason == L"DirectAppleVolumeRequiresContainerCoordinator" &&
                c.runtime_last_recovery_action == L"DirectNativeLaunchRejectedBeforeMount",
                "direct startup preserves the exact configuration refusal")) return false;
    }
    DirectorySymlinkFixture manifest(true);
    if (!Require(manifest.Initialize(true) && ValidateDirectNativeStartup(*manifest.context) &&
            manifest.context->native_write_enabled && !manifest.context->write_degraded,
            "complete two-volume coordinator remains eligible")) return false;
    MountContext read_only;
    return Require(ValidateDirectNativeStartup(read_only) && !read_only.write_degraded &&
        read_only.runtime_recovery_reason.empty(), "read-only inspection needs no writable sibling census");
}

bool InitializeDirectQuota456(DirectorySymlinkFixture& fixture, std::uint64_t quota, std::uint64_t free = 0)
{
    auto spec = TwoProjectableVolumeStore();
    spec.volumes.resize(1);
    spec.authoritative_checkpoint = true;
    spec.authoritative_checkpoint_ring_blocks = 16;
    spec.authoritative_internal_pool_blocks = 16;
    spec.volumes[0].quota_block_count = quota;
    if (free) spec.authoritative_main_free_blocks = free;
    return WriteFileBytes(fixture.image.path, apfsaccess::testfixture::BuildStoreImage(spec)) && fixture.Initialize(false);
}

bool TestDirectCapacityPreservesPrefix456()
{
    // Exercise both a committed existing file and the coalesced pending write
    // stream. A refused callback must not replace the older accepted payload.
    for (const bool flush_first : {false, true})
    {
        DirectorySymlinkFixture fixture(false);
        if (!Require(InitializeDirectQuota456(fixture, 10), "direct prefix source fixture loads")) return false;
        auto& c = *fixture.context;
        c.args.write_max_dirty_transactions = 64;
        auto fs = BuildFileSystem(&c);
        PVOID handle = nullptr;
        FSP_FSCTL_FILE_INFO info{};
        ScopeExit close{[&] { if (handle) CB_Close(&fs, handle); }};
        if (!Require(CB_Create(&fs, const_cast<PWSTR>(L"\\prefix"), FILE_NON_DIRECTORY_FILE,
                GENERIC_READ | GENERIC_WRITE, FILE_ATTRIBUTE_ARCHIVE, nullptr, 0, &handle, &info) == STATUS_SUCCESS,
                "direct prefix creates within quota")) return false;
        std::vector<std::byte> old(4096, std::byte{0x39});
        ULONG done = 0;
        if (!Require(CB_Write(&fs, handle, old.data(), 0, static_cast<ULONG>(old.size()), FALSE, FALSE, &done, &info) ==
                STATUS_SUCCESS && done == old.size() && (!flush_first || CB_Flush(&fs, handle, &info) == STATUS_SUCCESS),
                "in-quota content is acknowledged before failed growth")) return false;
        const auto oid = static_cast<OpenContext*>(handle)->node->object_id;
        const auto times = VisibleInodeTimes(*static_cast<OpenContext*>(handle)->node);
        const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
        const auto spool = ReadFileBytes(c.payload_spool->SpoolFilePath());
        const auto image = ReadFileBytes(fixture.image.path);
        const auto pending = c.metadata_store->PendingMutationCount();
        const auto next = c.tx_manager->NextMutationSequence();
        std::vector<std::byte> growth(65536, std::byte{0x7b});
        done = 999;
        const auto status = CB_Write(&fs, handle, growth.data(), old.size(), static_cast<ULONG>(growth.size()),
            FALSE, FALSE, &done, &info);
        if (!Require(status == STATUS_DISK_FULL && done == 0 && c.native_write_enabled && !c.write_degraded &&
                !c.recovery_active && static_cast<OpenContext*>(handle)->node->object_id == oid &&
                VisibleInodeTimes(*static_cast<OpenContext*>(handle)->node) == times &&
                c.metadata_store->PendingMutationCount() == pending && c.tx_manager->NextMutationSequence() == next &&
                wal == ReadFileBytes(c.session_root / "accepted.wal") && spool == ReadFileBytes(c.payload_spool->SpoolFilePath()) &&
                image == ReadFileBytes(fixture.image.path), "failed growth preserves earlier journal, spool, identity and timestamps")) return false;
        std::vector<std::byte> actual(old.size());
        ULONG read = 0;
        if (!Require(CB_Read(&fs, handle, actual.data(), 0, static_cast<ULONG>(actual.size()), &read) == STATUS_SUCCESS &&
                read == old.size() && actual == old && CB_Flush(&fs, handle, &info) == STATUS_SUCCESS,
                "older acknowledged bytes survive refusal and normal flush")) return false;
        apfsaccess::rw::MetadataStore reopened(fixture.volume);
        actual.clear();
        if (!Require(reopened.LoadCanonicalState() && reopened.ReadCommittedFileRange(L"\\prefix", 0, old.size(), actual) &&
                actual == old, "reopened checkpoint contains the original pending request payload")) return false;
        if (!Require(CB_SetFileSize(&fs, handle, 0, FALSE, &info) == STATUS_SUCCESS &&
                CB_Flush(&fs, handle, &info) == STATUS_SUCCESS, "explicit truncate remains writable after refusal")) return false;
    }
    return true;
}

bool TestDirectCreateNoQuota456()
{
    DirectorySymlinkFixture fixture(false);
    if (!Require(InitializeDirectQuota456(fixture, 0, 5), "five-free-block no-quota fixture loads")) return false;
    auto& c = *fixture.context;
    auto fs = BuildFileSystem(&c);
    const auto image = ReadFileBytes(fixture.image.path);
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    const auto next = c.tx_manager->NextMutationSequence();
    PVOID handle = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    ScopeExit close{[&] { if (handle) CB_Close(&fs, handle); }};
    const auto status = CB_Create(&fs, const_cast<PWSTR>(L"\\full"), FILE_NON_DIRECTORY_FILE,
        GENERIC_READ | GENERIC_WRITE, FILE_ATTRIBUTE_ARCHIVE, nullptr, 0, &handle, &info);
    return Require(status == STATUS_DISK_FULL && !handle && c.native_write_enabled && !c.write_degraded && !c.recovery_active &&
        !c.metadata_store->PendingMutationCount() && !c.metadata_store->LookupWorkingInodeByPath(L"\\full") &&
        c.tx_manager->NextMutationSequence() == next && !c.compression_verification_pending.load() &&
        image == ReadFileBytes(fixture.image.path) && wal == ReadFileBytes(c.session_root / "accepted.wal"),
        "metadata-only create refuses physical exhaustion before namespace/WAL acceptance without degrading");
}

bool TestDirectAdmissionRetainedCensus456()
{
    DirectorySymlinkFixture fixture(false);
    if (!Require(InitializeDirectQuota456(fixture, 0), "retained census fixture loads")) return false;
    auto& c = *fixture.context;
    c.args.write_max_dirty_transactions = 64;
    auto fs = BuildFileSystem(&c);
    std::vector<PVOID> handles;
    ScopeExit close{[&] { for (const auto handle : handles) CB_Close(&fs, handle); }};
    FSP_FSCTL_FILE_INFO info{};
    // Publish two real callback batches without cleanup, retaining historical
    // preimages in the same journal used by direct commit and admission.
    for (unsigned i = 0; i != 2; ++i)
    {
        PVOID handle = nullptr;
        auto path = L"\\retained-" + std::to_wstring(i);
        if (!Require(CB_Create(&fs, path.data(), FILE_NON_DIRECTORY_FILE, GENERIC_READ | GENERIC_WRITE,
                FILE_ATTRIBUTE_ARCHIVE, nullptr, 0, &handle, &info) == STATUS_SUCCESS && handle,
                "retained census creates a real callback batch")) return false;
        handles.push_back(handle);
        if (!Require(AcceptMutationJournalForDeferredCommitBestEffort(&c, L"CapacityCensusTest") &&
                NT_SUCCESS(CommitNativeMutationsBestEffort(&c, L"CapacityCensusTest")),
                "retained census publishes without retiring the journal")) return false;
    }
    std::vector<std::uint64_t> expected, preview_pins, commit_pins;
    if (!Require(c.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(expected) && expected.size() == 2 &&
            expected.front() < c.metadata_store->CheckpointXid(), "journal retains two historical checkpoint pins")) return false;
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    const auto image = ReadFileBytes(fixture.image.path);
    const auto marks = c.tx_manager->Watermarks();
    const auto request = NativeCallbackRequest(apfsaccess::rw::MetadataStore::MutationOperation::CreateFile, L"\\preview-only");
    NTSTATUS status;
    {
        std::unique_lock<std::mutex> commit(c.commit_mutex);
        std::unique_lock<std::shared_mutex> gate(c.committed_read_gate);
        std::lock_guard<std::mutex> metadata(c.metadata_mutex);
        std::string error;
        if (!Require(LoadDirectCheckpointPinsLocked(c, preview_pins, error, true) &&
                LoadDirectCheckpointPinsLocked(c, commit_pins, error) && preview_pins == expected && commit_pins == expected,
                "admission and commit load the identical retained WAL census")) return false;
        status = PreflightDirectCallbackLocked(&c, std::span(&request, 1));
    }
    std::vector<std::uint64_t> after;
    const auto now = c.tx_manager->Watermarks();
    return Require((status == STATUS_SUCCESS || status == STATUS_DEVICE_BUSY) &&
        c.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(after) && after == expected &&
        now.accepted_sequence == marks.accepted_sequence && now.apfs_durable_sequence == marks.apfs_durable_sequence &&
        now.cleanup_sequence == marks.cleanup_sequence && wal == ReadFileBytes(c.session_root / "accepted.wal") &&
        image == ReadFileBytes(fixture.image.path) && !c.metadata_store->PendingMutationCount() && c.native_write_enabled,
        "direct preview leaves retained checkpoint ownership and source bytes unchanged");
}

bool TestDirectCompressedQuota456()
{
    HostCompressionRewrite211Fixture fixture;
    if (!Require(fixture.Initialize(3, false, false, false, false, 7), "inline compressed quota fixture loads")) return false;
    auto& c = *fixture.fixture.context;
    auto fs = BuildFileSystem(&c);
    PVOID handle = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    ScopeExit close{[&] { if (handle) CB_Close(&fs, handle); }};
    if (!Require(CB_Open(&fs, const_cast<PWSTR>(L"\\compressed"), FILE_OPEN << 24,
            GENERIC_READ | GENERIC_WRITE, &handle, &info) == STATUS_SUCCESS, "compressed quota callback opens writable")) return false;
    const auto image = ReadFileBytes(fixture.fixture.image.path);
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    const auto spool = ReadFileBytes(c.payload_spool->SpoolFilePath());
    const auto next = c.tx_manager->NextMutationSequence();
    const auto times = VisibleInodeTimes(*static_cast<OpenContext*>(handle)->node);
    const auto attrs = VisibleWindowsAttributes(*static_cast<OpenContext*>(handle)->node);
    std::byte replacement{0x51};
    ULONG done = 999;
    const auto status = CB_Write(&fs, handle, &replacement, 1, 1, FALSE, FALSE, &done, &info);
    if (status != STATUS_DISK_FULL)
        std::wcerr << L"[DETAIL] compressed quota status=" << FormatNtStatus(status) << L" reason=" << c.runtime_recovery_reason << std::endl;
    if (!Require(status == STATUS_DISK_FULL && done == 0 && c.native_write_enabled && !c.write_degraded && !c.recovery_active &&
            !c.compression_verification_pending.load() && !c.metadata_store->PendingMutationCount() &&
            !c.tx_manager->HasUnappliedAcceptedWork() && c.tx_manager->NextMutationSequence() == next &&
            image == ReadFileBytes(fixture.fixture.image.path) && wal == ReadFileBytes(c.session_root / "accepted.wal") &&
            spool == ReadFileBytes(c.payload_spool->SpoolFilePath()) &&
            static_cast<OpenContext*>(handle)->node->object_id == 17 &&
            VisibleInodeTimes(*static_cast<OpenContext*>(handle)->node) == times &&
            VisibleWindowsAttributes(*static_cast<OpenContext*>(handle)->node) == attrs,
            "compressed conversion refuses full batch before any WAL/spool acceptance or verification debt")) return false;
    std::vector<std::byte> actual(fixture.eof);
    ULONG read = 0;
    return Require(CB_Read(&fs, handle, actual.data(), 0, static_cast<ULONG>(actual.size()), &read) == STATUS_SUCCESS &&
        read == actual.size() && actual == fixture.expected_source && CB_Flush(&fs, handle, &info) == STATUS_SUCCESS &&
        c.metadata_store->LookupCommittedExtendedAttribute(17, "com.apple.decmpfs").has_value(),
        "refused conversion preserves readable compressed source and normal flush");
}

bool TestDirectCapacityOverwrite456()
{
    DirectorySymlinkFixture fixture(false);
    if (!Require(InitializeDirectQuota456(fixture, 10), "overwrite quota fixture loads")) return false;
    auto& c = *fixture.context;
    auto fs = BuildFileSystem(&c);
    PVOID handle = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    ScopeExit close{[&] { if (handle) CB_Close(&fs, handle); }};
    std::vector<std::byte> old(4096, std::byte{0x4a});
    ULONG done = 0;
    if (!Require(CB_Create(&fs, const_cast<PWSTR>(L"\\overwrite"), FILE_NON_DIRECTORY_FILE,
            GENERIC_READ | GENERIC_WRITE, FILE_ATTRIBUTE_ARCHIVE, nullptr, 0, &handle, &info) == STATUS_SUCCESS &&
            CB_Write(&fs, handle, old.data(), 0, static_cast<ULONG>(old.size()), FALSE, FALSE, &done, &info) == STATUS_SUCCESS &&
            CB_Flush(&fs, handle, &info) == STATUS_SUCCESS, "overwrite starts with persisted original bytes")) return false;
    const auto image = ReadFileBytes(fixture.image.path);
    const auto times = VisibleInodeTimes(*static_cast<OpenContext*>(handle)->node);
    const auto attrs = VisibleWindowsAttributes(*static_cast<OpenContext*>(handle)->node);
    const auto status = CB_Overwrite(&fs, handle, FILE_ATTRIBUTE_HIDDEN, FALSE, 65536, &info);
    std::vector<std::byte> actual(old.size());
    ULONG read = 0;
    return Require(status == STATUS_DISK_FULL && c.native_write_enabled && !c.write_degraded && !c.recovery_active &&
        image == ReadFileBytes(fixture.image.path) && !c.metadata_store->PendingMutationCount() &&
        VisibleInodeTimes(*static_cast<OpenContext*>(handle)->node) == times &&
        VisibleWindowsAttributes(*static_cast<OpenContext*>(handle)->node) == attrs &&
        CB_Read(&fs, handle, actual.data(), 0, static_cast<ULONG>(actual.size()), &read) == STATUS_SUCCESS &&
        read == old.size() && actual == old, "overwrite admits truncate, reallocation and new DOS xattr atomically");
}

bool TestQuotaCallbacksPreserveWritableRetry()
{
    for (const bool manifest : {false, true})
    {
        DirectorySymlinkFixture fixture(manifest);
        auto spec = TwoProjectableVolumeStore();
        if (!manifest) spec.volumes.resize(1);
        spec.authoritative_checkpoint = true;
        spec.authoritative_checkpoint_ring_blocks = 16;
        spec.authoritative_internal_pool_blocks = 16;
        spec.volumes[0].quota_block_count = 8;
        if (!Require(WriteFileBytes(fixture.image.path, apfsaccess::testfixture::BuildStoreImage(spec)) &&
                fixture.Initialize(manifest), "quota callback fixture initializes")) return false;
        auto& c = *fixture.context;
        auto fs = BuildFileSystem(&c);
        PVOID handle = nullptr;
        FSP_FSCTL_FILE_INFO info{};
        ScopeExit close{[&] { if (handle) CB_Close(&fs, handle); }};
        if (!Require(CB_Create(&fs, const_cast<PWSTR>(L"\\quota.bin"), FILE_NON_DIRECTORY_FILE,
                GENERIC_READ | GENERIC_WRITE, FILE_ATTRIBUTE_ARCHIVE, nullptr, 0, &handle, &info) == STATUS_SUCCESS && handle,
                "quota callbacks create an empty file within quota")) return false;
        const std::vector<std::byte> payload(16384, std::byte{0x5a});
        ULONG done = 999;
        const auto written = CB_Write(&fs, handle, const_cast<std::byte*>(payload.data()), 0,
            static_cast<ULONG>(payload.size()), FALSE, FALSE, &done, &info);
        const auto flushed = written == STATUS_SUCCESS ? CB_Flush(&fs, handle, &info) : written;
        if (flushed != STATUS_DISK_FULL || c.write_degraded || c.recovery_active)
            std::wcerr << L"[DETAIL] quota manifest=" << manifest << L" write=" << FormatNtStatus(written)
                << L" flush=" << FormatNtStatus(flushed) << L" recovery=" << c.runtime_recovery_reason << std::endl;
        if (!Require(flushed == STATUS_DISK_FULL && c.native_write_enabled && !c.write_degraded && !c.recovery_active,
                "quota callback reports disk-full while retaining write access")) return false;
        if (written == STATUS_SUCCESS)
        {
            std::vector<std::byte> actual(payload.size());
            ULONG read = 0;
            if (!Require(done == payload.size() && CB_Read(&fs, handle, actual.data(), 0,
                    static_cast<ULONG>(actual.size()), &read) == STATUS_SUCCESS && read == actual.size() && actual == payload,
                    "acknowledged bytes remain readable after a full-volume flush")) return false;
        }
        if (!Require(CB_SetFileSize(&fs, handle, 0, FALSE, &info) == STATUS_SUCCESS &&
                CB_Flush(&fs, handle, &info) == STATUS_SUCCESS && !c.write_degraded && !c.recovery_active,
                "explicit truncate recovers from quota pressure through normal callbacks")) return false;
        apfsaccess::rw::MetadataStore reopened(fixture.volume);
        if (!Require(reopened.LoadCanonicalState(), "quota callbacks reopen their final checkpoint")) return false;
        const auto inode = reopened.LookupCommittedInodeByPath(L"\\quota.bin");
        if (!Require(inode && inode->logical_size == 0, "quota callback retry persists the explicit empty result")) return false;
    }
    return true;
}
