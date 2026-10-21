#pragma once
// Canonical two-volume callback fixture; include after FsHostSemanticsTests.cpp.
bool TestBasicInfoNoopCleanup626(std::string_view scenario)
{
    if (!DeferredAccessTimeScratch302()) return false;
    DeferredAccessTimeFixture302 owned(true);
    if (!owned.Initialize(true)) return false;
    auto& c = *owned.fixture.context;
    auto fs = BuildFileSystem(&c);
    const bool corrected = scenario == "noop" || scenario == "change-only";
    UINT32 access = FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES;
    if (scenario == "failed-noop") access &= ~FILE_WRITE_ATTRIBUTES;
    if (scenario == "write" || scenario == "resize") access |= FILE_WRITE_DATA;
    if (scenario == "rename" || scenario == "delete") access |= DELETE;
    PVOID handle = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    if (!Require(CB_Open(&fs, const_cast<PWSTR>(L"\\read17"), FILE_NON_DIRECTORY_FILE | (FILE_OPEN << 24),
            access, &handle, &info) == STATUS_SUCCESS, "626: canonical original opens")) return false;
    ScopeExit close{[&] { if (handle) CB_Close(&fs, handle); }};
    auto* o = static_cast<OpenContext*>(handle);
    const auto before = c.metadata_store->LookupCommittedInodeByPath(L"\\read17");
    if (!Require(before.has_value(), "626: original inode exists")) return false;
    const auto image = ReadFileBytes(owned.fixture.image.path);
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    unsigned publications = 0;
    c.metadata_store->SetCommitStageHook([&](std::string_view stage) {
        if (stage == "before-apple-publish") ++publications;
        return true;
    });
    ScopeExit clear{[&] { c.metadata_store->SetCommitStageHook({}); }};
    if (scenario != "no-noop")
    {
        const auto status = CB_SetBasicInfo(&fs, handle, INVALID_FILE_ATTRIBUTES, 0, 0, 0, 0, &info);
        if (!Require(status == (scenario == "failed-noop" ? STATUS_ACCESS_DENIED : STATUS_SUCCESS),
                "626: zero-field basic callback has expected success/failure")) return false;
    }
    std::array<std::byte, 64> bytes{}; ULONG done = 0;
    if (!Require(CB_Read(&fs, handle, bytes.data(), 0, bytes.size(), &done) == STATUS_SUCCESS &&
            done == owned.bytes.size() && std::equal(owned.bytes.begin(), owned.bytes.end(), bytes.begin()),
            "626: actual original data read matches seed")) return false;
    std::wstring path = L"\\read17";
    if (scenario == "explicit-time" || scenario == "same-time")
    {
        const auto time = before->access_time_utc + (scenario == "explicit-time" ? 10000000 : 0);
        if (!Require(CB_SetBasicInfo(&fs, handle, INVALID_FILE_ATTRIBUTES, 0, time, 0, 0, &info) == STATUS_SUCCESS &&
                info.LastAccessTime == time, "626: explicit timestamp honored including equal value")) return false;
        // A later no-op must not erase earlier explicit timestamp evidence.
        if (CB_SetBasicInfo(&fs, handle, INVALID_FILE_ATTRIBUTES, 0, 0, 0, 0, &info) != STATUS_SUCCESS) return false;
    }
    if (scenario == "attributes")
        if (!Require(CB_SetBasicInfo(&fs, handle, FILE_ATTRIBUTE_HIDDEN, 0, 0, 0, 0, &info) == STATUS_SUCCESS &&
                (info.FileAttributes & FILE_ATTRIBUTE_HIDDEN), "626: actual attribute change succeeds")) return false;
    if (scenario == "write")
    {
        std::byte value{0x72}; done = 0;
        if (!Require(CB_Write(&fs, handle, &value, 0, 1, FALSE, FALSE, &done, &info) == STATUS_SUCCESS && done == 1,
                "626: real data write succeeds")) return false;
    }
    if (scenario == "resize")
        if (!Require(CB_SetFileSize(&fs, handle, 16, FALSE, &info) == STATUS_SUCCESS,
                "626: real size change succeeds")) return false;
    if (scenario == "rename")
    {
        path = L"\\renamed626";
        if (!Require(CB_Rename(&fs, handle, const_cast<PWSTR>(L"\\read17"), path.data(), FALSE) == STATUS_SUCCESS,
                "626: real namespace change succeeds")) return false;
    }
    if (scenario == "attributes" || scenario == "write" || scenario == "resize" || scenario == "rename" || scenario == "explicit-time")
        if (!Require(o->mutation_observed.load(), "626: genuine mutation marks exact OpenContext")) return false;
    PVOID other = nullptr;
    ScopeExit close_other{[&] { if (other) CB_Close(&fs, other); }};
    PVOID cleanup_handle = handle;
    if (scenario == "other-handle")
    {
        if (CB_Open(&fs, path.data(), FILE_OPEN << 24, access, &other, &info) != STATUS_SUCCESS) return false;
        cleanup_handle = other;
    }
    if (scenario == "other-writer")
        if (!Require(CB_Open(&fs, const_cast<PWSTR>(L"\\read18"), FILE_OPEN << 24,
                FILE_WRITE_DATA | FILE_READ_ATTRIBUTES, &other, &info) == STATUS_SUCCESS,
                "626: unrelated writer remains open during reader cleanup")) return false;
    ULONG flags = FspCleanupSetChangeTime;
    if (scenario != "change-only") flags |= FspCleanupSetLastAccessTime;
    if (scenario == "delete")
    {
        if (!Require(CB_SetDelete(&fs, handle, nullptr, TRUE) == STATUS_SUCCESS,
                "626: delete intent accepted")) return false;
        flags |= FspCleanupDelete;
    }
    const auto publications_before_cleanup = publications;
    CB_Cleanup(&fs, cleanup_handle, nullptr, flags);
    if (!Require(CB_GetFileInfo(&fs, cleanup_handle, &info) == STATUS_SUCCESS,
            "626: cleanup metadata is visible")) return false;
    if (corrected)
    {
        const bool access_requested = scenario == "noop";
        if (!Require(info.ChangeTime == before->change_time_utc &&
                info.CreationTime == before->create_time_utc && info.LastWriteTime == before->modification_time_utc,
                "626: successful no-op cleanup preserves ctime/birth/mtime")) return false;
        if (!Require(publications == 0 && image == ReadFileBytes(owned.fixture.image.path) &&
                wal == ReadFileBytes(c.session_root / "accepted.wal") && c.tx_manager->Watermarks().accepted_sequence == 0 &&
                c.metadata_store->PendingMutationCount() == 0 && ManifestQueuedRequestCount(&c) == 0 &&
                c.deferred_access_times.size() == (access_requested ? 1u : 0u),
                "626: cleanup performs no synchronous canonical commit and only queues atime")) return false;
        if (!Require(access_requested ? info.LastAccessTime > before->access_time_utc : info.LastAccessTime == before->access_time_utc,
                "626: legitimate automatic atime retained only when requested")) return false;
        CB_Close(&fs, handle); handle = nullptr;
        if (!Require(publications == 0 && image == ReadFileBytes(owned.fixture.image.path) &&
                wal == ReadFileBytes(c.session_root / "accepted.wal") &&
                c.deferred_access_times.size() == (access_requested ? 1u : 0u),
                "626: normal Close also preserves deferred atime without canonical commit")) return false;
    }
    else if (scenario == "other-writer")
    {
        if (!Require(info.ChangeTime == before->change_time_utc && info.LastAccessTime > before->access_time_utc &&
                c.deferred_access_times.size() == 1 && publications == publications_before_cleanup && HasOpenWriteHandles(&c),
                "626: isolated reader queues exact atime beside unrelated writer and preserves ctime")) return false;
        const auto queued = c.deferred_access_times.find(o->node->object_id);
        if (!Require(queued != c.deferred_access_times.end() && queued->second.owner == o->node->shared_payload &&
                queued->second.time == info.LastAccessTime && image == ReadFileBytes(owned.fixture.image.path) &&
                wal == ReadFileBytes(c.session_root / "accepted.wal"),
                "626: queued time belongs to reader inode and leaves original image/WAL unchanged")) return false;
    }
    else if (!Require(info.ChangeTime > before->change_time_utc && publications > publications_before_cleanup &&
            c.deferred_access_times.empty(), "626: control cleanup retains synchronous ctime semantics")) return false;
    const auto expected_ctime = info.ChangeTime;
    const auto expected_atime = info.LastAccessTime;
    if (!Require(CB_Flush(&fs, nullptr, nullptr) == STATUS_SUCCESS, "626: ordinary durability boundary succeeds")) return false;
    if (scenario == "other-writer" && !Require(c.deferred_access_times.empty() &&
            publications == publications_before_cleanup + 1 && HasOpenWriteHandles(&c),
            "626: explicit flush publishes reader time once while unrelated writer remains held")) return false;
    if (corrected && !Require(publications == (scenario == "noop" ? 1u : 0u),
            "626: only the existing atime batch publishes at flush")) return false;
    if (scenario == "delete")
    {
        CB_Close(&fs, handle); handle = nullptr;
        return Require(!c.metadata_store->LookupCommittedInodeByPath(path), "626: requested unlink survives cleanup");
    }
    apfsaccess::rw::MetadataStore fresh(owned.fixture.volume);
    if (!fresh.PrepareNativeWritePath()) return false;
    const auto after = fresh.LookupCommittedInodeByPath(path);
    if (!Require(after && after->change_time_utc == expected_ctime && after->access_time_utc == expected_atime &&
            after->owner == before->owner && after->group == before->group && after->mode == before->mode,
            "626: fresh canonical reopen preserves exact intended times and Mac ownership/mode")) return false;
    if (scenario != "write" && scenario != "resize") return owned.CheckFresh({{path, expected_atime}});
    std::vector<std::byte> actual;
    auto expected = owned.bytes;
    if (scenario == "write") expected[0] = std::byte{0x72}; else expected.resize(16);
    return Require(fresh.ReadCommittedFileRange(path, 0, expected.size(), actual) && actual == expected,
        "626: real data/size mutation remains durable");
}
