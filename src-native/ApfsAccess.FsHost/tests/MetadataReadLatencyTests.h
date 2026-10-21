#pragma once

bool TestTraverseOnlyDirectoryCleanupDoesNotWaitOnCommit()
{
    bool ok = true;
    for (const bool hold_mutation_gate : {false, true})
    {
        MountContext c{};
        c.native_write_enabled = true;
        SeedRoot(c);
        c.owned_metadata_store = std::make_unique<apfsaccess::rw::MetadataStore>(
            apfsaccess::rw::MetadataStore::VolumeContext{});
        c.metadata_store = c.owned_metadata_store.get();
        // Exercise both gates independently; this existing unit seam admits
        // Cleanup to the mutation gate without requiring a mounted volume.
        c.test_force_native_mutation_staging_success = hold_mutation_gate;
        OpenContext opened{};
        opened.node = c.nodes.at(Key(&c, L"\\"));
        InitializeOpenAccess(&opened, FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE);
        if (!Require(opened.node->node_kind == NodeKind::Directory && opened.allow_read_data &&
                !opened.allow_list_directory && !opened.allow_write_data && !opened.allow_append_data,
                "traverse cleanup: actual access initializer exposes the directory execute/list distinction")) return false;
        const auto before = VisibleInodeTimes(*opened.node);
        auto fs = BuildFileSystem(&c);
        std::unique_lock<std::mutex> held(hold_mutation_gate ? c.mutation_callback_mutex : c.metadata_mutex);
        std::promise<void> entered;
        auto ready = entered.get_future();
        auto cleanup = std::async(std::launch::async, [&] {
            entered.set_value();
            CB_Cleanup(&fs, &opened, nullptr, FspCleanupSetLastAccessTime);
        });
        ready.wait();
        const bool responsive = cleanup.wait_for(std::chrono::milliseconds(400)) == std::future_status::ready;
        held.unlock();
        cleanup.get();
        std::cout << "TRAVERSE_CLEANUP gate=" << (hold_mutation_gate ? "mutation" : "metadata")
                  << " responsive=" << responsive << '\n';
        ok &= Require(responsive, "traverse-only directory automatic-atime Cleanup never enters native commit/mutation gates");
        ok &= Require(VisibleInodeTimes(*opened.node) == before && !opened.mutation_observed.load() &&
                c.metadata_store->PendingMutationCount() == 0 && c.deferred_access_times.empty(),
            "traverse cleanup leaves timestamps and native/deferred staging unchanged");
    }
    return ok;
}

bool TestCleanupAccessTimeClassificationPolicies()
{
    struct Case { const char* name; bool directory; UINT32 access; bool stream; bool changes_atime; };
    const Case cases[] = {
        {"directory-traverse", true, FILE_TRAVERSE, false, false},
        {"directory-attributes", true, FILE_READ_ATTRIBUTES, false, false},
        {"directory-list", true, FILE_LIST_DIRECTORY, false, true},
        {"directory-list-and-traverse", true, FILE_LIST_DIRECTORY | FILE_TRAVERSE, false, true},
        {"directory-write", true, FILE_ADD_FILE, false, true},
        {"directory-append", true, FILE_ADD_SUBDIRECTORY, false, true},
        {"regular-execute", false, FILE_EXECUTE, false, true},
        {"named-stream-execute", false, FILE_EXECUTE, true, true},
        {"directory-stream-execute", true, FILE_EXECUTE, true, true},
    };
    bool ok = true;
    for (const auto& test : cases)
    {
        MountContext c{};
        c.overlay_write_enabled = true;
        SeedRoot(c);
        OpenContext opened{};
        opened.node = test.directory ? c.nodes.at(Key(&c, L"\\")) : MakeNode(L"\\policy.bin", false, false);
        if (!test.directory) c.nodes.emplace(Key(&c, opened.node->path), opened.node);
        opened.named_stream = test.stream;
        if (test.stream) opened.stream_name = L"policy";
        InitializeOpenAccess(&opened, test.access);
        constexpr auto stamp = apfsaccess::rw::InodeMetadataPatch::UnixEpochTicks + 10000000;
        const InodeTimes before{stamp, stamp, stamp, stamp};
        SetVisiblePayloadMetadataLocked(opened.node, 0, before);
        auto fs = BuildFileSystem(&c);
        CB_Cleanup(&fs, &opened, nullptr, FspCleanupSetLastAccessTime);
        const auto after = VisibleInodeTimes(*opened.node);
        const bool changed = after.access_time_utc != before.access_time_utc;
        std::cout << "CLEANUP_POLICY case=" << test.name << " atime_changed=" << changed << '\n';
        ok &= Require(changed == test.changes_atime &&
                opened.mutation_observed.load() == test.changes_atime,
            "automatic atime preserves listing/write/file-execute/stream policy and excludes directory traversal");
        ok &= Require(after.create_time_utc == before.create_time_utc &&
                after.modification_time_utc == before.modification_time_utc &&
                after.change_time_utc == before.change_time_utc,
            "automatic atime classification does not change other timestamps");
    }
    {
        MountContext c{};
        c.overlay_write_enabled = true;
        SeedRoot(c);
        OpenContext opened{};
        opened.node = c.nodes.at(Key(&c, L"\\"));
        InitializeOpenAccess(&opened, FILE_TRAVERSE | FILE_WRITE_ATTRIBUTES);
        constexpr auto stamp = apfsaccess::rw::InodeMetadataPatch::UnixEpochTicks + 10000000;
        const InodeTimes before{stamp, stamp, stamp, stamp};
        SetVisiblePayloadMetadataLocked(opened.node, 0, before);
        auto fs = BuildFileSystem(&c);
        FSP_FSCTL_FILE_INFO info{};
        const auto requested_atime = stamp + 10000000;
        const auto status = CB_SetBasicInfo(&fs, &opened, INVALID_FILE_ATTRIBUTES,
            0, requested_atime, 0, 0, &info);
        std::cout << "CLEANUP_POLICY case=explicit-directory-atime status=" << status << '\n';
        ok &= Require(status == STATUS_SUCCESS &&
                VisibleInodeTimes(*opened.node).access_time_utc == requested_atime &&
                opened.explicit_basic_info_completed.load() && opened.mutation_observed.load(),
            "explicit SetBasicInfo access time remains effective on a traverse-only directory handle");
        CB_Cleanup(&fs, &opened, nullptr, FspCleanupSetLastWriteTime | FspCleanupSetChangeTime);
        const auto after = VisibleInodeTimes(*opened.node);
        ok &= Require(after.access_time_utc == requested_atime && after.create_time_utc == before.create_time_utc &&
                after.modification_time_utc != before.modification_time_utc && after.change_time_utc != before.change_time_utc,
            "traverse classification preserves requested cleanup modification/change times");
    }
    return ok;
}

bool TestMetadataOnlyRegularFileDoesNotWaitOnCommit()
{
    MountContext c{};
    c.native_write_enabled = true;
    SeedRoot(c);
    c.owned_metadata_store = std::make_unique<apfsaccess::rw::MetadataStore>(apfsaccess::rw::MetadataStore::VolumeContext{});
    c.metadata_store = c.owned_metadata_store.get();
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:BAD:P(A;;FR;;;WD)",
            SDDL_REVISION_1, &sd, nullptr)) return false;
    ScopeExit release_sd{[&] { LocalFree(sd); }};
    const auto sd_size = GetSecurityDescriptorLength(sd);
    c.sd = sd; c.sd_size = sd_size;
    auto security = std::make_shared<NativeInodeSecurity>();
    security->owner = 501; security->group = 20; security->mode = 0100640;
    security->windows_security_flags = apfsaccess::rw::kAppleXattrDataEmbedded;
    security->windows_security.emplace();
    if (EncodeWindowsSecurity(sd, *security->windows_security) != STATUS_SUCCESS) return false;
    auto file = MakeNode(L"\\metadata.bin", false, false);
    file->object_id = 17; file->file_size = 32; file->native_security = security;
    c.nodes.emplace(Key(file->path), file);
    auto fs = BuildFileSystem(&c);
    std::unique_lock<std::mutex> commit(c.metadata_mutex);
    auto query = std::async(std::launch::async, [&] {
        std::vector<std::byte> actual(sd_size); SIZE_T size = actual.size(); UINT32 attrs = 0;
        if (CB_GetSecurityByName(&fs, file->path.data(), &attrs, actual.data(), &size) != STATUS_SUCCESS ||
            size != sd_size || std::memcmp(actual.data(), sd, sd_size) != 0) return false;
        PVOID handle = nullptr; FSP_FSCTL_FILE_INFO info{};
        if (CB_Open(&fs, file->path.data(), (FILE_OPEN << 24) | FILE_NON_DIRECTORY_FILE,
                FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE, &handle, &info) != STATUS_SUCCESS) return false;
        const auto status = CB_GetFileInfo(&fs, handle, &info);
        CB_Cleanup(&fs, handle, nullptr, FspCleanupSetLastAccessTime);
        CB_Close(&fs, handle);
        FSP_FSCTL_VOLUME_INFO volume{};
        return status == STATUS_SUCCESS && info.FileSize == 32 && CB_GetVolumeInfo(&fs, &volume) == STATUS_SUCCESS;
    });
    const bool responsive = query.wait_for(std::chrono::milliseconds(200)) == std::future_status::ready;
    commit.unlock();
    bool ok = Require(query.get() && responsive,
        "regular-file metadata open/security/query/cleanup uses exact cached metadata while commit holds its lock");

    // A payload request must still cross the native content gate. Always release
    // the controlled lock, including failure, so the test cannot strand a worker.
    commit.lock();
    auto payload = std::async(std::launch::async, [&] {
        PVOID handle = nullptr; FSP_FSCTL_FILE_INFO info{};
        const auto status = CB_Open(&fs, file->path.data(), (FILE_OPEN << 24) | FILE_NON_DIRECTORY_FILE,
            FILE_READ_DATA, &handle, &info);
        if (NT_SUCCESS(status)) CB_Close(&fs, handle);
        return status;
    });
    const bool gated = payload.wait_for(std::chrono::milliseconds(100)) != std::future_status::ready;
    commit.unlock();
    const auto payload_status = payload.get();
    ok &= Require(gated && !NT_SUCCESS(payload_status), "metadata fast path cannot fabricate or bypass unavailable payload content");

    auto malformed = std::make_shared<NativeInodeSecurity>(*security);
    malformed->windows_security = std::vector<std::byte>{std::byte{1}};
    file->native_security = malformed;
    SIZE_T size = 0; UINT32 attrs = 0;
    ok &= Require(!NT_SUCCESS(CB_GetSecurityByName(&fs, file->path.data(), &attrs, nullptr, &size)),
        "malformed stored Windows ACL remains an error on metadata-only requests");
    file->native_security = security;
    c.recovery_active = true;
    PVOID handle = nullptr; FSP_FSCTL_FILE_INFO info{};
    const auto status = CB_Open(&fs, file->path.data(), (FILE_OPEN << 24) | FILE_NON_DIRECTORY_FILE,
        FILE_READ_ATTRIBUTES, &handle, &info);
    if (NT_SUCCESS(status)) CB_Close(&fs, handle);
    return Require(ok && NT_SUCCESS(status) && ReportsReadOnly(&c),
        "metadata remains readable during recovery without granting write access");
}
