#pragma once

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
