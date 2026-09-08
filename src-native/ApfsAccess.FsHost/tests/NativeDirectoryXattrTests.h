// Included after DirectorySymlinkFixture and native stream callback helpers.
#pragma once

bool TestNativeDirectoryXattr(bool manifest)
{
    using namespace apfsaccess::rw;
    DirectorySymlinkFixture fixture(manifest);
    auto builder = TwoProjectableVolumeStore();
    if (!manifest) builder.volumes.resize(1);
    builder.authoritative_checkpoint = true;
    builder.dual_checkpoint = false;
    builder.xid = 20;
    auto& records = builder.volumes.front().filesystem_records;
    apfsaccess::catalog::BtreeRecord encoded;
    std::string error;
    const auto add = [&](bool ok) { if (ok) records.push_back(encoded); return ok; };
    AppleInodeRecord root;
    root.object_id = root.private_id = root.parent_id = 2;
    root.mode = 0040755; root.children_or_links = 1;
    AppleInodeRecord dir;
    dir.object_id = dir.private_id = 17; dir.parent_id = 2;
    dir.mode = 0040750; dir.owner = 501; dir.group = 20;
    dir.create_time = dir.modification_time = dir.change_time = dir.access_time = 1700000000000000000ULL;
    AppleDirectoryRecord link;
    link.parent_id = 2; link.file_id = 17; link.flags = 4; link.name_utf8 = "folder";
    const std::vector<std::byte> finder(32, std::byte{0x46});
    const std::vector<std::byte> acl{std::byte{0xfd}, std::byte{0}, std::byte{0x9c}};
    if (!add(EncodeAppleInodeRecord(root, encoded, error)) ||
        !add(EncodeAppleInodeRecord(dir, encoded, error)) ||
        !add(EncodeAppleDirectoryRecord(link, encoded, error)) ||
        !add(EncodeAppleXattrRecord({17, "com.apple.FinderInfo", kAppleXattrDataEmbedded, finder}, encoded, error)) ||
        !add(EncodeAppleXattrRecord({17, kAppleSecurityName, kAppleXattrDataEmbedded, acl}, encoded, error)) ||
        !SortAppleBtreeRecords(records, AppleBtreeKeyOrder::FileSystemCaseSensitive, error) ||
        !WriteFileBytes(fixture.image.path, apfsaccess::testfixture::BuildStoreImage(builder)) ||
        !fixture.Initialize(manifest)) return false;
    auto& c = *fixture.context;
    auto fs = BuildFileSystem(&c);
    FSP_FSCTL_FILE_INFO info{};
    std::vector<PVOID> handles;
    ScopeExit close{[&] { for (auto handle : handles) CB_Close(&fs, handle); }};
    auto open = [&](std::wstring path, UINT32 access, PVOID& handle) {
        const auto status = CB_Open(&fs, path.data(), FILE_NON_DIRECTORY_FILE | (FILE_OPEN << 24), access, &handle, &info);
        if (NT_SUCCESS(status)) handles.push_back(handle);
        return status;
    };
    const auto read = [&](PVOID handle, const std::vector<std::byte>& expected) {
        std::vector<std::byte> bytes(expected.size() + 8);
        ULONG done = 0;
        return Require(NT_SUCCESS(CB_Read(&fs, handle, bytes.data(), 0, static_cast<ULONG>(bytes.size()), &done)) &&
            done == expected.size() && std::equal(expected.begin(), expected.end(), bytes.begin()), "directory attribute exact bytes");
    };
    PVOID attribute = nullptr;
    if (!Require(NT_SUCCESS(open(L"\\folder:APFS.FinderInfo:$DATA", GENERIC_READ | GENERIC_WRITE | DELETE, attribute)) &&
        !(info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY), "folder FinderInfo opens as a data stream") || !read(attribute, finder)) return false;
    SIZE_T security_size = 0;
    UINT32 attributes = FILE_ATTRIBUTE_DIRECTORY;
    auto finder_path = std::wstring(L"\\folder:APFS.FinderInfo");
    const auto security_status = CB_GetSecurityByName(&fs, finder_path.data(), &attributes, nullptr, &security_size);
    if (!Require((NT_SUCCESS(security_status) || security_status == STATUS_BUFFER_OVERFLOW) &&
        !(attributes & FILE_ATTRIBUTE_DIRECTORY), "stream security lookup reports data-stream type")) return false;
    PVOID protocol = nullptr;
    if (!Require(NT_SUCCESS(open(L"\\folder:APFS.XattrProtocol:$DATA", GENERIC_READ, protocol)), "folder protocol opens")) return false;
    std::array<std::byte, 4096> listing{};
    ULONG done = 0;
    if (!Require(NT_SUCCESS(CB_GetStreamInfo(&fs, protocol, listing.data(), listing.size(), &done)) && done > 0,
        "folder native attributes enumerate through the real callback")) return false;
    bool saw_finder = false, saw_acl = false;
    for (ULONG offset = 0; offset < done;)
    {
        const auto* entry = reinterpret_cast<const FSP_FSCTL_STREAM_INFO*>(listing.data() + offset);
        if (!Require(entry->Size >= sizeof(*entry) && entry->Size <= done - offset, "bounded directory stream entry")) return false;
        const std::wstring bare(entry->StreamNameBuf, (entry->Size - sizeof(*entry)) / sizeof(WCHAR));
        if (!Require(!bare.empty(), "directory has no unnamed data stream")) return false;
        saw_finder |= bare == StreamNameForWin32Path(NativeXattrStreamName("com.apple.FinderInfo"));
        saw_acl |= bare == StreamNameForWin32Path(NativeXattrStreamName(kAppleSecurityName));
        offset += entry->Size;
    }
    if (!Require(saw_finder && saw_acl, "folder protocol includes FinderInfo and original Mac ACL")) return false;
    PVOID created = nullptr;
    auto created_path = L"\\folder" + NativeXattrStreamName("user.folder");
    if (!Require(NT_SUCCESS(CB_Create(&fs, created_path.data(), FILE_NON_DIRECTORY_FILE, GENERIC_ALL,
        0, nullptr, 0, &created, &info)), "create directory native attribute")) return false;
    handles.push_back(created);
    auto value = BuildPatternPayloadForTest(47, 0x81);
    if (!Require(NT_SUCCESS(CB_Write(&fs, created, value.data(), 0, static_cast<ULONG>(value.size()), FALSE, FALSE, &done, &info)) &&
        done == value.size() && NT_SUCCESS(CB_SetFileSize(&fs, created, 19, FALSE, &info)), "write and truncate folder native attribute")) return false;
    value.resize(19);
    if (!read(created, value)) return false;
    if (!Require(NT_SUCCESS(CB_Flush(&fs, created, &info)), "folder attribute durable flush")) return false;
    if (!Require(CB_Rename(&fs, nullptr, const_cast<PWSTR>(L"\\folder"), const_cast<PWSTR>(L"\\renamed"), FALSE) == STATUS_SHARING_VIOLATION,
        "folder rename retains existing open-handle exclusion") || !read(created, value)) return false;
    for (auto handle : handles) CB_Close(&fs, handle);
    handles.clear();
    if (!Require(NT_SUCCESS(CB_Rename(&fs, nullptr, const_cast<PWSTR>(L"\\folder"), const_cast<PWSTR>(L"\\renamed"), FALSE)),
        "closed folder rename preserves native attributes")) return false;
    if (!Require(NT_SUCCESS(open(L"\\renamed" + NativeXattrStreamName("user.folder"), GENERIC_ALL, created)) &&
        NT_SUCCESS(open(L"\\renamed:APFS.FinderInfo:$DATA", GENERIC_READ, attribute)), "renamed folder attributes reopen") ||
        !read(created, value) || !read(attribute, finder)) return false;
    MetadataStore fresh(fixture.volume);
    if (!Require(fresh.PrepareNativeWritePath(), "fresh directory attribute image reopen")) return false;
    const auto owner = fresh.LookupCommittedInodeByPath(L"\\renamed");
    const auto saved = fresh.LookupCommittedExtendedAttribute(17, "user.folder");
    const auto saved_acl = fresh.LookupCommittedExtendedAttribute(17, kAppleSecurityName);
    if (!Require(owner && owner->is_directory && owner->mode == dir.mode && owner->owner == dir.owner && owner->group == dir.group &&
        saved && saved->data == value && saved_acl && saved_acl->data == acl,
        "fresh image preserves edited folder bytes and original Mac permissions")) return false;
    if (!Require(NT_SUCCESS(CB_Overwrite(&fs, created, 0, FALSE, 0, &info)) && info.FileSize == 0 &&
        NT_SUCCESS(CB_SetDelete(&fs, created, nullptr, TRUE)), "folder attribute overwrite and delete")) return false;
    CB_Cleanup(&fs, created, nullptr, FspCleanupDelete);
    MetadataStore deleted(fixture.volume);
    return Require(deleted.PrepareNativeWritePath() && deleted.LookupCommittedInodeByPath(L"\\renamed") &&
        !deleted.LookupCommittedExtendedAttribute(17, "user.folder") &&
        deleted.LookupCommittedExtendedAttribute(17, "com.apple.FinderInfo")->data == finder && !c.write_degraded,
        "attribute deletion preserves healthy folder and unrelated FinderInfo");
}
