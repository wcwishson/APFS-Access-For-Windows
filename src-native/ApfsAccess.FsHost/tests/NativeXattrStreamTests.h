// Included after DirectorySymlinkFixture; these tests invoke the real callbacks.
#pragma once

bool TestNativeXattrNoncanonicalEnumeration()
{
    MountContext c{};
    SeedRoot(c);
    auto node = MakeNode(L"\\file", false, false);
    node->object_id = 17;
    c.nodes.emplace(Key(node->path), node);
    c.owned_metadata_store = std::make_unique<apfsaccess::rw::MetadataStore>(apfsaccess::rw::MetadataStore::VolumeContext{});
    c.metadata_store = c.owned_metadata_store.get();
    OpenContext base{}; base.node = node;
    auto fs = BuildFileSystem(&c);
    std::array<std::byte, 512> bytes{}; ULONG done = 0;
    if (!Require(NT_SUCCESS(CB_GetStreamInfo(&fs, &base, bytes.data(), bytes.size(), &done)),
            "noncanonical provider can enumerate its ordinary default stream")) return false;
    const auto* entry = reinterpret_cast<const FSP_FSCTL_STREAM_INFO*>(bytes.data());
    PVOID protocol = nullptr; FSP_FSCTL_FILE_INFO info{};
    auto name = std::wstring(L"\\file:APFS.XattrProtocol:$DATA");
    return Require(done == entry->Size &&
        entry->Size == sizeof(*entry) &&
        CB_Open(&fs, name.data(), FILE_NON_DIRECTORY_FILE | (FILE_OPEN << 24), GENERIC_READ, &protocol, &info) == STATUS_NOT_SUPPORTED,
        "noncanonical source does not advertise or open a native attribute protocol");
}

bool TestNativeXattrStreams188(bool manifest, bool interrupt = false, int rejected_mutation = 0, bool kernel_names = false)
{
    using namespace apfsaccess::rw;
    using Store = MetadataStore;
    using Tx = TransactionManager;
    DirectorySymlinkFixture fixture(manifest);
    auto builder = TwoProjectableVolumeStore();
    if (!manifest) builder.volumes.resize(1);
    builder.authoritative_checkpoint = true; builder.dual_checkpoint = false; builder.xid = 20;
    auto& volume = builder.volumes.front();
    auto& records = volume.filesystem_records;
    apfsaccess::catalog::BtreeRecord encoded;
    std::string error;
    const auto add = [&](bool ok) { if (ok) records.push_back(encoded); return ok; };
    AppleInodeRecord root;
    root.object_id = root.private_id = root.parent_id = 2; root.mode = 0040755; root.children_or_links = 1;
    if (!add(EncodeAppleInodeRecord(root, encoded, error))) return false;
    const auto content = BuildPatternPayloadForTest(32, 0x19);
    AppleInodeRecord inode;
    inode.object_id = inode.private_id = 17; inode.parent_id = 2; inode.children_or_links = 1;
    inode.mode = 0100640; inode.owner = 501; inode.group = 20; inode.uncompressed_size = content.size();
    inode.create_time = inode.modification_time = inode.change_time = inode.access_time = 1700000000000000000ULL;
    AppleExtendedField stream; stream.type = 8; stream.data.resize(40);
    apfsaccess::testfixture::PutU64LE(stream.data, 0, content.size());
    apfsaccess::testfixture::PutU64LE(stream.data, 8, 4096);
    inode.extended_fields.push_back(stream);
    if (!add(EncodeAppleInodeRecord(inode, encoded, error))) return false;
    AppleDirectoryRecord link; link.parent_id = 2; link.file_id = 17; link.flags = 8; link.name_utf8 = "file";
    if (!add(EncodeAppleDirectoryRecord(link, encoded, error))) return false;
    const auto payload = [&](std::uint64_t id, std::uint64_t physical, std::vector<std::byte> bytes) {
        if (!add(EncodeAppleDataStreamIdRecord({id, 1}, encoded, error)) ||
            !add(EncodeAppleFileExtentRecord({id, 0, 4096, physical, 0, 4096}, encoded, error)) ||
            !EncodeApplePhysicalExtentRecord({physical, 1, kApplePhysicalExtentKindNew, id, 1}, encoded, error)) return false;
        volume.extentref_records.push_back(encoded); ++volume.additional_file_system_allocated_blocks;
        bytes.resize(4096); builder.authoritative_seeded_main_blocks.push_back({physical, bytes}); return true;
    };
    const auto external = BuildPatternPayloadForTest(257, 0x71);
    const std::vector<std::byte> finder(32, std::byte{0x46});
    const std::vector<std::byte> binary{std::byte{0}, std::byte{0xff}, std::byte{0x42}};
    const std::vector<std::byte> apple_acl{std::byte{0xfd}, std::byte{0}, std::byte{0x9c}, std::byte{0x12}};
    std::vector<std::byte> descriptor(kAppleXattrDataStreamBytes);
    apfsaccess::testfixture::PutU64LE(descriptor, 0, 777);
    apfsaccess::testfixture::PutU64LE(descriptor, 8, external.size());
    apfsaccess::testfixture::PutU64LE(descriptor, 16, 4096);
    if (!add(EncodeAppleXattrRecord({17, "com.apple.ResourceFork", kAppleXattrDataStream, descriptor}, encoded, error)) ||
        !add(EncodeAppleXattrRecord({17, "com.apple.FinderInfo", kAppleXattrDataEmbedded, finder}, encoded, error)) ||
        !add(EncodeAppleXattrRecord({17, "user.Binary", kAppleXattrDataEmbedded, binary}, encoded, error)) ||
        !add(EncodeAppleXattrRecord({17, kAppleSecurityName, kAppleXattrDataEmbedded, apple_acl}, encoded, error)) ||
        !payload(17, 100, content) || !payload(777, 102, external) ||
        !SortAppleBtreeRecords(records, AppleBtreeKeyOrder::FileSystemCaseSensitive, error) ||
        !SortAppleBtreeRecords(volume.extentref_records, AppleBtreeKeyOrder::PhysicalExtent, error) ||
        !WriteFileBytes(fixture.image.path, apfsaccess::testfixture::BuildStoreImage(builder)) || !fixture.Initialize(manifest)) return false;
    auto& c = *fixture.context; auto fs = BuildFileSystem(&c);
    FSP_FSCTL_FILE_INFO info{};
    std::vector<PVOID> handles;
    ScopeExit close{[&] { for (auto handle : handles) CB_Close(&fs, handle); }};
    const auto open = [&](const std::wstring& suffix, PVOID& handle, UINT32 access = GENERIC_READ | GENERIC_WRITE | DELETE) {
        auto path = L"\\file" + suffix;
        if (kernel_names && path.ends_with(L":$DATA")) path.resize(path.size() - 6);
        if (kernel_names)
        {
            SIZE_T size = 0; UINT32 attributes = 0;
            const auto security = CB_GetSecurityByName(&fs, path.data(), &attributes, nullptr, &size);
            if (security != STATUS_BUFFER_OVERFLOW && !NT_SUCCESS(security)) return security;
        }
        const auto status = CB_Open(&fs, path.data(), FILE_NON_DIRECTORY_FILE | (FILE_OPEN << 24), access, &handle, &info);
        if (NT_SUCCESS(status)) handles.push_back(handle);
        return status;
    };
    const auto read = [&](PVOID handle, const std::vector<std::byte>& expected) {
        std::vector<std::byte> bytes(expected.size() + 8, std::byte{0x55}); ULONG done = 0;
        return Require(NT_SUCCESS(CB_Read(&fs, handle, bytes.data(), 0, static_cast<ULONG>(bytes.size()), &done)) &&
            done == expected.size() && std::equal(expected.begin(), expected.end(), bytes.begin()), "native stream exact bytes and EOF");
    };
    PVOID resource = nullptr, generic = nullptr, inline_handle = nullptr, finder_handle = nullptr;
    if (!Require(NT_SUCCESS(open(L":APFS.ResourceFork:$DATA", resource)) &&
            NT_SUCCESS(open(NativeXattrStreamName("com.apple.ResourceFork"), generic)) &&
            NT_SUCCESS(open(NativeXattrStreamName("user.Binary"), inline_handle)) &&
            NT_SUCCESS(open(L":APFS.FinderInfo:$DATA", finder_handle)), "imported native streams open without ADS") ||
        !read(resource, external) || !read(generic, external) || !read(inline_handle, binary) || !read(finder_handle, finder)) return false;
    if (!Require(static_cast<OpenContext*>(generic)->file == INVALID_HANDLE_VALUE && c.named_stream_sizes.empty(),
            "native streams never acquire temporary NTFS handles")) return false;
    if (kernel_names)
    {
        FSP_FSCTL_VOLUME_PARAMS params{}; FILETIME now{};
        ConfigureVolumeParamsForExplorer(c, now, params);
        if (!Require(params.StreamInfoTimeoutValid && params.StreamInfoTimeout == 0,
                "handle-dependent native inspection cannot share the base-file stream cache")) return false;
    }
    if (rejected_mutation)
    {
        const auto image_before = ReadFileBytes(fixture.image.path);
        const auto journal_before = ReadFileBytes(c.session_root / "accepted.wal");
        const auto accepted_before = c.tx_manager->Watermarks().accepted_sequence;
        // An existing directory cannot be a WAL. The real callback stages its
        // native change before journal admission discovers this failure.
        c.tx_manager->SetJournalPath(c.session_root.wstring());
        ULONG done = 99;
        std::byte replacement{0x73};
        const auto status = rejected_mutation == 1
            ? CB_Write(&fs, inline_handle, &replacement, 0, 1, FALSE, FALSE, &done, &info)
            : CB_SetDelete(&fs, inline_handle, nullptr, TRUE);
        bool ok = Require(!NT_SUCCESS(status) && (rejected_mutation != 1 || done == 0) &&
            c.unjournaled_native_mutation && c.metadata_store->PendingMutationCount() > 0 &&
            c.tx_manager->Watermarks().accepted_sequence == accepted_before &&
            image_before == ReadFileBytes(fixture.image.path) &&
            journal_before == ReadFileBytes(c.session_root / "accepted.wal"),
            "preaccept failure retains staged evidence without accepting WAL or changing canonical source");
        std::array<std::byte, 32> value{};
        done = 99;
        ok &= Require(!NT_SUCCESS(CB_Read(&fs, inline_handle, value.data(), 0, value.size(), &done)) && done == 0,
            "rejected native set or remove never leaks staged bytes through a retained stream");
        ok &= Require(!NT_SUCCESS(CB_GetFileInfo(&fs, inline_handle, &info)),
            "rejected native mutation does not report working stream metadata as authoritative");
        PVOID base = nullptr;
        const auto opened = open(L"", base, GENERIC_READ);
        std::array<std::byte, 8192> streams{};
        done = 99;
        ok &= Require(NT_SUCCESS(opened) &&
            !NT_SUCCESS(CB_GetStreamInfo(&fs, base, streams.data(), streams.size(), &done)) && done == 0,
            "fresh enumeration refuses the unresolved native attribute namespace");
        Store canonical(fixture.volume);
        ok &= Require(canonical.PrepareNativeWritePath() &&
            canonical.LookupCommittedExtendedAttribute(17, "user.Binary")->data == binary,
            "fresh canonical reopen retains the old attribute after rejected set or remove");
        return ok;
    }
    std::array<std::byte, 8192> enumeration{}; ULONG enumerated = 0;
    if (!Require(NT_SUCCESS(CB_GetStreamInfo(&fs, resource, enumeration.data(), enumeration.size(), &enumerated)),
            "native enumeration succeeds")) return false;
    std::vector<std::wstring> names;
    for (ULONG offset = 0; offset < enumerated;)
    {
        auto* entry = reinterpret_cast<FSP_FSCTL_STREAM_INFO*>(enumeration.data() + offset);
        const std::wstring bare(entry->StreamNameBuf, (entry->Size - sizeof(FSP_FSCTL_STREAM_INFO)) / sizeof(WCHAR));
        if (!Require(bare.find(L':') == std::wstring::npos, "WinFsp callback stream names are undecorated")) return false;
        names.push_back(L":" + bare + L":$DATA");
        offset += entry->Size;
    }
    if (!Require(names.size() == 4 && std::count(names.begin(), names.end(), NativeXattrStreamName("com.apple.ResourceFork")) == 1 &&
            std::count(names.begin(), names.end(), NativeXattrStreamName(kAppleSecurityName)) == 0 &&
            std::count(names.begin(), names.end(), L":APFS.XattrProtocol:$DATA") == 0,
            "ordinary copy enumerates each user data attribute once without protected metadata or protocol")) return false;
    const auto before = ReadFileBytes(fixture.image.path);
    const auto wal_before = ReadFileBytes(c.session_root / "accepted.wal");
    const auto watermark = c.tx_manager->Watermarks().accepted_sequence;
    PVOID protocol = nullptr;
    const std::string protocol_text = "APFS-XATTR/1\n";
    const auto* protocol_begin = reinterpret_cast<const std::byte*>(protocol_text.data());
    if (!Require(NT_SUCCESS(open(L":APFS.XattrProtocol:$DATA", protocol, GENERIC_READ)),
            "provider protocol opens read-only") ||
        !read(protocol, std::vector<std::byte>(protocol_begin, protocol_begin + protocol_text.size()))) return false;
    enumerated = 0;
    if (!Require(NT_SUCCESS(CB_GetStreamInfo(&fs, protocol, enumeration.data(), enumeration.size(), &enumerated)),
            "explicit native protocol handle enumerates all original attributes")) return false;
    names.clear();
    for (ULONG offset = 0; offset < enumerated;)
    {
        auto* entry = reinterpret_cast<FSP_FSCTL_STREAM_INFO*>(enumeration.data() + offset);
        const std::wstring bare(entry->StreamNameBuf, (entry->Size - sizeof(FSP_FSCTL_STREAM_INFO)) / sizeof(WCHAR));
        if (!Require(bare.find(L':') == std::wstring::npos, "protocol listing also uses bare WinFsp names")) return false;
        names.push_back(L":" + bare + L":$DATA");
        offset += entry->Size;
    }
    if (!Require(names.size() == 5 && std::count(names.begin(), names.end(), NativeXattrStreamName(kAppleSecurityName)) == 1 &&
            std::count(names.begin(), names.end(), L":APFS.XattrProtocol:$DATA") == 0,
            "CLI inspection includes preserved Mac ACL without making the protocol a copyable stream")) return false;
    PVOID refused_protocol = nullptr;
    if (!Require(open(L":APFS.XattrProtocol:$DATA", refused_protocol) == STATUS_ACCESS_DENIED,
            "provider protocol never grants mutation access")) return false;
    ULONG protocol_done = 19;
    std::byte protocol_byte{1};
    if (!Require(!NT_SUCCESS(CB_Write(&fs, protocol, &protocol_byte, 0, 1, FALSE, FALSE, &protocol_done, &info)) &&
            protocol_done == 0 && !NT_SUCCESS(CB_SetFileSize(&fs, protocol, 1, FALSE, &info)) &&
            !NT_SUCCESS(CB_SetDelete(&fs, protocol, nullptr, TRUE)), "provider protocol mutations fail before native staging")) return false;
    for (const auto* malformed : {L":APFS.Xattr.0:$DATA", L":APFS.Xattr.GG:$DATA", L":APFS.Xattr.00:$DATA",
            L":APFS.Xattr.C080:$DATA", L":APFS.Xattr.EDA080:$DATA", L":APFS.Xattr.:$DATA", L":APFS.Xattr.41:$INDEX_ALLOCATION"})
    {
        PVOID rejected = nullptr;
        if (!Require(open(malformed, rejected) == STATUS_OBJECT_NAME_INVALID, "malformed reserved spelling refuses before ADS")) return false;
    }
    for (const auto* protected_name : {"com.apfsaccess.windows.Security", "com.apple.system.Security", "com.apple.decmpfs"})
    {
        auto path = L"\\file" + NativeXattrStreamName(protected_name); PVOID rejected = nullptr;
        if (!Require(!NT_SUCCESS(CB_Create(&fs, path.data(), FILE_NON_DIRECTORY_FILE, GENERIC_ALL, 0, nullptr, 0, &rejected, &info)),
                "protected xattr create refuses")) return false;
        OpenContext probe; probe.node = static_cast<OpenContext*>(resource)->node; probe.native_xattr_name = protected_name;
        probe.native_xattr = std::make_shared<NativeXattrStreamState>(); probe.named_stream = true; InitializeOpenAccess(&probe, GENERIC_ALL);
        ULONG done = 99; std::byte byte{1};
        if (!Require(!NT_SUCCESS(CB_Write(&fs, &probe, &byte, 0, 1, FALSE, FALSE, &done, &info)) && done == 0 &&
                !NT_SUCCESS(CB_SetDelete(&fs, &probe, path.data(), TRUE)), "protected writes and removes refuse")) return false;
    }
    if (!Require(before == ReadFileBytes(fixture.image.path) && wal_before == ReadFileBytes(c.session_root / "accepted.wal") &&
            watermark == c.tx_manager->Watermarks().accepted_sequence &&
            !c.write_degraded && !c.unjournaled_native_mutation && c.metadata_store->PendingMutationCount() == 0,
            "refusals leave image WAL and health unchanged")) return false;
    ULONG done = 0; std::byte replacement{0x73};
    if (interrupt)
    {
        unsigned faults = 0;
        c.metadata_store->SetCommitStageHook([&](std::string_view stage) {
            if (stage != "before-apple-publish") return true;
            ++faults; return false;
        });
        const auto status = CB_Write(&fs, generic, &replacement, 0, 1, FALSE, FALSE, &done, &info);
        const auto marks = c.tx_manager->Watermarks();
        if (!Require(!NT_SUCCESS(status) && done == 0 && faults == 1 && marks.accepted_sequence > marks.apfs_durable_sequence &&
                before == ReadFileBytes(fixture.image.path), "callback interruption retains accepted WAL without claiming bytes or durability")) return false;
        for (auto handle : handles) CB_Close(&fs, handle); handles.clear();
        StopDeferredCommitWorker(&c); c.metadata_store->SetCommitStageHook({});
        const auto args = c.args; const auto session = c.session_root;
        fixture.context.reset();
        auto recovered = std::make_unique<MountContext>(); recovered->args = args; recovered->native_write_enabled = true;
        recovered->session_root = session; recovered->recovery_marker_file = session / "recovery.marker";
        recovered->owned_metadata_store = std::make_unique<Store>(fixture.volume); recovered->metadata_store = recovered->owned_metadata_store.get();
        recovered->tx_manager = std::make_unique<Tx>(L"Conservative");
        recovered->tx_manager->SetVolumeIdentity(L"directory-symlink-volume");
        recovered->tx_manager->SetJournalPath((session / "accepted.wal").wstring());
        fixture.context = std::move(recovered); auto& r = *fixture.context;
        std::vector<Tx::AcceptedTransaction> accepted;
        if (!Require(r.metadata_store->PrepareNativeWritePath() && r.tx_manager->LoadUnappliedAcceptedTransactions(accepted) &&
                accepted.size() == 1 && accepted.front().mutations.size() == 1 &&
                accepted.front().mutations.front().object_id == 17 &&
                accepted.front().mutations.front().secondary_path_utf8 == "com.apple.ResourceFork" &&
                ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(r), "fresh canonical store recovers exact callback-accepted identity and attribute")) return false;
        auto expected = external; expected[0] = replacement; std::vector<std::byte> bytes(expected.size()); std::size_t count = 0;
        const auto stable = ReadFileBytes(fixture.image.path);
        return Require(r.metadata_store->ReadCommittedExtendedAttributeRange(17, "com.apple.ResourceFork", 0, bytes, count) && bytes == expected &&
            count == expected.size() && r.tx_manager->Watermarks().apfs_durable_sequence == marks.accepted_sequence &&
            ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(r) && stable == ReadFileBytes(fixture.image.path), "recovered bytes durable and second replay idempotent");
    }
    PVOID lower_hex = nullptr, protected_query = nullptr;
    if (!Require(NT_SUCCESS(open(ToLowerInvariant(NativeXattrStreamName("user.Binary")), lower_hex)) &&
            NT_SUCCESS(open(NativeXattrStreamName(kAppleSecurityName), protected_query, GENERIC_READ)),
            "lowercase hex aliases exact bytes and protected attributes remain queryable") ||
        !read(lower_hex, binary) || !read(protected_query, apple_acl)) return false;
    PVOID missing_case = nullptr;
    if (!Require(open(NativeXattrStreamName("user.binary"), missing_case) == STATUS_OBJECT_NAME_NOT_FOUND,
            "attribute byte case is never folded")) return false;
    if (!Require(CB_SetFileSize(&fs, resource, WriteAheadLog::MaxExtendedAttributePayloadBytes + 1, FALSE, &info) == STATUS_NOT_SUPPORTED &&
            !c.write_degraded, "oversize edit refuses without degrading")) return false;
    auto new_path = L"\\file" + NativeXattrStreamName("user.created"); PVOID created = nullptr;
    if (!Require(NT_SUCCESS(CB_Create(&fs, new_path.data(), FILE_NON_DIRECTORY_FILE, GENERIC_ALL, 0, nullptr, 0, &created, &info)),
            "Create commits an actual empty APFS attribute")) return false;
    handles.push_back(created);
    if (!Require(NT_SUCCESS(CB_Write(&fs, created, &replacement, 0, 1, FALSE, FALSE, &done, &info)) &&
            NT_SUCCESS(CB_Overwrite(&fs, created, 0, FALSE, 0, &info)) && info.FileSize == 0 &&
            NT_SUCCESS(CB_SetDelete(&fs, created, new_path.data(), TRUE)), "create write overwrite remove use real callbacks")) return false;
    CB_Cleanup(&fs, created, new_path.data(), FspCleanupDelete);
    CB_Cleanup(&fs, created, new_path.data(), FspCleanupDelete);
    if (!Require(!c.metadata_store->LookupCommittedExtendedAttribute(17, "user.created"), "duplicate cleanup never recreates a removed stream")) return false;
    if (!Require(NT_SUCCESS(CB_Write(&fs, generic, &replacement, external.size() + 2, 1, FALSE, FALSE, &done, &info)) && done == 1,
            "healthy next operation performs real offset write")) return false;
    auto expected = external; expected.resize(external.size() + 3); expected.back() = replacement;
    if (!read(resource, expected) || !Require(NT_SUCCESS(CB_SetFileSize(&fs, resource, 4, FALSE, &info)) && info.FileSize == 4,
            "shortcut truncation has native info")) return false;
    expected.resize(4);
    if (!read(generic, expected) || !Require(NT_SUCCESS(CB_Flush(&fs, generic, &info)) &&
            c.tx_manager->Watermarks().apfs_durable_sequence == c.tx_manager->Watermarks().accepted_sequence,
            "Flush uses native durable watermark")) return false;
    if (!Require(NT_SUCCESS(CB_SetDelete(&fs, resource, nullptr, TRUE)) &&
            !c.metadata_store->LookupCommittedExtendedAttribute(17, "com.apple.ResourceFork") && read(generic, expected) &&
            NT_SUCCESS(CB_SetDelete(&fs, resource, nullptr, FALSE)), "delete is native and cancellation restores exact bytes")) return false;
    PVOID base = nullptr;
    if (!Require(NT_SUCCESS(open(L"", base)) && NT_SUCCESS(CB_Rename(&fs, base, const_cast<PWSTR>(L"\\file"),
            const_cast<PWSTR>(L"\\renamed"), FALSE)) && read(generic, expected), "base rename preserves retained xattr identity")) return false;
    Store fresh(fixture.volume);
    std::vector<std::byte> actual(expected.size()); std::size_t count = 0; std::vector<std::byte> actual_content;
    if (!Require(fresh.PrepareNativeWritePath(), "fresh canonical reopen")) return false;
    const auto final = fresh.LookupCommittedInodeByPath(L"\\renamed");
    if (!Require(final && final->object_id == 17 && final->owner == 501 && final->group == 20 && final->mode == 0100640 &&
        fresh.ReadCommittedFileRange(L"\\renamed", 0, content.size(), actual_content) && actual_content == content &&
        fresh.ReadCommittedExtendedAttributeRange(17, "com.apple.ResourceFork", 0, actual, count) && actual == expected &&
        fresh.LookupCommittedExtendedAttribute(17, kAppleSecurityName)->data == apple_acl &&
        fresh.LookupCommittedExtendedAttribute(17, "com.apple.FinderInfo")->data == finder,
        "fresh image has native edited bytes and preserves default content Mac owner group mode ACL and unrelated FinderInfo")) return false;
    PVOID replacement_base = nullptr;
    if (!Require(NT_SUCCESS(CB_Create(&fs, const_cast<PWSTR>(L"\\replacement"), FILE_NON_DIRECTORY_FILE, GENERIC_ALL,
            0, nullptr, 0, &replacement_base, &info)), "replacement identity creates")) return false;
    handles.push_back(replacement_base);
    if (!Require(NT_SUCCESS(CB_Rename(&fs, replacement_base, const_cast<PWSTR>(L"\\replacement"),
            const_cast<PWSTR>(L"\\renamed"), TRUE)), "base replacement uses native rename") || !read(generic, expected)) return false;
    done = 17;
    return Require(CB_Write(&fs, generic, &replacement, 0, 1, FALSE, FALSE, &done, &info) == STATUS_FILE_DELETED && done == 0 &&
        c.metadata_store->LookupCommittedInodeByPath(L"\\renamed")->object_id != 17 && !c.write_degraded,
        "retained stream reads old identity and cannot write the replacement inode");
}
