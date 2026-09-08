#pragma once

// Task5: include after the existing compression fixture helpers. Registration
// belongs to the parent. These are synthetic Apple-format images, not an
// Apple-made corpus or evidence of macOS acceptance. No WinFsp mount is needed.
bool RunNativeCompressionReadTask5(bool malformed, bool resource_backed = false, bool lzfse = false)
{
    using namespace apfsaccess::rw;
    using Store = MetadataStore;
    // Check before DirectorySymlinkFixture constructs its temporary image.
    if (!Require(ToLowerInvariant(std::filesystem::temp_directory_path().root_name().wstring()) == L"d:",
            "Task5 requires runner TEMP/TMP on D: before fixture construction")) return false;
    for (const bool manifest : {false, true})
    {
        DirectorySymlinkFixture fixture(manifest);
        auto& c = *fixture.context;
        c.args.write_require_canonical_commit = true;
        c.args.allow_legacy_scaffold_for_fixtures = false;
        auto builder = TwoProjectableVolumeStore();
        if (!manifest) builder.volumes.resize(1);
        builder.authoritative_checkpoint = true;
        builder.dual_checkpoint = false;
        builder.xid = 20;
        auto& records = builder.volumes.front().filesystem_records;
        apfsaccess::catalog::BtreeRecord encoded;
        std::string error;
        const auto add = [&](bool valid) {
            if (!Require(valid, "Task5 Apple fixture record encodes")) return false;
            records.push_back(encoded);
            return true;
        };
        // Small records and frozen compressed bytes fit the fixture's single leaf.
        AppleInodeRecord root;
        root.object_id = root.private_id = root.parent_id = 2;
        root.mode = 0040755; root.children_or_links = 1;
        if (!add(EncodeAppleInodeRecord(root, encoded, error))) return false;
        AppleInodeRecord inode;
        inode.object_id = inode.private_id = 17; inode.parent_id = 2;
        inode.children_or_links = 1;
        inode.mode = 0100640; inode.owner = 501; inode.group = 20;
        inode.bsd_flags = kAppleBsdCompressedFlag; inode.uncompressed_size = 5;
        inode.create_time = inode.modification_time = inode.change_time = inode.access_time = 1700000000000000000ULL;
        AppleExtendedField stream;
        stream.type = 8; stream.data.resize(40); // Compressed dstream has no ordinary payload.
        inode.extended_fields.push_back(stream);
        if (!add(EncodeAppleInodeRecord(inode, encoded, error))) return false;
        AppleDirectoryRecord link;
        link.parent_id = 2; link.file_id = 17; link.flags = 8; link.name_utf8 = "compressed";
        if (!add(EncodeAppleDirectoryRecord(link, encoded, error))) return false;
        // Frozen vectors from TestLzvnInlineKnownBytes/TestLzvnInlineRefusals.
        // e5 + "hello" + canonical EOS; malformed variant has a partial EOS.
        const auto payload = HostCompressionHex(lzfse ? (malformed ?
            "6276782d0500000068656c6c6f627678" : "6276782d0500000068656c6c6f62767824") : (malformed ?
                "e568656c6c6f06" : "e568656c6c6f0600000000000000"));
        const auto type = lzfse ? (resource_backed ? 12 : 11) : (resource_backed ? 8 : 7);
        const auto marker = HostCompressionAttribute(type, 5,
            resource_backed ? std::vector<std::byte>{} : payload);
        std::vector<std::byte> fork;
        if (resource_backed)
        {
            fork.resize(8);
            apfsaccess::testfixture::PutU32LE(fork, 0, 8);
            apfsaccess::testfixture::PutU32LE(fork, 4, static_cast<std::uint32_t>(8 + payload.size()));
            fork.insert(fork.end(), payload.begin(), payload.end());
            if (!add(EncodeAppleXattrRecord({17, "com.apple.ResourceFork", kAppleXattrDataEmbedded, fork}, encoded, error))) return false;
        }
        const auto acl = HostCompressionHex("fd009c12"); // Existing opaque Mac ACL fixture.
        if (!add(EncodeAppleXattrRecord({17, "com.apple.decmpfs", kAppleXattrDataEmbedded, marker}, encoded, error)) ||
            !add(EncodeAppleXattrRecord({17, kAppleSecurityName, kAppleXattrDataEmbedded, acl}, encoded, error)) ||
            !Require(SortAppleBtreeRecords(records, AppleBtreeKeyOrder::FileSystemCaseSensitive, error) &&
                WriteFileBytes(fixture.image.path, apfsaccess::testfixture::BuildStoreImage(builder)) &&
                fixture.Initialize(manifest), "Task5 strict direct/manifest image initializes")) return false;
        auto& store = *c.metadata_store;
        auto fs = BuildFileSystem(&c);
        auto node = FindNode(&c, L"\\compressed");
        if (!Require(node && c.args.write_require_canonical_commit &&
                !c.args.allow_legacy_scaffold_for_fixtures && !fixture.volume.allow_legacy_scaffold_for_fixtures &&
                store.AuthoritativeAppleCheckpointView() && store.HasUnsupportedContentTransform(17),
                "Task5 canonical authority retains the compressed mutation guard")) return false;
        const auto plan = store.SnapshotCommittedFileReadPlan(NodePathKey(&c, *node));
        if (!Require(plan && plan->HasCompressionReadCandidate() && plan->unsupported_content_transform,
                "Task5 type7 is a read candidate, not write authority")) return false;
        const auto security = node->native_security;
        const auto preserved = [&] {
            const auto current = store.LookupCommittedInodeByPath(L"\\compressed");
            const auto current_acl = store.LookupCommittedExtendedAttribute(17, kAppleSecurityName);
            const auto current_marker = store.LookupCommittedExtendedAttribute(17, "com.apple.decmpfs");
            const auto current_fork = store.LookupCommittedExtendedAttribute(17, "com.apple.ResourceFork");
            return Require(current && current->object_id == 17 && current->mode == 0100640 &&
                current->owner == 501 && current->group == 20 && current->logical_size == 5 &&
                (current->bsd_flags & kAppleBsdCompressedFlag) && current_acl &&
                current_acl->flags == kAppleXattrDataEmbedded && current_acl->data == acl &&
                current_marker && current_marker->data == marker && node->native_security == security &&
                (resource_backed ? current_fork && current_fork->flags == kAppleXattrDataEmbedded && current_fork->data == fork : !current_fork),
                "Task5 preserves original Mac mode, UID, GID, opaque ACL and decmpfs bytes");
        };
        if (!preserved()) return false;
        const auto disk = [&] {
            std::map<std::filesystem::path, std::vector<std::byte>> files;
            for (const auto& entry : std::filesystem::recursive_directory_iterator(c.session_root))
                if (entry.is_regular_file()) files.emplace(entry.path(), ReadFileBytes(entry.path()));
            files.emplace(fixture.image.path, ReadFileBytes(fixture.image.path));
            return files;
        };
        const auto state = [&] {
            const auto marks = c.tx_manager->Watermarks();
            const auto spool = c.payload_spool->SnapshotCounters();
            return std::vector<std::uint64_t>{store.CheckpointXid().value_or(0),
                store.PendingMutationCount(), store.PendingAllocationCount(), store.PendingDeallocationCount(),
                store.PendingBtreeRecordCount(), store.PendingObjectMapUpdateCount(),
                store.PendingPayloadDirtyByteEstimate(), c.tx_manager->PendingMutationCount(),
                c.tx_manager->NextMutationSequence(), marks.accepted_sequence, marks.apfs_durable_sequence,
                marks.cleanup_sequence, spool.spool_bytes, spool.dirty_range_count,
                spool.append_direct_count, spool.append_merged_count, c.pending_native_writes.load(),
                ManifestQueuedRequestCount(&c)};
        };
        const auto before_disk = disk();
        const auto before_state = state();
        const auto unchanged = [&] {
            return Require(disk() == before_disk && state() == before_state &&
                store.IsNativeWriteReady() && !store.IsRecoveryRequired() && c.native_write_enabled &&
                !c.write_degraded && !c.recovery_active && !c.unjournaled_native_mutation,
                "Task5 reads/refusals change no image, WAL, spool, queue or checkpoint") && preserved();
        };
        FSP_FSCTL_FILE_INFO info{};
        PVOID reader = nullptr;
        ScopeExit close{[&] { if (reader) CB_Close(&fs, reader); }};
        if (!Require(CB_Open(&fs, const_cast<PWSTR>(L"\\compressed"), FILE_OPEN << 24,
                FILE_READ_ATTRIBUTES | READ_CONTROL, &reader, &info) == STATUS_SUCCESS && reader &&
                info.FileSize == 5 && info.IndexNumber == 17 && !(info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY),
                "Task5 metadata Open exposes logical EOF and regular-file identity")) return false;
        const auto attributes = info.FileAttributes;
        if (!Require(CB_GetFileInfo(&fs, reader, &info) == STATUS_SUCCESS && info.FileSize == 5 &&
                info.IndexNumber == 17 && info.FileAttributes == attributes,
                "Task5 read attributes agree with Open")) return false;
        CB_Close(&fs, reader); reader = nullptr;
        const auto status = CB_Open(&fs, const_cast<PWSTR>(L"\\compressed"),
            FILE_NON_DIRECTORY_FILE | (FILE_OPEN << 24), FILE_READ_DATA | FILE_READ_ATTRIBUTES, &reader, &info);
        if (!Require(malformed ? status == STATUS_NOT_SUPPORTED && !reader : status == STATUS_SUCCESS && reader,
                "Task5 normal data Open admits only a valid LZVN stream")) return false;
        OpenContext retained{};
        retained.node = node; retained.metadata_read_fallback = true;
        InitializeOpenAccess(&retained, FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES);
        const auto read = [&](std::uint64_t offset, ULONG length, const char* expected_hex) {
            std::array<std::byte, 20> bytes;
            bytes.fill(std::byte{0xa6});
            const auto before = bytes;
            const auto expected = HostCompressionHex(expected_hex);
            ULONG done = 999;
            const auto result = CB_Read(&fs, malformed ? static_cast<PVOID>(&retained) : reader,
                bytes.data(), offset, length, &done);
            if (malformed && (!resource_backed || (offset < 5 && length != 0)))
                return Require(result == STATUS_NOT_SUPPORTED && done == 0 && bytes == before,
                "Task5 partial LZVN EOS refuses before publishing caller bytes");
            return Require(result == STATUS_SUCCESS && done == expected.size() &&
                std::equal(expected.begin(), expected.end(), bytes.begin()) &&
                std::all_of(bytes.begin() + expected.size(), bytes.end(), [](auto b) { return b == std::byte{0xa6}; }),
                "Task5 callback returns literal expected range and preserves destination tail");
        };
        if (!read(0, 13, "68656c6c6f") || !read(1, 3, "656c6c") || !read(4, 8, "6f") ||
            !read(5, 8, "") || !read(UINT64_MAX, 8, "") || !read(0, 0, "") || !unchanged()) return false;
        if (reader)
        {
            CB_Close(&fs, reader); reader = nullptr;
        }
        for (const UINT32 access : std::array<UINT32, 4>{FILE_WRITE_DATA, FILE_APPEND_DATA,
                FILE_READ_DATA | FILE_WRITE_DATA, GENERIC_ALL})
        {
            PVOID denied = nullptr;
            const auto result = CB_Open(&fs, const_cast<PWSTR>(L"\\compressed"), FILE_OPEN << 24, access, &denied, &info);
            const bool refused = result == STATUS_NOT_SUPPORTED && !denied;
            if (denied) CB_Close(&fs, denied);
            if (!Require(refused, "Task5 type7 write/append Open stays outside rewrite allowlist 1/3/4") || !unchanged()) return false;
        }
        Store::MutationRequest rewrite;
        if (!Require(!CanOpenNativeCompressionRewrite(&c, node) &&
                !store.PrepareCompressionRewrite(L"\\compressed", rewrite),
                "Task5 native rewrite preparation refuses type7") || !unchanged()) return false;
        std::byte replacement{'Z'};
        for (const bool append : {false, true})
        {
            ULONG done = 999;
            if (!Require(CB_Write(&fs, &retained, &replacement, 1, 1, append, FALSE, &done, &info) == STATUS_NOT_SUPPORTED && done == 0,
                    "Task5 retained writable context cannot modify or append type7") || !unchanged()) return false;
        }
        for (const auto size : {0ULL, 5ULL, 4096ULL})
        for (const BOOLEAN allocation : std::array<BOOLEAN, 2>{FALSE, TRUE})
            if (!Require(CB_SetFileSize(&fs, &retained, size, allocation, &info) == STATUS_NOT_SUPPORTED,
                    "Task5 truncate/same-size/grow/allocation modifications refuse") || !unchanged()) return false;
        for (const UINT32 disposition : {FILE_OVERWRITE, FILE_OVERWRITE_IF, FILE_SUPERSEDE})
        {
            PVOID denied = nullptr;
            const auto result = CB_Open(&fs, const_cast<PWSTR>(L"\\compressed"), disposition << 24,
                FILE_READ_ATTRIBUTES | DELETE, &denied, &info);
            const bool refused = result == STATUS_NOT_SUPPORTED && !denied;
            if (denied) CB_Close(&fs, denied);
            if (!Require(refused, "Task5 destructive compressed Open refuses") || !unchanged()) return false;
        }
        if (!Require(CB_Overwrite(&fs, &retained, 0, FALSE, 0, &info) == STATUS_NOT_SUPPORTED,
                "Task5 retained overwrite callback refuses") || !unchanged()) return false;
    }
    return true;
}

bool TestNativeLzvnReadTask5() { return RunNativeCompressionReadTask5(false); }
bool TestNativeLzvnMalformedReadTask5() { return RunNativeCompressionReadTask5(true); }
bool TestNativeLzvnResourceReadTask5() { return RunNativeCompressionReadTask5(false, true); }
bool TestNativeLzvnResourceMalformedReadTask5() { return RunNativeCompressionReadTask5(true, true); }
bool TestNativeLzfseReadTask5() { return RunNativeCompressionReadTask5(false, false, true); }
bool TestNativeLzfseMalformedReadTask5() { return RunNativeCompressionReadTask5(true, false, true); }
bool TestNativeLzfseResourceReadTask5() { return RunNativeCompressionReadTask5(false, true, true); }
bool TestNativeLzfseResourceMalformedReadTask5() { return RunNativeCompressionReadTask5(true, true, true); }
