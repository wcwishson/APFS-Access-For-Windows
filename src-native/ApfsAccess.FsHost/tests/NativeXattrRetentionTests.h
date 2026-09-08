// Include after DirectorySymlinkFixture and NativeXattrStreamTests.h.
#pragma once

bool TestNativeXattrRetention204(bool manifest, bool replace, bool case_only = false, bool delete_on_close = false)
{
    using namespace apfsaccess::rw;
    // The existing fixture helpers honor TEMP/TMP. Refuse before constructing
    // them if the runner has not selected the required D: scratch directory.
    if (!Require(ToLowerInvariant(std::filesystem::temp_directory_path().root_name().wstring()) == L"d:",
            "retention 204: run with TEMP and TMP on D:")) return false;
    DirectorySymlinkFixture fixture(manifest);
    if (case_only) std::cerr << "[INFO] case retention: fixture created\n";
    auto builder = TwoProjectableVolumeStore();
    if (!manifest) builder.volumes.resize(1);
    builder.authoritative_checkpoint = true;
    builder.dual_checkpoint = false;
    builder.xid = 20;
    builder.block_count = 1024; // 4 MiB, including real attribute blocks and commit headroom.
    auto& volume = builder.volumes.front();
    if (case_only) volume.incompat = apfsaccess::catalog::kIncompatCaseInsensitive;
    const auto name_policy = ApfsNamePolicy::FromIncompatibleFeatures(volume.incompat);
    auto& records = volume.filesystem_records;
    apfsaccess::catalog::BtreeRecord encoded;
    std::string error;
    const auto add = [&](bool ok) { if (ok) records.push_back(encoded); return ok; };
    AppleInodeRecord root;
    root.object_id = root.private_id = root.parent_id = 2;
    root.mode = 0040755; root.children_or_links = 2;
    if (!add(EncodeAppleInodeRecord(root, encoded, error))) return false;
    const auto content = BuildPatternPayloadForTest(32, 0x19);
    const auto replacement = BuildPatternPayloadForTest(43, 0x39);
    const auto external = BuildPatternPayloadForTest(WriteAheadLog::MaxExtendedAttributePayloadBytes + 1, 0x71);
    // Ordinary external attributes admit retirement independently of value
    // size. ResourceFork retirement has a separate raw writer size restriction;
    // using an ordinary attribute proves retry without changing that admission.
    constexpr auto external_name = "user.RetentionLarge";
    const std::vector<std::byte> finder(32, std::byte{0x46});
    const auto payload = [&](std::uint64_t id, std::uint64_t physical, std::vector<std::byte> bytes) {
        const auto blocks = (bytes.size() + 4095) / 4096;
        const auto allocation = blocks * 4096;
        if (!add(EncodeAppleDataStreamIdRecord({id, 1}, encoded, error)) ||
            !add(EncodeAppleFileExtentRecord({id, 0, allocation, physical, 0, 4096}, encoded, error)) ||
            !EncodeApplePhysicalExtentRecord({physical, blocks, kApplePhysicalExtentKindNew, id, 1}, encoded, error))
            return false;
        volume.extentref_records.push_back(encoded);
        volume.additional_file_system_allocated_blocks += blocks;
        bytes.resize(allocation);
        builder.authoritative_seeded_main_blocks.push_back({physical, std::move(bytes)});
        return true;
    };
    const auto file = [&](std::uint64_t id, const char* name, std::uint64_t physical,
                          const std::vector<std::byte>& bytes) {
        AppleInodeRecord inode;
        inode.object_id = inode.private_id = id; inode.parent_id = 2;
        inode.children_or_links = 1; inode.mode = 0100640;
        inode.owner = 501; inode.group = 20; inode.uncompressed_size = bytes.size();
        inode.create_time = inode.modification_time = inode.change_time = inode.access_time = 1700000000000000000ULL;
        AppleExtendedField stream; stream.type = 8; stream.data.resize(40);
        apfsaccess::testfixture::PutU64LE(stream.data, 0, bytes.size());
        apfsaccess::testfixture::PutU64LE(stream.data, 8, 4096);
        inode.extended_fields.push_back(stream);
        AppleDirectoryRecord link;
        link.parent_id = 2; link.file_id = id; link.flags = 8; link.name_utf8 = name;
        return add(EncodeAppleInodeRecord(inode, encoded, error)) &&
            add(EncodeAppleDirectoryRecord(link, name_policy, encoded, error)) && payload(id, physical, bytes);
    };
    std::vector<std::byte> descriptor(kAppleXattrDataStreamBytes);
    apfsaccess::testfixture::PutU64LE(descriptor, 0, 777);
    apfsaccess::testfixture::PutU64LE(descriptor, 8, external.size());
    apfsaccess::testfixture::PutU64LE(descriptor, 16, ((external.size() + 4095) / 4096) * 4096);
    if (!file(17, "file", 100, content) || !file(18, "replacement", 101, replacement) ||
        !payload(777, 128, external) ||
        !add(EncodeAppleXattrRecord({17, external_name, kAppleXattrDataStream, descriptor}, encoded, error)) ||
        !add(EncodeAppleXattrRecord({17, "com.apple.FinderInfo", kAppleXattrDataEmbedded, finder}, encoded, error)) ||
        !SortAppleBtreeRecords(records, case_only ? AppleBtreeKeyOrder::FileSystemHashedDirectory :
            AppleBtreeKeyOrder::FileSystemCaseSensitive, error) ||
        !SortAppleBtreeRecords(volume.extentref_records, AppleBtreeKeyOrder::PhysicalExtent, error) ||
        !WriteFileBytes(fixture.image.path, apfsaccess::testfixture::BuildStoreImage(builder)) ||
        !fixture.Initialize(manifest)) return false;

    auto& c = *fixture.context;
    if (case_only) std::cerr << "[INFO] case retention: canonical source initialized\n";
    c.args.incompatible_features = volume.incompat;
    auto fs = BuildFileSystem(&c);
    PVOID base = nullptr, source = nullptr, large = nullptr, small_handle = nullptr;
    ScopeExit close{[&] { for (auto h : {large, small_handle, source, base}) if (h) CB_Close(&fs, h); }};
    FSP_FSCTL_FILE_INFO info{};
    const auto open = [&](std::wstring path, PVOID& handle, UINT32 access) {
        return CB_Open(&fs, path.data(), FILE_NON_DIRECTORY_FILE | (FILE_OPEN << 24), access, &handle, &info);
    };
    const auto read = [&](PVOID handle, const std::vector<std::byte>& expected) {
        std::vector<std::byte> actual(expected.size() + 8, std::byte{0x55});
        ULONG count = 99;
        return Require(NT_SUCCESS(CB_Read(&fs, handle, actual.data(), 0, static_cast<ULONG>(actual.size()), &count)) &&
                count == expected.size() && std::equal(expected.begin(), expected.end(), actual.begin()) &&
                NT_SUCCESS(CB_GetFileInfo(&fs, handle, &info)) && info.FileSize == expected.size(),
            "retention 204: callback reads exact authoritative bytes and reports full size");
    };
    if (!Require(NT_SUCCESS(open(L"\\file", base, GENERIC_READ | DELETE)) &&
            NT_SUCCESS(open(L"\\replacement", source, GENERIC_READ | DELETE)) &&
            NT_SUCCESS(open(L"\\file:APFS.FinderInfo:$DATA", small_handle, GENERIC_READ)),
            "retention 204: base, replacement, and small attribute open")) return false;

    // Capture a real small value, then force unreadable visibility. A failed
    // preparation must retain this already usable snapshot for a later retry.
    auto* small_open = static_cast<OpenContext*>(small_handle);
    {
        MutationCallbackScope mutation(&c);
        if (!Require(CaptureNativeXattrsBeforeUnlink(&c, L"\\file") == STATUS_SUCCESS &&
                small_open->native_xattr->unlinked_value == std::optional(finder),
                "retention 204: preparation obtains the small authoritative snapshot")) return false;
        c.unjournaled_native_mutation = true;
        const auto refused = CaptureNativeXattrsBeforeUnlink(&c, L"\\file");
        c.unjournaled_native_mutation = false;
        if (!Require(refused == STATUS_IO_DEVICE_ERROR &&
                small_open->native_xattr->unlinked_value == std::optional(finder),
                "retention 204: unreadable preparation preserves the usable previous snapshot")) return false;
    }
    if (!Require(NT_SUCCESS(open(L"\\file" + NativeXattrStreamName(external_name), large, GENERIC_READ)),
            "retention 204: actual external attribute larger than 1 MiB opens") || !read(large, external)) return false;
    auto* large_open = static_cast<OpenContext*>(large);
    auto* base_open = static_cast<OpenContext*>(base);
    auto* source_open = static_cast<OpenContext*>(source);
    const auto base_node = base_open->node;
    const auto source_node = source_open->node;
    const auto nodes_before = c.nodes.size();
    const auto root_node = FindNodeNormalized(&c, L"\\");
    const auto children_before = root_node->children;
    const auto image_before = ReadFileBytes(fixture.image.path);
    const auto wal_before = ReadFileBytes(c.session_root / "accepted.wal");
    const auto marker_before = ReadFileBytes(c.recovery_marker_file);
    const auto marker_existed = std::filesystem::exists(c.recovery_marker_file);
    const auto marks_before = c.tx_manager->Watermarks();
    if (case_only)
    {
        std::cerr << "[INFO] case retention: callback rename begins\n";
        if (!Require(FindNodeNormalized(&c, L"\\FILE") == base_node &&
                CB_Rename(&fs, base, const_cast<PWSTR>(L"\\file"), const_cast<PWSTR>(L"\\FILE"), TRUE) == STATUS_SUCCESS,
                "retention: case-only replace spelling succeeds with large attribute open") ||
            !read(large, external) || !read(small_handle, finder)) return false;
        std::cerr << "[INFO] case retention: callback rename and reads complete\n";
        CB_Close(&fs, large); large = nullptr;
        CB_Close(&fs, small_handle); small_handle = nullptr;
        CB_Close(&fs, base); base = nullptr;
        CB_Close(&fs, source); source = nullptr;
        const auto marks = c.tx_manager->Watermarks();
        MetadataStore fresh(fixture.volume);
        if (!Require(fresh.PrepareNativeWritePath(), "retention: reopen renamed canonical image")) return false;
        const auto children = fresh.SnapshotCommittedDirectoryChildInodes(2);
        std::vector<std::byte> bytes(external.size()); std::size_t count = 0;
        return Require(children && std::any_of(children->begin(), children->end(), [](const auto& child) {
                return child.object_id == 17 && child.name == L"FILE";
            }) && marks.accepted_sequence > marks_before.accepted_sequence &&
            marks.accepted_sequence == marks.apfs_durable_sequence && marks.cleanup_sequence == marks.accepted_sequence &&
            !c.write_degraded && !c.recovery_active && !c.unjournaled_native_mutation &&
            !fresh.IsRecoveryRequired() &&
            fresh.ReadCommittedExtendedAttributeRange(17, external_name, 0, bytes, count) &&
            count == external.size() && bytes == external,
            "retention: exact capitalization, owner and attribute bytes survive durable rename without degradation");
    }
    const auto operation = [&] {
        if (delete_on_close)
        {
            PVOID deleting = nullptr;
            const auto status = CB_Open(&fs, const_cast<PWSTR>(L"\\file"),
                FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE | (FILE_OPEN << 24),
                GENERIC_READ | DELETE, &deleting, &info);
            if (NT_SUCCESS(status))
            {
                CB_Cleanup(&fs, deleting, const_cast<PWSTR>(L"\\file"), FspCleanupDelete);
                CB_Close(&fs, deleting);
            }
            return status;
        }
        return replace
            ? CB_Rename(&fs, source, const_cast<PWSTR>(L"\\replacement"), const_cast<PWSTR>(L"\\file"), TRUE)
            : CB_SetDelete(&fs, base, const_cast<PWSTR>(L"\\file"), TRUE);
    };
    if (!Require(operation() == STATUS_SHARING_VIOLATION,
            "retention 204: destructive callback explicitly refuses while the large attribute is open")) return false;
    if (!replace && !Require(CB_SetDelete(&fs, base, nullptr, TRUE) == STATUS_SHARING_VIOLATION,
            "retention 204: context-only delete also refuses before intent")) return false;
    const auto marks_after = c.tx_manager->Watermarks();
    const auto working_base = c.metadata_store->LookupWorkingInodeByPath(L"\\file");
    const auto working_source = c.metadata_store->LookupWorkingInodeByPath(L"\\replacement");
    if (!Require(image_before == ReadFileBytes(fixture.image.path) &&
            wal_before == ReadFileBytes(c.session_root / "accepted.wal") &&
            marker_before == ReadFileBytes(c.recovery_marker_file) &&
            marker_existed == std::filesystem::exists(c.recovery_marker_file) &&
            marks_before.accepted_sequence == marks_after.accepted_sequence &&
            marks_before.apfs_durable_sequence == marks_after.apfs_durable_sequence &&
            marks_before.cleanup_sequence == marks_after.cleanup_sequence &&
            !c.write_degraded && !c.unjournaled_native_mutation && !c.recovery_active &&
            !c.metadata_store->IsRecoveryRequired() && c.metadata_store->PendingMutationCount() == 0 &&
            working_base && working_base->object_id == 17 && working_source && working_source->object_id == 18 &&
            c.nodes.size() == nodes_before && root_node->children == children_before &&
            FindNodeNormalized(&c, L"\\file") == base_node && FindNodeNormalized(&c, L"\\replacement") == source_node &&
            base_node->path == L"\\file" && source_node->path == L"\\replacement" &&
            !base_node->delete_pending && !base_node->delete_latched && base_node->delete_intent_count == 0 &&
            !base_open->delete_on_cleanup && !base_open->delete_on_close_requested &&
            !source_node->delete_pending && !source_node->delete_latched && source_node->delete_intent_count == 0 &&
            !large_open->native_xattr->unlinked_value &&
            small_open->native_xattr->unlinked_value == std::optional(finder),
            "retention 204: refusal preserves canonical source, WAL, marker, health, namespace, and delete intent") ||
        !read(large, external) || !read(small_handle, finder) || !read(base, content) || !read(source, replacement)) return false;
    {
        MetadataStore fresh(fixture.volume);
        std::vector<std::byte> actual(external.size()); std::size_t count = 0;
        if (!Require(fresh.PrepareNativeWritePath() &&
                fresh.ReadCommittedExtendedAttributeRange(17, external_name, 0, actual, count) &&
                count == external.size() && actual == external,
                "retention 204: fresh canonical reader retains every external byte after refusal")) return false;
    }

    // Leave the small stream open: only the large blocking handle is closed.
    CB_Close(&fs, large); large = nullptr;
    if (!Require(operation() == STATUS_SUCCESS,
            "retention 204: the same destructive callback succeeds after closing the blocking handle")) return false;
    if (!replace)
    {
        CB_Cleanup(&fs, base, const_cast<PWSTR>(L"\\file"), FspCleanupDelete);
        CB_Close(&fs, base); base = nullptr;
    }
    else
    {
        CB_Close(&fs, source); source = nullptr;
    }
    if (!read(small_handle, finder)) return false;
    CB_Close(&fs, small_handle); small_handle = nullptr;
    if (base) { CB_Close(&fs, base); base = nullptr; }
    if (source) { CB_Close(&fs, source); source = nullptr; }
    const auto final_marks = c.tx_manager->Watermarks();
    std::cerr << "[INFO] retention completion: accepted=" << final_marks.accepted_sequence
        << " durable=" << final_marks.apfs_durable_sequence << " cleanup=" << final_marks.cleanup_sequence
        << " pending=" << HasPendingNativeMutations(&c) << " degraded=" << c.write_degraded
        << " unjournaled=" << c.unjournaled_native_mutation << " recovery=" << c.recovery_active
        << " storeRecovery=" << c.metadata_store->IsRecoveryRequired() << '\n';
    if (!Require(final_marks.accepted_sequence > marks_before.accepted_sequence &&
            final_marks.accepted_sequence == final_marks.apfs_durable_sequence &&
            final_marks.accepted_sequence == final_marks.cleanup_sequence &&
            !HasPendingNativeMutations(&c) && !c.write_degraded && !c.unjournaled_native_mutation &&
            !c.recovery_active && !c.metadata_store->IsRecoveryRequired(),
            "retention 204: successful retry publishes durably with clean health")) return false;
    MetadataStore fresh(fixture.volume);
    if (!Require(fresh.PrepareNativeWritePath(), "retention 204: reopen final canonical image")) return false;
    const auto destination = fresh.LookupCommittedInodeByPath(L"\\file");
    const auto old_source = fresh.LookupCommittedInodeByPath(L"\\replacement");
    std::vector<std::byte> actual;
    return Require(!fresh.LookupCommittedInodeByObjectId(17) &&
        !fresh.LookupCommittedExtendedAttribute(17, external_name) &&
        !fresh.LookupCommittedExtendedAttribute(17, "com.apple.FinderInfo") &&
        (replace ? (destination && destination->object_id == 18 && !old_source)
                 : (!destination && old_source && old_source->object_id == 18)) &&
        fresh.ReadCommittedFileRange(replace ? L"\\file" : L"\\replacement", 0, replacement.size(), actual) &&
        actual == replacement,
        "retention 204: fresh canonical image has the correct surviving identity and bytes, with old attributes removed");
}
