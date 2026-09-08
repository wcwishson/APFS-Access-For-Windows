#pragma once
// Include in FsHostSemanticsTests.cpp's test namespace after DirectorySymlinkFixture.
// Register TestNativeSparseWriteCallbacks340 and TestNativeSparseRefusalCallbacks340.
// These gates intentionally require the parent callback preflight/allocation integration.
struct HostNativeSparse340Fixture
{
    DirectorySymlinkFixture fixture{false};
    static constexpr std::uint64_t tail = 64ULL * 1024 * 1024;
    bool Initialize(bool shared = false, bool aliases = true)
    {
        using namespace apfsaccess::rw;
        auto builder = TwoProjectableVolumeStore();
        builder.volumes.resize(1); builder.block_count = 1024;
        builder.authoritative_checkpoint = true; builder.dual_checkpoint = false; builder.xid = 20;
        builder.authoritative_internal_pool_blocks = 16; builder.authoritative_checkpoint_ring_blocks = 16;
        auto& volume = builder.volumes.front(); volume.incompat = 0;
        volume.additional_file_system_allocated_blocks = 6;
        auto& records = volume.filesystem_records;
        records.clear(); volume.extentref_records.clear();
        apfsaccess::catalog::BtreeRecord encoded; std::string error;
        const auto add = [&](bool ok) { if (ok) records.push_back(encoded); return ok; };
        AppleInodeRecord root;
        root.object_id = root.private_id = root.parent_id = 2;
        root.mode = 0040755; root.children_or_links = (shared ? 1 : 0) + (aliases ? 2 : 1);
        if (!add(EncodeAppleInodeRecord(root, encoded, error))) return false;
        AppleInodeRecord inode;
        inode.object_id = inode.private_id = 17; inode.parent_id = 2; inode.children_or_links = aliases ? 2 : 1;
        inode.mode = 0100640; inode.owner = 501; inode.group = 20;
        inode.create_time = inode.modification_time = inode.change_time = inode.access_time = 1700000000000000000ULL;
        AppleExtendedField stream; stream.type = 8; stream.data.resize(40);
        apfsaccess::testfixture::PutU64LE(stream.data, 0, tail + 12288);
        apfsaccess::testfixture::PutU64LE(stream.data, 8, 24576);
        inode.extended_fields.push_back(stream);
        AppleExtendedField name; name.type = 4;
        const std::string primary("original\0", 9);
        name.data.assign(reinterpret_cast<const std::byte*>(primary.data()), reinterpret_cast<const std::byte*>(primary.data() + primary.size()));
        inode.extended_fields.push_back(name);
        if (!add(EncodeAppleInodeRecord(inode, encoded, error)) ||
            !add(EncodeAppleDataStreamIdRecord({17, 1}, encoded, error))) return false;
        const auto attributes = EncodeWindowsAttributes(0);
        if (!add(EncodeAppleXattrRecord({17, kWindowsAttributesName, kAppleXattrDataEmbedded,
                {attributes.begin(), attributes.end()}}, encoded, error))) return false;
        for (const auto sibling : {700ULL, 701ULL})
        {
            if (!aliases && sibling == 701) continue;
            const auto leaf = sibling == 700 ? "original" : "alias";
            AppleDirectoryRecord link; link.parent_id = 2; link.file_id = 17; link.flags = 8; link.name_utf8 = leaf;
            if (!add(EncodeAppleDirectoryRecord(link, encoded, error))) return false;
            if (aliases && (!add(EncodeAppleSiblingLinkRecord({17, sibling, 2, leaf}, encoded, error)) ||
                !add(EncodeAppleSiblingMapRecord({sibling, 17}, encoded, error)))) return false;
        }
        if (shared)
        {
            inode.object_id = inode.private_id = 18; inode.children_or_links = 1;
            inode.extended_fields.resize(1);
            AppleDirectoryRecord link; link.parent_id = 2; link.file_id = 18; link.flags = 8; link.name_utf8 = "shared";
            if (!add(EncodeAppleInodeRecord(inode, encoded, error)) || !add(EncodeAppleDirectoryRecord(link, encoded, error)) ||
                !add(EncodeAppleDataStreamIdRecord({18, 1}, encoded, error))) return false;
        }
        for (auto owner = 17ULL; owner <= (shared ? 18ULL : 17ULL); ++owner)
            for (const auto& extent : {AppleFileExtentRecord{owner, 0, 12288, 100, 0, 4096},
                AppleFileExtentRecord{owner, 12288, tail - 12288, 0, 0, 4096},
                AppleFileExtentRecord{owner, tail, 12288, 110, 0, 4096}})
                if (!add(EncodeAppleFileExtentRecord(extent, encoded, error))) return false;
        for (const auto block : {100ULL, 110ULL})
        {
            if (!EncodeApplePhysicalExtentRecord({block, 3, kApplePhysicalExtentKindNew, 17, shared ? 2u : 1u}, encoded, error)) return false;
            volume.extentref_records.push_back(encoded);
            for (auto i = 0ULL; i < 3; ++i)
                builder.authoritative_seeded_main_blocks.push_back({block + i, std::vector<std::byte>(4096,
                    block == 100 ? std::byte{0x31} : std::byte{0xa7})});
        }
        return SortAppleBtreeRecords(records, AppleBtreeKeyOrder::FileSystemCaseSensitive, error) &&
            SortAppleBtreeRecords(volume.extentref_records, AppleBtreeKeyOrder::PhysicalExtent, error) &&
            WriteFileBytes(fixture.image.path, apfsaccess::testfixture::BuildStoreImage(builder)) && fixture.Initialize(false);
    }
};

bool TestNativeSparseWriteCallbacks340()
{
    using Store = apfsaccess::rw::MetadataStore;
    const auto drive = std::filesystem::temp_directory_path().root_name().wstring();
    if (!Require(drive == L"D:" || drive == L"d:", "sparse host gates require TEMP/TMP on D:")) return false;
    for (unsigned order = 0; order < 2; ++order)
    {
        HostNativeSparse340Fixture owned;
        if (!Require(owned.Initialize(), "host sparse archive-clear fixture initializes")) return false;
        auto& c = *owned.fixture.context; auto fs = BuildFileSystem(&c);
        c.args.write_max_dirty_transactions = 64;
        PVOID writer = nullptr, alias = nullptr, other = nullptr; FSP_FSCTL_FILE_INFO info{};
        ScopeExit close{[&] { if (writer) CB_Close(&fs, writer); if (alias) CB_Close(&fs, alias); if (other) CB_Close(&fs, other); }};
        if (!Require(CB_Open(&fs, const_cast<PWSTR>(L"\\original"), FILE_OPEN << 24,
                GENERIC_READ | GENERIC_WRITE | FILE_WRITE_ATTRIBUTES, &writer, &info) == STATUS_SUCCESS &&
                info.FileSize == owned.tail + 12288 && info.AllocationSize == 24576 &&
                CB_Open(&fs, const_cast<PWSTR>(L"\\alias"), FILE_OPEN << 24, GENERIC_READ, &alias, &info) == STATUS_SUCCESS,
                "host sparse initial EOF and allocation project exactly")) return false;
        const auto ordinary = [&] {
            std::byte value{0x71}; ULONG done = 0;
            return CB_Create(&fs, const_cast<PWSTR>(L"\\other"), FILE_NON_DIRECTORY_FILE,
                GENERIC_READ | GENERIC_WRITE, FILE_ATTRIBUTE_ARCHIVE, nullptr, 0, &other, &info) == STATUS_SUCCESS &&
                CB_Write(&fs, other, &value, 0, 1, FALSE, FALSE, &done, &info) == STATUS_SUCCESS && done == 1;
        };
        if (!order && !Require(ordinary(), "ordinary companion precedes sparse callback")) return false;
        for (const auto offset : {17ULL, owned.tail / 2 + 4095, owned.tail / 2 + 4095, owned.tail + 12288})
        {
            std::byte value{0x5a}; ULONG done = 999;
            if (!Require(CB_Write(&fs, writer, &value, offset, 1, FALSE, FALSE, &done, &info) == STATUS_SUCCESS && done == 1,
                    "sparse allocated, hole, overlap and append callbacks succeed")) return false;
            const auto inode = c.metadata_store->LookupWorkingInodeByPath(L"\\original");
            FSP_FSCTL_FILE_INFO alias_info{};
            if (!Require(inode && info.AllocationSize == inode->allocation_size && info.FileSize == inode->logical_size &&
                    CB_GetFileInfo(&fs, alias, &alias_info) == STATUS_SUCCESS && alias_info.AllocationSize == info.AllocationSize &&
                    alias_info.FileSize == info.FileSize && !c.write_degraded && !c.recovery_active,
                    "callback and alias allocation equal staged physical allocation")) return false;
        }
        if (order && !Require(ordinary(), "ordinary companion follows sparse callback")) return false;
        if (!Require(CB_Flush(&fs, writer, &info) == STATUS_SUCCESS, "mixed sparse callbacks flush")) return false;
        const auto committed = c.metadata_store->LookupCommittedInodeByPath(L"\\original");
        if (!Require(committed && committed->allocation_size == 8 * 4096 &&
                c.metadata_store->LookupCommittedInodeByPath(L"\\other"), "mixed callback data publishes")) return false;
        std::optional<UINT32> attributes;
        if (!Require(ReadWindowsAttributes(c.metadata_store->LookupCommittedExtendedAttribute(17, kWindowsAttributesName), attributes) &&
                attributes && (*attributes & FILE_ATTRIBUTE_ARCHIVE), "archive companion publishes with sparse bytes")) return false;
        for (const auto size : {8193ULL, owned.tail + 32768})
        {
            if (!Require(CB_SetFileSize(&fs, writer, size, FALSE, &info) == STATUS_SUCCESS &&
                    !c.write_degraded && !c.recovery_active, "sparse truncate and extension remain writable")) return false;
            const auto inode = c.metadata_store->LookupWorkingInodeByPath(L"\\original");
            if (!Require(inode && info.AllocationSize == inode->allocation_size, "resize callback reports physical allocation")) return false;
        }
        if (!Require(CB_Flush(&fs, writer, &info) == STATUS_SUCCESS, "sparse resize callback flushes")) return false;
        Store::VolumeContext context; context.device_path = owned.fixture.image.path.wstring(); context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false; Store fresh(context);
        if (!Require(fresh.PrepareNativeWritePath() && fresh.VerifyIntegrity(), "host sparse canonical reopen verifies")) return false;
        const auto inode = fresh.LookupCommittedInodeByPath(L"\\original"); std::vector<std::byte> zeros;
        if (!Require(inode && inode->allocation_size == 12288 && inode->logical_size == owned.tail + 32768 &&
                fresh.ReadCommittedFileRange(L"\\original", 8193, 4096, zeros) && zeros == std::vector<std::byte>(4096),
                "host sparse resize reopens with exact allocation and zero regrowth")) return false;
    }
    return true;
}

bool TestNativeSparseRefusalCallbacks340()
{
    const auto drive = std::filesystem::temp_directory_path().root_name().wstring();
    if (!Require(drive == L"D:" || drive == L"d:", "sparse host gates require TEMP/TMP on D:")) return false;
    HostNativeSparse340Fixture owned;
    if (!Require(owned.Initialize(true), "valid shared sparse callback fixture initializes")) return false;
    auto& c = *owned.fixture.context; auto fs = BuildFileSystem(&c);
    c.args.write_max_dirty_transactions = 64;
    PVOID writer = nullptr, other = nullptr; FSP_FSCTL_FILE_INFO info{};
    ScopeExit close{[&] { if (writer) CB_Close(&fs, writer); if (other) CB_Close(&fs, other); }};
    if (!Require(CB_Open(&fs, const_cast<PWSTR>(L"\\original"), FILE_OPEN << 24, GENERIC_READ | GENERIC_WRITE,
            &writer, &info) == STATUS_SUCCESS && CB_Create(&fs, const_cast<PWSTR>(L"\\other"), FILE_NON_DIRECTORY_FILE,
            GENERIC_READ | GENERIC_WRITE, FILE_ATTRIBUTE_ARCHIVE, nullptr, 0, &other, &info) == STATUS_SUCCESS,
            "shared sparse opens beside unrelated pending work")) return false;
    const auto pending = c.metadata_store->PendingMutationCount();
    const auto journal = c.tx_manager->PendingMutationCount(); const auto marks = c.tx_manager->Watermarks();
    const auto sequence = c.tx_manager->NextMutationSequence(); const auto xid = c.metadata_store->CheckpointXid();
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    const auto image = ReadFileBytes(owned.fixture.image.path); const auto spool = c.payload_spool->SnapshotCounters();
    for (unsigned operation = 0; operation < 5; ++operation)
    {
        std::byte value{0x5a}; ULONG done = 999;
        const auto status = operation < 3 ? CB_Write(&fs, writer, &value,
            operation == 0 ? 17 : operation == 1 ? owned.tail / 2 : owned.tail + 12288,
            1, FALSE, FALSE, &done, &info) : CB_SetFileSize(&fs, writer, operation == 3 ? 8193 : owned.tail + 32768, FALSE, &info);
        const auto after = c.tx_manager->Watermarks(); const auto after_spool = c.payload_spool->SnapshotCounters();
        if (!Require(status == STATUS_NOT_SUPPORTED && (operation >= 3 || done == 0) &&
                pending == c.metadata_store->PendingMutationCount() && journal == c.tx_manager->PendingMutationCount() &&
                sequence == c.tx_manager->NextMutationSequence() && xid == c.metadata_store->CheckpointXid() &&
                marks.accepted_sequence == after.accepted_sequence && marks.apfs_durable_sequence == after.apfs_durable_sequence &&
                marks.cleanup_sequence == after.cleanup_sequence && wal == ReadFileBytes(c.session_root / "accepted.wal") &&
                image == ReadFileBytes(owned.fixture.image.path) && spool.spool_bytes == after_spool.spool_bytes &&
                spool.dirty_range_count == after_spool.dirty_range_count && !c.recovery_active && !c.write_degraded,
                "shared sparse refusal precedes companion staging and preserves unrelated work and WAL")) return false;
    }
    std::byte value{0x71}; ULONG done = 0;
    return Require(CB_Write(&fs, other, &value, 0, 1, FALSE, FALSE, &done, &info) == STATUS_SUCCESS && done == 1 &&
        CB_Flush(&fs, other, &info) == STATUS_SUCCESS && !c.write_degraded,
        "supported write after sparse refusal still commits");
}

bool TestNativeSparseCommittedCallbacks355()
{
    using Store = apfsaccess::rw::MetadataStore;
    for (bool aliases : {false, true}) for (const auto shrink : {8193ULL, 0ULL})
    {
        HostNativeSparse340Fixture owned;
        if (!Require(owned.Initialize(false, aliases), "sparse checkpoint callback fixture initializes")) return false;
        {
            auto& c = *owned.fixture.context; auto fs = BuildFileSystem(&c);
            c.args.write_max_dirty_transactions = 64;
            PVOID writer = nullptr; FSP_FSCTL_FILE_INFO info{};
            ScopeExit close{[&] { if (writer) CB_Close(&fs, writer); }};
            if (!Require(CB_Open(&fs, const_cast<PWSTR>(L"\\original"), FILE_OPEN << 24,
                    GENERIC_READ | GENERIC_WRITE, &writer, &info) == STATUS_SUCCESS &&
                    CB_SetFileSize(&fs, writer, shrink, FALSE, &info) == STATUS_SUCCESS &&
                    CB_Flush(&fs, writer, &info) == STATUS_SUCCESS && !c.write_degraded,
                    "single-link/aliased partial/zero shrink commits through real callbacks")) return false;
        }
        const auto old_root = owned.fixture.context->session_root;
        StopDeferredCommitWorker(owned.fixture.context.get());
        owned.fixture.context = std::make_unique<MountContext>();
        std::error_code ec; std::filesystem::remove_all(old_root, ec);
        if (!Require(owned.fixture.Initialize(false), "new callback context imports committed sparse shrink")) return false;
        auto& c = *owned.fixture.context; auto fs = BuildFileSystem(&c);
        c.args.write_max_dirty_transactions = 64;
        PVOID writer = nullptr; FSP_FSCTL_FILE_INFO info{};
        ScopeExit close{[&] { if (writer) CB_Close(&fs, writer); }};
        if (!Require(CB_Open(&fs, const_cast<PWSTR>(L"\\original"), FILE_OPEN << 24,
                GENERIC_READ | GENERIC_WRITE, &writer, &info) == STATUS_SUCCESS &&
                CB_SetFileSize(&fs, writer, owned.tail + 32768, FALSE, &info) == STATUS_SUCCESS &&
                CB_Flush(&fs, writer, &info) == STATUS_SUCCESS && info.AllocationSize == (shrink ? 12288 : 0) &&
                !c.write_degraded && !c.recovery_active,
                "reopened sparse callback grows beyond capacity using holes")) return false;
        std::array<std::byte, 4096> zeros{}; ULONG done = 0;
        std::array<std::byte, 4096> actual; actual.fill(std::byte{0x7f});
        if (!Require(CB_Read(&fs, writer, actual.data(), shrink, 4096, &done) == STATUS_SUCCESS &&
                done == 4096 && actual == zeros, "callback regrowth reads exact zero bytes")) return false;
        std::byte value{0x75};
        if (!Require(CB_Write(&fs, writer, &value, owned.tail + 9, 1, FALSE, FALSE, &done, &info) == STATUS_SUCCESS &&
                done == 1 && CB_Flush(&fs, writer, &info) == STATUS_SUCCESS && !c.write_degraded,
                "reopened sparse callback remains writable")) return false;
        Store final(owned.fixture.volume);
        std::vector<std::byte> bytes;
        if (!Require(final.PrepareNativeWritePath() && final.VerifyIntegrity() &&
                final.ReadCommittedFileRange(L"\\original", owned.tail + 9, 1, bytes) && bytes == std::vector<std::byte>{value},
                "callback regrowth and later payload survive native reopen")) return false;
    }
    return true;
}

bool TestNativeSparseStageFailureCallbacks355()
{
    using Store = apfsaccess::rw::MetadataStore;
    using Tx = apfsaccess::rw::TransactionManager;
    HostNativeSparse340Fixture owned;
    if (!Require(owned.Initialize(), "sparse callback allocation failure fixture initializes")) return false;
    auto& c = *owned.fixture.context; auto fs = BuildFileSystem(&c);
    c.args.write_max_dirty_transactions = 64;
    PVOID writer = nullptr, prior = nullptr; FSP_FSCTL_FILE_INFO info{};
    ScopeExit close{[&] { if (writer) CB_Close(&fs, writer); if (prior) CB_Close(&fs, prior); }};
    if (!Require(CB_Open(&fs, const_cast<PWSTR>(L"\\original"), FILE_OPEN << 24,
            GENERIC_READ | GENERIC_WRITE, &writer, &info) == STATUS_SUCCESS &&
            CB_Create(&fs, const_cast<PWSTR>(L"\\accepted-prior"), FILE_NON_DIRECTORY_FILE,
            GENERIC_READ | GENERIC_WRITE, FILE_ATTRIBUTE_ARCHIVE, nullptr, 0, &prior, &info) == STATUS_SUCCESS,
            "prior create stages before sparse failure")) return false;
    if (!Require(c.tx_manager->Accept(c.metadata_store->CheckpointXid().value()) &&
            c.tx_manager->Watermarks().accepted_sequence > c.tx_manager->Watermarks().apfs_durable_sequence,
            "prior create has durable WAL acceptance before fault")) return false;
    const auto marks = c.tx_manager->Watermarks();
    const auto persisted = ReadFileBytes(c.session_root / "accepted.wal");
    unsigned scans = 0;
    c.metadata_store->SetSparsePreflightHookForTests([&] { if (++scans == 2) throw std::bad_alloc{}; });
    std::byte value{0x42}; ULONG done = 999;
    const auto status = CB_Write(&fs, writer, &value, owned.tail / 2, 1, FALSE, FALSE, &done, &info);
    c.metadata_store->SetSparsePreflightHookForTests({});
    const auto after = ReadFileBytes(c.session_root / "accepted.wal");
    if (!Require(!NT_SUCCESS(status) && done == 0 && scans == 2 &&
            after.size() >= persisted.size() && std::equal(persisted.begin(), persisted.end(), after.begin()) &&
            c.tx_manager->Watermarks().cleanup_sequence == marks.cleanup_sequence,
            "second sparse scan allocation failure stays contained and preserves accepted WAL")) return false;
    CB_Close(&fs, writer); writer = nullptr;
    CB_Close(&fs, prior); prior = nullptr;
    StopDeferredCommitWorker(&c);
    c.tx_manager.reset(); c.payload_spool.reset(); ResetRecoveryMarkerCache(&c);
    MountContext recovered;
    recovered.args = c.args; recovered.native_write_enabled = true;
    recovered.session_root = c.session_root; recovered.recovery_marker_file = c.recovery_marker_file;
    recovered.cache_root = c.cache_root;
    recovered.payload_spool_volume_identity = c.payload_spool_volume_identity;
    recovered.owned_metadata_store = std::make_unique<Store>(owned.fixture.volume);
    recovered.metadata_store = recovered.owned_metadata_store.get();
    recovered.tx_manager = std::make_unique<Tx>(L"Conservative");
    recovered.tx_manager->SetVolumeIdentity(L"directory-symlink-volume");
    recovered.tx_manager->SetJournalPath((recovered.session_root / "accepted.wal").wstring());
    recovered.payload_spool = std::make_unique<apfsaccess::rw::PayloadSpool>(apfsaccess::rw::PayloadSpool::Options{
        recovered.session_root / "payload-spool", recovered.payload_spool_volume_identity, 1024 * 1024});
    if (!Require(recovered.metadata_store->PrepareNativeWritePath() && ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(recovered),
            "accepted prior create recovers after sparse allocation failure")) return false;
    return Require(recovered.metadata_store->LookupCommittedInodeByPath(L"\\accepted-prior") &&
        recovered.tx_manager->Watermarks().cleanup_sequence == marks.accepted_sequence &&
        recovered.metadata_store->LookupCommittedInodeByPath(L"\\original")->allocation_size == 24576,
        "recovery publishes the prior accepted create without publishing failed sparse payload");
}
