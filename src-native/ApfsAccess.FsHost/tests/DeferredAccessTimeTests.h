#pragma once
// Include after DirectorySymlinkFixture. Parent owns registration and execution.

bool DeferredAccessTimeScratch302()
{
    return Require(ToLowerInvariant(std::filesystem::temp_directory_path().root_name().wstring()) == L"d:",
        "atime 302: TEMP and TMP must select D: before constructing native fixtures");
}

struct DeferredAccessTimeFixture302
{
    DirectorySymlinkFixture fixture;
    MountContext sibling;
    const std::vector<std::byte> bytes = BuildPatternPayloadForTest(32, 0x39);
    const std::vector<std::byte> acl{std::byte{0xfd}, std::byte{0}, std::byte{0x9c}};
    explicit DeferredAccessTimeFixture302(bool manifest) : fixture(manifest) {}

    bool InitializeContext(bool manifest)
    {
        using Store = apfsaccess::rw::MetadataStore;
        using Tx = apfsaccess::rw::TransactionManager;
        auto& c = *fixture.context;
        auto& volume = fixture.volume;
        volume.device_path = fixture.image.path.wstring();
        volume.volume_object_id = 101;
        volume.allow_legacy_scaffold_for_fixtures = false;
        c.args.device = volume.device_path; c.args.volume = L"Alpha";
        c.args.volume_object_id = 101; c.args.mount = L"E:";
        c.args.readwrite = true; c.args.readonly = false; c.args.write_backend = L"Native";
        c.args.allow_legacy_scaffold_for_fixtures = false;
        c.args.write_max_dirty_transactions = 1;
        c.native_write_enabled = true;
        SeedRoot(c);
        std::array<std::byte, 16> security{};
        SeedSecurity(c, security);

        // DirectorySymlinkFixture::Initialize uses a process-independent WAL
        // identity. Its named-pipe writer lease can collide even with different
        // TEMP roots. Configure our identity BEFORE the first SetJournalPath;
        // replacing an already poisoned transaction manager would hide failure.
        // The image name includes PID, tick and a per-process fixture counter.
        static std::atomic<std::uint64_t> next_session{0};
        const auto session_root = fixture.image.path.parent_path() /
            (L"atime-302-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
             std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(next_session.fetch_add(1)));
        std::error_code ec;
        if (!Require(std::filesystem::create_directory(session_root, ec) && !ec,
                "atime fixture exclusively creates its private session root")) return false;
        c.session_root = session_root;
        c.cache_root = c.session_root / "hydrate";
        std::filesystem::create_directories(c.cache_root, ec);
        if (!Require(!ec, "atime fixture creates its private session root")) return false;
        c.recovery_marker_file = c.session_root / "recovery.marker";
        if (manifest)
        {
            std::string error;
            fixture.coordinator = apfsaccess::catalog::ContainerMountCoordinator::Open(
                fixture.image.path.string(), 0, error,
                apfsaccess::catalog::CatalogLoadPolicy::StrictApple, true, true);
            if (!Require(fixture.coordinator != nullptr, "atime strict coordinator opens")) return false;
            c.args.container_id = Utf8ToWide(fixture.coordinator->ContainerUuidHex());
            std::wstring mount_error;
            if (!Require(MountManifestSession(*fixture.coordinator, c.args, c, mount_error),
                    "atime manifest session prepares without mounting WinFsp") ||
                !Require(fixture.coordinator->InitializeRequiredCheckpointCensus({{101, {}}, {102, {}}}, error),
                    "atime fixture volumes have a clean checkpoint census")) return false;
        }
        else
        {
            c.owned_metadata_store = std::make_unique<Store>(volume);
            c.metadata_store = c.owned_metadata_store.get();
            if (!c.metadata_store->PrepareNativeWritePath()) return false;
        }
        const auto* view = c.metadata_store->AuthoritativeAppleCheckpointView();
        if (!Require(view && view->volumes.size() == (manifest ? 2u : 1u) &&
                IsManifestSession(&c) == manifest,
                "atime direct authority has one volume; manifest authority owns both")) return false;
        if (!manifest)
        {
            std::uint64_t preimage = 0;
            std::string error;
            if (!Require(GetDirectApplePreimageLocked(*c.metadata_store, preimage, error) && preimage != 0,
                    "atime direct checkpoint identity permits WAL acceptance")) return false;
        }
        c.payload_spool_volume_identity = Tx::WideToUtf8(L"deferred-atime-302:" + volume.device_path);
        c.tx_manager = std::make_unique<Tx>(L"Conservative");
        c.tx_manager->SetVolumeIdentity(Utf8ToWide(c.payload_spool_volume_identity));
        c.tx_manager->SetJournalPath((c.session_root / "accepted.wal").wstring());
        if (!Require(c.tx_manager->RecoveryStateValid() && c.tx_manager->CurrentState() == Tx::State::Idle &&
                c.tx_manager->JournalAppendHandleOpenCount() == 1,
                "atime fixture acquires its own valid writer lease before any read or staging"))
        {
            std::wcerr << L"[atime302] journal initialization failed: pid=" << GetCurrentProcessId()
                << L" manifest=" << manifest << L" wal=" << (c.session_root / "accepted.wal")
                << L" identity=" << Utf8ToWide(c.payload_spool_volume_identity)
                << L" recovery-valid=" << c.tx_manager->RecoveryStateValid() << L'\n';
            return false;
        }
        c.payload_spool = std::make_unique<apfsaccess::rw::PayloadSpool>(apfsaccess::rw::PayloadSpool::Options{
            c.session_root / "payload-spool", c.payload_spool_volume_identity, 1024 * 1024});
        c.metadata_store->SetFilePayloadRangeProvider([&c](const std::wstring& path, Store::PayloadIdentity identity,
                std::uint64_t offset, std::span<std::byte> destination) {
            return ReadHydratedPayloadRangeForPath(&c, path, identity, offset, destination);
        });
        return MergeCommittedInodeStateIntoNodeIndex(&c);
    }

    bool Initialize(bool manifest, std::uint64_t file_count = 3)
    {
        using namespace apfsaccess::rw;
        auto builder = TwoProjectableVolumeStore();
        if (!manifest) builder.volumes.resize(1);
        builder.authoritative_checkpoint = true;
        builder.dual_checkpoint = false;
        builder.xid = 20;
        builder.block_count = file_count > 3 ? 8192 : 1024;
        auto& volume = builder.volumes.front();
        auto& records = volume.filesystem_records;
        apfsaccess::catalog::BtreeRecord encoded;
        std::string error;
        const auto add = [&](bool ok) { if (ok) records.push_back(encoded); return ok; };
        AppleInodeRecord root;
        root.object_id = root.private_id = root.parent_id = 2;
        root.mode = 0040755; root.children_or_links = 4;
        if (!add(EncodeAppleInodeRecord(root, encoded, error))) return false;
        for (std::uint64_t id = 17; id != 20; ++id)
        {
            const std::string name = "read" + std::to_string(id);
            AppleInodeRecord inode;
            inode.object_id = inode.private_id = id; inode.parent_id = 2;
            inode.mode = 0100640; inode.owner = 501; inode.group = 20;
            inode.children_or_links = id == 17 ? 2 : 1;
            inode.uncompressed_size = bytes.size();
            inode.create_time = inode.modification_time = inode.change_time = inode.access_time = 1700000000000000000ULL;
            AppleExtendedField stream; stream.type = 8; stream.data.resize(40);
            apfsaccess::testfixture::PutU64LE(stream.data, 0, bytes.size());
            apfsaccess::testfixture::PutU64LE(stream.data, 8, 4096);
            inode.extended_fields.push_back(stream);
            AppleExtendedField primary; primary.type = 4;
            primary.data.assign(reinterpret_cast<const std::byte*>(name.c_str()),
                reinterpret_cast<const std::byte*>(name.c_str() + name.size() + 1));
            inode.extended_fields.push_back(primary);
            AppleDirectoryRecord link;
            link.parent_id = 2; link.file_id = id; link.flags = 8; link.name_utf8 = name;
            const auto physical = 100 + id - 17;
            if (!add(EncodeAppleInodeRecord(inode, encoded, error)) ||
                !add(EncodeAppleDirectoryRecord(link, encoded, error)) ||
                !add(EncodeAppleDataStreamIdRecord({id, 1}, encoded, error)) ||
                !add(EncodeAppleFileExtentRecord({id, 0, 4096, physical, 0, 4096}, encoded, error)) ||
                !add(EncodeAppleXattrRecord({id, kAppleSecurityName, kAppleXattrDataEmbedded, acl}, encoded, error)) ||
                !EncodeApplePhysicalExtentRecord({physical, 1, kApplePhysicalExtentKindNew, id, 1}, encoded, error)) return false;
            volume.extentref_records.push_back(encoded);
            ++volume.additional_file_system_allocated_blocks;
            auto padded = bytes; padded.resize(4096);
            builder.authoritative_seeded_main_blocks.push_back({physical, std::move(padded)});
        }
        for (const auto sibling : {700ULL, 701ULL})
        {
            const auto name = sibling == 700 ? "read17" : "alias";
            if (sibling == 701)
            {
                AppleDirectoryRecord link;
                link.parent_id = 2; link.file_id = 17; link.flags = 8; link.name_utf8 = name;
                if (!add(EncodeAppleDirectoryRecord(link, encoded, error))) return false;
            }
            if (!add(EncodeAppleSiblingLinkRecord({17, sibling, 2, name}, encoded, error)) ||
                !add(EncodeAppleSiblingMapRecord({sibling, 17}, encoded, error))) return false;
        }
        if (!(SortAppleBtreeRecords(records, AppleBtreeKeyOrder::FileSystemCaseSensitive, error) &&
            SortAppleBtreeRecords(volume.extentref_records, AppleBtreeKeyOrder::PhysicalExtent, error) &&
            WriteFileBytes(fixture.image.path, apfsaccess::testfixture::BuildStoreImage(builder)) &&
            InitializeContext(manifest))) return false;
        if (file_count == 3) return true;
        if (!manifest) return false;
        // The raw builder encodes one leaf. Seed larger namespaces through the
        // actual writer, which allocates and publishes the multi-level trees.
        std::vector<MetadataStore::MutationRequest> mutations;
        for (std::uint64_t id = 20; id != 17 + file_count; ++id)
        {
            const auto path = L"\\read" + std::to_wstring(id);
            MetadataStore::MutationRequest create, write, metadata, security;
            create.operation = MetadataStore::MutationOperation::CreateFile; create.path = path;
            write.operation = MetadataStore::MutationOperation::Write; write.path = path; write.length = bytes.size();
            InodeMetadataPatch patch;
            patch.mask = InodeMetadataPatch::Owner | InodeMetadataPatch::Group | InodeMetadataPatch::Mode;
            patch.owner = 501; patch.group = 20; patch.mode = 0640;
            metadata.operation = MetadataStore::MutationOperation::SetInodeMetadata; metadata.path = path;
            if (!EncodeInodeMetadataPatch(patch, metadata.inline_payload)) return false;
            metadata.length = metadata.inline_payload.size();
            security.operation = MetadataStore::MutationOperation::SetExtendedAttribute;
            security.path = path; security.secondary_path = Utf8ToWide(kAppleSecurityName);
            security.inline_payload = acl; security.length = acl.size();
            mutations.insert(mutations.end(), {create, write, metadata, security});
        }
        auto& c = *fixture.context;
        c.metadata_store->SetFilePayloadRangeProvider([this](const std::wstring& path, MetadataStore::PayloadIdentity,
                std::uint64_t offset, std::span<std::byte> destination) -> std::size_t {
            if (!path.starts_with(L"\\read") || offset > bytes.size() || destination.size() > bytes.size() - offset) return 0;
            std::copy_n(bytes.data() + offset, destination.size(), destination.data()); return destination.size();
        });
        ScopeExit restore{[&] { c.metadata_store->SetFilePayloadRangeProvider([&c](const std::wstring& path,
                MetadataStore::PayloadIdentity identity, std::uint64_t offset, std::span<std::byte> destination) {
            return ReadHydratedPayloadRangeForPath(&c, path, identity, offset, destination);
        }); }};
        const auto seeded = fixture.coordinator->Commit(101, mutations);
        if (!Require(seeded.committed && !seeded.commit_recovery_required,
                "large atime fixture seeds through real native publication"))
        {
            std::cerr << "[atime311] seeding: " << seeded.error << '\n';
            return false;
        }
        return MergeCommittedInodeStateIntoNodeIndex(&c);
    }

    bool ReadCleanup(std::wstring path, std::uint64_t& access_time)
    {
        auto fs = BuildFileSystem(fixture.context.get());
        PVOID handle = nullptr;
        FSP_FSCTL_FILE_INFO info{};
        if (!Require(CB_Open(&fs, path.data(), FILE_NON_DIRECTORY_FILE | (FILE_OPEN << 24),
                FILE_READ_DATA | FILE_READ_ATTRIBUTES, &handle, &info) == STATUS_SUCCESS,
                "native ordinary reader opens")) return false;
        ScopeExit close{[&] { CB_Close(&fs, handle); }};
        std::array<std::byte, 64> actual{};
        ULONG done = 0;
        if (!Require(CB_Read(&fs, handle, actual.data(), 0, actual.size(), &done) == STATUS_SUCCESS &&
                done == bytes.size() && std::equal(bytes.begin(), bytes.end(), actual.begin()),
                "native reader returns exact seeded file bytes")) return false;
        CB_Cleanup(&fs, handle, nullptr, FspCleanupSetLastAccessTime);
        if (!Require(CB_GetFileInfo(&fs, handle, &info) == STATUS_SUCCESS,
                "cleanup timestamp is immediately visible")) return false;
        access_time = info.LastAccessTime;
        return true;
    }

    bool CheckFresh(const std::map<std::wstring, std::uint64_t>& expected)
    {
        apfsaccess::rw::MetadataStore fresh(fixture.volume);
        if (!Require(fresh.PrepareNativeWritePath(), "fresh native reopen selects a complete checkpoint")) return false;
        for (const auto& [path, time] : expected)
        {
            const auto inode = fresh.LookupCommittedInodeByPath(path);
            std::vector<std::byte> actual;
            if (!Require(inode && inode->access_time_utc == time && inode->owner == 501 &&
                    inode->group == 20 && inode->mode == 0100640 &&
                    fresh.ReadCommittedFileRange(path, 0, bytes.size(), actual) && actual == bytes,
                    "fresh checkpoint has exact atime, original bytes and Mac UID/GID/mode")) return false;
            const auto stored_acl = fresh.LookupCommittedExtendedAttribute(inode->object_id, kAppleSecurityName);
            if (!Require(stored_acl && stored_acl->data == acl, "Mac ACL bytes survive atime publication")) return false;
        }
        return true;
    }
};

bool TestDeferredAccessTimeBatch302(bool manifest)
{
    std::cerr << "[atime302] batch manifest=" << manifest << '\n';
    if (!DeferredAccessTimeScratch302()) return false;
    DeferredAccessTimeFixture302 owned(manifest);
    if (!owned.Initialize(manifest)) return false;
    auto& c = *owned.fixture.context;
    auto fs = BuildFileSystem(&c);
    const auto image = ReadFileBytes(owned.fixture.image.path);
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    const auto before = c.metadata_store->LookupCommittedInodeByPath(L"\\read17");
    unsigned publications = 0;
    c.metadata_store->SetCommitStageHook([&](std::string_view stage) {
        if (stage == "before-apple-publish") ++publications;
        return true;
    });
    ScopeExit clear{[&] { c.metadata_store->SetCommitStageHook({}); }};
    std::map<std::wstring, std::uint64_t> expected;
    for (const auto path : {L"\\read17", L"\\read18", L"\\read19", L"\\alias", L"\\read17"})
        if (!owned.ReadCleanup(path, expected[path])) return false;
    expected[L"\\alias"] = expected[L"\\read17"];
    PVOID alias = nullptr; FSP_FSCTL_FILE_INFO info{};
    if (!Require(CB_Open(&fs, const_cast<PWSTR>(L"\\alias"), FILE_OPEN << 24,
            FILE_READ_ATTRIBUTES, &alias, &info) == STATUS_SUCCESS &&
            info.LastAccessTime == expected[L"\\read17"], "hard-link alias observes the latest volatile atime")) return false;
    CB_Cleanup(&fs, alias, nullptr, FspCleanupSetLastAccessTime); CB_Close(&fs, alias);
    PVOID root = nullptr;
    if (CB_Open(&fs, const_cast<PWSTR>(L"\\"), FILE_DIRECTORY_FILE | (FILE_OPEN << 24),
            FILE_READ_ATTRIBUTES, &root, &info) != STATUS_SUCCESS) return false;
    CB_Cleanup(&fs, root, nullptr, FspCleanupSetLastAccessTime); CB_Close(&fs, root);
    if (!Require(before && expected[L"\\read17"] > before->access_time_utc && publications == 0 &&
            image == ReadFileBytes(owned.fixture.image.path) && wal == ReadFileBytes(c.session_root / "accepted.wal") &&
            c.tx_manager->Watermarks().accepted_sequence == 0 && c.metadata_store->PendingMutationCount() == 0 &&
            ManifestQueuedRequestCount(&c) == 0,
            "multiple real read cleanups and closes perform no per-file durable publication or WAL acceptance")) return false;
    if (!Require(CB_Flush(&fs, nullptr, nullptr) == STATUS_SUCCESS && publications == 1,
            "one volume flush publishes the coalesced native batch exactly once")) return false;
    const auto after = c.metadata_store->LookupCommittedInodeByPath(L"\\read17");
    return Require(after && after->create_time_utc == before->create_time_utc &&
            after->modification_time_utc == before->modification_time_utc &&
            after->change_time_utc == before->change_time_utc,
            "automatic atime leaves creation, modification and change times intact") && owned.CheckFresh(expected);
}

bool TestDeferredAccessTimeOrdering302(bool manifest)
{
    if (!DeferredAccessTimeScratch302()) return false;
    DeferredAccessTimeFixture302 owned(manifest);
    if (!owned.Initialize(manifest)) return false;
    auto& c = *owned.fixture.context;
    auto fs = BuildFileSystem(&c);
    std::uint64_t automatic = 0;
    if (!owned.ReadCleanup(L"\\read17", automatic)) return false;
    PVOID editor = nullptr; FSP_FSCTL_FILE_INFO info{};
    if (CB_Open(&fs, const_cast<PWSTR>(L"\\alias"), FILE_OPEN << 24,
            FILE_WRITE_ATTRIBUTES, &editor, &info) != STATUS_SUCCESS) return false;
    constexpr std::uint64_t backward = 116444736000000000ULL + 16000000000000000ULL;
    const auto status = CB_SetBasicInfo(&fs, editor, INVALID_FILE_ATTRIBUTES, 0, backward, 0, 0, &info);
    CB_Close(&fs, editor);
    if (!Require(status == STATUS_SUCCESS && info.LastAccessTime == backward && backward < automatic &&
            CB_Flush(&fs, nullptr, nullptr) == STATUS_SUCCESS,
            "later explicit backward access time drains and supersedes older automatic requests") ||
        !owned.CheckFresh({{L"\\read17", backward}, {L"\\alias", backward}})) return false;
    std::uint64_t renamed_time = 0;
    if (!owned.ReadCleanup(L"\\read18", renamed_time) ||
        !Require(CB_Rename(&fs, nullptr, const_cast<PWSTR>(L"\\read18"), const_cast<PWSTR>(L"\\moved"), FALSE) == STATUS_SUCCESS &&
            CB_Flush(&fs, nullptr, nullptr) == STATUS_SUCCESS, "rename drains the old inode atime before namespace change") ||
        !owned.CheckFresh({{L"\\moved", renamed_time}})) return false;
    // Replace the queued target with a distinct, previously unread inode.
    if (!owned.ReadCleanup(L"\\moved", renamed_time)) return false;
    const auto replacement = c.metadata_store->LookupCommittedInodeByPath(L"\\read19");
    if (!Require(replacement && CB_Rename(&fs, nullptr, const_cast<PWSTR>(L"\\read19"),
            const_cast<PWSTR>(L"\\moved"), TRUE) == STATUS_SUCCESS && CB_Flush(&fs, nullptr, nullptr) == STATUS_SUCCESS,
            "replacement drains old identity before unlink and path reuse")) return false;
    apfsaccess::rw::MetadataStore fresh(owned.fixture.volume);
    if (!fresh.PrepareNativeWritePath()) return false;
    const auto replaced = fresh.LookupCommittedInodeByPath(L"\\moved");
    if (!Require(replaced && replaced->object_id == replacement->object_id &&
            replaced->access_time_utc == replacement->access_time_utc &&
            !fresh.LookupCommittedInodeByObjectId(18),
            "replacement inode never receives old target atime and unlinked inode is not restored")) return false;
    std::uint64_t surviving_time = 0;
    if (!owned.ReadCleanup(L"\\alias", surviving_time)) return false;
    PVOID deleting = nullptr;
    if (CB_Open(&fs, const_cast<PWSTR>(L"\\alias"), FILE_OPEN << 24, DELETE, &deleting, &info) != STATUS_SUCCESS)
        return false;
    const auto deletion = CB_SetDelete(&fs, deleting, nullptr, TRUE);
    if (NT_SUCCESS(deletion)) CB_Cleanup(&fs, deleting, nullptr, FspCleanupDelete);
    CB_Close(&fs, deleting);
    if (!Require(NT_SUCCESS(deletion) && CB_Flush(&fs, nullptr, nullptr) == STATUS_SUCCESS,
            "hard-link unlink drains the inode timestamp before removing only that name")) return false;
    return owned.CheckFresh({{L"\\read17", surviving_time}});
}

bool TestDeferredAccessTimeShutdown302(bool manifest)
{
    if (!DeferredAccessTimeScratch302()) return false;
    DeferredAccessTimeFixture302 owned(manifest);
    if (!owned.Initialize(manifest)) return false;
    std::uint64_t time = 0;
    if (!owned.ReadCleanup(L"\\read17", time)) return false;
    // A second independent image must acquire its own writer lease while the
    // first still owns both its lease and a pending inode/alias timestamp.
    // Different WAL paths alone did not isolate the former fixed identity.
    if (!manifest)
    {
        DeferredAccessTimeFixture302 neighbor(false);
        if (!neighbor.Initialize(false)) return false;
        if (!Require(owned.fixture.context->payload_spool_volume_identity !=
                neighbor.fixture.context->payload_spool_volume_identity &&
                owned.fixture.context->session_root != neighbor.fixture.context->session_root &&
                owned.fixture.context->tx_manager->RecoveryStateValid(),
                "independent atime fixtures own distinct session paths and writer identities")) return false;
        std::uint64_t neighbor_time = 0;
        if (!neighbor.ReadCleanup(L"\\read18", neighbor_time) ||
            !Require(RunFsHostShutdownDrain(neighbor.fixture.context) == 0,
                "independent fixture shuts down while the first retains its timestamp") ||
            !neighbor.CheckFresh({{L"\\read18", neighbor_time}})) return false;
    }
    // No WinFsp instance is mounted. Exercise the production shutdown drain;
    // teardown sees an empty lifecycle and the context remains fixture-owned.
    if (!Require(RunFsHostShutdownDrain(owned.fixture.context) == 0,
            "clean host shutdown drains retained automatic atime")) return false;
    return owned.CheckFresh({{L"\\read17", time}, {L"\\alias", time}});
}

bool TestDeferredAccessTimeAcceptedFailure302(bool manifest, bool after_publication)
{
    std::cerr << "[atime302] accepted manifest=" << manifest << " after=" << after_publication << '\n';
    using Tx = apfsaccess::rw::TransactionManager;
    using Wal = apfsaccess::rw::WriteAheadLog;
    if (!DeferredAccessTimeScratch302()) return false;
    DeferredAccessTimeFixture302 owned(manifest);
    if (!owned.Initialize(manifest)) return false;
    auto& c = *owned.fixture.context;
    auto fs = BuildFileSystem(&c);
    std::map<std::uint64_t, std::uint64_t> expected;
    if (!owned.ReadCleanup(L"\\read17", expected[17]) || !owned.ReadCleanup(L"\\read18", expected[18])) return false;
    const auto preimage = c.metadata_store->CheckpointXid();
    const auto image = ReadFileBytes(owned.fixture.image.path);
    unsigned failed = 0;
    bool accepted_exact = false;
    c.metadata_store->SetCommitStageHook([&](std::string_view stage) {
        if (stage != (after_publication ? "after-apple-publish" : "before-apple-publish")) return true;
        ++failed;
        const auto persisted = Wal::ReadAll(c.session_root / "accepted.wal", c.payload_spool_volume_identity);
        const Wal::Record* marker = nullptr;
        std::vector<Wal::Record> mutations;
        unsigned markers = 0;
        for (const auto& record : persisted.records)
            if (record.operation == Wal::OperationKind::TransactionMarker) { marker = &record; ++markers; }
            else mutations.push_back(record);
        accepted_exact = persisted.status == Wal::ReadStatus::Ok && !persisted.recovered_torn_tail &&
            markers == 1 && marker && marker->state == Wal::RecordState::Accepted &&
            preimage && marker->object_id == *preimage && marker->logical_length == expected.size() &&
            mutations.size() == expected.size();
        if (accepted_exact) for (const auto& record : mutations)
        {
            apfsaccess::rw::InodeMetadataPatch patch;
            const auto found = expected.find(record.object_id);
            accepted_exact &= record.transaction_id == marker->transaction_id && record.sequence < marker->sequence &&
                record.state == Wal::RecordState::Prepared &&
                record.operation == Wal::OperationKind::SetInodeMetadata && found != expected.end() &&
                record.parent_object_id != 0 && apfsaccess::rw::DecodeInodeMetadataPatch(record.inline_payload, patch) &&
                patch.mask == apfsaccess::rw::InodeMetadataPatch::AccessTime &&
                (found == expected.end() || patch.access_time_utc == found->second);
        }
        return false;
    });
    ScopeExit clear{[&] { c.metadata_store->SetCommitStageHook({}); }};
    const auto status = CB_Flush(&fs, nullptr, nullptr);
    const auto marks = c.tx_manager->Watermarks();
    std::cerr << "[atime302] status=" << status << " failed=" << failed << " exact=" << accepted_exact
        << " degraded=" << c.write_degraded << " accepted=" << marks.accepted_sequence
        << " durable=" << marks.apfs_durable_sequence << " cleanup=" << marks.cleanup_sequence << '\n';
    if (!Require(!NT_SUCCESS(status) && failed == 1 && accepted_exact && c.write_degraded &&
            marks.accepted_sequence > marks.apfs_durable_sequence && marks.accepted_sequence > marks.cleanup_sequence &&
            std::filesystem::exists(c.recovery_marker_file) &&
            (after_publication || image == ReadFileBytes(owned.fixture.image.path)),
            "accepted failure retains exact inode-bound atime WAL and marker without false durable/cleanup watermarks")) return false;
    const auto wal_before_shutdown = ReadFileBytes(c.session_root / "accepted.wal");
    return Require(RunFsHostShutdownDrain(owned.fixture.context) != 0 &&
            wal_before_shutdown == ReadFileBytes(c.session_root / "accepted.wal"),
            "failed shutdown cannot erase accepted access-time recovery evidence");
}

bool TestDeferredAccessTimeWorker302(bool manifest)
{
    if (!DeferredAccessTimeScratch302()) return false;
    DeferredAccessTimeFixture302 owned(manifest);
    if (!owned.Initialize(manifest)) return false;
    auto& c = *owned.fixture.context;
    std::uint64_t time = 0;
    if (!owned.ReadCleanup(L"\\read17", time)) return false;
    std::promise<void> published;
    auto publication = published.get_future();
    std::atomic<unsigned> count{0};
    c.metadata_store->SetCommitStageHook([&](std::string_view stage) {
        if (stage == "after-apple-publish" && count.fetch_add(1) == 0) published.set_value();
        return true;
    });
    ScopeExit stop{[&] { StopDeferredCommitWorker(&c); c.metadata_store->SetCommitStageHook({}); }};
    StartDeferredCommitWorker(&c);
    const bool completed = publication.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
    // Join before reopening: observing the publication hook alone does not
    // prove WAL finalization or worker/context lifetime has completed.
    if (!Require(StopDeferredCommitWorker(&c) && completed && count.load() == 1,
            "existing deferred worker persists idle read atime without a flush callback")) return false;
    return owned.CheckFresh({{L"\\read17", time}, {L"\\alias", time}});
}

bool TestDeferredAccessTimeOverdue311(bool manifest)
{
    if (!DeferredAccessTimeScratch302()) return false;
    DeferredAccessTimeFixture302 owned(manifest);
    if (!owned.Initialize(manifest)) return false;
    auto& c = *owned.fixture.context;
    std::uint64_t previous = 0, latest = 0;
    if (!owned.ReadCleanup(L"\\read18", previous)) return false;
    {
        std::lock_guard<std::mutex> schedule(c.deferred_commit_mutex);
        // Deterministic equivalent of a worker repeatedly losing the gate:
        // its retry deadline moved, but the first retained request is overdue.
        c.deferred_access_time_first = std::chrono::steady_clock::now() - kDeferredAccessTimeMaximumDelay;
        c.deferred_access_time_deadline = std::chrono::steady_clock::now() + kDeferredAccessTimeIdleDelay;
    }
    if (!owned.ReadCleanup(L"\\read18", latest)) return false;
    return Require(c.deferred_access_times.empty() && !c.deferred_access_time_overflow,
            "continuous foreground reads drain overdue atime without waiting for the worker's retry") &&
        owned.CheckFresh({{L"\\read18", latest}});
}

bool TestDeferredAccessTimePressure311()
{
    if (!DeferredAccessTimeScratch302()) return false;
    DeferredAccessTimeFixture302 owned(true);
    constexpr auto count = kDeferredAccessTimeMaxInodes + 2;
    if (!owned.Initialize(true, count)) return false;
    auto& c = *owned.fixture.context;
    owned.sibling.args = ManifestSessionArgs(owned.fixture.image.path, 102,
        Utf8ToWide(owned.fixture.coordinator->ContainerUuidHex()), L"private-atime-sibling-311", true);
    owned.sibling.args.write_require_canonical_commit = true;
    owned.sibling.args.allow_legacy_scaffold_for_fixtures = false;
    std::wstring error;
    if (!MountManifestSession(*owned.fixture.coordinator, owned.sibling.args, owned.sibling, error)) return false;
    const auto sibling_root = owned.sibling.metadata_store->LookupCommittedInodeByPath(L"\\");
    if (!Require(sibling_root && sibling_root->object_id == 2 &&
            owned.sibling.metadata_store->AuthoritativeAppleCheckpointView(),
            "pressure sibling uses the genuine Apple root and canonical transaction policy") ||
        !CompressionManifestRefusal279::SeedAcceptedSibling(owned)) return false;
    const auto image = ReadFileBytes(owned.fixture.image.path);
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    std::map<std::wstring, std::uint64_t> expected;
    for (std::size_t i = 0; i != count; ++i)
    {
        const auto path = L"\\read" + std::to_wstring(17 + i);
        if (!owned.ReadCleanup(path, expected[path])) return false;
    }
    expected[L"\\alias"] = expected[L"\\read17"];
    auto fs = BuildFileSystem(&c);
    const auto first_retry = CB_Flush(&fs, nullptr, nullptr);
    const auto second_retry = CB_Flush(&fs, nullptr, nullptr);
    if (!Require(first_retry == STATUS_DEVICE_BUSY && second_retry == STATUS_DEVICE_BUSY &&
            c.deferred_access_times.size() == kDeferredAccessTimeMaxInodes && c.deferred_access_time_overflow &&
            !c.write_degraded && IsNativeWriteEnabled(&c) && image == ReadFileBytes(owned.fixture.image.path) &&
            wal == ReadFileBytes(c.session_root / "accepted.wal"),
            "514 successful reads retain all times through repeated real sibling-census refusal with a bounded queue")) return false;
    if (!Require(ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(owned.sibling), "first sibling replay resolves refusal"))
    {
        const auto* store = owned.sibling.metadata_store;
        std::wcerr << L"[atime311] sibling oid=" << owned.sibling.args.volume_object_id
            << L" detail=" << store->LastCommitFailureDetail() << L" object="
            << store->LastCommitFailureObjectId().value_or(0) << L'\n';
        for (const auto& inode : store->SnapshotCommittedInodes())
            std::wcerr << L"[atime311] committed id=" << inode.object_id << L" path=" << inode.full_path << L'\n';
        const auto retained = owned.fixture.image.path.wstring() + L".failure-retained";
        (void)CopyFileW(owned.fixture.image.path.c_str(), retained.c_str(), TRUE);
        std::wcerr << L"[atime311] retained=" << retained << L'\n';
        return false;
    }
    {
        MutationCallbackScope mutation(&c);
        if (!Require(DrainDeferredAccessTimeBatch(&c) == STATUS_SUCCESS && c.deferred_access_times.empty() &&
                c.deferred_access_time_overflow && c.deferred_access_time_requested,
                "successful first batch preserves scheduling and age for the remaining timestamps")) return false;
    }
    if (!CompressionManifestRefusal279::SeedAcceptedSibling(owned, L"\\accepted-sibling-second-314")) return false;
    if (!Require(CB_Flush(&fs, nullptr, nullptr) == STATUS_DEVICE_BUSY && c.deferred_access_time_requested &&
            c.deferred_access_times.size() == 2, "new refusal between batches keeps both remaining times scheduled")) return false;
    if (!Require(ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(owned.sibling),
            "second sibling replay uses the generation after first timestamp batch")) return false;
    std::promise<void> published; auto publication = published.get_future();
    std::atomic<unsigned> count_published{0};
    c.metadata_store->SetCommitStageHook([&](std::string_view stage) {
        if (stage == "after-apple-publish" && count_published.fetch_add(1) == 0) published.set_value();
        return true;
    });
    ScopeExit stop{[&] { StopDeferredCommitWorker(&c); c.metadata_store->SetCommitStageHook({}); }};
    StartDeferredCommitWorker(&c);
    const bool completed = publication.wait_for(std::chrono::seconds(15)) == std::future_status::ready;
    if (!Require(StopDeferredCommitWorker(&c) && completed && c.deferred_access_times.empty() &&
            !c.deferred_access_time_overflow && !c.deferred_access_time_requested,
            "idle worker retries remaining spill after actual sibling recovery")) return false;
    return owned.CheckFresh(expected);
}
