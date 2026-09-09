#pragma once
// Uses the existing host fixture lifecycle and engine image writer. No mounts.
std::optional<std::array<std::uint8_t, 32>> NativeCloneHash500(const std::vector<std::byte>& bytes)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return std::nullopt;
    ScopeExit close{[&] { BCryptCloseAlgorithmProvider(algorithm, 0); }};
    std::array<std::uint8_t, 32> digest{};
    if (BCryptHash(algorithm, nullptr, 0, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())),
            static_cast<ULONG>(bytes.size()), digest.data(), static_cast<ULONG>(digest.size())) < 0) return std::nullopt;
    return digest;
}

struct NativeCloneHost500Fixture
{
    DirectorySymlinkFixture fixture{false};
    std::vector<std::byte> original = std::vector<std::byte>(16384);
    FSP_FILE_SYSTEM fs{};
    PVOID source = nullptr, directory = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    bool Initialize(bool quota = false, bool windows_acl = false, std::uint64_t raw_padding = 0,
        bool case_alias = false, bool flagged_size = false, bool manifest = false)
    {
        using namespace apfsaccess::rw;
        auto builder = TwoProjectableVolumeStore();
        builder.volumes.resize(manifest ? 2 : 1); builder.block_count = 1024;
        builder.authoritative_checkpoint = true; builder.dual_checkpoint = false; builder.xid = 20;
        builder.authoritative_internal_pool_blocks = 16; builder.authoritative_checkpoint_ring_blocks = 16;
        auto& v = builder.volumes.front(); v.incompat = case_alias ? 1 : 0; v.next_object_id = 1000;
        v.additional_file_system_allocated_blocks = 4;
        auto& records = v.filesystem_records; records.clear(); v.extentref_records.clear();
        apfsaccess::catalog::BtreeRecord encoded; std::string error;
        auto add = [&](bool ok) { if (ok) records.push_back(encoded); return ok; };
        AppleInodeRecord root; root.object_id = root.private_id = root.parent_id = 2;
        root.mode = 0040755; root.children_or_links = 1;
        if (!add(EncodeAppleInodeRecord(root, encoded, error))) return false;
        AppleInodeRecord inode; inode.object_id = inode.private_id = 17; inode.parent_id = 2;
        inode.mode = 0100640; inode.owner = 501; inode.group = 20; inode.children_or_links = 1;
        inode.uncompressed_size = raw_padding;
        if (flagged_size) inode.internal_flags |= kAppleInodeHasUncompressedSize;
        inode.create_time = inode.modification_time = inode.change_time = inode.access_time = 1700000000000000000ULL;
        AppleExtendedField stream; stream.type = 8; stream.data.resize(40);
        apfsaccess::testfixture::PutU64LE(stream.data, 0, original.size());
        apfsaccess::testfixture::PutU64LE(stream.data, 8, original.size()); inode.extended_fields.push_back(stream);
        AppleDirectoryRecord link; link.parent_id = 2; link.file_id = 17; link.flags = 8; link.name_utf8 = "source";
        if (!add(EncodeAppleInodeRecord(inode, encoded, error)) || !add(EncodeAppleDirectoryRecord(link, encoded, error)) ||
            !add(EncodeAppleDataStreamIdRecord({17, 1}, encoded, error)) ||
            !add(EncodeAppleFileExtentRecord({17, 0, 16384, 128, 0, 4096}, encoded, error))) return false;
        for (const auto name : {"user.keep", "com.apple.ResourceFork"})
            if (!add(EncodeAppleXattrRecord({17, name, kAppleXattrDataEmbedded,
                std::vector<std::byte>(quota && std::string_view(name) == "user.keep" ? 2300 : 12, std::byte{0x61})}, encoded, error))) return false;
        AppleSecurityRecord mac_acl; mac_acl.acl_flags = 0x100; mac_acl.entries.push_back({{}, 1, 3});
        std::vector<std::byte> security;
        if (!ApfsExtendedRecordCodec::EncodeSecurity(mac_acl, security, error) ||
            !add(EncodeAppleXattrRecord({17, "com.apple.system.Security", kAppleXattrDataEmbedded, security}, encoded, error))) return false;
        if (windows_acl && !add(EncodeAppleXattrRecord({2, kWindowsSecurityName, kAppleXattrDataEmbedded,
                {std::byte{1}}}, encoded, error))) return false;
        if (!EncodeApplePhysicalExtentRecord({128, 4, kApplePhysicalExtentKindNew, 17, 1}, encoded, error)) return false;
        v.extentref_records.push_back(encoded);
        for (std::size_t i = 0; i < original.size(); ++i) original[i] = std::byte((i * 13 + i / 4096 * 47) % 251);
        for (unsigned i = 0; i < 4; ++i)
            builder.authoritative_seeded_main_blocks.push_back({128 + i,
                std::vector<std::byte>(original.begin() + i * 4096, original.begin() + (i + 1) * 4096)});
        if (case_alias)
        {
            AppleInodeRecord folder = root; folder.object_id = folder.private_id = 18;
            folder.children_or_links = 0;
            AppleDirectoryRecord folder_link; folder_link.parent_id = 2; folder_link.file_id = 18;
            folder_link.flags = 4; folder_link.name_utf8 = "Folder";
            if (!add(EncodeAppleInodeRecord(folder, encoded, error)) ||
                !add(EncodeAppleDirectoryRecord(folder_link, encoded, error))) return false;
        }
        if (!SortAppleBtreeRecords(records, case_alias ? AppleBtreeKeyOrder::FileSystemHashedDirectory :
                AppleBtreeKeyOrder::FileSystemCaseSensitive, error)) return false;
        if (manifest)
        {
            auto& sibling = builder.volumes[1];
            sibling.incompat = v.incompat; sibling.next_object_id = 1000;
            sibling.additional_file_system_allocated_blocks = 4;
            sibling.filesystem_records = records;
            for (auto& record : sibling.filesystem_records)
                if ((apfsaccess::catalog::ReadU64LE(record.key, 0).value_or(0) >> 60) == 8)
                    if (!EncodeAppleFileExtentRecord({17, 0, 16384, 132, 0, 4096}, record, error)) return false;
            sibling.extentref_records.clear();
            if (!EncodeApplePhysicalExtentRecord({132, 4, kApplePhysicalExtentKindNew, 17, 1}, encoded, error)) return false;
            sibling.extentref_records.push_back(encoded);
            for (unsigned i = 0; i != 4; ++i)
                builder.authoritative_seeded_main_blocks.push_back({132 + i, std::vector<std::byte>(4096, std::byte{0x39})});
        }
        auto image = apfsaccess::testfixture::BuildStoreImage(builder);
        if (quota)
        {
            apfsaccess::catalog::VectorRandomAccessSource bytes(image);
            auto view = apfsaccess::catalog::LoadAppleCheckpointView(bytes, 0, bytes.SizeBytes(), error);
            if (!view) return false;
            v.quota_block_count = view->volumes.front().superblock.space.allocated_block_count;
            image = apfsaccess::testfixture::BuildStoreImage(builder);
        }
        if (!WriteFileBytes(fixture.image.path, image) || !fixture.Initialize(manifest)) return false;
        fs = BuildFileSystem(fixture.context.get());
        return true;
    }
    bool Open(UINT32 source_access = FILE_READ_DATA, UINT32 directory_access = FILE_ADD_FILE)
    {
        return CB_Open(&fs, const_cast<PWSTR>(L"\\source"), FILE_OPEN << 24, source_access, &source, &info) == STATUS_SUCCESS &&
            CB_Open(&fs, const_cast<PWSTR>(L"\\"), FILE_DIRECTORY_FILE, directory_access, &directory, &info) == STATUS_SUCCESS;
    }
    NTSTATUS Export(apfsaccess::fshost::clone_control::ExportReply& reply)
    {
        apfsaccess::fshost::clone_control::ExportRequest request; ULONG done = 999;
        const auto status = ContainerServeInterface().Control(&fs, source, apfsaccess::fshost::clone_control::Export,
            &request, sizeof(request), &reply, sizeof(reply), &done);
        if (!NT_SUCCESS(status) && done != 0) return STATUS_UNSUCCESSFUL;
        return status;
    }
    NTSTATUS Import(const apfsaccess::fshost::clone_control::ExportReply& reply, std::wstring leaf = L"copy")
    {
        apfsaccess::fshost::clone_control::ImportRequest request; request.ticket = reply.ticket;
        request.leaf_chars = static_cast<std::uint32_t>(leaf.size());
        for (std::size_t i = 0; i < leaf.size() && i < request.leaf.size(); ++i) request.leaf[i] = leaf[i];
        ULONG done = 999;
        const auto status = ContainerServeInterface().Control(&fs, directory, apfsaccess::fshost::clone_control::Import,
            &request, sizeof(request), nullptr, 0, &done);
        return done == 0 ? status : STATUS_UNSUCCESSFUL;
    }
    ~NativeCloneHost500Fixture() { if (source) CB_Close(&fs, source); if (directory) CB_Close(&fs, directory); }
};

bool TestNativeCloneHost500()
{
    using F = NativeCloneHost500Fixture;
    using Store = apfsaccess::rw::MetadataStore;
    using Reply = apfsaccess::fshost::clone_control::ExportReply;
    if (!Require(std::filesystem::temp_directory_path().root_name() == L"D:", "clone host tests require D: TEMP")) return false;
    std::cerr << "[clone500] dispatcher refusals\n";
    {
        F f; Reply ticket;
        if (!Require(f.Initialize() && f.Open(), "clone host fixture opens real callback handles")) return false;
        auto& c = *f.fixture.context;
        ULONG done = 999;
        if (!Require(ContainerServeInterface().Control(&f.fs, f.source, FSCTL_DUPLICATE_EXTENTS_TO_FILE,
                nullptr, 0, nullptr, 0, &done) == STATUS_INVALID_DEVICE_REQUEST && done == 0,
                "standard FSCTL remains unsupported for application copy fallback")) return false;
        if (!Require(f.Export(ticket) == STATUS_SUCCESS, "source read handle exports unpredictable ticket")) return false;
        Reply repeated;
        if (!Require(f.Export(repeated) == STATUS_SUCCESS && repeated.ticket == ticket.ticket &&
                std::any_of(ticket.ticket.begin(), ticket.ticket.end(), [](auto byte) { return byte != 0; }) && c.clone_tickets.size() == 1,
                "export is bounded to one nonzero random ticket per open")) return false;
        if (!Require(f.Import(ticket, L"source") == STATUS_OBJECT_NAME_COLLISION,
                "existing source or target name cannot be replaced by import")) return false;
        apfsaccess::fshost::clone_control::ExportRequest bad_version; bad_version.version++;
        if (!Require(ContainerServeInterface().Control(&f.fs, f.source, apfsaccess::fshost::clone_control::Export,
                &bad_version, sizeof(bad_version), &repeated, sizeof(repeated), &done) == STATUS_INVALID_PARAMETER && done == 0,
                "unknown protocol version is refused")) return false;
        for (auto name : {L"..", L".", L"a:b", L"a/b", L"a\\b", L"", L"bad.", L"CON"})
            if (!Require(!NT_SUCCESS(f.Import(ticket, name)), "invalid leaf is refused")) return false;
        Reply forged = ticket; forged.ticket[0] ^= 1;
        if (!Require(f.Import(forged) == STATUS_INVALID_HANDLE && !c.metadata_store->LookupWorkingInodeByPath(L"\\copy"),
                "forged ticket cannot create a target")) return false;
        F other;
        if (!Require(other.Initialize() && other.Open() && other.Import(ticket) == STATUS_INVALID_HANDLE,
                "ticket cannot cross mount contexts")) return false;
        CB_Close(&f.fs, f.source); f.source = nullptr;
        if (!Require(f.Import(ticket) == STATUS_INVALID_HANDLE, "Close invalidates ticket")) return false;
        c.mutation_admission_state.fetch_or(kMutationAdmissionDrainFlag);
        if (!Require(f.Import(ticket) == STATUS_VOLUME_DISMOUNTED && c.active_callback_count == 0 &&
                MutationAdmissionCount(c.mutation_admission_state) == 0, "unmount gate owns and drains Control callbacks")) return false;
    }
    for (unsigned missing = 0; missing < 2; ++missing)
    {
        F f; Reply ticket;
        if (!Require(f.Initialize() && f.Open(missing ? FILE_READ_DATA : FILE_READ_ATTRIBUTES,
                missing ? FILE_LIST_DIRECTORY : FILE_ADD_FILE), "restricted handles open")) return false;
        if (!missing && !Require(f.Export(ticket) == STATUS_ACCESS_DENIED, "metadata-only source cannot export")) return false;
        if (missing && !Require(f.Export(ticket) == STATUS_SUCCESS && f.Import(ticket) == STATUS_ACCESS_DENIED,
                "destination requires FILE_ADD_FILE")) return false;
    }
    std::cerr << "[clone500] publication, metadata, shared extents and COW\n";
    {
        F f; Reply ticket;
        if (!Require(f.Initialize() && f.Open(), "earlier mutation fixture opens")) return false;
        auto& c = *f.fixture.context;
        c.args.write_max_dirty_transactions = 64;
        PVOID earlier = nullptr;
        if (!Require(CB_Create(&f.fs, const_cast<PWSTR>(L"\\earlier"), FILE_NON_DIRECTORY_FILE,
                GENERIC_READ | GENERIC_WRITE, FILE_ATTRIBUTE_NORMAL, nullptr, 0, &earlier, &f.info) == STATUS_SUCCESS,
                "normal Create callback precedes clone export")) return false;
        ScopeExit close_earlier{[&] { CB_Close(&f.fs, earlier); }};
        if (!Require(f.Export(ticket) == STATUS_SUCCESS &&
                c.metadata_store->LookupCommittedInodeByPath(L"\\earlier") && c.metadata_store->PendingMutationCount() == 0 &&
                c.tx_manager->Watermarks().cleanup_sequence == c.tx_manager->Watermarks().accepted_sequence &&
                f.Import(ticket) == STATUS_SUCCESS, "earlier native mutations drain and clean before isolated clone acceptance")) return false;
    }
    {
        F f; Reply ticket;
        if (!Require(f.Initialize() && f.Open() && f.Export(ticket) == STATUS_SUCCESS, "clone publication fixture exports")) return false;
        auto& c = *f.fixture.context;
        const auto before = c.metadata_store->LookupCommittedInodeByPath(L"\\source");
        const auto status = f.Import(ticket);
        if (!NT_SUCCESS(status)) std::wcerr << L"clone status " << std::hex << status << L" reason " << c.runtime_recovery_reason << L'\n';
        if (!Require(status == STATUS_SUCCESS, "actual Control dispatcher durably publishes clone")) return false;
        const auto clone = c.metadata_store->LookupCommittedInodeByPath(L"\\copy");
        std::vector<std::byte> bytes;
        if (!Require(clone && before && clone->object_id != before->object_id &&
                clone->owner == before->owner && clone->group == before->group && clone->mode == before->mode &&
                clone->create_time_utc == before->create_time_utc && clone->modification_time_utc == before->modification_time_utc &&
                clone->change_time_utc == before->change_time_utc && clone->access_time_utc == before->access_time_utc &&
                c.metadata_store->ReadCommittedFileRange(L"\\copy", 0, f.original.size(), bytes) && bytes == f.original &&
                NativeCloneHash500(f.original).has_value() && NativeCloneHash500(bytes) == NativeCloneHash500(f.original) &&
                c.tx_manager->Watermarks().cleanup_sequence == c.tx_manager->Watermarks().accepted_sequence &&
                c.tx_manager->RetainedAcceptedSequenceProofCount() == 0 &&
                f.Import(ticket, L"second") == STATUS_INVALID_HANDLE, "exact payload, Mac ownership and consumed ticket survive publication")) return false;
        for (const auto name : {"user.keep", "com.apple.ResourceFork", "com.apple.system.Security"})
        {
            auto a = c.metadata_store->LookupCommittedExtendedAttribute(before->object_id, name);
            auto b = c.metadata_store->LookupCommittedExtendedAttribute(clone->object_id, name);
            if (!Require(a && b && a->flags == b->flags && a->data == b->data, "complete supported Mac xattr bytes preserved")) return false;
        }
        apfsaccess::rw::NativeApfsVolumeProjection projection; std::wstring error;
        if (!Require(apfsaccess::rw::NativeApfsReader::TryLoadVolumeProjection(c.metadata_store->Device(), 101, projection, error), "clone projection loads")) return false;
        const auto source_extent = projection.read_extents_by_inode.at(before->object_id).front();
        const auto clone_extent = projection.read_extents_by_inode.at(clone->object_id).front();
        if (!Require(source_extent.physical_address == clone_extent.physical_address, "clone shares physical extent instead of copying payload")) return false;
        PVOID writer = nullptr;
        if (!Require(CB_Open(&f.fs, const_cast<PWSTR>(L"\\copy"), FILE_OPEN << 24,
                GENERIC_READ | GENERIC_WRITE, &writer, &f.info) == STATUS_SUCCESS, "clone opens for COW")) return false;
        ScopeExit close_writer{[&] { CB_Close(&f.fs, writer); }};
        std::byte value{0x7a}; ULONG written = 0;
        if (!Require(CB_Write(&f.fs, writer, &value, 4096 + 5, 1, FALSE, FALSE, &written, &f.info) == STATUS_SUCCESS &&
                written == 1 && CB_Flush(&f.fs, writer, &f.info) == STATUS_SUCCESS, "one-block COW uses real write and flush callbacks")) return false;
        auto expected = f.original; expected[4101] = value;
        if (!Require(c.metadata_store->ReadCommittedFileRange(L"\\copy", 0, expected.size(), bytes) && bytes == expected &&
                c.metadata_store->ReadCommittedFileRange(L"\\source", 0, f.original.size(), bytes) && bytes == f.original,
                "COW target changes exactly one byte and source remains exact")) return false;
        projection = {};
        if (!Require(apfsaccess::rw::NativeApfsReader::TryLoadVolumeProjection(c.metadata_store->Device(), 101, projection, error), "COW projection loads")) return false;
        const auto& extents = projection.read_extents_by_inode.at(clone->object_id);
        const auto physical_at = [&](std::uint64_t offset) {
            for (const auto& e : extents) if (offset >= e.logical_offset && offset - e.logical_offset < e.bytes)
                return e.physical_address + offset - e.logical_offset;
            return std::uint64_t{0};
        };
        if (!Require(physical_at(0) == source_extent.physical_address &&
                physical_at(4096) != source_extent.physical_address + 4096 &&
                physical_at(8192) == source_extent.physical_address + 8192, "only edited block loses sharing")) return false;
    }
    std::cerr << "[clone500] quota and ACL fallback\n";
    {
        F f; Reply ticket;
        if (!Require(f.Initialize() && f.Open() && f.Export(ticket) == STATUS_SUCCESS, "generation fixture exports")) return false;
        PVOID writer = nullptr;
        if (!Require(CB_Open(&f.fs, const_cast<PWSTR>(L"\\source"), FILE_OPEN << 24,
                GENERIC_READ | GENERIC_WRITE, &writer, &f.info) == STATUS_SUCCESS, "source writer opens")) return false;
        ScopeExit close_writer{[&] { CB_Close(&f.fs, writer); }};
        std::byte value{0x7a}; ULONG written = 0;
        if (!Require(CB_Write(&f.fs, writer, &value, 5, 1, FALSE, FALSE, &written, &f.info) == STATUS_SUCCESS &&
                CB_Flush(&f.fs, writer, &f.info) == STATUS_SUCCESS && f.Import(ticket) == STATUS_INVALID_HANDLE &&
                IsMutationWriteEnabled(f.fixture.context.get()), "changed source generation invalidates old ticket without stopping writes")) return false;
    }
    {
        F f; Reply ticket;
        std::cerr << "[clone500] initialize quota\n";
        if (!Require(f.Initialize(true) && f.Open() && f.Export(ticket) == STATUS_SUCCESS, "quota fixture opens")) return false;
        std::cerr << "[clone500] quota import\n";
        auto& c = *f.fixture.context;
        const auto marks = c.tx_manager->Watermarks();
        if (!Require(f.Import(ticket) == STATUS_DISK_FULL && !c.metadata_store->IsRecoveryRequired() &&
                IsMutationWriteEnabled(&c) && c.metadata_store->PendingMutationCount() == 0 &&
                !c.metadata_store->LookupWorkingInodeByPath(L"\\copy") &&
                c.tx_manager->Watermarks().accepted_sequence == marks.accepted_sequence &&
                !static_cast<OpenContext*>(f.source)->clone_ticket->consumed,
                "quota preview refuses before acceptance and retains writable state and ticket")) return false;
    }
    {
        F f; Reply ticket;
        std::cerr << "[clone500] initialize Windows ACL\n";
        if (!Require(f.Initialize(false, true) && f.Open() && f.Export(ticket) == STATUS_NOT_SUPPORTED,
                "explicit ancestor Windows descriptor takes ordinary copy fallback")) return false;
    }
    std::cerr << "[clone500] accepted restart and publication-before-cleanup restart\n";
    for (unsigned crash = 0; crash < 2; ++crash)
    {
        F f; Reply ticket;
        if (!Require(f.Initialize(false, false, crash ? 0x123456789abcdef0ULL : 0) && f.Open() &&
                f.Export(ticket) == STATUS_SUCCESS, "restart fixture exports")) return false;
        auto& c = *f.fixture.context;
        c.args.write_crash_replay_mode = L"ReplayIfSafe";
        c.args.write_recovery_policy = L"BestEffort";
        const auto preimage = c.metadata_store->CheckpointXid();
        if (!crash) c.metadata_store->SetCommitStageHook([](std::string_view stage) { return stage != "before-apple-checkpoint-switch"; });
        else g_clone_namespace_allocation_scope = [](bool begin) { g_clone_allocation_fail_after = begin ? 10 : -1; };
        if (!Require(!NT_SUCCESS(f.Import(ticket)) && !IsMutationWriteEnabled(&c) && c.write_degraded,
                "accepted failure blocks all writes even with BestEffort policy")) return false;
        g_clone_namespace_allocation_scope = {};
        const auto accepted = c.tx_manager->Watermarks().accepted_sequence;
        std::vector<std::uint64_t> pins;
        if (!Require(accepted != 0 && c.tx_manager->Watermarks().cleanup_sequence < accepted &&
                c.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(pins) && pins == std::vector<std::uint64_t>{*preimage} &&
                c.metadata_store->CheckpointXid() == *preimage + crash,
                "failure keeps accepted WAL and original checkpoint pin with truthful publication state")) return false;
        CB_Close(&f.fs, f.source); f.source = nullptr;
        CB_Close(&f.fs, f.directory); f.directory = nullptr;
        auto restarted = std::make_unique<MountContext>();
        restarted->args = c.args; restarted->session_root = c.session_root; restarted->cache_root = c.cache_root;
        restarted->recovery_marker_file = c.recovery_marker_file;
        ResetRecoveryMarkerCache(&c);
        f.fixture.context.reset(); f.fixture.context = std::move(restarted);
        auto& r = *f.fixture.context;
        r.native_write_enabled = true;
        SeedRoot(r); std::array<std::byte, 16> security{}; SeedSecurity(r, security);
        const auto startup = LoadRecoveryMarkerAtStartup(r);
        if (!Require(startup.load_status == RecoveryMarkerLoadStatus::Loaded && startup.state.dirty,
                "new mount context loads persisted dirty marker")) return false;
        r.tx_manager = std::make_unique<apfsaccess::rw::TransactionManager>(L"Conservative");
        r.tx_manager->SetVolumeIdentity(L"directory-symlink-volume");
        r.tx_manager->SetJournalPath((r.session_root / "accepted.wal").wstring());
        r.owned_metadata_store = std::make_unique<Store>(f.fixture.volume); r.metadata_store = r.owned_metadata_store.get();
        if (!Require(r.metadata_store->PrepareNativeWritePath() && r.tx_manager->RecoveryStateValid() &&
                ArmRecoveryMarkerForPendingWriteAheadLog(r, true) && ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(r),
                "actual startup replay publishes or verifies clone and cleans its journal")) return false;
        if (!Require(r.tx_manager->Watermarks().cleanup_sequence == accepted &&
                r.tx_manager->Watermarks().apfs_durable_sequence == accepted && !r.pending_native_writes &&
                !r.recovery_active && r.metadata_store->CheckpointXid() == *preimage + 1,
                "restart converges watermarks without duplicate publication")) return false;
        f.fs = BuildFileSystem(&r);
        if (!Require(CB_Open(&f.fs, const_cast<PWSTR>(L"\\copy"), FILE_OPEN << 24,
                FILE_READ_DATA, &f.source, &f.info) == STATUS_SUCCESS, "restarted clone is visible through normal Open")) return false;
        std::vector<std::byte> actual(f.original.size()); ULONG done = 0;
        if (!Require(CB_Read(&f.fs, f.source, actual.data(), 0, static_cast<ULONG>(actual.size()), &done) == STATUS_SUCCESS &&
                done == actual.size() && actual == f.original, "restarted clone reads exact source bytes through callback")) return false;
    }
    {
        F f; Reply ticket;
        if (!Require(f.Initialize() && f.Open() && f.Export(ticket) == STATUS_SUCCESS, "ambiguous acceptance fixture exports")) return false;
        auto& c = *f.fixture.context;
        c.args.write_recovery_policy = L"BestEffort";
        c.tx_manager->SetJournalFaultInjectionHook([](std::string_view stage) { return stage == "durable-flush"; });
        if (!Require(!NT_SUCCESS(f.Import(ticket)) && !IsMutationWriteEnabled(&c) &&
                !c.metadata_store->LookupWorkingInodeByPath(L"\\copy") && c.pending_native_writes && c.recovery_active,
                "ambiguous WAL acceptance exposes no target and stops writes")) return false;
        c.tx_manager->SetJournalFaultInjectionHook({});
    }
    std::cerr << "[clone500] source Close and unmount wait for admitted Control\n";
    for (const bool manifest : {false, true})
    for (const bool cleanup_only : {false, true})
    {
        F f; Reply ticket;
        if (!Require(f.Initialize(false, false, 0, false, false, manifest) && f.Open() &&
                f.Export(ticket) == STATUS_SUCCESS, "concurrent clone fixture exports")) return false;
        auto& c = *f.fixture.context;
        std::mutex mutex; std::condition_variable cv; bool entered = false, release = false;
        c.tx_manager->SetJournalFaultInjectionHook([&](std::string_view stage) {
            if (stage != "durable-flush") return false;
            std::unique_lock lock(mutex);
            if (!entered) { entered = true; cv.notify_all(); cv.wait(lock, [&] { return release; }); }
            return false;
        });
        auto importing = std::async(std::launch::async, [&] { return f.Import(ticket); });
        bool paused = false;
        { std::unique_lock lock(mutex); paused = cv.wait_for(lock, std::chrono::seconds(10), [&] { return entered; }); }
        if (!paused)
        {
            { std::lock_guard lock(mutex); release = true; } cv.notify_all();
            importing.wait(); return Require(false, "Control reaches durable acceptance hook");
        }
        auto closing = std::async(std::launch::async, [&] {
            if (cleanup_only) CB_Cleanup(&f.fs, f.source, const_cast<PWSTR>(L"\\source"), 0);
            else CB_Close(&f.fs, f.source);
        });
        auto draining = std::async(std::launch::async, [&] { return BeginMutationShutdownDrain(&c); });
        const bool close_waited = closing.wait_for(std::chrono::milliseconds(50)) == std::future_status::timeout;
        const bool drain_waited = draining.wait_for(std::chrono::milliseconds(50)) == std::future_status::timeout;
        const bool owned = c.active_callback_count >= 2 && MutationAdmissionCount(c.mutation_admission_state) >= 1;
        { std::lock_guard lock(mutex); release = true; } cv.notify_all();
        const auto status = importing.get(); closing.get(); if (!cleanup_only) f.source = nullptr;
        const bool drained = draining.get();
        c.tx_manager->SetJournalFaultInjectionHook({});
        if (!Require(close_waited && drain_waited && owned && status == STATUS_SUCCESS && drained &&
                c.active_callback_count == 0 && MutationAdmissionCount(c.mutation_admission_state) == 0 &&
                f.Import(ticket) == STATUS_VOLUME_DISMOUNTED,
                "source authority stays live until import completes; unmount drains owned callback and refuses newcomers")) return false;
    }
    return true;
}
