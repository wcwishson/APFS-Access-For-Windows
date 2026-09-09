#pragma once

bool RestartNativeClone513(NativeCloneHost500Fixture& f, std::uint64_t sequence,
    std::uint64_t checkpoint, const std::wstring& target = L"\\copy")
{
    using Store = apfsaccess::rw::MetadataStore;
    auto& c = *f.fixture.context;
    const bool manifest = IsManifestSession(&c);
    if (f.source) { CB_Close(&f.fs, f.source); f.source = nullptr; }
    if (f.directory) { CB_Close(&f.fs, f.directory); f.directory = nullptr; }
    auto restarted = std::make_unique<MountContext>();
    restarted->args = c.args; restarted->session_root = c.session_root; restarted->cache_root = c.cache_root;
    restarted->recovery_marker_file = c.recovery_marker_file;
    ResetRecoveryMarkerCache(&c);
    f.fixture.context.reset(); f.fixture.context = std::move(restarted);
    f.fixture.coordinator.reset();
    auto& r = *f.fixture.context;
    r.native_write_enabled = true;
    SeedRoot(r); std::array<std::byte, 16> security{}; SeedSecurity(r, security);
    const auto marker = LoadRecoveryMarkerAtStartup(r);
    r.tx_manager = std::make_unique<apfsaccess::rw::TransactionManager>(L"Conservative");
    r.tx_manager->SetVolumeIdentity(L"directory-symlink-volume");
    r.tx_manager->SetJournalPath((r.session_root / "accepted.wal").wstring());
    if (manifest)
    {
        std::string error; std::wstring mount_error;
        f.fixture.coordinator = apfsaccess::catalog::ContainerMountCoordinator::Open(f.fixture.image.path.string(), 0,
            error, apfsaccess::catalog::CatalogLoadPolicy::StrictApple, true, true);
        std::vector<std::uint64_t> pins;
        if (!Require(f.fixture.coordinator && MountManifestSession(*f.fixture.coordinator, r.args, r, mount_error) &&
                r.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(pins) &&
                f.fixture.coordinator->InitializeRequiredCheckpointCensus({{101, pins, true}, {102, {}, false}}, error),
                "513 restarted shared owner binds exact accepted census")) return false;
    }
    else
    {
        r.owned_metadata_store = std::make_unique<Store>(f.fixture.volume); r.metadata_store = r.owned_metadata_store.get();
        if (!r.metadata_store->PrepareNativeWritePath()) return false;
    }
    if (!Require(r.tx_manager->RecoveryStateValid() &&
            ArmRecoveryMarkerForPendingWriteAheadLog(r, marker.state.dirty) &&
            ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(r), "513 fresh startup replays exact clone WAL")) return false;
    if (!Require(r.tx_manager->Watermarks().cleanup_sequence == sequence &&
            r.tx_manager->Watermarks().apfs_durable_sequence == sequence &&
            r.metadata_store->CheckpointXid() == checkpoint && !r.recovery_active,
            "513 restart converges without a second publication")) return false;
    f.fs = BuildFileSystem(&r);
    if (!Require(CB_Open(&f.fs, const_cast<PWSTR>(target.c_str()), FILE_OPEN << 24,
            FILE_READ_DATA, &f.source, &f.info) == STATUS_SUCCESS, "513 recovered target opens")) return false;
    std::vector<std::byte> actual(f.original.size()); ULONG done = 0;
    if (!Require(CB_Read(&f.fs, f.source, actual.data(), 0, static_cast<ULONG>(actual.size()), &done) == STATUS_SUCCESS &&
            done == actual.size() && actual == f.original, "513 recovered target bytes match")) return false;
    if (manifest)
    {
        Store::VolumeContext beta = f.fixture.volume; beta.volume_object_id = 102;
        Store sibling(beta);
        if (!Require(sibling.PrepareNativeWritePath() &&
                sibling.ReadCommittedFileRange(L"\\source", 0, 16384, actual) &&
                actual == std::vector<std::byte>(16384, std::byte{0x39}) &&
                !sibling.LookupCommittedInodeByPath(target), "513 accepted restart preserves sibling bytes and isolation")) return false;
    }
    return true;
}

bool TestNativeCloneHost513()
{
    using F = NativeCloneHost500Fixture;
    using Reply = apfsaccess::fshost::clone_control::ExportReply;
    std::cerr << "[clone513] Cleanup authority and unrelated read-only Close\n";
    {
        F f; Reply ticket;
        if (!Require(f.Initialize() && f.Open() && f.Export(ticket) == STATUS_SUCCESS, "513 Cleanup fixture exports")) return false;
        const auto node = static_cast<OpenContext*>(f.source)->node;
        CB_Cleanup(&f.fs, f.source, const_cast<PWSTR>(L"\\source"), 0);
        if (!Require(f.source && node->live_context_count != 0 && f.Import(ticket) == STATUS_INVALID_HANDLE &&
                f.Export(ticket) == STATUS_INVALID_HANDLE &&
                f.fixture.context->tx_manager->Watermarks().accepted_sequence == 0,
                "Cleanup alone revokes exported authority while Close is delayed")) return false;
        PVOID unrelated = nullptr;
        if (!Require(CB_Open(&f.fs, const_cast<PWSTR>(L"\\source"), FILE_OPEN << 24,
                FILE_READ_ATTRIBUTES, &unrelated, &f.info) == STATUS_SUCCESS, "513 unrelated metadata open")) return false;
        std::unique_lock mutation(f.fixture.context->mutation_callback_mutex);
        auto close = std::async(std::launch::async, [&] { CB_Close(&f.fs, unrelated); });
        const bool fast = close.wait_for(std::chrono::seconds(2)) == std::future_status::ready;
        mutation.unlock(); close.get();
        if (!Require(fast, "unrelated read-only Close avoids mutation-lock starvation")) return false;
    }
    std::cerr << "[clone513] unflagged padding zero / opaque and case-alias destination\n";
    for (unsigned variant = 0; variant != 3; ++variant)
    {
        const bool flagged = variant == 2;
        const std::uint64_t padding = variant == 0 ? 0 : flagged ? 16384 : 0x123456789abcdef0ULL;
        F f; Reply ticket;
        if (!Require(f.Initialize(false, false, padding, false, flagged) && f.Open() && f.Export(ticket) == STATUS_SUCCESS,
                "513 padding fixture exports")) return false;
        if (flagged)
        {
            // The frozen engine admits internal_flags only within 0x400;
            // HAS_UNCOMPRESSED_SIZE is 0x40000. Do not rewrite that meaningful
            // flag or its value in the host to bypass the engine's admission.
            const auto before_image = ReadFileBytes(f.fixture.image.path);
            if (!Require(f.Import(ticket) == STATUS_NOT_SUPPORTED &&
                    f.fixture.context->tx_manager->Watermarks().accepted_sequence == 0 &&
                    IsMutationWriteEnabled(f.fixture.context.get()) && ReadFileBytes(f.fixture.image.path) == before_image,
                    "513 meaningful uncompressed-size flag remains an explicit untouched engine refusal")) return false;
            continue;
        }
        if (!Require(f.Import(ticket) == STATUS_SUCCESS, "unflagged source padding admits and publishes")) return false;
        auto& c = *f.fixture.context;
        const auto image = ReadFileBytes(f.fixture.image.path);
        apfsaccess::catalog::VectorRandomAccessSource raw_source(image);
        const auto* checkpoint = c.metadata_store->AuthoritativeAppleCheckpointView();
        const auto& volume = checkpoint->volumes.front();
        const auto& tree = volume.root_tree;
        apfsaccess::catalog::BtreeReadPolicy policy;
        policy.enforce_object_identity = true; policy.root_object_id = tree.object_id;
        policy.storage_type = tree.type; policy.subtype = tree.subtype;
        const bool physical = (tree.type & apfsaccess::catalog::kObjectStorageTypeMask) == apfsaccess::catalog::kObjectPhysical;
        std::vector<apfsaccess::catalog::BtreeRecord> raw_records; std::string failure;
        if (!Require(apfsaccess::catalog::ReadBtreeLeafRecords(raw_source, checkpoint->container.superblock.block_size,
                tree.physical_block, physical, physical ? 0 : volume.superblock.omap_oid,
                checkpoint->container.superblock.xid, policy, raw_records, failure), "513 raw tree reads")) return false;
        for (const auto path : {L"\\source", L"\\copy"})
        {
            const auto inode = c.metadata_store->LookupCommittedInodeByPath(path);
            if (!Require(inode.has_value(), "513 published inode exists")) return false;
            unsigned owners = 0;
            for (const auto& record : raw_records)
            {
                const auto key = apfsaccess::catalog::ReadU64LE(record.key, 0).value_or(0);
                if ((key >> 60) != 3 || (key & 0x0fffffffffffffffULL) != inode->object_id) continue;
                apfsaccess::rw::AppleInodeRecord raw; std::string error;
                if (!Require(apfsaccess::rw::ApfsExtendedRecordCodec::DecodeInode(record, raw, error) &&
                        ((raw.internal_flags & apfsaccess::rw::kAppleInodeHasUncompressedSize) != 0) == flagged && raw.uncompressed_size == padding,
                        "513 both raw inode padding fields preserved exactly")) return false;
                ++owners;
            }
            if (!Require(owners == 1, "513 inspected raw owner")) return false;
        }
    }
    {
        F f; Reply ticket;
        if (!Require(f.Initialize() && f.Open(), "513 case alias fixture")) return false;
        PVOID folder = nullptr;
        if (!Require(CB_Create(&f.fs, const_cast<PWSTR>(L"\\Folder"), FILE_DIRECTORY_FILE,
                GENERIC_READ | GENERIC_WRITE, FILE_ATTRIBUTE_DIRECTORY, nullptr, 0, &folder, &f.info) == STATUS_SUCCESS &&
                CB_Flush(&f.fs, folder, &f.info) == STATUS_SUCCESS, "513 original-spelling directory publishes")) return false;
        CB_Close(&f.fs, folder);
        CB_Close(&f.fs, f.directory); f.directory = nullptr;
        if (!Require(CB_Open(&f.fs, const_cast<PWSTR>(L"\\folder"), FILE_DIRECTORY_FILE,
                FILE_ADD_FILE, &f.directory, &f.info) == STATUS_SUCCESS && f.Export(ticket) == STATUS_SUCCESS &&
                f.Import(ticket, L"Copy") == STATUS_SUCCESS, "case-alias destination publishes exact clone")) return false;
    }
    std::cerr << "[clone513] exhaustive namespace allocation failure and restart\n";
    unsigned failures = 0;
    for (long allocation = 0; allocation != 1024; ++allocation)
    {
        F f; Reply ticket;
        if (!Require(f.Initialize() && f.Open() && f.Export(ticket) == STATUS_SUCCESS, "513 allocation fixture exports")) return false;
        auto& c = *f.fixture.context;
        c.args.write_crash_replay_mode = L"ReplayIfSafe"; c.args.write_recovery_policy = L"BestEffort";
        const auto old_index = c.nodes;
        const auto parent = static_cast<OpenContext*>(f.directory)->node;
        const Node old_parent = *parent;
        const auto checkpoint = *c.metadata_store->CheckpointXid();
        g_clone_allocation_count = 0;
        g_clone_namespace_allocation_scope = [allocation](bool begin) {
            g_clone_allocation_fail_after = begin ? allocation : -1;
            // Keep memory unavailable through the accepted-failure latch and
            // callback return, not just the transaction's first failing new.
            if (!begin && allocation == 40) g_clone_allocation_always_fail = true;
        };
        const auto status = f.Import(ticket);
        g_clone_allocation_always_fail = false;
        g_clone_namespace_allocation_scope = {};
        if (NT_SUCCESS(status))
        {
            std::cerr << "[clone513] allocation failure points=" << failures << " successful allocation count=" << g_clone_allocation_count << '\n';
            if (!Require(failures > 25 && g_clone_allocation_count == allocation, "513 swept actual node, child and index allocations")) return false;
            break;
        }
        ++failures;
        if (!Require(!IsMutationWriteEnabled(&c) && c.nodes == old_index && parent->children == old_parent.children &&
                parent->child_index_by_name_key == old_parent.child_index_by_name_key &&
                parent->native_security == old_parent.native_security && parent->inode_times == old_parent.inode_times &&
                !TryGetNodeLockedNormalized(&c, L"\\copy") && c.metadata_store->LookupCommittedInodeByPath(L"\\copy"),
                "513 allocation failure leaves entire visible namespace and identities unchanged")) return false;
        const auto accepted = c.tx_manager->Watermarks().accepted_sequence;
        std::vector<std::uint64_t> pins;
        if (!Require(accepted > c.tx_manager->Watermarks().cleanup_sequence &&
                c.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(pins) && pins == std::vector<std::uint64_t>{checkpoint},
                "513 each allocation failure retains accepted evidence and exact checkpoint pin")) return false;
        if (!RestartNativeClone513(f, accepted, checkpoint + 1)) return false;
        if (allocation == 1023) return Require(false, "513 allocation sweep must reach success");
    }
    return true;
}

bool TestNativeCloneManifest513()
{
    using F = NativeCloneHost500Fixture;
    using Reply = apfsaccess::fshost::clone_control::ExportReply;
    using Store = apfsaccess::rw::MetadataStore;
    std::cerr << "[clone513] manifest success, quota, accepted replay and namespace failure\n";
    for (unsigned scenario = 0; scenario != 5; ++scenario)
    {
        F f; Reply ticket;
        if (!Require(f.Initialize(scenario == 1, false, scenario == 4 ? 16384 : 0, false, scenario == 4, true) && f.Open() &&
                f.Export(ticket) == STATUS_SUCCESS, "513 manifest fixture exports")) return false;
        auto& c = *f.fixture.context;
        c.args.write_crash_replay_mode = L"ReplayIfSafe"; c.args.write_recovery_policy = L"BestEffort";
        const auto checkpoint = *c.metadata_store->CheckpointXid();
        if (scenario == 2)
            c.metadata_store->SetCommitStageHook([](std::string_view stage) { return stage != "before-apple-checkpoint-switch"; });
        if (scenario == 3)
            g_clone_namespace_allocation_scope = [](bool begin) { g_clone_allocation_fail_after = begin ? 40 : -1; };
        const auto status = f.Import(ticket);
        g_clone_namespace_allocation_scope = {};
        if (scenario == 1 || scenario == 4)
        {
            if (!Require(status == (scenario == 1 ? STATUS_DISK_FULL : STATUS_NOT_SUPPORTED) && IsMutationWriteEnabled(&c) &&
                    c.tx_manager->Watermarks().accepted_sequence == 0 && c.metadata_store->PendingMutationCount() == 0 &&
                    !static_cast<OpenContext*>(f.source)->clone_ticket->consumed &&
                    f.fixture.coordinator->CheckpointXid() == checkpoint,
                    "513 manifest quota or explicit unsupported refusal preserves writable state, ticket and shared checkpoint")) return false;
            continue;
        }
        if (scenario == 0)
        {
            if (!NT_SUCCESS(status)) std::wcerr << L"manifest clone status=" << std::hex << status << L" reason=" << c.runtime_recovery_reason << '\n';
            if (!Require(status == STATUS_SUCCESS && f.fixture.coordinator->CheckpointXid() == checkpoint + 1 &&
                    c.tx_manager->Watermarks().accepted_sequence == c.tx_manager->Watermarks().cleanup_sequence &&
                    c.tx_manager->RetainedAcceptedSequenceProofCount() == 0,
                    "513 manifest clone publishes through shared owner and durably cleans")) return false;
            for (const auto& entry : f.fixture.coordinator->CheckpointCensusSnapshot())
                if (!Require(entry.required_checkpoint_xids.empty() && !entry.unapplied_accepted_work,
                        "513 successful manifest cleanup releases exact census pins")) return false;
            continue;
        }
        if (!Require(!NT_SUCCESS(status) && !IsMutationWriteEnabled(&c) &&
                c.tx_manager->Watermarks().accepted_sequence > c.tx_manager->Watermarks().cleanup_sequence,
                "513 manifest accepted failure retains WAL and blocks writes")) return false;
        const auto accepted = c.tx_manager->Watermarks().accepted_sequence;
        const auto census = f.fixture.coordinator->CheckpointCensusSnapshot();
        const auto selected = std::find_if(census.begin(), census.end(), [](const auto& entry) { return entry.volume_object_id == 101; });
        if (!Require(selected != census.end() && selected->required_checkpoint_xids == std::vector<std::uint64_t>{checkpoint},
                "513 shared owner retains exact failed-clone checkpoint pin")) return false;
        if (!RestartNativeClone513(f, accepted, checkpoint + 1)) return false;
    }
    std::cerr << "[clone513] shared-owner sibling isolation\n";
    {
        F f; Reply ticket;
        if (!Require(f.Initialize(false, false, 0, false, false, true) && f.Open(), "513 sibling fixture opens")) return false;
        auto& c = *f.fixture.context;
        auto sibling = std::make_unique<MountContext>();
        auto& s = *sibling;
        s.args = c.args; s.args.volume = L"Beta"; s.args.volume_object_id = 102; s.args.mount = L"F:";
        s.native_write_enabled = true;
        SeedRoot(s); std::array<std::byte, 16> security{}; SeedSecurity(s, security);
        std::wstring error;
        if (!Require(PrepareUnitHydrationRoot(s, L"clone-sibling") &&
                MountManifestSession(*f.fixture.coordinator, s.args, s, error), "513 sibling borrows same owner")) return false;
        ScopeExit cleanup_sibling{[&] {
            const auto root = s.session_root; ResetRecoveryMarkerCache(&s);
            sibling.reset(); std::error_code ec; std::filesystem::remove_all(root, ec);
        }};
        s.recovery_marker_file = s.session_root / "recovery.marker";
        s.tx_manager = std::make_unique<apfsaccess::rw::TransactionManager>(L"Conservative");
        s.tx_manager->SetVolumeIdentity(L"clone-sibling"); s.tx_manager->SetJournalPath((s.session_root / "accepted.wal").wstring());
        s.payload_spool_volume_identity = "clone-sibling";
        s.payload_spool = std::make_unique<apfsaccess::rw::PayloadSpool>(apfsaccess::rw::PayloadSpool::Options{
            s.session_root / "spool", s.payload_spool_volume_identity, 1024 * 1024});
        s.metadata_store->SetFilePayloadRangeProvider([&s](const std::wstring& path, Store::PayloadIdentity identity,
                std::uint64_t offset, std::span<std::byte> bytes) {
            return ReadHydratedPayloadRangeForPath(&s, path, identity, offset, bytes);
        });
        if (!Require(MergeCommittedInodeStateIntoNodeIndex(&s), "513 sibling namespace loads")) return false;
        auto fs = BuildFileSystem(&s); PVOID directory = nullptr, marker = nullptr;
        FSP_FSCTL_FILE_INFO info{};
        if (!Require(CB_Open(&fs, const_cast<PWSTR>(L"\\"), FILE_DIRECTORY_FILE, FILE_ADD_FILE, &directory, &info) == STATUS_SUCCESS &&
                CB_Create(&fs, const_cast<PWSTR>(L"\\sibling-preserved"), FILE_NON_DIRECTORY_FILE,
                    GENERIC_READ | GENERIC_WRITE, FILE_ATTRIBUTE_NORMAL, nullptr, 0, &marker, &info) == STATUS_SUCCESS,
                    "513 sibling ordinary file creates")) return false;
        std::vector<std::byte> sibling_bytes(128, std::byte{0x6d}); ULONG written = 0;
        if (!Require(CB_Write(&fs, marker, sibling_bytes.data(), 0, static_cast<ULONG>(sibling_bytes.size()), FALSE, FALSE,
                &written, &info) == STATUS_SUCCESS && written == sibling_bytes.size() &&
                CB_Flush(&fs, marker, &info) == STATUS_SUCCESS, "513 sibling bytes durably publish")) return false;
        CB_Close(&fs, marker);
        ScopeExit close_directory{[&] { CB_Close(&fs, directory); }};
        const auto before = s.metadata_store->LookupCommittedInodeByPath(L"\\sibling-preserved");
        if (!Require(f.Export(ticket) == STATUS_SUCCESS, "513 source exports after sibling publication")) return false;
        apfsaccess::fshost::clone_control::ImportRequest request; request.ticket = ticket.ticket;
        request.leaf_chars = 4; request.leaf[0] = 'c'; request.leaf[1] = 'o'; request.leaf[2] = 'p'; request.leaf[3] = 'y';
        ULONG done = 99;
        if (!Require(ContainerServeInterface().Control(&fs, directory, apfsaccess::fshost::clone_control::Import,
                &request, sizeof(request), nullptr, 0, &done) == STATUS_INVALID_HANDLE && done == 0 &&
                s.tx_manager->Watermarks().accepted_sequence == s.tx_manager->Watermarks().cleanup_sequence,
                "513 clone ticket cannot cross volumes on the same coordinator")) return false;
        if (!Require(f.Import(ticket) == STATUS_SUCCESS, "513 volume-local clone succeeds after sibling mutation")) return false;
        Store::VolumeContext beta = f.fixture.volume; beta.volume_object_id = 102;
        Store reopened(beta);
        if (!Require(reopened.PrepareNativeWritePath(), "513 independent sibling image opens")) return false;
        const auto after = reopened.LookupCommittedInodeByPath(L"\\sibling-preserved");
        std::vector<std::byte> actual;
        if (!Require(before && after && before->object_id == after->object_id && before->xid == after->xid &&
                before->mode == after->mode && before->create_time_utc == after->create_time_utc &&
                !reopened.LookupCommittedInodeByPath(L"\\copy") &&
                reopened.ReadCommittedFileRange(L"\\sibling-preserved", 0, sibling_bytes.size(), actual) && actual == sibling_bytes,
                "513 sibling identity, metadata and bytes preserved with no cross-volume target")) return false;
        PVOID successor = nullptr;
        if (!Require(CB_Create(&fs, const_cast<PWSTR>(L"\\sibling-successor"), FILE_DIRECTORY_FILE,
                GENERIC_READ | GENERIC_WRITE, FILE_ATTRIBUTE_DIRECTORY, nullptr, 0, &successor, &info) == STATUS_SUCCESS &&
                CB_Flush(&fs, successor, &info) == STATUS_SUCCESS, "513 sibling remains independently writable after clone cleanup")) return false;
        CB_Close(&fs, successor);
        if (!Require(c.metadata_store->ReadCommittedFileRange(L"\\copy", 0, f.original.size(), actual) && actual == f.original,
                "513 sibling successor preserves cloned volume payload")) return false;
    }
    return true;
}
