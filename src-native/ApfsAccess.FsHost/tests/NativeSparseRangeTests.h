#pragma once

bool TestNativeReplayExtentGraphBinding()
{
    using namespace apfsaccess::rw;
    using namespace apfsaccess::testfixture;
    // Exercise inode selection, B-tree reconciliation, and rejected replay admission.
    for (unsigned target : {0u, 1u, 2u, 3u})
    {
        const bool inode_checkpoint = target != 1;
        const bool btree_checkpoint = target != 2;
        const bool invalid_replay = target == 3;
        ContainerFixtureFile fixture("mixed-replay-map", true, true);
        const auto path = fixture.path;
        auto builder = TwoProjectableVolumeStore(); builder.volumes.resize(1); builder.block_count = 1024;
        builder.authoritative_checkpoint = true; builder.dual_checkpoint = false; builder.xid = 20;
        builder.authoritative_internal_pool_blocks = 16; builder.authoritative_checkpoint_ring_blocks = 16;
        auto& volume = builder.volumes.front(); volume.incompat = 0; volume.additional_file_system_allocated_blocks = 1;
        volume.filesystem_records.clear(); volume.extentref_records.clear();
        apfsaccess::catalog::BtreeRecord encoded; std::string error;
        AppleInodeRecord root; root.object_id = root.private_id = root.parent_id = 2;
        root.mode = 0040755; root.children_or_links = 1;
        if (!Require(EncodeAppleInodeRecord(root, encoded, error), "mixed replay root encodes")) return false;
        volume.filesystem_records.push_back(encoded);
        AppleInodeRecord native; native.object_id = native.private_id = 17; native.parent_id = 2;
        native.mode = 0100644; native.children_or_links = 1;
        AppleExtendedField stream{8, 0, std::vector<std::byte>(40)};
        PutU64LE(stream.data, 0, 4096); PutU64LE(stream.data, 8, 4096); native.extended_fields.push_back(stream);
        if (!Require(EncodeAppleInodeRecord(native, encoded, error), "mixed replay native inode encodes")) return false;
        volume.filesystem_records.push_back(encoded);
        AppleDirectoryRecord directory; directory.parent_id = 2; directory.file_id = 17;
        directory.flags = 8; directory.name_utf8 = "original";
        if (!Require(EncodeAppleDirectoryRecord(directory, encoded, error), "mixed replay directory encodes")) return false;
        volume.filesystem_records.push_back(encoded);
        if (!Require(EncodeAppleDataStreamIdRecord({17, 1}, encoded, error), "mixed replay dstream encodes")) return false;
        volume.filesystem_records.push_back(encoded);
        if (!Require(EncodeAppleFileExtentRecord({17, 0, 4096, 100, 0, 4096}, encoded, error), "mixed replay baseline extent encodes")) return false;
        volume.filesystem_records.push_back(encoded);
        if (!Require(EncodeApplePhysicalExtentRecord({100, 1, kApplePhysicalExtentKindNew, 17, 1}, encoded, error), "mixed replay ownership encodes")) return false;
        volume.extentref_records.push_back(encoded);
        builder.authoritative_seeded_main_blocks.push_back({100, std::vector<std::byte>(4096, std::byte{0x31})});
        if (!Require(SortAppleBtreeRecords(volume.filesystem_records, AppleBtreeKeyOrder::FileSystemCaseSensitive, error), "mixed replay native records sort")) return false;
        auto image = BuildStoreImage(builder);
        if (!Require(WriteFileBytes(path, image), "mixed replay baseline image writes")) return false;
        MetadataStore::VolumeContext context; context.device_path = path.wstring(); context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false; context.crash_replay_mode = L"FailClosed";
        {
            MetadataStore baseline(context); std::vector<std::byte> bytes;
            if (!Require(baseline.PrepareNativeWritePath() && baseline.ReadCommittedFileRange(L"\\original", 0, 4096, bytes) &&
                    bytes == std::vector<std::byte>(4096, std::byte{0x31}), "mixed replay native X maps original payload A")) return false;
        }
        const auto hash = [](std::uint32_t value, std::span<const std::byte> data) {
            for (auto byte : data) { value ^= std::to_integer<unsigned char>(byte); value *= 16777619u; } return value;
        };
        const auto checkpoint = [&](const char* magic, std::uint32_t count, std::span<const std::byte> payload) {
            std::vector<std::byte> block(4096); std::memcpy(block.data(), magic, 12);
            PutU64LE(block, 12, 21); PutU32LE(block, 20, count); PutU32LE(block, 24, static_cast<std::uint32_t>(payload.size()));
            std::copy(payload.begin(), payload.end(), block.begin() + 32);
            PutU32LE(block, 28, hash(hash(2166136261u, std::span(block).first(28)), payload)); return block;
        };
        const auto install = [&](std::uint64_t block, const std::vector<std::byte>& bytes) {
            std::copy(bytes.begin(), bytes.end(), image.begin() + block * 4096);
        };
        constexpr std::uint64_t target_address = 200 * 4096;
        std::fill_n(image.begin() + target_address, 4096, std::byte{0xa7});
        std::vector<BtreeRecord> records{
            BtreeMutationCodec::EncodeInodeRecord(17, 2, L"original", false, 4096, target_address, 0, 21),
            BtreeMutationCodec::EncodeDirectoryRecord(2, L"original", 17, 21),
            BtreeMutationCodec::EncodeExtentRecord(17, 0, target_address, 4096, 21)};
        if (!inode_checkpoint) {
            records.push_back(BtreeMutationCodec::EncodeInodeRecord(18, 2, L"new-empty", false, 0, 0, 0, 21));
            records.push_back(BtreeMutationCodec::EncodeDirectoryRecord(2, L"new-empty", 18, 21));
        }
        std::vector<std::byte> btree;
        for (const auto& record : records) {
            const auto cursor = btree.size(); btree.resize(cursor + 16 + record.key.size() + record.value.size());
            PutU32LE(btree, cursor, static_cast<std::uint32_t>(record.kind)); PutU32LE(btree, cursor + 4, 0);
            PutU32LE(btree, cursor + 8, static_cast<std::uint32_t>(record.key.size())); PutU32LE(btree, cursor + 12, static_cast<std::uint32_t>(record.value.size()));
            std::copy(record.key.begin(), record.key.end(), btree.begin() + cursor + 16);
            std::copy(record.value.begin(), record.value.end(), btree.begin() + cursor + 16 + record.key.size());
        }
        if (btree_checkpoint)
            install(896 + 24, checkpoint("APFSRWBTR5\0\0", static_cast<std::uint32_t>(records.size()), btree));
        if (inode_checkpoint) {
            std::vector<std::byte> inodes;
            for (const auto object : {2ULL, 17ULL}) {
                const std::wstring name = object == 2 ? L"" : L"original", full = object == 2 ? L"\\" : L"\\original";
                const auto cursor = inodes.size(); inodes.resize(cursor + 60 + (name.size() + full.size()) * sizeof(wchar_t));
                PutU64LE(inodes, cursor, object); PutU64LE(inodes, cursor + 8, 2);
                PutU64LE(inodes, cursor + 16, object == 2 ? 0 : 4096); PutU64LE(inodes, cursor + 24, object == 2 ? 0 : target_address);
                PutU64LE(inodes, cursor + 32, 21); PutU32LE(inodes, cursor + 48, object == 2 ? 1 : 0);
                PutU32LE(inodes, cursor + 52, static_cast<std::uint32_t>(name.size())); PutU32LE(inodes, cursor + 56, static_cast<std::uint32_t>(full.size()));
                std::memcpy(inodes.data() + cursor + 60, name.data(), name.size() * sizeof(wchar_t));
                std::memcpy(inodes.data() + cursor + 60 + name.size() * sizeof(wchar_t), full.data(), full.size() * sizeof(wchar_t));
            }
            install(896 + 8, checkpoint("APFSRWINOD5\0", 2, inodes));
        }
        std::vector<std::byte> blob(4096); std::memcpy(blob.data(), "APFSRWCANON3\0", 13);
        PutU64LE(blob, 13, 20); PutU64LE(blob, 21, 21); PutU32LE(blob, 29, 1); PutU32LE(blob, 33, 1);
        PutU64LE(blob, 53, 17); PutU64LE(blob, 61, target_address); PutU64LE(blob, 69, 4096); PutU64LE(blob, 77, 21);
        PutU32LE(blob, 49, hash(2166136261u, std::span(blob).subspan(53, 32)));
        if (invalid_replay) blob[49] ^= std::byte{1};
        install(400, blob);
        std::vector<std::byte> replay(24); PutU64LE(replay, 0, 20); PutU64LE(replay, 8, 400 * 4096); PutU64LE(replay, 16, 4096);
        install(896 + 64, checkpoint("APFSRWRPL1\0\0", 1, replay));
        if (!Require(WriteFileBytes(path, image), "mixed replay target checkpoints install")) return false;
        MetadataStore pending(context);
        if (!Require(pending.PrepareNativeWritePath(), "mixed replay native baseline preparation succeeds")) return false;
        const bool replayed = pending.ReplayOrRecover();
        const auto selected = pending.LookupCommittedInodeByPath(L"\\original");
        const auto key = ApfsNameCodec::CanonicalWindowsPathKey(L"\\original", ApfsNamePolicy::FromIncompatibleFeatures(volume.incompat));
        if (!Require(key.ok(), "mixed replay read-plan key uses the declared native name policy")) return false;
        const auto plan = pending.SnapshotCommittedFileReadPlan(*key.value);
        const auto read_address = plan ? (plan->has_single_extent ? plan->single_extent.physical_address :
            plan->extents_snapshot && !plan->extents_snapshot->empty() ? plan->extents_snapshot->front().physical_address :
            plan->data_physical_address) : 0;
        std::vector<std::byte> bytes;
        const bool read = pending.ReadCommittedFileRange(L"\\original", 0, 4096, bytes);
        std::wcerr << L"Mixed replay fixture: target=" << target << L" replayed=" << replayed << L" candidate="
            << pending.LastReplayCheckpointCandidatePresent() << L" pending=" << pending.LastReplayCheckpointPendingWindow()
            << L" reason=" << pending.RecoveryReason() << L" inodeAddress=" << (selected ? selected->data_physical_address : 0)
            << L" planAddress=" << read_address << L" firstByte=" << (read && !bytes.empty() ? std::to_integer<unsigned>(bytes.front()) : 0) << L'\n';
        if (invalid_replay)
        {
            if (!Require(!pending.LastReplayCheckpointCandidatePresent() && !pending.LastReplayCheckpointPendingWindow() &&
                    selected && selected->data_physical_address == 100 * 4096 && read_address == 100 * 4096 &&
                    read && bytes == std::vector<std::byte>(4096, std::byte{0x31}) && ReadFileBytes(path) == image,
                    "invalid replay checksum preserves the complete native baseline and image")) return false;
            continue;
        }
        if (!Require(!replayed && pending.LastReplayCheckpointCandidatePresent() && pending.LastReplayCheckpointPendingWindow() &&
                pending.RecoveryReason() == L"PersistentStateAheadOfSuperblock" && selected && selected->object_id == 17 &&
                selected->logical_size == 4096 && selected->data_physical_address == target_address,
                "validated pending X to X+1 selects target graph under fail-closed recovery")) return false;
        if (!Require(plan && read_address == target_address,
                "selected target inode and actual read mapping both reference payload B")) return false;
        if (!Require(read && bytes == std::vector<std::byte>(4096, std::byte{0xa7}),
                "selected target read returns actual payload B bytes")) return false;
        if (!Require(ReadFileBytes(path) == image, "mixed checkpoint selection and refusal do not write the image")) return false;
    }
    return true;
}

bool TestNativeSparseReinitializationReplay()
{
    using Store = apfsaccess::rw::MetadataStore;
    HostNativeSparse340Fixture owned;
    if (!Require(owned.Initialize(), "native replay fixture initializes")) return false;
    const auto before = ReadFileBytes(owned.fixture.image.path);
    for (unsigned restart = 0; restart < 3; ++restart)
    {
        Store fresh(owned.fixture.volume);
        if (!Require(fresh.PrepareNativeWritePath(), "native restart preparation succeeds")) return false;
        const bool replayed = fresh.ReplayOrRecover();
        if (!replayed) std::wcerr << L"Sparse startup replay: " << fresh.RecoveryReason() << L'\n';
        if (!Require(replayed && fresh.ReplayOrRecover() && fresh.VerifyIntegrity(),
                "native startup replay retains complete sparse projection and is idempotent")) return false;
        const auto original = fresh.LookupCommittedInodeByPath(L"\\original");
        const auto alias = fresh.LookupCommittedInodeByPath(L"\\alias");
        std::vector<std::byte> bytes;
        if (!Require(original && alias && original->object_id == alias->object_id &&
                original->logical_size == owned.tail + 12288 && original->allocation_size == 24576 &&
                fresh.ReadCommittedFileRange(L"\\original", 0, 12288, bytes) &&
                bytes == std::vector<std::byte>(12288, std::byte{0x31}) &&
                fresh.ReadCommittedFileRange(L"\\alias", 12288, 8192, bytes) &&
                bytes == std::vector<std::byte>(8192) &&
                fresh.ReadCommittedFileRange(L"\\original", owned.tail, 12288, bytes) &&
                bytes == std::vector<std::byte>(12288, std::byte{0xa7}),
                "restart preserves native names, hardlink identity, mapped canaries, holes and allocation")) return false;
    }
    return Require(before == ReadFileBytes(owned.fixture.image.path),
        "startup reconstruction does not publish or modify the image");
}

bool TestNativeSparseRangeRoundTrip()
{
    namespace protocol = apfsaccess::fshost::sparse_control;
    using Store = apfsaccess::rw::MetadataStore;
    HostNativeSparse340Fixture owned;
    if (!Require(owned.Initialize(), "range fixture initializes")) return false;
    auto& c = *owned.fixture.context; auto fs = BuildFileSystem(&c);
    c.args.write_max_dirty_transactions = 64;
    PVOID writer = nullptr, alias = nullptr; FSP_FSCTL_FILE_INFO info{};
    ScopeExit close{[&] { if (writer) CB_Close(&fs, writer); if (alias) CB_Close(&fs, alias); }};
    if (!Require(CB_Open(&fs, const_cast<PWSTR>(L"\\original"), FILE_OPEN << 24,
            GENERIC_READ | GENERIC_WRITE, &writer, &info) == STATUS_SUCCESS &&
            CB_Open(&fs, const_cast<PWSTR>(L"\\alias"), FILE_OPEN << 24,
            GENERIC_READ, &alias, &info) == STATUS_SUCCESS, "range writer and hardlink open")) return false;
    protocol::RangeRequest request; request.length = owned.tail + 12288;
    protocol::Reply reply{}; ULONG transferred = 999;
    const auto control = [&](UINT32 code) {
        return CB_Control(&fs, writer, code, &request, sizeof(request), &reply, sizeof(reply), &transferred);
    };
    if (!Require(control(protocol::Query) == STATUS_SUCCESS && transferred == sizeof(reply) &&
            reply.range_count == 2 && reply.ranges[0].offset == 0 && reply.ranges[0].length == 12288 &&
            reply.ranges[1].offset == owned.tail && reply.ranges[1].length == 12288 &&
            reply.allocation_size == 24576 && reply.capabilities == 7,
            "private query exposes exact sparse allocation and supported operations")) return false;
    request.offset = 17; request.length = owned.tail + 9 - 17;
    if (!Require(control(protocol::Zero) == STATUS_SUCCESS && transferred == sizeof(reply) &&
            reply.file_size == owned.tail + 12288 && reply.allocation_size == 24576 &&
            reply.zeroed_bytes == 12288 - 17 + 9 && !c.write_degraded,
            "unaligned zero crossing a large hole preserves EOF and physical allocation")) return false;
    Store fresh(owned.fixture.volume); std::vector<std::byte> bytes;
    if (!Require(fresh.PrepareNativeWritePath() && fresh.VerifyIntegrity() &&
            fresh.ReadCommittedFileRange(L"\\original", 0, 12288, bytes) &&
            std::all_of(bytes.begin(), bytes.begin() + 17, [](auto b) { return b == std::byte{0x31}; }) &&
            std::all_of(bytes.begin() + 17, bytes.end(), [](auto b) { return b == std::byte{}; }) &&
            fresh.ReadCommittedFileRange(L"\\original", owned.tail, 12288, bytes) &&
            std::all_of(bytes.begin(), bytes.begin() + 9, [](auto b) { return b == std::byte{}; }) &&
            std::all_of(bytes.begin() + 9, bytes.end(), [](auto b) { return b == std::byte{0xa7}; }),
            "native reopen verifies range bytes and both outside canaries")) return false;
    std::array<std::byte, 48> alias_bytes{}; ULONG done = 0;
    if (!Require(CB_Read(&fs, alias, alias_bytes.data(), 0, alias_bytes.size(), &done) == STATUS_SUCCESS &&
            done == alias_bytes.size() && alias_bytes[16] == std::byte{0x31} && alias_bytes[17] == std::byte{},
            "open hardlink observes zeroed bytes through hydration")) return false;
    const auto image = ReadFileBytes(owned.fixture.image.path);
    request.offset = owned.tail / 2; request.length = 4096;
    if (!Require(control(protocol::Zero) == STATUS_SUCCESS && reply.zeroed_bytes == 0 &&
            image == ReadFileBytes(owned.fixture.image.path), "zeroing an existing hole publishes no allocation or checkpoint")) return false;
    // A pending ordinary write must become visible before planning the zero.
    std::byte value{0x6d};
    if (!Require(CB_Write(&fs, writer, &value, request.offset + 7, 1, FALSE, FALSE, &done, &info) == STATUS_SUCCESS &&
            control(protocol::Zero) == STATUS_SUCCESS && reply.zeroed_bytes == 4096 &&
            CB_Read(&fs, writer, &value, request.offset + 7, 1, &done) == STATUS_SUCCESS && value == std::byte{},
            "range planning includes earlier accepted hole writes")) return false;
    const auto growth_status = CB_SetFileSize(&fs, writer, 128ULL * 1024 * 1024, FALSE, &info);
    if (!NT_SUCCESS(growth_status))
        std::wcerr << L"Sparse EOF growth: " << FormatNtStatus(growth_status) << L" mutation="
            << c.metadata_store->LastMutationFailureReason() << L" commit="
            << c.metadata_store->LastCommitFailureReason() << L" detail="
            << c.metadata_store->LastCommitFailureDetail() << L'\n';
    if (!Require(growth_status == STATUS_SUCCESS &&
            CB_Flush(&fs, writer, &info) == STATUS_SUCCESS && info.FileSize == 128ULL * 1024 * 1024 && info.AllocationSize == 28672,
            "normal sparse growth exceeds image capacity without reserving holes")) return false;
    Store grown(owned.fixture.volume);
    if (!Require(grown.PrepareNativeWritePath() && grown.ReplayOrRecover() && grown.VerifyIntegrity(),
            "fresh native owner validates sparse growth stream records")) return false;
    const auto grown_inode = grown.LookupCommittedInodeByPath(L"\\original");
    if (!Require(grown_inode && grown_inode->object_id == 17 && grown_inode->private_id == 17 &&
            grown_inode->logical_size == 128ULL * 1024 * 1024 && grown_inode->allocation_size == 28672 &&
            grown.ReadCommittedFileRange(L"\\original", owned.tail + 9, 1, bytes) &&
            bytes == std::vector<std::byte>{std::byte{0xa7}} &&
            grown.ReadCommittedFileRange(L"\\original", grown_inode->logical_size - 4096, 4096, bytes) &&
            bytes == std::vector<std::byte>(4096),
            "growth retains dstream identity, allocation, outside canary and trailing hole after reopen")) return false;
    if (!Require(CB_SetFileSize(&fs, writer, 257, FALSE, &info) == STATUS_SUCCESS &&
            CB_Flush(&fs, writer, &info) == STATUS_SUCCESS && info.FileSize == 257 && info.AllocationSize == 4096,
            "sparse shrink reports retained block allocation")) return false;
    if (!Require(CB_SetFileSize(&fs, writer, owned.tail + 4096, FALSE, &info) == STATUS_SUCCESS &&
            CB_Flush(&fs, writer, &info) == STATUS_SUCCESS && info.AllocationSize == 4096,
            "sparse regrowth retains sparse identity")) return false;
    Store final(owned.fixture.volume);
    return Require(final.PrepareNativeWritePath() && final.ReplayOrRecover() && final.VerifyIntegrity() &&
        final.ReadCommittedFileRange(L"\\original", 257, 4096, bytes) && bytes == std::vector<std::byte>(4096),
        "shrink and regrowth preserve zero tail across native reopen");
}

bool TestNativeSparseRangeBoundariesAndReplay()
{
    namespace protocol = apfsaccess::fshost::sparse_control;
    using Store = apfsaccess::rw::MetadataStore;
    using Tx = apfsaccess::rw::TransactionManager;
    for (const bool shared : {false, true})
    {
        HostNativeSparse340Fixture owned;
        if (!Require(owned.Initialize(shared), "range boundary fixture initializes")) return false;
        auto& c = *owned.fixture.context; auto fs = BuildFileSystem(&c);
        c.args.write_max_dirty_transactions = 64;
        PVOID writer = nullptr, reader = nullptr; FSP_FSCTL_FILE_INFO info{};
        ScopeExit close{[&] { if (writer) CB_Close(&fs, writer); if (reader) CB_Close(&fs, reader); }};
        if (!Require(CB_Open(&fs, const_cast<PWSTR>(L"\\original"), FILE_OPEN << 24,
                GENERIC_READ | GENERIC_WRITE, &writer, &info) == STATUS_SUCCESS &&
                CB_Open(&fs, const_cast<PWSTR>(L"\\original"), FILE_OPEN << 24,
                GENERIC_READ, &reader, &info) == STATUS_SUCCESS, "boundary handles open")) return false;
        if (shared && !Require(owned.SetIncompleteCensus(true), "range refusal observes a real post-Open census fault")) return false;
        protocol::RangeRequest request; request.length = 4096;
        protocol::Reply reply{}; ULONG transferred = 999;
        const auto control = [&](PVOID handle, UINT32 code) {
            return CB_Control(&fs, handle, code, &request, sizeof(request), &reply, sizeof(reply), &transferred);
        };
        const auto image = ReadFileBytes(owned.fixture.image.path);
        const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
        c.fs = &fs;
        const auto mounted_query = control(writer, protocol::Query);
        const auto mounted_capabilities = reply.capabilities;
        const auto mounted_zero = control(writer, protocol::Zero);
        c.fs = nullptr;
        if (!Require(mounted_query == STATUS_SUCCESS && mounted_capabilities == protocol::CanQuery &&
                mounted_zero == STATUS_NOT_SUPPORTED && transferred == 0,
                "mounted private mutation stays disabled without kernel cache coordination")) return false;
        if (!Require(control(reader, protocol::Zero) == STATUS_ACCESS_DENIED && transferred == 0,
                "zero requires data write access, not append or read access")) return false;
        request.offset = UINT64_MAX - 1;
        if (!Require(control(writer, protocol::Zero) == STATUS_INVALID_PARAMETER && transferred == 0,
                "range overflow is rejected before mutation")) return false;
        request.offset = 0; request.reserved = 1;
        if (!Require(control(writer, protocol::Zero) == STATUS_INVALID_PARAMETER && transferred == 0,
                "reserved protocol bits are rejected")) return false;
        request.reserved = 0;
        ++request.version;
        if (!Require(control(writer, protocol::Zero) == STATUS_INVALID_PARAMETER && transferred == 0,
                "unknown protocol versions cannot mutate data")) return false;
        request.version = protocol::Version;
        if (!Require(CB_Control(&fs, writer, protocol::Zero, &request, sizeof(request), &reply,
                sizeof(reply) - 1, &transferred) == STATUS_BUFFER_TOO_SMALL && transferred == 0,
                "short reply buffer cannot initiate a zero mutation")) return false;
        if (shared && !Require(control(writer, protocol::Query) == STATUS_SUCCESS && reply.capabilities == protocol::CanQuery &&
                control(writer, protocol::Zero) == STATUS_NOT_SUPPORTED && transferred == 0 &&
                CB_SetFileSize(&fs, writer, owned.tail + 32768, FALSE, &info) == STATUS_NOT_SUPPORTED,
                "shared extent capability denies zero and growth before touching clone data")) return false;
        if (!Require(image == ReadFileBytes(owned.fixture.image.path) && wal == ReadFileBytes(c.session_root / "accepted.wal"),
                "invalid requests and shared extent refusals leave image and WAL unchanged")) return false;
        if (shared)
        {
            if (!Require(owned.SetIncompleteCensus(false), "range refusal restores only its exact saved test leaf")) return false;
            continue;
        }
        NativeSparseRangeView limit_view;
        limit_view.path = L"\\original";
        protocol::Reply oversized;
        oversized.range_count = 1; oversized.ranges[0].length = protocol::MaximumZeroBytes + 1;
        bool staged = false;
        if (!Require(StageNativeSparseZero(c, *static_cast<OpenContext*>(writer), limit_view, oversized, staged) ==
                STATUS_NOT_SUPPORTED && !staged && image == ReadFileBytes(owned.fixture.image.path) &&
                wal == ReadFileBytes(c.session_root / "accepted.wal"),
                "zero allocation byte bound rejects before staging or WAL mutation")) return false;
        request.offset = 17; request.length = owned.tail + 9 - 17;
        c.test_forced_native_commit_status = Store::CommitStatus::PersistFailed;
        if (!Require(!NT_SUCCESS(control(writer, protocol::Zero)) && transferred == 0 &&
                image == ReadFileBytes(owned.fixture.image.path) &&
                c.tx_manager->Watermarks().accepted_sequence > c.tx_manager->Watermarks().apfs_durable_sequence,
                "failed publication returns no success and retains accepted zero payload for replay")) return false;
        CB_Close(&fs, writer); writer = nullptr; CB_Close(&fs, reader); reader = nullptr;
        StopDeferredCommitWorker(&c); c.tx_manager.reset(); c.payload_spool.reset(); ResetRecoveryMarkerCache(&c);
        MountContext recovered;
        recovered.args = c.args; recovered.native_write_enabled = true;
        recovered.session_root = c.session_root; recovered.recovery_marker_file = c.recovery_marker_file;
        recovered.cache_root = c.cache_root; recovered.payload_spool_volume_identity = c.payload_spool_volume_identity;
        recovered.owned_metadata_store = std::make_unique<Store>(owned.fixture.volume);
        recovered.metadata_store = recovered.owned_metadata_store.get();
        recovered.tx_manager = std::make_unique<Tx>(L"Conservative");
        recovered.tx_manager->SetVolumeIdentity(L"directory-symlink-volume");
        recovered.tx_manager->SetJournalPath((recovered.session_root / "accepted.wal").wstring());
        recovered.payload_spool = std::make_unique<apfsaccess::rw::PayloadSpool>(apfsaccess::rw::PayloadSpool::Options{
            recovered.session_root / "payload-spool", recovered.payload_spool_volume_identity, 1024 * 1024});
        // Match production startup: recovery must have the identity-bound
        // range reader before replay, including untouched block canaries.
        recovered.metadata_store->SetFilePayloadProvider([&recovered](const auto& path, auto length) {
            return LoadHydratedPayloadForPath(&recovered, path, length, false);
        });
        recovered.metadata_store->SetFilePayloadRangeProvider([&recovered](const auto& path, auto identity,
            auto offset, auto destination) {
            return ReadHydratedPayloadRangeForPath(&recovered, path, identity, offset, destination);
        });
        std::vector<std::byte> bytes;
        if (!Require(recovered.metadata_store->PrepareNativeWritePath() && recovered.metadata_store->ReplayOrRecover() &&
                ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(recovered) &&
                recovered.metadata_store->VerifyIntegrity() && recovered.metadata_store->ReadCommittedFileRange(L"\\original", 17, 4096, bytes) &&
                bytes == std::vector<std::byte>(4096) && recovered.metadata_store->ReadCommittedFileRange(L"\\original", 16, 1, bytes) &&
                bytes == std::vector<std::byte>{std::byte{0x31}} &&
                recovered.metadata_store->ReadCommittedFileRange(L"\\original", owned.tail, 10, bytes) &&
                bytes == std::vector<std::byte>{std::byte{}, std::byte{}, std::byte{}, std::byte{}, std::byte{},
                    std::byte{}, std::byte{}, std::byte{}, std::byte{}, std::byte{0xa7}} &&
                recovered.metadata_store->LookupCommittedInodeByPath(L"\\original")->allocation_size == 24576,
                "accepted zero replays byte-exactly with outside canary and holes intact")) return false;
        const auto after = ReadFileBytes(owned.fixture.image.path);
        if (!Require(ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(recovered) && after == ReadFileBytes(owned.fixture.image.path),
                "zero replay is idempotent without another checkpoint")) return false;
    }
    return true;
}
