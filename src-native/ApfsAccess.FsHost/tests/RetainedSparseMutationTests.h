#pragma once

#include "RetainedGenerationPressureTests.h"

// Include after DirectorySymlinkFixture and the canonical mount-context helpers.
namespace RetainedSparseMutationTests
{
using namespace RetainedGenerationPressureTests;
using Operation = Store::MutationOperation;
constexpr std::uint64_t SparseHeadBlock = 256, SparseTailBlock = 266, BystanderBlock = 276;

bool BuildPreimage(DirectorySymlinkFixture& fixture, bool implicit, bool fully_sparse)
{
    using namespace apfsaccess::rw;
    using namespace apfsaccess::testfixture;
    auto spec = TwoProjectableVolumeStore();
    spec.volumes.resize(1); spec.authoritative_checkpoint = true; spec.dual_checkpoint = false;
    spec.xid = 20; spec.block_count = 1024; spec.authoritative_checkpoint_ring_blocks = 32;
    spec.authoritative_internal_pool_blocks = 64;
    auto& volume = spec.volumes.front();
    volume.incompat = 0; volume.additional_file_system_allocated_blocks = fully_sparse ? 4 : 6;
    auto& records = volume.filesystem_records;
    records.clear(); volume.extentref_records.clear();
    apfsaccess::catalog::BtreeRecord encoded;
    std::string error;
    const auto add = [&](bool ok) { if (ok) records.push_back(encoded); return ok; };
    AppleInodeRecord root;
    root.object_id = root.private_id = root.parent_id = 2; root.mode = 0040755; root.children_or_links = 3;
    if (!add(EncodeAppleInodeRecord(root, encoded, error))) return false;
    for (const auto id : {17ULL, 18ULL, 19ULL})
    {
        const bool sparse = id != 19;
        const auto size = id == 17 ? 8 * Block + 37 : id == 18 ? 4 * Block + 17 : 3 * Block + 11;
        const auto allocated = id == 19 ? 4 * Block : id == 18 || fully_sparse ? 0 : 2 * Block;
        AppleInodeRecord inode;
        inode.object_id = inode.private_id = id; inode.parent_id = 2;
        inode.mode = 0100640; inode.owner = 501; inode.group = 20; inode.children_or_links = 1;
        inode.internal_flags = sparse ? kAppleInodeSparseFlag : 0;
        AppleExtendedField stream{8, 0, std::vector<std::byte>(40)};
        PutU64LE(stream.data, 0, size); PutU64LE(stream.data, 8, allocated);
        inode.extended_fields.push_back(stream);
        if (sparse)
        {
            AppleExtendedField holes{kAppleInodeSparseBytesField, 0, std::vector<std::byte>(8)};
            PutU64LE(holes.data, 0, (size + Block - 1) / Block * Block - allocated);
            inode.extended_fields.push_back(holes);
        }
        AppleDirectoryRecord link;
        link.parent_id = 2; link.file_id = id; link.flags = 8;
        link.name_utf8 = id == 17 ? "sparse" : id == 18 ? "all-hole" : "bystander";
        if (!add(EncodeAppleInodeRecord(inode, encoded, error)) ||
            !add(EncodeAppleDirectoryRecord(link, encoded, error)) ||
            !add(EncodeAppleDataStreamIdRecord({id, 1}, encoded, error))) return false;
        const auto attribute = BuildPatternPayloadForTest(32, static_cast<unsigned char>(id));
        if (!add(EncodeAppleXattrRecord({id, "com.apple.FinderInfo", kAppleXattrDataEmbedded, attribute}, encoded, error)))
            return false;
    }
    std::vector<AppleFileExtentRecord> extents;
    if (!fully_sparse)
    {
        extents.push_back({17, 0, Block, SparseHeadBlock, 0, 4096});
        extents.push_back({17, 6 * Block, Block, SparseTailBlock, 0, 4096});
    }
    if (!implicit)
    {
        if (fully_sparse) extents.push_back({17, 0, 9 * Block, 0, 0, 4096});
        else
        {
            extents.push_back({17, Block, 5 * Block, 0, 0, 4096});
            extents.push_back({17, 7 * Block, 2 * Block, 0, 0, 4096});
        }
        extents.push_back({18, 0, 5 * Block, 0, 0, 4096});
    }
    extents.push_back({19, 0, 4 * Block, BystanderBlock, 0, 4096});
    for (const auto& extent : extents)
    {
        if (!add(EncodeAppleFileExtentRecord(extent, encoded, error))) return false;
        if (!extent.physical_block) continue;
        const auto blocks = extent.length_bytes / Block;
        if (!EncodeApplePhysicalExtentRecord({extent.physical_block, blocks, kApplePhysicalExtentKindNew,
                extent.object_id, 1}, encoded, error)) return false;
        volume.extentref_records.push_back(encoded);
        for (std::uint64_t block = 0; block < blocks; ++block)
            spec.authoritative_seeded_main_blocks.push_back({extent.physical_block + block,
                std::vector<std::byte>(Block, extent.object_id == 19 ? std::byte{0xc3} :
                    extent.logical_address ? std::byte{0xa7} : std::byte{0x31})});
    }
    if (!Require(SortAppleBtreeRecords(records, AppleBtreeKeyOrder::FileSystemCaseSensitive, error) &&
            SortAppleBtreeRecords(volume.extentref_records, AppleBtreeKeyOrder::PhysicalExtent, error),
            "W09 sparse seed records sort")) return false;
    const auto image = BuildStoreImage(spec);
    apfsaccess::catalog::VectorRandomAccessSource source(image);
    const auto view = apfsaccess::catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    if (!Require(view.has_value(), ("W09 sparse seed allocator decodes: " + error).c_str())) return false;
    const auto& nx = view->container.superblock;
    const auto& allocator = view->spaceman;
    const auto& pool = allocator.internal_pool;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> reserved{
        {0, 1}, {nx.xp_desc_base_block, nx.xp_desc_block_count}, {nx.xp_data_base_block, nx.xp_data_block_count},
        {pool.base_block, pool.block_count}, {pool.bitmap_base_block, pool.bitmap_block_count}};
    const auto reserve_object = [&](const apfsaccess::catalog::AppleObjectLocation& object) {
        if (object.physical_block) reserved.emplace_back(object.physical_block,
            (std::max)(std::uint64_t{1}, (object.size_bytes + Block - 1) / Block));
    };
    reserve_object(allocator.object);
    reserve_object(view->container_object_map.object); reserve_object(view->container_object_map.tree);
    for (const auto& device : allocator.devices)
    {
        for (const auto& cib : device.cibs) reserve_object(cib.object);
        for (const auto& cab : device.cabs) reserve_object(cab.object);
    }
    for (const auto& chunk : allocator.chunks) reserved.emplace_back(chunk.bitmap_block, 1);
    for (const auto& queue : allocator.free_queues)
        for (const auto block : queue.tree_blocks) reserved.emplace_back(block, 1);
    for (const auto& selected : view->volumes)
    {
        reserve_object(selected.superblock_object); reserve_object(selected.object_map.object);
        reserve_object(selected.object_map.tree); reserve_object(selected.root_tree);
        for (const auto* tree : {&selected.extentref_tree, &selected.snapshot_metadata_tree, &selected.file_extent_tree})
            if (*tree) reserve_object(**tree);
    }
    for (const auto& [block, bytes] : spec.authoritative_seeded_main_blocks)
    {
        const auto chunk = std::find_if(allocator.chunks.begin(), allocator.chunks.end(), [&](const auto& entry) {
            return entry.device_index == 0 && block >= entry.start_block && block - entry.start_block < entry.block_count;
        });
        const bool outside_reserved = std::none_of(reserved.begin(), reserved.end(), [&](const auto& range) {
            return block >= range.first && block - range.first < range.second;
        });
        const auto bit = chunk == allocator.chunks.end() ? UINT64_MAX : block - chunk->start_block;
        if (!Require(bytes.size() == Block && block < nx.block_count && outside_reserved &&
                chunk != allocator.chunks.end() && bit / 8 < chunk->allocation_bitmap.size() &&
                (std::to_integer<unsigned>(chunk->allocation_bitmap[bit / 8]) & (1u << (bit % 8))) != 0,
                "W09 sparse seed payload is allocated in the decoded main pool and avoids every reserved region"))
            return false;
    }
    return Require(WriteFileBytes(fixture.image.path, image) && fixture.Initialize(false),
        "W09 sparse preimage uses existing inode, extent and ownership codecs and ordinary native import");
}

bool WriteBorrowedBlock(HANDLE borrowed, std::uint64_t block, const std::vector<std::byte>& bytes)
{
    if (bytes.size() != Block) return false;
    const auto at = block * Block;
    OVERLAPPED write{};
    write.Offset = static_cast<DWORD>(at); write.OffsetHigh = static_cast<DWORD>(at >> 32);
    DWORD written = 0;
    const auto started = WriteFile(borrowed, bytes.data(), static_cast<DWORD>(Block), &written, &write);
    const auto completed = started || (GetLastError() == ERROR_IO_PENDING &&
        GetOverlappedResult(borrowed, &write, &written, TRUE));
    return completed && written == Block && FlushFileBuffers(borrowed);
}

// Default: writer-produced preimage. Other scenarios are explicit Root selectors.
bool Run(const std::string& scenario = {})
{
    const bool implicit = scenario == "implicit";
    const bool fully_sparse = scenario == "fully-sparse";
    const bool negative = !scenario.empty() && !implicit && !fully_sparse;
    const std::vector<std::string> faults{"corrupt-source", "malformed-hole", "malformed-allocation",
        "misbound-write", "misbound-tail", "corrupt-tail", "unlogged-hole"};
    if (!Require(!negative || std::find(faults.begin(), faults.end(), scenario) != faults.end(),
            "W09 sparse scenario is known")) return false;
    DirectorySymlinkFixture fixture(false);
    if (!BuildPreimage(fixture, implicit || fully_sparse, fully_sparse)) return false;
    auto& c = *fixture.context;
    c.args.write_require_canonical_commit = true; c.args.write_max_dirty_transactions = 64;
    std::map<std::uint64_t, std::vector<std::byte>> expected;
    expected[17].resize(8 * Block + 37);
    if (!fully_sparse)
    {
        std::fill_n(expected[17].begin(), Block, std::byte{0x31});
        std::fill_n(expected[17].begin() + 6 * Block, Block, std::byte{0xa7});
    }
    expected[18].resize(4 * Block + 17);
    Batch bystander{L"\\bystander", std::vector<std::byte>(3 * Block + 11, std::byte{0xc3}), {19, 20}};
    c.metadata_store->SetFilePayloadRangeProvider([&](const auto& path, auto identity, auto offset, auto destination) {
        const auto inode = c.metadata_store->LookupWorkingInodeByPath(path);
        const auto found = expected.find(identity.object_id);
        if (!inode || inode->object_id != identity.object_id || inode->xid != identity.generation ||
            found == expected.end() || offset > found->second.size() || destination.size() > found->second.size() - offset)
            return false;
        std::copy_n(found->second.begin() + offset, destination.size(), destination.begin());
        return true;
    });
    unsigned batch = 0;
    Spool::AppendResult tail_reference;
    const auto stage = [&](Operation operation, const std::wstring& path, std::uint64_t size,
            std::uint64_t offset = 0, const std::vector<std::byte>& payload = {}) {
        Store::MutationRequest request;
        request.operation = operation; request.path = path;
        request.length = operation == Operation::SetBasicInfo ? 0 : size;
        request.offset = offset;
        if (operation == Operation::SetBasicInfo) request.timestamp_utc = size;
        Store::PayloadIdentity identity;
        if (!Require(c.metadata_store->StageMutation(request, &identity) == Store::MutationStatus::Applied,
                "W09 sparse original mutation stages through existing sparse preflight")) return false;
        if (operation == Operation::SetFileSize) expected.at(identity.object_id).resize(size, std::byte{0});
        Tx::MutationIntent intent;
        const auto kind = ManifestJournalKindForOperation(operation);
        if (!kind) return false;
        intent.kind = *kind; intent.path = path; intent.object_id = identity.object_id; intent.generation = identity.generation;
        intent.offset = offset; intent.length = request.length; intent.timestamp_utc = request.timestamp_utc;
        if (operation == Operation::Write)
        {
            if (size != payload.size()) return false;
            auto& bytes = expected.at(identity.object_id);
            bytes.resize((std::max)(static_cast<std::uint64_t>(bytes.size()), offset + size), std::byte{0});
            std::copy(payload.begin(), payload.end(), bytes.begin() + offset);
            if (scenario == "misbound-write" && batch == 1) intent.path = bystander.path;
            if (scenario == "misbound-tail" && batch == 3) --intent.generation;
            intent.wal_sequence = c.tx_manager->NextMutationSequence();
            Spool::AppendResult reference;
            if (!c.payload_spool->Append({c.payload_spool_volume_identity, intent.object_id, intent.generation,
                    offset, intent.wal_sequence, payload}, &reference)) return false;
            intent.payload_spool_offset = reference.spool_offset; intent.payload_length = reference.payload_length;
            intent.payload_checksum = reference.payload_sha256;
            if (batch == 3) tail_reference = reference;
        }
        c.pending_native_writes = true;
        return Require(c.tx_manager->RecordMutation(intent), "W09 sparse WAL binds original path, identity and exact spool range");
    };
    const auto accept = [&](std::uint64_t& sequence) {
        return c.payload_spool->FlushDirtyState() &&
            AcceptMutationJournalForDeferredCommitBestEffort(&c, L"W09SparseAccept", &sequence);
    };
    // Default/fault cases start at a checkpoint actually emitted by the writer.
    // The two codec controls retain their original implicit extent evidence.
    if (!implicit && !fully_sparse)
    {
        std::uint64_t seed = 0;
        if (!c.tx_manager->Begin() || !stage(Operation::SetFileSize, L"\\sparse", 9 * Block + 37) ||
            !stage(Operation::SetFileSize, L"\\all-hole", 5 * Block + 17) || !accept(seed) ||
            !Require(NT_SUCCESS(CommitNativeMutationsBestEffort(&c, L"W09SparseSeed")) &&
                FinalizeMutationJournalBestEffort(&c, L"W09SparseSeed"), "W09 sparse writer produces genuine sparse preimages"))
            return false;
    }
    const auto original = ReadFileBytes(fixture.image.path);
    const auto source_xid = c.metadata_store->CheckpointXid().value_or(0);
    const auto initial = expected;
    const auto source_view = *c.metadata_store->AuthoritativeAppleCheckpointView();
    auto retained = std::make_unique<Store>(fixture.volume);
    if (!Require(retained->PrepareNativeWritePath(), "W09 sparse old reader pins original data, holes and bystander")) return false;
    const auto check = [&](Store& store, const std::map<std::uint64_t, std::vector<std::byte>>& content) {
        return CheckFile(store, Batch{L"\\sparse", content.at(17), {17, 0}}) &&
            CheckFile(store, Batch{L"\\all-hole", content.at(18), {18, 0}}) && CheckFile(store, bystander);
    };
    const auto validate_projection = [&](const auto& view, const auto& source, bool expect_valid) {
        std::vector<apfsaccess::catalog::BtreeRecord> records;
        apfsaccess::rw::NativeApfsVolumeProjection projection;
        std::string error;
        auto budget = std::make_shared<apfsaccess::catalog::ApfsReadBudget>(65536, 256ULL << 20, 262144, 256ULL << 20);
        const bool valid = apfsaccess::catalog::ReadAppleVolumeFileSystemRecords(source, view.container, view.volumes.front(), records, error) &&
            apfsaccess::rw::NativeApfsReader::TryProjectOrdinaryFileSystemRecords(records, view.container.superblock,
                view.volumes.front().superblock, budget, projection, error);
        if (!Require(valid == expect_valid, "W09 sparse authoritative ordinary projection independently admits or rejects exact preimage"))
            return false;
        if (!expect_valid)
        {
            std::fprintf(stderr, "[W09-sparse] malformed projection=%s\n", error.c_str());
            return Require(projection.inodes.empty() && projection.read_extents_by_inode.empty() &&
                error == (scenario == "malformed-hole" ? "SnapshotSparseByteCountMismatch" : "SnapshotFileExtentCoverageInvalid"),
                "W09 sparse authoritative accounting validator refuses malformed fields without manufactured zero mappings");
        }
        for (const auto object : {17ULL, 18ULL})
        {
            const auto map = projection.read_extents_by_inode.find(object);
            if (!Require(map != projection.read_extents_by_inode.end() && !map->second.empty() &&
                    std::any_of(map->second.begin(), map->second.end(), [](const auto& e) { return !e.physical_address; }),
                    "W09 sparse authoritative projection supplies explicit authenticated zero mappings")) return false;
        }
        return true;
    };
    {
        apfsaccess::catalog::HeldFileSource initial_source(fixture.image.path.string());
        if (!validate_projection(source_view, initial_source, true) || !check(*retained, initial)) return false;
    }
    std::vector<std::uint64_t> protected_blocks, accepted;
    std::vector<std::vector<std::byte>> wal_prefixes;
    const auto accept_batch = [&]() {
        std::uint64_t sequence = 0;
        if (!accept(sequence)) return false;
        accepted.push_back(sequence); wal_prefixes.push_back(ReadFileBytes(c.session_root / "accepted.wal"));
        return true;
    };
    const auto publish = [&]() {
        const auto status = CommitNativeMutationsBestEffort(&c, L"W09SparsePublish");
        std::fwprintf(stderr, L"[W09-sparse] batch=%u status=%lx xid=%llu detail=%ls\n", batch,
            static_cast<unsigned long>(status), c.metadata_store->CheckpointXid().value_or(0),
            c.metadata_store->LastCommitFailureDetail().c_str());
        if (!Require(NT_SUCCESS(status), "W09 sparse publishes accepted original batch without receipt")) return false;
        if (!CheckHistory(fixture.image.path, original, source_xid, protected_blocks.empty(), protected_blocks))
        {
            apfsaccess::catalog::HeldFileSource source(fixture.image.path.string());
            std::string error;
            const auto current = apfsaccess::catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
            std::vector<apfsaccess::rw::AppleRecoveryCheckpointView> history;
            const bool loaded = current && apfsaccess::rw::LoadAppleRecoveryCheckpoints(
                source, *current, {source_xid}, history, error);
            std::fprintf(stderr, "[W09-sparse] history-probe preimage=%llu endpoint=%llu loaded=%d checkpoints=%zu error=%s\n",
                source_xid, current ? current->container.superblock.xid : 0, loaded, history.size(), error.c_str());
            return false;
        }
        return check(*retained, initial) && check(*c.metadata_store, expected);
    };
    batch = 1;
    if (!c.tx_manager->Begin() ||
        !stage(Operation::Write, L"\\sparse", 31, Block - 7, BuildPatternPayloadForTest(31, 0x51)) ||
        !stage(Operation::Write, L"\\sparse", 29, 6 * Block - 9, BuildPatternPayloadForTest(29, 0x62)) ||
        !stage(Operation::Write, L"\\all-hole", 17, 2 * Block - 5, BuildPatternPayloadForTest(17, 0x73)) ||
        !stage(Operation::SetBasicInfo, L"\\sparse", 133700000000000111ULL) ||
        !stage(Operation::SetBasicInfo, L"\\all-hole", 133700000000000112ULL) || !accept_batch()) return false;
    if (scenario == "unlogged-hole") expected.at(17).at(Block + 100) ^= std::byte{0x67};
    if (!publish()) return false;
    batch = 2;
    if (!c.tx_manager->Begin() ||
        !stage(Operation::SetFileSize, L"\\sparse", Block + 13) ||
        !stage(Operation::SetFileSize, L"\\sparse", 8 * Block + 53) ||
        !stage(Operation::Write, L"\\sparse", 37, 4 * Block - 11, BuildPatternPayloadForTest(37, 0x84)) ||
        !stage(Operation::SetFileSize, L"\\all-hole", 0) ||
        !stage(Operation::SetFileSize, L"\\all-hole", 6 * Block + 7) ||
        !stage(Operation::SetBasicInfo, L"\\sparse", 133700000000000221ULL) ||
        !stage(Operation::SetBasicInfo, L"\\all-hole", 133700000000000222ULL) || !accept_batch() || !publish()) return false;
    const auto before_tail = expected;
    batch = 3;
    if (!c.tx_manager->Begin() ||
        !stage(Operation::Write, L"\\sparse", 31, 5 * Block - 7, BuildPatternPayloadForTest(31, 0x95)) ||
        !stage(Operation::Write, L"\\all-hole", 23, 3 * Block - 9, BuildPatternPayloadForTest(23, 0xa6)) ||
        !stage(Operation::SetBasicInfo, L"\\sparse", 133700000000000331ULL) ||
        !stage(Operation::SetBasicInfo, L"\\all-hole", 133700000000000332ULL) || !accept_batch()) return false;
    const auto final_expected = expected;
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    const auto spool = ReadFileBytes(c.payload_spool->SpoolFilePath());
    for (const auto& prefix : wal_prefixes)
        if (!Require(prefix.size() <= wal.size() && std::equal(prefix.begin(), prefix.end(), wal.begin()),
                "W09 sparse original accepted WAL prefixes remain exact")) return false;
    std::filesystem::path evidence;
    if (const auto* destination = std::getenv("APFSACCESS_W09_EVIDENCE"))
    {
        evidence = std::filesystem::path(destination) / (scenario.empty() ? "sparse-writer-positive" : "sparse-" + scenario);
        if (!WriteFileBytes(evidence / "original.img", original) ||
            !WriteFileBytes(evidence / "published.img", ReadFileBytes(fixture.image.path)) ||
            !WriteFileBytes(evidence / "accepted.wal", wal) || !WriteFileBytes(evidence / "payload-spool.bin", spool) ||
            !WriteFileBytes(evidence / "target-expected.bin", final_expected.at(17)) ||
            !WriteFileBytes(evidence / "all-hole-expected.bin", final_expected.at(18))) return false;
    }
    retained.reset();
    HANDLE borrowed = INVALID_HANDLE_VALUE;
    if (!Reopen(fixture, true, borrowed)) return false;
    auto& r = *fixture.context;
    const auto image_bytes = [&]() {
        std::vector<std::byte> bytes;
        if (!r.metadata_store->Device().ReadForVerification(0, original.size(), bytes)) bytes.clear();
        return bytes;
    };
    if (!Require(wal == ReadFileBytes(r.tx_journal_file) && spool == ReadFileBytes(r.payload_spool->SpoolFilePath()) &&
            check(*r.metadata_store, before_tail), "W09 sparse sole owner imports original evidence and published preimage")) return false;
    if (scenario == "corrupt-source")
    {
        auto wanted = image_bytes();
        std::vector<std::byte> cached;
        if (!Require(r.metadata_store->Device().Read(SparseHeadBlock * Block, Block, cached) && cached.size() == Block &&
                std::all_of(cached.begin(), cached.end(), [](auto byte) { return byte == std::byte{0x31}; }),
                "W09 sparse injected fault targets the codec-seeded retained data run")) return false;
        auto changed = cached; changed.at(31) ^= std::byte{1};
        if (!Require(WriteBorrowedBlock(borrowed, SparseHeadBlock, changed), "W09 sparse corrupts one actual retained source data byte")) return false;
        wanted.at(SparseHeadBlock * Block + 31) ^= std::byte{1};
        if (!Require(wanted.size() == original.size() && wanted == image_bytes(),
                "W09 sparse uncached read observes exactly one injected original extent byte corruption")) return false;
        std::vector<std::byte> general;
        const auto cache_enabled = std::getenv("APFSACCESS_EXPERIMENTAL_BLOCK_READ_CACHE");
        if (!Require(r.metadata_store->Device().Read(SparseHeadBlock * Block, Block, general) &&
                (!cache_enabled || std::string(cache_enabled) != "1" || general == cached),
                "W09 sparse general cache stays stale when enabled while verification reads actual data")) return false;
    }
    if (scenario == "malformed-hole" || scenario == "malformed-allocation")
    {
        using namespace apfsaccess::rw;
        apfsaccess::catalog::VectorRandomAccessSource original_source(original);
        std::vector<apfsaccess::catalog::BtreeRecord> records;
        std::string error;
        if (!apfsaccess::catalog::ReadAppleVolumeFileSystemRecords(original_source, source_view.container,
                source_view.volumes.front(), records, error)) return false;
        bool changed = false;
        for (auto& record : records)
        {
            AppleInodeRecord inode;
            if (!ApfsExtendedRecordCodec::DecodeInode(record, inode, error) || inode.object_id != 17) continue;
            for (auto& field : inode.extended_fields)
                if (field.type == (scenario == "malformed-hole" ? kAppleInodeSparseBytesField : 8))
                {
                    const auto offset = scenario == "malformed-hole" ? 0 : 8;
                    apfsaccess::testfixture::PutU64LE(field.data, offset,
                        apfsaccess::catalog::ReadU64LE(field.data, offset).value_or(0) + Block);
                    changed = true;
                }
            if (!EncodeAppleInodeRecord(inode, record, error)) return false;
        }
        const auto& root = source_view.volumes.front().root_tree;
        AppleBtreeOptions options;
        options.block_size = Block; options.xid = root.xid;
        options.root_object_id = root.object_id; options.root_physical_block = root.physical_block;
        options.storage_type = root.type & apfsaccess::catalog::kObjectStorageTypeMask; options.subtype = root.subtype;
        if (options.storage_type == apfsaccess::catalog::kObjectPhysical) options.tree_flags |= kAppleBtreePhysical;
        if (options.storage_type == apfsaccess::catalog::kObjectEphemeral) options.tree_flags |= kAppleBtreeEphemeral;
        options.key_order = AppleBtreeKeyOrder::FileSystemCaseSensitive;
        options.max_nodes = 1;
        AppleSerializedBtree tree;
        if (!Require(changed && SerializeAppleBtree(records, options, tree, error) && tree.objects.size() == 1 &&
                tree.objects.front().location.physical_block == root.physical_block &&
                WriteBorrowedBlock(borrowed, root.physical_block, tree.objects.front().bytes),
                "W09 sparse malformed accounting uses existing inode codec and checksum-valid B-tree serializer")) return false;
        const auto faulted = image_bytes();
        apfsaccess::catalog::VectorRandomAccessSource faulted_source(faulted);
        if (!validate_projection(source_view, faulted_source, false)) return false;
    }
    if (scenario == "corrupt-tail")
    {
        r.payload_spool.reset();
        auto changed = spool; changed.at(static_cast<std::size_t>(tail_reference.spool_offset)) ^= std::byte{1};
        if (!WriteFileBytes(r.session_root / "payload-spool" / "payload-spool.bin", changed)) return false;
        r.payload_spool = std::make_unique<Spool>(Spool::Options{
            r.session_root / "payload-spool", r.payload_spool_volume_identity, 1024 * 1024});
    }
    const auto before = image_bytes();
    const auto spool_before = ReadFileBytes(r.payload_spool->SpoolFilePath());
    const auto index = ReadFileBytes(r.session_root / "payload-spool" / "payload-spool.idx");
    const auto marks = r.tx_manager->Watermarks();
    const auto unchanged = [&]() {
        const auto now = r.tx_manager->Watermarks();
        return !before.empty() && before == image_bytes() && wal == ReadFileBytes(r.tx_journal_file) &&
            spool_before == ReadFileBytes(r.payload_spool->SpoolFilePath()) &&
            index == ReadFileBytes(r.session_root / "payload-spool" / "payload-spool.idx") &&
            now.accepted_sequence == marks.accepted_sequence && now.apfs_durable_sequence == marks.apfs_durable_sequence &&
            now.cleanup_sequence == marks.cleanup_sequence;
    };
    std::vector<std::uint64_t> sequences{UINT64_MAX};
    std::string error;
    const auto proof = r.metadata_store->ProveRetainedAcceptedPrefix(*r.tx_manager, *r.payload_spool,
        r.tx_journal_file, r.payload_spool_volume_identity, sequences, error);
    std::fprintf(stderr, "[W09-sparse] scenario=%s proof=%d sequences=%zu error=%s\n",
        scenario.c_str(), proof, sequences.size(), error.c_str());
    if (!Require(unchanged() && CheckFile(*r.metadata_store, bystander),
            "W09 sparse proof preserves complete image, original WAL/spool/index and every watermark")) return false;
    if (!evidence.empty() && (!WriteFileBytes(evidence / "before-proof.img", before) ||
            !WriteFileBytes(evidence / "after-proof.img", image_bytes()) ||
            !WriteFileBytes(evidence / "after-proof.wal", ReadFileBytes(r.tx_journal_file)) ||
            !WriteFileBytes(evidence / "before-proof-spool.bin", spool_before) ||
            !WriteFileBytes(evidence / "after-proof-spool.bin", ReadFileBytes(r.payload_spool->SpoolFilePath())) ||
            !WriteFileBytes(evidence / "before-proof-spool.idx", index) ||
            !WriteFileBytes(evidence / "after-proof-spool.idx", ReadFileBytes(r.session_root / "payload-spool" / "payload-spool.idx"))))
        return false;
    unsigned publications = 0;
    r.metadata_store->SetCommitStageHook([&](std::string_view point) {
        if (point == "before-apple-publish") ++publications;
        return true;
    });
    if (negative)
    {
        const bool expected_error = scenario == "corrupt-tail" ? error == "RetainedAcceptedOriginalPayloadInvalid" :
            scenario.starts_with("misbound-") ? error == "RetainedAcceptedOriginalStageMismatch" :
            scenario.starts_with("malformed-") ? error == "RetainedAcceptedSourceProjectionInvalid" ||
                error == "RetainedAcceptedHistoryUnavailable" : error == "RetainedAcceptedPublicationReadbackMismatch";
        if (!Require(!proof && sequences.empty() && expected_error,
                "W09 sparse corrupt, malformed, misbound or unlogged evidence refuses even the valid earlier prefix")) return false;
        if (!Require(!ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(r) && publications == 0 && unchanged(),
                "W09 sparse actual startup refusal publishes nothing and preserves complete evidence and watermarks")) return false;
        return evidence.empty() || (WriteFileBytes(evidence / "after-refusal.img", image_bytes()) &&
            WriteFileBytes(evidence / "after-refusal.wal", ReadFileBytes(r.tx_journal_file)) &&
            WriteFileBytes(evidence / "after-refusal-spool.bin", ReadFileBytes(r.payload_spool->SpoolFilePath())) &&
            WriteFileBytes(evidence / "after-refusal-spool.idx", ReadFileBytes(r.session_root / "payload-spool" / "payload-spool.idx")));
    }
    const std::vector<std::uint64_t> published(accepted.begin(), accepted.end() - 1);
    if (!Require(proof && sequences == published && published.size() == 2 && marks.apfs_durable_sequence < published.front() &&
            marks.cleanup_sequence < published.front(), "W09 sparse exact publication proof earns two missing receipts and validates original partial tail"))
        return false;
    const auto check_final = [&](Store& store) {
        const auto sparse = store.LookupCommittedInodeByPath(L"\\sparse");
        const auto empty = store.LookupCommittedInodeByPath(L"\\all-hole");
        if (!Require(sparse && empty && sparse->allocation_size == 5 * Block && empty->allocation_size == 2 * Block &&
                sparse->modification_time_utc == 133700000000000331ULL && empty->modification_time_utc == 133700000000000332ULL &&
                sparse->owner == 501 && sparse->group == 20 && sparse->mode == 0100640,
                "W09 sparse recovered physical allocation, exact timestamps and inode metadata")) return false;
        for (const auto id : {17ULL, 18ULL, 19ULL})
        {
            const auto attribute = store.LookupCommittedExtendedAttribute(id, "com.apple.FinderInfo");
            if (!Require(attribute && attribute->data == BuildPatternPayloadForTest(32, static_cast<unsigned char>(id)),
                    "W09 sparse retained FinderInfo remains byte-identical for every inode")) return false;
        }
        return check(store, final_expected);
    };
    if (!Require(ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(r) && publications == 1 &&
            r.tx_manager->Watermarks().accepted_sequence == accepted.back() &&
            r.tx_manager->Watermarks().apfs_durable_sequence == accepted.back() &&
            r.tx_manager->Watermarks().cleanup_sequence == accepted.back(),
            "W09 sparse startup retires proven prefix and publishes original partial pending tail exactly once") ||
        !check_final(*r.metadata_store)) return false;
    const auto stable = image_bytes();
    if (!Require(ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(r) && publications == 1 && stable == image_bytes(),
            "W09 sparse repeated recovery changes no image byte")) return false;
    if (!evidence.empty() && (!WriteFileBytes(evidence / "recovered.img", stable) ||
            !WriteFileBytes(evidence / "recovered.wal", ReadFileBytes(r.tx_journal_file)))) return false;
    r.owned_metadata_store.reset(); r.metadata_store = nullptr;
    Store fresh(fixture.volume);
    return Require(fresh.PrepareNativeWritePath() && fresh.VerifyIntegrity(), "W09 sparse independent canonical reopen verifies") &&
        check_final(fresh);
}
}
