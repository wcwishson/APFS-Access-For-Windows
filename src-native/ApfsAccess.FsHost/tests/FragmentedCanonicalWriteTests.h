#pragma once

// Include after FsHostSemanticsTests.cpp's canonical fixture helpers.
namespace FragmentedCanonicalWriteTests
{
using Store = apfsaccess::rw::MetadataStore;
using Tx = apfsaccess::rw::TransactionManager;
constexpr std::uint64_t Block = 4096;
constexpr std::uint64_t WriteBytes = 96 * Block + 17;
constexpr std::uint64_t GrowBytes = 160 * Block + 33;

struct FreeSpace
{
    std::uint64_t available = 0, largest = 0;
};

FreeSpace InspectFree(const Store& store)
{
    FreeSpace result;
    const auto* view = store.AuthoritativeAppleCheckpointView();
    if (!view) return result;
    std::uint64_t run = 0, previous = UINT64_MAX;
    for (const auto& chunk : view->spaceman.chunks)
    {
        if (chunk.device_index != 0) continue;
        for (std::uint64_t i = 0; i < chunk.block_count; ++i)
        {
            const auto block = chunk.start_block + i;
            if (previous == UINT64_MAX || block != previous + 1) run = 0;
            previous = block;
            const bool free = chunk.bitmap_block == 0 ||
                (std::to_integer<unsigned>(chunk.allocation_bitmap.at(static_cast<std::size_t>(i / 8))) &
                    (1u << (i % 8))) == 0;
            if (free) { ++result.available; result.largest = (std::max)(result.largest, ++run); }
            else run = 0;
        }
    }
    return result;
}

struct Fixture
{
    DirectorySymlinkFixture host{false};
    std::vector<std::byte> blockers;

    bool Initialize(bool fragmented)
    {
        using namespace apfsaccess::rw;
        auto builder = TwoProjectableVolumeStore();
        builder.volumes.resize(1);
        builder.authoritative_checkpoint = true;
        builder.dual_checkpoint = false;
        builder.xid = 20;
        builder.block_count = 1024;
        builder.authoritative_checkpoint_ring_blocks = 32;
        builder.authoritative_internal_pool_blocks = 32;
        auto& volume = builder.volumes.front();
        auto& records = volume.filesystem_records;
        records.clear();
        apfsaccess::catalog::BtreeRecord encoded;
        std::string error;
        const auto add = [&](bool ok) { if (ok) records.push_back(encoded); return ok; };
        AppleInodeRecord root;
        root.object_id = root.private_id = root.parent_id = 2;
        root.mode = 0040755; root.children_or_links = 2;
        if (!add(EncodeAppleInodeRecord(root, encoded, error))) return false;
        const auto file = [&](std::uint64_t id, const char* name, std::uint64_t bytes) {
            AppleInodeRecord inode;
            inode.object_id = inode.private_id = id; inode.parent_id = 2;
            inode.mode = 0100644; inode.children_or_links = 1;
            inode.uncompressed_size = bytes;
            inode.create_time = inode.change_time = inode.modification_time = inode.access_time = 1700000000000000000ULL;
            AppleExtendedField stream; stream.type = 8; stream.data.resize(40);
            apfsaccess::testfixture::PutU64LE(stream.data, 0, bytes);
            apfsaccess::testfixture::PutU64LE(stream.data, 8, bytes);
            inode.extended_fields.push_back(stream);
            if (!add(EncodeAppleInodeRecord(inode, encoded, error))) return false;
            AppleDirectoryRecord link;
            link.parent_id = 2; link.file_id = id; link.flags = 8; link.name_utf8 = name;
            return add(EncodeAppleDirectoryRecord(link, encoded, error));
        };
        constexpr std::uint64_t count = 14;
        blockers = BuildPatternPayloadForTest(count * Block, 0x2d);
        if (!file(17, "target", 0) || !file(18, "blockers", blockers.size()) ||
            !add(EncodeAppleDataStreamIdRecord({18, 1}, encoded, error))) return false;
        for (std::uint64_t i = 0; i < count; ++i)
        {
            const auto physical = fragmented ? 128 + i * 64 : 128 + i;
            if (!add(EncodeAppleFileExtentRecord({18, i * Block, Block, physical, 0, Block}, encoded, error)) ||
                !EncodeApplePhysicalExtentRecord({physical, 1, kApplePhysicalExtentKindNew, 18, 1}, encoded, error)) return false;
            volume.extentref_records.push_back(encoded);
            ++volume.additional_file_system_allocated_blocks;
            builder.authoritative_seeded_main_blocks.push_back({physical,
                std::vector<std::byte>(blockers.begin() + i * Block, blockers.begin() + (i + 1) * Block)});
        }
        if (!SortAppleBtreeRecords(records, AppleBtreeKeyOrder::FileSystemCaseSensitive, error) ||
            !SortAppleBtreeRecords(volume.extentref_records, AppleBtreeKeyOrder::PhysicalExtent, error) ||
            !WriteFileBytes(host.image.path, apfsaccess::testfixture::BuildStoreImage(builder)) ||
            !host.Initialize(false)) return false;
        host.context->args.write_require_canonical_commit = true;
        return Require(host.context->metadata_store->VerifyIntegrity(), "W10 fixture passes genuine canonical integrity");
    }
};

bool CheckPressure(const Store& store, std::uint64_t target, bool fragmented)
{
    const auto free = InspectFree(store);
    std::fprintf(stderr, "[W10] bitmap available=%llu largest=%llu target=%llu blocks\n",
        free.available, free.largest, (target + Block - 1) / Block);
    return Require(free.available * Block > target + 20 * Block &&
        (fragmented ? free.largest * Block < target : free.largest * Block >= target),
        "W10 bitmap proves aggregate capacity and requested contiguous-run boundary");
}

bool CheckFile(Store& store, const std::vector<std::byte>& expected, bool fragmented,
    const std::vector<std::byte>& blockers)
{
    const auto inode = store.LookupCommittedInodeByPath(L"\\target");
    const auto key = apfsaccess::rw::ApfsNameCodec::CanonicalWindowsPathKey(L"\\target",
        apfsaccess::rw::ApfsNamePolicy::FromIncompatibleFeatures(0));
    const auto plan = key.ok() ? store.SnapshotCommittedFileReadPlan(*key.value) : std::nullopt;
    std::vector<std::byte> actual, other;
    const auto integrity = store.VerifyIntegrity();
    const auto read = store.ReadCommittedFileRange(L"\\target", 0, expected.size() + 7, actual);
    const auto read_other = store.ReadCommittedFileRange(L"\\blockers", 0, blockers.size(), other);
    std::fprintf(stderr, "[W10] integrity=%d inode=%d plan=%d eof=%llu allocation=%llu read=%d actual=%zu other=%d other-size=%zu exact=%d/%d\n",
        integrity, !!inode, !!plan, inode ? inode->logical_size : 0, inode ? inode->allocation_size.value_or(0) : 0,
        read, actual.size(), read_other, other.size(), actual == expected, other == blockers);
    if (!Require(integrity && inode && plan && inode->object_id == 17 && inode->private_id == 17 &&
            inode->logical_size == expected.size() &&
            inode->allocation_size == (expected.size() + Block - 1) / Block * Block &&
            read && actual == expected && read_other && other == blockers,
            "W10 canonical bytes EOF allocation and blocker ownership survive publication")) return false;
    std::vector<Store::FileExtent> extents;
    if (plan->has_single_extent) extents.push_back(plan->single_extent);
    else if (plan->extents_snapshot) extents = *plan->extents_snapshot;
    std::uint64_t logical = 0, previous = 0;
    unsigned gaps = 0;
    for (const auto& extent : extents)
    {
        if (!Require(extent.logical_offset == logical && extent.physical_address != 0 && extent.bytes != 0,
                "W10 committed extent mapping covers logical stream without holes")) return false;
        if (logical && extent.physical_address != previous) ++gaps;
        logical += extent.bytes; previous = extent.physical_address + extent.bytes;
    }
    std::fprintf(stderr, "[W10] eof=%zu extents=%zu physical-gaps=%u checkpoint=%llu\n",
        expected.size(), extents.size(), gaps, store.CheckpointXid().value_or(0));
    return Require(logical == (expected.size() + Block - 1) / Block * Block && (!fragmented || gaps > 0) &&
        store.AuthoritativeAppleCheckpointView() &&
        store.ActiveCommitModel() == Store::NativeWriteCommitModel::CanonicalApfsCheckpoint &&
        store.IsProductionCanonicalPathActive() && !store.IsFixtureLegacyFallbackActive() && !store.UsesScaffoldCommitBlob(),
        "W10 mapping actually spans distinct physical runs under Apple checkpoint authority");
}

bool CheckRaw(const std::filesystem::path& image, const std::vector<std::byte>& expected)
{
    using namespace apfsaccess::catalog;
    using namespace apfsaccess::rw;
    HeldFileSource raw(image.string());
    std::string error;
    const auto checkpoint = LoadAppleCheckpointView(raw, 0, raw.SizeBytes(), error);
    if (!Require(checkpoint && checkpoint->volumes.size() == 1, "W10 independent raw Apple checkpoint opens")) return false;
    const auto& volume = checkpoint->volumes.front();
    const auto xid = checkpoint->container.superblock.xid;
    std::vector<apfsaccess::catalog::BtreeRecord> records, physical_records;
    if (!Require(ReadAppleVolumeFileSystemRecords(raw, checkpoint->container, volume, records, error) &&
            volume.extentref_tree && ReadBtreeLeafRecords(raw, Block, volume.extentref_tree->physical_block,
                true, 0, xid, physical_records, error), "W10 raw filesystem and physical ownership trees decode")) return false;
    std::vector<ApplePhysicalExtentRecord> physical;
    for (const auto& record : physical_records)
    {
        ApplePhysicalExtentRecord extent;
        if (!Require(DecodeApplePhysicalExtentRecord(record, extent, error), "W10 physical ownership record decodes")) return false;
        physical.push_back(extent);
    }
    std::uint64_t cursor = 0;
    unsigned references = 0;
    for (const auto& record : records)
    {
        const auto key = ReadU64LE(record.key, 0).value_or(0);
        if ((key & 0x0fffffffffffffffULL) != 17) continue;
        if ((key >> 60) == 6)
        {
            AppleDataStreamIdRecord stream;
            if (!Require(DecodeAppleDataStreamIdRecord(record, stream, error) && stream.reference_count == 1,
                    "W10 raw stream retains its exact single-owner refcount")) return false;
            ++references;
        }
        if ((key >> 60) != 8) continue;
        AppleFileExtentRecord extent;
        if (!Require(DecodeAppleFileExtentRecord(record, Block, extent, error) && extent.logical_address == cursor &&
                extent.physical_block != 0 && extent.length_bytes == Block && extent.crypto_id == 0,
                "W10 raw logical extent sequence and crypto identity match ordinary file")) return false;
        const auto owned = std::count_if(physical.begin(), physical.end(), [&](const auto& p) {
            return p.physical_block <= extent.physical_block && extent.physical_block - p.physical_block < p.block_count &&
                p.owning_object_id == 17 && p.reference_count == 1;
        });
        std::vector<std::byte> payload;
        if (!Require(owned == 1 && raw.Read(extent.physical_block * Block, Block, payload),
                "W10 raw extent has exactly one valid physical owner")) return false;
        bool matches = true;
        for (std::size_t i = 0; i < payload.size(); ++i)
            matches = matches && payload[i] == (cursor + i < expected.size() ? expected[cursor + i] : std::byte{0});
        if (!Require(matches, "W10 independently addressed physical payload and EOF padding match expected bytes")) return false;
        cursor += Block;
    }
    std::fprintf(stderr, "[W10] raw-owned-blocks=%llu stream-refcounts=%u checkpoint=%llu\n", cursor / Block, references, xid);
    return Require(references == 1 && cursor == (expected.size() + Block - 1) / Block * Block,
        "W10 raw ownership and mapping cover precisely the allocated stream");
}

bool Run(bool fragmented = true, unsigned interrupt = 0)
{
    using Wal = apfsaccess::rw::WriteAheadLog;
    Fixture fixture;
    if (!Require(fixture.Initialize(fragmented), "W10 canonical mounted callback fixture initializes")) return false;
    auto& c = *fixture.host.context;
    auto evidence = fixture.host.image.path;
    evidence += L".evidence";
    std::error_code error;
    if (!Require(std::filesystem::create_directory(evidence, error) && !error,
            "W10 exclusively creates evidence beside its owned temporary image")) return false;
    ScopeExit cleanup_evidence{[&] {
        std::error_code ignored;
        std::filesystem::remove_all(evidence, ignored);
    }};
    if (!WriteFileBytes(evidence / "fixture.img", ReadFileBytes(fixture.host.image.path))) return false;
    auto fs = BuildFileSystem(&c);
    PVOID writer = nullptr; FSP_FSCTL_FILE_INFO info{};
    ScopeExit close{[&] { if (writer) CB_Close(&fs, writer); }};
    if (!Require(CB_Open(&fs, const_cast<PWSTR>(L"\\target"), FILE_OPEN << 24,
            GENERIC_READ | GENERIC_WRITE, &writer, &info) == STATUS_SUCCESS,
            "W10 actual FsHost Open callback succeeds")) return false;
    auto expected = BuildPatternPayloadForTest(WriteBytes, 0x73);
    for (unsigned step = 1; step <= 3; ++step)
    {
        const auto target = step == 1 ? WriteBytes : step == 2 ? GrowBytes - WriteBytes : 72 * Block + 13;
        if (!CheckPressure(*c.metadata_store, target, fragmented)) return false;
        const auto preimage = c.metadata_store->CheckpointXid().value_or(0);
        const auto before = ReadFileBytes(fixture.host.image.path);
        Store retained(fixture.host.volume);
        if (!Require(retained.PrepareNativeWritePath(), "W10 independent preimage reader opens")) return false;
        auto after = expected;
        if (step == 2) after.resize(GrowBytes, std::byte{0});
        auto overwrite = BuildPatternPayloadForTest(72 * Block + 13, 0x97);
        if (step == 3) std::copy(overwrite.begin(), overwrite.end(), after.begin() + 31);
        unsigned faults = 0;
        if (interrupt == step) c.metadata_store->SetCommitStageHook([&](std::string_view stage) {
            if (stage != "before-apple-publish") return true;
            ++faults; return false;
        });
        ULONG done = 999;
        const auto status = step == 2 ? CB_SetFileSize(&fs, writer, GrowBytes, FALSE, &info) :
            CB_Write(&fs, writer, step == 1 ? expected.data() : overwrite.data(), step == 1 ? 0 : 31,
                static_cast<ULONG>(step == 1 ? expected.size() : overwrite.size()), FALSE, FALSE, &done, &info);
        std::fprintf(stderr, "[W10] step=%u status=%lx bytes=%lu mutation=%s stage=%s reason=%s\n", step,
            static_cast<unsigned long>(status), done, WideToUtf8(c.metadata_store->LastMutationFailureReason()).c_str(),
            c.metadata_store->LastCommitStage().c_str(), WideToUtf8(c.metadata_store->LastCommitFailureReason()).c_str());
        if (interrupt == step)
        {
            const auto interrupted_status = NT_SUCCESS(status) ? CB_Flush(&fs, writer, &info) : status;
            const auto marks = c.tx_manager->Watermarks();
            const auto journal = c.session_root / "accepted.wal";
            std::vector<Tx::AcceptedTransaction> accepted;
            std::fprintf(stderr, "[W10] interrupted flush=%lx faults=%u accepted=%llu durable=%llu\n",
                static_cast<unsigned long>(interrupted_status), faults, marks.accepted_sequence, marks.apfs_durable_sequence);
            if (!Require(!NT_SUCCESS(interrupted_status) && faults == 1 &&
                    marks.accepted_sequence > marks.apfs_durable_sequence &&
                    c.tx_manager->LoadUnappliedAcceptedTransactions(accepted) && accepted.size() == 1 &&
                    accepted.front().preimage_checkpoint_xid == preimage &&
                    std::any_of(accepted.front().mutations.begin(), accepted.front().mutations.end(), [&](const auto& m) {
                        return m.object_id == 17 && m.parent_object_id != 0 && m.path_utf8 == "\\target" &&
                            m.operation == (step == 2 ? Wal::OperationKind::SetFileSize : Wal::OperationKind::Write);
                    }) && before == ReadFileBytes(fixture.host.image.path),
                    "W10 interrupted callback leaves identity-bound accepted WAL and unchanged preimage")) return false;
            const auto accepted_target = std::find_if(accepted.front().mutations.begin(), accepted.front().mutations.end(),
                [&](const auto& m) { return m.operation == (step == 2 ? Wal::OperationKind::SetFileSize : Wal::OperationKind::Write); });
            const auto accepted_generation = accepted_target->parent_object_id;
            if (!WriteFileBytes(evidence / "interrupted.img", before) ||
                !WriteFileBytes(evidence / "accepted.wal", ReadFileBytes(journal)) ||
                !WriteFileBytes(evidence / "expected.bin", after)) return false;
            std::filesystem::copy(c.session_root / "payload-spool", evidence / "payload-spool",
                std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing);
            c.metadata_store->SetCommitStageHook({});
            CB_Close(&fs, writer); writer = nullptr;
            StopDeferredCommitWorker(&c);
            const auto args = c.args; const auto session = c.session_root;
            const auto cache = c.cache_root;
            fixture.host.context.reset();
            fixture.host.context = std::make_unique<MountContext>();
            auto& r = *fixture.host.context;
            r.args = args; r.native_write_enabled = true;
            r.session_root = session; r.recovery_marker_file = session / "recovery.marker";
            r.cache_root = cache;
            r.owned_metadata_store = std::make_unique<Store>(fixture.host.volume);
            r.metadata_store = r.owned_metadata_store.get();
            r.tx_manager = std::make_unique<Tx>(L"Conservative");
            r.tx_manager->SetVolumeIdentity(L"directory-symlink-volume");
            r.tx_manager->SetJournalPath(journal.wstring());
            r.payload_spool_volume_identity = "directory-symlink-volume";
            r.payload_spool = std::make_unique<apfsaccess::rw::PayloadSpool>(apfsaccess::rw::PayloadSpool::Options{
                session / "payload-spool", r.payload_spool_volume_identity, 1024 * 1024});
            // Match startup's identity-bound providers before replaying accepted bytes.
            r.metadata_store->SetFilePayloadProvider([&r](const auto& path, auto size) {
                return LoadHydratedPayloadForPath(&r, path, size, false);
            });
            r.metadata_store->SetFilePayloadRangeProvider([&r](const auto& path, auto identity, auto offset, auto destination) {
                return ReadHydratedPayloadRangeForPath(&r, path, identity, offset, destination);
            });
            if (!Require(r.metadata_store->PrepareNativeWritePath() &&
                    ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(r),
                    "W10 fresh mounted bootstrap replays accepted fragmented callback")) return false;
            if (!CheckFile(*r.metadata_store, after, fragmented, fixture.blockers)) return false;
            const auto recovered_inode = r.metadata_store->LookupCommittedInodeByPath(L"\\target");
            const auto recovered_marks = r.tx_manager->Watermarks();
            RecoveryMarkerState marker{};
            std::fprintf(stderr, "[W10] recovered identity=%llu/%llu generation=%llu accepted-generation=%llu marks=%llu/%llu/%llu\n",
                recovered_inode ? recovered_inode->object_id : 0, recovered_inode ? recovered_inode->private_id : 0,
                recovered_inode ? recovered_inode->xid : 0, accepted_generation,
                recovered_marks.accepted_sequence, recovered_marks.apfs_durable_sequence, recovered_marks.cleanup_sequence);
            if (!Require(recovered_inode && recovered_inode->object_id == 17 && recovered_inode->private_id == 17 &&
                    recovered_inode->xid == accepted_generation && recovered_marks.accepted_sequence == marks.accepted_sequence &&
                    recovered_marks.apfs_durable_sequence == marks.accepted_sequence &&
                    recovered_marks.cleanup_sequence == marks.accepted_sequence && !r.tx_manager->HasUnappliedAcceptedWork() &&
                    r.tx_manager->CanClearRecoveryState() && TryLoadRecoveryMarkerState(r.recovery_marker_file, marker) &&
                    !marker.dirty && !r.pending_native_writes && !r.recovery_active && !r.write_degraded,
                    "W10 replay finalizes original inode and WAL generation with exact debt-free watermarks and clean marker")) return false;
            const auto stable = ReadFileBytes(fixture.host.image.path);
            if (!WriteFileBytes(evidence / "recovered.img", stable) ||
                !WriteFileBytes(evidence / "recovered.wal", ReadFileBytes(journal))) return false;
            if (!Require(r.tx_manager->Watermarks().apfs_durable_sequence == marks.accepted_sequence &&
                    ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(r) &&
                    stable == ReadFileBytes(fixture.host.image.path), "W10 second replay is byte-idempotent and debt free")) return false;
            Store fresh(fixture.host.volume);
            return Require(fresh.PrepareNativeWritePath(), "W10 independent post-replay reopen") &&
                CheckFile(fresh, after, fragmented, fixture.blockers) && CheckRaw(fixture.host.image.path, after);
        }
        if (!Require(status == STATUS_SUCCESS && (step == 2 || done == (step == 1 ? expected.size() : overwrite.size())) &&
                CB_Flush(&fs, writer, &info) == STATUS_SUCCESS && info.FileSize == after.size() &&
                c.metadata_store->CheckpointXid().value_or(0) > preimage &&
                c.tx_manager->Watermarks().accepted_sequence == c.tx_manager->Watermarks().apfs_durable_sequence &&
                !c.write_degraded && !c.recovery_active,
                "W10 real Write SetFileSize and Flush callbacks publish canonical bytes")) return false;
        expected = std::move(after);
        if (!CheckFile(*c.metadata_store, expected, fragmented, fixture.blockers)) return false;
        Store fresh(fixture.host.volume);
        if (!Require(fresh.PrepareNativeWritePath(), "W10 independent fresh reopen selects canonical checkpoint") ||
            !CheckFile(fresh, expected, fragmented, fixture.blockers) || !CheckRaw(fixture.host.image.path, expected)) return false;
        std::array<std::byte, 7> past{}; past.fill(std::byte{0x5a}); ULONG count = 99;
        std::vector<std::byte> callback(expected.size() + 7, std::byte{0x5a});
        if (!Require(CB_Read(&fs, writer, callback.data(), 0, static_cast<ULONG>(callback.size()), &count) == STATUS_SUCCESS &&
                count == expected.size() && std::equal(expected.begin(), expected.end(), callback.begin()) &&
                CB_Read(&fs, writer, past.data(), expected.size(), static_cast<ULONG>(past.size()), &count) == STATUS_SUCCESS &&
                count == 0 && past == std::array<std::byte, 7>{std::byte{0x5a}, std::byte{0x5a}, std::byte{0x5a},
                    std::byte{0x5a}, std::byte{0x5a}, std::byte{0x5a}, std::byte{0x5a}},
                "W10 mounted Read callback returns exact bytes and EOF without overrunning destination")) return false;
        if (step == 3)
        {
            auto old = expected;
            auto original = BuildPatternPayloadForTest(WriteBytes, 0x73);
            original.resize(GrowBytes, std::byte{0});
            if (!Require(retained.ReadCommittedFileRange(L"\\target", 0, original.size(), old) && old == original,
                    "W10 COW overwrite preserves retained preimage payload bytes")) return false;
        }
        if (!WriteFileBytes(evidence / ("step-" + std::to_string(step) + ".img"), ReadFileBytes(fixture.host.image.path)) ||
            !WriteFileBytes(evidence / ("step-" + std::to_string(step) + "-expected.bin"), expected)) return false;
    }
    return true;
}
}
