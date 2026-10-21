#pragma once
// Include after DeferredAccessTimeTests.h. Root owns registration and execution.

namespace RootDirectoryAccessTimeTests
{
using Store = apfsaccess::rw::MetadataStore;
using Wal = apfsaccess::rw::WriteAheadLog;

bool ReadCleanup(DeferredAccessTimeFixture302& owned, std::uint64_t& time)
{
    auto& c = *owned.fixture.context;
    auto fs = BuildFileSystem(&c);
    PVOID handle = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    if (!Require(CB_Open(&fs, const_cast<PWSTR>(L"\\"), FILE_DIRECTORY_FILE | (FILE_OPEN << 24),
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES, &handle, &info) == STATUS_SUCCESS,
            "directory atime: real root LIST reader opens")) return false;
    ScopeExit close{[&] { CB_Close(&fs, handle); }};
    const auto* o = static_cast<OpenContext*>(handle);
    if (!Require(!o->cached_root_observation && o->allow_list_directory && o->allow_read_data &&
            !o->allow_write_data && !o->allow_append_data && o->node->object_id == 2,
            "directory atime: LIST reader exercises ordinary root Cleanup, outside the observation shortcut")) return false;
    CB_Cleanup(&fs, handle, nullptr, FspCleanupSetLastAccessTime);
    if (!Require(CB_GetFileInfo(&fs, handle, &info) == STATUS_SUCCESS && o->cleanup_seen,
            "directory atime: Cleanup retires reader accounting and exposes its timestamp")) return false;
    time = info.LastAccessTime;
    return true;
}

bool CheckFresh(DeferredAccessTimeFixture302& owned, const Store::InodeRecord& before,
    std::uint64_t time, const std::vector<std::byte>& payload)
{
    Store fresh(owned.fixture.volume);
    if (!Require(fresh.PrepareNativeWritePath(), "directory atime: fresh canonical reopen succeeds")) return false;
    const auto root = fresh.LookupCommittedInodeByPath(L"\\");
    const auto file = fresh.LookupCommittedInodeByPath(L"\\read18");
    std::vector<std::byte> actual;
    const auto acl = file ? fresh.LookupCommittedExtendedAttribute(file->object_id, kAppleSecurityName) : std::nullopt;
    return Require(root && root->object_id == before.object_id && root->is_directory &&
        root->access_time_utc == time && root->create_time_utc == before.create_time_utc &&
        root->modification_time_utc == before.modification_time_utc && root->change_time_utc == before.change_time_utc &&
        root->owner == before.owner && root->group == before.group && root->mode == before.mode &&
        file && file->object_id == 18 && file->owner == 501 && file->group == 20 && file->mode == 0100640 &&
        fresh.ReadCommittedFileRange(L"\\read18", 0, payload.size(), actual) && actual == payload &&
        acl && acl->data == owned.acl,
        "directory atime: exact root time, other root times, Mac permissions, file payload and ACL survive reopen");
}

bool OpenWriter(FSP_FILE_SYSTEM& fs, PVOID& writer, bool write_payload)
{
    FSP_FSCTL_FILE_INFO info{};
    if (!Require(CB_Open(&fs, const_cast<PWSTR>(L"\\read18"), FILE_NON_DIRECTORY_FILE | (FILE_OPEN << 24),
            FILE_WRITE_DATA | FILE_READ_ATTRIBUTES, &writer, &info) == STATUS_SUCCESS,
            "directory atime: unrelated file writer opens")) return false;
    if (!write_payload) return true;
    std::byte value{0x73};
    ULONG done = 0;
    return Require(CB_Write(&fs, writer, &value, 0, 1, FALSE, FALSE, &done, &info) == STATUS_SUCCESS && done == 1,
        "directory atime: unrelated writer stages a real payload mutation");
}
}

bool TestRootDirectoryAccessTimeIsolation(bool manifest, bool pending)
{
    using namespace RootDirectoryAccessTimeTests;
    if (!DeferredAccessTimeScratch302()) return false;
    DeferredAccessTimeFixture302 owned(manifest);
    if (!owned.Initialize(manifest)) return false;
    auto& c = *owned.fixture.context;
    c.args.write_max_dirty_transactions = 128;
    auto fs = BuildFileSystem(&c);
    PVOID writer = nullptr;
    ScopeExit close{[&] { if (writer) CB_Close(&fs, writer); }};
    if (!OpenWriter(fs, writer, pending)) return false;
    const auto before = c.metadata_store->LookupCommittedInodeByPath(L"\\");
    if (!Require(before && HasOpenWriteHandles(&c) && HasPendingNativeMutations(&c) == pending,
            "directory atime: writer and requested older pending state are real")) return false;
    const auto image = ReadFileBytes(owned.fixture.image.path);
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    const auto pending_count = c.metadata_store->PendingMutationCount();
    const auto queued_count = ManifestQueuedRequestCount(&c);
    const auto marks = c.tx_manager->Watermarks();
    const auto* tx = c.tx_manager.get();
    const auto* spool = c.payload_spool.get();
    const auto source = c.args.device;
    const auto identity = c.payload_spool_volume_identity;
    std::vector<Wal::ReadResult> publications;
    std::vector<std::uint64_t> preimages;
    c.metadata_store->SetCommitStageHook([&](std::string_view stage) {
        if (stage == "before-apple-publish")
        {
            publications.push_back(Wal::ReadAll(c.session_root / "accepted.wal", identity));
            preimages.push_back(c.metadata_store->CheckpointXid().value_or(0));
        }
        return true;
    });
    ScopeExit clear{[&] { c.metadata_store->SetCommitStageHook({}); }};
    std::uint64_t time = 0;
    if (!ReadCleanup(owned, time)) return false;
    const auto entry = c.deferred_access_times.find(2);
    if (!Require(publications.empty() && c.deferred_access_times.size() == 1 &&
            entry != c.deferred_access_times.end() && entry->second.node->object_id == 2 &&
            entry->second.owner == entry->second.node->shared_payload && entry->second.time == time &&
            time > before->access_time_utc && HasOpenWriteHandles(&c) && HasPendingNativeMutations(&c) == pending &&
            c.metadata_store->PendingMutationCount() == pending_count && ManifestQueuedRequestCount(&c) == queued_count &&
            c.tx_manager->Watermarks().accepted_sequence == marks.accepted_sequence &&
            c.tx_manager.get() == tx && c.payload_spool.get() == spool && c.args.device == source &&
            c.payload_spool_volume_identity == identity && image == ReadFileBytes(owned.fixture.image.path) &&
            wal == ReadFileBytes(c.session_root / "accepted.wal"),
            "directory atime: root Cleanup and Close queue inode 2 without publication, WAL changes or draining an active writer"))
        return false;
    if (!Require(CB_Flush(&fs, nullptr, nullptr) == STATUS_SUCCESS && HasOpenWriteHandles(&c) &&
            publications.size() == (pending ? 2u : 1u) && c.deferred_access_times.empty(),
            "directory atime: Flush publishes older payload separately, then root atime, while writer remains open")) return false;
    for (std::size_t i = 0; i != publications.size(); ++i)
    {
        const auto& persisted = publications[i];
        const Wal::Record* marker = nullptr;
        for (const auto& record : persisted.records)
            if (record.operation == Wal::OperationKind::TransactionMarker) marker = &record;
        bool root_atime = false, payload_write = false;
        std::size_t count = 0;
        if (marker) for (const auto& record : persisted.records)
        {
            if (record.transaction_id != marker->transaction_id || &record == marker) continue;
            ++count;
            if (record.object_id == 2)
            {
                apfsaccess::rw::InodeMetadataPatch patch;
                root_atime = record.operation == Wal::OperationKind::SetInodeMetadata &&
                    apfsaccess::rw::DecodeInodeMetadataPatch(record.inline_payload, patch) &&
                    patch.mask == apfsaccess::rw::InodeMetadataPatch::AccessTime && patch.access_time_utc == time;
            }
            payload_write |= record.object_id == 18 && record.operation == Wal::OperationKind::Write;
        }
        const bool older = pending && i == 0;
        if (!Require(persisted.status == Wal::ReadStatus::Ok && !persisted.recovered_torn_tail && marker &&
                marker->state == Wal::RecordState::Accepted && marker->object_id == preimages[i] &&
                preimages[i] != 0 && marker->logical_length == count &&
                (older ? payload_write && !root_atime : root_atime && !payload_write && count == 1) &&
                (i == 0 || preimages[i] > preimages[i - 1]),
                "directory atime: WAL binds separate older-data and metadata-only atime transactions to their own preimages"))
            return false;
    }
    auto payload = owned.bytes;
    if (pending) payload[0] = std::byte{0x73};
    return CheckFresh(owned, *before, time, payload);
}

bool TestRootDirectoryAccessTimeOrdering(bool manifest)
{
    using namespace RootDirectoryAccessTimeTests;
    if (!DeferredAccessTimeScratch302()) return false;
    DeferredAccessTimeFixture302 owned(manifest);
    if (!owned.Initialize(manifest)) return false;
    auto& c = *owned.fixture.context;
    const auto before = c.metadata_store->LookupCommittedInodeByPath(L"\\");
    if (!before) return false;
    std::uint64_t automatic = 0;
    if (!ReadCleanup(owned, automatic)) return false;
    auto fs = BuildFileSystem(&c);
    PVOID editor = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    if (CB_Open(&fs, const_cast<PWSTR>(L"\\"), FILE_DIRECTORY_FILE | (FILE_OPEN << 24),
            FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES, &editor, &info) != STATUS_SUCCESS) return false;
    ScopeExit close{[&] { if (editor) CB_Close(&fs, editor); }};
    constexpr std::uint64_t backward = 116444736000000000ULL + 16000000000000000ULL;
    if (!Require(backward < automatic && CB_SetBasicInfo(&fs, editor, INVALID_FILE_ATTRIBUTES,
            0, backward, 0, 0, &info) == STATUS_SUCCESS && info.LastAccessTime == backward &&
            c.deferred_access_times.empty(),
            "directory atime: explicit backward root timestamp drains and supersedes the older automatic time")) return false;
    CB_Cleanup(&fs, editor, nullptr, FspCleanupSetLastAccessTime);
    CB_Close(&fs, editor); editor = nullptr;
    if (!Require(CB_Flush(&fs, nullptr, nullptr) == STATUS_SUCCESS,
            "directory atime: explicit root timestamp persists at Flush") ||
        !CheckFresh(owned, *before, backward, owned.bytes)) return false;
    std::uint64_t later = 0;
    if (!ReadCleanup(owned, later) ||
        !Require(later > backward && RunFsHostShutdownDrain(owned.fixture.context) == 0,
            "directory atime: a later LIST access supersedes explicit time and persists through Quit")) return false;
    return CheckFresh(owned, *before, later, owned.bytes);
}

bool TestRootDirectoryAccessTimeWorker(bool manifest)
{
    using namespace RootDirectoryAccessTimeTests;
    if (!DeferredAccessTimeScratch302()) return false;
    DeferredAccessTimeFixture302 owned(manifest);
    if (!owned.Initialize(manifest)) return false;
    auto& c = *owned.fixture.context;
    c.args.write_max_dirty_transactions = 128;
    auto fs = BuildFileSystem(&c);
    PVOID writer = nullptr;
    ScopeExit close{[&] { if (writer) CB_Close(&fs, writer); }};
    if (!OpenWriter(fs, writer, true) || !Require(HasPendingNativeMutations(&c),
            "directory atime: worker starts with a real older payload transaction")) return false;
    const auto before = c.metadata_store->LookupCommittedInodeByPath(L"\\");
    if (!before) return false;
    unsigned publications = 0;
    c.metadata_store->SetCommitStageHook([&](std::string_view stage) {
        if (stage == "after-apple-publish") ++publications;
        return true;
    });
    ScopeExit stop{[&] { StopDeferredCommitWorker(&c); c.metadata_store->SetCommitStageHook({}); }};
    std::uint64_t time = 0;
    if (!ReadCleanup(owned, time)) return false;
    std::chrono::steady_clock::time_point first;
    {
        std::lock_guard<std::mutex> schedule(c.deferred_commit_mutex);
        first = c.deferred_access_time_first = std::chrono::steady_clock::now() - kDeferredAccessTimeMaximumDelay;
        c.deferred_access_time_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    }
    if (!ReadCleanup(owned, time)) return false;
    {
        std::lock_guard<std::mutex> schedule(c.deferred_commit_mutex);
        if (!Require(publications == 0 && c.deferred_access_times.size() == 1 &&
                c.deferred_access_time_requested && c.deferred_access_time_first == first &&
                c.deferred_access_time_deadline <= std::chrono::steady_clock::now(),
                "directory atime: overdue LIST Cleanup keeps original age and wakes worker without inline publication")) return false;
    }
    StartDeferredCommitWorker(&c);
    bool drained = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline)
    {
        {
            std::lock_guard<std::mutex> mutation(c.mutation_callback_mutex);
            drained = c.deferred_access_times.empty();
        }
        if (drained) break;
        Sleep(5);
    }
    if (!Require(StopDeferredCommitWorker(&c) && drained && publications == 2 && HasOpenWriteHandles(&c) &&
            !c.deferred_access_time_requested && !c.write_degraded,
            "directory atime: bounded worker persists overdue root atime despite the still-open unrelated writer")) return false;
    auto payload = owned.bytes;
    payload[0] = std::byte{0x73};
    return CheckFresh(owned, *before, time, payload);
}

bool TestRootDirectoryAccessTimePressure()
{
    using namespace RootDirectoryAccessTimeTests;
    if (!DeferredAccessTimeScratch302()) return false;
    DeferredAccessTimeFixture302 owned(true);
    if (!owned.Initialize(true, kDeferredAccessTimeMaxInodes + 4)) return false;
    auto& c = *owned.fixture.context;
    const auto before = c.metadata_store->LookupCommittedInodeByPath(L"\\");
    if (!before) return false;
    std::map<std::wstring, std::uint64_t> expected;
    const auto projected = c.metadata_store->SnapshotCommittedInodes();
    // Fill the cap deterministically from real projected inode identities. Only
    // the pressure setup is direct; root admission and both drains are callbacks.
    {
        std::lock_guard<std::mutex> names(c.mutex);
        const auto time = ToFileTimeValue(UtcNow());
        for (const auto& inode : projected)
        {
            if (inode.node_type != Store::NodeType::RegularFile || !inode.object_id ||
                c.deferred_access_times.contains(inode.object_id)) continue;
            const auto node = TryGetNodeLockedNormalized(&c, inode.full_path);
            if (!Require(node && node->node_kind == NodeKind::RegularFile && node->object_id == inode.object_id,
                    "directory atime: cap uses actual projected regular inode identities")) return false;
            node->deferred_access_time = time;
            if (node->shared_payload) node->shared_payload->deferred_access_time.store(time);
            c.deferred_access_times.emplace(node->object_id, MountContext::DeferredAccessTime{node, node->shared_payload, time});
            expected[inode.full_path] = time;
            if (c.deferred_access_times.size() == kDeferredAccessTimeMaxInodes) break;
        }
        if (!Require(c.deferred_access_times.size() == kDeferredAccessTimeMaxInodes,
                "directory atime: pressure setup fills exactly 512 distinct projected regular inodes")) return false;
    }
    const auto image = ReadFileBytes(owned.fixture.image.path);
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    unsigned publications = 0;
    c.metadata_store->SetCommitStageHook([&](std::string_view stage) {
        if (stage == "before-apple-publish") ++publications;
        return true;
    });
    ScopeExit clear{[&] { c.metadata_store->SetCommitStageHook({}); }};
    std::uint64_t time = 0;
    if (!ReadCleanup(owned, time)) return false;
    if (!Require(publications == 0 && c.deferred_access_times.size() == kDeferredAccessTimeMaxInodes &&
            !c.deferred_access_times.contains(2) && c.deferred_access_time_overflow && c.deferred_access_time_requested &&
            c.deferred_access_time_deadline <= std::chrono::steady_clock::now() &&
            image == ReadFileBytes(owned.fixture.image.path) && wal == ReadFileBytes(c.session_root / "accepted.wal"),
            "directory atime: full 512-entry queue retains root spill on its indexed node and schedules without inline drain"))
        return false;
    auto fs = BuildFileSystem(&c);
    if (!Require(CB_Flush(&fs, nullptr, nullptr) == STATUS_SUCCESS && publications == 2 &&
            c.deferred_access_times.empty() && !c.deferred_access_time_overflow && !c.deferred_access_time_requested,
            "directory atime: Flush drains the capped batch and retained root spill without dropping either")) return false;
    return CheckFresh(owned, *before, time, owned.bytes) && owned.CheckFresh(expected);
}

bool TestRootDirectoryAccessTimeFailure(bool manifest, bool older_payload, bool after_publication = false)
{
    using namespace RootDirectoryAccessTimeTests;
    if (!DeferredAccessTimeScratch302()) return false;
    DeferredAccessTimeFixture302 owned(manifest);
    if (!owned.Initialize(manifest)) return false;
    auto& c = *owned.fixture.context;
    c.args.write_max_dirty_transactions = 128;
    auto fs = BuildFileSystem(&c);
    PVOID writer = nullptr;
    ScopeExit close{[&] { if (writer) CB_Close(&fs, writer); }};
    if (older_payload && (!OpenWriter(fs, writer, true) || !HasPendingNativeMutations(&c))) return false;
    const auto before = c.metadata_store->LookupCommittedInodeByPath(L"\\");
    if (!before) return false;
    std::uint64_t time = 0;
    if (!ReadCleanup(owned, time)) return false;
    const auto image = ReadFileBytes(owned.fixture.image.path);
    unsigned failures = 0;
    c.metadata_store->SetCommitStageHook([&](std::string_view stage) {
        if (stage != (after_publication ? "after-apple-publish" : "before-apple-publish")) return true;
        ++failures;
        return false;
    });
    ScopeExit clear{[&] { c.metadata_store->SetCommitStageHook({}); }};
    const auto status = CB_Flush(&fs, nullptr, nullptr);
    const auto marks = c.tx_manager->Watermarks();
    const auto persisted = Wal::ReadAll(c.session_root / "accepted.wal", c.payload_spool_volume_identity);
    bool exact_root = false, payload_write = false;
    for (const auto& record : persisted.records)
    {
        apfsaccess::rw::InodeMetadataPatch patch;
        exact_root |= record.object_id == 2 && record.operation == Wal::OperationKind::SetInodeMetadata &&
            apfsaccess::rw::DecodeInodeMetadataPatch(record.inline_payload, patch) &&
            patch.mask == apfsaccess::rw::InodeMetadataPatch::AccessTime && patch.access_time_utc == time;
        payload_write |= record.object_id == 18 && record.operation == Wal::OperationKind::Write;
    }
    if (!Require(!NT_SUCCESS(status) && failures == 1 && c.write_degraded &&
            c.deferred_access_times.size() == 1 && c.deferred_access_times.at(2).time == time &&
            c.deferred_access_times.at(2).node->deferred_access_time == time &&
            persisted.status == Wal::ReadStatus::Ok && !persisted.recovered_torn_tail &&
            exact_root == !older_payload && payload_write == older_payload &&
            marks.accepted_sequence > marks.apfs_durable_sequence && marks.accepted_sequence > marks.cleanup_sequence &&
            std::filesystem::exists(c.recovery_marker_file) &&
            (after_publication || image == ReadFileBytes(owned.fixture.image.path)),
            "directory atime: failure keeps root debt, exact older-or-atime WAL, recovery marker and honest watermarks")) return false;
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    if (writer) { CB_Close(&fs, writer); writer = nullptr; }
    return Require(RunFsHostShutdownDrain(owned.fixture.context) != 0 &&
        wal == ReadFileBytes(c.session_root / "accepted.wal") && c.deferred_access_times.at(2).time == time &&
        c.tx_manager->Watermarks().apfs_durable_sequence == marks.apfs_durable_sequence &&
        c.tx_manager->Watermarks().cleanup_sequence == marks.cleanup_sequence,
        "directory atime: failed Quit retains accepted WAL and root debt without false persistence");
}

bool TestRootDirectoryAccessTimeRetry()
{
    using namespace RootDirectoryAccessTimeTests;
    if (!DeferredAccessTimeScratch302()) return false;
    DeferredAccessTimeFixture302 owned(true);
    if (!owned.Initialize(true)) return false;
    auto& c = *owned.fixture.context;
    const auto before = c.metadata_store->LookupCommittedInodeByPath(L"\\");
    if (!before) return false;
    std::uint64_t time = 0;
    if (!ReadCleanup(owned, time)) return false;
    owned.sibling.args = ManifestSessionArgs(owned.fixture.image.path, 102,
        Utf8ToWide(owned.fixture.coordinator->ContainerUuidHex()), L"directory-atime-retry", true);
    owned.sibling.args.write_require_canonical_commit = true;
    owned.sibling.args.allow_legacy_scaffold_for_fixtures = false;
    std::wstring error;
    if (!MountManifestSession(*owned.fixture.coordinator, owned.sibling.args, owned.sibling, error) ||
        !CompressionManifestRefusal279::SeedAcceptedSibling(owned)) return false;
    const auto image = ReadFileBytes(owned.fixture.image.path);
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    auto fs = BuildFileSystem(&c);
    for (unsigned attempt = 0; attempt != 2; ++attempt)
        if (!Require(CB_Flush(&fs, nullptr, nullptr) == STATUS_DEVICE_BUSY && !c.write_degraded &&
                c.deferred_access_times.size() == 1 && c.deferred_access_times.at(2).time == time &&
                c.deferred_access_time_requested && c.tx_manager->Watermarks().accepted_sequence == 0 &&
                image == ReadFileBytes(owned.fixture.image.path) && wal == ReadFileBytes(c.session_root / "accepted.wal"),
                "directory atime: genuine sibling refusal preserves exact root debt and scheduling across retries")) return false;
    if (!owned.ReplaySibling() || !Require(CB_Flush(&fs, nullptr, nullptr) == STATUS_SUCCESS &&
            c.deferred_access_times.empty() && !c.deferred_access_time_requested,
            "directory atime: ordinary Flush persists the original retained timestamp after sibling recovery")) return false;
    return CheckFresh(owned, *before, time, owned.bytes);
}

bool TestRootDirectoryAccessTimeIdentity(bool manifest)
{
    using namespace RootDirectoryAccessTimeTests;
    if (!DeferredAccessTimeScratch302()) return false;
    DeferredAccessTimeFixture302 owned(manifest);
    if (!owned.Initialize(manifest)) return false;
    auto& c = *owned.fixture.context;
    std::uint64_t time = 0;
    if (!ReadCleanup(owned, time)) return false;
    const auto image = ReadFileBytes(owned.fixture.image.path);
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    // Simulate a stale queue identity using a different real projected inode.
    // The production namespace callbacks drain before replacing any identity.
    {
        std::lock_guard<std::mutex> names(c.mutex);
        c.deferred_access_times.at(2).node = TryGetNodeLockedNormalized(&c, L"\\read18");
    }
    auto fs = BuildFileSystem(&c);
    return Require(!NT_SUCCESS(CB_Flush(&fs, nullptr, nullptr)) && c.write_degraded &&
        c.deferred_access_times.size() == 1 && c.deferred_access_times.at(2).time == time &&
        c.tx_manager->Watermarks().accepted_sequence == 0 &&
        image == ReadFileBytes(owned.fixture.image.path) && wal == ReadFileBytes(c.session_root / "accepted.wal"),
        "directory atime: stale identity retains debt and cannot publish root time onto an unrelated file");
}
