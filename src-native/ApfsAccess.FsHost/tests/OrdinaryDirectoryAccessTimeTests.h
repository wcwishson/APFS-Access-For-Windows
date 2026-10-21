#pragma once

namespace OrdinaryDirectoryAccessTimeTests
{
using Store = apfsaccess::rw::MetadataStore;
using Wal = apfsaccess::rw::WriteAheadLog;
constexpr std::uint64_t SeedTime = 116444736000000000ULL + 16000000000000000ULL;
const std::wstring Parent = L"\\list-parent", Child = Parent + L"\\child";

bool CreateDirectory(DeferredAccessTimeFixture302& owned, const std::wstring& path,
    std::uint64_t time = SeedTime)
{
    auto fs = BuildFileSystem(owned.fixture.context.get());
    PVOID handle = nullptr; FSP_FSCTL_FILE_INFO info{};
    if (!Require(CB_Create(&fs, const_cast<PWSTR>(path.c_str()), FILE_DIRECTORY_FILE,
            FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | DELETE,
            FILE_ATTRIBUTE_DIRECTORY, nullptr, 0, &handle, &info) == STATUS_SUCCESS && handle,
            "subdirectory atime: real Create authors an ordinary directory")) return false;
    ScopeExit close{[&] { CB_Close(&fs, handle); }};
    if (!Require(CB_SetBasicInfo(&fs, handle, INVALID_FILE_ATTRIBUTES, 0, time, 0, 0, &info) == STATUS_SUCCESS &&
            CB_Flush(&fs, handle, &info) == STATUS_SUCCESS,
            "subdirectory atime: exact seed time is durably authored through callbacks")) return false;
    CB_Cleanup(&fs, handle, nullptr, 0);
    return true;
}

bool Initialize(DeferredAccessTimeFixture302& owned, bool manifest, std::uint64_t count = 3)
{
    return DeferredAccessTimeScratch302() && owned.Initialize(manifest, count) &&
        CreateDirectory(owned, Parent) && CreateDirectory(owned, Child);
}

bool ReadCleanup(DeferredAccessTimeFixture302& owned, std::uint64_t& time,
    const std::wstring& path = Child)
{
    auto& c = *owned.fixture.context; auto fs = BuildFileSystem(&c);
    PVOID handle = nullptr; FSP_FSCTL_FILE_INFO info{};
    if (!Require(CB_Open(&fs, const_cast<PWSTR>(path.c_str()), FILE_DIRECTORY_FILE | (FILE_OPEN << 24),
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES, &handle, &info) == STATUS_SUCCESS && handle,
            "subdirectory atime: ordinary non-root LIST reader opens")) return false;
    ScopeExit close{[&] { CB_Close(&fs, handle); }};
    const auto* open = static_cast<OpenContext*>(handle);
    if (!Require(!open->cached_root_observation && open->node->object_id != 2 &&
            open->node->node_kind == NodeKind::Directory && open->allow_read_data &&
            open->allow_list_directory && !open->allow_write_data && !open->allow_append_data,
            "subdirectory atime: real directory identity stays outside the cached-root bypass")) return false;
    struct Listing { unsigned entries = 0; bool eof = false; } listing_output;
    const auto add_dir = c.api.AddDir;
    ScopeExit restore_listing{[&] { c.api.AddDir = add_dir; }};
    c.api.AddDir = [](FSP_FSCTL_DIR_INFO* entry, PVOID buffer, ULONG, PULONG transferred) -> BOOLEAN {
        auto& output = *static_cast<Listing*>(buffer);
        if (entry) { ++output.entries; *transferred += entry->Size; } else output.eof = true;
        return TRUE;
    };
    ULONG transferred = 0;
    const auto listing = CB_ReadDirectory(&fs, handle, nullptr, nullptr, &listing_output, 4096, &transferred);
    if (!Require((NT_SUCCESS(listing) || listing == STATUS_NO_MORE_FILES) && listing_output.eof,
            "subdirectory atime: actual directory enumeration completes")) return false;
    CB_Cleanup(&fs, handle, nullptr, FspCleanupSetLastAccessTime);
    if (!Require(CB_GetFileInfo(&fs, handle, &info) == STATUS_SUCCESS && open->cleanup_seen,
            "subdirectory atime: Cleanup immediately exposes its exact timestamp")) return false;
    time = info.LastAccessTime;
    return true;
}

bool Fresh(DeferredAccessTimeFixture302& owned, const Store::InodeRecord& before,
    const std::wstring& path, std::uint64_t time, bool other_times = true, bool pending = false)
{
    Store fresh(owned.fixture.volume);
    if (!Require(fresh.PrepareNativeWritePath(), "subdirectory atime: fresh canonical image reopens")) return false;
    const auto dir = fresh.LookupCommittedInodeByPath(path), file = fresh.LookupCommittedInodeByPath(L"\\read18");
    auto expected = owned.bytes; if (pending) expected[0] = std::byte{0x73};
    std::vector<std::byte> bytes;
    const auto acl = file ? fresh.LookupCommittedExtendedAttribute(file->object_id, kAppleSecurityName) : std::nullopt;
    return Require(dir && dir->is_directory && dir->object_id == before.object_id && dir->access_time_utc == time &&
        (!other_times || (dir->create_time_utc == before.create_time_utc &&
            dir->modification_time_utc == before.modification_time_utc && dir->change_time_utc == before.change_time_utc)) &&
        dir->owner == before.owner && dir->group == before.group && dir->mode == before.mode &&
        file && file->object_id == 18 && file->owner == 501 && file->group == 20 && file->mode == 0100640 &&
        fresh.ReadCommittedFileRange(L"\\read18", 0, expected.size(), bytes) && bytes == expected && acl && acl->data == owned.acl,
        "subdirectory atime: exact directory identity/time, permissions and unrelated payload/ACL survive fresh reopen");
}

bool CleanupAndFlush(bool manifest, unsigned writer_state)
{
    DeferredAccessTimeFixture302 owned(manifest);
    if (!Initialize(owned, manifest)) return false;
    auto& c = *owned.fixture.context; c.args.write_max_dirty_transactions = 128;
    auto fs = BuildFileSystem(&c); PVOID writer = nullptr;
    ScopeExit close{[&] { if (writer) CB_Close(&fs, writer); }};
    if (writer_state && !RootDirectoryAccessTimeTests::OpenWriter(fs, writer, writer_state == 2)) return false;
    const auto before = c.metadata_store->LookupCommittedInodeByPath(Child); if (!before) return false;
    const auto image = ReadFileBytes(owned.fixture.image.path), wal = ReadFileBytes(c.session_root / "accepted.wal");
    const auto marks = c.tx_manager->Watermarks();
    const auto pending = c.metadata_store->PendingMutationCount(), queued = ManifestQueuedRequestCount(&c);
    unsigned publications = 0;
    c.metadata_store->SetCommitStageHook([&](std::string_view stage) { if (stage == "before-apple-publish") ++publications; return true; });
    ScopeExit clear{[&] { c.metadata_store->SetCommitStageHook({}); }};
    std::uint64_t time = 0; if (!ReadCleanup(owned, time)) return false;
    const auto entry = c.deferred_access_times.find(before->object_id);
    if (!Require(publications == 0 && c.deferred_access_times.size() == 1 && entry != c.deferred_access_times.end() &&
            entry->second.time == time && entry->second.node->object_id == before->object_id && time > SeedTime &&
            c.metadata_store->PendingMutationCount() == pending && ManifestQueuedRequestCount(&c) == queued &&
            c.tx_manager->Watermarks().accepted_sequence == marks.accepted_sequence &&
            image == ReadFileBytes(owned.fixture.image.path) && wal == ReadFileBytes(c.session_root / "accepted.wal"),
            "subdirectory atime: Cleanup and Close queue without caller commit, WAL write or older writer drain")) return false;
    if (!Require(CB_Flush(&fs, nullptr, nullptr) == STATUS_SUCCESS && c.deferred_access_times.empty() &&
            publications == (writer_state == 2 ? 2u : 1u),
            "subdirectory atime: explicit Flush publishes older work separately, then directory atime")) return false;
    return Fresh(owned, *before, Child, time, true, writer_state == 2);
}

bool NamespaceAndIdentity(bool manifest)
{
    DeferredAccessTimeFixture302 owned(manifest); if (!Initialize(owned, manifest)) return false;
    auto& c = *owned.fixture.context; auto fs = BuildFileSystem(&c);
    const auto before = c.metadata_store->LookupCommittedInodeByPath(Child); if (!before) return false;
    std::uint64_t time = 0; if (!ReadCleanup(owned, time)) return false;
    const std::wstring renamed_parent = L"\\renamed-parent", renamed_child = renamed_parent + L"\\child";
    if (!Require(CB_Rename(&fs, nullptr, const_cast<PWSTR>(Parent.c_str()), const_cast<PWSTR>(renamed_parent.c_str()), FALSE) == STATUS_SUCCESS &&
            CB_Flush(&fs, nullptr, nullptr) == STATUS_SUCCESS && c.deferred_access_times.empty(),
            "subdirectory atime: ancestor rename drains queued child identity before moving its path") ||
        !Fresh(owned, *before, renamed_child, time, false)) return false;
    const std::wstring moved = renamed_parent + L"\\moved";
    if (!ReadCleanup(owned, time, renamed_child) ||
        !Require(CB_Rename(&fs, nullptr, const_cast<PWSTR>(renamed_child.c_str()), const_cast<PWSTR>(moved.c_str()), FALSE) == STATUS_SUCCESS &&
            CB_Flush(&fs, nullptr, nullptr) == STATUS_SUCCESS && c.deferred_access_times.empty(),
            "subdirectory atime: direct directory rename drains old path before publication") ||
        !Fresh(owned, *before, moved, time, false)) return false;
    if (!ReadCleanup(owned, time, moved)) return false;
    PVOID deleting = nullptr; FSP_FSCTL_FILE_INFO info{};
    if (CB_Open(&fs, const_cast<PWSTR>(moved.c_str()), FILE_DIRECTORY_FILE | (FILE_OPEN << 24),
            DELETE | FILE_READ_ATTRIBUTES, &deleting, &info) != STATUS_SUCCESS) return false;
    const auto status = CB_SetDelete(&fs, deleting, nullptr, TRUE);
    if (NT_SUCCESS(status)) CB_Cleanup(&fs, deleting, nullptr, FspCleanupDelete);
    CB_Close(&fs, deleting);
    if (!Require(status == STATUS_SUCCESS && CB_Flush(&fs, nullptr, nullptr) == STATUS_SUCCESS &&
            c.deferred_access_times.empty() && !c.metadata_store->LookupCommittedInodeByPath(moved),
            "subdirectory atime: deletion drains old identity and removes the empty directory")) return false;
    constexpr auto replacement_time = SeedTime + 10000000;
    if (!CreateDirectory(owned, moved, replacement_time)) return false;
    Store fresh(owned.fixture.volume); if (!fresh.PrepareNativeWritePath()) return false;
    const auto replacement = fresh.LookupCommittedInodeByPath(moved);
    return Require(replacement && replacement->is_directory && replacement->object_id != before->object_id &&
        replacement->access_time_utc == replacement_time && replacement->access_time_utc != time &&
        !c.deferred_access_times.contains(before->object_id),
        "subdirectory atime: recreated path has a distinct inode and cannot inherit deleted directory atime");
}

bool ExplicitAndShutdown(bool manifest)
{
    DeferredAccessTimeFixture302 owned(manifest); if (!Initialize(owned, manifest)) return false;
    auto& c = *owned.fixture.context; auto fs = BuildFileSystem(&c);
    const auto before = c.metadata_store->LookupCommittedInodeByPath(Child); if (!before) return false;
    std::uint64_t time = 0; if (!ReadCleanup(owned, time)) return false;
    PVOID editor = nullptr; FSP_FSCTL_FILE_INFO info{};
    if (CB_Open(&fs, const_cast<PWSTR>(Child.c_str()), FILE_DIRECTORY_FILE | (FILE_OPEN << 24),
            FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES, &editor, &info) != STATUS_SUCCESS) return false;
    const auto status = CB_SetBasicInfo(&fs, editor, INVALID_FILE_ATTRIBUTES, 0, SeedTime, 0, 0, &info);
    CB_Cleanup(&fs, editor, nullptr, FspCleanupSetLastAccessTime); CB_Close(&fs, editor);
    if (!Require(status == STATUS_SUCCESS && c.deferred_access_times.empty() && CB_Flush(&fs, nullptr, nullptr) == STATUS_SUCCESS,
            "subdirectory atime: explicit backward timestamp supersedes queued automatic access") ||
        !Fresh(owned, *before, Child, SeedTime)) return false;
    if (!ReadCleanup(owned, time) || !Require(RunFsHostShutdownDrain(owned.fixture.context) == 0,
            "subdirectory atime: successful shutdown persists admitted directory debt")) return false;
    return Fresh(owned, *before, Child, time);
}

bool MixedWriterAndStream(bool manifest)
{
    DeferredAccessTimeFixture302 owned(manifest); if (!Initialize(owned, manifest)) return false;
    auto& c = *owned.fixture.context; auto fs = BuildFileSystem(&c); PVOID writer = nullptr; FSP_FSCTL_FILE_INFO info{};
    const auto before = c.metadata_store->LookupCommittedInodeByPath(Child); if (!before) return false;
    unsigned publications = 0;
    c.metadata_store->SetCommitStageHook([&](std::string_view stage) { if (stage == "before-apple-publish") ++publications; return true; });
    ScopeExit clear{[&] { c.metadata_store->SetCommitStageHook({}); }};
    if (CB_Open(&fs, const_cast<PWSTR>(Child.c_str()), FILE_DIRECTORY_FILE | (FILE_OPEN << 24),
            FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_READ_ATTRIBUTES, &writer, &info) != STATUS_SUCCESS) return false;
    if (!Require(static_cast<OpenContext*>(writer)->allow_write_data,
            "subdirectory atime: mixed-handle premise includes actual writer access")) { CB_Close(&fs, writer); return false; }
    CB_Cleanup(&fs, writer, nullptr, FspCleanupSetLastAccessTime);
    const bool queued_at_cleanup = !c.deferred_access_times.empty();
    const auto queried = CB_GetFileInfo(&fs, writer, &info); CB_Close(&fs, writer);
    const auto writer_flush = CB_Flush(&fs, nullptr, nullptr);
    if (!Require(queried == STATUS_SUCCESS && !queued_at_cleanup && writer_flush == STATUS_SUCCESS &&
            publications > 0 && c.deferred_access_times.empty() && info.LastAccessTime > SeedTime,
            "subdirectory atime: mixed writer retains its metadata route and persists at explicit Flush")) {
        std::cerr << "[subdirectory mixed] manifest=" << manifest << " queried=" << queried << " queued=" << queued_at_cleanup
            << " flush=" << writer_flush << " publications=" << publications << " time=" << info.LastAccessTime << std::endl;
        return false;
    }
    if (!Fresh(owned, *before, Child, info.LastAccessTime)) return false;
    std::uint64_t time = 0; if (!ReadCleanup(owned, time)) return false;
    const auto directory = c.metadata_store->LookupCommittedInodeByPath(Child); if (!directory) return false;
    auto stream_path = Child + NativeXattrStreamName("user.directory-atime"); PVOID stream = nullptr;
    if (!Require(CB_Create(&fs, stream_path.data(), FILE_NON_DIRECTORY_FILE, GENERIC_ALL, 0, nullptr, 0, &stream, &info) == STATUS_SUCCESS,
            "subdirectory atime: actual directory named-stream creation retains its old route")) return false;
    const auto value = BuildPatternPayloadForTest(19, 0x61); ULONG written = 0;
    const auto write = CB_Write(&fs, stream, const_cast<std::byte*>(value.data()), 0, static_cast<ULONG>(value.size()), FALSE, FALSE, &written, &info);
    const auto flush = CB_Flush(&fs, stream, &info);
    CB_Cleanup(&fs, stream, nullptr, FspCleanupSetLastAccessTime); CB_Close(&fs, stream);
    if (!Require(write == STATUS_SUCCESS && written == value.size() && flush == STATUS_SUCCESS && c.deferred_access_times.empty(),
            "subdirectory atime: stream mutation drains the prior base timestamp but stream Cleanup adds no directory debt")) return false;
    Store fresh(owned.fixture.volume); if (!fresh.PrepareNativeWritePath()) return false;
    const auto saved = fresh.LookupCommittedExtendedAttribute(directory->object_id, "user.directory-atime");
    const auto dir = fresh.LookupCommittedInodeByPath(Child);
    return Require(saved && saved->data == value && dir && dir->object_id == directory->object_id && dir->access_time_utc == time,
        "subdirectory atime: fresh reopen preserves exact named-stream bytes and base directory timestamp");
}

bool Failure(bool manifest, bool after_publication)
{
    DeferredAccessTimeFixture302 owned(manifest); if (!Initialize(owned, manifest)) return false;
    auto& c = *owned.fixture.context; auto fs = BuildFileSystem(&c);
    const auto dir = c.metadata_store->LookupCommittedInodeByPath(Child); if (!dir) return false;
    std::uint64_t time = 0; if (!ReadCleanup(owned, time)) return false;
    const auto image = ReadFileBytes(owned.fixture.image.path); unsigned failures = 0;
    c.metadata_store->SetCommitStageHook([&](std::string_view stage) {
        if (stage != (after_publication ? "after-apple-publish" : "before-apple-publish")) return true;
        ++failures; return false;
    });
    ScopeExit clear{[&] { c.metadata_store->SetCommitStageHook({}); }};
    const auto status = CB_Flush(&fs, nullptr, nullptr);
    const auto marks = c.tx_manager->Watermarks();
    const auto persisted = Wal::ReadAll(c.session_root / "accepted.wal", c.payload_spool_volume_identity);
    bool exact = false;
    for (const auto& record : persisted.records) {
        apfsaccess::rw::InodeMetadataPatch patch;
        exact |= record.object_id == dir->object_id && record.operation == Wal::OperationKind::SetInodeMetadata &&
            apfsaccess::rw::DecodeInodeMetadataPatch(record.inline_payload, patch) &&
            patch.mask == apfsaccess::rw::InodeMetadataPatch::AccessTime && patch.access_time_utc == time;
    }
    if (!Require(!NT_SUCCESS(status) && failures == 1 && c.write_degraded && exact &&
            persisted.status == Wal::ReadStatus::Ok && !persisted.recovered_torn_tail &&
            c.deferred_access_times.at(dir->object_id).time == time &&
            marks.accepted_sequence > marks.apfs_durable_sequence && marks.accepted_sequence > marks.cleanup_sequence &&
            std::filesystem::exists(c.recovery_marker_file) && (after_publication || image == ReadFileBytes(owned.fixture.image.path)),
            "subdirectory atime: failed publication retains exact accepted WAL, directory identity/debt and honest watermarks")) return false;
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    return Require(RunFsHostShutdownDrain(owned.fixture.context) != 0 && wal == ReadFileBytes(c.session_root / "accepted.wal") &&
        c.deferred_access_times.at(dir->object_id).time == time &&
        c.tx_manager->Watermarks().apfs_durable_sequence == marks.apfs_durable_sequence &&
        c.tx_manager->Watermarks().cleanup_sequence == marks.cleanup_sequence,
        "subdirectory atime: failed shutdown cannot erase accepted ownership or claim cleanup");
}

bool Retry()
{
    DeferredAccessTimeFixture302 owned(true); if (!Initialize(owned, true)) return false;
    auto& c = *owned.fixture.context; auto fs = BuildFileSystem(&c);
    const auto dir = c.metadata_store->LookupCommittedInodeByPath(Child); if (!dir) return false;
    std::uint64_t time = 0; if (!ReadCleanup(owned, time)) return false;
    owned.sibling.args = ManifestSessionArgs(owned.fixture.image.path, 102,
        Utf8ToWide(owned.fixture.coordinator->ContainerUuidHex()), L"subdirectory-atime-retry", true);
    owned.sibling.args.write_require_canonical_commit = true; owned.sibling.args.allow_legacy_scaffold_for_fixtures = false;
    std::wstring error;
    if (!MountManifestSession(*owned.fixture.coordinator, owned.sibling.args, owned.sibling, error) ||
        !CompressionManifestRefusal279::SeedAcceptedSibling(owned)) return false;
    const auto image = ReadFileBytes(owned.fixture.image.path), wal = ReadFileBytes(c.session_root / "accepted.wal");
    const auto marks = c.tx_manager->Watermarks();
    for (unsigned attempt = 0; attempt != 2; ++attempt)
        if (!Require(CB_Flush(&fs, nullptr, nullptr) == STATUS_DEVICE_BUSY && !c.write_degraded &&
                c.deferred_access_times.at(dir->object_id).time == time && c.deferred_access_time_requested &&
                c.tx_manager->Watermarks().accepted_sequence == marks.accepted_sequence &&
                image == ReadFileBytes(owned.fixture.image.path) && wal == ReadFileBytes(c.session_root / "accepted.wal"),
                "subdirectory atime: actual sibling refusal retains exact directory timestamp and all original bytes")) return false;
    return owned.ReplaySibling() && Require(CB_Flush(&fs, nullptr, nullptr) == STATUS_SUCCESS && c.deferred_access_times.empty(),
        "subdirectory atime: ordinary retry persists retained debt after sibling recovery") && Fresh(owned, *dir, Child, time);
}

bool Pressure()
{
    DeferredAccessTimeFixture302 owned(true); if (!Initialize(owned, true, kDeferredAccessTimeMaxInodes + 4)) return false;
    auto& c = *owned.fixture.context; auto fs = BuildFileSystem(&c);
    const auto dir = c.metadata_store->LookupCommittedInodeByPath(Child); if (!dir) return false;
    std::map<std::wstring, std::uint64_t> expected;
    const auto projected = c.metadata_store->SnapshotCommittedInodes();
    {
    std::lock_guard<std::mutex> names(c.mutex);
    for (const auto& inode : projected) {
        if (inode.node_type != Store::NodeType::RegularFile) continue;
        const auto node = TryGetNodeLockedNormalized(&c, inode.full_path);
        if (!Require(node && node->object_id == inode.object_id, "subdirectory pressure uses real committed inode identities")) return false;
        node->deferred_access_time = ToFileTimeValue(UtcNow());
        if (node->shared_payload) node->shared_payload->deferred_access_time.store(node->deferred_access_time);
        c.deferred_access_times.emplace(node->object_id, MountContext::DeferredAccessTime{node, node->shared_payload, node->deferred_access_time});
        expected[inode.full_path] = node->deferred_access_time;
        if (c.deferred_access_times.size() == kDeferredAccessTimeMaxInodes) break;
    }
    }
    if (!Require(c.deferred_access_times.size() == 512, "subdirectory pressure fills exactly the unchanged 512-entry bound")) return false;
    const auto image = ReadFileBytes(owned.fixture.image.path), wal = ReadFileBytes(c.session_root / "accepted.wal");
    unsigned publications = 0;
    c.metadata_store->SetCommitStageHook([&](std::string_view stage) { if (stage == "before-apple-publish") ++publications; return true; });
    ScopeExit clear{[&] { c.metadata_store->SetCommitStageHook({}); }};
    std::uint64_t time = 0; if (!ReadCleanup(owned, time)) return false;
    if (!Require(publications == 0 && c.deferred_access_times.size() == 512 && !c.deferred_access_times.contains(dir->object_id) &&
            c.deferred_access_time_overflow && c.deferred_access_time_requested &&
            c.deferred_access_time_deadline <= std::chrono::steady_clock::now() &&
            image == ReadFileBytes(owned.fixture.image.path) && wal == ReadFileBytes(c.session_root / "accepted.wal"),
            "subdirectory pressure retains overflow on the exact indexed node and wakes worker without inline commit")) return false;
    return Require(CB_Flush(&fs, nullptr, nullptr) == STATUS_SUCCESS && publications == 2 && c.deferred_access_times.empty() &&
        !c.deferred_access_time_overflow && !c.deferred_access_time_requested,
        "subdirectory pressure Flush preserves both the capped batch and directory spill") && Fresh(owned, *dir, Child, time) && owned.CheckFresh(expected);
}

bool Worker()
{
    DeferredAccessTimeFixture302 owned(true); if (!Initialize(owned, true)) return false;
    auto& c = *owned.fixture.context; const auto dir = c.metadata_store->LookupCommittedInodeByPath(Child); if (!dir) return false;
    std::uint64_t time = 0; if (!ReadCleanup(owned, time)) return false;
    unsigned publications = 0;
    c.metadata_store->SetCommitStageHook([&](std::string_view stage) { if (stage == "before-apple-publish") ++publications; return true; });
    ScopeExit stop{[&] { StopDeferredCommitWorker(&c); c.metadata_store->SetCommitStageHook({}); }};
    {
        std::lock_guard<std::mutex> schedule(c.deferred_commit_mutex);
        c.deferred_access_time_first = std::chrono::steady_clock::now() - kDeferredAccessTimeMaximumDelay;
    }
    if (!ReadCleanup(owned, time) || !Require(publications == 0 && c.deferred_access_time_deadline <= std::chrono::steady_clock::now(),
            "subdirectory overdue Cleanup retains the original 2000 ms age and performs no caller commit")) return false;
    StartDeferredCommitWorker(&c); bool drained = false;
    const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < until) {
        { std::lock_guard<std::mutex> mutation(c.mutation_callback_mutex); drained = c.deferred_access_times.empty(); }
        if (drained) break; Sleep(5);
    }
    return Require(StopDeferredCommitWorker(&c) && drained && publications == 1 && !c.write_degraded,
        "subdirectory overdue bounded worker persists the exact admitted timestamp") && Fresh(owned, *dir, Child, time);
}
}

bool TestOrdinaryDirectoryDeferredAccessTimes()
{
    using namespace OrdinaryDirectoryAccessTimeTests;
    bool ok = true;
    for (const bool manifest : {false, true}) {
        for (unsigned writer = 0; writer != 3; ++writer) ok &= CleanupAndFlush(manifest, writer);
        ok &= NamespaceAndIdentity(manifest);
        ok &= ExplicitAndShutdown(manifest);
        ok &= MixedWriterAndStream(manifest);
        ok &= Failure(manifest, false);
        ok &= Failure(manifest, true);
    }
    ok &= Retry(); ok &= Pressure(); ok &= Worker();
    return ok;
}
