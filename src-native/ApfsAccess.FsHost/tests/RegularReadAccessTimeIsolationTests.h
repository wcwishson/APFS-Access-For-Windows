#pragma once
// Include after DeferredAccessTimeTests.h. Root owns selector registration.

namespace RegularReadAccessTimeIsolationTests
{
using Store = apfsaccess::rw::MetadataStore;
using Wal = apfsaccess::rw::WriteAheadLog;

bool CheckDecision(MountContext& c, std::uint64_t reason, std::uint64_t own,
    bool global, bool pending)
{
    if (!TraceFor(&c)) return true;
    LatencyTrace::Snapshot snapshot;
    if (!c.latency_trace.Capture(snapshot)) return false;
    const LatencyTrace::Event* latest = nullptr;
    for (const auto& event : snapshot.history)
        if (std::string_view(event.name) == "atime.decision" && (!latest || event.id > latest->id)) latest = &event;
    return Require(latest && latest->args == std::array<std::uint64_t, 6>{reason, own, global, pending, 17, 1},
        "regular atime: fixed diagnostic reason and same-inode/global/pending state match the actual decision");
}

bool OpenWriter(FSP_FILE_SYSTEM& fs, PVOID& writer, const wchar_t* path, bool pending,
    UINT32 access = FILE_WRITE_DATA)
{
    FSP_FSCTL_FILE_INFO info{};
    if (!Require(CB_Open(&fs, const_cast<PWSTR>(path), FILE_NON_DIRECTORY_FILE | (FILE_OPEN << 24),
            access | FILE_READ_ATTRIBUTES, &writer, &info) == STATUS_SUCCESS,
            "regular atime: real writer opens")) return false;
    if (!pending) return true;
    std::byte value{0x73};
    ULONG done = 0;
    return Require(CB_Write(&fs, writer, &value, 0, 1, FALSE, FALSE, &done, &info) == STATUS_SUCCESS && done == 1,
        "regular atime: real older payload mutation is pending");
}

bool CheckFresh(DeferredAccessTimeFixture302& owned, const Store::InodeRecord& before,
    std::uint64_t time, bool pending)
{
    if (!owned.CheckFresh({{L"\\read17", time}, {L"\\alias", time}})) return false;
    Store fresh(owned.fixture.volume);
    if (!fresh.PrepareNativeWritePath()) return false;
    const auto inode = fresh.LookupCommittedInodeByPath(L"\\read17");
    const auto alias = fresh.LookupCommittedInodeByPath(L"\\alias");
    const auto writer = fresh.LookupCommittedInodeByPath(L"\\read18");
    auto expected = owned.bytes;
    if (pending) expected[0] = std::byte{0x73};
    std::vector<std::byte> actual;
    const auto acl = writer ? fresh.LookupCommittedExtendedAttribute(writer->object_id, kAppleSecurityName) : std::nullopt;
    return Require(inode && alias && inode->object_id == before.object_id && alias->object_id == before.object_id &&
        inode->create_time_utc == before.create_time_utc && inode->modification_time_utc == before.modification_time_utc &&
        inode->change_time_utc == before.change_time_utc && writer && writer->object_id == 18 &&
        writer->owner == 501 && writer->group == 20 && writer->mode == 0100640 && acl && acl->data == owned.acl &&
        fresh.ReadCommittedFileRange(L"\\read18", 0, expected.size(), actual) && actual == expected,
        "regular atime: fresh checkpoint retains inode, hard link, other times, writer bytes, Mac permissions and ACL");
}

bool Isolation(bool manifest, bool pending, UINT32 access = FILE_WRITE_DATA, bool retired_writer = false)
{
    if (!DeferredAccessTimeScratch302()) return false;
    DeferredAccessTimeFixture302 owned(manifest);
    if (!owned.Initialize(manifest)) return false;
    auto& c = *owned.fixture.context;
    c.args.write_max_dirty_transactions = 128;
    auto fs = BuildFileSystem(&c);
    PVOID writer = nullptr;
    ScopeExit close{[&] { if (writer) CB_Close(&fs, writer); }};
    if (!OpenWriter(fs, writer, L"\\read18", pending, access)) return false;
    if (retired_writer) CB_Cleanup(&fs, writer, nullptr, 0);
    const auto before = c.metadata_store->LookupCommittedInodeByPath(L"\\read17");
    if (!Require(before && HasOpenWriteHandles(&c) == !retired_writer && HasPendingNativeMutations(&c) == pending,
            "regular atime: actual unrelated writer and older pending state match the case")) return false;
    const auto image = ReadFileBytes(owned.fixture.image.path);
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    const auto pending_count = c.metadata_store->PendingMutationCount();
    const auto queued_count = ManifestQueuedRequestCount(&c);
    const auto marks = c.tx_manager->Watermarks();
    const auto* tx = c.tx_manager.get();
    const auto* spool = c.payload_spool.get();
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
    if (!owned.ReadCleanup(L"\\read17", time)) return false;
    if (!CheckDecision(c, 0, 0, !retired_writer, pending)) return false;
    const auto entry = c.deferred_access_times.find(17);
    std::cerr << "regular atime isolation manifest=" << manifest << " pending=" << pending
        << " publications=" << publications.size() << " queued=" << c.deferred_access_times.size() << '\n';
    if (!Require(publications.empty() && entry != c.deferred_access_times.end() &&
            c.deferred_access_times.size() == 1 && entry->second.node->object_id == 17 &&
            entry->second.owner == entry->second.node->shared_payload && entry->second.time == time &&
            time > before->access_time_utc && HasOpenWriteHandles(&c) == !retired_writer && HasPendingNativeMutations(&c) == pending &&
            c.metadata_store->PendingMutationCount() == pending_count && ManifestQueuedRequestCount(&c) == queued_count &&
            c.tx_manager->Watermarks().accepted_sequence == marks.accepted_sequence &&
            c.tx_manager.get() == tx && c.payload_spool.get() == spool && c.payload_spool_volume_identity == identity &&
            image == ReadFileBytes(owned.fixture.image.path) && wal == ReadFileBytes(c.session_root / "accepted.wal"),
            "regular atime: reader Cleanup and Close queue exact atime without publishing or draining unrelated work"))
        return false;
    if (!Require(CB_Flush(&fs, nullptr, nullptr) == STATUS_SUCCESS && HasOpenWriteHandles(&c) == !retired_writer &&
            publications.size() == (pending ? 2u : 1u) && c.deferred_access_times.empty(),
            "regular atime: Flush publishes older data before separate atime while unrelated writer stays open")) return false;
    for (std::size_t i = 0; i != publications.size(); ++i)
    {
        const auto& persisted = publications[i];
        const Wal::Record* marker = nullptr;
        for (const auto& record : persisted.records)
            if (record.operation == Wal::OperationKind::TransactionMarker) marker = &record;
        bool atime = false, payload = false;
        std::size_t count = 0;
        if (marker) for (const auto& record : persisted.records)
        {
            if (record.transaction_id != marker->transaction_id || &record == marker) continue;
            ++count;
            apfsaccess::rw::InodeMetadataPatch patch;
            atime |= record.object_id == 17 && record.operation == Wal::OperationKind::SetInodeMetadata &&
                apfsaccess::rw::DecodeInodeMetadataPatch(record.inline_payload, patch) &&
                patch.mask == apfsaccess::rw::InodeMetadataPatch::AccessTime && patch.access_time_utc == time;
            payload |= record.object_id == 18 && record.operation == Wal::OperationKind::Write;
        }
        const bool older = pending && i == 0;
        if (!Require(persisted.status == Wal::ReadStatus::Ok && !persisted.recovered_torn_tail && marker &&
                marker->state == Wal::RecordState::Accepted && marker->object_id == preimages[i] && preimages[i] != 0 &&
                marker->logical_length == count && (older ? payload && !atime : atime && !payload && count == 1) &&
                (i == 0 || preimages[i] > preimages[i - 1]),
                "regular atime: accepted WAL binds distinct data and atime prefixes to increasing checkpoint preimages")) return false;
    }
    const auto settled = c.tx_manager->Watermarks();
    return Require(settled.accepted_sequence != 0 && settled.accepted_sequence == settled.apfs_durable_sequence &&
            settled.accepted_sequence == settled.cleanup_sequence && !c.write_degraded,
            "regular atime: accepted, durable and cleanup boundaries converge honestly") &&
        CheckFresh(owned, *before, time, pending);
}

bool Worker(bool manifest)
{
    if (!DeferredAccessTimeScratch302()) return false;
    DeferredAccessTimeFixture302 owned(manifest);
    if (!owned.Initialize(manifest)) return false;
    auto& c = *owned.fixture.context;
    c.args.write_max_dirty_transactions = 128;
    auto fs = BuildFileSystem(&c);
    PVOID writer = nullptr;
    ScopeExit close{[&] { if (writer) CB_Close(&fs, writer); }};
    if (!OpenWriter(fs, writer, L"\\read18", true)) return false;
    const auto before = c.metadata_store->LookupCommittedInodeByPath(L"\\read17");
    if (!before) return false;
    const auto image = ReadFileBytes(owned.fixture.image.path);
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    unsigned publications = 0;
    std::promise<void> published;
    auto completion = published.get_future();
    c.metadata_store->SetCommitStageHook([&](std::string_view stage) {
        if (stage == "after-apple-publish" && ++publications == 2) published.set_value();
        return true;
    });
    ScopeExit stop{[&] { StopDeferredCommitWorker(&c); c.metadata_store->SetCommitStageHook({}); }};
    std::uint64_t time = 0;
    if (!owned.ReadCleanup(L"\\read17", time)) return false;
    std::chrono::steady_clock::time_point first;
    {
        std::lock_guard<std::mutex> schedule(c.deferred_commit_mutex);
        first = c.deferred_access_time_first = std::chrono::steady_clock::now() - kDeferredAccessTimeMaximumDelay;
        c.deferred_access_time_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    }
    if (!owned.ReadCleanup(L"\\alias", time)) return false;
    if (!Require(publications == 0 && c.deferred_access_times.size() == 1 &&
            c.deferred_access_times.at(17).time == time && c.deferred_access_time_requested &&
            c.deferred_access_time_first == first && c.deferred_access_time_deadline <= std::chrono::steady_clock::now() &&
            image == ReadFileBytes(owned.fixture.image.path) && wal == ReadFileBytes(c.session_root / "accepted.wal"),
            "regular atime: overdue alias read preserves first deadline and coalesces without Cleanup or Close publication")) return false;
    StartDeferredCommitWorker(&c);
    const bool completed = completion.wait_for(std::chrono::seconds(15)) == std::future_status::ready;
    return Require(StopDeferredCommitWorker(&c) && completed && publications == 2 && HasOpenWriteHandles(&c) &&
            c.deferred_access_times.empty() && !c.deferred_access_time_requested && !c.write_degraded,
            "regular atime: existing idle worker drains older payload then exact atime with the unrelated writer still open") &&
        CheckFresh(owned, *before, time, true);
}

bool Failure(bool manifest, bool older_payload, bool after_publication)
{
    if (!DeferredAccessTimeScratch302()) return false;
    DeferredAccessTimeFixture302 owned(manifest);
    if (!owned.Initialize(manifest)) return false;
    auto& c = *owned.fixture.context;
    c.args.write_max_dirty_transactions = 128;
    auto fs = BuildFileSystem(&c);
    PVOID writer = nullptr;
    ScopeExit close{[&] { if (writer) CB_Close(&fs, writer); }};
    if (!OpenWriter(fs, writer, L"\\read18", older_payload)) return false;
    std::uint64_t time = 0;
    if (!owned.ReadCleanup(L"\\read17", time) || !Require(c.deferred_access_times.contains(17),
            "regular atime: failure starts with real queued reader debt")) return false;
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
    bool exact_atime = false, payload = false;
    for (const auto& record : persisted.records)
    {
        apfsaccess::rw::InodeMetadataPatch patch;
        exact_atime |= record.object_id == 17 && record.operation == Wal::OperationKind::SetInodeMetadata &&
            apfsaccess::rw::DecodeInodeMetadataPatch(record.inline_payload, patch) &&
            patch.mask == apfsaccess::rw::InodeMetadataPatch::AccessTime && patch.access_time_utc == time;
        payload |= record.object_id == 18 && record.operation == Wal::OperationKind::Write;
    }
    if (!Require(!NT_SUCCESS(status) && failures == 1 && c.write_degraded &&
            c.deferred_access_times.size() == 1 && c.deferred_access_times.at(17).time == time &&
            c.deferred_access_times.at(17).node->deferred_access_time == time &&
            persisted.status == Wal::ReadStatus::Ok && !persisted.recovered_torn_tail &&
            exact_atime == !older_payload && payload == older_payload &&
            marks.accepted_sequence > marks.apfs_durable_sequence && marks.accepted_sequence > marks.cleanup_sequence &&
            std::filesystem::exists(c.recovery_marker_file) && (after_publication || image == ReadFileBytes(owned.fixture.image.path)),
            "regular atime: fault retains exact debt and accepted WAL; failed older prefix never accepts newer atime")) return false;
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    CB_Close(&fs, writer); writer = nullptr;
    return Require(RunFsHostShutdownDrain(owned.fixture.context) != 0 &&
        wal == ReadFileBytes(c.session_root / "accepted.wal") && c.deferred_access_times.at(17).time == time &&
        c.tx_manager->Watermarks().apfs_durable_sequence == marks.apfs_durable_sequence &&
        c.tx_manager->Watermarks().cleanup_sequence == marks.cleanup_sequence,
        "regular atime: failed final drain retains ownership and cannot certify newer atime");
}

bool Guards(bool manifest)
{
    if (!DeferredAccessTimeScratch302()) return false;
    DeferredAccessTimeFixture302 owned(manifest);
    if (!owned.Initialize(manifest)) return false;
    auto& c = *owned.fixture.context;
    auto fs = BuildFileSystem(&c);
    const auto image = ReadFileBytes(owned.fixture.image.path);
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    for (const auto path : {L"\\read17", L"\\alias"})
    {
        PVOID writer = nullptr;
        if (!OpenWriter(fs, writer, path, false)) return false;
        ScopeExit close{[&] { CB_Close(&fs, writer); }};
        ExternalMutationRequestScope admission(&c, false);
        MutationCallbackScope mutation(&c, false);
        OpenContext reader;
        reader.node = TryGetNodeLockedNormalized(&c, L"\\read17");
        reader.allow_read_data = true;
        if (!Require(admission.Acquired() && !TryDeferAutomaticAccessTime(&c, &reader) &&
                c.deferred_access_times.empty() && !reader.node->deferred_access_time,
                "regular atime: writer on the same inode or its hard-link alias is refused before queue mutation")) return false;
        if (!CheckDecision(c, 4, 1, true, false)) return false;
    }
    PVOID writer = nullptr;
    if (!OpenWriter(fs, writer, L"\\read18", false)) return false;
    ScopeExit close{[&] { CB_Close(&fs, writer); }};
    {
        ExternalMutationRequestScope admission(&c, false);
        MutationCallbackScope mutation(&c, false);
        OpenContext reader;
        reader.node = TryGetNodeLockedNormalized(&c, L"\\read17");
        reader.allow_read_data = true;
        const auto alias = TryGetNodeLockedNormalized(&c, L"\\alias");
        const auto owner = reader.node->shared_payload;
        if (!Require(admission.Acquired() && owner && alias && alias->shared_payload == owner,
                "regular atime: guards use an actual shared hard-link owner")) return false;
        // Controlled stale runtime identities must not mutate the queue or disk.
        reader.node->committed_read_path = L"\\old-name";
        const bool renamed = TryDeferAutomaticAccessTime(&c, &reader);
        const bool renamed_trace = CheckDecision(c, 5, 0, true, false);
        reader.node->committed_read_path.clear();
        alias->namespace_detached = true;
        const bool detached = TryDeferAutomaticAccessTime(&c, &reader);
        const bool detached_trace = CheckDecision(c, 5, 0, true, false);
        alias->namespace_detached = false;
        alias->shared_payload = TryGetNodeLockedNormalized(&c, L"\\read18")->shared_payload;
        const bool moved_alias = TryDeferAutomaticAccessTime(&c, &reader);
        const bool moved_alias_trace = CheckDecision(c, 5, 0, true, false);
        alias->shared_payload = owner;
        const auto object = owner->object_id;
        owner->object_id = 18;
        const bool replaced = TryDeferAutomaticAccessTime(&c, &reader);
        const bool replaced_trace = CheckDecision(c, 3, 0, true, false);
        owner->object_id = object;
        if (!Require(!renamed && !detached && !moved_alias && !replaced &&
                renamed_trace && detached_trace && moved_alias_trace && replaced_trace &&
                c.deferred_access_times.empty() &&
                !reader.node->deferred_access_time && !owner->deferred_access_time.load(),
                "regular atime: renamed, detached/moved-alias and replaced-owner transitions stay refused")) return false;
    }
    PVOID reader = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    if (CB_Open(&fs, const_cast<PWSTR>(L"\\read17"), FILE_OPEN << 24,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES, &reader, &info) != STATUS_SUCCESS) return false;
    if (!BeginMutationShutdownDrain(&c)) { CB_Close(&fs, reader); return false; }
    CB_Cleanup(&fs, reader, nullptr, FspCleanupSetLastAccessTime);
    CB_Close(&fs, reader);
    return Require(c.deferred_access_times.empty() && !c.deferred_access_time_requested &&
        c.metadata_store->PendingMutationCount() == 0 && ManifestQueuedRequestCount(&c) == 0 &&
        c.tx_manager->Watermarks().accepted_sequence == 0 && image == ReadFileBytes(owned.fixture.image.path) &&
        wal == ReadFileBytes(c.session_root / "accepted.wal"),
        "regular atime: Cleanup and Close after external admission stop cannot queue, stage, accept or publish new atime");
}

bool Pressure()
{
    if (!DeferredAccessTimeScratch302()) return false;
    DeferredAccessTimeFixture302 owned(true);
    if (!owned.Initialize(true, kDeferredAccessTimeMaxInodes + 3)) return false;
    auto& c = *owned.fixture.context;
    c.args.write_max_dirty_transactions = 128;
    auto fs = BuildFileSystem(&c);
    PVOID writer = nullptr;
    ScopeExit close{[&] { if (writer) CB_Close(&fs, writer); }};
    if (!OpenWriter(fs, writer, L"\\read18", false)) return false;
    const auto image = ReadFileBytes(owned.fixture.image.path);
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    std::map<std::wstring, std::uint64_t> expected;
    std::chrono::steady_clock::time_point first;
    for (std::size_t i = 0; i != kDeferredAccessTimeMaxInodes + 3; ++i)
    {
        if (i == 1) continue; // The same-inode writer is deliberately ineligible.
        const auto path = L"\\read" + std::to_wstring(17 + i);
        if (!owned.ReadCleanup(path, expected[path])) return false;
        if (i == 0) first = c.deferred_access_time_first;
    }
    expected[L"\\alias"] = expected[L"\\read17"];
    if (!Require(c.deferred_access_times.size() == kDeferredAccessTimeMaxInodes && c.deferred_access_time_overflow &&
            c.deferred_access_time_requested && c.deferred_access_time_first == first &&
            c.deferred_access_time_deadline <= std::chrono::steady_clock::now() &&
            image == ReadFileBytes(owned.fixture.image.path) && wal == ReadFileBytes(c.session_root / "accepted.wal"),
            "regular atime: 514 real reader cleanups preserve 512-entry cap, exact spill and original age without inline publication"))
        return false;
    owned.sibling.args = ManifestSessionArgs(owned.fixture.image.path, 102,
        Utf8ToWide(owned.fixture.coordinator->ContainerUuidHex()), L"regular-atime-pressure", true);
    owned.sibling.args.write_require_canonical_commit = true;
    owned.sibling.args.allow_legacy_scaffold_for_fixtures = false;
    std::wstring error;
    if (!MountManifestSession(*owned.fixture.coordinator, owned.sibling.args, owned.sibling, error) ||
        !CompressionManifestRefusal279::SeedAcceptedSibling(owned)) return false;
    for (unsigned attempt = 0; attempt != 2; ++attempt)
        if (!Require(CB_Flush(&fs, nullptr, nullptr) == STATUS_DEVICE_BUSY && !c.write_degraded &&
                c.deferred_access_times.size() == kDeferredAccessTimeMaxInodes && c.deferred_access_time_overflow &&
                c.deferred_access_time_requested && c.deferred_access_time_first == first &&
                image == ReadFileBytes(owned.fixture.image.path) && wal == ReadFileBytes(c.session_root / "accepted.wal"),
                "regular atime: genuine sibling backpressure retains all timestamps and original queue age")) return false;
    if (!owned.ReplaySibling() || !Require(CB_Flush(&fs, nullptr, nullptr) == STATUS_SUCCESS && HasOpenWriteHandles(&c) &&
            c.deferred_access_times.empty() && !c.deferred_access_time_overflow && !c.deferred_access_time_requested,
            "regular atime: ordinary drain persists capped batch and spill after sibling recovery")) return false;
    return owned.CheckFresh(expected);
}

bool NamespacePrefix(bool manifest, bool fail_prefix)
{
    if (!DeferredAccessTimeScratch302()) return false;
    DeferredAccessTimeFixture302 owned(manifest);
    if (!owned.Initialize(manifest)) return false;
    auto& c = *owned.fixture.context;
    c.args.write_max_dirty_transactions = 128;
    {
        ExternalMutationRequestScope admission(&c, false);
        MutationCallbackScope mutation(&c, false);
        Store::PayloadIdentity identity{};
        bool staged = false;
        // Stop at the real staging boundary, before the ordinary namespace
        // callback would request its publication barrier. No success is forced.
        if (!Require(admission.Acquired() && RecordNativeMutationBestEffort(&c, Store::MutationOperation::CreateFile,
                L"\\older-name", L"", 0, 0, false, 0, &identity, &staged) &&
                (manifest || RecordMutationBestEffort(&c,
                    apfsaccess::rw::TransactionManager::MutationKind::CreateFile,
                    L"\\older-name", L"", 0, 0, false, 0, 0, &identity)),
                "regular atime: older namespace request reaches real native staging and direct WAL binder")) return false;
    }
    if (!Require(!HasOpenWriteHandles(&c) && HasPendingNativeMutations(&c),
            "regular atime: namespace case exercises pending work without any open writer")) return false;
    const auto image = ReadFileBytes(owned.fixture.image.path);
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    std::vector<Wal::ReadResult> publications;
    std::vector<std::uint64_t> preimages;
    c.metadata_store->SetCommitStageHook([&](std::string_view stage) {
        if (stage == "before-apple-publish")
        {
            publications.push_back(Wal::ReadAll(c.session_root / "accepted.wal", c.payload_spool_volume_identity));
            preimages.push_back(c.metadata_store->CheckpointXid().value_or(0));
            return !fail_prefix;
        }
        return true;
    });
    ScopeExit clear{[&] { c.metadata_store->SetCommitStageHook({}); }};
    if (manifest)
    {
        {
            ExternalMutationRequestScope admission(&c, false);
            MutationCallbackScope mutation(&c, false);
            OpenContext reader;
            reader.node = TryGetNodeLockedNormalized(&c, L"\\read17");
            reader.allow_read_data = true;
            if (!Require(admission.Acquired() && !TryDeferAutomaticAccessTime(&c, &reader) &&
                    c.deferred_access_times.empty() && !reader.node->deferred_access_time &&
                    ManifestQueuedRequestCount(&c) == 1 && publications.empty() &&
                    image == ReadFileBytes(owned.fixture.image.path) && wal == ReadFileBytes(c.session_root / "accepted.wal"),
                    "regular atime: unbound manifest namespace prefix refuses batching without changing queue, WAL or image") ||
                !CheckDecision(c, 7, 0, false, true)) return false;
            if (!Require(RecordMutationBestEffort(&c,
                    apfsaccess::rw::TransactionManager::MutationKind::CreateFile, L"\\older-name") == !fail_prefix,
                    "regular atime: original manifest namespace binder owns identity, WAL and publication")) return false;
        }
        if (fail_prefix)
        {
            const auto marks = c.tx_manager->Watermarks();
            return Require(publications.size() == 1 && c.deferred_access_times.empty() &&
                marks.accepted_sequence > marks.apfs_durable_sequence && marks.accepted_sequence > marks.cleanup_sequence &&
                image == ReadFileBytes(owned.fixture.image.path),
                "regular atime: failed original namespace binder cannot accept or publish any newer automatic timestamp");
        }
    }
    std::uint64_t time = 0;
    if (!owned.ReadCleanup(L"\\read17", time)) return false;
    if (!Require(publications.size() == (manifest ? 1u : 0u) && c.deferred_access_times.contains(17) &&
            (manifest || (image == ReadFileBytes(owned.fixture.image.path) && wal == ReadFileBytes(c.session_root / "accepted.wal"))),
            "regular atime: reader Cleanup and Close add no publication after the older namespace staging or binding boundary") ||
        !CheckDecision(c, 0, 0, false, !manifest)) return false;
    auto fs = BuildFileSystem(&c);
    const auto status = CB_Flush(&fs, nullptr, nullptr);
    if (!Require(NT_SUCCESS(status) == !fail_prefix && publications.size() == (fail_prefix ? 1u : 2u),
            "regular atime: failed namespace prefix blocks atime; successful prefix and atime publish separately")) return false;
    for (std::size_t i = 0; i != publications.size(); ++i)
    {
        const auto& persisted = publications[i];
        const Wal::Record* marker = nullptr;
        for (const auto& record : persisted.records)
            if (record.operation == Wal::OperationKind::TransactionMarker) marker = &record;
        bool created = false, atime = false;
        std::size_t count = 0;
        if (marker) for (const auto& record : persisted.records)
        {
            if (record.transaction_id != marker->transaction_id || &record == marker) continue;
            ++count;
            created |= record.operation == Wal::OperationKind::CreateFile && record.path_utf8 == "\\older-name";
            apfsaccess::rw::InodeMetadataPatch patch;
            atime |= record.operation == Wal::OperationKind::SetInodeMetadata && record.object_id == 17 &&
                apfsaccess::rw::DecodeInodeMetadataPatch(record.inline_payload, patch) &&
                patch.mask == apfsaccess::rw::InodeMetadataPatch::AccessTime && patch.access_time_utc == time;
        }
        if (!Require(persisted.status == Wal::ReadStatus::Ok && !persisted.recovered_torn_tail && marker &&
                marker->state == Wal::RecordState::Accepted && marker->object_id == preimages[i] &&
                preimages[i] != 0 && marker->logical_length == count && count == 1 &&
                created == (i == 0) && atime == (i != 0) && (i == 0 || preimages[i] > preimages[i - 1]),
                "regular atime: WAL preserves namespace-before-atime transaction boundaries and exact preimages")) return false;
    }
    const auto marks = c.tx_manager->Watermarks();
    if (fail_prefix)
        return Require(c.write_degraded && c.deferred_access_times.at(17).time == time &&
            marks.accepted_sequence > marks.apfs_durable_sequence && marks.accepted_sequence > marks.cleanup_sequence &&
            image == ReadFileBytes(owned.fixture.image.path) && std::filesystem::exists(c.recovery_marker_file),
            "regular atime: failed older namespace retains reader debt and recovery ownership without false durable progress");
    Store fresh(owned.fixture.volume);
    return Require(fresh.PrepareNativeWritePath() && fresh.LookupCommittedInodeByPath(L"\\older-name") &&
            c.deferred_access_times.empty() && marks.accepted_sequence == marks.apfs_durable_sequence &&
            marks.accepted_sequence == marks.cleanup_sequence,
            "regular atime: fresh canonical reopen observes both ordered transactions and converged receipts") &&
        owned.CheckFresh({{L"\\read17", time}, {L"\\alias", time}});
}

bool Run(const std::string& name)
{
    if (name == "writer-direct") return Isolation(false, false);
    if (name == "writer-manifest") return Isolation(true, false);
    if (name == "pending-direct") return Isolation(false, true);
    if (name == "pending-manifest") return Isolation(true, true);
    if (name == "metadata-direct") return Isolation(false, false, FILE_WRITE_ATTRIBUTES);
    if (name == "metadata-manifest") return Isolation(true, false, FILE_WRITE_ATTRIBUTES);
    if (name == "pending-only-direct") return Isolation(false, true, FILE_WRITE_DATA, true);
    if (name == "pending-only-manifest") return Isolation(true, true, FILE_WRITE_DATA, true);
    if (name == "namespace-direct") return NamespacePrefix(false, false) && NamespacePrefix(false, true);
    if (name == "namespace-manifest") return NamespacePrefix(true, false) && NamespacePrefix(true, true);
    if (name == "worker-direct") return Worker(false);
    if (name == "worker-manifest") return Worker(true);
    if (name == "guards-direct") return Guards(false);
    if (name == "guards-manifest") return Guards(true);
    if (name == "pressure") return Pressure();
    if (name == "faults")
    {
        bool ok = true;
        for (const bool manifest : {false, true})
            for (const bool older : {false, true})
                for (const bool after : {false, true}) ok &= Failure(manifest, older, after);
        return ok;
    }
    if (name != "all") return Require(false, "regular atime: unknown private case");
    bool ok = true;
    for (const bool manifest : {false, true})
    {
        ok &= Isolation(manifest, false);
        ok &= Isolation(manifest, true);
        ok &= Isolation(manifest, false, FILE_WRITE_ATTRIBUTES);
        ok &= Isolation(manifest, true, FILE_WRITE_DATA, true);
        ok &= NamespacePrefix(manifest, false);
        ok &= NamespacePrefix(manifest, true);
        ok &= Worker(manifest);
        ok &= Guards(manifest);
        for (const bool older : {false, true})
            for (const bool after : {false, true}) ok &= Failure(manifest, older, after);
    }
    ok &= Pressure();
    return ok;
}
}

bool TestRegularReadAccessTimeIsolation()
{
    return RegularReadAccessTimeIsolationTests::Run("all");
}
