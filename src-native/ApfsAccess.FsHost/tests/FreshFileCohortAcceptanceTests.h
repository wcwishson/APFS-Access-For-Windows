#pragma once

struct FreshCohortEnvironment
{
    const wchar_t* name;
    std::wstring previous;
    bool present = false;
    FreshCohortEnvironment(const wchar_t* key, const wchar_t* value) : name(key)
    {
        const auto needed = GetEnvironmentVariableW(name, nullptr, 0);
        if (needed)
        {
            previous.resize(needed);
            previous.resize(GetEnvironmentVariableW(name, previous.data(), needed));
            present = true;
        }
        SetEnvironmentVariableW(name, value);
    }
    ~FreshCohortEnvironment() { SetEnvironmentVariableW(name, present ? previous.c_str() : nullptr); }
};

constexpr const char* kFreshFileCohortCases[] = {
    "close", "flush", "shutdown", "publication-count", "create-only", "eof-only", "times-only", "write-only",
    "initial-allocation", "initial-security", "initial-attributes", "cleanup-allocation", "namespace-snapshot",
    "replay-create", "replay-allocation", "replay-eof", "replay-write", "replay-times", "replay-cleanup",
    "replay-published", "replay-security", "replay-wrong-generation", "replay-wrong-object", "replay-wrong-source",
    "wal-create-failure", "wal-resize-failure", "wal-times-failure", "publish-failure", "close-publish-failure",
    "disabled", "batching-disabled", "defer-disabled", "reopened", "over-limit", "mixed-queue", "security-queue",
    "source-proof", "sibling-blocked", "shrink-reextend",
    "gap-close-no-reader", "prefix-close-no-reader", "gap-flush-no-reader", "prefix-flush-no-reader",
    "zero-eof-close-no-reader", "gap-materialization", "zero-base-proof", "missing-payload",
    "sibling-published", "sibling-drained", "mixed-after-write", "over-limit-after-write",
    "multi-sequential-close", "multi-sequential-flush", "multi-prefix-close", "multi-prefix-flush",
    "multi-disjoint-close", "multi-overlap-flush", "multi-descending-close", "multi-eof-between-flush",
    "multi-second-handle-close", "multi-second-handle-flush", "multi-materialization", "multi-missing-earlier",
    "replay-multi-sequential", "replay-multi-disjoint", "replay-multi-overlap", "replay-multi-descending",
    "replay-multi-second-handle", "replay-multi-published"
};

bool RunFreshFileCohortCase(const std::string& mode, unsigned* total_publications = nullptr)
{
    using Store = apfsaccess::rw::MetadataStore;
    using Op = Store::MutationOperation;
    using Tx = apfsaccess::rw::TransactionManager;
    using Wal = apfsaccess::rw::WriteAheadLog;
    const bool baseline = mode == "baseline-sequence";
    const bool disabled = baseline || mode == "disabled" || mode == "batching-disabled" || mode == "defer-disabled";
    const bool replay = mode.starts_with("replay-");
    const bool reject_replay = mode.starts_with("replay-wrong-");
    const auto multi_mode = replay ? mode.substr(7) : mode;
    const bool multi_write = multi_mode.starts_with("multi-");
    const bool multi_second_handle = multi_mode.starts_with("multi-second-handle");
    const bool multi_descending = multi_mode.starts_with("multi-descending") || multi_mode == "multi-eof-between-flush";
    const bool multi_disjoint = multi_mode.starts_with("multi-disjoint");
    const bool multi_overlap = multi_mode.starts_with("multi-overlap");
    FreshCohortEnvironment defer(L"APFSACCESS_DEFER_CLOSE_COMMITS", mode == "defer-disabled" ? L"0" : L"1");
    FreshCohortEnvironment feature(L"APFSACCESS_DEFER_FRESH_FILE_COHORT", baseline || mode == "disabled" ? L"0" : L"1");
    FreshCohortEnvironment batching(L"APFSACCESS_DISABLE_MANIFEST_WRITE_BATCHING",
        mode == "batching-disabled" ? L"1" : L"0");
    DirectorySymlinkFixture fixture(true);
    if (!fixture.Initialize(true, replay)) return false;
    auto& c = *fixture.context;
    c.args.write_max_dirty_transactions = 128;
    auto fs = BuildFileSystem(&c);
    const bool sibling_case = mode == "sibling-published" || mode == "sibling-drained";
    const auto original_preimage = c.metadata_store->CheckpointXid().value_or(0);
    std::unique_ptr<MountContext> sibling;
    PVOID sibling_handle = nullptr;
    ScopeExit close_sibling{[&] {
        if (sibling_handle)
        {
            auto sibling_fs = BuildFileSystem(sibling.get());
            CB_Close(&sibling_fs, sibling_handle);
        }
        c.container_session_contexts.clear();
        if (sibling)
        {
            if (sibling->metadata_store) sibling->metadata_store->SetFilePayloadRangeProvider({});
            sibling->container_session_contexts.clear();
        }
    }};
    if (sibling_case)
    {
        sibling = std::make_unique<MountContext>();
        auto& b = *sibling;
        b.args = c.args;
        b.args.volume_object_id = 102;
        b.args.volume = L"Beta";
        b.args.mount = L"private-sibling";
        b.native_write_enabled = true;
        SeedRoot(b);
        std::array<std::byte, 16> security_seed{};
        SeedSecurity(b, security_seed);
        b.session_root = c.session_root / "sibling";
        b.cache_root = b.session_root / "hydrate";
        b.recovery_marker_file = b.session_root / "recovery.marker";
        std::filesystem::create_directories(b.cache_root);
        std::wstring mount_error;
        if (!Require(MountManifestSession(*fixture.coordinator, b.args, b, mount_error),
                "cohort: prepare actual sibling session")) return false;
        b.tx_manager = std::make_unique<Tx>(L"Conservative");
        b.tx_manager->SetVolumeIdentity(L"fresh-cohort-sibling");
        b.tx_manager->SetJournalPath((b.session_root / "accepted.wal").wstring());
        b.payload_spool_volume_identity = "fresh-cohort-sibling";
        b.payload_spool = std::make_unique<apfsaccess::rw::PayloadSpool>(apfsaccess::rw::PayloadSpool::Options{
            b.session_root / "payload-spool", b.payload_spool_volume_identity, 1024 * 1024});
        b.metadata_store->SetFilePayloadRangeProvider([&b](const auto& p, auto id, auto off, auto bytes) {
            return ReadHydratedPayloadRangeForPath(&b, p, id, off, bytes);
        });
        if (!MergeCommittedInodeStateIntoNodeIndex(&b)) return false;
        c.container_session_contexts = {&c, &b};
        b.container_session_contexts = {&c, &b};
        auto sibling_fs = BuildFileSystem(&b);
        FSP_FSCTL_FILE_INFO sibling_info{};
        if (!Require(CB_Create(&sibling_fs, const_cast<PWSTR>(L"\\sibling.bin"), FILE_NON_DIRECTORY_FILE,
                FILE_READ_DATA | FILE_WRITE_DATA, FILE_ATTRIBUTE_ARCHIVE, nullptr, 0,
                &sibling_handle, &sibling_info) == STATUS_SUCCESS && sibling_handle &&
                b.tx_manager->HasUnappliedAcceptedWork() && fixture.coordinator->CheckpointXid() == original_preimage,
                "cohort: sibling really accepts an unpublished Create")) return false;
        if (mode == "sibling-published")
        {
            CB_Cleanup(&sibling_fs, sibling_handle, const_cast<PWSTR>(L"\\sibling.bin"), 0);
            CB_Close(&sibling_fs, sibling_handle); sibling_handle = nullptr;
            const auto marks = b.tx_manager->Watermarks();
            if (!Require(fixture.coordinator->CheckpointXid() == original_preimage + 1 &&
                    c.metadata_store->CheckpointXid() == original_preimage &&
                    b.metadata_store->LookupCommittedInodeByPath(L"\\sibling.bin") &&
                    !b.tx_manager->HasUnappliedAcceptedWork() && marks.accepted_sequence == marks.cleanup_sequence,
                    "cohort: sibling publication/finalization leaves A's borrowed store stale")) return false;
        }
    }
    const auto path = L"\\fresh-cohort.bin";
    PVOID handle = nullptr, reader = nullptr, second_writer = nullptr;
    FSP_FSCTL_FILE_INFO info{};
    unsigned publications = 0, wal_flushes = 0;
    std::string fault;
    c.metadata_store->SetCommitStageHook([&](std::string_view stage) {
        if (stage == "before-apple-publish") ++publications;
        return stage != "before-apple-publish" || fault != "publish";
    });
    c.tx_manager->SetJournalFaultInjectionHook([&](std::string_view stage) {
        if (stage != "durable-flush") return false;
        ++wal_flushes;
        return fault == "wal";
    });
    ScopeExit close{[&] {
        c.tx_manager->SetJournalFaultInjectionHook({});
        c.metadata_store->SetCommitStageHook({});
        if (reader) CB_Close(&fs, reader);
        if (second_writer) CB_Close(&fs, second_writer);
        if (handle) CB_Close(&fs, handle);
    }};
    const auto preimage = sibling_case ? original_preimage + 1 : original_preimage;
    auto before_image = ReadFileBytes(fixture.image.path);
    const auto before_marks = c.tx_manager->Watermarks();
    PSECURITY_DESCRIPTOR security = nullptr;
    if ((mode == "initial-security" || mode == "replay-security" || multi_second_handle) &&
        !Require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:BAD:P(A;;FA;;;WD)",
            SDDL_REVISION_1, &security, nullptr) != FALSE, "cohort: initial security descriptor")) return false;
    ScopeExit free_security{[&] { if (security) LocalFree(security); }};
    const auto initial_allocation = mode == "initial-allocation" || multi_second_handle ? 32768ull : 0ull;
    const auto attributes = mode == "initial-attributes" ? FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_ARCHIVE : FILE_ATTRIBUTE_ARCHIVE;
    if (mode == "wal-create-failure") fault = "wal";
    const auto create_status = CB_Create(&fs, const_cast<PWSTR>(path), FILE_NON_DIRECTORY_FILE,
        FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES, attributes, security, initial_allocation, &handle, &info);
    fault.clear();
    if (sibling_case)
    {
        const auto marks = sibling->tx_manager->Watermarks();
        if (!Require(fixture.coordinator->CheckpointXid() == preimage &&
                sibling->metadata_store->LookupCommittedInodeByPath(L"\\sibling.bin") &&
                !sibling->tx_manager->HasUnappliedAcceptedWork() && marks.accepted_sequence == marks.cleanup_sequence &&
                marks.apfs_durable_sequence == marks.cleanup_sequence && sibling->metadata_store->PendingMutationCount() == 0 &&
                !fixture.coordinator->IsRecoveryRequired(),
                "cohort: actual sibling advance and cleanup precede A's accepted source")) return false;
        if (mode == "sibling-drained")
        {
            if (!Require(ReadFileBytes(fixture.image.path) != before_image,
                    "cohort: A's helper really published the pending sibling")) return false;
            before_image = ReadFileBytes(fixture.image.path);
        }
    }
    if (mode == "wal-create-failure")
        return Require(!NT_SUCCESS(create_status) && !handle && wal_flushes && publications == 0 &&
                ReadFileBytes(fixture.image.path) == before_image && !c.native_write_enabled &&
                c.tx_manager->Watermarks().cleanup_sequence == before_marks.cleanup_sequence &&
                !FindNode(&c, path), "cohort: failed Create ACK exposes no handle/name or publication");
    if (!Require(create_status == STATUS_SUCCESS && handle && publications == (disabled ? 1u : 0u),
            "cohort: real Create uses the selected durable acceptance path")) return false;
    auto* open = static_cast<OpenContext*>(handle);
    const auto node = open->node;
    const auto object = node->object_id;
    std::vector<std::byte> expected;
    auto expected_times = VisibleInodeTimes(*node);
    const auto initial_security = VisibleNativeSecurity(*node);
    std::vector<std::byte> expected_security_descriptor;
    if (security)
    {
        const auto* first = static_cast<const std::byte*>(security);
        expected_security_descriptor.assign(first, first + GetSecurityDescriptorLength(security));
        std::vector<std::byte> encoded;
        if (!Require(EncodeWindowsSecurity(security, encoded) == STATUS_SUCCESS && initial_security &&
                initial_security->windows_security == encoded,
                "cohort: initial stored security exactly encodes the caller descriptor")) return false;
    }
    const auto accepted_boundary = [&](std::uint64_t old_sequence, unsigned old_flushes, const char* label) {
        const auto marks = c.tx_manager->Watermarks();
        return Require(disabled || (publications == 0 && marks.accepted_sequence > old_sequence &&
            wal_flushes > old_flushes && marks.apfs_durable_sequence == before_marks.apfs_durable_sequence &&
            marks.cleanup_sequence == before_marks.cleanup_sequence && c.metadata_store->CheckpointXid() == preimage &&
            ReadFileBytes(fixture.image.path) == before_image), label);
    };
    if (!accepted_boundary(before_marks.accepted_sequence, 0, "cohort: Create flushes WAL before success without image writes")) return false;
    if (!disabled)
    {
        std::vector<Tx::AcceptedTransaction> accepted;
        std::string error;
        if (!Require(open->fresh_file_cohort && object != 0 &&
                c.metadata_store->PendingFreshFileCohortMatches(*open->fresh_file_cohort) &&
                !c.metadata_store->LookupCommittedInodeByPath(path) &&
                c.tx_manager->LoadUnappliedAcceptedTransactions(accepted, &error) && accepted.size() == 1 &&
                accepted.front().mutations.front().operation == Wal::OperationKind::CreateFile,
                "cohort: exact unpublished Create has a readable accepted batch")) return false;
        const auto& batch = accepted.front();
        if (!Require(batch.preimage_checkpoint_xid == preimage &&
                batch.mutations.size() == 2u + (security ? 1u : 0u) + (initial_allocation ? 1u : 0u) +
                    (mode == "initial-attributes" ? 1u : 0u),
                "cohort: initial security, attributes, all times and allocation share the Create batch")) return false;
        for (const auto& record : batch.mutations)
            if (!Require(record.object_id == object && record.parent_object_id == preimage + 1,
                    "cohort: every initial WAL record binds the actual OID and successor generation")) return false;
        const auto pins = fixture.coordinator->CheckpointCensusSnapshot();
        const auto owner = std::find_if(pins.begin(), pins.end(), [](const auto& entry) { return entry.volume_object_id == 101; });
        if (!Require(owner != pins.end() && owner->unapplied_accepted_work &&
                owner->required_checkpoint_xids == std::vector<std::uint64_t>{preimage},
                "cohort: durable acceptance retains the exact source and selected owner")) return false;
        if (mode == "source-proof")
        {
            auto unknown = batch.mutations.front();
            unknown.operation = static_cast<Wal::OperationKind>(0xffffffffu);
            Store::MutationRequest decoded;
            if (!Require(!BuildAcceptedReplayMutationRequest(unknown, decoded),
                    "cohort: unknown WAL operation still fails closed")) return false;
            for (unsigned field = 0; field != 4; ++field)
            {
                auto bad = *open->fresh_file_cohort;
                if (field == 0) ++bad.identity.object_id;
                if (field == 1) ++bad.identity.generation;
                if (field == 2) ++bad.source_checkpoint;
                if (field == 3) bad.path += L"-reused";
                if (!Require(!c.metadata_store->PendingFreshFileCohortMatches(bad),
                        "cohort: wrong OID, generation, source or path refuses continuation")) return false;
            }
        }
        if (mode == "sibling-blocked")
        {
            apfsaccess::catalog::ContainerVolumeSession sibling_session;
            sibling_session.volume_object_id = 102;
            sibling_session.container_uuid_hex = fixture.coordinator->ContainerUuidHex();
            sibling_session.requested_write = true;
            sibling_session.use_canonical_transaction = true;
            sibling_session.metadata_context.allow_legacy_scaffold_for_fixtures = false;
            if (!Require(fixture.coordinator->MountVolume(sibling_session, error) &&
                    fixture.coordinator->FindSessionStore(102) && fixture.coordinator->CheckpointXid() == preimage,
                    "cohort: sibling guard targets a real writable session at the accepted source")) return false;
            const auto marks = c.tx_manager->Watermarks();
            unsigned binds = 0;
            const auto result = fixture.coordinator->Commit(102, {NativeCallbackRequest(Op::CreateFile, L"\\sibling.bin")},
                [&](const auto&, const auto&, auto, auto&, auto&) { ++binds; return true; });
            const bool blocked = !result.committed && !binds && result.error == "SiblingAcceptedRecoveryPending: oid=101" &&
                fixture.coordinator->CheckpointXid() == preimage && ReadFileBytes(fixture.image.path) == before_image &&
                c.tx_manager->Watermarks().accepted_sequence == marks.accepted_sequence &&
                c.tx_manager->Watermarks().apfs_durable_sequence == marks.apfs_durable_sequence &&
                c.tx_manager->Watermarks().cleanup_sequence == marks.cleanup_sequence &&
                c.tx_manager->HasUnappliedAcceptedWork();
            if (!blocked) std::cerr << "[cohort sibling] committed=" << result.committed << " binds=" << binds
                << " error=" << result.error << " checkpoint=" << fixture.coordinator->CheckpointXid()
                << " expected=" << preimage << '\n';
            if (!Require(blocked, "cohort: sibling cannot advance the pinned source")) return false;
        }
    }
    if (mode == "reopened")
    {
        CB_Close(&fs, handle); handle = nullptr;
        if (!Require(publications == 1 && !c.tx_manager->HasUnappliedAcceptedWork() &&
                CB_Open(&fs, const_cast<PWSTR>(path), FILE_NON_DIRECTORY_FILE,
                    FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES, &handle, &info) == STATUS_SUCCESS &&
                !static_cast<OpenContext*>(handle)->fresh_file_cohort,
                "cohort: Close completes and reopen never acquires Create provenance")) return false;
        return Require(CB_SetFileSize(&fs, handle, 16384, FALSE, &info) == STATUS_SUCCESS && publications == 2 &&
                !c.tx_manager->HasUnappliedAcceptedWork(), "cohort: reopened growth preserves synchronous fallback");
    }
    if (multi_second_handle)
    {
        if (!Require(CB_Open(&fs, const_cast<PWSTR>(path), FILE_NON_DIRECTORY_FILE,
                FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES, &second_writer, &info) == STATUS_SUCCESS &&
                second_writer && static_cast<OpenContext*>(second_writer)->node == node &&
                !static_cast<OpenContext*>(second_writer)->fresh_file_cohort && publications == 0,
                "cohort multi: second writable handle shares the unpublished node without Create admission")) return false;
        SIZE_T size = 0;
        if (!Require(CB_GetSecurity(&fs, second_writer, nullptr, &size) == STATUS_BUFFER_OVERFLOW && size > 0,
                "cohort multi: second writer sees initial accepted security")) return false;
        std::vector<std::byte> descriptor(size);
        const auto security_status = CB_GetSecurity(&fs, second_writer, descriptor.data(), &size);
        const bool security_matches = security_status == STATUS_SUCCESS && initial_security &&
            size == expected_security_descriptor.size() && descriptor == expected_security_descriptor;
        if (!security_matches) std::cerr << "[cohort security] mode=" << mode << " status=0x" << std::hex
            << static_cast<std::uint32_t>(security_status) << std::dec << " returned=" << size
            << " buffer=" << descriptor.size() << " expected=" << expected_security_descriptor.size() << '\n';
        if (!Require(security_matches,
                "cohort multi: initial security bytes survive multiple writers")) return false;
    }
    const bool create_only = mode == "create-only" || mode == "replay-create";
    const bool times_only = mode == "times-only";
    const bool eof_only = mode == "eof-only" || mode == "replay-eof" || mode == "zero-eof-close-no-reader";
    const bool allocation_only = mode == "replay-allocation";
    const bool write_only = mode == "write-only";
    if (!create_only && !times_only && !write_only)
    {
        if (mode == "mixed-queue" || mode == "security-queue")
        {
            Store::MutationRequest extra;
            if (mode == "mixed-queue") extra = NativeCallbackRequest(Op::CreateFile, L"\\foreign.bin");
            else
            {
                apfsaccess::rw::InodeMetadataPatch patch;
                patch.mask = apfsaccess::rw::InodeMetadataPatch::Mode; patch.mode = 0600;
                extra = NativeCallbackRequest(Op::SetInodeMetadata, path);
                if (!apfsaccess::rw::EncodeInodeMetadataPatch(patch, extra.inline_payload)) return false;
                extra.length = extra.inline_payload.size();
            }
            EnqueueManifestRequest(&c, extra);
        }
        const auto sequence = c.tx_manager->Watermarks().accepted_sequence;
        const auto flushes = wal_flushes;
        if (mode == "wal-resize-failure") fault = "wal";
        const auto allocation = mode == "over-limit" ? kFreshFileCohortLimit + 4096 : 32768ull;
        const auto status = CB_SetFileSize(&fs, handle, allocation, TRUE, &info);
        fault.clear();
        if (mode == "wal-resize-failure")
            return Require(!NT_SUCCESS(status) && wal_flushes > flushes && publications == 0 &&
                    !c.native_write_enabled && node->file_size == 0 &&
                    c.tx_manager->Watermarks().cleanup_sequence == before_marks.cleanup_sequence &&
                    ReadFileBytes(fixture.image.path) == before_image,
                    "cohort: failed allocation ACK keeps accepted Create evidence and fails closed");
        if (!Require(status == STATUS_SUCCESS, "cohort: allocation-first callback")) return false;
        if (mode == "over-limit" || mode == "mixed-queue" || mode == "security-queue")
            return Require(publications == 1 && !c.tx_manager->HasUnappliedAcceptedWork() &&
                    c.tx_manager->Watermarks().accepted_sequence == c.tx_manager->Watermarks().cleanup_sequence &&
                    c.metadata_store->PendingMutationCount() == 0,
                    "cohort: unsupported size or mixed queue publishes through the unchanged fallback");
        if (!accepted_boundary(sequence, flushes, "cohort: allocation-first callback is durably accepted")) return false;
        if (!allocation_only && !multi_write)
        {
            const auto before = c.tx_manager->Watermarks().accepted_sequence;
            const auto flush_count = wal_flushes;
            if (!Require(CB_SetFileSize(&fs, handle, 16384, FALSE, &info) == STATUS_SUCCESS && info.FileSize == 16384,
                    "cohort: grow logical EOF after allocation")) return false;
            expected.resize(16384, std::byte{0});
            if (!accepted_boundary(before, flush_count, "cohort: EOF callback is durably accepted")) return false;
            if (!eof_only)
            {
                auto payload = BuildPatternPayloadForTest(8192, 0x39);
                ULONG written = 0;
                const auto old_sequence = c.tx_manager->Watermarks().accepted_sequence;
                const auto old_flushes = wal_flushes;
                const auto write_offset = mode.starts_with("prefix-") ? 0u : 4096u;
                if (!Require(CB_Write(&fs, handle, payload.data(), write_offset, static_cast<ULONG>(payload.size()),
                        FALSE, FALSE, &written, &info) == STATUS_SUCCESS && written == payload.size(),
                        "cohort: accepted write leaves known zero prefix and tail")) return false;
                std::copy(payload.begin(), payload.end(), expected.begin() + write_offset);
                if (!accepted_boundary(old_sequence, old_flushes, "cohort: Write ACK still waits for durable payload authority")) return false;
            }
        }
    }
    if (write_only)
    {
        auto payload = BuildPatternPayloadForTest(8192, 0x39);
        ULONG written = 0;
        const auto sequence = c.tx_manager->Watermarks().accepted_sequence;
        const auto flushes = wal_flushes;
        if (!Require(CB_Write(&fs, handle, payload.data(), 4096, static_cast<ULONG>(payload.size()),
                FALSE, FALSE, &written, &info) == STATUS_SUCCESS && written == payload.size(),
                "cohort: Create plus Write without any allocation/EOF callback")) return false;
        expected.resize(12288, std::byte{0});
        std::copy(payload.begin(), payload.end(), expected.begin() + 4096);
        if (!accepted_boundary(sequence, flushes, "cohort: direct Write has durable acceptance")) return false;
        if (!Require(c.metadata_store->PendingMutationsCanDelayClose(),
                "cohort: fixture reaches the otherwise delayable fresh-ingest Close shape")) return false;
    }
    if (multi_write)
    {
        const auto grow_eof = [&](std::uint64_t size) {
            const auto sequence = c.tx_manager->Watermarks().accepted_sequence;
            const auto flushes = wal_flushes;
            if (!Require(CB_SetFileSize(&fs, handle, size, FALSE, &info) == STATUS_SUCCESS && info.FileSize == size,
                    "cohort multi: EOF growth succeeds")) return false;
            expected.resize(static_cast<std::size_t>(size), std::byte{0});
            return accepted_boundary(sequence, flushes, "cohort multi: EOF growth is durably accepted");
        };
        if (!multi_descending && !grow_eof(multi_disjoint ? 32768 :
                multi_mode.starts_with("multi-sequential") ? 16384 : 24576)) return false;

        unsigned writes = 0;
        const auto write = [&](PVOID writer, std::uint64_t offset, std::size_t count, unsigned char seed) {
            auto payload = BuildPatternPayloadForTest(count, seed);
            const auto sequence = c.tx_manager->Watermarks().accepted_sequence;
            const auto flushes = wal_flushes;
            ULONG transferred = 0;
            if (!Require(CB_Write(&fs, writer, payload.data(), offset, static_cast<ULONG>(payload.size()),
                    FALSE, FALSE, &transferred, &info) == STATUS_SUCCESS && transferred == payload.size(),
                    "cohort multi: every data Write succeeds in full")) return false;
            ++writes;
            expected.resize((std::max)(expected.size(), static_cast<std::size_t>(offset + count)), std::byte{0});
            std::copy(payload.begin(), payload.end(), expected.begin() + static_cast<std::ptrdiff_t>(offset));
            if (!accepted_boundary(sequence, flushes, "cohort multi: each Write has its own durable acceptance")) return false;
            const auto summary = c.metadata_store->DebugSnapshotPendingMutations();
            if (!Require(std::count_if(summary.begin(), summary.end(), [&](const auto& request) {
                    return request.path == path && request.operation == Op::Write;
                }) == 1 && c.metadata_store->PendingFreshFileCohortMatches(*open->fresh_file_cohort),
                    "cohort multi: Writes really coalesce while exact cohort/size proof survives")) return false;
            std::vector<Tx::AcceptedTransaction> accepted;
            std::string error;
            if (!Require(c.tx_manager->LoadUnappliedAcceptedTransactions(accepted, &error),
                    "cohort multi: reopen each durable accepted prefix")) return false;
            unsigned wal_writes = 0;
            for (const auto& batch : accepted)
            {
                if (!Require(batch.preimage_checkpoint_xid == preimage,
                        "cohort multi: every callback retains the exact source")) return false;
                for (const auto& record : batch.mutations)
                {
                    if (!Require(record.object_id == object && record.parent_object_id == preimage + 1,
                            "cohort multi: WAL retains exact OID/generation for every callback")) return false;
                    if (record.operation == Wal::OperationKind::Write) ++wal_writes;
                }
            }
            return Require(wal_writes == writes, "cohort multi: accepted WAL retains all Writes removed from the summary");
        };
        const auto first_offset = multi_descending ? 16384u : multi_disjoint || multi_overlap ? 4096u : 0u;
        if (!write(handle, first_offset, multi_disjoint ? 4096 : 8192, 0x39)) return false;
        if (multi_mode == "multi-eof-between-flush")
        {
            // Spool-only Write leaves stale hydration; EOF must publish through the synchronous fallback.
            const auto fresh_proof = *open->fresh_file_cohort;
            const auto before_eof = c.tx_manager->Watermarks();
            const auto eof_flushes = wal_flushes;
            bool stale = false;
            {
                std::lock_guard<std::mutex> lock(c.mutex);
                stale = IsHydrationStaleLocked(&c, node);
            }
            if (!Require(stale && CB_SetFileSize(&fs, handle, 32768, FALSE, &info) == STATUS_SUCCESS &&
                    info.FileSize == 32768, "cohort multi EOF: stale-hydration EOF fallback succeeds")) return false;
            expected.resize(32768, std::byte{0});
            const auto eof_marks = c.tx_manager->Watermarks();
            const auto eof_source = c.metadata_store->CheckpointXid().value_or(0);
            const auto eof_publications = publications;
            const auto eof_inode = c.metadata_store->LookupCommittedInodeByPath(path);
            std::vector<std::byte> bytes;
            if (!Require(eof_publications == 1 && eof_source > preimage && eof_inode &&
                    eof_inode->object_id == object && eof_inode->logical_size == expected.size() &&
                    c.metadata_store->ReadCommittedFileRange(path, 0, expected.size(), bytes) && bytes == expected &&
                    eof_marks.accepted_sequence > before_eof.accepted_sequence && wal_flushes > eof_flushes &&
                    eof_marks.accepted_sequence == eof_marks.apfs_durable_sequence &&
                    eof_marks.apfs_durable_sequence == eof_marks.cleanup_sequence &&
                    !c.tx_manager->HasUnappliedAcceptedWork() && c.metadata_store->PendingMutationCount() == 0 &&
                    ManifestQueuedRequestCount(&c) == 0 && !c.metadata_store->PendingFreshFileCohortMatches(fresh_proof),
                    "cohort multi EOF: fallback durably publishes the high Write and zero gaps, retires fresh proof")) return false;

            auto payload = BuildPatternPayloadForTest(4096, 0xa6);
            const auto write_flushes = wal_flushes;
            ULONG transferred = 0;
            if (!Require(CB_Write(&fs, handle, payload.data(), 4096, static_cast<ULONG>(payload.size()),
                    FALSE, FALSE, &transferred, &info) == STATUS_SUCCESS && transferred == payload.size(),
                    "cohort multi EOF: lower Write succeeds against the committed file")) return false;
            std::copy(payload.begin(), payload.end(), expected.begin() + 4096);
            const auto write_marks = c.tx_manager->Watermarks();
            const auto identity = ResolvePayloadSpoolIdentity(&c, path);
            if (!Require(publications == eof_publications && c.metadata_store->CheckpointXid().value_or(0) == eof_source &&
                    identity && identity->object_id == object && identity->generation == eof_source + 1 &&
                    write_marks.accepted_sequence > eof_marks.accepted_sequence && wal_flushes > write_flushes &&
                    write_marks.apfs_durable_sequence == eof_marks.apfs_durable_sequence &&
                    write_marks.cleanup_sequence == eof_marks.cleanup_sequence &&
                    c.tx_manager->HasUnappliedAcceptedWork() && !c.metadata_store->PendingFreshFileCohortMatches(fresh_proof),
                    "cohort multi EOF: ordinary Write is durably accepted with the new source and generation")) return false;
            std::vector<Tx::AcceptedTransaction> accepted;
            std::string error;
            if (!Require(c.tx_manager->LoadUnappliedAcceptedTransactions(accepted, &error) && !accepted.empty(),
                    "cohort multi EOF: accepted ordinary Write remains replayable before Flush")) return false;
            unsigned wal_writes = 0;
            for (const auto& batch : accepted)
            {
                if (!Require(batch.preimage_checkpoint_xid == eof_source,
                        "cohort multi EOF: accepted batch binds the post-EOF source")) return false;
                for (const auto& record : batch.mutations)
                {
                    if (!Require(record.object_id == object && record.parent_object_id == identity->generation,
                            "cohort multi EOF: accepted records bind the original OID and new generation")) return false;
                    if (record.operation == Wal::OperationKind::Write) ++wal_writes;
                }
            }
            bytes.assign(expected.size(), std::byte{0x7f});
            ULONG read = 0;
            if (!Require(wal_writes == 1 && ReadHydratedPayloadRangeForPath(&c, path, *identity, 0, bytes) &&
                    bytes == expected && CB_Read(&fs, handle, bytes.data(), 0, static_cast<ULONG>(bytes.size()), &read) == STATUS_SUCCESS &&
                    read == bytes.size() && bytes == expected && publications == eof_publications,
                    "cohort multi EOF: provider and dirty read preserve both Writes and all unwritten gaps")) return false;
            expected_times = VisibleInodeTimes(*node);
            CB_Cleanup(&fs, handle, const_cast<PWSTR>(path), 0);
            if (!Require(open->cleanup_seen && publications == eof_publications &&
                    CB_Flush(&fs, handle, &info) == STATUS_SUCCESS,
                    "cohort multi EOF: Cleanup retains accepted work and terminal Flush succeeds")) return false;
            const auto final_marks = c.tx_manager->Watermarks();
            const auto final_publications = publications;
            const auto inode = c.metadata_store->LookupCommittedInodeByPath(path);
            bool idle = false;
            {
                std::lock_guard<std::mutex> lock(c.deferred_commit_mutex);
                idle = !c.deferred_commit_requested && !c.deferred_commit_in_flight;
            }
            if (!Require(final_publications == eof_publications + 1 && c.metadata_store->CheckpointXid().value_or(0) > eof_source &&
                    inode && inode->object_id == object && inode->logical_size == expected.size() &&
                    inode->create_time_utc == expected_times.create_time_utc &&
                    inode->modification_time_utc == expected_times.modification_time_utc &&
                    inode->change_time_utc == expected_times.change_time_utc && inode->access_time_utc == expected_times.access_time_utc &&
                    c.metadata_store->ReadCommittedFileRange(path, 0, expected.size(), bytes) && bytes == expected &&
                    final_marks.accepted_sequence == write_marks.accepted_sequence &&
                    final_marks.accepted_sequence == final_marks.apfs_durable_sequence &&
                    final_marks.apfs_durable_sequence == final_marks.cleanup_sequence && !c.tx_manager->HasUnappliedAcceptedWork() &&
                    c.metadata_store->PendingMutationCount() == 0 && ManifestQueuedRequestCount(&c) == 0 &&
                    idle && !c.close_commit_deferred.load() && !c.pending_native_writes &&
                    c.native_write_enabled && !c.write_degraded && !c.recovery_active,
                    "cohort multi EOF: Flush publishes exact final bytes/times and completes all accepted work")) return false;
            CB_Close(&fs, handle); handle = nullptr;
            if (total_publications) *total_publications = publications;
            return Require(publications == final_publications &&
                    c.tx_manager->Watermarks().accepted_sequence == final_marks.accepted_sequence &&
                    c.tx_manager->Watermarks().apfs_durable_sequence == final_marks.apfs_durable_sequence &&
                    c.tx_manager->Watermarks().cleanup_sequence == final_marks.cleanup_sequence &&
                    node->open_handle_count == 0 && node->live_context_count == 0 && node->closing_context_count == 0 &&
                    c.metadata_store->ReadCommittedFileRange(path, 0, expected.size(), bytes) && bytes == expected,
                    "cohort multi EOF: Close releases the writer without extra publication or durable work");
        }
        const auto second_offset = multi_descending ? 4096u : multi_disjoint ? 20480u : 8192u;
        if (!write(second_writer ? second_writer : handle, second_offset,
                multi_descending || multi_disjoint ? 4096 : 8192, 0xa6)) return false;
        if (multi_disjoint && !write(handle, 12288, 4096, 0xe3)) return false;
        if (multi_overlap && !write(handle, 6144, 4096, 0xe3)) return false;

        if (multi_mode == "multi-missing-earlier")
        {
            auto spool = std::move(c.payload_spool);
            ScopeExit restore_spool{[&] { c.payload_spool = std::move(spool); }};
            c.payload_spool = std::make_unique<apfsaccess::rw::PayloadSpool>(apfsaccess::rw::PayloadSpool::Options{
                c.session_root / "missing-earlier-spool", c.payload_spool_volume_identity, 1024 * 1024});
            const auto identity = open->fresh_file_cohort->identity;
            if (!Require(c.payload_spool->Append({c.payload_spool_volume_identity, identity.object_id,
                    identity.generation, 8192, 2, std::span<const std::byte>(expected).subspan(8192, 8192)}) &&
                    c.payload_spool->Append({c.payload_spool_volume_identity, identity.object_id,
                    identity.generation + 1, 0, 3, std::span<const std::byte>(expected).first(8192)}),
                    "cohort multi: latest Write exists, earlier payload has only a wrong-generation decoy")) return false;
            std::vector<std::byte> bytes(expected.size(), std::byte{0x7f});
            ULONG read = 0;
            const auto marks = c.tx_manager->Watermarks();
            if (!Require(!NT_SUCCESS(CB_Read(&fs, handle, bytes.data(), 0, static_cast<ULONG>(bytes.size()), &read)) &&
                    read == 0 && !ReadHydratedPayloadRangeForPath(&c, path, identity, 0, bytes) &&
                    !TryHydrateFromCurrentPayloadOverlay(&c, node) && publications == 0 &&
                    c.tx_manager->Watermarks().accepted_sequence == marks.accepted_sequence &&
                    c.tx_manager->Watermarks().apfs_durable_sequence == marks.apfs_durable_sequence &&
                    c.tx_manager->Watermarks().cleanup_sequence == marks.cleanup_sequence &&
                    ReadFileBytes(fixture.image.path) == before_image,
                    "cohort multi: coalesced earlier payload cannot become zeros in reads/materialization/publication")) return false;
        }
        // Exercise the publication provider independently of the full-spool read shortcut.
        std::vector<std::byte> bytes(expected.size(), std::byte{0x7f});
        ULONG read = 0;
        if (!Require(ReadHydratedPayloadRangeForPath(&c, path, open->fresh_file_cohort->identity, 0, bytes) &&
                bytes == expected && CB_Read(&fs, handle, bytes.data(), 0, static_cast<ULONG>(bytes.size()), &read) == STATUS_SUCCESS &&
                read == bytes.size() && bytes == expected && publications == 0,
                "cohort multi: provider and dirty reads agree on all writes, overlaps and unwritten gaps")) return false;
        std::vector<std::byte> slice(8193, std::byte{0x7f});
        if (!Require(ReadHydratedPayloadRangeForPath(&c, path, open->fresh_file_cohort->identity, 4095, slice) &&
                std::equal(slice.begin(), slice.end(), expected.begin() + 4095),
                "cohort multi: clipped unaligned read crosses written intervals and gaps exactly")) return false;
        if (second_writer)
        {
            if (!Require(CB_Read(&fs, second_writer, bytes.data(), 0, static_cast<ULONG>(bytes.size()), &read) == STATUS_SUCCESS &&
                    read == bytes.size() && bytes == expected && publications == 0,
                    "cohort multi: both writers see the same accepted bytes before publication")) return false;
        }
        if (multi_mode == "multi-materialization" && !Require(TryHydrateFromCurrentPayloadOverlay(&c, node) &&
                ReadFileBytes(HydrationPath(&c, *node)) == expected && publications == 0,
                "cohort multi: materialization preserves earlier coalesced data and the zero suffix")) return false;
    }
    const bool set_times = !create_only && !eof_only && !allocation_only && !write_only && mode != "replay-write";
    if (set_times)
    {
        const auto prior = VisibleInodeTimes(*node);
        const auto sequence = c.tx_manager->Watermarks().accepted_sequence;
        const auto flushes = wal_flushes;
        const auto time = ToFileTimeValue(UtcNow()) + 10000000;
        if (mode == "wal-times-failure") fault = "wal";
        const auto status = CB_SetBasicInfo(&fs, handle, INVALID_FILE_ATTRIBUTES, time, time + 1, time + 2, time + 3, &info);
        fault.clear();
        if (mode == "wal-times-failure")
            return Require(!NT_SUCCESS(status) && VisibleInodeTimes(*node) == prior && publications == 0 &&
                    !c.native_write_enabled && c.tx_manager->HasUnappliedAcceptedWork() &&
                    c.tx_manager->Watermarks().cleanup_sequence == before_marks.cleanup_sequence,
                    "cohort: failed time ACK cannot expose new times or retire accepted data");
        if (!Require(status == STATUS_SUCCESS, "cohort: initial explicit times")) return false;
        if (!accepted_boundary(sequence, flushes, "cohort: time callback is durably accepted")) return false;
    }
    expected_times = VisibleInodeTimes(*node);
    const bool fallback_after_write = mode == "mixed-after-write" || mode == "over-limit-after-write";
    if (fallback_after_write)
    {
        if (mode == "mixed-after-write")
        {
            PVOID other = nullptr;
            FSP_FSCTL_FILE_INFO other_info{};
            const auto status = CB_Create(&fs, const_cast<PWSTR>(L"\\other.bin"), FILE_NON_DIRECTORY_FILE,
                FILE_READ_DATA | FILE_WRITE_DATA, FILE_ATTRIBUTE_ARCHIVE, nullptr, 0, &other, &other_info);
            ScopeExit close_other{[&] { if (other) CB_Close(&fs, other); }};
            if (!Require(status == STATUS_SUCCESS && other &&
                    !static_cast<OpenContext*>(other)->fresh_file_cohort &&
                    c.metadata_store->LookupCommittedInodeByPath(L"\\other.bin"),
                    "cohort: a second Create uses synchronous fallback with the first file's gaps intact")) return false;
        }
        else if (!Require(CB_SetFileSize(&fs, handle, kFreshFileCohortLimit + 4096, TRUE, &info) == STATUS_SUCCESS,
                "cohort: larger allocation after a partial Write keeps synchronous fallback")) return false;
        expected_times = VisibleInodeTimes(*node);
        if (!Require(publications == 1 && !c.tx_manager->HasUnappliedAcceptedWork() &&
                !c.metadata_store->PendingFreshFileCohortMatches(*open->fresh_file_cohort) &&
                c.native_write_enabled && !c.write_degraded,
                "cohort: fallback publishes and finalizes instead of broadening admission")) return false;
    }
    if (mode == "zero-base-proof")
    {
        for (unsigned field = 0; field != 4; ++field)
        {
            auto bad = *open->fresh_file_cohort;
            if (field == 0) ++bad.identity.object_id;
            if (field == 1) ++bad.identity.generation;
            if (field == 2) ++bad.source_checkpoint;
            if (field == 3) bad.path += L"-reused";
            std::array<std::byte, 4096> gap{};
            unsigned payload_reads = 0;
            if (!Require(!c.metadata_store->ReadPendingFreshFileCohortRange(bad, 0, gap,
                    [&](auto, auto) { ++payload_reads; return true; }) && payload_reads == 0,
                    "cohort: even an unwritten gap requires exact source/OID/generation/path")) return false;
        }
    }
    if (mode == "missing-payload")
    {
        auto spool = std::move(c.payload_spool);
        ScopeExit restore_spool{[&] { c.payload_spool = std::move(spool); }};
        c.payload_spool = std::make_unique<apfsaccess::rw::PayloadSpool>(apfsaccess::rw::PayloadSpool::Options{
            c.session_root / "empty-spool", c.payload_spool_volume_identity, 1024 * 1024});
        const auto identity = open->fresh_file_cohort->identity;
        if (!Require(c.payload_spool->Append({c.payload_spool_volume_identity, identity.object_id,
                identity.generation, 4096, 1, std::span<const std::byte>(expected).subspan(4096, 4096)}),
                "cohort: isolated spool contains only half of the accepted Write")) return false;
        std::vector<std::byte> bytes(expected.size(), std::byte{0x7f});
        ULONG read = 0;
        const auto marks = c.tx_manager->Watermarks();
        if (!Require(!NT_SUCCESS(CB_Read(&fs, handle, bytes.data(), 0, static_cast<ULONG>(bytes.size()), &read)) &&
                read == 0 && !ReadHydratedPayloadRangeForPath(&c, path, open->fresh_file_cohort->identity, 0, bytes) &&
                !TryHydrateFromCurrentPayloadOverlay(&c, node) && publications == 0 &&
                c.tx_manager->Watermarks().accepted_sequence == marks.accepted_sequence &&
                c.tx_manager->Watermarks().cleanup_sequence == marks.cleanup_sequence &&
                ReadFileBytes(fixture.image.path) == before_image,
                "cohort: missing written payload fails read/materialization/publication provider without zero substitution")) return false;
    }
    if (mode == "gap-materialization" && !Require(TryHydrateFromCurrentPayloadOverlay(&c, node) &&
            ReadFileBytes(HydrationPath(&c, *node)) == expected && publications == 0,
            "cohort: actual materialization fills gaps and copies only identity-bound payload")) return false;
    if (mode == "namespace-snapshot")
    {
        const auto root = FindNode(&c, L"\\");
        if (!Require(root && MergeCommittedDirectoryChildrenIntoNodeIndex(&c, root) &&
                MergeCommittedInodeStateIntoNodeIndex(&c) &&
                FindNode(&c, path) == node && node->file_size == expected.size() &&
                VisibleInodeTimes(*node) == expected_times,
                "cohort: same-checkpoint directory snapshot cannot erase or rewind unpublished Create")) return false;
    }
    const bool no_reader = mode.ends_with("-no-reader") || multi_write;
    if (!no_reader && !expected.empty())
    {
        std::vector<std::byte> bytes(expected.size(), std::byte{0x7f}); ULONG read = 0;
        if (!Require(CB_Read(&fs, handle, bytes.data(), 0, static_cast<ULONG>(bytes.size()), &read) == STATUS_SUCCESS &&
                read == bytes.size() && bytes == expected, "cohort: dirty writer reads exact bytes and gaps before another open")) return false;
    }
    if (!no_reader)
    {
        info = {};
        const auto read_open_status = CB_Open(&fs, const_cast<PWSTR>(path), FILE_NON_DIRECTORY_FILE,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES, &reader, &info);
        const bool reader_matches = read_open_status == STATUS_SUCCESS && reader &&
            info.FileSize == expected.size() && info.CreationTime == expected_times.create_time_utc &&
            info.LastWriteTime == expected_times.modification_time_utc && info.ChangeTime == expected_times.change_time_utc &&
            info.LastAccessTime == expected_times.access_time_utc && (info.FileAttributes & attributes) == attributes;
        if (!reader_matches) std::cerr << "[cohort open] mode=" << mode << " status=0x" << std::hex
            << static_cast<std::uint32_t>(read_open_status) << " attributes=" << info.FileAttributes << '/' << attributes
            << std::dec << " reader=" << (reader != nullptr) << " eof=" << info.FileSize << '/' << expected.size()
            << " create=" << info.CreationTime << '/' << expected_times.create_time_utc
            << " write=" << info.LastWriteTime << '/' << expected_times.modification_time_utc
            << " change=" << info.ChangeTime << '/' << expected_times.change_time_utc
            << " access=" << info.LastAccessTime << '/' << expected_times.access_time_utc
            << " publications=" << publications << '\n';
        if (!Require(reader_matches,
                "cohort: second handle sees namespace, EOF, attributes and all four times before publication")) return false;
        if (security)
        {
            SIZE_T size = 0;
            if (!Require(CB_GetSecurity(&fs, reader, nullptr, &size) == STATUS_BUFFER_OVERFLOW && size > 0,
                    "cohort: pending initial security is available to another handle")) return false;
            std::vector<std::byte> descriptor(size);
            const auto security_status = CB_GetSecurity(&fs, reader, descriptor.data(), &size);
            const bool security_matches = security_status == STATUS_SUCCESS && initial_security &&
                size == expected_security_descriptor.size() && descriptor == expected_security_descriptor;
            if (!security_matches) std::cerr << "[cohort security] mode=" << mode << " status=0x" << std::hex
                << static_cast<std::uint32_t>(security_status) << std::dec << " returned=" << size
                << " buffer=" << descriptor.size() << " expected=" << expected_security_descriptor.size() << '\n';
            if (!Require(security_matches,
                    "cohort: second handle receives the exact accepted security descriptor")) return false;
        }
        if (!expected.empty())
        {
            std::vector<std::byte> bytes(expected.size()); ULONG read = 0;
            if (!Require(CB_Read(&fs, reader, bytes.data(), 0, static_cast<ULONG>(bytes.size()), &read) == STATUS_SUCCESS &&
                    read == bytes.size() && bytes == expected, "cohort: second handle reads exact payload and zero gaps")) return false;
        }
        CB_Close(&fs, reader); reader = nullptr;
    }
    if (!Require(disabled || publications == (fallback_after_write ? 1u : 0u),
            "cohort: read-only close did not publish the writer's batch")) return false;
    const bool replay_published = mode == "replay-published" || mode == "replay-multi-published";
    const bool cleanup = !replay || mode == "replay-cleanup" || replay_published;
    if (cleanup)
    {
        const auto count = publications;
        CB_Cleanup(&fs, handle, const_cast<PWSTR>(path), create_only || write_only || fallback_after_write ? 0 :
            FspCleanupSetLastWriteTime | FspCleanupSetChangeTime |
                (mode == "cleanup-allocation" ? FspCleanupSetAllocationSize : 0));
        expected_times = VisibleInodeTimes(*node);
        if (!Require(open->cleanup_seen && (disabled || publications == count + (mode == "cleanup-allocation" ? 1u : 0u)),
                "cohort: cleanup retains its existing synchronous allocation-release boundary")) return false;
    }
    if (mode == "shrink-reextend")
    {
        if (!Require(CB_SetFileSize(&fs, handle, 4096, FALSE, &info) == STATUS_SUCCESS &&
                !c.tx_manager->HasUnappliedAcceptedWork() &&
                CB_SetFileSize(&fs, handle, 16384, FALSE, &info) == STATUS_SUCCESS,
                "cohort: shrink preserves before/after publication and re-extension fallback")) return false;
        expected.assign(16384, std::byte{0}); expected_times = VisibleInodeTimes(*node);
    }
    if (replay)
    {
        if (replay_published && !Require(CommitNativeMutationsOnFlushBestEffort(&c) == STATUS_SUCCESS &&
                publications == 1 && c.tx_manager->HasUnappliedAcceptedWork(),
                "cohort: published checkpoint before journal finalization")) return false;
        const auto file = open->file.exchange(INVALID_HANDLE_VALUE);
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
        if (multi_write)
        {
            open->fresh_file_cohort.reset();
            node->fresh_file_zero_base.reset();
            if (second_writer)
            {
                const auto other_file = static_cast<OpenContext*>(second_writer)->file.exchange(INVALID_HANDLE_VALUE);
                if (other_file != INVALID_HANDLE_VALUE) CloseHandle(other_file);
            }
        }
        InvalidateHydrationReadHandle(&c);
        std::error_code ec;
        std::filesystem::remove(HydrationPath(&c, *node), ec);
        if (!Require(!ec && c.metadata_store->PrepareNativeWritePath(), "cohort: lose working state and hydration")) return false;
        c.container_session_contexts = {&c};
        // This fixture has no worker thread. A crash loses its volatile scheduler.
        {
            std::lock_guard<std::mutex> lock(c.deferred_commit_mutex);
            c.deferred_commit_requested = false;
            c.deferred_commit_requested_target = 0;
            c.deferred_commit_in_flight = false;
            c.deferred_commit_in_flight_target = 0;
            c.deferred_commit_completed_target = 0;
            c.deferred_commit_failed_target = 0;
            c.deferred_commit_last_status = STATUS_SUCCESS;
            c.deferred_commit_first_request_tick_ms = 0;
            c.deferred_commit_force_now = false;
            c.deferred_commit_burst_count = 0;
            c.deferred_commit_deadline_tick_ms = 0;
            c.close_commit_deferred.store(false);
        }
        c.tx_manager.reset();
        auto journal = c.session_root / "accepted.wal";
        if (reject_replay)
        {
            auto records = Wal::ReadAll(journal, c.payload_spool_volume_identity);
            if (!Require(records.status == Wal::ReadStatus::Ok, "cohort: read fixture evidence for refusal case")) return false;
            for (auto& record : records.records)
            {
                if (record.operation == Wal::OperationKind::CreateFile)
                {
                    if (mode == "replay-wrong-generation") ++record.parent_object_id;
                    if (mode == "replay-wrong-object") record.object_id = c.metadata_store->LookupCommittedInodeByPath(L"\\")->object_id;
                }
                if (mode == "replay-wrong-source" && record.operation == Wal::OperationKind::TransactionMarker &&
                    record.state == Wal::RecordState::Accepted) ++record.object_id;
            }
            journal = c.session_root / "refusal-copy.wal";
            Wal copy({journal, c.payload_spool_volume_identity});
            if (!Require(copy.AppendBatch(records.records), "cohort: create isolated malformed evidence copy")) return false;
        }
        c.tx_manager = std::make_unique<Tx>(L"Conservative");
        std::string error;
        const auto opened = c.tx_manager->OpenStartupJournal(journal.wstring(), L"directory-symlink-volume", error);
        c.payload_spool.reset();
        c.payload_spool = std::make_unique<apfsaccess::rw::PayloadSpool>(apfsaccess::rw::PayloadSpool::Options{
            c.session_root / "payload-spool", c.payload_spool_volume_identity, 1024 * 1024});
        const auto image = ReadFileBytes(fixture.image.path);
        const auto wal = ReadFileBytes(journal);
        const auto marks = c.tx_manager->Watermarks();
        const auto recovered = opened && ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(c);
        if (reject_replay)
            return Require(!recovered && ReadFileBytes(fixture.image.path) == image && ReadFileBytes(journal) == wal &&
                    c.tx_manager->Watermarks().apfs_durable_sequence == marks.apfs_durable_sequence &&
                    c.tx_manager->Watermarks().cleanup_sequence == marks.cleanup_sequence,
                    "cohort: wrong identity/source refuses recovery without publication or evidence retirement");
        if (!Require(recovered, "cohort: WAL and spool alone recover each accepted callback prefix")) return false;
        const auto after = ReadFileBytes(fixture.image.path);
        if (!Require(ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(c) && after == ReadFileBytes(fixture.image.path),
                "cohort: repeated startup recovery is image-idempotent")) return false;
    }
    else if (mode == "shutdown")
    {
        if (!Require(BeginMutationShutdownDrain(&c) && StopDeferredCommitWorker(&c) &&
                DrainNativeMutationsByPolicy(&c, L"Shutdown") == STATUS_SUCCESS &&
                FinalizeMutationJournalBestEffort(&c, L"Shutdown"), "cohort: actual shutdown drain and finalization")) return false;
    }
    else if (mode == "flush" || mode == "publish-failure" || mode == "gap-flush-no-reader" || mode == "prefix-flush-no-reader" ||
        (multi_write && mode.ends_with("-flush")))
    {
        if (mode == "publish-failure") fault = "publish";
        const auto status = CB_Flush(&fs, handle, &info);
        fault.clear();
        if (mode == "publish-failure")
            return Require(!NT_SUCCESS(status) && !c.native_write_enabled && c.tx_manager->HasUnappliedAcceptedWork() &&
                    c.tx_manager->Watermarks().cleanup_sequence == before_marks.cleanup_sequence,
                    "cohort: failed terminal publication is not reported as completed");
        if (!Require(status == STATUS_SUCCESS, "cohort: actual Flush returns after publication/finalization")) return false;
    }
    else
    {
        if (mode == "close-publish-failure") fault = "publish";
        CB_Close(&fs, handle); handle = nullptr;
        fault.clear();
        if (mode == "close-publish-failure")
            return Require(!c.native_write_enabled && c.tx_manager->HasUnappliedAcceptedWork() &&
                    c.tx_manager->Watermarks().cleanup_sequence == before_marks.cleanup_sequence,
                    "cohort: void Close latches failure and preserves accepted recovery debt");
    }
    if (multi_write)
    {
        const auto marks = c.tx_manager->Watermarks();
        bool idle = false;
        {
            std::lock_guard<std::mutex> lock(c.deferred_commit_mutex);
            idle = !c.deferred_commit_requested && !c.deferred_commit_in_flight;
        }
        std::vector<std::byte> bytes;
        if (!Require(publications == 1 && c.metadata_store->ReadCommittedFileRange(path, 0, expected.size(), bytes) &&
                bytes == expected && marks.accepted_sequence == marks.apfs_durable_sequence &&
                marks.apfs_durable_sequence == marks.cleanup_sequence && !c.tx_manager->HasUnappliedAcceptedWork() &&
                c.metadata_store->PendingMutationCount() == 0 && ManifestQueuedRequestCount(&c) == 0 &&
                idle && !c.close_commit_deferred.load() && !c.pending_native_writes,
                "cohort multi: selected terminal barrier completes exact bytes and all durable work before handle release")) return false;
        if (second_writer) { CB_Close(&fs, second_writer); second_writer = nullptr; }
        if (handle) { CB_Close(&fs, handle); handle = nullptr; }
        if (!Require(publications == 1 && c.tx_manager->Watermarks().accepted_sequence == marks.accepted_sequence &&
                c.tx_manager->Watermarks().cleanup_sequence == marks.cleanup_sequence &&
                node->open_handle_count == 0 && node->live_context_count == 0 && node->closing_context_count == 0,
                "cohort multi: release every writer without extra publication or accepted work")) return false;
    }
    const auto inode = c.metadata_store->LookupCommittedInodeByPath(path);
    if (mode == "zero-base-proof")
    {
        std::array<std::byte, 4096> gap{};
        if (!Require(!c.metadata_store->ReadPendingFreshFileCohortRange(*node->fresh_file_zero_base, 0, gap,
                [](auto, auto) { return true; }), "cohort: publication retires zero-base eligibility")) return false;
    }
    const auto marks = c.tx_manager->Watermarks();
    std::vector<std::byte> bytes;
    const auto final_security = c.metadata_store->LookupCommittedExtendedAttribute(object, kWindowsSecurityName);
    bool scheduler_idle = false;
    {
        std::lock_guard<std::mutex> lock(c.deferred_commit_mutex);
        scheduler_idle = !c.deferred_commit_requested && !c.deferred_commit_in_flight;
    }
    const bool contexts_released = handle || (node->open_handle_count == 0 && node->live_context_count == 0 &&
        node->closing_context_count == 0);
    if (total_publications) *total_publications = publications;
    return Require(inode && inode->object_id == object && inode->logical_size == expected.size() &&
            inode->create_time_utc == expected_times.create_time_utc && inode->modification_time_utc == expected_times.modification_time_utc &&
            inode->change_time_utc == expected_times.change_time_utc && inode->access_time_utc == expected_times.access_time_utc &&
            (expected.empty() || (c.metadata_store->ReadCommittedFileRange(path, 0, expected.size(), bytes) && bytes == expected)) &&
            (!security || (initial_security && final_security && final_security->data == initial_security->windows_security)) &&
            (disabled || mode == "shrink-reextend" || publications == 1) &&
            marks.accepted_sequence == marks.apfs_durable_sequence && marks.apfs_durable_sequence == marks.cleanup_sequence &&
            c.metadata_store->PendingMutationCount() == 0 && ManifestQueuedRequestCount(&c) == 0 &&
            !c.close_commit_deferred.load() && scheduler_idle && contexts_released && !c.pending_native_writes &&
            c.native_write_enabled && !c.write_degraded && !c.recovery_active,
            "cohort: terminal barrier leaves exact bytes/metadata, one publication, and no pending durable work");
}

bool TestFreshFileCohort(const std::string& mode)
{
    if (!Require(std::find(std::begin(kFreshFileCohortCases), std::end(kFreshFileCohortCases), mode) !=
            std::end(kFreshFileCohortCases), "cohort: known selector")) return false;
    if (mode != "publication-count") return RunFreshFileCohortCase(mode);
    unsigned baseline = 0, cohort = 0;
    if (!RunFreshFileCohortCase("baseline-sequence", &baseline) || !RunFreshFileCohortCase("close", &cohort)) return false;
    std::cerr << "[fresh-cohort terminal publications] baseline=" << baseline << " cohort=" << cohort << '\n';
    return Require(baseline >= 3 && cohort == 1 && cohort < baseline,
        "cohort: identical allocation-first callback sequence removes publications through completed Close");
}
