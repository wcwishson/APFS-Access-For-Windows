#pragma once
// Include immediately after NativeCompressionManifestTests.h. Regular images
// only; the caller must select D: TEMP/TMP before invoking either selector.

namespace CompressionManifestRefusal279
{
using Store = apfsaccess::rw::MetadataStore;
using Tx = apfsaccess::rw::TransactionManager;

struct FileEvidence
{
    std::filesystem::path path;
    bool exists;
    std::vector<std::byte> bytes;
    explicit FileEvidence(std::filesystem::path value)
        : path(std::move(value)), exists(std::filesystem::exists(path)), bytes(ReadFileBytes(path)) {}
    bool Unchanged() const
    {
        return std::filesystem::exists(path) == exists && ReadFileBytes(path) == bytes;
    }
};

bool NativeScratchEmpty(const Store& store)
{
    return !store.PendingMutationCount() && !store.PendingObjectMapUpdateCount() &&
        !store.PendingAllocationCount() && !store.PendingSpacemanAllocationIndexCount() &&
        !store.PendingDeallocationCount() && !store.PendingBtreeRecordCount() &&
        !store.PendingPayloadObjectSummaryCount() && !store.PendingPayloadDirtyByteEstimate();
}

struct SelectedEvidence
{
    FileEvidence image, wal, spool, index, marker;
    Tx::DurabilityWatermarks marks;
    std::uint64_t next, last, transaction, xid, dirty_ranges;
    bool native, overlay, pending;
    std::vector<apfsaccess::catalog::VolumeCheckpointPins> census;

    SelectedEvidence(NativeCompressionManifest266Fixture& f)
        : image(f.fixture.image.path), wal(f.fixture.context->session_root / "accepted.wal"),
          spool(f.fixture.context->payload_spool->SpoolFilePath()),
          index(f.fixture.context->payload_spool->SpoolFilePath().parent_path() / "payload-spool.idx"),
          marker(f.fixture.context->recovery_marker_file)
    {
        auto& c = *f.fixture.context;
        marks = c.tx_manager->Watermarks(); next = c.tx_manager->NextMutationSequence();
        last = c.tx_manager->LastCommittedSequence(); transaction = c.tx_manager->CurrentTransactionId();
        xid = f.fixture.coordinator->CheckpointXid();
        dirty_ranges = c.payload_spool->SnapshotCounters().dirty_range_count;
        native = c.native_write_enabled; overlay = c.overlay_write_enabled; pending = c.pending_native_writes;
        census = f.fixture.coordinator->CheckpointCensusSnapshot();
    }

    bool Unchanged(NativeCompressionManifest266Fixture& f) const
    {
        auto& c = *f.fixture.context;
        const auto after = c.tx_manager->Watermarks();
        const auto pins = f.fixture.coordinator->CheckpointCensusSnapshot();
        bool same_census = pins.size() == census.size();
        for (std::size_t i = 0; same_census && i < pins.size(); ++i)
            same_census = pins[i].volume_object_id == census[i].volume_object_id &&
                pins[i].required_checkpoint_xids == census[i].required_checkpoint_xids &&
                pins[i].unapplied_accepted_work == census[i].unapplied_accepted_work;
        return Require(image.Unchanged() && wal.Unchanged() && spool.Unchanged() && index.Unchanged() && marker.Unchanged() &&
            after.accepted_sequence == marks.accepted_sequence && after.apfs_durable_sequence == marks.apfs_durable_sequence &&
            after.cleanup_sequence == marks.cleanup_sequence && next == c.tx_manager->NextMutationSequence() &&
            last == c.tx_manager->LastCommittedSequence() && transaction == c.tx_manager->CurrentTransactionId() &&
            c.tx_manager->CurrentState() == Tx::State::Idle && c.tx_manager->RecoveryStateValid() &&
            !c.tx_manager->HasUnappliedAcceptedWork() && !c.tx_manager->PendingMutationCount() &&
            NativeScratchEmpty(*c.metadata_store) && same_census && f.fixture.coordinator->CheckpointXid() == xid &&
            !f.fixture.coordinator->IsRecoveryRequired() && !c.metadata_store->IsRecoveryRequired() &&
            c.payload_spool->SnapshotCounters().dirty_range_count == dirty_ranges &&
            c.native_write_enabled == native && c.overlay_write_enabled == overlay && c.pending_native_writes == pending &&
            IsNativeWriteEnabled(&c) && !c.recovery_active && !c.write_degraded && !c.unjournaled_native_mutation &&
            !HasBlockedRecoveryEvidence(c) && !c.compression_verification_pending.load(),
            "refusal279: exact selected image/WAL/spool/index/marker/sequences/census; clean native rollback and admission");
    }
};

// Compare every MutationRequest field, including absence of staged unlink
// evidence. These metadata requests deliberately carry no unlink outcome.
bool SameQueue(MountContext& c, const std::vector<Store::MutationRequest>& expected)
{
    std::lock_guard<std::mutex> lock(c.manifest_queue_mutex);
    if (c.manifest_queued_requests.size() != expected.size()) return false;
    for (std::size_t i = 0; i < expected.size(); ++i)
    {
        const auto& a = c.manifest_queued_requests[i]; const auto& b = expected[i];
        if (a.operation != b.operation || a.path != b.path || a.secondary_path != b.secondary_path ||
            a.offset != b.offset || a.length != b.length || a.replace_if_exists != b.replace_if_exists ||
            a.timestamp_utc != b.timestamp_utc || a.object_id != b.object_id || a.generation != b.generation ||
            a.inline_payload != b.inline_payload || a.expected_unlink_outcome || b.expected_unlink_outcome) return false;
    }
    return true;
}

template<typename Fixture>
bool SeedAcceptedSibling(Fixture& f, const std::wstring& path = L"\\accepted-sibling-279")
{
    auto& s = f.sibling;
    std::string refresh_error;
    if (s.metadata_store->CheckpointXid() != f.fixture.coordinator->CheckpointXid() &&
        !Require(f.fixture.coordinator->RefreshSessionForRecovery(102, refresh_error),
            "sibling seed refreshes after intervening selected-volume publication")) return false;
    s.session_root = f.fixture.context->session_root / "sibling-279";
    s.cache_root = s.session_root / "hydrate";
    std::filesystem::create_directories(s.cache_root);
    s.recovery_marker_file = s.session_root / "recovery.marker";
    s.native_write_enabled = true; s.args.write_backend = L"Native";
    s.args.write_crash_replay_mode = L"ReplayIfSafe";
    SeedRoot(s); std::array<std::byte, 16> security{}; SeedSecurity(s, security);
    s.payload_spool_volume_identity = "compression-refusal-sibling-279:" +
        std::to_string(GetCurrentProcessId()) + ":" + Tx::WideToUtf8(s.session_root.wstring());
    s.tx_manager = std::make_unique<Tx>(L"Conservative");
    s.tx_manager->SetVolumeIdentity(Utf8ToWide(s.payload_spool_volume_identity));
    s.tx_manager->SetJournalPath((s.session_root / "accepted.wal").wstring());
    s.payload_spool = std::make_unique<apfsaccess::rw::PayloadSpool>(apfsaccess::rw::PayloadSpool::Options{
        s.session_root / "payload-spool", s.payload_spool_volume_identity});
    Store::MutationRequest create;
    create.operation = Store::MutationOperation::CreateFile; create.path = path;
    Store::PayloadIdentity identity;
    if (!Require(s.metadata_store->StageMutation(create, &identity) == Store::MutationStatus::Applied,
            "refusal279: sibling stages a real create to obtain its WAL identity")) return false;
    Tx::MutationIntent intent;
    intent.kind = Tx::MutationKind::CreateFile; intent.path = create.path;
    intent.object_id = identity.object_id; intent.generation = identity.generation;
    const auto xid = f.fixture.coordinator->CheckpointXid();
    if (!Require(identity.generation == xid + 1 &&
            s.tx_manager->Begin() && s.tx_manager->RecordMutation(intent) && s.tx_manager->Accept(xid),
            "refusal279: sibling create is durably accepted before native publication")) return false;
    // Discard only the unpublished native session, as in the existing recovery
    // fixtures. The actual accepted journal remains the recovery authority.
    std::string error; std::wstring mount_error;
    if (!Require(f.fixture.coordinator->UnmountVolume(102, error), "refusal279: drop sibling native scratch")) return false;
    s.metadata_store = nullptr;
    if (!Require(MountManifestSession(*f.fixture.coordinator, s.args, s, mount_error),
            "refusal279: reopen sibling session on the unchanged preimage")) return false;
    std::vector<std::uint64_t> pins;
    std::vector<Tx::AcceptedTransaction> accepted;
    return Require(s.tx_manager->LoadAcceptedTransactionsSinceCleanup(accepted) && accepted.size() == 1 &&
        accepted.front().mutations.size() == 1 && accepted.front().preimage_checkpoint_xid == xid &&
        s.tx_manager->HasUnappliedAcceptedWork() && s.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(pins) &&
        pins == std::vector<std::uint64_t>{xid} &&
        f.fixture.coordinator->UpdateRequiredCheckpointXids(102, pins, error, true) &&
        !s.metadata_store->LookupCommittedInodeByPath(create.path) && NativeScratchEmpty(*s.metadata_store),
        "refusal279: sibling census represents real unpublished accepted WAL and its exact source pin");
}

struct OriginalSiblingRecoveryPeers
{
    MountContext& selected;
    MountContext& sibling;
    std::vector<MountContext*> selected_before, sibling_before;
    template<typename Fixture>
    explicit OriginalSiblingRecoveryPeers(Fixture& f)
        : selected(*f.fixture.context), sibling(f.sibling),
          selected_before(selected.container_session_contexts), sibling_before(sibling.container_session_contexts)
    {
        // Coordinator pressure is isolated from host sibling draining. Explicit
        // bootstrap still takes the complete original peer set's real gates.
        selected.container_session_contexts = {&selected, &sibling};
        sibling.container_session_contexts = selected.container_session_contexts;
    }
    ~OriginalSiblingRecoveryPeers()
    {
        selected.container_session_contexts = std::move(selected_before);
        sibling.container_session_contexts = std::move(sibling_before);
    }
};

// Separate local builder: reuse the existing compression encoder and canonical
// image builder, never a private parser. The external fork may span many blocks.
struct CapacityFixture : NativeCompressionManifest266Fixture
{
    bool InitializeLarge(std::size_t compression_blocks = 128, std::uint64_t container_blocks = 1024)
    {
        using namespace apfsaccess::rw;
        auto builder = TwoProjectableVolumeStore();
        builder.authoritative_checkpoint = true; builder.dual_checkpoint = false; builder.xid = 20;
        builder.authoritative_internal_pool_blocks = 32; builder.authoritative_checkpoint_ring_blocks = 32;
        builder.block_count = container_blocks;
        original.assign(compression_blocks * 65536, std::byte{'A'});
        auto resource = HostCompressionResource(std::vector<std::vector<std::byte>>(compression_blocks, kHostCompressionA64k));
        const auto resource_size = resource.size();
        const auto allocation = ((resource_size + 4095) / 4096) * 4096;
        if (!Require(compression_blocks && 200 + allocation / 4096 < container_blocks &&
                original.size() <= CompressionRewrite::MaxLogicalBytes && resource_size <= CompressionRewrite::MaxResourceBytes,
                "refusal279: large source/fork fit supported budgets and physical container")) return false;
        auto& volume = builder.volumes.front(); auto& records = volume.filesystem_records;
        apfsaccess::catalog::BtreeRecord encoded; std::string error;
        const auto add = [&](bool ok) { if (ok) records.push_back(encoded); return ok; };
        AppleInodeRecord root;
        root.object_id = root.private_id = root.parent_id = 2; root.mode = 0040755; root.children_or_links = 1;
        if (!add(EncodeAppleInodeRecord(root, encoded, error))) return false;
        AppleInodeRecord inode;
        inode.object_id = inode.private_id = 17; inode.parent_id = 2; inode.children_or_links = 1;
        inode.mode = 0100640; inode.owner = 501; inode.group = 20;
        inode.bsd_flags = kAppleBsdCompressedFlag; inode.uncompressed_size = original.size();
        inode.create_time = inode.modification_time = inode.change_time = inode.access_time = 1700000000000000000ULL;
        AppleExtendedField stream; stream.type = 8; stream.data.resize(40); inode.extended_fields.push_back(stream);
        AppleExtendedField name; name.type = 4;
        const std::string leaf("compressed\0", 11);
        name.data.assign(reinterpret_cast<const std::byte*>(leaf.data()), reinterpret_cast<const std::byte*>(leaf.data() + leaf.size()));
        inode.extended_fields.push_back(name);
        AppleDirectoryRecord link;
        link.parent_id = 2; link.file_id = 17; link.flags = 8; link.name_utf8 = "compressed"; link.date_added = 700;
        const auto attributes = EncodeWindowsAttributes(FILE_ATTRIBUTE_ARCHIVE);
        if (!add(EncodeAppleInodeRecord(inode, encoded, error)) || !add(EncodeAppleDirectoryRecord(link, encoded, error)) ||
            !add(EncodeAppleXattrRecord({17, kWindowsAttributesName, kAppleXattrDataEmbedded,
                {attributes.begin(), attributes.end()}}, encoded, error)) ||
            !add(EncodeAppleXattrRecord({17, "com.apple.decmpfs", kAppleXattrDataEmbedded,
                HostCompressionAttribute(4, original.size())}, encoded, error))) return false;
        std::vector<std::byte> descriptor(kAppleXattrDataStreamBytes);
        apfsaccess::testfixture::PutU64LE(descriptor, 0, 777);
        apfsaccess::testfixture::PutU64LE(descriptor, 8, resource_size);
        apfsaccess::testfixture::PutU64LE(descriptor, 16, allocation);
        if (!add(EncodeAppleXattrRecord({17, "com.apple.ResourceFork", kAppleXattrDataStream, descriptor}, encoded, error)) ||
            !add(EncodeAppleDataStreamIdRecord({777, 1}, encoded, error)) ||
            !add(EncodeAppleFileExtentRecord({777, 0, allocation, 200, 0, 4096}, encoded, error)) ||
            !EncodeApplePhysicalExtentRecord({200, allocation / 4096, kApplePhysicalExtentKindNew, 17, 1}, encoded, error)) return false;
        volume.extentref_records.push_back(encoded); volume.additional_file_system_allocated_blocks += allocation / 4096;
        resource.resize(allocation);
        for (std::size_t at = 0; at < resource.size(); at += 4096)
            builder.authoritative_seeded_main_blocks.push_back({200 + at / 4096,
                std::vector<std::byte>(resource.begin() + at, resource.begin() + at + 4096)});
        if (!SortAppleBtreeRecords(records, AppleBtreeKeyOrder::FileSystemCaseSensitive, error) ||
            !SortAppleBtreeRecords(volume.extentref_records, AppleBtreeKeyOrder::PhysicalExtent, error) ||
            !WriteFileBytes(fixture.image.path, apfsaccess::testfixture::BuildStoreImage(builder)) || !fixture.Initialize(true)) return false;
        fixture.context->args.write_require_canonical_commit = true;
        sibling.args = ManifestSessionArgs(fixture.image.path, 102, Utf8ToWide(fixture.coordinator->ContainerUuidHex()), L"private-beta-279", true);
        sibling.args.write_require_canonical_commit = true; sibling.args.allow_legacy_scaffold_for_fixtures = false;
        std::wstring mount_error;
        return Require(MountManifestSession(*fixture.coordinator, sibling.args, sibling, mount_error),
            "refusal279: large valid compressed source has a real second-volume session");
    }
};
} // namespace CompressionManifestRefusal279

bool TestNativeCompressionManifestOlderQueueRefusal279()
{
    using namespace CompressionManifestRefusal279;
    if (!CompressionReplay222ScratchReady()) return false;
    for (const auto policy : {L"FailClosed", L"BestEffort"})
    {
        NativeCompressionManifest266Fixture f;
        if (!Require(f.Initialize(4), "refusal279: two-volume queue fixture initializes")) return false;
        auto& c = *f.fixture.context; c.args.write_recovery_policy = policy;
        auto fs = BuildFileSystem(&c); FSP_FSCTL_FILE_INFO info{}; PVOID writer = nullptr;
        ScopeExit close{[&] { g_compressed_manifest_before_verification_hook = {}; if (writer) CB_Close(&fs, writer); }};
        if (!Require(CB_Open(&fs, const_cast<PWSTR>(L"\\alias"), FILE_OPEN << 24,
                GENERIC_READ | GENERIC_WRITE, &writer, &info) == STATUS_SUCCESS,
                "refusal279: compressed writer opens before sibling census barrier")) return false;
        Store::MutationRequest create, rename;
        create.operation = Store::MutationOperation::CreateFile; create.path = L"\\older-original-279";
        rename.operation = Store::MutationOperation::Rename; rename.path = create.path; rename.secondary_path = L"\\older-renamed-279";
        const std::vector<Store::MutationRequest> queue{create, rename};
        for (const auto& request : queue) EnqueueManifestRequest(&c, request);
        if (!SeedAcceptedSibling(f)) return false;
        SelectedEvidence before(f);
        FileEvidence sibling_wal(f.sibling.session_root / "accepted.wal");
        const auto sibling_marks = f.sibling.tx_manager->Watermarks();
        const auto diagnostics = f.fixture.coordinator->DiagnosticsSnapshot(101);
        std::byte value{'Z'}; ULONG done = 999;
        const auto status = CB_Write(&fs, writer, &value, 1, 1, FALSE, FALSE, &done, &info);
        const auto after_diagnostics = f.fixture.coordinator->DiagnosticsSnapshot(101);
        std::wcerr << L"[refusal279] policy=" << policy << L" status=" << status << L" done=" << done
            << L" queue=" << SameQueue(c, queue) << L" siblingWal=" << sibling_wal.Unchanged()
            << L" coordinatorAttempts=" << after_diagnostics.commit_attempts - diagnostics.commit_attempts
            << L" coordinatorFailures=" << after_diagnostics.commit_failures - diagnostics.commit_failures
            << L" reloads=" << after_diagnostics.reload_attempts - diagnostics.reload_attempts << L'\n';
        if (!Require(status == STATUS_DEVICE_BUSY && done == 0 && SameQueue(c, queue) && sibling_wal.Unchanged() &&
                f.sibling.tx_manager->Watermarks().accepted_sequence == sibling_marks.accepted_sequence &&
                f.sibling.tx_manager->Watermarks().apfs_durable_sequence == sibling_marks.apfs_durable_sequence &&
                f.sibling.tx_manager->Watermarks().cleanup_sequence == sibling_marks.cleanup_sequence &&
                after_diagnostics.commit_attempts == diagnostics.commit_attempts + 1 &&
                after_diagnostics.commit_failures == diagnostics.commit_failures + 1 &&
                after_diagnostics.reload_attempts == diagnostics.reload_attempts,
                "refusal279: actual pre-reload census refusal retains BOTH requests exactly in order and writes zero bytes") ||
            !before.Unchanged(f)) return false;
        {
            OriginalSiblingRecoveryPeers recovery_peers(f);
            if (!Require(ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(f.sibling) &&
                    f.sibling.metadata_store->LookupCommittedInodeByPath(L"\\accepted-sibling-279") &&
                    !f.sibling.tx_manager->HasUnappliedAcceptedWork() &&
                    f.sibling.tx_manager->Watermarks().cleanup_sequence == sibling_marks.accepted_sequence && SameQueue(c, queue),
                    "refusal279: real sibling replay/cleanup resolves its census while the SAME selected queue remains intact")) return false;
        }
        unsigned proof_calls = 0; bool proof_ok = false;
        const auto conversion_source = f.fixture.coordinator->CheckpointXid() + 1;
        g_compressed_manifest_before_verification_hook = [&](const Store& live) {
            ++proof_calls;
            std::vector<Tx::AcceptedTransaction> accepted;
            proof_ok = c.tx_manager->LoadAcceptedTransactionsSinceCleanup(accepted) && accepted.size() == 1 &&
                accepted.front().mutations.size() == 3 && accepted.front().preimage_checkpoint_xid == conversion_source &&
                !live.LookupCommittedInodeByPath(create.path) && live.LookupCommittedInodeByPath(rename.secondary_path) &&
                apfsaccess::fshost::NativeCompressionReplay::Verify(live, *c.tx_manager,
                    accepted.front().accepted_sequence, c.payload_spool.get(), c.payload_spool_volume_identity) ==
                    apfsaccess::fshost::NativeCompressionReplay::Result::Verified;
        };
        done = 999;
        const auto resumed = CB_Write(&fs, writer, &value, 1, 1, FALSE, FALSE, &done, &info);
        g_compressed_manifest_before_verification_hook = {};
        const auto marks = c.tx_manager->Watermarks();
        if (!Require(resumed == STATUS_SUCCESS && done == 1 && proof_calls == 1 && proof_ok && !ManifestQueuedRequestCount(&c) &&
                marks.accepted_sequence > before.marks.accepted_sequence && marks.accepted_sequence == marks.apfs_durable_sequence &&
                marks.accepted_sequence == marks.cleanup_sequence && !c.compression_verification_pending.load() && IsNativeWriteEnabled(&c),
                "refusal279: retry publishes order-dependent original batch then proves, materializes and cleans the conversion")) return false;
        Store fresh(f.fixture.volume); std::vector<std::byte> actual; auto expected = f.original; expected[1] = value;
        if (!Require(fresh.PrepareNativeWritePath() && !fresh.LookupCommittedInodeByPath(create.path) &&
                fresh.LookupCommittedInodeByPath(rename.secondary_path) && !fresh.LookupCommittedExtendedAttribute(17, "com.apple.decmpfs") &&
                fresh.ReadCommittedFileRange(L"\\compressed", 0, expected.size(), actual) && actual == expected,
                "refusal279: independent native reopen proves older rename and complete edited/untouched conversion bytes")) return false;
    }
    return true;
}

bool TestNativeCompressionManifestCapacityRefusal279()
{
    using namespace CompressionManifestRefusal279;
    using Preparation = apfsaccess::fshost::NativeCompressionRewrite;
    if (!CompressionReplay222ScratchReady()) return false;
    for (const auto policy : {L"FailClosed", L"BestEffort"})
    {
        CapacityFixture f;
        if (!Require(f.InitializeLarge(), "refusal279: supported 8 MiB source in a 4 MiB canonical container initializes")) return false;
        auto& c = *f.fixture.context; c.args.write_recovery_policy = policy;
        auto fs = BuildFileSystem(&c); FSP_FSCTL_FILE_INFO info{}; PVOID writer = nullptr, reopened = nullptr, small_handle = nullptr;
        ScopeExit close{[&] {
            g_compressed_manifest_before_verification_hook = {};
            if (small_handle) CB_Close(&fs, small_handle); if (reopened) CB_Close(&fs, reopened); if (writer) CB_Close(&fs, writer);
        }};
        if (!Require(CB_Open(&fs, const_cast<PWSTR>(L"\\compressed"), FILE_OPEN << 24,
                GENERIC_READ | GENERIC_WRITE, &writer, &info) == STATUS_SUCCESS &&
                CanOpenNativeCompressionRewrite(&c, static_cast<OpenContext*>(writer)->node),
                "refusal279: real compressed Open/probe succeeds before capacity refusal")) return false;
        SelectedEvidence before(f);
        unsigned preparation_calls = 0, binder_calls = 0, verifier_calls = 0;
        bool prepared = false;
        const apfsaccess::catalog::ContainerMutationPreparationHook prepare = [&](const Store& live, auto& requests, std::string& error) {
            ++preparation_calls;
            Preparation::Admission admission;
            admission.native_writes_admitted = IsNativeWriteEnabled(&c); admission.visibility_unresolved = HasBlockedRecoveryEvidence(c);
            admission.manifest_session = true; admission.container_commit_owned = true; admission.windows_attributes_pending = false;
            admission.queued_requests = requests.size(); admission.publication_budget_bytes = apfsaccess::rw::CompressionRewrite::MaxLogicalBytes;
            Preparation::Failure failure = Preparation::Failure::None;
            std::lock_guard<std::mutex> journal(c.tx_mutex);
            const auto inode = live.LookupCommittedInodeByPath(L"\\compressed");
            if (!inode) { error = "Refusal279MissingSource"; return false; }
            const auto plan = Preparation::Prepare(live, *c.tx_manager, admission, L"\\compressed", {inode->object_id, inode->xid}, 1, 1, failure);
            apfsaccess::rw::CompressionRewrite evidence;
            prepared = plan && failure == Preparation::Failure::None && plan->Revalidate(live, *c.tx_manager, admission) == Preparation::Failure::None &&
                plan->LogicalEof() == f.original.size() && plan->PublicationByteReservation() > before.image.bytes.size() &&
                apfsaccess::rw::DecodeCompressionRewrite(plan->Request().inline_payload, evidence) && evidence.type == 4 &&
                evidence.size == f.original.size() && evidence.volume == 101 && evidence.object == 17 &&
                evidence.checkpoint == before.xid && evidence.preserved_attributes_sha256.has_value();
            if (!prepared) { error = "Refusal279FullPreparationDidNotSucceed"; return false; }
            Store::MutationRequest times, write;
            times.operation = Store::MutationOperation::SetInodeMetadata; times.path = L"\\compressed";
            times.object_id = 17; times.generation = plan->PreimageCheckpoint() + 1;
            times.inline_payload = EncodeContentTimes(UtcNow()); times.length = times.inline_payload.size();
            write.operation = Store::MutationOperation::Write; write.path = times.path;
            write.object_id = times.object_id; write.generation = times.generation; write.offset = 1; write.length = 1;
            requests = {plan->Request(), times, write}; return true;
        };
        const apfsaccess::catalog::ContainerPrepublicationHook observe_binder =
            [&](const auto&, const auto&, std::uint64_t, auto&, std::string&) { ++binder_calls; return true; };
        ManifestCommitOutcome allocation;
        {
            std::unique_lock<std::mutex> commit(c.commit_mutex);
            std::unique_lock<std::shared_mutex> gate(c.committed_read_gate);
            std::lock_guard<std::mutex> metadata(c.metadata_mutex);
            allocation = CommitManifestMutations(&c, {}, observe_binder, {}, false, std::nullopt, prepare);
        }
        if (!prepared || allocation.mutation_staging_status != Store::MutationStatus::AllocationFailed ||
            allocation.stage != "mutation-staging" || binder_calls || !allocation.clean_prepublication_refusal)
            std::cerr << "refusal279 allocation branch: prepared=" << prepared << " builders=" << preparation_calls
                << " binders=" << binder_calls << " status=" << static_cast<int>(allocation.status)
                << " stage=" << allocation.stage << " clean=" << allocation.clean_prepublication_refusal
                << " error=" << allocation.error << '\n';
        if (!Require(preparation_calls == 1 && prepared && binder_calls == 0 &&
                allocation.mutation_staging_status == Store::MutationStatus::AllocationFailed && allocation.stage == "mutation-staging" &&
                allocation.error.find("CommitStageFailed: status=" + std::to_string(static_cast<int>(Store::MutationStatus::AllocationFailed))) == 0 &&
                allocation.clean_prepublication_refusal && !allocation.recovery_required && allocation.staged_identities.empty(),
                "refusal279: full authenticated preparation succeeds; real native staging exhausts capacity BEFORE binder with proven rollback") ||
            !before.Unchanged(f)) return false;
        // Now exercise the actual callback, whose successful builder must reach
        // AllocationFailed to return DISK_FULL. A source/preparation refusal is
        // NOT_SUPPORTED and must never satisfy this regression.
        g_compressed_manifest_before_verification_hook = [&](const Store&) { ++verifier_calls; };
        const auto diagnostics = f.fixture.coordinator->DiagnosticsSnapshot(101);
        std::byte value{'Z'}; ULONG done = 999;
        const auto status = CB_Write(&fs, writer, &value, 1, 1, FALSE, FALSE, &done, &info);
        const auto after_diagnostics = f.fixture.coordinator->DiagnosticsSnapshot(101);
        g_compressed_manifest_before_verification_hook = {};
        if (status != STATUS_DISK_FULL || done != 0)
            std::cerr << "refusal279 callback: status=" << std::hex << status << std::dec << " done=" << done
                << " commit delta=" << after_diagnostics.commit_attempts - diagnostics.commit_attempts
                << " reload delta=" << after_diagnostics.reload_attempts - diagnostics.reload_attempts << '\n';
        if (!Require(status == STATUS_DISK_FULL && done == 0 && verifier_calls == 0 &&
                after_diagnostics.commit_attempts == diagnostics.commit_attempts + 1 &&
                after_diagnostics.commit_failures == diagnostics.commit_failures + 1 &&
                after_diagnostics.reload_attempts == diagnostics.reload_attempts + 2 && !ManifestQueuedRequestCount(&c),
                "refusal279: compressed callback reaches real staging capacity failure after reload, rolls back, and reports zero written bytes") ||
            !before.Unchanged(f)) return false;
        std::vector<std::byte> actual;
        if (!Require(c.metadata_store->ReadCommittedFileRange(L"\\compressed", 0, f.original.size(), actual) && actual == f.original &&
                c.metadata_store->LookupCommittedExtendedAttribute(17, "com.apple.decmpfs") &&
                CB_Open(&fs, const_cast<PWSTR>(L"\\compressed"), FILE_OPEN << 24,
                    GENERIC_READ | GENERIC_WRITE, &reopened, &info) == STATUS_SUCCESS,
                "refusal279: rollback preserves every compressed source byte and clears the compression OID for a new Open")) return false;
        if (!Require(CB_Create(&fs, const_cast<PWSTR>(L"\\small-after-capacity-279"), FILE_NON_DIRECTORY_FILE,
                FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES, FILE_ATTRIBUTE_ARCHIVE, nullptr, 0, &small_handle, &info) == STATUS_SUCCESS,
                "refusal279: unrelated subsequent small create remains admitted")) return false;
        done = 999;
        if (!Require(CB_Write(&fs, small_handle, &value, 0, 1, FALSE, FALSE, &done, &info) == STATUS_SUCCESS && done == 1 &&
                CB_Flush(&fs, small_handle, &info) == STATUS_SUCCESS && IsNativeWriteEnabled(&c) && !c.write_degraded && !c.recovery_active,
                "refusal279: unrelated one-byte mutation still accepts, publishes and flushes under both policies")) return false;
        const auto marks = c.tx_manager->Watermarks(); Store fresh(f.fixture.volume);
        if (!Require(marks.accepted_sequence > before.marks.accepted_sequence && marks.accepted_sequence == marks.apfs_durable_sequence &&
                marks.accepted_sequence == marks.cleanup_sequence && fresh.PrepareNativeWritePath() &&
                fresh.ReadCommittedFileRange(L"\\small-after-capacity-279", 0, 1, actual) && actual == std::vector<std::byte>{value} &&
                fresh.ReadCommittedFileRange(L"\\compressed", 0, f.original.size(), actual) && actual == f.original,
                "refusal279: independent native reopen proves small mutation durability and unchanged complete compressed source")) return false;
        if (!f.PublishSibling(L"\\sibling-after-capacity-279")) return false;
    }
    return true;
}
