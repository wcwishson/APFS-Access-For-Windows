#pragma once
// Include after NativeCompressionManifestRefusalTests.h. Caller must set D:
// TEMP/TMP before running these regular-image, unmounted host callback tests.

namespace CompressionManifestAcceptance295
{
using Store = apfsaccess::rw::MetadataStore;
using Tx = apfsaccess::rw::TransactionManager;
using Wal = apfsaccess::rw::WriteAheadLog;
using CompressionManifestRefusal279::FileEvidence;

// A non-owning WAL read preserves the failed live journal's validity/lease
// state. Do not replace the failed manager with a fresh recovery session here.
bool AcceptedEvidence(NativeCompressionManifest266Fixture& f, bool older,
    std::uint64_t source_xid, std::uint64_t accepted_sequence)
{
    auto& c = *f.fixture.context;
    const auto persisted = Wal::ReadAll(c.session_root / "accepted.wal", c.payload_spool_volume_identity);
    if (!Require(persisted.status == Wal::ReadStatus::Ok && !persisted.recovered_torn_tail,
            "acceptance295: complete checksum-valid WAL remains independently readable")) return false;
    std::vector<Wal::Record> mutations;
    const Wal::Record* accepted_marker = nullptr;
    unsigned terminal_count = 0;
    for (const auto& record : persisted.records)
    {
        if (record.operation == Wal::OperationKind::TransactionMarker)
        {
            ++terminal_count;
            accepted_marker = &record;
        }
        else if (record.state == Wal::RecordState::Prepared) mutations.push_back(record);
    }
    if (!Require(terminal_count == 1 && accepted_marker &&
            accepted_marker->state == Wal::RecordState::Accepted &&
            accepted_marker->sequence == accepted_sequence && accepted_marker->object_id == source_xid &&
            accepted_marker->logical_length == mutations.size() && mutations.size() == (older ? 2u : 3u),
            "acceptance295: exactly one accepted terminal names the original source and complete batch")) return false;
    for (const auto& mutation : mutations)
        if (!Require(mutation.transaction_id == accepted_marker->transaction_id &&
                mutation.sequence < accepted_sequence && mutation.object_id != 0 && mutation.parent_object_id != 0,
                "acceptance295: every persisted mutation belongs to the accepted transaction and has bound identity")) return false;
    Store source(f.fixture.volume);
    std::vector<std::byte> source_bytes;
    if (!Require(source.PrepareNativeWritePath() && source.CheckpointXid() == source_xid &&
            source.LookupCommittedExtendedAttribute(17, "com.apple.decmpfs") &&
            source.ReadCommittedFileRange(L"\\compressed", 0, f.original.size(), source_bytes) && source_bytes == f.original,
            "acceptance295: independent native reopen still reads the entire pinned compressed source")) return false;
    if (older)
        return Require(mutations[0].operation == Wal::OperationKind::CreateFile &&
            mutations[0].path_utf8 == "\\older-original-295" &&
            mutations[1].operation == Wal::OperationKind::Rename &&
            mutations[1].path_utf8 == mutations[0].path_utf8 &&
            mutations[1].secondary_path_utf8 == "\\older-renamed-295" &&
            mutations[0].object_id == mutations[1].object_id &&
            mutations[0].parent_object_id == source_xid + 1 && mutations[1].parent_object_id == source_xid + 1,
            "acceptance295: accepted older create/rename retains exact order, paths and staged successor");

    apfsaccess::rw::CompressionRewrite proof;
    const auto& conversion = mutations[0];
    const auto& times = mutations[1];
    const auto& write = mutations[2];
    const auto source_inode = source.LookupCommittedInodeByObjectId(17);
    if (!Require(conversion.operation == Wal::OperationKind::RewriteCompressedContent &&
            Wal::CompressionRewriteIsConsistent(conversion) &&
            apfsaccess::rw::DecodeCompressionRewrite(conversion.inline_payload, proof) &&
            proof.type == 4 && proof.volume == 101 && proof.object == 17 && proof.checkpoint == source_xid &&
            proof.size == f.original.size() && proof.preserved_attributes_sha256.has_value() &&
            source_inode && proof.generation == source_inode->xid &&
            conversion.path_utf8 == "\\alias" && conversion.object_id == proof.object &&
            conversion.parent_object_id == proof.generation &&
            times.operation == Wal::OperationKind::SetInodeMetadata &&
            Wal::InodeMetadataMutationIsConsistent(times) &&
            write.operation == Wal::OperationKind::Write && write.path_utf8 == conversion.path_utf8 &&
            times.path_utf8 == conversion.path_utf8 && times.object_id == proof.object && write.object_id == proof.object &&
            times.parent_object_id == source_xid + 1 && write.parent_object_id == source_xid + 1 &&
            write.logical_offset == 1 && write.logical_length == 1 && write.payload_length == 1,
            "acceptance295: CRW2 source evidence and exact times/write successor survive the failed boundary")) return false;
    std::array<std::byte, 1> payload{};
    std::vector<std::byte> persisted_payload;
    std::size_t read = 0;
    return Require(c.payload_spool->ReadPersistedRange({c.payload_spool_volume_identity,
            write.object_id, write.parent_object_id, write.logical_offset, write.payload_length,
            write.payload_offset, write.payload_spool_id, write.payload_sha256}, persisted_payload) &&
            persisted_payload == std::vector<std::byte>{std::byte{'Z'}} &&
            c.payload_spool->ReadFullyCoveredRange({c.payload_spool_volume_identity,
            write.object_id, write.parent_object_id, write.logical_offset, payload}, read) &&
            read == payload.size() && payload[0] == std::byte{'Z'} &&
            c.payload_spool->SnapshotCounters().dirty_range_count == 1,
            "acceptance295: accepted write still owns its exact dirty spool byte");
}

bool CensusRetained(NativeCompressionManifest266Fixture& f, std::uint64_t source_xid)
{
    const auto census = f.fixture.coordinator->CheckpointCensusSnapshot();
    const auto selected = std::find_if(census.begin(), census.end(), [](const auto& entry) {
        return entry.volume_object_id == 101;
    });
    return Require(selected != census.end() && selected->unapplied_accepted_work &&
            selected->required_checkpoint_xids == std::vector<std::uint64_t>{source_xid},
            "acceptance295: selected census keeps unresolved acceptance and the exact source pin");
}

// Routes 0/1 exercise the production compression callback, with/without an
// older ordered batch. Route 2 repeats that older host binder boundary with
// its public outcome argument, because CB_Write does not expose that result.
// It checks classification directly; only the CB routes assert the callback's
// unconditional both-policy admission block (the lower helper is policy-based).
bool AcceptedFailure(bool census_failure, unsigned route, const wchar_t* policy)
{
    std::wcerr << L"[acceptance295] phase=" << (census_failure ? L"census" : L"publication")
        << L" route=" << route << L" policy=" << policy << L'\n';
    NativeCompressionManifest266Fixture f;
    if (!Require(f.Initialize(4), "acceptance295: real compression manifest fixture initializes")) return false;
    auto& c = *f.fixture.context;
    c.args.write_recovery_policy = policy;
    // The fixture's Conservative transaction safety level is independent of
    // the host recovery policy exercised by this loop.
    std::wcerr << L"[acceptance295] recoveryPolicy=" << c.args.write_recovery_policy
        << L" safetyLevel=" << c.args.write_safety_level << L" backend=" << c.args.write_backend << L'\n';
    if (!Require(!HasBlockedRecoveryEvidence(c),
            "acceptance295: fixture starts without startup identity/invalid-marker blocks")) return false;
    auto fs = BuildFileSystem(&c);
    FSP_FSCTL_FILE_INFO info{};
    PVOID writer = nullptr;
    ScopeExit close{[&] {
        c.tx_manager->SetFaultInjectionHook({});
        c.tx_manager->SetJournalFaultInjectionHook({});
        c.metadata_store->SetCommitStageHook({});
        g_compressed_manifest_before_verification_hook = {};
        if (writer) CB_Close(&fs, writer);
    }};
    if (!Require(CB_Open(&fs, const_cast<PWSTR>(L"\\alias"), FILE_OPEN << 24,
            GENERIC_READ | GENERIC_WRITE, &writer, &info) == STATUS_SUCCESS,
            "acceptance295: compressed alias opens before fault injection")) return false;
    const bool older = route != 0;
    Store::MutationRequest create, rename;
    create.operation = Store::MutationOperation::CreateFile; create.path = L"\\older-original-295";
    rename.operation = Store::MutationOperation::Rename; rename.path = create.path; rename.secondary_path = L"\\older-renamed-295";
    if (older) { EnqueueManifestRequest(&c, create); EnqueueManifestRequest(&c, rename); }
    const auto source_xid = f.fixture.coordinator->CheckpointXid();
    const auto initial_marks = c.tx_manager->Watermarks();
    FileEvidence original_image(f.fixture.image.path);
    unsigned accepts = 0, census_faults = 0, publication_faults = 0, verifications = 0;
    bool acceptance_finished = false;
    std::optional<FileEvidence> accepted_wal, accepted_spool, accepted_index;
    const auto capture = [&] {
        if (accepted_wal) return;
        accepted_wal.emplace(c.session_root / "accepted.wal");
        accepted_spool.emplace(c.payload_spool->SpoolFilePath());
        accepted_index.emplace(c.payload_spool->SpoolFilePath().parent_path() / "payload-spool.idx");
    };
    c.tx_manager->SetFaultInjectionHook([&](const std::string& stage) {
        if (stage == "accept-finish") { ++accepts; acceptance_finished = true; }
    });
    c.tx_manager->SetJournalFaultInjectionHook([&](std::string_view stage) {
        // The host reaches this census rescan only after its real deferred WAL
        // durability wait succeeds. Preaccept lease/reseed reads remain intact.
        if (!census_failure || !acceptance_finished || stage != "read-all-exclusive") return false;
        ++census_faults; capture(); return true;
    });
    c.metadata_store->SetCommitStageHook([&](std::string_view stage) {
        if (stage != "before-apple-publish") return true;
        ++publication_faults; capture(); return false;
    });
    g_compressed_manifest_before_verification_hook = [&](const Store&) { ++verifications; };
    std::byte value{'Z'};
    ULONG done = 999;
    if (route == 2)
    {
        ManifestJournalExpectation boundary;
        boundary.kind = Tx::MutationKind::Rename; boundary.path = rename.path;
        boundary.secondary_path = rename.secondary_path; boundary.has_payload = true;
        ManifestCommitOutcome outcome;
        const bool succeeded = CommitQueuedManifestMutationWithWalBestEffort(&c, boundary,
            L"CompressionAcceptedOlder295", {}, {}, false, &outcome, true);
        if (!Require(!succeeded && !outcome.clean_prepublication_refusal &&
                outcome.status == (census_failure ? Store::CommitStatus::InvariantFailed : Store::CommitStatus::PersistFailed) &&
                outcome.stage == (census_failure ? "before-checkpoint-publication" : "apple-publish-stage-blocked") &&
                (!census_failure || outcome.error.find("CommitPrepublicationHookFailed") == 0),
                "acceptance295: real older host binder returns exact failed phase and NEVER clean refusal")) return false;
    }
    else if (!Require(!NT_SUCCESS(CB_Write(&fs, writer, &value, 1, 1, FALSE, FALSE, &done, &info)) && done == 0,
            "acceptance295: production compression callback refuses with zero acknowledged bytes")) return false;
    c.tx_manager->SetFaultInjectionHook({});
    c.tx_manager->SetJournalFaultInjectionHook({});
    c.metadata_store->SetCommitStageHook({});
    g_compressed_manifest_before_verification_hook = {};
    const auto marks = c.tx_manager->Watermarks();
    if (!Require(accepts == 1 && verifications == 0 &&
            (census_failure ? census_faults >= 1 && publication_faults == 0 : census_faults == 0 && publication_faults == 1) &&
            accepted_wal && !accepted_wal->bytes.empty() && accepted_wal->Unchanged() &&
            accepted_spool && accepted_spool->Unchanged() && accepted_index && accepted_index->Unchanged() &&
            marks.accepted_sequence > initial_marks.accepted_sequence && marks.apfs_durable_sequence == initial_marks.apfs_durable_sequence &&
            marks.cleanup_sequence == initial_marks.cleanup_sequence && marks.accepted_sequence > marks.apfs_durable_sequence &&
            original_image.Unchanged() && f.fixture.coordinator->CheckpointXid() == source_xid &&
            CompressionManifestRefusal279::SameQueue(c, {}) &&
            !c.metadata_store->LookupCommittedInodeByPath(create.path) && !c.metadata_store->LookupCommittedInodeByPath(rename.secondary_path) &&
            c.compression_verification_pending.load() == (older ? 0u : 17u),
            "acceptance295: exact accepted evidence survives failure; accepted older queue is never restored; conversion OID stays armed") ||
        !AcceptedEvidence(f, older, source_xid, marks.accepted_sequence) || !CensusRetained(f, source_xid)) return false;
    if (route == 2) return true;

    FileEvidence marker(c.recovery_marker_file);
    RecoveryMarkerState marker_state;
    if (!Require(TryLoadRecoveryMarkerState(c.recovery_marker_file, marker_state) && marker_state.dirty,
            "acceptance295: retained recovery marker is valid and explicitly dirty")) return false;
    const auto retained = [&](const wchar_t* step) {
        const auto after = c.tx_manager->Watermarks();
        bool ok = true;
        const auto check = [&](const wchar_t* conjunct, auto actual, auto expected) {
            if (actual == expected) return;
            ok = false;
            std::wcerr << L"[acceptance295] phase=" << (census_failure ? L"census" : L"publication")
                << L" route=" << route << L" policy=" << policy << L" step=" << step
                << L" conjunct=" << conjunct << L" actual=" << actual << L" expected=" << expected << L'\n';
        };
        // Evaluate every conjunct so an admission failure cannot hide lost evidence.
        check(L"recovery_active", c.recovery_active.load(), true);
        check(L"write_degraded", c.write_degraded.load(), true);
        check(L"native_write_enabled", c.native_write_enabled.load(), false);
        check(L"overlay_write_enabled", c.overlay_write_enabled.load(), false);
        check(L"IsNativeWriteEnabled", IsNativeWriteEnabled(&c), false);
        check(L"IsMutationWriteEnabled", IsMutationWriteEnabled(&c), false);
        // HasBlockedRecoveryEvidence only describes startup identity/invalid-marker
        // blocks. Live accepted debt is retained by the journal and census instead.
        check(L"startup_evidence_block", HasBlockedRecoveryEvidence(c), false);
        check(L"unapplied_accepted_work", HasUnappliedAcceptedWorkBestEffort(&c), true);
        check(L"preaccept_status", c.manifest_preaccept_failure_status.load(), STATUS_SUCCESS);
        check(L"conversion_oid", c.compression_verification_pending.load(), older ? 0u : 17u);
        check(L"accepted_sequence", after.accepted_sequence, marks.accepted_sequence);
        check(L"apfs_durable_sequence", after.apfs_durable_sequence, marks.apfs_durable_sequence);
        check(L"cleanup_sequence", after.cleanup_sequence, marks.cleanup_sequence);
        check(L"wal_unchanged", accepted_wal->Unchanged(), true);
        check(L"spool_unchanged", accepted_spool->Unchanged(), true);
        check(L"index_unchanged", accepted_index->Unchanged(), true);
        check(L"marker_exists", marker.exists, true);
        check(L"marker_nonempty", !marker.bytes.empty(), true);
        check(L"marker_unchanged", marker.Unchanged(), true);
        check(L"image_unchanged", original_image.Unchanged(), true);
        check(L"checkpoint_xid", f.fixture.coordinator->CheckpointXid(), source_xid);
        check(L"queue_empty", CompressionManifestRefusal279::SameQueue(c, {}), true);
        check(L"census_retained", CensusRetained(f, source_xid), true);
        return Require(ok,
            "acceptance295: both policies keep admission blocked and all accepted evidence/guard/marker unchanged");
    };
    if (!retained(L"after-failure")) return false;
    (void)CB_Flush(&fs, writer, &info);
    if (!retained(L"after-flush") || !Require(!FinalizeMutationJournalBestEffort(&c, L"CompressionAcceptance295"),
            "acceptance295: finalization cannot retire accepted failure debt") || !retained(L"after-finalize")) return false;
    Store::MutationRequest sibling;
    sibling.operation = Store::MutationOperation::CreateFile; sibling.path = L"\\blocked-sibling-295";
    if (!Require(CommitManifestMutations(&f.sibling, {sibling}).status != Store::CommitStatus::Committed,
            "acceptance295: selected unresolved acceptance fences actual sibling publication") || !retained(L"after-sibling")) return false;
    done = 999;
    if (!Require(!NT_SUCCESS(CB_Write(&fs, writer, &value, 1, 1, FALSE, FALSE, &done, &info)) && done == 0,
            "acceptance295: retry cannot accept a duplicate or acknowledge the rejected byte") || !retained(L"after-retry")) return false;
    CB_Close(&fs, writer); writer = nullptr;
    return retained(L"after-close") && AcceptedEvidence(f, older, source_xid, marks.accepted_sequence);
}
} // namespace CompressionManifestAcceptance295

bool TestNativeCompressionManifestAcceptedCensusFailure295()
{
    if (!CompressionReplay222ScratchReady()) return false;
    for (const auto policy : {L"FailClosed", L"BestEffort"})
        for (unsigned route = 0; route != 3; ++route)
            if (!CompressionManifestAcceptance295::AcceptedFailure(true, route, policy)) return false;
    return true;
}

bool TestNativeCompressionManifestAcceptedPublicationFailure295()
{
    if (!CompressionReplay222ScratchReady()) return false;
    for (const auto policy : {L"FailClosed", L"BestEffort"})
        for (unsigned route = 0; route != 3; ++route)
            if (!CompressionManifestAcceptance295::AcceptedFailure(false, route, policy)) return false;
    return true;
}

bool TestNativeCompressionManifestExternalStagingFailure295()
{
    using namespace CompressionManifestAcceptance295;
    using Preparation = apfsaccess::fshost::NativeCompressionRewrite;
    if (!CompressionReplay222ScratchReady()) return false;
    for (const auto policy : {L"FailClosed", L"BestEffort"})
    {
        NativeCompressionManifest266Fixture f;
        if (!Require(f.Initialize(4), "acceptance295: external staging fixture initializes")) return false;
        auto& c = *f.fixture.context; c.args.write_recovery_policy = policy;
        CompressionManifestRefusal279::SelectedEvidence before(f);
        const auto external_path = c.session_root / "external-staging-295.bin";
        const std::vector<std::byte> external_bytes{std::byte{'2'}, std::byte{'9'}, std::byte{'5'}};
        unsigned preparations = 0, stages = 0, binders = 0;
        bool prepared = false, external_written = false;
        const apfsaccess::catalog::ContainerMutationPreparationHook prepare =
            [&](const Store& live, auto& requests, std::string& error) {
                ++preparations;
                Preparation::Admission admission;
                admission.native_writes_admitted = IsNativeWriteEnabled(&c);
                admission.visibility_unresolved = HasBlockedRecoveryEvidence(c);
                admission.manifest_session = true; admission.container_commit_owned = true;
                admission.windows_attributes_pending = false; admission.queued_requests = requests.size();
                admission.publication_budget_bytes = apfsaccess::rw::CompressionRewrite::MaxLogicalBytes;
                const auto inode = live.LookupCommittedInodeByPath(L"\\compressed");
                if (!inode) { error = "Acceptance295MissingSource"; return false; }
                Preparation::Failure failure = Preparation::Failure::None;
                std::lock_guard<std::mutex> journal(c.tx_mutex);
                const auto plan = Preparation::Prepare(live, *c.tx_manager, admission,
                    L"\\compressed", {inode->object_id, inode->xid}, 1, 1, failure);
                prepared = plan && failure == Preparation::Failure::None &&
                    plan->Revalidate(live, *c.tx_manager, admission) == Preparation::Failure::None;
                if (!prepared) { error = "Acceptance295PreparationFailed"; return false; }
                requests = {plan->Request()}; return true;
            };
        const apfsaccess::catalog::ContainerMutationStagingHook external =
            [&](std::size_t index, const auto& request, const auto& identity, std::string& error) {
                ++stages;
                external_written = index == 0 && request.operation == Store::MutationOperation::RewriteCompressedContent &&
                    identity.object_id == 17 && identity.generation == before.xid + 1 &&
                    WriteFileBytes(external_path, external_bytes);
                error = "Acceptance295ExternalEvidenceOwned"; return false;
            };
        const apfsaccess::catalog::ContainerPrepublicationHook binder =
            [&](const auto&, const auto&, std::uint64_t, auto&, std::string&) { ++binders; return true; };
        ManifestCommitOutcome outcome;
        {
            std::unique_lock<std::mutex> commit(c.commit_mutex);
            std::unique_lock<std::shared_mutex> gate(c.committed_read_gate);
            std::lock_guard<std::mutex> metadata(c.metadata_mutex);
            outcome = CommitManifestMutations(&c, {}, binder, external, false, std::nullopt, prepare);
        }
        if (!Require(preparations == 1 && prepared && stages == 1 && external_written && binders == 0 &&
                outcome.status == Store::CommitStatus::InvariantFailed && outcome.stage == "mutation-staging-hook" &&
                outcome.error.find("Acceptance295ExternalEvidenceOwned") != std::string::npos &&
                !outcome.clean_prepublication_refusal && outcome.staged_identities.empty() &&
                ReadFileBytes(external_path) == external_bytes,
                "acceptance295: real prepared conversion rolls back native scratch but external evidence forbids clean classification") ||
            !before.Unchanged(f)) return false;
    }
    return true;
}
