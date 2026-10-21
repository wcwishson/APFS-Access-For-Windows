#pragma once

#include <stdexcept>

#include "PayloadSpool.h"

namespace deferred_tests
{
using namespace apfsaccess::catalog;
using namespace apfsaccess::rw;
using Store = MetadataStore;

struct Fixture
{
    std::filesystem::path root;
    std::filesystem::path image;
    std::string identity;
    std::string error;
    std::unique_ptr<ContainerMountCoordinator> owner;
    TransactionManager journal{L"Strict"};
    std::unique_ptr<PayloadSpool> spool;
    Store* store = nullptr;
    std::uint64_t volume = 101;
    unsigned acceptances = 0;
    unsigned publications = 0;
    unsigned verifications = 0;
    std::vector<std::vector<Store::MutationRequest>> accepted_requests;
    std::vector<std::vector<Store::PayloadIdentity>> accepted_identities;
    std::vector<std::uint64_t> accepted_preimages;

    ~Fixture()
    {
        if (store)
        {
            store->SetCommitStageHook({});
            store->SetFilePayloadRangeProvider({});
        }
    }

    bool Open(const char* label, bool exclusive = false, std::uint64_t selected_volume = 101,
        bool snapshot_cohort = false)
    {
        root = MakeRunDir(label);
        image = root / "two.raw";
        if (!Require(WriteAuthoritativeTwoVolumeImage(image, 0, 32, 32), "deferred: native fixture")) return false;
        if (snapshot_cohort)
        {
            auto bytes = ReadFileBytes(image);
            VectorRandomAccessSource source(bytes);
            const auto checkpoint = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
            if (!Require(checkpoint.has_value(), "deferred: snapshot source checkpoint")) return false;
            AppleSnapshotCreatePlan plan;
            if (!Require(PlanAppleSnapshotCreate(source, *checkpoint,
                    {101, "accepted-worker-history", 1700000000000000000ull}, plan, error),
                    "deferred: real snapshot inventory")) return false;
            const auto apply = [&](const auto& write) {
                const auto offset = write.physical_block * checkpoint->container.superblock.block_size;
                if (!Require(offset <= bytes.size() && write.bytes.size() <= bytes.size() - offset,
                        "deferred: snapshot fixture writes remain bounded")) return false;
                std::copy(write.bytes.begin(), write.bytes.end(), bytes.begin() + offset);
                return true;
            };
            for (const auto& write : plan.commit.publication.before_superblock_writes)
                if (!apply(write)) return false;
            if (!apply(plan.commit.publication.superblock_write) ||
                !Require(WriteFileBytes(image, bytes), "deferred: save native snapshot fixture")) return false;
        }
        volume = selected_volume;
        owner = ContainerMountCoordinator::Open(image.string(), 0, error, CatalogLoadPolicy::StrictApple, false, true, exclusive);
        if (!Require(owner && owner->InitializeRequiredCheckpointCensus({{101, {}}, {102, {}}}, error),
                "deferred: complete census")) return false;
        ContainerVolumeSession session;
        session.container_uuid_hex = owner->ContainerUuidHex();
        session.requested_write = true;
        session.use_canonical_transaction = true;
        session.metadata_context.allow_native_snapshot_runtime = snapshot_cohort;
        if (snapshot_cohort) session.metadata_context.allow_legacy_scaffold_for_fixtures = false;
        for (const auto oid : {101u, 102u})
        {
            session.volume_object_id = oid;
            if (!Require(owner->MountVolume(session, error), "deferred: fixture volume session")) return false;
        }
        store = owner->FindSessionStore(volume);
        identity = "apfs-vol:" + owner->ContainerUuidHex() + ":" + std::to_string(volume);
        journal.SetVolumeIdentity(std::wstring(identity.begin(), identity.end()));
        journal.SetJournalPath((root / "accepted.wal").wstring());
        PayloadSpool::Options options;
        options.root = root / "payload";
        options.volume_identity = identity;
        spool = std::make_unique<PayloadSpool>(options);
        store->SetFilePayloadRangeProvider([this](const auto&, auto object, auto offset, auto destination) {
            std::size_t read = 0;
            return spool->ReadFullyCoveredRange(
                {identity, object.object_id, object.generation, offset, destination}, read) && read == destination.size();
        });
        store->SetCommitStageHook([this](std::string_view stage) {
            if (stage == "before-apple-publish") ++publications;
            return true;
        });
        return true;
    }

    ContainerPrepublicationHook Accept(std::uint64_t accepted_source = 20)
    {
        return [this, accepted_source](const auto& requests, const auto& identities, auto source, auto& pins, auto& why) {
            if (source != accepted_source || requests.empty() || requests.size() != identities.size() || !journal.Begin()) return false;
            for (std::size_t i = 0; i < requests.size(); ++i)
            {
                const auto& request = requests[i];
                TransactionManager::MutationIntent intent;
                if (request.operation == Store::MutationOperation::CreateFile)
                    intent.kind = TransactionManager::MutationKind::CreateFile;
                else if (request.operation == Store::MutationOperation::Write)
                    intent.kind = TransactionManager::MutationKind::Write;
                else if (request.operation == Store::MutationOperation::SetInodeMetadata)
                    intent.kind = TransactionManager::MutationKind::SetInodeMetadata;
                else return false;
                intent.path = request.path;
                intent.offset = request.offset;
                intent.length = request.length;
                intent.object_id = identities[i].object_id;
                intent.generation = identities[i].generation;
                intent.wal_sequence = journal.NextMutationSequence();
                if (intent.kind == TransactionManager::MutationKind::SetInodeMetadata)
                {
                    intent.inline_payload = request.inline_payload;
                    intent.payload_length = intent.inline_payload.size();
                    const auto checksum = PortableSha256Hex(std::string(
                        reinterpret_cast<const char*>(intent.inline_payload.data()), intent.inline_payload.size()));
                    if (checksum.size() != intent.payload_checksum.size() * 2) return false;
                    for (std::size_t n = 0; n < intent.payload_checksum.size(); ++n)
                        intent.payload_checksum[n] = static_cast<std::uint8_t>(std::stoul(checksum.substr(n * 2, 2), nullptr, 16));
                }
                if (intent.kind == TransactionManager::MutationKind::Write)
                {
                    PayloadSpool::AppendResult appended;
                    if (request.deferred_payload.size() != request.length || !spool->Append(
                            {identity, intent.object_id, intent.generation, intent.offset,
                                intent.wal_sequence, request.deferred_payload}, &appended)) return false;
                    intent.payload_spool_offset = appended.spool_offset;
                    intent.payload_length = appended.payload_length;
                    intent.payload_checksum = appended.payload_sha256;
                    intent.inline_payload = request.deferred_payload;
                }
                if (!journal.RecordMutation(intent)) return false;
            }
            if (!spool->FlushDirtyState() || !journal.Accept(source) ||
                !journal.LoadRequiredCheckpointXidsSinceCleanup(pins, &why)) return false;
            ++acceptances;
            accepted_requests.push_back(requests);
            accepted_identities.push_back(identities);
            accepted_preimages.push_back(source);
            return true;
        };
    }

    ContainerCommitResult Defer(const std::vector<Store::MutationRequest>& requests)
    {
        return owner->Commit(volume, requests, Accept(owner->CheckpointXid()), {}, {}, false, std::nullopt, {},
            [this](const Store&, auto, auto&) { ++verifications; return true; }, true, true);
    }

    bool AcceptedWalMatches()
    {
        std::vector<TransactionManager::AcceptedTransaction> transactions;
        if (!journal.LoadAcceptedTransactionsSinceCleanup(transactions, &error) ||
            transactions.size() != accepted_requests.size()) return false;
        for (std::size_t i = 0; i < transactions.size(); ++i)
        {
            const auto& transaction = transactions[i];
            if (transaction.preimage_checkpoint_xid != accepted_preimages[i] ||
                transaction.mutations.size() != accepted_requests[i].size()) return false;
            for (std::size_t j = 0; j < transaction.mutations.size(); ++j)
            {
                const auto& record = transaction.mutations[j];
                const auto& request = accepted_requests[i][j];
                const auto object = accepted_identities[i][j];
                const bool metadata = request.operation == Store::MutationOperation::SetInodeMetadata;
                if (record.volume_identity != identity || record.object_id != object.object_id ||
                    record.parent_object_id != object.generation ||
                    std::wstring(record.path_utf8.begin(), record.path_utf8.end()) != request.path ||
                    record.logical_offset != request.offset || record.logical_length != (metadata ? 0 : request.length) ||
                    record.inline_payload != (metadata ? request.inline_payload : request.deferred_payload) ||
                    (metadata && (record.operation != WriteAheadLog::OperationKind::SetInodeMetadata ||
                        record.payload_length != request.inline_payload.size() ||
                        !WriteAheadLog::InodeMetadataMutationIsConsistent(record)))) return false;
            }
        }
        return true;
    }

    bool WorkingBytes(const std::wstring& path, Store::PayloadIdentity object, const std::vector<std::byte>& expected)
    {
        const auto inode = store->LookupWorkingInodeByPath(path);
        std::vector<std::byte> actual(expected.size());
        std::size_t read = 0;
        return inode && inode->object_id == object.object_id && inode->xid == object.generation &&
            inode->logical_size == expected.size() && spool->ReadFullyCoveredRange(
                {identity, object.object_id, object.generation, 0, actual}, read) &&
            read == expected.size() && actual == expected;
    }
};

Store::MutationRequest Create(const wchar_t* path)
{
    Store::MutationRequest request;
    request.operation = Store::MutationOperation::CreateFile;
    request.path = path;
    return request;
}

Store::MutationRequest Write(const wchar_t* path, std::uint64_t offset, std::size_t size, unsigned seed)
{
    Store::MutationRequest request;
    request.operation = Store::MutationOperation::Write;
    request.path = path;
    request.offset = offset;
    request.length = size;
    request.deferred_payload.resize(size);
    for (std::size_t i = 0; i < size; ++i) request.deferred_payload[i] = static_cast<std::byte>((i * 31u + seed) & 0xffu);
    return request;
}

bool TestBatchesPublishOnceAndReopen()
{
    Fixture f;
    if (!f.Open("deferred-batches")) return false;
    bool ok = true;
    const auto original = ReadFileBytes(f.image);
    const auto first = Write(L"\\first", 0, 8192, 7);
    const auto overwrite = Write(L"\\first", 4093, 5000, 29);
    const auto tail = Write(L"\\first", 9093, 5007, 83);
    const auto second = Write(L"\\second", 0, 4097, 111);
    const std::vector<std::vector<Store::MutationRequest>> batches{
        {Create(L"\\first"), first}, {overwrite, Create(L"\\second"), second}, {tail}};
    auto expected = first.deferred_payload;
    Store::PayloadIdentity first_identity{}, second_identity{};
    for (std::size_t i = 0; i < batches.size(); ++i)
    {
        const auto before = f.owner->DiagnosticsSnapshot();
        const auto selected_before = f.owner->DiagnosticsSnapshot(101);
        const auto result = f.Defer(batches[i]);
        if (!Require(result.accepted_without_publication, "deferred: each batch accepted"))
        {
            std::fprintf(stderr, "[DIAG] deferred batch %zu: %s stage=%s\n", i, result.error.c_str(), result.commit_stage.c_str());
            return false;
        }
        ok &= Require(!result.committed && !result.commit_recovery_required && result.error.empty() &&
                result.commit_stage == "accepted-deferred" && result.checkpoint_xid == 20 && result.committed_xid == 20 &&
                !result.clean_prepublication_refusal && result.staged_identities.size() == batches[i].size(),
            "deferred: acceptance is distinct from publication or clean refusal");
        for (const auto oid : {0u, 101u})
        {
            const auto prior = oid == 0 ? before : selected_before;
            const auto after = f.owner->DiagnosticsSnapshot(oid == 0 ? std::nullopt : std::optional<std::uint64_t>{oid});
            ok &= Require(after.commit_attempts == prior.commit_attempts + 1 &&
                    after.commit_deferred_acceptances == prior.commit_deferred_acceptances + 1 &&
                    after.commit_failures == prior.commit_failures && after.commit_successes == prior.commit_successes &&
                    after.commit_noops == prior.commit_noops && after.last_failure_stage == prior.last_failure_stage &&
                    after.last_failure_detail == prior.last_failure_detail,
                "deferred: container and selected diagnostics count only acceptance");
        }
        if (i == 0) first_identity = result.staged_identities.front();
        else
        {
            const auto& write = i == 1 ? overwrite : tail;
            expected.resize(static_cast<std::size_t>(write.offset + write.length));
            std::copy(write.deferred_payload.begin(), write.deferred_payload.end(), expected.begin() + write.offset);
        }
        for (const auto object : result.staged_identities)
            ok &= Require(object.object_id != 0 && object.generation == 21, "deferred: staged identity uses one successor generation");
        ok &= Require(result.staged_identities.front().object_id == first_identity.object_id &&
                f.WorkingBytes(L"\\first", first_identity, expected), "deferred: earlier bytes and identity survive overlapping batches");
        if (i == 1) second_identity = result.staged_identities[1];
        if (i >= 1)
            ok &= Require(second_identity.object_id != first_identity.object_id &&
                    f.WorkingBytes(L"\\second", second_identity, second.deferred_payload),
                "deferred: second file has independent identity and bytes");
        const auto watermarks = f.journal.Watermarks();
        const auto census = f.owner->CheckpointCensusSnapshot();
        ok &= Require(f.AcceptedWalMatches() && watermarks.accepted_sequence > 0 && watermarks.apfs_durable_sequence == 0 &&
                watermarks.cleanup_sequence == 0 && f.journal.HasUnappliedAcceptedWork() &&
                census.size() == 2 && census[0].unapplied_accepted_work && census[0].required_checkpoint_xids == std::vector<std::uint64_t>{20} &&
                !census[1].unapplied_accepted_work && census[1].required_checkpoint_xids.empty(),
            "deferred: exact WAL bytes, source pin and unresolved owner survive every batch");
        ok &= Require(f.publications == 0 && f.verifications == 0 && f.owner->CheckpointXid() == 20 &&
                f.store->CheckpointXid() == 20 && f.store->PendingMutationCount() > 0 &&
                !f.store->LookupCommittedInodeByPath(L"\\first") && ReadFileBytes(f.image) == original,
            "deferred: complete image and durable namespace remain unchanged");
    }
    unsigned sibling_hooks = 0;
    const auto pending = CheckpointDeltaCodec::Encode(f.store->DebugBuildPendingCheckpointDelta());
    const auto sibling = f.owner->Commit(102, {Create(L"\\blocked")},
        [&](const auto&, const auto&, auto, auto&, auto&) { ++sibling_hooks; return true; },
        [&](auto, const auto&, const auto&, auto&) { ++sibling_hooks; return true; }, {}, false, {}, {}, {}, true, true);
    ok &= Require(!sibling.committed && !sibling.accepted_without_publication && sibling.clean_prepublication_refusal &&
            sibling.commit_status_code == static_cast<int>(Store::CommitStatus::RetentionBlocked) &&
            sibling.commit_stage == "awaiting-accepted-recovery" && sibling_hooks == 0 &&
            !sibling.commit_recovery_required && !f.owner->IsRecoveryRequired() &&
            f.owner->FindSessionStore(102)->PendingMutationCount() == 0 &&
            CheckpointDeltaCodec::Encode(f.store->DebugBuildPendingCheckpointDelta()) == pending &&
            ReadFileBytes(f.image) == original, "deferred: sibling refusal preserves selected accepted work before any hook");

    const auto before_publish = f.owner->DiagnosticsSnapshot(101);
    const auto final = f.owner->Commit(101, {}, {}, {}, {}, false, {}, {},
        [&](const Store&, auto xid, auto&) { ++f.verifications; return xid == 21; }, true);
    ok &= Require(final.committed && !final.accepted_without_publication && !final.commit_recovery_required &&
            final.commit_status_code == static_cast<int>(Store::CommitStatus::Committed) && final.checkpoint_xid == 21 &&
            f.publications == 1 && f.verifications == 1 && f.acceptances == batches.size() &&
            f.store->PendingMutationCount() == 0 && f.owner->CheckpointXid() == 21,
        "deferred: empty final commit publishes every accepted batch exactly once");
    if (!final.committed)
    {
        std::fprintf(stderr, "[DIAG] deferred final: %s stage=%s\n", final.error.c_str(), final.commit_stage.c_str());
        return false;
    }
    const auto after_publish = f.owner->DiagnosticsSnapshot(101);
    ok &= Require(after_publish.commit_successes == before_publish.commit_successes + 1 &&
            after_publish.commit_deferred_acceptances == before_publish.commit_deferred_acceptances &&
            after_publish.commit_failures == before_publish.commit_failures &&
            f.owner->CheckpointCensusSnapshot()[0].unapplied_accepted_work && f.AcceptedWalMatches(),
        "deferred: publication success retains accepted evidence until durable cleanup");
    const auto published = ReadFileBytes(f.image);
    const auto awaiting_cleanup = f.owner->Commit(102, {Create(L"\\blocked")});
    ok &= Require(!awaiting_cleanup.committed && awaiting_cleanup.clean_prepublication_refusal &&
            awaiting_cleanup.commit_status_code == static_cast<int>(Store::CommitStatus::RetentionBlocked) &&
            !f.owner->IsRecoveryRequired() && ReadFileBytes(f.image) == published,
        "deferred: sibling remains retryable until published work is durably finalized");
    const auto sequence = f.journal.Watermarks().accepted_sequence;
    std::vector<std::uint64_t> pins;
    ok &= Require(f.journal.MarkApfsDurableThrough(sequence) && f.spool->CleanupThroughSequence(sequence) &&
            f.journal.MarkCleanedThrough(sequence) && f.journal.LoadRequiredCheckpointXidsSinceCleanup(pins, &f.error) &&
            pins.empty() && f.owner->UpdateRequiredCheckpointXids(101, pins, f.error, false),
        "deferred: explicit finalization releases WAL and source pin");
    const auto sibling_retry = f.owner->Commit(102, {Create(L"\\blocked")});
    ok &= Require(sibling_retry.committed && !sibling_retry.accepted_without_publication &&
            sibling_retry.checkpoint_xid == 22 && !f.owner->IsRecoveryRequired() &&
            f.owner->FindSessionStore(102)->LookupCommittedInodeByPath(L"\\blocked").has_value(),
        "deferred: same sibling request succeeds after selected flush and cleanup without remount");
    f.store->SetCommitStageHook({});
    f.store->SetFilePayloadRangeProvider({});
    f.store = nullptr;
    f.owner.reset();
    auto reopened = ContainerMountCoordinator::Open(f.image.string(), 0, f.error);
    if (!Require(reopened && reopened->CheckpointXid() == 22, "deferred: fresh owner sees selected and sibling publications")) return false;
    ContainerVolumeSession session;
    session.volume_object_id = 101; session.container_uuid_hex = reopened->ContainerUuidHex();
    session.use_canonical_transaction = true;
    if (!Require(reopened->MountVolume(session, f.error), "deferred: reopen image session")) return false;
    const auto* store = reopened->FindSessionStore(101);
    for (const auto& entry : {std::make_pair(L"\\first", expected), std::make_pair(L"\\second", second.deferred_payload)})
    {
        const auto object = entry.first == std::wstring(L"\\first") ? first_identity : second_identity;
        const auto inode = store->LookupCommittedInodeByPath(entry.first);
        std::vector<std::byte> actual;
        ok &= Require(inode && inode->object_id == object.object_id && inode->xid == object.generation &&
                inode->logical_size == entry.second.size() && store->ReadCommittedFileRange(entry.first, 0, entry.second.size() + 1, actual) &&
                actual == entry.second, "deferred: fresh native read has exact identity, EOF and payload without spool provider");
    }
    return ok;
}

bool TestFailuresPreserveAcceptedWork()
{
    bool ok = true;
    for (const std::string mode : {"hook-required", "preparation", "preparation-throw", "mutation", "staging-refuse", "staging-throw", "wal-refuse", "wal-throw", "plan"})
    {
        Fixture f;
        if (!f.Open(("deferred-failure-" + mode).c_str())) return false;
        const auto payload = Write(L"\\accepted", 0, 6147, 43);
        const auto accepted = f.Defer({Create(L"\\accepted"), payload});
        if (!Require(accepted.accepted_without_publication && accepted.staged_identities.size() == 2,
                "deferred failure: seed accepted bytes")) return false;
        const auto object = accepted.staged_identities.front();
        const auto image = ReadFileBytes(f.image);
        const auto wal = ReadFileBytes(f.root / "accepted.wal");
        const auto pending_count = f.store->PendingMutationCount();
        const auto diagnostics = f.owner->DiagnosticsSnapshot(101);
        ContainerPrepublicationHook accept = f.Accept();
        ContainerMutationStagingHook staging;
        ContainerMutationPreparationHook preparation;
        std::vector<Store::MutationRequest> requests{Create(L"\\unaccepted")};
        bool defer = true;
        if (mode == "hook-required") accept = {};
        else if (mode == "preparation" || mode == "preparation-throw") preparation = [&](const Store&, auto&, auto&) -> bool {
            if (mode == "preparation-throw") throw std::runtime_error("injected preparation failure");
            return false;
        };
        else if (mode == "mutation") requests = {Write(L"\\missing", 0, 1, 5)};
        else if (mode == "staging-refuse" || mode == "staging-throw") staging = [&](auto, const auto&, const auto&, auto&) -> bool {
            if (mode == "staging-throw") throw std::runtime_error("injected staging failure");
            return false;
        };
        else if (mode == "wal-refuse" || mode == "wal-throw") accept = [&](const auto&, const auto&, auto, auto&, auto&) -> bool {
            if (mode == "wal-throw") throw std::runtime_error("injected acceptance failure");
            return false;
        };
        else if (mode == "plan")
        {
            defer = false; requests.clear(); accept = {};
            f.store->SetCommitStageHook([](std::string_view stage) { return stage != "before-apple-plan"; });
        }
        const auto failed = f.owner->Commit(101, requests, accept, staging, {}, false, {}, preparation, {}, true, defer);
        const auto census = f.owner->CheckpointCensusSnapshot();
        const auto after = f.owner->DiagnosticsSnapshot(101);
        const std::string expected_stage = mode == "hook-required" ? "deferred-publication-hook-required" :
            mode == "preparation" || mode == "preparation-throw" ? "mutation-preparation-hook" :
            mode == "mutation" ? "mutation-staging" :
            mode == "staging-refuse" || mode == "staging-throw" ? "mutation-staging-hook" :
            mode == "plan" ? "apple-plan-stage-blocked" : "before-checkpoint-publication";
        const bool preserved = !failed.committed && !failed.accepted_without_publication && !failed.clean_prepublication_refusal &&
            failed.commit_stage == expected_stage &&
            f.store->PendingMutationCount() >= pending_count && f.WorkingBytes(L"\\accepted", object, payload.deferred_payload) &&
            f.AcceptedWalMatches() && ReadFileBytes(f.root / "accepted.wal") == wal &&
            f.owner->CheckpointXid() == 20 && ReadFileBytes(f.image) == image &&
            census.size() == 2 && census[0].unapplied_accepted_work && census[0].required_checkpoint_xids == std::vector<std::uint64_t>{20} &&
            after.rollback_reload_attempts == diagnostics.rollback_reload_attempts &&
            after.commit_deferred_acceptances == diagnostics.commit_deferred_acceptances &&
            after.commit_successes == diagnostics.commit_successes && after.commit_failures == diagnostics.commit_failures + 1;
        std::fprintf(stderr, "[DIAG] deferred failure %s: preserved=%d pending=%zu stage=%s error=%s\n",
            mode.c_str(), preserved ? 1 : 0, f.store->PendingMutationCount(), failed.commit_stage.c_str(), failed.error.c_str());
        ok &= Require(preserved, "deferred failure: refusal or exception never reloads away accepted bytes, identity or WAL");
        if (mode == "staging-refuse" || mode == "staging-throw" || mode == "wal-refuse" || mode == "wal-throw")
            ok &= Require(failed.commit_recovery_required && f.owner->IsRecoveryRequired() &&
                    !f.owner->Commit(101, {}).committed && ReadFileBytes(f.image) == image,
                "deferred failure: partially staged unaccepted batch cannot leak into a later publication");
    }
    return ok;
}

bool TestUnstagedAcceptedDebtIsNotDeferredWorkingState()
{
    Fixture f;
    if (!f.Open("deferred-unstaged-debt")) return false;
    if (!Require(f.owner->UpdateRequiredCheckpointXids(101, {20}, f.error, true),
            "deferred debt: unresolved startup acceptance")) return false;
    const auto image = ReadFileBytes(f.image);
    const auto rejected = f.Defer({Create(L"\\must-not-replace-accepted-work")});
    return Require(!rejected.committed && !rejected.accepted_without_publication &&
            rejected.commit_status_code == static_cast<int>(Store::CommitStatus::RetentionBlocked) &&
            rejected.error == "VolumeAcceptedRecoveryPending: oid=101" &&
            rejected.commit_stage == "awaiting-accepted-recovery" && f.acceptances == 0 &&
            f.store->PendingMutationCount() == 0 && f.publications == 0 &&
            f.owner->CheckpointXid() == 20 && ReadFileBytes(f.image) == image &&
            !f.owner->IsRecoveryRequired(),
        "deferred debt: selected unresolved census without staged state still requires explicit recovery");
}

bool TestFirstPreacceptanceRefusalRemainsRetryable()
{
    bool ok = true;
    for (const std::string mode : {"preparation", "mutation", "staging"})
    {
        Fixture f;
        if (!f.Open(("deferred-first-refusal-" + mode).c_str())) return false;
        const auto image = ReadFileBytes(f.image);
        ContainerMutationPreparationHook preparation;
        ContainerMutationStagingHook staging;
        std::vector<Store::MutationRequest> requests{Create(L"\\refused")};
        if (mode == "preparation") preparation = [](const Store&, auto&, auto&) { return false; };
        else if (mode == "staging") staging = [](auto, const auto&, const auto&, auto&) { return false; };
        else requests.push_back(Write(L"\\missing", 0, 1, 5));
        const auto refused = f.owner->Commit(101, requests, f.Accept(), staging, {}, false, {}, preparation, {}, true, true);
        const auto census = f.owner->CheckpointCensusSnapshot();
        const std::string expected_stage = mode == "preparation" ? "mutation-preparation-hook" :
            mode == "staging" ? "mutation-staging-hook" : "mutation-staging";
        ok &= Require(!refused.committed && !refused.accepted_without_publication && refused.commit_stage == expected_stage &&
                !refused.commit_recovery_required && !f.owner->IsRecoveryRequired() && f.acceptances == 0 &&
                f.store->PendingMutationCount() == 0 && !f.store->LookupWorkingInodeByPath(L"\\refused") &&
                f.store->IsNativeWriteReady() && f.journal.Watermarks().accepted_sequence == 0 &&
                census.size() == 2 && !census[0].unapplied_accepted_work && census[0].required_checkpoint_xids.empty() &&
                ReadFileBytes(f.image) == image,
            "deferred first refusal: unaccepted scratch rolls back without degrading the volume");
        const auto retry = f.Defer({Create(L"\\retry"), Write(L"\\retry", 0, 8193, 19)});
        ok &= Require(retry.accepted_without_publication && !retry.commit_recovery_required && f.AcceptedWalMatches(),
            "deferred first refusal: next batch can be accepted without remount");
    }
    return ok;
}
} // namespace deferred_tests
