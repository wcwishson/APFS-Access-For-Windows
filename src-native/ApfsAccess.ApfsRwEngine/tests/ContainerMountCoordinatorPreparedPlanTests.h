#pragma once

namespace prepared_plan_tests
{
using namespace apfsaccess::catalog;
using namespace apfsaccess::rw;
using Store = MetadataStore;

bool TestIdenticalMetadataAndPayload(std::uint64_t volume, bool payload)
{
    std::vector<std::byte> baseline;
    std::uint64_t baseline_space = 0;
    bool ok = true;
    for (const bool exclusive : {false, true})
    {
        deferred_tests::Fixture f;
        if (!f.Open(exclusive ? "prepared-owned" : "prepared-shared", exclusive, volume)) return false;
        const auto before = f.store->DebugAppleTransactionPlanningCount();
        std::vector<Store::MutationRequest> requests{deferred_tests::Create(L"\\first")};
        requests.front().timestamp_utc = 132000000000000000;
        if (payload) requests.push_back(deferred_tests::Write(L"\\first", 0, 4097, 37));
        else
        {
            requests.push_back(deferred_tests::Create(L"\\second"));
            requests.back().timestamp_utc = requests.front().timestamp_utc;
        }
        for (auto& request : requests) request.timestamp_utc = 132000000000000000;
        const auto result = f.owner->Commit(volume, requests, f.Accept());
        if (!Require(result.committed && result.error.empty(), "prepared: canonical real-WAL commit"))
        {
            std::fprintf(stderr, "[DIAG] prepared volume=%llu payload=%d exclusive=%d stage=%s error=%s\n",
                static_cast<unsigned long long>(volume), payload, exclusive, result.commit_stage.c_str(), result.error.c_str());
            return false;
        }
        const auto count = f.store->DebugAppleTransactionPlanningCount() - before;
        ok &= Require(count == (exclusive && !payload ? 1u : 2u),
            "prepared: actual planner runs once for owned metadata, twice for shared or payload");
        ok &= Require(f.AcceptedWalMatches() && f.journal.Watermarks().accepted_sequence > 0 &&
                f.journal.Watermarks().apfs_durable_sequence == 0 && f.journal.Watermarks().cleanup_sequence == 0,
            "prepared: original accepted WAL is retained until explicit verification/cleanup");
        if (payload)
        {
            std::vector<std::byte> actual;
            ok &= Require(f.store->ReadCommittedFileRange(L"\\first", 0, 4097, actual) &&
                    actual == requests.back().deferred_payload,
                "prepared: zero-byte capacity geometry never becomes file content");
        }
        const auto sequence = f.journal.Watermarks().accepted_sequence;
        std::vector<std::uint64_t> pins;
        ok &= Require(f.journal.MarkApfsDurableThrough(sequence) && f.journal.MarkCleanedThrough(sequence) &&
                f.journal.LoadRequiredCheckpointXidsSinceCleanup(pins, &f.error) && pins.empty() &&
                f.owner->UpdateRequiredCheckpointXids(volume, pins, f.error),
            "prepared: verified durable cleanup releases the original pins");
        const auto space = f.owner->LookupSharedSpace(f.owner->ContainerUuidHex(), volume);
        if (!Require(space.has_value(), "prepared: durable shared space present")) return false;
        const auto available = space->available_bytes;
        ok &= Require(f.owner->CheckpointXid() == 21 && f.owner->DrainAndStop(std::chrono::seconds(2)).clean,
            "prepared: one generation and clean owned drain");
        f.store = nullptr;
        f.owner.reset();
        const auto bytes = ReadFileBytes(f.image);
        if (!exclusive) { baseline = bytes; baseline_space = available; }
        else ok &= Require(bytes == baseline && available == baseline_space,
            "prepared: complete on-disk bytes and allocation match the original planner path");
        auto reopened = ContainerMountCoordinator::Open(f.image.string(), 0, f.error, CatalogLoadPolicy::StrictApple);
        ContainerVolumeSession session;
        session.volume_object_id = volume; session.container_uuid_hex = reopened ? reopened->ContainerUuidHex() : "";
        if (!Require(reopened && reopened->MountVolume(session, f.error), "prepared: canonical remount")) return false;
        ok &= Require(reopened->FindSessionStore(volume)->LookupCommittedInodeByPath(L"\\first").has_value() &&
                (payload || reopened->FindSessionStore(volume)->LookupCommittedInodeByPath(L"\\second").has_value()),
            "prepared: namespace survives canonical reopen");
    }
    return ok;
}

bool TestSourceChangesRetainAcceptedDebt(unsigned boundary)
{
    deferred_tests::Fixture f;
    if (!f.Open("prepared-source-change", true)) return false;
    auto& device = const_cast<BlockDevice&>(f.owner->Device());
    std::vector<std::byte> original, anchor;
    if (!Require(device.Read(0, 512 * 4096, original) && device.Read(0, 4096, anchor),
            "prepared source: held original bytes")) return false;
    unsigned injections = 0, writes = 0;
    f.store->SetCommitStageHook([&](std::string_view stage) {
        if (stage == "before-apple-device-write") ++writes;
        if ((boundary == 1 && stage == "before-apple-plan") ||
            (boundary == 2 && stage == "before-apple-publish"))
        {
            ++injections;
            return device.Write(0, anchor) && device.Flush();
        }
        return true;
    });
    const auto accept = f.Accept();
    auto create = deferred_tests::Create(L"\\must-remain-accepted");
    create.timestamp_utc = 132000000000000000;
    const auto result = f.owner->Commit(101, {create}, [&](const auto& requests, const auto& identities,
        auto source, auto& pins, auto& why) {
        if (!accept(requests, identities, source, pins, why)) return false;
        if (boundary == 0)
        {
            ++injections;
            return device.Write(0, anchor) && device.Flush();
        }
        return true;
    });
    std::vector<std::byte> after;
    return Require(injections == 1 && writes == 0 && !result.committed &&
            result.commit_stage == "apple-prepared-source-changed" && result.commit_recovery_required &&
            f.store->LastCommitFailureReason() == L"ApplePreparedPlanSourceChanged" &&
            f.store->DebugAppleTransactionPlanningCount() == 1 &&
            f.owner->CheckpointXid() == 20 && device.Read(0, original.size(), after) && after == original,
        "prepared source: same-byte/same-XID write invalidates ticket before publisher writes") &&
        Require(f.AcceptedWalMatches() && f.journal.HasUnappliedAcceptedWork() &&
            f.journal.Watermarks().apfs_durable_sequence == 0 && f.journal.Watermarks().cleanup_sequence == 0,
        "prepared source: refusal retains exact accepted WAL and original debt");
}

bool TestPublisherGuardStillChecksAfterWrites()
{
    deferred_tests::Fixture f;
    if (!f.Open("prepared-publisher-guard", true)) return false;
    auto& device = const_cast<BlockDevice&>(f.owner->Device());
    const auto* checkpoint = f.store->AuthoritativeAppleCheckpointView();
    if (!Require(checkpoint != nullptr, "prepared guard: exact source checkpoint")) return false;
    const auto offset = checkpoint->container.superblock_physical_block * checkpoint->container.superblock.block_size;
    auto corrupted = checkpoint->container.superblock_bytes;
    corrupted[0] ^= std::byte{1};
    unsigned writes = 0, switches = 0, injections = 0;
    f.store->SetCommitStageHook([&](std::string_view stage) {
        if (stage == "before-apple-device-write") ++writes;
        if (stage == "before-apple-checkpoint-switch") ++switches;
        if (stage == "before-apple-prepublication-flush")
        {
            ++injections;
            return device.Write(offset, corrupted);
        }
        return true;
    });
    auto create = deferred_tests::Create(L"\\guarded");
    create.timestamp_utc = 132000000000000000;
    const auto result = f.owner->Commit(101, {create}, f.Accept());
    return Require(!result.committed && result.commit_recovery_required && writes == 1 && injections == 1 &&
            switches == 0 && f.owner->CheckpointXid() == 20 &&
            f.store->LastCommitFailureDetail() == L"AppleCheckpointGuardChanged" &&
            f.store->DebugAppleTransactionPlanningCount() == 1 && f.AcceptedWalMatches() &&
            f.journal.Watermarks().apfs_durable_sequence == 0 && f.journal.Watermarks().cleanup_sequence == 0,
        "prepared guard: real publisher rechecks guards after writes/flush and preserves accepted debt");
}

bool TestStagingChangesRetainAcceptedDebt(unsigned boundary, bool change_pins)
{
    deferred_tests::Fixture f;
    if (!f.Open("prepared-staging-change", true)) return false;
    std::uint64_t source = 20;
    if (change_pins)
    {
        auto prefix = deferred_tests::Create(L"\\prefix");
        prefix.timestamp_utc = 132000000000000000;
        if (!Require(f.owner->Commit(101, {prefix}, f.Accept()).committed,
                "prepared staging: real accepted historical prefix")) return false;
        const auto sequence = f.journal.Watermarks().accepted_sequence;
        if (!Require(f.journal.MarkApfsDurableThrough(sequence) && f.journal.MarkCleanedThrough(sequence) &&
                f.owner->UpdateRequiredCheckpointXids(101, {}, f.error),
                "prepared staging: prefix debt cleaned before late pin rescan")) return false;
        f.accepted_requests.clear(); f.accepted_identities.clear(); f.accepted_preimages.clear();
        source = 21;
    }
    auto& device = const_cast<BlockDevice&>(f.owner->Device());
    std::vector<std::byte> original, after;
    if (!device.Read(0, 512 * 4096, original)) return false;
    const auto planning_before = f.store->DebugAppleTransactionPlanningCount();
    unsigned injections = 0, writes = 0;
    const auto inject = [&] {
        ++injections;
        auto extra = deferred_tests::Create(L"\\outside-accepted-wal");
        extra.timestamp_utc = 132000000000000000;
        return f.store->StageMutation(extra) == Store::MutationStatus::Applied;
    };
    f.store->SetCommitStageHook([&](std::string_view stage) {
        if (stage == "before-apple-device-write") ++writes;
        if ((boundary == 1 && stage == "before-apple-plan") ||
            (boundary == 2 && stage == "before-apple-publish")) return inject();
        return true;
    });
    auto create = deferred_tests::Create(L"\\accepted");
    create.timestamp_utc = 132000000000000000;
    const auto accept = f.Accept(source);
    const auto result = f.owner->Commit(101, {create}, [&](const auto& requests, const auto& identities,
        auto preimage, auto& pins, auto& why) {
        if (!accept(requests, identities, preimage, pins, why)) return false;
        if (change_pins) pins.push_back(20);
        return boundary != 0 || inject();
    });
    const auto expected_plans = change_pins && boundary == 2 ? 2u : 1u;
    return Require(injections == 1 && writes == 0 && !result.committed && result.commit_recovery_required &&
            result.commit_stage == "apple-prepared-staging-changed" &&
            f.store->LastCommitFailureReason() == L"ApplePreparedPlanStagingChanged" &&
            f.store->DebugAppleTransactionPlanningCount() - planning_before == expected_plans &&
            f.owner->CheckpointXid() == source && device.Read(0, original.size(), after) && after == original,
        "prepared staging: changed accepted stream refused even through changed-pin fallback") &&
        Require(f.AcceptedWalMatches() && f.journal.HasUnappliedAcceptedWork() &&
            f.journal.Watermarks().apfs_durable_sequence == f.journal.Watermarks().cleanup_sequence &&
            f.journal.Watermarks().accepted_sequence > f.journal.Watermarks().apfs_durable_sequence,
        "prepared staging: exact original WAL and uncleaned debt survive refusal");
}

bool TestChangedPinsReplanLegitimately()
{
    deferred_tests::Fixture f;
    if (!f.Open("prepared-changed-pins", true)) return false;
    auto prefix = deferred_tests::Create(L"\\prefix");
    prefix.timestamp_utc = 132000000000000000;
    if (!f.owner->Commit(101, {prefix}, f.Accept()).committed) return false;
    const auto sequence = f.journal.Watermarks().accepted_sequence;
    if (!f.journal.MarkApfsDurableThrough(sequence) || !f.journal.MarkCleanedThrough(sequence) ||
        !f.owner->UpdateRequiredCheckpointXids(101, {}, f.error)) return false;
    f.accepted_requests.clear(); f.accepted_identities.clear(); f.accepted_preimages.clear();
    const auto before = f.store->DebugAppleTransactionPlanningCount();
    const auto accept = f.Accept(21);
    auto create = deferred_tests::Create(L"\\new-pin");
    create.timestamp_utc = 132000000000000000;
    const auto result = f.owner->Commit(101, {create}, [&](const auto& requests, const auto& identities,
        auto source, auto& pins, auto& why) {
        if (!accept(requests, identities, source, pins, why)) return false;
        pins.push_back(20);
        return true;
    });
    return Require(result.committed && !result.commit_recovery_required && f.owner->CheckpointXid() == 22 &&
            f.store->DebugAppleTransactionPlanningCount() - before == 2 && f.AcceptedWalMatches() &&
            f.store->LookupCommittedInodeByPath(L"\\new-pin").has_value(),
        "prepared pins: valid available historical pin uses full planner with original accepted stream");
}

bool TestPublisherHooksRetainAcceptedDebt(const char* boundary, bool before_writes)
{
    deferred_tests::Fixture f;
    if (!f.Open("prepared-publisher-staging", true)) return false;
    auto& device = const_cast<BlockDevice&>(f.owner->Device());
    std::vector<std::byte> original, after;
    if (!device.Read(0, 512 * 4096, original)) return false;
    unsigned injections = 0;
    f.store->SetCommitStageHook([&](std::string_view stage) {
        if (stage != boundary) return true;
        ++injections;
        auto extra = deferred_tests::Create(L"\\outside-published-wal");
        extra.timestamp_utc = 132000000000000000;
        return f.store->StageMutation(extra) == Store::MutationStatus::Applied;
    });
    auto create = deferred_tests::Create(L"\\accepted");
    create.timestamp_utc = 132000000000000000;
    const auto result = f.owner->Commit(101, {create}, f.Accept());
    return Require(injections == 1 && !result.committed && result.commit_recovery_required &&
            result.commit_stage == "apple-prepared-staging-changed" &&
            f.store->LastCommitFailureReason() == L"ApplePreparedPlanStagingChanged" &&
            f.store->DebugAppleTransactionPlanningCount() == 1 && f.AcceptedWalMatches() &&
            f.journal.Watermarks().apfs_durable_sequence == 0 && f.journal.Watermarks().cleanup_sequence == 0,
        "prepared publisher: every later hook preserves original accepted debt on changed staging") &&
        Require(!before_writes || (device.Read(0, original.size(), after) && after == original),
        "prepared publisher: prewrite staging change leaves complete image unchanged");
}

bool TestOptionalRetentionFailureFallsBack()
{
    std::vector<std::byte> baseline;
    bool ok = true;
    for (unsigned mode = 0; mode != 3; ++mode)
    {
        deferred_tests::Fixture f;
        if (!f.Open("prepared-optional-retain", mode != 0)) return false;
        unsigned injected = 0;
        f.store->SetCommitStageHook([&](std::string_view stage) {
            if (stage != "after-apple-prepared-plan-retain") return true;
            ++injected;
            if (mode == 2) throw std::bad_alloc{};
            return false;
        });
        const auto before = f.store->DebugAppleTransactionPlanningCount();
        auto create = deferred_tests::Create(L"\\fallback");
        create.timestamp_utc = 132000000000000000;
        const auto result = f.owner->Commit(101, {create}, f.Accept());
        ok &= Require(result.committed && !result.commit_recovery_required &&
                injected == (mode ? 1u : 0u) && f.store->DebugAppleTransactionPlanningCount() - before == 2 &&
                f.AcceptedWalMatches() && f.store->PendingMutationCount() == 0 && f.owner->CheckpointXid() == 21,
            "prepared retention: denied or allocation-failed optional retention preserves original successful flow");
        const auto sequence = f.journal.Watermarks().accepted_sequence;
        ok &= Require(f.journal.MarkApfsDurableThrough(sequence) && f.journal.MarkCleanedThrough(sequence) &&
                f.owner->UpdateRequiredCheckpointXids(101, {}, f.error) &&
                f.owner->DrainAndStop(std::chrono::seconds(2)).clean,
            "prepared retention: fallback finishes durable cleanup and owned drain");
        f.store = nullptr; f.owner.reset();
        const auto bytes = ReadFileBytes(f.image);
        if (!mode) baseline = bytes;
        else ok &= Require(bytes == baseline, "prepared retention: optional failure produces identical complete image bytes");
    }
    return ok;
}

bool TestRetentionSourceChangeBeforeAcceptance(bool throw_allocation)
{
    deferred_tests::Fixture f;
    if (!f.Open("prepared-retain-source-change", true)) return false;
    auto& device = const_cast<BlockDevice&>(f.owner->Device());
    std::vector<std::byte> original, anchor, after;
    if (!device.Read(0, 512 * 4096, original) || !device.Read(0, 4096, anchor)) return false;
    unsigned injections = 0;
    f.store->SetCommitStageHook([&](std::string_view stage) {
        if (stage != "after-apple-prepared-plan-retain") return true;
        ++injections;
        if (!device.Write(0, anchor) || !device.Flush()) return false;
        if (throw_allocation) throw std::bad_alloc{};
        return true;
    });
    auto create = deferred_tests::Create(L"\\unaccepted");
    create.timestamp_utc = 132000000000000000;
    const auto result = f.owner->Commit(101, {create}, f.Accept());
    f.store = f.owner->FindSessionStore(101);
    return Require(injections == 1 && !result.committed && f.acceptances == 0 &&
            result.error.find("ApplePreparedPlanSourceChanged") != std::string::npos &&
            f.journal.Watermarks().accepted_sequence == 0 && !f.journal.HasUnappliedAcceptedWork() &&
            f.store && f.store->PendingMutationCount() == 0 && f.owner->CheckpointXid() == 20 &&
            device.Read(0, original.size(), after) && after == original,
        "prepared retain: same-XID source write reports exact source refusal before WAL, including allocation unwind");
}

bool SnapshotWorkerMetadata(deferred_tests::Fixture& f, Store::MutationRequest& request, bool atime_only = true)
{
    const auto root = f.store->LookupCommittedInodeByPath(L"\\");
    if (!Require(root.has_value(), "accepted worker: committed root")) return false;
    InodeMetadataPatch patch;
    patch.mask = InodeMetadataPatch::AccessTime;
    patch.access_time_utc = (std::max)(root->access_time_utc, InodeMetadataPatch::UnixEpochTicks) + 1;
    if (!atime_only)
    {
        patch.mask |= InodeMetadataPatch::ModificationTime;
        patch.modification_time_utc = patch.access_time_utc;
    }
    request.operation = Store::MutationOperation::SetInodeMetadata;
    request.path = L"\\";
    if (!Require(EncodeInodeMetadataPatch(patch, request.inline_payload), "accepted worker: encode metadata")) return false;
    request.length = request.inline_payload.size();
    return true;
}

bool SnapshotWorkerDebt(deferred_tests::Fixture& f, const std::vector<std::byte>& wal, std::uint64_t source)
{
    const auto census = f.owner->CheckpointCensusSnapshot();
    const auto own = std::find_if(census.begin(), census.end(), [&](const auto& pins) { return pins.volume_object_id == f.volume; });
    const auto marks = f.journal.Watermarks();
    return Require(!wal.empty() && ReadFileBytes(f.root / "accepted.wal") == wal && f.AcceptedWalMatches() &&
            f.acceptances == 1 && f.accepted_preimages == std::vector<std::uint64_t>{source} &&
            marks.accepted_sequence > 0 && marks.apfs_durable_sequence == 0 && marks.cleanup_sequence == 0 &&
            f.journal.HasUnappliedAcceptedWork() && own != census.end() && own->unapplied_accepted_work &&
            own->required_checkpoint_xids == std::vector<std::uint64_t>{source},
        "accepted worker: exact WAL, accepted source, incomplete watermarks and owner survive");
}

bool CleanupSnapshotWorker(deferred_tests::Fixture& f)
{
    const auto sequence = f.journal.Watermarks().accepted_sequence;
    std::vector<std::uint64_t> pins;
    if (!Require(f.journal.MarkApfsDurableThrough(sequence) && f.journal.MarkCleanedThrough(sequence) &&
            f.journal.LoadRequiredCheckpointXidsSinceCleanup(pins, &f.error) && pins.empty() &&
            f.owner->UpdateRequiredCheckpointXids(f.volume, pins, f.error),
            "accepted worker: only explicit verified cleanup releases debt")) return false;
    f.store->SetCommitStageHook({});
    f.store->SetFilePayloadRangeProvider({});
    f.store = nullptr;
    return Require(f.owner->DrainAndStop(std::chrono::seconds(2)).clean, "accepted worker: clean owned drain");
}

bool TestSnapshotAcceptedWorkerPublish(std::uint64_t volume, bool atime_only)
{
    std::vector<std::byte> baseline;
    for (const bool exclusive : {false, true})
    {
        deferred_tests::Fixture f;
        if (!f.Open("prepared-snapshot-worker", exclusive, volume, true)) return false;
        const auto source = f.owner->CheckpointXid();
        const auto* checkpoint = f.store->AuthoritativeAppleCheckpointView();
        if (!Require(checkpoint && checkpoint->volumes.size() == 2 &&
                checkpoint->volumes[0].object_map.snapshot_tree_oid != 0 &&
                checkpoint->volumes[1].object_map.snapshot_tree_oid == 0,
                "accepted worker: actual Alpha snapshots with ordinary Beta sibling")) return false;
        Store::MutationRequest request;
        if (!SnapshotWorkerMetadata(f, request, atime_only)) return false;
        const auto deferred_before = f.store->DebugAppleTransactionPlanningCount();
        unsigned deferred_retained = 0;
        f.store->SetCommitStageHook([&](std::string_view stage) {
            if (stage == "after-apple-prepared-plan-retain") ++deferred_retained;
            if (stage == "before-apple-publish") ++f.publications;
            return true;
        });
        const auto accepted = f.Defer({request});
        if (!Require(accepted.accepted_without_publication && !accepted.committed && f.verifications == 0 &&
                f.publications == 0 && deferred_retained == 0 &&
                f.store->DebugAppleTransactionPlanningCount() - deferred_before == 1 &&
                f.owner->CheckpointXid() == source && f.store->PendingMutationCount() == 1,
                "accepted worker: accept without publishing or completing debt")) return false;
        const auto wal = ReadFileBytes(f.root / "accepted.wal");
        const auto before = f.store->DebugAppleTransactionPlanningCount();
        unsigned retained = 0, hooks = 0;
        f.store->SetCommitStageHook([&](std::string_view stage) {
            if (stage == "after-apple-prepared-plan-retain") ++retained;
            if (stage == "before-apple-publish") ++f.publications;
            return true;
        });
        const auto result = f.owner->Commit(volume, {}, [&](const auto& requests, const auto& identities,
            auto xid, auto& pins, auto& why) {
            ++hooks;
            return requests.empty() && identities.empty() && xid == source &&
                f.journal.LoadRequiredCheckpointXidsSinceCleanup(pins, &why);
        }, {}, {}, false, {}, {}, [&](const Store& store, auto xid, auto&) {
            ++f.verifications;
            const auto root = store.LookupCommittedInodeByPath(L"\\");
            InodeMetadataPatch patch;
            return xid == source + 1 && root && DecodeInodeMetadataPatch(request.inline_payload, patch) &&
                root->access_time_utc == patch.access_time_utc &&
                (atime_only || root->modification_time_utc == patch.modification_time_utc);
        }, true);
        const auto plans = f.store->DebugAppleTransactionPlanningCount() - before;
        std::printf("accepted-worker volume=%llu exclusive=%d atime=%d plans=%llu retained=%u committed=%d\n",
            static_cast<unsigned long long>(volume), exclusive, atime_only,
            static_cast<unsigned long long>(plans), retained, result.committed);
        if (!Require(result.committed && !result.commit_recovery_required && hooks == 1 && f.verifications == 1 &&
                f.publications == 1 && f.owner->CheckpointXid() == source + 1 && f.store->PendingMutationCount() == 0,
                "accepted worker: one original acceptance and one verified successor") || !SnapshotWorkerDebt(f, wal, source)) return false;
        if (!Require(plans == (exclusive && atime_only ? 1u : 2u) && retained == (exclusive && atime_only ? 1u : 0u),
                "accepted worker: one plan only for exclusive snapshot atime; ordinary metadata uses two")) return false;
        std::vector<std::byte> image, after;
        if (!Require(f.owner->Device().Read(0, 512 * 4096, image), "accepted worker: full held-image read")) return false;
        unsigned sibling_hooks = 0;
        const auto blocked = f.owner->Commit(volume == 101 ? 102 : 101, {},
            [&](const auto&, const auto&, auto, auto&, auto&) { ++sibling_hooks; return true; });
        if (!Require(!blocked.committed && blocked.commit_stage == "awaiting-accepted-recovery" && sibling_hooks == 0 &&
                f.owner->Device().Read(0, image.size(), after) && after == image,
                "accepted worker: published owner still blocks siblings until cleanup") || !CleanupSnapshotWorker(f)) return false;
        if (!exclusive) baseline = std::move(image);
        else if (!Require(image == baseline, "accepted worker: full publication bytes equal two-plan baseline")) return false;
    }
    return true;
}

bool TestSnapshotAcceptedWorkerBinding(std::uint64_t volume, unsigned boundary)
{
    deferred_tests::Fixture f;
    if (!f.Open("prepared-snapshot-worker-binding", true, volume, true)) return false;
    Store::MutationRequest request;
    if (!SnapshotWorkerMetadata(f, request) || !Require(f.Defer({request}).accepted_without_publication,
            "accepted worker binding: original deferred WAL")) return false;
    const auto source = f.owner->CheckpointXid();
    const auto wal = ReadFileBytes(f.root / "accepted.wal");
    auto& device = const_cast<BlockDevice&>(f.owner->Device());
    std::vector<std::byte> image, anchor, after;
    if (!device.Read(0, 512 * 4096, image) || !device.Read(0, 4096, anchor)) return false;
    unsigned retained = 0, injected = 0, writes = 0;
    const auto before = f.store->DebugAppleTransactionPlanningCount();
    f.store->SetCommitStageHook([&](std::string_view stage) {
        if (stage == "after-apple-prepared-plan-retain") ++retained;
        if (stage == "before-apple-device-write") ++writes;
        const auto target = boundary == 0 ? "after-apple-prepared-plan-retain" :
            boundary == 2 ? "before-apple-publish" : "before-apple-plan";
        if (stage != target) return true;
        ++injected;
        if (boundary == 3)
        {
            auto extra = request;
            InodeMetadataPatch patch;
            if (!DecodeInodeMetadataPatch(extra.inline_payload, patch)) return false;
            ++patch.access_time_utc;
            return EncodeInodeMetadataPatch(patch, extra.inline_payload) &&
                f.store->StageMutation(extra) == Store::MutationStatus::Applied;
        }
        return device.Write(0, anchor) && device.Flush();
    });
    const auto result = f.owner->Commit(volume, {}, {}, {}, {}, false, {}, {}, {}, true);
    return Require(!result.committed && !result.clean_prepublication_refusal && result.commit_recovery_required &&
            retained == 1 && injected == 1 && writes == 0 && f.owner->CheckpointXid() == source &&
            f.store->DebugAppleTransactionPlanningCount() - before == 1 && f.store->PendingMutationCount() >= 1 &&
            result.error.find(boundary == 3 ? "ApplePreparedPlanStagingChanged" : "ApplePreparedPlanSourceChanged") != std::string::npos &&
            device.Read(0, image.size(), after) && after == image,
        "accepted worker binding: changed generation or overlay refuses before writes without dropping accepted work") &&
        SnapshotWorkerDebt(f, wal, source);
}

bool TestSnapshotAcceptedWorkerPeerDebt(std::uint64_t volume, bool unapplied)
{
    deferred_tests::Fixture f;
    if (!f.Open("prepared-snapshot-worker-peer", true, volume, true)) return false;
    Store::MutationRequest request;
    if (!SnapshotWorkerMetadata(f, request) || !Require(f.Defer({request}).accepted_without_publication,
            "accepted worker peer: original accepted WAL")) return false;
    const auto source = f.owner->CheckpointXid();
    const auto peer = volume == 101 ? 102 : 101;
    if (!Require(f.owner->UpdateRequiredCheckpointXids(peer, {unapplied ? source : source - 1}, f.error, unapplied),
            "accepted worker peer: independent unresolved census owner")) return false;
    const auto wal = ReadFileBytes(f.root / "accepted.wal");
    const auto delta = CheckpointDeltaCodec::Encode(f.store->DebugBuildPendingCheckpointDelta());
    const auto before = f.store->DebugAppleTransactionPlanningCount();
    std::vector<std::byte> image, after;
    if (!f.owner->Device().Read(0, 512 * 4096, image)) return false;
    unsigned hooks = 0;
    const auto result = f.owner->Commit(volume, {}, [&](const auto&, const auto&, auto, auto&, auto&) { ++hooks; return true; });
    if (!Require(!result.committed && hooks == 0 && f.publications == 0 && !result.commit_recovery_required &&
            result.commit_stage == (unapplied ? "awaiting-accepted-recovery" : "awaiting-checkpoint-cleanup") &&
            f.store->DebugAppleTransactionPlanningCount() == before && f.owner->CheckpointXid() == source &&
            CheckpointDeltaCodec::Encode(f.store->DebugBuildPendingCheckpointDelta()) == delta &&
            f.owner->Device().Read(0, image.size(), after) && after == image,
            "accepted worker peer: debt refuses before hooks/proof and preserves exact overlay") || !SnapshotWorkerDebt(f, wal, source)) return false;
    if (!Require(f.owner->UpdateRequiredCheckpointXids(peer, {}, f.error), "accepted worker peer: explicit peer cleanup refresh")) return false;
    const auto retry = f.owner->Commit(volume, {}, {}, {}, {}, false, {}, {}, {}, true);
    return Require(retry.committed && !retry.commit_recovery_required && f.owner->CheckpointXid() == source + 1 &&
            f.store->DebugAppleTransactionPlanningCount() - before == 1,
        "accepted worker peer: fresh proof succeeds once after peer cleanup") &&
        SnapshotWorkerDebt(f, wal, source) && CleanupSnapshotWorker(f);
}

bool RunAcceptedSnapshotWorker()
{
    _putenv_s("APFSACCESS_PERF_COUNTERS", "1");
    bool ok = true;
    for (const auto volume : {101u, 102u})
    {
        ok &= TestSnapshotAcceptedWorkerPublish(volume, true);
        ok &= TestSnapshotAcceptedWorkerPublish(volume, false);
        for (unsigned boundary = 0; boundary != 4; ++boundary)
            ok &= TestSnapshotAcceptedWorkerBinding(volume, boundary);
        ok &= TestSnapshotAcceptedWorkerPeerDebt(volume, true);
        ok &= TestSnapshotAcceptedWorkerPeerDebt(volume, false);
    }
    return ok;
}

bool PrepareImmediateSnapshotFixture(deferred_tests::Fixture& f, bool exclusive, std::uint64_t volume)
{
    if (!f.Open("prepared-immediate-snapshot", exclusive, volume, true)) return false;
    auto create = deferred_tests::Create(L"\\retained-payload");
    auto write = deferred_tests::Write(L"\\retained-payload", 0, 4097, 37);
    create.timestamp_utc = write.timestamp_utc = 132000000000000000;
    const auto result = f.owner->Commit(volume, {create, write}, f.Accept(f.owner->CheckpointXid()));
    std::vector<std::byte> payload;
    if (!Require(result.committed && f.store->ReadCommittedFileRange(L"\\retained-payload", 0, 4097, payload) &&
            payload == write.deferred_payload && f.AcceptedWalMatches(),
            "immediate snapshot: seed and verify nonzero payload before measured atime")) return false;
    const auto sequence = f.journal.Watermarks().accepted_sequence;
    if (!Require(f.journal.MarkApfsDurableThrough(sequence) && f.journal.MarkCleanedThrough(sequence) &&
            f.owner->UpdateRequiredCheckpointXids(volume, {}, f.error),
            "immediate snapshot: seed journal is explicitly verified and cleaned")) return false;
    f.acceptances = f.publications = f.verifications = 0;
    f.accepted_requests.clear(); f.accepted_identities.clear(); f.accepted_preimages.clear();
    return true;
}

bool ImmediateSnapshotWalDebt(deferred_tests::Fixture& f, std::uint64_t source,
    std::uint64_t prior_cleaned, const std::vector<std::byte>& accepted_wal)
{
    const auto census = f.owner->CheckpointCensusSnapshot();
    const auto own = std::find_if(census.begin(), census.end(), [&](const auto& pins) { return pins.volume_object_id == f.volume; });
    const auto marks = f.journal.Watermarks();
    return Require(f.acceptances == 1 && f.AcceptedWalMatches() && !accepted_wal.empty() &&
            ReadFileBytes(f.root / "accepted.wal") == accepted_wal &&
            f.accepted_preimages == std::vector<std::uint64_t>{source} &&
            marks.accepted_sequence > prior_cleaned && marks.apfs_durable_sequence == prior_cleaned &&
            marks.cleanup_sequence == prior_cleaned && f.journal.HasUnappliedAcceptedWork() &&
            own != census.end() && own->unapplied_accepted_work &&
            std::find(own->required_checkpoint_xids.begin(), own->required_checkpoint_xids.end(), source) != own->required_checkpoint_xids.end(),
        "immediate snapshot: exact accepted WAL and preimage stay owned until verified cleanup");
}

bool SameImmediateSnapshotHistory(const std::vector<std::byte>& before, const std::vector<std::byte>& after,
    std::uint64_t selected_volume)
{
    VectorRandomAccessSource old_source(before), new_source(after);
    std::string error;
    const auto old_checkpoint = LoadAppleCheckpointView(old_source, 0, old_source.SizeBytes(), error);
    const auto new_checkpoint = LoadAppleCheckpointView(new_source, 0, new_source.SizeBytes(), error);
    AppleSnapshotCatalogRecords old_catalog, new_catalog;
    if (!Require(old_checkpoint && new_checkpoint &&
            LoadAppleSnapshotCatalog(old_source, *old_checkpoint, 101, old_catalog, error) &&
            LoadAppleSnapshotCatalog(new_source, *new_checkpoint, 101, new_catalog, error) &&
            old_catalog.inventory.size() == 1 && new_catalog.inventory.size() == 1 &&
            old_catalog.snapshots.size() == 1 && new_catalog.snapshots.size() == 1,
            "immediate snapshot: canonical snapshot inventory and historical trees remain readable")) return false;
    const auto same_records = [](const auto& a, const auto& b) {
        return std::equal(a.begin(), a.end(), b.begin(), b.end(),
            [](const auto& x, const auto& y) { return x.key == y.key && x.value == y.value; });
    };
    const auto& old_snapshot = old_catalog.inventory.front();
    const auto& new_snapshot = new_catalog.inventory.front();
    const auto offset = old_snapshot.volume.superblock_object.physical_block * old_checkpoint->container.superblock.block_size;
    const auto size = old_checkpoint->container.superblock.block_size;
    const auto peer = selected_volume == 101 ? 102u : 101u;
    const auto old_peer = std::find_if(old_checkpoint->volumes.begin(), old_checkpoint->volumes.end(),
        [&](const auto& volume) { return volume.superblock.object_id == peer; });
    const auto new_peer = std::find_if(new_checkpoint->volumes.begin(), new_checkpoint->volumes.end(),
        [&](const auto& volume) { return volume.superblock.object_id == peer; });
    if (!Require(old_peer != old_checkpoint->volumes.end() && new_peer != new_checkpoint->volumes.end(),
            "immediate snapshot: both canonical peer volumes remain present")) return false;
    const auto peer_offset = old_peer->superblock_object.physical_block * size;
    return Require(new_peer->superblock_object.physical_block == old_peer->superblock_object.physical_block &&
            peer_offset <= before.size() && size <= before.size() - peer_offset &&
            peer_offset <= after.size() && size <= after.size() - peer_offset &&
            std::equal(before.begin() + peer_offset, before.begin() + peer_offset + size, after.begin() + peer_offset) &&
            old_snapshot.xid == new_snapshot.xid && old_snapshot.name_utf8 == new_snapshot.name_utf8 &&
            old_snapshot.volume.superblock_object.physical_block == new_snapshot.volume.superblock_object.physical_block &&
            offset <= before.size() && size <= before.size() - offset &&
            offset <= after.size() && size <= after.size() - offset &&
            std::equal(before.begin() + offset, before.begin() + offset + size, after.begin() + offset) &&
            same_records(old_catalog.snapshots.front().filesystem, new_catalog.snapshots.front().filesystem) &&
            same_records(old_catalog.snapshots.front().extentref, new_catalog.snapshots.front().extentref),
        "immediate snapshot: exact sibling APSB and historical APSB/filesystem/extentref records are preserved");
}

bool TestImmediateSnapshotAtimePublish(std::uint64_t volume, bool expect_reuse = true)
{
    std::vector<std::byte> baseline;
    std::optional<ContainerVolumeSpaceSnapshot> baseline_space;
    bool ok = true;
    for (unsigned mode = 0; mode != 4; ++mode)
    {
        deferred_tests::Fixture f;
        if (!PrepareImmediateSnapshotFixture(f, mode != 0, volume)) return false;
        const auto source = f.owner->CheckpointXid();
        const auto cleaned = f.journal.Watermarks().cleanup_sequence;
        const auto before_plans = f.store->DebugAppleTransactionPlanningCount();
        std::vector<std::byte> before_image, image;
        if (!f.owner->Device().Read(0, 512 * 4096, before_image)) return false;
        Store::MutationRequest request;
        if (!SnapshotWorkerMetadata(f, request)) return false;
        unsigned retained = 0;
        f.store->SetCommitStageHook([&](std::string_view stage) {
            if (stage == "before-apple-publish") ++f.publications;
            if (stage != "after-apple-prepared-plan-retain") return true;
            ++retained;
            if (mode == 3) throw std::bad_alloc{};
            return mode != 2;
        });
        std::vector<std::byte> accepted_wal;
        const auto accept = f.Accept(source);
        const auto started = std::chrono::steady_clock::now();
        const auto result = f.owner->Commit(volume, {request}, [&](const auto& requests, const auto& identities,
            auto xid, auto& pins, auto& why) {
            if (!accept(requests, identities, xid, pins, why)) return false;
            accepted_wal = ReadFileBytes(f.root / "accepted.wal");
            return !accepted_wal.empty();
        }, {}, {}, false, {}, {}, [&](const Store& store, auto xid, auto&) {
            ++f.verifications;
            InodeMetadataPatch patch;
            const auto root = store.LookupCommittedInodeByPath(L"\\");
            return xid == source + 1 && root && DecodeInodeMetadataPatch(request.inline_payload, patch) &&
                root->access_time_utc == patch.access_time_utc;
        }, true);
        const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - started).count();
        const auto plans = f.store->DebugAppleTransactionPlanningCount() - before_plans;
        const auto expected_plans = expect_reuse && mode == 1 ? 1u : 2u;
        const auto expected_retained = expect_reuse && mode != 0 ? 1u : 0u;
        std::printf("immediate-atime volume=%llu mode=%u plans=%llu retained=%u commitUs=%lld source=%llu successor=%llu\n",
            static_cast<unsigned long long>(volume), mode, static_cast<unsigned long long>(plans), retained,
            static_cast<long long>(elapsed), static_cast<unsigned long long>(source),
            static_cast<unsigned long long>(f.owner->CheckpointXid()));
        ok &= Require(plans == expected_plans && retained == expected_retained,
            "immediate snapshot: one planner only for exclusive retained atime; optional retention falls back");
        if (!Require(result.committed && result.error.empty() && !result.commit_recovery_required &&
                f.publications == 1 && f.verifications == 1 && f.store->PendingMutationCount() == 0 &&
                f.owner->CheckpointXid() == source + 1,
                "immediate snapshot: immediate one-checkpoint publication and verified atime") ||
            !ImmediateSnapshotWalDebt(f, source, cleaned, accepted_wal)) return false;
        const auto expected_payload = deferred_tests::Write(L"\\retained-payload", 0, 4097, 37).deferred_payload;
        std::vector<std::byte> payload;
        if (!Require(f.store->ReadCommittedFileRange(L"\\retained-payload", 0, 4097, payload) && payload == expected_payload &&
                f.owner->Device().Read(0, 512 * 4096, image),
                "immediate snapshot: nonzero payload remains exact after metadata-only publication") ||
            !SameImmediateSnapshotHistory(before_image, image, volume)) return false;
        const auto space = f.owner->LookupSharedSpace(f.owner->ContainerUuidHex(), volume);
        if (!Require(space.has_value(), "immediate snapshot: published space observation")) return false;
        const auto image_sha256 = PortableSha256Hex(std::string(
            reinterpret_cast<const char*>(image.data()), image.size()));
        std::printf("immediate-image volume=%llu mode=%u sha256=%s total=%llu available=%llu\n",
            static_cast<unsigned long long>(volume), mode, image_sha256.c_str(),
            static_cast<unsigned long long>(space->total_bytes), static_cast<unsigned long long>(space->available_bytes));
        if (mode == 0) { baseline = image; baseline_space = space; }
        else ok &= Require(image == baseline && space->available_bytes == baseline_space->available_bytes &&
                space->total_bytes == baseline_space->total_bytes,
            "immediate snapshot: entire publication image and shared space equal the two-plan baseline");
        if (!CleanupSnapshotWorker(f)) return false;
    }
    return ok;
}

bool RunImmediateSnapshotAtime(bool expect_reuse = true)
{
    _putenv_s("APFSACCESS_PERF_COUNTERS", "1");
    bool ok = true;
    for (const auto volume : {101u, 102u}) ok &= TestImmediateSnapshotAtimePublish(volume, expect_reuse);
    return ok;
}

bool TestImmediateSnapshotAtimeRefusal(std::uint64_t volume, unsigned boundary)
{
    deferred_tests::Fixture f;
    if (!PrepareImmediateSnapshotFixture(f, true, volume)) return false;
    const auto source = f.owner->CheckpointXid();
    const auto cleaned = f.journal.Watermarks().cleanup_sequence;
    auto& device = const_cast<BlockDevice&>(f.owner->Device());
    std::vector<std::byte> image, anchor, after, accepted_wal;
    if (!device.Read(0, 512 * 4096, image) || !device.Read(0, 4096, anchor)) return false;
    const auto* checkpoint = f.store->AuthoritativeAppleCheckpointView();
    if (!Require(checkpoint != nullptr, "immediate refusal: exact source checkpoint")) return false;
    const auto guard_offset = checkpoint->container.superblock_physical_block * checkpoint->container.superblock.block_size;
    auto corrupted = checkpoint->container.superblock_bytes;
    corrupted[0] ^= std::byte{1};
    const auto epoch = f.store->StateEpoch();
    Store::MutationRequest request;
    if (!SnapshotWorkerMetadata(f, request)) return false;
    unsigned retained = 0, injected = 0, writes = 0, switches = 0;
    f.store->SetCommitStageHook([&](std::string_view stage) {
        if (stage == "after-apple-prepared-plan-retain") ++retained;
        if (stage == "before-apple-device-write") ++writes;
        if (stage == "before-apple-checkpoint-switch") ++switches;
        if ((boundary == 0 && stage == "after-apple-prepared-plan-retain") ||
            (boundary == 2 && stage == "before-apple-publish"))
        {
            ++injected;
            return device.Write(0, anchor) && device.Flush();
        }
        if (boundary == 5 && stage == "before-apple-prepublication-flush")
        {
            ++injected;
            return device.Write(guard_offset, corrupted);
        }
        return true;
    });
    const auto accept = f.Accept(source);
    const auto result = f.owner->Commit(volume, {request}, [&](const auto& requests, const auto& identities,
        auto xid, auto& pins, auto& why) {
        if (!accept(requests, identities, xid, pins, why)) return false;
        accepted_wal = ReadFileBytes(f.root / "accepted.wal");
        if (boundary == 1) { ++injected; return device.Write(0, anchor) && device.Flush(); }
        if (boundary == 3)
        {
            ++injected;
            return f.store->PrepareNativeWritePath() && f.store->StateEpoch() != epoch &&
                f.store->StageMutation(request) == Store::MutationStatus::Applied;
        }
        if (boundary == 4)
        {
            ++injected;
            Store::MutationRequest extra;
            return SnapshotWorkerMetadata(f, extra, false) && f.store->StageMutation(extra) == Store::MutationStatus::Applied;
        }
        return true;
    }, {}, {}, false, {}, {}, {}, true);
    f.store = f.owner->FindSessionStore(volume);
    if (!Require(f.store && retained == 1 && injected == 1 && !result.committed &&
            f.owner->CheckpointXid() == source && switches == 0 && writes == (boundary == 5 ? 1u : 0u) &&
            device.Read(0, image.size(), after) && (boundary == 5 || after == image),
            "immediate refusal: source/epoch/staging/guard change cannot publish the prepared checkpoint")) return false;
    std::printf("immediate-refusal volume=%llu boundary=%u accepted=%u stage=%s error=%s\n",
        static_cast<unsigned long long>(volume), boundary, f.acceptances, result.commit_stage.c_str(), result.error.c_str());
    if (boundary == 0)
        return Require(f.acceptances == 0 && f.journal.Watermarks().accepted_sequence == cleaned &&
                !f.journal.HasUnappliedAcceptedWork() && f.store->PendingMutationCount() == 0 &&
                result.error.find("ApplePreparedPlanSourceChanged") != std::string::npos,
            "immediate refusal: changed retained source refuses before new WAL acceptance");
    const auto expected = boundary == 3 || boundary == 4 ? "ApplePreparedPlanOwnerChanged" :
        boundary == 5 ? "AppleCheckpointGuardChanged" : "ApplePreparedPlanSourceChanged";
    return Require(result.commit_recovery_required && result.error.find(expected) != std::string::npos,
            "immediate refusal: exact owner/source/publisher guard failure retains recovery authority") &&
        ImmediateSnapshotWalDebt(f, source, cleaned, accepted_wal);
}

bool TestImmediateSnapshotChangedPins(std::uint64_t volume)
{
    deferred_tests::Fixture f;
    if (!PrepareImmediateSnapshotFixture(f, true, volume)) return false;
    Store::MutationRequest request;
    if (!SnapshotWorkerMetadata(f, request)) return false;
    const auto source = f.owner->CheckpointXid();
    const auto before = f.store->DebugAppleTransactionPlanningCount();
    const auto cleaned = f.journal.Watermarks().cleanup_sequence;
    unsigned retained = 0;
    f.store->SetCommitStageHook([&](std::string_view stage) {
        if (stage == "after-apple-prepared-plan-retain") ++retained;
        return true;
    });
    std::vector<std::byte> accepted_wal;
    const auto accept = f.Accept(source);
    const auto result = f.owner->Commit(volume, {request}, [&](const auto& requests, const auto& identities,
        auto xid, auto& pins, auto& why) {
        if (!accept(requests, identities, xid, pins, why)) return false;
        accepted_wal = ReadFileBytes(f.root / "accepted.wal");
        pins.push_back(source - 1);
        return true;
    }, {}, {}, false, {}, {}, {}, true);
    return Require(result.committed && !result.commit_recovery_required && retained == 1 &&
            f.store->DebugAppleTransactionPlanningCount() - before == 2 && f.owner->CheckpointXid() == source + 1,
            "immediate pins: available changed historical pin forces a second full planner") &&
        ImmediateSnapshotWalDebt(f, source, cleaned, accepted_wal) && CleanupSnapshotWorker(f);
}

bool TestImmediateSnapshotIneligibleBatch(std::uint64_t volume, bool payload)
{
    deferred_tests::Fixture f;
    if (!PrepareImmediateSnapshotFixture(f, true, volume)) return false;
    Store::MutationRequest request;
    if (!SnapshotWorkerMetadata(f, request, payload)) return false;
    std::vector<Store::MutationRequest> requests{request};
    if (payload) requests.push_back(deferred_tests::Write(L"\\retained-payload", 0, 4097, 71));
    const auto source = f.owner->CheckpointXid();
    const auto before = f.store->DebugAppleTransactionPlanningCount();
    unsigned retained = 0;
    f.store->SetCommitStageHook([&](std::string_view stage) {
        if (stage == "after-apple-prepared-plan-retain") ++retained;
        return true;
    });
    const auto result = f.owner->Commit(volume, requests, f.Accept(source), {}, {}, false, {}, {}, {}, true);
    std::vector<std::byte> actual;
    const auto expected = deferred_tests::Write(L"\\retained-payload", 0, 4097, payload ? 71 : 37).deferred_payload;
    return Require(result.committed && !result.commit_recovery_required && retained == 0 &&
            f.store->DebugAppleTransactionPlanningCount() - before == 2 && f.AcceptedWalMatches() &&
            f.store->ReadCommittedFileRange(L"\\retained-payload", 0, 4097, actual) && actual == expected,
            "immediate exclusion: atime plus other metadata or payload keeps real-content replanning") &&
        CleanupSnapshotWorker(f);
}

bool TestImmediateSnapshotReplayKeepsReplanning(std::uint64_t volume)
{
    deferred_tests::Fixture f;
    if (!PrepareImmediateSnapshotFixture(f, true, volume)) return false;
    Store::MutationRequest request;
    if (!SnapshotWorkerMetadata(f, request)) return false;
    const auto source = f.owner->CheckpointXid();
    const auto cleaned = f.journal.Watermarks().cleanup_sequence;
    if (!Require(f.Defer({request}).accepted_without_publication && f.store->PrepareNativeWritePath() &&
            f.store->PendingMutationCount() == 0,
            "immediate replay: durable accepted request with clean reloaded staging")) return false;
    const auto wal = ReadFileBytes(f.root / "accepted.wal");
    const auto before = f.store->DebugAppleTransactionPlanningCount();
    unsigned retained = 0;
    f.store->SetCommitStageHook([&](std::string_view stage) {
        if (stage == "after-apple-prepared-plan-retain") ++retained;
        return true;
    });
    const auto result = f.owner->Commit(volume, {request}, {}, {}, {}, true, source, {}, {}, true);
    return Require(result.committed && !result.commit_recovery_required && retained == 0 &&
            f.store->DebugAppleTransactionPlanningCount() - before == 2 &&
            f.owner->CheckpointXid() == source + 1,
            "immediate replay: accepted recovery remains outside plan retention") &&
        ImmediateSnapshotWalDebt(f, source, cleaned, wal) && CleanupSnapshotWorker(f);
}

bool RunImmediateSnapshotAtimeSafety()
{
    _putenv_s("APFSACCESS_PERF_COUNTERS", "1");
    bool ok = true;
    for (const auto volume : {101u, 102u})
    {
        for (unsigned boundary = 0; boundary != 6; ++boundary)
            ok &= TestImmediateSnapshotAtimeRefusal(volume, boundary);
        ok &= TestImmediateSnapshotChangedPins(volume);
        ok &= TestImmediateSnapshotIneligibleBatch(volume, false);
        ok &= TestImmediateSnapshotIneligibleBatch(volume, true);
        ok &= TestImmediateSnapshotReplayKeepsReplanning(volume);
    }
    return ok;
}

bool Run()
{
    _putenv_s("APFSACCESS_PERF_COUNTERS", "1");
    bool ok = true;
    for (const auto volume : {101u, 102u})
    {
        ok &= TestIdenticalMetadataAndPayload(volume, false);
        ok &= TestIdenticalMetadataAndPayload(volume, true);
    }
    for (unsigned boundary = 0; boundary != 3; ++boundary) ok &= TestSourceChangesRetainAcceptedDebt(boundary);
    ok &= TestPublisherGuardStillChecksAfterWrites();
    for (const bool pins : {false, true})
        for (unsigned boundary = 0; boundary != 3; ++boundary) ok &= TestStagingChangesRetainAcceptedDebt(boundary, pins);
    ok &= TestChangedPinsReplanLegitimately();
    ok &= TestOptionalRetentionFailureFallsBack();
    ok &= TestPublisherHooksRetainAcceptedDebt("before-apple-device-write", true);
    ok &= TestPublisherHooksRetainAcceptedDebt("before-apple-prepublication-flush", false);
    ok &= TestPublisherHooksRetainAcceptedDebt("after-apple-publish", false);
    ok &= TestRetentionSourceChangeBeforeAcceptance(false);
    ok &= TestRetentionSourceChangeBeforeAcceptance(true);
    ok &= RunAcceptedSnapshotWorker();
    ok &= RunImmediateSnapshotAtime();
    ok &= RunImmediateSnapshotAtimeSafety();
    return ok;
}
}
