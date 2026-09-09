#pragma once

bool TestDeferredAccessTimeStop567(bool manifest, bool accepted_failure, bool earlier_close)
{
    using Wal = apfsaccess::rw::WriteAheadLog;
    if (!DeferredAccessTimeScratch302()) return false;
    DeferredAccessTimeFixture302 owned(manifest);
    if (!owned.Initialize(manifest)) return false;
    auto& c = *owned.fixture.context;
    c.args.write_commit_timeout_seconds = 10;
    std::uint64_t time = 0;
    if (!owned.ReadCleanup(L"\\read17", time)) return false;
    const auto original_time = c.metadata_store->LookupCommittedInodeByPath(L"\\read17")->access_time_utc;
    const auto original_image = ReadFileBytes(owned.fixture.image.path);
    const auto preimage = c.metadata_store->CheckpointXid();
    std::promise<void> staged, release;
    auto ready = staged.get_future();
    auto resume = release.get_future();
    bool hook_ok = true, exact_wal = false;
    std::uint64_t target = 0;
    unsigned publication_attempts = 0;
    c.test_before_deferred_atime_publish = [&] {
        if (!manifest)
        {
            // Exercise a real nonzero accepted target in the exact direct
            // staged/pre-Flush window, using the ordinary durability helper.
            hook_ok = EnsureDeferredWalAcceptanceDurableBeforeApfsCommitBestEffort(&c, L"Flush");
            target = c.tx_manager->Watermarks().accepted_sequence;
            hook_ok &= target != 0;
            RequestDeferredCloseCommit(&c, target);
        }
        staged.set_value();
        hook_ok &= resume.wait_for(std::chrono::seconds(4)) == std::future_status::ready;
    };
    c.metadata_store->SetCommitStageHook([&](std::string_view stage) {
        if (stage != "before-apple-publish") return true;
        ++publication_attempts;
        const auto persisted = Wal::ReadAll(c.session_root / "accepted.wal", c.payload_spool_volume_identity);
        const Wal::Record* marker = nullptr;
        const Wal::Record* mutation = nullptr;
        for (const auto& record : persisted.records)
            if (record.operation == Wal::OperationKind::TransactionMarker) marker = &record;
            else mutation = &record;
        apfsaccess::rw::InodeMetadataPatch patch;
        exact_wal = persisted.status == Wal::ReadStatus::Ok && !persisted.recovered_torn_tail &&
            persisted.records.size() == 2 && marker && mutation && preimage &&
            marker->state == Wal::RecordState::Accepted && marker->object_id == *preimage &&
            marker->logical_length == 1 && mutation->transaction_id == marker->transaction_id &&
            mutation->sequence < marker->sequence && mutation->state == Wal::RecordState::Prepared &&
            mutation->operation == Wal::OperationKind::SetInodeMetadata && mutation->object_id == 17 &&
            mutation->parent_object_id != 0 &&
            apfsaccess::rw::DecodeInodeMetadataPatch(mutation->inline_payload, patch) &&
            patch.mask == apfsaccess::rw::InodeMetadataPatch::AccessTime && patch.access_time_utc == time;
        return !accepted_failure;
    });
    if (earlier_close) RequestDeferredCloseCommit(&c, 0);
    {
        std::lock_guard<std::mutex> lock(c.deferred_commit_mutex);
        c.deferred_commit_deadline = std::chrono::steady_clock::now();
        c.deferred_access_time_deadline = std::chrono::steady_clock::now() +
            (earlier_close ? std::chrono::seconds(30) : std::chrono::seconds(0));
    }
    StartDeferredCommitWorker(&c);
    if (ready.wait_for(std::chrono::seconds(3)) != std::future_status::ready)
    {
        release.set_value();
        StopDeferredCommitWorker(&c);
        return Require(false, "stop 567 reaches the exact staged pre-Flush window");
    }
    const bool callbacks_drained = BeginMutationShutdownDrain(&c);
    auto stop = std::async(std::launch::async, [&] { return StopDeferredCommitWorker(&c); });
    bool stop_observed = false, target_retained = false;
    {
        std::unique_lock<std::mutex> lock(c.deferred_commit_mutex);
        stop_observed = c.deferred_commit_cv.wait_for(lock, std::chrono::seconds(1),
            [&] { return c.deferred_commit_thread_stop; });
        target_retained = manifest || (c.deferred_commit_requested && c.deferred_commit_requested_target == target);
    }
    const bool unrelated_cancelled = !BeginDeferredCommitBarrier(&c, false, target);
    release.set_value();
    const bool finite = stop.wait_for(std::chrono::seconds(12)) == std::future_status::ready;
    const bool stopped = stop.get();
    c.test_before_deferred_atime_publish = {};
    c.metadata_store->SetCommitStageHook({});
    if (!stopped) ExitProcess(91); // never destroy a context with an active worker
    const auto marks = c.tx_manager->Watermarks();
    std::cerr << "[stop567] manifest=" << manifest << " failure=" << accepted_failure
        << " earlier=" << earlier_close << " target=" << target << " retained=" << target_retained
        << " publish=" << publication_attempts << " accepted=" << marks.accepted_sequence
        << " durable=" << marks.apfs_durable_sequence << " cleanup=" << marks.cleanup_sequence
        << " finite=" << finite << " degraded=" << c.write_degraded << '\n';
    if (!Require(hook_ok && callbacks_drained && stop_observed && unrelated_cancelled && finite &&
            !c.deferred_commit_thread.joinable(), "stop 567 cancels unrelated barriers and joins finitely")) return false;
    if (!accepted_failure)
    {
        const bool canonical = owned.CheckFresh({{L"\\read17", time}, {L"\\alias", time}});
        const auto shutdown = RunFsHostShutdownDrain(owned.fixture.context);
        return Require(canonical && shutdown == 0 && target_retained && publication_attempts == 1 &&
            exact_wal && !c.write_degraded && c.deferred_access_times.empty() &&
            marks.accepted_sequence == marks.apfs_durable_sequence && marks.apfs_durable_sequence == marks.cleanup_sequence &&
            (manifest || c.deferred_commit_completed_target == target) && c.deferred_commit_failed_target == 0,
            "stop 567 publishes admitted atime with exact durability and honest successful shutdown");
    }
    const auto wal = ReadFileBytes(c.session_root / "accepted.wal");
    const bool evidence = exact_wal && publication_attempts == 1 && c.write_degraded &&
        marks.accepted_sequence > marks.apfs_durable_sequence && marks.accepted_sequence > marks.cleanup_sequence &&
        std::filesystem::exists(c.recovery_marker_file) && c.deferred_access_times.size() == 1 &&
        c.deferred_access_times.at(17).time == time && original_image == ReadFileBytes(owned.fixture.image.path) &&
        (manifest || (c.deferred_commit_failed_target == target && c.deferred_commit_completed_target < target));
    const bool canonical = owned.CheckFresh({{L"\\read17", original_time}, {L"\\alias", original_time}});
    const auto shutdown = RunFsHostShutdownDrain(owned.fixture.context);
    return Require(target_retained && evidence && canonical && shutdown != 0 &&
        wal == ReadFileBytes(c.session_root / "accepted.wal") &&
        c.tx_manager->Watermarks().apfs_durable_sequence == marks.apfs_durable_sequence &&
        c.tx_manager->Watermarks().cleanup_sequence == marks.cleanup_sequence,
        "stop 567 retains exact accepted atime recovery evidence and reports true publication failure");
}
