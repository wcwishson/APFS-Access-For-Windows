#include "TransactionManager.h"
#include "WriteAheadLog.h"
#include "PayloadSpool.h"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <vector>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace
{
bool Require(bool condition, const std::string& message)
{
    if (!condition)
    {
        std::cerr << "[FAIL] " << message << std::endl;
        return false;
    }

    return true;
}

bool EnvironmentFlag(const char* name)
{
    char* value = nullptr;
    std::size_t value_size = 0;
    if (_dupenv_s(&value, &value_size, name) != 0 || !value)
    {
        if (value)
        {
            std::free(value);
        }
        return false;
    }

    const std::string text(value);
    std::free(value);
    return text == "1" || text == "true" || text == "on";
}

std::uint64_t EnvironmentUnsigned(const char* name, std::uint64_t fallback)
{
    char* value = nullptr;
    std::size_t value_size = 0;
    if (_dupenv_s(&value, &value_size, name) != 0 || !value)
    {
        if (value)
        {
            std::free(value);
        }
        return fallback;
    }

    const std::string text(value);
    std::free(value);
    try
    {
        return std::stoull(text);
    }
    catch (...)
    {
        return fallback;
    }
}

bool RunAcceptanceBenchmark(const std::filesystem::path& run_root)
{
    const auto file_count = (std::max)(
        std::uint64_t{1},
        EnvironmentUnsigned("APFSACCESS_ACCEPTANCE_BENCHMARK_FILES", 64));
    const auto group_size = (std::min)(
        (std::min)(file_count, std::uint64_t{16}),
        (std::max)(
            std::uint64_t{1},
            EnvironmentUnsigned("APFSACCESS_ACCEPTANCE_GROUP_SIZE", 1)));
    constexpr std::size_t payload_bytes = 16 * 1024;
    const auto benchmark_root = run_root / "acceptance-benchmark";
    const std::string volume_identity = "acceptance-benchmark-volume";
    apfsaccess::rw::PayloadSpool spool({
        benchmark_root / "spool",
        volume_identity,
        128ull * 1024ull * 1024ull,
        128ull * 1024ull * 1024ull,
        8192,
    });
    apfsaccess::rw::TransactionManager tx(L"DeferredContent");
    tx.SetVolumeIdentity(L"acceptance-benchmark-volume");
    tx.SetJournalPath((benchmark_root / "write-ahead.wal").wstring());
    std::vector<std::byte> payload(payload_bytes, std::byte{0x5a});
    const bool deferred_index_persistence =
        !EnvironmentFlag("APFSACCESS_DISABLE_DEFERRED_INDEX_PERSISTENCE");

    const auto started = std::chrono::steady_clock::now();
    std::uint64_t accepted_targets = 0;
    for (std::uint64_t batch_start = 0; batch_start < file_count; batch_start += group_size)
    {
        if (!tx.Begin())
        {
            return Require(false, "Acceptance benchmark transaction should begin");
        }
        const auto batch_end = (std::min)(file_count, batch_start + group_size);
        for (auto index = batch_start; index < batch_end; ++index)
        {
            const auto wal_sequence = tx.NextMutationSequence();
            apfsaccess::rw::PayloadSpool::AppendResult reference{};
            if (!spool.Append({
                    volume_identity,
                    1000 + index,
                    1,
                    0,
                    wal_sequence,
                    std::span<const std::byte>(payload.data(), payload.size()),
                }, &reference))
            {
                return Require(false, "Acceptance benchmark payload append should succeed");
            }

            apfsaccess::rw::TransactionManager::MutationIntent mutation{};
            mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::Write;
            mutation.path = L"\\small-" + std::to_wstring(index) + L".bin";
            mutation.length = payload.size();
            mutation.wal_sequence = reference.wal_sequence;
            mutation.object_id = reference.object_id;
            mutation.generation = reference.generation;
            mutation.payload_spool_offset = reference.spool_offset;
            mutation.payload_length = reference.payload_length;
            mutation.payload_checksum = reference.payload_sha256;
            if (!tx.RecordMutation(mutation))
            {
                return Require(false, "Acceptance benchmark mutation should be recorded");
            }
        }

        const bool payload_boundary_flushed = deferred_index_persistence
            ? spool.FlushPayloadBytes()
            : spool.FlushDirtyState();
        if (!payload_boundary_flushed || !tx.Accept())
        {
            return Require(false, "Acceptance benchmark durable boundary should succeed");
        }
        ++accepted_targets;
    }

    const auto acceptance_finished = std::chrono::steady_clock::now();
    if (deferred_index_persistence && !spool.FlushDirtyState())
    {
        return Require(false, "Acceptance benchmark final index persistence should succeed");
    }
    const auto finished = std::chrono::steady_clock::now();

    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        finished - started).count();
    const auto acceptance_elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        acceptance_finished - started).count();
    const auto final_drain_elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        finished - acceptance_finished).count();
    const auto spool_counters = spool.SnapshotCounters();
    const auto watermarks = tx.Watermarks();
    std::cout << "[BENCH] mode=" << (deferred_index_persistence ? "payload-only" : "full-index")
              << " files=" << file_count
              << " groupSize=" << group_size
              << " payloadBytes=" << payload_bytes
              << " wallUs=" << elapsed
              << " acceptanceUs=" << acceptance_elapsed
              << " finalDrainUs=" << final_drain_elapsed
              << " acceptedTargets=" << accepted_targets
              << " acceptedSequence=" << watermarks.accepted_sequence
              << " payloadOnlyFlushUs=" << spool_counters.payload_only_flush_microseconds
              << " payloadOnlyFlushCount=" << spool_counters.payload_only_flush_count
              << " spoolFlushUs=" << spool_counters.durable_flush_microseconds
              << " spoolSyncCount=" << spool_counters.spool_sync_count
              << " spoolSyncUs=" << spool_counters.spool_sync_microseconds
              << " spoolSyncHandleFlushes=" << spool_counters.spool_sync_handle_flush_count
              << " spoolSyncReopens=" << spool_counters.spool_sync_reopen_count
              << " indexPersistUs=" << spool_counters.index_persist_microseconds
              << " indexPersistBytes=" << spool_counters.index_persist_bytes
              << " indexJournalFrames=" << spool_counters.index_journal_frame_count
              << " indexJournalSnapshots=" << spool_counters.index_journal_snapshot_count
              << " indexJournalAppendFrames=" << spool_counters.index_journal_append_count
              << " indexJournalHandleOpens=" << spool_counters.index_journal_handle_open_count
              << " indexJournalHandleFlushes=" << spool_counters.index_journal_handle_flush_count
              << " walAppendUs=" << tx.DurableJournalAppendMicroseconds()
              << " walAppendMaxUs=" << tx.DurableJournalAppendMaxMicroseconds()
              << " walAppendCount=" << tx.DurableJournalAppendCount()
              << " walHandleOpens=" << tx.JournalAppendHandleOpenCount()
              << " walHandleFlushes=" << tx.JournalAppendHandleFlushCount()
              << std::endl;
    return true;
}

bool RunFinalizationCoverageBenchmark(const std::filesystem::path& run_root)
{
    constexpr std::uint64_t wal_flag_committed = 0x1;
    const auto history_transactions = (std::max)(
        std::uint64_t{1},
        EnvironmentUnsigned("APFSACCESS_FINALIZATION_BENCHMARK_HISTORY", 2048));
    const auto iterations = (std::max)(
        std::uint64_t{1},
        EnvironmentUnsigned("APFSACCESS_FINALIZATION_BENCHMARK_ITERATIONS", 8));
    const auto path_bytes = static_cast<std::size_t>((std::max)(
        std::uint64_t{32},
        EnvironmentUnsigned("APFSACCESS_FINALIZATION_BENCHMARK_PATH_BYTES", 2048)));
    const bool use_cache = !EnvironmentFlag("APFSACCESS_DISABLE_FINALIZATION_COVERAGE_CACHE");
    const auto benchmark_root = run_root / "finalization-coverage-benchmark";
    const auto wal_path = benchmark_root / "write-ahead.wal";
    const std::string volume_identity = "finalization-coverage-benchmark-volume";
    std::filesystem::create_directories(benchmark_root);

    std::vector<apfsaccess::rw::WriteAheadLog::Record> history;
    history.reserve(static_cast<std::size_t>(history_transactions * 2 + 1));
    std::uint64_t sequence = 1;
    std::uint64_t latest_accepted_sequence = 0;
    for (std::uint64_t index = 0; index < history_transactions; ++index)
    {
        apfsaccess::rw::WriteAheadLog::Record prepared{};
        prepared.volume_identity = volume_identity;
        prepared.transaction_id = index + 1;
        prepared.sequence = sequence++;
        prepared.operation = apfsaccess::rw::WriteAheadLog::OperationKind::SetBasicInfo;
        prepared.state = apfsaccess::rw::WriteAheadLog::RecordState::Prepared;
        prepared.path_utf8.assign(path_bytes, static_cast<char>('a' + (index % 26)));
        history.push_back(std::move(prepared));

        apfsaccess::rw::WriteAheadLog::Record marker{};
        marker.volume_identity = volume_identity;
        marker.transaction_id = index + 1;
        marker.sequence = sequence++;
        marker.operation = apfsaccess::rw::WriteAheadLog::OperationKind::TransactionMarker;
        marker.state = apfsaccess::rw::WriteAheadLog::RecordState::Checkpointed;
        marker.flags = wal_flag_committed;
        marker.logical_length = 1;
        latest_accepted_sequence = marker.sequence;
        history.push_back(std::move(marker));
    }

    apfsaccess::rw::WriteAheadLog::Record cleanup{};
    cleanup.volume_identity = volume_identity;
    cleanup.sequence = sequence++;
    cleanup.operation = apfsaccess::rw::WriteAheadLog::OperationKind::DurabilityWatermark;
    cleanup.state = apfsaccess::rw::WriteAheadLog::RecordState::Cleaned;
    cleanup.logical_offset = latest_accepted_sequence;
    history.push_back(std::move(cleanup));
    {
        apfsaccess::rw::WriteAheadLog wal({
            wal_path,
            volume_identity,
            128ull * 1024ull * 1024ull,
        });
        if (!wal.AppendBatch(history))
        {
            return Require(false, "Finalization benchmark history should persist");
        }
    }

    apfsaccess::rw::TransactionManager tx(L"DeferredContent");
    tx.SetVolumeIdentity(L"finalization-coverage-benchmark-volume");
    tx.SetJournalPath(wal_path.wstring());
    const std::vector<std::byte> inline_payload{
        std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
    };
    const std::array<std::uint8_t, apfsaccess::rw::WriteAheadLog::PayloadHashSize> inline_payload_sha256{
        0x9f, 0x64, 0xa7, 0x47, 0xe1, 0xb9, 0x7f, 0x13,
        0x1f, 0xab, 0xb6, 0xb4, 0x47, 0x29, 0x6c, 0x9b,
        0x6f, 0x02, 0x01, 0xe7, 0x9f, 0xb3, 0xc5, 0x35,
        0x6e, 0x6c, 0x77, 0xe8, 0x9b, 0x6a, 0x80, 0x6a,
    };
    apfsaccess::rw::TransactionManager::MutationIntent mutation{};
    mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::Write;
    mutation.path = L"\\current.bin";
    mutation.length = inline_payload.size();
    mutation.object_id = history_transactions + 100;
    mutation.generation = 1;
    mutation.payload_spool_offset = 4096;
    mutation.payload_length = inline_payload.size();
    mutation.payload_checksum = inline_payload_sha256;
    mutation.inline_payload = inline_payload;
    if (!tx.Begin() || !tx.RecordMutation(mutation) || !tx.Accept())
    {
        return Require(false, "Finalization benchmark inline transaction should become accepted");
    }

    bool eligible = true;
    const auto started = std::chrono::steady_clock::now();
    for (std::uint64_t iteration = 0; iteration < iterations; ++iteration)
    {
        eligible = tx.CanFinalizeWithoutPayloadSpoolFlush(use_cache) && eligible;
    }
    const auto finished = std::chrono::steady_clock::now();
    const auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
        finished - started).count();
    std::error_code size_error;
    const auto wal_bytes = std::filesystem::file_size(wal_path, size_error);
    std::cout << "[BENCH] mode=" << (use_cache ? "coverage-cache" : "wal-scan")
              << " historyTransactions=" << history_transactions
              << " iterations=" << iterations
              << " walBytes=" << (size_error ? 0 : wal_bytes)
              << " wallUs=" << elapsed_us
              << " perCallUs=" << (elapsed_us / static_cast<long long>(iterations))
              << " cacheHits=" << tx.FinalizationCoverageCacheHitCount()
              << " walScans=" << tx.FinalizationCoverageWalScanCount()
              << " walScanUs=" << tx.FinalizationCoverageWalScanMicroseconds()
              << std::endl;
    return Require(eligible, "Finalization benchmark transaction should remain inline-recoverable");
}

apfsaccess::rw::TransactionManager::MutationIntent MakeMetadataMutation(std::wstring path)
{
    apfsaccess::rw::TransactionManager::MutationIntent mutation{};
    mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::SetBasicInfo;
    mutation.path = std::move(path);
    mutation.timestamp_utc = 123456789;
    return mutation;
}

bool TestConfigurationOrderAndLeaseTransfer(const std::filesystem::path& run_root)
{
    const auto path = run_root / "configuration-order-and-lease-transfer.wal";
    constexpr auto identity = L"configuration-order-volume";
    auto first_mutation = MakeMetadataMutation(L"\\first.txt");

    apfsaccess::rw::TransactionManager path_first(L"DeferredContent");
    path_first.SetJournalPath(path.wstring());
    path_first.SetVolumeIdentity(identity);
    if (!Require(path_first.Begin(), "path-first manager should begin") ||
        !Require(path_first.RecordMutation(first_mutation), "path-first manager should record metadata") ||
        !Require(path_first.Accept(), "path-first manager should accept its first transaction"))
    {
        return false;
    }
    const auto first_accepted_sequence = path_first.Watermarks().accepted_sequence;

    apfsaccess::rw::TransactionManager identity_first(L"DeferredContent");
    identity_first.SetVolumeIdentity(identity);
    identity_first.SetJournalPath(path.wstring());
    if (!Require(identity_first.RecoveryStateValid(), "identity-first configuration should recover the same WAL") ||
        !Require(
            identity_first.Watermarks().accepted_sequence == first_accepted_sequence &&
                identity_first.NextMutationSequence() > first_accepted_sequence,
            "configuration order should reconstruct identical sequence and watermark state") ||
        !Require(
            identity_first.MarkApfsDurableThrough(first_accepted_sequence),
            "the successor manager should append the APFS durability watermark") ||
        !Require(
            path_first.MarkCleanedThrough(first_accepted_sequence),
            "an idle stale manager should reacquire, reseed, and append the cleanup watermark"))
    {
        return false;
    }

    auto second_mutation = MakeMetadataMutation(L"\\second.txt");
    if (!Require(path_first.Begin(), "reseeded stale manager should begin a later transaction") ||
        !Require(path_first.RecordMutation(second_mutation), "reseeded stale manager should record later metadata") ||
        !Require(path_first.Accept(), "reseeded stale manager should append a later acceptance"))
    {
        return false;
    }
    const auto second_accepted_sequence = path_first.Watermarks().accepted_sequence;
    const auto snapshot = apfsaccess::rw::WriteAheadLog::ReadAll(
        path,
        apfsaccess::rw::TransactionManager::WideToUtf8(identity));
    if (!Require(snapshot.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok, "lease-transfer WAL should remain readable"))
    {
        return false;
    }
    std::uint64_t previous_sequence = 0;
    for (const auto& record : snapshot.records)
    {
        if (!Require(
                record.sequence > previous_sequence,
                "stale-manager reacquisition must preserve unique increasing WAL sequences"))
        {
            return false;
        }
        previous_sequence = record.sequence;
    }

    apfsaccess::rw::TransactionManager recovered(L"DeferredContent");
    recovered.SetJournalPath(path.wstring());
    recovered.SetVolumeIdentity(identity);
    if (!Require(
            recovered.Watermarks().accepted_sequence == second_accepted_sequence &&
                recovered.Watermarks().apfs_durable_sequence == first_accepted_sequence &&
                recovered.Watermarks().cleanup_sequence == first_accepted_sequence,
            "restart should retain independent watermarks across stale-manager lease transfer") ||
        !Require(path_first.CanFinalizeWithoutPayloadSpoolFlush(), "previous manager should rescan after restart takes its lease") ||
        !Require(path_first.CanFinalizeWithoutPayloadSpoolFlush(), "previous manager should cache its newly leased snapshot") ||
        !Require(recovered.CanFinalizeWithoutPayloadSpoolFlush(), "restarted manager should rescan after the lease returns") ||
        !Require(recovered.CanFinalizeWithoutPayloadSpoolFlush(), "restarted manager should cache its reacquired snapshot"))
    {
        return false;
    }
    return Require(
               path_first.FinalizationCoverageWalScanCount() == 1 &&
                   path_first.FinalizationCoverageCacheHitCount() == 1,
               "previous manager should scan once and cache once after transfer") &&
           Require(
               recovered.FinalizationCoverageWalScanCount() == 1 &&
                   recovered.FinalizationCoverageCacheHitCount() == 1,
               "restarted manager should scan once and cache once after transfer");
}

bool TestCompactionRetryRetainsCoverageTrust(const std::filesystem::path& run_root)
{
    const auto path = run_root / "compaction-retry-coverage.wal";
    apfsaccess::rw::TransactionManager tx(L"DeferredContent");
    tx.SetJournalMaxBytesForTest(900);
    tx.SetVolumeIdentity(L"compaction-retry-volume");
    tx.SetJournalPath(path.wstring());

    auto first_mutation = MakeMetadataMutation(L"\\cleaned-before-compaction.txt");
    if (!Require(tx.Begin(), "compaction fixture should begin its cleaned transaction") ||
        !Require(tx.RecordMutation(first_mutation), "compaction fixture should record its cleaned mutation") ||
        !Require(tx.Accept(), "compaction fixture should accept its cleaned transaction"))
    {
        return false;
    }
    const auto cleaned_sequence = tx.Watermarks().accepted_sequence;
    if (!Require(tx.MarkApfsDurableThrough(cleaned_sequence), "compaction fixture should mark APFS durability") ||
        !Require(tx.MarkCleanedThrough(cleaned_sequence), "compaction fixture should mark cleanup"))
    {
        return false;
    }

    auto second_mutation = MakeMetadataMutation(L"\\accepted-after-compaction.txt");
    if (!Require(tx.Begin(), "compaction retry transaction should begin") ||
        !Require(tx.RecordMutation(second_mutation), "compaction retry transaction should record metadata") ||
        !Require(tx.Accept(), "size rejection should compact and retry the accepted batch") ||
        !Require(
            tx.CanFinalizeWithoutPayloadSpoolFlush(),
            "successful compaction retry should retain trusted finalization coverage") ||
        !Require(
            tx.FinalizationCoverageCacheHitCount() == 1 &&
                tx.FinalizationCoverageWalScanCount() == 0,
            "compaction retry should not force a redundant validation scan"))
    {
        return false;
    }

    const auto snapshot = apfsaccess::rw::WriteAheadLog::ReadAll(
        path,
        "compaction-retry-volume");
    const auto has_compaction_index = std::any_of(
        snapshot.records.begin(),
        snapshot.records.end(),
        [](const auto& record)
        {
            return record.operation == apfsaccess::rw::WriteAheadLog::OperationKind::CompactionIndex;
        });
    return Require(
               snapshot.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok && has_compaction_index,
               "compaction retry fixture should prove that compaction actually occurred") &&
           Require(
               tx.RecoveryStateValid() && tx.Watermarks().accepted_sequence > cleaned_sequence,
               "compaction retry should retain valid advancing transaction state");
}

bool TestObserverReadsAndActiveLeaseLoss(const std::filesystem::path& run_root)
{
    const auto observer_path = run_root / "active-observer-read.wal";
    apfsaccess::rw::TransactionManager observed_tx(L"DeferredContent");
    observed_tx.SetVolumeIdentity(L"active-observer-volume");
    observed_tx.SetJournalPath(observer_path.wstring());
    auto observed_mutation = MakeMetadataMutation(L"\\observed.txt");
    if (!Require(observed_tx.Begin(), "observed transaction should begin") ||
        !Require(observed_tx.RecordMutation(observed_mutation), "observed transaction should buffer metadata"))
    {
        return false;
    }
    apfsaccess::rw::WriteAheadLog observer({
        observer_path,
        "active-observer-volume",
        0,
    });
    const auto observed_snapshot = observer.ReadAll();
    if (!Require(
            observed_snapshot.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                observed_snapshot.records.empty(),
            "observer should see the complete persisted prefix without revoking active ownership") ||
        !Require(observed_tx.Accept(), "observer read must not prevent the active owner from accepting"))
    {
        return false;
    }

    const auto stolen_path = run_root / "active-lease-loss.wal";
    apfsaccess::rw::TransactionManager stale_tx(L"DeferredContent");
    stale_tx.SetVolumeIdentity(L"active-lease-loss-volume");
    stale_tx.SetJournalPath(stolen_path.wstring());
    auto first_mutation = MakeMetadataMutation(L"\\prepared-before-theft.txt");
    auto second_mutation = MakeMetadataMutation(L"\\rejected-after-theft.txt");
    if (!Require(stale_tx.Begin(), "lease-loss transaction should begin") ||
        !Require(stale_tx.RecordMutation(first_mutation), "lease-loss fixture should record its first mutation") ||
        !Require(stale_tx.FlushPreparedRecords(), "lease-loss fixture should persist prepared evidence"))
    {
        return false;
    }
    apfsaccess::rw::WriteAheadLog successor({
        stolen_path,
        "active-lease-loss-volume",
        0,
    });
    if (!Require(successor.AcquireExclusiveWriterLease(), "successor should explicitly take the active writer lease") ||
        !Require(
            !stale_tx.RecordMutation(second_mutation),
            "active manager should reject new staging immediately after lease loss") ||
        !Require(!stale_tx.Abort(), "abort must report failure when its terminal marker cannot be persisted") ||
        !Require(
            stale_tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Failed &&
                !stale_tx.RecoveryStateValid(),
            "lease loss should leave the stale transaction failed and recovery-blocked"))
    {
        return false;
    }
    const auto stolen_snapshot = successor.ReadAll();
    if (!Require(
            stolen_snapshot.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                stolen_snapshot.records.size() == 1 &&
                stolen_snapshot.records.front().state == apfsaccess::rw::WriteAheadLog::RecordState::Prepared,
            "failed abort should retain prepared evidence without a false terminal marker"))
    {
        return false;
    }
    apfsaccess::rw::TransactionManager recovered(L"DeferredContent");
    recovered.SetVolumeIdentity(L"active-lease-loss-volume");
    recovered.SetJournalPath(stolen_path.wstring());
    return Require(
        !recovered.RecoveryStateValid(),
        "restart should fail closed on unterminated prepared evidence after lease loss");
}

bool TestPoisonedManagerRejectsFurtherMutationAndReuse(const std::filesystem::path& run_root)
{
    const auto path = run_root / "poisoned-manager-reuse.wal";
    apfsaccess::rw::TransactionManager tx(L"DeferredContent");
    tx.SetVolumeIdentity(L"poisoned-manager-reuse-volume");
    tx.SetJournalPath(path.wstring());

    auto first = MakeMetadataMutation(L"\\first.txt");
    auto second = MakeMetadataMutation(L"\\second.txt");
    if (!Require(tx.Begin(), "poisoned-manager fixture should begin") ||
        !Require(tx.RecordMutation(first), "poisoned-manager fixture should record metadata"))
    {
        return false;
    }
    tx.SetJournalFaultInjectionHook([](std::string_view stage)
    {
        return stage == "read-all-exclusive";
    });
    const auto finalization_eligible = tx.CanFinalizeWithoutPayloadSpoolFlush(false);
    tx.SetJournalFaultInjectionHook({});
    if (!Require(
            !finalization_eligible,
            "strict validation should reject an unreadable WAL snapshot") ||
        !Require(
            !tx.RecoveryStateValid(),
            "strict validation failure should poison recovery state"))
    {
        return false;
    }

    const auto journal_before_abort = apfsaccess::rw::WriteAheadLog::ReadAll(
        path,
        "poisoned-manager-reuse-volume");
    const bool mutation_rejected = !tx.RecordMutation(second);
    const bool aborted = tx.Abort();
    const auto journal_after_abort = apfsaccess::rw::WriteAheadLog::ReadAll(
        path,
        "poisoned-manager-reuse-volume");
    return Require(mutation_rejected, "a poisoned active manager must reject later mutations") &&
           Require(!aborted, "a poisoned manager must not publish an abort boundary") &&
           Require(
               tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Failed,
               "a rejected poisoned abort should leave the manager failed") &&
           Require(
               journal_before_abort.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   journal_after_abort.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                   journal_after_abort.records.size() == journal_before_abort.records.size(),
               "a poisoned abort must leave WAL evidence unchanged") &&
           Require(
               !tx.Begin(),
               "an idle manager with poisoned recovery state must not begin another transaction");
}

bool TestPoisonedManagerRejectsDurabilityWatermarks(const std::filesystem::path& run_root)
{
    const auto run_case = [&](std::string_view stem, bool cleanup_watermark, bool no_op)
    {
        const auto path = run_root / (std::string(stem) + ".wal");
        const auto volume = std::string(stem) + "-volume";
        apfsaccess::rw::TransactionManager tx(L"DeferredContent");
        tx.SetVolumeIdentity(std::wstring(volume.begin(), volume.end()));
        tx.SetJournalPath(path.wstring());
        auto mutation = MakeMetadataMutation(L"\\watermark.txt");
        if (!Require(tx.Begin(), "poisoned-watermark fixture should begin") ||
            !Require(tx.RecordMutation(mutation), "poisoned-watermark fixture should record metadata") ||
            !Require(tx.Accept(), "poisoned-watermark fixture should accept metadata"))
        {
            return false;
        }

        const auto accepted = tx.Watermarks().accepted_sequence;
        if (cleanup_watermark &&
            !Require(
                tx.MarkApfsDurableThrough(accepted),
                "cleanup-watermark fixture should establish APFS durability before poisoning"))
        {
            return false;
        }

        tx.SetJournalFaultInjectionHook([](std::string_view stage)
        {
            return stage == "read-all-exclusive";
        });
        const auto finalization_eligible = tx.CanFinalizeWithoutPayloadSpoolFlush(false);
        tx.SetJournalFaultInjectionHook({});
        if (!Require(!finalization_eligible, "strict WAL read failure should reject finalization") ||
            !Require(!tx.RecoveryStateValid(), "strict WAL read failure should poison the manager"))
        {
            return false;
        }

        const auto before_watermarks = tx.Watermarks();
        const auto before_journal = apfsaccess::rw::WriteAheadLog::ReadAll(path, volume);
        const auto target = cleanup_watermark
            ? (no_op ? before_watermarks.cleanup_sequence : before_watermarks.apfs_durable_sequence)
            : (no_op ? before_watermarks.apfs_durable_sequence : before_watermarks.accepted_sequence);
        const bool marked = cleanup_watermark
            ? tx.MarkCleanedThrough(target)
            : tx.MarkApfsDurableThrough(target);
        const auto after_watermarks = tx.Watermarks();
        const auto after_journal = apfsaccess::rw::WriteAheadLog::ReadAll(path, volume);
        return Require(!marked, "poisoned manager must reject durability watermark calls") &&
               Require(!tx.RecoveryStateValid(), "watermark rejection must not heal poisoned recovery state") &&
               Require(
                   after_watermarks.accepted_sequence == before_watermarks.accepted_sequence &&
                       after_watermarks.apfs_durable_sequence == before_watermarks.apfs_durable_sequence &&
                       after_watermarks.cleanup_sequence == before_watermarks.cleanup_sequence,
                   "poisoned watermark rejection must preserve in-memory watermarks") &&
               Require(
                   before_journal.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                       after_journal.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
                       after_journal.records.size() == before_journal.records.size(),
                   "poisoned watermark rejection must not append WAL records");
    };

    return run_case("poisoned-apfs-noop", false, true) &&
           run_case("poisoned-apfs-advance", false, false) &&
           run_case("poisoned-cleanup-noop", true, true) &&
           run_case("poisoned-cleanup-advance", true, false);
}

bool TestRecoveryClearingRequiresCurrentWriterGeneration(const std::filesystem::path& run_root)
{
    const auto path = run_root / "recovery-clear-writer-generation.wal";
    apfsaccess::rw::TransactionManager stale(L"DeferredContent");
    stale.SetVolumeIdentity(L"recovery-clear-writer-generation-volume");
    stale.SetJournalPath(path.wstring());
    auto first = MakeMetadataMutation(L"\\first.txt");
    if (!Require(stale.Begin(), "recovery-clear fixture should begin its first transaction") ||
        !Require(stale.RecordMutation(first), "recovery-clear fixture should record its first mutation") ||
        !Require(stale.Accept(), "recovery-clear fixture should accept its first transaction"))
    {
        return false;
    }
    const auto first_boundary = stale.Watermarks().accepted_sequence;
    if (!Require(stale.MarkApfsDurableThrough(first_boundary), "first boundary should become APFS durable") ||
        !Require(stale.MarkCleanedThrough(first_boundary), "first boundary should become clean") ||
        !Require(stale.CanClearRecoveryState(), "the current clean writer should permit recovery clearing"))
    {
        return false;
    }

    apfsaccess::rw::TransactionManager successor(L"DeferredContent");
    successor.SetVolumeIdentity(L"recovery-clear-writer-generation-volume");
    successor.SetJournalPath(path.wstring());
    auto second = MakeMetadataMutation(L"\\second.txt");
    if (!Require(successor.Begin(), "successor should acquire the transferred writer lease") ||
        !Require(successor.RecordMutation(second), "successor should record new accepted work") ||
        !Require(successor.Accept(), "successor should publish new accepted work"))
    {
        return false;
    }

    const auto stale_watermarks = stale.Watermarks();
    return Require(
               stale_watermarks.accepted_sequence == stale_watermarks.apfs_durable_sequence &&
                   stale_watermarks.apfs_durable_sequence == stale_watermarks.cleanup_sequence,
               "stale cached watermarks should reproduce the misleading clean state") &&
           Require(
               !stale.CanClearRecoveryState(),
               "a manager that lost its writer generation must not clear recovery state");
}

} // namespace

int main()
{
    std::error_code ec;
    const auto unique_id = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto run_root = std::filesystem::temp_directory_path(ec) / ("ApfsAccessTxTests_" + std::to_string(unique_id));
    if (ec)
    {
        std::cerr << "[FAIL] unable to access temporary directory" << std::endl;
        return 1;
    }

    std::filesystem::remove_all(run_root, ec);
    ec.clear();
    std::filesystem::create_directories(run_root, ec);
    if (ec)
    {
        std::cerr << "[FAIL] unable to create test directory" << std::endl;
        return 1;
    }

    char* benchmark_flag = nullptr;
    std::size_t benchmark_flag_size = 0;
    const bool benchmark_enabled =
        _dupenv_s(&benchmark_flag, &benchmark_flag_size, "APFSACCESS_ACCEPTANCE_BENCHMARK") == 0 &&
        benchmark_flag != nullptr;
    if (benchmark_flag)
    {
        std::free(benchmark_flag);
    }
    if (benchmark_enabled)
    {
        const auto benchmark_ok = RunAcceptanceBenchmark(run_root);
        std::filesystem::remove_all(run_root, ec);
        return benchmark_ok ? 0 : 1;
    }
    if (EnvironmentFlag("APFSACCESS_FINALIZATION_COVERAGE_BENCHMARK"))
    {
        const auto benchmark_ok = RunFinalizationCoverageBenchmark(run_root);
        std::filesystem::remove_all(run_root, ec);
        return benchmark_ok ? 0 : 1;
    }

    const auto journal_path = run_root / "rw-journal.wal";
    const std::string volume_identity = "tx-test-volume";
    apfsaccess::rw::TransactionManager tx(L"Conservative");
    tx.SetJournalPath(journal_path.wstring());
    tx.SetVolumeIdentity(L"tx-test-volume");

    std::vector<std::string> stages;
    tx.SetFaultInjectionHook([&stages](const std::string& stage)
    {
        stages.push_back(stage);
    });

    bool ok = true;
    ok &= TestPoisonedManagerRejectsFurtherMutationAndReuse(run_root);
    ok &= TestPoisonedManagerRejectsDurabilityWatermarks(run_root);
    ok &= TestRecoveryClearingRequiresCurrentWriterGeneration(run_root);
    ok &= TestConfigurationOrderAndLeaseTransfer(run_root);
    ok &= TestCompactionRetryRetainsCoverageTrust(run_root);
    ok &= TestObserverReadsAndActiveLeaseLoss(run_root);
    ok &= Require(tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Idle, "Initial state should be idle");
    ok &= Require(tx.Begin(), "Begin should succeed from idle state");
    ok &= Require(tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Active, "State should be active after begin");
    ok &= Require(tx.CurrentTransactionId() == 1, "First transaction id should be 1");

    apfsaccess::rw::TransactionManager::MutationIntent mutation{};
    mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::CreateFile;
    mutation.path = L"\\docs\\tx.txt";
    ok &= Require(tx.RecordMutation(mutation), "RecordMutation should succeed in active state");
    apfsaccess::rw::TransactionManager::MutationIntent size_mutation{};
    size_mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::SetFileSize;
    size_mutation.path = L"\\docs\\tx.txt";
    size_mutation.length = 4096;
    ok &= Require(tx.RecordMutation(size_mutation), "Second mutation in same transaction should succeed");
    ok &= Require(tx.PendingMutationCount() == 2, "Pending mutation count should be 2");
    auto pre_commit_journal = apfsaccess::rw::WriteAheadLog::ReadAll(journal_path, volume_identity);
    ok &= Require(
        pre_commit_journal.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
            pre_commit_journal.records.empty(),
        "Prepared transaction mutations should stay buffered until commit boundary");

    ok &= Require(tx.Commit(), "Commit should succeed");
    ok &= Require(tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Idle, "State should return to idle after commit");
    ok &= Require(tx.PendingMutationCount() == 0, "Pending mutation count should be reset after commit");
    ok &= Require(
        tx.DurableJournalAppendCount() == 1,
        "Commit should persist prepared mutations and final marker with one durable WAL append");
    ok &= Require(
        tx.DurableJournalAppendMicroseconds() >= tx.DurableJournalAppendMaxMicroseconds(),
        "WAL timing telemetry should include the slowest durable append");
    ok &= Require(
        tx.JournalAppendHandleOpenCount() == 1 &&
            tx.JournalAppendHandleFlushCount() == 1,
        "Transaction manager should reuse one WAL append handle for the commit boundary");

    const std::vector<std::string> expected_stages =
    {
        "begin",
        "mutation-recorded",
        "mutation-recorded",
        "commit-start",
        "prepare",
        "write-data",
        "write-metadata",
        "flush-data",
        "switch-checkpoint",
        "finalize",
        "commit-finish",
    };
    ok &= Require(stages == expected_stages, "Stage callback sequence should match commit state machine");

    auto journal_read = apfsaccess::rw::WriteAheadLog::ReadAll(journal_path, volume_identity);
    ok &= Require(journal_read.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok, "WAL should read after commit");
    ok &= Require(journal_read.records.size() == 3, "WAL should capture prepared mutations plus a commit marker");
    ok &= Require(
        journal_read.records[0].state == apfsaccess::rw::WriteAheadLog::RecordState::Prepared &&
            journal_read.records[1].state == apfsaccess::rw::WriteAheadLog::RecordState::Prepared,
        "Committed transaction mutations should stay prepared until the final marker");
    ok &= Require(
        journal_read.records[2].operation == apfsaccess::rw::WriteAheadLog::OperationKind::TransactionMarker &&
            journal_read.records[2].state == apfsaccess::rw::WriteAheadLog::RecordState::Checkpointed &&
            journal_read.records[2].logical_length == 2,
        "Committed transaction should end with a durable marker and mutation count");
    ok &= Require(journal_read.records.front().path_utf8.find("\\docs\\tx.txt") != std::string::npos, "WAL should persist committed path");

    apfsaccess::rw::TransactionManager::MutationIntent delete_mutation{};
    delete_mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::Delete;
    delete_mutation.path = L"\\docs\\tx.txt";
    ok &= Require(tx.Begin(), "Second Begin should succeed");
    ok &= Require(tx.RecordMutation(delete_mutation), "Second RecordMutation should succeed");
    auto pre_abort_journal = apfsaccess::rw::WriteAheadLog::ReadAll(journal_path, volume_identity);
    ok &= Require(pre_abort_journal.records.size() == 3, "Prepared abort mutation should stay buffered before abort marker");
    ok &= Require(tx.Abort(), "Abort should succeed");
    ok &= Require(tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Idle, "State should return to idle after abort");
    ok &= Require(
        tx.DurableJournalAppendCount() == 2,
        "Abort marker should add one durable WAL append after the committed transaction");

    journal_read = apfsaccess::rw::WriteAheadLog::ReadAll(journal_path, volume_identity);
    ok &= Require(journal_read.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok, "WAL should read after abort");
    ok &= Require(journal_read.records.size() == 4, "WAL should capture committed transaction plus aborted marker");
    ok &= Require(
        journal_read.records.back().operation == apfsaccess::rw::WriteAheadLog::OperationKind::TransactionMarker &&
            journal_read.records.back().state == apfsaccess::rw::WriteAheadLog::RecordState::Cleaned,
        "Aborted transaction should end with a cleaned marker");

    apfsaccess::rw::TransactionManager unicode_tx(L"Conservative");
    unicode_tx.SetJournalPath(journal_path.wstring());
    unicode_tx.SetVolumeIdentity(L"tx-test-volume");
    apfsaccess::rw::TransactionManager::MutationIntent unicode_mutation{};
    unicode_mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::CreateDirectory;
    unicode_mutation.path = L"\\unicode-\x6587\x4EF6-\xD83D\xDE80";
    ok &= Require(unicode_tx.Begin(), "Unicode Begin should succeed");
    ok &= Require(unicode_tx.RecordMutation(unicode_mutation), "Unicode RecordMutation should succeed");
    ok &= Require(unicode_tx.Commit(), "Unicode Commit should succeed");
    ok &= Require(
        unicode_tx.DurableJournalAppendCount() == 1,
        "New transaction manager should also batch prepared mutation and marker into one durable WAL append");

    journal_read = apfsaccess::rw::WriteAheadLog::ReadAll(journal_path, volume_identity);
    ok &= Require(journal_read.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok, "WAL should read after Unicode commit");
    ok &= Require(journal_read.records.size() == 6, "WAL should contain prepared mutations and final markers");
    const auto unicode_path_utf8 = apfsaccess::rw::TransactionManager::WideToUtf8(unicode_mutation.path);
    ok &= Require(
        !unicode_path_utf8.empty() &&
        journal_read.records[journal_read.records.size() - 2].path_utf8.find(unicode_path_utf8) != std::string::npos,
        "WAL should persist Unicode paths as UTF-8 without truncating the transaction record");
    ok &= Require(
        journal_read.records[journal_read.records.size() - 2].transaction_id == 3 &&
            journal_read.records.back().transaction_id == 3,
        "New manager should seed the next transaction id from the existing WAL");
    ok &= Require(
        journal_read.records[journal_read.records.size() - 2].sequence == 5 &&
            journal_read.records.back().sequence == 6,
        "New manager should seed the next sequence id from the existing WAL");

    apfsaccess::rw::TransactionManager checkpointed_recovery(L"Conservative");
    checkpointed_recovery.SetJournalPath(journal_path.wstring());
    checkpointed_recovery.SetVolumeIdentity(L"tx-test-volume");
    std::vector<apfsaccess::rw::TransactionManager::AcceptedTransaction> checkpointed_transactions;
    std::string checkpointed_failure;
    ok &= Require(
        checkpointed_recovery.LoadAcceptedTransactionsSinceCleanup(
            checkpointed_transactions,
            &checkpointed_failure),
        "Replay lookup should include checkpointed transactions after the cleanup watermark");
    ok &= Require(
        checkpointed_failure.empty() && checkpointed_transactions.size() == 2,
        "Replay lookup should reconstruct both committed transaction boundaries");
    if (checkpointed_transactions.size() == 2)
    {
        ok &= Require(
            checkpointed_transactions.front().accepted_sequence == journal_read.records[2].sequence &&
                checkpointed_transactions.front().mutations.size() == 2 &&
                checkpointed_transactions.back().accepted_sequence == journal_read.records.back().sequence &&
                checkpointed_transactions.back().mutations.size() == 1,
            "Replay lookup should preserve checkpointed transaction order and mutation counts");
    }

    apfsaccess::rw::TransactionManager proof_tx(L"DeferredContent");
    std::vector<std::uint64_t> retained_proof_ids;
    retained_proof_ids.reserve(
        apfsaccess::rw::TransactionManager::MaxRetainedAcceptedSequenceProofs());
    std::uint64_t oldest_proof_sequence = 0;
    for (std::size_t index = 0;
         index < apfsaccess::rw::TransactionManager::MaxRetainedAcceptedSequenceProofs();
         ++index)
    {
        apfsaccess::rw::TransactionManager::MutationIntent proof_mutation{};
        proof_mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::CreateFile;
        proof_mutation.path = L"\\proof-" + std::to_wstring(index) + L".bin";
        ok &= Require(proof_tx.Begin(), "Pinned proof transaction should begin");
        const auto proof_id = proof_tx.CurrentTransactionId();
        ok &= Require(
            proof_tx.RetainAcceptedSequenceProof(proof_id),
            "Pinned proof registry should retain an active transaction");
        ok &= Require(
            proof_tx.RecordMutation(proof_mutation),
            "Pinned proof transaction should record a mutation");
        ok &= Require(
            proof_tx.Accept(),
            "Pinned proof transaction should reach an accepted boundary");
        const auto proof_sequence = proof_tx.AcceptedSequenceForTransaction(proof_id);
        ok &= Require(
            proof_sequence.has_value(),
            "Pinned proof should resolve the exact accepted transaction");
        if (index == 0 && proof_sequence.has_value())
        {
            oldest_proof_sequence = *proof_sequence;
        }
        retained_proof_ids.push_back(proof_id);
    }
    ok &= Require(
        proof_tx.RetainedAcceptedSequenceProofCount() ==
            apfsaccess::rw::TransactionManager::MaxRetainedAcceptedSequenceProofs(),
        "Pinned proof registry should stop at its fixed capacity");
    ok &= Require(proof_tx.Begin(), "Proof-cap fallback transaction should begin");
    apfsaccess::rw::TransactionManager::MutationIntent overflow_proof_mutation{};
    overflow_proof_mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::CreateFile;
    overflow_proof_mutation.path = L"\\proof-overflow.bin";
    ok &= Require(
        proof_tx.RecordMutation(overflow_proof_mutation),
        "Proof-cap fallback transaction should record a mutation");
    ok &= Require(
        !proof_tx.RetainAcceptedSequenceProof(proof_tx.CurrentTransactionId()),
        "Pinned proof registry should apply backpressure instead of evicting a live proof");
    ok &= Require(proof_tx.Abort(), "Proof-cap fallback transaction should abort cleanly");
    ok &= Require(
        proof_tx.AcceptedSequenceForTransaction(retained_proof_ids.front()) == oldest_proof_sequence,
        "A full proof registry must preserve its oldest live transaction exactly");

    proof_tx.ReleaseAcceptedSequenceProof(retained_proof_ids.back());
    ok &= Require(proof_tx.Begin(), "Freed proof slot transaction should begin");
    const auto reused_proof_id = proof_tx.CurrentTransactionId();
    ok &= Require(
        proof_tx.RetainAcceptedSequenceProof(reused_proof_id) &&
            proof_tx.RetainAcceptedSequenceProof(reused_proof_id),
        "A freed proof slot should admit two callers for the same transaction");
    apfsaccess::rw::TransactionManager::MutationIntent reused_proof_mutation{};
    reused_proof_mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::CreateFile;
    reused_proof_mutation.path = L"\\proof-reused-slot.bin";
    ok &= Require(
        proof_tx.RecordMutation(reused_proof_mutation),
        "Freed proof slot transaction should record a mutation");
    ok &= Require(
        proof_tx.Accept(),
        "Freed proof slot transaction should reach an accepted boundary");
    const auto reused_proof_sequence = proof_tx.AcceptedSequenceForTransaction(reused_proof_id);
    ok &= Require(
        reused_proof_sequence.has_value() &&
            proof_tx.RetainedAcceptedSequenceProofCount() ==
                apfsaccess::rw::TransactionManager::MaxRetainedAcceptedSequenceProofs(),
        "Reusing one slot should restore the registry to capacity without duplicating its entry");
    proof_tx.ReleaseAcceptedSequenceProof(reused_proof_id);
    ok &= Require(
        proof_tx.AcceptedSequenceForTransaction(reused_proof_id) == reused_proof_sequence,
        "The first grouped caller release must preserve a shared exact-transaction proof");
    proof_tx.ReleaseAcceptedSequenceProof(reused_proof_id);
    ok &= Require(
        !proof_tx.AcceptedSequenceForTransaction(reused_proof_id).has_value(),
        "The final grouped caller release should remove the shared exact-transaction proof");

    const auto latest_proof_sequence = proof_tx.Watermarks().accepted_sequence;
    ok &= Require(
        proof_tx.MarkApfsDurableThrough(latest_proof_sequence),
        "Pinned proof fixture should mark all accepted work APFS-durable");
    ok &= Require(
        proof_tx.MarkCleanedThrough(latest_proof_sequence),
        "Pinned proof fixture should advance cleanup through all accepted work");
    ok &= Require(
        proof_tx.TrackedAcceptedBoundaryCount() == 0,
        "Cleanup should prune accepted boundaries that can no longer be targeted");
    ok &= Require(
        proof_tx.AcceptedSequenceForTransaction(retained_proof_ids.front()) == oldest_proof_sequence,
        "Cleanup must not erase an explicitly pinned exact-transaction proof");
    for (const auto proof_id : retained_proof_ids)
    {
        proof_tx.ReleaseAcceptedSequenceProof(proof_id);
    }
    ok &= Require(
        proof_tx.RetainedAcceptedSequenceProofCount() == 0,
        "The final grouped caller should release every exact-transaction proof");

    const std::vector<std::byte> inline_payload{
        std::byte{0x01},
        std::byte{0x02},
        std::byte{0x03},
        std::byte{0x04},
    };
    const std::array<std::uint8_t, apfsaccess::rw::WriteAheadLog::PayloadHashSize> inline_payload_sha256{
        0x9f, 0x64, 0xa7, 0x47, 0xe1, 0xb9, 0x7f, 0x13,
        0x1f, 0xab, 0xb6, 0xb4, 0x47, 0x29, 0x6c, 0x9b,
        0x6f, 0x02, 0x01, 0xe7, 0x9f, 0xb3, 0xc5, 0x35,
        0x6e, 0x6c, 0x77, 0xe8, 0x9b, 0x6a, 0x80, 0x6a,
    };

    const auto inline_acceptance_path = run_root / "inline-accepted-write.wal";
    apfsaccess::rw::TransactionManager inline_acceptance_tx(L"DeferredContent");
    inline_acceptance_tx.SetVolumeIdentity(L"inline-accepted-volume");
    inline_acceptance_tx.SetJournalPath(inline_acceptance_path.wstring());
    apfsaccess::rw::TransactionManager::MutationIntent inline_mutation{};
    inline_mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::Write;
    inline_mutation.path = L"\\inline.bin";
    inline_mutation.length = inline_payload.size();
    inline_mutation.object_id = 41;
    inline_mutation.generation = 7;
    inline_mutation.payload_spool_offset = 1024;
    inline_mutation.payload_length = inline_payload.size();
    inline_mutation.payload_checksum = inline_payload_sha256;
    inline_mutation.inline_payload = inline_payload;
    ok &= Require(inline_acceptance_tx.Begin(), "Inline acceptance transaction should begin");
    ok &= Require(
        inline_acceptance_tx.CanAddInlinePayload(apfsaccess::rw::WriteAheadLog::MaxInlinePayloadBytes),
        "An empty transaction should admit the complete inline payload budget");
    ok &= Require(
        !inline_acceptance_tx.CanAddInlinePayload(apfsaccess::rw::WriteAheadLog::MaxInlinePayloadBytes + 1),
        "A transaction should reject payload data beyond the inline budget");
    ok &= Require(
        inline_acceptance_tx.RecordMutation(inline_mutation),
        "Inline acceptance transaction should record its write");
    ok &= Require(
        inline_acceptance_tx.CanAddInlinePayload(
            apfsaccess::rw::WriteAheadLog::MaxInlinePayloadBytes - inline_payload.size()),
        "A transaction should admit payload data exactly through the inline budget") &&
        Require(
            !inline_acceptance_tx.CanAddInlinePayload(
                apfsaccess::rw::WriteAheadLog::MaxInlinePayloadBytes - inline_payload.size() + 1),
            "A transaction should reject aggregate inline payload data beyond its budget");
    ok &= Require(
        inline_acceptance_tx.CanAcceptWithoutPayloadSpoolFlush(),
        "A transaction with complete inline recovery bytes should not require a payload-spool flush");
    ok &= Require(
        inline_acceptance_tx.Accept(),
        "Inline acceptance transaction should persist its durable WAL boundary");
    ok &= Require(
        inline_acceptance_tx.CanFinalizeWithoutPayloadSpoolFlush(),
        "Accepted inline work should remain self-contained through finalization");
    ok &= Require(
        inline_acceptance_tx.FinalizationCoverageCacheHitCount() == 1 &&
            inline_acceptance_tx.FinalizationCoverageWalScanCount() == 0,
        "Same-process accepted work should use the bounded finalization coverage summary");
    ok &= Require(
        inline_acceptance_tx.CanFinalizeWithoutPayloadSpoolFlush(false),
        "The rollback path should preserve strict WAL-scanned finalization coverage");
    ok &= Require(
        inline_acceptance_tx.FinalizationCoverageWalScanCount() == 1,
        "Disabling the finalization coverage cache should force one complete WAL scan");
    const auto inline_acceptance_read = apfsaccess::rw::WriteAheadLog::ReadAll(
        inline_acceptance_path,
        "inline-accepted-volume");
    ok &= Require(
        inline_acceptance_read.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
            inline_acceptance_read.records.size() == 2 &&
            inline_acceptance_read.records.front().inline_payload == inline_payload,
        "Accepted WAL should retain byte-identical inline recovery payload data");
    apfsaccess::rw::TransactionManager restarted_inline_acceptance_tx(L"DeferredContent");
    restarted_inline_acceptance_tx.SetVolumeIdentity(L"inline-accepted-volume");
    restarted_inline_acceptance_tx.SetJournalPath(inline_acceptance_path.wstring());
    ok &= Require(
        restarted_inline_acceptance_tx.CanFinalizeWithoutPayloadSpoolFlush(),
        "Restarted inline accepted work should remain recoverable after strict WAL validation");
    ok &= Require(
        restarted_inline_acceptance_tx.FinalizationCoverageCacheHitCount() == 1 &&
            restarted_inline_acceptance_tx.FinalizationCoverageWalScanCount() == 0,
        "Restarted inline work should use coverage rebuilt from its exclusively leased WAL snapshot");
    ok &= Require(
        restarted_inline_acceptance_tx.MarkApfsDurableThrough(
            restarted_inline_acceptance_tx.Watermarks().accepted_sequence),
        "Restarted manager should be able to take over the writer lease and mark replay durable");
    ok &= Require(
        inline_acceptance_tx.CanFinalizeWithoutPayloadSpoolFlush(),
        "A manager that lost its writer lease should still validate inline recovery through the WAL") &&
        Require(
            inline_acceptance_tx.FinalizationCoverageCacheHitCount() == 1 &&
                inline_acceptance_tx.FinalizationCoverageWalScanCount() == 2,
            "Writer-lease transfer must force the previous manager back to strict WAL scanning");

    const auto mixed_acceptance_path = run_root / "mixed-accepted-write.wal";
    apfsaccess::rw::TransactionManager mixed_acceptance_tx(L"DeferredContent");
    mixed_acceptance_tx.SetVolumeIdentity(L"mixed-accepted-volume");
    mixed_acceptance_tx.SetJournalPath(mixed_acceptance_path.wstring());
    auto legacy_mutation = inline_mutation;
    legacy_mutation.path = L"\\legacy.bin";
    legacy_mutation.inline_payload.clear();
    ok &= Require(mixed_acceptance_tx.Begin(), "Mixed acceptance transaction should begin");
    ok &= Require(
        mixed_acceptance_tx.RecordMutation(inline_mutation) &&
            mixed_acceptance_tx.RecordMutation(legacy_mutation),
        "Mixed acceptance transaction should record both writes");
    ok &= Require(
        !mixed_acceptance_tx.CanAddInlinePayload(1),
        "A transaction with a non-inline write must reject further inline payload admission");
    ok &= Require(
        !mixed_acceptance_tx.CanAcceptWithoutPayloadSpoolFlush(),
        "One non-inline write should keep the complete transaction on the payload-spool flush path");
    ok &= Require(
        mixed_acceptance_tx.Accept(),
        "Mixed acceptance transaction should remain valid through the legacy acceptance path");
    ok &= Require(
        !mixed_acceptance_tx.CanFinalizeWithoutPayloadSpoolFlush(),
        "Accepted mixed work should retain payload-spool finalization durability");
    ok &= Require(
        mixed_acceptance_tx.FinalizationCoverageCacheHitCount() == 1 &&
            mixed_acceptance_tx.FinalizationCoverageWalScanCount() == 0,
        "Same-process mixed acceptance should be rejected by the bounded coverage summary");
    const auto mixed_accepted_sequence = mixed_acceptance_tx.Watermarks().accepted_sequence;
    ok &= Require(
        mixed_acceptance_tx.MarkApfsDurableThrough(mixed_accepted_sequence),
        "Mixed acceptance should advance only after its APFS checkpoint is proven durable");
    ok &= Require(
        mixed_acceptance_tx.CanFinalizeWithoutPayloadSpoolFlush(),
        "APFS-durable mixed work should no longer require a redundant pre-cleanup spool flush") &&
        Require(
            mixed_acceptance_tx.FinalizationCoverageCacheHitCount() == 2 &&
                mixed_acceptance_tx.FinalizationCoverageWalScanCount() == 0,
            "Durability advancement should prune the mixed acceptance coverage blocker");

    const auto flushed_legacy_path = run_root / "flushed-legacy-accepted-write.wal";
    apfsaccess::rw::TransactionManager flushed_legacy_tx(L"DeferredContent");
    flushed_legacy_tx.SetVolumeIdentity(L"flushed-legacy-accepted-volume");
    flushed_legacy_tx.SetJournalPath(flushed_legacy_path.wstring());
    ok &= Require(flushed_legacy_tx.Begin(), "Flushed legacy transaction should begin");
    ok &= Require(
        flushed_legacy_tx.RecordMutation(legacy_mutation),
        "Flushed legacy transaction should record its non-inline write");
    ok &= Require(
        flushed_legacy_tx.FlushPreparedRecords(),
        "Flushed legacy transaction should persist prepared records separately");
    ok &= Require(
        flushed_legacy_tx.Accept(),
        "Flushed legacy transaction should append its accepted marker");
    ok &= Require(
        !flushed_legacy_tx.CanFinalizeWithoutPayloadSpoolFlush(),
        "Separately flushed non-inline writes must retain their spool-flush requirement");
    ok &= Require(
        flushed_legacy_tx.FinalizationCoverageCacheHitCount() == 1 &&
            flushed_legacy_tx.FinalizationCoverageWalScanCount() == 0,
        "Flushed prepared records should retain bounded recovery classification");

    const auto poisoned_coverage_path = run_root / "poisoned-finalization-coverage.wal";
    apfsaccess::rw::TransactionManager poisoned_coverage_tx(L"DeferredContent");
    poisoned_coverage_tx.SetVolumeIdentity(L"poisoned-finalization-coverage-volume");
    poisoned_coverage_tx.SetJournalPath(poisoned_coverage_path.wstring());
    ok &= Require(poisoned_coverage_tx.Begin(), "Poisoned coverage transaction should begin");
    ok &= Require(
        poisoned_coverage_tx.RecordMutation(inline_mutation) && poisoned_coverage_tx.Accept(),
        "Poisoned coverage fixture should accept inline recovery data");
    const auto poisoned_accepted_sequence = poisoned_coverage_tx.Watermarks().accepted_sequence;
    ok &= Require(
        poisoned_coverage_tx.MarkApfsDurableThrough(poisoned_accepted_sequence),
        "Poisoned coverage fixture should first reach APFS durability");
    poisoned_coverage_tx.SetJournalFaultInjectionHook([](std::string_view stage)
    {
        return stage == "durable-flush";
    });
    ok &= Require(
        !poisoned_coverage_tx.MarkCleanedThrough(poisoned_accepted_sequence),
        "Ambiguous cleanup-watermark durability should poison finalization coverage");
    poisoned_coverage_tx.SetJournalFaultInjectionHook({});
    const auto poisoned_watermarks = poisoned_coverage_tx.Watermarks();
    ok &= Require(
        poisoned_watermarks.accepted_sequence == poisoned_watermarks.apfs_durable_sequence &&
            poisoned_watermarks.cleanup_sequence < poisoned_watermarks.apfs_durable_sequence,
        "Poisoned coverage fixture should retain equal accepted and APFS-durable watermarks");
    ok &= Require(
        !poisoned_coverage_tx.CanFinalizeWithoutPayloadSpoolFlush() &&
            !poisoned_coverage_tx.CanFinalizeWithoutPayloadSpoolFlush(),
        "Poisoned coverage must fail closed even when accepted and durable watermarks are equal");
    ok &= Require(
        poisoned_coverage_tx.FinalizationCoverageCacheHitCount() == 0 &&
            poisoned_coverage_tx.FinalizationCoverageWalScanCount() == 0,
        "Poisoned coverage should reject before cache use or redundant WAL scans");

    const auto acceptance_journal_path = run_root / "accepted-write.wal";
    apfsaccess::rw::TransactionManager accepted_tx(L"DeferredContent");
    accepted_tx.SetVolumeIdentity(L"accepted-test-volume");
    accepted_tx.SetJournalPath(acceptance_journal_path.wstring());

    apfsaccess::rw::TransactionManager::MutationIntent payload_mutation{};
    payload_mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::Write;
    payload_mutation.path = L"\\accepted.bin";
    payload_mutation.offset = 4096;
    payload_mutation.length = 8192;
    payload_mutation.object_id = 77;
    payload_mutation.generation = 9;
    payload_mutation.payload_spool_offset = 12345;
    payload_mutation.payload_length = 8192;
    payload_mutation.payload_checksum[0] = 0x5a;

    ok &= Require(accepted_tx.Begin(), "Accepted transaction should begin");
    const auto first_accepted_transaction_id = accepted_tx.CurrentTransactionId();
    ok &= Require(
        accepted_tx.RetainAcceptedSequenceProof(first_accepted_transaction_id),
        "Accepted transaction fixture should pin its live exact-transaction proof");
    ok &= Require(accepted_tx.RecordMutation(payload_mutation), "Accepted transaction should record payload mutation");
    ok &= Require(accepted_tx.Accept(), "Accepted transaction should persist its durable acceptance boundary");
    const auto first_accepted_sequence = accepted_tx.Watermarks().accepted_sequence;
    ok &= Require(first_accepted_sequence == 2, "Accepted marker should become the accepted watermark");
    ok &= Require(
        accepted_tx.DurableJournalAppendCount() == 1 &&
            accepted_tx.DurableJournalAppendMicroseconds() >= accepted_tx.DurableJournalAppendMaxMicroseconds(),
        "Accepted transaction should expose one timed durable WAL append");
    ok &= Require(
        accepted_tx.Watermarks().apfs_durable_sequence == 0 &&
            accepted_tx.Watermarks().cleanup_sequence == 0,
        "Acceptance alone must not imply APFS durability or cleanup");
    ok &= Require(
        accepted_tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Idle,
        "Accepted transaction should release the active slot for the next foreground batch");
    ok &= Require(
        accepted_tx.AcceptedSequenceForTransaction(first_accepted_transaction_id) == first_accepted_sequence,
        "Pinned acceptance proof should bind the original transaction to its accepted sequence");

    apfsaccess::rw::TransactionManager restarted_proof_tx(L"DeferredContent");
    restarted_proof_tx.SetVolumeIdentity(L"accepted-test-volume");
    restarted_proof_tx.SetJournalPath(acceptance_journal_path.wstring());
    ok &= Require(
        restarted_proof_tx.RetainedAcceptedSequenceProofCount() == 0 &&
            !restarted_proof_tx.AcceptedSequenceForTransaction(first_accepted_transaction_id).has_value(),
        "Restart should reconstruct WAL replay state without reviving process-local grouped proofs");
    accepted_tx.ReleaseAcceptedSequenceProof(first_accepted_transaction_id);

    const auto grouped_acceptance_path = run_root / "grouped-accepted-write.wal";
    apfsaccess::rw::TransactionManager grouped_acceptance_tx(L"DeferredContent");
    grouped_acceptance_tx.SetVolumeIdentity(L"grouped-accepted-volume");
    grouped_acceptance_tx.SetJournalPath(grouped_acceptance_path.wstring());
    auto grouped_mutation = payload_mutation;
    grouped_mutation.path = L"\\grouped.bin";
    std::mutex grouped_mutex;
    std::condition_variable grouped_cv;
    bool first_grouped_acceptance_ready = false;
    bool second_grouped_acceptance_ready = false;
    bool first_grouped_ok = false;
    std::uint64_t first_grouped_sequence = 0;
    std::thread first_grouped_thread([&]()
    {
        first_grouped_ok =
            grouped_acceptance_tx.Begin() &&
            grouped_acceptance_tx.RecordMutation(grouped_mutation) &&
            grouped_acceptance_tx.AcceptForDeferredCommit(&first_grouped_sequence);
        {
            std::lock_guard<std::mutex> lock(grouped_mutex);
            first_grouped_acceptance_ready = true;
        }
        grouped_cv.notify_all();
        {
            std::unique_lock<std::mutex> lock(grouped_mutex);
            grouped_cv.wait(lock, [&]() { return second_grouped_acceptance_ready; });
        }
        first_grouped_ok = first_grouped_ok &&
            grouped_acceptance_tx.WaitForDeferredAcceptanceDurability(first_grouped_sequence);
    });
    {
        std::unique_lock<std::mutex> lock(grouped_mutex);
        grouped_cv.wait(lock, [&]() { return first_grouped_acceptance_ready; });
    }
    std::uint64_t second_grouped_sequence = 0;
    const bool second_grouped_ok =
        grouped_acceptance_tx.Begin() &&
        grouped_acceptance_tx.RecordMutation(grouped_mutation) &&
        grouped_acceptance_tx.AcceptForDeferredCommit(&second_grouped_sequence) &&
        grouped_acceptance_tx.WaitForDeferredAcceptanceDurability(second_grouped_sequence);
    {
        std::lock_guard<std::mutex> lock(grouped_mutex);
        second_grouped_acceptance_ready = true;
    }
    grouped_cv.notify_all();
    first_grouped_thread.join();
    ok &= Require(
        first_grouped_ok && second_grouped_ok &&
            first_grouped_sequence != 0 &&
            second_grouped_sequence > first_grouped_sequence,
        "Deferred acceptance group should durably complete two sequential transactions");
    ok &= Require(
        grouped_acceptance_tx.DeferredWalGroupFlushCount() == 1,
        "Two deferred acceptance transactions should share one WAL flush barrier");
    ok &= Require(
        grouped_acceptance_tx.MarkApfsDurableThrough(second_grouped_sequence) &&
            grouped_acceptance_tx.MarkCleanedThrough(second_grouped_sequence),
        "Grouped deferred acceptance should remain valid through APFS durability and cleanup");

    auto accepted_read = apfsaccess::rw::WriteAheadLog::ReadAll(
        acceptance_journal_path,
        "accepted-test-volume");
    ok &= Require(
        accepted_read.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
            accepted_read.records.size() == 2,
        "Accepted WAL should contain one prepared payload record and one acceptance marker");
    if (accepted_read.records.size() == 2)
    {
        const auto& payload_record = accepted_read.records[0];
        const auto& accepted_marker = accepted_read.records[1];
        ok &= Require(
            payload_record.object_id == 77 &&
                payload_record.parent_object_id == 9 &&
                payload_record.payload_spool_id == payload_record.sequence &&
                payload_record.payload_offset == 12345 &&
                payload_record.payload_length == 8192 &&
                payload_record.logical_offset == 4096 &&
                payload_record.logical_length == 8192 &&
                payload_record.payload_sha256[0] == 0x5a,
            "Accepted payload record should bind object, generation, spool range, logical range, sequence, and checksum");
        ok &= Require(
            accepted_marker.operation == apfsaccess::rw::WriteAheadLog::OperationKind::TransactionMarker &&
                accepted_marker.state == apfsaccess::rw::WriteAheadLog::RecordState::Accepted &&
                accepted_marker.sequence == first_accepted_sequence,
            "Accepted transaction should end with a durable accepted marker");
    }

    ok &= Require(
        !accepted_tx.MarkCleanedThrough(first_accepted_sequence),
        "Cleanup watermark must not advance before APFS durability");
    ok &= Require(
        !accepted_tx.MarkApfsDurableThrough(first_accepted_sequence + 1),
        "APFS durability watermark must not advance beyond accepted work");
    ok &= Require(
        !accepted_tx.MarkApfsDurableThrough(first_accepted_sequence - 1),
        "APFS durability watermark must target an accepted transaction boundary");
    ok &= Require(
        accepted_tx.MarkApfsDurableThrough(first_accepted_sequence),
        "APFS durability watermark should advance through accepted work");
    ok &= Require(
        !accepted_tx.MarkCleanedThrough(first_accepted_sequence - 1),
        "Cleanup watermark must target an accepted transaction boundary");
    ok &= Require(
        accepted_tx.MarkCleanedThrough(first_accepted_sequence),
        "Cleanup watermark should advance through APFS-durable work");

    ok &= Require(accepted_tx.Begin(), "A second foreground transaction should begin after acceptance");
    payload_mutation.path = L"\\accepted-2.bin";
    payload_mutation.payload_spool_offset = 23456;
    ok &= Require(accepted_tx.RecordMutation(payload_mutation), "Second accepted transaction should record payload mutation");
    ok &= Require(accepted_tx.Accept(), "Second transaction should become durably accepted");
    const auto second_accepted_sequence = accepted_tx.Watermarks().accepted_sequence;
    ok &= Require(
        second_accepted_sequence > first_accepted_sequence &&
            accepted_tx.HasUnappliedAcceptedWork(),
        "A later accepted batch should remain distinguishable from the APFS-durable watermark");

    apfsaccess::rw::TransactionManager recovered_tx(L"DeferredContent");
    recovered_tx.SetVolumeIdentity(L"accepted-test-volume");
    recovered_tx.SetJournalPath(acceptance_journal_path.wstring());
    ok &= Require(recovered_tx.RecoveryStateValid(), "Restart should reconstruct a valid watermark state");
    ok &= Require(
        recovered_tx.Watermarks().accepted_sequence == second_accepted_sequence &&
            recovered_tx.Watermarks().apfs_durable_sequence == first_accepted_sequence &&
            recovered_tx.Watermarks().cleanup_sequence == first_accepted_sequence,
        "Restart should reconstruct accepted, APFS-durable, and cleanup watermarks independently");
    ok &= Require(
        recovered_tx.NextMutationSequence() > second_accepted_sequence,
        "Restart should seed later WAL writes after acceptance and watermark records");

    std::vector<apfsaccess::rw::TransactionManager::AcceptedTransaction> replay_transactions;
    std::string replay_failure;
    ok &= Require(
        recovered_tx.LoadUnappliedAcceptedTransactions(replay_transactions, &replay_failure),
        "Restart should reconstruct complete unapplied accepted transactions");
    ok &= Require(replay_failure.empty(), "Valid accepted transaction reconstruction should not report a failure");
    ok &= Require(replay_transactions.size() == 1, "Only the transaction beyond the APFS-durable watermark should require replay");
    if (replay_transactions.size() == 1)
    {
        ok &= Require(
            replay_transactions[0].accepted_sequence == second_accepted_sequence &&
                replay_transactions[0].mutations.size() == 1 &&
                replay_transactions[0].mutations[0].path_utf8.find("accepted-2.bin") != std::string::npos,
            "Replay reconstruction should bind the accepted marker to its complete prepared mutation set");
    }

    apfsaccess::rw::WriteAheadLog compacted_wal({
        acceptance_journal_path,
        "accepted-test-volume",
        1024 * 1024,
    });
    ok &= Require(
        compacted_wal.Compact(first_accepted_sequence),
        "Accepted WAL fixture should compact cleaned mutations while retaining their transaction boundary");
    apfsaccess::rw::TransactionManager compacted_tx(L"DeferredContent");
    compacted_tx.SetVolumeIdentity(L"accepted-test-volume");
    compacted_tx.SetJournalPath(acceptance_journal_path.wstring());
    ok &= Require(
        compacted_tx.RecoveryStateValid(),
        "Compaction metadata must preserve valid accepted-write watermark recovery");
    replay_transactions.clear();
    replay_failure.clear();
    ok &= Require(
        compacted_tx.LoadUnappliedAcceptedTransactions(replay_transactions, &replay_failure),
        "Compaction metadata must not be interpreted as an out-of-order mutation") &&
        Require(replay_transactions.size() == 1, "Compacted WAL should retain the unapplied accepted transaction") &&
        Require(
            replay_transactions.empty() || replay_transactions[0].accepted_sequence == second_accepted_sequence,
            "Compacted WAL replay should preserve the accepted transaction boundary");

    constexpr std::uint64_t wal_flag_committed = 0x1;
    constexpr std::uint64_t wal_flag_accepted = 0x8;
    const auto invalid_boundary_path = run_root / "invalid-boundary.wal";
    apfsaccess::rw::WriteAheadLog invalid_boundary_wal({
        invalid_boundary_path,
        "invalid-boundary-volume",
        1024 * 1024,
    });
    apfsaccess::rw::WriteAheadLog::Record invalid_mutation{};
    invalid_mutation.volume_identity = "invalid-boundary-volume";
    invalid_mutation.transaction_id = 1;
    invalid_mutation.sequence = 1;
    invalid_mutation.operation = apfsaccess::rw::WriteAheadLog::OperationKind::Write;
    invalid_mutation.state = apfsaccess::rw::WriteAheadLog::RecordState::Prepared;
    apfsaccess::rw::WriteAheadLog::Record invalid_marker{};
    invalid_marker.volume_identity = "invalid-boundary-volume";
    invalid_marker.transaction_id = 1;
    invalid_marker.sequence = 2;
    invalid_marker.operation = apfsaccess::rw::WriteAheadLog::OperationKind::TransactionMarker;
    invalid_marker.state = apfsaccess::rw::WriteAheadLog::RecordState::Accepted;
    invalid_marker.flags = wal_flag_accepted;
    invalid_marker.logical_length = 1;
    apfsaccess::rw::WriteAheadLog::Record invalid_watermark{};
    invalid_watermark.volume_identity = "invalid-boundary-volume";
    invalid_watermark.sequence = 3;
    invalid_watermark.operation = apfsaccess::rw::WriteAheadLog::OperationKind::DurabilityWatermark;
    invalid_watermark.state = apfsaccess::rw::WriteAheadLog::RecordState::Checkpointed;
    invalid_watermark.logical_offset = invalid_mutation.sequence;
    ok &= Require(
        invalid_boundary_wal.AppendBatch({invalid_mutation, invalid_marker, invalid_watermark}),
        "Invalid boundary fixture should persist a checksum-valid WAL");
    apfsaccess::rw::TransactionManager invalid_boundary_tx(L"DeferredContent");
    invalid_boundary_tx.SetVolumeIdentity(L"invalid-boundary-volume");
    invalid_boundary_tx.SetJournalPath(invalid_boundary_path.wstring());
    ok &= Require(
        !invalid_boundary_tx.RecoveryStateValid(),
        "Restart must reject a durability watermark inside an accepted transaction");

    const auto incomplete_path = run_root / "incomplete-accepted.wal";
    apfsaccess::rw::WriteAheadLog incomplete_wal({incomplete_path, "incomplete-volume", 1024 * 1024});
    apfsaccess::rw::WriteAheadLog::Record incomplete_mutation{};
    incomplete_mutation.volume_identity = "incomplete-volume";
    incomplete_mutation.transaction_id = 1;
    incomplete_mutation.sequence = 1;
    incomplete_mutation.operation = apfsaccess::rw::WriteAheadLog::OperationKind::Write;
    incomplete_mutation.state = apfsaccess::rw::WriteAheadLog::RecordState::Prepared;
    apfsaccess::rw::WriteAheadLog::Record incomplete_marker{};
    incomplete_marker.volume_identity = "incomplete-volume";
    incomplete_marker.transaction_id = 1;
    incomplete_marker.sequence = 2;
    incomplete_marker.operation = apfsaccess::rw::WriteAheadLog::OperationKind::TransactionMarker;
    incomplete_marker.state = apfsaccess::rw::WriteAheadLog::RecordState::Accepted;
    incomplete_marker.flags = wal_flag_accepted;
    incomplete_marker.logical_length = 2;
    ok &= Require(
        incomplete_wal.AppendBatch({incomplete_mutation, incomplete_marker}),
        "Incomplete accepted transaction fixture should persist a checksum-valid WAL");
    apfsaccess::rw::TransactionManager incomplete_tx(L"DeferredContent");
    incomplete_tx.SetVolumeIdentity(L"incomplete-volume");
    incomplete_tx.SetJournalPath(incomplete_path.wstring());
    replay_transactions.clear();
    replay_failure.clear();
    ok &= Require(
        !incomplete_tx.LoadUnappliedAcceptedTransactions(replay_transactions, &replay_failure),
        "Accepted marker with a missing mutation must fail closed") &&
        Require(!replay_failure.empty(), "Incomplete accepted transaction should report a replay validation reason");

    const auto make_prepared = [](
        const std::string& identity,
        std::uint64_t transaction_id,
        std::uint64_t sequence)
    {
        apfsaccess::rw::WriteAheadLog::Record record{};
        record.volume_identity = identity;
        record.transaction_id = transaction_id;
        record.sequence = sequence;
        record.operation = apfsaccess::rw::WriteAheadLog::OperationKind::Write;
        record.state = apfsaccess::rw::WriteAheadLog::RecordState::Prepared;
        return record;
    };
    const auto make_marker = [](
        const std::string& identity,
        std::uint64_t transaction_id,
        std::uint64_t sequence,
        apfsaccess::rw::WriteAheadLog::RecordState state,
        std::uint64_t flags,
        std::uint64_t mutation_count)
    {
        apfsaccess::rw::WriteAheadLog::Record record{};
        record.volume_identity = identity;
        record.transaction_id = transaction_id;
        record.sequence = sequence;
        record.operation = apfsaccess::rw::WriteAheadLog::OperationKind::TransactionMarker;
        record.state = state;
        record.flags = flags;
        record.logical_length = mutation_count;
        return record;
    };
    const auto make_watermark = [](
        const std::string& identity,
        std::uint64_t sequence,
        apfsaccess::rw::WriteAheadLog::RecordState state,
        std::uint64_t target_sequence)
    {
        apfsaccess::rw::WriteAheadLog::Record record{};
        record.volume_identity = identity;
        record.sequence = sequence;
        record.operation = apfsaccess::rw::WriteAheadLog::OperationKind::DurabilityWatermark;
        record.state = state;
        record.logical_offset = target_sequence;
        return record;
    };

    const auto require_rejected_wal = [&](
        const std::string& fixture_name,
        const std::string& identity,
        const std::vector<apfsaccess::rw::WriteAheadLog::Record>& records,
        const std::string& rejection_reason)
    {
        const auto path = run_root / (fixture_name + ".wal");
        apfsaccess::rw::WriteAheadLog wal({path, identity, 1024 * 1024});
        if (!Require(wal.AppendBatch(records), fixture_name + " should persist a checksum-valid WAL"))
        {
            return false;
        }

        apfsaccess::rw::TransactionManager recovered(L"DeferredContent");
        recovered.SetVolumeIdentity(std::wstring(identity.begin(), identity.end()));
        recovered.SetJournalPath(path.wstring());
        return Require(!recovered.RecoveryStateValid(), rejection_reason);
    };

    auto unknown_operation = make_prepared("unknown-operation-volume", 1, 1);
    unknown_operation.operation = static_cast<apfsaccess::rw::WriteAheadLog::OperationKind>(99);
    ok &= require_rejected_wal(
        "unknown-operation",
        "unknown-operation-volume",
        {
            unknown_operation,
            make_marker(
                "unknown-operation-volume",
                1,
                2,
                apfsaccess::rw::WriteAheadLog::RecordState::Accepted,
                wal_flag_accepted,
                1),
        },
        "Startup must reject an unsupported prepared WAL operation");

    auto overlapping_first = make_prepared("overlapping-transactions-volume", 1, 1);
    auto overlapping_second = make_prepared("overlapping-transactions-volume", 2, 2);
    overlapping_first.object_id = 77;
    overlapping_second.object_id = 77;
    ok &= require_rejected_wal(
        "overlapping-transactions",
        "overlapping-transactions-volume",
        {
            overlapping_first,
            overlapping_second,
            make_marker(
                "overlapping-transactions-volume",
                2,
                3,
                apfsaccess::rw::WriteAheadLog::RecordState::Accepted,
                wal_flag_accepted,
                1),
            make_marker(
                "overlapping-transactions-volume",
                1,
                4,
                apfsaccess::rw::WriteAheadLog::RecordState::Accepted,
                wal_flag_accepted,
                1),
        },
        "Startup must reject interleaved transactions that reverse same-object replay order");

    constexpr auto exhausted = (std::numeric_limits<std::uint64_t>::max)();
    ok &= require_rejected_wal(
        "exhausted-transaction-id",
        "exhausted-transaction-id-volume",
        {
            make_prepared("exhausted-transaction-id-volume", exhausted, 1),
            make_marker(
                "exhausted-transaction-id-volume",
                exhausted,
                2,
                apfsaccess::rw::WriteAheadLog::RecordState::Accepted,
                wal_flag_accepted,
                1),
        },
        "Startup must reject a WAL transaction id that would wrap recovery seeding");
    ok &= require_rejected_wal(
        "exhausted-sequence",
        "exhausted-sequence-volume",
        {
            make_prepared("exhausted-sequence-volume", 1, exhausted - 1),
            make_marker(
                "exhausted-sequence-volume",
                1,
                exhausted,
                apfsaccess::rw::WriteAheadLog::RecordState::Accepted,
                wal_flag_accepted,
                1),
        },
        "Startup must reject a WAL sequence that would wrap recovery seeding");

    apfsaccess::rw::WriteAheadLog::Record forged_compaction{};
    forged_compaction.volume_identity = "forged-compaction-volume";
    forged_compaction.sequence = 5;
    forged_compaction.operation = apfsaccess::rw::WriteAheadLog::OperationKind::CompactionIndex;
    forged_compaction.state = apfsaccess::rw::WriteAheadLog::RecordState::Cleaned;
    ok &= require_rejected_wal(
        "forged-compaction",
        "forged-compaction-volume",
        {
            make_prepared("forged-compaction-volume", 1, 1),
            make_marker(
                "forged-compaction-volume",
                1,
                5,
                apfsaccess::rw::WriteAheadLog::RecordState::Accepted,
                wal_flag_accepted,
                2),
            make_watermark(
                "forged-compaction-volume",
                6,
                apfsaccess::rw::WriteAheadLog::RecordState::Checkpointed,
                5),
            make_watermark(
                "forged-compaction-volume",
                7,
                apfsaccess::rw::WriteAheadLog::RecordState::Cleaned,
                5),
            forged_compaction,
        },
        "Startup must reject ordinary WAL records below the declared compaction floor");

    const auto duplicate_terminal_path = run_root / "all-clean-duplicate-terminal.wal";
    const std::string duplicate_terminal_identity = "all-clean-duplicate-terminal-volume";
    apfsaccess::rw::WriteAheadLog duplicate_terminal_wal({
        duplicate_terminal_path,
        duplicate_terminal_identity,
        1024 * 1024,
    });
    ok &= Require(
        duplicate_terminal_wal.AppendBatch({
            make_prepared(duplicate_terminal_identity, 1, 1),
            make_marker(
                duplicate_terminal_identity,
                1,
                2,
                apfsaccess::rw::WriteAheadLog::RecordState::Accepted,
                wal_flag_accepted,
                1),
            make_marker(
                duplicate_terminal_identity,
                1,
                3,
                apfsaccess::rw::WriteAheadLog::RecordState::Accepted,
                wal_flag_accepted,
                1),
            make_watermark(
                duplicate_terminal_identity,
                4,
                apfsaccess::rw::WriteAheadLog::RecordState::Checkpointed,
                3),
            make_watermark(
                duplicate_terminal_identity,
                5,
                apfsaccess::rw::WriteAheadLog::RecordState::Cleaned,
                3),
        }),
        "Duplicate-terminal fixture should persist a checksum-valid all-clean WAL");
    apfsaccess::rw::TransactionManager duplicate_terminal_tx(L"DeferredContent");
    duplicate_terminal_tx.SetVolumeIdentity(L"all-clean-duplicate-terminal-volume");
    duplicate_terminal_tx.SetJournalPath(duplicate_terminal_path.wstring());
    ok &= Require(
        !duplicate_terminal_tx.RecoveryStateValid(),
        "Startup must reject an all-clean WAL with duplicate terminal markers");

    const auto accepted_count_path = run_root / "all-clean-accepted-count.wal";
    const std::string accepted_count_identity = "all-clean-accepted-count-volume";
    apfsaccess::rw::WriteAheadLog accepted_count_wal({
        accepted_count_path,
        accepted_count_identity,
        1024 * 1024,
    });
    ok &= Require(
        accepted_count_wal.AppendBatch({
            make_prepared(accepted_count_identity, 1, 1),
            make_marker(
                accepted_count_identity,
                1,
                2,
                apfsaccess::rw::WriteAheadLog::RecordState::Accepted,
                wal_flag_accepted,
                2),
            make_watermark(
                accepted_count_identity,
                3,
                apfsaccess::rw::WriteAheadLog::RecordState::Checkpointed,
                2),
            make_watermark(
                accepted_count_identity,
                4,
                apfsaccess::rw::WriteAheadLog::RecordState::Cleaned,
                2),
        }),
        "Accepted-count fixture should persist a checksum-valid all-clean WAL");
    apfsaccess::rw::TransactionManager accepted_count_tx(L"DeferredContent");
    accepted_count_tx.SetVolumeIdentity(L"all-clean-accepted-count-volume");
    accepted_count_tx.SetJournalPath(accepted_count_path.wstring());
    ok &= Require(
        !accepted_count_tx.RecoveryStateValid(),
        "Startup must reject an all-clean accepted marker with a mismatched prepared count");

    const auto committed_count_path = run_root / "all-clean-committed-count.wal";
    const std::string committed_count_identity = "all-clean-committed-count-volume";
    apfsaccess::rw::WriteAheadLog committed_count_wal({
        committed_count_path,
        committed_count_identity,
        1024 * 1024,
    });
    ok &= Require(
        committed_count_wal.AppendBatch({
            make_prepared(committed_count_identity, 1, 1),
            make_marker(
                committed_count_identity,
                1,
                2,
                apfsaccess::rw::WriteAheadLog::RecordState::Checkpointed,
                wal_flag_committed,
                2),
            make_watermark(
                committed_count_identity,
                3,
                apfsaccess::rw::WriteAheadLog::RecordState::Cleaned,
                2),
        }),
        "Committed-count fixture should persist a checksum-valid all-clean WAL");
    apfsaccess::rw::TransactionManager committed_count_tx(L"Conservative");
    committed_count_tx.SetVolumeIdentity(L"all-clean-committed-count-volume");
    committed_count_tx.SetJournalPath(committed_count_path.wstring());
    ok &= Require(
        !committed_count_tx.RecoveryStateValid(),
        "Startup must reject an all-clean committed marker with a mismatched prepared count");

    const auto out_of_order_path = run_root / "all-clean-out-of-order.wal";
    const std::string out_of_order_identity = "all-clean-out-of-order-volume";
    apfsaccess::rw::WriteAheadLog out_of_order_wal({
        out_of_order_path,
        out_of_order_identity,
        1024 * 1024,
    });
    ok &= Require(
        out_of_order_wal.AppendBatch({
            make_prepared(out_of_order_identity, 1, 2),
            make_marker(
                out_of_order_identity,
                1,
                1,
                apfsaccess::rw::WriteAheadLog::RecordState::Accepted,
                wal_flag_accepted,
                1),
            make_watermark(
                out_of_order_identity,
                3,
                apfsaccess::rw::WriteAheadLog::RecordState::Checkpointed,
                1),
            make_watermark(
                out_of_order_identity,
                4,
                apfsaccess::rw::WriteAheadLog::RecordState::Cleaned,
                1),
        }),
        "Ordering fixture should persist a checksum-valid all-clean WAL");
    apfsaccess::rw::TransactionManager out_of_order_tx(L"DeferredContent");
    out_of_order_tx.SetVolumeIdentity(L"all-clean-out-of-order-volume");
    out_of_order_tx.SetJournalPath(out_of_order_path.wstring());
    ok &= Require(
        !out_of_order_tx.RecoveryStateValid(),
        "Startup must reject an all-clean WAL with out-of-order sequences");

    const auto invalid_flags_path = run_root / "all-clean-invalid-flags.wal";
    const std::string invalid_flags_identity = "all-clean-invalid-flags-volume";
    apfsaccess::rw::WriteAheadLog invalid_flags_wal({
        invalid_flags_path,
        invalid_flags_identity,
        1024 * 1024,
    });
    ok &= Require(
        invalid_flags_wal.AppendBatch({
            make_prepared(invalid_flags_identity, 1, 1),
            make_marker(
                invalid_flags_identity,
                1,
                2,
                apfsaccess::rw::WriteAheadLog::RecordState::Accepted,
                wal_flag_committed,
                1),
            make_watermark(
                invalid_flags_identity,
                3,
                apfsaccess::rw::WriteAheadLog::RecordState::Checkpointed,
                2),
            make_watermark(
                invalid_flags_identity,
                4,
                apfsaccess::rw::WriteAheadLog::RecordState::Cleaned,
                2),
        }),
        "Invalid-flags fixture should persist a checksum-valid all-clean WAL");
    apfsaccess::rw::TransactionManager invalid_flags_tx(L"DeferredContent");
    invalid_flags_tx.SetVolumeIdentity(L"all-clean-invalid-flags-volume");
    invalid_flags_tx.SetJournalPath(invalid_flags_path.wstring());
    ok &= Require(
        !invalid_flags_tx.RecoveryStateValid(),
        "Startup must reject an all-clean accepted marker with invalid flags");
    ok &= Require(
        invalid_flags_tx.JournalAppendHandleOpenCount() == 1,
        "A live degraded owner must retain its opened writer handle and quarantine semantic-invalid WAL evidence");

    const auto unterminated_path = run_root / "unterminated-transaction.wal";
    const std::string unterminated_identity = "unterminated-transaction-volume";
    apfsaccess::rw::WriteAheadLog unterminated_wal({
        unterminated_path,
        unterminated_identity,
        1024 * 1024,
    });
    ok &= Require(
        unterminated_wal.Append(make_prepared(unterminated_identity, 1, 1)),
        "Unterminated transaction fixture should persist a checksum-valid prepared record");
    apfsaccess::rw::TransactionManager unterminated_tx(L"DeferredContent");
    unterminated_tx.SetVolumeIdentity(L"unterminated-transaction-volume");
    unterminated_tx.SetJournalPath(unterminated_path.wstring());
    ok &= Require(
        !unterminated_tx.RecoveryStateValid(),
        "Startup must reject a WAL suffix with prepared records but no terminal marker");

    const auto ambiguous_path = run_root / "ambiguous-accept.wal";
    apfsaccess::rw::TransactionManager ambiguous_tx(L"DeferredContent");
    ambiguous_tx.SetVolumeIdentity(L"ambiguous-accept-volume");
    ambiguous_tx.SetJournalPath(ambiguous_path.wstring());
    ambiguous_tx.SetJournalFaultInjectionHook([](std::string_view stage)
    {
        return stage == "durable-flush";
    });
    apfsaccess::rw::TransactionManager::MutationIntent ambiguous_mutation{};
    ambiguous_mutation.kind = apfsaccess::rw::TransactionManager::MutationKind::Write;
    ambiguous_mutation.path = L"\\ambiguous.bin";
    ambiguous_mutation.length = 4;
    ok &= Require(ambiguous_tx.Begin(), "Ambiguous acceptance transaction should begin");
    ok &= Require(ambiguous_tx.RecordMutation(ambiguous_mutation), "Ambiguous acceptance transaction should buffer mutation");
    ok &= Require(!ambiguous_tx.Accept(), "Ambiguous acceptance must fail closed");
    ok &= Require(
        ambiguous_tx.CurrentState() == apfsaccess::rw::TransactionManager::State::Failed,
        "Ambiguous acceptance must leave the transaction manager failed");
    ok &= Require(
        ambiguous_tx.Watermarks().accepted_sequence == 0,
        "Ambiguous acceptance must not publish an accepted watermark");
    const auto ambiguous_read = apfsaccess::rw::WriteAheadLog::ReadAll(
        ambiguous_path,
        "ambiguous-accept-volume");
    ok &= Require(
        ambiguous_read.status == apfsaccess::rw::WriteAheadLog::ReadStatus::Ok &&
            ambiguous_read.records.size() == 2,
        "Ambiguous acceptance must retain the prepared record and terminal evidence");
    ok &= Require(
        std::none_of(
            ambiguous_read.records.begin(),
            ambiguous_read.records.end(),
            [](const auto& record)
            {
                return record.operation == apfsaccess::rw::WriteAheadLog::OperationKind::CompactionIndex;
            }),
        "Ambiguous acceptance must not compact before retrying the append");
    ok &= Require(
        ambiguous_tx.JournalAppendHandleOpenCount() == 1,
        "Ambiguous acceptance must not reopen the WAL for an unsafe retry");

    const auto empty_commit_path = run_root / "empty-committed.wal";
    apfsaccess::rw::TransactionManager empty_commit_tx(L"Conservative");
    empty_commit_tx.SetVolumeIdentity(L"empty-committed-volume");
    empty_commit_tx.SetJournalPath(empty_commit_path.wstring());
    ok &= Require(empty_commit_tx.Begin(), "Empty transaction should begin");
    ok &= Require(empty_commit_tx.Commit(), "Empty committed transaction should remain valid");
    apfsaccess::rw::TransactionManager empty_commit_recovery(L"Conservative");
    empty_commit_recovery.SetVolumeIdentity(L"empty-committed-volume");
    empty_commit_recovery.SetJournalPath(empty_commit_path.wstring());
    ok &= Require(
        empty_commit_recovery.RecoveryStateValid(),
        "Startup should preserve valid zero-mutation checkpointed transactions");

    std::filesystem::remove_all(run_root, ec);
    if (!ok)
    {
        return 1;
    }

    std::cout << "[PASS] TransactionManagerTests" << std::endl;
    return 0;
}
