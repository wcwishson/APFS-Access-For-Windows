#include "TransactionManager.h"

#include "WriteAheadLog.h"

#include <algorithm>
#include <chrono>
#include <cwchar>
#include <filesystem>
#include <limits>
#include <unordered_map>
#include <unordered_set>
#include <thread>
#include <utility>
#include <windows.h>
#ifdef CreateFile
#undef CreateFile
#endif
#ifdef CreateDirectory
#undef CreateDirectory
#endif

namespace apfsaccess::rw
{
namespace
{
constexpr std::uint64_t kWalFlagCommitted = 0x1;
constexpr std::uint64_t kWalFlagAborted = 0x2;
constexpr std::uint64_t kWalFlagReplaceIfExists = 0x4;
constexpr std::uint64_t kWalFlagAccepted = 0x8;
constexpr auto kDeferredWalGroupCommitWindow = std::chrono::milliseconds(8);
std::uint64_t ElapsedMicroseconds(const std::chrono::steady_clock::time_point& started)
{
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - started).count());
}

std::string EffectiveVolumeIdentity(const std::wstring& volume_identity)
{
    auto identity = volume_identity.empty()
        ? std::string("default")
        : TransactionManager::WideToUtf8(volume_identity);
    return identity.empty() ? std::string("default") : identity;
}

WriteAheadLog::OperationKind ToWalOperation(TransactionManager::MutationKind kind)
{
    switch (kind)
    {
    case TransactionManager::MutationKind::CreateFile:
        return WriteAheadLog::OperationKind::CreateFile;
    case TransactionManager::MutationKind::CreateDirectory:
        return WriteAheadLog::OperationKind::CreateDirectory;
    case TransactionManager::MutationKind::Write:
        return WriteAheadLog::OperationKind::Write;
    case TransactionManager::MutationKind::SetFileSize:
        return WriteAheadLog::OperationKind::SetFileSize;
    case TransactionManager::MutationKind::Rename:
        return WriteAheadLog::OperationKind::Rename;
    case TransactionManager::MutationKind::Delete:
        return WriteAheadLog::OperationKind::Delete;
    case TransactionManager::MutationKind::SetBasicInfo:
        return WriteAheadLog::OperationKind::SetBasicInfo;
    default:
        return WriteAheadLog::OperationKind::TransactionMarker;
    }
}

bool IsTransactionMarkerWithState(
    const WriteAheadLog::Record& record,
    WriteAheadLog::RecordState state,
    std::uint64_t flags)
{
    return record.state == state && record.flags == flags;
}

bool IsMutationOperation(WriteAheadLog::OperationKind operation)
{
    switch (operation)
    {
    case WriteAheadLog::OperationKind::CreateFile:
    case WriteAheadLog::OperationKind::CreateDirectory:
    case WriteAheadLog::OperationKind::Write:
    case WriteAheadLog::OperationKind::SetFileSize:
    case WriteAheadLog::OperationKind::Rename:
    case WriteAheadLog::OperationKind::Delete:
    case WriteAheadLog::OperationKind::SetBasicInfo:
        return true;
    default:
        return false;
    }
}

bool RequiresPayloadSpoolFlushForRecovery(const std::vector<WriteAheadLog::Record>& records)
{
    return std::any_of(
        records.begin(),
        records.end(),
        [](const WriteAheadLog::Record& record)
        {
            return record.operation == WriteAheadLog::OperationKind::Write &&
                   (record.inline_payload.empty() ||
                    !WriteAheadLog::InlinePayloadIsConsistent(record));
        });
}

bool ValidateWalSemantics(const std::vector<WriteAheadLog::Record>& records)
{
    constexpr auto exhausted = (std::numeric_limits<std::uint64_t>::max)();
    std::unordered_map<std::uint64_t, std::size_t> prepared_counts;
    std::unordered_set<std::uint64_t> terminal_transactions;
    std::uint64_t previous_sequence = 0;
    std::uint64_t compaction_floor = 0;
    std::uint64_t active_transaction_id = 0;

    for (const auto& record : records)
    {
        if (record.operation != WriteAheadLog::OperationKind::CompactionIndex)
        {
            continue;
        }
        if (record.transaction_id != 0 ||
            record.sequence == 0 ||
            record.sequence == exhausted ||
            record.state != WriteAheadLog::RecordState::Cleaned ||
            record.flags != 0)
        {
            return false;
        }
        compaction_floor = (std::max)(compaction_floor, record.sequence);
    }

    for (const auto& record : records)
    {
        if (record.operation == WriteAheadLog::OperationKind::CompactionIndex)
        {
            continue;
        }

        if (record.sequence == 0 ||
            record.sequence == exhausted ||
            record.sequence < compaction_floor ||
            record.sequence <= previous_sequence)
        {
            return false;
        }
        previous_sequence = record.sequence;

        if (record.operation == WriteAheadLog::OperationKind::TransactionMarker)
        {
            if (record.transaction_id == 0 ||
                record.transaction_id == exhausted ||
                (active_transaction_id != 0 && active_transaction_id != record.transaction_id) ||
                !terminal_transactions.insert(record.transaction_id).second)
            {
                return false;
            }

            const bool accepted = IsTransactionMarkerWithState(
                record,
                WriteAheadLog::RecordState::Accepted,
                kWalFlagAccepted);
            const bool committed = IsTransactionMarkerWithState(
                record,
                WriteAheadLog::RecordState::Checkpointed,
                kWalFlagCommitted);
            const bool aborted = IsTransactionMarkerWithState(
                record,
                WriteAheadLog::RecordState::Cleaned,
                kWalFlagAborted);
            if (!accepted && !committed && !aborted)
            {
                return false;
            }

            if (accepted || committed)
            {
                const auto prepared = prepared_counts.find(record.transaction_id);
                const bool compacted_before_this_boundary = record.sequence == compaction_floor;
                if (!compacted_before_this_boundary)
                {
                    if (prepared == prepared_counts.end())
                    {
                        if (!committed || record.logical_length != 0)
                        {
                            return false;
                        }
                    }
                    else if (prepared->second != record.logical_length)
                    {
                        return false;
                    }
                }
            }

            prepared_counts.erase(record.transaction_id);
            if (active_transaction_id == record.transaction_id)
            {
                active_transaction_id = 0;
            }
            continue;
        }

        if (record.operation == WriteAheadLog::OperationKind::DurabilityWatermark)
        {
            if (record.transaction_id != 0 ||
                active_transaction_id != 0 ||
                record.flags != 0 ||
                record.logical_offset == 0 ||
                (record.state != WriteAheadLog::RecordState::Checkpointed &&
                 record.state != WriteAheadLog::RecordState::Cleaned))
            {
                return false;
            }
            continue;
        }

        if (!IsMutationOperation(record.operation) ||
            record.state != WriteAheadLog::RecordState::Prepared ||
            record.transaction_id == 0 ||
            record.transaction_id == exhausted ||
            (active_transaction_id != 0 && active_transaction_id != record.transaction_id) ||
            terminal_transactions.contains(record.transaction_id))
        {
            return false;
        }
        active_transaction_id = record.transaction_id;
        ++prepared_counts[record.transaction_id];
    }

    return active_transaction_id == 0 && prepared_counts.empty();
}
}

TransactionManager::TransactionManager(std::wstring safety_level)
    : safety_level_(std::move(safety_level)),
      journal_(WriteAheadLog::Options{})
{
}

TransactionManager::State TransactionManager::CurrentState() const noexcept
{
    return state_;
}

bool TransactionManager::Begin()
{
    if (!recovery_state_valid_ ||
        state_ != State::Idle ||
        next_transaction_id_ == 0 ||
        next_transaction_id_ == (std::numeric_limits<std::uint64_t>::max)())
    {
        return false;
    }

    if (!journal_path_.empty() && !JournalStateMatchesWriterLease())
    {
        if (!SeedIdsFromExistingJournal(true) ||
            !recovery_state_valid_ ||
            !JournalStateMatchesWriterLease())
        {
            return false;
        }
    }

    current_transaction_id_ = next_transaction_id_++;
    pending_mutations_.clear();
    ClearBufferedPreparedRecords();
    current_transaction_requires_payload_spool_flush_ = false;
    state_ = State::Active;
    NotifyStage("begin");
    return true;
}

bool TransactionManager::Commit()
{
    if (!recovery_state_valid_ || state_ != State::Active)
    {
        return false;
    }

    state_ = State::Committing;
    NotifyStage("commit-start");
    NotifyStage("prepare");
    NotifyStage("write-data");
    NotifyStage("write-metadata");
    if (!PersistTransactionBatchLocked(L"committed"))
    {
        state_ = State::Failed;
        NotifyStage("commit-failed");
        return false;
    }
    NotifyStage("flush-data");
    NotifyStage("switch-checkpoint");
    NotifyStage("finalize");
    NotifyStage("commit-finish");
    pending_mutations_.clear();
    ClearBufferedPreparedRecords();
    current_transaction_requires_payload_spool_flush_ = false;
    current_transaction_id_ = 0;
    state_ = State::Idle;
    return true;
}

bool TransactionManager::Accept()
{
    if (!recovery_state_valid_ || state_ != State::Active || pending_mutations_.empty())
    {
        return false;
    }

    state_ = State::Committing;
    NotifyStage("accept-start");
    if (!PersistTransactionBatchLocked(L"accepted"))
    {
        state_ = State::Failed;
        NotifyStage("accept-failed");
        return false;
    }

    NotifyStage("accept-finish");
    pending_mutations_.clear();
    ClearBufferedPreparedRecords();
    current_transaction_requires_payload_spool_flush_ = false;
    current_transaction_id_ = 0;
    state_ = State::Idle;
    return true;
}

bool TransactionManager::AcceptForDeferredCommit(std::uint64_t* accepted_sequence)
{
    if (accepted_sequence)
    {
        *accepted_sequence = 0;
    }
    if (!recovery_state_valid_ || state_ != State::Active || pending_mutations_.empty())
    {
        return false;
    }

    state_ = State::Committing;
    NotifyStage("accept-start");
    if (!PersistTransactionBatchLocked(L"accepted", false))
    {
        state_ = State::Failed;
        NotifyStage("accept-failed");
        return false;
    }

    const auto accepted = watermarks_.accepted_sequence;
    pending_mutations_.clear();
    ClearBufferedPreparedRecords();
    current_transaction_requires_payload_spool_flush_ = false;
    current_transaction_id_ = 0;
    state_ = State::Idle;
    {
        std::lock_guard<std::mutex> lock(deferred_wal_state_mutex_);
        deferred_wal_pending_sequence_ =
            (std::max)(deferred_wal_pending_sequence_, accepted);
    }
    deferred_wal_state_cv_.notify_all();
    if (accepted_sequence)
    {
        *accepted_sequence = accepted;
    }
    NotifyStage("accept-finish");
    return true;
}

bool TransactionManager::WaitForDeferredAcceptanceDurability(std::uint64_t accepted_sequence)
{
    return EnsureDeferredAcceptanceDurability(accepted_sequence, true);
}

bool TransactionManager::FlushDeferredAcceptanceDurabilityNow(std::uint64_t accepted_sequence)
{
    return EnsureDeferredAcceptanceDurability(accepted_sequence, false);
}

void TransactionManager::MarkDeferredAcceptanceDurabilityFailure() noexcept
{
    {
        std::lock_guard<std::mutex> lock(deferred_wal_state_mutex_);
        deferred_wal_flush_failed_ = true;
        deferred_wal_flush_in_progress_ = false;
    }
    deferred_wal_state_cv_.notify_all();
    recovery_state_valid_ = false;
    journal_append_ambiguous_ = true;
    journal_state_writer_generation_ = 0;
    InvalidateFinalizationCoverage(true);
    state_ = State::Failed;
}

bool TransactionManager::EnsureDeferredAcceptanceDurability(
    std::uint64_t accepted_sequence,
    bool coalesce)
{
    if (accepted_sequence == 0 || journal_path_.empty())
    {
        return true;
    }

    for (;;)
    {
        bool become_flusher = false;
        {
            std::unique_lock<std::mutex> state_lock(deferred_wal_state_mutex_);
            if (deferred_wal_durable_sequence_ >= accepted_sequence ||
                deferred_wal_pending_sequence_ < accepted_sequence)
            {
                return true;
            }
            if (deferred_wal_flush_failed_)
            {
                return false;
            }
            if (!deferred_wal_flush_in_progress_)
            {
                deferred_wal_flush_in_progress_ = true;
                become_flusher = true;
            }
            else
            {
                deferred_wal_state_cv_.wait(state_lock, [&]()
                {
                    return deferred_wal_durable_sequence_ >= accepted_sequence ||
                           deferred_wal_flush_failed_ ||
                           !deferred_wal_flush_in_progress_;
                });
            }
        }

        if (!become_flusher)
        {
            continue;
        }

        if (coalesce)
        {
            std::this_thread::sleep_for(kDeferredWalGroupCommitWindow);
        }

        std::unique_lock<std::mutex> append_lock(deferred_wal_append_mutex_);
        std::uint64_t target_sequence = 0;
        {
            std::lock_guard<std::mutex> state_lock(deferred_wal_state_mutex_);
            target_sequence = deferred_wal_pending_sequence_;
        }

        const auto flush_started = std::chrono::steady_clock::now();
        const bool flushed = journal_.FlushPendingAppends();
        const auto flush_elapsed = ElapsedMicroseconds(flush_started);
        {
            std::lock_guard<std::mutex> state_lock(deferred_wal_state_mutex_);
            if (flushed)
            {
                deferred_wal_durable_sequence_ =
                    (std::max)(deferred_wal_durable_sequence_, target_sequence);
                ++deferred_wal_group_flush_count_;
                deferred_wal_group_flush_microseconds_ += flush_elapsed;
            }
            else
            {
                deferred_wal_flush_failed_ = true;
            }
            deferred_wal_flush_in_progress_ = false;
        }
        deferred_wal_state_cv_.notify_all();
        if (!flushed)
        {
            return false;
        }
    }
}

bool TransactionManager::CanAcceptWithoutPayloadSpoolFlush() const noexcept
{
    if (!recovery_state_valid_ ||
        state_ != State::Active ||
        pending_mutations_.empty() ||
        buffered_prepared_records_.size() != pending_mutations_.size() ||
        journal_path_.empty() ||
        volume_identity_.empty())
    {
        return false;
    }

    return !buffered_prepared_records_have_incomplete_inline_payload_;
}

bool TransactionManager::CanAddInlinePayload(std::size_t payload_bytes) const noexcept
{
    if (!recovery_state_valid_ ||
        state_ != State::Active ||
        payload_bytes == 0 ||
        payload_bytes > WriteAheadLog::MaxInlinePayloadBytes)
    {
        return false;
    }

    if (buffered_prepared_records_have_empty_write_payload_)
    {
        return false;
    }

    return payload_bytes <=
        WriteAheadLog::MaxInlinePayloadBytes - buffered_inline_payload_bytes_;
}

bool TransactionManager::CanFinalizeWithoutPayloadSpoolFlush(
    bool allow_process_local_coverage)
{
    if (!recovery_state_valid_ ||
        state_ == State::Failed ||
        state_ == State::Committing ||
        journal_path_.empty() ||
        volume_identity_.empty())
    {
        return false;
    }

    bool has_finalization_work = false;
    if (state_ == State::Active)
    {
        if (!CanAcceptWithoutPayloadSpoolFlush())
        {
            return false;
        }
        has_finalization_work = true;
    }

    const auto writer_generation = journal_.ExclusiveWriterLeaseGeneration();
    const bool trusted_process_local_coverage =
        finalization_coverage_trust_ == FinalizationCoverageTrust::Trusted &&
        writer_generation != 0 &&
        writer_generation == finalization_coverage_writer_generation_;
    if (allow_process_local_coverage && trusted_process_local_coverage)
    {
        ++finalization_coverage_cache_hit_count_;
        if (!accepted_boundaries_requiring_payload_spool_flush_.empty())
        {
            return false;
        }
        if (HasUnappliedAcceptedWork())
        {
            has_finalization_work = true;
        }
    }
    else
    {
        const auto scan_started = std::chrono::steady_clock::now();
        ++finalization_coverage_wal_scan_count_;
        std::vector<AcceptedTransaction> transactions;
        std::string failure_reason;
        const auto loaded = LoadUnappliedAcceptedTransactions(transactions, &failure_reason);
        finalization_coverage_wal_scan_microseconds_ += ElapsedMicroseconds(scan_started);
        if (!loaded)
        {
            InvalidateFinalizationCoverage(true);
            return false;
        }
        const auto validated_writer_generation = journal_.ExclusiveWriterLeaseGeneration();
        if (validated_writer_generation == 0 ||
            validated_writer_generation != journal_state_writer_generation_)
        {
            InvalidateFinalizationCoverage(true);
            return false;
        }
        for (const auto& transaction : transactions)
        {
            has_finalization_work = true;
            if (RequiresPayloadSpoolFlushForRecovery(transaction.mutations))
            {
                return false;
            }
        }
    }

    if (watermarks_.cleanup_sequence < watermarks_.apfs_durable_sequence)
    {
        has_finalization_work = true;
    }
    return has_finalization_work;
}

bool TransactionManager::Abort()
{
    if (!recovery_state_valid_)
    {
        state_ = State::Failed;
        NotifyStage("abort-failed");
        return false;
    }
    if (state_ == State::Idle)
    {
        return true;
    }

    if (journal_append_ambiguous_)
    {
        state_ = State::Failed;
        NotifyStage("abort-failed");
        return false;
    }

    state_ = State::Failed;
    NotifyStage("abort");
    if (!buffered_prepared_records_.empty())
    {
        next_sequence_ = buffered_prepared_records_.front().sequence;
    }
    ClearBufferedPreparedRecords();
    if (!PersistTransactionBatchLocked(L"aborted"))
    {
        NotifyStage("abort-failed");
        return false;
    }
    ClearBufferedPreparedRecords();
    pending_mutations_.clear();
    current_transaction_requires_payload_spool_flush_ = false;
    current_transaction_id_ = 0;
    state_ = State::Idle;
    return true;
}

bool TransactionManager::RecordMutation(const MutationIntent& mutation)
{
    if (!recovery_state_valid_ || state_ != State::Active)
    {
        return false;
    }
    if (!journal_path_.empty() && !JournalStateMatchesWriterLease())
    {
        recovery_state_valid_ = false;
        InvalidateFinalizationCoverage(true);
        return false;
    }

    auto prepared_mutation = mutation;
    if (!AppendPreparedMutationLocked(prepared_mutation))
    {
        return false;
    }

    pending_mutations_.push_back(std::move(prepared_mutation));
    NotifyStage("mutation-recorded");
    return true;
}

void TransactionManager::ClearBufferedPreparedRecords() noexcept
{
    buffered_prepared_records_.clear();
    buffered_inline_payload_bytes_ = 0;
    buffered_prepared_records_have_empty_write_payload_ = false;
    buffered_prepared_records_have_incomplete_inline_payload_ = false;
}

void TransactionManager::SetJournalPath(std::wstring journal_path)
{
    journal_path_ = std::move(journal_path);
    {
        std::lock_guard<std::mutex> lock(deferred_wal_state_mutex_);
        deferred_wal_pending_sequence_ = 0;
        deferred_wal_durable_sequence_ = 0;
        deferred_wal_flush_in_progress_ = false;
        deferred_wal_flush_failed_ = false;
    }
    ConfigureJournal();
    journal_state_writer_generation_ = 0;
    InvalidateFinalizationCoverage(false);
    if (!journal_path_.empty() && !volume_identity_.empty())
    {
        (void)SeedIdsFromExistingJournal(true);
    }
}

void TransactionManager::SetVolumeIdentity(std::wstring volume_identity)
{
    volume_identity_ = std::move(volume_identity);
    {
        std::lock_guard<std::mutex> lock(deferred_wal_state_mutex_);
        deferred_wal_pending_sequence_ = 0;
        deferred_wal_durable_sequence_ = 0;
        deferred_wal_flush_in_progress_ = false;
        deferred_wal_flush_failed_ = false;
    }
    ConfigureJournal();
    journal_state_writer_generation_ = 0;
    InvalidateFinalizationCoverage(false);
    if (!journal_path_.empty())
    {
        (void)SeedIdsFromExistingJournal(true);
    }
}

void TransactionManager::SetJournalMaxBytesForTest(std::uint64_t max_bytes)
{
    journal_max_bytes_ = max_bytes;
}

void TransactionManager::SetJournalFaultInjectionHook(WriteAheadLog::FaultInjectionHook hook)
{
    journal_.SetFaultInjectionHook(std::move(hook));
}

std::uint64_t TransactionManager::CurrentTransactionId() const noexcept
{
    return current_transaction_id_;
}

bool TransactionManager::RetainAcceptedSequenceProof(std::uint64_t transaction_id)
{
    if (transaction_id == 0 ||
        state_ != State::Active ||
        current_transaction_id_ != transaction_id)
    {
        return false;
    }

    const auto existing = accepted_transaction_sequences_.find(transaction_id);
    if (existing != accepted_transaction_sequences_.end())
    {
        if (existing->second.retain_count == (std::numeric_limits<std::size_t>::max)())
        {
            return false;
        }
        ++existing->second.retain_count;
        return true;
    }
    if (accepted_transaction_sequences_.size() >= MaxRetainedAcceptedSequenceProofs())
    {
        return false;
    }

    accepted_transaction_sequences_.emplace(
        transaction_id,
        AcceptedSequenceProof{0, 1});
    return true;
}

void TransactionManager::ReleaseAcceptedSequenceProof(std::uint64_t transaction_id) noexcept
{
    const auto existing = accepted_transaction_sequences_.find(transaction_id);
    if (existing == accepted_transaction_sequences_.end())
    {
        return;
    }
    if (existing->second.retain_count > 1)
    {
        --existing->second.retain_count;
        return;
    }
    accepted_transaction_sequences_.erase(existing);
}

std::optional<std::uint64_t> TransactionManager::AcceptedSequenceForTransaction(
    std::uint64_t transaction_id) const noexcept
{
    if (transaction_id == 0)
    {
        return std::nullopt;
    }

    const auto it = accepted_transaction_sequences_.find(transaction_id);
    if (it == accepted_transaction_sequences_.end())
    {
        return std::nullopt;
    }

    return it->second.accepted_sequence == 0
        ? std::nullopt
        : std::optional<std::uint64_t>{it->second.accepted_sequence};
}

std::size_t TransactionManager::RetainedAcceptedSequenceProofCount() const noexcept
{
    return accepted_transaction_sequences_.size();
}

std::size_t TransactionManager::TrackedAcceptedBoundaryCount() const noexcept
{
    return accepted_boundaries_.size();
}

std::uint64_t TransactionManager::NextMutationSequence() const noexcept
{
    return next_sequence_ == (std::numeric_limits<std::uint64_t>::max)()
        ? 0
        : next_sequence_;
}

std::uint64_t TransactionManager::LastCommittedSequence() const noexcept
{
    return last_committed_sequence_;
}

TransactionManager::DurabilityWatermarks TransactionManager::Watermarks() const noexcept
{
    return watermarks_;
}

bool TransactionManager::HasUnappliedAcceptedWork() const noexcept
{
    return watermarks_.accepted_sequence > watermarks_.apfs_durable_sequence;
}

bool TransactionManager::RecoveryStateValid() const noexcept
{
    return recovery_state_valid_;
}

bool TransactionManager::CanClearRecoveryState() const
{
    if (!recovery_state_valid_ || state_ != State::Idle)
    {
        return false;
    }
    if (!journal_path_.empty() && !JournalStateMatchesWriterLease())
    {
        return false;
    }
    return watermarks_.accepted_sequence <= watermarks_.apfs_durable_sequence &&
           watermarks_.apfs_durable_sequence <= watermarks_.cleanup_sequence;
}

bool TransactionManager::LoadUnappliedAcceptedTransactions(
    std::vector<AcceptedTransaction>& transactions,
    std::string* failure_reason)
{
    return LoadAcceptedTransactionsAfter(
        false,
        transactions,
        failure_reason);
}

bool TransactionManager::LoadAcceptedTransactionsSinceCleanup(
    std::vector<AcceptedTransaction>& transactions,
    std::string* failure_reason)
{
    return LoadAcceptedTransactionsAfter(
        true,
        transactions,
        failure_reason);
}

bool TransactionManager::LoadAcceptedTransactionsAfter(
    bool include_checkpointed_transactions,
    std::vector<AcceptedTransaction>& transactions,
    std::string* failure_reason)
{
    transactions.clear();
    if (failure_reason)
    {
        failure_reason->clear();
    }
    const auto fail = [&](const char* reason)
    {
        transactions.clear();
        if (failure_reason)
        {
            *failure_reason = reason;
        }
        return false;
    };
    if (!recovery_state_valid_)
    {
        return fail("WAL watermark state is invalid");
    }
    if (journal_path_.empty())
    {
        const auto lower_sequence_exclusive = include_checkpointed_transactions
            ? watermarks_.cleanup_sequence
            : watermarks_.apfs_durable_sequence;
        const auto has_work = include_checkpointed_transactions
            ? watermarks_.accepted_sequence > lower_sequence_exclusive
            : HasUnappliedAcceptedWork();
        return has_work
            ? fail("Accepted work has no WAL path")
            : true;
    }

    if (state_ != State::Idle && state_ != State::Active)
    {
        return fail("WAL cannot be read while a transaction is committing or failed");
    }
    if (state_ == State::Active && !JournalStateMatchesWriterLease())
    {
        recovery_state_valid_ = false;
        InvalidateFinalizationCoverage(true);
        return fail("Active transaction lost exclusive WAL ownership");
    }

    const auto existing = journal_.ReadAllWithExclusiveWriterLease();
    if (existing.status != WriteAheadLog::ReadStatus::Ok)
    {
        recovery_state_valid_ = false;
        InvalidateFinalizationCoverage(true);
        return fail("WAL could not be read for replay");
    }
    if (!ValidateWalSemantics(existing.records))
    {
        recovery_state_valid_ = false;
        InvalidateFinalizationCoverage(true);
        return fail("WAL semantic validation failed");
    }
    const auto writer_generation = journal_.ExclusiveWriterLeaseGeneration();
    if (state_ == State::Idle)
    {
        if (!SeedIdsFromJournalRecords(existing.records, writer_generation))
        {
            return fail("WAL state could not be reseeded after lease acquisition");
        }
    }
    else if (writer_generation == 0 ||
             writer_generation != journal_state_writer_generation_)
    {
        recovery_state_valid_ = false;
        InvalidateFinalizationCoverage(true);
        return fail("Active transaction changed WAL ownership during validation");
    }

    const auto lower_sequence_exclusive = include_checkpointed_transactions
        ? watermarks_.cleanup_sequence
        : watermarks_.apfs_durable_sequence;

    std::unordered_map<std::uint64_t, std::vector<WriteAheadLog::Record>> prepared_by_transaction;
    std::unordered_set<std::uint64_t> terminal_transactions;
    std::uint64_t previous_sequence = 0;
    for (const auto& record : existing.records)
    {
        if (record.operation == WriteAheadLog::OperationKind::CompactionIndex)
        {
            continue;
        }
        if (record.sequence == 0 || record.sequence <= previous_sequence)
        {
            return fail("WAL sequence ordering is invalid");
        }
        previous_sequence = record.sequence;

        if (record.operation == WriteAheadLog::OperationKind::DurabilityWatermark)
        {
            continue;
        }
        if (record.operation == WriteAheadLog::OperationKind::TransactionMarker)
        {
            if (record.transaction_id == 0 || !terminal_transactions.insert(record.transaction_id).second)
            {
                return fail("WAL transaction terminal marker is invalid");
            }
            auto prepared = prepared_by_transaction.find(record.transaction_id);
            const auto is_accepted_marker =
                record.state == WriteAheadLog::RecordState::Accepted ||
                (include_checkpointed_transactions &&
                 record.state == WriteAheadLog::RecordState::Checkpointed &&
                 (record.flags & kWalFlagCommitted) != 0);
            if (is_accepted_marker)
            {
                if (record.sequence > watermarks_.accepted_sequence)
                {
                    return fail("Accepted WAL transaction exceeds its watermark");
                }
                if (record.sequence > lower_sequence_exclusive)
                {
                    if (prepared == prepared_by_transaction.end() ||
                        prepared->second.size() != record.logical_length)
                    {
                        return fail("Accepted WAL transaction is incomplete");
                    }
                    transactions.push_back(AcceptedTransaction{
                        record.transaction_id,
                        record.sequence,
                        std::move(prepared->second),
                    });
                }
            }
            if (prepared != prepared_by_transaction.end())
            {
                prepared_by_transaction.erase(prepared);
            }
            continue;
        }

        if (record.state != WriteAheadLog::RecordState::Prepared ||
            record.transaction_id == 0 ||
            terminal_transactions.contains(record.transaction_id))
        {
            return fail("WAL mutation record is not replayable");
        }
        prepared_by_transaction[record.transaction_id].push_back(record);
    }

    const auto expected_latest_sequence = include_checkpointed_transactions
        ? watermarks_.accepted_sequence
        : (HasUnappliedAcceptedWork() ? watermarks_.accepted_sequence : 0);
    if (expected_latest_sequence > lower_sequence_exclusive &&
        (transactions.empty() || transactions.back().accepted_sequence != expected_latest_sequence))
    {
        return fail("Accepted WAL watermark has no complete transaction");
    }
    return true;
}

std::size_t TransactionManager::PendingMutationCount() const noexcept
{
    return pending_mutations_.size();
}

std::uint64_t TransactionManager::DurableJournalAppendCount() const noexcept
{
    return durable_journal_append_count_;
}

std::uint64_t TransactionManager::DurableJournalAppendMicroseconds() const noexcept
{
    return durable_journal_append_microseconds_;
}

std::uint64_t TransactionManager::DurableJournalAppendMaxMicroseconds() const noexcept
{
    return durable_journal_append_max_microseconds_;
}

std::uint64_t TransactionManager::DeferredWalGroupFlushCount() const noexcept
{
    std::lock_guard<std::mutex> lock(deferred_wal_state_mutex_);
    return deferred_wal_group_flush_count_;
}

std::uint64_t TransactionManager::DeferredWalGroupFlushMicroseconds() const noexcept
{
    std::lock_guard<std::mutex> lock(deferred_wal_state_mutex_);
    return deferred_wal_group_flush_microseconds_;
}

std::uint64_t TransactionManager::JournalAppendHandleOpenCount() const
{
    return journal_.SnapshotCounters().append_handle_open_count;
}

std::uint64_t TransactionManager::JournalAppendHandleFlushCount() const
{
    return journal_.SnapshotCounters().append_handle_flush_count;
}

std::uint64_t TransactionManager::FinalizationCoverageCacheHitCount() const noexcept
{
    return finalization_coverage_cache_hit_count_;
}

std::uint64_t TransactionManager::FinalizationCoverageWalScanCount() const noexcept
{
    return finalization_coverage_wal_scan_count_;
}

std::uint64_t TransactionManager::FinalizationCoverageWalScanMicroseconds() const noexcept
{
    return finalization_coverage_wal_scan_microseconds_;
}

bool TransactionManager::FlushPreparedRecords()
{
    if (!recovery_state_valid_)
    {
        return false;
    }
    if (buffered_prepared_records_.empty())
    {
        return true;
    }

    if (journal_path_.empty())
    {
        ClearBufferedPreparedRecords();
        return true;
    }
    if (!JournalStateMatchesWriterLease())
    {
        recovery_state_valid_ = false;
        InvalidateFinalizationCoverage(true);
        return false;
    }

    std::unique_lock<std::mutex> append_lock(deferred_wal_append_mutex_);

    const auto first_sequence_to_keep = pending_mutations_.empty()
        ? buffered_prepared_records_.front().sequence
        : pending_mutations_.front().wal_sequence;
    const auto effective_volume_identity = EffectiveVolumeIdentity(volume_identity_);

    std::vector<WriteAheadLog::Record> records;
    records.reserve(buffered_prepared_records_.size());
    for (auto& record : buffered_prepared_records_)
    {
        if (record.volume_identity.empty())
        {
            record.volume_identity = effective_volume_identity;
        }
        if (record.sequence == 0 || record.sequence >= next_sequence_)
        {
            return false;
        }
        records.push_back(record);
    }

    const auto coverage_generation_before_append = journal_state_writer_generation_;
    const bool coverage_trusted_before_append =
        finalization_coverage_trust_ == FinalizationCoverageTrust::Trusted &&
        coverage_generation_before_append != 0 &&
        coverage_generation_before_append == finalization_coverage_writer_generation_;
    bool compacted_for_retry = false;
    const auto append_started = std::chrono::steady_clock::now();
    const auto append_result = journal_.AppendBatchWithResult(
        records,
        true,
        coverage_generation_before_append);
    if (append_result == WriteAheadLog::AppendResult::BytesMayHavePersisted)
    {
        journal_append_ambiguous_ = true;
        recovery_state_valid_ = false;
        journal_state_writer_generation_ = 0;
        InvalidateFinalizationCoverage(true);
        return false;
    }
    if (append_result == WriteAheadLog::AppendResult::RejectedBeforeWrite)
    {
        const auto compaction_result = journal_.CompactWithResult(
            SafeCompactionFloor(first_sequence_to_keep),
            coverage_generation_before_append);
        if (compaction_result != WriteAheadLog::CompactionResult::Succeeded)
        {
            journal_append_ambiguous_ =
                compaction_result == WriteAheadLog::CompactionResult::BytesMayHavePersisted;
            recovery_state_valid_ = false;
            journal_state_writer_generation_ = 0;
            InvalidateFinalizationCoverage(true);
            return false;
        }
        compacted_for_retry = true;
        const auto retry_generation = journal_.ExclusiveWriterLeaseGeneration();
        if (retry_generation == 0)
        {
            recovery_state_valid_ = false;
            journal_state_writer_generation_ = 0;
            InvalidateFinalizationCoverage(true);
            return false;
        }
        journal_state_writer_generation_ = retry_generation;
        const auto retry_result = journal_.AppendBatchWithResult(
            records,
            true,
            retry_generation);
        if (retry_result == WriteAheadLog::AppendResult::BytesMayHavePersisted)
        {
            journal_append_ambiguous_ = true;
            recovery_state_valid_ = false;
            journal_state_writer_generation_ = 0;
            InvalidateFinalizationCoverage(true);
            return false;
        }
        if (retry_result != WriteAheadLog::AppendResult::Succeeded)
        {
            recovery_state_valid_ = false;
            journal_state_writer_generation_ = 0;
            InvalidateFinalizationCoverage(true);
            return false;
        }
    }
    const auto coverage_generation_after_append = journal_.ExclusiveWriterLeaseGeneration();
    if (coverage_generation_after_append == 0)
    {
        recovery_state_valid_ = false;
        journal_state_writer_generation_ = 0;
        InvalidateFinalizationCoverage(true);
        return false;
    }
    journal_state_writer_generation_ = coverage_generation_after_append;
    if (coverage_trusted_before_append &&
        (coverage_generation_after_append == coverage_generation_before_append ||
         compacted_for_retry))
    {
        finalization_coverage_trust_ = FinalizationCoverageTrust::Trusted;
        finalization_coverage_writer_generation_ = coverage_generation_after_append;
    }
    else
    {
        InvalidateFinalizationCoverage(false);
    }
    ObserveDurableJournalAppend(ElapsedMicroseconds(append_started));
    ClearBufferedPreparedRecords();
    return true;
}

bool TransactionManager::MarkApfsDurableThrough(std::uint64_t accepted_sequence)
{
    if (!recovery_state_valid_ || state_ != State::Idle)
    {
        return false;
    }
    if (!journal_path_.empty() && !JournalStateMatchesWriterLease())
    {
        if (!SeedIdsFromExistingJournal(true) ||
            !recovery_state_valid_ ||
            !JournalStateMatchesWriterLease())
        {
            return false;
        }
    }
    if (accepted_sequence < watermarks_.apfs_durable_sequence ||
        accepted_sequence > watermarks_.accepted_sequence)
    {
        return false;
    }
    if (accepted_sequence == watermarks_.apfs_durable_sequence)
    {
        return true;
    }
    if (!IsAcceptedBoundary(accepted_sequence))
    {
        return false;
    }
    if (!FlushDeferredAcceptanceDurabilityNow(accepted_sequence))
    {
        MarkDeferredAcceptanceDurabilityFailure();
        return false;
    }
    if (!AppendWatermarkLocked(WriteAheadLog::RecordState::Checkpointed, accepted_sequence))
    {
        return false;
    }
    watermarks_.apfs_durable_sequence = accepted_sequence;
    last_committed_sequence_ = accepted_sequence;
    for (auto it = accepted_boundaries_requiring_payload_spool_flush_.begin();
         it != accepted_boundaries_requiring_payload_spool_flush_.end();)
    {
        if (*it <= accepted_sequence)
        {
            it = accepted_boundaries_requiring_payload_spool_flush_.erase(it);
        }
        else
        {
            ++it;
        }
    }
    if (watermarks_.apfs_durable_sequence == watermarks_.accepted_sequence)
    {
        accepted_boundaries_requiring_payload_spool_flush_.clear();
    }
    return true;
}

bool TransactionManager::MarkCleanedThrough(std::uint64_t durable_sequence)
{
    if (!recovery_state_valid_ || state_ != State::Idle)
    {
        return false;
    }
    if (!journal_path_.empty() && !JournalStateMatchesWriterLease())
    {
        if (!SeedIdsFromExistingJournal(true) ||
            !recovery_state_valid_ ||
            !JournalStateMatchesWriterLease())
        {
            return false;
        }
    }
    if (durable_sequence < watermarks_.cleanup_sequence ||
        durable_sequence > watermarks_.apfs_durable_sequence)
    {
        return false;
    }
    if (durable_sequence == watermarks_.cleanup_sequence)
    {
        return true;
    }
    if (!IsAcceptedBoundary(durable_sequence))
    {
        return false;
    }
    if (!FlushDeferredAcceptanceDurabilityNow(durable_sequence))
    {
        MarkDeferredAcceptanceDurabilityFailure();
        return false;
    }
    if (!AppendWatermarkLocked(WriteAheadLog::RecordState::Cleaned, durable_sequence))
    {
        return false;
    }
    watermarks_.cleanup_sequence = durable_sequence;
    PruneAcceptedBoundariesThrough(durable_sequence);
    return true;
}

void TransactionManager::SetFaultInjectionHook(std::function<void(const std::string& stage)> hook)
{
    fault_hook_ = std::move(hook);
}

void TransactionManager::NotifyStage(const std::string& stage)
{
    if (fault_hook_)
    {
        fault_hook_(stage);
    }
}

bool TransactionManager::PersistTransactionBatchLocked(
    const wchar_t* outcome,
    bool durable_flush)
{
    if (next_sequence_ == 0 ||
        next_sequence_ == (std::numeric_limits<std::uint64_t>::max)())
    {
        return false;
    }

    if (journal_path_.empty())
    {
        ClearBufferedPreparedRecords();
        if (outcome && wcscmp(outcome, L"committed") == 0 && !pending_mutations_.empty())
        {
            last_committed_sequence_ = pending_mutations_.back().wal_sequence;
        }
        if (outcome && wcscmp(outcome, L"accepted") == 0 && !pending_mutations_.empty())
        {
            watermarks_.accepted_sequence = pending_mutations_.back().wal_sequence;
            accepted_boundaries_.insert(watermarks_.accepted_sequence);
            const auto proof = accepted_transaction_sequences_.find(current_transaction_id_);
            if (proof != accepted_transaction_sequences_.end())
            {
                proof->second.accepted_sequence = watermarks_.accepted_sequence;
            }
        }
        return true;
    }
    if (!JournalStateMatchesWriterLease())
    {
        recovery_state_valid_ = false;
        InvalidateFinalizationCoverage(true);
        return false;
    }

    std::unique_lock<std::mutex> append_lock(deferred_wal_append_mutex_);

    const auto effective_volume_identity = EffectiveVolumeIdentity(volume_identity_);
    const bool accepted_outcome = outcome && wcscmp(outcome, L"accepted") == 0;
    const bool accepted_requires_payload_spool_flush =
        accepted_outcome && current_transaction_requires_payload_spool_flush_;
    const auto first_sequence_to_keep = pending_mutations_.empty()
        ? next_sequence_
        : pending_mutations_.front().wal_sequence;

    std::vector<WriteAheadLog::Record> records;
    records.reserve(buffered_prepared_records_.size() + 1);
    for (auto& record : buffered_prepared_records_)
    {
        if (record.volume_identity.empty())
        {
            record.volume_identity = effective_volume_identity;
        }
        if (record.sequence == 0 || record.sequence >= next_sequence_)
        {
            return false;
        }
        records.push_back(record);
    }

    auto marker = BuildTransactionMarkerLocked(outcome, effective_volume_identity);
    marker.sequence = next_sequence_;
    records.push_back(marker);

    const auto coverage_generation_before_append = journal_state_writer_generation_;
    const bool coverage_trusted_before_append =
        finalization_coverage_trust_ == FinalizationCoverageTrust::Trusted &&
        coverage_generation_before_append != 0 &&
        coverage_generation_before_append == finalization_coverage_writer_generation_;
    bool compacted_for_retry = false;
    const auto append_started = std::chrono::steady_clock::now();
    const auto append_result = journal_.AppendBatchWithResult(
        records,
        durable_flush,
        coverage_generation_before_append);
    if (append_result == WriteAheadLog::AppendResult::BytesMayHavePersisted)
    {
        journal_append_ambiguous_ = true;
        recovery_state_valid_ = false;
        journal_state_writer_generation_ = 0;
        InvalidateFinalizationCoverage(true);
        return false;
    }
    if (append_result == WriteAheadLog::AppendResult::RejectedBeforeWrite)
    {
        const auto compaction_result = journal_.CompactWithResult(
            SafeCompactionFloor(first_sequence_to_keep),
            coverage_generation_before_append);
        if (compaction_result != WriteAheadLog::CompactionResult::Succeeded)
        {
            journal_append_ambiguous_ =
                compaction_result == WriteAheadLog::CompactionResult::BytesMayHavePersisted;
            recovery_state_valid_ = false;
            journal_state_writer_generation_ = 0;
            InvalidateFinalizationCoverage(true);
            return false;
        }
        compacted_for_retry = true;
        const auto retry_generation = journal_.ExclusiveWriterLeaseGeneration();
        if (retry_generation == 0)
        {
            recovery_state_valid_ = false;
            journal_state_writer_generation_ = 0;
            InvalidateFinalizationCoverage(true);
            return false;
        }
        journal_state_writer_generation_ = retry_generation;
        const auto retry_result = journal_.AppendBatchWithResult(
            records,
            durable_flush,
            retry_generation);
        if (retry_result == WriteAheadLog::AppendResult::BytesMayHavePersisted)
        {
            journal_append_ambiguous_ = true;
            recovery_state_valid_ = false;
            journal_state_writer_generation_ = 0;
            InvalidateFinalizationCoverage(true);
            return false;
        }
        if (retry_result != WriteAheadLog::AppendResult::Succeeded)
        {
            recovery_state_valid_ = false;
            journal_state_writer_generation_ = 0;
            InvalidateFinalizationCoverage(true);
            return false;
        }
    }

    const auto coverage_generation_after_append = journal_.ExclusiveWriterLeaseGeneration();
    const bool coverage_remains_trusted =
        coverage_trusted_before_append &&
        coverage_generation_after_append != 0 &&
        (coverage_generation_after_append == coverage_generation_before_append ||
         compacted_for_retry);
    if (coverage_generation_after_append == 0)
    {
        recovery_state_valid_ = false;
        journal_state_writer_generation_ = 0;
        InvalidateFinalizationCoverage(true);
        return false;
    }
    journal_state_writer_generation_ = coverage_generation_after_append;
    if (coverage_remains_trusted)
    {
        finalization_coverage_trust_ = FinalizationCoverageTrust::Trusted;
        finalization_coverage_writer_generation_ = coverage_generation_after_append;
    }
    else
    {
        InvalidateFinalizationCoverage(false);
    }
    if (durable_flush)
    {
        ObserveDurableJournalAppend(ElapsedMicroseconds(append_started));
    }
    ++next_sequence_;
    if (outcome && wcscmp(outcome, L"committed") == 0)
    {
        last_committed_sequence_ = marker.sequence;
    }
    else if (accepted_outcome)
    {
        watermarks_.accepted_sequence = marker.sequence;
        accepted_boundaries_.insert(marker.sequence);
        if (coverage_remains_trusted &&
            accepted_requires_payload_spool_flush)
        {
            accepted_boundaries_requiring_payload_spool_flush_.insert(marker.sequence);
        }
        const auto proof = accepted_transaction_sequences_.find(current_transaction_id_);
        if (proof != accepted_transaction_sequences_.end())
        {
            proof->second.accepted_sequence = marker.sequence;
        }
    }
    ClearBufferedPreparedRecords();
    return true;
}

bool TransactionManager::AppendWatermarkLocked(
    WriteAheadLog::RecordState state,
    std::uint64_t target_sequence)
{
    WriteAheadLog::Record record{};
    record.volume_identity = EffectiveVolumeIdentity(volume_identity_);
    record.operation = WriteAheadLog::OperationKind::DurabilityWatermark;
    record.state = state;
    record.logical_offset = target_sequence;
    const auto first_sequence_to_keep = watermarks_.cleanup_sequence == (std::numeric_limits<std::uint64_t>::max)()
        ? watermarks_.cleanup_sequence
        : watermarks_.cleanup_sequence + 1;
    return AppendWalRecordWithCleanup(record, true, first_sequence_to_keep);
}

bool TransactionManager::AppendWalRecordWithCleanup(
    WriteAheadLog::Record& record,
    bool durable_flush,
    std::uint64_t first_sequence_to_keep)
{
    if (!recovery_state_valid_ ||
        next_sequence_ == 0 ||
        next_sequence_ == (std::numeric_limits<std::uint64_t>::max)())
    {
        return false;
    }

    if (journal_path_.empty())
    {
        return true;
    }
    if (!JournalStateMatchesWriterLease())
    {
        recovery_state_valid_ = false;
        InvalidateFinalizationCoverage(true);
        return false;
    }

    std::unique_lock<std::mutex> append_lock(deferred_wal_append_mutex_);

    if (record.sequence == 0)
    {
        record.sequence = next_sequence_;
    }
    if (record.sequence != next_sequence_)
    {
        return false;
    }

    const auto generation_before_append = journal_state_writer_generation_;
    const bool coverage_trusted_before_append =
        finalization_coverage_trust_ == FinalizationCoverageTrust::Trusted &&
        generation_before_append != 0 &&
        generation_before_append == finalization_coverage_writer_generation_;
    bool compacted_for_retry = false;
    const auto append_started = std::chrono::steady_clock::now();
    auto append_result = journal_.AppendWithResult(
        record,
        durable_flush,
        generation_before_append);

    if (append_result == WriteAheadLog::AppendResult::BytesMayHavePersisted)
    {
        journal_append_ambiguous_ = true;
        recovery_state_valid_ = false;
        journal_state_writer_generation_ = 0;
        InvalidateFinalizationCoverage(true);
        return false;
    }

    if (append_result == WriteAheadLog::AppendResult::RejectedBeforeWrite)
    {
        const auto compaction_result = journal_.CompactWithResult(
            SafeCompactionFloor(first_sequence_to_keep),
            generation_before_append);
        if (compaction_result != WriteAheadLog::CompactionResult::Succeeded)
        {
            journal_append_ambiguous_ =
                compaction_result == WriteAheadLog::CompactionResult::BytesMayHavePersisted;
            recovery_state_valid_ = false;
            journal_state_writer_generation_ = 0;
            InvalidateFinalizationCoverage(true);
            return false;
        }
        compacted_for_retry = true;
        const auto retry_generation = journal_.ExclusiveWriterLeaseGeneration();
        if (retry_generation == 0)
        {
            recovery_state_valid_ = false;
            journal_state_writer_generation_ = 0;
            InvalidateFinalizationCoverage(true);
            return false;
        }
        journal_state_writer_generation_ = retry_generation;
        append_result = journal_.AppendWithResult(
            record,
            durable_flush,
            retry_generation);
        if (append_result == WriteAheadLog::AppendResult::BytesMayHavePersisted)
        {
            journal_append_ambiguous_ = true;
            recovery_state_valid_ = false;
            journal_state_writer_generation_ = 0;
            InvalidateFinalizationCoverage(true);
            return false;
        }
        if (append_result != WriteAheadLog::AppendResult::Succeeded)
        {
            recovery_state_valid_ = false;
            journal_state_writer_generation_ = 0;
            InvalidateFinalizationCoverage(true);
            return false;
        }
    }

    const auto generation_after_append = journal_.ExclusiveWriterLeaseGeneration();
    if (generation_after_append == 0)
    {
        recovery_state_valid_ = false;
        journal_state_writer_generation_ = 0;
        InvalidateFinalizationCoverage(true);
        return false;
    }
    journal_state_writer_generation_ = generation_after_append;
    if (coverage_trusted_before_append &&
        (generation_after_append == generation_before_append || compacted_for_retry))
    {
        finalization_coverage_trust_ = FinalizationCoverageTrust::Trusted;
        finalization_coverage_writer_generation_ = generation_after_append;
    }
    else
    {
        InvalidateFinalizationCoverage(false);
    }
    ++next_sequence_;
    if (durable_flush)
    {
        ObserveDurableJournalAppend(ElapsedMicroseconds(append_started));
    }
    return true;
}

void TransactionManager::ObserveDurableJournalAppend(std::uint64_t elapsed_microseconds) noexcept
{
    ++durable_journal_append_count_;
    durable_journal_append_microseconds_ += elapsed_microseconds;
    durable_journal_append_max_microseconds_ =
        (std::max)(durable_journal_append_max_microseconds_, elapsed_microseconds);
}

void TransactionManager::ConfigureJournal()
{
    journal_.Reconfigure({
        std::filesystem::path(journal_path_),
        EffectiveVolumeIdentity(volume_identity_),
        journal_max_bytes_,
    });
}

WriteAheadLog::Record TransactionManager::BuildTransactionMarkerLocked(
    const wchar_t* outcome,
    const std::string& volume_identity) const
{
    const bool committed = outcome && wcscmp(outcome, L"committed") == 0;
    const bool aborted = outcome && wcscmp(outcome, L"aborted") == 0;
    const bool accepted = outcome && wcscmp(outcome, L"accepted") == 0;

    WriteAheadLog::Record marker{};
    marker.volume_identity = volume_identity;
    marker.transaction_id = current_transaction_id_;
    marker.operation = WriteAheadLog::OperationKind::TransactionMarker;
    marker.state = accepted
        ? WriteAheadLog::RecordState::Accepted
        : (committed ? WriteAheadLog::RecordState::Checkpointed : WriteAheadLog::RecordState::Cleaned);
    marker.flags = accepted
        ? kWalFlagAccepted
        : (committed ? kWalFlagCommitted : (aborted ? kWalFlagAborted : 0));
    marker.logical_length = static_cast<std::uint64_t>(pending_mutations_.size());
    marker.path_utf8 = WideToUtf8(safety_level_);
    return marker;
}

bool TransactionManager::IsAcceptedBoundary(std::uint64_t sequence) const noexcept
{
    return accepted_boundaries_.contains(sequence);
}

std::uint64_t TransactionManager::SafeCompactionFloor(std::uint64_t preferred_floor) const noexcept
{
    if (watermarks_.accepted_sequence <= watermarks_.cleanup_sequence)
    {
        return preferred_floor;
    }
    if (watermarks_.cleanup_sequence == 0)
    {
        return 1;
    }
    return (std::min)(preferred_floor, watermarks_.cleanup_sequence);
}

bool TransactionManager::AppendPreparedMutationLocked(MutationIntent& mutation)
{
    if (next_sequence_ == 0 ||
        next_sequence_ == (std::numeric_limits<std::uint64_t>::max)())
    {
        return false;
    }

    if (journal_path_.empty())
    {
        if (mutation.wal_sequence == 0)
        {
            mutation.wal_sequence = next_sequence_;
        }
        if (mutation.wal_sequence != next_sequence_)
        {
            return false;
        }
        ++next_sequence_;
        return true;
    }

    const auto effective_volume_identity = EffectiveVolumeIdentity(volume_identity_);
    if (mutation.wal_sequence == 0)
    {
        mutation.wal_sequence = next_sequence_;
    }
    if (mutation.wal_sequence != next_sequence_)
    {
        return false;
    }

    WriteAheadLog::Record record{};
    record.volume_identity = effective_volume_identity;
    record.transaction_id = current_transaction_id_;
    record.sequence = mutation.wal_sequence;
    record.operation = ToWalOperation(mutation.kind);
    record.state = WriteAheadLog::RecordState::Prepared;
    record.object_id = mutation.object_id;
    record.parent_object_id = mutation.generation;
    record.payload_spool_id = mutation.payload_length == 0 ? 0 : mutation.wal_sequence;
    record.payload_offset = mutation.payload_spool_offset;
    record.payload_length = mutation.payload_length;
    record.logical_offset = mutation.kind == MutationKind::SetBasicInfo
        ? mutation.timestamp_utc
        : mutation.offset;
    record.logical_length = mutation.length;
    record.flags = mutation.replace_if_exists ? kWalFlagReplaceIfExists : 0;
    record.path_utf8 = WideToUtf8(mutation.path);
    record.secondary_path_utf8 = WideToUtf8(mutation.secondary_path);
    record.payload_sha256 = mutation.payload_checksum;
    record.inline_payload = std::move(mutation.inline_payload);

    if (record.operation == WriteAheadLog::OperationKind::Write &&
        (record.inline_payload.empty() ||
         !WriteAheadLog::InlinePayloadIsConsistent(record)))
    {
        current_transaction_requires_payload_spool_flush_ = true;
    }
    buffered_prepared_records_.push_back(std::move(record));
    const auto& buffered_record = buffered_prepared_records_.back();
    if (buffered_record.operation == WriteAheadLog::OperationKind::Write &&
        buffered_record.inline_payload.empty())
    {
        buffered_prepared_records_have_empty_write_payload_ = true;
    }
    const bool complete_inline_payload =
        buffered_record.operation == WriteAheadLog::OperationKind::Write
            ? !buffered_record.inline_payload.empty() &&
                WriteAheadLog::InlinePayloadIsConsistent(buffered_record)
            : buffered_record.inline_payload.empty();
    if (!complete_inline_payload)
    {
        buffered_prepared_records_have_incomplete_inline_payload_ = true;
    }
    if (buffered_inline_payload_bytes_ < WriteAheadLog::MaxInlinePayloadBytes)
    {
        const auto remaining =
            WriteAheadLog::MaxInlinePayloadBytes - buffered_inline_payload_bytes_;
        buffered_inline_payload_bytes_ +=
            (std::min)(remaining, buffered_record.inline_payload.size());
    }
    ++next_sequence_;
    return true;
}

bool TransactionManager::SeedIdsFromExistingJournal(bool acquire_writer_lease)
{
    if (state_ != State::Idle)
    {
        return false;
    }
    if (journal_path_.empty())
    {
        journal_state_writer_generation_ = 0;
        InvalidateFinalizationCoverage(false);
        return true;
    }

    const auto existing = acquire_writer_lease
        ? journal_.ReadAllWithExclusiveWriterLease()
        : journal_.ReadAll();
    if (existing.status != WriteAheadLog::ReadStatus::Ok ||
        !ValidateWalSemantics(existing.records))
    {
        // Keep the writer lease while this degraded owner is alive. Releasing
        // it would let a second process mutate evidence that this owner has
        // already classified as unsafe for recovery.
        recovery_state_valid_ = false;
        journal_state_writer_generation_ = 0;
        InvalidateFinalizationCoverage(true);
        return false;
    }

    const auto writer_generation = acquire_writer_lease
        ? journal_.ExclusiveWriterLeaseGeneration()
        : 0;
    return SeedIdsFromJournalRecords(existing.records, writer_generation);
}

bool TransactionManager::SeedIdsFromJournalRecords(
    const std::vector<WriteAheadLog::Record>& records,
    std::uint64_t writer_generation)
{
    if (state_ != State::Idle || !ValidateWalSemantics(records))
    {
        recovery_state_valid_ = false;
        journal_state_writer_generation_ = 0;
        InvalidateFinalizationCoverage(true);
        return false;
    }

    std::unordered_set<std::uint64_t> recovered_boundaries;
    std::unordered_map<std::uint64_t, std::uint64_t> recovered_transaction_sequences;
    std::unordered_map<std::uint64_t, bool> transaction_requires_spool_flush;
    std::vector<std::pair<std::uint64_t, bool>> accepted_recovery_requirements;
    std::uint64_t max_transaction_id = 0;
    std::uint64_t max_sequence = 0;
    DurabilityWatermarks recovered_watermarks{};
    bool recovered_state_valid = true;

    for (const auto& record : records)
    {
        max_transaction_id = (std::max)(max_transaction_id, record.transaction_id);
        max_sequence = (std::max)(max_sequence, record.sequence);

        if (record.state == WriteAheadLog::RecordState::Prepared &&
            IsMutationOperation(record.operation))
        {
            auto& requires_spool_flush = transaction_requires_spool_flush[record.transaction_id];
            if (record.operation == WriteAheadLog::OperationKind::Write &&
                (record.inline_payload.empty() ||
                 !WriteAheadLog::InlinePayloadIsConsistent(record)))
            {
                requires_spool_flush = true;
            }
            continue;
        }

        if (record.operation == WriteAheadLog::OperationKind::TransactionMarker)
        {
            const auto requirement = transaction_requires_spool_flush.find(record.transaction_id);
            const bool requires_spool_flush =
                requirement != transaction_requires_spool_flush.end() && requirement->second;
            transaction_requires_spool_flush.erase(record.transaction_id);

            if (record.state == WriteAheadLog::RecordState::Accepted)
            {
                recovered_boundaries.insert(record.sequence);
                recovered_transaction_sequences[record.transaction_id] = record.sequence;
                recovered_watermarks.accepted_sequence = (std::max)(
                    recovered_watermarks.accepted_sequence,
                    record.sequence);
                accepted_recovery_requirements.emplace_back(
                    record.sequence,
                    requires_spool_flush);
            }
            else if (record.state == WriteAheadLog::RecordState::Checkpointed &&
                     (record.flags & kWalFlagCommitted) != 0)
            {
                recovered_boundaries.insert(record.sequence);
                recovered_transaction_sequences[record.transaction_id] = record.sequence;
                recovered_watermarks.accepted_sequence = (std::max)(
                    recovered_watermarks.accepted_sequence,
                    record.sequence);
                recovered_watermarks.apfs_durable_sequence = (std::max)(
                    recovered_watermarks.apfs_durable_sequence,
                    record.sequence);
            }
            continue;
        }

        if (record.operation != WriteAheadLog::OperationKind::DurabilityWatermark)
        {
            continue;
        }

        const auto target_sequence = record.logical_offset;
        if (record.state == WriteAheadLog::RecordState::Checkpointed)
        {
            if (target_sequence < recovered_watermarks.apfs_durable_sequence ||
                target_sequence > recovered_watermarks.accepted_sequence ||
                !recovered_boundaries.contains(target_sequence))
            {
                recovered_state_valid = false;
            }
            recovered_watermarks.apfs_durable_sequence = (std::max)(
                recovered_watermarks.apfs_durable_sequence,
                target_sequence);
        }
        else if (record.state == WriteAheadLog::RecordState::Cleaned)
        {
            if (target_sequence < recovered_watermarks.cleanup_sequence ||
                target_sequence > recovered_watermarks.apfs_durable_sequence ||
                !recovered_boundaries.contains(target_sequence))
            {
                recovered_state_valid = false;
            }
            recovered_watermarks.cleanup_sequence = (std::max)(
                recovered_watermarks.cleanup_sequence,
                target_sequence);
        }
    }

    if (!transaction_requires_spool_flush.empty() ||
        recovered_watermarks.cleanup_sequence > recovered_watermarks.apfs_durable_sequence ||
        recovered_watermarks.apfs_durable_sequence > recovered_watermarks.accepted_sequence ||
        max_transaction_id == (std::numeric_limits<std::uint64_t>::max)() ||
        max_sequence == (std::numeric_limits<std::uint64_t>::max)())
    {
        recovered_state_valid = false;
    }

    accepted_boundaries_ = std::move(recovered_boundaries);
    accepted_boundaries_requiring_payload_spool_flush_.clear();
    for (const auto& [accepted_sequence, requires_spool_flush] : accepted_recovery_requirements)
    {
        if (requires_spool_flush &&
            accepted_sequence > recovered_watermarks.apfs_durable_sequence)
        {
            accepted_boundaries_requiring_payload_spool_flush_.insert(accepted_sequence);
        }
    }
    watermarks_ = recovered_watermarks;
    last_committed_sequence_ = recovered_watermarks.apfs_durable_sequence;
    recovery_state_valid_ = recovered_state_valid && !journal_append_ambiguous_;
    for (auto proof = accepted_transaction_sequences_.begin();
         proof != accepted_transaction_sequences_.end();)
    {
        const auto recovered = recovered_transaction_sequences.find(proof->first);
        if (recovered == recovered_transaction_sequences.end())
        {
            proof = accepted_transaction_sequences_.erase(proof);
            continue;
        }
        proof->second.accepted_sequence = recovered->second;
        ++proof;
    }
    PruneAcceptedBoundariesThrough(watermarks_.cleanup_sequence);

    if (next_transaction_id_ <= max_transaction_id)
    {
        next_transaction_id_ = max_transaction_id + 1;
    }
    if (next_sequence_ <= max_sequence)
    {
        next_sequence_ = max_sequence + 1;
    }
    if (!recovery_state_valid_ || (writer_generation == 0 && !journal_path_.empty()))
    {
        journal_state_writer_generation_ = 0;
        InvalidateFinalizationCoverage(!recovery_state_valid_);
        return recovery_state_valid_;
    }

    journal_state_writer_generation_ = writer_generation;
    if (writer_generation != 0)
    {
        finalization_coverage_trust_ = FinalizationCoverageTrust::Trusted;
        finalization_coverage_writer_generation_ = writer_generation;
    }
    else
    {
        InvalidateFinalizationCoverage(false);
    }
    return true;
}

bool TransactionManager::JournalStateMatchesWriterLease() const
{
    if (journal_path_.empty())
    {
        return true;
    }
    const auto writer_generation = journal_.ExclusiveWriterLeaseGeneration();
    return writer_generation != 0 && writer_generation == journal_state_writer_generation_;
}

void TransactionManager::InvalidateFinalizationCoverage(bool poison) noexcept
{
    if (poison)
    {
        finalization_coverage_trust_ = FinalizationCoverageTrust::Poisoned;
    }
    else if (finalization_coverage_trust_ != FinalizationCoverageTrust::Poisoned)
    {
        finalization_coverage_trust_ = FinalizationCoverageTrust::Unknown;
    }
    finalization_coverage_writer_generation_ = 0;
}

void TransactionManager::PruneAcceptedBoundariesThrough(
    std::uint64_t cleanup_sequence) noexcept
{
    for (auto it = accepted_boundaries_.begin(); it != accepted_boundaries_.end();)
    {
        if (*it <= cleanup_sequence)
        {
            it = accepted_boundaries_.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

std::string TransactionManager::WideToUtf8(const std::wstring& value)
{
    if (value.empty())
    {
        return {};
    }

    const int required = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (required <= 0)
    {
        return {};
    }

    std::string output(static_cast<std::size_t>(required), '\0');
    const int written = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        output.data(),
        required,
        nullptr,
        nullptr);
    if (written != required)
    {
        return {};
    }

    return output;
}

} // namespace apfsaccess::rw
