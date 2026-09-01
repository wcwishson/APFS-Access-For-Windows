#pragma once

#include <array>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "WriteAheadLog.h"

namespace apfsaccess::rw
{
class TransactionManager
{
public:
    enum class MutationKind
    {
        CreateFile,
        CreateDirectory,
        Write,
        SetFileSize,
        Rename,
        Delete,
        SetBasicInfo,
    };

    struct MutationIntent
    {
        MutationKind kind = MutationKind::Write;
        std::wstring path;
        std::wstring secondary_path;
        std::uint64_t offset = 0;
        std::uint64_t length = 0;
        std::uint64_t wal_sequence = 0;
        std::uint64_t object_id = 0;
        std::uint64_t generation = 0;
        std::uint64_t payload_spool_offset = 0;
        std::uint64_t payload_length = 0;
        std::uint64_t timestamp_utc = 0;
        std::array<std::uint8_t, WriteAheadLog::PayloadHashSize> payload_checksum{};
        std::vector<std::byte> inline_payload;
        bool replace_if_exists = false;
    };

    struct DurabilityWatermarks
    {
        std::uint64_t accepted_sequence = 0;
        std::uint64_t apfs_durable_sequence = 0;
        std::uint64_t cleanup_sequence = 0;
    };

    struct AcceptedTransaction
    {
        std::uint64_t transaction_id = 0;
        std::uint64_t accepted_sequence = 0;
        std::vector<WriteAheadLog::Record> mutations;
    };

    enum class State
    {
        Idle,
        Active,
        Committing,
        Failed,
    };

    explicit TransactionManager(std::wstring safety_level);

    [[nodiscard]] State CurrentState() const noexcept;
    [[nodiscard]] bool Begin();
    [[nodiscard]] bool Accept();
    [[nodiscard]] bool AcceptForDeferredCommit(
        std::uint64_t* accepted_sequence = nullptr);
    [[nodiscard]] bool WaitForDeferredAcceptanceDurability(
        std::uint64_t accepted_sequence);
    [[nodiscard]] bool FlushDeferredAcceptanceDurabilityNow(
        std::uint64_t accepted_sequence);
    void MarkDeferredAcceptanceDurabilityFailure() noexcept;
    [[nodiscard]] bool CanAddInlinePayload(std::size_t payload_bytes) const noexcept;
    [[nodiscard]] bool CanAcceptWithoutPayloadSpoolFlush() const noexcept;
    [[nodiscard]] bool CanFinalizeWithoutPayloadSpoolFlush(
        bool allow_process_local_coverage = true);
    [[nodiscard]] bool Commit();
    [[nodiscard]] bool Abort();
    [[nodiscard]] bool RecordMutation(const MutationIntent& mutation);
    [[nodiscard]] bool FlushPreparedRecords();
    [[nodiscard]] bool MarkApfsDurableThrough(std::uint64_t accepted_sequence);
    [[nodiscard]] bool MarkCleanedThrough(std::uint64_t durable_sequence);
    void SetJournalPath(std::wstring journal_path);
    void SetVolumeIdentity(std::wstring volume_identity);
    void SetJournalMaxBytesForTest(std::uint64_t max_bytes);
    [[nodiscard]] std::uint64_t CurrentTransactionId() const noexcept;
    [[nodiscard]] bool RetainAcceptedSequenceProof(std::uint64_t transaction_id);
    void ReleaseAcceptedSequenceProof(std::uint64_t transaction_id) noexcept;
    [[nodiscard]] std::optional<std::uint64_t> AcceptedSequenceForTransaction(
        std::uint64_t transaction_id) const noexcept;
    [[nodiscard]] std::size_t RetainedAcceptedSequenceProofCount() const noexcept;
    [[nodiscard]] std::size_t TrackedAcceptedBoundaryCount() const noexcept;
    [[nodiscard]] static constexpr std::size_t MaxRetainedAcceptedSequenceProofs() noexcept
    {
        return 64;
    }
    [[nodiscard]] std::uint64_t NextMutationSequence() const noexcept;
    [[nodiscard]] std::uint64_t LastCommittedSequence() const noexcept;
    [[nodiscard]] DurabilityWatermarks Watermarks() const noexcept;
    [[nodiscard]] bool HasUnappliedAcceptedWork() const noexcept;
    [[nodiscard]] bool RecoveryStateValid() const noexcept;
    [[nodiscard]] bool CanClearRecoveryState() const;
    [[nodiscard]] bool LoadUnappliedAcceptedTransactions(
        std::vector<AcceptedTransaction>& transactions,
        std::string* failure_reason = nullptr);
    [[nodiscard]] bool LoadAcceptedTransactionsSinceCleanup(
        std::vector<AcceptedTransaction>& transactions,
        std::string* failure_reason = nullptr);
    [[nodiscard]] std::size_t PendingMutationCount() const noexcept;
    [[nodiscard]] std::uint64_t DurableJournalAppendCount() const noexcept;
    [[nodiscard]] std::uint64_t DurableJournalAppendMicroseconds() const noexcept;
    [[nodiscard]] std::uint64_t DurableJournalAppendMaxMicroseconds() const noexcept;
    [[nodiscard]] std::uint64_t DeferredWalGroupFlushCount() const noexcept;
    [[nodiscard]] std::uint64_t DeferredWalGroupFlushMicroseconds() const noexcept;
    [[nodiscard]] std::uint64_t JournalAppendHandleOpenCount() const;
    [[nodiscard]] std::uint64_t JournalAppendHandleFlushCount() const;
    [[nodiscard]] std::uint64_t FinalizationCoverageCacheHitCount() const noexcept;
    [[nodiscard]] std::uint64_t FinalizationCoverageWalScanCount() const noexcept;
    [[nodiscard]] std::uint64_t FinalizationCoverageWalScanMicroseconds() const noexcept;
    [[nodiscard]] static std::string WideToUtf8(const std::wstring& value);
    void SetJournalFaultInjectionHook(WriteAheadLog::FaultInjectionHook hook);

    // Fault-injection hook used by the planned deterministic crash harness.
    void SetFaultInjectionHook(std::function<void(const std::string& stage)> hook);
    void NotifyStage(const std::string& stage);

private:
    enum class FinalizationCoverageTrust
    {
        Unknown,
        Trusted,
        Poisoned,
    };

    [[nodiscard]] bool PersistTransactionBatchLocked(
        const wchar_t* outcome,
        bool durable_flush = true);
    [[nodiscard]] bool AppendWatermarkLocked(
        WriteAheadLog::RecordState state,
        std::uint64_t target_sequence);
    [[nodiscard]] bool AppendWalRecordWithCleanup(WriteAheadLog::Record& record, bool durable_flush, std::uint64_t first_sequence_to_keep);
    [[nodiscard]] bool AppendPreparedMutationLocked(MutationIntent& mutation);
    [[nodiscard]] WriteAheadLog::Record BuildTransactionMarkerLocked(
        const wchar_t* outcome,
        const std::string& volume_identity) const;
    [[nodiscard]] bool IsAcceptedBoundary(std::uint64_t sequence) const noexcept;
    [[nodiscard]] std::uint64_t SafeCompactionFloor(std::uint64_t preferred_floor) const noexcept;
    void ObserveDurableJournalAppend(std::uint64_t elapsed_microseconds) noexcept;
    [[nodiscard]] bool LoadAcceptedTransactionsAfter(
        bool include_checkpointed_transactions,
        std::vector<AcceptedTransaction>& transactions,
        std::string* failure_reason);
    void ConfigureJournal();
    [[nodiscard]] bool SeedIdsFromExistingJournal(bool acquire_writer_lease);
    [[nodiscard]] bool SeedIdsFromJournalRecords(
        const std::vector<WriteAheadLog::Record>& records,
        std::uint64_t writer_generation);
    [[nodiscard]] bool JournalStateMatchesWriterLease() const;
    [[nodiscard]] bool EnsureDeferredAcceptanceDurability(
        std::uint64_t accepted_sequence,
        bool coalesce);
    void ClearBufferedPreparedRecords() noexcept;
    void InvalidateFinalizationCoverage(bool poison) noexcept;
    void PruneAcceptedBoundariesThrough(std::uint64_t cleanup_sequence) noexcept;

    struct AcceptedSequenceProof
    {
        std::uint64_t accepted_sequence = 0;
        std::size_t retain_count = 0;
    };

    std::wstring safety_level_;
    State state_ = State::Idle;
    std::function<void(const std::string& stage)> fault_hook_;
    std::wstring journal_path_;
    std::wstring volume_identity_;
    WriteAheadLog journal_;
    std::uint64_t journal_max_bytes_ = 64ull * 1024ull * 1024ull;
    std::uint64_t next_transaction_id_ = 1;
    std::uint64_t next_sequence_ = 1;
    std::uint64_t last_committed_sequence_ = 0;
    DurabilityWatermarks watermarks_{};
    bool recovery_state_valid_ = true;
    std::uint64_t current_transaction_id_ = 0;
    std::uint64_t durable_journal_append_count_ = 0;
    std::uint64_t durable_journal_append_microseconds_ = 0;
    std::uint64_t durable_journal_append_max_microseconds_ = 0;
    mutable std::mutex deferred_wal_state_mutex_;
    std::condition_variable deferred_wal_state_cv_;
    std::mutex deferred_wal_append_mutex_;
    std::uint64_t deferred_wal_pending_sequence_ = 0;
    std::uint64_t deferred_wal_durable_sequence_ = 0;
    std::uint64_t deferred_wal_group_flush_count_ = 0;
    std::uint64_t deferred_wal_group_flush_microseconds_ = 0;
    bool deferred_wal_flush_in_progress_ = false;
    bool deferred_wal_flush_failed_ = false;
    std::unordered_set<std::uint64_t> accepted_boundaries_;
    std::unordered_set<std::uint64_t> accepted_boundaries_requiring_payload_spool_flush_;
    mutable FinalizationCoverageTrust finalization_coverage_trust_ = FinalizationCoverageTrust::Unknown;
    mutable std::uint64_t finalization_coverage_writer_generation_ = 0;
    std::uint64_t journal_state_writer_generation_ = 0;
    mutable std::uint64_t finalization_coverage_cache_hit_count_ = 0;
    mutable std::uint64_t finalization_coverage_wal_scan_count_ = 0;
    mutable std::uint64_t finalization_coverage_wal_scan_microseconds_ = 0;
    bool journal_append_ambiguous_ = false;
    bool current_transaction_requires_payload_spool_flush_ = false;
    std::vector<MutationIntent> pending_mutations_;
    std::vector<WriteAheadLog::Record> buffered_prepared_records_;
    // Avoid rescanning every prepared record for each small-write admission check.
    std::size_t buffered_inline_payload_bytes_ = 0;
    bool buffered_prepared_records_have_empty_write_payload_ = false;
    bool buffered_prepared_records_have_incomplete_inline_payload_ = false;
    std::unordered_map<std::uint64_t, AcceptedSequenceProof> accepted_transaction_sequences_;
};
} // namespace apfsaccess::rw
