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
#include "PayloadSpool.h"

namespace apfsaccess::rw
{
class FusionJournalContinuation;
class FusionOriginalCapture;
class FusionCertifiedPredecessor;
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
        SetSymbolicLinkTarget,
        RemoveSymbolicLinkTarget,
        SetExtendedAttribute,
        RemoveExtendedAttribute,
        SetInodeMetadata = 12,
        // No payload; length is allocation bytes, EOF becomes min(previous EOF, length).
        SetAllocationSize = 13,
        RestoreDirectoryFromSymbolicLink = 14,
        RewriteCompressedContent = 15,
        CloneFile = 16,
        RenameVolume = 17,
        CreateSnapshot = 18,
        DeleteSnapshot = 19,
        RepairVolumeFileCount = 24,
        SetVolumeQuotaReserve = 20,
        HardLink = 21,
        NativeSparse = 22,
        CloneRange = 23,
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
        std::optional<UnlinkOutcome> unlink_outcome;
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
        std::uint64_t preimage_checkpoint_xid = 0;
    };

    enum class RetainedHistoryCoverage { NoAcceptedHistory, RetainedComplete, Unavailable };
    struct RetainedAcceptedHistory
    {
        RetainedHistoryCoverage coverage = RetainedHistoryCoverage::Unavailable;
        DurabilityWatermarks watermarks;
        std::uint64_t writer_lease_generation = 0;
        std::vector<AcceptedTransaction> cleaned;
        std::vector<AcceptedTransaction> pending;
    };

    enum class State
    {
        Idle,
        Active,
        Committing,
        Failed,
    };

    explicit TransactionManager(std::wstring safety_level);

    [[nodiscard]] const std::wstring& ConfiguredVolumeIdentity() const noexcept { return volume_identity_; }
    [[nodiscard]] State CurrentState() const noexcept;
    [[nodiscard]] bool Begin();
    [[nodiscard]] bool Accept(std::uint64_t preimage_checkpoint_xid = 0);
    [[nodiscard]] bool AcceptForDeferredCommit(
        std::uint64_t* accepted_sequence = nullptr,
        std::uint64_t preimage_checkpoint_xid = 0);
    [[nodiscard]] bool WaitForDeferredAcceptanceDurability(
        std::uint64_t accepted_sequence);
    [[nodiscard]] bool FlushDeferredAcceptanceDurabilityNow(
        std::uint64_t accepted_sequence);
    // Caller holds the journal gate. Unlike the process-local deferred fast
    // path, also flushes a validated original WAL reopened after interruption.
    [[nodiscard]] bool FlushAcceptedEvidenceDurability(std::uint64_t accepted_sequence);
    // Caller holds the journal gate. Flush the validated retained original even
    // when a readable Cleaned marker has already retired all accepted boundaries.
    // Never creates/reseeds evidence; a failed flush poisons this owner.
    [[nodiscard]] bool FlushRetainedOriginalEvidenceDurability();
    void MarkDeferredAcceptanceDurabilityFailure() noexcept;
    [[nodiscard]] bool CanAddInlinePayload(std::size_t payload_bytes) const noexcept;
    [[nodiscard]] bool CanAcceptWithoutPayloadSpoolFlush() const noexcept;
    [[nodiscard]] bool CanFinalizeWithoutPayloadSpoolFlush(
        bool allow_process_local_coverage = true);
    [[nodiscard]] bool Commit(std::uint64_t preimage_checkpoint_xid = 0);
    [[nodiscard]] bool Abort();
    [[nodiscard]] bool RecordMutation(const MutationIntent& mutation);
    [[nodiscard]] bool FlushPreparedRecords();
    [[nodiscard]] bool MarkApfsDurableThrough(std::uint64_t accepted_sequence);
    [[nodiscard]] bool MarkCleanedThrough(std::uint64_t durable_sequence);
    // Fresh command owner only: existing strict lease before any canonical collector runs.
    [[nodiscard]] bool OpenExistingRepairJournal(std::wstring path, std::wstring identity, std::string& error);
    [[nodiscard]] bool OwnsJournalForMaintenance(const std::wstring& path, const std::wstring& identity) const
    { return journal_path_ == path && volume_identity_ == identity && journal_.HasExclusiveWriterLease(); }
    // Caller holds the session journal gate. These observations cannot repair
    // or remove compaction evidence while authenticating a recovery source.
    [[nodiscard]] std::uint64_t ObservedJournalWriterLeaseGeneration() const
    { return journal_.ExclusiveWriterLeaseGeneration(); }
    [[nodiscard]] std::uint64_t ObservedJournalAppendLeaseGeneration() const
    { return journal_.ValidatedAppendLeaseGeneration(true); }
    // Owner-enrolled canonical journal identity ("apfs-vol:<container>:<oid>"),
    // recorded by the session owner from catalog-resolved owner-known values.
    // The configured volume identity (recovery/legacy form) is never disturbed:
    // recovery storage keys, spool identity and legacy evidence recognition keep
    // working. First enrollment wins; remapping to a different identity refuses.
    bool EnrollCanonicalJournalIdentity(std::wstring canonical_identity);
    [[nodiscard]] const std::wstring& EnrolledCanonicalJournalIdentity() const noexcept
    { return canonical_journal_identity_; }
    [[nodiscard]] bool OwnsEnrolledCanonicalJournal(const std::wstring& path, const std::wstring& canonical) const
    {
        return !canonical.empty() && journal_path_ == path &&
            canonical_journal_identity_ == canonical && journal_.HasExclusiveWriterLease();
    }
    // Ensures this owner holds the exclusive writer lease for its configured
    // journal (idempotent). Reads, validates, reseeds and mutates nothing;
    // the gate still verifies path, identity, cleanliness and currency, and
    // the commit path opens append handles as before. Refuses while another
    // live owner holds the identity.
    bool AcquireJournalOwnership(std::string& error);
    // Fresh owner only. Acquires ownership and seeds from the original bounded
    // evidence without entering the legacy startup repair or creation path.
    bool OpenStartupJournal(std::wstring path, std::wstring identity, std::string& error);
    // Caller pins every ancestor through authority admission. Empty CREATE_NEW
    // materialization only, for an idle startup owner with no journal debt.
    [[nodiscard]] bool MaterializeAbsentStartupJournal(std::string& error);
    [[nodiscard]] bool MaterializeAbsentProtectedStartupJournal(
        const std::function<bool()>& census_current, std::string& error);
    // Existing native WAL shapes for the explicit backup consumer. Capacity only;
    // role, source, typed staging and publication authority remain with that owner.
    [[nodiscard]] bool ProtectedBackupMutationCapacityAvailable(
        const MutationIntent&, std::string& error);
    [[nodiscard]] bool SnapshotEvidenceCapacityAvailable(const MutationIntent&, std::string& error) const;
    [[nodiscard]] bool NativeSparseEvidenceCapacityAvailable(const MutationIntent&, std::string& error) const;
    [[nodiscard]] bool NativeCloneRangeEvidenceCapacityAvailable(const MutationIntent&, std::string& error) const;
    // Read-only quota check for an idle protected owner and bounded inline
    // preparation. Includes acceptance/durability/cleanup reserve; grants no
    // mutation or recovery authority and materializes no absent journal.
    [[nodiscard]] bool ProtectedAcceptanceCapacityAvailable(
        std::span<const MutationIntent> mutations, std::string& error) const;
    // Caller holds the session journal gate through Begin/payload append/Accept.
    // Sizes one actual typed record plus seven markers without payload I/O.
    // External payloads supply the genuine next sequence and generation; this
    // is a capacity observation, not a reservation or recovery authority.
    [[nodiscard]] bool ProtectedMutationCapacityAvailable(
        const MutationIntent& mutation, std::string& error);
    // Read-only seeding permits a caller to retain its file fence until ownership is acquired.
    void SetJournalPath(std::wstring journal_path, bool acquire_writer_lease = true);
    void SetVolumeIdentity(std::wstring volume_identity);
    // Fresh owner only. The caller supplies trusted source/stream identity and
    // an approved external key directory. Protection and routing cannot change
    // during this owner's lifetime, including after failed recovery admission.
    [[nodiscard]] bool OpenProtectedJournal(std::wstring path, std::wstring identity,
        WriteAheadLog::ProtectedPersistence protection, std::string& error);
    // Fresh protected startup owner. Preserve exact original evidence without
    // repair or absent-file creation, while retaining the authenticated lease.
    [[nodiscard]] bool OpenProtectedStartupJournal(std::wstring path, std::wstring identity,
        WriteAheadLog::ProtectedPersistence protection, std::string& error);
    [[nodiscard]] std::optional<std::array<std::byte, 32>> ProtectedSourceBinding() const noexcept
    { return journal_protection_ ? std::optional{journal_protection_->source_binding} : std::nullopt; }
    [[nodiscard]] std::optional<std::array<std::byte, 32>> ProtectedJournalIdentity() const noexcept
    { return journal_protection_ ? std::optional{journal_protection_->journal_identity} : std::nullopt; }
    // Caller holds the session journal gate for both methods. Capture is a local
    // authenticated fence, not freshness against rollback. Reconciliation accepts
    // no caller refs/floors: complete original history supplies every physical ref
    // and watermark. Retain the expected head outside the rollback domain when
    // required. Idle protected owner only; no compaction/incomplete-history repair.
    [[nodiscard]] bool CaptureProtectedOriginalHistoryHead(
        WriteAheadLog::ProtectedHistoryHead& head, std::string& error);
    [[nodiscard]] PayloadSpool::ProtectedMaintenanceResult ReconcileProtectedPayloadSpool(
        PayloadSpool& spool, const WriteAheadLog::ProtectedHistoryHead& expected_original_head,
        std::string& error);
    [[nodiscard]] bool JournalMatchesVolumeIdentity(const std::wstring& identity) const noexcept
    { return !journal_path_.empty() && volume_identity_ == identity; }
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
    [[nodiscard]] static constexpr std::size_t MaxCachedCheckpointPinBoundaries() noexcept { return 4096; }
    [[nodiscard]] static constexpr std::size_t MaxCachedCheckpointPinEntries() noexcept { return 65536; }
    [[nodiscard]] std::uint64_t NextMutationSequence() const noexcept;
    [[nodiscard]] std::uint64_t LastCommittedSequence() const noexcept;
    [[nodiscard]] DurabilityWatermarks Watermarks() const noexcept;
    [[nodiscard]] bool HasUnappliedAcceptedWork() const noexcept;
    [[nodiscard]] bool RecoveryStateValid() const noexcept;
    [[nodiscard]] bool CanClearRecoveryState() const;
    // Caller holds the journal gate. No replay, reseed, repair or lease acquisition.
    // Zero means that this owner cannot prove its current journal fully cleaned.
    [[nodiscard]] std::uint64_t ValidatedCleanJournalGeneration() const;
    [[nodiscard]] bool LoadUnappliedAcceptedTransactions(
        std::vector<AcceptedTransaction>& transactions,
        std::string* failure_reason = nullptr);
    [[nodiscard]] bool LoadAcceptedTransactionsSinceCleanup(
        std::vector<AcceptedTransaction>& transactions,
        std::string* failure_reason = nullptr,
        WalReadLimits limits = {});
    // Caller holds the journal gate. Startup owner only; retains the same lease,
    // reads original evidence without repair/reseed, and never advances fences.
    // Unavailable means history was pruned, not that pending debt is absent.
    [[nodiscard]] bool LoadRetainedAcceptedHistory(
        RetainedAcceptedHistory& history, std::string& error, WalReadLimits limits = {});
    [[nodiscard]] bool LoadRequiredCheckpointXidsSinceCleanup(
        std::vector<std::uint64_t>& checkpoint_xids,
        std::string* failure_reason = nullptr);
    // Side-effect-free management census; never acquires a writer lease,
    // creates an empty WAL, truncates a torn tail, or changes a watermark.
    [[nodiscard]] static bool InspectAcceptedTransactionsReadOnly(const std::filesystem::path& path,
        const std::string& identity, std::vector<AcceptedTransaction>& transactions,
        DurabilityWatermarks& watermarks, std::string& error);
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
    void InvalidateJournalReadCacheForTest() noexcept;

    // Fault-injection hook used by the planned deterministic crash harness.
    void SetFaultInjectionHook(std::function<void(const std::string& stage)> hook);
    void NotifyStage(const std::string& stage);

private:
    [[nodiscard]] bool OpenProtectedJournalImpl(std::wstring path, std::wstring identity,
        WriteAheadLog::ProtectedPersistence protection, bool preserve_evidence, std::string& error);
    friend class ProtectedJournalContinuation;
    friend class EncryptedPublicationJournal;
    [[nodiscard]] bool ReadAuthorizationDispositionHistory(WriteAheadLog::ProtectedHistoryHead&,
        std::vector<WriteAheadLog::Record>&, std::string& error);
    // Private staging only: authenticates a typed prepared suffix but leaves
    // recovery invalid until its real durable abort closes the original WAL.
    [[nodiscard]] bool SeedAuthorizationPreparedPrefix(
        const std::vector<WriteAheadLog::Record>&, std::uint64_t writer_generation);
    [[nodiscard]] bool AppendAuthorizationAbort(const WriteAheadLog::ProtectedHistoryHead&,
        const WriteAheadLog::Record&, std::string& error);
#ifdef APFSACCESS_PROTECTED_CONTINUATION_TESTING
    friend struct ProtectedContinuationTestAccess;
#endif
    struct ContinuationSeed
    {
        std::uint64_t last_sequence = 0, next_transaction_id = 0;
        DurabilityWatermarks watermarks;
    };
    std::optional<ContinuationSeed> continuation_seed_;
#ifdef APFSACCESS_PROTECTED_TM_SPOOL_TESTING
    friend struct ProtectedSpoolBridgeTestAccess;
#endif
    [[nodiscard]] bool ProtectedSpoolOwnerValid() const;
    [[nodiscard]] bool ReadProtectedOriginalHistory(
        WriteAheadLog::ProtectedHistoryHead& head, std::vector<WriteAheadLog::Record>& records,
        std::string& error);
    bool CollectAcceptedTransactions(const std::vector<WriteAheadLog::Record>& records,
        bool include_checkpointed_transactions, std::vector<AcceptedTransaction>& transactions,
        std::string* failure_reason);
    [[nodiscard]] bool CollectRetainedAcceptedTransactions(
        const std::vector<WriteAheadLog::Record>& records,
        RetainedAcceptedHistory& history, std::string& error) const;
    friend class FusionJournalContinuation;
    [[nodiscard]] bool CaptureFusionOriginalForContinuation(FusionOriginalCapture&, std::string&);
    [[nodiscard]] bool CompactFusionOriginalForContinuation(const FusionCertifiedPredecessor&, std::string&);
    enum class FinalizationCoverageTrust
    {
        Unknown,
        Trusted,
        Poisoned,
    };

    [[nodiscard]] bool PersistTransactionBatchLocked(
        const wchar_t* outcome,
        bool durable_flush = true,
        std::uint64_t preimage_checkpoint_xid = 0);
    [[nodiscard]] bool AppendWatermarkLocked(
        WriteAheadLog::RecordState state,
        std::uint64_t target_sequence);
    [[nodiscard]] bool AppendWalRecordWithCleanup(WriteAheadLog::Record& record, bool durable_flush, std::uint64_t first_sequence_to_keep);
    [[nodiscard]] bool AppendPreparedMutationLocked(MutationIntent& mutation);
    [[nodiscard]] WriteAheadLog::Record BuildTransactionMarkerLocked(
        const wchar_t* outcome,
        const std::string& volume_identity,
        std::uint64_t preimage_checkpoint_xid) const;
    [[nodiscard]] bool IsAcceptedBoundary(std::uint64_t sequence) const noexcept;
    [[nodiscard]] std::uint64_t SafeCompactionFloor(std::uint64_t preferred_floor) const noexcept;
    void ObserveDurableJournalAppend(std::uint64_t elapsed_microseconds) noexcept;
    [[nodiscard]] bool LoadAcceptedTransactionsAfter(
        bool include_checkpointed_transactions,
        std::vector<AcceptedTransaction>& transactions,
        std::string* failure_reason,
        WalReadLimits limits = {});
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
    void InvalidateCheckpointPinCensus() noexcept;
    void AdvanceCheckpointPinCensusGeneration(std::uint64_t before, std::uint64_t after, bool compacted) noexcept;
    void CacheAcceptedCheckpointPins(std::uint64_t sequence, std::vector<std::uint64_t> pins);
    void SeedCheckpointPinCensus(const std::vector<WriteAheadLog::Record>& records, std::uint64_t writer_generation);

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
    std::wstring canonical_journal_identity_;
    std::optional<WriteAheadLog::ProtectedPersistence> journal_protection_;
    bool preserve_startup_evidence_ = false;
    WriteAheadLog journal_;
    std::uint64_t journal_max_bytes_ = 64ull * 1024ull * 1024ull;
    std::uint64_t next_transaction_id_ = 1;
    std::uint64_t next_sequence_ = 1;
    std::uint64_t last_committed_sequence_ = 0;
    std::uint64_t highest_checkpointed_marker_sequence_ = 0;
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
    // Only unresolved boundary XIDs, never mutation or inline payload copies.
    std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> accepted_checkpoint_pins_;
    std::size_t cached_checkpoint_pin_entries_ = 0;
    std::uint64_t checkpoint_pin_census_writer_generation_ = 0;
    bool checkpoint_pin_census_trusted_ = false;
};
} // namespace apfsaccess::rw
