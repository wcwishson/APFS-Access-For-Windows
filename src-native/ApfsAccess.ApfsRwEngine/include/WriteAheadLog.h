#pragma once

#include "UnlinkOutcome.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace apfsaccess::journal { class ProtectedJournalEpoch; }

namespace apfsaccess::rw
{
struct WalReadLimits
{
    std::uint64_t bytes = UINT64_MAX;
    std::size_t records = SIZE_MAX;
};

class WriteAheadLog
{
public:
    static constexpr std::size_t PayloadHashSize = 32;
    static constexpr std::size_t MaxInlinePayloadBytes = 1024u * 1024u;
    static constexpr std::size_t MaxExtendedAttributePayloadBytes = MaxInlinePayloadBytes;
    static constexpr std::size_t MaxExtendedAttributeNameBytes = 821;

    enum class OperationKind : std::uint32_t
    {
        CreateFile = 1,
        CreateDirectory = 2,
        Write = 3,
        SetFileSize = 4,
        Rename = 5,
        Delete = 6,
        SetBasicInfo = 7,
        SetSymbolicLinkTarget = 8,
        RemoveSymbolicLinkTarget = 9,
        SetExtendedAttribute = 10,
        RemoveExtendedAttribute = 11,
        SetInodeMetadata = 12,
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
        TransactionMarker = 100,
        CompactionIndex = 101,
        DurabilityWatermark = 102,
    };

    enum class RecordState : std::uint32_t
    {
        Prepared = 1,
        ApfsApplied = 2,
        Checkpointed = 3,
        Cleaned = 4,
        Accepted = 5,
        PublishArmed = 6,
        CleanupArmed = 7,
    };

    enum class ReadStatus
    {
        Ok,
        IoError,
        Corrupt,
        ChecksumMismatch,
        VersionMismatch,
        VolumeMismatch,
        ResourceLimit,
    };

    enum class AppendResult
    {
        Succeeded,
        RejectedBeforeWrite,
        BytesMayHavePersisted,
    };

    enum class CompactionResult
    {
        Succeeded,
        RejectedBeforeWrite,
        BytesMayHavePersisted,
    };

    using FaultInjectionHook = std::function<bool(std::string_view stage)>;

    // Opt-in only. Caller approves an existing ordinary local recovery/key root
    // outside the APFS provider and supplies exact canonical source/container/
    // volume/generation and journal-stream digests. WAL and spool MUST use
    // separate key directories (the epoch writer lease covers its directory).
    // No inference, migration, plaintext fallback, mixed replay, tail repair,
    // implicit compaction or slot cleanup. Instance readers carry this authority; static
    // legacy/evidence readers cannot decode protected history.
    struct ProtectedPersistence
    {
        std::filesystem::path key_directory;
        std::array<std::byte, 32> source_binding{};
        std::array<std::byte, 32> journal_identity{};
        WalReadLimits read_limits{64ull << 20, 65536};
        std::uint64_t max_allocation_bytes = 256ull << 20;
    };

    struct Options
    {
        std::filesystem::path path;
        std::string volume_identity;
        std::uint64_t max_bytes = 64ull * 1024ull * 1024ull;
        std::optional<ProtectedPersistence> protected_persistence;
    };

    struct Record
    {
        std::string volume_identity;
        std::uint64_t transaction_id = 0;
        std::uint64_t sequence = 0;
        OperationKind operation = OperationKind::Write;
        RecordState state = RecordState::Prepared;
        // Accepted transaction markers store their required preimage checkpoint XID here.
        std::uint64_t object_id = 0;
        std::uint64_t parent_object_id = 0;
        std::uint64_t payload_spool_id = 0;
        std::uint64_t payload_offset = 0;
        std::uint64_t payload_length = 0;
        std::uint64_t logical_offset = 0;
        std::uint64_t logical_length = 0;
        std::uint64_t flags = 0;
        std::array<std::uint8_t, PayloadHashSize> payload_sha256{};
        std::vector<std::byte> inline_payload;
        std::string path_utf8;
        std::string secondary_path_utf8;
        std::optional<UnlinkOutcome> unlink_outcome;
    };

    struct ReadResult
    {
        ReadStatus status = ReadStatus::Ok;
        bool recovered_torn_tail = false;
        std::vector<Record> records;
    };

    // Caller must retain this OUTSIDE the journal rollback domain. Capturing a
    // local head authenticates bytes, not their freshness against valid rollback.
    struct ProtectedHistoryHead
    {
        std::array<std::uint8_t, 32> sha256{};
        std::uint64_t bytes = 0, records = 0, last_sequence = 0;
        bool operator==(const ProtectedHistoryHead&) const = default;
    };
    enum class ProtectedRecoveryChoice { RetainOriginal, PromoteReplacement };

    // Capture authenticates a readable head; it does not establish durability.
    [[nodiscard]] bool CaptureProtectedHistoryHead(ProtectedHistoryHead&) const;
    [[nodiscard]] ReadResult ReadAllAtProtectedHead(const ProtectedHistoryHead&) const;
    // Whole-transaction retention: preserve progressed/accepted/marker/watermark
    // transactions, floor-crossing transactions and original ID bounds. Only
    // wholly Prepared transactions below the caller-authorized floor can leave
    // canonical history. Original encrypted history/keys are retained, not deleted.
    // Flushes the authenticated original handle before any replacement resealing.
    [[nodiscard]] CompactionResult CompactProtectedWithResult(std::uint64_t floor,
        const ProtectedHistoryHead& expected, ProtectedHistoryHead& replacement,
        std::uint64_t expected_writer_generation = 0) const;
    // Explicit old/new recovery only. RetainOriginal preserves a reserved pending
    // candidate in quarantine and cannot roll an already-published replacement back.
    // An original canonical file is flushed before namespace changes or success,
    // including RetainOriginal with no pending candidate and no changes to make.
    [[nodiscard]] CompactionResult RecoverProtectedCompaction(const ProtectedHistoryHead& previous,
        std::uint64_t floor, ProtectedRecoveryChoice, ProtectedHistoryHead& recovered) const;

    struct Counters
    {
        std::uint64_t append_handle_open_count = 0;
        std::uint64_t append_handle_flush_count = 0;
    };

    explicit WriteAheadLog(Options options);
    ~WriteAheadLog();

    WriteAheadLog(const WriteAheadLog&) = delete;
    WriteAheadLog& operator=(const WriteAheadLog&) = delete;

    void Reconfigure(Options options);

    // Existing canonical file only. No creation, truncation, compaction or receipt cleanup.
    // Used before command inspection; retains the real writer handle until destruction.
    [[nodiscard]] bool AcquireExistingRepairLease(std::string& error) const;
    // Retains writer ownership before bounded startup inspection. Never creates,
    // repairs, truncates or cleans evidence; a missing journal stays missing.
    // Subsequent history reads on this owner keep this preservation policy.
    [[nodiscard]] ReadResult ReadStartupEvidence(WalReadLimits limits,
        std::uint64_t max_allocation_bytes) const;
    // Caller pins all existing ancestors. Creates only an originally absent
    // canonical file with CREATE_NEW, retains its handle, and writes no records.
    [[nodiscard]] bool MaterializeAbsentStartupJournal() const;
    // Protected startup only, after the caller's complete source/ancestor census.
    // The callback checks held source/path evidence only; it must not call WAL/TM.
    [[nodiscard]] bool MaterializeAbsentProtectedStartupJournal(
        const std::function<bool()>& census_current) const;
    // Ensures only the exclusive writer lease (named-pipe mutual exclusion).
    // Reads, validates, opens handles, reseeds and mutates nothing else.
    [[nodiscard]] bool AcquireWriterLeaseOnly() const { return EnsureWriterLease(); }
    [[nodiscard]] bool AcquireExclusiveWriterLease() const;
    [[nodiscard]] bool Append(const Record& record, bool durable_flush = true) const;
    [[nodiscard]] bool AppendBatch(const std::vector<Record>& records, bool durable_flush = true) const;
    [[nodiscard]] AppendResult AppendWithResult(
        const Record& record,
        bool durable_flush = true,
        std::uint64_t expected_writer_generation = 0) const;
    [[nodiscard]] AppendResult AppendBatchWithResult(
        const std::vector<Record>& records,
        bool durable_flush = true,
        std::uint64_t expected_writer_generation = 0) const;
    [[nodiscard]] bool FlushPendingAppends() const;
    [[nodiscard]] bool Compact(std::uint64_t minimum_sequence_to_keep) const;
    [[nodiscard]] CompactionResult CompactWithResult(
        std::uint64_t minimum_sequence_to_keep,
        std::uint64_t expected_writer_generation = 0) const;
    [[nodiscard]] ReadResult ReadAll() const;
    [[nodiscard]] ReadResult ReadAllWithExclusiveWriterLease(WalReadLimits limits = {}) const;

    [[nodiscard]] static ReadResult ReadAll(
        const std::filesystem::path& path,
        const std::string& expected_volume_identity);
    // Caller retains a synchronous, read-only file handle that excludes deletion.
    // Evidence only: finite budgets, no path reopen, repair or partial history.
    [[nodiscard]] static ReadResult ReadAllEvidenceFromHeldHandle(
        void* handle,
        const std::string& expected_volume_identity,
        WalReadLimits limits,
        std::uint64_t max_allocation_bytes);
    // Caller holds its journal gate. Includes future acceptance/completion
    // records in the same byte/allocation budget used by evidence decoding.
    [[nodiscard]] bool EvidenceAppendCapacityAvailable(const std::vector<Record>&,
        WalReadLimits, std::uint64_t max_allocation_bytes) const;
    [[nodiscard]] static std::vector<std::uint8_t> EncodeForTest(
        const Record& record,
        std::uint16_t version_override = 0);
    [[nodiscard]] static bool InlinePayloadIsConsistent(const Record& record);
    [[nodiscard]] static bool InodeMetadataMutationIsConsistent(const Record& record);
    [[nodiscard]] static bool AllocationSizeMutationIsConsistent(const Record& record);
    [[nodiscard]] static bool DirectoryRestoreMutationIsConsistent(const Record& record);
    [[nodiscard]] static bool NativeCloneIsConsistent(const Record& record);
    [[nodiscard]] static bool NativeHardLinkIsConsistent(const Record& record);
    [[nodiscard]] static bool NativeSparseIsConsistent(const Record& record);
    [[nodiscard]] static bool NativeCloneRangeIsConsistent(const Record& record);
    [[nodiscard]] static bool SnapshotIntentIsConsistent(const Record& record);
    [[nodiscard]] static bool VolumeRenameIsConsistent(const Record& record);
    [[nodiscard]] static bool CountRepairIsConsistent(const Record& record);
    [[nodiscard]] static bool VolumeQuotaReserveIsConsistent(const Record& record);
    [[nodiscard]] static bool CompressionRewriteIsConsistent(const Record& record);
    [[nodiscard]] static bool ExtendedAttributeMutationIsConsistent(const Record& record);
    [[nodiscard]] static bool UnlinkOutcomeIsConsistent(const Record& record);
    [[nodiscard]] Counters SnapshotCounters() const;
    [[nodiscard]] bool HasExclusiveWriterLease() const;
    [[nodiscard]] std::uint64_t ExclusiveWriterLeaseGeneration() const;
    // Both modes are read-only. Evidence mode adds finite receipt decoding
    // budgets and accepts only the original fully completed compaction proof.
    [[nodiscard]] std::uint64_t ValidatedAppendLeaseGeneration(
        bool bounded_evidence = false) const;
    void SetFaultInjectionHook(FaultInjectionHook hook);

private:
    friend class FusionJournalContinuation;
    friend class TransactionManager;
    [[nodiscard]] bool CaptureFusionOriginalForContinuation(class FusionOriginalCapture&) const;
    [[nodiscard]] bool MatchesFusionOriginalForContinuation(const class FusionOriginalCapture&) const;
    [[nodiscard]] static ReadResult DecodeFusionOriginalForContinuation(const std::vector<std::uint8_t>&, const std::string&);
    [[nodiscard]] bool ValidateFusionReplacementReceipt(const class FusionOriginalCapture&, const class FusionOriginalCapture&) const;
    [[nodiscard]] bool InspectFusionCompactionRecovery(class FusionOriginalCapture&) const;
    [[nodiscard]] bool RecoverFusionCompaction(const class FusionCertifiedPredecessor&) const;
    [[nodiscard]] CompactionResult CompactOrdinaryWithResult(std::uint64_t,
        std::uint64_t, const class FusionCertifiedPredecessor*) const;
    friend class EncryptedPublicationJournal;
    friend class ProtectedJournalContinuation;
    [[nodiscard]] bool VerifyProtectedHistoryPrefix(const ProtectedHistoryHead&) const;
    [[nodiscard]] bool ProtectedAppendCapacityAvailable(std::span<const Record>) const;
    [[nodiscard]] static bool DecodeCertifiedOriginalRecord(std::span<const std::uint8_t>,
        const std::string& identity, Record&);
#ifdef APFSACCESS_PROTECTED_CONTINUATION_TESTING
    friend struct ProtectedContinuationTestAccess;
#endif
    struct ContinuationAdmission
    {
        std::array<std::byte, 192> anchor{};
        std::uint64_t last_sequence = 0;
        std::vector<std::wstring> immutable_siblings;
        std::function<bool()> validate_authority;
    };
    [[nodiscard]] bool SealContinuationAnchor(const ContinuationAdmission&,
        journal::ProtectedJournalEpoch&, std::vector<std::uint8_t>&) const;
    [[nodiscard]] bool SealContinuationRecords(const ContinuationAdmission&, std::span<const Record>,
        journal::ProtectedJournalEpoch&, std::vector<std::uint8_t>&) const;
    [[nodiscard]] ReadResult DecodeContinuationEvidence(std::span<const std::uint8_t>,
        const std::optional<ContinuationAdmission>&, ProtectedHistoryHead&) const;
    [[nodiscard]] bool InstallContinuationAdmission(const ContinuationAdmission&,
        std::shared_ptr<void> retained_authority) const;
#ifdef APFSACCESS_DERIVED_WITNESS_TESTING
    friend struct DerivedWitnessResetTestAccess;
#endif
    // Minted only by the typed journal from its live original v4 acceptance,
    // including already-durable/not-cleaned work. Neither a damaged suffix nor
    // an authenticated reset receipt supplies this authority on restart.
    struct DerivedWitnessResetAuthority
    {
        std::array<std::byte, 32> source_binding{}, original_journal_identity{}, scope_binding{};
        std::uint64_t accepted_sequence = 0, transaction_id = 0, preimage_xid = 0, inode = 0;
        std::uint64_t template_bytes = 0, body_bytes = 0, authorization_bytes = 0;
        std::array<std::uint8_t, 32> template_sha256{}, body_sha256{}, authorization_sha256{};
    };
    using DerivedWitnessAuthorizer = std::function<bool(std::span<const Record>, DerivedWitnessResetAuthority&)>;
    // Candidate records grant no authority. The authorizer receives ONLY the
    // held old witness's authenticated prefix, including a complete selected
    // v4 certificate chunk; it matches that private authorization to the exact
    // original acceptance before minting authority. No certificate => refusal.
    // Records use sequences 1..N. The barrier revalidates/flushes the acceptance.
    // No target access. Initial profile: proper final-frame EOF fragments only;
    // no incomplete anchor, full-length bad tag, original-WAL or spool repair.
    [[nodiscard]] CompactionResult RebuildDerivedWitnessV4(
        std::span<const Record> regenerated_records,
        const DerivedWitnessAuthorizer& authorize_existing_prefix,
        const std::function<bool()>& flush_original_acceptance,
        ProtectedHistoryHead& replacement) const;
    [[nodiscard]] CompactionResult RebuildDerivedWitnessV8(
        std::span<const Record> regenerated_records,
        const DerivedWitnessAuthorizer& authorize_existing_prefix,
        const std::function<bool()>& flush_original_acceptance,
        ProtectedHistoryHead& replacement) const;
    [[nodiscard]] CompactionResult RebuildDerivedWitness(
        std::uint64_t expected_body_version, std::span<const Record>,
        const DerivedWitnessAuthorizer&, const std::function<bool()>&,
        ProtectedHistoryHead&) const;
    struct ProtectedState;
    [[nodiscard]] bool EnsureProtectedState() const;
    [[nodiscard]] bool EnsureProtectedState(bool allow_pending) const;
    [[nodiscard]] bool ProtectedMaintenanceAbsent() const;
    [[nodiscard]] bool EnsureProtectedAppendHandle(bool allow_create) const;
    [[nodiscard]] ReadResult ReadProtected(WalReadLimits limits,
        std::uint64_t allocation, bool retain_writer) const;
    [[nodiscard]] AppendResult AppendProtected(std::span<const Record> records,
        bool durable_flush, std::uint64_t expected_writer_generation) const;
    enum class StartupJournalState { Unobserved, Absent, Present, Materialized };
    enum class EncodedAppendResult
    {
        Succeeded,
        RejectedBeforeWrite,
        BytesMayHavePersisted,
    };

    [[nodiscard]] bool EnsureAppendHandle(
        bool resolve_compaction_intent = true,
        bool allow_create = true) const;
    [[nodiscard]] bool EnsureWriterLease() const;
    [[nodiscard]] bool EnsureWriterLease(bool allow_protected_maintenance) const;
    [[nodiscard]] bool StartupCompactionNamespaceIsProven() const;
    [[nodiscard]] bool CloseAppendFileHandle() const noexcept;
    [[nodiscard]] bool CloseWriterLeaseHandle() const noexcept;
    [[nodiscard]] bool CloseAppendHandle() const noexcept;
    [[nodiscard]] bool PersistCompactionIntent(
        std::uint32_t volume_serial,
        std::uint64_t file_id,
        RecordState state = RecordState::Prepared,
        std::uint64_t replacement_file_id = 0,
        bool* bytes_may_have_persisted = nullptr,
        bool namespace_durable = false) const;
    [[nodiscard]] bool ReadLatestCompactionIntent(
        void* intent_handle,
        std::uint32_t intent_volume_serial,
        std::uint64_t intent_file_id,
        Record& latest_intent) const;
    [[nodiscard]] bool DeleteRetainedCompactionTemp(
        std::uint32_t volume_serial,
        std::uint64_t replacement_file_id) const;
    [[nodiscard]] bool CleanupPreIntentCompactionOrphans() const;
    [[nodiscard]] bool DeleteCompletedCompactionPredecessorTombstone(
        std::uint32_t volume_serial,
        std::uint64_t predecessor_file_id) const;
    [[nodiscard]] bool ClearCompletedCompactionIntentForNewCompaction() const;
    [[nodiscard]] bool RestoreMissingCanonicalForPublishArmedIntent() const;
    [[nodiscard]] bool ResolvePendingCompactionIntent() const;
    [[nodiscard]] bool ClearCompactionIntent(
        const Record& intent,
        std::uint32_t intent_volume_serial,
        std::uint64_t intent_file_id) const;
    [[nodiscard]] bool TruncateAppendHandle(std::uint64_t complete_prefix_bytes) const;
    [[nodiscard]] bool FlushAppendHandle() const;
    [[nodiscard]] EncodedAppendResult AppendEncoded(const std::vector<std::uint8_t>& encoded) const;
    void RegisterPath();
    void UnregisterPath() noexcept;
    [[nodiscard]] bool AnotherStartupEvidenceOwnerForPath() const;
    [[nodiscard]] static bool TryTransferRegisteredHandlesForPath(
        const std::filesystem::path& path,
        const WriteAheadLog* successor);
    [[nodiscard]] static ReadResult ReadAllInternal(
        const std::filesystem::path& path,
        const std::string& expected_volume_identity,
        bool repair_torn_tail,
        std::uint64_t* complete_prefix_bytes,
        WalReadLimits limits = {});

    Options options_;
    mutable std::optional<ContinuationAdmission> continuation_admission_;
    mutable std::shared_ptr<void> continuation_authority_;
    mutable std::unique_ptr<ProtectedState> protected_state_;
    mutable void* append_handle_ = nullptr;
    mutable void* writer_lease_handle_ = nullptr;
    mutable std::wstring writer_lease_name_;
    mutable std::uint64_t append_handle_size_ = 0;
    mutable bool append_handle_size_known_ = false;
    mutable std::uint64_t append_handle_open_count_ = 0;
    mutable std::uint64_t append_handle_flush_count_ = 0;
    mutable std::uint64_t writer_lease_generation_ = 0;
    mutable bool preserve_startup_evidence_ = false;
    mutable StartupJournalState startup_journal_state_ = StartupJournalState::Unobserved;
    mutable std::uint64_t startup_writer_lease_generation_ = 0;
    mutable bool startup_evidence_valid_ = false;
    FaultInjectionHook fault_injection_hook_;
    std::wstring registered_path_;
};
} // namespace apfsaccess::rw
