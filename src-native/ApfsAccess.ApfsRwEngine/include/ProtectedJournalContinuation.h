#pragma once

#include "WriteAheadLog.h"

#include <array>
#include <functional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace apfsaccess::catalog { class ApfsEncryptedImageWriteSession; class EncryptedImageRuntime; }

namespace apfsaccess::rw
{
class TransactionManager;
class PayloadSpool;

// Finite all-clean continuation of the original and publication-witness streams.
// This file protocol has no image/device opener. Only the held image owner can
// construct Endpoint; only the typed publication journal can mint Authority.
// Ordinary startup cannot import records, seeds, advisory refs or certificates.
class ProtectedJournalContinuation final
{
public:
    enum class Result { Succeeded, RejectedBeforeWrite, RecoveryRequired };
    using StageHook = std::function<bool(std::string_view)>;
    using Digest = std::array<std::uint8_t, 32>;
    using Binding = std::array<std::byte, 32>;

    enum class DurableBoundary : std::uint8_t
    {
        OriginalSpoolBarrier, IntentFlushed, RecoveryBarrier, ControlRenamed,
        CertificatePromoted, CandidateFlushed, OldRenamed, NewRenamed,
        CompletionReceipt, RetirementReceipt, ReadyReceipt
    };
    // Borrowed only during a completed protocol barrier. Diagnostic stage
    // strings and callers cannot construct or retain a copy of this proof.
    class DurableProgress final
    {
    public:
        DurableProgress(const DurableProgress&) = delete;
        DurableProgress(DurableProgress&&) = delete;
        DurableProgress& operator=(const DurableProgress&) = delete;
        DurableProgress& operator=(DurableProgress&&) = delete;
        [[nodiscard]] DurableBoundary Boundary() const noexcept { return boundary_; }
        [[nodiscard]] std::uint8_t Index() const noexcept { return index_; }
        [[nodiscard]] std::uint8_t Slot() const noexcept { return slot_; }
        [[nodiscard]] std::uint8_t Ordinal() const noexcept { return ordinal_; }
    private:
        friend class ProtectedJournalContinuation;
        DurableProgress(DurableBoundary boundary, std::uint8_t index, std::uint8_t slot, std::uint8_t ordinal)
            : boundary_(boundary), index_(index), slot_(slot), ordinal_(ordinal) {}
        DurableBoundary boundary_;
        std::uint8_t index_, slot_, ordinal_;
    };
    using ProgressHook = std::function<bool(const DurableProgress&)>;

    class Endpoint final
    {
    public:
        Endpoint(Endpoint&&) noexcept = default;
        Endpoint& operator=(Endpoint&&) noexcept = default;
        Endpoint(const Endpoint&) = delete;
        Endpoint& operator=(const Endpoint&) = delete;
        ~Endpoint() = default;
    private:
        friend class apfsaccess::catalog::ApfsEncryptedImageWriteSession;
        friend class EncryptedPublicationJournal;
        friend class ProtectedJournalContinuation;
#ifdef APFSACCESS_AUTHORIZATION_DISPOSITION_TESTING
        friend struct AuthorizationDispositionTestAccess;
#endif
#ifdef APFSACCESS_PROTECTED_CONTINUATION_TESTING
        friend struct ProtectedContinuationTestAccess;
#endif
        struct Description
        {
            Binding source_binding{};
            std::string source_identity, container_uuid, volume_uuid;
            std::uint64_t container_bytes = 0, volume_object_id = 0, checkpoint_xid = 0;
            // Byte offset relative to the held container source (not a disk
            // address). Exact selected NX bytes, bounded to 64 KiB by protocol.
            std::uint64_t physical_nx_offset = 0;
            std::vector<std::byte> physical_nx_bytes;
            Digest physical_nx_sha256{};
        };
        // Both callbacks borrow only the same held owner/source. Root must keep
        // its owner gate, shared I/O lifetime and cancellation guard alive for
        // every synchronous use. Revalidation checks the exact raw selection;
        // read_guard reads bounded source-relative planned/guard bytes. Neither
        // grants arbitrary public target access or asserts journal cleanliness.
        using Revalidate = std::function<bool(std::string&)>;
        using ReadGuard = std::function<bool(std::uint64_t, std::span<std::byte>, std::string&)>;
        Endpoint(Description description, Revalidate revalidate, ReadGuard read_guard)
            : description_(std::move(description)), revalidate_(std::move(revalidate)),
              read_guard_(std::move(read_guard)) {}
        Description description_;
        Revalidate revalidate_;
        ReadGuard read_guard_;
    };

private:
    friend class EncryptedPublicationJournal;
#ifdef APFSACCESS_PROTECTED_CONTINUATION_TESTING
    friend struct ProtectedContinuationTestAccess;
#endif
    struct Seed
    {
        std::uint64_t last_sequence = 0, next_transaction_id = 0;
        std::uint64_t accepted_sequence = 0, durable_sequence = 0, cleanup_sequence = 0;
    };
    // Construct AFTER matching every complete authenticated original/witness
    // group and the last publication's planned/guard bytes to Endpoint. The
    // protocol independently checks actual heads, source/stream options, TM
    // all-clean state and complete original-derived spool reconciliation.
    // This is private authority, not an "all durable" flag or history importer.
    struct Authority
    {
        struct RetainedAuthorization
        {
            RetainedAuthorization() = default;
            RetainedAuthorization(const RetainedAuthorization&) = default;
            RetainedAuthorization(RetainedAuthorization&&) noexcept = default;
            RetainedAuthorization& operator=(const RetainedAuthorization&);
            RetainedAuthorization& operator=(RetainedAuthorization&&) noexcept;
            ~RetainedAuthorization();
            void Swap(RetainedAuthorization&) noexcept;
            std::uint64_t version = 0, accepted = 0, transaction = 0;
            bool spent = false;
            Digest body_sha256{}, intent_sha256{}, receipt_sha256{};
            // Exact existing WAL encodings, authenticated before capture. Only
            // accepted v6 needs original rows; spent v4/v6 keeps its receipt.
            std::vector<std::vector<std::uint8_t>> original_records;
            std::vector<std::uint64_t> witness_sequences;
        };
        std::vector<RetainedAuthorization> retained_authorizations;
        Binding source_binding{}, original_journal_identity{}, witness_journal_identity{}, scope_binding{};
        WriteAheadLog::ProtectedHistoryHead original_head, witness_head;
        Seed original_seed;
        std::uint64_t witness_last_sequence = 0, witness_retained_first_sequence = 0, checkpoint_xid = 0;
        Digest complete_publication_sha256{}, planned_guard_sha256{};
        // Journal repeats the complete original/witness/endpoint correspondence
        // and unconditional original acceptance barrier under its owner gate.
        // A missing/failing callback cannot authorize any namespace mutation.
        std::function<bool(std::string&)> flush_and_recheck;
    };
    struct RecoveryEvidence
    {
        // All fields/records originate in bounded authenticated held files.
        // Pending recovery supplies the retained predecessor histories. A
        // completed generation supplies the active histories and certified seed.
        Authority certificate_authority;
        Endpoint::Description certified_endpoint;
        Seed active_original_seed;
        std::uint64_t active_witness_sequence = 0, generation = 0;
        bool pending = false;
        bool admission_only = false;
        WriteAheadLog::ProtectedHistoryHead original_head, witness_head;
        WriteAheadLog::ReadResult original, witness;
        Digest certificate_sha256{};
    };
    using RecoveryAuthorizer = std::function<bool(const RecoveryEvidence&, Authority&, std::string&)>;
    struct Operation;

    // Names and signatures used by Root's private Journal integration. Options
    // are trusted frozen configuration only, never records/heads/proof inputs.
    using OriginalDescriptor = WriteAheadLog::Options;
    [[nodiscard]] static bool CaptureOriginalSeed(const TransactionManager&, Seed&, std::string& error);
    [[nodiscard]] static bool FlushCleanOriginalEvidence(TransactionManager&, const WriteAheadLog::ProtectedHistoryHead&,
        std::uint64_t cleanup_sequence, std::string& error);
    [[nodiscard]] static bool CaptureEvidence(TransactionManager&, WriteAheadLog&, RecoveryEvidence&, std::string& error);
    [[nodiscard]] static bool ValidateOriginalEvidence(const RecoveryEvidence&, Seed&, std::string& error);
    [[nodiscard]] static OriginalDescriptor OriginalOptions(const TransactionManager&);
    [[nodiscard]] static bool ReadRetainedAuthorization(const TransactionManager&, std::uint64_t accepted,
        const Digest& body_sha256, std::optional<Authority::RetainedAuthorization>&, std::string& error);
    [[nodiscard]] static Result Continue(TransactionManager& original, PayloadSpool& spool,
        WriteAheadLog& witness, const Authority&, Endpoint&, std::string& error,
        const StageHook& hook = {});
    [[nodiscard]] static Result Continue(TransactionManager& original, PayloadSpool& spool,
        WriteAheadLog& witness, const Authority&, Endpoint&, std::string& error,
        const StageHook&, const ProgressHook&);
    [[nodiscard]] static Result Recover(TransactionManager& fresh_original, const OriginalDescriptor&, PayloadSpool& spool,
        WriteAheadLog& witness, const Authority&, Endpoint&, std::string& error,
        const StageHook& hook = {});
    [[nodiscard]] static Result Recover(TransactionManager& fresh_original, const OriginalDescriptor&, PayloadSpool& spool,
        WriteAheadLog& witness, const Authority&, Endpoint&, std::string& error,
        const StageHook&, const ProgressHook&);
    // Fresh owner pre-open path. Root's Journal validates the authenticated
    // certificate baseline AND the actual active/pending histories against the
    // held endpoint before minting authority. No ordinary startup bypass exists.
    [[nodiscard]] static Result OpenOrRecover(TransactionManager& fresh_original,
        const OriginalDescriptor&, PayloadSpool&, WriteAheadLog& witness, Endpoint&,
        const RecoveryAuthorizer&, std::string& error, const StageHook& hook = {});
    [[nodiscard]] static Result OpenOrRecover(TransactionManager& fresh_original,
        const OriginalDescriptor&, PayloadSpool&, WriteAheadLog& witness, Endpoint&,
        const RecoveryAuthorizer&, std::string& error, const StageHook&, const ProgressHook&);
};
} // namespace apfsaccess::rw
