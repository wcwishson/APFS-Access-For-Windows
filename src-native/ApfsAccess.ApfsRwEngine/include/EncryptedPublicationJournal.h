#pragma once

#include "ApfsEncryptedCowOverwrite.h"
#include "ApfsSoftwareKeybagPublication.h"
#include "SoftwareVolumeTransition.h"
#include "SoftwareVolumeKeyRotation.h"
#include "TransactionManager.h"
#include "ProtectedJournalContinuation.h"
#include <memory>
#include <string_view>
#include <utility>

namespace apfsaccess::rw
{
// The owner obtains this binding from its held exact file/device identity, never
// from the recovery record. The same exclusive target spans replay and flushes.
class EncryptedPublicationTarget : public AppleCheckpointWriteTarget
{
public:
    virtual std::array<std::byte, 32> SourceBinding() const noexcept = 0;
};

// Persists the exact ciphertext publication prepared by the encrypted session.
// This is a separate protected stream: its records are publication witnesses,
// not user mutations, and must never be replayed through MetadataStore. The
// caller holds the container commit/journal gate across every method.
class EncryptedPublicationJournal final
{
public:
    enum class AcceptedDataRecovery { CompleteWitness, TypedReprepareAllowed };
    struct Options
    {
        WriteAheadLog::Options witness;
        std::uint64_t container_bytes = 0;
        std::string container_uuid;
        std::string preimage_source_identity;
        std::uint64_t volume_object_id = 0;
        std::string volume_uuid;
        // Required only for maintenance v4; supplied from the owner's original
        // protected WAL configuration, never from recovered bytes.
        std::array<std::byte, 32> maintenance_original_journal_identity{};
    };
    explicit EncryptedPublicationJournal(Options options);
    ~EncryptedPublicationJournal();
    EncryptedPublicationJournal(const EncryptedPublicationJournal&) = delete;
    EncryptedPublicationJournal& operator=(const EncryptedPublicationJournal&) = delete;

    // Private protected-stream contract, never replayed through MetadataStore:
    // Write uses the ordinary offset/length/payload fields. Spool generations
    // bind to the exact preimage checkpoint XID; inline Write also permits zero.
    // CreateFile binds
    // generation to parent, offset to permissions, and path to the leaf name.
    // SetFileSize uses length for EOF. Rename binds generation/offset to source/
    // destination parents and path/secondary_path to their leaf names. Delete
    // binds generation/path to its parent/name. Non-payload records have zero
    // payload fields; ReplaceRename alone permits exact replace flag 0x4;
    // every operation forbids unlink outcomes.
    // MakeDirectory uses CreateDirectory with parent/name/permissions, length
    // zero and no payload. SetInodeMetadata uses its existing canonical inline
    // codec, exact preimage generation, zero logical/spool fields, and exact
    // payload length/SHA. Its private namespace parent remains zero.
    // Set/RemoveExtendedAttribute bind the raw attribute name in secondary_path,
    // exact preimage generation and zero logical/spool fields. Set carries the
    // canonical inline bytes/SHA, including an empty value; Remove carries no
    // payload. Their private witness version 7 binds the observed name hash.
    // The accepted operation must match the privately captured intent exactly.
    // No APFS writes occur until this witness has been durably appended.
    bool Stage(TransactionManager& transactions, std::uint64_t accepted_sequence,
        const catalog::EncryptedCowOverwrite& prepared, std::string& error);
    // Capacity and complete-history check before original acceptance. This
    // reserves nothing and grants no publication authority; Stage revalidates
    // the actual accepted boundary under the same owner gate.
    bool DataCapacityAvailable(TransactionManager&, const catalog::EncryptedCowOverwrite&,
        std::string& error);
    // Classify under the original container/journal gate. A missing selected
    // witness permits only exact typed-intent reprepare with an unlocked owner;
    // incomplete/corrupt evidence and opaque maintenance requests refuse.
    bool InspectAcceptedDataRecovery(TransactionManager&, std::uint64_t accepted_sequence,
        AcceptedDataRecovery&, std::string& error);
    bool RestageData(TransactionManager&, std::uint64_t accepted_sequence,
        const catalog::EncryptedCowOverwrite& prepared, std::string& error);
    // Capture before original acceptance. The records overload splits the exact
    // ciphertext intent into bounded inline protected WAL chunks. Record and
    // FlushPreparedRecords incrementally before Accept(preimage XID) so no large
    // batch requires a large locked buffer. Never replay this private stream
    // through MetadataStore. Neither password nor plaintext key enters the blob.
    static constexpr std::wstring_view MaintenanceAcceptancePath = L"\\$apfs-keybag-rewrap-v2";
    bool BuildMaintenanceAcceptance(const catalog::SoftwareKeybagPublication& prepared,
        std::vector<std::byte>& ciphertext_intent, std::string& error) const;
    bool BuildMaintenanceAcceptanceRecords(const catalog::SoftwareKeybagPublication& prepared,
        std::vector<TransactionManager::MutationIntent>& records, std::string& error) const;
    // The private capability authorizes a durable complete witness BEFORE the
    // original WAL acceptance. Preview records alone grant no recovery rights.
    // The caller holds its original journal/container gate for the entire call.
    bool AcceptMaintenance(TransactionManager& transactions,
        const catalog::SoftwareKeybagPublication& prepared, std::uint64_t& accepted_sequence,
        std::string& error);
    bool StageMaintenance(TransactionManager& transactions, std::uint64_t accepted_sequence,
        const catalog::SoftwareKeybagPublication& prepared, std::string& error);
    // The caller recovers these bytes using the original authenticated WAL
    // reference, never a sidecar or a newly prepared password change. Exact
    // matching durable private authorization is required. Raw accepted bytes
    // alone cannot mint a plan or substitute for a missing authorization.
    bool RestageMaintenance(TransactionManager& transactions, std::uint64_t accepted_sequence,
        std::span<const std::byte> original_ciphertext_intent, std::string& error);
    bool RestageMaintenance(TransactionManager& transactions, std::uint64_t accepted_sequence,
        std::string& error);
    // Version 6 is a separate private transition purpose. Decryption plans may
    // contain intended plaintext; every original/witness record stays protected.
    static constexpr std::wstring_view TransitionAcceptancePath = L"\\$apfs-software-transition-v1";
    bool AcceptTransition(TransactionManager&, const catalog::SoftwareVolumeTransitionPublication&,
        std::uint64_t& accepted_sequence, std::string& error);
    bool StageTransition(TransactionManager&, std::uint64_t accepted_sequence,
        const catalog::SoftwareVolumeTransitionPublication&, std::string& error);
    bool RestageTransition(TransactionManager&, std::uint64_t accepted_sequence, std::string& error);
    static constexpr std::wstring_view KeyRotationAcceptancePath = L"\\$apfs-software-key-rotation-v1";
    bool AcceptKeyRotation(TransactionManager&, const catalog::SoftwareVolumeKeyRotationPublication&,
        std::uint64_t& accepted_sequence, std::string& error);
    bool StageKeyRotation(TransactionManager&, std::uint64_t accepted_sequence,
        const catalog::SoftwareVolumeKeyRotationPublication&, std::string& error);
    bool RestageKeyRotation(TransactionManager&, std::uint64_t accepted_sequence, std::string& error);
    bool TryRestoreTransitionRetainedOwners(TransactionManager&, const catalog::ImmutableEncryptedReadSource& exact_held_source,
        std::unique_ptr<const catalog::SoftwareVolumeRetainedOwners>& restored, std::string& error);
    std::unique_ptr<const catalog::SoftwareVolumeRetainedOwners> RestoreTransitionRetainedOwners(
        TransactionManager&, const catalog::ImmutableEncryptedReadSource& exact_held_source, std::string& error);
    // Restores only an earlier cleaned v6 exclusion certificate while one exact
    // accepted ordinary plain Write awaits normal native replay. Grants no
    // data publication authority and never admits a pending private sentinel.
    std::unique_ptr<const catalog::SoftwareVolumeRetainedOwners> RestoreTransitionRetainedOwnersForPlainReplay(
        TransactionManager&, const catalog::ImmutableEncryptedReadSource& exact_held_source,
        std::uint64_t accepted_write_sequence, std::string& error);
    // Exact authenticated ordinary data intent at its current encrypted preimage.
    // Restores exclusions only; data replay still needs fresh private preparation.
    std::unique_ptr<const catalog::SoftwareVolumeRetainedOwners> RestoreTransitionRetainedOwnersForEncryptedReplay(
        TransactionManager&, const catalog::ImmutableEncryptedReadSource& exact_held_source,
        std::uint64_t accepted_data_sequence, std::string& error);
    bool TryRestoreTransitionRetainedOwnersForEncryptedReplay(TransactionManager&,
        const catalog::ImmutableEncryptedReadSource& exact_held_source, std::uint64_t accepted_data_sequence,
        std::unique_ptr<const catalog::SoftwareVolumeRetainedOwners>&, std::string& error);
    // Reopens the original accepted boundary, proves pre/post-switch state and
    // exact block bytes, flushes, then advances the original durable watermark.
    // Cleanup remains the owner's separate responsibility.
    bool PublishOrRecover(TransactionManager& transactions, std::uint64_t accepted_sequence,
        EncryptedPublicationTarget& target, std::string& error,
        const AppleCheckpointStageHook& stage_hook = {});
    void SetWitnessFaultInjectionHook(WriteAheadLog::FaultInjectionHook hook)
    { witness_.SetFaultInjectionHook(std::move(hook)); }

private:
    Options options_;
    WriteAheadLog witness_;
    bool poisoned_ = false;
    std::shared_ptr<void> transition_pristine_ancestry_;
    bool AppendWitness(std::uint64_t accepted_sequence, std::span<const std::byte> encoded,
        std::string& error, bool resume = false, TransactionManager* original = nullptr);
    bool ConfirmMaintenanceAuthorization(std::span<const std::byte> encoded, std::string& error);
    bool RebuildMaintenanceAuthorization(TransactionManager&, std::span<const std::byte> encoded,
        std::string& error);
    bool RebuildPrivateAuthorization(TransactionManager&, std::span<const std::byte>,
        std::uint64_t expected_version, std::string& error);
    bool ConfirmTransitionAuthorization(std::span<const std::byte>, std::string& error);
    bool KeyManagementEndpointClean(TransactionManager&, std::string& error);
    bool AcceptRetainedRewrite(TransactionManager&, std::span<const std::byte> private_template,
        std::uint64_t& accepted, std::string& error);
    bool StageRetainedRewrite(TransactionManager&, std::uint64_t accepted,
        std::span<const std::byte> private_template, std::string& error);
    bool RestageRetainedRewrite(TransactionManager&, std::uint64_t accepted,
        std::uint64_t expected_version, std::string& error);
    enum class RetainedReplayPurpose { PlainWrite, EncryptedData };
    bool TryRestoreTransitionRetainedOwnersImpl(TransactionManager&, const catalog::ImmutableEncryptedReadSource&,
        std::unique_ptr<const catalog::SoftwareVolumeRetainedOwners>&, std::string& error,
        std::uint64_t accepted_replay_sequence, RetainedReplayPurpose = RetainedReplayPurpose::PlainWrite);
    // Synchronous owner-gated absence reconciliation. Endpoint is minted by
    // the held image owner; no accepted operation or APFS write is authorized.
    bool ReconcileUnacceptedAuthorizations(TransactionManager&,
        ProtectedJournalContinuation::Endpoint&, std::string& error,
        const ProtectedJournalContinuation::StageHook& = {});
    bool ValidateUnacceptedDispositions(TransactionManager&, std::vector<std::uint64_t>& spent,
        std::string& error, bool allow_last_pending = false);
    bool ValidateUnacceptedDispositionRecords(TransactionManager&, const std::vector<WriteAheadLog::Record>&,
        std::vector<std::uint64_t>& spent, std::string& error, bool allow_last_pending,
        bool allow_authenticated_incomplete_suffix);
    bool ReadCertifiedTransitionOriginal(TransactionManager&, std::uint64_t accepted,
        std::span<const std::byte> authenticated_body, TransactionManager::AcceptedTransaction&,
        bool& found, std::string& error);
    bool ValidateOriginalStreamConfiguration(const TransactionManager&, std::string& error) const;
#ifdef APFSACCESS_AUTHORIZATION_DISPOSITION_TESTING
    friend struct AuthorizationDispositionTestAccess;
#endif
    friend class catalog::EncryptedImageRuntime;
    ProtectedJournalContinuation::Result ContinueCleanGeneration(TransactionManager&, PayloadSpool&,
        ProtectedJournalContinuation::Endpoint&, std::string& error,
        const ProtectedJournalContinuation::StageHook& = {});
    ProtectedJournalContinuation::Result ContinueCleanGeneration(TransactionManager&, PayloadSpool&,
        ProtectedJournalContinuation::Endpoint&, std::string& error,
        const ProtectedJournalContinuation::StageHook&, const ProtectedJournalContinuation::ProgressHook&);
    ProtectedJournalContinuation::Result RecoverCleanGeneration(TransactionManager&, const WriteAheadLog::Options&, PayloadSpool&,
        ProtectedJournalContinuation::Endpoint&, std::string& error,
        const ProtectedJournalContinuation::StageHook& = {});
    ProtectedJournalContinuation::Result RecoverCleanGeneration(TransactionManager&, const WriteAheadLog::Options&, PayloadSpool&,
        ProtectedJournalContinuation::Endpoint&, std::string& error,
        const ProtectedJournalContinuation::StageHook&, const ProtectedJournalContinuation::ProgressHook&);
    bool OpenOrRecoverCleanGeneration(TransactionManager&, const WriteAheadLog::Options&, PayloadSpool&,
        ProtectedJournalContinuation::Endpoint&, std::string& error,
        const ProtectedJournalContinuation::StageHook& = {});
    bool OpenOrRecoverCleanGeneration(TransactionManager&, const WriteAheadLog::Options&, PayloadSpool&,
        ProtectedJournalContinuation::Endpoint&, std::string& error,
        const ProtectedJournalContinuation::StageHook&, const ProtectedJournalContinuation::ProgressHook&);
    bool AuthorizeCleanContinuation(const ProtectedJournalContinuation::RecoveryEvidence&,
        const WriteAheadLog::Options&, ProtectedJournalContinuation::Endpoint&,
        ProtectedJournalContinuation::Authority&, std::string& error);
};
}
