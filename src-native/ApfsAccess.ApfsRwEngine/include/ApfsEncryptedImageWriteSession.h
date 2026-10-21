#pragma once
#include "ApfsEncryptedReadSession.h"
#include "EncryptedPublicationJournal.h"
#include "ProtectedJournalContinuation.h"
#include "SoftwareVolumeTransition.h"
#include "ImageKeyManagementEndpoint.h"
#include <array>
#include <memory>
#include <optional>

namespace apfsaccess::rw { class MetadataStore; }
namespace apfsaccess::catalog
{
enum class EncryptedImageWritePhase { Locked, Ready, Preparing, Publishing, RecoveryRequired, Closed };
struct EncryptedImageWriteStatus
{
    EncryptedImageWritePhase phase = EncryptedImageWritePhase::Locked;
    std::uint64_t checkpoint_xid = 0, container_bytes = 0, free_bytes = 0, commits = 0;
    std::uint64_t next_inode_id = 0; // Tentative create identity, valid only at this Ready XID.
    bool key_present = false, recovery_required = false, free_space_valid = false;
};

// Image-only owner. Keeps one exclusive handle until Close, including while
// locked. Read views are closed/revoked and drained before all physical writes.
// CachedStatus never takes the commit or I/O mutex. Passwords are borrowed only.
class ApfsEncryptedImageWriteSession final
{
    struct Impl;
public:
    class ReadInode final
    {
    public:
        ~ReadInode();
        std::uint64_t Inode() const noexcept;
        ReadInode(const ReadInode&) = delete;
        ReadInode& operator=(const ReadInode&) = delete;
    private:
        friend class ApfsEncryptedImageWriteSession;
        friend struct Impl;
        struct State;
        explicit ReadInode(std::shared_ptr<State>);
        const std::shared_ptr<State> state_;
    };
    class PreparedMutation final
    {
    public:
        const EncryptedCowOverwrite& Intent() const noexcept { return *prepared_; }
        PreparedMutation(const PreparedMutation&) = delete;
        PreparedMutation& operator=(const PreparedMutation&) = delete;
    private:
        friend class ApfsEncryptedImageWriteSession;
        PreparedMutation() = default;
        std::unique_ptr<EncryptedCowOverwrite> prepared_;
        std::weak_ptr<const ImmutableEncryptedReadSource> source_;
    };
    struct Image
    {
        std::wstring path;
        std::uint64_t offset = 0, bytes = 0, volume_oid = 0;
        KeybagLength keybag_length = KeybagLength::IncludesHeader;
    };
    static std::unique_ptr<ApfsEncryptedImageWriteSession> Open(const Image&, std::string& error);
    ~ApfsEncryptedImageWriteSession();
    ApfsEncryptedImageWriteSession(const ApfsEncryptedImageWriteSession&) = delete;
    ApfsEncryptedImageWriteSession& operator=(const ApfsEncryptedImageWriteSession&) = delete;
    bool Unlock(const crypto::SecureBytes& password, PasswordUnlockBudget&, std::string& error);
    std::shared_ptr<ApfsEncryptedReadSession> OpenReadView(EncryptedReadError& error);
    // Read-only inode lifetime. Tokens contain no key/view and are revoked by
    // Lock/Close. Each use opens a fresh view drained before the next write.
    std::shared_ptr<ReadInode> RetainReadInode(std::uint64_t inode, std::string& error);
    std::shared_ptr<ApfsEncryptedReadSession> OpenReadView(const ReadInode&, EncryptedReadError& error);
    // Caller holds its original container/journal gate; acceptance and cleanup
    // remain Root-owned. The delta planner preserves unaffected dense extents;
    // its changed-block/tree/ownership budgets can refuse before staging.
    // Failure after staging requires RecoverAccepted before another commit.
    // All old read views become Closed before physical publication starts.
    bool CommitAcceptedOverwrite(rw::TransactionManager&, rw::EncryptedPublicationJournal&,
        std::uint64_t accepted_sequence, std::uint64_t expected_checkpoint_xid,
        std::uint64_t inode, std::uint64_t offset, std::span<const std::byte> replacement,
        std::string& error, const rw::AppleCheckpointStageHook& hook = {});
    bool CommitAcceptedMutation(rw::TransactionManager&, rw::EncryptedPublicationJournal&,
        std::uint64_t accepted_sequence, std::uint64_t expected_checkpoint_xid,
        const EncryptedMutationRequest&, std::string& error,
        std::span<const std::uint64_t> required_checkpoint_xids = {},
        const rw::AppleCheckpointStageHook& hook = {});
    // Caller holds the original journal gate. Private authorization is durable
    // before original acceptance. Publication revokes all admitted readers and
    // leaves this owner locked; a fresh canonical password unlock is required.
    bool ChangePassword(rw::TransactionManager&, rw::EncryptedPublicationJournal&,
        std::uint64_t expected_checkpoint_xid, const crypto::SecureBytes& old_password,
        const crypto::SecureBytes& new_password, PasswordUnlockBudget&,
        std::uint64_t& accepted_sequence, std::string& error,
        const rw::AppleCheckpointStageHook& hook = {});
    // Only authenticated original records plus the prior private authorization
    // can restage maintenance. No credential or admitted key is needed.
    bool RecoverAcceptedMaintenance(rw::TransactionManager&, rw::EncryptedPublicationJournal&,
        std::uint64_t accepted_sequence, std::string& error,
        const rw::AppleCheckpointStageHook& hook = {});
    bool Encrypt(rw::TransactionManager&, rw::EncryptedPublicationJournal&, std::uint64_t expected_checkpoint_xid,
        const crypto::SecureBytes&, PasswordUnlockBudget&, std::uint64_t& accepted_sequence,
        std::string& error, const rw::AppleCheckpointStageHook& hook = {});
    bool Decrypt(rw::TransactionManager&, rw::EncryptedPublicationJournal&, std::uint64_t expected_checkpoint_xid,
        const crypto::SecureBytes&, PasswordUnlockBudget&, std::uint64_t& accepted_sequence,
        std::string& error, const rw::AppleCheckpointStageHook& hook = {});
    bool RecoverAcceptedTransition(rw::TransactionManager&, rw::EncryptedPublicationJournal&,
        std::uint64_t accepted_sequence, std::string& error, const rw::AppleCheckpointStageHook& hook = {});
    bool RotateVolumeKey(rw::TransactionManager&, rw::EncryptedPublicationJournal&, std::uint64_t expected_checkpoint_xid,
        const crypto::SecureBytes& old_password, const crypto::SecureBytes& new_password, PasswordUnlockBudget&,
        std::uint64_t& accepted_sequence, std::string& error, const rw::AppleCheckpointStageHook& hook = {});
    bool RecoverAcceptedKeyRotation(rw::TransactionManager&, rw::EncryptedPublicationJournal&,
        std::uint64_t accepted_sequence, std::string& error, const rw::AppleCheckpointStageHook& hook = {});
    // Runtime holds its outer lifetime/journal gate across these two calls and
    // original acceptance. Invalid requests can fail before any accepted debt.
    // This opaque capability is bound to this owner's exact current read view;
    // Lock/Close/rebind invalidate it. It retains no key or borrowed plaintext.
    std::unique_ptr<PreparedMutation> PrepareMutation(std::uint64_t expected_checkpoint_xid,
        const EncryptedMutationRequest&, std::string& error,
        std::span<const std::uint64_t> required_checkpoint_xids = {});
    std::unique_ptr<PreparedMutation> PrepareMutationWithTransitionRetention(
        rw::TransactionManager&, rw::EncryptedPublicationJournal&, std::uint64_t expected_checkpoint_xid,
        const EncryptedMutationRequest&, std::string& error,
        std::span<const std::uint64_t> required_checkpoint_xids = {});
    bool CommitAcceptedPrepared(rw::TransactionManager&, rw::EncryptedPublicationJournal&,
        std::uint64_t accepted_sequence, std::uint64_t expected_checkpoint_xid,
        std::unique_ptr<PreparedMutation>, std::string& error,
        const rw::AppleCheckpointStageHook& hook = {});
    bool RecoverAccepted(rw::TransactionManager&, rw::EncryptedPublicationJournal&,
        std::uint64_t accepted_sequence, std::string& error,
        const rw::AppleCheckpointStageHook& hook = {});
    // Complete witnesses replay without a key. Missing witnesses require the
    // admitted preimage key and reconstruct only the original typed mutation.
    // Inline bytes are recovered from that record; a spool payload is borrowed
    // and must match its exact accepted length/hash. No password is retained.
    // A locked refusal preserves debt; Close/Open/Unlock admits a retry.
    bool RecoverAcceptedMutation(rw::TransactionManager&, rw::EncryptedPublicationJournal&,
        std::uint64_t accepted_sequence, std::span<const std::byte> exact_payload,
        std::string& error, std::span<const std::uint64_t> required_checkpoint_xids = {},
        const rw::AppleCheckpointStageHook& hook = {});
    bool RecoverAcceptedMutationWithTransitionRetention(rw::TransactionManager&, rw::EncryptedPublicationJournal&,
        std::uint64_t accepted_sequence, std::span<const std::byte> exact_recovered_payload,
        std::string& error, std::span<const std::uint64_t> required_checkpoint_xids = {},
        const rw::AppleCheckpointStageHook& hook = {});
    // Sticky for this owner lifetime. Does not take a gate, drain views, or wipe
    // the key. The caller subsequently Close()s after its worker has stopped.
    void Cancel() noexcept;
    // Exact public selectors admitted at unlock, not a new parse or key export.
    // No selection is exposed while locked, cancelled, closed, or in recovery.
    std::optional<PasswordUnlockRequest> UnlockedSelection() const;
    bool ObserveKeyManagementEndpoint(ImageKeyManagementEndpoint&, std::string& error);
    void Lock() noexcept;
    void Close() noexcept;
    EncryptedImageWriteStatus CachedStatus() const noexcept;
    const std::string& SourceIdentity() const noexcept;
    const std::string& ContainerUuid() const noexcept;
    std::uint64_t VolumeObjectId() const noexcept;
    const std::string& VolumeUuid() const noexcept;
    const std::array<std::byte, 32>& SourceBinding() const noexcept;
private:
    friend class EncryptedImageRuntime;
    enum class PlainWriterPurpose { Mutation, AcceptedRecovery };
    bool WithTransitionPlainStore(rw::TransactionManager&, rw::EncryptedPublicationJournal&,
        PlainWriterPurpose, std::uint64_t accepted_sequence,
        const std::function<bool(rw::MetadataStore&, std::string&)>&, std::string&);
    enum class RetainedDataRecovery { Existing, ProtectedTransitionOwners };
    bool RecoverAcceptedMutationCore(rw::TransactionManager&, rw::EncryptedPublicationJournal&,
        std::uint64_t, std::span<const std::byte>, std::string&, std::span<const std::uint64_t>,
        const rw::AppleCheckpointStageHook&, RetainedDataRecovery);
    bool TransitionVolume(SoftwareVolumeMode, rw::TransactionManager&, rw::EncryptedPublicationJournal&,
        std::uint64_t, const crypto::SecureBytes&, PasswordUnlockBudget&, std::uint64_t&,
        std::string&, const rw::AppleCheckpointStageHook&);
    rw::ProtectedJournalContinuation::Result WithCleanJournalEndpoint(
        const std::function<rw::ProtectedJournalContinuation::Result(
            rw::ProtectedJournalContinuation::Endpoint&, std::string&)>&,
        std::string& error);
    explicit ApfsEncryptedImageWriteSession(std::unique_ptr<Impl>);
    std::unique_ptr<Impl> impl_;
};
}
