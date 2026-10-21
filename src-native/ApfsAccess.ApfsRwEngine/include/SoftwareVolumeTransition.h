#pragma once

#include "ApfsEncryptedReadSession.h"
#include "AppleCheckpointPublisher.h"
#include <array>
#include <memory>

namespace apfsaccess::rw { class EncryptedPublicationJournal; }

namespace apfsaccess::catalog
{
enum class SoftwareVolumeMode : std::uint8_t { Plain, OneKeyGenerationZero };
enum class SoftwareVolumeOwnerKind : std::uint8_t { Metadata, Payload, Keybag };
struct SoftwareVolumeOwnedRange
{
    std::uint64_t start_block = 0, block_count = 0;
    SoftwareVolumeOwnerKind kind = SoftwareVolumeOwnerKind::Metadata;
};
struct SoftwareVolumeRetainedGeneration
{
    ContainerCheckpointView checkpoint;
    std::vector<SoftwareVolumeOwnedRange> ranges;
    std::vector<rw::AppleCheckpointGuardBlock> checkpoint_guards;
    std::vector<rw::AppleCheckpointGuardBlock> graph_guards;
};

// Minted from a complete pre-transition graph, or restored by the protected v6
// journal from that exact private authorization. This is an exclusion proof,
// never a key, decrypted read context, or replacement for the current bitmap.
class SoftwareVolumeRetainedOwners final
{
public:
    ~SoftwareVolumeRetainedOwners();
    SoftwareVolumeRetainedOwners(const SoftwareVolumeRetainedOwners&) = delete;
    SoftwareVolumeRetainedOwners& operator=(const SoftwareVolumeRetainedOwners&) = delete;
    const std::string& SourceIdentity() const noexcept { return identity_; }
    const std::string& ContainerUuid() const noexcept { return container_uuid_; }
    const std::string& VolumeUuid() const noexcept { return volume_uuid_; }
    std::uint64_t VolumeObjectId() const noexcept { return volume_oid_; }
    std::uint64_t MintedCheckpointXid() const noexcept { return minted_xid_; }
    std::uint64_t ContainerBlockCount() const noexcept { return block_count_; }
    const std::array<std::byte, 32>& SourceBinding() const noexcept { return binding_; }
    const std::array<std::byte, 32>& OriginalJournalIdentity() const noexcept { return journal_identity_; }
    const std::array<std::byte, 32>& MintedAllocatorSha256() const noexcept { return allocator_sha256_; }
    const std::vector<SoftwareVolumeRetainedGeneration>& Generations() const noexcept { return generations_; }
    bool VerifyGenerationRetirement(const ImmutableEncryptedReadSource&,
        const std::array<std::byte, 32>& original_journal_identity, std::uint64_t checkpoint_xid,
        bool& retired, std::string& error) const;

    // Exact held source and actual original WAL identity are supplied by the
    // owner. A complete current allocator is independently loaded on every call.
    // Retired generations need an authenticated canonical successor occupying an
    // old checkpoint slot; a damaged old graph alone cannot imply retirement.
    bool Revalidate(const ImmutableEncryptedReadSource& source,
        const std::array<std::byte, 32>& original_journal_identity,
        std::vector<SoftwareVolumeOwnedRange>& exclusions, std::string& error,
        std::span<const std::uint64_t> required_checkpoint_xids = {}) const;
    // Allocation after restart requires the protected accepted history, as well
    // as the canonical raw-byte and complete current-bitmap proof above.
    bool RevalidateProtectedHistory(const ImmutableEncryptedReadSource& source,
        const std::array<std::byte, 32>& original_journal_identity,
        std::vector<SoftwareVolumeOwnedRange>& exclusions, std::string& error,
        std::span<const std::uint64_t> required_checkpoint_xids = {}) const;
private:
    friend class SoftwareVolumeTransition;
    friend class rw::EncryptedPublicationJournal;
    SoftwareVolumeRetainedOwners() = default;
    std::string identity_, container_uuid_, volume_uuid_;
    std::uint64_t volume_oid_ = 0, minted_xid_ = 0, block_count_ = 0;
    std::array<std::byte, 32> binding_{}, journal_identity_{}, allocator_sha256_{};
    std::vector<SoftwareVolumeRetainedGeneration> generations_;
    std::uint64_t restored_accepted_sequence_ = 0;
    std::array<std::byte, 32> restored_plan_sha256_{};
};

class SoftwareVolumeTransitionPublication final
{
public:
    ~SoftwareVolumeTransitionPublication();
    SoftwareVolumeTransitionPublication(const SoftwareVolumeTransitionPublication&) = delete;
    SoftwareVolumeTransitionPublication& operator=(const SoftwareVolumeTransitionPublication&) = delete;
    const rw::AppleCheckpointPublicationPlan& Publication() const noexcept { return publication_; }
    const std::string& SourceIdentity() const noexcept { return owners_->SourceIdentity(); }
    const std::array<std::byte, 32>& SourceBinding() const noexcept { return owners_->SourceBinding(); }
    const std::array<std::byte, 32>& OriginalJournalIdentity() const noexcept { return owners_->OriginalJournalIdentity(); }
    std::uint64_t VolumeObjectId() const noexcept { return owners_->VolumeObjectId(); }
    const std::string& VolumeUuid() const noexcept { return owners_->VolumeUuid(); }
    SoftwareVolumeMode BeforeMode() const noexcept { return before_; }
    SoftwareVolumeMode AfterMode() const noexcept { return after_; }
    const SoftwareVolumeRetainedOwners& RetainedOwners() const noexcept { return *owners_; }
private:
    friend class SoftwareVolumeTransition;
    SoftwareVolumeTransitionPublication() = default;
    rw::AppleCheckpointPublicationPlan publication_;
    std::unique_ptr<SoftwareVolumeRetainedOwners> owners_;
    SoftwareVolumeMode before_ = SoftwareVolumeMode::OneKeyGenerationZero, after_ = SoftwareVolumeMode::Plain;
};

class SoftwareVolumeTransition final
{
public:
    static std::unique_ptr<SoftwareVolumeTransitionPublication> PrepareDecryption(
        std::shared_ptr<const ImmutableEncryptedReadSource> source,
        const std::string& expected_identity, std::uint64_t expected_revision,
        std::uint64_t volume_oid, KeybagLength,
        const crypto::SecureBytes& old_password, PasswordUnlockBudget&,
        const std::array<std::byte, 32>& original_journal_identity,
        std::string& error, std::span<const std::uint64_t> required_recovery_xids = {},
        std::span<const std::uint64_t> required_read_xids = {},
        const SoftwareVolumeRetainedOwners* retained_encrypted_owners = nullptr);
    static std::unique_ptr<SoftwareVolumeTransitionPublication> PrepareEncryption(
        std::shared_ptr<const ImmutableEncryptedReadSource> source,
        const std::string& expected_identity, std::uint64_t expected_revision,
        std::uint64_t volume_oid, const crypto::SecureBytes& new_password, PasswordUnlockBudget&,
        const std::array<std::byte, 32>& original_journal_identity,
        const SoftwareVolumeRetainedOwners* retained_encrypted_owners,
        std::string& error, std::span<const std::uint64_t> required_recovery_xids = {},
        std::span<const std::uint64_t> required_read_xids = {});
private:
    friend class SoftwareVolumeKeyRotation;
    static std::unique_ptr<SoftwareVolumeTransitionPublication> PrepareEncryptionCore(
        std::shared_ptr<const ImmutableEncryptedReadSource> source,
        const std::string& expected_identity, std::uint64_t expected_revision,
        std::uint64_t volume_oid, const crypto::SecureBytes& new_password, PasswordUnlockBudget&,
        const std::array<std::byte, 32>& original_journal_identity,
        const SoftwareVolumeRetainedOwners*, std::string& error,
        std::span<const std::uint64_t> required_recovery_xids,
        std::span<const std::uint64_t> required_read_xids,
        const crypto::SecureBytes* old_password);
    // Uses only an exact retained canonical bag template selected inside the
    // source-rooted factory. Fresh keys never leave this private call chain.
    static bool InitializeRetainedKeybags(const RandomAccessSource&, const PasswordUnlockRequest&,
        std::uint64_t container_block, std::uint64_t volume_block, std::uint64_t xid,
        const crypto::SecureBytes&, PasswordUnlockBudget&, crypto::SecureBytes& volume_key,
        std::vector<std::byte>& container_ciphertext, std::vector<std::byte>& volume_ciphertext,
        std::string& error);
    static bool InitializePristineKeybags(const RandomAccessSource&, std::uint64_t volume_oid,
        std::uint64_t container_block, std::uint64_t volume_block, std::uint64_t xid,
        const crypto::SecureBytes&, PasswordUnlockBudget&, crypto::SecureBytes& volume_key,
        std::vector<std::byte>& container_ciphertext, std::vector<std::byte>& volume_ciphertext,
        std::string& error);
};
}
