#pragma once
#include "AppleCheckpointPublisher.h"
#include "ApfsEncryptedMutation.h"
#include <array>
#include <memory>
#include <vector>

namespace apfsaccess::catalog
{
class ApfsEncryptedReadSession;
// Prepared under an immutable source lease. Contains ciphertext and raw guards
// only. The image caller must reacquire exclusive ownership of the same file
// identity before using the canonical publisher. No WAL or mount admission.
class EncryptedCowOverwrite final
{
public:
    const rw::AppleCheckpointPublicationPlan& Publication() const noexcept { return publication_; }
    const std::string& SourceIdentity() const noexcept { return source_identity_; }
    EncryptedMutationKind IntentKind() const noexcept { return intent_kind_; }
    std::uint64_t RequestedInode() const noexcept { return requested_inode_; }
    std::uint64_t RequestedOffset() const noexcept { return requested_offset_; }
    std::uint64_t ReplacementLength() const noexcept { return replacement_length_; }
    const std::array<std::uint8_t, 32>& ReplacementSha256() const noexcept { return replacement_sha256_; }
    std::uint64_t IntentInode() const noexcept { return requested_inode_; }
    std::uint64_t IntentOffset() const noexcept { return requested_offset_; }
    std::uint64_t IntentLength() const noexcept { return replacement_length_; }
    const std::array<std::uint8_t, 32>& IntentSha256() const noexcept { return replacement_sha256_; }
    std::uint64_t IntentParent() const noexcept { return parent_; }
    std::uint64_t IntentDestinationParent() const noexcept { return destination_parent_; }
    // Exact request field; Create applies these bits without an implicit umask.
    std::uint16_t RequestedPermissions() const noexcept { return requested_permissions_; }
    // Published inode mode, or the removed inode's mode for Unlink.
    std::uint16_t EffectiveMode() const noexcept { return effective_mode_; }
    std::uint16_t EffectivePermissions() const noexcept { return static_cast<std::uint16_t>(effective_mode_ & 07777); }
    const std::array<std::uint8_t, 32>& IntentNameSha256() const noexcept { return name_sha256_; }
    const std::array<std::uint8_t, 32>& IntentDestinationNameSha256() const noexcept { return destination_name_sha256_; }
    std::uint64_t ResultSize() const noexcept { return result_size_; }
    std::uint64_t ReplacedInode() const noexcept { return replaced_inode_; }
    std::uint64_t ReplacedPrivateId() const noexcept { return replaced_private_id_; }
    std::uint64_t ReplacedSize() const noexcept { return replaced_size_; }
    std::uint16_t ReplacedMode() const noexcept { return replaced_mode_; }
    const std::array<std::uint8_t, 32>& ReplacedNameSha256() const noexcept { return replaced_name_sha256_; }
    std::uint64_t SourceCheckpointXid() const noexcept { return source_container_.xid; }
    std::uint64_t PublishedCheckpointXid() const noexcept { return published_container_.xid; }
    std::uint64_t VolumeObjectId() const noexcept { return volume_oid_; }
    const std::string& VolumeUuid() const noexcept { return volume_uuid_; }
    const NxSuperblock& SourceContainer() const noexcept { return source_container_; }
    const NxSuperblock& PublishedContainer() const noexcept { return published_container_; }
    std::uint64_t OldPhysicalBlock() const noexcept { return old_block_; }
    std::uint64_t NewPhysicalBlock() const noexcept { return new_block_; }
    std::uint64_t OldCryptoId() const noexcept { return old_crypto_id_; }
    std::uint64_t NewCryptoId() const noexcept { return new_crypto_id_; }
    std::size_t RetainedCheckpoints() const noexcept { return retained_checkpoints_; }
    std::size_t RetiredCheckpoints() const noexcept { return retired_checkpoints_; }
    std::size_t RequiredGenerationsProved() const noexcept { return required_generations_proved_; }
    // Exact proved set: source current plus explicitly required generations.
    const std::vector<std::uint64_t>& RequiredCheckpointXids() const noexcept { return required_checkpoint_xids_; }
    const std::vector<std::uint64_t>& RequiredRecoveryCheckpointXids() const noexcept { return required_recovery_checkpoint_xids_; }
    const std::vector<std::uint64_t>& RequiredReadCheckpointXids() const noexcept { return required_read_checkpoint_xids_; }
    std::size_t MetadataSurvivorsWalked() const noexcept { return metadata_survivors_walked_; }
    EncryptedCowOverwrite(const EncryptedCowOverwrite&) = delete;
    EncryptedCowOverwrite& operator=(const EncryptedCowOverwrite&) = delete;
private:
    friend class ApfsEncryptedReadSession;
    EncryptedCowOverwrite() = default;
    rw::AppleCheckpointPublicationPlan publication_;
    std::string source_identity_;
    EncryptedMutationKind intent_kind_ = EncryptedMutationKind::Overwrite;
    std::uint64_t requested_inode_ = 0, requested_offset_ = 0, replacement_length_ = 0;
    std::uint64_t parent_ = 0, destination_parent_ = 0, result_size_ = 0, volume_oid_ = 0;
    std::array<std::uint8_t, 32> replacement_sha256_{}, name_sha256_{}, destination_name_sha256_{};
    std::string volume_uuid_;
    NxSuperblock source_container_, published_container_;
    std::uint64_t old_block_ = 0, new_block_ = 0, old_crypto_id_ = 0, new_crypto_id_ = 0;
    std::size_t retained_checkpoints_ = 0;
    std::size_t retired_checkpoints_ = 0;
    std::size_t required_generations_proved_ = 0, metadata_survivors_walked_ = 0;
    std::vector<std::uint64_t> required_checkpoint_xids_;
    std::uint16_t requested_permissions_ = 0, effective_mode_ = 0;
    std::uint64_t replaced_inode_ = 0, replaced_private_id_ = 0, replaced_size_ = 0;
    std::uint16_t replaced_mode_ = 0;
    std::array<std::uint8_t, 32> replaced_name_sha256_{};
    std::vector<std::uint64_t> required_recovery_checkpoint_xids_, required_read_checkpoint_xids_;
};
}
