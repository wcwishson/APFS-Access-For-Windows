#pragma once

#include "SoftwareVolumeTransition.h"
#include <utility>

namespace apfsaccess::catalog
{
class SoftwareVolumeKeyRotationPublication final
{
public:
    ~SoftwareVolumeKeyRotationPublication() = default;
    SoftwareVolumeKeyRotationPublication(const SoftwareVolumeKeyRotationPublication&) = delete;
    SoftwareVolumeKeyRotationPublication& operator=(const SoftwareVolumeKeyRotationPublication&) = delete;
    const rw::AppleCheckpointPublicationPlan& Publication() const noexcept { return material_->Publication(); }
    const std::string& SourceIdentity() const noexcept { return material_->SourceIdentity(); }
    const std::array<std::byte, 32>& SourceBinding() const noexcept { return material_->SourceBinding(); }
    const std::array<std::byte, 32>& OriginalJournalIdentity() const noexcept { return material_->OriginalJournalIdentity(); }
    std::uint64_t VolumeObjectId() const noexcept { return material_->VolumeObjectId(); }
    const std::string& VolumeUuid() const noexcept { return material_->VolumeUuid(); }
    const SoftwareVolumeRetainedOwners& RetainedOwners() const noexcept { return material_->RetainedOwners(); }
private:
    friend class SoftwareVolumeKeyRotation;
    explicit SoftwareVolumeKeyRotationPublication(std::unique_ptr<SoftwareVolumeTransitionPublication> material)
        : material_(std::move(material)) {}
    const std::unique_ptr<SoftwareVolumeTransitionPublication> material_;
};

// This purpose remains distinct from password rewrap and plain/encrypted mode
// transitions. No key or intermediate plaintext publication is exposed.
class SoftwareVolumeKeyRotation final
{
public:
    static std::unique_ptr<SoftwareVolumeKeyRotationPublication> Prepare(
        std::shared_ptr<const ImmutableEncryptedReadSource> source,
        const std::string& expected_identity, std::uint64_t expected_revision, std::uint64_t volume_oid,
        const crypto::SecureBytes& old_password, const crypto::SecureBytes& new_password, PasswordUnlockBudget&,
        const std::array<std::byte, 32>& original_journal_identity,
        const SoftwareVolumeRetainedOwners* retained_owners, std::string& error,
        std::span<const std::uint64_t> required_recovery_xids = {},
        std::span<const std::uint64_t> required_read_xids = {});
};
}
