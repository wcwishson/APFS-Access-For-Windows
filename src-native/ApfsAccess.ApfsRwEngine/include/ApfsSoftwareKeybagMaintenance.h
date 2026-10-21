#pragma once

#include "ApfsKeybagUnlock.h"
#include <memory>
#include <mutex>

namespace apfsaccess::catalog
{
class ImmutableEncryptedReadSource;
class ApfsEncryptedReadSession;
class SoftwareKeybagPublication;

// Source-bound rewrap capability. It retains its admitted read session privately.
// Explicit publication preparation proves allocation, retained owners and a fresh
// candidate. Protected maintenance journal integration remains separate.
class SoftwareKeybagRewrap final
{
public:
    SoftwareKeybagRewrap(const SoftwareKeybagRewrap&) = delete;
    SoftwareKeybagRewrap& operator=(const SoftwareKeybagRewrap&) = delete;
    ~SoftwareKeybagRewrap();

    // Exact held source, one software ONEKEY generation-zero volume and one user.
    // The existing encrypted session validates the authenticated old credential,
    // volume metadata and supported crypto profile. No caller supplies keybags,
    // keys, bag identities, salts, iteration counts or a candidate overlay.
    // Credentials are already encoded, locked bytes; no normalization is inferred.
    // Four KDF charges (including session admission) share the supplied budget.
    [[nodiscard]] static std::unique_ptr<SoftwareKeybagRewrap> Prepare(
        std::shared_ptr<const ImmutableEncryptedReadSource> source,
        const std::string& expected_source_identity, std::uint64_t expected_revision,
        std::uint64_t volume_oid, KeybagLength length,
        const crypto::SecureBytes& old_password, const crypto::SecureBytes& new_password,
        PasswordUnlockBudget& budget, UnlockError& error);

    [[nodiscard]] std::unique_ptr<SoftwareKeybagPublication> PreparePublication(
        const crypto::SecureBytes& old_password, const crypto::SecureBytes& new_password,
        PasswordUnlockBudget& budget, std::string& error,
        std::span<const std::uint64_t> required_checkpoint_xids = {});

    const std::string& SourceIdentity() const noexcept { return identity_; }
    std::uint64_t SourceRevision() const noexcept { return revision_; }
    std::uint64_t CheckpointXid() const noexcept { return selection_.checkpoint_xid; }
    std::uint64_t VolumeObjectId() const noexcept { return selection_.volume_oid; }
    std::uint64_t ContainerBagBlock() const noexcept { return container_block_; }
    std::uint64_t VolumeBagBlock() const noexcept { return volume_block_; }
    std::span<const std::byte> OriginalVolumeBagCiphertext() const noexcept { return original_; }
    std::span<const std::byte> RewrappedVolumeBagCiphertext() const noexcept { return replacement_; }

private:
    SoftwareKeybagRewrap() = default;
    static UnlockError TransformBags(const RandomAccessSource&, const PasswordUnlockRequest&,
        const crypto::SecureBytes&, const crypto::SecureBytes&, PasswordUnlockBudget&,
        SoftwareKeybagRewrap&);
    static std::shared_ptr<const ImmutableEncryptedReadSource> ObserveSource(
        std::shared_ptr<const ImmutableEncryptedReadSource>);
    bool RelocateBags(std::uint64_t container_block, std::uint64_t volume_block,
        std::uint64_t xid, std::vector<std::byte>& container,
        std::vector<std::byte>& volume, std::string& error) const;
    std::unique_ptr<ApfsEncryptedReadSession> session_;
    std::mutex mutex_;
    std::shared_ptr<const ImmutableEncryptedReadSource> source_;
    std::string identity_;
    std::uint64_t revision_ = 0, container_block_ = 0, volume_block_ = 0;
    PasswordUnlockRequest selection_;
    std::vector<std::byte> original_, replacement_;
};
} // namespace apfsaccess::catalog
