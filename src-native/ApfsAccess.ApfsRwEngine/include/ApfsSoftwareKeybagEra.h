#pragma once

#include "ApfsKeybagUnlock.h"
#include "ApfsFormat.h"
#include <memory>

namespace apfsaccess::catalog
{
class ImmutableEncryptedReadSource;
class ApfsEncryptedReadSession;

// A private comparison of two canonical password eras on one held source.
// It contains no key and admits no credential. Only an already admitted session
// can prove an era and reuse its own locked VEK for those exact historical bytes.
class SoftwareKeybagEraAuthority final
{
public:
    ~SoftwareKeybagEraAuthority() = default;
    SoftwareKeybagEraAuthority(const SoftwareKeybagEraAuthority&) = delete;
    SoftwareKeybagEraAuthority& operator=(const SoftwareKeybagEraAuthority&) = delete;
private:
    friend class ApfsEncryptedReadSession;
    SoftwareKeybagEraAuthority() = default;
    // proof_reads is the session's budgeted reader or planner's tracked BASE,
    // never a caller overlay/candidate. Identity stays with the immutable lease.
    static std::unique_ptr<SoftwareKeybagEraAuthority> Prove(
        const ImmutableEncryptedReadSource& identity_source,
        const RandomAccessSource& proof_reads,
        const std::string& expected_identity, std::uint64_t expected_revision,
        const PasswordUnlockResult& admitted_key,
        const ContainerCheckpointView& admitted_checkpoint,
        const ApsbVolume& admitted_volume, std::uint64_t historical_xid,
        std::string& error);
    // Verification-only parent. The session may encapsulate this solely in its
    // opaque snapshot context, after the complete canonical catalog walk.
    static std::unique_ptr<SoftwareKeybagEraAuthority> ProveReadOnlySnapshotParent(
        const ImmutableEncryptedReadSource& identity_source,
        const RandomAccessSource& proof_reads,
        const std::string& expected_identity, std::uint64_t expected_revision,
        const PasswordUnlockResult& admitted_key,
        const ContainerCheckpointView& admitted_checkpoint,
        const ApsbVolume& admitted_volume, std::uint64_t historical_xid,
        std::string& error);
    PasswordUnlockRequest selection_;
    ContainerCheckpointView checkpoint_;
    ApsbVolume volume_;
    std::uint64_t container_block_ = 0, volume_block_ = 0;
    std::uint64_t current_container_block_ = 0, current_volume_block_ = 0;
};
} // namespace apfsaccess::catalog
