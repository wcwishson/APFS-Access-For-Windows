#pragma once

#include "ApfsKeybagUnlock.h"
#include <atomic>
#include <memory>
#include <string>
#include <vector>

namespace apfsaccess::catalog
{
// The host must hold an immutable, container-relative snapshot for this object's
// entire lifetime. Revision is an opaque host token, not an mtime or UUID guess.
// Reads must charge the same advertised cumulative budget. A held mutable file
// alone does not satisfy this contract. Session serializes all accesses.
class ImmutableEncryptedReadSource : public RandomAccessSource
{
public:
    [[nodiscard]] virtual std::string SourceIdentity() const = 0;
    [[nodiscard]] virtual std::uint64_t Revision() const = 0;
};

enum class EncryptedReadError
{
    None, InvalidArgument, UnlockFailed, UnsupportedEncryptionLayout,
    SourceIdentityMismatch, ResourceLimit, ReadFailure, CryptoFailure,
    MetadataIntegrityFailure, Closed, Cancelled, FileNotFound
};

struct EncryptedFileInfo
{
    std::uint64_t inode_id = 0, size = 0, default_crypto_id = 0;
};

// Software ONEKEY, generation zero, header-bearing virtual FS trees only.
// Encrypted nodes require OBJ_ENCRYPTED in their decrypted header. Plain nodes
// require a plain header. No trial decrypt, snapshot reselection, global cache,
// mount/write admission, compression, per-file key or hardware-key support.
class ApfsEncryptedReadSession final
{
public:
    ~ApfsEncryptedReadSession();
    ApfsEncryptedReadSession(const ApfsEncryptedReadSession&) = delete;
    ApfsEncryptedReadSession& operator=(const ApfsEncryptedReadSession&) = delete;

    // Unlock and bind within one owned source lifetime; credentials are borrowed
    // only during this call. Caller clears its locked credential buffer afterwards.
    [[nodiscard]] static std::unique_ptr<ApfsEncryptedReadSession> Unlock(
        std::shared_ptr<const ImmutableEncryptedReadSource> source,
        std::string expected_source_identity, std::uint64_t expected_revision,
        const PasswordUnlockRequest& request, std::span<const std::byte> password,
        PasswordUnlockBudget& attempts, EncryptedReadError& error, UnlockError& unlock_error,
        std::shared_ptr<const std::atomic<bool>> cancellation = {});

    // Exact-read: failure leaves output empty; no EOF clipping. Zero-byte reads
    // are accepted at/before EOF. Requests are capped at SecureBytes::kMaxBytes.
    // Successful outputs are ordinary caller-owned plaintext, not locked storage.
    EncryptedReadError ReadFile(std::uint64_t inode_id, std::uint64_t offset,
        std::size_t size, std::vector<std::byte>& output);
    EncryptedReadError ListFiles(std::vector<EncryptedFileInfo>& output);
    // Cancellation is sticky. Close first cancels, then waits for the serialized
    // reader to drain, wipes the VEK and clears session-local metadata.
    void Cancel() noexcept;
    void Close() noexcept;

#ifdef APFSACCESS_CRYPTO_TESTING
    // Deterministic vector injection only. Absent from production builds.
    static std::unique_ptr<ApfsEncryptedReadSession> OpenForTesting(
        std::shared_ptr<const ImmutableEncryptedReadSource> source,
        PasswordUnlockResult key, EncryptedReadError& error,
        std::shared_ptr<const std::atomic<bool>> cancellation = {});
#endif
private:
    struct Impl;
    explicit ApfsEncryptedReadSession(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};
} // namespace apfsaccess::catalog
