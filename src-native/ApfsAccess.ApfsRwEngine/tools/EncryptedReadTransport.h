#pragma once
#include "ApfsEncryptedReadSession.h"
#include "WindowsImageLease.h"
#include <chrono>

namespace apfsaccess::transport
{
enum class CredentialError { None, PipeRequired, ParentPipeRequired, UnprotectedPipe, InvalidFrame,
    TruncatedFrame, OversizedFrame, Timeout, Cancelled, ReadFailure, SecureAllocationFailed };
const char* CredentialErrorName(CredentialError error) noexcept;
struct CredentialResult
{
    CredentialError error = CredentialError::InvalidFrame;
    crypto::SecureBytes bytes;
    explicit operator bool() const noexcept { return error == CredentialError::None; }
};
// Consumes/closes the supplied handle. Only a byte pipe created by this process's
// actual parent is admitted, with a DACL limited to this user, SYSTEM and this
// logon session. Null/permissive/unknown ACLs are refused. Caller must arrange
// exclusive inheritance/reading and keep its writer buffers securely owned.
// APC1 + LE32 length (1..1024) + exact encoded bytes + EOF, no NUL or normalization.
// EOF is mandatory: leaving the write end open is an incomplete frame.
// The total receive deadline includes header, payload and EOF. No blocking read
// is issued until PeekNamedPipe proves data exists. All received bytes are locked.
CredentialResult ReceiveCredential(HANDLE owned_input, std::chrono::milliseconds timeout,
    const std::atomic<bool>& cancellation) noexcept;

// Exact container-relative view of one actual Windows deny-write/delete lease.
// Revision is a per-acquisition opaque random token, never an mtime surrogate.
class OwnedEncryptedImageSource final : public catalog::ImmutableEncryptedReadSource
{
public:
    OwnedEncryptedImageSource(std::shared_ptr<WindowsImageLease> lease,
        std::uint64_t offset, std::uint64_t size);
    std::uint64_t SizeBytes() const override { return size_; }
    std::string SourceIdentity() const override { return identity_; }
    std::uint64_t Revision() const override { return revision_; }
    std::shared_ptr<catalog::ApfsReadBudget> ReadBudget() const override { return budget_; }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override;
    std::optional<catalog::EncryptedRuntimeReadLimits> RuntimeReadLimits() const override
    { return catalog::EncryptedRuntimeReadLimits{}; }
    bool ReadRuntime(const RuntimeRead& request, std::vector<std::byte>& out) const override;
    bool VerifyUnchanged() const { return lease_->VerifyUnchanged(); }
private:
    std::shared_ptr<WindowsImageLease> lease_;
    std::shared_ptr<catalog::ApfsReadBudget> budget_;
    std::uint64_t offset_, size_, revision_ = 0;
    std::string identity_;
};
}
