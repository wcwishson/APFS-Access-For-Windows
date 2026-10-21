#pragma once

#include "EncryptedReadTransport.h"
#include <array>

namespace apfsaccess::transport
{
struct CredentialSetResult
{
    CredentialError error = CredentialError::InvalidFrame;
    std::array<crypto::SecureBytes, 2> credentials;
    std::size_t count = 0;
    explicit operator bool() const noexcept { return error == CredentialError::None; }
};

// The caller supplies a fixed operation-specific count. The owned pipe closes
// on every outcome; credentials are returned only after all frames and EOF.
CredentialSetResult ReceiveCredentials(HANDLE owned_input, std::size_t expected_count,
    std::chrono::milliseconds timeout, const std::atomic<bool>& cancellation) noexcept;
}
