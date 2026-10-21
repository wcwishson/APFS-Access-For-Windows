#pragma once

#include "ApfsCrypto.h"
#include <cstdint>
#include <span>
#include <vector>

namespace apfsaccess::catalog
{
// Write-side inverse of the encrypted read session's metadata decrypt path
// (ONEKEY software volumes only). One complete APFS metadata block, 512..65536
// bytes in 512-byte units. The plaintext checksum must already verify: the
// writer finalizes checksums over plaintext exactly as readers verify them,
// then encrypts. Per-unit XTS with tweak LE64(physical_block * units + i)
// and the borrowed 32-byte volume key; the key is never retained. File data
// uses crypto_id-derived tweaks and is NOT covered here: crypto_id assignment
// needs platform truth to avoid tweak reuse, so data stays refused.
// Publication plumbing (omap-flag-driven selection, OBJ_ENCRYPTED projection)
// is a separate layer; this unit only ciphers caller-supplied blocks.
enum class EncryptedWriteError
{
    None, InvalidArgument, ChecksumMismatch, CryptoFailure, ResourceLimit
};

struct EncryptedBlockWriteResult
{
    EncryptedWriteError error = EncryptedWriteError::InvalidArgument;
    std::vector<std::byte> bytes; // Caller-owned ciphertext; empty on failure.
    [[nodiscard]] explicit operator bool() const noexcept
        { return error == EncryptedWriteError::None && !bytes.empty(); }
};

[[nodiscard]] EncryptedBlockWriteResult EncryptAppleMetadataBlock(
    std::span<const std::byte> volume_key, std::uint64_t physical_block,
    std::span<const std::byte> plaintext_block) noexcept;
} // namespace apfsaccess::catalog
