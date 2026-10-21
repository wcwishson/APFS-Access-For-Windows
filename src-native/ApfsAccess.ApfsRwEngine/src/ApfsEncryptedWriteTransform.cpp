#include "ApfsEncryptedWriteTransform.h"
#include "ApfsFormat.h"
#include <cstdint>
#include <cstring>

namespace apfsaccess::catalog
{
namespace
{
constexpr std::size_t kUnitBytes = 512;
constexpr std::size_t kMinBlockBytes = 512;
constexpr std::size_t kMaxBlockBytes = 65536;
constexpr std::size_t kVolumeKeyBytes = 32;
} // namespace

EncryptedBlockWriteResult EncryptAppleMetadataBlock(
    std::span<const std::byte> volume_key, std::uint64_t physical_block,
    std::span<const std::byte> plaintext_block) noexcept
{
    EncryptedBlockWriteResult out;
    try
    {
        const auto size = plaintext_block.size();
        if (volume_key.size() != kVolumeKeyBytes || size < kMinBlockBytes ||
            size > kMaxBlockBytes || size % kUnitBytes != 0)
        {
            out.error = EncryptedWriteError::InvalidArgument;
            return out;
        }
        const auto units = size / kUnitBytes;
        if (units == 0 || physical_block > (UINT64_MAX - (units - 1)) / units)
        {
            out.error = EncryptedWriteError::InvalidArgument;
            return out;
        }
        // The writer finalizes the plaintext checksum first; readers verify
        // it after decryption. Never encrypt an unchecked object: a corrupt
        // plaintext would become an undiagnosable ciphertext.
        if (!VerifyObjectChecksum(plaintext_block, size))
        {
            out.error = EncryptedWriteError::ChecksumMismatch;
            return out;
        }
        std::vector<std::byte> cipher(size);
        const auto first_unit = physical_block * units;
        for (std::size_t offset = 0; offset < size; offset += kUnitBytes)
        {
            const auto unit = first_unit + offset / kUnitBytes;
            std::array<std::byte, 16> tweak{};
            for (unsigned i = 0; i < 8; ++i)
                tweak[i] = static_cast<std::byte>(unit >> (8 * i));
            auto piece = crypto::XtsTransform(volume_key, tweak,
                plaintext_block.subspan(offset, kUnitBytes), crypto::XtsDirection::Encrypt);
            if (!piece)
            {
                out = {};
                out.error = piece.error == crypto::CryptoError::ResourceLimit ||
                        piece.error == crypto::CryptoError::AllocationFailed
                    ? EncryptedWriteError::ResourceLimit
                    : EncryptedWriteError::CryptoFailure;
                return out;
            }
            const auto& bytes = piece.bytes.Bytes();
            if (bytes.size() != kUnitBytes)
            {
                out = {};
                out.error = EncryptedWriteError::CryptoFailure;
                return out;
            }
            std::memcpy(cipher.data() + offset, bytes.data(), kUnitBytes);
        }
        out.bytes = std::move(cipher);
        out.error = EncryptedWriteError::None;
        return out;
    }
    catch (...)
    {
        out = {};
        out.error = EncryptedWriteError::ResourceLimit;
        return out;
    }
}
} // namespace apfsaccess::catalog
