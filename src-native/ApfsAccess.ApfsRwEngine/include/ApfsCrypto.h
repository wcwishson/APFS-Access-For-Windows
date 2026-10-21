#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace apfsaccess::crypto
{
enum class CryptoError
{
    None, InvalidArgument, ResourceLimit, AllocationFailed, MemoryLockFailed,
    ProviderFailure, IntegrityFailure
};

struct CryptoResult;

// Owns one private VirtualAlloc region. Allocation MUST lock successfully before
// bytes are returned. No pageable fallback and no working-set/privilege changes.
// Entire page-rounded allocation is SecureZeroMemory'd before unlock/release.
// This covers owned bytes on handled paths, not caller buffers, provider-internal
// copies, registers, crash dumps, forced termination, hibernation or OS compromise.
// A span is borrowed: do not retain it across move, Clear or destruction. Objects
// are not safe for concurrent mutation. No implicit copy, resize, string or log API.
class SecureBytes final
{
public:
    static constexpr std::size_t kMaxBytes = 1024 * 1024;
    SecureBytes() noexcept = default;
    ~SecureBytes() noexcept;
    SecureBytes(const SecureBytes&) = delete;
    SecureBytes& operator=(const SecureBytes&) = delete;
    SecureBytes(SecureBytes&& other) noexcept;
    SecureBytes& operator=(SecureBytes&& other) noexcept;

    [[nodiscard]] static CryptoResult Allocate(std::size_t bytes) noexcept;
    void Clear() noexcept;
    [[nodiscard]] std::span<std::byte> Bytes() noexcept { return {data_, size_}; }
    [[nodiscard]] std::span<const std::byte> Bytes() const noexcept { return {data_, size_}; }
    [[nodiscard]] std::size_t Size() const noexcept { return size_; }
    [[nodiscard]] bool IsLocked() const noexcept { return data_ != nullptr; }
private:
    std::byte* data_ = nullptr;
    std::size_t size_ = 0;
    std::size_t allocation_size_ = 0;
};

// A failure ALWAYS contains an empty bytes owner. No partially derived/unwrapped
// result is published. os_status is Win32 for allocation/lock, NTSTATUS for CNG.
struct CryptoResult
{
    CryptoError error = CryptoError::None;
    std::uint32_t os_status = 0;
    SecureBytes bytes;
    [[nodiscard]] explicit operator bool() const noexcept { return error == CryptoError::None; }
};

// Byte-oriented; no text conversion, normalization, NUL termination or APFS
// password/recovery-key interpretation. Inputs stay owned by the caller.
// Caps are resource policy, not on-disk format limits. Rate limiting is external.
inline constexpr std::uint64_t kMaxPbkdf2Iterations = 10'000'000;
inline constexpr std::size_t kMaxPbkdf2InputBytes = 4096;
inline constexpr std::size_t kMaxDerivedBytes = 64;
[[nodiscard]] CryptoResult Pbkdf2HmacSha256(std::span<const std::byte> password,
    std::span<const std::byte> salt, std::uint64_t iterations, std::size_t bytes) noexcept;

// RFC 3394, default A6 IV only; NOT RFC 5649. KEK 16/24/32 bytes,
// ciphertext 24..4096 bytes, multiple of 8. Integrity is checked with a fixed
// eight-byte constant-time comparison before any plaintext leaves secure storage.
[[nodiscard]] CryptoResult Rfc3394Unwrap(std::span<const std::byte> kek,
    std::span<const std::byte> ciphertext) noexcept;

inline constexpr std::size_t kGcmTagBytes = 16;
inline constexpr std::size_t kMaxGcmRecordBytes = SecureBytes::kMaxBytes;
inline constexpr std::size_t kMaxGcmAadBytes = SecureBytes::kMaxBytes;
// AES-256-GCM, exactly 32 key bytes and 12 nonce bytes. Record = ciphertext ||
// 16-byte tag; nonce and AAD are external. Records INCLUDING the tag and AAD are
// each capped independently above; plaintext is at most kMaxGcmRecordBytes - 16.
// Empty plaintext seals to a tag-only record; authenticated empty opens succeed
// with an empty, unlocked owner. Every failure has empty output; authentication
// failure is IntegrityFailure. Other errors follow the CryptoResult contract.
// Caller MUST ensure nonce uniqueness per key. This primitive does NOT manage
// epochs, nonces, recovery or source/AAD policy and cannot enable a writer alone.
[[nodiscard]] CryptoResult Aes256GcmSeal(std::span<const std::byte> key,
    std::span<const std::byte> nonce, std::span<const std::byte> plaintext,
    std::span<const std::byte> aad) noexcept;
[[nodiscard]] CryptoResult Aes256GcmOpen(std::span<const std::byte> key,
    std::span<const std::byte> nonce, std::span<const std::byte> record,
    std::span<const std::byte> aad) noexcept;

enum class XtsDirection { Encrypt, Decrypt };
inline constexpr std::size_t kMaxXtsDataUnitBytes = 65536;
// One complete data unit, 16..65536 bytes, multiple of 16; no ciphertext stealing.
// combined_key = data key || tweak key (32 or 64 bytes); equal halves rejected.
// tweak_input is exactly the 16 bytes encrypted under the tweak key at block 0.
// Caller supplies its byte representation; no APFS crypto_id/block arithmetic is
// inferred. This is a confidentiality transform, NOT authentication: a wrong key
// or modified ciphertext generally returns success with incorrect plaintext.
// Not an APFS outer-keybag API (observed UUID-key reuse is intentionally excluded).
[[nodiscard]] CryptoResult XtsTransform(std::span<const std::byte> combined_key,
    std::span<const std::byte> tweak_input, std::span<const std::byte> data_unit,
    XtsDirection direction) noexcept;
} // namespace apfsaccess::crypto
