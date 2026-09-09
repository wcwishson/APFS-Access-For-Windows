#pragma once

#include "ApfsCrypto.h"
#include "ApfsKeybag.h"
#include <chrono>

namespace apfsaccess::catalog
{
using KeybagUuid = std::array<std::byte, 16>;
enum class UnlockError
{
    None, InvalidArgument, UnsupportedFormat, Malformed, IdentityMismatch,
    IntegrityFailure, CredentialOrKeyMismatch, ResourceLimit, RateLimited,
    ReadFailure, CryptoFailure
};

// Single-threaded, caller-retained session allowance. No reset/refund on failure.
// At most 8 attempts, 2 million total iterations, 250 ms between reservations.
// Keep the same object for retries. This is local work control, not an account
// lockout against callers that deliberately construct a fresh session.
class PasswordUnlockBudget final
{
public:
    PasswordUnlockBudget() = default;
    PasswordUnlockBudget(const PasswordUnlockBudget&) = delete;
    PasswordUnlockBudget& operator=(const PasswordUnlockBudget&) = delete;
    [[nodiscard]] bool Begin() noexcept;
    [[nodiscard]] bool Charge(std::uint64_t iterations) noexcept;
private:
    unsigned attempts_left_ = 8;
    std::uint64_t iterations_left_ = 2'000'000;
    std::chrono::steady_clock::time_point next_{};
};

struct PasswordRecordResult
{
    UnlockError error = UnlockError::InvalidArgument;
    crypto::SecureBytes xts_key;
    [[nodiscard]] explicit operator bool() const noexcept
        { return error == UnlockError::None && xts_key.Size() == 32; }
};

// Low-level DER records only: does NOT establish container/volume identity.
// Inputs are exact container tag-2 and selected user tag-3 payloads, not lockers.
// Supports explicit KEK info flags 0 / 0x10 / 2 and VEK flags 0 / 2, 22-byte
// info, and exact RFC3394 lengths (40 bytes for class 0/0x10, 24 for class 2).
// Class-2 VEK expands its second XTS half as SHA256(VEK16 || DER key UUID)[:16].
// Other classes/lengths/extensions, including class-2 ignored tails, unsupported.
// Canonical DER, cookie-derived envelope HMAC, both unwrap integrity values,
// and distinct XTS halves must all validate before publishing any secret.
// Password is already encoded bytes, <=1024, no NUL; no encoding/normalization
// is inferred. Caller owns/wipes it (prefer SecureBytes). No text/key logging.
[[nodiscard]] PasswordRecordResult DecodePasswordKeyRecords(
    std::span<const std::byte> vek_der, std::span<const std::byte> kek_der,
    std::span<const std::byte> password, PasswordUnlockBudget& budget) noexcept;

// Exact-format exception to general XTS's unequal-halves rule. Decrypt only,
// exactly one 4K..64K power-of-two APFS block, UUID used as both AES-128 keys,
// 512-byte units, LE64(container-relative block * block_size/512 + sector) || 0.
// Reverse-engineered apfs-fuse profile; not Apple's published RFC3394 outer
// description. Not authenticated and not an unlock result. Caller MUST validate
// the complete plaintext object's checksum/type/identity before parsing it.
[[nodiscard]] crypto::CryptoResult DecryptApfsUuidKeybagBlock(
    const KeybagUuid& uuid, std::uint64_t physical_block,
    std::span<const std::byte> ciphertext) noexcept;

struct KeybagObjectExpectation
{
    // Must come from independent caller evidence, never guessed from paddr.
    // No automatic OID/XID discovery is claimed for these special object types.
    std::uint64_t oid = 0;
    std::uint64_t xid = 0;
};
struct PasswordUnlockRequest
{
    std::uint64_t checkpoint_xid = 0;
    std::uint64_t volume_oid = 0;
    KeybagUuid container_uuid{}, volume_uuid{}, user_uuid{};
    KeybagObjectExpectation container_bag, volume_bag;
    KeybagLength length = static_cast<KeybagLength>(-1); // mandatory explicit profile
};
struct PasswordUnlockResult
{
    UnlockError error = UnlockError::InvalidArgument;
    KeybagUuid container_uuid{}, volume_uuid{}, user_uuid{};
    std::uint64_t checkpoint_xid = 0, volume_oid = 0, volume_xid = 0;
    crypto::SecureBytes xts_key;
    [[nodiscard]] explicit operator bool() const noexcept
        { return error == UnlockError::None && xts_key.Size() == 32; }
};

// Source is an immutable, container-relative snapshot (zero is NX block zero),
// with a caller-supplied cumulative ReadBudget. Caller must prevent concurrent
// source mutation; checksums cannot authenticate malicious/replayed media.
// Reloads requested complete checkpoint, resolves APSB through its NX OMAP,
// verifies full APSB identity/ONEKEY, follows only this NX/volume's bag ranges.
// The frozen resolver requires a separate strict OMAP traversal first; both
// walks charge the same budget. Node flags outside the plain header-bearing
// profile and zero XIDs fail. Traversal allocation exceptions become ResourceLimit;
// other source exceptions propagate after owned secure storage is unwound.
// Single-block UUID-XTS profile only. Never probes plaintext/other profiles.
// Full selected frames validate, duplicate (UUID,tag) entries fail, and unknown
// tags/classes fail closed. Hints are ignored. One selected user, no KDF scan.
// Result is in-memory key possession only: no mount, write or capability grant.
[[nodiscard]] PasswordUnlockResult UnlockPasswordKeybags(
    const RandomAccessSource& source, const PasswordUnlockRequest& request,
    std::span<const std::byte> password, PasswordUnlockBudget& budget);
} // namespace apfsaccess::catalog
