#pragma once

#include "RandomAccessSource.h"
#include <array>

namespace apfsaccess::catalog
{
enum class KeybagKind { Container, Volume };
// Explicit because Apple Reference p.145 says entry bytes, but apfs-fuse
// Keybag::Init copies kl_nbytes starting at the locker header. No autodetection.
enum class KeybagLength { EntriesOnly, IncludesHeader };
enum class KeybagError
{
    None, InvalidArgument, ResourceLimit, ReadFailure, Malformed,
    UnsupportedVersion, UnsupportedTag, UnsupportedKeyPayload, UnsupportedPadding,
    AllocationFailure
};
struct KeybagMetadataEntry
{
    std::array<std::byte, 16> uuid{}; // Opaque APFS bytes; never GPT byte ordering.
    std::uint16_t tag = 0;
    std::uint16_t payload_bytes = 0;
    // Only meaningful for container tag 3; relative to the container in blocks.
    // Arithmetic is validated here; geometry, checkpoint and source binding are
    // the caller's responsibility. This parser never follows these references.
    std::uint64_t keybag_start_block = 0;
    std::uint64_t keybag_block_count = 0;
};
struct KeybagMetadataResult
{
    KeybagError error = KeybagError::None;
    std::vector<KeybagMetadataEntry> entries;
    [[nodiscard]] explicit operator bool() const noexcept { return error == KeybagError::None; }
};
inline constexpr std::size_t kMaxKeybagLockerBytes = 65536;
inline constexpr std::size_t kMaxKeybagEntries = 1024;

// STRICT METADATA SUBSET, NOT AN UNLOCK/PAYLOAD PARSER. Input is one exact bare
// plaintext kb_locker_t, not media_keybag_t, block padding or encrypted bytes.
// Field offsets/tag contexts/ke_keylen <512: Apple Reference pp.144-149.
// Entry stride round_up(24 + ke_keylen,16): observed apfs-fuse GetKey, not a
// documented Apple guarantee. Both length conventions require this stride.
// Caller must select a convention from independently established evidence.
// Nonzero reserved/alignment padding is refused as an explicit subset policy;
// Apple says preserve reserved bytes, so refusal need not imply corrupt media.
// Known DER-bearing tags (container 2 / volume 3) are structurally checked but
// return UnsupportedKeyPayload with NO entries. DER classes/flags, HMAC, KDF
// mapping and wrapped-key selection are not inferred. Tags 5/6 and unknown tags
// are unsupported. Hint text is never copied, returned or logged.
// Full framing validates before materialization; all failures have empty entries.
[[nodiscard]] KeybagMetadataResult ParseKeybagMetadata(
    const std::vector<std::byte>& locker, KeybagKind kind, KeybagLength length,
    ApfsReadBudget* budget = nullptr);

// One bounded exact read through existing RandomAccessSource conventions.
// Source implementations advertising ReadBudget must charge their own Read.
// Caller supplies a source already containing the bare plaintext locker. This
// does not load/decrypt on-disk outer objects. Temporary bytes are wiped even if
// Read throws or returns a partial buffer. Does not catch non-allocation source
// exceptions; callers retain their source error policy.
[[nodiscard]] KeybagMetadataResult ReadKeybagMetadata(const RandomAccessSource& source,
    std::uint64_t offset, std::size_t exact_bytes, KeybagKind kind, KeybagLength length);
} // namespace apfsaccess::catalog
