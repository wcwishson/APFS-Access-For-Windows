#pragma once

#include "ApfsCrypto.h"
#include <array>
#include <memory>
#include <string_view>

namespace apfsaccess::journal
{
using JournalDigest = std::array<std::byte, 32>;
using JournalEpochId = std::array<std::byte, 16>;
inline constexpr std::size_t kJournalRecordHeaderBytes = 64;
inline constexpr std::size_t kMaxJournalRecordBytes = crypto::SecureBytes::kMaxBytes;
inline constexpr std::size_t kMaxJournalPlaintextBytes = kMaxJournalRecordBytes - kJournalRecordHeaderBytes - crypto::kGcmTagBytes;
inline constexpr std::size_t kMaxJournalKeySlotBytes = 4096;
inline constexpr std::uint64_t kMaxJournalEpochRecords = std::uint64_t{1} << 32;

enum class JournalError
{
    None, InvalidArgument, ResourceLimit, UnsafePath, IoFailure, Busy, MissingKey,
    InvalidFrame, BindingMismatch, ProtectionFailure, CryptoFailure, IntegrityFailure,
    NonceExhausted
};
struct JournalStatus
{
    JournalError error = JournalError::None;
    std::uint32_t os_status = 0; // Win32 for file/DPAPI, NTSTATUS for CNG.
    crypto::CryptoError crypto_error = crypto::CryptoError::None;
    [[nodiscard]] explicit operator bool() const noexcept { return error == JournalError::None; }
};
// Reconstruct these from trusted operation state, NEVER from an untrusted record.
// Digests are opaque exact bytes. The caller defines their canonical encoding and
// collision-resistant construction, including source/container/volume/generation.
// Zero binding/operation digests and purpose zero are refused to catch omissions.
struct JournalRecordContext
{
    std::uint32_t purpose = 0;
    JournalDigest operation{};
    std::uint64_t chunk = 0;
};
struct JournalRecordResult
{
    JournalStatus status;
    crypto::SecureBytes bytes;
    [[nodiscard]] explicit operator bool() const noexcept { return static_cast<bool>(status); }
};
class ProtectedJournalEpoch;
class ProtectedJournalReadPass;
struct JournalEpochAcquisition
{
    JournalStatus status;
    std::unique_ptr<ProtectedJournalEpoch> epoch;
    [[nodiscard]] explicit operator bool() const noexcept { return static_cast<bool>(status); }
};
struct JournalReadPassAcquisition
{
    JournalStatus status;
    std::unique_ptr<ProtectedJournalReadPass> reader;
    [[nodiscard]] explicit operator bool() const noexcept { return static_cast<bool>(status); }
};

// Short synchronous current-user read capability. Pins directory ancestors once
// and caches at most ONE locked key and one bounded encrypted slot. Every Open
// still reopens, validates and reads the complete actual slot; only byte-identical
// previously authenticated slots can reuse that key. Each record/context always
// undergoes GCM authentication. Any failure clears the key. No plaintext cache,
// writer/nonce API, persistence mutation or quota adjustment. End the pass before
// changing Windows security context; like a writer, a live key is a capability,
// not an impersonation boundary. Calls are serialized; destruction must not race.
class ProtectedJournalReadPass final
{
public:
    ~ProtectedJournalReadPass() noexcept;
    ProtectedJournalReadPass(const ProtectedJournalReadPass&) = delete;
    ProtectedJournalReadPass& operator=(const ProtectedJournalReadPass&) = delete;
    [[nodiscard]] static JournalReadPassAcquisition Acquire(std::wstring_view directory,
        std::span<const std::byte> exact_binding) noexcept;
    [[nodiscard]] JournalRecordResult Open(const JournalRecordContext& expected_context,
        std::span<const std::byte> record) noexcept;
private:
    struct Impl;
    explicit ProtectedJournalReadPass(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;
};

// One exclusive writer lease for an existing ordinary local directory. Every
// acquisition generates a FRESH random 256-bit key and 128-bit epoch ID. No API
// imports/resumes an old key for encryption. Old immutable slots are read-only
// recovery inputs; this component never deletes, replaces or compacts any file.
// The wrapped slot is CREATE_NEW + WRITE_THROUGH, flushed and read back before
// returning a writer. Its non-delete/non-write-shared handle stays pinned for the
// writer lifetime. Interrupted/failed publications leave evidence, not a writer.
// Durability relies on Windows/file-system/device honoring write-through/flush;
// software failure injection does not establish physical power-loss behavior.
//
// Seal is serialized and burns its 96-bit big-endian monotonic nonce BEFORE any
// fallible encryption work. Provider/allocation failures cannot reuse it. Refuse
// full counter exhaustion or the conservative 2^32-attempt per-key budget. After
// crash/release, reacquisition has a new key: no per-record durable counter write
// is required. This relies on the system RNG, exclusive lease and no key-resume API.
// Concurrent Seal calls are supported; destruction must not race other methods.
//
// Frame v1 exposes only format/length, random epoch ID, nonce and ciphertext/tag.
// Binding, purpose and operation/chunk context are authenticated with the exact
// header; purpose/context are NOT stored. No caller paths/metadata/payload/key is
// written in plaintext. Seal does not persist records or assert WAL durability.
//
// DPAPI is current-user scope, UI forbidden, no machine flag/description. Owned
// key material is locked SecureBytes. DPAPI's unavoidable LocalAlloc plaintext
// initially belongs to the OS; it is immediately locked, copied to locked storage
// and its ENTIRE allocation wiped before unlock/LocalFree on all handled paths.
// Provider/OS copies, caller buffers, registers, dumps, forced termination and
// hibernation are outside these wiping guarantees. E04/runtime/WAL/spool/recovery
// admission and safe deletion require separate integration evidence.
class ProtectedJournalEpoch final
{
public:
    ~ProtectedJournalEpoch() noexcept;
    ProtectedJournalEpoch(const ProtectedJournalEpoch&) = delete;
    ProtectedJournalEpoch& operator=(const ProtectedJournalEpoch&) = delete;
    [[nodiscard]] static JournalEpochAcquisition AcquireWriter(std::wstring_view directory,
        std::span<const std::byte> exact_binding) noexcept;
    [[nodiscard]] JournalEpochId Id() const noexcept;
    [[nodiscard]] JournalRecordResult Seal(const JournalRecordContext& context,
        std::span<const std::byte> plaintext) noexcept;
    [[nodiscard]] static JournalRecordResult Open(std::wstring_view directory,
        std::span<const std::byte> exact_binding, const JournalRecordContext& expected_context,
        std::span<const std::byte> record) noexcept;
#ifdef APFSACCESS_PROTECTED_JOURNAL_TESTING
    void TestSetNextNonce(std::array<std::byte, 12> next, std::uint64_t attempts) noexcept;
#endif
private:
    struct Impl;
    explicit ProtectedJournalEpoch(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;
};

#ifdef APFSACCESS_PROTECTED_JOURNAL_TESTING
namespace testing
{
enum class EpochFault { None, Random, ProtectAfter, UnprotectAfter, SlotCreate, SlotWrite,
    SlotFlush, SlotReadback, AfterPublication };
struct EpochHooks
{
    EpochFault fault = EpochFault::None;
    bool triggered = false;
    std::span<const std::byte> key_override; // Borrowed public canary fixture only.
    std::span<const std::byte> id_override;
    unsigned dpapi_wipes = 0, dpapi_releases = 0, dpapi_unlocks = 0;
    bool dpapi_released_zero = true;
};
extern thread_local EpochHooks hooks;
}
#endif
} // namespace apfsaccess::journal
