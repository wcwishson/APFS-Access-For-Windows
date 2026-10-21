#include "ApfsKeybagUnlock.h"
#include "ApfsSoftwareKeybagMaintenance.h"
#include "ApfsSoftwareKeybagEra.h"
#include "SoftwareVolumeTransition.h"
#include "SoftwareKeybagEncodingProfile.h"
#include "ApfsEncryptedReadSession.h"
#include "ApfsFormat.h"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <cstring>
#include <limits>
#include <new>
#include <utility>
#ifdef APFSACCESS_CRYPTO_TESTING
#include "ApfsCryptoTestHooks.h"
#endif

namespace apfsaccess::catalog
{
namespace
{
using Bytes = std::span<const std::byte>;
using crypto::CryptoError;
using crypto::CryptoResult;
using crypto::SecureBytes;
CryptoResult CryptoFail() noexcept { return {CryptoError::ProviderFailure, 0, {}}; }
PasswordRecordResult Refuse(UnlockError error) noexcept { return {error, {}}; }
bool Equal(Bytes a, Bytes b) noexcept
{
    if (a.size() != b.size()) return false;
    volatile unsigned difference = 0;
    for (std::size_t i = 0; i < a.size(); ++i)
        difference = difference | std::to_integer<unsigned>(a[i] ^ b[i]);
    return difference == 0;
}
bool Zero(Bytes b) noexcept
{
    return std::all_of(b.begin(), b.end(), [](std::byte v) { return v == std::byte{}; });
}
std::uint64_t Le(Bytes b) noexcept
{
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < b.size(); ++i)
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned>(b[i])) << (i * 8);
    return value;
}
PUCHAR In(Bytes b) noexcept { return reinterpret_cast<PUCHAR>(const_cast<std::byte*>(b.data())); }
PUCHAR Out(std::span<std::byte> b) noexcept { return reinterpret_cast<PUCHAR>(b.data()); }
template<class F> NTSTATUS Cng(F&& operation) noexcept
{
#ifdef APFSACCESS_CRYPTO_TESTING
    auto& hooks = crypto::testing::hooks;
    if (hooks.cng_calls++ == hooks.cng_failure_at)
    {
        if (hooks.cng_fail_after_call) (void)operation();
        return static_cast<NTSTATUS>(0xC0000001UL);
    }
#endif
    return operation();
}
struct Algorithm
{
    Algorithm() = default;
    Algorithm(const Algorithm&) = delete;
    Algorithm& operator=(const Algorithm&) = delete;
    BCRYPT_ALG_HANDLE h = nullptr;
    ~Algorithm() { if (h) BCryptCloseAlgorithmProvider(h, 0); }
};
struct HashHandle
{
    HashHandle() = default;
    HashHandle(const HashHandle&) = delete;
    HashHandle& operator=(const HashHandle&) = delete;
    BCRYPT_HASH_HANDLE h = nullptr;
    ~HashHandle() { if (h) BCryptDestroyHash(h); }
};
struct KeyHandle
{
    KeyHandle() = default;
    KeyHandle(const KeyHandle&) = delete;
    KeyHandle& operator=(const KeyHandle&) = delete;
    BCRYPT_KEY_HANDLE h = nullptr;
    ~KeyHandle() { if (h) BCryptDestroyKey(h); }
};
CryptoResult ObjectStorage(BCRYPT_ALG_HANDLE algorithm) noexcept
{
    ULONG size = 0, written = 0;
    if (Cng([&] { return BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&size),
            sizeof(size), &written, 0); }) < 0 || written != sizeof(size) || size == 0)
        return CryptoFail();
    return SecureBytes::Allocate(size);
}
CryptoResult Digest(Bytes message, Bytes key = {}) noexcept
{
    Algorithm algorithm;
    if (Cng([&] { return BCryptOpenAlgorithmProvider(&algorithm.h, BCRYPT_SHA256_ALGORITHM,
            MS_PRIMITIVE_PROVIDER, key.empty() ? 0 : BCRYPT_ALG_HANDLE_HMAC_FLAG); }) < 0)
        return CryptoFail();
    auto object = ObjectStorage(algorithm.h);
    if (!object) return object;
    HashHandle hash; // destroyed before locked object and algorithm
    if (Cng([&] { return BCryptCreateHash(algorithm.h, &hash.h, Out(object.bytes.Bytes()),
            static_cast<ULONG>(object.bytes.Size()), In(key), static_cast<ULONG>(key.size()), 0); }) < 0)
        return CryptoFail();
    auto result = SecureBytes::Allocate(32);
    if (!result) return result;
    if (Cng([&] { return BCryptHashData(hash.h, In(message), static_cast<ULONG>(message.size()), 0); }) < 0 ||
        Cng([&] { return BCryptFinishHash(hash.h, Out(result.bytes.Bytes()), 32, 0); }) < 0)
        return CryptoFail();
    return result;
}

// Bounded forward-only DER reader: only expected single-octet tags, definite
// shortest lengths, no high-tag-number form, no indefinite length, no recursion.
class Der
{
public:
    explicit Der(Bytes bytes) : rest_(bytes) {}
    bool Take(unsigned tag, Bytes& value) noexcept
    {
        if (rest_.size() < 2 || std::to_integer<unsigned>(rest_[0]) != tag) return false;
        std::size_t count = 2, length = std::to_integer<unsigned>(rest_[1]);
        if (length & 128)
        {
            const std::size_t octets = length & 127;
            if (octets == 0 || octets > 2 || rest_.size() < 2 + octets || rest_[2] == std::byte{})
                return false;
            length = 0;
            for (std::size_t i = 0; i < octets; ++i)
                length = length * 256 + std::to_integer<unsigned>(rest_[2 + i]);
            if (length < 128 || (octets == 2 && length < 256)) return false;
            count += octets;
        }
        if (length > rest_.size() - count) return false;
        value = rest_.subspan(count, length);
        rest_ = rest_.subspan(count + length);
        return true;
    }
    bool Integer(unsigned tag, std::uint64_t& value) noexcept
    {
        Bytes bytes;
        if (!Take(tag, bytes) || bytes.empty() || bytes.size() > 9) return false;
        const auto first = std::to_integer<unsigned>(bytes[0]);
        if (first & 128) return false;
        if (bytes.size() > 1 && first == 0 && (std::to_integer<unsigned>(bytes[1]) & 128) == 0)
            return false;
        if (bytes.size() == 9 && first != 0) return false;
        value = 0;
        for (const auto b : bytes) value = (value << 8) | std::to_integer<unsigned>(b);
        return true;
    }
    Bytes Remaining() const noexcept { return rest_; }
    bool Done() const noexcept { return rest_.empty(); }
private:
    Bytes rest_;
};
struct Record
{
    Bytes wrapped, salt, key_uuid, info;
    std::uint64_t iterations = 0;
    std::size_t key_bytes = 0;
    Bytes checksum, checksum_salt, authenticated;
    std::uint64_t envelope_integer = 0, body_integer = 0;
};
UnlockError ParseRecord(Bytes encoded, bool kek, Record& result) noexcept
{
    if (encoded.empty() || encoded.size() >= 512) return UnlockError::Malformed;
    Der top(encoded);
    Bytes sequence;
    if (!top.Take(0x30, sequence) || !top.Done()) return UnlockError::Malformed;
    Der envelope(sequence);
    std::uint64_t envelope_integer = 0, body_integer = 0;
    Bytes hmac, salt;
    if (!envelope.Integer(0x80, envelope_integer) || !envelope.Take(0x81, hmac) ||
        hmac.size() != 32 || !envelope.Take(0x82, salt) || salt.size() != 8)
        return UnlockError::Malformed;
    const Bytes authenticated = envelope.Remaining(); // includes A3 tag and length
    Bytes body;
    if (!envelope.Take(0xA3, body) || !envelope.Done()) return UnlockError::Malformed;
    Der fields(body);
    Bytes key_uuid, info, wrapped, kdf_salt;
    std::uint64_t iterations = 0;
    if (!fields.Integer(0x80, body_integer) || !fields.Take(0x81, key_uuid) ||
        key_uuid.size() != 16 || !fields.Take(0x82, info)) return UnlockError::Malformed;
    // info's remaining bytes/key UUID are opaque, NOT volume or user UUIDs.
    // No behavior is selected by the unknown envelope/header integer values.
    if (info.size() != 8 && info.size() != 22) return UnlockError::UnsupportedFormat;
    const auto flags = Le(info.first(4));
    if (flags != 0 && flags != 2 && !(kek && flags == 0x10)) return UnlockError::UnsupportedFormat;
    if (!fields.Take(0x83, wrapped)) return UnlockError::Malformed;
    const std::size_t key_bytes = flags == 2 ? 16 : 32;
    if (wrapped.size() != key_bytes + 8) return UnlockError::UnsupportedFormat;
    if (kek && (!fields.Integer(0x84, iterations) || !fields.Take(0x85, kdf_salt) ||
        kdf_salt.size() != 16)) return UnlockError::Malformed;
    if (!fields.Done()) return UnlockError::UnsupportedFormat;
    if (kek && (iterations == 0 || iterations > 1'000'000)) return UnlockError::ResourceLimit;
    // Public-format checksum key, not a password authentication mechanism.
    std::array<std::byte, 14> cookie_salt{std::byte{1}, std::byte{0x16}, std::byte{0x20},
        std::byte{0x17}, std::byte{0x15}, std::byte{5}};
    std::copy(salt.begin(), salt.end(), cookie_salt.begin() + 6);
    auto checksum_key = Digest(cookie_salt);
    if (!checksum_key) return UnlockError::CryptoFailure;
    auto computed = Digest(authenticated, checksum_key.bytes.Bytes());
    if (!computed) return UnlockError::CryptoFailure;
    if (!Equal(computed.bytes.Bytes(), hmac)) return UnlockError::IntegrityFailure;
    result = {wrapped, kdf_salt, key_uuid, info, iterations, key_bytes, hmac, salt, authenticated, envelope_integer, body_integer};
    return UnlockError::None;
}
bool PasswordValid(Bytes password) noexcept
{
    return password.size() <= 1024 &&
        std::find(password.begin(), password.end(), std::byte{}) == password.end();
}
PasswordRecordResult DecodeRecords(Bytes vek_der, Bytes kek_der, Bytes password,
    PasswordUnlockBudget& budget, SecureBytes* recovered_kek = nullptr) noexcept
{
    Record vek, kek;
    auto error = ParseRecord(vek_der, false, vek);
    if (error != UnlockError::None) return Refuse(error);
    error = ParseRecord(kek_der, true, kek);
    if (error != UnlockError::None) return Refuse(error);
    if (!budget.Charge(kek.iterations)) return Refuse(UnlockError::ResourceLimit);
    auto derived = crypto::Pbkdf2HmacSha256(password, kek.salt, kek.iterations, 32);
    if (!derived) return Refuse(UnlockError::CryptoFailure);
    auto unwrapped_kek = crypto::Rfc3394Unwrap(derived.bytes.Bytes().first(kek.key_bytes), kek.wrapped);
    derived.bytes.Clear();
    if (!unwrapped_kek) return Refuse(unwrapped_kek.error == CryptoError::IntegrityFailure
        ? UnlockError::CredentialOrKeyMismatch : UnlockError::CryptoFailure);
    auto unwrapped_vek = crypto::Rfc3394Unwrap(unwrapped_kek.bytes.Bytes(), vek.wrapped);
    if (!recovered_kek) unwrapped_kek.bytes.Clear();
    if (!unwrapped_vek) return Refuse(unwrapped_vek.error == CryptoError::IntegrityFailure
        ? UnlockError::CredentialOrKeyMismatch : UnlockError::CryptoFailure);
    if (vek.key_bytes == 16)
    {
        // Observed legacy FileVault/CoreStorage conversion profile. The DER
        // UUID here identifies the key; using outer volume UUID would be wrong.
        auto expanded = SecureBytes::Allocate(32);
        if (!expanded) return Refuse(UnlockError::CryptoFailure);
        std::copy(unwrapped_vek.bytes.Bytes().begin(), unwrapped_vek.bytes.Bytes().end(), expanded.bytes.Bytes().begin());
        std::copy(vek.key_uuid.begin(), vek.key_uuid.end(), expanded.bytes.Bytes().begin() + 16);
        auto digest = Digest(expanded.bytes.Bytes());
        if (!digest) return Refuse(UnlockError::CryptoFailure);
        std::copy_n(digest.bytes.Bytes().begin(), 16, expanded.bytes.Bytes().begin() + 16);
        unwrapped_vek.bytes = std::move(expanded.bytes);
    }
    if (unwrapped_vek.bytes.Size() != 32 ||
        Equal(unwrapped_vek.bytes.Bytes().first(16), unwrapped_vek.bytes.Bytes().last(16)))
        return Refuse(UnlockError::UnsupportedFormat);
    if (recovered_kek) *recovered_kek = std::move(unwrapped_kek.bytes);
    return {UnlockError::None, std::move(unwrapped_vek.bytes)};
}

CryptoResult WrapKek(Bytes wrapping_key, Bytes plaintext) noexcept
{
    if ((wrapping_key.size() != 16 && wrapping_key.size() != 32) ||
        (plaintext.size() != 16 && plaintext.size() != 32))
        return {CryptoError::InvalidArgument, 0, {}};
    Algorithm algorithm;
    if (Cng([&] { return BCryptOpenAlgorithmProvider(&algorithm.h, BCRYPT_AES_ALGORITHM,
            MS_PRIMITIVE_PROVIDER, 0); }) < 0 ||
        Cng([&] { return BCryptSetProperty(algorithm.h, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_ECB)),
            sizeof(BCRYPT_CHAIN_MODE_ECB), 0); }) < 0) return CryptoFail();
    auto object = ObjectStorage(algorithm.h);
    if (!object) return object;
    KeyHandle key;
    if (Cng([&] { return BCryptGenerateSymmetricKey(algorithm.h, &key.h,
            Out(object.bytes.Bytes()), static_cast<ULONG>(object.bytes.Size()),
            In(wrapping_key), static_cast<ULONG>(wrapping_key.size()), 0); }) < 0)
        return CryptoFail();
    auto state = SecureBytes::Allocate(plaintext.size() + 8);
    if (!state) return state;
    auto scratch = SecureBytes::Allocate(32);
    if (!scratch) return scratch;
    auto buffer = state.bytes.Bytes();
    std::fill_n(buffer.begin(), 8, std::byte{0xA6});
    std::copy(plaintext.begin(), plaintext.end(), buffer.begin() + 8);
    const auto count = plaintext.size() / 8;
    auto input = scratch.bytes.Bytes().first(16), output = scratch.bytes.Bytes().last(16);
    for (std::size_t round = 0; round < 6; ++round)
        for (std::size_t index = 1; index <= count; ++index)
        {
            std::copy_n(buffer.begin(), 8, input.begin());
            std::copy_n(buffer.begin() + index * 8, 8, input.begin() + 8);
            ULONG written = 0;
            if (Cng([&] { return BCryptEncrypt(key.h, Out(input), 16, nullptr,
                    nullptr, 0, Out(output), 16, &written, 0); }) < 0 || written != 16)
                return CryptoFail();
            const std::uint64_t t = count * round + index;
            for (unsigned i = 0; i < 8; ++i)
                buffer[i] = output[i] ^ static_cast<std::byte>((t >> ((7 - i) * 8)) & 255);
            std::copy_n(output.begin() + 8, 8, buffer.begin() + index * 8);
        }
    return state;
}
struct WipedVector
{
    std::vector<std::byte> bytes;
    ~WipedVector() { if (!bytes.empty()) SecureZeroMemory(bytes.data(), bytes.size()); }
};
struct Entry { Bytes uuid, payload; std::uint16_t tag = 0; };
struct Locker
{
    std::array<Entry, kMaxKeybagEntries> entries{};
    std::size_t count = 0;
};
UnlockError ParseLocker(Bytes object, KeybagKind kind, KeybagLength convention,
    Locker& result, ApfsReadBudget& budget) noexcept
{
    if (object.size() < 48) return UnlockError::Malformed;
    const Bytes locker = object.subspan(32);
    if (Le(locker.first(2)) != 2) return UnlockError::UnsupportedFormat;
    const auto count = Le(locker.subspan(2, 2));
    const auto declared = Le(locker.subspan(4, 4));
    if (count > kMaxKeybagEntries) return UnlockError::ResourceLimit;
    if (!budget.Materialize(count, count * sizeof(Entry))) return UnlockError::ResourceLimit;
    std::uint64_t length = declared;
    if (convention == KeybagLength::EntriesOnly) length += 16;
    else if (convention != KeybagLength::IncludesHeader) return UnlockError::InvalidArgument;
    if (length < 16 || length > locker.size()) return UnlockError::Malformed;
    if (!Zero(locker.subspan(8, 8)) || !Zero(locker.subspan(static_cast<std::size_t>(length))))
        return UnlockError::UnsupportedFormat;
    std::size_t cursor = 16;
    for (std::size_t i = 0; i < count; ++i)
    {
        if (length - cursor < 24) return UnlockError::Malformed;
        const auto header = locker.subspan(cursor, 24);
        const auto tag = static_cast<std::uint16_t>(Le(header.subspan(16, 2)));
        const auto bytes = Le(header.subspan(18, 2));
        if (bytes >= 512) return UnlockError::Malformed;
        const auto stride = (24 + static_cast<std::size_t>(bytes) + 15) & ~std::size_t{15};
        if (stride > length - cursor) return UnlockError::Malformed;
        // The alignment gap is outside ke_keydata, not a zero-valued field.
        // Apple-created objects can retain nonzero bytes here; the complete
        // object checksum and DER HMAC still cover their respective frames.
        if (!Zero(header.last(4)))
            return UnlockError::UnsupportedFormat;
        const auto payload = locker.subspan(cursor + 24, static_cast<std::size_t>(bytes));
        if (kind == KeybagKind::Container ? (tag != 2 && tag != 3) : (tag != 3 && tag != 4))
            return UnlockError::UnsupportedFormat;
        if (Zero(header.first(16))) return UnlockError::IdentityMismatch;
        if (kind == KeybagKind::Container && tag == 3)
        {
            if (payload.size() != 16) return UnlockError::Malformed;
            const auto block = Le(payload.first(8)), blocks = Le(payload.last(8));
            constexpr auto limit = static_cast<std::uint64_t>(INT64_MAX);
            if (block == 0 || block > limit || blocks == 0 || blocks > limit - block)
                return UnlockError::Malformed;
        }
        else if (tag != 4)
        {
            Record record;
            const auto error = ParseRecord(payload, kind == KeybagKind::Volume, record);
            if (error != UnlockError::None) return error;
        }
        for (std::size_t j = 0; j < i; ++j)
            if (result.entries[j].tag == tag && Equal(result.entries[j].uuid, header.first(16)))
                return UnlockError::IdentityMismatch;
        result.entries[i] = {header.first(16), payload, tag};
        cursor += stride;
    }
    if (cursor != length) return UnlockError::Malformed;
    result.count = static_cast<std::size_t>(count);
    return UnlockError::None;
}
const Entry* Find(const Locker& locker, const KeybagUuid& uuid, std::uint16_t tag) noexcept
{
    for (std::size_t i = 0; i < locker.count; ++i)
        if (locker.entries[i].tag == tag && Equal(locker.entries[i].uuid, uuid)) return &locker.entries[i];
    return nullptr;
}
bool ObjectMatches(Bytes bytes, const KeybagObjectExpectation& expected,
    std::uint32_t type, std::uint64_t checkpoint, bool allow_zero_oid = false) noexcept
{
    if (bytes.size() < 32 || (!allow_zero_oid && expected.oid == 0) || expected.xid == 0 || expected.xid > checkpoint)
        return false;
    const auto checksum = Fletcher64(bytes.data() + 8, bytes.size() - 8);
    const auto stored = Le(bytes.first(8));
    return checksum && stored != 0 && stored != UINT64_MAX && stored == *checksum &&
        Le(bytes.subspan(8, 8)) == expected.oid && Le(bytes.subspan(16, 8)) == expected.xid &&
        Le(bytes.subspan(24, 4)) == type && Le(bytes.subspan(28, 4)) == 0;
}
bool ReadBlock(const RandomAccessSource& source, std::uint64_t block,
    std::uint32_t size, std::uint64_t blocks, std::vector<std::byte>& out)
{
    if (block >= blocks || block > UINT64_MAX / size) return false;
    const auto offset = block * size;
    if (offset > source.SizeBytes() || size > source.SizeBytes() - offset) return false;
    return source.Read(offset, size, out) && out.size() == size;
}
} // namespace

std::optional<SoftwareKeyRecordEncoding> ObserveSoftwareKeyRecordEncoding(Bytes vek_der, Bytes kek_der)
{
    Record vek, kek;
    if (ParseRecord(vek_der, false, vek) != UnlockError::None || ParseRecord(kek_der, true, kek) != UnlockError::None)
        return std::nullopt;
    SoftwareKeyRecordEncoding result;
    result.vek_envelope_integer = vek.envelope_integer; result.vek_body_integer = vek.body_integer;
    result.kek_envelope_integer = kek.envelope_integer; result.kek_body_integer = kek.body_integer;
    result.vek_info.assign(vek.info.begin(), vek.info.end()); result.kek_info.assign(kek.info.begin(), kek.info.end());
    result.iterations = kek.iterations; result.vek_key_bytes = vek.key_bytes; result.kek_key_bytes = kek.key_bytes;
    return result;
}

bool PasswordUnlockBudget::Begin() noexcept
{
    const auto now = std::chrono::steady_clock::now();
    if (attempts_left_ == 0 || now < next_) return false;
    --attempts_left_;
    next_ = now + std::chrono::milliseconds(250);
    return true;
}
bool PasswordUnlockBudget::Charge(std::uint64_t iterations) noexcept
{
    if (iterations == 0 || iterations > iterations_left_)
    {
        iterations_left_ = 0;
        return false;
    }
    iterations_left_ -= iterations;
    return true;
}
PasswordRecordResult DecodePasswordKeyRecords(Bytes vek, Bytes kek, Bytes password,
    PasswordUnlockBudget& budget) noexcept
{
    if (!budget.Begin()) return Refuse(UnlockError::RateLimited);
    if (!PasswordValid(password)) return Refuse(UnlockError::InvalidArgument);
    return DecodeRecords(vek, kek, password, budget);
}

static PasswordRecordRewrapResult RewrapRecords(Bytes vek_der, Bytes kek_der,
    const SecureBytes& old_password, const SecureBytes& new_password,
    PasswordUnlockBudget& budget) noexcept
{
    const auto fail = [](UnlockError error) { return PasswordRecordRewrapResult{error, {}}; };
    if (!old_password.IsLocked() || !new_password.IsLocked() ||
        !PasswordValid(old_password.Bytes()) || !PasswordValid(new_password.Bytes()) ||
        new_password.Size() == 0 || Equal(old_password.Bytes(), new_password.Bytes()))
        return fail(UnlockError::InvalidArgument);
    try
    {
        SecureBytes kek;
        auto original = DecodeRecords(vek_der, kek_der, old_password.Bytes(), budget, &kek);
        if (!original) return fail(original.error);
        Record record;
        auto status = ParseRecord(kek_der, true, record);
        if (status != UnlockError::None) return fail(status);
        std::vector<std::byte> changed(kek_der.begin(), kek_der.end());
        const auto field = [&](Bytes input) {
            return std::span<std::byte>(changed).subspan(
                static_cast<std::size_t>(input.data() - kek_der.data()), input.size());
        };
        auto salt = field(record.salt), envelope_salt = field(record.checksum_salt);
        if (Cng([&] { return BCryptGenRandom(nullptr, Out(salt), static_cast<ULONG>(salt.size()),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG); }) < 0 ||
            Cng([&] { return BCryptGenRandom(nullptr, Out(envelope_salt),
                static_cast<ULONG>(envelope_salt.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG); }) < 0)
            return fail(UnlockError::CryptoFailure);
        if (!budget.Charge(record.iterations)) return fail(UnlockError::ResourceLimit);
        auto derived = crypto::Pbkdf2HmacSha256(new_password.Bytes(), salt, record.iterations, 32);
        if (!derived) return fail(UnlockError::CryptoFailure);
        auto wrapped = WrapKek(derived.bytes.Bytes().first(record.key_bytes), kek.Bytes());
        derived.bytes.Clear(); kek.Clear();
        if (!wrapped) return fail(UnlockError::CryptoFailure);
        std::copy(wrapped.bytes.Bytes().begin(), wrapped.bytes.Bytes().end(), field(record.wrapped).begin());
        std::array<std::byte, 14> cookie_salt{std::byte{1}, std::byte{0x16}, std::byte{0x20},
            std::byte{0x17}, std::byte{0x15}, std::byte{5}};
        std::copy(envelope_salt.begin(), envelope_salt.end(), cookie_salt.begin() + 6);
        auto checksum_key = Digest(cookie_salt);
        if (!checksum_key) return fail(UnlockError::CryptoFailure);
        auto checksum = Digest(field(record.authenticated), checksum_key.bytes.Bytes());
        if (!checksum) return fail(UnlockError::CryptoFailure);
        std::copy(checksum.bytes.Bytes().begin(), checksum.bytes.Bytes().end(), field(record.checksum).begin());
        auto verified = DecodeRecords(vek_der, changed, new_password.Bytes(), budget);
        if (!verified) return fail(verified.error);
        if (!Equal(original.xts_key.Bytes(), verified.xts_key.Bytes()))
            return fail(UnlockError::IntegrityFailure);
        return {UnlockError::None, std::move(changed)};
    }
    catch (const std::bad_alloc&) { return fail(UnlockError::ResourceLimit); }
}

PasswordRecordRewrapResult RewrapPasswordKeyRecords(Bytes vek_der, Bytes kek_der,
    const SecureBytes& old_password, const SecureBytes& new_password,
    PasswordUnlockBudget& budget) noexcept
{
    if (!budget.Begin()) return {UnlockError::RateLimited, {}};
    return RewrapRecords(vek_der, kek_der, old_password, new_password, budget);
}

static CryptoResult TransformUuidKeybagBlock(const KeybagUuid& uuid, std::uint64_t block,
    Bytes ciphertext, bool encrypt) noexcept
{
    const auto size = ciphertext.size();
    if (Zero(uuid) || size < 4096 || size > 65536 || (size & (size - 1)) ||
        block == 0 || block > (UINT64_MAX - size / 512 + 1) / (size / 512))
        return {CryptoError::InvalidArgument, 0, {}};
    Algorithm algorithm;
    if (Cng([&] { return BCryptOpenAlgorithmProvider(&algorithm.h, BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0); }) < 0 ||
        Cng([&] { return BCryptSetProperty(algorithm.h, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_ECB)),
            sizeof(BCRYPT_CHAIN_MODE_ECB), 0); }) < 0) return CryptoFail();
    auto object = ObjectStorage(algorithm.h);
    if (!object) return object;
    KeyHandle key;
    if (Cng([&] { return BCryptGenerateSymmetricKey(algorithm.h, &key.h, Out(object.bytes.Bytes()),
        static_cast<ULONG>(object.bytes.Size()), In(uuid), 16, 0); }) < 0) return CryptoFail();
    auto output = SecureBytes::Allocate(size);
    if (!output) return output;
    auto scratch = SecureBytes::Allocate(48);
    if (!scratch) return scratch;
    auto tweak = scratch.bytes.Bytes().first(16);
    auto xored = scratch.bytes.Bytes().subspan(16, 16);
    auto transformed = scratch.bytes.Bytes().last(16);
    for (std::size_t sector = 0; sector < size / 512; ++sector)
    {
        std::fill(xored.begin(), xored.end(), std::byte{});
        const auto number = block * (size / 512) + sector;
        for (unsigned i = 0; i < 8; ++i) xored[i] = static_cast<std::byte>((number >> (8 * i)) & 255);
        ULONG written = 0;
        if (Cng([&] { return BCryptEncrypt(key.h, Out(xored), 16, nullptr, nullptr, 0, Out(tweak), 16, &written, 0); }) < 0 ||
            written != 16) return CryptoFail();
        for (std::size_t position = sector * 512; position < (sector + 1) * 512; position += 16)
        {
            for (std::size_t i = 0; i < 16; ++i) xored[i] = ciphertext[position + i] ^ tweak[i];
            if (Cng([&] { return encrypt
                    ? BCryptEncrypt(key.h, Out(xored), 16, nullptr, nullptr, 0, Out(transformed), 16, &written, 0)
                    : BCryptDecrypt(key.h, Out(xored), 16, nullptr, nullptr, 0, Out(transformed), 16, &written, 0);
                }) < 0 || written != 16) return CryptoFail();
            for (std::size_t i = 0; i < 16; ++i) output.bytes.Bytes()[position + i] = transformed[i] ^ tweak[i];
            unsigned carry = 0;
            for (auto& byte : tweak)
            {
                const auto value = std::to_integer<unsigned>(byte);
                byte = static_cast<std::byte>(((value << 1) | carry) & 255);
                carry = value >> 7;
            }
            tweak[0] ^= static_cast<std::byte>(0x87u * carry);
        }
    }
    return output;
}

CryptoResult DecryptApfsUuidKeybagBlock(const KeybagUuid& uuid, std::uint64_t block,
    Bytes ciphertext) noexcept
{
    return TransformUuidKeybagBlock(uuid, block, ciphertext, false);
}
CryptoResult EncryptApfsUuidKeybagBlock(const KeybagUuid& uuid, std::uint64_t block,
    Bytes plaintext) noexcept
{
    return TransformUuidKeybagBlock(uuid, block, plaintext, true);
}

UnlockError SoftwareKeybagRewrap::TransformBags(const RandomAccessSource& source,
    const PasswordUnlockRequest& request, const SecureBytes& old_password,
    const SecureBytes& new_password, PasswordUnlockBudget& budget, SoftwareKeybagRewrap& result)
{
    std::string detail;
    auto cp = LoadContainerCheckpointView(source, 0, source.SizeBytes(), detail, request.checkpoint_xid);
    if (!cp) return UnlockError::IdentityMismatch;
    const auto& nx = cp->superblock;
    const auto block = ReadU64LE(cp->superblock_bytes, 0x510).value_or(0);
    if (ReadU64LE(cp->superblock_bytes, 0x518) != std::uint64_t{1})
        return UnlockError::UnsupportedFormat;
    WipedVector raw;
    if (!ReadBlock(source, block, nx.block_size, nx.block_count, raw.bytes)) return UnlockError::ReadFailure;
    auto container = DecryptApfsUuidKeybagBlock(request.container_uuid, block, raw.bytes);
    if (!container) return UnlockError::CryptoFailure;
    if (!ObjectMatches(container.bytes.Bytes(), request.container_bag, 0x6B657973, nx.xid, true))
        return UnlockError::IdentityMismatch;
    Locker containers;
    auto error = ParseLocker(container.bytes.Bytes(), KeybagKind::Container, request.length,
        containers, *source.ReadBudget());
    if (error != UnlockError::None) return error;
    const auto* reference = Find(containers, request.volume_uuid, 3);
    const auto* vek = Find(containers, request.volume_uuid, 2);
    if (!reference || !vek) return UnlockError::IdentityMismatch;
    const auto volume_block = Le(reference->payload.first(8));
    if (volume_block == block || Le(reference->payload.last(8)) != 1) return UnlockError::UnsupportedFormat;
    if (!ReadBlock(source, volume_block, nx.block_size, nx.block_count, raw.bytes)) return UnlockError::ReadFailure;
    auto volume = DecryptApfsUuidKeybagBlock(request.volume_uuid, volume_block, raw.bytes);
    if (!volume) return UnlockError::CryptoFailure;
    if (!ObjectMatches(volume.bytes.Bytes(), request.volume_bag, 0x72656373, nx.xid, true))
        return UnlockError::IdentityMismatch;
    Locker users;
    error = ParseLocker(volume.bytes.Bytes(), KeybagKind::Volume, request.length, users, *source.ReadBudget());
    if (error != UnlockError::None) return error;
    const auto* kek = Find(users, request.user_uuid, 3);
    if (!kek) return UnlockError::IdentityMismatch;
    auto changed = RewrapRecords(vek->payload, kek->payload, old_password, new_password, budget);
    if (!changed) return changed.error;
    if (changed.kek_der.size() != kek->payload.size()) return UnlockError::UnsupportedFormat;
    const auto offset = static_cast<std::size_t>(kek->payload.data() - volume.bytes.Bytes().data());
    std::copy(changed.kek_der.begin(), changed.kek_der.end(), volume.bytes.Bytes().begin() + offset);
    const auto checksum = Fletcher64(volume.bytes.Bytes().data() + 8, volume.bytes.Size() - 8);
    if (!checksum) return UnlockError::IntegrityFailure;
    for (unsigned i = 0; i < 8; ++i)
        volume.bytes.Bytes()[i] = static_cast<std::byte>((*checksum >> (i * 8)) & 255);
    auto encrypted = EncryptApfsUuidKeybagBlock(request.volume_uuid, volume_block, volume.bytes.Bytes());
    if (!encrypted) return UnlockError::CryptoFailure;
    // Roundtrip the complete authentic object, including opaque alignment bytes.
    auto roundtrip = DecryptApfsUuidKeybagBlock(request.volume_uuid, volume_block, encrypted.bytes.Bytes());
    if (!roundtrip || !Equal(roundtrip.bytes.Bytes(), volume.bytes.Bytes()) ||
        !ObjectMatches(roundtrip.bytes.Bytes(), request.volume_bag, 0x72656373, nx.xid, true))
        return UnlockError::IntegrityFailure;
    result.container_block_ = block;
    result.volume_block_ = volume_block;
    result.original_ = std::move(raw.bytes);
    result.replacement_.assign(encrypted.bytes.Bytes().begin(), encrypted.bytes.Bytes().end());
    return UnlockError::None;
}

PasswordUnlockResult UnlockPasswordKeybags(const RandomAccessSource& source,
    const PasswordUnlockRequest& request, Bytes password, PasswordUnlockBudget& budget)
{
    const auto fail = [](UnlockError error) { PasswordUnlockResult r; r.error = error; return r; };
    if (!budget.Begin()) return fail(UnlockError::RateLimited);
    if (!PasswordValid(password) || request.checkpoint_xid == 0 || request.volume_oid == 0 ||
        Zero(request.container_uuid) || Zero(request.volume_uuid) || Zero(request.user_uuid) ||
        request.container_bag.xid == 0 || request.volume_bag.xid == 0 ||
        (request.length != KeybagLength::EntriesOnly && request.length != KeybagLength::IncludesHeader))
        return fail(UnlockError::InvalidArgument);
    const auto read_budget = source.ReadBudget();
    if (!read_budget || read_budget->Failed()) return fail(UnlockError::ResourceLimit);
    try
    {
        std::string ignored_error; // existing format API diagnostics, never key/password data
        auto checkpoint = LoadContainerCheckpointView(source, 0, source.SizeBytes(), ignored_error,
            request.checkpoint_xid);
        if (!checkpoint) return fail(read_budget->Failed() ? UnlockError::ResourceLimit : UnlockError::IdentityMismatch);
        const auto& nx = checkpoint->superblock;
        const auto& nxbytes = checkpoint->superblock_bytes;
        if ((nx.incompatible_features & ~kNxSupportedIncompatibleFeaturesMask) != 0)
            return fail(UnlockError::UnsupportedFormat);
        if (nxbytes.size() < 0x520 || nx.xid != request.checkpoint_xid ||
            !Equal(Bytes(nxbytes).subspan(72, 16), request.container_uuid) ||
            ReadU32LE(nxbytes, 24) != (kObjectEphemeral | kNxSuperblockObjectType) ||
            ReadU32LE(nxbytes, 28) != 0u ||
            std::find(nx.fs_oids.begin(), nx.fs_oids.end(), request.volume_oid) == nx.fs_oids.end())
            return fail(UnlockError::IdentityMismatch);
        if (nx.block_count > UINT64_MAX / nx.block_size ||
            source.SizeBytes() != nx.block_count * nx.block_size)
            return fail(UnlockError::IdentityMismatch);
        // Force the resolver's strict physical-OMAP identity path. Its legacy
        // compatibility path is intentionally not admitted by password unlock.
        WipedVector omap;
        if (!ReadBlock(source, nx.omap_oid, nx.block_size, nx.block_count, omap.bytes))
            return fail(read_budget->Failed() ? UnlockError::ResourceLimit : UnlockError::ReadFailure);
        const KeybagObjectExpectation omap_identity{nx.omap_oid, ReadU64LE(omap.bytes, 16).value()};
        if (!ObjectMatches(omap.bytes, omap_identity, kObjectPhysical | kObjectTypeOmap, nx.xid) ||
            ReadU32LE(omap.bytes, 40) != (kObjectPhysical | kObjectTypeBtree))
            return fail(UnlockError::IdentityMismatch);
        {
            // The frozen resolver enforces OIDs/storage/subtypes but leaves
            // its optional node-profile policy disabled. Reuse the existing
            // strict parser before resolving: no zero-XID, encrypted, headerless,
            // hashed or unknown node layouts may enter password unlock.
            // Both traversals share the source budget and immutable snapshot.
            const auto tree_oid = ReadU64LE(omap.bytes, 48).value();
            BtreeReadPolicy policy;
            policy.enforce_object_identity = true;
            policy.root_object_id = tree_oid;
            policy.storage_type = kObjectPhysical;
            policy.subtype = kObjectTypeOmap;
            policy.require_complete_traversal = true;
            policy.reject_unsupported_flags = true;
            std::vector<BtreeRecord> checked_records;
            if (!ReadBtreeLeafRecords(source, nx.block_size, tree_oid, true, 0, nx.xid,
                    policy, checked_records, ignored_error))
                return fail(read_budget->Failed() ? UnlockError::ResourceLimit : UnlockError::UnsupportedFormat);
        }
        auto mapping = ResolveOmapValue(source, nx.block_size, nx.omap_oid, request.volume_oid,
            nx.xid, ignored_error);
        if (!mapping || mapping->flags != 0 || mapping->size != nx.block_size || mapping->xid == 0)
            return fail(read_budget->Failed() ? UnlockError::ResourceLimit : UnlockError::UnsupportedFormat);
        WipedVector volume;
        if (!ReadBlock(source, mapping->physical_block, nx.block_size, nx.block_count, volume.bytes))
            return fail(read_budget->Failed() ? UnlockError::ResourceLimit : UnlockError::ReadFailure);
        auto apsb = ParseApsb(volume.bytes);
        if (!apsb || apsb->object_id != request.volume_oid || apsb->xid != mapping->xid ||
            apsb->xid > nx.xid || apsb->uuid_hex != BytesToHexLower(request.volume_uuid.data(), 16) ||
            ReadU32LE(volume.bytes, 24) != kObjectTypeFs || ReadU32LE(volume.bytes, 28) != 0u)
            return fail(UnlockError::IdentityMismatch);
        if (!(apsb->fs_flags & kFsFlagOneKey) || (apsb->fs_flags & kFsFlagUnencrypted))
            return fail(UnlockError::UnsupportedFormat);
        // Apple nx_superblock_t field layout: nx_keylocker at 0x510.
        const auto container_block = ReadU64LE(nxbytes, 0x510).value();
        if (ReadU64LE(nxbytes, 0x518) != std::uint64_t{1}) return fail(UnlockError::UnsupportedFormat);
        WipedVector ciphertext;
        if (!ReadBlock(source, container_block, nx.block_size, nx.block_count, ciphertext.bytes))
            return fail(read_budget->Failed() ? UnlockError::ResourceLimit : UnlockError::ReadFailure);
        auto container = DecryptApfsUuidKeybagBlock(request.container_uuid, container_block, ciphertext.bytes);
        if (!container) return fail(UnlockError::CryptoFailure);
        if (!ObjectMatches(container.bytes.Bytes(), request.container_bag, 0x6B657973, nx.xid, true))
            return fail(UnlockError::IdentityMismatch);
        Locker container_locker;
        auto error = ParseLocker(container.bytes.Bytes(), KeybagKind::Container, request.length, container_locker, *read_budget);
        if (error != UnlockError::None) return fail(error);
        const auto* reference = Find(container_locker, request.volume_uuid, 3);
        const auto* vek = Find(container_locker, request.volume_uuid, 2);
        if (!reference || !vek) return fail(UnlockError::IdentityMismatch);
        const auto volume_block = Le(reference->payload.first(8));
        if (Le(reference->payload.last(8)) != 1) return fail(UnlockError::UnsupportedFormat);
        if (volume_block == container_block) return fail(UnlockError::IdentityMismatch);
        if (!ReadBlock(source, volume_block, nx.block_size, nx.block_count, ciphertext.bytes))
            return fail(read_budget->Failed() ? UnlockError::ResourceLimit : UnlockError::ReadFailure);
        auto bag = DecryptApfsUuidKeybagBlock(request.volume_uuid, volume_block, ciphertext.bytes);
        if (!bag) return fail(UnlockError::CryptoFailure);
        if (!ObjectMatches(bag.bytes.Bytes(), request.volume_bag, 0x72656373, nx.xid, true))
            return fail(UnlockError::IdentityMismatch);
        Locker volume_locker;
        error = ParseLocker(bag.bytes.Bytes(), KeybagKind::Volume, request.length, volume_locker, *read_budget);
        if (error != UnlockError::None) return fail(error);
        const auto* kek = Find(volume_locker, request.user_uuid, 3);
        if (!kek) return fail(UnlockError::IdentityMismatch);
        auto decoded = DecodeRecords(vek->payload, kek->payload, password, budget);
        if (!decoded) return fail(decoded.error);
        PasswordUnlockResult result;
        result.error = UnlockError::None;
        result.container_uuid = request.container_uuid;
        result.volume_uuid = request.volume_uuid;
        result.user_uuid = request.user_uuid;
        result.checkpoint_xid = nx.xid;
        result.volume_oid = apsb->object_id;
        result.volume_xid = apsb->xid;
        result.xts_key = std::move(decoded.xts_key);
        return result;
    }
    catch (const std::bad_alloc&) { return fail(UnlockError::ResourceLimit); }
}

static std::optional<PasswordKeybagMetadata> InspectMetadata(
    const RandomAccessSource& source, std::uint64_t volume_oid,
    KeybagLength length, UnlockError& error, std::optional<std::uint64_t> xid,
    std::uint64_t* container_owner = nullptr, std::uint64_t* volume_owner = nullptr)
{
    error = UnlockError::None;
    const auto fail = [&](UnlockError value) -> std::optional<PasswordKeybagMetadata> {
        error = value; return {};
    };
    if (!volume_oid || (length != KeybagLength::IncludesHeader && length != KeybagLength::EntriesOnly))
        return fail(UnlockError::InvalidArgument);
    const auto budget = source.ReadBudget();
    if (!budget || budget->Failed()) return fail(UnlockError::ResourceLimit);
    try
    {
        std::string detail;
        auto checkpoint = LoadContainerCheckpointView(source, 0, source.SizeBytes(), detail, xid);
        if (!checkpoint) return fail(budget->Failed() ? UnlockError::ResourceLimit : UnlockError::IntegrityFailure);
        const auto& nx = checkpoint->superblock;
        if (nx.block_count > UINT64_MAX / nx.block_size || nx.block_count * nx.block_size != source.SizeBytes())
            return fail(UnlockError::IdentityMismatch);
        if (nx.readonly_features || (nx.incompatible_features & ~kNxSupportedIncompatibleFeaturesMask))
            return fail(UnlockError::UnsupportedFormat);
        auto view = LoadAppleReadOnlyVolumeView(source, *checkpoint, detail);
        if (!view) return fail(budget->Failed() ? UnlockError::ResourceLimit : UnlockError::IntegrityFailure);
        const auto volume = std::find_if(view->volumes.begin(), view->volumes.end(),
            [&](const auto& value) { return value.superblock.object_id == volume_oid; });
        if (volume == view->volumes.end()) return fail(UnlockError::IdentityMismatch);
        const auto& apsb = volume->superblock;
        if (apsb.fs_flags != kFsFlagOneKey) return fail(UnlockError::UnsupportedFormat);
        PasswordKeybagMetadata result;
        auto& selected = result.selection;
        selected.checkpoint_xid = nx.xid; selected.volume_oid = volume_oid; selected.length = length;
        std::copy_n(checkpoint->superblock_bytes.begin()+72, 16, selected.container_uuid.begin());
        WipedVector volume_bytes;
        if (!ReadBlock(source,volume->superblock_object.physical_block,
                nx.block_size,nx.block_count,volume_bytes.bytes))
            return fail(budget->Failed() ? UnlockError::ResourceLimit : UnlockError::IntegrityFailure);
        if (!ObjectMatches(volume_bytes.bytes,{volume_oid,apsb.xid},kObjectTypeFs,nx.xid))
            return fail(UnlockError::IdentityMismatch);
        std::copy_n(volume_bytes.bytes.begin()+0xF0,16,selected.volume_uuid.begin());
        if (BytesToHexLower(selected.volume_uuid.data(),16) != apsb.uuid_hex)
            return fail(UnlockError::IdentityMismatch);
        const auto block = ReadU64LE(checkpoint->superblock_bytes,0x510).value_or(0);
        if (ReadU64LE(checkpoint->superblock_bytes,0x518) != std::uint64_t{1})
            return fail(UnlockError::UnsupportedFormat);
        WipedVector ciphertext;
        if (!ReadBlock(source,block,nx.block_size,nx.block_count,ciphertext.bytes))
            return fail(budget->Failed() ? UnlockError::ResourceLimit : UnlockError::ReadFailure);
        auto container = DecryptApfsUuidKeybagBlock(selected.container_uuid,block,ciphertext.bytes);
        if (!container) return fail(UnlockError::CryptoFailure);
        const auto public_identity = [&](Bytes bytes, std::uint32_t type, KeybagObjectExpectation& identity) {
            if (!VerifyObjectChecksum(bytes,nx.block_size)) return false;
            identity = {ReadU64LE(bytes,8).value(),ReadU64LE(bytes,16).value()};
            return ObjectMatches(bytes,identity,type,nx.xid,true);
        };
        if (!public_identity(container.bytes.Bytes(),0x6B657973,selected.container_bag))
            return fail(UnlockError::IntegrityFailure);
        Locker container_locker;
        auto status = ParseLocker(container.bytes.Bytes(),KeybagKind::Container,length,container_locker,*budget);
        if (status != UnlockError::None) return fail(status);
        const auto* reference = Find(container_locker,selected.volume_uuid,3);
        if (!reference || !Find(container_locker,selected.volume_uuid,2)) return fail(UnlockError::IdentityMismatch);
        const auto volume_block = Le(reference->payload.first(8));
        if (Le(reference->payload.last(8)) != 1) return fail(UnlockError::UnsupportedFormat);
        if (volume_block == block) return fail(UnlockError::IdentityMismatch);
        if (!ReadBlock(source,volume_block,nx.block_size,nx.block_count,ciphertext.bytes))
            return fail(budget->Failed() ? UnlockError::ResourceLimit : UnlockError::ReadFailure);
        auto bag = DecryptApfsUuidKeybagBlock(selected.volume_uuid,volume_block,ciphertext.bytes);
        if (!bag) return fail(UnlockError::CryptoFailure);
        if (!public_identity(bag.bytes.Bytes(),0x72656373,selected.volume_bag)) return fail(UnlockError::IntegrityFailure);
        Locker users;
        status = ParseLocker(bag.bytes.Bytes(),KeybagKind::Volume,length,users,*budget);
        if (status != UnlockError::None) return fail(status);
        for (std::size_t i=0;i<users.count;++i) if (users.entries[i].tag == 3)
        {
            if (!budget->Materialize(1,sizeof(KeybagUuid))) return fail(UnlockError::ResourceLimit);
            KeybagUuid uuid{}; std::copy(users.entries[i].uuid.begin(),users.entries[i].uuid.end(),uuid.begin());
            result.users.push_back(uuid);
        }
        if (result.users.empty()) return fail(UnlockError::IdentityMismatch);
        if (container_owner) *container_owner = block;
        if (volume_owner) *volume_owner = volume_block;
        return result;
    }
    catch (const std::bad_alloc&) { return fail(UnlockError::ResourceLimit); }
}
std::optional<PasswordKeybagMetadata> InspectPasswordKeybagMetadata(
    const RandomAccessSource& source, std::uint64_t volume_oid, KeybagLength length, UnlockError& error)
{
    return InspectMetadata(source, volume_oid, length, error, {});
}
std::optional<PasswordKeybagMetadata> InspectPasswordKeybagMetadataAtCheckpoint(
    const RandomAccessSource& source, std::uint64_t volume_oid, KeybagLength length,
    std::uint64_t xid, UnlockError& error, std::uint64_t& container_block, std::uint64_t& volume_block)
{
    container_block = 0; volume_block = 0;
    if (!xid) { error = UnlockError::InvalidArgument; return {}; }
    return InspectMetadata(source, volume_oid, length, error, xid, &container_block, &volume_block);
}

std::unique_ptr<SoftwareKeybagEraAuthority> SoftwareKeybagEraAuthority::Prove(
    const ImmutableEncryptedReadSource& identity_source, const RandomAccessSource& source,
    const std::string& identity, std::uint64_t revision, const PasswordUnlockResult& admitted,
    const ContainerCheckpointView& admitted_checkpoint, const ApsbVolume& admitted_volume,
    std::uint64_t historical_xid, std::string& error)
{
    error.clear();
    const auto fail = [&](const char* why) -> std::unique_ptr<SoftwareKeybagEraAuthority> { error = why; return {}; };
    const auto bound = [&] { return identity_source.SourceIdentity() == identity &&
        identity_source.Revision() == revision && identity_source.SizeBytes() == source.SizeBytes(); };
    const auto budget = source.ReadBudget();
    if (identity.empty() || !bound() || !admitted || !admitted.xts_key.IsLocked() ||
        !historical_xid || historical_xid >= admitted.checkpoint_xid)
        return fail("SoftwareKeybagEraSourceOrAdmissionMismatch");
    if (!budget || budget->Failed()) return fail("SoftwareKeybagEraResourceLimit");
    try {
        std::string detail;
        auto latest = LoadContainerCheckpointView(source, 0, source.SizeBytes(), detail);
        if (!latest || latest->superblock.xid != admitted.checkpoint_xid ||
            latest->superblock_bytes != admitted_checkpoint.superblock_bytes ||
            admitted.volume_oid != admitted_volume.object_id || admitted.volume_xid != admitted_volume.xid)
            return fail("SoftwareKeybagEraCurrentCanonicalAdmissionRequired");
        struct Era {
            PasswordUnlockRequest selection;
            ContainerCheckpointView checkpoint;
            ApsbVolume volume;
            std::vector<std::byte> apsb;
            crypto::SecureBytes container, users;
            Bytes vek_der;
            Record vek, kek;
            std::uint64_t container_block = 0, volume_block = 0;
        };
        const auto load = [&](std::uint64_t xid, Era& era) {
            auto cp = LoadContainerCheckpointView(source, 0, source.SizeBytes(), detail, xid);
            if (!cp || cp->superblock.block_size != 4096 || cp->superblock.fs_oids != std::vector<std::uint64_t>{admitted.volume_oid} ||
                cp->superblock.readonly_features || cp->superblock.xp_desc_noncontiguous || cp->superblock.xp_data_noncontiguous ||
                ReadU32LE(cp->superblock_bytes, 24) != (kObjectEphemeral | kNxSuperblockObjectType) ||
                ReadU32LE(cp->superblock_bytes, 28) != 0u)
                return false;
            std::uint64_t container_block = 0, volume_block = 0; UnlockError status{};
            auto metadata = InspectMetadata(source, admitted.volume_oid, KeybagLength::IncludesHeader, status,
                xid, &container_block, &volume_block);
            if (!metadata || metadata->users != std::vector<KeybagUuid>{admitted.user_uuid} ||
                metadata->selection.container_uuid != admitted.container_uuid || metadata->selection.volume_uuid != admitted.volume_uuid)
                return false;
            auto view = LoadAppleReadOnlyVolumeView(source, *cp, detail);
            if (!view || view->volumes.size() != 1) return false;
            const auto& selected = view->volumes.front(); const auto& volume = selected.superblock;
            if (volume.object_id != admitted.volume_oid || volume.fs_flags != kFsFlagOneKey || volume.readonly_features ||
                volume.features != admitted_volume.features || volume.incompatible_features != admitted_volume.incompatible_features ||
                volume.role_raw != admitted_volume.role_raw || volume.fext_tree_oid || volume.snap_meta_ext_oid ||
                !ReadBlock(source, selected.superblock_object.physical_block, 4096, cp->superblock.block_count, era.apsb) ||
                !ObjectMatches(era.apsb, {volume.object_id, volume.xid}, kObjectTypeFs, xid) ||
                ReadU64LE(era.apsb, 0xA0).value_or(~0ULL) || ReadU64LE(era.apsb, 0xA8).value_or(~0ULL) ||
                ReadU64LE(era.apsb, 0xD8).value_or(~0ULL) || ReadU64LE(era.apsb, 0x3D0).value_or(~0ULL))
                return false;
            WipedVector raw;
            if (!ReadBlock(source, container_block, 4096, cp->superblock.block_count, raw.bytes)) return false;
            auto container = DecryptApfsUuidKeybagBlock(admitted.container_uuid, container_block, raw.bytes);
            if (!container || !ObjectMatches(container.bytes.Bytes(), metadata->selection.container_bag, 0x6B657973, xid, true))
                return false;
            Locker containers;
            if (ParseLocker(container.bytes.Bytes(), KeybagKind::Container, KeybagLength::IncludesHeader, containers, *budget) != UnlockError::None ||
                containers.count != 2) return false;
            const auto* vek = Find(containers, admitted.volume_uuid, 2);
            const auto* reference = Find(containers, admitted.volume_uuid, 3);
            if (!vek || !reference || Le(reference->payload.first(8)) != volume_block || Le(reference->payload.last(8)) != 1 ||
                ParseRecord(vek->payload, false, era.vek) != UnlockError::None) return false;
            if (!ReadBlock(source, volume_block, 4096, cp->superblock.block_count, raw.bytes)) return false;
            auto users = DecryptApfsUuidKeybagBlock(admitted.volume_uuid, volume_block, raw.bytes);
            if (!users || !ObjectMatches(users.bytes.Bytes(), metadata->selection.volume_bag, 0x72656373, xid, true)) return false;
            Locker locker;
            if (ParseLocker(users.bytes.Bytes(), KeybagKind::Volume, KeybagLength::IncludesHeader, locker, *budget) != UnlockError::None)
                return false;
            const auto* kek = Find(locker, admitted.user_uuid, 3);
            if (!kek || ParseRecord(kek->payload, true, era.kek) != UnlockError::None) return false;
            era.vek_der = vek->payload; era.selection = metadata->selection; era.selection.user_uuid = admitted.user_uuid;
            era.checkpoint = std::move(*cp); era.volume = volume;
            era.container_block = container_block; era.volume_block = volume_block;
            era.container = std::move(container.bytes); era.users = std::move(users.bytes);
            return true;
        };
        Era current, historical;
        if (!load(admitted.checkpoint_xid, current) || !load(historical_xid, historical))
            return fail(budget->Failed() ? "SoftwareKeybagEraResourceLimit" : "SoftwareKeybagEraCanonicalProfileMismatch");
        if (current.volume.xid != admitted.volume_xid || current.checkpoint.superblock_bytes != admitted_checkpoint.superblock_bytes ||
            !Equal(current.vek_der, historical.vek_der) || current.vek.key_bytes != historical.vek.key_bytes ||
            !Equal(current.vek.key_uuid, historical.vek.key_uuid) ||
            !Equal(current.kek.info, historical.kek.info) || !Equal(current.kek.key_uuid, historical.kek.key_uuid) ||
            current.kek.iterations != historical.kek.iterations ||
            !Equal(Bytes(current.apsb).subspan(0x60, 0x18), Bytes(historical.apsb).subspan(0x60, 0x18)))
            return fail("SoftwareKeybagEraWrappedKeyOrCryptoStateChanged");
        if (!bound() || budget->Failed()) return fail("SoftwareKeybagEraSourceOrBudgetChanged");
        if (!budget->Materialize(1, sizeof(SoftwareKeybagEraAuthority))) return fail("SoftwareKeybagEraResourceLimit");
        auto proof = std::unique_ptr<SoftwareKeybagEraAuthority>(new SoftwareKeybagEraAuthority);
        proof->selection_ = historical.selection; proof->checkpoint_ = std::move(historical.checkpoint);
        proof->volume_ = historical.volume;
        proof->container_block_ = historical.container_block; proof->volume_block_ = historical.volume_block;
        proof->current_container_block_ = current.container_block; proof->current_volume_block_ = current.volume_block;
        return proof;
    } catch (const std::bad_alloc&) { return fail("SoftwareKeybagEraResourceLimit"); }
      catch (...) { return fail("SoftwareKeybagEraReadFailure"); }
}

#include "SoftwareKeybagSnapshotEra.inc"

bool SoftwareKeybagRewrap::RelocateBags(std::uint64_t new_container, std::uint64_t new_volume,
    std::uint64_t xid, std::vector<std::byte>& container_out,
    std::vector<std::byte>& volume_out, std::string& error) const
{
    container_out.clear(); volume_out.clear();
    const auto fail = [&] { error = "MaintenanceKeybagRelocationInvalid"; return false; };
    if (!xid || xid <= selection_.checkpoint_xid || new_container == new_volume ||
        !new_container || !new_volume || new_container >= source_->SizeBytes()/4096 ||
        new_volume >= source_->SizeBytes()/4096) return fail();
    WipedVector raw;
    if (!source_->Read(container_block_*4096,4096,raw.bytes)) return fail();
    auto container = DecryptApfsUuidKeybagBlock(selection_.container_uuid,container_block_,raw.bytes);
    auto volume = DecryptApfsUuidKeybagBlock(selection_.volume_uuid,volume_block_,replacement_);
    if (!container || !volume ||
        !ObjectMatches(container.bytes.Bytes(),selection_.container_bag,0x6B657973,selection_.checkpoint_xid,true) ||
        !ObjectMatches(volume.bytes.Bytes(),selection_.volume_bag,0x72656373,selection_.checkpoint_xid,true)) return fail();
    Locker locker;
    if (ParseLocker(container.bytes.Bytes(),KeybagKind::Container,selection_.length,locker,*source_->ReadBudget()) != UnlockError::None)
        return fail();
    const auto* reference = Find(locker,selection_.volume_uuid,3);
    if (!reference || Le(reference->payload.first(8)) != volume_block_ || Le(reference->payload.last(8)) != 1) return fail();
    const auto offset = static_cast<std::size_t>(reference->payload.data()-container.bytes.Bytes().data());
    const auto put = [](std::span<std::byte> bytes,std::size_t at,std::uint64_t value) {
        for(unsigned i=0;i<8;++i) bytes[at+i]=static_cast<std::byte>(value>>(i*8));
    };
    put(container.bytes.Bytes(),offset,new_volume);
    for (auto* bytes : {&container.bytes,&volume.bytes}) {
        put(bytes->Bytes(),16,xid);
        const auto checksum=Fletcher64(bytes->Bytes().data()+8,bytes->Size()-8);
        if(!checksum) return fail();
        put(bytes->Bytes(),0,*checksum);
    }
    auto encrypted_container=EncryptApfsUuidKeybagBlock(selection_.container_uuid,new_container,container.bytes.Bytes());
    auto encrypted_volume=EncryptApfsUuidKeybagBlock(selection_.volume_uuid,new_volume,volume.bytes.Bytes());
    if(!encrypted_container || !encrypted_volume) return fail();
    container_out.assign(encrypted_container.bytes.Bytes().begin(),encrypted_container.bytes.Bytes().end());
    volume_out.assign(encrypted_volume.bytes.Bytes().begin(),encrypted_volume.bytes.Bytes().end());
    return true;
}

#include "SoftwarePristineKeybagConstruction.inc"

bool SoftwareVolumeTransition::InitializeRetainedKeybags(const RandomAccessSource& source,
    const PasswordUnlockRequest& selected, std::uint64_t new_container, std::uint64_t new_volume,
    std::uint64_t xid, const SecureBytes& password, PasswordUnlockBudget& budget,
    SecureBytes& volume_key, std::vector<std::byte>& container_out,
    std::vector<std::byte>& volume_out, std::string& error)
{
    volume_key.Clear(); container_out.clear(); volume_out.clear();
    const auto fail = [&](const char* reason) { error = reason; return false; };
    if (!source.ReadBudget() || !password.IsLocked() || !PasswordValid(password.Bytes()) || !password.Size() ||
        !xid || xid <= selected.checkpoint_xid || !new_container || !new_volume || new_container == new_volume ||
        new_container >= source.SizeBytes() / 4096 || new_volume >= source.SizeBytes() / 4096 || !budget.Begin())
        return fail("SoftwareTransitionKeyInitializationScopeInvalid");
    try {
        UnlockError status{}; std::uint64_t old_container = 0, old_volume = 0;
        auto metadata = InspectPasswordKeybagMetadataAtCheckpoint(source, selected.volume_oid, selected.length,
            selected.checkpoint_xid, status, old_container, old_volume);
        if (!metadata || metadata->selection.container_uuid != selected.container_uuid ||
            metadata->selection.volume_uuid != selected.volume_uuid || metadata->selection.container_bag.oid != selected.container_bag.oid ||
            metadata->selection.container_bag.xid != selected.container_bag.xid || metadata->selection.volume_bag.oid != selected.volume_bag.oid ||
            metadata->selection.volume_bag.xid != selected.volume_bag.xid || metadata->users != std::vector<KeybagUuid>{selected.user_uuid})
            return fail("SoftwareTransitionRetainedBagTemplateChanged");
        WipedVector raw;
        if (!source.Read(old_container * 4096, 4096, raw.bytes) || raw.bytes.size() != 4096)
            return fail("SoftwareTransitionRetainedBagReadFailed");
        auto container = DecryptApfsUuidKeybagBlock(selected.container_uuid, old_container, raw.bytes);
        if (!source.Read(old_volume * 4096, 4096, raw.bytes) || raw.bytes.size() != 4096)
            return fail("SoftwareTransitionRetainedBagReadFailed");
        auto users = DecryptApfsUuidKeybagBlock(selected.volume_uuid, old_volume, raw.bytes);
        if (!container || !users || !ObjectMatches(container.bytes.Bytes(), selected.container_bag, 0x6B657973, selected.checkpoint_xid, true) ||
            !ObjectMatches(users.bytes.Bytes(), selected.volume_bag, 0x72656373, selected.checkpoint_xid, true))
            return fail("SoftwareTransitionRetainedBagObjectInvalid");
        Locker container_locker, user_locker;
        if (ParseLocker(container.bytes.Bytes(), KeybagKind::Container, selected.length, container_locker, *source.ReadBudget()) != UnlockError::None ||
            ParseLocker(users.bytes.Bytes(), KeybagKind::Volume, selected.length, user_locker, *source.ReadBudget()) != UnlockError::None ||
            container_locker.count != 2 || user_locker.count != 1)
            return fail("SoftwareTransitionRetainedBagProfileUnsupported");
        const auto* reference = Find(container_locker, selected.volume_uuid, 3);
        const auto* vek_entry = Find(container_locker, selected.volume_uuid, 2);
        const auto* kek_entry = Find(user_locker, selected.user_uuid, 3);
        if (!reference || !vek_entry || !kek_entry || Le(reference->payload.first(8)) != old_volume || Le(reference->payload.last(8)) != 1)
            return fail("SoftwareTransitionRetainedBagSelectionInvalid");
        Record vek, kek;
        if (ParseRecord(vek_entry->payload, false, vek) != UnlockError::None || ParseRecord(kek_entry->payload, true, kek) != UnlockError::None ||
            vek.key_bytes != 32 || kek.key_bytes != 32 || Le(vek.info.first(4)) != 0 || Le(kek.info.first(4)) != 0)
            return fail("SoftwareTransitionFreshKeyProfileUnsupported");
        auto new_vek = SecureBytes::Allocate(32), new_kek = SecureBytes::Allocate(32);
        const auto random = [](std::span<std::byte> bytes) {
            return Cng([&] { return BCryptGenRandom(nullptr, Out(bytes), static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG); }) >= 0;
        };
        if (!new_vek || !new_kek || !random(new_vek.bytes.Bytes()) || !random(new_kek.bytes.Bytes()) ||
            Equal(new_vek.bytes.Bytes().first(16), new_vek.bytes.Bytes().last(16)))
            return fail("SoftwareTransitionFreshLockedKeyGenerationFailed");
        const auto field = [](SecureBytes& object, Bytes old) {
            return object.Bytes().subspan(static_cast<std::size_t>(old.data() - object.Bytes().data()), old.size());
        };
        if (!random(field(container.bytes, vek.key_uuid)) || !random(field(users.bytes, kek.key_uuid)) ||
            !random(field(container.bytes, vek.checksum_salt)) || !random(field(users.bytes, kek.checksum_salt)) ||
            !random(field(users.bytes, kek.salt)) || !budget.Charge(kek.iterations))
            return fail("SoftwareTransitionFreshRecordGenerationFailed");
        auto derived = crypto::Pbkdf2HmacSha256(password.Bytes(), kek.salt, kek.iterations, 32);
        if (!derived) return fail("SoftwareTransitionFreshPasswordDerivationFailed");
        auto wrapped_kek = WrapKek(derived.bytes.Bytes(), new_kek.bytes.Bytes());
        auto wrapped_vek = WrapKek(new_kek.bytes.Bytes(), new_vek.bytes.Bytes());
        derived.bytes.Clear(); new_kek.bytes.Clear();
        if (!wrapped_kek || !wrapped_vek) return fail("SoftwareTransitionFreshKeyWrapFailed");
        std::copy(wrapped_kek.bytes.Bytes().begin(), wrapped_kek.bytes.Bytes().end(), field(users.bytes, kek.wrapped).begin());
        std::copy(wrapped_vek.bytes.Bytes().begin(), wrapped_vek.bytes.Bytes().end(), field(container.bytes, vek.wrapped).begin());
        const auto authenticate = [&](SecureBytes& object, const Record& record) {
            std::array<std::byte, 14> cookie_salt{std::byte{1}, std::byte{0x16}, std::byte{0x20}, std::byte{0x17}, std::byte{0x15}, std::byte{5}};
            std::copy(record.checksum_salt.begin(), record.checksum_salt.end(), cookie_salt.begin() + 6);
            auto key = Digest(cookie_salt);
            if (!key) return false;
            auto checksum = Digest(record.authenticated, key.bytes.Bytes());
            if (!checksum) return false;
            std::copy(checksum.bytes.Bytes().begin(), checksum.bytes.Bytes().end(), field(object, record.checksum).begin());
            return true;
        };
        if (!authenticate(container.bytes, vek) || !authenticate(users.bytes, kek))
            return fail("SoftwareTransitionFreshRecordChecksumFailed");
        auto verified = DecodeRecords(vek_entry->payload, kek_entry->payload, password.Bytes(), budget);
        if (!verified || !Equal(verified.xts_key.Bytes(), new_vek.bytes.Bytes()))
            return fail("SoftwareTransitionFreshKeyRoundTripFailed");
        const auto put = [](std::span<std::byte> bytes, std::size_t at, std::uint64_t value) {
            for (unsigned i = 0; i < 8; ++i) bytes[at + i] = static_cast<std::byte>(value >> (8 * i));
        };
        put(container.bytes.Bytes(), static_cast<std::size_t>(reference->payload.data() - container.bytes.Bytes().data()), new_volume);
        for (auto* object : {&container.bytes, &users.bytes}) {
            put(object->Bytes(), 16, xid);
            const auto checksum = Fletcher64(object->Bytes().data() + 8, object->Size() - 8);
            if (!checksum) return fail("SoftwareTransitionFreshBagChecksumFailed");
            put(object->Bytes(), 0, *checksum);
        }
        auto encrypted_container = EncryptApfsUuidKeybagBlock(selected.container_uuid, new_container, container.bytes.Bytes());
        auto encrypted_volume = EncryptApfsUuidKeybagBlock(selected.volume_uuid, new_volume, users.bytes.Bytes());
        if (!encrypted_container || !encrypted_volume) return fail("SoftwareTransitionFreshBagEncryptionFailed");
        container_out.assign(encrypted_container.bytes.Bytes().begin(), encrypted_container.bytes.Bytes().end());
        volume_out.assign(encrypted_volume.bytes.Bytes().begin(), encrypted_volume.bytes.Bytes().end());
        volume_key = std::move(new_vek.bytes); return true;
    } catch (...) { return fail("SoftwareTransitionFreshBagResourceFailure"); }
}
} // namespace apfsaccess::catalog
