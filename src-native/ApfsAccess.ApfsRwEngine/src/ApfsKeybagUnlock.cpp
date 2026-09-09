#include "ApfsKeybagUnlock.h"
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
    Bytes wrapped, salt, key_uuid;
    std::uint64_t iterations = 0;
    std::size_t key_bytes = 0;
};
UnlockError ParseRecord(Bytes encoded, bool kek, Record& result) noexcept
{
    if (encoded.empty() || encoded.size() >= 512) return UnlockError::Malformed;
    Der top(encoded);
    Bytes sequence;
    if (!top.Take(0x30, sequence) || !top.Done()) return UnlockError::Malformed;
    Der envelope(sequence);
    std::uint64_t opaque_integer = 0;
    Bytes hmac, salt;
    if (!envelope.Integer(0x80, opaque_integer) || !envelope.Take(0x81, hmac) ||
        hmac.size() != 32 || !envelope.Take(0x82, salt) || salt.size() != 8)
        return UnlockError::Malformed;
    const Bytes authenticated = envelope.Remaining(); // includes A3 tag and length
    Bytes body;
    if (!envelope.Take(0xA3, body) || !envelope.Done()) return UnlockError::Malformed;
    Der fields(body);
    Bytes key_uuid, info, wrapped, kdf_salt;
    std::uint64_t iterations = 0;
    if (!fields.Integer(0x80, opaque_integer) || !fields.Take(0x81, key_uuid) ||
        key_uuid.size() != 16 || !fields.Take(0x82, info)) return UnlockError::Malformed;
    // info's remaining bytes/key UUID are opaque, NOT volume or user UUIDs.
    // No behavior is selected by the unknown envelope/header integer values.
    if (info.size() != 22) return UnlockError::UnsupportedFormat;
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
    result = {wrapped, kdf_salt, key_uuid, iterations, key_bytes};
    return UnlockError::None;
}
bool PasswordValid(Bytes password) noexcept
{
    return password.size() <= 1024 &&
        std::find(password.begin(), password.end(), std::byte{}) == password.end();
}
PasswordRecordResult DecodeRecords(Bytes vek_der, Bytes kek_der, Bytes password,
    PasswordUnlockBudget& budget) noexcept
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
    unwrapped_kek.bytes.Clear();
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
    return {UnlockError::None, std::move(unwrapped_vek.bytes)};
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
        if (!Zero(header.last(4)) || !Zero(locker.subspan(cursor + 24 + bytes, stride - 24 - bytes)))
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
    std::uint32_t type, std::uint64_t checkpoint) noexcept
{
    if (bytes.size() < 32 || expected.oid == 0 || expected.xid == 0 || expected.xid > checkpoint)
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

CryptoResult DecryptApfsUuidKeybagBlock(const KeybagUuid& uuid, std::uint64_t block,
    Bytes ciphertext) noexcept
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
            if (Cng([&] { return BCryptDecrypt(key.h, Out(xored), 16, nullptr, nullptr, 0,
                    Out(transformed), 16, &written, 0); }) < 0 || written != 16) return CryptoFail();
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

PasswordUnlockResult UnlockPasswordKeybags(const RandomAccessSource& source,
    const PasswordUnlockRequest& request, Bytes password, PasswordUnlockBudget& budget)
{
    const auto fail = [](UnlockError error) { PasswordUnlockResult r; r.error = error; return r; };
    if (!budget.Begin()) return fail(UnlockError::RateLimited);
    if (!PasswordValid(password) || request.checkpoint_xid == 0 || request.volume_oid == 0 ||
        Zero(request.container_uuid) || Zero(request.volume_uuid) || Zero(request.user_uuid) ||
        request.container_bag.oid == 0 || request.container_bag.xid == 0 ||
        request.volume_bag.oid == 0 || request.volume_bag.xid == 0 ||
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
        if (!ObjectMatches(container.bytes.Bytes(), request.container_bag, 0x6B657973, nx.xid))
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
        if (!ObjectMatches(bag.bytes.Bytes(), request.volume_bag, 0x72656373, nx.xid))
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
} // namespace apfsaccess::catalog
