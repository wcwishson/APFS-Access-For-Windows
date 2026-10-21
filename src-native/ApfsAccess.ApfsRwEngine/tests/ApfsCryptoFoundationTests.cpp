#include "ApfsCrypto.h"
#include "ApfsCryptoTestHooks.h"
#include "ApfsCryptoVectors.h"
#ifndef APFSACCESS_CRYPTO_ONLY_TESTS
#include "ApfsKeybag.h"
#endif

#include <algorithm>
#include <cstring>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

using namespace apfsaccess::crypto;
#ifndef APFSACCESS_CRYPTO_ONLY_TESTS
using namespace apfsaccess::catalog;
#endif
namespace
{
unsigned checks = 0, groups = 0;
#define CHECK(expression) do { ++checks; if (!(expression)) throw std::runtime_error( \
    "check failed at line " + std::to_string(__LINE__) + ": " #expression); } while (false)

std::vector<std::byte> Hex(std::string_view hex)
{
    if (hex.size() % 2) throw std::runtime_error("invalid public hex fixture");
    const auto nibble = [](char c) -> unsigned {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw std::runtime_error("invalid public hex fixture");
    };
    std::vector<std::byte> result;
    for (std::size_t i = 0; i < hex.size(); i += 2)
        result.push_back(static_cast<std::byte>(16 * nibble(hex[i]) + nibble(hex[i+1])));
    return result;
}
bool Same(std::span<const std::byte> a, std::span<const std::byte> b)
{
    return std::equal(a.begin(), a.end(), b.begin(), b.end());
}
bool AllZero(std::span<const std::byte> bytes)
{
    return std::all_of(bytes.begin(), bytes.end(), [](std::byte b) { return b == std::byte{0}; });
}
void Failed(const CryptoResult& result, CryptoError expected)
{
    CHECK(!result);
    CHECK(result.error == expected);
    CHECK(result.bytes.Size() == 0);
    CHECK(!result.bytes.IsLocked());
}
template<class F> void Group(const char* name, F run)
{
    testing::hooks = {};
    run();
    CHECK(testing::hooks.all_released_bytes_zero);
    CHECK(testing::hooks.wipes == testing::hooks.releases);
    ++groups;
    std::cout << "PASS " << name << '\n';
}

// RFC 3394 sections 4.1 through 4.6, independently published plaintext/ciphertext.
struct WrapVector { const char* kek; const char* plain; const char* cipher; };
constexpr WrapVector wraps[] = {
    {"000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF",
     "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"},
    {"000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF",
     "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"},
    {"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF",
     "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"},
    {"000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF0001020304050607",
     "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2"},
    {"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF0001020304050607",
     "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1"},
    {"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
     "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"}
};

void Storage()
{
    static_assert(!std::is_copy_constructible_v<SecureBytes>);
    static_assert(!std::is_copy_assignable_v<SecureBytes>);
    static_assert(std::is_nothrow_move_constructible_v<SecureBytes>);
    static_assert(std::is_nothrow_move_assignable_v<SecureBytes>);
    auto a = SecureBytes::Allocate(31);
    CHECK(a); CHECK(a.bytes.IsLocked()); CHECK(AllZero(a.bytes.Bytes()));
    std::fill(a.bytes.Bytes().begin(), a.bytes.Bytes().end(), std::byte{0x7b});
    const auto* original = a.bytes.Bytes().data();
    SecureBytes b(std::move(a.bytes));
    CHECK(a.bytes.Size() == 0); CHECK(!a.bytes.IsLocked());
    CHECK(b.Bytes().data() == original); CHECK(b.Size() == 31);
    auto c = SecureBytes::Allocate(4097);
    CHECK(c);
    std::fill(c.bytes.Bytes().begin(), c.bytes.Bytes().end(), std::byte{0x9c});
    c.bytes = std::move(b);
    CHECK(b.Size() == 0); CHECK(testing::hooks.releases == 1);
    CHECK(testing::hooks.wiped_bytes >= 4097);
    auto& alias = c.bytes;
    c.bytes = std::move(alias);
    CHECK(c.bytes.Bytes().data() == original);
    c.bytes.Clear(); c.bytes.Clear();
    CHECK(testing::hooks.releases == 2); CHECK(testing::hooks.unlocks == 2);
    CHECK(c.bytes.Size() == 0);
    { auto d = SecureBytes::Allocate(1); CHECK(d); d.bytes.Bytes()[0] = std::byte{0xff}; }
    CHECK(testing::hooks.releases == 3);
}
void StorageFailures()
{
    auto zero = SecureBytes::Allocate(0);
    CHECK(zero); CHECK(!zero.bytes.IsLocked()); CHECK(testing::hooks.allocations == 0);
    Failed(SecureBytes::Allocate(SecureBytes::kMaxBytes + 1), CryptoError::ResourceLimit);
    Failed(SecureBytes::Allocate(std::numeric_limits<std::size_t>::max()), CryptoError::ResourceLimit);
    testing::hooks.allocation_failure_at = 0;
    Failed(SecureBytes::Allocate(17), CryptoError::AllocationFailed);
    CHECK(testing::hooks.locks == 0);
    testing::hooks = {};
    testing::hooks.lock_failure_at = 0;
    auto failed = SecureBytes::Allocate(17);
    Failed(failed, CryptoError::MemoryLockFailed); CHECK(failed.os_status != 0);
    CHECK(testing::hooks.releases == 1); CHECK(testing::hooks.unlocks == 0);
}
void PbkdfVectors()
{
    for (const auto& v : kPbkdfVectors)
    {
        auto password = Hex(v.password), salt = Hex(v.salt), expected = Hex(v.output);
        auto result = Pbkdf2HmacSha256(password, salt, v.iterations, expected.size());
        CHECK(result); CHECK(result.bytes.IsLocked()); CHECK(Same(result.bytes.Bytes(), expected));
        password.push_back(std::byte{0x41});
        auto wrong = Pbkdf2HmacSha256(password, salt, v.iterations, expected.size());
        CHECK(wrong); CHECK(!Same(wrong.bytes.Bytes(), expected)); // KDF does not authenticate.
    }
}
void PbkdfBounds()
{
    const auto pass = Hex(kPbkdfVectors[0].password), salt = Hex(kPbkdfVectors[0].salt);
    Failed(Pbkdf2HmacSha256(pass, salt, 0, 32), CryptoError::InvalidArgument);
    Failed(Pbkdf2HmacSha256(pass, salt, 1, 0), CryptoError::InvalidArgument);
    Failed(Pbkdf2HmacSha256(pass, salt, kMaxPbkdf2Iterations + 1, 32), CryptoError::ResourceLimit);
    Failed(Pbkdf2HmacSha256(pass, salt, UINT64_MAX, 32), CryptoError::ResourceLimit);
    Failed(Pbkdf2HmacSha256(pass, salt, 1, 65), CryptoError::ResourceLimit);
    std::vector<std::byte> long_input(4097);
    Failed(Pbkdf2HmacSha256(long_input, salt, 1, 32), CryptoError::ResourceLimit);
    Failed(Pbkdf2HmacSha256(pass, long_input, 1, 32), CryptoError::ResourceLimit);
    CHECK(testing::hooks.cng_calls == 0); CHECK(testing::hooks.allocations == 0);
}
void UnwrapVectors()
{
    for (const auto& v : wraps)
    {
        const auto kek = Hex(v.kek), cipher = Hex(v.cipher), expected = Hex(v.plain);
        auto result = Rfc3394Unwrap(kek, cipher);
        CHECK(result); CHECK(result.bytes.IsLocked()); CHECK(Same(result.bytes.Bytes(), expected));
    }
}
void UnwrapIntegrity()
{
    for (const auto& v : wraps)
    {
        auto kek = Hex(v.kek), cipher = Hex(v.cipher);
        kek[0] ^= std::byte{1};
        Failed(Rfc3394Unwrap(kek, cipher), CryptoError::IntegrityFailure);
        kek[0] ^= std::byte{1};
        for (std::size_t i = 0; i < cipher.size(); ++i)
        {
            cipher[i] ^= std::byte{0x80};
            Failed(Rfc3394Unwrap(kek, cipher), CryptoError::IntegrityFailure);
            cipher[i] ^= std::byte{0x80};
        }
    }
}
void UnwrapBounds()
{
    const auto kek = Hex(wraps[0].kek), cipher = Hex(wraps[0].cipher);
    for (std::size_t n = 0; n < 24; ++n)
        Failed(Rfc3394Unwrap(kek, std::span(cipher).first(n)), CryptoError::InvalidArgument);
    for (const std::size_t n : {0, 15, 17, 23, 25, 31, 33})
        Failed(Rfc3394Unwrap(std::vector<std::byte>(n), cipher), CryptoError::InvalidArgument);
    auto trailing = cipher; trailing.push_back(std::byte{0});
    Failed(Rfc3394Unwrap(kek, trailing), CryptoError::InvalidArgument);
    Failed(Rfc3394Unwrap(kek, std::vector<std::byte>(4104)), CryptoError::ResourceLimit);
    CHECK(testing::hooks.cng_calls == 0);
}
void XtsVectors()
{
    for (const auto& v : kXtsVectors)
    {
        const auto key = Hex(v.key), tweak = Hex(v.tweak), plain = Hex(v.plain), cipher = Hex(v.cipher);
        auto enc = XtsTransform(key, tweak, plain, XtsDirection::Encrypt);
        CHECK(enc); CHECK(Same(enc.bytes.Bytes(), cipher));
        // Independent ciphertext input, never the preceding encryption output.
        auto dec = XtsTransform(key, tweak, cipher, XtsDirection::Decrypt);
        CHECK(dec); CHECK(Same(dec.bytes.Bytes(), plain));
    }
}
void XtsBounds()
{
    const auto key = Hex(kXtsVectors[0].key), tweak = Hex(kXtsVectors[0].tweak);
    const auto plain = Hex(kXtsVectors[0].plain);
    for (const std::size_t n : {0, 16, 24, 31, 33, 48, 63, 65})
        Failed(XtsTransform(std::vector<std::byte>(n), tweak, plain, XtsDirection::Encrypt), CryptoError::InvalidArgument);
    for (const std::size_t n : {0, 15, 17, 31, 33})
        Failed(XtsTransform(key, tweak, std::vector<std::byte>(n), XtsDirection::Decrypt), CryptoError::InvalidArgument);
    for (const std::size_t n : {0, 15, 17})
        Failed(XtsTransform(key, std::vector<std::byte>(n), plain, XtsDirection::Encrypt), CryptoError::InvalidArgument);
    Failed(XtsTransform(key, tweak, plain, static_cast<XtsDirection>(9)), CryptoError::InvalidArgument);
    Failed(XtsTransform(std::vector<std::byte>(32), tweak, plain, XtsDirection::Decrypt), CryptoError::InvalidArgument);
    Failed(XtsTransform(std::vector<std::byte>(64), tweak, plain, XtsDirection::Encrypt), CryptoError::InvalidArgument);
    Failed(XtsTransform(key, tweak, std::vector<std::byte>(65552), XtsDirection::Encrypt), CryptoError::ResourceLimit);
    CHECK(testing::hooks.cng_calls == 0);
}
void XtsNotAuthenticated()
{
    auto key = Hex(kXtsVectors[0].key), tweak = Hex(kXtsVectors[0].tweak);
    auto cipher = Hex(kXtsVectors[0].cipher), plain = Hex(kXtsVectors[0].plain);
    key[0] ^= std::byte{1};
    auto wrong = XtsTransform(key, tweak, cipher, XtsDirection::Decrypt);
    CHECK(wrong); CHECK(!Same(wrong.bytes.Bytes(), plain));
    key[0] ^= std::byte{1}; cipher[0] ^= std::byte{1};
    auto modified = XtsTransform(key, tweak, cipher, XtsDirection::Decrypt);
    CHECK(modified); CHECK(!Same(modified.bytes.Bytes(), plain));
    cipher[0] ^= std::byte{1}; tweak[15] ^= std::byte{1};
    auto wrong_tweak = XtsTransform(key, tweak, cipher, XtsDirection::Decrypt);
    CHECK(wrong_tweak); CHECK(!Same(wrong_tweak.bytes.Bytes(), plain));
}
// NIST CAVP CAVS 14.0, gcmtestvectors.zip, directly published fixtures:
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
// gcmEncryptExtIV256.rsp, Count=0 for each (PTlen,AADlen) below;
// all Keylen=256, IVlen=96, Taglen=128. Last vector: gcmDecrypt256.rsp,
// Count=0, PTlen=256, AADlen=160. Expected decryption never uses seal output.
struct GcmVector { const char* key; const char* nonce; const char* aad; const char* plain; const char* record; };
constexpr GcmVector gcm_vectors[] = {
    // (0,0)
    {"b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4",
     "516c33929df5a3284ff463d7", "", "", "bdc1ac884d332457a1d2664f168c76f0"},
    // (0,160)
    {"886cff5f3e6b8d0e1ad0a38fcdb26de97e8acbe79f6bed66959a598fa5047d65",
     "3a8efa1cd74bbab5448f9945", "519fee519d25c7a304d6c6aa1897ee1eb8c59655", "",
     "f6d47505ec96c98a42dc3ae719877b87"},
    // (128,0)
    {"31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22",
     "0d18e06c7c725ac9e362e1ce", "", "2db5168e932556f8089a0622981d017d",
     "fa4362189661d163fcd6a56d8bf0405a" "d636ac1bbedd5cc3ee727dc2ab4a9489"},
    // (128,160)
    {"83688deb4af8007f9b713b47cfa6c73e35ea7a3aa4ecdb414dded03bf7a0fd3a",
     "0b459724904e010a46901cf3", "794a14ccd178c8ebfd1379dc704c5e208f9d8424",
     "33d893a2114ce06fc15d55e454cf90c3",
     "cc66bee423e3fcd4c0865715e9586696" "0fb291bd3dba94a1dfd8b286cfb97ac5"},
    // (256,160)
    {"5853c020946b35f2c58ec427152b840420c40029636adcbb027471378cfdde0f",
     "eec313dd07cc1b3e6b068a47", "1389b522c24a774181700553f0246bbabdd38d6f",
     "ce7458e56aef9061cb0c42ec2315565e6168f5a6249ffd31610b6d17ab64935e",
     "eadc3b8766a77ded1a58cb727eca2a9790496c298654cda78febf0da16b6903b"
     "3d49a5b32fde7eafcce90079217ffb57"},
    // (408,160), partial final block
    {"24501ad384e473963d476edcfe08205237acfd49b5b8f33857f8114e863fec7f",
     "9ff18563b978ec281b3f2794", "adb5ec720ccf9898500028bf34afccbcaca126ef",
     "27f348f9cdc0c5bd5e66b1ccb63ad920ff2219d14e8d631b3872265cf117ee86757accb158bd9abb3868fdc0d0b074b5f01b2c",
     "eb7cb754c824e8d96f7c6d9b76c7d26fb874ffbf1d65c6f64a698d839b0b06145dae82057ad55994cf59ad7f67c0fa5e85fab8"
     "bc95c532fecc594c36d1550286a7a3f0"},
    {"c70fcbba915478f66315a15ffc3b11d92c24cbf213cc858f8740713ed9493182",
     "5b413f5dbfccc6a7c65ff5c4", "ee7b3521f1363c1fcbbb24c2c65f7ecee99d457c",
     "f135e924c57ca538f72c700fb0c9c103a70fc1935797cfe08024397f1c1a8277",
     "2ab2d676861b2281d3f740f637c997e25569ec7352e1767ce4c4c9ed5a6ab15a"
     "9a4a3febec6413d461f26364b51237f3"}
};

void GcmVectors()
{
    for (const auto& v : gcm_vectors)
    {
        const auto key = Hex(v.key), nonce = Hex(v.nonce), aad = Hex(v.aad);
        const auto plain = Hex(v.plain), record = Hex(v.record);
        auto sealed = Aes256GcmSeal(key, nonce, plain, aad);
        CHECK(sealed); CHECK(sealed.os_status == 0); CHECK(sealed.bytes.IsLocked());
        CHECK(Same(sealed.bytes.Bytes(), record));
        auto opened = Aes256GcmOpen(key, nonce, record, aad);
        CHECK(opened); CHECK(opened.os_status == 0); CHECK(Same(opened.bytes.Bytes(), plain));
        CHECK(opened.bytes.IsLocked() == !plain.empty());
        CHECK(Same(key, Hex(v.key))); CHECK(Same(nonce, Hex(v.nonce)));
        CHECK(Same(aad, Hex(v.aad))); CHECK(Same(plain, Hex(v.plain))); CHECK(Same(record, Hex(v.record)));
    }
}
void GcmEmpty()
{
    const auto key = Hex(gcm_vectors[0].key), nonce = Hex(gcm_vectors[0].nonce);
    auto record = Hex(gcm_vectors[0].record);
    const auto nonnull_empty = std::span<const std::byte>(key).first(0);
    for (bool nonnull : {false, true})
    {
        const auto empty = nonnull ? nonnull_empty : std::span<const std::byte>{};
        auto sealed = Aes256GcmSeal(key, nonce, empty, empty);
        CHECK(sealed); CHECK(sealed.bytes.Size() == kGcmTagBytes);
        CHECK(Same(sealed.bytes.Bytes(), record));
        auto opened = Aes256GcmOpen(key, nonce, record, empty);
        CHECK(opened); CHECK(opened.bytes.Size() == 0); CHECK(!opened.bytes.IsLocked());
        auto wrong = record; wrong[0] ^= std::byte{1};
        Failed(Aes256GcmOpen(key, nonce, wrong, empty), CryptoError::IntegrityFailure);
    }
}
void GcmIntegrity()
{
    const auto rejected = [](CryptoResult result) {
        Failed(result, CryptoError::IntegrityFailure);
        CHECK(result.os_status == 0xC000A002UL); // SDK STATUS_AUTH_TAG_MISMATCH.
        CHECK(testing::hooks.all_released_bytes_zero);
        CHECK(testing::hooks.releases == testing::hooks.locks);
        CHECK(testing::hooks.unlocks == testing::hooks.locks);
    };
    for (const auto& v : gcm_vectors)
    {
        auto key = Hex(v.key), nonce = Hex(v.nonce), aad = Hex(v.aad), record = Hex(v.record);
        key[0] ^= std::byte{1}; rejected(Aes256GcmOpen(key, nonce, record, aad)); key[0] ^= std::byte{1};
        for (auto& b : nonce)
        { b ^= std::byte{1}; rejected(Aes256GcmOpen(key, nonce, record, aad)); b ^= std::byte{1}; }
        for (auto& b : record) // Every ciphertext AND tag byte; includes tag-only records.
        { b ^= std::byte{1}; rejected(Aes256GcmOpen(key, nonce, record, aad)); b ^= std::byte{1}; }
        for (auto& b : aad)
        { b ^= std::byte{1}; rejected(Aes256GcmOpen(key, nonce, record, aad)); b ^= std::byte{1}; }
        aad.push_back(std::byte{0}); rejected(Aes256GcmOpen(key, nonce, record, aad)); aad.pop_back();
        if (!aad.empty()) rejected(Aes256GcmOpen(key, nonce, record, {}));
        record.push_back(std::byte{0}); rejected(Aes256GcmOpen(key, nonce, record, aad)); record.pop_back();
        if (record.size() > kGcmTagBytes)
            rejected(Aes256GcmOpen(key, nonce, std::span(record).first(record.size() - 1), aad));
    }
    // Independently published FAIL records from gcmDecrypt256.rsp, Count=0,
    // IVlen=96, Taglen=128: (PTlen,AADlen) = (0,160), (408,160).
    rejected(Aes256GcmOpen(Hex("c0b46dc989a7bd45c15553e86a0bf206bf85a5222df1d5a7c8620ec8fa94cb95"),
        Hex("c140cffdba21d9226eca8284"), Hex("54ba2bc9b8621d84e936c839c0de7118"),
        Hex("410a4afa61dd30c2d687ba9cba18fe8a0cd37d58")));
    rejected(Aes256GcmOpen(Hex("e9d381a9c413bee66175d5586a189836e5c20f5583535ab4d3f3e612dc21700e"),
        Hex("23e81571da1c7821c681c7ca"),
        Hex("a25f3f580306cd5065d22a6b7e9660110af7204bb77d370f7f34bee547feeff7b32a596fce29c9040e68b1589aad48da881990"
            "5b6dcd70eefb0892fab1539298b92a4b"), Hex("6f39c9ae7b8e8a58a95f0dd8ea6a9087cbccdfd6")));
}
void GcmBounds()
{
    const auto key = Hex(gcm_vectors[0].key), nonce = Hex(gcm_vectors[0].nonce);
    const auto record = Hex(gcm_vectors[0].record);
    for (const std::size_t n : {0, 16, 24, 31, 33})
    {
        const std::vector<std::byte> bad(n);
        Failed(Aes256GcmSeal(bad, nonce, {}, {}), CryptoError::InvalidArgument);
        Failed(Aes256GcmOpen(bad, nonce, record, {}), CryptoError::InvalidArgument);
    }
    for (const std::size_t n : {0, 1, 11, 13, 16})
    {
        const std::vector<std::byte> bad(n);
        Failed(Aes256GcmSeal(key, bad, {}, {}), CryptoError::InvalidArgument);
        Failed(Aes256GcmOpen(key, bad, record, {}), CryptoError::InvalidArgument);
    }
    for (std::size_t n = 0; n < kGcmTagBytes; ++n)
        Failed(Aes256GcmOpen(key, nonce, std::span(record).first(n), {}), CryptoError::InvalidArgument);
    const std::vector<std::byte> over_record(kMaxGcmRecordBytes + 1), over_aad(kMaxGcmAadBytes + 1);
    Failed(Aes256GcmSeal(key, nonce, std::span(over_record).first(kMaxGcmRecordBytes - kGcmTagBytes + 1), {}),
        CryptoError::ResourceLimit);
    Failed(Aes256GcmOpen(key, nonce, over_record, {}), CryptoError::ResourceLimit);
    Failed(Aes256GcmSeal(key, nonce, {}, over_aad), CryptoError::ResourceLimit);
    Failed(Aes256GcmOpen(key, nonce, record, over_aad), CryptoError::ResourceLimit);
    CHECK(testing::hooks.cng_calls == 0); CHECK(testing::hooks.allocations == 0);
    // Exact limits pass validation. Inject failure at the first secure allocation
    // to exercise admission without depending on the host's 1 MiB lock quota.
    for (bool seal : {false, true})
    {
        testing::hooks = {}; testing::hooks.allocation_failure_at = 0;
        const auto input = std::span(over_record).first(seal ? kMaxGcmRecordBytes - kGcmTagBytes : kMaxGcmRecordBytes);
        const auto aad = std::span(over_aad).first(kMaxGcmAadBytes);
        auto result = seal ? Aes256GcmSeal(key, nonce, input, aad) : Aes256GcmOpen(key, nonce, input, aad);
        Failed(result, CryptoError::AllocationFailed); CHECK(result.os_status != 0);
        CHECK(testing::hooks.cng_calls > 0); CHECK(testing::hooks.locks == 0);
    }
}

template<class F> void FailureSweep(F operation)
{
    testing::hooks = {};
    { auto result = operation(); CHECK(result); }
    const auto baseline = testing::hooks;
    for (bool after : {false, true})
    {
        for (int i = 0; i < baseline.cng_calls; ++i)
        {
            testing::hooks = {};
            testing::hooks.cng_failure_at = i;
            testing::hooks.cng_fail_after_call = after;
            Failed(operation(), CryptoError::ProviderFailure);
            CHECK(testing::hooks.all_released_bytes_zero);
            CHECK(testing::hooks.releases == testing::hooks.locks);
            CHECK(testing::hooks.releases == testing::hooks.unlocks);
        }
    }
    for (int i = 0; i < baseline.allocations; ++i)
    {
        testing::hooks = {}; testing::hooks.allocation_failure_at = i;
        Failed(operation(), CryptoError::AllocationFailed);
        CHECK(testing::hooks.releases == i); CHECK(testing::hooks.all_released_bytes_zero);
        testing::hooks = {}; testing::hooks.lock_failure_at = i;
        Failed(operation(), CryptoError::MemoryLockFailed);
        CHECK(testing::hooks.releases == i + 1); CHECK(testing::hooks.unlocks == i);
        CHECK(testing::hooks.all_released_bytes_zero);
    }
}

void GcmFailures(bool seal)
{
    for (const std::size_t index : {0, 1, 5}) // Empty, AAD-only and partial multiblock.
    {
        const auto& v = gcm_vectors[index];
        const auto key = Hex(v.key), nonce = Hex(v.nonce), aad = Hex(v.aad);
        const auto input = Hex(seal ? v.plain : v.record);
        const auto operation = [&] { return seal ? Aes256GcmSeal(key, nonce, input, aad)
                                               : Aes256GcmOpen(key, nonce, input, aad); };
        FailureSweep(operation);
        testing::hooks = {};
        { auto result = operation(); CHECK(result); }
        const auto baseline = testing::hooks;
        CHECK(baseline.allocations == ((!seal && index < 2) ? 1 : 2));
        CHECK(baseline.unlocks == baseline.allocations);
        testing::hooks = {};
        testing::hooks.cng_failure_at = baseline.cng_calls - 1;
        testing::hooks.cng_fail_after_call = true;
        auto failed = operation(); // Fail after real encryption/decryption/tag processing.
        Failed(failed, CryptoError::ProviderFailure); CHECK(failed.os_status != 0);
        CHECK(testing::hooks.releases == baseline.allocations);
        CHECK(testing::hooks.wipes == baseline.allocations);
        CHECK(testing::hooks.unlocks == baseline.allocations);
        CHECK(testing::hooks.all_released_bytes_zero);
    }
}

#ifndef APFSACCESS_CRYPTO_ONLY_TESTS
void Put(std::vector<std::byte>& b, std::size_t offset, std::uint64_t value, std::size_t n)
{
    for (std::size_t i = 0; i < n; ++i) b.at(offset + i) = static_cast<std::byte>((value >> (8*i)) & 255);
}
std::vector<std::byte> Locker(std::uint16_t tag = 3, std::size_t payload = 16,
    KeybagLength length = KeybagLength::EntriesOnly)
{
    std::vector<std::byte> b(16 + ((24 + payload + 15) & ~std::size_t{15}));
    Put(b, 0, 2, 2); Put(b, 2, 1, 2);
    Put(b, 4, length == KeybagLength::EntriesOnly ? b.size() - 16 : b.size(), 4);
    b[16] = std::byte{0x01}; b[31] = std::byte{0xfe};
    Put(b, 32, tag, 2); Put(b, 34, payload, 2);
    if (tag == 3 && payload == 16) { Put(b, 40, 100, 8); Put(b, 48, 2, 8); }
    return b;
}
void BadBag(const std::vector<std::byte>& bag, KeybagError expected,
    KeybagKind kind = KeybagKind::Container)
{
    auto result = ParseKeybagMetadata(bag, kind, KeybagLength::EntriesOnly);
    CHECK(!result); CHECK(result.error == expected); CHECK(result.entries.empty());
}
void KeybagMetadata()
{
    for (auto length : {KeybagLength::EntriesOnly, KeybagLength::IncludesHeader})
    {
        auto bag = Locker(3, 16, length);
        auto result = ParseKeybagMetadata(bag, KeybagKind::Container, length);
        CHECK(result); CHECK(result.entries.size() == 1);
        CHECK(result.entries[0].uuid[0] == std::byte{1}); CHECK(result.entries[0].uuid[15] == std::byte{0xfe});
        CHECK(result.entries[0].keybag_start_block == 100); CHECK(result.entries[0].keybag_block_count == 2);
        auto mismatch = ParseKeybagMetadata(bag, KeybagKind::Container,
            length == KeybagLength::EntriesOnly ? KeybagLength::IncludesHeader : KeybagLength::EntriesOnly);
        CHECK(!mismatch); CHECK(mismatch.entries.empty());
    }
    auto hint = Locker(4, 5);
    hint[40] = std::byte{0x41}; hint[44] = std::byte{0x42};
    auto result = ParseKeybagMetadata(hint, KeybagKind::Volume, KeybagLength::EntriesOnly);
    CHECK(result); CHECK(result.entries[0].payload_bytes == 5);
    CHECK(result.entries[0].keybag_start_block == 0);
    std::vector<std::byte> empty(16); Put(empty, 0, 2, 2);
    auto no_entries = ParseKeybagMetadata(empty, KeybagKind::Container, KeybagLength::EntriesOnly);
    CHECK(no_entries); CHECK(no_entries.entries.empty());
    auto two = Locker(); const auto other = two;
    two.insert(two.end(), other.begin() + 16, other.end());
    Put(two, 2, 2, 2); Put(two, 4, two.size() - 16, 4); two[64] = std::byte{2};
    auto pair = ParseKeybagMetadata(two, KeybagKind::Container, KeybagLength::EntriesOnly);
    CHECK(pair); CHECK(pair.entries.size() == 2); CHECK(pair.entries[1].uuid[0] == std::byte{2});
}
void KeybagMalformed()
{
    const auto original = Locker();
    for (std::size_t n = 0; n < original.size(); ++n)
    {
        auto cut = std::vector<std::byte>(original.begin(), original.begin() + n);
        BadBag(cut, KeybagError::Malformed);
        if (n >= 16) { Put(cut, 4, n - 16, 4); BadBag(cut, KeybagError::Malformed); }
    }
    for (std::size_t extra = 1; extra <= 32; ++extra)
    {
        auto trailing = original; trailing.resize(trailing.size() + extra);
        BadBag(trailing, KeybagError::Malformed);
        Put(trailing, 4, trailing.size() - 16, 4); BadBag(trailing, KeybagError::Malformed);
    }
    for (std::uint64_t value : {0ULL, 15ULL, 0xffffffffULL})
    { auto b = original; Put(b, 4, value, 4); BadBag(b, KeybagError::Malformed); }
    for (std::uint64_t value : {0ULL, 2ULL})
    { auto b = original; Put(b, 2, value, 2); BadBag(b, KeybagError::Malformed); }
    for (std::uint64_t value : {0ULL, 15ULL, 17ULL, 511ULL, 512ULL, 65535ULL})
    { auto b = original; Put(b, 34, value, 2); BadBag(b, KeybagError::Malformed); }
    for (std::size_t offset : {8, 15, 36, 39, 56, 63})
    { auto b = original; b[offset] = std::byte{1}; BadBag(b, KeybagError::UnsupportedPadding); }
    auto b = original; Put(b, 0, 1, 2); BadBag(b, KeybagError::UnsupportedVersion);
    b = original; Put(b, 2, 1025, 2); BadBag(b, KeybagError::ResourceLimit);
    b.resize(kMaxKeybagLockerBytes + 1); BadBag(b, KeybagError::ResourceLimit);
}
void KeybagUnsupported()
{
    for (const auto tag : {0, 1, 4, 5, 6, 0xf8, 0x8003, 0xffff})
        BadBag(Locker(static_cast<std::uint16_t>(tag)), KeybagError::UnsupportedTag);
    BadBag(Locker(2), KeybagError::UnsupportedTag, KeybagKind::Volume);
    BadBag(Locker(2), KeybagError::UnsupportedKeyPayload);
    BadBag(Locker(3), KeybagError::UnsupportedKeyPayload, KeybagKind::Volume);
    // Arbitrary DER classes/bits cannot escape through an opaque key payload.
    for (unsigned value = 0; value <= 255; ++value)
    {
        auto b = Locker(2); b[40] = static_cast<std::byte>(value);
        BadBag(b, KeybagError::UnsupportedKeyPayload);
    }
    auto first = Locker(), second = Locker(2);
    first.insert(first.end(), second.begin() + 16, second.end());
    Put(first, 2, 2, 2); Put(first, 4, first.size() - 16, 4);
    BadBag(first, KeybagError::UnsupportedKeyPayload); // No partial valid entry.
    auto bad_kind = ParseKeybagMetadata(Locker(), static_cast<KeybagKind>(99), KeybagLength::EntriesOnly);
    CHECK(!bad_kind); CHECK(bad_kind.error == KeybagError::InvalidArgument);
    auto bad_length = ParseKeybagMetadata(Locker(), KeybagKind::Container, static_cast<KeybagLength>(99));
    CHECK(!bad_length); CHECK(bad_length.entries.empty());
}
void KeybagRanges()
{
    for (auto start : {0ULL, 0x8000000000000000ULL, 0xffffffffffffffffULL, 0x7fffffffffffffffULL})
    { auto b = Locker(); Put(b, 40, start, 8); BadBag(b, KeybagError::Malformed); }
    for (auto count : {0ULL, 0x7fffffffffffffffULL, 0xffffffffffffffffULL})
    { auto b = Locker(); Put(b, 48, count, 8); BadBag(b, KeybagError::Malformed); }
}
class ShortSource final : public RandomAccessSource
{
public:
    mutable unsigned reads = 0;
    bool returns_true = true;
    bool oversized = false;
    std::uint64_t SizeBytes() const override { return UINT64_MAX; }
    bool Read(std::uint64_t, std::size_t n, std::vector<std::byte>& out) const override
    {
        ++reads; out.assign(oversized ? n + 1 : n - 1, std::byte{0x6a}); return returns_true;
    }
};
void KeybagSources()
{
    const auto bag = Locker();
    VectorRandomAccessSource vector(bag);
    auto budget = std::make_shared<ApfsReadBudget>(1, bag.size(), 1, sizeof(KeybagMetadataEntry));
    BudgetedRandomAccessSource source(vector, budget);
    auto result = ReadKeybagMetadata(source, 0, bag.size(), KeybagKind::Container, KeybagLength::EntriesOnly);
    CHECK(result); CHECK(result.entries.size() == 1);
    auto again = ReadKeybagMetadata(source, 0, bag.size(), KeybagKind::Container, KeybagLength::EntriesOnly);
    CHECK(!again); CHECK(again.error == KeybagError::ResourceLimit); CHECK(again.entries.empty());
    CHECK(budget->Failed());
    ApfsReadBudget no_records(1, bag.size(), 0, 9999);
    auto denied = ParseKeybagMetadata(bag, KeybagKind::Container, KeybagLength::EntriesOnly, &no_records);
    CHECK(!denied); CHECK(denied.entries.empty()); CHECK(no_records.Failed());
    ApfsReadBudget no_bytes(1, bag.size(), 1, sizeof(KeybagMetadataEntry) - 1);
    CHECK(!ParseKeybagMetadata(bag, KeybagKind::Container, KeybagLength::EntriesOnly, &no_bytes));
    ShortSource short_source;
    for (bool returns_true : {true, false})
    {
        short_source.returns_true = returns_true;
        auto short_read = ReadKeybagMetadata(short_source, 0, 64, KeybagKind::Container, KeybagLength::EntriesOnly);
        CHECK(!short_read); CHECK(short_read.error == KeybagError::ReadFailure); CHECK(short_read.entries.empty());
    }
    short_source.returns_true = true; short_source.oversized = true;
    CHECK(!ReadKeybagMetadata(short_source, 0, 64, KeybagKind::Container, KeybagLength::EntriesOnly));
    const auto reads = short_source.reads;
    CHECK(!ReadKeybagMetadata(short_source, UINT64_MAX - 7, 64, KeybagKind::Container, KeybagLength::EntriesOnly));
    CHECK(!ReadKeybagMetadata(short_source, 0, kMaxKeybagLockerBytes + 1, KeybagKind::Container, KeybagLength::EntriesOnly));
    CHECK(!ReadKeybagMetadata(short_source, 0, 15, KeybagKind::Container, KeybagLength::EntriesOnly));
    CHECK(short_source.reads == reads);
    CHECK(!ReadKeybagMetadata(vector, 1, bag.size(), KeybagKind::Container, KeybagLength::EntriesOnly));
}
#endif // APFSACCESS_CRYPTO_ONLY_TESTS
} // namespace

int main()
{
    try
    {
        Group("secure move, assignment, self-move, clear and destructor", Storage);
        Group("secure allocation/lock failure and bounds", StorageFailures);
        Group("PBKDF2 published vectors and wrong input", PbkdfVectors);
        Group("PBKDF2 resource and argument bounds", PbkdfBounds);
        Group("RFC 3394 six published vectors", UnwrapVectors);
        Group("RFC 3394 wrong key and every ciphertext byte modified", UnwrapIntegrity);
        Group("RFC 3394 invalid key/short/trailing/oversized ciphertext", UnwrapBounds);
        Group("XTS independent encryption and decryption vectors", XtsVectors);
        Group("XTS key/tweak/data-unit/direction bounds", XtsBounds);
        Group("XTS wrong key, ciphertext and tweak are not authenticated", XtsNotAuthenticated);
        Group("GCM NIST CAVP independent seal/open KATs: empty, AAD, multiblock and partial block", GcmVectors);
        Group("GCM tag-only authentication with null and non-null empty spans", GcmEmpty);
        Group("GCM wrong key/nonce/AAD, every record byte, framing and NIST FAIL vectors", GcmIntegrity);
        Group("GCM exact key/nonce sizes and record/AAD resource limits", GcmBounds);
        Group("GCM seal exhaustive CNG/allocation/lock failures and wipes", [] { GcmFailures(true); });
        Group("GCM open exhaustive CNG/allocation/lock failures and wipes", [] { GcmFailures(false); });
        Group("PBKDF2 exhaustive CNG/allocation/lock failure points", [] {
            const auto pass = Hex(kPbkdfVectors[0].password), salt = Hex(kPbkdfVectors[0].salt);
            FailureSweep([&] { return Pbkdf2HmacSha256(pass, salt, 2, 32); });
        });
        Group("unwrap exhaustive CNG/allocation/lock failure points", [] {
            const auto kek = Hex(wraps[0].kek), cipher = Hex(wraps[0].cipher);
            FailureSweep([&] { return Rfc3394Unwrap(kek, cipher); });
        });
        for (auto direction : {XtsDirection::Encrypt, XtsDirection::Decrypt})
            Group("XTS exhaustive CNG/allocation/lock failure points", [&] {
                const auto key = Hex(kXtsVectors[0].key), tweak = Hex(kXtsVectors[0].tweak);
                const auto input = Hex(direction == XtsDirection::Encrypt ? kXtsVectors[0].plain : kXtsVectors[0].cipher);
                FailureSweep([&] { return XtsTransform(key, tweak, input, direction); });
            });
#ifndef APFSACCESS_CRYPTO_ONLY_TESTS
        Group("keybag explicit framing conventions and metadata subset", KeybagMetadata);
        Group("keybag all truncations, trailing data, count/length/padding", KeybagMalformed);
        Group("keybag unknown tags/classes and no partial metadata", KeybagUnsupported);
        Group("keybag signed physical-range overflow", KeybagRanges);
        Group("keybag exact source reads and shared read/materialization budgets", KeybagSources);
#endif
        std::cout << "PASS " << groups << " groups / " << checks << " assertions; "
            << std::size(kPbkdfVectors) << " PBKDF2, " << std::size(wraps) << " RFC3394, "
            << std::size(kXtsVectors) << " XTS, " << std::size(gcm_vectors)
            << " GCM public KATs (XTS/GCM both directions).\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "FAIL " << error.what() << '\n'; // Never prints input/output bytes.
        return 1;
    }
}
