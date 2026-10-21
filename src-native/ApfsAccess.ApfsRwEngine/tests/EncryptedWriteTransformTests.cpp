// Write-side inverse of the encrypted read session's metadata decrypt path,
// proven against the read suite's own fixture vectors: decrypting a known
// fixture block and re-encrypting it must reproduce the fixture bytes
// exactly. File-data tweaks (crypto_id-assigned) are deliberately out of
// scope: crypto_id assignment needs platform truth to avoid tweak reuse.
#include "ApfsEncryptedWriteTransform.h"
#include "ApfsEncryptedReadVectors.h"
#include "ApfsKeybagUnlockVectors.h"
#include "ApfsKeybagUnlock.h"
#include "TestFixtureBuilder.h"
#include <algorithm>
#include <iostream>
#include <stdexcept>
using namespace apfsaccess::catalog;
using namespace apfsaccess::crypto;
using namespace apfsaccess::testfixture;
namespace f = apfsaccess::encrypted_fixture;
namespace k = apfsaccess::keybag_fixture;
namespace {
unsigned cases = 0, checks = 0;
void Check(bool value, const std::string& text) { ++checks; if (!value) throw std::runtime_error(text); }
void Pass(const std::string& text) { ++cases; std::cout << "PASS " << text << '\n'; }
std::vector<std::byte> Hex(std::string_view s) { return HexToBytes(std::string(s)); }
std::vector<std::byte> VolumeKey() {
    PasswordUnlockBudget budget;
    auto decoded = DecodePasswordKeyRecords(Hex(k::Vek), Hex(k::Kek), Hex(k::Password), budget);
    Check(static_cast<bool>(decoded) && decoded.xts_key.Size() == 32, "fixture volume key unwraps");
    std::vector<std::byte> key(decoded.xts_key.Size());
    std::copy(decoded.xts_key.Bytes().begin(), decoded.xts_key.Bytes().end(), key.begin());
    return key;
}
std::vector<std::byte> DecryptUnit(const std::vector<std::byte>& key, std::uint64_t unit,
    const std::byte* cipher) {
    std::array<std::byte, 16> tweak{};
    for (unsigned i = 0; i < 8; ++i) tweak[i] = static_cast<std::byte>(unit >> (8 * i));
    auto piece = XtsTransform(key, tweak, std::span<const std::byte>(cipher, 512), XtsDirection::Decrypt);
    Check(static_cast<bool>(piece) && piece.bytes.Size() == 512, "fixture unit decrypts");
    std::vector<std::byte> plain(512);
    std::copy(piece.bytes.Bytes().begin(), piece.bytes.Bytes().end(), plain.begin());
    return plain;
}
void FixtureRoundTrip() {
    // SmallRoot lives at block 80 with 4K blocks: units 640..647.
    const auto key = VolumeKey();
    const auto cipher = Hex(f::SmallRoot);
    Check(cipher.size() == 4096, "fixture root is one block");
    std::vector<std::byte> plain;
    for (std::uint64_t i = 0; i < 8; ++i) {
        const auto unit = DecryptUnit(key, 80 * 8 + i, cipher.data() + i * 512);
        plain.insert(plain.end(), unit.begin(), unit.end());
    }
    Check(VerifyObjectChecksum(plain, plain.size()), "decrypted fixture checksum verifies");
    const auto reencrypted = EncryptAppleMetadataBlock(key, 80, plain);
    Check(static_cast<bool>(reencrypted), "re-encryption succeeds");
    Check(reencrypted.bytes == cipher, "re-encrypted bytes match the fixture exactly");
    Pass("fixture decrypt/re-encrypt round-trips byte-for-byte");
}
void Refusals() {
    const auto key = VolumeKey();
    const auto cipher = Hex(f::SmallRoot);
    std::vector<std::byte> plain;
    for (std::uint64_t i = 0; i < 8; ++i) {
        const auto unit = DecryptUnit(key, 80 * 8 + i, cipher.data() + i * 512);
        plain.insert(plain.end(), unit.begin(), unit.end());
    }
    const auto expect = [&](EncryptedWriteError error, const std::vector<std::byte>& k,
        std::uint64_t block, const std::vector<std::byte>& body) {
        const auto result = EncryptAppleMetadataBlock(k, block, body);
        Check(!result && result.error == error && result.bytes.empty(), "refusal pins exact error");
    };
    expect(EncryptedWriteError::InvalidArgument, std::vector<std::byte>(key.begin(), key.begin() + 16), 80, plain);
    expect(EncryptedWriteError::InvalidArgument, {}, 80, plain);
    expect(EncryptedWriteError::InvalidArgument, key, 80, std::vector<std::byte>(plain.begin(), plain.begin() + 100));
    expect(EncryptedWriteError::InvalidArgument, key, 80, std::vector<std::byte>(511, std::byte{0}));
    expect(EncryptedWriteError::InvalidArgument, key, UINT64_MAX, plain);
    auto corrupt = plain; corrupt[100] = static_cast<std::byte>(corrupt[100] ^ std::byte{0xFF});
    expect(EncryptedWriteError::ChecksumMismatch, key, 80, corrupt);
    Pass("malformed inputs refuse with exact errors and no output");
}
void TweakBinding() {
    const auto key = VolumeKey();
    const auto cipher = Hex(f::SmallRoot);
    std::vector<std::byte> plain;
    for (std::uint64_t i = 0; i < 8; ++i) {
        const auto unit = DecryptUnit(key, 80 * 8 + i, cipher.data() + i * 512);
        plain.insert(plain.end(), unit.begin(), unit.end());
    }
    const auto moved = EncryptAppleMetadataBlock(key, 81, plain);
    Check(static_cast<bool>(moved) && moved.bytes != cipher, "block address binds the tweak");
    const auto wrong = DecryptUnit(key, 80 * 8, moved.bytes.data());
    Check(wrong != std::vector<std::byte>(plain.begin(), plain.begin() + 512),
        "wrong-tweak decryption does not recover plaintext");
    Pass("ciphertext is bound to the physical block address");
}
}
int main() {
    try { FixtureRoundTrip(); Refusals(); TweakBinding();
        std::cout << "PASS " << cases << " cases, " << checks << " checks\n"; return 0;
    } catch(const std::exception& e){ std::cerr << "FAIL after " << cases << " cases, " << checks << " checks: " << e.what() << '\n'; return 1; }
}
