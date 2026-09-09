#include "ApfsCrypto.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <cstring>
#include <utility>

#ifdef APFSACCESS_CRYPTO_TESTING
#include "ApfsCryptoTestHooks.h"
namespace apfsaccess::crypto::testing { thread_local Hooks hooks; }
#endif

namespace apfsaccess::crypto
{
namespace
{
CryptoResult Fail(CryptoError error, std::uint32_t status = 0) noexcept
{
    return {error, status, {}};
}

// Volatile reduction prevents early-exit substitution. Loop bounds are public;
// no data-dependent branches or memory addresses in the integrity comparison.
bool Equal(std::span<const std::byte> a, std::span<const std::byte> b) noexcept
{
    if (a.size() != b.size()) return false;
    volatile unsigned int difference = 0;
    for (std::size_t i = 0; i < a.size(); ++i)
        difference = difference | std::to_integer<unsigned int>(a[i] ^ b[i]);
    return difference == 0;
}

PUCHAR Input(std::span<const std::byte> bytes) noexcept
{
    // CNG's legacy signature is mutable; these calls do not modify input buffers.
    return reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data()));
}
PUCHAR Output(std::span<std::byte> bytes) noexcept
{
    return reinterpret_cast<PUCHAR>(bytes.data());
}

template<class F> NTSTATUS Cng(F&& operation) noexcept
{
#ifdef APFSACCESS_CRYPTO_TESTING
    if (testing::hooks.cng_calls++ == testing::hooks.cng_failure_at)
    {
        if (testing::hooks.cng_fail_after_call) (void)operation();
        return static_cast<NTSTATUS>(0xC0000001UL);
    }
#endif
    return operation();
}

class Algorithm final
{
public:
    BCRYPT_ALG_HANDLE handle = nullptr;
    Algorithm() noexcept = default;
    Algorithm(const Algorithm&) = delete;
    Algorithm& operator=(const Algorithm&) = delete;
    ~Algorithm() noexcept { if (handle) BCryptCloseAlgorithmProvider(handle, 0); }
};

class Aes final
{
public:
    Aes() noexcept = default;
    Aes(const Aes&) = delete;
    Aes& operator=(const Aes&) = delete;
    ~Aes() noexcept { if (key_) BCryptDestroyKey(key_); }

    CryptoResult Init(std::span<const std::byte> key) noexcept
    {
        auto status = Cng([&] { return BCryptOpenAlgorithmProvider(&algorithm_.handle,
            BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0); });
        if (status < 0) return Fail(CryptoError::ProviderFailure, status);
        status = Cng([&] { return BCryptSetProperty(algorithm_.handle, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_ECB)),
            sizeof(BCRYPT_CHAIN_MODE_ECB), 0); });
        if (status < 0) return Fail(CryptoError::ProviderFailure, status);
        DWORD object_bytes = 0, received = 0;
        status = Cng([&] { return BCryptGetProperty(algorithm_.handle, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_bytes), sizeof(object_bytes), &received, 0); });
        if (status < 0) return Fail(CryptoError::ProviderFailure, status);
        if (received != sizeof(object_bytes) || object_bytes == 0)
            return Fail(CryptoError::ProviderFailure);
        auto storage = SecureBytes::Allocate(object_bytes);
        if (!storage) return storage;
        object_ = std::move(storage.bytes);
        status = Cng([&] { return BCryptGenerateSymmetricKey(algorithm_.handle, &key_,
            Output(object_.Bytes()), object_bytes, Input(key), static_cast<ULONG>(key.size()), 0); });
        if (status < 0) return Fail(CryptoError::ProviderFailure, status);
        return {};
    }

    NTSTATUS Block(std::span<const std::byte> input, std::span<std::byte> output,
        bool encrypt) noexcept
    {
        ULONG written = 0;
        auto status = Cng([&] {
            return encrypt
                ? BCryptEncrypt(key_, Input(input), 16, nullptr, nullptr, 0,
                    Output(output), 16, &written, 0)
                : BCryptDecrypt(key_, Input(input), 16, nullptr, nullptr, 0,
                    Output(output), 16, &written, 0);
        });
        if (status >= 0 && written != 16) status = static_cast<NTSTATUS>(0xC0000001UL);
        return status;
    }
private:
    // Destruction order: key handle, owned object bytes, algorithm handle.
    Algorithm algorithm_;
    SecureBytes object_;
    BCRYPT_KEY_HANDLE key_ = nullptr;
};

void Release(std::byte* data, std::size_t size, bool locked) noexcept
{
    SecureZeroMemory(data, size);
#ifdef APFSACCESS_CRYPTO_TESTING
    ++testing::hooks.wipes;
    testing::hooks.wiped_bytes += size;
    for (std::size_t i = 0; i < size; ++i)
        if (data[i] != std::byte{0}) testing::hooks.all_released_bytes_zero = false;
#endif
    if (locked)
    {
        VirtualUnlock(data, size);
#ifdef APFSACCESS_CRYPTO_TESTING
        ++testing::hooks.unlocks;
#endif
    }
    VirtualFree(data, 0, MEM_RELEASE);
#ifdef APFSACCESS_CRYPTO_TESTING
    ++testing::hooks.releases;
#endif
}
} // namespace

SecureBytes::~SecureBytes() noexcept { Clear(); }
SecureBytes::SecureBytes(SecureBytes&& other) noexcept
    : data_(std::exchange(other.data_, nullptr)), size_(std::exchange(other.size_, 0)),
      allocation_size_(std::exchange(other.allocation_size_, 0)) {}
SecureBytes& SecureBytes::operator=(SecureBytes&& other) noexcept
{
    if (this != &other)
    {
        Clear();
        data_ = std::exchange(other.data_, nullptr);
        size_ = std::exchange(other.size_, 0);
        allocation_size_ = std::exchange(other.allocation_size_, 0);
    }
    return *this;
}
void SecureBytes::Clear() noexcept
{
    if (data_) Release(data_, allocation_size_, true);
    data_ = nullptr;
    size_ = allocation_size_ = 0;
}
CryptoResult SecureBytes::Allocate(std::size_t bytes) noexcept
{
    if (bytes == 0) return {};
    if (bytes > kMaxBytes) return Fail(CryptoError::ResourceLimit);
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    const std::size_t page = info.dwPageSize;
    if (page == 0 || page > kMaxBytes) return Fail(CryptoError::AllocationFailed);
    const auto allocation_size = ((bytes + page - 1) / page) * page;
#ifdef APFSACCESS_CRYPTO_TESTING
    if (testing::hooks.allocations++ == testing::hooks.allocation_failure_at)
        return Fail(CryptoError::AllocationFailed, ERROR_NOT_ENOUGH_MEMORY);
#endif
    auto* data = static_cast<std::byte*>(VirtualAlloc(nullptr, allocation_size,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!data) return Fail(CryptoError::AllocationFailed, GetLastError());
    bool lock = false;
    DWORD error = ERROR_WORKING_SET_QUOTA;
#ifdef APFSACCESS_CRYPTO_TESTING
    if (testing::hooks.locks++ != testing::hooks.lock_failure_at)
#endif
    {
        lock = VirtualLock(data, allocation_size) != FALSE;
        if (!lock) error = GetLastError();
    }
    if (!lock)
    {
        Release(data, allocation_size, false);
        return Fail(CryptoError::MemoryLockFailed, error);
    }
    CryptoResult result;
    result.bytes.data_ = data;
    result.bytes.size_ = bytes;
    result.bytes.allocation_size_ = allocation_size;
    return result;
}

CryptoResult Pbkdf2HmacSha256(std::span<const std::byte> password,
    std::span<const std::byte> salt, std::uint64_t iterations, std::size_t bytes) noexcept
{
    if (iterations == 0 || bytes == 0) return Fail(CryptoError::InvalidArgument);
    if (iterations > kMaxPbkdf2Iterations || bytes > kMaxDerivedBytes ||
        password.size() > kMaxPbkdf2InputBytes || salt.size() > kMaxPbkdf2InputBytes)
        return Fail(CryptoError::ResourceLimit);
    Algorithm algorithm;
    auto status = Cng([&] { return BCryptOpenAlgorithmProvider(&algorithm.handle,
        BCRYPT_SHA256_ALGORITHM, MS_PRIMITIVE_PROVIDER, BCRYPT_ALG_HANDLE_HMAC_FLAG); });
    if (status < 0) return Fail(CryptoError::ProviderFailure, status);
    auto result = SecureBytes::Allocate(bytes);
    if (!result) return result;
    status = Cng([&] { return BCryptDeriveKeyPBKDF2(algorithm.handle,
        Input(password), static_cast<ULONG>(password.size()), Input(salt),
        static_cast<ULONG>(salt.size()), iterations, Output(result.bytes.Bytes()),
        static_cast<ULONG>(bytes), 0); });
    if (status < 0) return Fail(CryptoError::ProviderFailure, status);
    return result;
}

CryptoResult Rfc3394Unwrap(std::span<const std::byte> kek,
    std::span<const std::byte> ciphertext) noexcept
{
    if ((kek.size() != 16 && kek.size() != 24 && kek.size() != 32) ||
        ciphertext.size() < 24 || ciphertext.size() % 8 != 0)
        return Fail(CryptoError::InvalidArgument);
    if (ciphertext.size() > 4096) return Fail(CryptoError::ResourceLimit);
    Aes aes;
    auto init = aes.Init(kek);
    if (!init) return init;
    auto state = SecureBytes::Allocate(ciphertext.size());
    if (!state) return state;
    auto scratch = SecureBytes::Allocate(32);
    if (!scratch) return scratch;
    auto buffer = state.bytes.Bytes();
    auto input = scratch.bytes.Bytes().first(16);
    auto output = scratch.bytes.Bytes().subspan(16, 16);
    std::memcpy(buffer.data(), ciphertext.data(), ciphertext.size());
    const auto n = ciphertext.size() / 8 - 1;
    for (int j = 5; j >= 0; --j)
    {
        for (auto i = n; i != 0; --i)
        {
            std::memcpy(input.data(), buffer.data(), 8);
            const auto t = static_cast<std::uint64_t>(n) * static_cast<unsigned>(j) + i;
            for (unsigned k = 0; k < 8; ++k)
                input[7 - k] ^= static_cast<std::byte>((t >> (8 * k)) & 0xff);
            std::memcpy(input.data() + 8, buffer.data() + i * 8, 8);
            const auto status = aes.Block(input, output, false);
            if (status < 0) return Fail(CryptoError::ProviderFailure, status);
            std::memcpy(buffer.data(), output.data(), 8);
            std::memcpy(buffer.data() + i * 8, output.data() + 8, 8);
        }
    }
    constexpr std::byte iv[8] = {std::byte{0xa6}, std::byte{0xa6}, std::byte{0xa6},
        std::byte{0xa6}, std::byte{0xa6}, std::byte{0xa6}, std::byte{0xa6}, std::byte{0xa6}};
    if (!Equal(buffer.first(8), iv)) return Fail(CryptoError::IntegrityFailure);
    auto result = SecureBytes::Allocate(ciphertext.size() - 8);
    if (!result) return result;
    std::memcpy(result.bytes.Bytes().data(), buffer.data() + 8, result.bytes.Size());
    return result;
}

CryptoResult XtsTransform(std::span<const std::byte> combined_key,
    std::span<const std::byte> tweak_input, std::span<const std::byte> data_unit,
    XtsDirection direction) noexcept
{
    if ((combined_key.size() != 32 && combined_key.size() != 64) ||
        tweak_input.size() != 16 || data_unit.size() < 16 || data_unit.size() % 16 != 0 ||
        (direction != XtsDirection::Encrypt && direction != XtsDirection::Decrypt))
        return Fail(CryptoError::InvalidArgument);
    if (data_unit.size() > kMaxXtsDataUnitBytes) return Fail(CryptoError::ResourceLimit);
    const auto half = combined_key.size() / 2;
    if (Equal(combined_key.first(half), combined_key.subspan(half)))
        return Fail(CryptoError::InvalidArgument);
    Aes data_key, tweak_key;
    auto init = data_key.Init(combined_key.first(half));
    if (!init) return init;
    init = tweak_key.Init(combined_key.subspan(half));
    if (!init) return init;
    auto scratch = SecureBytes::Allocate(32);
    if (!scratch) return scratch;
    auto tweak = scratch.bytes.Bytes().first(16);
    auto input = scratch.bytes.Bytes().subspan(16, 16);
    auto status = tweak_key.Block(tweak_input, tweak, true);
    if (status < 0) return Fail(CryptoError::ProviderFailure, status);
    auto result = SecureBytes::Allocate(data_unit.size());
    if (!result) return result;
    for (std::size_t offset = 0; offset < data_unit.size(); offset += 16)
    {
        for (std::size_t i = 0; i < 16; ++i) input[i] = data_unit[offset + i] ^ tweak[i];
        auto output = result.bytes.Bytes().subspan(offset, 16);
        status = data_key.Block(input, output, direction == XtsDirection::Encrypt);
        if (status < 0) return Fail(CryptoError::ProviderFailure, status);
        for (std::size_t i = 0; i < 16; ++i) output[i] ^= tweak[i];
        // IEEE 1619 little-endian GF(2^128) multiplication by x.
        unsigned carry = 0;
        for (std::size_t i = 0; i < 16; ++i)
        {
            const auto value = std::to_integer<unsigned>(tweak[i]);
            tweak[i] = static_cast<std::byte>(((value << 1) | carry) & 0xff);
            carry = value >> 7;
        }
        tweak[0] ^= static_cast<std::byte>(0x87U & (0U - carry));
    }
    return result;
}
} // namespace apfsaccess::crypto
