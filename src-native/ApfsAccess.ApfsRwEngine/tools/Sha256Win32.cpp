// CNG/BCrypt SHA-256 for Windows production observer builds. Same digest
// bytes as the portable implementation for identical input.

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <bcrypt.h>

#include "Sha256.h"

namespace apfsaccess::observer
{
namespace
{

class BcryptSha256Stream final : public Sha256Stream
{
public:
    BcryptSha256Stream(BCRYPT_ALG_HANDLE algorithm, BCRYPT_HASH_HANDLE hash) noexcept
        : algorithm_(algorithm)
        , hash_(hash)
    {
    }

    ~BcryptSha256Stream() override
    {
        if (hash_ != nullptr)
        {
            BCryptDestroyHash(hash_);
        }
        if (algorithm_ != nullptr)
        {
            BCryptCloseAlgorithmProvider(algorithm_, 0);
        }
    }

    BcryptSha256Stream(const BcryptSha256Stream&) = delete;
    BcryptSha256Stream& operator=(const BcryptSha256Stream&) = delete;

    [[nodiscard]] bool Update(const std::byte* data, std::size_t size) override
    {
        if (data == nullptr && size != 0)
        {
            return false;
        }
        if (size > static_cast<std::size_t>(MAXDWORD))
        {
            return false;
        }
        return BCryptHashData(
                   hash_,
                   reinterpret_cast<PUCHAR>(const_cast<std::byte*>(data)),
                   static_cast<ULONG>(size),
                   0) == 0;
    }

    [[nodiscard]] bool FinalHex(std::string& out_hex_lower) override
    {
        if (finished_)
        {
            return false;
        }
        finished_ = true;
        unsigned char digest[32] = {};
        if (BCryptFinishHash(hash_, digest, sizeof(digest), 0) != 0)
        {
            return false;
        }
        static constexpr char kHex[] = "0123456789abcdef";
        out_hex_lower.clear();
        for (unsigned char byte : digest)
        {
            out_hex_lower.push_back(kHex[(byte >> 4) & 0xF]);
            out_hex_lower.push_back(kHex[byte & 0xF]);
        }
        return out_hex_lower.size() == 64;
    }

private:
    BCRYPT_ALG_HANDLE algorithm_ = nullptr;
    BCRYPT_HASH_HANDLE hash_ = nullptr;
    bool finished_ = false;
};

} // namespace

std::unique_ptr<Sha256Stream> Sha256Stream::Create(std::string& out_error)
{
    out_error.clear();
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
    {
        out_error = "CNG SHA-256 provider unavailable";
        return nullptr;
    }
    if (BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) != 0)
    {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        out_error = "CNG SHA-256 init failed";
        return nullptr;
    }
    return std::make_unique<BcryptSha256Stream>(algorithm, hash);
}

} // namespace apfsaccess::observer
