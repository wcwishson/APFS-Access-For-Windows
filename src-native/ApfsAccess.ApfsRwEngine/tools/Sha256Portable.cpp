// Portable self-contained SHA-256 (FIPS 180-4). Used on non-Windows builds
// and by unit tests on every platform; byte-identical digests to CNG.

#include "Sha256.h"

#include <array>
#include <cstdint>
#include <cstring>

namespace apfsaccess::observer
{
namespace
{

constexpr std::array<std::uint32_t, 64> kRoundConstants = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

constexpr std::uint32_t RotateRight(std::uint32_t value, unsigned bits) noexcept
{
    return (value >> bits) | (value << (32u - bits));
}

class PortableSha256Stream final : public Sha256Stream
{
public:
    PortableSha256Stream() noexcept
    {
        state_[0] = 0x6a09e667u;
        state_[1] = 0xbb67ae85u;
        state_[2] = 0x3c6ef372u;
        state_[3] = 0xa54ff53au;
        state_[4] = 0x510e527fu;
        state_[5] = 0x9b05688cu;
        state_[6] = 0x1f83d9abu;
        state_[7] = 0x5be0cd19u;
    }

    [[nodiscard]] bool Update(const std::byte* data, std::size_t size) override
    {
        if (data == nullptr && size != 0)
        {
            return false;
        }
        if (size > 0xFFFFFFFFFFFFFFFFull - total_bytes_)
        {
            return false;
        }
        total_bytes_ += static_cast<std::uint64_t>(size);
        std::size_t offset = 0;
        if (buffered_ > 0)
        {
            const std::size_t take = (std::min)(64 - buffered_, size);
            std::memcpy(buffer_.data() + buffered_, data, take);
            buffered_ += take;
            offset += take;
            if (buffered_ == 64)
            {
                CompressBlock(buffer_.data());
                buffered_ = 0;
            }
        }
        while (offset + 64 <= size)
        {
            CompressBlock(reinterpret_cast<const unsigned char*>(data) + offset);
            offset += 64;
        }
        if (offset < size)
        {
            const std::size_t rest = size - offset;
            std::memcpy(buffer_.data(), reinterpret_cast<const unsigned char*>(data) + offset, rest);
            buffered_ = rest;
        }
        return true;
    }

    [[nodiscard]] bool FinalHex(std::string& out_hex_lower) override
    {
        if (finished_)
        {
            return false;
        }
        finished_ = true;
        const std::uint64_t bit_length = total_bytes_ * 8ull;
        unsigned char pad = 0x80;
        if (!UpdateRaw(&pad, 1))
        {
            return false;
        }
        unsigned char zero = 0x00;
        while (buffered_ != 56)
        {
            if (!UpdateRaw(&zero, 1))
            {
                return false;
            }
        }
        unsigned char length_bytes[8] = {};
        for (int index = 0; index < 8; ++index)
        {
            length_bytes[index] = static_cast<unsigned char>((bit_length >> ((7 - index) * 8)) & 0xFFu);
        }
        // Append directly: the buffer is exactly 56 bytes, so this fills it.
        std::memcpy(buffer_.data() + 56, length_bytes, 8);
        CompressBlock(buffer_.data());
        buffered_ = 0;
        static constexpr char kHex[] = "0123456789abcdef";
        out_hex_lower.clear();
        for (std::uint32_t word : state_)
        {
            for (int index = 0; index < 4; ++index)
            {
                const unsigned char byte = static_cast<unsigned char>((word >> ((3 - index) * 8)) & 0xFFu);
                out_hex_lower.push_back(kHex[(byte >> 4) & 0xF]);
                out_hex_lower.push_back(kHex[byte & 0xF]);
            }
        }
        return out_hex_lower.size() == 64;
    }

private:
    bool UpdateRaw(const unsigned char* data, std::size_t size)
    {
        if (size > 0xFFFFFFFFFFFFFFFFull - total_bytes_)
        {
            return false;
        }
        total_bytes_ += static_cast<std::uint64_t>(size);
        std::size_t offset = 0;
        if (buffered_ > 0)
        {
            const std::size_t take = (std::min)(64 - buffered_, size);
            std::memcpy(buffer_.data() + buffered_, data + offset, take);
            buffered_ += take;
            offset += take;
            if (buffered_ == 64)
            {
                CompressBlock(buffer_.data());
                buffered_ = 0;
            }
        }
        while (offset + 64 <= size)
        {
            CompressBlock(data + offset);
            offset += 64;
        }
        if (offset < size)
        {
            const std::size_t rest = size - offset;
            std::memcpy(buffer_.data(), data + offset, rest);
            buffered_ = rest;
        }
        return true;
    }

    void CompressBlock(const unsigned char block[64]) noexcept
    {
        std::uint32_t schedule[64];
        for (int index = 0; index < 16; ++index)
        {
            schedule[index] = (static_cast<std::uint32_t>(block[index * 4]) << 24) |
                (static_cast<std::uint32_t>(block[index * 4 + 1]) << 16) |
                (static_cast<std::uint32_t>(block[index * 4 + 2]) << 8) |
                static_cast<std::uint32_t>(block[index * 4 + 3]);
        }
        for (int index = 16; index < 64; ++index)
        {
            const std::uint32_t s0 =
                RotateRight(schedule[index - 15], 7) ^ RotateRight(schedule[index - 15], 18) ^ (schedule[index - 15] >> 3);
            const std::uint32_t s1 =
                RotateRight(schedule[index - 2], 17) ^ RotateRight(schedule[index - 2], 19) ^ (schedule[index - 2] >> 10);
            schedule[index] = schedule[index - 16] + s0 + schedule[index - 7] + s1;
        }
        std::uint32_t a = state_[0];
        std::uint32_t b = state_[1];
        std::uint32_t c = state_[2];
        std::uint32_t d = state_[3];
        std::uint32_t e = state_[4];
        std::uint32_t f = state_[5];
        std::uint32_t g = state_[6];
        std::uint32_t h = state_[7];
        for (int index = 0; index < 64; ++index)
        {
            const std::uint32_t s1 = RotateRight(e, 6) ^ RotateRight(e, 11) ^ RotateRight(e, 25);
            const std::uint32_t choice = (e & f) ^ (~e & g);
            const std::uint32_t temp1 = h + s1 + choice + kRoundConstants[static_cast<std::size_t>(index)] +
                schedule[index];
            const std::uint32_t s0 = RotateRight(a, 2) ^ RotateRight(a, 13) ^ RotateRight(a, 22);
            const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t temp2 = s0 + majority;
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
        state_[5] += f;
        state_[6] += g;
        state_[7] += h;
    }

    std::array<std::uint32_t, 8> state_{};
    std::array<unsigned char, 64> buffer_{};
    std::size_t buffered_ = 0;
    std::uint64_t total_bytes_ = 0;
    bool finished_ = false;
};

} // namespace

std::unique_ptr<Sha256Stream> Sha256Stream::Create(std::string& out_error)
{
    out_error.clear();
    return std::make_unique<PortableSha256Stream>();
}

} // namespace apfsaccess::observer
