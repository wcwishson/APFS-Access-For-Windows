#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace apfsaccess::fshost::standard_mount
{
inline constexpr std::uint32_t ProtocolMagic = 0x54535041;
inline constexpr std::uint16_t ProtocolVersion = 1;
inline constexpr std::size_t HeaderBytes = 40, MaximumFrameBytes = 1u << 20;
inline constexpr std::size_t MaximumIoBytes = 65536, MaximumPathUnits = 16384;
using Epoch = std::array<std::byte, 16>;
enum class Operation : std::uint16_t
{
    Hello = 0, Open = 1, Cleanup = 2, Close = 3, Read = 4, Write = 5, Flush = 6,
    QueryFile = 7, SetFile = 8, QueryDirectory = 9, QueryVolume = 10,
    QuerySecurity = 11, SetSecurity = 12, Lock = 13, Unlock = 14,
    SetSparse = 15, ZeroRange = 16, QueryAllocatedRanges = 17, CloneRange = 18,
    Disconnect = 19, Stop = 20
};
struct Header
{
    Operation operation{};
    std::uint32_t payload_bytes = 0;
    std::uint64_t request_id = 0;
    Epoch epoch{};
};
inline bool NonzeroEpoch(const Epoch& value) noexcept
{
    for (const auto byte : value) if (byte != std::byte{}) return true;
    return false;
}
inline std::uint64_t GetLittle(std::span<const std::byte> bytes) noexcept
{
    std::uint64_t result = 0;
    for (std::size_t i = 0; i < bytes.size(); ++i)
        result |= std::uint64_t(std::to_integer<unsigned char>(bytes[i])) << (i * 8);
    return result;
}
inline void PutLittle(std::span<std::byte> bytes, std::uint64_t value) noexcept
{
    for (std::size_t i = 0; i < bytes.size(); ++i)
        bytes[i] = std::byte((value >> (i * 8)) & 255);
}
inline bool DecodeHeader(std::span<const std::byte> bytes, Header& out) noexcept
{
    out = {};
    if (bytes.size() != HeaderBytes || GetLittle(bytes.first(4)) != ProtocolMagic ||
        GetLittle(bytes.subspan(4, 2)) != ProtocolVersion || GetLittle(bytes.subspan(12, 4)) != 0)
        return false;
    const auto operation = GetLittle(bytes.subspan(6, 2));
    const auto length = GetLittle(bytes.subspan(8, 4));
    if (operation > static_cast<std::uint16_t>(Operation::Stop) || length > MaximumFrameBytes - HeaderBytes)
        return false;
    out.operation = static_cast<Operation>(operation);
    out.payload_bytes = static_cast<std::uint32_t>(length);
    out.request_id = GetLittle(bytes.subspan(16, 8));
    for (std::size_t i = 0; i < out.epoch.size(); ++i) out.epoch[i] = bytes[24 + i];
    return true;
}
inline std::array<std::byte, HeaderBytes> EncodeHeader(const Header& header) noexcept
{
    std::array<std::byte, HeaderBytes> bytes{};
    PutLittle(std::span(bytes).first(4), ProtocolMagic);
    PutLittle(std::span(bytes).subspan(4, 2), ProtocolVersion);
    PutLittle(std::span(bytes).subspan(6, 2), static_cast<std::uint16_t>(header.operation));
    PutLittle(std::span(bytes).subspan(8, 4), header.payload_bytes);
    PutLittle(std::span(bytes).subspan(16, 8), header.request_id);
    for (std::size_t i = 0; i < header.epoch.size(); ++i) bytes[24 + i] = header.epoch[i];
    return bytes;
}
class Reader
{
    std::span<const std::byte> remaining_;
public:
    explicit Reader(std::span<const std::byte> bytes) noexcept : remaining_(bytes) {}
    bool Done() const noexcept { return remaining_.empty(); }
    bool Bytes(std::size_t count, std::span<const std::byte>& out) noexcept
    {
        if (count > remaining_.size()) return false;
        out = remaining_.first(count); remaining_ = remaining_.subspan(count); return true;
    }
    bool Integer(std::size_t count, std::uint64_t& out) noexcept
    {
        std::span<const std::byte> bytes;
        if (!count || count > 8 || !Bytes(count, bytes)) return false;
        out = GetLittle(bytes); return true;
    }
    bool U32(std::uint32_t& out) noexcept
    {
        std::uint64_t value = 0;
        if (!Integer(4, value)) return false;
        out = static_cast<std::uint32_t>(value); return true;
    }
    bool U64(std::uint64_t& out) noexcept { return Integer(8, out); }
    bool Identity(Epoch& epoch) noexcept
    {
        std::span<const std::byte> bytes;
        if (!Bytes(epoch.size(), bytes)) return false;
        for (std::size_t i = 0; i < epoch.size(); ++i) epoch[i] = bytes[i];
        return NonzeroEpoch(epoch);
    }
    bool String(std::wstring& out)
    {
        std::uint32_t units = 0;
        std::span<const std::byte> bytes;
        if (!U32(units) || units > MaximumPathUnits || !Bytes(std::size_t(units) * 2, bytes)) return false;
        bool high = false;
        for (std::size_t i = 0; i < units; ++i)
        {
            const auto value = GetLittle(bytes.subspan(i * 2, 2));
            if (!value || (high && (value < 0xdc00 || value > 0xdfff)) ||
                (!high && value >= 0xdc00 && value <= 0xdfff)) return false;
            high = value >= 0xd800 && value <= 0xdbff;
        }
        if (high) return false;
        out.resize(units);
        for (std::size_t i = 0; i < units; ++i) out[i] = static_cast<wchar_t>(GetLittle(bytes.subspan(i * 2, 2)));
        return true;
    }
};
inline bool ValidRelativePath(std::wstring_view path) noexcept
{
    if (path.empty() || path == L"\\") return true;
    if (path.size() > MaximumPathUnits || path.front() != L'\\' || path.back() == L'\\') return false;
    std::size_t component = 1;
    for (std::size_t i = 1; i <= path.size(); ++i)
    {
        if (i != path.size() && path[i] != L'\\')
        {
            if (path[i] < 32 || path[i] == L'/') return false;
            continue;
        }
        const auto name = path.substr(component, i - component);
        if (name.empty() || name == L"." || name == L".." ||
            (i != path.size() && name.find(L':') != std::wstring_view::npos)) return false;
        component = i + 1;
    }
    return true;
}
}
