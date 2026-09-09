#pragma once
#include <array>
#include <optional>

#include "ApfsCompression.h"
#include <array>
#include <span>

namespace apfsaccess::rw
{
// Versioned, bounded source evidence. This slice deliberately caps conversion
// before the existing canonical planner materializes replacement data writes.
struct CompressionRewrite
{
    static constexpr bool SupportsType(std::uint32_t type) noexcept
    { return type == 1 || type == 3 || type == 4 || type == 7 || type == 8 || type == 9 ||
        type == 10 || type == 11 || type == 12 || type == 13 || type == 14; }
    static constexpr bool UsesResourceFork(std::uint32_t type) noexcept
    { return type == 4 || type == 8 || type == 10 || type == 12 || type == 14; }
    static constexpr std::uint64_t MaxLogicalBytes = 16ULL << 20;
    static constexpr std::uint64_t MaxResourceBytes = 512ULL << 10;
    std::uint64_t checkpoint = 0, object = 0, generation = 0, private_id = 0, size = 0, volume = 0;
    std::uint32_t type = 0;
    std::uint16_t decmpfs_flags = 0, resource_flags = 0;
    std::vector<std::byte> decmpfs_descriptor, resource_descriptor, decmpfs, resource;
    std::optional<std::array<std::uint8_t, 32>> preserved_attributes_sha256;
};

inline std::vector<std::byte> EncodeCompressionRewrite(const CompressionRewrite& p)
{
    std::vector<std::byte> out;
    auto put = [&](std::uint64_t n) { for (unsigned i = 0; i != 8; ++i) out.push_back(std::byte((n >> (8*i)) & 255)); };
    put(p.preserved_attributes_sha256 ? 0x32575243 : 0x31575243); // CRW2 adds preserved attribute authentication.
    for (auto n : {p.checkpoint, p.object, p.generation, p.private_id, p.size, p.volume,
            std::uint64_t(p.type), std::uint64_t(p.decmpfs_flags), std::uint64_t(p.resource_flags)}) put(n);
    for (const auto* bytes : {&p.decmpfs_descriptor, &p.resource_descriptor, &p.decmpfs, &p.resource})
    { put(bytes->size()); out.insert(out.end(), bytes->begin(), bytes->end()); }
    if (p.preserved_attributes_sha256)
        for (auto byte : *p.preserved_attributes_sha256) out.push_back(std::byte{byte});
    return out;
}

inline bool DecodeCompressionRewrite(std::span<const std::byte> bytes, CompressionRewrite& p)
{
    if (bytes.size() > (1u << 20)) return false;
    std::size_t at = 0;
    auto get = [&]() { std::uint64_t n = 0; if (bytes.size() - at < 8) { at = bytes.size(); return UINT64_MAX; }
        for (unsigned i = 0; i != 8; ++i) n |= std::uint64_t(std::to_integer<unsigned char>(bytes[at++])) << (8*i); return n; };
    const auto version = get();
    if (version != 0x31575243 && version != 0x32575243) return false;
    p.preserved_attributes_sha256.reset();
    p.checkpoint=get(); p.object=get(); p.generation=get(); p.private_id=get(); p.size=get(); p.volume=get();
    const auto type=get(), df=get(), rf=get();
    if (!p.checkpoint || !p.object || !p.generation || !p.private_id || !p.volume ||
        p.size > CompressionRewrite::MaxLogicalBytes || type > UINT32_MAX ||
        !CompressionRewrite::SupportsType(static_cast<std::uint32_t>(type)) ||
        (df != 1 && df != 2) || (rf != 0 && rf != 1 && rf != 2)) return false;
    p.type=static_cast<std::uint32_t>(type); p.decmpfs_flags=static_cast<std::uint16_t>(df); p.resource_flags=static_cast<std::uint16_t>(rf);
    for (auto* value : {&p.decmpfs_descriptor, &p.resource_descriptor, &p.decmpfs, &p.resource})
    { const auto count=get(); if (count > bytes.size()-at) return false;
      value->assign(bytes.begin()+at, bytes.begin()+at+static_cast<std::size_t>(count)); at += static_cast<std::size_t>(count); }
    if (version == 0x32575243)
    {
        if (bytes.size() - at != 32) return false;
        std::array<std::uint8_t, 32> digest{};
        for (auto& byte : digest) byte = std::to_integer<std::uint8_t>(bytes[at++]);
        p.preserved_attributes_sha256 = digest;
    }
    ApfsCompressionHeader header;
    return at == bytes.size() && p.resource.size() <= CompressionRewrite::MaxResourceBytes &&
        ApfsCompression::Inspect(p.decmpfs, {}, header) && header.type == p.type && header.uncompressed_size == p.size &&
        (df == 1 ? p.decmpfs_descriptor.size() == 48 : p.decmpfs_descriptor == p.decmpfs) &&
        (rf == 0 ? p.resource_descriptor.empty() && p.resource.empty() :
            rf == 1 ? p.resource_descriptor.size() == 48 : p.resource_descriptor == p.resource) &&
        (!CompressionRewrite::UsesResourceFork(p.type) || rf != 0);
}
}
