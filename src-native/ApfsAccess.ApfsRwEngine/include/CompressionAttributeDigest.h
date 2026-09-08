#pragma once

#include "ApfsExtendedRecordCodec.h"
#include "ApfsFormat.h"
#include <Windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <map>
#include <span>

namespace apfsaccess::rw
{
// Bind the accepted preimage to preserved attribute payloads, including data
// shared by retained/current checkpoints. Callers supply their native reader.
template<class Read>
bool ComputeCompressionAttributeDigest(const std::vector<AppleXattrRecord>& attributes,
    Read&& read, std::array<std::uint8_t, 32>& digest)
{
    constexpr std::size_t MaxAttributes = 256;
    constexpr std::uint64_t MaxBytes = 8ULL << 20;
    if (attributes.size() > MaxAttributes) return false;
    std::map<std::string, const AppleXattrRecord*> ordered;
    std::uint64_t total = 0;
    for (const auto& attribute : attributes)
    {
        if (attribute.name_utf8 == "com.apple.decmpfs" || attribute.name_utf8 == "com.apple.ResourceFork") continue;
        if (attribute.name_utf8.empty() || attribute.name_utf8.size() > 821 ||
            !ordered.emplace(attribute.name_utf8, &attribute).second) return false;
        const auto size = attribute.flags == kAppleXattrDataEmbedded ? attribute.data.size() :
            attribute.flags == kAppleXattrDataStream && attribute.data.size() == kAppleXattrDataStreamBytes ?
                catalog::ReadU64LE(attribute.data, 8).value_or(UINT64_MAX) : UINT64_MAX;
        if (size > MaxBytes - total || attribute.data.size() > MaxBytes - total - size) return false;
        total += size + attribute.data.size();
    }
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return false;
    BCRYPT_HASH_HANDLE hash = nullptr;
    const auto created = BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0);
    if (created < 0) { BCryptCloseAlgorithmProvider(algorithm, 0); return false; }
    struct Handles
    {
        BCRYPT_ALG_HANDLE algorithm;
        BCRYPT_HASH_HANDLE hash;
        ~Handles() { BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0); }
    } handles{algorithm, hash};
    const auto finish = [&](bool ok) {
        if (ok) ok = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) >= 0;
        return ok;
    };
    const auto append = [&](std::span<const std::byte> bytes) {
        return bytes.empty() || BCryptHashData(hash,
            reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())), static_cast<ULONG>(bytes.size()), 0) >= 0;
    };
    const auto number = [&](std::uint64_t value) {
        std::array<std::byte, 8> encoded{};
        for (unsigned i = 0; i < 8; ++i) encoded[i] = std::byte((value >> (8*i)) & 255);
        return append(encoded);
    };
    // Stack scratch and preflight limits keep attribute payload hashing bounded.
    std::array<std::byte, 65536> scratch{};
    for (const auto& [name, attribute] : ordered)
    {
        const auto size = attribute->flags == kAppleXattrDataEmbedded ? attribute->data.size() :
            *catalog::ReadU64LE(attribute->data, 8);
        if (!number(name.size()) || !append(std::as_bytes(std::span(name))) ||
            !number(attribute->flags) || !number(attribute->data.size()) || !append(attribute->data) || !number(size))
            return finish(false);
        for (std::uint64_t at = 0; at < size;)
        {
            const auto count = static_cast<std::size_t>((std::min)(std::uint64_t{scratch.size()}, size - at));
            auto target = std::span(scratch).first(count);
            if (!read(*attribute, at, target) || !append(target)) return finish(false);
            at += count;
        }
    }
    return finish(true);
}
}
