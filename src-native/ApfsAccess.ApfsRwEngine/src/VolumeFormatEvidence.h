#pragma once
#include "ApfsFormat.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <map>
#include <span>
#include <stdexcept>

namespace apfsaccess::rw::format_evidence
{
using Bytes = std::vector<std::byte>;
using Digest = std::array<std::byte, 32>;
inline constexpr std::uint64_t Magic = 0x3246495653465041ull;
inline constexpr std::uint64_t EraseMagic = 0x3346495653465041ull;
inline constexpr std::uint64_t ResizeMagic = 0x3446495653465041ull;
inline constexpr std::uint64_t RelocationMagic = 0x3546495653465041ull;
inline constexpr std::uint64_t FlaggedImageMagic = 0x4146495653465041ull;
inline constexpr std::uint64_t FlaggedStreamedMagic = 0x4246495653465041ull;
inline constexpr std::uint64_t CursorTag = 1ull << 63;
inline constexpr std::uint64_t Chunk = 4ull * 1024 * 1024, Maximum = 1ull << 40;
inline constexpr std::uint64_t CapturedLimit = 240ull * 1024 * 1024;
inline void Need(bool ok, const char* error)
{ if (!ok) throw std::runtime_error(error); }
inline Digest Hash(std::span<const std::byte> bytes)
{
    BCRYPT_ALG_HANDLE alg{}; Digest digest{};
    Need(bytes.size() <= ULONG_MAX && BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0,
        "VolumeFormatEvidenceHashFailed");
    const auto status = BCryptHash(alg, nullptr, 0, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())),
        static_cast<ULONG>(bytes.size()), reinterpret_cast<PUCHAR>(digest.data()), 32);
    BCryptCloseAlgorithmProvider(alg, 0); Need(status >= 0, "VolumeFormatEvidenceHashFailed"); return digest;
}
inline void Number(Bytes& bytes, std::uint64_t value)
{ for (unsigned i = 0; i < 8; ++i) bytes.push_back(std::byte((value >> (8 * i)) & 255)); }
struct Original
{
    std::uint64_t size = 0;
    std::vector<Digest> digests;
    std::map<std::uint64_t, Bytes> chunks;
    std::size_t Length(std::uint64_t index) const
    { Need(index < digests.size(), "VolumeFormatEvidenceChunkBounds"); return static_cast<std::size_t>((std::min)(Chunk, size - index * Chunk)); }
};
inline Original Scan(const catalog::RandomAccessSource& source, bool retain_checkpoints = false)
{
    Original original; original.size = source.SizeBytes();
    Need(original.size && original.size <= Maximum && original.size % 4096 == 0, "VolumeFormatEvidenceGeometryInvalid");
    const auto count = (original.size + Chunk - 1) / Chunk; original.digests.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t i = 0; i < count; ++i) {
        Bytes bytes; const auto length = static_cast<std::size_t>((std::min)(Chunk, original.size - i * Chunk));
        Need(source.Read(i * Chunk, length, bytes) && bytes.size() == length, "VolumeFormatEvidenceSourceReadFailed");
        original.digests.push_back(Hash(bytes));
        if (retain_checkpoints) for (std::size_t at = 0; at < bytes.size(); at += 4096) {
            // Valid original NX headers may survive a torn cleanup chunk. Keep
            // their exact bytes so replay never accepts a foreign valid header.
            if (catalog::ReadU32LE(bytes, at + 0x20).value_or(0) != 0x4253584e) continue;
            const Bytes block(bytes.begin() + at, bytes.begin() + at + 4096);
            if (!catalog::ParseNxSuperblock(block)) continue;
            Need(original.chunks.size() < CapturedLimit / Chunk, "VolumeFormatEvidenceCaptureLimit");
            original.chunks.emplace(i, bytes); break;
        }
    }
    return original;
}
inline bool EraseTransition(unsigned state, std::uint64_t cursor, std::uint64_t next, std::uint64_t count)
{
    if (state == 2 && cursor < count && next == (CursorTag | (cursor + 1))) return true;
    return (state == 0 && (next == 1 || next == 4)) || (state == 1 && next == 2) ||
        (state == 2 && cursor == count && next == 3);
}
class Capture final : public catalog::RandomAccessSource
{
public:
    Capture(const catalog::RandomAccessSource& source, Original& original) : source_(source), original_(original) {}
    std::uint64_t SizeBytes() const override { return original_.size; }
    bool Read(std::uint64_t offset, std::size_t size, Bytes& out) const override
    {
        out.clear(); if (offset > SizeBytes() || size > SizeBytes() - offset || size > CapturedLimit) return false;
        for (std::size_t at = 0; at < size;) {
            const auto position = offset + at, index = position / Chunk;
            if (!original_.chunks.contains(index)) {
                Need(original_.chunks.size() < CapturedLimit / Chunk, "VolumeFormatEvidenceCaptureLimit");
                Bytes bytes;
                Need(source_.Read(index * Chunk, original_.Length(index), bytes) && bytes.size() == original_.Length(index),
                    "VolumeFormatEvidenceCaptureReadFailed");
                Need(Hash(bytes) == original_.digests.at(static_cast<std::size_t>(index)), "VolumeFormatEvidenceSourceChanged");
                original_.chunks.emplace(index, std::move(bytes));
            }
            const auto count = (std::min)(size - at, static_cast<std::size_t>(Chunk - position % Chunk)); at += count;
        }
        out.resize(size);
        for (std::size_t at = 0; at < size;) {
            const auto position = offset + at;
            const auto count = (std::min)(size - at, static_cast<std::size_t>(Chunk - position % Chunk));
            const auto& bytes = original_.chunks.at(position / Chunk);
            std::copy_n(bytes.begin() + position % Chunk, count, out.begin() + at); at += count;
        }
        return true;
    }
private:
    const catalog::RandomAccessSource& source_;
    Original& original_;
};
// Deliberately has no live fallback. Original metadata absent from the frame is
// unknown, including holes in a sparse file; it must never become zero bytes.
class Snapshot final : public catalog::RandomAccessSource
{
public:
    explicit Snapshot(const Original& original) : original_(original) {}
    std::uint64_t SizeBytes() const override { return original_.size; }
    bool Read(std::uint64_t offset, std::size_t size, Bytes& out) const override
    {
        out.clear(); if (offset > SizeBytes() || size > SizeBytes() - offset || size > CapturedLimit) return false;
        for (std::size_t at = 0; at < size;) {
            const auto position = offset + at;
            if (!original_.chunks.contains(position / Chunk)) return false;
            at += (std::min)(size - at, static_cast<std::size_t>(Chunk - position % Chunk));
        }
        out.resize(size);
        for (std::size_t at = 0; at < size;) {
            const auto position = offset + at;
            const auto count = (std::min)(size - at, static_cast<std::size_t>(Chunk - position % Chunk));
            const auto& bytes = original_.chunks.at(position / Chunk);
            std::copy_n(bytes.begin() + position % Chunk, count, out.begin() + at); at += count;
        }
        return true;
    }
private:
    const Original& original_;
};
inline Bytes Encode(const Original& original)
{
    Bytes out; Number(out, 1); Number(out, original.size); Number(out, Chunk); Number(out, original.digests.size());
    for (const auto& hash : original.digests) out.insert(out.end(), hash.begin(), hash.end());
    Number(out, original.chunks.size());
    for (const auto& [index, bytes] : original.chunks) {
        Number(out, index); Number(out, bytes.size()); out.insert(out.end(), bytes.begin(), bytes.end());
    }
    return out;
}
inline Original Decode(std::span<const std::byte> bytes, std::uint64_t expected)
{
    std::size_t at = 0;
    const auto number = [&]() { Need(at <= bytes.size() && bytes.size() - at >= 8, "VolumeFormatEvidenceTruncated");
        const auto value = catalog::ReadU64LE(bytes, at).value(); at += 8; return value; };
    Need(number() == 1 && expected && expected <= Maximum && expected % 4096 == 0, "VolumeFormatEvidenceVersionOrGeometryInvalid");
    Original original; original.size = number();
    Need(original.size == expected && number() == Chunk, "VolumeFormatEvidenceGeometryInvalid");
    const auto count = number();
    Need(count == (expected + Chunk - 1) / Chunk && count * 32 <= bytes.size() - at, "VolumeFormatEvidenceDigestCountInvalid");
    original.digests.resize(static_cast<std::size_t>(count));
    for (auto& hash : original.digests) { std::copy_n(bytes.begin() + at, 32, hash.begin()); at += 32; }
    const auto stored = number(); Need(stored && stored <= CapturedLimit / Chunk && stored <= count, "VolumeFormatEvidenceCaptureCountInvalid");
    std::uint64_t prior = 0;
    for (std::uint64_t i = 0; i < stored; ++i) {
        const auto index = number(), size = number();
        Need(index < count && (!i || index > prior) && size == original.Length(index) && size <= bytes.size() - at,
            "VolumeFormatEvidenceStoredChunkInvalid");
        const auto chunk = bytes.subspan(at, static_cast<std::size_t>(size));
        Need(Hash(chunk) == original.digests.at(static_cast<std::size_t>(index)), "VolumeFormatEvidenceStoredHashMismatch");
        original.chunks.emplace(index, Bytes(chunk.begin(), chunk.end())); at += static_cast<std::size_t>(size); prior = index;
    }
    Need(at == bytes.size() && original.chunks.contains(0), "VolumeFormatEvidenceCoverageInvalid"); return original;
}
}
