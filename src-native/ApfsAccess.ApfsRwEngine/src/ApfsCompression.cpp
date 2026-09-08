#include "ApfsCompression.h"

#include "zlib.h"
#include "apfsaccess_lzvn.h"
#include "apfsaccess_lzfse.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <limits>
#include <new>
#include <stdexcept>
#include <utility>

namespace apfsaccess::rw
{
namespace
{
using Status = ApfsCompressionStatus;
using Result = ApfsCompressionResult;
constexpr std::uint64_t kBlockBytes = 65536;
constexpr std::size_t kHeaderBytes = 16;

// Format facts only (no source copied): Apple XNU bsd/sys/decmpfs.h;
// Simon Gander's apfs-fuse ApfsLib/Decmpfs.cpp; afsctool src/afsctool.c.
// Type 4: BE resource header and length; LE count and (offset,length) pairs.
// Offsets are relative to the count, four bytes after the data-section start.
// Dependency: unmodified zlib 1.3.2, https://zlib.net/zlib-1.3.2.tar.gz
// SHA256 bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16
// License: third_party/zlib/LICENSE. No raw-deflate/gzip autodetection.

Result Fail(Status status, const char* detail) noexcept { return {status, detail}; }

std::uint32_t U32(std::span<const std::byte> bytes, std::size_t at, bool big = false) noexcept
{
    std::uint32_t value = 0;
    for (unsigned i = 0; i < 4; ++i)
        value |= std::to_integer<std::uint32_t>(bytes[at + i]) << (8 * (big ? 3 - i : i));
    return value;
}

std::uint64_t U64(std::span<const std::byte> bytes, std::size_t at) noexcept
{
    return U32(bytes, at) | (static_cast<std::uint64_t>(U32(bytes, at + 4)) << 32);
}

bool Within(std::uint64_t offset, std::uint64_t length, std::uint64_t size) noexcept
{ return offset <= size && length <= size - offset; }

bool RawMarker(std::byte first) noexcept
{ return (std::to_integer<unsigned>(first) & 0x0f) == 0x0f; }

bool FitsVector(std::uint64_t size) noexcept
{
    return size <= static_cast<std::uint64_t>((std::numeric_limits<std::ptrdiff_t>::max)());
}

struct AllocationBudget
{
    std::uint64_t remaining;
    static voidpf Alloc(voidpf opaque, uInt count, uInt size) noexcept
    {
        auto& budget = *static_cast<AllocationBudget*>(opaque);
        const auto bytes = static_cast<std::uint64_t>(count) * size;
        if (bytes > budget.remaining || bytes > (std::numeric_limits<std::size_t>::max)())
            return nullptr;
        void* result = std::calloc(count, size);
        if (result) budget.remaining -= bytes;
        return result;
    }
    static void Free(voidpf, voidpf address) noexcept { std::free(address); }
};

struct InflateState
{
    z_stream stream{};
    bool initialized = false;
    ~InflateState() { if (initialized) inflateEnd(&stream); }
};

Result DecodeBlock(std::span<const std::byte> encoded, std::uint64_t expected,
    const ApfsCompressionLimits& limits, std::vector<std::byte>& decoded)
{
    if (encoded.empty()) return Fail(Status::Corrupt, "CompressionPayloadMissing");
    if (RawMarker(encoded.front()))
    {
        if (encoded.size() - 1 != expected)
            return Fail(Status::Corrupt, "CompressionRawSizeMismatch");
        decoded.assign(encoded.begin() + 1, encoded.end());
        return {};
    }
    // One guard byte distinguishes exact output from an overlong stream. Require
    // stream end, complete input consumption AND exact output, including checksum.
    if (expected >= (std::numeric_limits<uInt>::max)() || !FitsVector(expected + 1) ||
        encoded.size() > (std::numeric_limits<uInt>::max)())
        return Fail(Status::LimitExceeded, "CompressionZlibApiSizeLimit");
    decoded.resize(static_cast<std::size_t>(expected + 1));
    AllocationBudget budget{limits.max_zlib_allocation_bytes};
    InflateState state;
    auto& stream = state.stream;
    stream.zalloc = AllocationBudget::Alloc;
    stream.zfree = AllocationBudget::Free;
    stream.opaque = &budget;
    const int init = inflateInit2(&stream, 15); // RFC 1950 only; verifies Adler-32.
    if (init != Z_OK)
        return Fail(init == Z_MEM_ERROR ? Status::LimitExceeded : Status::Corrupt,
            "CompressionZlibInitFailed");
    state.initialized = true;
    stream.next_in = reinterpret_cast<Bytef*>(const_cast<std::byte*>(encoded.data()));
    stream.avail_in = static_cast<uInt>(encoded.size());
    stream.next_out = reinterpret_cast<Bytef*>(decoded.data());
    stream.avail_out = static_cast<uInt>(decoded.size());
    const int rc = inflate(&stream, Z_FINISH);
    if (rc == Z_MEM_ERROR) return Fail(Status::LimitExceeded, "CompressionZlibMemoryLimit");
    if (rc != Z_STREAM_END || stream.avail_in != 0 || stream.total_out != expected)
        return Fail(Status::Corrupt, "CompressionZlibStreamInvalid");
    decoded.resize(static_cast<std::size_t>(expected));
    return {};
}

Result DecodeLzvn(std::span<const std::byte> encoded, std::uint64_t expected,
    std::vector<std::byte>& decoded)
{
    if (encoded.empty()) return Fail(Status::Corrupt, "CompressionPayloadMissing");
    // decmpfs uses 06 as a raw-block escape, independently of LZVN's EOS opcode.
    if (encoded.front() == std::byte{0x06})
    {
        if (encoded.size() - 1 != expected)
            return Fail(Status::Corrupt, "CompressionLzvnRawSizeMismatch");
        decoded.assign(encoded.begin() + 1, encoded.end());
        return {};
    }
    // Apple lzfse low-level decoder, pinned in third_party/lzfse/PROVENANCE.md.
    // One guard byte detects overlong output and permits EOS at exact output size.
    if (expected == (std::numeric_limits<std::uint64_t>::max)() ||
        !FitsVector(expected + 1) || !FitsVector(encoded.size()))
        return Fail(Status::LimitExceeded, "CompressionLzvnApiSizeLimit");
    decoded.resize(static_cast<std::size_t>(expected + 1));
    if (!apfsaccess_lzvn_decode_exact(
        reinterpret_cast<const unsigned char*>(encoded.data()), encoded.size(),
        reinterpret_cast<unsigned char*>(decoded.data()), decoded.size(),
        static_cast<std::size_t>(expected)))
        return Fail(Status::Corrupt, "CompressionLzvnStreamInvalid");
    // Upstream accepts any seven bytes after EOS. Only the canonical zero bytes
    // emitted by Apple's encoder are admitted here; no trailing-data tolerance.
    if (encoded.size() < 8 || encoded[encoded.size() - 8] != std::byte{0x06} ||
        !std::all_of(encoded.end() - 7, encoded.end(),
            [](std::byte value) { return value == std::byte{0}; }))
        return Fail(Status::Unsupported, "CompressionLzvnNoncanonicalEosUnsupported");
    decoded.resize(static_cast<std::size_t>(expected));
    return {};
}

Result DecodeLzfse(std::span<const std::byte> encoded, std::uint64_t expected,
    const ApfsCompressionLimits& limits, std::uint64_t& remaining_work, std::vector<std::byte>& decoded)
{
    if (encoded.empty()) return Fail(Status::Corrupt, "CompressionLzfsePayloadMissing");
    const auto state_bytes = apfsaccess_lzfse_scratch_size();
    if (!FitsVector(expected) || state_bytes > limits.max_lzfse_state_bytes ||
        encoded.size() > UINT64_MAX - expected ||
        encoded.size() + expected > (UINT64_MAX - 4096) / 16)
        return Fail(Status::LimitExceeded, "CompressionLzfseStateOrSizeLimit");
    const auto work = 4096 + 16 * (encoded.size() + expected);
    if (work > remaining_work) return Fail(Status::LimitExceeded, "CompressionLzfseWorkLimit");
    remaining_work -= work;
    std::vector<std::byte> state(state_bytes);
    decoded.resize(static_cast<std::size_t>((std::max)(expected, std::uint64_t{1})));
    const auto rc = apfsaccess_lzfse_decode_exact(
        reinterpret_cast<const std::uint8_t*>(encoded.data()), encoded.size(),
        reinterpret_cast<std::uint8_t*>(decoded.data()), decoded.size(), static_cast<std::size_t>(expected),
        state.data(), state.size(), work);
    if (rc != APFSACCESS_LZFSE_OK)
        return Fail(rc == APFSACCESS_LZFSE_LIMIT ? Status::LimitExceeded : Status::Corrupt,
            "CompressionLzfseStreamInvalid");
    decoded.resize(static_cast<std::size_t>(expected));
    return {};
}

class ForkReads
{
public:
    ForkReads(const ApfsCompressionResourceReader& reader, std::uint64_t budget)
        : reader_(reader), remaining_(budget) {}

    Result Read(std::uint64_t offset, std::span<std::byte> destination)
    {
        if (!Within(offset, destination.size(), reader_.size))
            return Fail(Status::Corrupt, "CompressionResourceReadOutOfBounds");
        if (destination.size() > remaining_)
            return Fail(Status::LimitExceeded, "CompressionResourceReadBudget");
        if (destination.empty()) return {};
        remaining_ -= destination.size();
        try
        {
            if (!reader_.read || reader_.read(offset, destination) != destination.size())
                return Fail(Status::ReadError, "CompressionResourceReadFailed");
        }
        catch (...) { return Fail(Status::ReadError, "CompressionResourceReaderThrew"); }
        return {};
    }
private:
    const ApfsCompressionResourceReader& reader_;
    std::uint64_t remaining_;
};

Result DecodeOffsetResource(const ApfsCompressionHeader& header,
    const ApfsCompressionResourceReader& resource, std::uint64_t offset,
    std::uint64_t wanted, const ApfsCompressionLimits& limits,
    std::vector<std::byte>& result)
{
    // Types 8/12 use N+1 little-endian absolute offsets, with no resource-map header.
    // Format cross-checks: apfs-fuse Decmpfs.cpp and afsctool's LZVN writer.
    // Only format facts are used; no implementation code is copied.
    if (resource.size > limits.max_resource_bytes || resource.size > UINT32_MAX)
        return Fail(Status::LimitExceeded, "CompressionResourceSizeLimit");
    const auto count = header.uncompressed_size / kBlockBytes + (header.uncompressed_size % kBlockBytes != 0);
    const auto table_size = (count + 1) * 4; // count <= ceil(UINT64_MAX / 65536).
    if (table_size > limits.max_table_bytes || !FitsVector(table_size))
        return Fail(Status::LimitExceeded, "CompressionResourceTableLimit");
    if (table_size > resource.size)
        return Fail(Status::Corrupt, "CompressionResourceTableSizeInvalid");
    ForkReads reads(resource, limits.max_resource_read_bytes);
    std::vector<std::byte> table(static_cast<std::size_t>(table_size));
    auto rc = reads.Read(0, table);
    if (!rc) return rc;
    if (U32(table, 0) != table_size || U32(table, static_cast<std::size_t>(count * 4)) != resource.size)
        return Fail(Status::Corrupt, "CompressionResourceOffsetsInvalid");
    for (std::uint64_t i = 0; i < count; ++i)
    {
        const auto begin = U32(table, static_cast<std::size_t>(i * 4));
        const auto end = U32(table, static_cast<std::size_t>((i + 1) * 4));
        const auto max_encoded = kBlockBytes + (header.type == 12 ? 4096 : 1);
        if (end <= begin || end > resource.size || end - begin > max_encoded)
            return Fail(Status::Corrupt, "CompressionResourceBlockBoundsInvalid");
    }
    if (!wanted) return {};
    const auto last = (offset + wanted - 1) / kBlockBytes;
    const auto first = offset / kBlockBytes;
    const auto decoded_end = last == count - 1 ? header.uncompressed_size : (last + 1) * kBlockBytes;
    if (decoded_end - first * kBlockBytes > limits.max_decoded_bytes)
        return Fail(Status::LimitExceeded, "CompressionDecodedWorkLimit");
    result.resize(static_cast<std::size_t>(wanted));
    std::vector<std::byte> encoded, decoded;
    auto remaining_work = limits.max_lzfse_work_units;
    for (auto i = first; i <= last; ++i)
    {
        const auto begin = U32(table, static_cast<std::size_t>(i * 4));
        const auto end = U32(table, static_cast<std::size_t>((i + 1) * 4));
        encoded.resize(end - begin);
        rc = reads.Read(begin, encoded);
        if (!rc) return rc;
        const auto logical_start = i * kBlockBytes;
        const auto expected = (std::min)(kBlockBytes, header.uncompressed_size - logical_start);
        rc = header.type == 12 ? DecodeLzfse(encoded, expected, limits, remaining_work, decoded) :
            DecodeLzvn(encoded, expected, decoded);
        if (!rc) return rc;
        const auto copy_begin = (std::max)(offset, logical_start);
        const auto copy_end = (std::min)(offset + wanted, logical_start + expected);
        std::copy_n(decoded.begin() + static_cast<std::size_t>(copy_begin - logical_start),
            static_cast<std::size_t>(copy_end - copy_begin),
            result.begin() + static_cast<std::size_t>(copy_begin - offset));
    }
    return {};
}

Result DecodeResource(const ApfsCompressionHeader& header,
    const ApfsCompressionResourceReader& resource, std::uint64_t offset,
    std::uint64_t wanted, const ApfsCompressionLimits& limits,
    std::vector<std::byte>& result)
{
    if (resource.size > limits.max_resource_bytes)
        return Fail(Status::LimitExceeded, "CompressionResourceSizeLimit");
    ForkReads reads(resource, limits.max_resource_read_bytes);
    std::array<std::byte, 16> outer{};
    auto rc = reads.Read(0, outer);
    if (!rc) return rc;
    const std::uint64_t data_offset = U32(outer, 0, true);
    const std::uint64_t map_offset = U32(outer, 4, true);
    const std::uint64_t data_size = U32(outer, 8, true);
    const std::uint64_t map_size = U32(outer, 12, true);
    if (data_offset < 16 || map_offset < 16 || data_size < 8 || map_size < 28 ||
        !Within(data_offset, data_size, resource.size) ||
        !Within(map_offset, map_size, resource.size) ||
        (data_offset < map_offset + map_size && map_offset < data_offset + data_size))
        return Fail(Status::Corrupt, "CompressionResourceSectionsInvalid");
    std::array<std::byte, 8> prefix{};
    rc = reads.Read(data_offset, prefix);
    if (!rc) return rc;
    const std::uint64_t payload_size = U32(prefix, 0, true);
    const std::uint64_t count = U32(prefix, 4);
    const auto expected_count = header.uncompressed_size / kBlockBytes +
        (header.uncompressed_size % kBlockBytes != 0 ? 1 : 0);
    const auto table_size = count * 8; // count is 32-bit; arithmetic is 64-bit.
    if (payload_size != data_size - 4 || count != expected_count ||
        table_size + 4 > payload_size)
        return Fail(Status::Corrupt, "CompressionResourceTableSizeInvalid");
    if (table_size + 4 > limits.max_table_bytes || !FitsVector(table_size))
        return Fail(Status::LimitExceeded, "CompressionResourceTableLimit");
    const auto base = data_offset + 4;
    std::vector<std::byte> table(static_cast<std::size_t>(table_size));
    rc = reads.Read(base + 4, table);
    if (!rc) return rc;
    // Sorting an independent interval array accepts nonmonotonic physical order
    // while rejecting aliasing/overlap, including blocks outside the read range.
    std::vector<std::pair<std::uint32_t, std::uint32_t>> intervals;
    intervals.reserve(static_cast<std::size_t>(count));
    for (std::size_t i = 0; i < static_cast<std::size_t>(count); ++i)
    {
        const auto start = U32(table, i * 8);
        const auto size = U32(table, i * 8 + 4);
        if (start < table_size + 4 || size == 0 || size > kBlockBytes + 1 ||
            !Within(start, size, payload_size))
            return Fail(Status::Corrupt, "CompressionResourceBlockBoundsInvalid");
        intervals.emplace_back(start, size);
    }
    std::sort(intervals.begin(), intervals.end());
    std::uint64_t previous_end = table_size + 4;
    for (const auto& interval : intervals)
    {
        if (interval.first < previous_end)
            return Fail(Status::Corrupt, "CompressionResourceBlocksOverlap");
        previous_end = static_cast<std::uint64_t>(interval.first) + interval.second;
    }
    if (wanted == 0) return {};
    const auto end = offset + wanted; // wanted was clipped using subtraction.
    const auto first = offset / kBlockBytes;
    const auto last = (end - 1) / kBlockBytes;
    const auto decoded_end = last == expected_count - 1 ? header.uncompressed_size : (last + 1) * kBlockBytes;
    if (decoded_end - first * kBlockBytes > limits.max_decoded_bytes)
        return Fail(Status::LimitExceeded, "CompressionDecodedWorkLimit");
    result.resize(static_cast<std::size_t>(wanted));
    std::vector<std::byte> encoded;
    std::vector<std::byte> decoded;
    for (auto i = first; i <= last; ++i)
    {
        const auto entry = static_cast<std::size_t>(i * 8);
        const auto start = U32(table, entry);
        const auto size = U32(table, entry + 4);
        encoded.resize(size);
        rc = reads.Read(base + start, encoded);
        if (!rc) return rc;
        const auto block_offset = i * kBlockBytes;
        const auto expected = (std::min)(kBlockBytes, header.uncompressed_size - block_offset);
        rc = DecodeBlock(encoded, expected, limits, decoded);
        if (!rc) return rc;
        const auto begin_copy = (std::max)(offset, block_offset);
        const auto end_copy = (std::min)(end, block_offset + expected);
        std::copy_n(decoded.begin() + static_cast<std::size_t>(begin_copy - block_offset),
            static_cast<std::size_t>(end_copy - begin_copy),
            result.begin() + static_cast<std::size_t>(begin_copy - offset));
    }
    return {};
}
} // namespace

ApfsCompressionResult ApfsCompression::Inspect(std::span<const std::byte> decmpfs,
    const ApfsCompressionLimits& limits, ApfsCompressionHeader& out_header) noexcept
{
    if (decmpfs.size() < kHeaderBytes || U32(decmpfs, 0) != 0x636d7066)
        return Fail(Status::Corrupt, "CompressionHeaderInvalid");
    ApfsCompressionHeader header{U32(decmpfs, 4), U64(decmpfs, 8)};
    if (header.type != 1 && header.type != 3 && header.type != 4 && header.type != 7 && header.type != 8 &&
        header.type != 11 && header.type != 12)
        return Fail(Status::Unsupported, "CompressionTypeUnsupported");
    if (header.type == 1 && decmpfs.size() - kHeaderBytes != header.uncompressed_size)
        return Fail(Status::Corrupt, "CompressionInlineRawSizeMismatch");
    if ((header.type == 4 || header.type == 8 || header.type == 12) && decmpfs.size() != kHeaderBytes)
        return Fail(Status::Corrupt, "CompressionResourceAttributeSizeInvalid");
    if (header.type == 3)
    {
        const auto payload = decmpfs.subspan(kHeaderBytes);
        if (payload.empty() || (RawMarker(payload.front()) && payload.size() - 1 != header.uncompressed_size))
            return Fail(Status::Corrupt, "CompressionInlinePayloadInvalid");
    }
    if (header.type == 7)
    {
        const auto payload = decmpfs.subspan(kHeaderBytes);
        if (payload.empty()) return Fail(Status::Corrupt, "CompressionInlinePayloadInvalid");
        if (payload.front() == std::byte{0x06} && payload.size() - 1 != header.uncompressed_size)
            return Fail(Status::Corrupt, "CompressionLzvnRawSizeMismatch");
    }
    if (decmpfs.size() > limits.max_decmpfs_bytes || header.uncompressed_size > limits.max_file_bytes ||
        (header.type != 4 && header.type != 8 && header.type != 12 && header.uncompressed_size > limits.max_inline_decoded_bytes))
        return Fail(Status::LimitExceeded, "CompressionHeaderSizeLimit");
    out_header = header;
    return {};
}

ApfsCompressionResult ApfsCompression::DecodeRange(std::span<const std::byte> decmpfs,
    const ApfsCompressionResourceReader& resource, std::uint64_t offset, std::uint64_t length,
    const ApfsCompressionLimits& limits, std::vector<std::byte>& out_bytes) noexcept
{
    try
    {
        ApfsCompressionHeader header;
        auto rc = Inspect(decmpfs, limits, header);
        if (!rc) return rc;
        if ((header.type == 7 || header.type == 11) && (resource.size != 0 || resource.read))
            return Fail(Status::Corrupt, "CompressionInlineResourceReaderUnexpected");
        const auto wanted = offset >= header.uncompressed_size ? 0 :
            (std::min)(length, header.uncompressed_size - offset);
        if (wanted > limits.max_output_bytes || !FitsVector(wanted))
            return Fail(Status::LimitExceeded, "CompressionOutputLimit");
        std::vector<std::byte> result;
        if (header.type == 4 || header.type == 8 || header.type == 12)
        {
            rc = header.type != 4 ? DecodeOffsetResource(header, resource, offset, wanted, limits, result) :
                DecodeResource(header, resource, offset, wanted, limits, result);
            if (!rc) return rc;
        }
        else
        {
            auto payload = decmpfs.subspan(kHeaderBytes);
            std::vector<std::byte> decoded;
            if (header.type == 3 || header.type == 7 || header.type == 11)
            {
                if (header.uncompressed_size > limits.max_decoded_bytes)
                    return Fail(Status::LimitExceeded, "CompressionDecodedWorkLimit");
                auto remaining_work = limits.max_lzfse_work_units;
                rc = header.type == 11 ? DecodeLzfse(payload, header.uncompressed_size, limits, remaining_work, decoded) :
                    header.type == 7 ? DecodeLzvn(payload, header.uncompressed_size, decoded) :
                        DecodeBlock(payload, header.uncompressed_size, limits, decoded);
                if (!rc) return rc;
                payload = decoded;
            }
            else if (wanted > limits.max_decoded_bytes)
                return Fail(Status::LimitExceeded, "CompressionDecodedWorkLimit");
            if (wanted != 0)
            {
                const auto slice = payload.subspan(static_cast<std::size_t>(offset), static_cast<std::size_t>(wanted));
                result.assign(slice.begin(), slice.end());
            }
        }
        out_bytes.swap(result); // The only mutation of caller-owned bytes.
        return {};
    }
    catch (const std::bad_alloc&) { return Fail(Status::LimitExceeded, "CompressionAllocationFailed"); }
    catch (const std::length_error&) { return Fail(Status::LimitExceeded, "CompressionAllocationSizeLimit"); }
}

} // namespace apfsaccess::rw
