#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <vector>

namespace apfsaccess::rw
{

enum class ApfsCompressionStatus { Ok, Unsupported, Corrupt, LimitExceeded, ReadError };

struct ApfsCompressionResult
{
    ApfsCompressionStatus status = ApfsCompressionStatus::Ok;
    const char* detail = ""; // Static diagnostic; never owns memory.
    [[nodiscard]] explicit operator bool() const noexcept
    { return status == ApfsCompressionStatus::Ok; }
};

struct ApfsCompressionHeader
{
    std::uint32_t type = 0;
    std::uint64_t uncompressed_size = 0;
};

struct ApfsCompressionLimits
{
    std::uint64_t max_file_bytes = 1ULL << 40;
    std::uint64_t max_resource_bytes = 8ULL << 30;
    std::uint64_t max_decmpfs_bytes = 3802;
    std::uint64_t max_inline_decoded_bytes = 65536;
    std::uint64_t max_output_bytes = 16ULL << 20;
    std::uint64_t max_table_bytes = 4ULL << 20;
    std::uint64_t max_resource_read_bytes = 32ULL << 20; // Sum of callback requests per call.
    std::uint64_t max_decoded_bytes = 32ULL << 20; // Full selected blocks, including discarded bytes.
    std::uint64_t max_zlib_allocation_bytes = 256ULL << 10; // Cumulative allocations per stream.
    std::uint64_t max_lzfse_state_bytes = 256ULL << 10;
    std::uint64_t max_lzfse_work_units = 1ULL << 30; // Sum of conservative per-block decoder budgets.
    std::uint64_t max_lzbitmap_state_bytes = 4096; // Fixed stack state; no codec heap.
    std::uint64_t max_lzbitmap_work_units = 1ULL << 28; // Shared decrementing operation budget.
};

struct ApfsCompressionResourceReader
{
    std::uint64_t size = 0; // Exact immutable fork size, not allocation size.
    // Must fill the entire span and return its size. Any other result or exception
    // is ReadError. Never write outside the supplied span. Calls are synchronous;
    // backing bytes must remain stable for the entire DecodeRange operation.
    std::function<std::size_t(std::uint64_t, std::span<std::byte>)> read;
};

class ApfsCompression
{
public:
    // Validate the little-endian 16-byte decmpfs header, supported type, limits,
    // and inline framing. Does not inflate a stream or read a resource fork.
    // Supported types: 1, 3, 4, 7, 8, 9, 10, 11, 12, 13 and 14.
    // out_header is unchanged on failure.
    [[nodiscard]] static ApfsCompressionResult Inspect(
        std::span<const std::byte> decmpfs, const ApfsCompressionLimits& limits,
        ApfsCompressionHeader& out_header) noexcept;

    // Replace out_bytes with [offset, offset + length), clipped to logical EOF.
    // Offset at/beyond EOF succeeds with empty output; addition cannot overflow.
    // All failures preserve out_bytes, including reader exceptions and allocation
    // failure. decmpfs may alias out_bytes; no input is modified during decoding.
    // Type 1: inline raw. Type 3: zlib-wrapped inline or low-nibble-0xF raw marker.
    // Type 4: ordinary single-payload resource fork, 64 KiB blocks with the same
    // encodings. Validates the whole table, but only inflates intersecting blocks.
    // Type 7: inline LZVN (canonical 8-byte EOS) or 06-prefixed raw bytes.
    // Type 8: N+1 little-endian offsets and 64 KiB LZVN/raw resource blocks.
    // Types 9/10: CC-prefixed raw bytes, inline or in the same offset-table fork.
    // Types 11/12: complete LZFSE streams, inline or in the same offset-table fork.
    // Exact input/output sizes; no wrapper or trailing bytes. See lzfse/UPSTREAM.md.
    // Types 13/14: LZBITMAP ZBM09 streams or FF-prefixed raw bytes; inline or
    // offset-table fork. Strict contiguous metadata, zero reserved trailer bytes;
    // final unused half-nibble is unspecified. See third_party/lzbitmap/UPSTREAM.md.
    // Even empty reads validate framing/table; inline streams are fully validated.
    // Unselected resource blocks and the resource map's internal records are not
    // decoded/validated. This is a range reader, not a whole-file integrity audit.
    // Peak owned payload storage: output + two table-sized arrays + one encoded
    // block (<=69632) + one decoded block (<=65537), or bounded inline output + 1.
    // zlib memory is bounded separately; LZVN uses a fixed decoder state with no
    // heap allocation beyond inline output + 1. LZFSE state/work have separate
    // limits. LZBITMAP uses a fixed stack state and a shared operation budget;
    // raw escapes use the decoded-byte budget only. Caller/callback memory is excluded.
    [[nodiscard]] static ApfsCompressionResult DecodeRange(
        std::span<const std::byte> decmpfs,
        const ApfsCompressionResourceReader& resource,
        std::uint64_t offset, std::uint64_t length,
        const ApfsCompressionLimits& limits,
        std::vector<std::byte>& out_bytes) noexcept;
};

} // namespace apfsaccess::rw
