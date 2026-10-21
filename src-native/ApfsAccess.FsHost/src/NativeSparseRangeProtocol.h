#pragma once
#include <array>
#include <cstdint>

// Private, little-endian METHOD_BUFFERED controls. These are not Windows sparse
// FSCTLs. Zero is an unmounted ordinary-image primitive: it retains allocation
// and holes. Sparse EOF changes use the normal SetFileSize callback, not IOCTLs.
namespace apfsaccess::fshost::sparse_control
{
inline constexpr std::uint32_t Version = 1;
inline constexpr std::uint32_t Query = (0x8000u << 16) | (1u << 14) | (0x810u << 2);
inline constexpr std::uint32_t Zero = (0x8000u << 16) | (2u << 14) | (0x811u << 2);
inline constexpr std::uint32_t CanQuery = 1, CanZero = 2, CanResizeSparse = 4;
inline constexpr std::uint32_t MaximumRanges = 64;
inline constexpr std::uint64_t MaximumZeroBytes = 1024 * 1024;
static_assert(MaximumZeroBytes <= UINT32_MAX);
struct Range { std::uint64_t offset = 0, length = 0; };
struct RangeRequest
{
    std::uint32_t version = Version, reserved = 0;
    std::uint64_t offset = 0, length = 0;
};
struct Reply
{
    std::uint32_t version = Version, capabilities = 0;
    std::uint64_t file_size = 0, allocation_size = 0;
    // Query pagination resumes here; Zero reports the number of allocated
    // bytes changed. Holes need no writes. Successful replies are durable.
    std::uint64_t next_offset = 0, zeroed_bytes = 0;
    std::uint32_t range_count = 0, more_ranges = 0;
    std::array<Range, MaximumRanges> ranges{};
};
static_assert(sizeof(RangeRequest) == 24);
static_assert(sizeof(Reply) == 1072);
}
