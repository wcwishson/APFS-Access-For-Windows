#include "MetadataStore.h"
#include "ApfsObjectMapStore.h"
#include "ApfsSpacemanStore.h"
#include "ApfsVolumeTreeStore.h"
#include "ExtentAllocator.h"
#include "MutationCompactor.h"
#include "NativeApfsReader.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <cwctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <limits>
#include <memory>
#include <memory_resource>
#include <span>
#include <sstream>
#include <unordered_set>
#include <utility>
#include <Windows.h>

namespace apfsaccess::rw
{
namespace
{
constexpr std::uint64_t kApfsRootDirectoryObjectId = 2;
constexpr std::size_t kCheckpointHeaderBytes = 32;
constexpr std::size_t kCheckpointChecksumOffset = 28;
constexpr std::uint32_t kCheckpointChecksumSeed = 2166136261u;
constexpr std::uint32_t kCheckpointChecksumPrime = 16777619u;
constexpr std::uint64_t kNativeCheckpointBandBlocks = 128;
constexpr std::uint64_t kNativeObjectMapCheckpointOffset = 0;
constexpr std::uint64_t kNativeSpacemanCheckpointOffset = 4;
constexpr std::uint64_t kNativeInodeCheckpointOffset = 8;
constexpr std::uint64_t kNativeBtreeCheckpointOffset = 24;
constexpr std::uint64_t kNativeReplayCheckpointOffset = 64;
constexpr std::uint64_t kNativeOverflowCheckpointOffset = kNativeReplayCheckpointOffset + 2;
constexpr std::uint64_t kNativeObjectMapOverflowBlocks = 48;
constexpr std::uint64_t kNativeInodeOverflowOffset = kNativeOverflowCheckpointOffset + kNativeObjectMapOverflowBlocks;
constexpr std::uint64_t kNativeSpacemanExtensionBlocks = 32;
constexpr std::uint64_t kNativeInodeExtensionBlocks = 192;
constexpr std::uint64_t kNativeBtreeExtensionBlocks = 384;
constexpr std::uint64_t kNativeMetadataExtensionBlocks =
    kNativeInodeExtensionBlocks + kNativeBtreeExtensionBlocks;
constexpr std::uint64_t kNativeCheckpointExtensionBlocks =
    kNativeSpacemanExtensionBlocks + kNativeMetadataExtensionBlocks;
constexpr std::uint64_t kNativeMinimumSpacemanExtensionStartBlock = 1024;
constexpr std::uint64_t kNativeMinimumMetadataExtensionStartBlock = 1024;
constexpr std::uint64_t kNativeSpacemanExtensionOffset = 0;
constexpr std::uint64_t kNativeInodeExtensionOffset = 0;
constexpr std::uint64_t kNativeBtreeExtensionOffset = kNativeInodeExtensionBlocks;
constexpr std::size_t kPayloadBatchContiguousStorageLimit = 64ull * 1024ull * 1024ull;
constexpr std::size_t kPayloadRangeMaterializationChunkBytes = 1024ull * 1024ull;
constexpr std::size_t kPayloadRangeMaterializationWindowBytes = 8ull * 1024ull * 1024ull;
constexpr std::size_t kPayloadTailZeroPadReferenceCopyLimit = 256ull * 1024ull;
constexpr std::size_t kCommittedReadExtentSnapshotCacheMaxEntries = 128;
constexpr std::uint64_t kCommittedReadExtentSnapshotCacheMaxBytes = 4ull * 1024ull * 1024ull;

std::uint32_t UpdateFnv1a(std::uint32_t hash, const std::byte* bytes, std::size_t length)
{
    for (std::size_t index = 0; index < length; ++index)
    {
        hash ^= static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[index]));
        hash *= kCheckpointChecksumPrime;
    }
    return hash;
}

std::optional<std::uint64_t> ComputeApfsObjectChecksum(std::span<const std::byte> block)
{
    constexpr std::uint64_t kModulus = std::numeric_limits<std::uint32_t>::max();
    constexpr std::size_t kChecksumBytes = sizeof(std::uint64_t);
    if (block.size() < kChecksumBytes + sizeof(std::uint32_t) ||
        ((block.size() - kChecksumBytes) % sizeof(std::uint32_t)) != 0)
    {
        return std::nullopt;
    }

    std::uint64_t sum1 = 0;
    std::uint64_t sum2 = 0;
    for (std::size_t offset = kChecksumBytes; offset < block.size(); offset += sizeof(std::uint32_t))
    {
        const auto value =
            static_cast<std::uint32_t>(std::to_integer<unsigned char>(block[offset + 0])) |
            (static_cast<std::uint32_t>(std::to_integer<unsigned char>(block[offset + 1])) << 8) |
            (static_cast<std::uint32_t>(std::to_integer<unsigned char>(block[offset + 2])) << 16) |
            (static_cast<std::uint32_t>(std::to_integer<unsigned char>(block[offset + 3])) << 24);
        sum1 = (sum1 + value) % kModulus;
        sum2 = (sum2 + sum1) % kModulus;
    }

    const auto low = kModulus - ((sum1 + sum2) % kModulus);
    const auto high = kModulus - ((sum1 + low) % kModulus);
    return (high << 32) | low;
}

bool IsReadTraceEnabled()
{
    static const bool enabled = []()
    {
        wchar_t value[8]{};
        const auto chars = GetEnvironmentVariableW(L"APFSACCESS_TRACE_READS", value, static_cast<DWORD>(std::size(value)));
        return chars > 0 && value[0] != L'\0' && value[0] != L'0';
    }();
    return enabled;
}

void TraceReadFailure(
    std::wstring_view path,
    std::uint64_t object_id,
    std::uint64_t offset,
    std::uint64_t bytes,
    std::wstring_view reason)
{
    if (!IsReadTraceEnabled())
    {
        return;
    }

    std::wcerr << L"[MetadataStore] ReadCommittedFileRange failed"
               << L" path=" << path
               << L" object=" << object_id
               << L" offset=" << offset
               << L" bytes=" << bytes
               << L" reason=" << reason
               << std::endl;
}

void TraceIntegrityFailure(std::wstring_view reason, std::uint64_t object_id = 0)
{
    if (!IsReadTraceEnabled())
    {
        return;
    }

    std::wcerr << L"[MetadataStore] VerifyIntegrity failed"
               << L" reason=" << reason
               << L" object=" << object_id
               << std::endl;
}

void TraceGraphFailure(std::wstring_view reason, std::uint64_t object_id = 0)
{
    if (!IsReadTraceEnabled())
    {
        return;
    }

    std::wcerr << L"[MetadataStore] ValidateInodeGraphState failed"
               << L" reason=" << reason
               << L" object=" << object_id
               << std::endl;
}

void TraceMutationFailure(
    std::wstring_view operation,
    std::wstring_view path,
    std::wstring_view secondary_path,
    std::wstring_view reason)
{
    if (!IsReadTraceEnabled())
    {
        return;
    }

    std::wcerr << L"[MetadataStore] ApplyMutation rejected"
               << L" operation=" << operation
               << L" path=" << path;
    if (!secondary_path.empty())
    {
        std::wcerr << L" secondary=" << secondary_path;
    }
    std::wcerr << L" reason=" << reason
               << std::endl;
}

bool IsCommitTraceEnabled()
{
    static const bool enabled = []()
    {
        wchar_t value[8]{};
        const auto chars = GetEnvironmentVariableW(L"APFSACCESS_TRACE_COMMITS", value, static_cast<DWORD>(std::size(value)));
        return chars > 0 && value[0] != L'\0' && value[0] != L'0';
    }();
    return enabled;
}

bool IsPerfCountersEnabled()
{
    static const bool enabled = []()
    {
        wchar_t value[8]{};
        const auto chars = GetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", value, static_cast<DWORD>(std::size(value)));
        if (chars > 0 && value[0] != L'\0')
        {
            return value[0] != L'0';
        }

        std::error_code ec;
        auto marker = std::filesystem::temp_directory_path(ec);
        if (ec)
        {
            return false;
        }
        marker /= "ApfsAccess";
        marker /= "perf-counters.enabled";
        return std::filesystem::exists(marker, ec) && !ec;
    }();
    return enabled;
}

bool IsCheckpointDeltaShadowEnabled()
{
    wchar_t value[8]{};
    const auto chars = GetEnvironmentVariableW(
        L"APFSACCESS_CHECKPOINT_DELTA_SHADOW",
        value,
        static_cast<DWORD>(std::size(value)));
    return chars > 0 && value[0] != L'\0' && value[0] != L'0';
}

bool IsStrictCommitVerificationEnabled()
{
    static const bool enabled = []()
    {
        wchar_t value[8]{};
        const auto chars = GetEnvironmentVariableW(L"APFSACCESS_STRICT_COMMIT_VERIFY", value, static_cast<DWORD>(std::size(value)));
        return chars > 0 && value[0] != L'\0' && value[0] != L'0';
    }();
    return enabled;
}

bool IsWorkingFreeExtentSanitizeCacheEnabled()
{
    static const bool enabled = []()
    {
        wchar_t value[8]{};
        const auto chars = GetEnvironmentVariableW(
            L"APFSACCESS_DISABLE_WORKING_FREE_SANITIZE_CACHE",
            value,
            static_cast<DWORD>(std::size(value)));
        return !(chars > 0 && value[0] != L'\0' && value[0] != L'0');
    }();
    return enabled;
}

bool IsCheckpointSerializationBufferReuseEnabled()
{
    static const bool enabled = []()
    {
        wchar_t value[8]{};
        const auto chars = GetEnvironmentVariableW(
            L"APFSACCESS_DISABLE_CHECKPOINT_SERIALIZATION_BUFFER_REUSE",
            value,
            static_cast<DWORD>(std::size(value)));
        return !(chars > 0 && value[0] != L'\0' && value[0] != L'0');
    }();
    return enabled;
}

bool IsCheckpointSlotAllocationIndexEnabled()
{
    static const bool enabled = []()
    {
        wchar_t value[8]{};
        const auto chars = GetEnvironmentVariableW(
            L"APFSACCESS_DISABLE_CHECKPOINT_SLOT_INDEX",
            value,
            static_cast<DWORD>(std::size(value)));
        return !(chars > 0 && value[0] != L'\0' && value[0] != L'0');
    }();
    return enabled;
}

bool IsCheckpointBlockIndexCacheEnabled()
{
    static const bool enabled = []()
    {
        wchar_t value[8]{};
        const auto chars = GetEnvironmentVariableW(
            L"APFSACCESS_DISABLE_CHECKPOINT_BLOCK_INDEX_CACHE",
            value,
            static_cast<DWORD>(std::size(value)));
        return !(chars > 0 && value[0] != L'\0' && value[0] != L'0');
    }();
    return enabled;
}

std::uint64_t ElapsedMicroseconds(std::chrono::steady_clock::time_point started)
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - started).count());
}


void TracePendingCommitFailure(std::wstring_view reason, std::uint64_t object_id = 0)
{
    if (!IsCommitTraceEnabled() && !IsReadTraceEnabled())
    {
        return;
    }

    std::wcerr << L"[MetadataStore] ValidatePendingCommitState failed"
               << L" reason=" << reason
               << L" object=" << object_id
               << std::endl;
}

bool PhysicalRangeContains(std::uint64_t container_start, std::uint64_t container_bytes, std::uint64_t physical_address, std::uint64_t required_bytes)
{
    if (container_start > physical_address ||
        container_start > (std::numeric_limits<std::uint64_t>::max() - container_bytes) ||
        physical_address > (std::numeric_limits<std::uint64_t>::max() - required_bytes))
    {
        return false;
    }

    const auto container_end = container_start + container_bytes;
    const auto requested_end = physical_address + required_bytes;
    return requested_end <= container_end;
}

bool HasPhysicalObjectMapping(const MetadataStore::ObjectMapUpdate& update) noexcept
{
    return update.object_id != 0 &&
           update.physical_address != 0 &&
           update.logical_size != 0;
}

bool RangeOverlapsSorted(
    const std::vector<MetadataStore::SpacemanAllocation>& sorted_extents,
    const MetadataStore::SpacemanAllocation& extent) noexcept
{
    if (extent.physical_address == 0 ||
        extent.bytes == 0 ||
        extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
    {
        return false;
    }

    const auto extent_end = extent.physical_address + extent.bytes;
    const auto next = std::lower_bound(
        sorted_extents.begin(),
        sorted_extents.end(),
        extent.physical_address,
        [](const MetadataStore::SpacemanAllocation& candidate, std::uint64_t physical_address)
        {
            return candidate.physical_address < physical_address;
        });
    if (next != sorted_extents.end() &&
        next->physical_address < extent_end)
    {
        return true;
    }
    if (next != sorted_extents.begin())
    {
        const auto& previous = *(next - 1);
        if (previous.physical_address <= (std::numeric_limits<std::uint64_t>::max() - previous.bytes) &&
            (previous.physical_address + previous.bytes) > extent.physical_address)
        {
            return true;
        }
    }

    return false;
}

std::string NarrowForCheckpointIdentity(std::wstring_view value)
{
    std::string out;
    out.reserve(value.size());
    for (const auto ch : value)
    {
        out.push_back(ch >= 0 && ch <= 0x7f ? static_cast<char>(ch) : '?');
    }
    return out;
}

bool HasLogicalExtentCoverage(
    const std::vector<MetadataStore::FileExtent>& extents,
    std::uint64_t logical_size)
{
    if (logical_size == 0)
    {
        return extents.empty();
    }
    if (extents.empty())
    {
        return false;
    }

    std::uint64_t covered_until = 0;
    for (const auto& extent : extents)
    {
        if (extent.bytes == 0 ||
            extent.physical_address == 0 ||
            extent.logical_offset != covered_until ||
            extent.logical_offset > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
        {
            return false;
        }

        covered_until = extent.logical_offset + extent.bytes;
        if (covered_until >= logical_size)
        {
            return true;
        }
    }

    return false;
}

std::vector<MetadataStore::FileExtent> SortFileExtents(std::vector<MetadataStore::FileExtent> extents)
{
    std::sort(extents.begin(), extents.end(), [](const MetadataStore::FileExtent& lhs, const MetadataStore::FileExtent& rhs)
    {
        if (lhs.logical_offset == rhs.logical_offset)
        {
            return lhs.physical_address < rhs.physical_address;
        }
        return lhs.logical_offset < rhs.logical_offset;
    });
    return extents;
}

bool FileExtentsAreSortedByLogicalOffset(const std::vector<MetadataStore::FileExtent>& extents)
{
    for (std::size_t index = 1; index < extents.size(); ++index)
    {
        const auto& previous = extents[index - 1];
        const auto& current = extents[index];
        if (current.logical_offset < previous.logical_offset)
        {
            return false;
        }
        if (current.logical_offset == previous.logical_offset &&
            current.physical_address < previous.physical_address)
        {
            return false;
        }
    }
    return true;
}

const std::vector<MetadataStore::FileExtent>* SortedOrCopiedFileExtents(
    const std::vector<MetadataStore::FileExtent>& extents,
    std::vector<MetadataStore::FileExtent>& scratch)
{
    if (FileExtentsAreSortedByLogicalOffset(extents))
    {
        return &extents;
    }

    scratch = SortFileExtents(extents);
    return &scratch;
}

bool ConservativePhysicalRangeContains(
    std::uint64_t extent_physical_address,
    std::uint64_t extent_bytes,
    std::uint64_t physical_address,
    std::uint64_t required_bytes,
    std::uint32_t block_size)
{
    if (block_size == 0 ||
        extent_physical_address == 0 ||
        extent_bytes == 0 ||
        physical_address == 0 ||
        required_bytes == 0)
    {
        return false;
    }

    const auto block_bytes = static_cast<std::uint64_t>(block_size);
    if (extent_physical_address > (std::numeric_limits<std::uint64_t>::max() - extent_bytes))
    {
        return false;
    }

    const auto aligned_start = extent_physical_address - (extent_physical_address % block_bytes);
    const auto extent_end = extent_physical_address + extent_bytes;
    if ((extent_end % block_bytes) != 0 &&
        extent_end > (std::numeric_limits<std::uint64_t>::max() - (block_bytes - (extent_end % block_bytes))))
    {
        return false;
    }
    const auto aligned_end = (extent_end % block_bytes) == 0
        ? extent_end
        : extent_end + (block_bytes - (extent_end % block_bytes));
    if (aligned_end <= aligned_start)
    {
        return false;
    }

    return PhysicalRangeContains(
        aligned_start,
        aligned_end - aligned_start,
        physical_address,
        required_bytes);
}

bool AddConservativeAllocationFromReadExtents(
    const std::vector<MetadataStore::FileExtent>& extents,
    std::vector<MetadataStore::SpacemanAllocation>& allocations,
    std::uint32_t block_size)
{
    if (block_size == 0)
    {
        return false;
    }

    const auto block_bytes = static_cast<std::uint64_t>(block_size);
    for (const auto& extent : extents)
    {
        if (extent.physical_address == 0 || extent.bytes == 0)
        {
            continue;
        }
        if (extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
        {
            return false;
        }

        const auto aligned_start = extent.physical_address - (extent.physical_address % block_bytes);
        const auto physical_end = extent.physical_address + extent.bytes;
        if ((physical_end % block_bytes) != 0 &&
            physical_end > (std::numeric_limits<std::uint64_t>::max() - (block_bytes - (physical_end % block_bytes))))
        {
            return false;
        }
        const auto aligned_end = (physical_end % block_bytes) == 0
            ? physical_end
            : physical_end + (block_bytes - (physical_end % block_bytes));
        if (aligned_end <= aligned_start)
        {
            return false;
        }

        const auto aligned_bytes = aligned_end - aligned_start;
        if (aligned_start == 0 || aligned_bytes == 0)
        {
            return false;
        }
        if (aligned_start > (std::numeric_limits<std::uint64_t>::max() - aligned_bytes))
        {
            return false;
        }

        allocations.push_back({ aligned_start, aligned_bytes });
    }

    std::sort(
        allocations.begin(),
        allocations.end(),
        [](const MetadataStore::SpacemanAllocation& lhs, const MetadataStore::SpacemanAllocation& rhs)
        {
            if (lhs.physical_address == rhs.physical_address)
            {
                return lhs.bytes < rhs.bytes;
            }
            return lhs.physical_address < rhs.physical_address;
        });

    std::vector<MetadataStore::SpacemanAllocation> merged;
    merged.reserve(allocations.size());
    for (const auto& extent : allocations)
    {
        if (extent.physical_address == 0 || extent.bytes == 0)
        {
            continue;
        }

        if (merged.empty())
        {
            merged.push_back(extent);
            continue;
        }

        auto& previous = merged.back();
        if (previous.physical_address > (std::numeric_limits<std::uint64_t>::max() - previous.bytes))
        {
            return false;
        }
        const auto previous_end = previous.physical_address + previous.bytes;
        const auto extent_end = extent.physical_address + extent.bytes;
        if (extent.physical_address <= previous_end)
        {
            if (extent_end > previous_end)
            {
                previous.bytes = extent_end - previous.physical_address;
            }
            continue;
        }

        merged.push_back(extent);
    }

    allocations = std::move(merged);
    return true;
}

bool NormalizeSpacemanExtents(std::vector<MetadataStore::SpacemanAllocation>& extents);

bool SortNonOverlappingSpacemanExtents(std::vector<MetadataStore::SpacemanAllocation>& extents)
{
    std::sort(
        extents.begin(),
        extents.end(),
        [](const MetadataStore::SpacemanAllocation& lhs, const MetadataStore::SpacemanAllocation& rhs)
        {
            if (lhs.physical_address == rhs.physical_address)
            {
                return lhs.bytes < rhs.bytes;
            }
            return lhs.physical_address < rhs.physical_address;
        });

    std::uint64_t previous_end = 0;
    bool have_previous = false;
    for (const auto& extent : extents)
    {
        if (extent.physical_address == 0 ||
            extent.bytes == 0 ||
            extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
        {
            return false;
        }

        const auto extent_end = extent.physical_address + extent.bytes;
        if (have_previous && extent.physical_address < previous_end)
        {
            return false;
        }

        previous_end = extent_end;
        have_previous = true;
    }

    return true;
}

bool SpacemanExtentsAreSortedNonOverlapping(const std::vector<MetadataStore::SpacemanAllocation>& extents)
{
    std::uint64_t previous_end = 0;
    bool have_previous = false;
    for (const auto& extent : extents)
    {
        if (extent.physical_address == 0 ||
            extent.bytes == 0 ||
            extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
        {
            return false;
        }

        const auto extent_end = extent.physical_address + extent.bytes;
        if (have_previous && extent.physical_address < previous_end)
        {
            return false;
        }

        previous_end = extent_end;
        have_previous = true;
    }

    return true;
}

bool SubtractAllocationsFromFreeExtents(
    std::vector<MetadataStore::SpacemanAllocation>& free_extents,
    const std::vector<MetadataStore::SpacemanAllocation>& allocations)
{
    if (free_extents.empty() || allocations.empty())
    {
        return true;
    }

    std::vector<MetadataStore::SpacemanAllocation> sorted_allocations;
    sorted_allocations.reserve(allocations.size());
    for (const auto& allocation : allocations)
    {
        if (allocation.physical_address == 0 || allocation.bytes == 0)
        {
            continue;
        }
        if (allocation.physical_address > (std::numeric_limits<std::uint64_t>::max() - allocation.bytes))
        {
            return false;
        }
        sorted_allocations.push_back(allocation);
    }

    std::sort(
        sorted_allocations.begin(),
        sorted_allocations.end(),
        [](const MetadataStore::SpacemanAllocation& lhs, const MetadataStore::SpacemanAllocation& rhs)
        {
            if (lhs.physical_address == rhs.physical_address)
            {
                return lhs.bytes < rhs.bytes;
            }
            return lhs.physical_address < rhs.physical_address;
        });

    std::vector<MetadataStore::SpacemanAllocation> adjusted;
    adjusted.reserve(free_extents.size());
    for (const auto& free_extent : free_extents)
    {
        if (free_extent.physical_address == 0 || free_extent.bytes == 0)
        {
            continue;
        }
        if (free_extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - free_extent.bytes))
        {
            return false;
        }

        const auto free_end = free_extent.physical_address + free_extent.bytes;
        auto cursor = free_extent.physical_address;
        for (const auto& allocation : sorted_allocations)
        {
            const auto allocation_end = allocation.physical_address + allocation.bytes;
            if (allocation_end <= cursor)
            {
                continue;
            }
            if (allocation.physical_address >= free_end)
            {
                break;
            }
            if (allocation.physical_address > cursor)
            {
                adjusted.push_back({ cursor, allocation.physical_address - cursor });
            }
            cursor = std::max(cursor, std::min(allocation_end, free_end));
            if (cursor >= free_end)
            {
                break;
            }
        }

        if (cursor < free_end)
        {
            adjusted.push_back({ cursor, free_end - cursor });
        }
    }

    std::sort(
        adjusted.begin(),
        adjusted.end(),
        [](const MetadataStore::SpacemanAllocation& lhs, const MetadataStore::SpacemanAllocation& rhs)
        {
            if (lhs.physical_address == rhs.physical_address)
            {
                return lhs.bytes < rhs.bytes;
            }
            return lhs.physical_address < rhs.physical_address;
        });

    std::vector<MetadataStore::SpacemanAllocation> merged;
    merged.reserve(adjusted.size());
    for (const auto& extent : adjusted)
    {
        if (extent.physical_address == 0 || extent.bytes == 0)
        {
            continue;
        }
        if (extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
        {
            return false;
        }

        if (merged.empty())
        {
            merged.push_back(extent);
            continue;
        }

        auto& previous = merged.back();
        if (previous.physical_address > (std::numeric_limits<std::uint64_t>::max() - previous.bytes))
        {
            return false;
        }
        const auto previous_end = previous.physical_address + previous.bytes;
        const auto extent_end = extent.physical_address + extent.bytes;
        if (extent.physical_address <= previous_end)
        {
            if (extent_end > previous_end)
            {
                previous.bytes = extent_end - previous.physical_address;
            }
            continue;
        }

        merged.push_back(extent);
    }

    free_extents = std::move(merged);
    return true;
}

bool SubtractExtentsFromAllocations(
    std::vector<MetadataStore::SpacemanAllocation>& allocations,
    const std::vector<MetadataStore::SpacemanAllocation>& removals)
{
    if (allocations.empty())
    {
        return true;
    }
    if (removals.empty())
    {
        return NormalizeSpacemanExtents(allocations);
    }

    std::vector<MetadataStore::SpacemanAllocation> sorted_removals;
    sorted_removals.reserve(removals.size());
    for (const auto& removal : removals)
    {
        if (removal.physical_address == 0 || removal.bytes == 0)
        {
            continue;
        }
        if (removal.physical_address > (std::numeric_limits<std::uint64_t>::max() - removal.bytes))
        {
            return false;
        }
        sorted_removals.push_back(removal);
    }
    if (!NormalizeSpacemanExtents(sorted_removals))
    {
        return false;
    }

    std::vector<MetadataStore::SpacemanAllocation> adjusted;
    adjusted.reserve(allocations.size());
    for (const auto& allocation : allocations)
    {
        if (allocation.physical_address == 0 || allocation.bytes == 0)
        {
            continue;
        }
        if (allocation.physical_address > (std::numeric_limits<std::uint64_t>::max() - allocation.bytes))
        {
            return false;
        }

        const auto allocation_end = allocation.physical_address + allocation.bytes;
        auto cursor = allocation.physical_address;
        for (const auto& removal : sorted_removals)
        {
            const auto removal_end = removal.physical_address + removal.bytes;
            if (removal_end <= cursor)
            {
                continue;
            }
            if (removal.physical_address >= allocation_end)
            {
                break;
            }
            if (removal.physical_address > cursor)
            {
                adjusted.push_back({ cursor, removal.physical_address - cursor });
            }
            cursor = std::max(cursor, std::min(removal_end, allocation_end));
            if (cursor >= allocation_end)
            {
                break;
            }
        }

        if (cursor < allocation_end)
        {
            adjusted.push_back({ cursor, allocation_end - cursor });
        }
    }

    allocations = std::move(adjusted);
    return NormalizeSpacemanExtents(allocations);
}

bool NormalizeSpacemanExtents(std::vector<MetadataStore::SpacemanAllocation>& extents)
{
    if (extents.empty())
    {
        return true;
    }

    std::sort(
        extents.begin(),
        extents.end(),
        [](const MetadataStore::SpacemanAllocation& lhs, const MetadataStore::SpacemanAllocation& rhs)
        {
            if (lhs.physical_address == rhs.physical_address)
            {
                return lhs.bytes < rhs.bytes;
            }
            return lhs.physical_address < rhs.physical_address;
        });

    std::vector<MetadataStore::SpacemanAllocation> merged;
    merged.reserve(extents.size());
    for (const auto& extent : extents)
    {
        if (extent.physical_address == 0 || extent.bytes == 0)
        {
            continue;
        }
        if (extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
        {
            return false;
        }

        if (merged.empty())
        {
            merged.push_back(extent);
            continue;
        }

        auto& previous = merged.back();
        if (previous.physical_address > (std::numeric_limits<std::uint64_t>::max() - previous.bytes))
        {
            return false;
        }

        const auto previous_end = previous.physical_address + previous.bytes;
        const auto extent_end = extent.physical_address + extent.bytes;
        if (extent.physical_address <= previous_end)
        {
            if (extent_end > previous_end)
            {
                previous.bytes = extent_end - previous.physical_address;
            }
            continue;
        }

        merged.push_back(extent);
    }

    extents = std::move(merged);
    return true;
}

bool IsCanonicalSpacemanExtents(const std::vector<MetadataStore::SpacemanAllocation>& extents) noexcept
{
    std::uint64_t previous_end = 0;
    bool have_previous = false;
    for (const auto& extent : extents)
    {
        if (extent.physical_address == 0 ||
            extent.bytes == 0 ||
            extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
        {
            return false;
        }

        const auto extent_end = extent.physical_address + extent.bytes;
        if (have_previous && extent.physical_address <= previous_end)
        {
            return false;
        }

        previous_end = extent_end;
        have_previous = true;
    }

    return true;
}

std::uint32_t ComputeCheckpointChecksum(const std::vector<std::byte>& block, std::size_t payload_bytes)
{
    if (block.size() < kCheckpointHeaderBytes || payload_bytes > (block.size() - kCheckpointHeaderBytes))
    {
        return 0;
    }

    auto hash = UpdateFnv1a(kCheckpointChecksumSeed, block.data(), kCheckpointChecksumOffset);
    if (payload_bytes > 0)
    {
        hash = UpdateFnv1a(hash, block.data() + kCheckpointHeaderBytes, payload_bytes);
    }
    return hash;
}

std::string BuildBtreeKeyBlob(const std::vector<std::byte>& key)
{
    if (key.empty())
    {
        return {};
    }

    return std::string(
        reinterpret_cast<const char*>(key.data()),
        reinterpret_cast<const char*>(key.data()) + static_cast<std::ptrdiff_t>(key.size()));
}

bool BtreeRecordKeyLess(const apfsaccess::rw::BtreeRecord& lhs, const apfsaccess::rw::BtreeRecord& rhs)
{
    return std::lexicographical_compare(
        lhs.key.begin(),
        lhs.key.end(),
        rhs.key.begin(),
        rhs.key.end(),
        [](std::byte l, std::byte r)
        {
            return std::to_integer<unsigned char>(l) < std::to_integer<unsigned char>(r);
        });
}

std::vector<apfsaccess::rw::BtreeRecord> CanonicalizeBtreeRecords(
    const std::vector<apfsaccess::rw::BtreeRecord>& source)
{
    std::unordered_map<std::string, apfsaccess::rw::BtreeRecord> latest_by_key;
    latest_by_key.reserve(source.size());
    std::unordered_map<std::uint64_t, std::string> inode_key_by_object_id;
    inode_key_by_object_id.reserve(source.size());

    for (const auto& record : source)
    {
        if (record.key.empty())
        {
            continue;
        }

        auto key_blob = BuildBtreeKeyBlob(record.key);
        if (key_blob.empty())
        {
            continue;
        }

        if (record.kind == apfsaccess::rw::BtreeRecordKind::Inode)
        {
            constexpr std::size_t kInodeKeyObjectIdOffset = 9;
            constexpr std::size_t kExpectedInodeKeyBytes = 1 + 8 + 8;
            if (record.key.size() != kExpectedInodeKeyBytes)
            {
                continue;
            }

            std::uint64_t object_id = 0;
            for (int index = 0; index < 8; ++index)
            {
                object_id |= static_cast<std::uint64_t>(
                    std::to_integer<unsigned char>(record.key[kInodeKeyObjectIdOffset + static_cast<std::size_t>(index)])) << (index * 8);
            }
            if (object_id == 0)
            {
                continue;
            }

            if (auto previous_key = inode_key_by_object_id.find(object_id);
                previous_key != inode_key_by_object_id.end())
            {
                latest_by_key.erase(previous_key->second);
            }

            if (record.tombstone)
            {
                latest_by_key.erase(key_blob);
                inode_key_by_object_id.erase(object_id);
                continue;
            }

            inode_key_by_object_id[object_id] = key_blob;
            latest_by_key.insert_or_assign(std::move(key_blob), record);
            continue;
        }

        if (record.tombstone)
        {
            latest_by_key.erase(key_blob);
            continue;
        }

        latest_by_key.insert_or_assign(std::move(key_blob), record);
    }

    std::vector<apfsaccess::rw::BtreeRecord> canonicalized;
    canonicalized.reserve(latest_by_key.size());
    for (auto& [_, record] : latest_by_key)
    {
        canonicalized.push_back(std::move(record));
    }

    std::sort(canonicalized.begin(), canonicalized.end(), BtreeRecordKeyLess);
    return canonicalized;
}

std::optional<std::uint64_t> DecodeBtreeInodeObjectIdFromKey(
    const apfsaccess::rw::BtreeRecord& record)
{
    constexpr std::size_t kInodeKeyObjectIdOffset = 9;
    constexpr std::size_t kExpectedInodeKeyBytes = 1 + 8 + 8;
    if (record.kind != apfsaccess::rw::BtreeRecordKind::Inode ||
        record.key.size() != kExpectedInodeKeyBytes)
    {
        return std::nullopt;
    }

    std::uint64_t object_id = 0;
    for (int index = 0; index < 8; ++index)
    {
        object_id |= static_cast<std::uint64_t>(
            std::to_integer<unsigned char>(record.key[kInodeKeyObjectIdOffset + static_cast<std::size_t>(index)])) << (index * 8);
    }
    if (object_id == 0)
    {
        return std::nullopt;
    }
    return object_id;
}

bool ApplyBtreeRecordDeltas(
    std::vector<apfsaccess::rw::BtreeRecord>& target,
    const std::vector<apfsaccess::rw::BtreeRecord>& pending)
{
    std::unordered_map<std::string, std::size_t> index_by_key;
    index_by_key.reserve(target.size() + pending.size());
    std::unordered_map<std::uint64_t, std::string> inode_key_by_object_id;
    inode_key_by_object_id.reserve(target.size() + pending.size());

    for (std::size_t index = 0; index < target.size(); ++index)
    {
        const auto& record = target[index];
        if (record.key.empty() ||
            record.kind < apfsaccess::rw::BtreeRecordKind::Inode ||
            record.kind > apfsaccess::rw::BtreeRecordKind::FileExtent ||
            std::to_integer<unsigned char>(record.key.front()) != static_cast<unsigned char>(record.kind))
        {
            return false;
        }

        auto key_blob = BuildBtreeKeyBlob(record.key);
        if (key_blob.empty())
        {
            return false;
        }

        if (record.kind == apfsaccess::rw::BtreeRecordKind::Inode)
        {
            const auto object_id = DecodeBtreeInodeObjectIdFromKey(record);
            if (!object_id.has_value())
            {
                return false;
            }
            inode_key_by_object_id[*object_id] = key_blob;
        }
        index_by_key[std::move(key_blob)] = index;
    }

    const auto erase_by_key = [&](const std::string& key)
    {
        auto index_it = index_by_key.find(key);
        if (index_it == index_by_key.end() ||
            index_it->second >= target.size())
        {
            return;
        }

        const auto removed_index = index_it->second;
        const auto last_index = target.size() - 1;
        if (removed_index != last_index)
        {
            target[removed_index] = std::move(target[last_index]);
            auto moved_key = BuildBtreeKeyBlob(target[removed_index].key);
            if (!moved_key.empty())
            {
                index_by_key[moved_key] = removed_index;
                if (target[removed_index].kind == apfsaccess::rw::BtreeRecordKind::Inode)
                {
                    if (const auto moved_object_id = DecodeBtreeInodeObjectIdFromKey(target[removed_index]);
                        moved_object_id.has_value())
                    {
                        inode_key_by_object_id[*moved_object_id] = std::move(moved_key);
                    }
                }
            }
        }

        target.pop_back();
        index_by_key.erase(key);
    };

    const auto upsert_record = [&](const std::string& key, const apfsaccess::rw::BtreeRecord& record)
    {
        auto index_it = index_by_key.find(key);
        if (index_it != index_by_key.end() &&
            index_it->second < target.size())
        {
            target[index_it->second] = record;
            return;
        }

        index_by_key[key] = target.size();
        target.push_back(record);
    };

    for (const auto& record : pending)
    {
        if (record.key.empty() ||
            record.kind < apfsaccess::rw::BtreeRecordKind::Inode ||
            record.kind > apfsaccess::rw::BtreeRecordKind::FileExtent ||
            std::to_integer<unsigned char>(record.key.front()) != static_cast<unsigned char>(record.kind))
        {
            return false;
        }

        auto key_blob = BuildBtreeKeyBlob(record.key);
        if (key_blob.empty())
        {
            return false;
        }

        if (record.kind == apfsaccess::rw::BtreeRecordKind::Inode)
        {
            const auto object_id = DecodeBtreeInodeObjectIdFromKey(record);
            if (!object_id.has_value())
            {
                return false;
            }

            if (auto previous_key = inode_key_by_object_id.find(*object_id);
                previous_key != inode_key_by_object_id.end() &&
                previous_key->second != key_blob)
            {
                erase_by_key(previous_key->second);
                inode_key_by_object_id.erase(*object_id);
            }

            if (record.tombstone)
            {
                erase_by_key(key_blob);
                inode_key_by_object_id.erase(*object_id);
                continue;
            }

            upsert_record(key_blob, record);
            inode_key_by_object_id[*object_id] = std::move(key_blob);
            continue;
        }

        if (record.tombstone)
        {
            erase_by_key(key_blob);
            continue;
        }
        upsert_record(key_blob, record);
    }

    std::sort(target.begin(), target.end(), BtreeRecordKeyLess);
    return true;
}

struct BtreeRecordRestoreEntry
{
    std::string key;
    std::optional<apfsaccess::rw::BtreeRecord> previous;
};

bool ApplyBtreeRecordDeltasWithRestoreLog(
    std::vector<apfsaccess::rw::BtreeRecord>& target,
    std::unordered_map<std::string, std::size_t>& index_by_key,
    std::unordered_map<std::uint64_t, std::string>& inode_key_by_object_id,
    const std::vector<apfsaccess::rw::BtreeRecord>& pending,
    std::vector<BtreeRecordRestoreEntry>& restore_log)
{
    std::unordered_set<std::string> restored_keys;
    restored_keys.reserve(pending.size() * 2);
    bool needs_sorted_index_rebuild = false;

    if (index_by_key.size() != target.size())
    {
        return false;
    }

    const auto remember_restore = [&](const std::string& key)
    {
        if (!restored_keys.insert(key).second)
        {
            return;
        }

        auto index_it = index_by_key.find(key);
        restore_log.push_back(
            {
                key,
                (index_it == index_by_key.end() || index_it->second >= target.size())
                    ? std::optional<apfsaccess::rw::BtreeRecord>{}
                    : target[index_it->second],
            });
    };

    const auto erase_by_key = [&](const std::string& key)
    {
        remember_restore(key);
        auto index_it = index_by_key.find(key);
        if (index_it == index_by_key.end() ||
            index_it->second >= target.size())
        {
            return;
        }

        const auto removed_index = index_it->second;
        const auto last_index = target.size() - 1;
        std::optional<std::uint64_t> removed_object_id;
        if (target[removed_index].kind == apfsaccess::rw::BtreeRecordKind::Inode)
        {
            removed_object_id = DecodeBtreeInodeObjectIdFromKey(target[removed_index]);
        }
        if (removed_index != last_index)
        {
            target[removed_index] = std::move(target[last_index]);
            auto moved_key = BuildBtreeKeyBlob(target[removed_index].key);
            if (!moved_key.empty())
            {
                index_by_key[moved_key] = removed_index;
                if (target[removed_index].kind == apfsaccess::rw::BtreeRecordKind::Inode)
                {
                    if (const auto moved_object_id = DecodeBtreeInodeObjectIdFromKey(target[removed_index]);
                        moved_object_id.has_value())
                    {
                        inode_key_by_object_id[*moved_object_id] = std::move(moved_key);
                    }
                }
            }
        }

        if (removed_object_id.has_value())
        {
            inode_key_by_object_id.erase(*removed_object_id);
        }
        target.pop_back();
        index_by_key.erase(key);
        needs_sorted_index_rebuild = true;
    };

    const auto upsert_record = [&](const std::string& key, const apfsaccess::rw::BtreeRecord& record)
    {
        remember_restore(key);
        auto index_it = index_by_key.find(key);
        if (index_it != index_by_key.end() &&
            index_it->second < target.size())
        {
            target[index_it->second] = record;
            return;
        }

        index_by_key[key] = target.size();
        target.push_back(record);
        needs_sorted_index_rebuild = true;
    };

    for (const auto& record : pending)
    {
        if (record.key.empty() ||
            record.kind < apfsaccess::rw::BtreeRecordKind::Inode ||
            record.kind > apfsaccess::rw::BtreeRecordKind::FileExtent ||
            std::to_integer<unsigned char>(record.key.front()) != static_cast<unsigned char>(record.kind))
        {
            return false;
        }

        auto key_blob = BuildBtreeKeyBlob(record.key);
        if (key_blob.empty())
        {
            return false;
        }

        if (record.kind == apfsaccess::rw::BtreeRecordKind::Inode)
        {
            const auto object_id = DecodeBtreeInodeObjectIdFromKey(record);
            if (!object_id.has_value())
            {
                return false;
            }

            if (auto previous_key = inode_key_by_object_id.find(*object_id);
                previous_key != inode_key_by_object_id.end() &&
                previous_key->second != key_blob)
            {
                erase_by_key(previous_key->second);
                inode_key_by_object_id.erase(*object_id);
            }

            if (record.tombstone)
            {
                erase_by_key(key_blob);
                inode_key_by_object_id.erase(*object_id);
                continue;
            }

            upsert_record(key_blob, record);
            inode_key_by_object_id[*object_id] = std::move(key_blob);
            continue;
        }

        if (record.tombstone)
        {
            erase_by_key(key_blob);
            continue;
        }
        upsert_record(key_blob, record);
    }

    if (needs_sorted_index_rebuild)
    {
        std::sort(target.begin(), target.end(), BtreeRecordKeyLess);
        index_by_key.clear();
        inode_key_by_object_id.clear();
        index_by_key.reserve(target.size());
        inode_key_by_object_id.reserve(target.size());
        for (std::size_t index = 0; index < target.size(); ++index)
        {
            auto key_blob = BuildBtreeKeyBlob(target[index].key);
            if (key_blob.empty())
            {
                return false;
            }
            if (target[index].kind == apfsaccess::rw::BtreeRecordKind::Inode)
            {
                const auto object_id = DecodeBtreeInodeObjectIdFromKey(target[index]);
                if (!object_id.has_value())
                {
                    return false;
                }
                inode_key_by_object_id[*object_id] = key_blob;
            }
            index_by_key[std::move(key_blob)] = index;
        }
    }

    return true;
}

bool RestoreBtreeRecordDeltas(
    std::vector<apfsaccess::rw::BtreeRecord>& target,
    std::unordered_map<std::string, std::size_t>& index_by_key,
    std::unordered_map<std::uint64_t, std::string>& inode_key_by_object_id,
    const std::vector<BtreeRecordRestoreEntry>& restore_log)
{
    if (index_by_key.size() != target.size())
    {
        return false;
    }

    bool needs_sorted_index_rebuild = false;

    const auto erase_by_key = [&](const std::string& key)
    {
        auto index_it = index_by_key.find(key);
        if (index_it == index_by_key.end() ||
            index_it->second >= target.size())
        {
            return;
        }

        const auto removed_index = index_it->second;
        const auto last_index = target.size() - 1;
        std::optional<std::uint64_t> removed_object_id;
        if (target[removed_index].kind == apfsaccess::rw::BtreeRecordKind::Inode)
        {
            removed_object_id = DecodeBtreeInodeObjectIdFromKey(target[removed_index]);
        }
        if (removed_index != last_index)
        {
            target[removed_index] = std::move(target[last_index]);
            auto moved_key = BuildBtreeKeyBlob(target[removed_index].key);
            if (!moved_key.empty())
            {
                index_by_key[moved_key] = removed_index;
                if (target[removed_index].kind == apfsaccess::rw::BtreeRecordKind::Inode)
                {
                    if (const auto moved_object_id = DecodeBtreeInodeObjectIdFromKey(target[removed_index]);
                        moved_object_id.has_value())
                    {
                        inode_key_by_object_id[*moved_object_id] = std::move(moved_key);
                    }
                }
            }
        }
        if (removed_object_id.has_value())
        {
            inode_key_by_object_id.erase(*removed_object_id);
        }
        target.pop_back();
        index_by_key.erase(key);
        needs_sorted_index_rebuild = true;
    };

    for (auto it = restore_log.rbegin(); it != restore_log.rend(); ++it)
    {
        if (it->previous.has_value())
        {
            auto index_it = index_by_key.find(it->key);
            if (index_it != index_by_key.end() &&
                index_it->second < target.size())
            {
                target[index_it->second] = it->previous.value();
            }
            else
            {
                index_by_key[it->key] = target.size();
                target.push_back(it->previous.value());
                needs_sorted_index_rebuild = true;
            }

            if (it->previous->kind == apfsaccess::rw::BtreeRecordKind::Inode)
            {
                if (const auto object_id = DecodeBtreeInodeObjectIdFromKey(it->previous.value());
                    object_id.has_value())
                {
                    inode_key_by_object_id[*object_id] = it->key;
                }
            }
            continue;
        }

        erase_by_key(it->key);
    }

    if (needs_sorted_index_rebuild)
    {
        std::sort(target.begin(), target.end(), BtreeRecordKeyLess);
        index_by_key.clear();
        inode_key_by_object_id.clear();
        index_by_key.reserve(target.size());
        inode_key_by_object_id.reserve(target.size());
        for (std::size_t index = 0; index < target.size(); ++index)
        {
            auto key_blob = BuildBtreeKeyBlob(target[index].key);
            if (key_blob.empty())
            {
                return false;
            }
            if (target[index].kind == apfsaccess::rw::BtreeRecordKind::Inode)
            {
                const auto object_id = DecodeBtreeInodeObjectIdFromKey(target[index]);
                if (!object_id.has_value())
                {
                    return false;
                }
                inode_key_by_object_id[*object_id] = key_blob;
            }
            index_by_key[std::move(key_blob)] = index;
        }
    }

    return true;
}

struct ScopeExit
{
    std::function<void()> callback;

    ~ScopeExit()
    {
        if (callback)
        {
            callback();
        }
    }
};

bool TryReadLe32(const std::vector<std::byte>& buffer, std::size_t offset, std::uint32_t& value)
{
    if (offset + sizeof(std::uint32_t) > buffer.size())
    {
        return false;
    }

    value = static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 0])) |
            (static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 1])) << 8) |
            (static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 2])) << 16) |
            (static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 3])) << 24);
    return true;
}

bool CanReportCanonicalCommitReady(
    bool canonical_state_loaded,
    bool commit_path_ready,
    bool recovery_required,
    bool legacy_fixture_fallback_used)
{
    return canonical_state_loaded &&
           commit_path_ready &&
           !recovery_required &&
           !legacy_fixture_fallback_used;
}

bool TryReadLe64(const std::vector<std::byte>& buffer, std::size_t offset, std::uint64_t& value)
{
    if (offset + sizeof(std::uint64_t) > buffer.size())
    {
        return false;
    }

    value = static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + 0])) |
            (static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + 1])) << 8) |
            (static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + 2])) << 16) |
            (static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + 3])) << 24) |
            (static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + 4])) << 32) |
            (static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + 5])) << 40) |
            (static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + 6])) << 48) |
            (static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + 7])) << 56);
    return true;
}

bool TryReadWideStringWithLength(
    const std::vector<std::byte>& buffer,
    std::size_t& cursor,
    std::wstring& value)
{
    value.clear();

    std::uint32_t length = 0;
    if (!TryReadLe32(buffer, cursor, length))
    {
        return false;
    }
    cursor += sizeof(std::uint32_t);

    const auto required_bytes = static_cast<std::uint64_t>(length) * 2ull;
    if (required_bytes > (std::numeric_limits<std::size_t>::max() - cursor))
    {
        return false;
    }
    if (static_cast<std::size_t>(required_bytes) > (buffer.size() - cursor))
    {
        return false;
    }

    value.reserve(length);
    for (std::uint32_t index = 0; index < length; ++index)
    {
        const auto lo = static_cast<std::uint16_t>(std::to_integer<unsigned char>(buffer[cursor + 0]));
        const auto hi = static_cast<std::uint16_t>(std::to_integer<unsigned char>(buffer[cursor + 1]));
        const auto code_unit = static_cast<std::uint16_t>(lo | (hi << 8));
        value.push_back(static_cast<wchar_t>(code_unit));
        cursor += 2;
    }
    return true;
}

struct DecodedBtreeInode
{
    std::uint64_t object_id = 0;
    std::uint64_t parent_object_id = 0;
    std::uint64_t xid = 0;
    bool is_directory = false;
    std::uint64_t logical_size = 0;
    std::uint64_t data_physical_address = 0;
    std::uint64_t timestamp_utc = 0;
    std::wstring name;
};

struct DecodedBtreeDirectoryEntry
{
    std::uint64_t parent_object_id = 0;
    std::wstring entry_name;
    std::uint64_t child_object_id = 0;
    std::uint64_t xid = 0;
};

struct DecodedBtreeExtent
{
    std::uint64_t object_id = 0;
    std::uint64_t logical_offset = 0;
    std::uint64_t physical_address = 0;
    std::uint64_t extent_bytes = 0;
    std::uint64_t xid = 0;
};

std::wstring BuildDirectoryEntryIndexKey(std::uint64_t parent_object_id, const std::wstring& entry_name)
{
    std::wstring key = std::to_wstring(parent_object_id);
    key.push_back(L'\x1f');
    key += entry_name;
    return key;
}

bool DecodeBtreeInodeRecord(const apfsaccess::rw::BtreeRecord& record, DecodedBtreeInode& decoded)
{
    constexpr std::size_t kExpectedKeyBytes = 1 + 8 + 8;
    constexpr std::uint32_t kDirectoryFlag = 0x1u;
    constexpr std::uint32_t kTombstoneFlag = 0x2u;
    constexpr std::uint32_t kTimestampPresentFlag = 0x4u;
    if (record.key.size() != kExpectedKeyBytes)
    {
        return false;
    }

    if (!TryReadLe64(record.key, 1, decoded.parent_object_id) ||
        !TryReadLe64(record.key, 9, decoded.object_id))
    {
        return false;
    }

    std::size_t cursor = 0;
    std::uint32_t flags = 0;
    if (!TryReadLe64(record.value, cursor, decoded.xid))
    {
        return false;
    }
    cursor += 8;
    if (!TryReadLe32(record.value, cursor, flags))
    {
        return false;
    }
    cursor += 4;
    if (!TryReadLe64(record.value, cursor, decoded.logical_size))
    {
        return false;
    }
    cursor += 8;
    if (!TryReadLe64(record.value, cursor, decoded.data_physical_address))
    {
        return false;
    }
    cursor += 8;
    if ((flags & kTimestampPresentFlag) != 0)
    {
        if (!TryReadLe64(record.value, cursor, decoded.timestamp_utc))
        {
            return false;
        }
        cursor += 8;
    }
    if (!TryReadWideStringWithLength(record.value, cursor, decoded.name))
    {
        return false;
    }
    if (cursor != record.value.size())
    {
        return false;
    }

    decoded.is_directory = (flags & kDirectoryFlag) != 0;
    if ((flags & kTombstoneFlag) != 0)
    {
        return false;
    }
    if ((flags & ~(kDirectoryFlag | kTimestampPresentFlag)) != 0)
    {
        return false;
    }
    if (decoded.object_id == 0 || decoded.name.empty())
    {
        return false;
    }
    if (decoded.is_directory)
    {
        if (decoded.logical_size != 0 || decoded.data_physical_address != 0)
        {
            return false;
        }
    }

    return true;
}

bool DecodeBtreeDirectoryRecord(const apfsaccess::rw::BtreeRecord& record, DecodedBtreeDirectoryEntry& decoded)
{
    if (record.key.size() < 1 + 8 + 4)
    {
        return false;
    }

    if (!TryReadLe64(record.key, 1, decoded.parent_object_id))
    {
        return false;
    }
    std::size_t key_cursor = 1 + 8;
    if (!TryReadWideStringWithLength(record.key, key_cursor, decoded.entry_name))
    {
        return false;
    }
    if (key_cursor != record.key.size() || decoded.entry_name.empty())
    {
        return false;
    }

    if (record.value.size() != (8 + 8 + 1))
    {
        return false;
    }
    if (!TryReadLe64(record.value, 0, decoded.xid) ||
        !TryReadLe64(record.value, 8, decoded.child_object_id))
    {
        return false;
    }
    if (decoded.child_object_id == 0)
    {
        return false;
    }
    const auto tombstone_flag = std::to_integer<unsigned char>(record.value[16]);
    if (tombstone_flag != 0)
    {
        return false;
    }

    return true;
}

bool DecodeBtreeExtentRecord(const apfsaccess::rw::BtreeRecord& record, DecodedBtreeExtent& decoded)
{
    constexpr std::size_t kExpectedKeyBytes = 1 + 8 + 8;
    if (record.key.size() != kExpectedKeyBytes)
    {
        return false;
    }
    if (!TryReadLe64(record.key, 1, decoded.object_id) ||
        !TryReadLe64(record.key, 9, decoded.logical_offset))
    {
        return false;
    }
    if (decoded.object_id == 0)
    {
        return false;
    }

    if (record.value.size() != (8 + 8 + 8 + 1))
    {
        return false;
    }
    if (!TryReadLe64(record.value, 0, decoded.xid) ||
        !TryReadLe64(record.value, 8, decoded.physical_address) ||
        !TryReadLe64(record.value, 16, decoded.extent_bytes))
    {
        return false;
    }
    if (decoded.extent_bytes == 0)
    {
        return false;
    }
    const auto tombstone_flag = std::to_integer<unsigned char>(record.value[24]);
    if (tombstone_flag != 0)
    {
        return false;
    }

    return true;
}

bool DecodedBtreeExtentsAreSortedByLogicalOffset(const std::vector<DecodedBtreeExtent>& extents)
{
    for (std::size_t index = 1; index < extents.size(); ++index)
    {
        const auto& previous = extents[index - 1];
        const auto& current = extents[index];
        if (previous.logical_offset > current.logical_offset ||
            (previous.logical_offset == current.logical_offset &&
             previous.physical_address > current.physical_address))
        {
            return false;
        }
    }

    return true;
}

std::vector<MetadataStore::FileExtent> ExtentsFromDecodedBtreeExtents(
    const std::vector<DecodedBtreeExtent>& decoded_extents)
{
    std::vector<MetadataStore::FileExtent> extents;
    extents.reserve(decoded_extents.size());
    for (const auto& decoded : decoded_extents)
    {
        extents.push_back(MetadataStore::FileExtent
        {
            decoded.logical_offset,
            decoded.physical_address,
            decoded.extent_bytes,
        });
    }
    if (DecodedBtreeExtentsAreSortedByLogicalOffset(decoded_extents))
    {
        return extents;
    }

    return SortFileExtents(std::move(extents));
}

bool ExtentsMatchDecodedBtreeExtents(
    const std::vector<MetadataStore::FileExtent>& file_extents,
    const std::vector<DecodedBtreeExtent>& decoded_extents,
    std::uint64_t logical_size,
    std::uint64_t anchor_physical_address,
    std::uint64_t xid_upper_bound)
{
    if (!HasLogicalExtentCoverage(file_extents, logical_size) ||
        decoded_extents.size() != file_extents.size())
    {
        return false;
    }

    std::vector<MetadataStore::FileExtent> sorted_file_extents_storage;
    const auto* sorted_file_extents = SortedOrCopiedFileExtents(file_extents, sorted_file_extents_storage);
    auto sorted_decoded_extents = decoded_extents;
    std::sort(sorted_decoded_extents.begin(), sorted_decoded_extents.end(), [](const DecodedBtreeExtent& lhs, const DecodedBtreeExtent& rhs)
    {
        if (lhs.logical_offset == rhs.logical_offset)
        {
            return lhs.physical_address < rhs.physical_address;
        }
        return lhs.logical_offset < rhs.logical_offset;
    });

    for (std::size_t index = 0; index < sorted_file_extents->size(); ++index)
    {
        const auto& expected = (*sorted_file_extents)[index];
        const auto& decoded = sorted_decoded_extents[index];
        if (decoded.logical_offset != expected.logical_offset ||
            decoded.physical_address != expected.physical_address ||
            decoded.extent_bytes != expected.bytes ||
            decoded.xid == 0 ||
            decoded.xid > xid_upper_bound)
        {
            return false;
        }
    }

    return !sorted_file_extents->empty() &&
           sorted_file_extents->front().logical_offset == 0 &&
           sorted_file_extents->front().physical_address == anchor_physical_address;
}

bool FileExtentsEqual(
    const std::vector<MetadataStore::FileExtent>& lhs,
    const std::vector<MetadataStore::FileExtent>& rhs)
{
    if (lhs.size() != rhs.size())
    {
        return false;
    }

    for (std::size_t index = 0; index < lhs.size(); ++index)
    {
        if (lhs[index].logical_offset != rhs[index].logical_offset ||
            lhs[index].physical_address != rhs[index].physical_address ||
            lhs[index].bytes != rhs[index].bytes)
        {
            return false;
        }
    }

    return true;
}

void TraceExtentMismatchDetail(
    std::uint64_t object_id,
    const std::vector<MetadataStore::FileExtent>& expected_extents,
    const std::vector<DecodedBtreeExtent>& decoded_extents,
    std::uint64_t logical_size,
    std::uint64_t anchor_physical_address,
    std::uint64_t xid_upper_bound)
{
    if (!IsReadTraceEnabled())
    {
        return;
    }

    std::wcerr << L"[MetadataStore] ExtentMismatch detail"
               << L" object=" << object_id
               << L" logicalSize=" << logical_size
               << L" anchor=" << anchor_physical_address
               << L" xidUpper=" << xid_upper_bound
               << L" expectedCount=" << expected_extents.size()
               << L" decodedCount=" << decoded_extents.size()
               << std::endl;
    for (const auto& extent : expected_extents)
    {
        std::wcerr << L"  expected logical=" << extent.logical_offset
                   << L" physical=" << extent.physical_address
                   << L" bytes=" << extent.bytes
                   << std::endl;
    }
    for (const auto& extent : decoded_extents)
    {
        std::wcerr << L"  decoded logical=" << extent.logical_offset
                   << L" physical=" << extent.physical_address
                   << L" bytes=" << extent.extent_bytes
                   << L" xid=" << extent.xid
                   << std::endl;
    }
}
} // namespace

MetadataStore::MetadataStore(VolumeContext context)
    : context_(std::move(context))
    , device_(context_.device_path, context_.device_offset_bytes)
{
    SyncCommitBlobTelemetryWithMode();
}

const MetadataStore::VolumeContext& MetadataStore::Context() const noexcept
{
    return context_;
}

const BlockDevice& MetadataStore::Device() const noexcept
{
    return device_;
}

bool MetadataStore::LoadContainerState()
{
    return LoadContainerSuperblocks();
}

bool MetadataStore::LoadVolumeState()
{
    if (!LoadContainerState())
    {
        MarkRecoveryRequired(L"ContainerStateLoadFailed");
        return false;
    }

    if (!LoadObjectMap())
    {
        if (recovery_reason_.empty())
        {
            MarkRecoveryRequired(L"ObjectMapLoadFailed");
        }
        return false;
    }

    if (!LoadSpacemanState())
    {
        if (recovery_reason_.empty())
        {
            MarkRecoveryRequired(L"SpacemanStateLoadFailed");
        }
        return false;
    }

    if (!EnsureRootState())
    {
        MarkRecoveryRequired(L"RootStateInvalid");
        return false;
    }

    if (context_.integrity_check_on_mount && !VerifyIntegrity())
    {
        MarkRecoveryRequired(ResolveIntegrityCheckFailureRecoveryReason());
        return false;
    }

    return true;
}

bool MetadataStore::LoadCanonicalState()
{
    canonical_state_loaded_ = false;
    canonical_commit_ready_ = false;

    if (!LoadVolumeState())
    {
        if (recovery_reason_.empty())
        {
            MarkRecoveryRequired(L"CanonicalVolumeStateLoadFailed");
        }
        return false;
    }

    ApfsObjectMapStore object_map_store;
    std::vector<ApfsObjectMapEntry> object_map_entries;
    object_map_entries.reserve(committed_object_map_.size());
    for (const auto& [_, update] : committed_object_map_)
    {
        if (!HasPhysicalObjectMapping(update))
        {
            continue;
        }

        object_map_entries.push_back(
            {
                update.object_id,
                update.physical_address,
                update.logical_size,
                update.xid,
            });
    }
    if (!object_map_store.ValidateEntries(object_map_entries))
    {
        MarkRecoveryRequired(L"CanonicalObjectMapStateInvalid");
        return false;
    }

    ApfsSpacemanStore spaceman_store;
    std::vector<ApfsExtent> allocations;
    allocations.reserve(committed_spaceman_allocations_.size());
    for (const auto& allocation : committed_spaceman_allocations_)
    {
        allocations.push_back({ allocation.physical_address, allocation.bytes });
    }

    std::vector<ApfsExtent> free_extents;
    free_extents.reserve(committed_spaceman_free_extents_.size());
    for (const auto& extent : committed_spaceman_free_extents_)
    {
        free_extents.push_back({ extent.physical_address, extent.bytes });
    }
    if (!spaceman_store.ValidateState(allocations, free_extents))
    {
        MarkRecoveryRequired(L"CanonicalSpacemanStateInvalid");
        return false;
    }

    ApfsVolumeTreeStore volume_tree_store;
    ApfsVolumeTreeProjection volume_tree_projection{};
    std::wstring volume_tree_error;
    if (!volume_tree_store.TryProjectFromBtreeRecords(
            committed_btree_records_,
            volume_tree_projection,
            volume_tree_error))
    {
        MarkRecoveryRequired(
            volume_tree_error.empty()
                ? L"CanonicalVolumeTreeStateInvalid"
                : volume_tree_error);
        return false;
    }

    canonical_state_loaded_ = container_loaded_ &&
                              object_map_loaded_ &&
                              spaceman_loaded_;
    canonical_commit_ready_ = CanReportCanonicalCommitReady(
        canonical_state_loaded_,
        commit_path_ready_,
        recovery_required_,
        legacy_fixture_fallback_used_);
    return canonical_state_loaded_;
}

bool MetadataStore::LoadContainerSuperblocks()
{
    // NXSB superblock field offsets used by the native APFS metadata reader.
    constexpr std::size_t kSuperblockBytes = 0x570;
    constexpr std::size_t kMagicOffset = 0x20;
    constexpr std::size_t kBlockSizeOffset = 0x24;
    constexpr std::size_t kTotalBlocksOffset = 0x28;
    constexpr std::size_t kCheckpointXidOffset = 0x10;
    constexpr std::size_t kSpacemanObjectIdOffset = 0x98;
    constexpr std::size_t kVolumeRootBlockOffset = 0xA0;
    constexpr std::size_t kFirstSbBlockOffset = 0x70;
    constexpr std::size_t kFirstMetaBlockOffset = 0x78;
    constexpr std::size_t kCurrentSbMapIndexOffset = 0x88;
    constexpr std::size_t kNextMetaIndexOffset = 0x84;
    constexpr std::size_t kCurrentMetaIndexOffset = 0x90;
    constexpr std::uint32_t kNxsbMagic = 0x4253584E; // 'NXSB'

    struct ParsedSuperblock
    {
        std::uint32_t block_size = 0;
        std::uint64_t total_blocks = 0;
        std::uint64_t checkpoint_xid = 0;
        std::uint64_t spaceman_object_id = 0;
        std::uint64_t volume_root_block = 0;
        std::uint64_t first_sb_block = 0;
        std::uint64_t first_meta_block = 0;
        std::uint32_t current_sb_map_index = 0;
        std::uint32_t next_meta_index = 0;
        std::uint32_t current_meta_index = 0;
    };

    const auto parse_superblock = [&](const std::vector<std::byte>& raw, ParsedSuperblock& parsed) -> bool
    {
        if (raw.size() < kSuperblockBytes)
        {
            return false;
        }

        const auto magic = ReadLe32(raw, kMagicOffset);
        if (magic != kNxsbMagic)
        {
            return false;
        }

        const auto block_size = ReadLe32(raw, kBlockSizeOffset);
        if (block_size == 0 || block_size > (1u << 20))
        {
            return false;
        }

        parsed.block_size = block_size;
        parsed.total_blocks = ReadLe64(raw, kTotalBlocksOffset);
        parsed.checkpoint_xid = ReadLe64(raw, kCheckpointXidOffset);
        parsed.spaceman_object_id = ReadLe64(raw, kSpacemanObjectIdOffset);
        parsed.volume_root_block = ReadLe64(raw, kVolumeRootBlockOffset);
        parsed.first_sb_block = ReadLe64(raw, kFirstSbBlockOffset);
        parsed.first_meta_block = ReadLe64(raw, kFirstMetaBlockOffset);
        parsed.current_sb_map_index = ReadLe32(raw, kCurrentSbMapIndexOffset);
        parsed.next_meta_index = ReadLe32(raw, kNextMetaIndexOffset);
        parsed.current_meta_index = ReadLe32(raw, kCurrentMetaIndexOffset);
        return true;
    };

    std::vector<std::byte> primary_superblock;
    if (!device_.Read(0, kSuperblockBytes, primary_superblock) || primary_superblock.size() < kSuperblockBytes)
    {
        container_loaded_ = false;
        active_superblock_bytes_.clear();
        return false;
    }

    ParsedSuperblock primary{};
    if (!parse_superblock(primary_superblock, primary))
    {
        container_loaded_ = false;
        active_superblock_bytes_.clear();
        return false;
    }
    if (primary.block_size > kSuperblockBytes)
    {
        std::vector<std::byte> full_primary_superblock;
        if (!device_.Read(0, static_cast<std::size_t>(primary.block_size), full_primary_superblock) ||
            full_primary_superblock.size() < static_cast<std::size_t>(primary.block_size) ||
            !parse_superblock(full_primary_superblock, primary))
        {
            container_loaded_ = false;
            active_superblock_bytes_.clear();
            return false;
        }
        primary_superblock = std::move(full_primary_superblock);
    }

    ParsedSuperblock selected = primary;
    std::uint64_t selected_offset = 0;
    std::uint64_t secondary_offset = static_cast<std::uint64_t>(primary.block_size);

    std::vector<std::byte> secondary_superblock;
    ParsedSuperblock secondary{};
    const auto secondary_read_bytes = primary.block_size > kSuperblockBytes
        ? static_cast<std::size_t>(primary.block_size)
        : kSuperblockBytes;
    const auto has_secondary = device_.Read(secondary_offset, secondary_read_bytes, secondary_superblock) &&
                               secondary_superblock.size() >= secondary_read_bytes &&
                               parse_superblock(secondary_superblock, secondary) &&
                               secondary.block_size == primary.block_size &&
                               secondary.total_blocks == primary.total_blocks &&
                               secondary.spaceman_object_id == primary.spaceman_object_id &&
                               secondary.volume_root_block == primary.volume_root_block;
    if (has_secondary && secondary.checkpoint_xid > primary.checkpoint_xid)
    {
        selected = secondary;
        selected_offset = secondary_offset;
        secondary_offset = 0;
    }

    block_size_ = selected.block_size;
    total_blocks_ = selected.total_blocks;
    if (IsCheckpointBlockIndexCacheEnabled())
    {
        (void)ResolveObjectMapCheckpointBlockIndices();
        (void)ResolveSpacemanCheckpointBlockIndices();
        (void)ResolveInodeCheckpointBlockIndices();
        (void)ResolveBtreeCheckpointBlockIndices();
        (void)ResolveReplayCheckpointBlockIndices();
    }
    checkpoint_xid_ = selected.checkpoint_xid;
    loaded_superblock_checkpoint_xid_ = selected.checkpoint_xid;
    active_superblock_offset_ = selected_offset;
    alternate_superblock_offset_ = secondary_offset;
    first_superblock_block_ = selected.first_sb_block;
    first_meta_block_ = selected.first_meta_block;
    current_superblock_map_index_ = selected.current_sb_map_index;
    next_meta_index_ = selected.next_meta_index;
    current_meta_index_ = selected.current_meta_index;
    spaceman_object_id_ = selected.spaceman_object_id;
    volume_root_block_ = selected.volume_root_block;
    active_superblock_bytes_ = selected_offset == 0
        ? primary_superblock
        : secondary_superblock;
    if (active_superblock_bytes_.size() > static_cast<std::size_t>(block_size_))
    {
        active_superblock_bytes_.resize(static_cast<std::size_t>(block_size_));
    }
    if (active_superblock_bytes_.size() < static_cast<std::size_t>(block_size_))
    {
        active_superblock_bytes_.clear();
    }
    checkpoint_anchor_block_ = ResolveObjectBlockIndex(volume_root_block_).value_or(volume_root_block_);
    next_ephemeral_extent_ = static_cast<std::uint64_t>(block_size_) * 0x100ull;
    const auto metadata_cursor_index = static_cast<std::uint64_t>(std::max(current_meta_index_, next_meta_index_));
    if (first_meta_block_ != 0 && block_size_ != 0)
    {
        if (first_meta_block_ <= (std::numeric_limits<std::uint64_t>::max() - metadata_cursor_index))
        {
            const auto metadata_cursor_block = first_meta_block_ + metadata_cursor_index;
            if (metadata_cursor_block <= (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
            {
                const auto metadata_cursor_bytes = metadata_cursor_block * static_cast<std::uint64_t>(block_size_);
                if (metadata_cursor_bytes > next_ephemeral_extent_)
                {
                    next_ephemeral_extent_ = metadata_cursor_bytes;
                }
            }
        }
    }
    working_next_ephemeral_extent_ = next_ephemeral_extent_;
    object_map_loaded_ = false;
    spaceman_loaded_ = false;
    native_write_ready_ = false;
    commit_path_ready_ = false;
    canonical_state_loaded_ = false;
    canonical_commit_ready_ = false;
    legacy_fixture_fallback_used_ = false;
    SyncCommitBlobTelemetryWithMode();
    write_device_allowed_ = false;
    recovery_required_ = false;
    recovery_reason_.clear();
    persistent_state_loaded_ = false;
    last_committed_xid_.reset();
    last_commit_blob_address_.reset();
    last_commit_blob_bytes_.reset();
    spaceman_free_bytes_.reset();
    superblock_object_block_map_.clear();
    pending_mutations_.clear();
    pending_mutation_path_key_cache_.clear();
    pending_write_object_ids_.clear();
    pending_write_mutation_index_by_object_id_.clear();
    pending_basic_info_mutation_index_by_object_id_.clear();
    ClearPendingPayloadPathKeys();
    ClearPendingPayloadObjectSummary();
    ClearPendingCloseDelaySummary();
    committed_object_map_.clear();
    InvalidateCommittedObjectMapOrderCache();
    committed_inodes_.clear();
    InvalidateCommittedInodeOrderCache();
    committed_path_index_.clear();
    last_committed_inode_changes_.clear();
    committed_directory_links_.clear();
    ClearCommittedDirectoryLinkIndexes();
    committed_btree_records_.clear();
    committed_btree_index_by_key_.clear();
    committed_btree_inode_key_by_object_id_.clear();
    committed_read_extents_.clear();
    InvalidateCommittedReadExtentSnapshotCache();
    working_read_extents_.clear();
    pending_read_extent_updates_.clear();
    prepared_payload_ranges_.clear();
    pending_written_ranges_.clear();
    pending_payload_dirty_bytes_ = 0;
    working_inodes_.clear();
    working_path_index_.clear();
    working_directory_links_.clear();
    RebuildWorkingDirectoryIndexes();
    committed_spaceman_allocations_.clear();
    committed_spaceman_free_extents_.clear();
    working_spaceman_free_extents_.clear();
    working_free_extents_sanitized_ = false;
    pending_object_map_updates_.clear();
    pending_object_map_update_index_.clear();
    pending_spaceman_allocations_.clear();
    pending_spaceman_allocation_index_.clear();
    pending_spaceman_deallocations_.clear();
    tracking_spaceman_free_extent_delta_ = false;
    pending_spaceman_untracked_free_extent_delta_ = false;
    pending_spaceman_released_existing_allocation_ = false;
    pending_btree_records_.clear();
    pending_btree_inode_record_count_by_object_.clear();
    pending_btree_file_inode_index_.clear();
    pending_btree_file_extent_index_.clear();
    pending_btree_file_extent_offsets_by_object_.clear();
    pending_btree_file_extent_record_count_by_object_.clear();
    pending_btree_directory_record_count_by_child_object_.clear();
    pending_btree_tombstone_record_count_ = 0;
    pending_btree_directory_inode_record_count_ = 0;
    pending_btree_untracked_record_count_ = 0;
    next_generated_object_id_ = 1;
    last_commit_stage_.clear();
    last_replay_stage_.clear();
    last_replay_checkpoint_candidate_present_ = false;
    last_replay_checkpoint_pending_window_ = false;
    persistent_state_path_.clear();
    container_loaded_ = true;
    return true;
}

bool MetadataStore::LoadObjectMap()
{
    if (!container_loaded_ && !LoadContainerSuperblocks())
    {
        return false;
    }

    superblock_object_block_map_.clear();
    object_map_loaded_ = false;

    const auto block_has_header = [&](const std::vector<std::byte>& block) -> bool
    {
        return block.size() >= 0x20 &&
               ReadLe64(block, 0x08) != 0 &&
               ReadLe64(block, 0x10) != 0;
    };

    // Preferred path: parse checkpoint SB-map entries and build object->block map.
    if (first_superblock_block_ != 0 && block_size_ != 0)
    {
        if (first_superblock_block_ <= (std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(current_superblock_map_index_)))
        {
            const auto sb_map_block_index = first_superblock_block_ + static_cast<std::uint64_t>(current_superblock_map_index_);
            std::vector<std::byte> sb_map_block;
            if (ReadMetadataBlock(sb_map_block_index, sb_map_block))
            {
                constexpr std::size_t kEntriesCountOffset = 0x24;
                constexpr std::size_t kEntriesBaseOffset = 0x28;
                constexpr std::size_t kEntrySize = 0x28;
                constexpr std::size_t kEntryObjectIdOffset = 0x18;
                constexpr std::size_t kEntryBlockOffset = 0x20;

                const auto entries_count = ReadLe32(sb_map_block, kEntriesCountOffset);
                for (std::uint32_t index = 0; index < entries_count; ++index)
                {
                    const auto entry_offset = kEntriesBaseOffset + static_cast<std::size_t>(index) * kEntrySize;
                    if (entry_offset > sb_map_block.size() ||
                        kEntrySize > (sb_map_block.size() - entry_offset))
                    {
                        break;
                    }

                    const auto object_id = ReadLe64(sb_map_block, entry_offset + kEntryObjectIdOffset);
                    const auto block_index = ReadLe64(sb_map_block, entry_offset + kEntryBlockOffset);
                    if (object_id == 0 || block_index == 0)
                    {
                        continue;
                    }
                    superblock_object_block_map_[object_id] = block_index;
                }
            }
        }
    }

    const auto baseline_object_map = committed_object_map_;
    const auto baseline_last_committed_xid = last_committed_xid_;
    std::unordered_map<std::uint64_t, ObjectMapUpdate> selected_object_map;
    std::optional<std::uint64_t> selected_last_committed_xid;
    std::uint64_t selected_checkpoint_xid = 0;
    bool selected_checkpoint_valid = false;

    for (const auto candidate_block : ResolveObjectMapCheckpointBlockIndices())
    {
        std::vector<std::byte> checkpoint_block;
        if (!ReadBlockByIndexDirect(candidate_block, checkpoint_block))
        {
            continue;
        }

        committed_object_map_ = baseline_object_map;
        InvalidateCommittedObjectMapOrderCache();
        last_committed_xid_ = baseline_last_committed_xid;
        if (!LoadObjectMapCheckpointBlock(candidate_block, checkpoint_block))
        {
            continue;
        }

        const auto candidate_xid = ReadLe64(checkpoint_block, 12);
        if (!selected_checkpoint_valid || candidate_xid > selected_checkpoint_xid)
        {
            selected_checkpoint_xid = candidate_xid;
            selected_object_map = committed_object_map_;
            selected_last_committed_xid = last_committed_xid_;
            selected_checkpoint_valid = true;
        }
    }

    if (selected_checkpoint_valid)
    {
        committed_object_map_ = std::move(selected_object_map);
        InvalidateCommittedObjectMapOrderCache();
        last_committed_xid_ = selected_last_committed_xid;
        object_map_loaded_ = true;
    }
    else
    {
        committed_object_map_ = baseline_object_map;
        InvalidateCommittedObjectMapOrderCache();
        last_committed_xid_ = baseline_last_committed_xid;
    }

    const auto allow_fixture_fallback = IsLegacyFixtureFallbackAllowedForCurrentContext();
    const auto volume_block_candidate = ResolveObjectBlockIndex(volume_root_block_).value_or(0);
    if (!object_map_loaded_ &&
        allow_fixture_fallback &&
        volume_block_candidate != 0)
    {
        std::vector<std::byte> volume_block;
        if (ReadMetadataBlock(volume_block_candidate, volume_block) && block_has_header(volume_block))
        {
            object_map_loaded_ = true;
            legacy_fixture_fallback_used_ = true;
        }
    }
    if (!object_map_loaded_ && allow_fixture_fallback)
    {
        // Test/image fixtures may not expose full checkpoint metadata yet.
        object_map_loaded_ = volume_root_block_ != 0;
        legacy_fixture_fallback_used_ = object_map_loaded_;
    }

    if (!object_map_loaded_)
    {
        NativeApfsVolumeProjection projection{};
        std::wstring projection_error;
        if (IsLikelyRawDevicePath(context_.device_path) &&
            NativeApfsReader::TryLoadVolumeProjection(
                device_,
                0,
                projection,
                projection_error))
        {
            committed_object_map_.clear();
            InvalidateCommittedObjectMapOrderCache();
            committed_inodes_.clear();
            InvalidateCommittedInodeOrderCache();
            committed_path_index_.clear();
            committed_directory_links_.clear();
            ClearCommittedDirectoryLinkIndexes();
            committed_btree_records_ = std::move(projection.btree_records);
            if (!RebuildCommittedBtreeIndex())
            {
                return false;
            }
            committed_read_extents_.clear();
            InvalidateCommittedReadExtentSnapshotCache();
            for (const auto& inode : projection.inodes)
            {
                committed_inodes_[inode.object_id] = inode;
                committed_path_index_[CanonicalPathKeyFromNormalizedPath(inode.full_path)] = inode.object_id;
                if (!inode.is_directory && inode.data_physical_address != 0 && inode.logical_size != 0)
                {
                    committed_object_map_[inode.object_id] = ObjectMapUpdate
                    {
                        inode.object_id,
                        inode.data_physical_address,
                        inode.logical_size,
                        projection.checkpoint_xid
                    };
                }
            }
            for (auto& [object_id, extents] : projection.read_extents_by_inode)
            {
                if (!SetCommittedReadExtents(object_id, std::move(extents)))
                {
                    committed_read_extents_.erase(object_id);
                    InvalidateCommittedReadExtentSnapshotCacheForObject(object_id);
                }
            }
            object_map_loaded_ = true;
            last_committed_xid_ = projection.checkpoint_xid;
            checkpoint_anchor_block_ = projection.root_tree_block != 0
                ? projection.root_tree_block
                : checkpoint_anchor_block_;
            volume_root_block_ = projection.root_directory_inode != 0 ? projection.root_directory_inode : volume_root_block_;
        }
        else
        {
            MarkRecoveryRequired(
                projection_error.empty()
                    ? L"CanonicalObjectMapCheckpointMissing"
                    : projection_error);
            return false;
        }
    }

    return object_map_loaded_;
}

bool MetadataStore::LoadSpacemanState()
{
    if (!container_loaded_ && !LoadContainerSuperblocks())
    {
        return false;
    }

    spaceman_loaded_ = false;
    working_free_extents_sanitized_ = false;
    const auto baseline_allocations = committed_spaceman_allocations_;
    const auto baseline_free_extents = committed_spaceman_free_extents_;
    const auto baseline_working_free_extents = working_spaceman_free_extents_;
    const auto baseline_next_ephemeral_extent = next_ephemeral_extent_;
    const auto baseline_working_next_ephemeral_extent = working_next_ephemeral_extent_;
    const auto baseline_last_committed_xid = last_committed_xid_;

    std::vector<SpacemanAllocation> selected_allocations;
    std::vector<SpacemanAllocation> selected_free_extents;
    std::vector<SpacemanAllocation> selected_working_free_extents;
    std::uint64_t selected_next_ephemeral_extent = baseline_next_ephemeral_extent;
    std::uint64_t selected_working_next_ephemeral_extent = baseline_working_next_ephemeral_extent;
    std::optional<std::uint64_t> selected_last_committed_xid;
    std::uint64_t selected_checkpoint_xid = 0;
    bool selected_checkpoint_valid = false;
    bool apple_spaceman_loaded = false;

    const auto spaceman_block = ResolveObjectBlockIndex(spaceman_object_id_).value_or(0);
    if (RequiresCanonicalNonFixtureCommitPath() && spaceman_block != 0)
    {
        std::vector<std::byte> spaceman;
        const auto read_spaceman = ReadBlockByIndexDirect(spaceman_block, spaceman);
        if (IsReadTraceEnabled())
        {
            std::wcerr << L"[MetadataStore] Spaceman load decision"
                       << L" object=" << spaceman_object_id_
                       << L" block=" << spaceman_block
                       << L" read=" << (read_spaceman ? L"true" : L"false")
                       << L" bytes=" << spaceman.size()
                       << std::endl;
        }
        if (read_spaceman &&
            LoadSpacemanCheckpointBlock(spaceman_block, spaceman))
        {
            selected_checkpoint_xid = ReadLe64(spaceman, 12);
            selected_allocations = committed_spaceman_allocations_;
            selected_free_extents = committed_spaceman_free_extents_;
            selected_working_free_extents = working_spaceman_free_extents_;
            selected_next_ephemeral_extent = next_ephemeral_extent_;
            selected_working_next_ephemeral_extent = working_next_ephemeral_extent_;
            selected_last_committed_xid = last_committed_xid_;
            selected_checkpoint_valid = true;
        }
        if (read_spaceman &&
            LoadSpacemanChunkInfoState(spaceman_block, spaceman))
        {
            apple_spaceman_loaded = true;
        }
    }

    // A production mount may have a valid Apple spaceman block and a newer
    // native checkpoint from our last transaction. Prefer the native checkpoint
    // so object-map and allocation state advance together during replay.
    for (const auto candidate_block : ResolveSpacemanCheckpointBlockIndices())
    {
        std::vector<std::byte> checkpoint_block;
        if (!ReadBlockByIndexDirect(candidate_block, checkpoint_block))
        {
            continue;
        }

        committed_spaceman_allocations_ = baseline_allocations;
        committed_spaceman_free_extents_ = baseline_free_extents;
        working_spaceman_free_extents_ = baseline_working_free_extents;
        next_ephemeral_extent_ = baseline_next_ephemeral_extent;
        working_next_ephemeral_extent_ = baseline_working_next_ephemeral_extent;
        last_committed_xid_ = baseline_last_committed_xid;

        if (!LoadSpacemanCheckpointBlock(candidate_block, checkpoint_block))
        {
            continue;
        }

        const auto candidate_xid = ReadLe64(checkpoint_block, 12);
        if (!selected_checkpoint_valid || candidate_xid > selected_checkpoint_xid)
        {
            selected_checkpoint_xid = candidate_xid;
            selected_allocations = committed_spaceman_allocations_;
            selected_free_extents = committed_spaceman_free_extents_;
            selected_working_free_extents = working_spaceman_free_extents_;
            selected_next_ephemeral_extent = next_ephemeral_extent_;
            selected_working_next_ephemeral_extent = working_next_ephemeral_extent_;
            selected_last_committed_xid = last_committed_xid_;
            selected_checkpoint_valid = true;
        }
    }

    if (selected_checkpoint_valid)
    {
        committed_spaceman_allocations_ = std::move(selected_allocations);
        committed_spaceman_free_extents_ = std::move(selected_free_extents);
        working_spaceman_free_extents_ = std::move(selected_working_free_extents);
        working_read_extents_ = committed_read_extents_;
        pending_read_extent_updates_.clear();
        prepared_payload_ranges_.clear();
        pending_written_ranges_.clear();
        pending_payload_dirty_bytes_ = 0;
        pending_payload_dirty_bytes_ = 0;
        next_ephemeral_extent_ = selected_next_ephemeral_extent;
        working_next_ephemeral_extent_ = selected_working_next_ephemeral_extent;
        last_committed_xid_ = selected_last_committed_xid;
        spaceman_loaded_ = true;
    }
    else if (apple_spaceman_loaded)
    {
        next_ephemeral_extent_ = baseline_next_ephemeral_extent;
        for (const auto& allocation : committed_spaceman_allocations_)
        {
            if (allocation.physical_address <= (std::numeric_limits<std::uint64_t>::max() - allocation.bytes))
            {
                next_ephemeral_extent_ = std::max(next_ephemeral_extent_, allocation.physical_address + allocation.bytes);
            }
        }
        working_spaceman_free_extents_ = committed_spaceman_free_extents_;
        working_read_extents_ = committed_read_extents_;
        pending_read_extent_updates_.clear();
        prepared_payload_ranges_.clear();
        pending_written_ranges_.clear();
        pending_payload_dirty_bytes_ = 0;
        working_next_ephemeral_extent_ = next_ephemeral_extent_;
        last_committed_xid_ = baseline_last_committed_xid;
        spaceman_loaded_ = true;
    }
    else
    {
        committed_spaceman_allocations_ = baseline_allocations;
        committed_spaceman_free_extents_ = baseline_free_extents;
        working_spaceman_free_extents_ = baseline_working_free_extents;
        next_ephemeral_extent_ = baseline_next_ephemeral_extent;
        working_next_ephemeral_extent_ = baseline_working_next_ephemeral_extent;
        last_committed_xid_ = baseline_last_committed_xid;
    }

    if (!spaceman_loaded_ && spaceman_block != 0)
    {
        std::vector<std::byte> spaceman;
        if (ReadBlockByIndexDirect(spaceman_block, spaceman))
        {
            if (LoadSpacemanChunkInfoState(spaceman_block, spaceman))
            {
                spaceman_loaded_ = true;
            }

            constexpr std::size_t kBmdBlockSizeOffset = 0x20;
            constexpr std::size_t kBmdTotalBlocksOffset = 0x30;
            constexpr std::size_t kBmdFreeBlocksOffset = 0x48;
            constexpr std::size_t kBmdBitmapBlockOffset = 0xB0;

            const auto bmd_block_size = ReadLe32(spaceman, kBmdBlockSizeOffset);
            const auto bmd_total_blocks = ReadLe64(spaceman, kBmdTotalBlocksOffset);
            const auto bmd_free_blocks = ReadLe64(spaceman, kBmdFreeBlocksOffset);
            const auto bmd_bitmap_block = ReadLe64(spaceman, kBmdBitmapBlockOffset);

            const auto block_size_matches = bmd_block_size == 0 || bmd_block_size == block_size_;
            const auto total_blocks_plausible = bmd_total_blocks == 0 || bmd_total_blocks == total_blocks_;
            const auto bitmap_block_plausible = bmd_bitmap_block == 0 || total_blocks_ == 0 || bmd_bitmap_block < total_blocks_;
            const auto free_blocks_plausible = total_blocks_ == 0 || bmd_free_blocks <= total_blocks_;

            if (block_size_matches && total_blocks_plausible && bitmap_block_plausible && free_blocks_plausible)
            {
                spaceman_loaded_ = true;
                if (bmd_free_blocks > 0 &&
                    bmd_free_blocks <= (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
                {
                    spaceman_free_bytes_ = bmd_free_blocks * static_cast<std::uint64_t>(block_size_);
                }
            }
        }
    }

    if (IsLikelyRawDevicePath(context_.device_path))
    {
        const auto read_extents_snapshot = committed_read_extents_;
        if (!RefreshNativeReadExtentProjection())
        {
            committed_read_extents_ = read_extents_snapshot;
            InvalidateCommittedReadExtentSnapshotCache();
        }
    }

    const auto allow_fixture_fallback = IsLegacyFixtureFallbackAllowedForCurrentContext();
    if (!spaceman_loaded_ && allow_fixture_fallback)
    {
        // Test/image fixtures may not expose full checkpoint metadata yet.
        spaceman_loaded_ = spaceman_object_id_ != 0;
        legacy_fixture_fallback_used_ = legacy_fixture_fallback_used_ || spaceman_loaded_;
    }

    if (!spaceman_loaded_)
    {
        MarkRecoveryRequired(L"CanonicalSpacemanCheckpointMissing");
        return false;
    }

    if (RequiresCanonicalNonFixtureCommitPath() &&
        !persistent_state_loaded_ &&
        !LoadPersistentState())
    {
        if (recovery_reason_.empty())
        {
            MarkRecoveryRequired(L"PersistentStateLoadFailed");
        }
        return false;
    }

    if (context_.allow_raw_physical_write &&
        IsLikelyRawDevicePath(context_.device_path) &&
        !committed_read_extents_.empty())
    {
        auto merged_allocations = committed_spaceman_allocations_;
        const auto original_allocation_count = merged_allocations.size();
        for (const auto& [_, extents] : committed_read_extents_)
        {
            if (!AddConservativeAllocationFromReadExtents(
                    extents,
                    merged_allocations,
                    block_size_))
            {
                MarkRecoveryRequired(L"RecoveredReadExtentAllocationInvalid");
                return false;
            }
        }

        if (merged_allocations.size() != original_allocation_count)
        {
            committed_spaceman_allocations_ = std::move(merged_allocations);
            if (!SubtractAllocationsFromFreeExtents(
                    committed_spaceman_free_extents_,
                    committed_spaceman_allocations_))
            {
                MarkRecoveryRequired(L"RecoveredReadExtentFreeLedgerInvalid");
                return false;
            }

            for (const auto& allocation : committed_spaceman_allocations_)
            {
                if (allocation.physical_address <= (std::numeric_limits<std::uint64_t>::max() - allocation.bytes))
                {
                    next_ephemeral_extent_ = std::max(next_ephemeral_extent_, allocation.physical_address + allocation.bytes);
                }
            }

            working_spaceman_free_extents_ = committed_spaceman_free_extents_;
            if (!SubtractAllocationsFromFreeExtents(
                    working_spaceman_free_extents_,
                    committed_spaceman_allocations_))
            {
                MarkRecoveryRequired(L"RecoveredReadExtentWorkingLedgerInvalid");
                return false;
            }
            working_next_ephemeral_extent_ = next_ephemeral_extent_;

            if (IsReadTraceEnabled())
            {
                std::wcerr << L"[MetadataStore] Added recovered read-extents to spaceman allocation ledger"
                           << L" allocationsBefore=" << original_allocation_count
                           << L" allocationsAfter=" << committed_spaceman_allocations_.size()
                           << L" freeExtents=" << committed_spaceman_free_extents_.size()
                           << std::endl;
            }
        }
    }

    if (!SanitizeWorkingFreeExtents())
    {
        MarkRecoveryRequired(L"WorkingFreeExtentSanitizeFailed");
        return false;
    }
    committed_spaceman_free_extents_ = working_spaceman_free_extents_;

    return spaceman_loaded_;
}

std::optional<std::uint64_t> MetadataStore::ResolveObjectBlockIndex(std::uint64_t object_or_block) const
{
    if (block_size_ == 0 || object_or_block == 0)
    {
        return std::nullopt;
    }

    auto block_index = object_or_block;
    if (auto mapped = superblock_object_block_map_.find(object_or_block); mapped != superblock_object_block_map_.end())
    {
        block_index = mapped->second;
    }

    if (block_index == 0)
    {
        return std::nullopt;
    }

    if (total_blocks_ != 0 && block_index >= total_blocks_)
    {
        return std::nullopt;
    }
    if (block_index > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
    {
        return std::nullopt;
    }
    return block_index;
}

bool MetadataStore::ReadBlockByIndexDirect(std::uint64_t block_index, std::vector<std::byte>& out_block) const
{
    out_block.clear();
    if (block_size_ == 0 || block_index == 0)
    {
        return false;
    }
    if (total_blocks_ != 0 && block_index >= total_blocks_)
    {
        return false;
    }
    if (block_index > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
    {
        return false;
    }

    const auto block_offset = block_index * static_cast<std::uint64_t>(block_size_);
    return device_.Read(block_offset, block_size_, out_block) &&
           out_block.size() >= static_cast<std::size_t>(block_size_);
}

bool MetadataStore::WriteBlockByIndexDirect(std::uint64_t block_index, std::vector<std::byte> block)
{
    if (block_size_ == 0 || block_index == 0)
    {
        return false;
    }
    if (total_blocks_ != 0 && block_index >= total_blocks_)
    {
        return false;
    }
    if (block_index > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
    {
        return false;
    }
    if (block.size() > static_cast<std::size_t>(block_size_))
    {
        return false;
    }

    if (block.size() < static_cast<std::size_t>(block_size_))
    {
        block.resize(static_cast<std::size_t>(block_size_), std::byte{0});
    }

    const auto block_offset = block_index * static_cast<std::uint64_t>(block_size_);
    return device_.Write(block_offset, block);
}

bool MetadataStore::WriteContiguousBlocksDirect(
    std::uint64_t first_block_index,
    const std::vector<std::byte>& blocks)
{
    if (block_size_ == 0 ||
        first_block_index == 0 ||
        blocks.empty() ||
        blocks.size() % static_cast<std::size_t>(block_size_) != 0)
    {
        return false;
    }

    const auto block_count = blocks.size() / static_cast<std::size_t>(block_size_);
    if (block_count == 0 ||
        static_cast<std::uint64_t>(block_count) > (std::numeric_limits<std::uint64_t>::max() - first_block_index))
    {
        return false;
    }

    const auto last_block_index = first_block_index + static_cast<std::uint64_t>(block_count) - 1;
    if (total_blocks_ != 0 && last_block_index >= total_blocks_)
    {
        return false;
    }
    if (first_block_index > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
    {
        return false;
    }

    const auto block_offset = first_block_index * static_cast<std::uint64_t>(block_size_);
    return device_.Write(block_offset, blocks);
}

std::vector<std::uint64_t> RotateCheckpointBlocks(
    const std::vector<std::uint64_t>& block_indices,
    std::uint64_t target_xid)
{
    if (block_indices.empty())
    {
        return {};
    }

    std::vector<std::uint64_t> rotated;
    rotated.reserve(block_indices.size());
    const auto start = static_cast<std::size_t>(
        target_xid % static_cast<std::uint64_t>(block_indices.size()));
    rotated.insert(rotated.end(), block_indices.begin() + static_cast<std::ptrdiff_t>(start), block_indices.end());
    rotated.insert(rotated.end(), block_indices.begin(), block_indices.begin() + static_cast<std::ptrdiff_t>(start));
    return rotated;
}

std::vector<std::vector<std::uint64_t>> SelectChunkedCheckpointBlockWindows(
    const std::vector<std::uint64_t>& block_indices,
    std::uint64_t target_xid,
    std::size_t required_blocks);

std::vector<std::uint64_t> SelectChunkedCheckpointBlocks(
    const std::vector<std::uint64_t>& block_indices,
    std::uint64_t target_xid,
    std::size_t required_blocks)
{
    auto windows = SelectChunkedCheckpointBlockWindows(block_indices, target_xid, required_blocks);
    if (windows.empty())
    {
        return {};
    }

    return std::move(windows.front());
}

std::vector<std::vector<std::uint64_t>> SelectChunkedCheckpointBlockWindows(
    const std::vector<std::uint64_t>& block_indices,
    std::uint64_t target_xid,
    std::size_t required_blocks)
{
    if (block_indices.empty() ||
        required_blocks == 0 ||
        required_blocks > block_indices.size())
    {
        return {};
    }

    const auto generation_count = block_indices.size() / required_blocks;
    if (generation_count == 0)
    {
        return {};
    }

    const auto preferred_generation = static_cast<std::size_t>(
        target_xid % static_cast<std::uint64_t>(generation_count));

    std::vector<std::vector<std::uint64_t>> windows;
    windows.reserve(generation_count);
    for (std::size_t offset = 0; offset < generation_count; ++offset)
    {
        const auto generation_index = (preferred_generation + offset) % generation_count;
        const auto begin = generation_index * required_blocks;
        if (begin > (block_indices.size() - required_blocks))
        {
            continue;
        }

        windows.emplace_back(
            block_indices.begin() + static_cast<std::ptrdiff_t>(begin),
            block_indices.begin() + static_cast<std::ptrdiff_t>(begin + required_blocks));
    }

    return windows;
}

bool MetadataStore::WriteChunkedCheckpointBlocks(
    const std::vector<std::uint64_t>& block_indices,
    std::uint64_t target_xid,
    const std::vector<std::byte>& data)
{
    if (block_indices.empty() || block_size_ == 0)
    {
        return false;
    }

    const auto block_size = static_cast<std::size_t>(block_size_);
    const auto block_count = (data.size() + block_size - 1) / block_size;
    if (block_count > block_indices.size())
    {
        return false;
    }
    auto selected_blocks = SelectWritableChunkedCheckpointBlocks(block_indices, target_xid, block_count);
    if (selected_blocks.empty())
    {
        return false;
    }

    if (active_checkpoint_write_batch_)
    {
        active_checkpoint_write_batch_->storage.push_back(data);
        auto& shared_full_run_storage = active_checkpoint_write_batch_->storage.back();
        return AppendSelectedChunkedCheckpointWriteSpans(
            selected_blocks,
            shared_full_run_storage,
            &shared_full_run_storage,
            active_checkpoint_write_batch_->storage,
            active_checkpoint_write_batch_->writes);
    }

    std::deque<std::vector<std::byte>> block_batch_storage;
    std::vector<BlockDevice::WriteSpan> block_batch_writes;
    if (!AppendSelectedChunkedCheckpointWriteSpans(
            selected_blocks,
            data,
            &data,
            block_batch_storage,
            block_batch_writes))
    {
        return false;
    }

    return device_.WriteBatch(block_batch_writes);
}

bool MetadataStore::WriteSelectedChunkedCheckpointBlocks(
    const std::vector<std::uint64_t>& selected_blocks,
    std::vector<std::byte> data)
{
    if (active_checkpoint_write_batch_)
    {
        active_checkpoint_write_batch_->storage.push_back(std::move(data));
        auto& shared_full_run_storage = active_checkpoint_write_batch_->storage.back();
        return WriteBorrowedSelectedChunkedCheckpointBlocks(selected_blocks, shared_full_run_storage);
    }

    return WriteBorrowedSelectedChunkedCheckpointBlocks(selected_blocks, data);
}

bool MetadataStore::WriteBorrowedSelectedChunkedCheckpointBlocks(
    const std::vector<std::uint64_t>& selected_blocks,
    const std::vector<std::byte>& data)
{
    if (active_checkpoint_write_batch_)
    {
        return AppendSelectedChunkedCheckpointWriteSpans(
            selected_blocks,
            data,
            &data,
            active_checkpoint_write_batch_->storage,
            active_checkpoint_write_batch_->writes);
    }

    std::deque<std::vector<std::byte>> block_batch_storage;
    std::vector<BlockDevice::WriteSpan> block_batch_writes;
    if (!AppendSelectedChunkedCheckpointWriteSpans(
            selected_blocks,
            data,
            &data,
            block_batch_storage,
            block_batch_writes))
    {
        return false;
    }

    return device_.WriteBatch(block_batch_writes);
}

MetadataStore::PreparedCheckpointSerializationBuffer MetadataStore::PrepareCheckpointSerializationBuffer(
    std::vector<std::byte>& reusable_buffer,
    std::vector<std::byte>& local_buffer,
    std::size_t initial_size,
    std::size_t reserve_capacity)
{
    const bool reuse_buffer =
        active_checkpoint_write_batch_ != nullptr &&
        IsCheckpointSerializationBufferReuseEnabled();
    auto& buffer = reuse_buffer ? reusable_buffer : local_buffer;
    const auto original_capacity = buffer.capacity();
    buffer.clear();
    buffer.reserve(std::max(initial_size, reserve_capacity));
    buffer.resize(initial_size, std::byte{0});
    return PreparedCheckpointSerializationBuffer{
        &buffer,
        original_capacity,
        reuse_buffer,
    };
}

void MetadataStore::ObserveCheckpointSerializationBuffer(
    const PreparedCheckpointSerializationBuffer& buffer) noexcept
{
    if (!buffer.reusable || buffer.bytes == nullptr)
    {
        return;
    }
    if (buffer.bytes->capacity() > buffer.original_capacity)
    {
        checkpoint_serialization_buffer_growth_count_.fetch_add(1, std::memory_order_relaxed);
    }
    else
    {
        checkpoint_serialization_buffer_reuse_count_.fetch_add(1, std::memory_order_relaxed);
    }
}

bool MetadataStore::WritePreparedCheckpointBlocks(
    const std::vector<std::uint64_t>& selected_blocks,
    PreparedCheckpointSerializationBuffer buffer)
{
    if (buffer.bytes == nullptr)
    {
        return false;
    }
    ObserveCheckpointSerializationBuffer(buffer);
    if (buffer.reusable)
    {
        return WriteBorrowedSelectedChunkedCheckpointBlocks(selected_blocks, *buffer.bytes);
    }
    return WriteSelectedChunkedCheckpointBlocks(selected_blocks, std::move(*buffer.bytes));
}

bool MetadataStore::AppendSelectedChunkedCheckpointWriteSpans(
    const std::vector<std::uint64_t>& selected_blocks,
    const std::vector<std::byte>& data,
    const std::vector<std::byte>* shared_full_run_storage,
    std::deque<std::vector<std::byte>>& block_batch_storage,
    std::vector<BlockDevice::WriteSpan>& block_batch_writes) const
{
    if (selected_blocks.empty() || block_size_ == 0)
    {
        return false;
    }

    const auto block_size = static_cast<std::size_t>(block_size_);
    const auto block_count = (data.size() + block_size - 1) / block_size;
    if (block_count == 0 || block_count > selected_blocks.size())
    {
        return false;
    }

    block_batch_writes.reserve(block_batch_writes.size() + block_count);

    std::size_t index = 0;
    while (index < block_count)
    {
        std::size_t run_blocks = 1;
        while (index + run_blocks < block_count &&
               selected_blocks[index + run_blocks] == selected_blocks[index] + static_cast<std::uint64_t>(run_blocks))
        {
            ++run_blocks;
        }

        const auto run_bytes = run_blocks * block_size;
        const auto begin_index = index * block_size;
        const auto end_index = std::min(data.size(), begin_index + run_bytes);
        const auto available_bytes = end_index - begin_index;

        if (selected_blocks[index] == 0 ||
            selected_blocks[index] > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
        {
            return false;
        }

        const auto block_offset = selected_blocks[index] * static_cast<std::uint64_t>(block_size_);
        std::span<const std::byte> block_span{};
        if (available_bytes == run_bytes && shared_full_run_storage != nullptr)
        {
            block_span = std::span<const std::byte>(
                shared_full_run_storage->data() + static_cast<std::ptrdiff_t>(begin_index),
                run_bytes);
        }
        else
        {
            std::vector<std::byte> blocks(run_bytes, std::byte{0});
            std::copy(
                data.begin() + static_cast<std::vector<std::byte>::difference_type>(begin_index),
                data.begin() + static_cast<std::vector<std::byte>::difference_type>(end_index),
                blocks.begin());
            block_batch_storage.push_back(std::move(blocks));
            const auto& batch_block = block_batch_storage.back();
            block_span = std::span<const std::byte>(batch_block.data(), batch_block.size());
            checkpoint_write_partial_materialization_count_.fetch_add(1, std::memory_order_relaxed);
        }
        block_batch_writes.push_back(BlockDevice::WriteSpan{
            block_offset,
            block_span,
        });

        index += run_blocks;
    }

    return true;
}

bool MetadataStore::PadCheckpointWriteDataToBlockBoundary(std::vector<std::byte>& data) const
{
    if (block_size_ == 0)
    {
        return false;
    }

    const auto block_size = static_cast<std::size_t>(block_size_);
    if (data.empty())
    {
        return false;
    }

    const auto remainder = data.size() % block_size;
    if (remainder == 0)
    {
        return true;
    }

    const auto padding = block_size - remainder;
    if (padding > data.max_size() - data.size())
    {
        return false;
    }

    data.resize(data.size() + padding, std::byte{0});
    checkpoint_write_pad_count_.fetch_add(1, std::memory_order_relaxed);
    checkpoint_write_pad_bytes_.fetch_add(static_cast<std::uint64_t>(padding), std::memory_order_relaxed);
    return true;
}

bool MetadataStore::FlushActiveCheckpointWriteBatch()
{
    if (!active_checkpoint_write_batch_)
    {
        return false;
    }
    if (active_checkpoint_write_batch_->writes.empty())
    {
        return true;
    }

    if (!device_.WriteBatch(active_checkpoint_write_batch_->writes))
    {
        return false;
    }
    checkpoint_family_batch_count_.fetch_add(1, std::memory_order_relaxed);
    checkpoint_family_batch_write_count_.fetch_add(
        static_cast<std::uint64_t>(active_checkpoint_write_batch_->writes.size()),
        std::memory_order_relaxed);
    active_checkpoint_write_batch_->writes.clear();
    active_checkpoint_write_batch_->storage.clear();
    return true;
}

std::vector<std::byte> MetadataStore::ReadOrderedCheckpointWindowBytes(
    const std::vector<std::uint64_t>& ordered_blocks,
    std::size_t required_blocks) const
{
    if (block_size_ == 0 || required_blocks == 0 || ordered_blocks.size() < required_blocks)
    {
        return {};
    }

    const auto block_size = static_cast<std::size_t>(block_size_);
    if (required_blocks > (std::numeric_limits<std::size_t>::max() / block_size))
    {
        return {};
    }

    std::vector<std::byte> combined;
    combined.reserve(required_blocks * block_size);

    std::size_t index = 0;
    while (index < required_blocks)
    {
        const auto first_block = ordered_blocks[index];
        if (first_block == 0 ||
            first_block > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
        {
            return {};
        }

        std::size_t run_blocks = 1;
        while (index + run_blocks < required_blocks &&
               first_block <= (std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(run_blocks)) &&
               ordered_blocks[index + run_blocks] == first_block + static_cast<std::uint64_t>(run_blocks))
        {
            ++run_blocks;
        }

        if (run_blocks > (std::numeric_limits<std::size_t>::max() / block_size))
        {
            return {};
        }

        if (first_block > (std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(run_blocks - 1)))
        {
            return {};
        }
        const auto last_block = first_block + static_cast<std::uint64_t>(run_blocks - 1);
        if (total_blocks_ != 0 && last_block >= total_blocks_)
        {
            return {};
        }

        const auto run_bytes = run_blocks * block_size;
        const auto block_offset = first_block * static_cast<std::uint64_t>(block_size_);
        std::vector<std::byte> run_data;
        if (!device_.Read(block_offset, run_bytes, run_data) || run_data.size() < run_bytes)
        {
            return {};
        }

        combined.insert(
            combined.end(),
            run_data.begin(),
            run_data.begin() + static_cast<std::vector<std::byte>::difference_type>(run_bytes));
        index += run_blocks;
    }

    return combined;
}

std::vector<std::byte> MetadataStore::ReadChunkedCheckpointBytes(
    const std::vector<std::uint64_t>& block_indices,
    std::uint64_t target_xid,
    const std::array<char, 12>& magic,
    std::uint32_t expected_payload_bytes) const
{
    if (block_indices.empty() || block_size_ == 0)
    {
        return {};
    }

    const auto block_size = static_cast<std::size_t>(block_size_);
    if (expected_payload_bytes > (std::numeric_limits<std::size_t>::max() - kCheckpointHeaderBytes))
    {
        return {};
    }
    const auto required_bytes = kCheckpointHeaderBytes + static_cast<std::size_t>(expected_payload_bytes);
    const auto required_blocks = (required_bytes + block_size - 1) / block_size;
    if (required_blocks == 0 || required_blocks > block_indices.size())
    {
        return {};
    }
    auto block_orders = SelectChunkedCheckpointBlockWindows(block_indices, target_xid, required_blocks);
    if (auto legacy_blocks = RotateCheckpointBlocks(block_indices, target_xid);
        !legacy_blocks.empty())
    {
        block_orders.push_back(std::move(legacy_blocks));
    }
    if (block_orders.empty())
    {
        return {};
    }

    for (const auto& ordered_blocks : block_orders)
    {
        if (ordered_blocks.size() < required_blocks)
        {
            continue;
        }

        auto combined = ReadOrderedCheckpointWindowBytes(ordered_blocks, required_blocks);
        if (combined.size() < required_blocks * block_size)
        {
            continue;
        }

        bool magic_matches = true;
        for (std::size_t magic_index = 0; magic_index < magic.size(); ++magic_index)
        {
            if (std::to_integer<unsigned char>(combined[magic_index]) != static_cast<unsigned char>(magic[magic_index]))
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        std::uint64_t persisted_xid = 0;
        if (!TryReadLe64(combined, 12, persisted_xid) || persisted_xid != target_xid)
        {
            continue;
        }

        combined.resize(required_bytes);
        return combined;
    }

    return {};
}

bool MetadataStore::ReadMetadataBlock(std::uint64_t block_index, std::vector<std::byte>& out_block) const
{
    out_block.clear();
    auto resolved = ResolveObjectBlockIndex(block_index);
    if (!resolved.has_value())
    {
        return false;
    }

    return ReadBlockByIndexDirect(resolved.value(), out_block);
}

bool MetadataStore::WriteMetadataBlock(std::uint64_t block_index, const std::vector<std::byte>& block)
{
    auto resolved = ResolveObjectBlockIndex(block_index);
    if (!resolved.has_value())
    {
        return false;
    }

    return WriteBlockByIndexDirect(resolved.value(), block);
}

bool MetadataStore::IsReservedMetadataBlock(std::uint64_t block_index) const
{
    if (block_index == 0)
    {
        return true;
    }
    if (total_blocks_ != 0 && block_index >= total_blocks_)
    {
        return true;
    }
    if (IsNativeCheckpointBandBlock(block_index))
    {
        return true;
    }

    if (block_size_ != 0)
    {
        const auto matches_offset_block = [&](std::uint64_t offset) -> bool
        {
            if (offset == 0 || (offset % static_cast<std::uint64_t>(block_size_)) != 0)
            {
                return false;
            }
            return (offset / static_cast<std::uint64_t>(block_size_)) == block_index;
        };

        if (matches_offset_block(active_superblock_offset_) ||
            matches_offset_block(alternate_superblock_offset_))
        {
            return true;
        }
    }

    if (first_superblock_block_ != 0)
    {
        if (first_superblock_block_ <= (std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(current_superblock_map_index_)) &&
            block_index == (first_superblock_block_ + static_cast<std::uint64_t>(current_superblock_map_index_)))
        {
            return true;
        }
    }
    if (first_meta_block_ != 0)
    {
        if (first_meta_block_ <= (std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(current_meta_index_)) &&
            block_index == (first_meta_block_ + static_cast<std::uint64_t>(current_meta_index_)))
        {
            return true;
        }
        if (first_meta_block_ <= (std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(next_meta_index_)) &&
            block_index == (first_meta_block_ + static_cast<std::uint64_t>(next_meta_index_)))
        {
            return true;
        }
    }

    for (const auto& entry : superblock_object_block_map_)
    {
        if (entry.second == block_index)
        {
            return true;
        }
    }

    if (auto volume_root_block = ResolveObjectBlockIndex(checkpoint_anchor_block_ != 0 ? checkpoint_anchor_block_ : volume_root_block_);
        volume_root_block.has_value() && volume_root_block.value() == block_index)
    {
        return true;
    }
    if (auto spaceman_block = ResolveObjectBlockIndex(spaceman_object_id_);
        spaceman_block.has_value() && spaceman_block.value() == block_index)
    {
        return true;
    }

    return false;
}

std::optional<std::uint64_t> MetadataStore::ResolveNativeCheckpointBandStartBlock() const
{
    if (total_blocks_ <= kNativeCheckpointBandBlocks)
    {
        return std::nullopt;
    }

    return total_blocks_ - kNativeCheckpointBandBlocks;
}

bool MetadataStore::IsNativeCheckpointBandBlock(std::uint64_t block_index) const
{
    const auto band_start = ResolveNativeCheckpointBandStartBlock();
    if (!band_start.has_value())
    {
        return false;
    }

    if (block_index >= band_start.value() && block_index < total_blocks_)
    {
        return true;
    }

    if (band_start.value() >= kNativeMetadataExtensionBlocks)
    {
        const auto metadata_extension_start = band_start.value() - kNativeMetadataExtensionBlocks;
        if (metadata_extension_start >= kNativeMinimumMetadataExtensionStartBlock &&
            block_index >= metadata_extension_start &&
            block_index < band_start.value())
        {
            return true;
        }
    }

    if (band_start.value() >= kNativeCheckpointExtensionBlocks)
    {
        const auto spaceman_extension_start = band_start.value() - kNativeCheckpointExtensionBlocks;
        if (spaceman_extension_start >= kNativeMinimumSpacemanExtensionStartBlock &&
            block_index >= spaceman_extension_start &&
            block_index < spaceman_extension_start + kNativeSpacemanExtensionBlocks)
        {
            return true;
        }
    }

    return false;
}

bool MetadataStore::AreNativeCheckpointBlocksWritable(const std::vector<std::uint64_t>& block_indices) const
{
    if (block_indices.empty() || block_size_ == 0)
    {
        return false;
    }

    const auto overlaps_linear = [](std::uint64_t physical_address, const std::vector<SpacemanAllocation>& extents)
    {
        for (const auto& extent : extents)
        {
            if (extent.bytes == 0 ||
                extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
            {
                continue;
            }

            const auto extent_end = extent.physical_address + extent.bytes;
            if (physical_address >= extent.physical_address && physical_address < extent_end)
            {
                return true;
            }
        }
        return false;
    };

    const auto scan_allocations = [&]()
    {
        checkpoint_slot_validation_fallback_scan_count_.fetch_add(1, std::memory_order_relaxed);
        for (const auto block_index : block_indices)
        {
            if (!IsNativeCheckpointBandBlock(block_index) ||
                block_index > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
            {
                return false;
            }

            const auto physical_address = block_index * static_cast<std::uint64_t>(block_size_);
            if (overlaps_linear(physical_address, committed_spaceman_allocations_) ||
                overlaps_linear(physical_address, pending_spaceman_allocations_))
            {
                return false;
            }
        }
        return true;
    };

    if (!IsCheckpointSlotAllocationIndexEnabled() ||
        !SpacemanExtentsAreSortedNonOverlapping(committed_spaceman_allocations_) ||
        pending_spaceman_allocation_index_.size() != pending_spaceman_allocations_.size())
    {
        return scan_allocations();
    }

    std::uint64_t previous_pending_end = 0;
    bool have_previous_pending = false;
    for (const auto& [physical_address, index] : pending_spaceman_allocation_index_)
    {
        if (index >= pending_spaceman_allocations_.size())
        {
            return scan_allocations();
        }

        const auto& allocation = pending_spaceman_allocations_[index];
        if (allocation.physical_address != physical_address ||
            allocation.physical_address == 0 ||
            allocation.bytes == 0 ||
            allocation.physical_address > (std::numeric_limits<std::uint64_t>::max() - allocation.bytes))
        {
            return scan_allocations();
        }

        const auto allocation_end = allocation.physical_address + allocation.bytes;
        if (have_previous_pending && allocation.physical_address < previous_pending_end)
        {
            return scan_allocations();
        }
        previous_pending_end = allocation_end;
        have_previous_pending = true;
    }

    const auto sorted_extents_contain = [](const std::vector<SpacemanAllocation>& extents, std::uint64_t physical_address)
    {
        auto extent_it = std::upper_bound(
            extents.begin(),
            extents.end(),
            physical_address,
            [](std::uint64_t address, const SpacemanAllocation& extent)
            {
                return address < extent.physical_address;
            });
        if (extent_it == extents.begin())
        {
            return false;
        }

        --extent_it;
        return physical_address < (extent_it->physical_address + extent_it->bytes);
    };
    const auto pending_index_contains = [&](std::uint64_t physical_address)
    {
        auto allocation_it = pending_spaceman_allocation_index_.upper_bound(physical_address);
        if (allocation_it == pending_spaceman_allocation_index_.begin())
        {
            return false;
        }

        --allocation_it;
        const auto& allocation = pending_spaceman_allocations_[allocation_it->second];
        return physical_address < (allocation.physical_address + allocation.bytes);
    };

    checkpoint_slot_validation_indexed_count_.fetch_add(1, std::memory_order_relaxed);
    for (const auto block_index : block_indices)
    {
        if (!IsNativeCheckpointBandBlock(block_index) ||
            block_index > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
        {
            return false;
        }

        const auto physical_address = block_index * static_cast<std::uint64_t>(block_size_);
        if (sorted_extents_contain(committed_spaceman_allocations_, physical_address) ||
            pending_index_contains(physical_address))
        {
            return false;
        }
    }

    return true;
}

std::vector<std::uint64_t> MetadataStore::SelectWritableChunkedCheckpointBlocks(
    const std::vector<std::uint64_t>& block_indices,
    std::uint64_t target_xid,
    std::size_t required_blocks) const
{
    chunked_checkpoint_selection_count_.fetch_add(1, std::memory_order_relaxed);
    for (auto candidate_blocks : SelectChunkedCheckpointBlockWindows(block_indices, target_xid, required_blocks))
    {
        if (AreNativeCheckpointBlocksWritable(candidate_blocks))
        {
            return candidate_blocks;
        }
    }

    return {};
}

std::optional<std::uint64_t> MetadataStore::FindCheckpointCompanionBlock(
    std::uint64_t primary_block,
    const std::vector<std::uint64_t>& disallowed_blocks) const
{
    if (primary_block == 0)
    {
        return std::nullopt;
    }

    const auto is_disallowed = [&](std::uint64_t candidate) -> bool
    {
        if (candidate == 0 || candidate == primary_block)
        {
            return true;
        }
        if (IsReservedMetadataBlock(candidate))
        {
            return true;
        }
        return std::find(disallowed_blocks.begin(), disallowed_blocks.end(), candidate) != disallowed_blocks.end();
    };

    for (std::uint64_t delta = 1; delta <= 64; ++delta)
    {
        if (primary_block > (std::numeric_limits<std::uint64_t>::max() - delta))
        {
            break;
        }

        const auto candidate = primary_block + delta;
        if (is_disallowed(candidate))
        {
            continue;
        }
        return candidate;
    }

    return std::nullopt;
}

std::vector<std::uint64_t> MetadataStore::ResolveObjectMapCheckpointBlockIndices() const
{
    const auto cache_enabled = IsCheckpointBlockIndexCacheEnabled();
    if (cache_enabled && object_map_checkpoint_block_indices_cache_total_blocks_ == total_blocks_)
    {
        checkpoint_block_index_cache_hit_count_.fetch_add(1, std::memory_order_relaxed);
        return object_map_checkpoint_block_indices_cache_;
    }
    const auto finish = [&](std::vector<std::uint64_t> built)
    {
        if (cache_enabled)
        {
            object_map_checkpoint_block_indices_cache_ = built;
            object_map_checkpoint_block_indices_cache_total_blocks_ = total_blocks_;
            checkpoint_block_index_cache_build_count_.fetch_add(1, std::memory_order_relaxed);
        }
        else
        {
            checkpoint_block_index_cache_bypass_build_count_.fetch_add(1, std::memory_order_relaxed);
        }
        return built;
    };
    std::vector<std::uint64_t> candidates;
    const auto band_start = ResolveNativeCheckpointBandStartBlock();
    if (!band_start.has_value() ||
        band_start.value() > (std::numeric_limits<std::uint64_t>::max() - kNativeObjectMapCheckpointOffset))
    {
        return finish(std::move(candidates));
    }

    const auto append_range = [&](std::uint64_t offset, std::uint64_t count)
    {
        if (count == 0 ||
            band_start.value() > (std::numeric_limits<std::uint64_t>::max() - offset))
        {
            return;
        }

        const auto range_start = band_start.value() + offset;
        for (std::uint64_t index = 0; index < count; ++index)
        {
            if (range_start > (std::numeric_limits<std::uint64_t>::max() - index))
            {
                break;
            }

            const auto candidate = range_start + index;
            if (IsNativeCheckpointBandBlock(candidate))
            {
                candidates.push_back(candidate);
            }
        }
    };

    append_range(
        kNativeObjectMapCheckpointOffset,
        kNativeSpacemanCheckpointOffset - kNativeObjectMapCheckpointOffset);
    append_range(
        kNativeOverflowCheckpointOffset,
        kNativeObjectMapOverflowBlocks);
    return finish(std::move(candidates));
}

std::vector<std::uint64_t> MetadataStore::ResolveSpacemanCheckpointBlockIndices() const
{
    const auto cache_enabled = IsCheckpointBlockIndexCacheEnabled();
    if (cache_enabled && spaceman_checkpoint_block_indices_cache_total_blocks_ == total_blocks_)
    {
        checkpoint_block_index_cache_hit_count_.fetch_add(1, std::memory_order_relaxed);
        return spaceman_checkpoint_block_indices_cache_;
    }
    const auto finish = [&](std::vector<std::uint64_t> built)
    {
        if (cache_enabled)
        {
            spaceman_checkpoint_block_indices_cache_ = built;
            spaceman_checkpoint_block_indices_cache_total_blocks_ = total_blocks_;
            checkpoint_block_index_cache_build_count_.fetch_add(1, std::memory_order_relaxed);
        }
        else
        {
            checkpoint_block_index_cache_bypass_build_count_.fetch_add(1, std::memory_order_relaxed);
        }
        return built;
    };
    std::vector<std::uint64_t> candidates;
    const auto band_start = ResolveNativeCheckpointBandStartBlock();
    if (!band_start.has_value() ||
        band_start.value() > (std::numeric_limits<std::uint64_t>::max() - kNativeSpacemanCheckpointOffset))
    {
        return finish(std::move(candidates));
    }

    const auto primary = band_start.value() + kNativeSpacemanCheckpointOffset;
    for (std::uint64_t index = 0; index < (kNativeInodeCheckpointOffset - kNativeSpacemanCheckpointOffset); ++index)
    {
        const auto candidate = primary + index;
        if (IsNativeCheckpointBandBlock(candidate))
        {
            candidates.push_back(candidate);
        }
    }

    if (band_start.value() >= kNativeCheckpointExtensionBlocks)
    {
        const auto extension_start = band_start.value() - kNativeCheckpointExtensionBlocks;
        if (extension_start >= kNativeMinimumSpacemanExtensionStartBlock)
        {
            const auto range_start = extension_start + kNativeSpacemanExtensionOffset;
            for (std::uint64_t index = 0; index < kNativeSpacemanExtensionBlocks; ++index)
            {
                if (range_start > (std::numeric_limits<std::uint64_t>::max() - index))
                {
                    break;
                }

                const auto candidate = range_start + index;
                if (candidate >= band_start.value())
                {
                    break;
                }

                if (IsNativeCheckpointBandBlock(candidate))
                {
                    candidates.push_back(candidate);
                }
            }
        }
    }
    return finish(std::move(candidates));
}

std::vector<std::uint64_t> MetadataStore::ResolveInodeCheckpointBlockIndices() const
{
    const auto cache_enabled = IsCheckpointBlockIndexCacheEnabled();
    if (cache_enabled && inode_checkpoint_block_indices_cache_total_blocks_ == total_blocks_)
    {
        checkpoint_block_index_cache_hit_count_.fetch_add(1, std::memory_order_relaxed);
        return inode_checkpoint_block_indices_cache_;
    }
    const auto finish = [&](std::vector<std::uint64_t> built)
    {
        if (cache_enabled)
        {
            inode_checkpoint_block_indices_cache_ = built;
            inode_checkpoint_block_indices_cache_total_blocks_ = total_blocks_;
            checkpoint_block_index_cache_build_count_.fetch_add(1, std::memory_order_relaxed);
        }
        else
        {
            checkpoint_block_index_cache_bypass_build_count_.fetch_add(1, std::memory_order_relaxed);
        }
        return built;
    };
    std::vector<std::uint64_t> candidates;
    const auto band_start = ResolveNativeCheckpointBandStartBlock();
    if (!band_start.has_value() ||
        band_start.value() > (std::numeric_limits<std::uint64_t>::max() - kNativeInodeCheckpointOffset))
    {
        return finish(std::move(candidates));
    }

    const auto append_range = [&](std::uint64_t offset, std::uint64_t count)
    {
        if (count == 0 ||
            band_start.value() > (std::numeric_limits<std::uint64_t>::max() - offset))
        {
            return;
        }

        const auto range_start = band_start.value() + offset;
        for (std::uint64_t index = 0; index < count; ++index)
        {
            if (range_start > (std::numeric_limits<std::uint64_t>::max() - index))
            {
                break;
            }

            const auto candidate = range_start + index;
            if (IsNativeCheckpointBandBlock(candidate))
            {
                candidates.push_back(candidate);
            }
        }
    };

    append_range(
        kNativeInodeCheckpointOffset,
        kNativeBtreeCheckpointOffset - kNativeInodeCheckpointOffset);
    append_range(
        kNativeInodeOverflowOffset,
        kNativeCheckpointBandBlocks - kNativeInodeOverflowOffset);

    if (band_start.value() >= kNativeMetadataExtensionBlocks)
    {
        const auto extension_start = band_start.value() - kNativeMetadataExtensionBlocks;
        if (extension_start >= kNativeMinimumMetadataExtensionStartBlock)
        {
            const auto range_start = extension_start + kNativeInodeExtensionOffset;
            for (std::uint64_t index = 0; index < kNativeInodeExtensionBlocks; ++index)
            {
                if (range_start > (std::numeric_limits<std::uint64_t>::max() - index))
                {
                    break;
                }

                const auto candidate = range_start + index;
                if (candidate >= band_start.value())
                {
                    break;
                }

                if (IsNativeCheckpointBandBlock(candidate))
                {
                    candidates.push_back(candidate);
                }
            }
        }
    }

    return finish(std::move(candidates));
}

std::vector<std::uint64_t> ResolveLegacyContiguousCheckpointBlocks(
    std::optional<std::uint64_t> band_start,
    std::uint64_t offset,
    std::uint64_t count,
    const std::function<bool(std::uint64_t)>& is_allowed)
{
    std::vector<std::uint64_t> candidates;
    if (!band_start.has_value() ||
        count == 0 ||
        band_start.value() > (std::numeric_limits<std::uint64_t>::max() - offset))
    {
        return candidates;
    }

    const auto range_start = band_start.value() + offset;
    for (std::uint64_t index = 0; index < count; ++index)
    {
        if (range_start > (std::numeric_limits<std::uint64_t>::max() - index))
        {
            break;
        }

        const auto candidate = range_start + index;
        if (is_allowed(candidate))
        {
            candidates.push_back(candidate);
        }
    }

    return candidates;
}

std::vector<std::uint64_t> MetadataStore::ResolveBtreeCheckpointBlockIndices() const
{
    const auto cache_enabled = IsCheckpointBlockIndexCacheEnabled();
    if (cache_enabled && btree_checkpoint_block_indices_cache_total_blocks_ == total_blocks_)
    {
        checkpoint_block_index_cache_hit_count_.fetch_add(1, std::memory_order_relaxed);
        return btree_checkpoint_block_indices_cache_;
    }
    const auto finish = [&](std::vector<std::uint64_t> built)
    {
        if (cache_enabled)
        {
            btree_checkpoint_block_indices_cache_ = built;
            btree_checkpoint_block_indices_cache_total_blocks_ = total_blocks_;
            checkpoint_block_index_cache_build_count_.fetch_add(1, std::memory_order_relaxed);
        }
        else
        {
            checkpoint_block_index_cache_bypass_build_count_.fetch_add(1, std::memory_order_relaxed);
        }
        return built;
    };
    std::vector<std::uint64_t> candidates;
    const auto band_start = ResolveNativeCheckpointBandStartBlock();
    if (!band_start.has_value() ||
        band_start.value() > (std::numeric_limits<std::uint64_t>::max() - kNativeBtreeCheckpointOffset))
    {
        return finish(std::move(candidates));
    }

    const auto primary = band_start.value() + kNativeBtreeCheckpointOffset;
    for (std::uint64_t index = 0; index < (kNativeReplayCheckpointOffset - kNativeBtreeCheckpointOffset); ++index)
    {
        const auto candidate = primary + index;
        if (IsNativeCheckpointBandBlock(candidate))
        {
            candidates.push_back(candidate);
        }
    }

    if (band_start.value() >= kNativeMetadataExtensionBlocks)
    {
        const auto extension_start = band_start.value() - kNativeMetadataExtensionBlocks;
        if (extension_start >= kNativeMinimumMetadataExtensionStartBlock)
        {
            for (std::uint64_t index = 0; index < kNativeBtreeExtensionBlocks; ++index)
            {
                if (extension_start > (std::numeric_limits<std::uint64_t>::max() - index))
                {
                    break;
                }

                const auto candidate = extension_start + kNativeBtreeExtensionOffset + index;
                if (candidate >= band_start.value())
                {
                    break;
                }

                if (IsNativeCheckpointBandBlock(candidate))
                {
                    candidates.push_back(candidate);
                }
            }
        }
    }

    return finish(std::move(candidates));
}

std::vector<std::uint64_t> MetadataStore::ResolveReplayCheckpointBlockIndices() const
{
    const auto cache_enabled = IsCheckpointBlockIndexCacheEnabled();
    if (cache_enabled && replay_checkpoint_block_indices_cache_total_blocks_ == total_blocks_)
    {
        checkpoint_block_index_cache_hit_count_.fetch_add(1, std::memory_order_relaxed);
        return replay_checkpoint_block_indices_cache_;
    }
    const auto finish = [&](std::vector<std::uint64_t> built)
    {
        if (cache_enabled)
        {
            replay_checkpoint_block_indices_cache_ = built;
            replay_checkpoint_block_indices_cache_total_blocks_ = total_blocks_;
            checkpoint_block_index_cache_build_count_.fetch_add(1, std::memory_order_relaxed);
        }
        else
        {
            checkpoint_block_index_cache_bypass_build_count_.fetch_add(1, std::memory_order_relaxed);
        }
        return built;
    };
    std::vector<std::uint64_t> candidates;
    const auto band_start = ResolveNativeCheckpointBandStartBlock();
    if (!band_start.has_value() ||
        band_start.value() > (std::numeric_limits<std::uint64_t>::max() - kNativeReplayCheckpointOffset))
    {
        return finish(std::move(candidates));
    }

    const auto primary = band_start.value() + kNativeReplayCheckpointOffset;
    for (std::uint64_t index = 0; index < 2; ++index)
    {
        const auto candidate = primary + index;
        if (IsNativeCheckpointBandBlock(candidate))
        {
            candidates.push_back(candidate);
        }
    }

    return finish(std::move(candidates));
}

bool MetadataStore::LoadObjectMapCheckpointBlock(std::uint64_t block_index, const std::vector<std::byte>& block)
{
    (void)block_index;
    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'O', 'M', 'A', 'P', '3', '\0'
    };
    if (block.size() < kCheckpointHeaderBytes)
    {
        return false;
    }
    auto payload_block = block;
    const auto persisted_xid_hint = ReadLe64(block, 12);
    const auto persisted_payload_bytes = ReadLe32(block, 24);
    if (persisted_payload_bytes > (payload_block.size() - kCheckpointHeaderBytes))
    {
        const auto checkpoint_blocks = ResolveObjectMapCheckpointBlockIndices();
        payload_block = ReadChunkedCheckpointBytes(
            checkpoint_blocks,
            persisted_xid_hint,
            kMagic,
            persisted_payload_bytes);
        if (payload_block.empty())
        {
            auto legacy_blocks = ResolveLegacyContiguousCheckpointBlocks(
                ResolveNativeCheckpointBandStartBlock(),
                kNativeObjectMapCheckpointOffset,
                kNativeSpacemanCheckpointOffset - kNativeObjectMapCheckpointOffset,
                [this](std::uint64_t candidate)
                {
                    return IsNativeCheckpointBandBlock(candidate);
                });
            payload_block = ReadChunkedCheckpointBytes(
                legacy_blocks,
                persisted_xid_hint,
                kMagic,
                persisted_payload_bytes);
            if (payload_block.empty())
            {
                return false;
            }
        }
    }

    ApfsObjectMapStore object_map_store;
    std::vector<ApfsObjectMapEntry> parsed_entries;
    std::uint64_t persisted_xid = 0;
    if (!object_map_store.TryParseCheckpointV3(payload_block, parsed_entries, persisted_xid))
    {
        return false;
    }
    if (!CanLoadNativeCheckpointXid(persisted_xid))
    {
        return false;
    }

    committed_object_map_.clear();
    InvalidateCommittedObjectMapOrderCache();
    committed_object_map_.reserve(parsed_entries.size());
    for (const auto& entry : parsed_entries)
    {
        ObjectMapUpdate update
        {
            entry.object_id,
            entry.physical_address,
            entry.logical_size,
            entry.xid
        };
        if (HasPhysicalObjectMapping(update))
        {
            committed_object_map_.emplace(entry.object_id, update);
        }
    }

    if (persisted_xid > 0)
    {
        last_committed_xid_ = std::max(last_committed_xid_.value_or(0), persisted_xid);
    }
    InvalidateCommittedObjectMapOrderCache();
    return true;
}

bool MetadataStore::LoadSpacemanCheckpointBlock(std::uint64_t block_index, const std::vector<std::byte>& block)
{
    (void)block_index;
    working_free_extents_sanitized_ = false;
    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'P', 'M', '3', '\0', '\0'
    };
    if (block.size() < kCheckpointHeaderBytes)
    {
        return false;
    }

    auto payload_block = block;
    const auto persisted_xid_hint = ReadLe64(block, 12);
    const auto allocation_count = ReadLe32(block, 20);
    const auto free_extent_count = ReadLe32(block, 24);
    const auto total_records = static_cast<std::uint64_t>(allocation_count) + static_cast<std::uint64_t>(free_extent_count);
    if (total_records > (std::numeric_limits<std::uint32_t>::max() / 16u))
    {
        return false;
    }
    const auto persisted_payload_bytes = static_cast<std::uint32_t>(total_records * 16u);
    if (persisted_payload_bytes > (payload_block.size() - kCheckpointHeaderBytes))
    {
        const auto checkpoint_blocks = ResolveSpacemanCheckpointBlockIndices();
        payload_block = ReadChunkedCheckpointBytes(
            checkpoint_blocks,
            persisted_xid_hint,
            kMagic,
            persisted_payload_bytes);
        if (payload_block.empty())
        {
            return false;
        }
    }

    ApfsSpacemanStore spaceman_store;
    std::vector<ApfsExtent> parsed_allocations;
    std::vector<ApfsExtent> parsed_free_extents;
    std::uint64_t persisted_xid = 0;
    if (!spaceman_store.TryParseCheckpointV3(
            payload_block,
            parsed_allocations,
            parsed_free_extents,
            persisted_xid))
    {
        return false;
    }
    if (!CanLoadNativeCheckpointXid(persisted_xid))
    {
        return false;
    }

    committed_spaceman_allocations_.clear();
    committed_spaceman_allocations_.reserve(parsed_allocations.size());
    for (const auto& extent : parsed_allocations)
    {
        const auto aligned_bytes = AlignExtentBytes(extent.bytes);
        if (aligned_bytes == 0 || aligned_bytes != extent.bytes)
        {
            return false;
        }
        committed_spaceman_allocations_.push_back(
            SpacemanAllocation
            {
                extent.physical_address,
                aligned_bytes
            });
    }

    committed_spaceman_free_extents_.clear();
    committed_spaceman_free_extents_.reserve(parsed_free_extents.size());
    for (const auto& extent : parsed_free_extents)
    {
        const auto aligned_bytes = AlignExtentBytes(extent.bytes);
        if (aligned_bytes == 0 || aligned_bytes != extent.bytes)
        {
            return false;
        }
        committed_spaceman_free_extents_.push_back(
            SpacemanAllocation
            {
                extent.physical_address,
                aligned_bytes
            });
    }

    if (!NormalizeSpacemanExtents(committed_spaceman_allocations_) ||
        !NormalizeSpacemanExtents(committed_spaceman_free_extents_))
    {
        return false;
    }

    for (const auto& allocation : committed_spaceman_allocations_)
    {
        const auto allocation_end = allocation.physical_address + allocation.bytes;
        if (allocation_end > next_ephemeral_extent_)
        {
            next_ephemeral_extent_ = allocation_end;
        }
    }
    working_spaceman_free_extents_ = committed_spaceman_free_extents_;
    working_read_extents_ = committed_read_extents_;
    pending_read_extent_updates_.clear();
    prepared_payload_ranges_.clear();
    pending_written_ranges_.clear();
    pending_payload_dirty_bytes_ = 0;
    working_next_ephemeral_extent_ = next_ephemeral_extent_;

    if (persisted_xid > 0)
    {
        last_committed_xid_ = std::max(last_committed_xid_.value_or(0), persisted_xid);
    }

    return true;
}

bool MetadataStore::LoadSpacemanChunkInfoState(std::uint64_t spaceman_block_index, const std::vector<std::byte>& block)
{
    (void)spaceman_block_index;
    working_free_extents_sanitized_ = false;
    if (!container_loaded_ || block_size_ == 0 || total_blocks_ == 0 || block.size() < 0x60)
    {
        return false;
    }

    constexpr std::size_t kObjectTypeOffset = 0x18;
    constexpr std::size_t kBlockSizeOffset = 0x20;
    constexpr std::size_t kBlocksPerChunkOffset = 0x24;
    constexpr std::size_t kChunksPerCibOffset = 0x28;
    constexpr std::size_t kCibsPerCabOffset = 0x2C;
    constexpr std::size_t kMainDeviceOffset = 0x30;
    constexpr std::size_t kDeviceBlockCountOffset = 0x00;
    constexpr std::size_t kDeviceChunkCountOffset = 0x08;
    constexpr std::size_t kDeviceCibCountOffset = 0x10;
    constexpr std::size_t kDeviceCabCountOffset = 0x14;
    constexpr std::size_t kDeviceFreeCountOffset = 0x18;
    constexpr std::size_t kDeviceAddrOffsetOffset = 0x20;
    constexpr std::size_t kCibHeaderBytes = 0x28;
    constexpr std::size_t kCabHeaderBytes = 0x28;
    constexpr std::size_t kChunkInfoBytes = 0x20;
    constexpr std::size_t kChunkInfoXidOffset = 0x00;
    constexpr std::size_t kChunkInfoAddressOffset = 0x08;
    constexpr std::size_t kChunkInfoBlockCountOffset = 0x10;
    constexpr std::size_t kChunkInfoFreeCountOffset = 0x14;
    constexpr std::size_t kChunkInfoBitmapAddressOffset = 0x18;
    constexpr std::uint32_t kObjectTypeMask = 0x0000FFFF;
    constexpr std::uint32_t kObjectTypeSpaceman = 0x00000005;
    constexpr std::uint32_t kObjectTypeChunkInfoAddress = 0x00000006;
    constexpr std::uint32_t kObjectTypeChunkInfo = 0x00000007;

    if ((ReadLe32(block, kObjectTypeOffset) & kObjectTypeMask) != kObjectTypeSpaceman)
    {
        if (IsReadTraceEnabled())
        {
            std::wcerr << L"[MetadataStore] Spaceman chunk-info parse failed"
                       << L" reason=SpacemanHeader"
                       << L" type=" << (ReadLe32(block, kObjectTypeOffset) & kObjectTypeMask)
                       << std::endl;
        }
        return false;
    }

    const auto sm_block_size = ReadLe32(block, kBlockSizeOffset);
    const auto blocks_per_chunk = ReadLe32(block, kBlocksPerChunkOffset);
    const auto chunks_per_cib = ReadLe32(block, kChunksPerCibOffset);
    const auto cibs_per_cab = ReadLe32(block, kCibsPerCabOffset);
    const auto device_block_count = ReadLe64(block, kMainDeviceOffset + kDeviceBlockCountOffset);
    const auto device_chunk_count = ReadLe64(block, kMainDeviceOffset + kDeviceChunkCountOffset);
    const auto device_cib_count = ReadLe32(block, kMainDeviceOffset + kDeviceCibCountOffset);
    const auto device_cab_count = ReadLe32(block, kMainDeviceOffset + kDeviceCabCountOffset);
    const auto device_free_count = ReadLe64(block, kMainDeviceOffset + kDeviceFreeCountOffset);
    const auto device_addr_offset = ReadLe32(block, kMainDeviceOffset + kDeviceAddrOffsetOffset);

    if (sm_block_size != block_size_ ||
        blocks_per_chunk == 0 ||
        chunks_per_cib == 0 ||
        cibs_per_cab == 0 ||
        device_chunk_count == 0 ||
        device_cib_count == 0 ||
        device_cib_count > 4096 ||
        device_cab_count > 4096 ||
        device_chunk_count > static_cast<std::uint64_t>(device_cib_count) * static_cast<std::uint64_t>(chunks_per_cib) ||
        device_block_count == 0 ||
        device_block_count > total_blocks_ ||
        device_free_count > device_block_count)
    {
        if (IsReadTraceEnabled())
        {
            std::wcerr << L"[MetadataStore] Spaceman chunk-info parse failed"
                       << L" reason=DeviceSummary"
                       << L" smBlockSize=" << sm_block_size
                       << L" blocksPerChunk=" << blocks_per_chunk
                       << L" chunksPerCib=" << chunks_per_cib
                       << L" cibsPerCab=" << cibs_per_cab
                       << L" blockCount=" << device_block_count
                       << L" chunkCount=" << device_chunk_count
                       << L" cibCount=" << device_cib_count
                       << L" cabCount=" << device_cab_count
                       << L" freeCount=" << device_free_count
                       << L" addrOffset=" << device_addr_offset
                       << std::endl;
        }
        return false;
    }
    if (blocks_per_chunk > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
    {
        return false;
    }
    if (static_cast<std::uint64_t>(blocks_per_chunk) > (std::numeric_limits<std::size_t>::max() * 8ull))
    {
        return false;
    }

    std::vector<SpacemanAllocation> parsed_allocations;
    std::vector<SpacemanAllocation> parsed_free_extents;
    parsed_allocations.reserve(static_cast<std::size_t>(std::min<std::uint64_t>(device_chunk_count, 4096)));
    parsed_free_extents.reserve(static_cast<std::size_t>(std::min<std::uint64_t>(device_chunk_count, 4096)));

    const auto push_extent = [](std::vector<SpacemanAllocation>& extents, std::uint64_t physical_address, std::uint64_t bytes) -> bool
    {
        if (bytes == 0)
        {
            return true;
        }
        if (physical_address > (std::numeric_limits<std::uint64_t>::max() - bytes))
        {
            return false;
        }
        if (!extents.empty())
        {
            auto& previous = extents.back();
            if (previous.physical_address <= (std::numeric_limits<std::uint64_t>::max() - previous.bytes) &&
                previous.physical_address + previous.bytes == physical_address)
            {
                if (previous.bytes > (std::numeric_limits<std::uint64_t>::max() - bytes))
                {
                    return false;
                }
                previous.bytes += bytes;
                return true;
            }
        }
        extents.push_back(SpacemanAllocation{ physical_address, bytes });
        return true;
    };

    const auto record_run = [&](std::uint64_t chunk_start_block, std::uint64_t start_in_chunk, std::uint64_t block_count, bool allocated) -> bool
    {
        if (block_count == 0)
        {
            return true;
        }
        if (start_in_chunk > static_cast<std::uint64_t>(blocks_per_chunk) ||
            block_count > (static_cast<std::uint64_t>(blocks_per_chunk) - start_in_chunk) ||
            chunk_start_block > (std::numeric_limits<std::uint64_t>::max() - start_in_chunk))
        {
            return false;
        }
        const auto start_block = chunk_start_block + start_in_chunk;
        if (start_block > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)) ||
            block_count > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
        {
            return false;
        }
        const auto physical_address = start_block * static_cast<std::uint64_t>(block_size_);
        const auto bytes = block_count * static_cast<std::uint64_t>(block_size_);
        if (physical_address == 0 && bytes > 0)
        {
            if (bytes == static_cast<std::uint64_t>(block_size_))
            {
                return true;
            }
            return push_extent(
                allocated ? parsed_allocations : parsed_free_extents,
                static_cast<std::uint64_t>(block_size_),
                bytes - static_cast<std::uint64_t>(block_size_));
        }
        return push_extent(allocated ? parsed_allocations : parsed_free_extents, physical_address, bytes);
    };

    std::uint64_t parsed_chunk_count = 0;
    std::uint64_t parsed_free_blocks = 0;
    std::vector<std::uint64_t> cib_block_indices;
    cib_block_indices.reserve(device_cib_count);

    const auto read_address_from_spaceman = [&](std::uint32_t index, std::uint64_t& out_block_index) -> bool
    {
        const auto address_offset = static_cast<std::size_t>(device_addr_offset) +
            static_cast<std::size_t>(index) * sizeof(std::uint64_t);
        if (address_offset > block.size() || sizeof(std::uint64_t) > (block.size() - address_offset))
        {
            return false;
        }

        out_block_index = ReadLe64(block, address_offset);
        return out_block_index != 0 && out_block_index < total_blocks_;
    };

    if (device_cab_count == 0)
    {
        for (std::uint32_t cib_index = 0; cib_index < device_cib_count; ++cib_index)
        {
            std::uint64_t cib_block_index = 0;
            if (!read_address_from_spaceman(cib_index, cib_block_index))
            {
                if (IsReadTraceEnabled())
                {
                    std::wcerr << L"[MetadataStore] Spaceman chunk-info parse failed"
                               << L" reason=CibBlockAddress"
                               << L" cibIndex=" << cib_index
                               << L" cibBlock=" << cib_block_index
                               << std::endl;
                }
                return false;
            }
            cib_block_indices.push_back(cib_block_index);
        }
    }
    else
    {
        for (std::uint32_t cab_index = 0; cab_index < device_cab_count; ++cab_index)
        {
            std::uint64_t cab_block_index = 0;
            if (!read_address_from_spaceman(cab_index, cab_block_index))
            {
                if (IsReadTraceEnabled())
                {
                    std::wcerr << L"[MetadataStore] Spaceman chunk-info parse failed"
                               << L" reason=CabBlockAddress"
                               << L" cabIndex=" << cab_index
                               << L" cabBlock=" << cab_block_index
                               << std::endl;
                }
                return false;
            }

            std::vector<std::byte> cab_block;
            if (!ReadBlockByIndexDirect(cab_block_index, cab_block) ||
                cab_block.size() < kCabHeaderBytes)
            {
                return false;
            }

            const auto cab_type = ReadLe32(cab_block, 0x18) & kObjectTypeMask;
            const auto stored_cab_index = ReadLe32(cab_block, 0x20);
            const auto cab_cib_count = ReadLe32(cab_block, 0x24);
            if (cab_type != kObjectTypeChunkInfoAddress ||
                stored_cab_index != cab_index ||
                cab_cib_count == 0 ||
                cab_cib_count > cibs_per_cab ||
                kCabHeaderBytes + (static_cast<std::size_t>(cab_cib_count) * sizeof(std::uint64_t)) > cab_block.size())
            {
                if (IsReadTraceEnabled())
                {
                    std::wcerr << L"[MetadataStore] Spaceman chunk-info parse failed"
                               << L" reason=CabHeader"
                               << L" cabIndex=" << cab_index
                               << L" cabType=" << cab_type
                               << L" storedIndex=" << stored_cab_index
                               << L" cibCount=" << cab_cib_count
                               << std::endl;
                }
                return false;
            }

            for (std::uint32_t index = 0; index < cab_cib_count; ++index)
            {
                const auto entry_offset = kCabHeaderBytes + static_cast<std::size_t>(index) * sizeof(std::uint64_t);
                const auto cib_block_index = ReadLe64(cab_block, entry_offset);
                if (cib_block_index == 0 || cib_block_index >= total_blocks_)
                {
                    if (IsReadTraceEnabled())
                    {
                        std::wcerr << L"[MetadataStore] Spaceman chunk-info parse failed"
                                   << L" reason=CabCibBlockAddress"
                                   << L" cabIndex=" << cab_index
                                   << L" cibIndex=" << index
                                   << L" cibBlock=" << cib_block_index
                                   << std::endl;
                    }
                    return false;
                }
                cib_block_indices.push_back(cib_block_index);
            }
        }

        if (cib_block_indices.size() != device_cib_count)
        {
            if (IsReadTraceEnabled())
            {
                std::wcerr << L"[MetadataStore] Spaceman chunk-info parse failed"
                           << L" reason=CabCibCount"
                           << L" parsedCibs=" << cib_block_indices.size()
                           << L" expectedCibs=" << device_cib_count
                           << std::endl;
            }
            return false;
        }
    }

    for (std::uint32_t cib_index = 0; cib_index < device_cib_count; ++cib_index)
    {
        const auto cib_block_index = cib_block_indices[static_cast<std::size_t>(cib_index)];
        std::vector<std::byte> cib_block;
        if (!ReadBlockByIndexDirect(cib_block_index, cib_block) ||
            cib_block.size() < kCibHeaderBytes)
        {
            return false;
        }

        const auto cib_type = ReadLe32(cib_block, 0x18) & kObjectTypeMask;
        const auto stored_cib_index = ReadLe32(cib_block, 0x20);
        const auto chunk_info_count = ReadLe32(cib_block, 0x24);
        if (cib_type != kObjectTypeChunkInfo ||
            stored_cib_index != cib_index ||
            chunk_info_count == 0 ||
            chunk_info_count > chunks_per_cib ||
            kCibHeaderBytes + (static_cast<std::size_t>(chunk_info_count) * kChunkInfoBytes) > cib_block.size())
        {
            if (IsReadTraceEnabled())
            {
                std::wcerr << L"[MetadataStore] Spaceman chunk-info parse failed"
                           << L" reason=CibHeader"
                           << L" cibIndex=" << cib_index
                           << L" cibType=" << cib_type
                           << L" storedIndex=" << stored_cib_index
                           << L" chunkCount=" << chunk_info_count
                           << std::endl;
            }
            return false;
        }

        for (std::uint32_t chunk_info_index = 0; chunk_info_index < chunk_info_count; ++chunk_info_index)
        {
            const auto entry_offset = kCibHeaderBytes + static_cast<std::size_t>(chunk_info_index) * kChunkInfoBytes;
            const auto ci_xid = ReadLe64(cib_block, entry_offset + kChunkInfoXidOffset);
            const auto ci_addr = ReadLe64(cib_block, entry_offset + kChunkInfoAddressOffset);
            const auto ci_block_count = ReadLe32(cib_block, entry_offset + kChunkInfoBlockCountOffset);
            const auto ci_free_count = ReadLe32(cib_block, entry_offset + kChunkInfoFreeCountOffset);
            const auto ci_bitmap_addr = ReadLe64(cib_block, entry_offset + kChunkInfoBitmapAddressOffset);

            if (ci_xid == 0 ||
                ci_block_count == 0 ||
                ci_block_count > blocks_per_chunk ||
                ci_free_count > ci_block_count ||
                ci_addr >= total_blocks_ ||
                ci_block_count > (total_blocks_ - ci_addr))
            {
                if (IsReadTraceEnabled())
                {
                    std::wcerr << L"[MetadataStore] Spaceman chunk-info parse failed"
                               << L" reason=ChunkInfo"
                               << L" cibIndex=" << cib_index
                               << L" chunkIndex=" << chunk_info_index
                               << L" xid=" << ci_xid
                               << L" addr=" << ci_addr
                               << L" blocks=" << ci_block_count
                               << L" free=" << ci_free_count
                               << L" bitmap=" << ci_bitmap_addr
                               << std::endl;
                }
                return false;
            }

            ++parsed_chunk_count;
            parsed_free_blocks += ci_free_count;

            if (ci_free_count == ci_block_count)
            {
                if (!record_run(ci_addr, 0, ci_block_count, false))
                {
                    return false;
                }
                continue;
            }

            if (ci_free_count == 0 && ci_bitmap_addr == 0)
            {
                if (!record_run(ci_addr, 0, ci_block_count, true))
                {
                    return false;
                }
                continue;
            }

            if (ci_bitmap_addr == 0 || ci_bitmap_addr >= total_blocks_)
            {
                if (IsReadTraceEnabled())
                {
                    std::wcerr << L"[MetadataStore] Spaceman chunk-info parse failed"
                               << L" reason=BitmapAddress"
                               << L" cibIndex=" << cib_index
                               << L" chunkIndex=" << chunk_info_index
                               << L" bitmap=" << ci_bitmap_addr
                               << std::endl;
                }
                return false;
            }

            std::vector<std::byte> bitmap;
            if (!ReadBlockByIndexDirect(ci_bitmap_addr, bitmap))
            {
                return false;
            }
            const auto bytes_needed = static_cast<std::size_t>((static_cast<std::uint64_t>(ci_block_count) + 7ull) / 8ull);
            if (bytes_needed == 0 || bytes_needed > bitmap.size())
            {
                return false;
            }

            bool current_allocated = (std::to_integer<unsigned char>(bitmap[0]) & 0x1u) != 0;
            std::uint64_t run_start = 0;
            std::uint64_t counted_free = 0;
            const auto free_count_from_bitmap = [&]() -> std::uint64_t
            {
                std::uint64_t value = 0;
                for (std::uint32_t bit_index = 0; bit_index < ci_block_count; ++bit_index)
                {
                    const auto byte_value = std::to_integer<unsigned char>(bitmap[static_cast<std::size_t>(bit_index / 8u)]);
                    const bool allocated = ((byte_value >> (bit_index % 8u)) & 0x1u) != 0;
                    if (!allocated)
                    {
                        ++value;
                    }
                }
                return value;
            }();
            const auto suppressed_free_bits = free_count_from_bitmap > ci_free_count
                ? free_count_from_bitmap - static_cast<std::uint64_t>(ci_free_count)
                : 0;
            std::uint64_t suppressed_so_far = 0;
            if (free_count_from_bitmap < ci_free_count)
            {
                if (IsReadTraceEnabled())
                {
                    std::wcerr << L"[MetadataStore] Spaceman chunk-info parse failed"
                               << L" reason=BitmapFreeCount"
                               << L" cibIndex=" << cib_index
                               << L" chunkIndex=" << chunk_info_index
                               << L" countedFree=" << free_count_from_bitmap
                               << L" expectedFree=" << ci_free_count
                               << std::endl;
                }
                return false;
            }

            for (std::uint32_t bit_index = 0; bit_index < ci_block_count; ++bit_index)
            {
                const auto byte_value = std::to_integer<unsigned char>(bitmap[static_cast<std::size_t>(bit_index / 8u)]);
                bool allocated = ((byte_value >> (bit_index % 8u)) & 0x1u) != 0;
                if (!allocated && suppressed_so_far < suppressed_free_bits)
                {
                    allocated = true;
                    ++suppressed_so_far;
                }
                if (!allocated)
                {
                    ++counted_free;
                }
                if (allocated == current_allocated)
                {
                    continue;
                }
                if (!record_run(ci_addr, run_start, static_cast<std::uint64_t>(bit_index) - run_start, current_allocated))
                {
                    return false;
                }
                current_allocated = allocated;
                run_start = bit_index;
            }
            if (!record_run(ci_addr, run_start, static_cast<std::uint64_t>(ci_block_count) - run_start, current_allocated))
            {
                return false;
            }
            if (counted_free != ci_free_count)
            {
                if (IsReadTraceEnabled())
                {
                    std::wcerr << L"[MetadataStore] Spaceman chunk-info parse failed"
                               << L" reason=BitmapFreeCount"
                               << L" cibIndex=" << cib_index
                               << L" chunkIndex=" << chunk_info_index
                               << L" countedFree=" << counted_free
                               << L" expectedFree=" << ci_free_count
                               << std::endl;
                }
                return false;
            }
        }
    }

    if (parsed_chunk_count != device_chunk_count ||
        parsed_free_blocks != device_free_count)
    {
        if (IsReadTraceEnabled())
        {
            std::wcerr << L"[MetadataStore] Spaceman chunk-info parse failed"
                       << L" reason=SummaryMismatch"
                       << L" parsedChunks=" << parsed_chunk_count
                       << L" expectedChunks=" << device_chunk_count
                       << L" parsedFree=" << parsed_free_blocks
                       << L" expectedFree=" << device_free_count
                       << std::endl;
        }
        return false;
    }

    committed_spaceman_allocations_ = std::move(parsed_allocations);
    committed_spaceman_free_extents_ = std::move(parsed_free_extents);
    working_spaceman_free_extents_ = committed_spaceman_free_extents_;
    working_next_ephemeral_extent_ = next_ephemeral_extent_;
    if (IsReadTraceEnabled())
    {
        std::wcerr << L"[MetadataStore] Spaceman chunk-info parse loaded"
                   << L" chunks=" << parsed_chunk_count
                   << L" freeBlocks=" << parsed_free_blocks
                   << L" allocations=" << committed_spaceman_allocations_.size()
                   << L" freeExtents=" << committed_spaceman_free_extents_.size()
                   << std::endl;
    }
    return true;
}

bool MetadataStore::RefreshNativeReadExtentProjection()
{
    if (!IsLikelyRawDevicePath(context_.device_path))
    {
        return true;
    }

    NativeApfsVolumeProjection projection{};
    std::wstring projection_error;
    if (!NativeApfsReader::TryLoadVolumeProjection(
            device_,
            0,
            projection,
            projection_error))
    {
        return false;
    }

    std::unordered_map<std::uint64_t, const InodeRecord*> native_inode_by_object_id;
    native_inode_by_object_id.reserve(projection.inodes.size());
    for (const auto& inode : projection.inodes)
    {
        if (!inode.is_directory && inode.logical_size > 0)
        {
            native_inode_by_object_id[inode.object_id] = &inode;
        }
    }

    for (auto& [native_object_id, extents] : projection.read_extents_by_inode)
    {
        const auto native_inode_it = native_inode_by_object_id.find(native_object_id);
        if (native_inode_it == native_inode_by_object_id.end())
        {
            continue;
        }
        const auto& native_inode = *native_inode_it->second;

        const auto path_key = CanonicalPathKeyFromNormalizedPath(native_inode.full_path);
        const auto committed_path_it = committed_path_index_.find(path_key);
        if (committed_path_it == committed_path_index_.end())
        {
            continue;
        }

        const auto committed_inode_it = committed_inodes_.find(committed_path_it->second);
        if (committed_inode_it == committed_inodes_.end() ||
            committed_inode_it->second.is_directory ||
            committed_inode_it->second.logical_size != native_inode.logical_size)
        {
            continue;
        }

        if (!DebugMergeNativeProjectionReadExtents(committed_inode_it->first, std::move(extents)))
        {
            committed_read_extents_.erase(committed_inode_it->first);
            InvalidateCommittedReadExtentSnapshotCacheForObject(committed_inode_it->first);
        }
    }

    return true;
}

std::optional<std::uint64_t> MetadataStore::ResolveInodeCheckpointBlockIndex() const
{
    auto candidates = ResolveInodeCheckpointBlockIndices();
    if (candidates.empty())
    {
        return std::nullopt;
    }

    return candidates.front();
}

bool MetadataStore::LoadInodeCheckpointBlock(std::uint64_t block_index, const std::vector<std::byte>& block)
{
    (void)block_index;
    constexpr std::array<char, 12> kMagicV4 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'I', 'N', 'O', 'D', '4', '\0'
    };
    constexpr std::array<char, 12> kMagicV5 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'I', 'N', 'O', 'D', '5', '\0'
    };
    constexpr std::array<char, 12> kMagicV6 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'I', 'N', 'O', 'D', '6', '\0'
    };
    constexpr std::size_t kHeaderBytes = kCheckpointHeaderBytes;
    constexpr std::size_t kRecordFixedBytesV4 = 52;
    constexpr std::size_t kRecordFixedBytesV5 = 60;
    constexpr std::size_t kRecordFixedBytesV6 = 60;
    if (block.size() < kHeaderBytes)
    {
        return false;
    }

    const auto matches_magic = [&](const std::array<char, 12>& magic)
    {
        for (std::size_t index = 0; index < magic.size(); ++index)
        {
            if (std::to_integer<unsigned char>(block[index]) != static_cast<unsigned char>(magic[index]))
            {
                return false;
            }
        }
        return true;
    };
    const auto has_compact_parent_name_paths = matches_magic(kMagicV6);
    const auto has_persisted_timestamp = has_compact_parent_name_paths || matches_magic(kMagicV5);
    if (!has_persisted_timestamp && !has_compact_parent_name_paths && !matches_magic(kMagicV4))
    {
        return false;
    }
    const auto kRecordFixedBytes = has_compact_parent_name_paths
        ? kRecordFixedBytesV6
        : (has_persisted_timestamp ? kRecordFixedBytesV5 : kRecordFixedBytesV4);

    const auto persisted_xid = ReadLe64(block, 12);
    if (!CanLoadNativeCheckpointXid(persisted_xid))
    {
        return false;
    }
    const auto inode_count = ReadLe32(block, 20);
    const auto persisted_payload_bytes = ReadLe32(block, 24);
    const auto persisted_checksum = ReadLe32(block, kCheckpointChecksumOffset);
    auto payload_block = block;
    if (persisted_payload_bytes > (payload_block.size() - kHeaderBytes))
    {
        const auto chunk_magic = has_compact_parent_name_paths
            ? kMagicV6
            : (has_persisted_timestamp ? kMagicV5 : kMagicV4);
        payload_block = ReadChunkedCheckpointBytes(
            ResolveInodeCheckpointBlockIndices(),
            persisted_xid,
            chunk_magic,
            persisted_payload_bytes);
        if (payload_block.empty())
        {
            auto legacy_blocks = ResolveLegacyContiguousCheckpointBlocks(
                ResolveNativeCheckpointBandStartBlock(),
                kNativeInodeCheckpointOffset,
                12,
                [this](std::uint64_t candidate)
                {
                    return IsNativeCheckpointBandBlock(candidate);
                });
            payload_block = ReadChunkedCheckpointBytes(legacy_blocks, persisted_xid, chunk_magic, persisted_payload_bytes);
            if (payload_block.empty())
            {
                return false;
            }
        }
    }

    std::unordered_map<std::uint64_t, InodeRecord> loaded_inodes;
    std::unordered_map<std::wstring, std::uint64_t> loaded_path_index;
    std::vector<DirectoryLink> loaded_directory_links;
    loaded_inodes.reserve(inode_count);
    loaded_path_index.reserve(inode_count);
    loaded_directory_links.reserve(inode_count > 0 ? static_cast<std::size_t>(inode_count - 1) : 0);

    std::size_t cursor = kHeaderBytes;
    for (std::uint32_t index = 0; index < inode_count; ++index)
    {
        if (cursor > payload_block.size() ||
            kRecordFixedBytes > (payload_block.size() - cursor))
        {
            return false;
        }

        InodeRecord inode{};
        inode.object_id = ReadLe64(payload_block, cursor + 0);
        inode.parent_object_id = ReadLe64(payload_block, cursor + 8);
        inode.logical_size = ReadLe64(payload_block, cursor + 16);
        inode.data_physical_address = ReadLe64(payload_block, cursor + 24);
        inode.xid = ReadLe64(payload_block, cursor + 32);
        std::size_t flags_offset = cursor + 40;
        std::size_t name_length_offset = cursor + 44;
        std::size_t path_length_offset = cursor + 48;
        if (has_persisted_timestamp)
        {
            inode.timestamp_utc = ReadLe64(payload_block, cursor + 40);
            flags_offset += 8;
            name_length_offset += 8;
            path_length_offset += 8;
        }
        const auto flags = ReadLe32(payload_block, flags_offset);
        const auto name_length = ReadLe32(payload_block, name_length_offset);
        const auto path_length = ReadLe32(payload_block, path_length_offset);
        cursor += kRecordFixedBytes;

        const auto name_bytes = static_cast<std::uint64_t>(name_length) * static_cast<std::uint64_t>(sizeof(wchar_t));
        const auto path_bytes = static_cast<std::uint64_t>(path_length) * static_cast<std::uint64_t>(sizeof(wchar_t));
        if (name_bytes > (std::numeric_limits<std::size_t>::max() - cursor) ||
            path_bytes > (std::numeric_limits<std::size_t>::max() - cursor - static_cast<std::size_t>(name_bytes)))
        {
            return false;
        }
        const auto required_bytes = static_cast<std::size_t>(name_bytes + path_bytes);
        if (required_bytes > (payload_block.size() - cursor))
        {
            return false;
        }

        inode.is_directory = (flags & 0x1u) != 0;
        inode.name.resize(name_length);
        if (name_bytes > 0)
        {
            std::memcpy(inode.name.data(), payload_block.data() + cursor, static_cast<std::size_t>(name_bytes));
        }
        cursor += static_cast<std::size_t>(name_bytes);
        inode.full_path.resize(path_length);
        if (path_bytes > 0)
        {
            std::memcpy(inode.full_path.data(), payload_block.data() + cursor, static_cast<std::size_t>(path_bytes));
        }
        cursor += static_cast<std::size_t>(path_bytes);

        if (inode.object_id == 0 || (!has_compact_parent_name_paths && inode.full_path.empty()))
        {
            return false;
        }
        if (!inode.full_path.empty() && NormalizePath(inode.full_path) != inode.full_path)
        {
            return false;
        }
        if (!inode.is_directory &&
            inode.logical_size > 0 &&
            inode.data_physical_address == 0 &&
            !committed_read_extents_.contains(inode.object_id) &&
            !(context_.allow_raw_physical_write && IsLikelyRawDevicePath(context_.device_path)))
        {
            return false;
        }
        if (inode.is_directory && (inode.logical_size != 0 || inode.data_physical_address != 0))
        {
            return false;
        }

        auto [inode_it, inserted] = loaded_inodes.emplace(inode.object_id, inode);
        if (!inserted)
        {
            return false;
        }

        if (!has_compact_parent_name_paths)
        {
            const auto canonical_path = CanonicalPathKeyFromNormalizedPath(inode.full_path);
            auto [path_it, path_inserted] = loaded_path_index.emplace(canonical_path, inode.object_id);
            if (!path_inserted && path_it->second != inode.object_id)
            {
                return false;
            }

            if (!IsRootPath(inode.full_path))
            {
                loaded_directory_links.push_back(DirectoryLink
                {
                    inode.parent_object_id,
                    inode.name,
                    inode.object_id,
                    inode.xid
                });
            }
        }
    }

    const auto payload_bytes = cursor - kHeaderBytes;
    if (persisted_payload_bytes != 0 &&
        persisted_payload_bytes != static_cast<std::uint32_t>(payload_bytes))
    {
        return false;
    }
    if (persisted_checksum != 0 &&
        ComputeCheckpointChecksum(payload_block, payload_bytes) != persisted_checksum)
    {
        return false;
    }

    if (has_compact_parent_name_paths)
    {
        std::optional<std::uint64_t> root_object_id;
        std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> children_by_parent;
        children_by_parent.reserve(loaded_inodes.size());
        for (const auto& [object_id, inode] : loaded_inodes)
        {
            const auto is_root_candidate =
                inode.parent_object_id == object_id &&
                inode.name.empty() &&
                inode.is_directory;
            if (is_root_candidate)
            {
                if (root_object_id.has_value())
                {
                    return false;
                }
                root_object_id = object_id;
                continue;
            }

            if (inode.name.empty() ||
                inode.parent_object_id == 0 ||
                inode.parent_object_id == object_id)
            {
                return false;
            }
            auto parent_it = loaded_inodes.find(inode.parent_object_id);
            if (parent_it == loaded_inodes.end() || !parent_it->second.is_directory)
            {
                return false;
            }
            children_by_parent[inode.parent_object_id].push_back(object_id);
        }
        if (!root_object_id.has_value())
        {
            return false;
        }

        auto root_it = loaded_inodes.find(root_object_id.value());
        if (root_it == loaded_inodes.end())
        {
            return false;
        }
        root_it->second.full_path = L"\\";
        loaded_path_index.emplace(CanonicalPathKeyFromNormalizedPath(root_it->second.full_path), root_it->first);

        std::vector<std::uint64_t> queue;
        queue.push_back(root_it->first);
        std::size_t cursor_index = 0;
        std::unordered_set<std::uint64_t> visited;
        visited.reserve(loaded_inodes.size());
        visited.insert(root_it->first);
        while (cursor_index < queue.size())
        {
            const auto parent_id = queue[cursor_index++];
            auto parent_it = loaded_inodes.find(parent_id);
            if (parent_it == loaded_inodes.end() || parent_it->second.full_path.empty())
            {
                return false;
            }

            auto children_it = children_by_parent.find(parent_id);
            if (children_it == children_by_parent.end())
            {
                continue;
            }
            for (const auto child_id : children_it->second)
            {
                if (!visited.insert(child_id).second)
                {
                    return false;
                }

                auto child_it = loaded_inodes.find(child_id);
                if (child_it == loaded_inodes.end())
                {
                    return false;
                }

                auto child_path = parent_it->second.full_path;
                if (!IsRootPath(child_path))
                {
                    child_path.push_back(L'\\');
                }
                child_path.append(child_it->second.name);
                child_path = NormalizePath(child_path);
                if (child_path.empty() || IsRootPath(child_path))
                {
                    return false;
                }

                if (child_it->second.full_path.empty())
                {
                    child_it->second.full_path = child_path;
                }
                else if (CanonicalPathKeyFromNormalizedPath(child_it->second.full_path) != CanonicalPathKeyFromNormalizedPath(child_path))
                {
                    return false;
                }
                const auto canonical_path = CanonicalPathKeyFromNormalizedPath(child_it->second.full_path);
                auto [path_it, path_inserted] = loaded_path_index.emplace(canonical_path, child_id);
                if (!path_inserted && path_it->second != child_id)
                {
                    return false;
                }
                loaded_directory_links.push_back(DirectoryLink
                {
                    child_it->second.parent_object_id,
                    child_it->second.name,
                    child_id,
                    child_it->second.xid
                });

                if (child_it->second.is_directory)
                {
                    queue.push_back(child_id);
                }
            }
        }

        if (visited.size() != loaded_inodes.size())
        {
            return false;
        }
    }

    if (!ValidateInodeGraphState(
            loaded_inodes,
            loaded_path_index,
            loaded_directory_links,
            /*require_root_object=*/true))
    {
        return false;
    }

    committed_inodes_ = std::move(loaded_inodes);
    InvalidateCommittedInodeOrderCache();
    committed_path_index_ = std::move(loaded_path_index);
    committed_directory_links_ = std::move(loaded_directory_links);
    RebuildCommittedDirectoryLinkIndex();
    working_inodes_ = committed_inodes_;
    working_path_index_ = committed_path_index_;
    working_directory_links_ = committed_directory_links_;
    RebuildWorkingDirectoryIndexes();

    if (persisted_xid > 0)
    {
        last_committed_xid_ = std::max(last_committed_xid_.value_or(0), persisted_xid);
    }
    return true;
}

bool MetadataStore::LoadBtreeCheckpointBlock(std::uint64_t block_index, const std::vector<std::byte>& block)
{
    (void)block_index;
    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'B', 'T', 'R', '5', '\0', '\0'
    };
    constexpr std::size_t kHeaderBytes = kCheckpointHeaderBytes;
    constexpr std::size_t kRecordHeaderBytes = 16;
    if (block.size() < kHeaderBytes)
    {
        return false;
    }

    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        if (std::to_integer<unsigned char>(block[index]) != static_cast<unsigned char>(kMagic[index]))
        {
            return false;
        }
    }

    const auto persisted_xid = ReadLe64(block, 12);
    if (!CanLoadNativeCheckpointXid(persisted_xid))
    {
        return false;
    }
    const auto record_count = ReadLe32(block, 20);
    const auto persisted_payload_bytes = ReadLe32(block, 24);
    const auto persisted_checksum = ReadLe32(block, kCheckpointChecksumOffset);
    auto payload_block = block;
    if (persisted_payload_bytes > (payload_block.size() - kHeaderBytes))
    {
        payload_block = ReadChunkedCheckpointBytes(
            ResolveBtreeCheckpointBlockIndices(),
            persisted_xid,
            kMagic,
            persisted_payload_bytes);
        if (payload_block.empty())
        {
            auto legacy_blocks = ResolveLegacyContiguousCheckpointBlocks(
                ResolveNativeCheckpointBandStartBlock(),
                kNativeBtreeCheckpointOffset,
                kNativeReplayCheckpointOffset - kNativeBtreeCheckpointOffset,
                [this](std::uint64_t candidate)
                {
                    return IsNativeCheckpointBandBlock(candidate);
                });
            payload_block = ReadChunkedCheckpointBytes(legacy_blocks, persisted_xid, kMagic, persisted_payload_bytes);
            if (payload_block.empty())
            {
                return false;
            }
        }
    }

    std::vector<BtreeRecord> loaded_records;
    loaded_records.reserve(record_count);
    std::size_t cursor = kHeaderBytes;
    for (std::uint32_t index = 0; index < record_count; ++index)
    {
        if (cursor > payload_block.size() ||
            kRecordHeaderBytes > (payload_block.size() - cursor))
        {
            return false;
        }

        const auto kind_value = ReadLe32(payload_block, cursor + 0);
        const auto tombstone_flag = ReadLe32(payload_block, cursor + 4);
        const auto key_length = ReadLe32(payload_block, cursor + 8);
        const auto value_length = ReadLe32(payload_block, cursor + 12);
        cursor += kRecordHeaderBytes;

        if (kind_value < static_cast<std::uint32_t>(BtreeRecordKind::Inode) ||
            kind_value > static_cast<std::uint32_t>(BtreeRecordKind::FileExtent))
        {
            return false;
        }

        const auto required_payload =
            static_cast<std::uint64_t>(key_length) + static_cast<std::uint64_t>(value_length);
        if (required_payload > (std::numeric_limits<std::size_t>::max() - cursor))
        {
            return false;
        }
        if (static_cast<std::size_t>(required_payload) > (payload_block.size() - cursor))
        {
            return false;
        }

        BtreeRecord record{};
        record.kind = static_cast<BtreeRecordKind>(kind_value);
        record.tombstone = tombstone_flag != 0;
        if (key_length > 0)
        {
            record.key.insert(
                record.key.end(),
                payload_block.begin() + static_cast<std::vector<std::byte>::difference_type>(cursor),
                payload_block.begin() + static_cast<std::vector<std::byte>::difference_type>(cursor + key_length));
            cursor += key_length;
        }
        if (value_length > 0)
        {
            record.value.insert(
                record.value.end(),
                payload_block.begin() + static_cast<std::vector<std::byte>::difference_type>(cursor),
                payload_block.begin() + static_cast<std::vector<std::byte>::difference_type>(cursor + value_length));
            cursor += value_length;
        }
        loaded_records.push_back(std::move(record));
    }

    const auto payload_bytes = cursor - kHeaderBytes;
    if (persisted_payload_bytes != 0 &&
        persisted_payload_bytes != static_cast<std::uint32_t>(payload_bytes))
    {
        return false;
    }
    if (persisted_checksum != 0 &&
        ComputeCheckpointChecksum(payload_block, payload_bytes) != persisted_checksum)
    {
        return false;
    }

    committed_btree_records_ = CanonicalizeBtreeRecords(loaded_records);
    if (!RebuildCommittedBtreeIndex())
    {
        return false;
    }

    const auto allow_fixture_fallback = IsLegacyFixtureFallbackAllowedForCurrentContext();

    ApfsVolumeTreeStore volume_tree_store;
    ApfsVolumeTreeProjection volume_tree_projection{};
    std::wstring volume_tree_error;
    if (!volume_tree_store.TryProjectFromBtreeRecords(
            committed_btree_records_,
            volume_tree_projection,
            volume_tree_error))
    {
        if (!allow_fixture_fallback)
        {
            return false;
        }

        legacy_fixture_fallback_used_ = true;
    }
    if (persisted_xid > 0)
    {
        last_committed_xid_ = std::max(last_committed_xid_.value_or(0), persisted_xid);
    }
    return true;
}

bool MetadataStore::LoadReplayCheckpointBlock(
    std::uint64_t block_index,
    const std::vector<std::byte>& block,
    std::uint64_t& out_target_xid,
    std::uint64_t& out_source_xid,
    std::uint64_t& out_commit_blob_address,
    std::uint64_t& out_commit_blob_bytes) const
{
    (void)block_index;
    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'R', 'P', 'L', '1', '\0', '\0'
    };
    constexpr std::size_t kHeaderBytes = kCheckpointHeaderBytes;
    constexpr std::size_t kReplayPayloadBytes = 24;

    if (block.size() < (kHeaderBytes + kReplayPayloadBytes))
    {
        return false;
    }

    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        if (std::to_integer<unsigned char>(block[index]) != static_cast<unsigned char>(kMagic[index]))
        {
            return false;
        }
    }

    const auto persisted_xid = ReadLe64(block, 12);
    const auto persisted_version = ReadLe32(block, 20);
    const auto persisted_payload_bytes = ReadLe32(block, 24);
    const auto persisted_checksum = ReadLe32(block, kCheckpointChecksumOffset);
    if (persisted_xid == 0 || persisted_version != 1)
    {
        return false;
    }
    if (persisted_payload_bytes != kReplayPayloadBytes)
    {
        return false;
    }
    if (persisted_checksum == 0 ||
        ComputeCheckpointChecksum(block, persisted_payload_bytes) != persisted_checksum)
    {
        return false;
    }
    for (std::size_t index = (kHeaderBytes + kReplayPayloadBytes); index < block.size(); ++index)
    {
        if (block[index] != std::byte{0})
        {
            return false;
        }
    }

    const auto source_xid = ReadLe64(block, kHeaderBytes + 0);
    const auto commit_blob_address = ReadLe64(block, kHeaderBytes + 8);
    const auto commit_blob_bytes = ReadLe64(block, kHeaderBytes + 16);
    if (source_xid >= persisted_xid || (source_xid + 1) != persisted_xid)
    {
        return false;
    }
    if (!ValidateCommitBlobLocation(commit_blob_address, commit_blob_bytes))
    {
        return false;
    }

    out_target_xid = persisted_xid;
    out_source_xid = source_xid;
    out_commit_blob_address = commit_blob_address;
    out_commit_blob_bytes = commit_blob_bytes;
    return true;
}

bool MetadataStore::RebuildInodeStateFromBtreeRecords(
    const std::vector<BtreeRecord>& records,
    std::unordered_map<std::uint64_t, InodeRecord>& out_inodes,
    std::unordered_map<std::wstring, std::uint64_t>& out_path_index,
    std::vector<DirectoryLink>& out_directory_links) const
{
    out_inodes.clear();
    out_path_index.clear();
    out_directory_links.clear();

    std::unordered_map<std::uint64_t, DecodedBtreeInode> decoded_inodes;
    std::unordered_map<std::uint64_t, std::vector<DecodedBtreeExtent>> decoded_extents;
    std::unordered_map<std::uint64_t, std::vector<DecodedBtreeDirectoryEntry>> decoded_directory_entries_by_parent;
    std::unordered_set<std::wstring> seen_directory_entry_keys;

    const auto canonical_name_key = [](const std::wstring& name)
    {
        std::wstring key = name;
        std::transform(key.begin(), key.end(), key.begin(), [](wchar_t ch)
        {
            return static_cast<wchar_t>(std::towlower(ch));
        });
        return key;
    };
    const auto build_directory_entry_key = [&](std::uint64_t parent_object_id, const std::wstring& entry_name)
    {
        std::wstring key = std::to_wstring(parent_object_id);
        key.push_back(L'\x1f');
        key.append(canonical_name_key(entry_name));
        return key;
    };

    for (const auto& record : records)
    {
        if (record.tombstone)
        {
            return false;
        }

        switch (record.kind)
        {
        case BtreeRecordKind::Inode:
        {
            DecodedBtreeInode decoded{};
            if (!DecodeBtreeInodeRecord(record, decoded))
            {
                return false;
            }
            if (!decoded_inodes.emplace(decoded.object_id, std::move(decoded)).second)
            {
                return false;
            }
            break;
        }
        case BtreeRecordKind::DirectoryEntry:
        {
            DecodedBtreeDirectoryEntry decoded{};
            if (!DecodeBtreeDirectoryRecord(record, decoded))
            {
                return false;
            }
            auto entry_key = build_directory_entry_key(decoded.parent_object_id, decoded.entry_name);
            if (!seen_directory_entry_keys.emplace(std::move(entry_key)).second)
            {
                return false;
            }
            decoded_directory_entries_by_parent[decoded.parent_object_id].push_back(std::move(decoded));
            break;
        }
        case BtreeRecordKind::FileExtent:
        {
            DecodedBtreeExtent decoded{};
            if (!DecodeBtreeExtentRecord(record, decoded))
            {
                return false;
            }
            decoded_extents[decoded.object_id].push_back(std::move(decoded));
            break;
        }
        default:
            return false;
        }
    }

    for (const auto& [object_id, inode] : decoded_inodes)
    {
        if (inode.is_directory)
        {
            if (decoded_extents.contains(object_id))
            {
                return false;
            }
            continue;
        }

        if (inode.logical_size == 0)
        {
            if (inode.data_physical_address != 0 || decoded_extents.contains(object_id))
            {
                return false;
            }
            continue;
        }

        auto extent_it = decoded_extents.find(object_id);
        if (extent_it == decoded_extents.end())
        {
            if (context_.allow_raw_physical_write &&
                IsLikelyRawDevicePath(context_.device_path))
            {
                continue;
            }
            return false;
        }
        const auto file_extents = ExtentsFromDecodedBtreeExtents(extent_it->second);
        if (!HasLogicalExtentCoverage(file_extents, inode.logical_size) ||
            file_extents.empty() ||
            file_extents.front().logical_offset != 0 ||
            file_extents.front().physical_address != inode.data_physical_address)
        {
            return false;
        }
    }

    const auto root_path = std::wstring(L"\\");
    const auto root_object_id = RootDirectoryObjectId();
    InodeRecord root_inode{};
    root_inode.object_id = root_object_id;
    root_inode.parent_object_id = root_object_id;
    root_inode.name = L"";
    root_inode.full_path = root_path;
    root_inode.is_directory = true;
    root_inode.logical_size = 0;
    root_inode.data_physical_address = 0;
    root_inode.xid = checkpoint_xid_;
    out_inodes.emplace(root_inode.object_id, root_inode);
    out_path_index.emplace(CanonicalPathKeyFromNormalizedPath(root_inode.full_path), root_inode.object_id);

    std::vector<std::uint64_t> directory_queue;
    directory_queue.push_back(root_object_id);
    std::size_t queue_cursor = 0;
    std::unordered_set<std::uint64_t> visited_non_root_inodes;
    while (queue_cursor < directory_queue.size())
    {
        const auto parent_object_id = directory_queue[queue_cursor++];
        auto parent_inode_it = out_inodes.find(parent_object_id);
        if (parent_inode_it == out_inodes.end())
        {
            return false;
        }

        auto entries_it = decoded_directory_entries_by_parent.find(parent_object_id);
        if (entries_it == decoded_directory_entries_by_parent.end())
        {
            continue;
        }

        auto entries = entries_it->second;
        std::sort(entries.begin(), entries.end(), [&](const DecodedBtreeDirectoryEntry& lhs, const DecodedBtreeDirectoryEntry& rhs)
        {
            const auto lhs_key = canonical_name_key(lhs.entry_name);
            const auto rhs_key = canonical_name_key(rhs.entry_name);
            if (lhs_key == rhs_key)
            {
                return lhs.child_object_id < rhs.child_object_id;
            }
            return lhs_key < rhs_key;
        });

        for (const auto& entry : entries)
        {
            if (entry.child_object_id == 0 || entry.child_object_id == root_object_id)
            {
                return false;
            }

            auto decoded_inode_it = decoded_inodes.find(entry.child_object_id);
            if (decoded_inode_it == decoded_inodes.end())
            {
                return false;
            }
            const auto& decoded_inode = decoded_inode_it->second;
            if (decoded_inode.parent_object_id != parent_object_id ||
                canonical_name_key(decoded_inode.name) != canonical_name_key(entry.entry_name))
            {
                return false;
            }

            if (!visited_non_root_inodes.emplace(entry.child_object_id).second)
            {
                return false;
            }
            if (out_inodes.contains(entry.child_object_id))
            {
                return false;
            }

            std::wstring child_path = parent_inode_it->second.full_path;
            if (!IsRootPath(child_path))
            {
                child_path.push_back(L'\\');
            }
            child_path.append(decoded_inode.name);
            child_path = NormalizePath(child_path);
            if (child_path.empty() || IsRootPath(child_path))
            {
                return false;
            }

            const auto child_path_key = CanonicalPathKeyFromNormalizedPath(child_path);
            if (child_path_key.empty())
            {
                return false;
            }
            if (!out_path_index.emplace(child_path_key, entry.child_object_id).second)
            {
                return false;
            }

            InodeRecord rebuilt_inode{};
            rebuilt_inode.object_id = entry.child_object_id;
            rebuilt_inode.parent_object_id = parent_object_id;
            rebuilt_inode.name = decoded_inode.name;
            rebuilt_inode.full_path = std::move(child_path);
            rebuilt_inode.is_directory = decoded_inode.is_directory;
            rebuilt_inode.logical_size = decoded_inode.logical_size;
            rebuilt_inode.data_physical_address = decoded_inode.data_physical_address;
            rebuilt_inode.xid = decoded_inode.xid;
            rebuilt_inode.timestamp_utc = decoded_inode.timestamp_utc;
            out_inodes.emplace(rebuilt_inode.object_id, rebuilt_inode);
            out_directory_links.push_back(DirectoryLink
            {
                parent_object_id,
                rebuilt_inode.name,
                rebuilt_inode.object_id,
                entry.xid
            });

            if (rebuilt_inode.is_directory)
            {
                directory_queue.push_back(rebuilt_inode.object_id);
            }
        }
    }

    if (visited_non_root_inodes.size() != decoded_inodes.size())
    {
        return false;
    }

    return ValidateInodeGraphState(
        out_inodes,
        out_path_index,
        out_directory_links,
        /*require_root_object=*/true);
}

bool MetadataStore::RebuildReadExtentsFromBtreeRecords(
    const std::vector<BtreeRecord>& records,
    const std::unordered_map<std::uint64_t, InodeRecord>& inode_table,
    std::unordered_map<std::uint64_t, std::vector<FileExtent>>& out_read_extents) const
{
    out_read_extents.clear();

    std::unordered_map<std::uint64_t, std::vector<DecodedBtreeExtent>> decoded_extents;
    decoded_extents.reserve(records.size());
    for (const auto& record : records)
    {
        if (record.tombstone || record.kind != BtreeRecordKind::FileExtent)
        {
            continue;
        }

        DecodedBtreeExtent decoded{};
        if (!DecodeBtreeExtentRecord(record, decoded))
        {
            return false;
        }
        decoded_extents[decoded.object_id].push_back(std::move(decoded));
    }

    for (const auto& [object_id, extents] : decoded_extents)
    {
        auto inode_it = inode_table.find(object_id);
        if (inode_it == inode_table.end() ||
            inode_it->second.is_directory ||
            inode_it->second.logical_size == 0)
        {
            return false;
        }

        auto file_extents = ExtentsFromDecodedBtreeExtents(extents);
        if (!HasLogicalExtentCoverage(file_extents, inode_it->second.logical_size) ||
            file_extents.empty() ||
            file_extents.front().logical_offset != 0 ||
            file_extents.front().physical_address != inode_it->second.data_physical_address)
        {
            return false;
        }

        out_read_extents.emplace(object_id, std::move(file_extents));
    }

    return true;
}

bool MetadataStore::IsContainerLoaded() const noexcept
{
    return container_loaded_;
}

std::optional<std::uint32_t> MetadataStore::BlockSizeBytes() const noexcept
{
    return container_loaded_ ? std::optional<std::uint32_t>(block_size_) : std::nullopt;
}

std::optional<std::uint64_t> MetadataStore::TotalBlocks() const noexcept
{
    return container_loaded_ ? std::optional<std::uint64_t>(total_blocks_) : std::nullopt;
}

std::optional<std::uint64_t> MetadataStore::TotalSizeBytes() const noexcept
{
    if (!container_loaded_ || block_size_ == 0)
    {
        return std::nullopt;
    }
    if (total_blocks_ == 0)
    {
        return std::nullopt;
    }
    if (total_blocks_ > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
    {
        return std::nullopt;
    }

    return total_blocks_ * static_cast<std::uint64_t>(block_size_);
}

std::optional<std::uint64_t> MetadataStore::FreeSizeBytes() const noexcept
{
    if (!container_loaded_ || block_size_ == 0)
    {
        return std::nullopt;
    }

    if (!spaceman_loaded_ &&
        committed_spaceman_allocations_.empty() &&
        committed_spaceman_free_extents_.empty() &&
        !spaceman_free_bytes_.has_value())
    {
        return std::nullopt;
    }

    const auto accumulated_bytes = [](const std::vector<SpacemanAllocation>& extents) -> std::optional<std::uint64_t>
    {
        std::uint64_t total = 0;
        for (const auto& extent : extents)
        {
            if (extent.bytes == 0)
            {
                continue;
            }
            if (total > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
            {
                return std::nullopt;
            }
            total += extent.bytes;
        }
        return total;
    };

    const auto total_bytes = TotalSizeBytes();
    const auto allocated_bytes = accumulated_bytes(committed_spaceman_allocations_);
    if (total_bytes.has_value() && allocated_bytes.has_value())
    {
        if (allocated_bytes.value() >= total_bytes.value())
        {
            return 0ull;
        }

        return total_bytes.value() - allocated_bytes.value();
    }

    if (spaceman_free_bytes_.has_value())
    {
        if (total_bytes.has_value() && spaceman_free_bytes_.value() > total_bytes.value())
        {
            return total_bytes;
        }
        return spaceman_free_bytes_;
    }

    const auto free_extents = accumulated_bytes(working_spaceman_free_extents_.empty()
        ? committed_spaceman_free_extents_
        : working_spaceman_free_extents_);
    if (free_extents.has_value() && total_bytes.has_value() && free_extents.value() > total_bytes.value())
    {
        return total_bytes;
    }

    return free_extents;
}

std::optional<std::uint64_t> MetadataStore::CheckpointXid() const noexcept
{
    return container_loaded_ ? std::optional<std::uint64_t>(checkpoint_xid_) : std::nullopt;
}

bool MetadataStore::PrepareNativeWritePath()
{
    const auto fail_prepare = [this](std::wstring reason) -> bool
    {
        native_write_ready_ = false;
        commit_path_ready_ = false;
        canonical_state_loaded_ = false;
        canonical_commit_ready_ = false;
        write_device_allowed_ = false;
        SyncCommitBlobTelemetryWithMode();
        if (!reason.empty())
        {
            if (recovery_reason_.empty())
            {
                MarkRecoveryRequired(std::move(reason));
            }
            else
            {
                MarkRecoveryRequired(recovery_reason_);
            }
        }
        return false;
    };

    if (!container_loaded_ && !LoadContainerState())
    {
        return fail_prepare(L"ContainerStateLoadFailed");
    }
    if (!LoadCanonicalState())
    {
        if (!recovery_reason_.empty())
        {
            return fail_prepare(recovery_reason_);
        }
        return fail_prepare(L"CanonicalStateNotLoaded");
    }
    if (!persistent_state_loaded_ && !LoadPersistentState())
    {
        return fail_prepare(L"PersistentStateLoadFailed");
    }

    native_write_ready_ = true;
    write_device_allowed_ = device_.IsWritable() &&
                            (context_.allow_raw_physical_write || !IsLikelyRawDevicePath(context_.device_path));
    commit_path_ready_ = native_write_ready_ && write_device_allowed_ && !recovery_required_;
    canonical_state_loaded_ = canonical_state_loaded_ && native_write_ready_;
    canonical_commit_ready_ = CanReportCanonicalCommitReady(
        canonical_state_loaded_,
        commit_path_ready_,
        recovery_required_,
        legacy_fixture_fallback_used_);
    if (!EnsureRootState())
    {
        return fail_prepare(L"RootStateInvalid");
    }
    if (context_.integrity_check_on_mount && !VerifyIntegrity())
    {
        return fail_prepare(ResolveIntegrityCheckFailureRecoveryReason());
    }

    working_inodes_ = committed_inodes_;
    working_path_index_ = committed_path_index_;
    working_directory_links_ = committed_directory_links_;
    working_spaceman_free_extents_ = committed_spaceman_free_extents_;
    working_free_extents_sanitized_ = false;
    working_next_ephemeral_extent_ = next_ephemeral_extent_;
    RebuildWorkingDirectoryIndexes();
    pending_mutations_.clear();
    pending_mutation_path_key_cache_.clear();
    pending_write_object_ids_.clear();
    pending_write_mutation_index_by_object_id_.clear();
    pending_basic_info_mutation_index_by_object_id_.clear();
    ClearPendingPayloadPathKeys();
    ClearPendingPayloadObjectSummary();
    ClearPendingCloseDelaySummary();
    pending_object_map_updates_.clear();
    pending_object_map_update_index_.clear();
    pending_spaceman_allocations_.clear();
    pending_spaceman_allocation_index_.clear();
    pending_spaceman_deallocations_.clear();
    tracking_spaceman_free_extent_delta_ = false;
    pending_spaceman_untracked_free_extent_delta_ = false;
    pending_spaceman_released_existing_allocation_ = false;
    pending_btree_records_.clear();
    pending_btree_inode_record_count_by_object_.clear();
    pending_btree_file_inode_index_.clear();
    pending_btree_file_extent_index_.clear();
    pending_btree_file_extent_offsets_by_object_.clear();
    pending_btree_file_extent_record_count_by_object_.clear();
    pending_btree_directory_record_count_by_child_object_.clear();
    pending_btree_tombstone_record_count_ = 0;
    pending_btree_directory_inode_record_count_ = 0;
    pending_btree_untracked_record_count_ = 0;
    pending_read_extent_updates_.clear();
    prepared_payload_ranges_.clear();
    pending_written_ranges_.clear();
    pending_payload_dirty_bytes_ = 0;
    last_committed_inode_changes_.clear();
    working_read_extents_ = committed_read_extents_;
    canonical_commit_ready_ = CanReportCanonicalCommitReady(
        canonical_state_loaded_,
        commit_path_ready_,
        recovery_required_,
        legacy_fixture_fallback_used_);
    SyncCommitBlobTelemetryWithMode();
    return true;
}

bool MetadataStore::IsNativeWriteReady() const noexcept
{
    return native_write_ready_ && container_loaded_ && object_map_loaded_ && spaceman_loaded_;
}

bool MetadataStore::IsCommitPathReady() const noexcept
{
    return IsNativeWriteReady() && commit_path_ready_;
}

void MetadataStore::InvalidateCommittedObjectMapOrderCache() const noexcept
{
    committed_object_map_order_cache_valid_ = false;
    ++committed_object_map_order_generation_;
}

void MetadataStore::InvalidateCommittedReadExtentSnapshotCache() const noexcept
{
    committed_read_extent_snapshot_cache_.clear();
    committed_read_extent_snapshot_cache_use_ = 0;
    committed_read_extent_snapshot_cache_bytes_ = 0;
}

void MetadataStore::InvalidateCommittedReadExtentSnapshotCacheForObject(std::uint64_t object_id) const noexcept
{
    if (object_id == 0)
    {
        return;
    }

    const auto cache_it = committed_read_extent_snapshot_cache_.find(object_id);
    if (cache_it == committed_read_extent_snapshot_cache_.end())
    {
        return;
    }

    const auto snapshot_bytes = cache_it->second.extents != nullptr
        ? static_cast<std::uint64_t>(cache_it->second.extents->size() * sizeof(FileExtent))
        : 0;
    committed_read_extent_snapshot_cache_bytes_ = snapshot_bytes <= committed_read_extent_snapshot_cache_bytes_
        ? committed_read_extent_snapshot_cache_bytes_ - snapshot_bytes
        : 0;
    committed_read_extent_snapshot_cache_.erase(cache_it);
}

void MetadataStore::InvalidateCommittedInodeOrderCache() const noexcept
{
    committed_inode_order_cache_valid_ = false;
    committed_inode_checkpoint_required_bytes_cache_.reset();
    ++committed_inode_order_generation_;
}

const std::vector<MetadataStore::CommittedObjectMapOrderEntry>* MetadataStore::OrderedCommittedObjectMapEntries() const
{
    if (committed_object_map_order_cache_valid_)
    {
        if (committed_object_map_order_cache_generation_ == committed_object_map_order_generation_ &&
            committed_object_map_order_cache_.size() == committed_object_map_.size())
        {
            object_map_checkpoint_order_cache_hit_count_.fetch_add(1, std::memory_order_relaxed);
            return &committed_object_map_order_cache_;
        }

        committed_object_map_order_cache_valid_ = false;
    }

    committed_object_map_order_cache_.clear();
    committed_object_map_order_cache_.reserve(committed_object_map_.size());
    for (const auto& [object_id, update] : committed_object_map_)
    {
        if (HasPhysicalObjectMapping(update))
        {
            committed_object_map_order_cache_.push_back(CommittedObjectMapOrderEntry{object_id, &update});
        }
    }
    std::sort(committed_object_map_order_cache_.begin(), committed_object_map_order_cache_.end(), [](const auto& lhs, const auto& rhs)
    {
        return lhs.object_id < rhs.object_id;
    });
    committed_object_map_order_cache_valid_ = true;
    committed_object_map_order_cache_generation_ = committed_object_map_order_generation_;
    object_map_checkpoint_order_rebuild_count_.fetch_add(1, std::memory_order_relaxed);
    return &committed_object_map_order_cache_;
}

bool MetadataStore::TryUpdateCommittedObjectMapOrderCacheForObject(std::uint64_t object_id) const
{
    if (object_id == 0 ||
        !committed_object_map_order_cache_valid_ ||
        committed_object_map_order_cache_generation_ != committed_object_map_order_generation_)
    {
        object_map_checkpoint_order_delta_fallback_count_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    const auto erase_begin = std::lower_bound(
        committed_object_map_order_cache_.begin(),
        committed_object_map_order_cache_.end(),
        object_id,
        [](const CommittedObjectMapOrderEntry& entry, std::uint64_t id)
        {
            return entry.object_id < id;
        });
    auto erase_end = erase_begin;
    while (erase_end != committed_object_map_order_cache_.end() &&
           erase_end->object_id == object_id)
    {
        ++erase_end;
    }
    if (erase_end != erase_begin)
    {
        committed_object_map_order_cache_.erase(erase_begin, erase_end);
    }

    auto map_it = committed_object_map_.find(object_id);
    if (map_it != committed_object_map_.end() && HasPhysicalObjectMapping(map_it->second))
    {
        const auto insert_at = std::lower_bound(
            committed_object_map_order_cache_.begin(),
            committed_object_map_order_cache_.end(),
            object_id,
            [](const CommittedObjectMapOrderEntry& entry, std::uint64_t id)
            {
                return entry.object_id < id;
            });
        committed_object_map_order_cache_.insert(insert_at, CommittedObjectMapOrderEntry{object_id, &map_it->second});
    }

    committed_object_map_order_cache_generation_ = ++committed_object_map_order_generation_;
    object_map_checkpoint_order_delta_update_count_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

const std::vector<MetadataStore::CommittedInodeOrderEntry>* MetadataStore::OrderedCommittedInodeEntries() const
{
    if (committed_inode_order_cache_valid_)
    {
        if (committed_inode_order_cache_generation_ == committed_inode_order_generation_ &&
            committed_inode_order_cache_.size() == committed_inodes_.size())
        {
            inode_checkpoint_order_cache_hit_count_.fetch_add(1, std::memory_order_relaxed);
            return &committed_inode_order_cache_;
        }

        committed_inode_order_cache_valid_ = false;
    }

    struct SnapshotEntry
    {
        std::wstring path_key;
        const InodeRecord* inode = nullptr;
        bool persist_full_path = false;
    };

    std::vector<SnapshotEntry> snapshot;
    snapshot.reserve(committed_inodes_.size());
    for (const auto& [object_id, inode] : committed_inodes_)
    {
        snapshot.push_back(SnapshotEntry{
            CanonicalPathKeyFromNormalizedPath(inode.full_path),
            &inode,
            ShouldPersistCommittedInodeFullPath(inode),
        });
    }

    std::sort(snapshot.begin(), snapshot.end(), [](const SnapshotEntry& lhs, const SnapshotEntry& rhs)
    {
        if (lhs.path_key == rhs.path_key)
        {
            return lhs.inode->object_id < rhs.inode->object_id;
        }
        return lhs.path_key < rhs.path_key;
    });

    committed_inode_order_cache_.clear();
    committed_inode_order_cache_.reserve(snapshot.size());
    constexpr std::size_t kInodeCheckpointHeaderBytes = kCheckpointHeaderBytes;
    constexpr std::size_t kInodeCheckpointRecordFixedBytes = 60;
    std::size_t required_bytes = kInodeCheckpointHeaderBytes;
    bool required_bytes_valid = true;
    for (const auto& item : snapshot)
    {
        const auto name_bytes = item.inode == nullptr
            ? 0
            : item.inode->name.size() * sizeof(wchar_t);
        const auto path_bytes = item.inode != nullptr && item.persist_full_path
            ? item.inode->full_path.size() * sizeof(wchar_t)
            : 0;
        std::size_t serialized_record_bytes = 0;
        if (item.inode == nullptr ||
            path_bytes > (std::numeric_limits<std::size_t>::max() - kInodeCheckpointRecordFixedBytes) ||
            name_bytes > (std::numeric_limits<std::size_t>::max() - kInodeCheckpointRecordFixedBytes - path_bytes))
        {
            required_bytes_valid = false;
        }
        else
        {
            serialized_record_bytes = kInodeCheckpointRecordFixedBytes + name_bytes + path_bytes;
        }
        committed_inode_order_cache_.push_back(CommittedInodeOrderEntry{
            item.inode == nullptr ? 0 : item.inode->object_id,
            item.path_key,
            item.inode,
            item.persist_full_path,
            serialized_record_bytes,
        });
        if (item.inode == nullptr)
        {
            required_bytes_valid = false;
            continue;
        }

        if (serialized_record_bytes == 0 ||
            required_bytes > (std::numeric_limits<std::size_t>::max() - serialized_record_bytes))
        {
            required_bytes_valid = false;
        }
        else
        {
            required_bytes += serialized_record_bytes;
        }
    }
    committed_inode_order_cache_valid_ = true;
    committed_inode_order_cache_generation_ = committed_inode_order_generation_;
    committed_inode_checkpoint_required_bytes_cache_ = required_bytes_valid
        ? std::optional<std::size_t>{required_bytes}
        : std::nullopt;
    inode_checkpoint_order_rebuild_count_.fetch_add(1, std::memory_order_relaxed);
    return &committed_inode_order_cache_;
}

bool MetadataStore::TryUpdateCommittedInodeOrderCacheForObject(
    std::uint64_t object_id,
    const std::wstring* previous_path_key,
    const std::wstring* current_path_key) const
{
    const auto fallback = [&]()
    {
        inode_checkpoint_order_delta_fallback_count_.fetch_add(1, std::memory_order_relaxed);
        return false;
    };
    if (object_id == 0 ||
        !committed_inode_order_cache_valid_ ||
        committed_inode_order_cache_generation_ != committed_inode_order_generation_)
    {
        return fallback();
    }

    const auto find_entry = [&](const std::wstring& path_key)
    {
        const auto lower = std::lower_bound(
            committed_inode_order_cache_.begin(),
            committed_inode_order_cache_.end(),
            std::make_pair(&path_key, object_id),
            [](const CommittedInodeOrderEntry& entry, const std::pair<const std::wstring*, std::uint64_t>& key)
            {
                if (entry.path_key == *key.first)
                {
                    return entry.object_id < key.second;
                }
                return entry.path_key < *key.first;
            });
        if (lower != committed_inode_order_cache_.end() &&
            lower->object_id == object_id &&
            lower->path_key == path_key)
        {
            return lower;
        }
        return committed_inode_order_cache_.end();
    };

    auto erase_it = committed_inode_order_cache_.end();
    if (previous_path_key != nullptr && !previous_path_key->empty())
    {
        erase_it = find_entry(*previous_path_key);
        if (erase_it == committed_inode_order_cache_.end())
        {
            return fallback();
        }
    }

    std::optional<CommittedInodeOrderEntry> inserted_entry;
    if (current_path_key != nullptr && !current_path_key->empty())
    {
        auto inode_it = committed_inodes_.find(object_id);
        if (inode_it == committed_inodes_.end() ||
            CanonicalPathKeyFromNormalizedPath(inode_it->second.full_path) != *current_path_key)
        {
            return fallback();
        }

        constexpr std::size_t kInodeCheckpointRecordFixedBytes = 60;
        const auto persist_full_path = ShouldPersistCommittedInodeFullPath(inode_it->second);
        const auto name_bytes = inode_it->second.name.size() * sizeof(wchar_t);
        const auto path_bytes = persist_full_path
            ? inode_it->second.full_path.size() * sizeof(wchar_t)
            : 0;
        if (path_bytes > (std::numeric_limits<std::size_t>::max() - kInodeCheckpointRecordFixedBytes) ||
            name_bytes > (std::numeric_limits<std::size_t>::max() - kInodeCheckpointRecordFixedBytes - path_bytes))
        {
            return fallback();
        }
        inserted_entry = CommittedInodeOrderEntry{
            object_id,
            *current_path_key,
            &inode_it->second,
            persist_full_path,
            kInodeCheckpointRecordFixedBytes + name_bytes + path_bytes,
        };
    }

    auto required_bytes_cache = committed_inode_checkpoint_required_bytes_cache_;
    if (required_bytes_cache.has_value() &&
        erase_it != committed_inode_order_cache_.end())
    {
        if (required_bytes_cache.value() < erase_it->serialized_record_bytes)
        {
            required_bytes_cache.reset();
        }
        else
        {
            required_bytes_cache = required_bytes_cache.value() - erase_it->serialized_record_bytes;
        }
    }
    if (required_bytes_cache.has_value() &&
        inserted_entry.has_value())
    {
        if (required_bytes_cache.value() >
            (std::numeric_limits<std::size_t>::max() - inserted_entry->serialized_record_bytes))
        {
            required_bytes_cache.reset();
        }
        else
        {
            required_bytes_cache = required_bytes_cache.value() + inserted_entry->serialized_record_bytes;
        }
    }

    if (erase_it != committed_inode_order_cache_.end())
    {
        committed_inode_order_cache_.erase(erase_it);
    }
    if (inserted_entry.has_value())
    {
        const auto insert_at = std::lower_bound(
            committed_inode_order_cache_.begin(),
            committed_inode_order_cache_.end(),
            *inserted_entry,
            [](const CommittedInodeOrderEntry& lhs, const CommittedInodeOrderEntry& rhs)
            {
                if (lhs.path_key == rhs.path_key)
                {
                    return lhs.object_id < rhs.object_id;
                }
                return lhs.path_key < rhs.path_key;
            });
        committed_inode_order_cache_.insert(insert_at, *inserted_entry);
    }

    committed_inode_checkpoint_required_bytes_cache_ = required_bytes_cache;
    committed_inode_order_cache_generation_ = ++committed_inode_order_generation_;
    inode_checkpoint_order_delta_update_count_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

std::optional<std::size_t> MetadataStore::CommittedInodeCheckpointRequiredBytesFromCache() const
{
    if (!committed_inode_order_cache_valid_ ||
        committed_inode_order_cache_generation_ != committed_inode_order_generation_)
    {
        return std::nullopt;
    }

    return committed_inode_checkpoint_required_bytes_cache_;
}

bool MetadataStore::ShouldPersistCommittedInodeFullPath(const InodeRecord& inode) const
{
    if (IsRootPath(inode.full_path))
    {
        return false;
    }

    auto parent_it = committed_inodes_.find(inode.parent_object_id);
    if (parent_it == committed_inodes_.end())
    {
        return true;
    }

    auto reconstructed_path = parent_it->second.full_path;
    if (!IsRootPath(reconstructed_path))
    {
        reconstructed_path.push_back(L'\\');
    }
    reconstructed_path.append(inode.name);
    reconstructed_path = NormalizePath(reconstructed_path);
    return reconstructed_path != inode.full_path;
}

void MetadataStore::RefreshCanonicalGateState() const
{
    production_canonical_path_active_ = false;

    if (!canonical_state_loaded_)
    {
        last_canonical_gate_failure_ = L"CanonicalStateNotLoaded";
        return;
    }

    if (recovery_required_)
    {
        last_canonical_gate_failure_ = recovery_reason_.empty()
            ? std::wstring(L"RecoveryRequired")
            : recovery_reason_;
        return;
    }

    if (!native_write_ready_ || !IsNativeWriteReady())
    {
        last_canonical_gate_failure_ = L"NativeWriteNotReady";
        return;
    }

    if (!write_device_allowed_)
    {
        last_canonical_gate_failure_ = L"WriteDeviceNotAllowed";
        return;
    }

    if (!commit_path_ready_ || !IsCommitPathReady())
    {
        last_canonical_gate_failure_ = L"CommitPathNotReady";
        return;
    }

    if (legacy_fixture_fallback_used_)
    {
        last_canonical_gate_failure_ = L"FixtureLegacyFallbackActive";
        return;
    }

    if (uses_scaffold_commit_blob_)
    {
        last_canonical_gate_failure_ = L"ScaffoldCommitBlobActive";
        return;
    }

    if (!canonical_commit_ready_)
    {
        last_canonical_gate_failure_ = L"CanonicalCommitNotReady";
        return;
    }

    production_canonical_path_active_ = true;
    last_canonical_gate_failure_.clear();
}

bool MetadataStore::IsCanonicalCommitReady() const noexcept
{
    RefreshCanonicalGateState();
    return production_canonical_path_active_;
}

bool MetadataStore::IsProductionCanonicalPathActive() const noexcept
{
    RefreshCanonicalGateState();
    return production_canonical_path_active_;
}

std::wstring MetadataStore::LastCanonicalGateFailure() const
{
    RefreshCanonicalGateState();
    return last_canonical_gate_failure_;
}

std::string MetadataStore::LastCommitStage() const
{
    return last_commit_stage_;
}

std::wstring MetadataStore::LastCommitFailureReason() const
{
    return last_commit_failure_reason_;
}

std::wstring MetadataStore::LastCommitFailureDetail() const
{
    return last_commit_failure_detail_;
}

std::optional<std::uint64_t> MetadataStore::LastCommitFailureObjectId() const noexcept
{
    return last_commit_failure_object_id_;
}

std::string MetadataStore::LastReplayStage() const
{
    return last_replay_stage_;
}

std::string MetadataStore::LastCommitBlobMagic() const
{
    return last_commit_blob_magic_;
}

void MetadataStore::RecordIntegrityFailure(std::wstring reason, std::uint64_t object_id) const
{
    if (last_integrity_failure_reason_.empty())
    {
        last_integrity_failure_reason_ = reason.empty() ? L"Unknown" : std::move(reason);
        last_integrity_failure_object_id_ = object_id == 0
            ? std::nullopt
            : std::optional<std::uint64_t>(object_id);
    }

    TraceIntegrityFailure(last_integrity_failure_reason_, object_id);
}

std::wstring MetadataStore::ResolveIntegrityCheckFailureRecoveryReason() const
{
    if (!_wcsicmp(last_integrity_failure_reason_.c_str(), L"MissingAllocation"))
    {
        return L"IntegrityMissingAllocationMap";
    }

    return L"IntegrityCheckFailedOnMount";
}

bool MetadataStore::LastReplayCheckpointCandidatePresent() const noexcept
{
    return last_replay_checkpoint_candidate_present_;
}

bool MetadataStore::LastReplayCheckpointPendingWindow() const noexcept
{
    return last_replay_checkpoint_pending_window_;
}

MetadataStore::NativeWriteCommitModel MetadataStore::ActiveCommitModel() const noexcept
{
    // Commit model reports the active commit-blob format, independent of
    // readiness. Readiness/canonical gate state is exposed separately.
    return uses_scaffold_commit_blob_
        ? NativeWriteCommitModel::ScaffoldCheckpoint
        : NativeWriteCommitModel::CanonicalApfsCheckpoint;
}

MetadataStore::NativeWriteValidationState MetadataStore::ValidationState() const noexcept
{
    if (!native_write_ready_ || recovery_required_)
    {
        return NativeWriteValidationState::Scaffold;
    }

    if (legacy_fixture_fallback_used_ || !canonical_state_loaded_)
    {
        return NativeWriteValidationState::Scaffold;
    }

    if (!IsLikelyRawDevicePath(context_.device_path))
    {
        return NativeWriteValidationState::CanonicalImageValidated;
    }

    if (context_.allow_raw_physical_write)
    {
        return NativeWriteValidationState::HardwarePilotValidated;
    }

    return NativeWriteValidationState::CanonicalImageValidated;
}

bool MetadataStore::IsFixtureLegacyFallbackActive() const noexcept
{
    return legacy_fixture_fallback_used_;
}

bool MetadataStore::IsFixtureCompatibilityPathActive() const noexcept
{
    // Fixture compatibility path activity is fixture-scoped. Non-fixture media can
    // still surface scaffold telemetry via UsesScaffoldCommitBlob(), but should not
    // be reported as "fixture compatibility path active".
    return legacy_fixture_fallback_used_ ||
           (uses_scaffold_commit_blob_ && IsLegacyFixtureFallbackAllowedForCurrentContext());
}

bool MetadataStore::UsesScaffoldCommitBlob() const noexcept
{
    return uses_scaffold_commit_blob_;
}

bool MetadataStore::IsRecoveryRequired() const noexcept
{
    return recovery_required_;
}

std::wstring MetadataStore::RecoveryReason() const
{
    return recovery_reason_;
}

std::wstring MetadataStore::LastIntegrityFailureReason() const
{
    return last_integrity_failure_reason_;
}

std::wstring MetadataStore::LastMutationFailureReason() const
{
    return last_mutation_failure_reason_;
}

std::optional<std::uint64_t> MetadataStore::LastIntegrityFailureObjectId() const noexcept
{
    return last_integrity_failure_object_id_;
}

MetadataStore::MutationStatus MetadataStore::StageMutation(
    const MutationRequest& request,
    PayloadIdentity* out_staged_payload_identity)
{
    return ApplyMutation(request, out_staged_payload_identity);
}

void MetadataStore::SyncWorkingStateFromCommitted()
{
    working_inodes_ = committed_inodes_;
    working_path_index_ = committed_path_index_;
    working_directory_links_ = committed_directory_links_;
    working_read_extents_ = committed_read_extents_;
    working_spaceman_free_extents_ = committed_spaceman_free_extents_;
    working_free_extents_sanitized_ = false;
    working_next_ephemeral_extent_ = next_ephemeral_extent_;
    RebuildWorkingDirectoryIndexes();
}

MetadataStore::MutationStatus MetadataStore::RejectMutation(std::wstring reason)
{
    last_mutation_failure_reason_ = reason.empty() ? L"Unknown" : std::move(reason);
    return MutationStatus::InvalidRequest;
}

void MetadataStore::MarkRecoveryRequired(std::wstring reason)
{
    recovery_required_ = true;
    recovery_reason_ = reason.empty() ? L"RecoveryRequired" : std::move(reason);
    commit_path_ready_ = false;
}

void MetadataStore::ClearRecoveryRequired()
{
    recovery_required_ = false;
    recovery_reason_.clear();
    commit_path_ready_ = native_write_ready_ && write_device_allowed_;
}

struct MetadataStore::ScopedPerfTimer
{
    PerfCounter& counter;
    std::chrono::steady_clock::time_point started{};
    bool enabled = false;

    explicit ScopedPerfTimer(PerfCounter& perf_counter) noexcept
        : counter(perf_counter)
        , enabled(IsPerfCountersEnabled())
    {
        if (enabled)
        {
            started = std::chrono::steady_clock::now();
        }
    }

    ~ScopedPerfTimer()
    {
        if (enabled)
        {
            counter.Observe(ElapsedMicroseconds(started));
        }
    }
};

void MetadataStore::PerfCounter::Observe(std::uint64_t elapsed_us) noexcept
{
    count.fetch_add(1, std::memory_order_relaxed);
    total_us.fetch_add(elapsed_us, std::memory_order_relaxed);
    last_us.store(elapsed_us, std::memory_order_relaxed);

    auto current_max = max_us.load(std::memory_order_relaxed);
    while (elapsed_us > current_max &&
           !max_us.compare_exchange_weak(current_max, elapsed_us, std::memory_order_relaxed))
    {
    }
}

std::string MetadataStore::PerformanceJson() const
{
    const auto append_counter = [](std::ostringstream& buffer, const char* name, const PerfCounter& counter)
    {
        const auto count = counter.count.load(std::memory_order_relaxed);
        const auto total_us = counter.total_us.load(std::memory_order_relaxed);
        const auto max_us = counter.max_us.load(std::memory_order_relaxed);
        const auto last_us = counter.last_us.load(std::memory_order_relaxed);
        buffer << "\"" << name << "\":{\"count\":" << count
               << ",\"totalUs\":" << total_us
               << ",\"maxUs\":" << max_us
               << ",\"lastUs\":" << last_us
               << "}";
    };

    std::ostringstream buffer;
    buffer << "{";
    append_counter(buffer, "applyMutation", apply_mutation_perf_);
    buffer << ",";
    append_counter(buffer, "commitPending", commit_pending_perf_);
    buffer << ",";
    append_counter(buffer, "commitTransaction", commit_transaction_perf_);
    buffer << ",";
    append_counter(buffer, "commitCanonical", commit_canonical_perf_);
    buffer << ",";
    append_counter(buffer, "validateInodeGraph", validate_inode_graph_perf_);
    buffer << ",";
    append_counter(buffer, "snapshotCommittedInodes", snapshot_committed_inodes_perf_);
    buffer << ",";
    append_counter(buffer, "readCommittedRange", read_committed_range_perf_);
    buffer << ",";
    append_counter(buffer, "allocationLookup", allocation_lookup_perf_);
    buffer << ",";
    append_counter(buffer, "freeListLookup", free_list_lookup_perf_);
    buffer << ",";
    append_counter(buffer, "buildCommitBlob", build_commit_blob_perf_);
    buffer << ",\"commitBlobReserve\":{\"precise\":"
           << commit_blob_precise_reserve_count_.load(std::memory_order_relaxed)
           << ",\"fallback\":"
           << commit_blob_reserve_fallback_count_.load(std::memory_order_relaxed)
           << ",\"directFill\":"
           << commit_blob_direct_fill_count_.load(std::memory_order_relaxed)
           << "},";
    append_counter(buffer, "persistObjectMapCheckpoint", persist_object_map_checkpoint_perf_);
    buffer << ",";
    append_counter(buffer, "persistSpacemanCheckpoint", persist_spaceman_checkpoint_perf_);
    buffer << ",";
    append_counter(buffer, "persistInodeCheckpoint", persist_inode_checkpoint_perf_);
    buffer << ",";
    append_counter(buffer, "persistBtreeCheckpoint", persist_btree_checkpoint_perf_);
    buffer << ",";
    append_counter(buffer, "persistReplayCheckpoint", persist_replay_checkpoint_perf_);
    buffer << ",";
    append_counter(buffer, "persistSuperblockCheckpoint", persist_superblock_checkpoint_perf_);
    buffer << ",";
    append_counter(buffer, "takeLastCommittedInodeChanges", take_last_committed_inode_changes_perf_);
    buffer << ",\"pendingWriteCoalesce\":{\"scans\":"
           << pending_write_coalesce_scan_count_.load(std::memory_order_relaxed)
           << ",\"trackedObjects\":" << pending_write_object_ids_.size()
           << "}";
    buffer << ",\"pendingBasicInfoCoalesce\":{\"pathFallbacks\":"
           << pending_basic_info_coalesce_path_fallback_count_.load(std::memory_order_relaxed)
           << ",\"trackedObjects\":" << pending_basic_info_mutation_index_by_object_id_.size()
           << "}";
    buffer << ",\"pendingSetFileSizeCoalesce\":{\"pathFallbacks\":"
           << pending_set_file_size_coalesce_path_fallback_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"pendingRenamePathKeyCache\":{\"hits\":"
           << pending_rename_path_key_cache_hit_count_.load(std::memory_order_relaxed)
           << ",\"misses\":"
           << pending_rename_path_key_cache_miss_count_.load(std::memory_order_relaxed)
           << ",\"trackedMutations\":" << pending_mutation_path_key_cache_.size()
           << "}";
    buffer << ",\"directoryRenameDescendants\":{\"pathLookups\":"
           << directory_rename_descendant_path_lookup_count_.load(std::memory_order_relaxed)
           << ",\"directoryLinkUpdates\":"
           << directory_rename_descendant_directory_link_update_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"pendingPayloadRename\":{\"pathScans\":"
           << pending_payload_rename_path_scan_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"pendingPayloadDelete\":{\"pathScans\":"
           << pending_payload_delete_path_scan_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"pendingPayloadSummary\":{\"pathScans\":"
           << pending_payload_summary_path_scan_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"pendingPayloadPathOrder\":{\"builds\":"
           << pending_payload_path_order_build_count_.load(std::memory_order_relaxed)
           << ",\"trackedPaths\":" << pending_payload_path_keys_.size()
           << ",\"orderedPaths\":" << pending_payload_path_key_order_.size()
           << ",\"valid\":" << (pending_payload_path_key_order_valid_ ? "true" : "false")
           << "}";
    buffer << ",\"pendingPayloadObjectOrder\":{\"orderedIterations\":"
           << pending_payload_object_order_iteration_count_.load(std::memory_order_relaxed)
           << ",\"compactions\":"
           << pending_payload_object_order_compaction_count_.load(std::memory_order_relaxed)
           << ",\"trackedObjects\":" << pending_payload_object_order_.size()
           << "}";
    buffer << ",\"pendingObjectMapUpdateIndex\":{\"scans\":"
           << pending_object_map_update_scan_count_.load(std::memory_order_relaxed)
           << ",\"trackedObjects\":" << pending_object_map_update_index_.size()
           << "}";
    buffer << ",\"pendingBtreeFileMetadataIndex\":{\"fallbackScans\":"
           << pending_btree_file_metadata_scan_count_.load(std::memory_order_relaxed)
           << ",\"rebuilds\":" << pending_btree_file_metadata_rebuild_count_.load(std::memory_order_relaxed)
           << ",\"localErases\":" << pending_btree_file_metadata_local_erase_count_.load(std::memory_order_relaxed)
           << ",\"touchedInodeIndexReuse\":"
           << pending_btree_touched_inode_index_reuse_count_.load(std::memory_order_relaxed)
           << ",\"touchedInodeFallbackScans\":"
           << pending_btree_touched_inode_fallback_scan_count_.load(std::memory_order_relaxed)
           << ",\"touchedInodeDedupeFastPaths\":"
           << commit_touched_inode_dedupe_fast_path_count_.load(std::memory_order_relaxed)
           << ",\"touchedInodeSortFallbacks\":"
           << commit_touched_inode_sort_fallback_count_.load(std::memory_order_relaxed)
           << ",\"trackedTouchedInodes\":" << pending_btree_inode_record_count_by_object_.size()
           << ",\"trackedInodes\":" << pending_btree_file_inode_index_.size()
           << ",\"trackedExtents\":" << pending_btree_file_extent_index_.size()
           << ",\"trackedExtentObjects\":" << pending_btree_file_extent_offsets_by_object_.size()
           << ",\"trackedExtentRecordObjects\":" << pending_btree_file_extent_record_count_by_object_.size()
           << ",\"trackedDirectoryChildren\":" << pending_btree_directory_record_count_by_child_object_.size()
           << ",\"tombstones\":" << pending_btree_tombstone_record_count_
           << ",\"directoryInodes\":" << pending_btree_directory_inode_record_count_
           << ",\"untrackedRecords\":" << pending_btree_untracked_record_count_
           << "}";
    buffer << ",\"pendingCloseDelaySummary\":{\"rebuilds\":"
           << pending_close_delay_summary_rebuild_count_.load(std::memory_order_relaxed)
           << ",\"createdFiles\":" << pending_close_delay_created_file_object_ids_.size()
           << ",\"writes\":" << pending_close_delay_write_count_
           << ",\"payloadWrites\":" << pending_close_delay_payload_write_count_
           << ",\"metadataOnly\":" << pending_close_delay_metadata_only_count_
           << ",\"mixedValid\":" << (pending_close_delay_mixed_valid_ ? "true" : "false")
           << ",\"continueValid\":" << (pending_close_delay_continue_valid_ ? "true" : "false")
           << "}";
    buffer << ",\"freeExtentSanitize\":{\"working\":"
           << working_free_extent_sanitize_count_.load(std::memory_order_relaxed)
           << ",\"workingSkipped\":"
           << working_free_extent_sanitize_skip_count_.load(std::memory_order_relaxed)
           << ",\"full\":"
           << free_extent_sanitize_count_.load(std::memory_order_relaxed)
           << ",\"skipped\":" << free_extent_sanitize_skip_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"commitRestoreDedupe\":{\"linearScans\":"
           << commit_restore_dedupe_linear_scan_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"mutationRestoreDedupe\":{\"hashFastPaths\":"
           << mutation_restore_dedupe_hash_fast_path_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"committedDirectoryLinkIndex\":{\"rebuilds\":"
           << committed_directory_link_index_rebuild_count_.load(std::memory_order_relaxed)
           << ",\"trackedLinks\":" << committed_directory_link_index_.size()
           << "}";
    buffer << ",\"committedBtreeIndex\":{\"rebuilds\":"
           << committed_btree_index_rebuild_count_.load(std::memory_order_relaxed)
           << ",\"trackedRecords\":" << committed_btree_index_by_key_.size()
           << ",\"trackedInodes\":" << committed_btree_inode_key_by_object_id_.size()
           << "}";
    buffer << ",\"commitBtreeRollback\":{\"fullSnapshots\":"
           << commit_btree_full_snapshot_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"commitPreflight\":{\"inodeGraphSkips\":"
           << commit_inode_graph_validation_skip_count_.load(std::memory_order_relaxed)
           << ",\"projectedBtreeStateSkips\":"
           << commit_projected_btree_validation_skip_count_.load(std::memory_order_relaxed)
           << ",\"freshIngestOverlayOnly\":"
           << commit_fresh_ingest_overlay_preflight_count_.load(std::memory_order_relaxed)
           << ",\"fullObjectSweeps\":"
           << commit_full_object_preflight_sweep_count_.load(std::memory_order_relaxed)
           << ",\"objectMapIndexLookups\":"
           << commit_object_map_preflight_index_lookup_count_.load(std::memory_order_relaxed)
           << ",\"freshIngestPhysicalOrderFastPaths\":"
           << commit_fresh_ingest_physical_order_fast_path_count_.load(std::memory_order_relaxed)
           << ",\"freshIngestPhysicalSetFallbacks\":"
           << commit_fresh_ingest_physical_set_fallback_count_.load(std::memory_order_relaxed)
           << ",\"freshIngestMappingRecheckSkips\":"
           << commit_fresh_ingest_mapping_recheck_skip_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"pendingAllocationValidation\":{\"sortedPasses\":"
           << pending_allocation_validation_sorted_count_.load(std::memory_order_relaxed)
           << ",\"fallbackScans\":"
           << pending_allocation_validation_fallback_scan_count_.load(std::memory_order_relaxed)
           << ",\"committedSortedReuse\":"
           << pending_allocation_validation_committed_sorted_reuse_count_.load(std::memory_order_relaxed)
           << ",\"committedIndexFallbacks\":"
           << pending_allocation_validation_committed_index_fallback_count_.load(std::memory_order_relaxed)
           << ",\"pendingSortedReuse\":"
           << pending_allocation_validation_pending_sorted_reuse_count_.load(std::memory_order_relaxed)
           << ",\"pendingIndexReuse\":"
           << pending_allocation_validation_pending_index_reuse_count_.load(std::memory_order_relaxed)
           << ",\"pendingSortFallbacks\":"
           << pending_allocation_validation_pending_sort_fallback_count_.load(std::memory_order_relaxed)
           << ",\"commitExtentFast\":"
           << commit_extent_fast_validation_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"projectedSpacemanValidation\":{\"fast\":"
           << projected_spaceman_validation_fast_count_.load(std::memory_order_relaxed)
           << ",\"full\":"
           << projected_spaceman_validation_full_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"commitExtentRollback\":{\"workingFreeSnapshots\":"
           << commit_extent_working_free_snapshot_count_.load(std::memory_order_relaxed)
           << ",\"workingFreeLocalRollbacks\":"
           << commit_extent_working_free_local_rollback_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"mutationWorkingFreeRollback\":{\"workingFreeSnapshots\":"
           << mutation_working_free_snapshot_count_.load(std::memory_order_relaxed)
           << ",\"workingFreeLocalUndos\":"
           << mutation_working_free_local_undo_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"pendingSpacemanAllocationIndex\":{\"rebuilds\":"
           << pending_spaceman_allocation_index_rebuild_count_.load(std::memory_order_relaxed)
           << ",\"localErases\":"
           << pending_spaceman_allocation_index_local_erase_count_.load(std::memory_order_relaxed)
           << ",\"localResizes\":"
           << pending_spaceman_allocation_index_local_resize_count_.load(std::memory_order_relaxed)
           << ",\"trackedAllocations\":" << pending_spaceman_allocation_index_.size()
           << "}";
    buffer << ",\"chunkedCheckpointSelection\":{\"attempts\":"
           << chunked_checkpoint_selection_count_.load(std::memory_order_relaxed)
           << ",\"indexedWritableChecks\":"
           << checkpoint_slot_validation_indexed_count_.load(std::memory_order_relaxed)
           << ",\"fallbackWritableChecks\":"
           << checkpoint_slot_validation_fallback_scan_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"checkpointBlockIndices\":{\"cacheHits\":"
           << checkpoint_block_index_cache_hit_count_.load(std::memory_order_relaxed)
           << ",\"cacheBuilds\":"
           << checkpoint_block_index_cache_build_count_.load(std::memory_order_relaxed)
           << ",\"bypassBuilds\":"
           << checkpoint_block_index_cache_bypass_build_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"checkpointFamilyBatch\":{\"count\":"
           << checkpoint_family_batch_count_.load(std::memory_order_relaxed)
           << ",\"writes\":" << checkpoint_family_batch_write_count_.load(std::memory_order_relaxed)
           << "}";
    const auto checkpoint_serialization_capacity =
        static_cast<std::uint64_t>(object_map_checkpoint_serialization_buffer_.capacity()) +
        static_cast<std::uint64_t>(spaceman_checkpoint_serialization_buffer_.capacity()) +
        static_cast<std::uint64_t>(inode_checkpoint_serialization_buffer_.capacity()) +
        static_cast<std::uint64_t>(btree_checkpoint_serialization_buffer_.capacity()) +
        static_cast<std::uint64_t>(replay_checkpoint_serialization_buffer_.capacity());
    buffer << ",\"checkpointSerializationBuffers\":{\"growths\":"
           << checkpoint_serialization_buffer_growth_count_.load(std::memory_order_relaxed)
           << ",\"reuses\":"
           << checkpoint_serialization_buffer_reuse_count_.load(std::memory_order_relaxed)
           << ",\"capacityBytes\":" << checkpoint_serialization_capacity
           << "}";
    buffer << ",\"checkpointWritePadding\":{\"pads\":"
           << checkpoint_write_pad_count_.load(std::memory_order_relaxed)
           << ",\"padBytes\":" << checkpoint_write_pad_bytes_.load(std::memory_order_relaxed)
           << ",\"partialMaterializations\":"
           << checkpoint_write_partial_materialization_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"preparedPayloadRangeWrites\":{\"singleExtentDirect\":"
           << prepared_payload_single_extent_direct_write_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"committedSingleExtentReadFastPath\":{\"count\":"
           << committed_single_extent_read_fast_path_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"committedReadExtentSnapshotCache\":{\"hits\":"
           << committed_read_extent_snapshot_cache_hit_count_.load(std::memory_order_relaxed)
           << ",\"misses\":"
           << committed_read_extent_snapshot_cache_miss_count_.load(std::memory_order_relaxed)
           << ",\"entries\":"
           << committed_read_extent_snapshot_cache_.size()
           << ",\"bytes\":"
           << committed_read_extent_snapshot_cache_bytes_
           << "}";
    buffer << ",\"payloadWriteAlignment\":{\"tailZeroPads\":"
           << payload_tail_zero_pad_count_.load(std::memory_order_relaxed)
           << ",\"tailZeroPadBytes\":"
           << payload_tail_zero_pad_bytes_.load(std::memory_order_relaxed)
           << ",\"rangeMaterializedChunks\":"
           << payload_range_materialized_chunk_count_.load(std::memory_order_relaxed)
           << ",\"rangeMaterializedChunkBytes\":"
           << payload_range_materialized_chunk_bytes_.load(std::memory_order_relaxed)
           << ",\"rangeMaterializedBufferResizes\":"
           << payload_range_materialized_buffer_resize_count_.load(std::memory_order_relaxed)
           << ",\"rangeMaterializedBufferReuses\":"
           << payload_range_materialized_buffer_reuse_count_.load(std::memory_order_relaxed)
           << ",\"windowBatches\":"
           << payload_window_batch_count_.load(std::memory_order_relaxed)
           << ",\"windowBatchBytes\":"
           << payload_window_batch_bytes_.load(std::memory_order_relaxed)
           << ",\"orderedFastPaths\":"
           << pending_payload_write_order_fast_count_.load(std::memory_order_relaxed)
           << ",\"sorts\":"
           << pending_payload_write_sort_count_.load(std::memory_order_relaxed)
           << ",\"writeViewReserveExtraPasses\":"
           << pending_payload_write_reserve_extra_pass_count_.load(std::memory_order_relaxed)
           << ",\"writeViewReserveExtraEntries\":"
           << pending_payload_write_reserve_extra_entry_count_.load(std::memory_order_relaxed)
           << ",\"coalesceInPlacePasses\":"
           << pending_payload_write_coalesce_in_place_count_.load(std::memory_order_relaxed)
           << ",\"coalescedEntries\":"
           << pending_payload_write_coalesced_entry_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"pendingPayloadRanges\":{\"localMerges\":"
           << pending_payload_range_local_merge_count_.load(std::memory_order_relaxed)
           << ",\"fullMerges\":"
           << pending_payload_range_full_merge_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"committedSpacemanApply\":{\"full\":"
           << committed_spaceman_apply_count_.load(std::memory_order_relaxed)
           << ",\"local\":" << committed_spaceman_apply_local_count_.load(std::memory_order_relaxed)
           << ",\"freeFull\":"
           << committed_spaceman_free_apply_count_.load(std::memory_order_relaxed)
           << ",\"freeLocal\":"
           << committed_spaceman_free_apply_local_count_.load(std::memory_order_relaxed)
           << ",\"freeLocalInPlace\":"
           << committed_spaceman_free_apply_in_place_count_.load(std::memory_order_relaxed)
           << ",\"freeFullVerifies\":"
           << committed_spaceman_free_verify_full_count_.load(std::memory_order_relaxed)
           << ",\"freeFullVerifySkips\":"
           << committed_spaceman_free_verify_skip_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"committedSpacemanRollback\":{\"fullSnapshots\":"
           << committed_spaceman_full_snapshot_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"spacemanCheckpoint\":{\"fastPath\":"
           << spaceman_checkpoint_fast_path_count_.load(std::memory_order_relaxed)
           << ",\"normalizeFallback\":"
           << spaceman_checkpoint_normalize_fallback_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"objectMapCheckpoint\":{\"orderRebuilds\":"
           << object_map_checkpoint_order_rebuild_count_.load(std::memory_order_relaxed)
           << ",\"orderCacheHits\":"
           << object_map_checkpoint_order_cache_hit_count_.load(std::memory_order_relaxed)
           << ",\"orderDeltaUpdates\":"
           << object_map_checkpoint_order_delta_update_count_.load(std::memory_order_relaxed)
           << ",\"orderDeltaFallbacks\":"
           << object_map_checkpoint_order_delta_fallback_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"inodeCheckpoint\":{\"orderRebuilds\":"
           << inode_checkpoint_order_rebuild_count_.load(std::memory_order_relaxed)
           << ",\"orderCacheHits\":"
           << inode_checkpoint_order_cache_hit_count_.load(std::memory_order_relaxed)
           << ",\"orderDeltaUpdates\":"
           << inode_checkpoint_order_delta_update_count_.load(std::memory_order_relaxed)
           << ",\"orderDeltaFallbacks\":"
           << inode_checkpoint_order_delta_fallback_count_.load(std::memory_order_relaxed)
           << ",\"sizeCacheHits\":"
           << inode_checkpoint_size_cache_hit_count_.load(std::memory_order_relaxed)
           << "}";
    buffer << ",\"btreeCheckpoint\":{\"sizePreScans\":"
           << btree_checkpoint_size_prescan_count_.load(std::memory_order_relaxed)
           << "}";
    const auto checkpoint_delta_shadow_bytes =
        checkpoint_delta_shadow_bytes_.load(std::memory_order_relaxed);
    const auto checkpoint_delta_shadow_full_bytes =
        checkpoint_delta_shadow_full_bytes_.load(std::memory_order_relaxed);
    buffer << ",\"checkpointDeltaShadow\":{\"count\":"
           << checkpoint_delta_shadow_count_.load(std::memory_order_relaxed)
           << ",\"records\":" << checkpoint_delta_shadow_record_count_.load(std::memory_order_relaxed)
           << ",\"bytes\":" << checkpoint_delta_shadow_bytes
           << ",\"fullCheckpointBytes\":" << checkpoint_delta_shadow_full_bytes
           << ",\"ratioTimes1000\":"
           << (checkpoint_delta_shadow_full_bytes == 0
               ? 0
               : (checkpoint_delta_shadow_bytes * 1000) / checkpoint_delta_shadow_full_bytes)
           << "}";
    std::uint64_t committed_extent_file_count = 0;
    std::uint64_t committed_extent_count = 0;
    std::uint64_t committed_extent_bytes = 0;
    std::uint64_t committed_extent_max_per_file = 0;
    for (const auto& [_, extents] : committed_read_extents_)
    {
        if (extents.empty())
        {
            continue;
        }

        ++committed_extent_file_count;
        committed_extent_count += static_cast<std::uint64_t>(extents.size());
        committed_extent_max_per_file = std::max(
            committed_extent_max_per_file,
            static_cast<std::uint64_t>(extents.size()));
        for (const auto& extent : extents)
        {
            committed_extent_bytes += extent.bytes;
        }
    }
    const auto committed_extent_fragmentation_score =
        committed_extent_count > committed_extent_file_count
            ? committed_extent_count - committed_extent_file_count
            : 0;
    buffer << ",\"committedExtentShape\":{\"files\":" << committed_extent_file_count
           << ",\"extents\":" << committed_extent_count
           << ",\"averageExtentsPerFileTimes1000\":"
           << (committed_extent_file_count == 0
               ? 0
               : (committed_extent_count * 1000) / committed_extent_file_count)
           << ",\"fragmentationScore\":" << committed_extent_fragmentation_score
           << ",\"maxExtentsPerFile\":" << committed_extent_max_per_file
           << ",\"bytes\":" << committed_extent_bytes
           << "}";
    const auto raw_compaction_count = last_raw_mutation_count_.load(std::memory_order_relaxed);
    const auto compacted_mutation_count = last_compacted_mutation_count_.load(std::memory_order_relaxed);
    buffer << ",\"mutationCompaction\":{\"raw\":" << raw_compaction_count
           << ",\"compacted\":" << compacted_mutation_count
           << ",\"ratio\":" << (raw_compaction_count == 0
               ? 0.0
               : static_cast<double>(compacted_mutation_count) / static_cast<double>(raw_compaction_count))
           << "}";
    buffer << ",\"blockDevice\":" << device_.PerformanceJson();
    buffer << "}";
    return buffer.str();
}

MetadataStore::MutationStatus MetadataStore::ApplyMutation(
    const MutationRequest& request,
    PayloadIdentity* out_staged_payload_identity)
{
    ScopedPerfTimer perf_scope(apply_mutation_perf_);

    if (out_staged_payload_identity)
    {
        *out_staged_payload_identity = {};
    }

    const auto operation_name = [](MutationOperation operation) -> std::wstring_view
    {
        switch (operation)
        {
        case MutationOperation::CreateFile:
            return L"CreateFile";
        case MutationOperation::CreateDirectory:
            return L"CreateDirectory";
        case MutationOperation::Write:
            return L"Write";
        case MutationOperation::SetFileSize:
            return L"SetFileSize";
        case MutationOperation::Rename:
            return L"Rename";
        case MutationOperation::Delete:
            return L"Delete";
        case MutationOperation::SetBasicInfo:
            return L"SetBasicInfo";
        default:
            return L"Unknown";
        }
    };
    const auto reject = [&](std::wstring reason) -> MutationStatus
    {
        TraceMutationFailure(
            operation_name(request.operation),
            request.path,
            request.secondary_path,
            reason);
        return RejectMutation(std::move(reason));
    };

    last_mutation_failure_reason_.clear();
    if (!IsNativeWriteReady() || recovery_required_)
    {
        return MutationStatus::NotReady;
    }
    const auto normalized_path = NormalizePath(request.path);
    if (normalized_path.empty())
    {
        return reject(L"EmptyPath");
    }
    const auto path_key = CanonicalPathKeyFromNormalizedPath(normalized_path);
    std::wstring normalized_secondary;
    std::wstring secondary_key_storage;
    const std::wstring* secondary_key = nullptr;
    const auto target_xid = checkpoint_xid_ + 1;
    const bool identity_bound = request.object_id != 0 || request.generation != 0;
    if (identity_bound &&
        (request.object_id == 0 || request.generation == 0))
    {
        return reject(L"ReplayIdentityIncomplete");
    }
    const auto validate_existing_replay_identity = [&, target_xid](
        const InodeRecord& inode,
        bool generation_is_pre_mutation)
    {
        if (!identity_bound || inode.object_id != request.object_id)
        {
            return !identity_bound;
        }

        if (generation_is_pre_mutation)
        {
            const auto inode_generation = inode.xid == 0 ? inode.object_id : inode.xid;
            return inode_generation == request.generation;
        }

        return request.generation == target_xid;
    };
    const auto set_staged_identity = [&](std::uint64_t object_id, std::uint64_t generation)
    {
        if (out_staged_payload_identity)
        {
            *out_staged_payload_identity = { object_id, generation == 0 ? object_id : generation };
        }
    };
    std::optional<std::uint64_t> resolved_mutation_object_id;
    struct InodeRestoreEntry
    {
        std::uint64_t object_id = 0;
        std::optional<InodeRecord> previous;
    };
    struct PathIndexRestoreEntry
    {
        std::wstring key;
        std::optional<std::uint64_t> previous;
    };
    struct PendingObjectMapRestoreEntry
    {
        std::uint64_t object_id = 0;
        std::optional<ObjectMapUpdate> previous;
    };
    struct ReadExtentRestoreEntry
    {
        std::uint64_t object_id = 0;
        std::optional<std::vector<FileExtent>> previous_working;
        std::optional<std::vector<FileExtent>> previous_pending;
    };
    struct DirectoryLinkRestoreEntry
    {
        std::uint64_t parent_object_id = 0;
        std::wstring entry_name;
        std::optional<DirectoryLink> previous;
    };
    struct DirectoryLinkRestoreKey
    {
        std::uint64_t parent_object_id = 0;
        std::wstring entry_name;

        bool operator==(const DirectoryLinkRestoreKey& other) const noexcept
        {
            return parent_object_id == other.parent_object_id &&
                   entry_name == other.entry_name;
        }
    };
    struct DirectoryLinkRestoreKeyHash
    {
        std::size_t operator()(const DirectoryLinkRestoreKey& key) const noexcept
        {
            auto seed = std::hash<std::uint64_t>{}(key.parent_object_id);
            seed ^= std::hash<std::wstring>{}(key.entry_name) + 0x9e3779b97f4a7c15ull + (seed << 6) + (seed >> 2);
            return seed;
        }
    };
    struct PendingAllocationRestoreEntry
    {
        std::size_t index = 0;
        SpacemanAllocation allocation;
    };
    struct PendingAllocationResizeRestoreEntry
    {
        std::size_t index = 0;
        std::uint64_t previous_bytes = 0;
    };
    struct PreparedPayloadRangesRestoreEntry
    {
        std::uint64_t object_id = 0;
        std::optional<std::vector<PreparedPayloadRange>> previous;
    };
    struct PendingWrittenRangesRestoreEntry
    {
        std::uint64_t object_id = 0;
        std::optional<std::vector<PreparedPayloadRange>> previous;
    };
    struct PendingBtreeRecordRestoreEntry
    {
        std::size_t index = 0;
        BtreeRecord previous;
    };
    struct PendingBtreeRecordEraseRestoreEntry
    {
        std::size_t index = 0;
        BtreeRecord erased;
    };
    alignas(std::max_align_t) std::array<std::byte, 24 * 1024> mutation_undo_storage{};
    std::pmr::monotonic_buffer_resource mutation_undo_resource(
        mutation_undo_storage.data(),
        mutation_undo_storage.size());
    struct MutationUndoLog
    {
        std::size_t pending_mutations_size = 0;
        std::size_t pending_object_map_updates_size = 0;
        std::size_t pending_spaceman_allocations_size = 0;
        std::size_t pending_spaceman_deallocations_size = 0;
        std::size_t pending_btree_records_size = 0;
        std::uint64_t working_next_ephemeral_extent = 0;
        bool working_free_extents_sanitized = false;
        bool pending_spaceman_untracked_free_extent_delta = false;
        bool pending_spaceman_released_existing_allocation = false;
        std::pmr::vector<InodeRestoreEntry> inode_restores;
        std::pmr::vector<PathIndexRestoreEntry> path_index_restores;
        std::pmr::vector<PendingObjectMapRestoreEntry> pending_object_map_restores;
        std::pmr::vector<ReadExtentRestoreEntry> read_extent_restores;
        std::pmr::vector<DirectoryLinkRestoreEntry> directory_link_restores;
        std::pmr::vector<SpacemanAllocation> appended_pending_allocations;
        std::pmr::vector<PendingAllocationRestoreEntry> erased_pending_allocations;
        std::pmr::vector<PendingAllocationResizeRestoreEntry> resized_pending_allocations;
        std::pmr::vector<PreparedPayloadRangesRestoreEntry> prepared_payload_range_restores;
        std::pmr::vector<PendingWrittenRangesRestoreEntry> pending_written_range_restores;
        std::pmr::vector<PendingBtreeRecordRestoreEntry> pending_btree_record_restores;
        std::pmr::vector<PendingBtreeRecordEraseRestoreEntry> erased_pending_btree_records;
        std::optional<std::pmr::unordered_set<std::uint64_t>> inode_restore_ids;
        std::optional<std::pmr::unordered_set<std::wstring>> path_index_restore_keys;
        std::optional<std::pmr::unordered_set<std::uint64_t>> pending_object_map_restore_ids;
        std::optional<std::pmr::unordered_set<std::uint64_t>> read_extent_restore_ids;
        std::optional<std::pmr::unordered_set<std::uint64_t>> prepared_payload_range_restore_ids;
        std::optional<std::pmr::unordered_set<std::uint64_t>> pending_written_range_restore_ids;
        std::optional<std::pmr::unordered_set<std::size_t>> pending_btree_record_restore_indexes;
        std::optional<std::pmr::unordered_set<DirectoryLinkRestoreKey, DirectoryLinkRestoreKeyHash>> directory_link_restore_keys;
        std::pmr::vector<ExtentAllocator::ContiguousAllocationUndo> working_spaceman_allocation_undos;
        std::pmr::vector<ExtentAllocator::AddFreeExtentUndo> working_spaceman_free_extent_add_undos;
        std::optional<std::vector<SpacemanAllocation>> working_spaceman_free_extents;

        MutationUndoLog(
            std::pmr::memory_resource* resource,
            std::size_t pending_mutations_size_value,
            std::size_t pending_object_map_updates_size_value,
            std::size_t pending_spaceman_allocations_size_value,
            std::size_t pending_spaceman_deallocations_size_value,
            std::size_t pending_btree_records_size_value,
            std::uint64_t working_next_ephemeral_extent_value,
            bool working_free_extents_sanitized_value,
            bool pending_spaceman_untracked_free_extent_delta_value,
            bool pending_spaceman_released_existing_allocation_value)
            : pending_mutations_size(pending_mutations_size_value),
              pending_object_map_updates_size(pending_object_map_updates_size_value),
              pending_spaceman_allocations_size(pending_spaceman_allocations_size_value),
              pending_spaceman_deallocations_size(pending_spaceman_deallocations_size_value),
              pending_btree_records_size(pending_btree_records_size_value),
              working_next_ephemeral_extent(working_next_ephemeral_extent_value),
              working_free_extents_sanitized(working_free_extents_sanitized_value),
              pending_spaceman_untracked_free_extent_delta(pending_spaceman_untracked_free_extent_delta_value),
              pending_spaceman_released_existing_allocation(pending_spaceman_released_existing_allocation_value),
              inode_restores(resource),
              path_index_restores(resource),
              pending_object_map_restores(resource),
              read_extent_restores(resource),
              directory_link_restores(resource),
              appended_pending_allocations(resource),
              erased_pending_allocations(resource),
              resized_pending_allocations(resource),
              prepared_payload_range_restores(resource),
              pending_written_range_restores(resource),
              pending_btree_record_restores(resource),
              erased_pending_btree_records(resource),
              working_spaceman_allocation_undos(resource),
              working_spaceman_free_extent_add_undos(resource)
        {
        }
    } undo_log
    {
        &mutation_undo_resource,
        pending_mutations_.size(),
        pending_object_map_updates_.size(),
        pending_spaceman_allocations_.size(),
        pending_spaceman_deallocations_.size(),
        pending_btree_records_.size(),
        working_next_ephemeral_extent_,
        working_free_extents_sanitized_,
        pending_spaceman_untracked_free_extent_delta_,
        pending_spaceman_released_existing_allocation_,
    };
    constexpr std::size_t kMutationRestoreHashThreshold = 16;
    const auto has_restored_uint64 = [&](
        std::uint64_t value,
        auto& restore_entries,
        auto& restore_ids,
        const auto& selector)
    {
        if (restore_ids.has_value())
        {
            mutation_restore_dedupe_hash_fast_path_count_.fetch_add(1, std::memory_order_relaxed);
            return restore_ids->find(value) != restore_ids->end();
        }

        if (restore_entries.size() >= kMutationRestoreHashThreshold)
        {
            restore_ids.emplace();
            restore_ids->reserve(restore_entries.size() + 1);
            for (const auto& entry : restore_entries)
            {
                restore_ids->insert(selector(entry));
            }
            mutation_restore_dedupe_hash_fast_path_count_.fetch_add(1, std::memory_order_relaxed);
            return restore_ids->find(value) != restore_ids->end();
        }

        return std::any_of(
            restore_entries.begin(),
            restore_entries.end(),
            [&](const auto& entry) { return selector(entry) == value; });
    };
    const auto track_restored_uint64 = [&](std::uint64_t value, auto& restore_ids)
    {
        if (restore_ids.has_value())
        {
            restore_ids->insert(value);
        }
    };
    const auto remember_inode = [&](std::uint64_t object_id)
    {
        if (has_restored_uint64(
                object_id,
                undo_log.inode_restores,
                undo_log.inode_restore_ids,
                [](const InodeRestoreEntry& entry) { return entry.object_id; }))
        {
            return;
        }

        auto existing = working_inodes_.find(object_id);
        undo_log.inode_restores.push_back(
            {
                object_id,
                existing == working_inodes_.end() ? std::optional<InodeRecord>{} : existing->second,
            });
        track_restored_uint64(object_id, undo_log.inode_restore_ids);
    };
    const auto remember_path_index = [&](const std::wstring& key)
    {
        if (undo_log.path_index_restore_keys.has_value())
        {
            mutation_restore_dedupe_hash_fast_path_count_.fetch_add(1, std::memory_order_relaxed);
            if (undo_log.path_index_restore_keys->find(key) != undo_log.path_index_restore_keys->end())
            {
                return;
            }
        }
        else if (undo_log.path_index_restores.size() >= kMutationRestoreHashThreshold)
        {
            undo_log.path_index_restore_keys.emplace(&mutation_undo_resource);
            undo_log.path_index_restore_keys->reserve(undo_log.path_index_restores.size() + 1);
            for (const auto& entry : undo_log.path_index_restores)
            {
                undo_log.path_index_restore_keys->insert(entry.key);
            }
            mutation_restore_dedupe_hash_fast_path_count_.fetch_add(1, std::memory_order_relaxed);
            if (undo_log.path_index_restore_keys->find(key) != undo_log.path_index_restore_keys->end())
            {
                return;
            }
        }
        else
        {
            if (std::any_of(
                    undo_log.path_index_restores.begin(),
                    undo_log.path_index_restores.end(),
                    [&](const PathIndexRestoreEntry& entry) { return entry.key == key; }))
            {
                return;
            }
        }

        auto existing = working_path_index_.find(key);
        undo_log.path_index_restores.push_back(
            {
                key,
                existing == working_path_index_.end() ? std::optional<std::uint64_t>{} : existing->second,
            });
        if (undo_log.path_index_restore_keys.has_value())
        {
            undo_log.path_index_restore_keys->insert(key);
        }
    };
    const auto remember_pending_object_map_update = [&](std::uint64_t object_id)
    {
        if (has_restored_uint64(
                object_id,
                undo_log.pending_object_map_restores,
                undo_log.pending_object_map_restore_ids,
                [](const PendingObjectMapRestoreEntry& entry) { return entry.object_id; }))
        {
            return;
        }

        auto existing = pending_object_map_updates_.end();
        if (auto indexed = pending_object_map_update_index_.find(object_id);
            indexed != pending_object_map_update_index_.end() &&
            indexed->second < pending_object_map_updates_.size() &&
            pending_object_map_updates_[indexed->second].object_id == object_id)
        {
            existing = pending_object_map_updates_.begin() + static_cast<std::ptrdiff_t>(indexed->second);
        }
        else
        {
            existing = std::find_if(
                pending_object_map_updates_.begin(),
                pending_object_map_updates_.end(),
                [&](const ObjectMapUpdate& update) { return update.object_id == object_id; });
        }
        undo_log.pending_object_map_restores.push_back(
            {
                object_id,
                existing == pending_object_map_updates_.end() ? std::optional<ObjectMapUpdate>{} : *existing,
            });
        track_restored_uint64(object_id, undo_log.pending_object_map_restore_ids);
    };
    const auto remember_read_extents = [&](std::uint64_t object_id)
    {
        if (has_restored_uint64(
                object_id,
                undo_log.read_extent_restores,
                undo_log.read_extent_restore_ids,
                [](const ReadExtentRestoreEntry& entry) { return entry.object_id; }))
        {
            return;
        }

        auto existing_working = working_read_extents_.find(object_id);
        auto existing_pending = pending_read_extent_updates_.find(object_id);
        undo_log.read_extent_restores.push_back(
            {
                object_id,
                existing_working == working_read_extents_.end()
                    ? std::optional<std::vector<FileExtent>>{}
                    : existing_working->second,
                existing_pending == pending_read_extent_updates_.end()
                    ? std::optional<std::vector<FileExtent>>{}
                    : existing_pending->second,
            });
        track_restored_uint64(object_id, undo_log.read_extent_restore_ids);
    };
    const auto remember_prepared_payload_ranges = [&](std::uint64_t object_id)
    {
        if (has_restored_uint64(
                object_id,
                undo_log.prepared_payload_range_restores,
                undo_log.prepared_payload_range_restore_ids,
                [](const PreparedPayloadRangesRestoreEntry& entry) { return entry.object_id; }))
        {
            return;
        }

        auto existing = prepared_payload_ranges_.find(object_id);
        undo_log.prepared_payload_range_restores.push_back(
            {
                object_id,
                existing == prepared_payload_ranges_.end()
                    ? std::optional<std::vector<PreparedPayloadRange>>{}
                    : existing->second,
            });
        track_restored_uint64(object_id, undo_log.prepared_payload_range_restore_ids);
    };
    const auto remember_pending_written_ranges = [&](std::uint64_t object_id)
    {
        if (has_restored_uint64(
                object_id,
                undo_log.pending_written_range_restores,
                undo_log.pending_written_range_restore_ids,
                [](const PendingWrittenRangesRestoreEntry& entry) { return entry.object_id; }))
        {
            return;
        }

        auto existing = pending_written_ranges_.find(object_id);
        undo_log.pending_written_range_restores.push_back(
            {
                object_id,
                existing == pending_written_ranges_.end()
                    ? std::optional<std::vector<PreparedPayloadRange>>{}
                    : std::optional<std::vector<PreparedPayloadRange>>{ existing->second },
            });
        track_restored_uint64(object_id, undo_log.pending_written_range_restore_ids);
    };
    const auto remember_pending_btree_record = [&](std::size_t index)
    {
        if (index >= undo_log.pending_btree_records_size ||
            index >= pending_btree_records_.size())
        {
            return;
        }
        if (undo_log.pending_btree_record_restore_indexes.has_value())
        {
            mutation_restore_dedupe_hash_fast_path_count_.fetch_add(1, std::memory_order_relaxed);
            if (undo_log.pending_btree_record_restore_indexes->find(index) !=
                undo_log.pending_btree_record_restore_indexes->end())
            {
                return;
            }
        }
        else if (undo_log.pending_btree_record_restores.size() >= kMutationRestoreHashThreshold)
        {
            undo_log.pending_btree_record_restore_indexes.emplace(&mutation_undo_resource);
            undo_log.pending_btree_record_restore_indexes->reserve(undo_log.pending_btree_record_restores.size() + 1);
            for (const auto& entry : undo_log.pending_btree_record_restores)
            {
                undo_log.pending_btree_record_restore_indexes->insert(entry.index);
            }
            mutation_restore_dedupe_hash_fast_path_count_.fetch_add(1, std::memory_order_relaxed);
            if (undo_log.pending_btree_record_restore_indexes->find(index) !=
                undo_log.pending_btree_record_restore_indexes->end())
            {
                return;
            }
        }
        else
        {
            if (std::any_of(
                    undo_log.pending_btree_record_restores.begin(),
                    undo_log.pending_btree_record_restores.end(),
                    [&](const PendingBtreeRecordRestoreEntry& entry) { return entry.index == index; }))
            {
                return;
            }
        }

        undo_log.pending_btree_record_restores.push_back({ index, pending_btree_records_[index] });
        if (undo_log.pending_btree_record_restore_indexes.has_value())
        {
            undo_log.pending_btree_record_restore_indexes->insert(index);
        }
    };
    const auto remember_erased_pending_btree_record = [&](std::size_t index)
    {
        if (index >= undo_log.pending_btree_records_size ||
            index >= pending_btree_records_.size())
        {
            return;
        }

        undo_log.erased_pending_btree_records.push_back({ index, pending_btree_records_[index] });
    };
    const auto clear_prepared_payload_ranges = [&](std::uint64_t object_id)
    {
        remember_prepared_payload_ranges(object_id);
        prepared_payload_ranges_.erase(object_id);
    };
    const auto clear_pending_written_ranges = [&](std::uint64_t object_id)
    {
        remember_pending_written_ranges(object_id);
        ClearPendingWrittenRanges(object_id);
    };
    const auto mark_pending_written_range = [&](
        std::uint64_t object_id,
        std::uint64_t offset,
        std::uint64_t bytes)
    {
        remember_pending_written_ranges(object_id);
        RememberPendingWrittenRange(object_id, offset, bytes);
    };
    const auto remember_directory_link = [&](std::uint64_t parent_object_id, const std::wstring& entry_name)
    {
        const DirectoryLinkRestoreKey restore_key{parent_object_id, entry_name};
        if (undo_log.directory_link_restore_keys.has_value())
        {
            mutation_restore_dedupe_hash_fast_path_count_.fetch_add(1, std::memory_order_relaxed);
            if (undo_log.directory_link_restore_keys->find(restore_key) != undo_log.directory_link_restore_keys->end())
            {
                return;
            }
        }
        else if (undo_log.directory_link_restores.size() >= kMutationRestoreHashThreshold)
        {
            undo_log.directory_link_restore_keys.emplace(&mutation_undo_resource);
            undo_log.directory_link_restore_keys->reserve(undo_log.directory_link_restores.size() + 1);
            for (const auto& entry : undo_log.directory_link_restores)
            {
                undo_log.directory_link_restore_keys->insert({entry.parent_object_id, entry.entry_name});
            }
            mutation_restore_dedupe_hash_fast_path_count_.fetch_add(1, std::memory_order_relaxed);
            if (undo_log.directory_link_restore_keys->find(restore_key) != undo_log.directory_link_restore_keys->end())
            {
                return;
            }
        }
        else
        {
            if (std::any_of(
                    undo_log.directory_link_restores.begin(),
                    undo_log.directory_link_restores.end(),
                    [&](const DirectoryLinkRestoreEntry& entry)
                    {
                        return entry.parent_object_id == parent_object_id &&
                               entry.entry_name == entry_name;
                    }))
            {
                return;
            }
        }

        auto index_it = working_directory_link_index_.find(
            BuildWorkingDirectoryLinkIndexKey(parent_object_id, entry_name));
        std::optional<DirectoryLink> previous;
        if (index_it != working_directory_link_index_.end() &&
            index_it->second < working_directory_links_.size())
        {
            previous = working_directory_links_[index_it->second];
        }
        undo_log.directory_link_restores.push_back(
            {
                parent_object_id,
                entry_name,
                std::move(previous),
            });
        if (undo_log.directory_link_restore_keys.has_value())
        {
            undo_log.directory_link_restore_keys->insert(restore_key);
        }
    };
    const auto remember_working_free_extents = [&]()
    {
        if (!undo_log.working_spaceman_free_extents.has_value())
        {
            mutation_working_free_snapshot_count_.fetch_add(1, std::memory_order_relaxed);
            undo_log.working_spaceman_free_extents = working_spaceman_free_extents_;
        }
    };
    const auto rollback_contiguous_allocation = [&](const ExtentAllocator::ContiguousAllocationUndo& undo)
    {
        if (!ExtentAllocator::RollbackContiguousAllocation(
                working_spaceman_free_extents_,
                working_next_ephemeral_extent_,
                undo))
        {
            remember_working_free_extents();
            return false;
        }
        mutation_working_free_local_undo_count_.fetch_add(1, std::memory_order_relaxed);
        return true;
    };
    const auto set_working_path_index = [&](const std::wstring& key, std::uint64_t object_id)
    {
        remember_path_index(key);
        working_path_index_[key] = object_id;
    };
    const auto erase_working_path_index = [&](const std::wstring& key)
    {
        remember_path_index(key);
        working_path_index_.erase(key);
    };
    const auto set_working_inode = [&](const InodeRecord& inode)
    {
        remember_inode(inode.object_id);
        working_inodes_[inode.object_id] = inode;
    };
    const auto erase_working_inode = [&](std::uint64_t object_id)
    {
        remember_inode(object_id);
        working_inodes_.erase(object_id);
    };
    const auto mutable_working_inode = [&](std::uint64_t object_id) -> InodeRecord&
    {
        remember_inode(object_id);
        return working_inodes_[object_id];
    };
    const auto remove_working_directory_link = [&](std::uint64_t parent_object_id, const std::wstring& entry_name)
    {
        remember_directory_link(parent_object_id, entry_name);
        RemoveWorkingDirectoryLink(parent_object_id, entry_name);
    };
    const auto upsert_working_directory_link = [&](std::uint64_t parent_object_id, const std::wstring& entry_name, std::uint64_t child_object_id, std::uint64_t xid)
    {
        remember_directory_link(parent_object_id, entry_name);
        UpsertWorkingDirectoryLink(parent_object_id, entry_name, child_object_id, xid);
    };
    const auto allocate_extent = [&](std::uint64_t bytes) -> std::optional<std::uint64_t>
    {
        if (!SanitizeWorkingFreeExtents())
        {
            return std::nullopt;
        }
        ExtentAllocator::ContiguousAllocationUndo undo{};
        auto allocation = AllocateExtentFromSanitizedWorkingFreeExtents(bytes, &undo);
        if (allocation.has_value() &&
            undo.source != ExtentAllocator::ContiguousAllocationUndo::Source::None)
        {
            undo_log.working_spaceman_allocation_undos.push_back(undo);
        }
        else if (allocation.has_value())
        {
            remember_working_free_extents();
        }
        return allocation;
    };
    const auto allocate_file_extents = [&](std::uint64_t bytes) -> std::optional<std::vector<FileExtent>>
    {
        const auto aligned_total = AlignExtentBytes(bytes);
        if (aligned_total == 0)
        {
            return std::nullopt;
        }

        if (SpacemanExtentsAreSortedNonOverlapping(working_spaceman_free_extents_))
        {
            std::optional<std::uint64_t> container_bytes;
            if (total_blocks_ != 0)
            {
                if (block_size_ == 0 ||
                    total_blocks_ > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
                {
                    return std::nullopt;
                }
                container_bytes = total_blocks_ * static_cast<std::uint64_t>(block_size_);
            }

            ExtentAllocator::AllocationPolicy clean_prefix_policy
            {
                container_bytes,
                this,
                [](const void* context, std::uint64_t physical_address, std::uint64_t required_bytes)
                {
                    const auto* store = static_cast<const MetadataStore*>(context);
                    return store->ExtentOverlapsReservedMetadata(physical_address, required_bytes) ||
                           store->ExtentOverlapsLiveAllocation(physical_address, required_bytes);
                },
                nullptr,
            };

            ScopedPerfTimer allocation_perf_scope(allocation_lookup_perf_);
            ScopedPerfTimer free_list_perf_scope(free_list_lookup_perf_);
            ExtentAllocator::ContiguousAllocationUndo undo{};
            auto allocation = ExtentAllocator::AllocateContiguousFromFree(
                working_spaceman_free_extents_,
                aligned_total,
                clean_prefix_policy,
                &undo);
            if (allocation.has_value() &&
                undo.source != ExtentAllocator::ContiguousAllocationUndo::Source::None)
            {
                undo_log.working_spaceman_allocation_undos.push_back(undo);
                return std::vector<FileExtent>{ FileExtent{ 0, allocation.value(), bytes } };
            }

            if (ExtentAllocator::CanAllocateFromFragmentedFreeExtents(
                    working_spaceman_free_extents_,
                    aligned_total,
                    clean_prefix_policy))
            {
                remember_working_free_extents();
                return AllocateFileExtents(bytes);
            }
        }

        ExtentAllocator::ContiguousAllocationUndo tail_undo{};
        auto tail_allocation = AllocateExtentFromSanitizedWorkingFreeExtents(aligned_total, &tail_undo);
        if (tail_allocation.has_value() &&
            tail_undo.source != ExtentAllocator::ContiguousAllocationUndo::Source::None)
        {
            undo_log.working_spaceman_allocation_undos.push_back(tail_undo);
            return std::vector<FileExtent>{ FileExtent{ 0, tail_allocation.value(), bytes } };
        }

        return std::nullopt;
    };
    const auto release_pending_spaceman_allocation = [&](std::uint64_t physical_address, std::uint64_t bytes)
    {
        if (!IsNativeWriteReady() || physical_address == 0 || bytes == 0)
        {
            return false;
        }

        const auto aligned_bytes = AlignExtentBytes(bytes);
        if (aligned_bytes == 0)
        {
            return false;
        }

        const auto allocation_index = FindPendingSpacemanAllocationIndex(physical_address);
        if (!allocation_index.has_value() ||
            pending_spaceman_allocations_[allocation_index.value()].bytes != aligned_bytes)
        {
            return false;
        }

        const auto erased_allocation = pending_spaceman_allocations_[allocation_index.value()];
        if (allocation_index.value() < undo_log.pending_spaceman_allocations_size)
        {
            undo_log.erased_pending_allocations.push_back({ allocation_index.value(), erased_allocation });
            pending_spaceman_released_existing_allocation_ = true;
        }
        ErasePendingSpacemanAllocationAt(allocation_index.value());
        const auto can_use_local_free_undo =
            SpacemanExtentsAreSortedNonOverlapping(working_spaceman_free_extents_) &&
            !ExtentOverlapsEffectiveLiveAllocation(physical_address, aligned_bytes);
        if (!can_use_local_free_undo)
        {
            remember_working_free_extents();
        }

        ExtentAllocator::AddFreeExtentUndo undo{};
        tracking_spaceman_free_extent_delta_ = true;
        ScopeExit clear_tracking_spaceman_free_extent_delta{
            [&]()
            {
                tracking_spaceman_free_extent_delta_ = false;
            }};
        if (!FreeExtent(
                physical_address,
                aligned_bytes,
                can_use_local_free_undo ? &undo : nullptr))
        {
            return false;
        }
        if (can_use_local_free_undo && undo.valid)
        {
            undo_log.working_spaceman_free_extent_add_undos.push_back(std::move(undo));
        }
        else if (can_use_local_free_undo)
        {
            remember_working_free_extents();
        }
        return true;
    };
    const auto stage_spaceman_allocation = [&](std::uint64_t physical_address, std::uint64_t bytes)
    {
        const auto before_size = pending_spaceman_allocations_.size();
        if (!StageSpacemanAllocation(physical_address, bytes))
        {
            return false;
        }
        if (pending_spaceman_allocations_.size() > before_size)
        {
            undo_log.appended_pending_allocations.push_back(pending_spaceman_allocations_.back());
        }
        return true;
    };
    const auto release_pending_file_extents =
        [&](std::uint64_t object_id, std::vector<FileExtent>& retained_committed_extents)
    {
        retained_committed_extents.clear();
        auto extents_it = pending_read_extent_updates_.find(object_id);
        if (extents_it == pending_read_extent_updates_.end())
        {
            return true;
        }

        remember_read_extents(object_id);
        clear_prepared_payload_ranges(object_id);
        const auto& extents = extents_it->second;
        if (extents.size() == 1)
        {
            const auto& extent = extents.front();
            const auto aligned_bytes = AlignExtentBytes(extent.bytes);
            if (extent.physical_address == 0 || aligned_bytes == 0 ||
                extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - aligned_bytes))
            {
                return false;
            }

            bool released_pending_allocation = false;
            auto allocation_it = pending_spaceman_allocation_index_.upper_bound(extent.physical_address);
            if (allocation_it != pending_spaceman_allocation_index_.begin())
            {
                --allocation_it;
                if (allocation_it->second >= pending_spaceman_allocations_.size())
                {
                    return false;
                }

                const auto& allocation = pending_spaceman_allocations_[allocation_it->second];
                if (allocation.physical_address != allocation_it->first)
                {
                    return false;
                }
                if (PhysicalRangeContains(
                        allocation.physical_address,
                        allocation.bytes,
                        extent.physical_address,
                        aligned_bytes))
                {
                    if (!release_pending_spaceman_allocation(allocation.physical_address, allocation.bytes))
                    {
                        return false;
                    }
                    released_pending_allocation = true;
                }
            }

            if (!released_pending_allocation)
            {
                if (PendingSpacemanAllocationsOverlap(extent.physical_address, aligned_bytes))
                {
                    return false;
                }
                retained_committed_extents.push_back(extent);
            }

            pending_read_extent_updates_.erase(object_id);
            working_read_extents_.erase(object_id);
            return true;
        }

        std::map<std::uint64_t, SpacemanAllocation> owned_pending_allocations;
        retained_committed_extents.reserve(extents.size());
        for (const auto& extent : extents)
        {
            const auto aligned_bytes = AlignExtentBytes(extent.bytes);
            if (extent.physical_address == 0 || aligned_bytes == 0 ||
                extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - aligned_bytes))
            {
                return false;
            }

            auto allocation_it = pending_spaceman_allocation_index_.upper_bound(extent.physical_address);
            if (allocation_it != pending_spaceman_allocation_index_.begin())
            {
                --allocation_it;
                if (allocation_it->second >= pending_spaceman_allocations_.size())
                {
                    return false;
                }

                const auto& allocation = pending_spaceman_allocations_[allocation_it->second];
                if (allocation.physical_address != allocation_it->first)
                {
                    return false;
                }
                if (PhysicalRangeContains(
                        allocation.physical_address,
                        allocation.bytes,
                        extent.physical_address,
                        aligned_bytes))
                {
                    owned_pending_allocations.insert_or_assign(
                        allocation.physical_address,
                        allocation);
                    continue;
                }
            }

            if (PendingSpacemanAllocationsOverlap(extent.physical_address, aligned_bytes))
            {
                return false;
            }
            retained_committed_extents.push_back(extent);
        }

        for (const auto& [_, allocation] : owned_pending_allocations)
        {
            if (!release_pending_spaceman_allocation(allocation.physical_address, allocation.bytes))
            {
                return false;
            }
        }
        pending_read_extent_updates_.erase(object_id);
        working_read_extents_.erase(object_id);
        return true;
    };
    const auto restore_pending_allocations = [&]()
    {
        for (auto append_it = undo_log.appended_pending_allocations.rbegin();
             append_it != undo_log.appended_pending_allocations.rend();
             ++append_it)
        {
            const auto existing_index = FindPendingSpacemanAllocationIndex(append_it->physical_address);
            if (existing_index.has_value() &&
                pending_spaceman_allocations_[existing_index.value()].bytes == append_it->bytes)
            {
                const auto index = existing_index.value();
                if (index + 1 == pending_spaceman_allocations_.size())
                {
                    pending_spaceman_allocations_.pop_back();
                    pending_spaceman_allocation_index_.erase(append_it->physical_address);
                }
                else
                {
                    pending_spaceman_allocations_.erase(
                        pending_spaceman_allocations_.begin() + static_cast<std::ptrdiff_t>(index));
                    RebuildPendingSpacemanAllocationIndex();
                }
            }
        }
        std::sort(
            undo_log.erased_pending_allocations.begin(),
            undo_log.erased_pending_allocations.end(),
            [](const PendingAllocationRestoreEntry& lhs, const PendingAllocationRestoreEntry& rhs)
            {
                return lhs.index < rhs.index;
            });
        for (const auto& restore : undo_log.erased_pending_allocations)
        {
            const auto index = std::min(restore.index, pending_spaceman_allocations_.size());
            pending_spaceman_allocations_.insert(
                pending_spaceman_allocations_.begin() + static_cast<std::ptrdiff_t>(index),
                restore.allocation);
        }
        for (const auto& restore : undo_log.resized_pending_allocations)
        {
            if (restore.index < pending_spaceman_allocations_.size())
            {
                pending_spaceman_allocations_[restore.index].bytes = restore.previous_bytes;
            }
        }
        if (pending_spaceman_allocations_.size() > undo_log.pending_spaceman_allocations_size)
        {
            pending_spaceman_allocations_.resize(undo_log.pending_spaceman_allocations_size);
        }
        RebuildPendingSpacemanAllocationIndex();
    };
    const auto restore_directory_links = [&]()
    {
        for (const auto& restore : undo_log.directory_link_restores)
        {
            if (restore.previous.has_value())
            {
                UpsertWorkingDirectoryLink(
                    restore.previous->parent_object_id,
                    restore.previous->entry_name,
                    restore.previous->child_object_id,
                    restore.previous->xid);
            }
            else
            {
                RemoveWorkingDirectoryLink(restore.parent_object_id, restore.entry_name);
            }
        }
    };
    const auto stage_object_map_update = [&](std::uint64_t object_id, std::uint64_t physical_address, std::uint64_t logical_size)
    {
        remember_pending_object_map_update(object_id);
        return StageObjectMapUpdate(object_id, physical_address, logical_size);
    };
    bool mutation_applied = false;
    bool pending_mutation_recorded = false;
    ScopeExit rollback_guard{
        [&]()
        {
            if (mutation_applied)
            {
                return;
            }

            if (pending_mutations_.size() > undo_log.pending_mutations_size)
            {
                pending_mutations_.resize(undo_log.pending_mutations_size);
                if (pending_mutation_path_key_cache_.size() > pending_mutations_.size())
                {
                    pending_mutation_path_key_cache_.resize(pending_mutations_.size());
                }
            }
            if (pending_object_map_updates_.size() > undo_log.pending_object_map_updates_size)
            {
                pending_object_map_updates_.resize(undo_log.pending_object_map_updates_size);
                RebuildPendingObjectMapUpdateIndex();
            }
            restore_pending_allocations();
            if (pending_spaceman_deallocations_.size() > undo_log.pending_spaceman_deallocations_size)
            {
                pending_spaceman_deallocations_.resize(undo_log.pending_spaceman_deallocations_size);
            }
            pending_spaceman_untracked_free_extent_delta_ =
                undo_log.pending_spaceman_untracked_free_extent_delta;
            pending_spaceman_released_existing_allocation_ =
                undo_log.pending_spaceman_released_existing_allocation;
            bool rebuild_pending_btree_index = false;
            const auto erased_pending_btree_records_count = undo_log.erased_pending_btree_records.size();
            const auto pending_btree_records_size_before_erase =
                erased_pending_btree_records_count > undo_log.pending_btree_records_size
                    ? 0
                    : undo_log.pending_btree_records_size - erased_pending_btree_records_count;
            if (pending_btree_records_.size() > pending_btree_records_size_before_erase)
            {
                pending_btree_records_.resize(pending_btree_records_size_before_erase);
                rebuild_pending_btree_index = true;
            }
            std::sort(
                undo_log.erased_pending_btree_records.begin(),
                undo_log.erased_pending_btree_records.end(),
                [](const PendingBtreeRecordEraseRestoreEntry& lhs, const PendingBtreeRecordEraseRestoreEntry& rhs)
                {
                    return lhs.index < rhs.index;
                });
            for (const auto& restore : undo_log.erased_pending_btree_records)
            {
                const auto index = std::min(restore.index, pending_btree_records_.size());
                pending_btree_records_.insert(
                    pending_btree_records_.begin() + static_cast<std::ptrdiff_t>(index),
                    restore.erased);
                rebuild_pending_btree_index = true;
            }
            for (const auto& restore : undo_log.pending_btree_record_restores)
            {
                if (restore.index < pending_btree_records_.size())
                {
                    pending_btree_records_[restore.index] = restore.previous;
                    rebuild_pending_btree_index = true;
                }
            }
            if (rebuild_pending_btree_index)
            {
                RebuildPendingBtreeFileMetadataIndex();
            }
            for (const auto& restore : undo_log.pending_object_map_restores)
            {
                auto existing_index = pending_object_map_update_index_.find(restore.object_id);
                if (restore.previous.has_value())
                {
                    if (existing_index != pending_object_map_update_index_.end() &&
                        existing_index->second < pending_object_map_updates_.size())
                    {
                        pending_object_map_updates_[existing_index->second] = restore.previous.value();
                    }
                    else
                    {
                        pending_object_map_update_index_[restore.object_id] = pending_object_map_updates_.size();
                        pending_object_map_updates_.push_back(restore.previous.value());
                    }
                }
                else if (existing_index != pending_object_map_update_index_.end() &&
                         existing_index->second < pending_object_map_updates_.size())
                {
                    const auto removed_index = existing_index->second;
                    const auto last_index = pending_object_map_updates_.size() - 1;
                    if (removed_index != last_index)
                    {
                        pending_object_map_updates_[removed_index] = pending_object_map_updates_[last_index];
                        pending_object_map_update_index_[pending_object_map_updates_[removed_index].object_id] = removed_index;
                    }
                    pending_object_map_updates_.pop_back();
                    pending_object_map_update_index_.erase(restore.object_id);
                }
            }
            for (const auto& restore : undo_log.read_extent_restores)
            {
                if (restore.previous_working.has_value())
                {
                    working_read_extents_[restore.object_id] = restore.previous_working.value();
                }
                else
                {
                    working_read_extents_.erase(restore.object_id);
                }

                if (restore.previous_pending.has_value())
                {
                    pending_read_extent_updates_[restore.object_id] = restore.previous_pending.value();
                }
                else
                {
                    pending_read_extent_updates_.erase(restore.object_id);
                }
            }
            for (const auto& restore : undo_log.prepared_payload_range_restores)
            {
                if (restore.previous.has_value())
                {
                    prepared_payload_ranges_[restore.object_id] = restore.previous.value();
                }
                else
                {
                    prepared_payload_ranges_.erase(restore.object_id);
                }
            }
            for (const auto& restore : undo_log.pending_written_range_restores)
            {
                if (restore.previous.has_value())
                {
                    ReplacePendingWrittenRanges(restore.object_id, restore.previous);
                }
                else
                {
                    ReplacePendingWrittenRanges(restore.object_id, std::nullopt);
                }
            }
            if (!undo_log.working_spaceman_free_extents.has_value())
            {
                for (auto undo_it = undo_log.working_spaceman_free_extent_add_undos.rbegin();
                     undo_it != undo_log.working_spaceman_free_extent_add_undos.rend();
                     ++undo_it)
                {
                    if (!ExtentAllocator::RollbackAddFreeExtent(working_spaceman_free_extents_, *undo_it))
                    {
                        remember_working_free_extents();
                        break;
                    }
                    mutation_working_free_local_undo_count_.fetch_add(1, std::memory_order_relaxed);
                }
            }
            if (!undo_log.working_spaceman_free_extents.has_value())
            {
                for (auto undo_it = undo_log.working_spaceman_allocation_undos.rbegin();
                     undo_it != undo_log.working_spaceman_allocation_undos.rend();
                     ++undo_it)
                {
                    if (!rollback_contiguous_allocation(*undo_it))
                    {
                        break;
                    }
                }
            }
            if (undo_log.working_spaceman_free_extents.has_value())
            {
                working_spaceman_free_extents_ = std::move(*undo_log.working_spaceman_free_extents);
            }
            working_next_ephemeral_extent_ = undo_log.working_next_ephemeral_extent;
            working_free_extents_sanitized_ = undo_log.working_free_extents_sanitized;
            for (const auto& restore : undo_log.path_index_restores)
            {
                if (restore.previous.has_value())
                {
                    working_path_index_[restore.key] = restore.previous.value();
                }
                else
                {
                    working_path_index_.erase(restore.key);
                }
            }
            for (const auto& restore : undo_log.inode_restores)
            {
                if (restore.previous.has_value())
                {
                    working_inodes_[restore.object_id] = restore.previous.value();
                }
                else
                {
                    working_inodes_.erase(restore.object_id);
                }
            }
            restore_directory_links();
            RebuildPendingWriteObjectIds();
            RebuildPendingBasicInfoMutationIndex();
            RebuildPendingPayloadSummary();
            RebuildPendingCloseDelaySummary();
        }};
    const auto stage_pending_btree_record = [&](BtreeRecord record)
    {
        if (!record.tombstone && record.kind == BtreeRecordKind::Inode)
        {
            DecodedBtreeInode decoded{};
            if (DecodeBtreeInodeRecord(record, decoded) && !decoded.is_directory)
            {
                auto existing = pending_btree_file_inode_index_.find(decoded.object_id);
                if (existing != pending_btree_file_inode_index_.end() &&
                    existing->second < pending_btree_records_.size())
                {
                    const auto existing_index = existing->second;
                    DecodedBtreeInode existing_decoded{};
                    const auto& existing_record = pending_btree_records_[existing_index];
                    if (!existing_record.tombstone &&
                        existing_record.kind == BtreeRecordKind::Inode &&
                        DecodeBtreeInodeRecord(existing_record, existing_decoded) &&
                        !existing_decoded.is_directory &&
                        existing_decoded.object_id == decoded.object_id)
                    {
                        remember_pending_btree_record(existing_index);
                        UntrackPendingBtreeRecordIndex(pending_btree_records_[existing_index], existing_index);
                        pending_btree_records_[existing_index] = std::move(record);
                        TrackPendingBtreeRecordIndex(pending_btree_records_[existing_index], existing_index);
                        return;
                    }
                }
            }
        }
        else if (record.tombstone && record.kind == BtreeRecordKind::FileExtent)
        {
            constexpr std::size_t kExpectedExtentKeyBytes = 1 + 8 + 8;
            std::uint64_t object_id = 0;
            std::uint64_t logical_offset = 0;
            if (record.key.size() == kExpectedExtentKeyBytes &&
                TryReadLe64(record.key, 1, object_id) &&
                TryReadLe64(record.key, 9, logical_offset) &&
                object_id != 0)
            {
                const PendingBtreeExtentKey key{ object_id, logical_offset };
                auto existing = pending_btree_file_extent_index_.find(key);
                if (existing != pending_btree_file_extent_index_.end() &&
                    existing->second < pending_btree_records_.size())
                {
                    const auto existing_index = existing->second;
                    remember_pending_btree_record(existing_index);
                    UntrackPendingBtreeRecordIndex(pending_btree_records_[existing_index], existing_index);
                    pending_btree_records_[existing_index] = std::move(record);
                    TrackPendingBtreeRecordIndex(pending_btree_records_[existing_index], existing_index);
                    return;
                }
            }
        }
        else if (!record.tombstone && record.kind == BtreeRecordKind::FileExtent)
        {
            DecodedBtreeExtent decoded{};
            if (DecodeBtreeExtentRecord(record, decoded))
            {
                const PendingBtreeExtentKey key{ decoded.object_id, decoded.logical_offset };
                auto existing = pending_btree_file_extent_index_.find(key);
                if (existing != pending_btree_file_extent_index_.end() &&
                    existing->second < pending_btree_records_.size())
                {
                    const auto existing_index = existing->second;
                    DecodedBtreeExtent existing_decoded{};
                    const auto& existing_record = pending_btree_records_[existing_index];
                    if (!existing_record.tombstone &&
                        existing_record.kind == BtreeRecordKind::FileExtent &&
                        DecodeBtreeExtentRecord(existing_record, existing_decoded) &&
                        existing_decoded.object_id == decoded.object_id &&
                        existing_decoded.logical_offset == decoded.logical_offset)
                    {
                        remember_pending_btree_record(existing_index);
                        UntrackPendingBtreeRecordIndex(pending_btree_records_[existing_index], existing_index);
                        pending_btree_records_[existing_index] = std::move(record);
                        TrackPendingBtreeRecordIndex(pending_btree_records_[existing_index], existing_index);
                        return;
                    }
                }
            }
        }

        StagePendingBtreeRecord(std::move(record));
    };
    const auto stage_inode_record = [&](const InodeRecord& inode, bool tombstone)
    {
        stage_pending_btree_record(BtreeMutationCodec::EncodeInodeRecord(
            inode.object_id,
            inode.parent_object_id,
            inode.name,
            inode.is_directory,
            inode.logical_size,
            inode.data_physical_address,
            inode.timestamp_utc,
            tombstone ? target_xid : inode.xid,
            tombstone));
    };
    const auto stage_directory_record = [&](std::uint64_t parent_object_id, const std::wstring& name, std::uint64_t child_object_id, bool tombstone)
    {
        stage_pending_btree_record(BtreeMutationCodec::EncodeDirectoryRecord(
            parent_object_id,
            name,
            child_object_id,
            target_xid,
            tombstone));
    };
    const auto stage_extent_record = [&](std::uint64_t object_id, std::uint64_t logical_offset, std::uint64_t physical_address, std::uint64_t extent_bytes, bool tombstone)
    {
        stage_pending_btree_record(BtreeMutationCodec::EncodeExtentRecord(
            object_id,
            logical_offset,
            physical_address,
            extent_bytes,
            target_xid,
            tombstone));
    };
    const auto stage_file_extents = [&](std::uint64_t object_id, const std::vector<FileExtent>& extents) -> bool
    {
        remember_read_extents(object_id);
        clear_prepared_payload_ranges(object_id);
        if (extents.empty())
        {
            clear_pending_written_ranges(object_id);
            working_read_extents_.erase(object_id);
            pending_read_extent_updates_.erase(object_id);
            return true;
        }

        working_read_extents_[object_id] = extents;
        pending_read_extent_updates_[object_id] = extents;
        for (const auto& extent : extents)
        {
            stage_extent_record(
                object_id,
                extent.logical_offset,
                extent.physical_address,
                extent.bytes,
                false);
        }
        return true;
    };
    const auto try_consume_free_extent_for_pending_extension =
        [&](std::uint64_t physical_address, std::uint64_t bytes) -> bool
    {
        if (physical_address == 0 || bytes == 0)
        {
            return false;
        }
        if (physical_address > (std::numeric_limits<std::uint64_t>::max() - bytes))
        {
            return false;
        }

        const auto request_end = physical_address + bytes;
        for (auto it = working_spaceman_free_extents_.begin(); it != working_spaceman_free_extents_.end(); ++it)
        {
            if (it->physical_address > physical_address ||
                it->physical_address > (std::numeric_limits<std::uint64_t>::max() - it->bytes) ||
                (it->physical_address + it->bytes) < request_end)
            {
                continue;
            }

            const auto free_end = it->physical_address + it->bytes;
            if (it->physical_address == physical_address && free_end == request_end)
            {
                working_spaceman_free_extents_.erase(it);
                return true;
            }
            if (it->physical_address == physical_address)
            {
                it->physical_address = request_end;
                it->bytes = free_end - request_end;
                return true;
            }
            if (free_end == request_end)
            {
                it->bytes = physical_address - it->physical_address;
                return true;
            }

            const auto tail = SpacemanAllocation{ request_end, free_end - request_end };
            it->bytes = physical_address - it->physical_address;
            working_spaceman_free_extents_.insert(std::next(it), tail);
            return true;
        }

        return false;
    };
    const auto try_extend_single_pending_file_extent =
        [&](std::uint64_t object_id, std::uint64_t required_logical_size) -> bool
    {
        if (required_logical_size == 0)
        {
            return true;
        }

        auto extents_it = pending_read_extent_updates_.find(object_id);
        if (extents_it == pending_read_extent_updates_.end() ||
            extents_it->second.size() != 1)
        {
            return false;
        }

        auto& extent = extents_it->second.front();
        if (extent.logical_offset != 0 ||
            extent.physical_address == 0 ||
            extent.bytes == 0)
        {
            return false;
        }

        const auto required_aligned = AlignExtentBytes(required_logical_size);
        const auto current_aligned = AlignExtentBytes(extent.bytes);
        if (required_aligned == 0 || current_aligned == 0)
        {
            return false;
        }
        if (required_aligned <= current_aligned)
        {
            remember_read_extents(object_id);
            clear_prepared_payload_ranges(object_id);
            const auto updated_extent_bytes = std::max(extent.bytes, required_logical_size);
            const bool extent_changed = updated_extent_bytes != extent.bytes;
            extent.bytes = updated_extent_bytes;
            working_read_extents_[object_id] = extents_it->second;
            if (extent_changed)
            {
                stage_extent_record(object_id, 0, extent.physical_address, extent.bytes, false);
            }
            return true;
        }

        const auto next_reserved = StreamingGrowthReservationBytes(current_aligned, required_aligned);
        if (next_reserved < required_aligned ||
            extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - next_reserved))
        {
            return false;
        }
        if (total_blocks_ != 0)
        {
            if (block_size_ == 0 ||
                total_blocks_ > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
            {
                return false;
            }

            const auto container_bytes = total_blocks_ * static_cast<std::uint64_t>(block_size_);
            if ((extent.physical_address + next_reserved) > container_bytes)
            {
                return false;
            }
        }

        const auto old_end = extent.physical_address + current_aligned;
        const auto additional_bytes = next_reserved - current_aligned;
        if (additional_bytes == 0 ||
            old_end > (std::numeric_limits<std::uint64_t>::max() - additional_bytes) ||
            ExtentOverlapsReservedMetadata(old_end, additional_bytes) ||
            ExtentOverlapsLiveAllocation(old_end, additional_bytes))
        {
            return false;
        }

        const auto allocation_index = FindPendingSpacemanAllocationIndex(extent.physical_address);
        if (!allocation_index.has_value())
        {
            return false;
        }
        if (pending_spaceman_allocations_[allocation_index.value()].bytes != current_aligned)
        {
            return false;
        }

        remember_working_free_extents();
        if (!SanitizeWorkingFreeExtents())
        {
            return false;
        }

        if (working_next_ephemeral_extent_ == old_end)
        {
            ExtentAllocator::ContiguousAllocationUndo undo{};
            undo.source = ExtentAllocator::ContiguousAllocationUndo::Source::EphemeralTail;
            undo.previous_next_ephemeral_extent = working_next_ephemeral_extent_;
            undo_log.working_spaceman_allocation_undos.push_back(undo);
            working_next_ephemeral_extent_ += additional_bytes;
        }
        else
        {
            remember_working_free_extents();
            if (!try_consume_free_extent_for_pending_extension(old_end, additional_bytes))
            {
                return false;
            }
        }

        undo_log.resized_pending_allocations.push_back(
            {
                allocation_index.value(),
                pending_spaceman_allocations_[allocation_index.value()].bytes,
            });
        ResizePendingSpacemanAllocationAt(allocation_index.value(), next_reserved);
        remember_read_extents(object_id);
        clear_prepared_payload_ranges(object_id);
        extent.bytes = next_reserved;
        working_read_extents_[object_id] = extents_it->second;
        stage_extent_record(object_id, 0, extent.physical_address, extent.bytes, false);
        return true;
    };
    const auto stage_committed_file_extents_for_removal = [&](const InodeRecord& inode) -> bool
    {
        remember_read_extents(inode.object_id);
        clear_prepared_payload_ranges(inode.object_id);
        auto extents = CommittedFileExtentsForMutation(inode);
        if (!extents.has_value() || !StageCommittedFileExtentDeallocations(extents.value()))
        {
            return false;
        }
        for (const auto& extent : extents->file_extents)
        {
            stage_extent_record(
                inode.object_id,
                extent.logical_offset,
                extent.physical_address,
                extent.bytes,
                true);
        }
        working_read_extents_.erase(inode.object_id);
        pending_read_extent_updates_.erase(inode.object_id);
        return true;
    };
    const auto stage_committed_file_extent_tombstones = [&](std::uint64_t object_id, const std::vector<FileExtent>& extents)
    {
        for (const auto& extent : extents)
        {
            stage_extent_record(
                object_id,
                extent.logical_offset,
                extent.physical_address,
                extent.bytes,
                true);
        }
    };
    const auto stage_retained_committed_file_extents_for_removal =
        [&](std::uint64_t object_id, const std::vector<FileExtent>& extents)
    {
        stage_committed_file_extent_tombstones(object_id, extents);
        for (const auto& extent : extents)
        {
            if (!StageSpacemanDeallocation(extent.physical_address, extent.bytes))
            {
                return false;
            }
        }
        return true;
    };
    enum class PartialCommittedOverwriteResult
    {
        NotApplicable,
        Applied,
        Failed,
    };
    const auto pending_allocation_contains_range =
        [&](std::uint64_t physical_address, std::uint64_t bytes) -> bool
    {
        if (physical_address == 0 ||
            bytes == 0 ||
            physical_address > (std::numeric_limits<std::uint64_t>::max() - bytes) ||
            pending_spaceman_allocation_index_.size() != pending_spaceman_allocations_.size())
        {
            return false;
        }

        auto allocation_it = pending_spaceman_allocation_index_.upper_bound(physical_address);
        if (allocation_it == pending_spaceman_allocation_index_.begin())
        {
            return false;
        }
        --allocation_it;
        if (allocation_it->second >= pending_spaceman_allocations_.size())
        {
            return false;
        }

        const auto& allocation = pending_spaceman_allocations_[allocation_it->second];
        return allocation.physical_address == allocation_it->first &&
               PhysicalRangeContains(allocation.physical_address, allocation.bytes, physical_address, bytes);
    };
    const auto try_stage_partial_committed_overwrite = [&](const InodeRecord& inode,
                                                             std::uint64_t previous_size,
                                                             std::uint64_t offset,
                                                             std::uint64_t length) -> PartialCommittedOverwriteResult
    {
        if (previous_size == 0 || length == 0 || offset >= previous_size ||
            offset > (std::numeric_limits<std::uint64_t>::max() - length))
        {
            return PartialCommittedOverwriteResult::NotApplicable;
        }

        const auto request_end = offset + length;
        if (request_end > previous_size || block_size_ == 0)
        {
            return PartialCommittedOverwriteResult::NotApplicable;
        }

        const auto block_bytes = static_cast<std::uint64_t>(block_size_);
        if ((offset % block_bytes) != 0 || (length % block_bytes) != 0)
        {
            return PartialCommittedOverwriteResult::NotApplicable;
        }

        const auto source = CommittedFileExtentsForMutation(inode);
        if (!source.has_value() || source->file_extents.empty())
        {
            return PartialCommittedOverwriteResult::NotApplicable;
        }

        std::vector<FileExtent> final_extents;
        final_extents.reserve(source->file_extents.size() + 2);
        std::vector<FileExtent> replaced_committed_extents;
        replaced_committed_extents.reserve(source->file_extents.size());
        std::uint64_t covered_until = 0;
        bool intersects_request = false;
        for (const auto& extent : source->file_extents)
        {
            if (extent.bytes == 0 || extent.physical_address == 0 ||
                extent.logical_offset != covered_until ||
                extent.logical_offset > (std::numeric_limits<std::uint64_t>::max() - extent.bytes) ||
                extent.logical_offset >= previous_size ||
                extent.bytes > (previous_size - extent.logical_offset) ||
                (extent.logical_offset % block_bytes) != 0 ||
                (extent.physical_address % block_bytes) != 0 ||
                extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
            {
                return PartialCommittedOverwriteResult::NotApplicable;
            }

            const auto extent_end = extent.logical_offset + extent.bytes;
            const auto overlap_begin = std::max(extent.logical_offset, offset);
            const auto overlap_end = std::min(extent_end, request_end);
            if (overlap_begin >= overlap_end)
            {
                final_extents.push_back(extent);
                covered_until = extent_end;
                continue;
            }

            intersects_request = true;
            if (overlap_begin > extent.logical_offset)
            {
                final_extents.push_back(
                    {
                        extent.logical_offset,
                        extent.physical_address,
                        overlap_begin - extent.logical_offset,
                    });
            }

            const auto physical_overlap = extent.physical_address + (overlap_begin - extent.logical_offset);
            if (physical_overlap > (std::numeric_limits<std::uint64_t>::max() - (overlap_end - overlap_begin)))
            {
                return PartialCommittedOverwriteResult::NotApplicable;
            }
            const auto overlap_bytes = overlap_end - overlap_begin;
            if (pending_allocation_contains_range(physical_overlap, overlap_bytes))
            {
                final_extents.push_back(
                    {
                        overlap_begin,
                        physical_overlap,
                        overlap_bytes,
                    });
            }
            else
            {
                auto replacement_extents = allocate_file_extents(overlap_bytes);
                if (!replacement_extents.has_value() || replacement_extents->empty())
                {
                    return PartialCommittedOverwriteResult::Failed;
                }

                std::uint64_t replacement_cursor = 0;
                for (const auto& replacement_extent : replacement_extents.value())
                {
                    if (replacement_extent.bytes == 0 || replacement_extent.physical_address == 0 ||
                        replacement_extent.bytes > (overlap_bytes - replacement_cursor) ||
                        (replacement_extent.physical_address % block_bytes) != 0)
                    {
                        return PartialCommittedOverwriteResult::Failed;
                    }

                    if (!stage_spaceman_allocation(
                            replacement_extent.physical_address,
                            replacement_extent.bytes))
                    {
                        return PartialCommittedOverwriteResult::Failed;
                    }

                    final_extents.push_back(
                        {
                            overlap_begin + replacement_cursor,
                            replacement_extent.physical_address,
                            replacement_extent.bytes,
                        });
                    replacement_cursor += replacement_extent.bytes;
                }
                if (replacement_cursor != overlap_bytes)
                {
                    return PartialCommittedOverwriteResult::Failed;
                }

                replaced_committed_extents.push_back(
                    {
                        overlap_begin,
                        physical_overlap,
                        overlap_bytes,
                    });
            }

            if (overlap_end < extent_end)
            {
                final_extents.push_back(
                    {
                        overlap_end,
                        physical_overlap + (overlap_end - overlap_begin),
                        extent_end - overlap_end,
                    });
            }
            covered_until = extent_end;
        }

        if (!intersects_request || covered_until != previous_size)
        {
            return PartialCommittedOverwriteResult::NotApplicable;
        }

        std::uint64_t final_coverage = 0;
        for (const auto& extent : final_extents)
        {
            if (extent.bytes == 0 || extent.logical_offset != final_coverage ||
                extent.logical_offset > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
            {
                return PartialCommittedOverwriteResult::Failed;
            }
            final_coverage += extent.bytes;
        }
        if (final_coverage != previous_size)
        {
            return PartialCommittedOverwriteResult::Failed;
        }

        stage_committed_file_extent_tombstones(inode.object_id, replaced_committed_extents);
        for (const auto& extent : replaced_committed_extents)
        {
            if (!StageSpacemanDeallocation(extent.physical_address, extent.bytes))
            {
                return PartialCommittedOverwriteResult::Failed;
            }
        }
        if (!stage_file_extents(inode.object_id, final_extents))
        {
            return PartialCommittedOverwriteResult::Failed;
        }

        return PartialCommittedOverwriteResult::Applied;
    };
    const auto adopt_committed_extents_for_write = [&](const InodeRecord& inode,
                                                       std::uint64_t previous_size,
                                                       std::uint64_t requested_end) -> bool
    {
        if (previous_size == 0 || requested_end == 0 || requested_end <= previous_size)
        {
            return false;
        }

        auto committed = CommittedFileExtentsForMutation(inode);
        if (!committed.has_value() || committed->file_extents.empty())
        {
            return false;
        }

        std::vector<FileExtent> combined;
        combined.reserve(committed->file_extents.size() + 2);
        auto cursor = static_cast<std::uint64_t>(0);
        for (const auto& extent : committed->file_extents)
        {
            if (extent.logical_offset != cursor ||
                extent.physical_address == 0 ||
                extent.bytes == 0 ||
                extent.bytes > (previous_size - cursor))
            {
                return false;
            }
            cursor += extent.bytes;
            combined.push_back(extent);
        }
        if (cursor != previous_size || cursor >= requested_end)
        {
            return false;
        }

        const auto tail_bytes = requested_end - cursor;
        auto tail = allocate_file_extents(tail_bytes);
        if (!tail.has_value() || tail->empty())
        {
            return false;
        }
        for (const auto& extent : tail.value())
        {
            if (!stage_spaceman_allocation(extent.physical_address, extent.bytes))
            {
                return false;
            }
        }
        for (const auto& extent : tail.value())
        {
            if (cursor > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
            {
                return false;
            }
            combined.push_back(FileExtent{ cursor, extent.physical_address, extent.bytes });
            cursor += extent.bytes;
        }
        if (cursor < requested_end)
        {
            return false;
        }

        return stage_file_extents(inode.object_id, combined);
    };
    const auto remove_pending_file_extent_records = [&](std::uint64_t object_id)
    {
        const auto compact_pending_btree_records = [&](std::span<const std::size_t> removal_indices)
        {
            if (removal_indices.empty())
            {
                return;
            }

            for (const auto record_index : removal_indices)
            {
                if (record_index >= pending_btree_records_.size())
                {
                    return;
                }
            }
            for (const auto record_index : removal_indices)
            {
                remember_erased_pending_btree_record(record_index);
                UntrackPendingBtreeRecordIndex(pending_btree_records_[record_index], record_index);
            }

            std::size_t removal_cursor = 0;
            std::size_t output_index = 0;
            for (std::size_t input_index = 0; input_index < pending_btree_records_.size(); ++input_index)
            {
                if (removal_cursor < removal_indices.size() &&
                    removal_indices[removal_cursor] == input_index)
                {
                    ++removal_cursor;
                    continue;
                }

                if (output_index != input_index)
                {
                    pending_btree_records_[output_index] = std::move(pending_btree_records_[input_index]);
                }
                ++output_index;
            }
            pending_btree_records_.resize(output_index);

            const auto adjust_index_after_compaction = [&](std::size_t& index)
            {
                const auto removed_before = static_cast<std::size_t>(std::lower_bound(
                    removal_indices.begin(),
                    removal_indices.end(),
                    index) - removal_indices.begin());
                if (removed_before <= index)
                {
                    index -= removed_before;
                }
            };
            for (auto& [_, index] : pending_btree_file_inode_index_)
            {
                adjust_index_after_compaction(index);
            }
            for (auto& [_, index] : pending_btree_file_extent_index_)
            {
                adjust_index_after_compaction(index);
            }
            pending_btree_file_metadata_local_erase_count_.fetch_add(
                static_cast<std::uint64_t>(removal_indices.size()),
                std::memory_order_relaxed);
        };
        std::vector<std::size_t> removal_indices;
        if (auto offsets_it = pending_btree_file_extent_offsets_by_object_.find(object_id);
            offsets_it != pending_btree_file_extent_offsets_by_object_.end())
        {
            if (offsets_it->second.size() == 1)
            {
                const auto logical_offset = *offsets_it->second.begin();
                const PendingBtreeExtentKey key{ object_id, logical_offset };
                const auto extent_it = pending_btree_file_extent_index_.find(key);
                bool index_valid = extent_it != pending_btree_file_extent_index_.end() &&
                                   extent_it->second < pending_btree_records_.size();
                if (index_valid)
                {
                    DecodedBtreeExtent decoded{};
                    const auto& record = pending_btree_records_[extent_it->second];
                    index_valid = !record.tombstone &&
                                  record.kind == BtreeRecordKind::FileExtent &&
                                  DecodeBtreeExtentRecord(record, decoded) &&
                                  decoded.object_id == object_id &&
                                  decoded.logical_offset == logical_offset;
                }
                if (const auto record_count_it = pending_btree_file_extent_record_count_by_object_.find(object_id);
                    record_count_it == pending_btree_file_extent_record_count_by_object_.end() ||
                    record_count_it->second != 1)
                {
                    index_valid = false;
                }

                if (index_valid)
                {
                    const std::array<std::size_t, 1> single_removal{ extent_it->second };
                    compact_pending_btree_records(single_removal);
                    return;
                }
            }

            std::vector<std::pair<std::size_t, PendingBtreeExtentKey>> indexed_extents;
            indexed_extents.reserve(offsets_it->second.size());
            bool index_valid = true;
            for (const auto logical_offset : offsets_it->second)
            {
                const PendingBtreeExtentKey key{ object_id, logical_offset };
                const auto extent_it = pending_btree_file_extent_index_.find(key);
                if (extent_it == pending_btree_file_extent_index_.end() ||
                    extent_it->second >= pending_btree_records_.size())
                {
                    index_valid = false;
                    break;
                }

                DecodedBtreeExtent decoded{};
                const auto& record = pending_btree_records_[extent_it->second];
                if (record.tombstone ||
                    record.kind != BtreeRecordKind::FileExtent ||
                    !DecodeBtreeExtentRecord(record, decoded) ||
                    decoded.object_id != object_id ||
                    decoded.logical_offset != logical_offset)
                {
                    index_valid = false;
                    break;
                }
                indexed_extents.emplace_back(extent_it->second, key);
            }
            if (const auto record_count_it = pending_btree_file_extent_record_count_by_object_.find(object_id);
                record_count_it == pending_btree_file_extent_record_count_by_object_.end() ||
                record_count_it->second != indexed_extents.size())
            {
                index_valid = false;
            }

            if (index_valid)
            {
                std::sort(
                    indexed_extents.begin(),
                    indexed_extents.end(),
                    [](const auto& lhs, const auto& rhs)
                    {
                        return lhs.first > rhs.first;
                    });

                std::optional<std::size_t> previous_index;
                for (const auto& [record_index, key] : indexed_extents)
                {
                    if (previous_index.has_value() && *previous_index == record_index)
                    {
                        index_valid = false;
                        break;
                    }
                    previous_index = record_index;
                    if (record_index >= pending_btree_records_.size())
                    {
                        index_valid = false;
                        break;
                    }
                }
            }

            if (index_valid)
            {
                removal_indices.reserve(indexed_extents.size());
                for (const auto& [record_index, key] : indexed_extents)
                {
                    removal_indices.push_back(record_index);
                }
                std::sort(removal_indices.begin(), removal_indices.end());
                removal_indices.erase(
                    std::unique(removal_indices.begin(), removal_indices.end()),
                    removal_indices.end());
                compact_pending_btree_records(removal_indices);
                return;
            }
        }

        removal_indices.clear();
        for (std::size_t record_index = 0; record_index < pending_btree_records_.size(); ++record_index)
        {
            const auto& record = pending_btree_records_[record_index];
            if (record.kind != BtreeRecordKind::FileExtent)
            {
                continue;
            }

            DecodedBtreeExtent decoded{};
            if (!DecodeBtreeExtentRecord(record, decoded) || decoded.object_id != object_id)
            {
                continue;
            }
            removal_indices.push_back(record_index);
        }
        compact_pending_btree_records(removal_indices);
    };

    switch (request.operation)
    {
    case MutationOperation::CreateFile:
    case MutationOperation::CreateDirectory:
    {
        if (IsRootPath(normalized_path))
        {
            return reject(L"CreateRootPath");
        }

        const auto parent_path = ParentPath(normalized_path);
        const auto* parent_inode = LookupWorkingInodeByCanonicalPathKeyView(CanonicalPathKeyFromNormalizedPath(parent_path));
        if (parent_inode == nullptr || !parent_inode->is_directory)
        {
            return reject(L"CreateParentMissingOrNotDirectory:" + parent_path);
        }

        const auto leaf_name = LeafName(normalized_path);
        if (leaf_name.empty())
        {
            return reject(L"CreateLeafNameEmpty");
        }

        if (identity_bound && request.generation != target_xid)
        {
            return reject(L"ReplayCreateGenerationMismatch");
        }

        const auto* existing = LookupWorkingInodeByCanonicalPathKeyView(path_key);
        std::optional<std::uint64_t> replacement_id;
        if (existing != nullptr)
        {
            const auto existing_generation = existing->xid == 0
                ? existing->object_id
                : existing->xid;
            if (identity_bound &&
                (existing->object_id != request.object_id ||
                 existing_generation != request.generation))
            {
                return reject(L"ReplayCreateIdentityMismatch");
            }
            if (!request.replace_if_exists)
            {
                return reject(L"CreateDestinationExists");
            }
            if (existing->is_directory != (request.operation == MutationOperation::CreateDirectory))
            {
                return reject(L"CreateReplacementTypeMismatch");
            }
            if (existing->is_directory && HasWorkingChildren(existing->object_id))
            {
                return reject(L"CreateReplacementDirectoryNotEmpty");
            }

            const auto existing_snapshot = *existing;
            replacement_id = existing_snapshot.object_id;
            remove_working_directory_link(existing_snapshot.parent_object_id, existing_snapshot.name);
            erase_working_path_index(path_key);
            erase_working_inode(existing_snapshot.object_id);
            stage_directory_record(existing_snapshot.parent_object_id, existing_snapshot.name, existing_snapshot.object_id, true);
            if (!existing_snapshot.is_directory && existing_snapshot.logical_size > 0)
            {
                if (!stage_committed_file_extents_for_removal(existing_snapshot))
                {
                    return MutationStatus::AllocationFailed;
                }
            }
            stage_inode_record(existing_snapshot, true);
            if (!stage_object_map_update(existing_snapshot.object_id, 0, 0))
            {
                return MutationStatus::AllocationFailed;
            }
        }

        InodeRecord inode{};
        inode.object_id = identity_bound
            ? request.object_id
            : replacement_id.value_or(ResolveUniqueObjectId(normalized_path));
        if (identity_bound && working_inodes_.contains(inode.object_id) &&
            (!existing || existing->object_id != inode.object_id))
        {
            return reject(L"ReplayCreateObjectIdCollision");
        }
        inode.parent_object_id = parent_inode->object_id;
        inode.name = leaf_name;
        inode.full_path = normalized_path;
        inode.is_directory = request.operation == MutationOperation::CreateDirectory;
        inode.logical_size = 0;
        inode.data_physical_address = 0;
        inode.xid = target_xid;

        set_working_inode(inode);
        set_working_path_index(path_key, inode.object_id);
        upsert_working_directory_link(inode.parent_object_id, inode.name, inode.object_id, target_xid);

        if (!stage_object_map_update(inode.object_id, inode.data_physical_address, inode.logical_size))
        {
            return MutationStatus::AllocationFailed;
        }
        stage_inode_record(inode, false);
        stage_directory_record(inode.parent_object_id, inode.name, inode.object_id, false);
        resolved_mutation_object_id = inode.object_id;
        set_staged_identity(inode.object_id, inode.xid);
        break;
    }
    case MutationOperation::Write:
    {
        if (request.length == 0)
        {
            break;
        }
        const auto* inode = LookupWorkingInodeByCanonicalPathKeyView(path_key);
        if (inode == nullptr || inode->is_directory)
        {
            return reject(L"WriteTargetMissingOrDirectory");
        }
        if (!validate_existing_replay_identity(*inode, false))
        {
            return reject(L"ReplayWriteIdentityMismatch");
        }

        if (request.offset > (std::numeric_limits<std::uint64_t>::max() - request.length))
        {
            return reject(L"WriteRangeOverflow");
        }

        const auto requested_end = request.offset + request.length;
        const auto target_logical_size = std::max<std::uint64_t>(inode->logical_size, requested_end);
        auto& inode_ref = mutable_working_inode(inode->object_id);
        const auto previous_physical = inode_ref.data_physical_address;
        const auto previous_size = inode_ref.logical_size;
        auto next_physical = previous_physical;
        const auto previous_extent_is_pending =
            previous_physical != 0 &&
            previous_size > 0 &&
            !committed_read_extents_.contains(inode_ref.object_id) &&
            !working_read_extents_.contains(inode_ref.object_id) &&
            HasPendingSpacemanAllocation(previous_physical, previous_size);
        const auto pending_extents_cover_request = PendingReadExtentsCoverLogicalRange(
            inode_ref.object_id,
            request.offset,
            request.length);
        const auto can_extend_pending_extents =
            target_logical_size > previous_size &&
            pending_read_extent_updates_.contains(inode_ref.object_id);
        if (next_physical == 0 ||
            target_logical_size > previous_size ||
            (!previous_extent_is_pending && !pending_extents_cover_request))
        {
            if (can_extend_pending_extents &&
                try_extend_single_pending_file_extent(inode_ref.object_id, target_logical_size))
            {
                next_physical = pending_read_extent_updates_.at(inode_ref.object_id).front().physical_address;
            }
            else if (!pending_read_extent_updates_.contains(inode_ref.object_id) &&
                     !previous_extent_is_pending &&
                     previous_physical != 0 &&
                     previous_size > 0 &&
                     request.offset == previous_size &&
                     adopt_committed_extents_for_write(inode_ref, previous_size, requested_end))
            {
                // Exact appends can retain the already durable prefix and add
                // only a new tail extent. In-body overwrites must continue to
                // use copy-on-write so an interrupted commit cannot modify
                // the old committed bytes.
                next_physical = previous_physical;
            }
            else
            {
                const auto partial_overwrite_result =
                    try_stage_partial_committed_overwrite(
                        inode_ref,
                        previous_size,
                        request.offset,
                        request.length);
                if (partial_overwrite_result == PartialCommittedOverwriteResult::Applied)
                {
                    next_physical = pending_read_extent_updates_.at(inode_ref.object_id).front().physical_address;
                }
                else
                {
                    if (partial_overwrite_result == PartialCommittedOverwriteResult::Failed)
                    {
                        return MutationStatus::AllocationFailed;
                    }

                    const auto old_extents_were_pending = pending_read_extent_updates_.contains(inode_ref.object_id);
                    std::vector<FileExtent> retained_committed_extents;
                    if (old_extents_were_pending &&
                        !release_pending_file_extents(
                            inode_ref.object_id,
                            retained_committed_extents))
                    {
                        return MutationStatus::AllocationFailed;
                    }
                    if (old_extents_were_pending)
                    {
                        remove_pending_file_extent_records(inode_ref.object_id);
                        if (!stage_retained_committed_file_extents_for_removal(
                                inode_ref.object_id,
                                retained_committed_extents))
                        {
                            return MutationStatus::AllocationFailed;
                        }
                    }
                    const auto old_committed_extents_need_removal =
                        previous_physical != 0 &&
                        previous_size > 0 &&
                        !old_extents_were_pending &&
                        !previous_extent_is_pending;
                    const auto must_materialize_existing_payload =
                        old_committed_extents_need_removal ||
                        !retained_committed_extents.empty();
                    if (old_committed_extents_need_removal &&
                        !stage_committed_file_extents_for_removal(*inode))
                    {
                        return MutationStatus::AllocationFailed;
                    }
                    auto extents = allocate_file_extents(target_logical_size);
                    if (!extents.has_value() || extents->empty())
                    {
                        return MutationStatus::AllocationFailed;
                    }
                    for (const auto& extent : extents.value())
                    {
                        if (!stage_spaceman_allocation(extent.physical_address, extent.bytes))
                        {
                            return MutationStatus::AllocationFailed;
                        }
                    }
                    if (!stage_file_extents(inode_ref.object_id, extents.value()))
                    {
                        return MutationStatus::AllocationFailed;
                    }
                    if (must_materialize_existing_payload)
                    {
                        mark_pending_written_range(inode_ref.object_id, 0, target_logical_size);
                    }
                    next_physical = extents->front().physical_address;
                }
            }
        }

        inode_ref.data_physical_address = next_physical;
        inode_ref.logical_size = target_logical_size;
        inode_ref.xid = target_xid;
        if (!stage_object_map_update(inode_ref.object_id, inode_ref.data_physical_address, inode_ref.logical_size))
        {
            return MutationStatus::AllocationFailed;
        }
        if (previous_extent_is_pending &&
            previous_physical != 0 &&
            previous_physical != inode_ref.data_physical_address &&
            previous_size > 0)
        {
            const auto released_pending_extent = release_pending_spaceman_allocation(previous_physical, previous_size);
            if (!released_pending_extent && !stage_committed_file_extents_for_removal(*inode))
            {
                return MutationStatus::AllocationFailed;
            }
        }
        if (!working_read_extents_.contains(inode_ref.object_id))
        {
            stage_extent_record(inode_ref.object_id, 0, inode_ref.data_physical_address, inode_ref.logical_size, false);
        }
        stage_inode_record(inode_ref, false);
        (void)CoalescePendingWriteMutation(
            inode_ref.object_id,
            request,
            &path_key,
            &normalized_path);
        mark_pending_written_range(inode_ref.object_id, request.offset, request.length);
        TrackPendingPayloadSummaryMutation(
            request,
            normalized_path,
            normalized_secondary,
            inode_ref.object_id,
            &path_key,
            secondary_key);
        TrackPendingCloseDelaySummaryMutation(request, normalized_path, inode_ref.object_id, &path_key);
        if (out_staged_payload_identity)
        {
            *out_staged_payload_identity = {
                inode_ref.object_id,
                inode_ref.xid == 0 ? inode_ref.object_id : inode_ref.xid,
            };
        }
        CoalescePendingBtreeFileMetadata(inode_ref.object_id);
        mutation_applied = true;
        return MutationStatus::Applied;
        break;
    }
    case MutationOperation::SetFileSize:
    {
        const auto* inode = LookupWorkingInodeByCanonicalPathKeyView(path_key);
        if (inode == nullptr || inode->is_directory)
        {
            return reject(L"SetFileSizeTargetMissingOrDirectory");
        }
        if (!validate_existing_replay_identity(*inode, false))
        {
            return reject(L"ReplaySetFileSizeIdentityMismatch");
        }

        auto& inode_ref = mutable_working_inode(inode->object_id);
        const auto previous_physical = inode_ref.data_physical_address;
        const auto previous_size = inode_ref.logical_size;
        const auto committed_extents_it = committed_read_extents_.find(inode_ref.object_id);
        const bool preserve_committed_extents_for_same_size =
            request.length == previous_size &&
            previous_size > 0 &&
            previous_physical != 0 &&
            committed_extents_it != committed_read_extents_.end() &&
            !committed_extents_it->second.empty() &&
            !pending_read_extent_updates_.contains(inode_ref.object_id) &&
            !pending_written_ranges_.contains(inode_ref.object_id) &&
            !prepared_payload_ranges_.contains(inode_ref.object_id);
        if (request.length == 0)
        {
            if (previous_physical != 0 && previous_size > 0)
            {
                const auto pending_extents_it = pending_read_extent_updates_.find(inode_ref.object_id);
                if (pending_extents_it != pending_read_extent_updates_.end())
                {
                    std::vector<FileExtent> retained_committed_extents;
                    if (!release_pending_file_extents(
                            inode_ref.object_id,
                            retained_committed_extents))
                    {
                        return MutationStatus::AllocationFailed;
                    }
                    remove_pending_file_extent_records(inode_ref.object_id);
                    clear_pending_written_ranges(inode_ref.object_id);
                    if (!stage_retained_committed_file_extents_for_removal(
                            inode_ref.object_id,
                            retained_committed_extents))
                    {
                        return MutationStatus::AllocationFailed;
                    }
                }
                else if (!stage_committed_file_extents_for_removal(*inode))
                {
                    return MutationStatus::AllocationFailed;
                }
            }
            inode_ref.data_physical_address = 0;
        }
        else if (!preserve_committed_extents_for_same_size)
        {
            const auto old_extents_were_pending = pending_read_extent_updates_.contains(inode_ref.object_id);
            if (old_extents_were_pending &&
                try_extend_single_pending_file_extent(inode_ref.object_id, request.length))
            {
                inode_ref.data_physical_address =
                    pending_read_extent_updates_.at(inode_ref.object_id).front().physical_address;
            }
            else
            {
                std::vector<FileExtent> retained_committed_extents;
                if (old_extents_were_pending &&
                    !release_pending_file_extents(
                        inode_ref.object_id,
                        retained_committed_extents))
                {
                    return MutationStatus::AllocationFailed;
                }
                if (old_extents_were_pending)
                {
                    remove_pending_file_extent_records(inode_ref.object_id);
                    if (!stage_retained_committed_file_extents_for_removal(
                            inode_ref.object_id,
                            retained_committed_extents))
                    {
                        return MutationStatus::AllocationFailed;
                    }
                }
                const auto old_committed_extents_need_removal =
                    previous_physical != 0 &&
                    previous_size > 0 &&
                    !old_extents_were_pending &&
                    !(!committed_read_extents_.contains(inode_ref.object_id) &&
                      !working_read_extents_.contains(inode_ref.object_id) &&
                      HasPendingSpacemanAllocation(previous_physical, previous_size));
                if (old_committed_extents_need_removal &&
                    !stage_committed_file_extents_for_removal(*inode))
                {
                    return MutationStatus::AllocationFailed;
                }
                auto extents = allocate_file_extents(request.length);
                if (!extents.has_value() || extents->empty())
                {
                    return MutationStatus::AllocationFailed;
                }
                for (const auto& extent : extents.value())
                {
                    if (!stage_spaceman_allocation(extent.physical_address, extent.bytes))
                    {
                        return MutationStatus::AllocationFailed;
                    }
                }

                if (previous_physical != 0 &&
                    previous_size > 0 &&
                    (extents->size() != 1 || previous_physical != extents->front().physical_address))
                {
                    const auto released_pending_extent =
                        old_extents_were_pending ||
                        (!committed_read_extents_.contains(inode_ref.object_id) &&
                         !working_read_extents_.contains(inode_ref.object_id) &&
                         release_pending_spaceman_allocation(previous_physical, previous_size));
                    if (!released_pending_extent && !old_committed_extents_need_removal &&
                        !stage_committed_file_extents_for_removal(*inode))
                    {
                        return MutationStatus::AllocationFailed;
                    }
                }

                if (!stage_file_extents(inode_ref.object_id, extents.value()))
                {
                    return MutationStatus::AllocationFailed;
                }
                inode_ref.data_physical_address = extents->front().physical_address;
            }
        }
        inode_ref.logical_size = request.length;
        inode_ref.xid = target_xid;
        if (!stage_object_map_update(inode_ref.object_id, inode_ref.data_physical_address, inode_ref.logical_size))
        {
            return MutationStatus::AllocationFailed;
        }
        stage_inode_record(inode_ref, false);
        pending_mutation_recorded = CoalescePendingSetFileSizeMutation(inode_ref.object_id, request, &path_key);
        if (pending_mutation_recorded && !preserve_committed_extents_for_same_size)
        {
            TrackPendingPayloadSummaryMutation(
                request,
                normalized_path,
                normalized_secondary,
                inode_ref.object_id,
                &path_key,
                secondary_key);
        }
        resolved_mutation_object_id = inode_ref.object_id;
        set_staged_identity(inode_ref.object_id, inode_ref.xid);
        break;
    }
    case MutationOperation::Rename:
    {
        normalized_secondary = NormalizePath(request.secondary_path);
        if (normalized_secondary.empty() || IsRootPath(normalized_path))
        {
            return reject(normalized_secondary.empty() ? L"RenameDestinationEmpty" : L"RenameRootPath");
        }
        secondary_key_storage = CanonicalPathKeyFromNormalizedPath(normalized_secondary);
        secondary_key = &secondary_key_storage;

        const auto* inode = LookupWorkingInodeByCanonicalPathKeyView(path_key);
        if (inode == nullptr)
        {
            return reject(L"RenameSourceMissing");
        }
        if (!validate_existing_replay_identity(*inode, false))
        {
            return reject(L"ReplayRenameIdentityMismatch");
        }
        const auto source_path_key = path_key;
        const auto destination_path_key = secondary_key_storage;

        const auto destination_parent_path = ParentPath(normalized_secondary);
        const auto destination_parent_key = CanonicalPathKeyFromNormalizedPath(destination_parent_path);
        const auto* destination_parent = LookupWorkingInodeByCanonicalPathKeyView(destination_parent_key);
        if (destination_parent == nullptr || !destination_parent->is_directory)
        {
            return reject(L"RenameDestinationParentMissingOrNotDirectory:" + destination_parent_path);
        }
        if (LeafName(normalized_secondary).empty())
        {
            return reject(L"RenameDestinationLeafNameEmpty");
        }
        if (inode->is_directory &&
            (IsDescendantPath(destination_parent_path, normalized_path) ||
             CanonicalPathKeyFromNormalizedPath(destination_parent_path) == source_path_key))
        {
            return reject(L"RenameDirectoryIntoSelf");
        }

        const auto* destination_inode = LookupWorkingInodeByCanonicalPathKeyView(secondary_key_storage);
        const auto destination_is_same_object = destination_inode != nullptr &&
                                                destination_inode->object_id == inode->object_id;
        if (destination_is_same_object &&
            source_path_key == destination_path_key &&
            normalized_secondary == normalized_path)
        {
            // No-op rename request.
            return MutationStatus::Applied;
        }
        if (destination_inode != nullptr)
        {
            if (!destination_is_same_object && !request.replace_if_exists)
            {
                return reject(L"RenameDestinationExists");
            }
            if (!destination_is_same_object &&
                destination_inode->is_directory != inode->is_directory)
            {
                return reject(L"RenameDestinationTypeMismatch");
            }
            if (!destination_is_same_object &&
                destination_inode->is_directory && HasWorkingChildren(destination_inode->object_id))
            {
                return reject(L"RenameDestinationDirectoryNotEmpty");
            }
            if (!destination_is_same_object)
            {
                const auto destination_snapshot = *destination_inode;
                remove_working_directory_link(destination_snapshot.parent_object_id, destination_snapshot.name);
                erase_working_path_index(destination_path_key);
                erase_working_inode(destination_snapshot.object_id);
                stage_directory_record(destination_snapshot.parent_object_id, destination_snapshot.name, destination_snapshot.object_id, true);
                if (!destination_snapshot.is_directory &&
                    destination_snapshot.logical_size > 0)
                {
                    if (!stage_committed_file_extents_for_removal(destination_snapshot))
                    {
                        return MutationStatus::AllocationFailed;
                    }
                }
                stage_inode_record(destination_snapshot, true);
                if (!stage_object_map_update(destination_snapshot.object_id, 0, 0))
                {
                    return MutationStatus::AllocationFailed;
                }
            }
        }

        const auto source_prefix = IsRootPath(normalized_path) ? normalized_path : normalized_path + L"\\";
        const auto source_prefix_key = IsRootPath(normalized_path) ? source_path_key : source_path_key + L"\\";
        struct DescendantRename
        {
            std::uint64_t object_id = 0;
            std::wstring old_path;
            std::wstring new_path;
        };
        std::vector<DescendantRename> descendant_renames;
        if (inode->is_directory)
        {
            const auto descendant_object_ids = SnapshotWorkingDirectoryDescendantObjectIds(inode->object_id);
            descendant_renames.reserve(descendant_object_ids.size());
            for (const auto object_id : descendant_object_ids)
            {
                if (object_id == inode->object_id)
                {
                    continue;
                }

                auto child_it = working_inodes_.find(object_id);
                if (child_it == working_inodes_.end())
                {
                    continue;
                }
                const auto& child_inode = child_it->second;
                const auto child_path = child_inode.full_path;
                const auto child_path_key = CanonicalPathKeyFromNormalizedPath(child_path);
                if (child_path.size() >= source_prefix.size() &&
                    child_path_key.rfind(source_prefix_key, 0) == 0)
                {
                    descendant_renames.push_back(DescendantRename{
                        object_id,
                        child_path,
                        normalized_secondary + L"\\" + child_path.substr(source_prefix.size()) });
                }
            }
        }

        const auto old_parent_object_id = inode->parent_object_id;
        const auto old_name = inode->name;
        remove_working_directory_link(inode->parent_object_id, inode->name);
        erase_working_path_index(source_path_key);
        stage_directory_record(old_parent_object_id, old_name, inode->object_id, true);

        auto& inode_ref = mutable_working_inode(inode->object_id);
        inode_ref.parent_object_id = destination_parent->object_id;
        inode_ref.name = LeafName(normalized_secondary);
        inode_ref.full_path = normalized_secondary;
        inode_ref.xid = target_xid;
        set_working_path_index(destination_path_key, inode_ref.object_id);
        upsert_working_directory_link(inode_ref.parent_object_id, inode_ref.name, inode_ref.object_id, target_xid);
        stage_directory_record(inode_ref.parent_object_id, inode_ref.name, inode_ref.object_id, false);
        stage_inode_record(inode_ref, false);

        for (const auto& rename : descendant_renames)
        {
            const auto old_descendant_key = CanonicalPathKeyFromNormalizedPath(rename.old_path);
            const auto new_descendant_key = CanonicalPathKeyFromNormalizedPath(rename.new_path);
            erase_working_path_index(old_descendant_key);
            auto& descendant_inode = mutable_working_inode(rename.object_id);
            descendant_inode.full_path = rename.new_path;
            descendant_inode.xid = target_xid;
            set_working_path_index(new_descendant_key, rename.object_id);
            if (!stage_object_map_update(
                    descendant_inode.object_id,
                    descendant_inode.data_physical_address,
                    descendant_inode.logical_size))
            {
                return MutationStatus::AllocationFailed;
            }
            stage_inode_record(descendant_inode, false);
        }

        if (!stage_object_map_update(inode_ref.object_id, inode_ref.data_physical_address, inode_ref.logical_size))
        {
            return MutationStatus::AllocationFailed;
        }
        if (!inode_ref.is_directory && !request.replace_if_exists)
        {
            pending_mutation_recorded = CoalescePendingRenameMutation(
                inode_ref.object_id,
                request,
                source_path_key,
                destination_path_key);
            if (pending_mutation_recorded)
            {
                TrackPendingPayloadSummaryMutation(
                    request,
                    normalized_path,
                    normalized_secondary,
                    inode_ref.object_id,
                    &path_key,
                    secondary_key);
            }
        }
        resolved_mutation_object_id = inode_ref.object_id;
        set_staged_identity(inode_ref.object_id, inode_ref.xid);
        break;
    }
    case MutationOperation::Delete:
    {
        if (IsRootPath(normalized_path))
        {
            return reject(L"DeleteRootPath");
        }

        const auto* inode = LookupWorkingInodeByCanonicalPathKeyView(path_key);
        if (inode == nullptr)
        {
            return reject(L"DeleteTargetMissing");
        }
        if (inode->is_directory && HasWorkingChildren(inode->object_id))
        {
            return reject(L"DeleteDirectoryNotEmpty");
        }

        const auto inode_snapshot = *inode;
        if (!validate_existing_replay_identity(inode_snapshot, true))
        {
            return reject(L"ReplayDeleteIdentityMismatch");
        }
        remove_working_directory_link(inode_snapshot.parent_object_id, inode_snapshot.name);
        erase_working_path_index(path_key);
        erase_working_inode(inode_snapshot.object_id);
        stage_directory_record(inode_snapshot.parent_object_id, inode_snapshot.name, inode_snapshot.object_id, true);
        if (!inode_snapshot.is_directory && inode_snapshot.logical_size > 0)
        {
            if (pending_read_extent_updates_.contains(inode_snapshot.object_id))
            {
                std::vector<FileExtent> retained_committed_extents;
                if (!release_pending_file_extents(
                        inode_snapshot.object_id,
                        retained_committed_extents))
                {
                    return MutationStatus::AllocationFailed;
                }
                remove_pending_file_extent_records(inode_snapshot.object_id);
                clear_pending_written_ranges(inode_snapshot.object_id);
                if (!stage_retained_committed_file_extents_for_removal(
                        inode_snapshot.object_id,
                        retained_committed_extents))
                {
                    return MutationStatus::AllocationFailed;
                }
            }
            else if (!stage_committed_file_extents_for_removal(inode_snapshot))
            {
                return MutationStatus::AllocationFailed;
            }
        }
        stage_inode_record(inode_snapshot, true);

        if (!stage_object_map_update(inode_snapshot.object_id, 0, 0))
        {
            return MutationStatus::AllocationFailed;
        }
        resolved_mutation_object_id = inode_snapshot.object_id;
        set_staged_identity(
            inode_snapshot.object_id,
            inode_snapshot.xid == 0 ? inode_snapshot.object_id : inode_snapshot.xid);
        break;
    }
    case MutationOperation::SetBasicInfo:
    {
        const auto* inode = LookupWorkingInodeByCanonicalPathKeyView(path_key);
        if (inode == nullptr)
        {
            return reject(L"SetBasicInfoTargetMissing");
        }
        if (!validate_existing_replay_identity(*inode, false))
        {
            return reject(L"ReplaySetBasicInfoIdentityMismatch");
        }

        auto& inode_ref = mutable_working_inode(inode->object_id);
        inode_ref.xid = target_xid;
        inode_ref.timestamp_utc = request.timestamp_utc;
        stage_inode_record(inode_ref, false);
        pending_mutation_recorded = CoalescePendingBasicInfoMutation(inode_ref.object_id, request, &path_key);
        CoalescePendingBtreeFileMetadata(inode_ref.object_id);
        resolved_mutation_object_id = inode_ref.object_id;
        set_staged_identity(inode_ref.object_id, inode_ref.xid);
        break;
    }
    default:
        return MutationStatus::UnsupportedOperation;
    }

    if (!pending_mutation_recorded)
    {
        pending_mutations_.push_back(request);
        pending_mutation_path_key_cache_.emplace_back();
        TrackPendingPayloadSummaryMutation(
            request,
            normalized_path,
            normalized_secondary,
            resolved_mutation_object_id,
            &path_key,
            secondary_key);
        TrackPendingCloseDelaySummaryMutation(request, normalized_path, resolved_mutation_object_id, &path_key);
        if (request.operation == MutationOperation::SetBasicInfo &&
            resolved_mutation_object_id.has_value() &&
            *resolved_mutation_object_id != 0)
        {
            pending_basic_info_mutation_index_by_object_id_[*resolved_mutation_object_id] = pending_mutations_.size() - 1;
        }
    }
    mutation_applied = true;
    return MutationStatus::Applied;
}

MetadataStore::CommitStatus MetadataStore::CommitPendingMutations()
{
    ScopedPerfTimer perf_scope(commit_pending_perf_);

    last_commit_stage_ = "start";
    last_commit_failure_reason_.clear();
    last_commit_failure_detail_.clear();
    last_commit_failure_object_id_.reset();
    const auto fail_commit = [this](CommitStatus status, std::string_view stage) -> CommitStatus
    {
        if (!stage.empty())
        {
            last_commit_stage_ = std::string(stage);
        }
        return status;
    };

    if (!IsNativeWriteReady())
    {
        return fail_commit(CommitStatus::NotReady, "not-ready");
    }

    if (pending_mutations_.empty())
    {
        return fail_commit(CommitStatus::NothingToCommit, "nothing-to-commit");
    }

    if (!commit_path_ready_ || !write_device_allowed_)
    {
        return fail_commit(CommitStatus::NotWritable, "not-writable");
    }
    if (!AllowCommitStage("before-preflight"))
    {
        return fail_commit(CommitStatus::InvariantFailed, "preflight-stage-blocked");
    }
    if (!SanitizeWorkingFreeExtents())
    {
        return fail_commit(CommitStatus::InvariantFailed, "working-free-extents-sanitize-failed");
    }
    const auto strict_preflight =
        commit_stage_hook_requires_strict_verification_ || IsStrictCommitVerificationEnabled();
    const auto delayable_content_preflight = PendingMutationsCanSkipPreflightInodeGraphValidation();
    const auto validate_inode_graphs = strict_preflight || !delayable_content_preflight;
    const auto validate_projected_btree_state =
        strict_preflight ||
        !PendingMutationsCanSkipPreflightProjectedBtreeValidation();
    if (!validate_inode_graphs)
    {
        commit_inode_graph_validation_skip_count_.fetch_add(1, std::memory_order_relaxed);
    }
    if (!validate_projected_btree_state)
    {
        commit_projected_btree_validation_skip_count_.fetch_add(1, std::memory_order_relaxed);
    }
    if (!ValidatePendingCommitState(validate_inode_graphs, validate_projected_btree_state))
    {
        return fail_commit(CommitStatus::InvariantFailed, "preflight-validation-failed");
    }

    const auto target_xid = checkpoint_xid_ + 1;
    if (!BuildCommitBlob(target_xid) || commit_blob_serialization_buffer_.empty())
    {
        return fail_commit(CommitStatus::PersistFailed, "commit-blob-build-failed");
    }
    auto& commit_blob = commit_blob_serialization_buffer_;
    const auto commit_blob_persist_bytes = AlignExtentBytes(static_cast<std::uint64_t>(commit_blob.size()));
    if (commit_blob_persist_bytes == 0 ||
        commit_blob_persist_bytes < static_cast<std::uint64_t>(commit_blob.size()) ||
        commit_blob_persist_bytes > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
    {
        return fail_commit(CommitStatus::PersistFailed, "commit-blob-alignment-invalid");
    }
    if (static_cast<std::size_t>(commit_blob_persist_bytes) > commit_blob.size())
    {
        commit_blob.resize(static_cast<std::size_t>(commit_blob_persist_bytes), std::byte{0});
    }

    ExtentAllocator::ContiguousAllocationUndo commit_extent_undo{};
    const auto working_next_extent_snapshot = working_next_ephemeral_extent_;
    const auto working_free_extents_sanitized_snapshot = working_free_extents_sanitized_;
    auto commit_extent = AllocateExtentFromSanitizedWorkingFreeExtents(
        commit_blob_persist_bytes,
        &commit_extent_undo);
    if (!commit_extent.has_value())
    {
        return fail_commit(CommitStatus::AllocationFailed, "commit-extent-allocate-failed");
    }
    const auto restore_commit_extent_allocation = [&]() -> bool
    {
        switch (commit_extent_undo.source)
        {
        case ExtentAllocator::ContiguousAllocationUndo::Source::FreeExtent:
            if (commit_extent_undo.free_extent_erased)
            {
                const auto insert_index = std::min(
                    commit_extent_undo.free_extent_index,
                    working_spaceman_free_extents_.size());
                working_spaceman_free_extents_.insert(
                    working_spaceman_free_extents_.begin() + static_cast<std::ptrdiff_t>(insert_index),
                    commit_extent_undo.previous_free_extent);
            }
            else if (commit_extent_undo.free_extent_index < working_spaceman_free_extents_.size())
            {
                working_spaceman_free_extents_[commit_extent_undo.free_extent_index] =
                    commit_extent_undo.previous_free_extent;
            }
            else
            {
                return false;
            }
            commit_extent_working_free_local_rollback_count_.fetch_add(1, std::memory_order_relaxed);
            return true;
        case ExtentAllocator::ContiguousAllocationUndo::Source::EphemeralTail:
            working_next_ephemeral_extent_ = commit_extent_undo.previous_next_ephemeral_extent;
            commit_extent_working_free_local_rollback_count_.fetch_add(1, std::memory_order_relaxed);
            return true;
        case ExtentAllocator::ContiguousAllocationUndo::Source::None:
        default:
            return false;
        }
    };
    std::vector<ExtentAllocator::AddFreeExtentUndo> commit_working_free_extent_add_undos;
    if (!StageSpacemanAllocation(*commit_extent, commit_blob_persist_bytes))
    {
        if (!restore_commit_extent_allocation())
        {
            working_next_ephemeral_extent_ = working_next_extent_snapshot;
            commit_extent_working_free_snapshot_count_.fetch_add(1, std::memory_order_relaxed);
            (void)SanitizeWorkingFreeExtents();
        }
        return fail_commit(CommitStatus::AllocationFailed, "commit-extent-stage-allocation-failed");
    }
    const auto rollback_commit_extent_stage = [&]()
    {
        bool exact_working_free_rollback = true;
        for (auto undo_it = commit_working_free_extent_add_undos.rbegin();
             undo_it != commit_working_free_extent_add_undos.rend();
             ++undo_it)
        {
            if (!ExtentAllocator::RollbackAddFreeExtent(working_spaceman_free_extents_, *undo_it))
            {
                commit_extent_working_free_snapshot_count_.fetch_add(1, std::memory_order_relaxed);
                (void)SanitizeWorkingFreeExtents();
                exact_working_free_rollback = false;
                break;
            }
            commit_extent_working_free_local_rollback_count_.fetch_add(1, std::memory_order_relaxed);
        }
        commit_working_free_extent_add_undos.clear();
        if (!pending_spaceman_allocations_.empty() &&
            pending_spaceman_allocations_.back().physical_address == *commit_extent)
        {
            ErasePendingSpacemanAllocationAt(pending_spaceman_allocations_.size() - 1);
        }
        working_next_ephemeral_extent_ = working_next_extent_snapshot;
        if (exact_working_free_rollback && restore_commit_extent_allocation())
        {
            return;
        }

        tracking_spaceman_free_extent_delta_ = true;
        ScopeExit clear_tracking_spaceman_free_extent_delta{
            [&]()
            {
                tracking_spaceman_free_extent_delta_ = false;
            }};
        if (FreeExtent(*commit_extent, commit_blob_persist_bytes))
        {
            commit_extent_working_free_local_rollback_count_.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        commit_extent_working_free_snapshot_count_.fetch_add(1, std::memory_order_relaxed);
        (void)SanitizeWorkingFreeExtents();
    };
    if (!ValidateCommitExtentStage(*commit_extent, commit_blob_persist_bytes))
    {
        rollback_commit_extent_stage();
        return fail_commit(CommitStatus::InvariantFailed, "commit-extent-fast-validation-failed");
    }

    struct PendingPayloadWriteView
    {
        std::uint64_t physical_address = 0;
        std::uint64_t object_id = 0;
        std::uint64_t generation = 0;
        const std::wstring* path = nullptr;
        std::shared_ptr<std::vector<std::byte>> payload;
        std::uint64_t logical_offset = 0;
        std::uint64_t logical_size = 0;
        std::size_t offset = 0;
        std::size_t length = 0;
    };

    last_raw_mutation_count_.store(
        static_cast<std::uint64_t>(pending_mutations_.size()),
        std::memory_order_relaxed);
    last_compacted_mutation_count_.store(
        static_cast<std::uint64_t>(pending_payload_object_ids_.size()),
        std::memory_order_relaxed);
    CompactPendingPayloadSummaryObjectOrder();

    std::size_t pending_payload_write_reserve = pending_payload_object_order_.size();
    std::size_t pending_payload_write_reserve_extra = 0;
    const auto add_pending_payload_write_reserve_extra =
        [&](std::size_t extra_entries)
    {
        if (extra_entries == 0)
        {
            return;
        }
        if (extra_entries > (std::numeric_limits<std::size_t>::max() - pending_payload_write_reserve_extra))
        {
            pending_payload_write_reserve_extra = std::numeric_limits<std::size_t>::max();
            return;
        }
        pending_payload_write_reserve_extra += extra_entries;
    };
    for (const auto& [object_id, ranges] : pending_written_ranges_)
    {
        if (ranges.size() > 1 && pending_payload_object_ids_.contains(object_id))
        {
            add_pending_payload_write_reserve_extra(ranges.size() - 1);
        }
    }
    for (const auto& [object_id, extents] : pending_read_extent_updates_)
    {
        if (extents.size() <= 1 || !pending_payload_object_ids_.contains(object_id))
        {
            continue;
        }
        const auto written_ranges_it = pending_written_ranges_.find(object_id);
        const auto already_estimated_views = written_ranges_it == pending_written_ranges_.end()
            ? std::size_t{1}
            : std::max<std::size_t>(1, written_ranges_it->second.size());
        if (extents.size() > already_estimated_views)
        {
            add_pending_payload_write_reserve_extra(extents.size() - already_estimated_views);
        }
    }
    if (pending_payload_write_reserve_extra > 0)
    {
        pending_payload_write_reserve_extra_pass_count_.fetch_add(1, std::memory_order_relaxed);
        pending_payload_write_reserve_extra_entry_count_.fetch_add(
            static_cast<std::uint64_t>(
                std::min<std::size_t>(
                    pending_payload_write_reserve_extra,
                    static_cast<std::size_t>(std::numeric_limits<std::uint64_t>::max()))),
            std::memory_order_relaxed);
        if (pending_payload_write_reserve_extra <=
            (std::numeric_limits<std::size_t>::max() - pending_payload_write_reserve))
        {
            pending_payload_write_reserve += pending_payload_write_reserve_extra;
        }
    }

    std::vector<PendingPayloadWriteView> pending_payload_writes;
    pending_payload_writes.reserve(pending_payload_write_reserve);
    pending_payload_object_order_iteration_count_.fetch_add(1, std::memory_order_relaxed);
    for (const auto object_id : pending_payload_object_order_)
    {
        if (!pending_payload_object_ids_.contains(object_id))
        {
            continue;
        }

        const auto inode_it = working_inodes_.find(object_id);
        if (inode_it == working_inodes_.end() ||
            inode_it->second.is_directory ||
            inode_it->second.data_physical_address == 0 ||
            inode_it->second.logical_size == 0)
        {
            continue;
        }
        const auto& inode = inode_it->second;

        if (inode.logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
        {
            rollback_commit_extent_stage();
            return fail_commit(CommitStatus::PersistFailed, "payload-size-overflow");
        }

        std::shared_ptr<std::vector<std::byte>> payload_bytes;

        std::vector<FileExtent> fallback_payload_extents;
        const auto* payload_extents = LookupSortedReadExtents(inode.object_id);
        if (!payload_extents)
        {
            if (auto pending_extents_it = pending_read_extent_updates_.find(inode.object_id);
                pending_extents_it != pending_read_extent_updates_.end())
            {
                payload_extents = &pending_extents_it->second;
            }
            else if (auto working_extents_it = working_read_extents_.find(inode.object_id);
                     working_extents_it != working_read_extents_.end())
            {
                payload_extents = &working_extents_it->second;
            }
            else if (auto committed_extents_it = committed_read_extents_.find(inode.object_id);
                     committed_extents_it != committed_read_extents_.end())
            {
                payload_extents = &committed_extents_it->second;
            }
            else
            {
                fallback_payload_extents.push_back(FileExtent{ 0, inode.data_physical_address, inode.logical_size });
                payload_extents = &fallback_payload_extents;
            }
        }
        if (!HasLogicalExtentCoverage(*payload_extents, inode.logical_size))
        {
            rollback_commit_extent_stage();
            return fail_commit(CommitStatus::PersistFailed, "payload-extent-coverage-invalid");
        }

        const auto prepared_ranges_it = prepared_payload_ranges_.find(inode.object_id);
        const auto written_ranges_it = pending_written_ranges_.find(inode.object_id);
        const auto append_pending_payload_write =
            [&](std::uint64_t logical_offset, std::uint64_t physical_address, std::uint64_t bytes) -> bool
        {
            if (bytes == 0 ||
                bytes > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()) ||
                logical_offset > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
            {
                return false;
            }

            const auto slice_offset = static_cast<std::size_t>(logical_offset);
            const auto slice_bytes = static_cast<std::size_t>(bytes);
            if (!file_payload_range_provider_ && !payload_bytes)
            {
                if (!file_payload_provider_)
                {
                    return false;
                }
                auto resolved = file_payload_provider_(inode.full_path, inode.logical_size);
                if (!resolved.has_value())
                {
                    return false;
                }
                payload_bytes = std::make_shared<std::vector<std::byte>>(std::move(resolved.value()));
                const auto logical_size = static_cast<std::size_t>(inode.logical_size);
                if (payload_bytes->size() < logical_size)
                {
                    payload_bytes->resize(logical_size, std::byte{0});
                }
                else if (payload_bytes->size() > logical_size)
                {
                    payload_bytes->resize(logical_size);
                }
            }
            if (payload_bytes &&
                (slice_offset > payload_bytes->size() ||
                 slice_bytes > (payload_bytes->size() - slice_offset)))
            {
                return false;
            }

            pending_payload_writes.push_back(PendingPayloadWriteView{
                physical_address,
                inode.object_id,
                target_xid,
                &inode.full_path,
                payload_bytes,
                logical_offset,
                inode.logical_size,
                slice_offset,
                slice_bytes,
            });
            return true;
        };

        for (const auto& extent : *payload_extents)
        {
            if (extent.logical_offset >= inode.logical_size)
            {
                continue;
            }

            const auto logical_tail = inode.logical_size - extent.logical_offset;
            const auto extent_logical_bytes = std::min(extent.bytes, logical_tail);
            if (extent_logical_bytes == 0 ||
                extent_logical_bytes > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()) ||
                extent.logical_offset > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
            {
                rollback_commit_extent_stage();
                return fail_commit(CommitStatus::PersistFailed, "payload-extent-size-invalid");
            }

            const auto extent_end = extent.logical_offset + extent_logical_bytes;
            const auto append_unprepared_written_window =
                [&](std::uint64_t window_begin, std::uint64_t window_end) -> bool
            {
                if (window_begin >= window_end)
                {
                    return true;
                }

                auto cursor = window_begin;
                if (prepared_ranges_it != prepared_payload_ranges_.end())
                {
                    for (const auto& prepared_range : prepared_ranges_it->second)
                    {
                        if (prepared_range.bytes == 0 ||
                            prepared_range.offset > (std::numeric_limits<std::uint64_t>::max() - prepared_range.bytes))
                        {
                            continue;
                        }

                        const auto prepared_end = prepared_range.offset + prepared_range.bytes;
                        if (prepared_end <= cursor)
                        {
                            continue;
                        }
                        if (prepared_range.offset >= window_end)
                        {
                            break;
                        }
                        if (prepared_range.offset > cursor)
                        {
                            const auto logical_offset = cursor;
                            const auto bytes = prepared_range.offset - cursor;
                            if (extent.physical_address >
                                (std::numeric_limits<std::uint64_t>::max() - (logical_offset - extent.logical_offset)))
                            {
                                rollback_commit_extent_stage();
                                return false;
                            }
                            const auto physical_address = extent.physical_address + (logical_offset - extent.logical_offset);
                            if (!append_pending_payload_write(logical_offset, physical_address, bytes))
                            {
                                rollback_commit_extent_stage();
                                return false;
                            }
                        }

                        cursor = std::max(cursor, std::min(prepared_end, window_end));
                        if (cursor >= window_end)
                        {
                            break;
                        }
                    }
                }

                if (cursor < window_end)
                {
                    if (extent.physical_address >
                        (std::numeric_limits<std::uint64_t>::max() - (cursor - extent.logical_offset)))
                    {
                        rollback_commit_extent_stage();
                        return false;
                    }
                    const auto physical_address = extent.physical_address + (cursor - extent.logical_offset);
                    if (!append_pending_payload_write(cursor, physical_address, window_end - cursor))
                    {
                        rollback_commit_extent_stage();
                        return false;
                    }
                }

                return true;
            };

            if (written_ranges_it == pending_written_ranges_.end())
            {
                if (!append_unprepared_written_window(extent.logical_offset, extent_end))
                {
                    return fail_commit(CommitStatus::PersistFailed, "payload-extent-slice-invalid");
                }
                continue;
            }

            for (const auto& written_range : written_ranges_it->second)
            {
                if (written_range.bytes == 0 ||
                    written_range.offset > (std::numeric_limits<std::uint64_t>::max() - written_range.bytes))
                {
                    continue;
                }

                const auto written_end = written_range.offset + written_range.bytes;
                if (written_end <= extent.logical_offset)
                {
                    continue;
                }
                if (written_range.offset >= extent_end)
                {
                    break;
                }

                const auto window_begin = std::max(extent.logical_offset, written_range.offset);
                const auto window_end = std::min(extent_end, written_end);
                if (!append_unprepared_written_window(window_begin, window_end))
                {
                    return fail_commit(CommitStatus::PersistFailed, "payload-extent-slice-invalid");
                }
            }
        }
    }

    const auto pending_payload_write_less =
        [](const PendingPayloadWriteView& lhs, const PendingPayloadWriteView& rhs)
    {
        if (lhs.physical_address == rhs.physical_address)
        {
            return lhs.length < rhs.length;
        }
        return lhs.physical_address < rhs.physical_address;
    };
    const bool payload_writes_already_ordered =
        pending_payload_writes.size() < 2 ||
        std::is_sorted(
            pending_payload_writes.begin(),
            pending_payload_writes.end(),
            pending_payload_write_less);
    if (payload_writes_already_ordered)
    {
        pending_payload_write_order_fast_count_.fetch_add(1, std::memory_order_relaxed);
    }
    else
    {
        pending_payload_write_sort_count_.fetch_add(1, std::memory_order_relaxed);
        std::sort(
            pending_payload_writes.begin(),
            pending_payload_writes.end(),
            pending_payload_write_less);
    }
    if (pending_payload_writes.size() > 1)
    {
        pending_payload_write_coalesce_in_place_count_.fetch_add(1, std::memory_order_relaxed);
        std::size_t output_index = 1;
        std::uint64_t coalesced_entries = 0;
        for (std::size_t read_index = 1; read_index < pending_payload_writes.size(); ++read_index)
        {
            auto& previous = pending_payload_writes[output_index - 1];
            auto& write = pending_payload_writes[read_index];
            const auto write_length = static_cast<std::uint64_t>(write.length);
            const auto previous_length = static_cast<std::uint64_t>(previous.length);
            const bool size_t_lengths_fit =
                write.length <= (std::numeric_limits<std::size_t>::max() - previous.length);
            const bool uint64_lengths_fit =
                write_length <= (std::numeric_limits<std::uint64_t>::max() - previous_length);
            const auto merged_size_t_length = size_t_lengths_fit ? (previous.length + write.length) : 0;
            const auto merged_length = uint64_lengths_fit ? (previous_length + write_length) : 0;
            const bool can_merge =
                size_t_lengths_fit &&
                uint64_lengths_fit &&
                !previous.payload &&
                !write.payload &&
                previous.object_id == write.object_id &&
                previous.generation == write.generation &&
                previous.path != nullptr &&
                write.path != nullptr &&
                *previous.path == *write.path &&
                previous.logical_size == write.logical_size &&
                previous.physical_address <= (std::numeric_limits<std::uint64_t>::max() - merged_length) &&
                previous.logical_offset <= (std::numeric_limits<std::uint64_t>::max() - merged_length) &&
                previous.offset <= (std::numeric_limits<std::size_t>::max() - merged_size_t_length) &&
                previous.physical_address + previous_length == write.physical_address &&
                previous.logical_offset + previous_length == write.logical_offset &&
                previous.offset + previous.length == write.offset;
            if (can_merge)
            {
                previous.length += write.length;
                ++coalesced_entries;
                continue;
            }

            if (output_index != read_index)
            {
                pending_payload_writes[output_index] = std::move(write);
            }
            ++output_index;
        }
        if (coalesced_entries > 0)
        {
            pending_payload_write_coalesced_entry_count_.fetch_add(coalesced_entries, std::memory_order_relaxed);
        }
        pending_payload_writes.resize(output_index);
    }

    if (!AllowCommitStage("before-device-write"))
    {
        rollback_commit_extent_stage();
        return CommitStatus::PersistFailed;
    }

    if (!pending_payload_writes.empty() && !AllowCommitStage("before-payload-device-write"))
    {
        rollback_commit_extent_stage();
        return CommitStatus::PersistFailed;
    }

    const auto append_payload_segment = [&](const PendingPayloadWriteView& segment, std::vector<std::byte>& destination) -> bool
    {
        const auto original_size = destination.size();
        if (segment.length > destination.max_size() - original_size)
        {
            return false;
        }

        if (segment.payload)
        {
            if (segment.offset > segment.payload->size() ||
                segment.length > (segment.payload->size() - segment.offset))
            {
                return false;
            }
            destination.insert(
                destination.end(),
                segment.payload->begin() + static_cast<std::ptrdiff_t>(segment.offset),
                segment.payload->begin() + static_cast<std::ptrdiff_t>(segment.offset + segment.length));
            return true;
        }

        if (!segment.path ||
            !file_payload_range_provider_ ||
            segment.logical_offset > (std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(segment.length)))
        {
            return false;
        }

        destination.resize(original_size + segment.length);
        if (file_payload_range_provider_(
                *segment.path,
                PayloadIdentity{ segment.object_id, segment.generation },
                segment.logical_offset,
                std::span<std::byte>(destination.data() + static_cast<std::ptrdiff_t>(original_size), segment.length)))
        {
            return true;
        }

        if (!file_payload_provider_)
        {
            destination.resize(original_size);
            return false;
        }

        auto fallback_payload = file_payload_provider_(*segment.path, segment.logical_size);
        if (!fallback_payload.has_value())
        {
            destination.resize(original_size);
            return false;
        }
        if (segment.logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
        {
            destination.resize(original_size);
            return false;
        }
        auto& fallback = fallback_payload.value();
        const auto fallback_size = static_cast<std::size_t>(segment.logical_size);
        if (fallback.size() < fallback_size)
        {
            fallback.resize(fallback_size, std::byte{0});
        }
        else if (fallback.size() > fallback_size)
        {
            fallback.resize(fallback_size);
        }
        if (segment.offset > fallback.size() ||
            segment.length > (fallback.size() - segment.offset))
        {
            destination.resize(original_size);
            return false;
        }
        std::copy(
            fallback.begin() + static_cast<std::ptrdiff_t>(segment.offset),
            fallback.begin() + static_cast<std::ptrdiff_t>(segment.offset + segment.length),
            destination.begin() + static_cast<std::ptrdiff_t>(original_size));
        return true;
    };

    const auto can_reference_payload = [](const PendingPayloadWriteView& write) -> bool
    {
        return write.payload &&
            write.offset <= write.payload->size() &&
            write.length <= (write.payload->size() - write.offset);
    };

    const auto pending_allocation_contains_range =
        [&](std::uint64_t physical_address, std::uint64_t bytes) -> bool
    {
        if (physical_address == 0 ||
            bytes == 0 ||
            physical_address > (std::numeric_limits<std::uint64_t>::max() - bytes) ||
            pending_spaceman_allocation_index_.size() != pending_spaceman_allocations_.size())
        {
            return false;
        }

        auto allocation_it = pending_spaceman_allocation_index_.upper_bound(physical_address);
        if (allocation_it == pending_spaceman_allocation_index_.begin())
        {
            return false;
        }
        --allocation_it;
        if (allocation_it->second >= pending_spaceman_allocations_.size())
        {
            return false;
        }

        const auto& allocation = pending_spaceman_allocations_[allocation_it->second];
        return allocation.physical_address == allocation_it->first &&
               PhysicalRangeContains(allocation.physical_address, allocation.bytes, physical_address, bytes);
    };

    const auto aligned_fresh_tail_write_length =
        [&](const PendingPayloadWriteView& write) -> std::optional<std::size_t>
    {
        if (block_size_ == 0 || write.length == 0)
        {
            return std::nullopt;
        }
        if (write.payload && write.length > kPayloadTailZeroPadReferenceCopyLimit)
        {
            return std::nullopt;
        }
        const auto block_bytes = static_cast<std::uint64_t>(block_size_);
        if ((write.physical_address % block_bytes) != 0 ||
            (write.logical_offset % block_bytes) != 0 ||
            write.logical_offset > (std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(write.length)))
        {
            return std::nullopt;
        }
        if ((write.logical_offset + static_cast<std::uint64_t>(write.length)) != write.logical_size)
        {
            return std::nullopt;
        }

        const auto aligned_length = AlignExtentBytes(static_cast<std::uint64_t>(write.length));
        if (aligned_length == 0 ||
            aligned_length == static_cast<std::uint64_t>(write.length) ||
            aligned_length > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()) ||
            write.physical_address > (std::numeric_limits<std::uint64_t>::max() - aligned_length) ||
            !pending_allocation_contains_range(write.physical_address, aligned_length))
        {
            return std::nullopt;
        }

        return static_cast<std::size_t>(aligned_length);
    };

    const auto record_tail_zero_pad = [&](std::size_t payload_length, std::size_t padded_length)
    {
        if (padded_length <= payload_length)
        {
            return;
        }
        payload_tail_zero_pad_count_.fetch_add(1, std::memory_order_relaxed);
        payload_tail_zero_pad_bytes_.fetch_add(
            static_cast<std::uint64_t>(padded_length - payload_length),
            std::memory_order_relaxed);
    };

    const auto should_use_bounded_range_materialization =
        [&](const PendingPayloadWriteView& write) -> bool
    {
        return !write.payload &&
            file_payload_range_provider_ &&
            write.length > kPayloadBatchContiguousStorageLimit;
    };

    const auto append_payload_write_window =
        [&](const std::vector<BlockDevice::WriteSpan>& writes) -> bool
    {
        if (writes.empty())
        {
            return true;
        }
        std::uint64_t bytes = 0;
        for (const auto& write : writes)
        {
            const auto write_bytes = static_cast<std::uint64_t>(write.buffer.size());
            if (bytes <= (std::numeric_limits<std::uint64_t>::max() - write_bytes))
            {
                bytes += write_bytes;
            }
            else
            {
                bytes = std::numeric_limits<std::uint64_t>::max();
            }
        }
        if (!device_.WriteBatch(writes))
        {
            return false;
        }
        payload_window_batch_count_.fetch_add(1, std::memory_order_relaxed);
        payload_window_batch_bytes_.fetch_add(bytes, std::memory_order_relaxed);
        return true;
    };

    std::string bounded_materialize_failure = "unknown";
    const auto write_bounded_range_materialized_payload =
        [&](const PendingPayloadWriteView& write) -> bool
    {
        if (!file_payload_range_provider_ ||
            write.path == nullptr ||
            write.logical_offset > (std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(write.length)) ||
            write.physical_address > (std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(write.length)))
        {
            bounded_materialize_failure = "invalid-range";
            return false;
        }

        std::vector<std::vector<std::byte>> window_storage;
        window_storage.reserve(
            (kPayloadRangeMaterializationWindowBytes / kPayloadRangeMaterializationChunkBytes) + 1);
        std::vector<BlockDevice::WriteSpan> window_writes;
        window_writes.reserve(
            (kPayloadRangeMaterializationWindowBytes / kPayloadRangeMaterializationChunkBytes) + 1);
        std::uint64_t window_bytes = 0;
        std::size_t window_storage_cursor = 0;
        std::size_t cursor = 0;
        const auto reset_window = [&]()
        {
            window_writes.clear();
            window_bytes = 0;
            window_storage_cursor = 0;
        };
        while (cursor < write.length)
        {
            const auto remaining = write.length - cursor;
            const auto chunk_length = std::min<std::size_t>(
                remaining,
                kPayloadRangeMaterializationChunkBytes);
            if (chunk_length == 0 ||
                window_bytes > (std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(chunk_length)))
            {
                bounded_materialize_failure = "invalid-window";
                return false;
            }

            if (!window_writes.empty() &&
                (window_bytes + static_cast<std::uint64_t>(chunk_length)) >
                    static_cast<std::uint64_t>(kPayloadRangeMaterializationWindowBytes))
            {
                if (!append_payload_write_window(window_writes))
                {
                    bounded_materialize_failure = "device-write";
                    return false;
                }
                reset_window();
            }

            const auto logical_offset = write.logical_offset + static_cast<std::uint64_t>(cursor);
            const auto physical_address = write.physical_address + static_cast<std::uint64_t>(cursor);
            if (window_storage_cursor == window_storage.size())
            {
                window_storage.emplace_back();
            }
            else
            {
                payload_range_materialized_buffer_reuse_count_.fetch_add(1, std::memory_order_relaxed);
            }
            auto& chunk = window_storage[window_storage_cursor++];
            if (chunk.size() != chunk_length)
            {
                chunk.resize(chunk_length);
                payload_range_materialized_buffer_resize_count_.fetch_add(1, std::memory_order_relaxed);
            }
            if (!file_payload_range_provider_(
                    *write.path,
                    PayloadIdentity{ write.object_id, write.generation },
                    logical_offset,
                    std::span<std::byte>(chunk.data(), chunk.size())))
            {
                bounded_materialize_failure = "range-provider";
                return false;
            }

            payload_range_materialized_chunk_count_.fetch_add(1, std::memory_order_relaxed);
            payload_range_materialized_chunk_bytes_.fetch_add(
                static_cast<std::uint64_t>(chunk_length),
                std::memory_order_relaxed);
            window_writes.push_back(BlockDevice::WriteSpan{
                physical_address,
                std::span<const std::byte>(chunk.data(), chunk.size()),
            });
            window_bytes += static_cast<std::uint64_t>(chunk_length);
            cursor += chunk_length;
        }

        if (!append_payload_write_window(window_writes))
        {
            bounded_materialize_failure = "device-write";
            return false;
        }
        return true;
    };

    std::size_t materialized_payload_bytes = 0;
    bool use_contiguous_payload_storage = true;
    for (const auto& write : pending_payload_writes)
    {
        if (should_use_bounded_range_materialization(write))
        {
            continue;
        }
        const auto padded_length = aligned_fresh_tail_write_length(write);
        if (!padded_length.has_value() && can_reference_payload(write))
        {
            continue;
        }
        const auto materialized_length = padded_length.value_or(write.length);
        if (materialized_length > (std::numeric_limits<std::size_t>::max() - materialized_payload_bytes))
        {
            use_contiguous_payload_storage = false;
            break;
        }
        materialized_payload_bytes += materialized_length;
    }
    if (materialized_payload_bytes > kPayloadBatchContiguousStorageLimit)
    {
        use_contiguous_payload_storage = false;
    }

    std::vector<std::byte> contiguous_payload_storage;
    if (use_contiguous_payload_storage && materialized_payload_bytes > 0)
    {
        contiguous_payload_storage.reserve(materialized_payload_bytes);
    }

    std::vector<std::vector<std::byte>> payload_batch_storage;
    if (!use_contiguous_payload_storage)
    {
        payload_batch_storage.reserve(pending_payload_writes.size());
    }
    std::vector<BlockDevice::WriteSpan> payload_batch_writes;
    payload_batch_writes.reserve(pending_payload_writes.size() + 1);
    std::vector<PendingPayloadWriteView> bounded_payload_writes;
    for (const auto& write : pending_payload_writes)
    {
        if (write.length > static_cast<std::size_t>(std::numeric_limits<std::uint64_t>::max() - write.physical_address))
        {
            rollback_commit_extent_stage();
            return fail_commit(
                CommitStatus::PersistFailed,
                ("payload-device-write-failed:overflow-phys:err=" + std::to_string(device_.LastIoError())).c_str());
        }

        if (should_use_bounded_range_materialization(write))
        {
            bounded_payload_writes.push_back(write);
            continue;
        }

        const auto padded_length = aligned_fresh_tail_write_length(write);
        const auto materialized_length = padded_length.value_or(write.length);
        if (!padded_length.has_value() && can_reference_payload(write))
        {
            payload_batch_writes.push_back(BlockDevice::WriteSpan{
                write.physical_address,
                std::span<const std::byte>(
                    write.payload->data() + static_cast<std::ptrdiff_t>(write.offset),
                    write.length),
                write.payload.get(),
            });
            continue;
        }

        if (use_contiguous_payload_storage)
        {
            const auto materialized_offset = contiguous_payload_storage.size();
            if (!append_payload_segment(write, contiguous_payload_storage) ||
                contiguous_payload_storage.size() != (materialized_offset + write.length))
            {
                rollback_commit_extent_stage();
                return fail_commit(
                    CommitStatus::PersistFailed,
                    ("payload-device-write-failed:append-contiguous:err=" + std::to_string(device_.LastIoError())).c_str());
            }
            if (materialized_length < write.length ||
                materialized_length > (std::numeric_limits<std::size_t>::max() - materialized_offset))
            {
                rollback_commit_extent_stage();
                return fail_commit(
                    CommitStatus::PersistFailed,
                    ("payload-device-write-failed:padded-length:err=" + std::to_string(device_.LastIoError())).c_str());
            }
            if (padded_length.has_value())
            {
                contiguous_payload_storage.resize(materialized_offset + materialized_length, std::byte{0});
                record_tail_zero_pad(write.length, materialized_length);
            }
            payload_batch_writes.push_back(BlockDevice::WriteSpan{
                write.physical_address,
                std::span<const std::byte>(
                    contiguous_payload_storage.data() + static_cast<std::ptrdiff_t>(materialized_offset),
                    materialized_length),
                &contiguous_payload_storage,
            });
            continue;
        }

        payload_batch_storage.emplace_back();
        auto& materialized_payload = payload_batch_storage.back();
        if (!append_payload_segment(write, materialized_payload) ||
            materialized_payload.size() != write.length)
        {
            rollback_commit_extent_stage();
            return fail_commit(
                CommitStatus::PersistFailed,
                ("payload-device-write-failed:append-batch:err=" + std::to_string(device_.LastIoError())).c_str());
        }
        if (padded_length.has_value())
        {
            materialized_payload.resize(materialized_length, std::byte{0});
            record_tail_zero_pad(write.length, materialized_length);
        }
        payload_batch_writes.push_back(BlockDevice::WriteSpan{
            write.physical_address,
            std::span<const std::byte>(materialized_payload.data(), materialized_payload.size()),
        });
    }

    if (!AllowCommitStage("before-commit-blob-device-write"))
    {
        rollback_commit_extent_stage();
        return CommitStatus::PersistFailed;
    }
    if (!bounded_payload_writes.empty())
    {
        if (!append_payload_write_window(payload_batch_writes))
        {
            rollback_commit_extent_stage();
            return fail_commit(
                CommitStatus::PersistFailed,
                (std::string("payload-device-write-failed:batch-window:err=") + std::to_string(device_.LastIoError())).c_str());
        }
        payload_batch_writes.clear();
        for (const auto& write : bounded_payload_writes)
        {
            if (!write_bounded_range_materialized_payload(write))
            {
                rollback_commit_extent_stage();
                return fail_commit(
                    CommitStatus::PersistFailed,
                    (std::string("payload-device-write-failed:bounded-materialize:") +
                     bounded_materialize_failure +
                     ":err=" +
                     std::to_string(device_.LastIoError())).c_str());
            }
        }
    }
    payload_batch_writes.push_back(BlockDevice::WriteSpan{
        *commit_extent,
        std::span<const std::byte>(commit_blob.data(), commit_blob.size()),
    });
    if (!device_.WriteBatch(payload_batch_writes))
    {
        rollback_commit_extent_stage();
        return fail_commit(CommitStatus::PersistFailed, "commit-blob-device-write-failed");
    }
    if (!AllowCommitStage("before-device-flush"))
    {
        rollback_commit_extent_stage();
        return CommitStatus::FlushFailed;
    }
    if (!device_.Flush())
    {
        rollback_commit_extent_stage();
        return fail_commit(
            CommitStatus::FlushFailed,
            (std::string("device-flush-failed:err=") + std::to_string(device_.LastIoError())).c_str());
    }

    const auto has_spaceman_deltas =
        !pending_spaceman_allocations_.empty() ||
        !pending_spaceman_deallocations_.empty();
    const auto can_apply_allocations_locally =
        !pending_spaceman_allocations_.empty() &&
        pending_spaceman_deallocations_.empty();
    const auto can_apply_spaceman_deltas_locally =
        can_apply_allocations_locally ||
        !pending_spaceman_deallocations_.empty();
    std::optional<std::vector<SpacemanAllocation>> committed_allocations_snapshot;
    std::optional<std::vector<SpacemanAllocation>> committed_free_extents_snapshot;
    if (has_spaceman_deltas && !can_apply_spaceman_deltas_locally)
    {
        committed_allocations_snapshot = committed_spaceman_allocations_;
        committed_free_extents_snapshot = committed_spaceman_free_extents_;
        committed_spaceman_full_snapshot_count_.fetch_add(1, std::memory_order_relaxed);
    }
    std::vector<BtreeRecordRestoreEntry> committed_btree_restores;
    committed_btree_restores.reserve(pending_btree_records_.size() * 2);
    auto last_commit_blob_snapshot = last_commit_blob_address_;
    auto last_commit_blob_bytes_snapshot = last_commit_blob_bytes_;
    auto checkpoint_xid_snapshot = checkpoint_xid_;
    auto last_committed_xid_snapshot = last_committed_xid_;

    struct CommittedObjectMapRestoreEntry
    {
        std::uint64_t object_id = 0;
        std::optional<ObjectMapUpdate> previous;
    };
    struct CommittedReadExtentRestoreEntry
    {
        std::uint64_t object_id = 0;
        std::optional<std::vector<FileExtent>> previous;
    };
    struct CommittedInodeRestoreEntry
    {
        std::uint64_t object_id = 0;
        std::optional<InodeRecord> previous;
    };
    struct CommittedPathIndexRestoreEntry
    {
        std::wstring key;
        std::optional<std::uint64_t> previous;
    };
    struct CommittedDirectoryLinkRestoreEntry
    {
        std::uint64_t parent_object_id = 0;
        std::wstring entry_name;
        std::optional<DirectoryLink> previous;
    };
    std::vector<CommittedObjectMapRestoreEntry> committed_object_map_restores;
    std::vector<CommittedReadExtentRestoreEntry> committed_read_extent_restores;
    std::vector<CommittedInodeRestoreEntry> committed_inode_restores;
    std::vector<CommittedPathIndexRestoreEntry> committed_path_index_restores;
    std::vector<CommittedDirectoryLinkRestoreEntry> committed_directory_link_restores;
    std::unordered_set<std::uint64_t> committed_object_map_restore_ids;
    std::unordered_set<std::uint64_t> committed_read_extent_restore_ids;
    std::unordered_set<std::uint64_t> committed_inode_restore_ids;
    std::unordered_set<std::wstring> committed_path_index_restore_keys;
    std::unordered_set<DirectoryLinkIndexKey, DirectoryLinkIndexKeyHash> committed_directory_link_restore_keys;
    committed_object_map_restore_ids.reserve(pending_object_map_updates_.size());
    committed_read_extent_restore_ids.reserve(pending_object_map_updates_.size());
    committed_inode_restore_ids.reserve(pending_object_map_updates_.size() + pending_btree_records_.size());
    committed_path_index_restore_keys.reserve((pending_object_map_updates_.size() + pending_btree_records_.size()) * 2);
    committed_directory_link_restore_keys.reserve((pending_object_map_updates_.size() + pending_btree_records_.size()) * 2);

    const auto remember_committed_object_map = [&](std::uint64_t object_id)
    {
        if (!committed_object_map_restore_ids.insert(object_id).second)
        {
            return;
        }

        const auto existing = committed_object_map_.find(object_id);
        committed_object_map_restores.push_back(
            {
                object_id,
                existing == committed_object_map_.end() ? std::optional<ObjectMapUpdate>{} : existing->second,
            });
    };
    const auto remember_committed_read_extents = [&](std::uint64_t object_id)
    {
        if (!committed_read_extent_restore_ids.insert(object_id).second)
        {
            return;
        }

        const auto existing = committed_read_extents_.find(object_id);
        committed_read_extent_restores.push_back(
            {
                object_id,
                existing == committed_read_extents_.end()
                    ? std::optional<std::vector<FileExtent>>{}
                    : existing->second,
            });
    };
    const auto remember_committed_inode = [&](std::uint64_t object_id)
    {
        if (!committed_inode_restore_ids.insert(object_id).second)
        {
            return;
        }

        const auto existing = committed_inodes_.find(object_id);
        committed_inode_restores.push_back(
            {
                object_id,
                existing == committed_inodes_.end() ? std::optional<InodeRecord>{} : existing->second,
            });
    };
    const auto remember_committed_path_index = [&](const std::wstring& key)
    {
        if (!committed_path_index_restore_keys.insert(key).second)
        {
            return;
        }

        const auto existing = committed_path_index_.find(key);
        committed_path_index_restores.push_back(
            {
                key,
                existing == committed_path_index_.end() ? std::optional<std::uint64_t>{} : existing->second,
            });
    };
    const auto remember_committed_directory_link = [&](std::uint64_t parent_object_id, const std::wstring& entry_name)
    {
        const auto key = BuildWorkingDirectoryLinkIndexKey(parent_object_id, entry_name);
        if (!committed_directory_link_restore_keys.insert(key).second)
        {
            return;
        }

        auto index_it = committed_directory_link_index_.find(key);
        if (index_it != committed_directory_link_index_.end() &&
            index_it->second >= committed_directory_links_.size())
        {
            RebuildCommittedDirectoryLinkIndex();
            index_it = committed_directory_link_index_.find(key);
        }

        std::optional<DirectoryLink> previous;
        if (index_it != committed_directory_link_index_.end() &&
            index_it->second < committed_directory_links_.size())
        {
            previous = committed_directory_links_[index_it->second];
        }
        committed_directory_link_restores.push_back(
            {
                parent_object_id,
                entry_name,
                std::move(previous),
            });
    };
    const auto remove_committed_directory_link = [&](std::uint64_t parent_object_id, const std::wstring& entry_name)
    {
        const auto key = BuildWorkingDirectoryLinkIndexKey(parent_object_id, entry_name);
        auto index_it = committed_directory_link_index_.find(key);
        if (index_it == committed_directory_link_index_.end() ||
            index_it->second >= committed_directory_links_.size())
        {
            RebuildCommittedDirectoryLinkIndex();
            index_it = committed_directory_link_index_.find(key);
            if (index_it == committed_directory_link_index_.end())
            {
                return;
            }
        }

        const auto removed_index = index_it->second;
        const auto last_index = committed_directory_links_.size() - 1;
        const auto removed_parent_object_id = committed_directory_links_[removed_index].parent_object_id;
        const auto removed_child_object_id = committed_directory_links_[removed_index].child_object_id;
        if (removed_index != last_index)
        {
            committed_directory_links_[removed_index] = std::move(committed_directory_links_[last_index]);
            committed_directory_link_index_[
                BuildWorkingDirectoryLinkIndexKey(
                    committed_directory_links_[removed_index].parent_object_id,
                    committed_directory_links_[removed_index].entry_name)] = removed_index;
        }
        RemoveCommittedDirectoryChild(removed_parent_object_id, removed_child_object_id);
        committed_directory_links_.pop_back();
        committed_directory_link_index_.erase(key);
    };
    const auto upsert_committed_directory_link =
        [&](std::uint64_t parent_object_id, const std::wstring& entry_name, std::uint64_t child_object_id, std::uint64_t xid)
    {
        const auto key = BuildWorkingDirectoryLinkIndexKey(parent_object_id, entry_name);
        auto index_it = committed_directory_link_index_.find(key);
        if (index_it != committed_directory_link_index_.end() &&
            index_it->second < committed_directory_links_.size())
        {
            auto& link = committed_directory_links_[index_it->second];
            if (link.parent_object_id != parent_object_id ||
                link.child_object_id != child_object_id)
            {
                RemoveCommittedDirectoryChild(link.parent_object_id, link.child_object_id);
                AddCommittedDirectoryChild(parent_object_id, child_object_id);
            }
            link.entry_name = entry_name;
            link.child_object_id = child_object_id;
            link.xid = xid;
            return;
        }

        const auto new_index = committed_directory_links_.size();
        committed_directory_links_.push_back(DirectoryLink
        {
            parent_object_id,
            entry_name,
            child_object_id,
            xid,
        });
        AddCommittedDirectoryChild(parent_object_id, child_object_id);
        committed_directory_link_index_[key] = new_index;
    };
    const auto add_spaceman_extents =
        [](std::vector<SpacemanAllocation>& target, const std::vector<SpacemanAllocation>& extents) -> bool
    {
        for (const auto& extent : extents)
        {
            if (!ExtentAllocator::AddFreeExtent(target, extent))
            {
                return false;
            }
        }
        return true;
    };
    const auto rollback_committed_spaceman_state = [&]() -> bool
    {
        if (!has_spaceman_deltas)
        {
            return true;
        }

        if (committed_allocations_snapshot.has_value() &&
            committed_free_extents_snapshot.has_value())
        {
            committed_spaceman_allocations_ = committed_allocations_snapshot.value();
            committed_spaceman_free_extents_ = committed_free_extents_snapshot.value();
            return true;
        }

        std::vector<SpacemanAllocation> restored_allocations = committed_spaceman_allocations_;
        std::vector<SpacemanAllocation> restored_free_extents = committed_spaceman_free_extents_;
        if (!add_spaceman_extents(restored_allocations, pending_spaceman_deallocations_) ||
            !SubtractExtentsFromAllocations(restored_allocations, pending_spaceman_allocations_))
        {
            return false;
        }

        if (!ExtentAllocator::RemoveAllocatedExtents(restored_free_extents, pending_spaceman_deallocations_) ||
            !add_spaceman_extents(restored_free_extents, pending_spaceman_allocations_))
        {
            return false;
        }

        if (!NormalizeSpacemanExtents(restored_allocations) ||
            !NormalizeSpacemanExtents(restored_free_extents))
        {
            return false;
        }

        committed_spaceman_allocations_ = std::move(restored_allocations);
        committed_spaceman_free_extents_ = std::move(restored_free_extents);
        return true;
    };
    const auto rollback_committed_state = [&]() -> bool
    {
        bool object_map_membership_changed = false;
        for (const auto& restore : committed_object_map_restores)
        {
            const auto had_entry = committed_object_map_.contains(restore.object_id);
            if (restore.previous.has_value())
            {
                committed_object_map_[restore.object_id] = restore.previous.value();
            }
            else
            {
                committed_object_map_.erase(restore.object_id);
            }
            if (had_entry != restore.previous.has_value())
            {
                object_map_membership_changed = true;
            }
        }
        if (object_map_membership_changed)
        {
            InvalidateCommittedObjectMapOrderCache();
        }
        for (const auto& restore : committed_read_extent_restores)
        {
            if (restore.previous.has_value())
            {
                committed_read_extents_[restore.object_id] = restore.previous.value();
            }
            else
            {
                committed_read_extents_.erase(restore.object_id);
            }
            InvalidateCommittedReadExtentSnapshotCacheForObject(restore.object_id);
        }
        for (const auto& restore : committed_inode_restores)
        {
            if (restore.previous.has_value())
            {
                committed_inodes_[restore.object_id] = restore.previous.value();
            }
            else
            {
                committed_inodes_.erase(restore.object_id);
            }
        }
        if (!committed_inode_restores.empty())
        {
            InvalidateCommittedInodeOrderCache();
        }
        for (const auto& restore : committed_path_index_restores)
        {
            if (restore.previous.has_value())
            {
                committed_path_index_[restore.key] = restore.previous.value();
            }
            else
            {
                committed_path_index_.erase(restore.key);
            }
        }
        for (const auto& restore : committed_directory_link_restores)
        {
            if (restore.previous.has_value())
            {
                upsert_committed_directory_link(
                    restore.previous->parent_object_id,
                    restore.previous->entry_name,
                    restore.previous->child_object_id,
                    restore.previous->xid);
            }
            else
            {
                remove_committed_directory_link(restore.parent_object_id, restore.entry_name);
            }
        }
        if (!rollback_committed_spaceman_state())
        {
            return false;
        }
        if (committed_btree_index_by_key_.size() != committed_btree_records_.size() &&
            !RebuildCommittedBtreeIndex())
        {
            return false;
        }
        if (!RestoreBtreeRecordDeltas(
                committed_btree_records_,
                committed_btree_index_by_key_,
                committed_btree_inode_key_by_object_id_,
                committed_btree_restores))
        {
            return false;
        }
        last_commit_blob_address_ = last_commit_blob_snapshot;
        last_commit_blob_bytes_ = last_commit_blob_bytes_snapshot;
        checkpoint_xid_ = checkpoint_xid_snapshot;
        last_committed_xid_ = last_committed_xid_snapshot;
        next_ephemeral_extent_ = working_next_extent_snapshot;
        working_free_extents_sanitized_ = working_free_extents_sanitized_snapshot;
        return true;
    };

    for (const auto& update : pending_object_map_updates_)
    {
        remember_committed_object_map(update.object_id);
        const auto had_entry = committed_object_map_.contains(update.object_id);
        if (HasPhysicalObjectMapping(update))
        {
            committed_object_map_[update.object_id] = update;
        }
        else
        {
            committed_object_map_.erase(update.object_id);
        }
        if (had_entry != committed_object_map_.contains(update.object_id))
        {
            if (!TryUpdateCommittedObjectMapOrderCacheForObject(update.object_id))
            {
                InvalidateCommittedObjectMapOrderCache();
            }
        }
        const auto pending_extents = pending_read_extent_updates_.find(update.object_id);
        if (pending_extents != pending_read_extent_updates_.end())
        {
            remember_committed_read_extents(update.object_id);
            InvalidateCommittedReadExtentSnapshotCacheForObject(update.object_id);
            if (HasPhysicalObjectMapping(update) && !pending_extents->second.empty())
            {
                committed_read_extents_[update.object_id] = pending_extents->second;
            }
            else
            {
                committed_read_extents_.erase(update.object_id);
            }
        }
        else if (!HasPhysicalObjectMapping(update))
        {
            remember_committed_read_extents(update.object_id);
            committed_read_extents_.erase(update.object_id);
            InvalidateCommittedReadExtentSnapshotCacheForObject(update.object_id);
        }
    }
    const auto apply_tracked_free_extent =
        [&](std::uint64_t physical_address, std::uint64_t bytes)
        {
            tracking_spaceman_free_extent_delta_ = true;
            ScopeExit clear_tracking_spaceman_free_extent_delta{
                [&]()
                {
                    tracking_spaceman_free_extent_delta_ = false;
                }};
            ExtentAllocator::AddFreeExtentUndo undo{};
            if (!FreeExtent(physical_address, bytes, &undo))
            {
                return false;
            }
            if (!undo.valid)
            {
                return false;
            }
            commit_working_free_extent_add_undos.push_back(std::move(undo));
            return true;
        };
    const auto rollback_committed_state_or_fail = [&](const char* reason) -> CommitStatus
    {
        if (!rollback_committed_state())
        {
            return fail_commit(CommitStatus::InvariantFailed, "committed-state-rollback-failed");
        }
        return fail_commit(CommitStatus::InvariantFailed, reason);
    };
    if (has_spaceman_deltas)
    {
        if (can_apply_spaceman_deltas_locally)
        {
            committed_spaceman_apply_local_count_.fetch_add(1, std::memory_order_relaxed);
            if (can_apply_allocations_locally)
            {
                for (const auto& allocation : pending_spaceman_allocations_)
                {
                    if (!ExtentAllocator::AddFreeExtent(committed_spaceman_allocations_, allocation))
                    {
                        rollback_commit_extent_stage();
                        return rollback_committed_state_or_fail("committed-allocation-local-insert-failed");
                    }
                }
                if (!NormalizeSpacemanExtents(committed_spaceman_allocations_))
                {
                    rollback_commit_extent_stage();
                    return rollback_committed_state_or_fail("committed-allocation-local-normalize-failed");
                }
            }
            else
            {
                committed_spaceman_allocations_.insert(
                    committed_spaceman_allocations_.end(),
                    pending_spaceman_allocations_.begin(),
                    pending_spaceman_allocations_.end()
                );
                if (!SubtractExtentsFromAllocations(committed_spaceman_allocations_, pending_spaceman_deallocations_))
                {
                    rollback_commit_extent_stage();
                    return rollback_committed_state_or_fail("committed-allocation-local-subtract-failed");
                }
                for (const auto& deallocation : pending_spaceman_deallocations_)
                {
                    if (!apply_tracked_free_extent(deallocation.physical_address, deallocation.bytes))
                    {
                        rollback_commit_extent_stage();
                        if (!rollback_committed_state())
                        {
                            return fail_commit(CommitStatus::InvariantFailed, "committed-state-rollback-failed");
                        }
                        return fail_commit(CommitStatus::AllocationFailed, "deallocation-free-extent-failed");
                    }
                }
            }
        }
        else
        {
            committed_spaceman_apply_count_.fetch_add(1, std::memory_order_relaxed);
            committed_spaceman_allocations_.insert(
                committed_spaceman_allocations_.end(),
                pending_spaceman_allocations_.begin(),
                pending_spaceman_allocations_.end()
            );
            if (!NormalizeSpacemanExtents(committed_spaceman_allocations_))
            {
                rollback_commit_extent_stage();
                return rollback_committed_state_or_fail("committed-allocation-normalize-failed");
            }
            for (const auto& deallocation : pending_spaceman_deallocations_)
            {
                std::vector<SpacemanAllocation> adjusted_allocations;
                adjusted_allocations.reserve(committed_spaceman_allocations_.size() + 1);
                const auto deallocation_end = deallocation.physical_address + deallocation.bytes;
                for (const auto& allocation : committed_spaceman_allocations_)
                {
                    if (!PhysicalRangeContains(
                            allocation.physical_address,
                            allocation.bytes,
                            deallocation.physical_address,
                            deallocation.bytes))
                    {
                        adjusted_allocations.push_back(allocation);
                        continue;
                    }

                    if (allocation.physical_address < deallocation.physical_address)
                    {
                        adjusted_allocations.push_back(
                            {
                                allocation.physical_address,
                                deallocation.physical_address - allocation.physical_address,
                            });
                    }

                    const auto allocation_end = allocation.physical_address + allocation.bytes;
                    if (deallocation_end < allocation_end)
                    {
                        adjusted_allocations.push_back(
                            {
                                deallocation_end,
                                allocation_end - deallocation_end,
                            });
                    }
                }
                committed_spaceman_allocations_ = std::move(adjusted_allocations);
                if (!NormalizeSpacemanExtents(committed_spaceman_allocations_))
                {
                    rollback_commit_extent_stage();
                    return rollback_committed_state_or_fail("committed-allocation-deallocation-normalize-failed");
                }
                if (!apply_tracked_free_extent(deallocation.physical_address, deallocation.bytes))
                {
                    rollback_commit_extent_stage();
                    if (!rollback_committed_state())
                    {
                        return fail_commit(CommitStatus::InvariantFailed, "committed-state-rollback-failed");
                    }
                    return fail_commit(CommitStatus::AllocationFailed, "deallocation-free-extent-failed");
                }
            }
        }
    }
    std::vector<std::uint64_t> touched_inode_ids;
    touched_inode_ids.reserve(pending_object_map_updates_.size() + pending_btree_inode_record_count_by_object_.size());
    bool pending_object_map_index_sane =
        pending_object_map_update_index_.size() == pending_object_map_updates_.size();
    std::uint64_t previous_object_map_touch = 0;
    for (std::size_t index = 0; index < pending_object_map_updates_.size(); ++index)
    {
        const auto& update = pending_object_map_updates_[index];
        if (update.object_id != 0)
        {
            touched_inode_ids.push_back(update.object_id);
        }
        if (update.object_id == 0 ||
            (!touched_inode_ids.empty() &&
             touched_inode_ids.back() <= previous_object_map_touch))
        {
            pending_object_map_index_sane = false;
        }
        previous_object_map_touch = update.object_id;

        const auto indexed_update = pending_object_map_update_index_.find(update.object_id);
        if (indexed_update == pending_object_map_update_index_.end() ||
            indexed_update->second != index)
        {
            pending_object_map_index_sane = false;
        }
    }
    bool used_pending_btree_inode_index = pending_btree_records_.empty();
    std::size_t indexed_pending_btree_inode_records = 0;
    bool pending_btree_inode_index_sane = true;
    std::vector<std::uint64_t> pending_btree_touched_inode_ids;
    pending_btree_touched_inode_ids.reserve(pending_btree_inode_record_count_by_object_.size());
    for (const auto& [object_id, record_count] : pending_btree_inode_record_count_by_object_)
    {
        if (object_id == 0 ||
            record_count == 0 ||
            record_count > (pending_btree_records_.size() - indexed_pending_btree_inode_records))
        {
            pending_btree_inode_index_sane = false;
            break;
        }
        indexed_pending_btree_inode_records += record_count;
        pending_btree_touched_inode_ids.push_back(object_id);
    }
    if (pending_btree_inode_index_sane)
    {
        pending_btree_touched_inode_index_reuse_count_.fetch_add(1, std::memory_order_relaxed);
        used_pending_btree_inode_index = true;
    }
    if (!used_pending_btree_inode_index)
    {
        pending_btree_touched_inode_fallback_scan_count_.fetch_add(1, std::memory_order_relaxed);
        for (const auto& record : pending_btree_records_)
        {
            DecodedBtreeInode decoded{};
            if (DecodeBtreeInodeRecord(record, decoded))
            {
                pending_btree_touched_inode_ids.push_back(decoded.object_id);
            }
        }
    }
    bool can_skip_touched_inode_sort = pending_object_map_index_sane && used_pending_btree_inode_index;
    if (can_skip_touched_inode_sort)
    {
        for (const auto object_id : pending_btree_touched_inode_ids)
        {
            if (!pending_object_map_update_index_.contains(object_id))
            {
                can_skip_touched_inode_sort = false;
                break;
            }
        }
    }
    if (can_skip_touched_inode_sort)
    {
        commit_touched_inode_dedupe_fast_path_count_.fetch_add(1, std::memory_order_relaxed);
    }
    else
    {
        commit_touched_inode_sort_fallback_count_.fetch_add(1, std::memory_order_relaxed);
        touched_inode_ids.insert(
            touched_inode_ids.end(),
            pending_btree_touched_inode_ids.begin(),
            pending_btree_touched_inode_ids.end());
        std::sort(touched_inode_ids.begin(), touched_inode_ids.end());
        touched_inode_ids.erase(std::unique(touched_inode_ids.begin(), touched_inode_ids.end()), touched_inode_ids.end());
    }

    std::vector<CommittedInodeChange> commit_inode_changes;
    commit_inode_changes.reserve(touched_inode_ids.size());
    struct TouchedInodeCommitKey
    {
        std::uint64_t object_id = 0;
        std::wstring previous_key;
        std::wstring current_key;
    };
    std::vector<TouchedInodeCommitKey> touched_inode_commit_keys;
    touched_inode_commit_keys.reserve(touched_inode_ids.size());
    for (const auto object_id : touched_inode_ids)
    {
        CommittedInodeChange change{};
        change.object_id = object_id;
        remember_committed_inode(object_id);
        const auto committed_inode = committed_inodes_.find(object_id);
        TouchedInodeCommitKey touched_key{};
        touched_key.object_id = object_id;
        if (committed_inode != committed_inodes_.end())
        {
            change.previous_path = committed_inode->second.full_path;
            touched_key.previous_key = CanonicalPathKeyFromNormalizedPath(committed_inode->second.full_path);
            remember_committed_path_index(touched_key.previous_key);
            if (!IsRootPath(committed_inode->second.full_path))
            {
                remember_committed_directory_link(
                    committed_inode->second.parent_object_id,
                    committed_inode->second.name);
            }
        }

        const auto working_inode = working_inodes_.find(object_id);
        if (working_inode != working_inodes_.end())
        {
            touched_key.current_key = CanonicalPathKeyFromNormalizedPath(working_inode->second.full_path);
            remember_committed_path_index(touched_key.current_key);
            if (!IsRootPath(working_inode->second.full_path))
            {
                remember_committed_directory_link(
                    working_inode->second.parent_object_id,
                    working_inode->second.name);
            }
        }
        if (working_inode != working_inodes_.end())
        {
            change.current = working_inode->second;
        }
        commit_inode_changes.push_back(std::move(change));
        touched_inode_commit_keys.push_back(std::move(touched_key));
    }

    bool committed_inode_order_changed = false;
    for (const auto& touched_key : touched_inode_commit_keys)
    {
        if (touched_key.previous_key != touched_key.current_key)
        {
            committed_inode_order_changed = true;
            break;
        }
    }

    for (const auto& touched_key : touched_inode_commit_keys)
    {
        const auto committed_inode = committed_inodes_.find(touched_key.object_id);
        if (committed_inode == committed_inodes_.end())
        {
            continue;
        }
        committed_path_index_.erase(touched_key.previous_key);
        if (!IsRootPath(committed_inode->second.full_path))
        {
            remove_committed_directory_link(
                committed_inode->second.parent_object_id,
                committed_inode->second.name);
        }
    }
    for (const auto& touched_key : touched_inode_commit_keys)
    {
        const auto working_inode = working_inodes_.find(touched_key.object_id);
        if (working_inode == working_inodes_.end())
        {
            committed_inodes_.erase(touched_key.object_id);
            continue;
        }

        committed_inodes_[touched_key.object_id] = working_inode->second;
        committed_path_index_[touched_key.current_key] = touched_key.object_id;
        if (!IsRootPath(working_inode->second.full_path))
        {
            upsert_committed_directory_link(
                working_inode->second.parent_object_id,
                working_inode->second.name,
                touched_key.object_id,
                working_inode->second.xid);
        }
    }
    if (committed_inode_order_changed)
    {
        bool inode_order_cache_updated = true;
        for (const auto& touched_key : touched_inode_commit_keys)
        {
            if (touched_key.previous_key == touched_key.current_key)
            {
                continue;
            }
            if (!TryUpdateCommittedInodeOrderCacheForObject(
                    touched_key.object_id,
                    touched_key.previous_key.empty() ? nullptr : &touched_key.previous_key,
                    touched_key.current_key.empty() ? nullptr : &touched_key.current_key))
            {
                inode_order_cache_updated = false;
                break;
            }
        }
        if (!inode_order_cache_updated)
        {
            InvalidateCommittedInodeOrderCache();
        }
    }
    if (committed_btree_index_by_key_.size() != committed_btree_records_.size() &&
        !RebuildCommittedBtreeIndex())
    {
        rollback_commit_extent_stage();
        return rollback_committed_state_or_fail("committed-btree-index-rebuild-failed");
    }
    if (!ApplyBtreeRecordDeltasWithRestoreLog(
            committed_btree_records_,
            committed_btree_index_by_key_,
            committed_btree_inode_key_by_object_id_,
            pending_btree_records_,
            committed_btree_restores))
    {
        rollback_commit_extent_stage();
        return rollback_committed_state_or_fail("committed-btree-delta-apply-failed");
    }

    const auto can_apply_committed_free_extents_locally =
        !pending_spaceman_untracked_free_extent_delta_ &&
        !pending_spaceman_released_existing_allocation_;
    bool committed_free_extents_delta_ok = can_apply_committed_free_extents_locally;
    if (committed_free_extents_delta_ok)
    {
        committed_free_extents_delta_ok =
            ExtentAllocator::RemoveAllocatedExtents(
                committed_spaceman_free_extents_,
                pending_spaceman_allocations_);
    }
    if (committed_free_extents_delta_ok)
    {
        for (const auto& deallocation : pending_spaceman_deallocations_)
        {
            committed_free_extents_delta_ok =
                ExtentAllocator::AddFreeExtent(committed_spaceman_free_extents_, deallocation);
            if (!committed_free_extents_delta_ok)
            {
                break;
            }
        }
    }
    if (committed_free_extents_delta_ok)
    {
        committed_spaceman_free_apply_local_count_.fetch_add(1, std::memory_order_relaxed);
        committed_spaceman_free_apply_in_place_count_.fetch_add(1, std::memory_order_relaxed);
    }
    else
    {
        committed_spaceman_free_apply_count_.fetch_add(1, std::memory_order_relaxed);
        committed_spaceman_free_extents_ = working_spaceman_free_extents_;
        if (!NormalizeSpacemanExtents(committed_spaceman_free_extents_))
        {
            rollback_commit_extent_stage();
            return rollback_committed_state_or_fail("committed-free-extents-normalize-failed");
        }
    }
    const auto verify_committed_free_extents =
        !committed_free_extents_delta_ok ||
        commit_stage_hook_requires_strict_verification_ ||
        IsStrictCommitVerificationEnabled();
    if (verify_committed_free_extents)
    {
        committed_spaceman_free_verify_full_count_.fetch_add(1, std::memory_order_relaxed);
    }
    else
    {
        committed_spaceman_free_verify_skip_count_.fetch_add(1, std::memory_order_relaxed);
    }
    if (verify_committed_free_extents &&
        committed_spaceman_free_extents_ != working_spaceman_free_extents_)
    {
        rollback_commit_extent_stage();
        return rollback_committed_state_or_fail("committed-free-extents-delta-mismatch");
    }
    next_ephemeral_extent_ = working_next_ephemeral_extent_;

    if (IsPerfCountersEnabled() && IsCheckpointDeltaShadowEnabled())
    {
        ObserveCheckpointDeltaShadow(DebugBuildPendingCheckpointDelta());
    }
    checkpoint_xid_ = target_xid;
    last_committed_xid_ = target_xid;
    last_commit_blob_address_ = *commit_extent;
    last_commit_blob_bytes_ = commit_blob_persist_bytes;
    const auto verify_commit_roundtrips =
        commit_stage_hook_requires_strict_verification_ || IsStrictCommitVerificationEnabled();
    CheckpointWriteBatch checkpoint_write_batch;
    const bool batch_checkpoint_family_writes = !verify_commit_roundtrips;
    if (batch_checkpoint_family_writes)
    {
        active_checkpoint_write_batch_ = &checkpoint_write_batch;
    }
    ScopeExit clear_checkpoint_write_batch{[&]()
    {
        active_checkpoint_write_batch_ = nullptr;
    }};
    const auto read_chunked_checkpoint_roundtrip_candidate =
        [&](const std::vector<std::uint64_t>& checkpoint_blocks,
            std::size_t required_blocks) -> std::optional<std::pair<std::uint64_t, std::vector<std::byte>>>
    {
        for (const auto& checkpoint_slots : SelectChunkedCheckpointBlockWindows(
                 checkpoint_blocks,
                 target_xid,
                 required_blocks))
        {
            if (checkpoint_slots.empty())
            {
                continue;
            }

            auto checkpoint_block = ReadOrderedCheckpointWindowBytes(checkpoint_slots, required_blocks);
            if (checkpoint_block.size() < kCheckpointHeaderBytes ||
                ReadLe64(checkpoint_block, 12) != target_xid)
            {
                continue;
            }

            return std::make_pair(checkpoint_slots.front(), std::move(checkpoint_block));
        }

        return std::nullopt;
    };
    const auto verify_object_map_checkpoint_roundtrip = [&]() -> bool
    {
        auto checkpoint_blocks = ResolveObjectMapCheckpointBlockIndices();
        if (checkpoint_blocks.empty() || block_size_ == 0)
        {
            return false;
        }

        constexpr std::size_t kObjectMapCheckpointEntryBytes = 32;
        std::unordered_map<std::uint64_t, ObjectMapUpdate> persisted_object_map_snapshot;
        persisted_object_map_snapshot.reserve(committed_object_map_.size());
        for (const auto& [object_id, update] : committed_object_map_)
        {
            if (HasPhysicalObjectMapping(update))
            {
                persisted_object_map_snapshot.emplace(object_id, update);
            }
        }
        const auto required_bytes = kCheckpointHeaderBytes + (persisted_object_map_snapshot.size() * kObjectMapCheckpointEntryBytes);
        const auto required_blocks = (required_bytes + static_cast<std::size_t>(block_size_) - 1) /
            static_cast<std::size_t>(block_size_);
        if (required_blocks == 0)
        {
            return false;
        }

        auto checkpoint_candidate = read_chunked_checkpoint_roundtrip_candidate(
            checkpoint_blocks,
            required_blocks);
        if (!checkpoint_candidate.has_value())
        {
            return false;
        }

        const auto committed_object_map_snapshot = committed_object_map_;
        const auto last_committed_xid_snapshot = last_committed_xid_;
        const auto loaded_superblock_checkpoint_xid_snapshot = loaded_superblock_checkpoint_xid_;
        const auto restore_state = [&]()
        {
            committed_object_map_ = committed_object_map_snapshot;
            last_committed_xid_ = last_committed_xid_snapshot;
            loaded_superblock_checkpoint_xid_ = loaded_superblock_checkpoint_xid_snapshot;
        };

        loaded_superblock_checkpoint_xid_ = std::max(loaded_superblock_checkpoint_xid_, target_xid);
        if (!LoadObjectMapCheckpointBlock(checkpoint_candidate->first, checkpoint_candidate->second) ||
            last_committed_xid_.value_or(0) != target_xid ||
            committed_object_map_.size() != persisted_object_map_snapshot.size())
        {
            restore_state();
            return false;
        }

        for (const auto& [object_id, expected] : persisted_object_map_snapshot)
        {
            auto parsed = committed_object_map_.find(object_id);
            if (parsed == committed_object_map_.end())
            {
                restore_state();
                return false;
            }
            if (parsed->second.physical_address != expected.physical_address ||
                parsed->second.logical_size != expected.logical_size ||
                parsed->second.xid != expected.xid)
            {
                restore_state();
                return false;
            }
        }

        restore_state();
        return true;
    };
    const auto verify_spaceman_checkpoint_roundtrip = [&]() -> bool
    {
        auto checkpoint_blocks = ResolveSpacemanCheckpointBlockIndices();
        if (checkpoint_blocks.empty() || block_size_ == 0)
        {
            return false;
        }

        constexpr std::size_t kSpacemanCheckpointEntryBytes = 16;
        const auto required_entries = committed_spaceman_allocations_.size() + committed_spaceman_free_extents_.size();
        if (required_entries > ((std::numeric_limits<std::size_t>::max() - kCheckpointHeaderBytes) /
                                kSpacemanCheckpointEntryBytes))
        {
            return false;
        }
        const auto required_bytes = kCheckpointHeaderBytes + (required_entries * kSpacemanCheckpointEntryBytes);
        const auto required_blocks = (required_bytes + static_cast<std::size_t>(block_size_) - 1) /
            static_cast<std::size_t>(block_size_);
        if (required_blocks == 0)
        {
            return false;
        }

        const auto checkpoint_candidate = read_chunked_checkpoint_roundtrip_candidate(
            checkpoint_blocks,
            required_blocks);
        if (!checkpoint_candidate.has_value())
        {
            return false;
        }

        const auto committed_allocations_snapshot = committed_spaceman_allocations_;
        const auto committed_free_extents_snapshot = committed_spaceman_free_extents_;
        const auto working_free_extents_snapshot = working_spaceman_free_extents_;
        const auto working_free_extents_sanitized_snapshot = working_free_extents_sanitized_;
        const auto next_extent_snapshot = next_ephemeral_extent_;
        const auto working_next_extent_snapshot = working_next_ephemeral_extent_;
        const auto last_committed_xid_snapshot = last_committed_xid_;
        const auto loaded_superblock_checkpoint_xid_snapshot = loaded_superblock_checkpoint_xid_;
        const auto restore_state = [&]()
        {
            committed_spaceman_allocations_ = committed_allocations_snapshot;
            committed_spaceman_free_extents_ = committed_free_extents_snapshot;
            working_spaceman_free_extents_ = working_free_extents_snapshot;
            working_free_extents_sanitized_ = working_free_extents_sanitized_snapshot;
            next_ephemeral_extent_ = next_extent_snapshot;
            working_next_ephemeral_extent_ = working_next_extent_snapshot;
            last_committed_xid_ = last_committed_xid_snapshot;
            loaded_superblock_checkpoint_xid_ = loaded_superblock_checkpoint_xid_snapshot;
        };

        loaded_superblock_checkpoint_xid_ = std::max(loaded_superblock_checkpoint_xid_, target_xid);
        if (!LoadSpacemanCheckpointBlock(checkpoint_candidate->first, checkpoint_candidate->second) ||
            last_committed_xid_.value_or(0) != target_xid)
        {
            restore_state();
            return false;
        }

        const auto normalize_spaceman = [](const std::vector<SpacemanAllocation>& extents)
        {
            std::vector<std::pair<std::uint64_t, std::uint64_t>> normalized;
            normalized.reserve(extents.size());
            for (const auto& extent : extents)
            {
                normalized.emplace_back(extent.physical_address, extent.bytes);
            }
            std::sort(normalized.begin(), normalized.end());
            return normalized;
        };

        const auto matches =
            normalize_spaceman(committed_spaceman_allocations_) == normalize_spaceman(committed_allocations_snapshot) &&
            normalize_spaceman(committed_spaceman_free_extents_) == normalize_spaceman(committed_free_extents_snapshot);
        restore_state();
        return matches;
    };
    const auto verify_inode_checkpoint_roundtrip = [&]() -> bool
    {
        auto checkpoint_blocks = ResolveInodeCheckpointBlockIndices();
        if (checkpoint_blocks.empty() || block_size_ == 0)
        {
            return false;
        }

        constexpr std::size_t kInodeCheckpointRecordFixedBytes = 60;
        const auto should_persist_full_path = [&](const InodeRecord& inode)
        {
            if (IsRootPath(inode.full_path))
            {
                return false;
            }

            auto parent_it = committed_inodes_.find(inode.parent_object_id);
            if (parent_it == committed_inodes_.end())
            {
                return true;
            }

            auto reconstructed_path = parent_it->second.full_path;
            if (!IsRootPath(reconstructed_path))
            {
                reconstructed_path.push_back(L'\\');
            }
            reconstructed_path.append(inode.name);
            reconstructed_path = NormalizePath(reconstructed_path);
            return reconstructed_path != inode.full_path;
        };
        std::size_t required_bytes = kCheckpointHeaderBytes;
        for (const auto& [_, inode] : committed_inodes_)
        {
            const auto name_bytes = inode.name.size() * sizeof(wchar_t);
            const auto path_bytes = should_persist_full_path(inode)
                ? inode.full_path.size() * sizeof(wchar_t)
                : 0;
            if (required_bytes > (std::numeric_limits<std::size_t>::max() -
                                  kInodeCheckpointRecordFixedBytes -
                                  name_bytes -
                                  path_bytes))
            {
                return false;
            }
            required_bytes += kInodeCheckpointRecordFixedBytes + name_bytes + path_bytes;
        }
        const auto required_blocks = (required_bytes + static_cast<std::size_t>(block_size_) - 1) /
            static_cast<std::size_t>(block_size_);
        if (required_blocks == 0)
        {
            return false;
        }

        const auto checkpoint_candidate = read_chunked_checkpoint_roundtrip_candidate(
            checkpoint_blocks,
            required_blocks);
        if (!checkpoint_candidate.has_value())
        {
            return false;
        }

        const auto committed_inodes_snapshot = committed_inodes_;
        const auto committed_path_index_snapshot = committed_path_index_;
        const auto committed_directory_links_snapshot = committed_directory_links_;
        const auto committed_directory_link_index_snapshot = committed_directory_link_index_;
        const auto committed_child_ids_snapshot = committed_child_object_ids_by_parent_;
        const auto committed_child_index_snapshot = committed_child_index_by_parent_child_;
        const auto working_inodes_snapshot = working_inodes_;
        const auto working_path_index_snapshot = working_path_index_;
        const auto working_directory_links_snapshot = working_directory_links_;
        const auto working_child_count_snapshot = working_child_count_by_parent_;
        const auto working_child_ids_snapshot = working_child_object_ids_by_parent_;
        const auto working_child_index_snapshot = working_child_index_by_parent_child_;
        const auto working_directory_link_index_snapshot = working_directory_link_index_;
        const auto last_committed_xid_snapshot = last_committed_xid_;
        const auto loaded_superblock_checkpoint_xid_snapshot = loaded_superblock_checkpoint_xid_;

        const auto restore_state = [&]()
        {
            committed_inodes_ = committed_inodes_snapshot;
            InvalidateCommittedInodeOrderCache();
            committed_path_index_ = committed_path_index_snapshot;
            committed_directory_links_ = committed_directory_links_snapshot;
            committed_directory_link_index_ = committed_directory_link_index_snapshot;
            committed_child_object_ids_by_parent_ = committed_child_ids_snapshot;
            committed_child_index_by_parent_child_ = committed_child_index_snapshot;
            working_inodes_ = working_inodes_snapshot;
            working_path_index_ = working_path_index_snapshot;
            working_directory_links_ = working_directory_links_snapshot;
            working_child_count_by_parent_ = working_child_count_snapshot;
            working_child_object_ids_by_parent_ = working_child_ids_snapshot;
            working_child_index_by_parent_child_ = working_child_index_snapshot;
            working_directory_link_index_ = working_directory_link_index_snapshot;
            last_committed_xid_ = last_committed_xid_snapshot;
            loaded_superblock_checkpoint_xid_ = loaded_superblock_checkpoint_xid_snapshot;
        };

        loaded_superblock_checkpoint_xid_ = std::max(loaded_superblock_checkpoint_xid_, target_xid);
        if (!LoadInodeCheckpointBlock(checkpoint_candidate->first, checkpoint_candidate->second))
        {
            restore_state();
            return false;
        }

        const auto normalize_directory_links = [](const std::vector<DirectoryLink>& links)
        {
            std::vector<std::wstring> normalized;
            normalized.reserve(links.size());
            for (const auto& link : links)
            {
                std::wstring entry = std::to_wstring(link.parent_object_id);
                entry.push_back(L'\x1f');
                entry.append(link.entry_name);
                entry.push_back(L'\x1f');
                entry.append(std::to_wstring(link.child_object_id));
                normalized.push_back(std::move(entry));
            }
            std::sort(normalized.begin(), normalized.end());
            return normalized;
        };

        const auto same_inodes = [](
            const std::unordered_map<std::uint64_t, InodeRecord>& lhs,
            const std::unordered_map<std::uint64_t, InodeRecord>& rhs) -> bool
        {
            if (lhs.size() != rhs.size())
            {
                return false;
            }
            for (const auto& [object_id, inode] : lhs)
            {
                auto other = rhs.find(object_id);
                if (other == rhs.end())
                {
                    return false;
                }
                const auto& rhs_inode = other->second;
                if (inode.object_id != rhs_inode.object_id ||
                    inode.parent_object_id != rhs_inode.parent_object_id ||
                    inode.name != rhs_inode.name ||
                    inode.full_path != rhs_inode.full_path ||
                    inode.is_directory != rhs_inode.is_directory ||
                    inode.logical_size != rhs_inode.logical_size ||
                    inode.data_physical_address != rhs_inode.data_physical_address ||
                    inode.xid != rhs_inode.xid)
                {
                    return false;
                }
            }
            return true;
        };

        const auto matches =
            same_inodes(committed_inodes_, committed_inodes_snapshot) &&
            committed_path_index_ == committed_path_index_snapshot &&
            normalize_directory_links(committed_directory_links_) == normalize_directory_links(committed_directory_links_snapshot) &&
            last_committed_xid_.value_or(0) == target_xid;

        restore_state();
        return matches;
    };
    const auto verify_btree_checkpoint_roundtrip = [&]() -> bool
    {
        auto checkpoint_blocks = ResolveBtreeCheckpointBlockIndices();
        if (checkpoint_blocks.empty())
        {
            return false;
        }

        constexpr std::size_t kBtreeCheckpointRecordHeaderBytes = 16;
        std::size_t required_bytes = kCheckpointHeaderBytes;
        for (const auto& record : committed_btree_records_)
        {
            if (required_bytes > (std::numeric_limits<std::size_t>::max() -
                                  kBtreeCheckpointRecordHeaderBytes -
                                  record.key.size() -
                                  record.value.size()))
            {
                return false;
            }
            required_bytes += kBtreeCheckpointRecordHeaderBytes + record.key.size() + record.value.size();
        }
        if (block_size_ == 0)
        {
            return false;
        }
        const auto required_blocks = (required_bytes + static_cast<std::size_t>(block_size_) - 1) /
            static_cast<std::size_t>(block_size_);
        const auto checkpoint_candidate = read_chunked_checkpoint_roundtrip_candidate(
            checkpoint_blocks,
            required_blocks);
        if (!checkpoint_candidate.has_value())
        {
            return false;
        }

        const auto committed_btree_snapshot = committed_btree_records_;
        const auto committed_btree_index_snapshot = committed_btree_index_by_key_;
        const auto committed_btree_inode_key_snapshot = committed_btree_inode_key_by_object_id_;
        const auto last_committed_xid_snapshot = last_committed_xid_;
        const auto loaded_superblock_checkpoint_xid_snapshot = loaded_superblock_checkpoint_xid_;

        const auto restore_state = [&]()
        {
            committed_btree_records_ = committed_btree_snapshot;
            committed_btree_index_by_key_ = committed_btree_index_snapshot;
            committed_btree_inode_key_by_object_id_ = committed_btree_inode_key_snapshot;
            last_committed_xid_ = last_committed_xid_snapshot;
            loaded_superblock_checkpoint_xid_ = loaded_superblock_checkpoint_xid_snapshot;
        };

        loaded_superblock_checkpoint_xid_ = std::max(loaded_superblock_checkpoint_xid_, target_xid);
        if (!LoadBtreeCheckpointBlock(checkpoint_candidate->first, checkpoint_candidate->second))
        {
            restore_state();
            return false;
        }

        const auto same_btree_records = [](
            const std::vector<BtreeRecord>& lhs,
            const std::vector<BtreeRecord>& rhs) -> bool
        {
            if (lhs.size() != rhs.size())
            {
                return false;
            }

            for (std::size_t index = 0; index < lhs.size(); ++index)
            {
                const auto& left = lhs[index];
                const auto& right = rhs[index];
                if (left.kind != right.kind ||
                    left.tombstone != right.tombstone ||
                    left.key != right.key ||
                    left.value != right.value)
                {
                    return false;
                }
            }
            return true;
        };

        const auto matches =
            same_btree_records(committed_btree_records_, committed_btree_snapshot) &&
            last_committed_xid_.value_or(0) == target_xid;
        restore_state();
        return matches;
    };
    const auto verify_replay_checkpoint_roundtrip = [&]() -> bool
    {
        auto checkpoint_blocks = ResolveReplayCheckpointBlockIndices();
        if (checkpoint_blocks.empty() ||
            !last_commit_blob_address_.has_value() ||
            !last_commit_blob_bytes_.has_value())
        {
            return false;
        }

        const auto expected_source_xid = target_xid - 1;
        const auto expected_commit_blob_address = last_commit_blob_address_.value();
        const auto expected_commit_blob_bytes = last_commit_blob_bytes_.value();
        if (expected_commit_blob_address == 0 || expected_commit_blob_bytes == 0)
        {
            return false;
        }

        const auto checkpoint_slot = checkpoint_blocks[
            static_cast<std::size_t>(target_xid % static_cast<std::uint64_t>(checkpoint_blocks.size()))];

        std::vector<std::byte> checkpoint_block;
        if (!ReadBlockByIndexDirect(checkpoint_slot, checkpoint_block))
        {
            return false;
        }

        std::uint64_t parsed_target_xid = 0;
        std::uint64_t parsed_source_xid = 0;
        std::uint64_t parsed_commit_blob_address = 0;
        std::uint64_t parsed_commit_blob_bytes = 0;
        if (!LoadReplayCheckpointBlock(
                checkpoint_slot,
                checkpoint_block,
                parsed_target_xid,
                parsed_source_xid,
                parsed_commit_blob_address,
                parsed_commit_blob_bytes))
        {
            return false;
        }

        if (parsed_target_xid != target_xid ||
            parsed_source_xid != expected_source_xid ||
            parsed_commit_blob_address != expected_commit_blob_address ||
            parsed_commit_blob_bytes != expected_commit_blob_bytes)
        {
            return false;
        }

        return ValidateReplayCommitBlobCandidate(
            parsed_commit_blob_address,
            parsed_commit_blob_bytes,
            parsed_source_xid,
            parsed_target_xid);
    };
    const auto verify_superblock_checkpoint_roundtrip = [&]() -> bool
    {
        if (!container_loaded_ || block_size_ == 0)
        {
            return false;
        }

        constexpr std::size_t kSuperblockBytes = 0x570;
        constexpr std::size_t kMagicOffset = 0x20;
        constexpr std::size_t kBlockSizeOffset = 0x24;
        constexpr std::size_t kCheckpointXidOffset = 0x10;
        constexpr std::uint32_t kNxsbMagic = 0x4253584E; // 'NXSB'

        if (active_superblock_offset_ > (std::numeric_limits<std::uint64_t>::max() - kSuperblockBytes))
        {
            return false;
        }

        std::vector<std::byte> superblock;
        if (!device_.Read(active_superblock_offset_, kSuperblockBytes, superblock) ||
            superblock.size() < kSuperblockBytes)
        {
            return false;
        }

        return ReadLe32(superblock, kMagicOffset) == kNxsbMagic &&
               ReadLe32(superblock, kBlockSizeOffset) == block_size_ &&
               ReadLe64(superblock, kCheckpointXidOffset) == target_xid;
    };

    if (!AllowCommitStage("before-object-map-persist"))
    {
        MarkRecoveryRequired(L"CommitInterruptedBeforeObjectMapPersist");
        return CommitStatus::PersistFailed;
    }
    if (!PersistObjectMapCheckpoint(target_xid))
    {
        MarkRecoveryRequired(L"CommitObjectMapPersistFailed");
        return CommitStatus::PersistFailed;
    }
    if (verify_commit_roundtrips && !verify_object_map_checkpoint_roundtrip())
    {
        MarkRecoveryRequired(L"CommitObjectMapRoundTripFailed");
        return CommitStatus::PersistFailed;
    }

    if (!AllowCommitStage("before-spaceman-persist"))
    {
        MarkRecoveryRequired(L"CommitInterruptedBeforeSpacemanPersist");
        return CommitStatus::PersistFailed;
    }
    if (!PersistSpacemanCheckpoint(target_xid))
    {
        MarkRecoveryRequired(L"CommitSpacemanPersistFailed");
        return CommitStatus::PersistFailed;
    }
    if (verify_commit_roundtrips && !verify_spaceman_checkpoint_roundtrip())
    {
        MarkRecoveryRequired(L"CommitSpacemanRoundTripFailed");
        return CommitStatus::PersistFailed;
    }

    if (!AllowCommitStage("before-inode-persist"))
    {
        MarkRecoveryRequired(L"CommitInterruptedBeforeInodePersist");
        return CommitStatus::PersistFailed;
    }
    if (!PersistInodeCheckpoint(target_xid))
    {
        MarkRecoveryRequired(L"CommitInodePersistFailed");
        return CommitStatus::PersistFailed;
    }
    if (verify_commit_roundtrips && !verify_inode_checkpoint_roundtrip())
    {
        MarkRecoveryRequired(L"CommitInodeRoundTripFailed");
        return CommitStatus::PersistFailed;
    }

    if (!AllowCommitStage("before-btree-persist"))
    {
        MarkRecoveryRequired(L"CommitInterruptedBeforeBtreePersist");
        return CommitStatus::PersistFailed;
    }
    if (!PersistBtreeCheckpoint(target_xid))
    {
        MarkRecoveryRequired(L"CommitBtreePersistFailed");
        return CommitStatus::PersistFailed;
    }
    if (verify_commit_roundtrips && !verify_btree_checkpoint_roundtrip())
    {
        MarkRecoveryRequired(L"CommitBtreeRoundTripFailed");
        return CommitStatus::PersistFailed;
    }

    if (!AllowCommitStage("before-replay-persist"))
    {
        MarkRecoveryRequired(L"CommitInterruptedBeforeReplayPersist");
        return CommitStatus::PersistFailed;
    }
    if (!PersistReplayCheckpoint(target_xid, verify_commit_roundtrips))
    {
        MarkRecoveryRequired(L"CommitReplayPersistFailed");
        return CommitStatus::PersistFailed;
    }
    if (verify_commit_roundtrips && !AllowCommitStage("before-replay-roundtrip-verify"))
    {
        MarkRecoveryRequired(L"CommitInterruptedBeforeReplayRoundTripVerify");
        return CommitStatus::PersistFailed;
    }
    if (verify_commit_roundtrips && !verify_replay_checkpoint_roundtrip())
    {
        MarkRecoveryRequired(L"CommitReplayRoundTripFailed");
        return CommitStatus::PersistFailed;
    }
    if (batch_checkpoint_family_writes &&
        !AllowCommitStage("before-checkpoint-batch-persist"))
    {
        MarkRecoveryRequired(L"CommitInterruptedBeforeCheckpointBatchPersist");
        return CommitStatus::PersistFailed;
    }
    if (batch_checkpoint_family_writes && !FlushActiveCheckpointWriteBatch())
    {
        MarkRecoveryRequired(L"CommitCheckpointBatchPersistFailed");
        return CommitStatus::PersistFailed;
    }

    const auto require_canonical_non_fixture_commit_path = RequiresCanonicalNonFixtureCommitPath();
    const auto allow_state_persist_stage = AllowCommitStage("before-state-persist");
    if (!allow_state_persist_stage)
    {
        if (!require_canonical_non_fixture_commit_path)
        {
            rollback_commit_extent_stage();
            if (!rollback_committed_state())
            {
                return fail_commit(CommitStatus::InvariantFailed, "committed-state-rollback-failed");
            }
            return CommitStatus::PersistFailed;
        }

        // Canonical non-fixture commit/replay paths are disk-authoritative.
        // Sidecar state persistence is best-effort telemetry and must not block
        // durable checkpoint switch on production media.
        last_commit_stage_ = "state-persist-skipped";
    }
    else if (!PersistPersistentState(*commit_extent, static_cast<std::uint64_t>(commit_blob.size())))
    {
        if (!require_canonical_non_fixture_commit_path)
        {
            rollback_commit_extent_stage();
            if (!rollback_committed_state())
            {
                return fail_commit(CommitStatus::InvariantFailed, "committed-state-rollback-failed");
            }
            return CommitStatus::PersistFailed;
        }

        last_commit_stage_ = "state-persist-best-effort-failed";
    }
    if (!AllowCommitStage("before-checkpoint-switch"))
    {
        MarkRecoveryRequired(L"CommitInterruptedBeforeCheckpointSwitch");
        return CommitStatus::PersistFailed;
    }
    if (!PersistCheckpointSuperblock(target_xid))
    {
        MarkRecoveryRequired(L"CommitCheckpointWriteFailed");
        return CommitStatus::PersistFailed;
    }
    if (verify_commit_roundtrips && !AllowCommitStage("before-checkpoint-roundtrip-verify"))
    {
        MarkRecoveryRequired(L"CommitInterruptedBeforeCheckpointRoundTripVerify");
        return CommitStatus::PersistFailed;
    }
    if (verify_commit_roundtrips && !verify_superblock_checkpoint_roundtrip())
    {
        MarkRecoveryRequired(L"CommitCheckpointRoundTripFailed");
        return CommitStatus::PersistFailed;
    }
    if (!AllowCommitStage("before-checkpoint-flush"))
    {
        MarkRecoveryRequired(L"CommitInterruptedBeforeCheckpointFlush");
        return CommitStatus::FlushFailed;
    }
    if (!device_.Flush())
    {
        MarkRecoveryRequired(L"CommitCheckpointFlushFailed");
        return CommitStatus::FlushFailed;
    }

    last_committed_inode_changes_ = std::move(commit_inode_changes);
    ClearRecoveryRequired();
    pending_mutations_.clear();
    pending_mutation_path_key_cache_.clear();
    pending_write_object_ids_.clear();
    pending_write_mutation_index_by_object_id_.clear();
    pending_basic_info_mutation_index_by_object_id_.clear();
    ClearPendingPayloadPathKeys();
    ClearPendingPayloadObjectSummary();
    ClearPendingCloseDelaySummary();
    pending_object_map_updates_.clear();
    pending_object_map_update_index_.clear();
    pending_spaceman_allocations_.clear();
    pending_spaceman_allocation_index_.clear();
    pending_spaceman_deallocations_.clear();
    tracking_spaceman_free_extent_delta_ = false;
    pending_spaceman_untracked_free_extent_delta_ = false;
    pending_spaceman_released_existing_allocation_ = false;
    pending_btree_records_.clear();
    pending_btree_inode_record_count_by_object_.clear();
    pending_btree_file_inode_index_.clear();
    pending_btree_file_extent_index_.clear();
    pending_btree_file_extent_offsets_by_object_.clear();
    pending_btree_file_extent_record_count_by_object_.clear();
    pending_btree_directory_record_count_by_child_object_.clear();
    pending_btree_tombstone_record_count_ = 0;
    pending_btree_directory_inode_record_count_ = 0;
    pending_btree_untracked_record_count_ = 0;
    pending_read_extent_updates_.clear();
    prepared_payload_ranges_.clear();
    pending_written_ranges_.clear();
    pending_payload_dirty_bytes_ = 0;
    canonical_commit_ready_ = CanReportCanonicalCommitReady(
        canonical_state_loaded_,
        commit_path_ready_,
        recovery_required_,
        legacy_fixture_fallback_used_);
    last_commit_stage_ = "finalize";
    return CommitStatus::Committed;
}

MetadataStore::CommitStatus MetadataStore::CommitTransaction()
{
    ScopedPerfTimer perf_scope(commit_transaction_perf_);

    return CommitPendingMutations();
}

MetadataStore::CommitStatus MetadataStore::CommitCanonicalTransaction()
{
    ScopedPerfTimer perf_scope(commit_canonical_perf_);

    if (!canonical_state_loaded_)
    {
        return CommitStatus::NotReady;
    }

    if (!IsCanonicalCommitReady())
    {
        return CommitStatus::NotWritable;
    }

    auto status = CommitPendingMutations();
    if (status == CommitStatus::Committed || status == CommitStatus::NothingToCommit)
    {
        canonical_commit_ready_ = CanReportCanonicalCommitReady(
            canonical_state_loaded_,
            commit_path_ready_,
            recovery_required_,
            legacy_fixture_fallback_used_);
    }
    else
    {
        canonical_commit_ready_ = false;
    }

    return status;
}

bool MetadataStore::ReplayOrRecover()
{
    last_replay_stage_ = "start";
    const auto set_replay_stage = [this](std::string_view stage)
    {
        last_replay_stage_ = std::string(stage);
    };

    const auto fail_recovery = [this](std::wstring reason) -> bool
    {
        if (!reason.empty())
        {
            MarkRecoveryRequired(std::move(reason));
        }
        canonical_state_loaded_ = false;
        canonical_commit_ready_ = false;
        SyncCommitBlobTelemetryWithMode();
        return false;
    };

    if (!container_loaded_ || !object_map_loaded_ || !spaceman_loaded_)
    {
        set_replay_stage("load-volume-state");
        if (!LoadVolumeState())
        {
            if (recovery_reason_.empty())
            {
                return fail_recovery(L"RecoveryLoadVolumeStateFailed");
            }
            return false;
        }
    }
    else
    {
        set_replay_stage("volume-state-ready");
    }

    if (RequiresCanonicalNonFixtureCommitPath() &&
        !persistent_state_loaded_ &&
        !LoadPersistentState())
    {
        return fail_recovery(L"RecoveryPersistentStateLoadFailed");
    }

    set_replay_stage("load-persistent-state");
    if (!persistent_state_loaded_ && !LoadPersistentState())
    {
        return fail_recovery(L"RecoveryPersistentStateLoadFailed");
    }

    set_replay_stage("evaluate-recovery");
    native_write_ready_ = container_loaded_ && object_map_loaded_ && spaceman_loaded_;
    write_device_allowed_ = device_.IsWritable() &&
                            (context_.allow_raw_physical_write || !IsLikelyRawDevicePath(context_.device_path));
    commit_path_ready_ = native_write_ready_ && write_device_allowed_ && !recovery_required_;
    canonical_state_loaded_ = native_write_ready_ && !recovery_required_;
    canonical_commit_ready_ = CanReportCanonicalCommitReady(
        canonical_state_loaded_,
        commit_path_ready_,
        recovery_required_,
        legacy_fixture_fallback_used_);
    SyncCommitBlobTelemetryWithMode();

    if (!recovery_required_)
    {
        set_replay_stage("complete-no-recovery");
        return true;
    }

    const auto replay_if_safe = !_wcsicmp(context_.crash_replay_mode.c_str(), L"ReplayIfSafe");
    if (!replay_if_safe)
    {
        canonical_commit_ready_ = false;
        return false;
    }

    const auto maybe_roll_forward_orphan_native_checkpoint = [&]() -> bool
    {
        if (!IsLikelyRawDevicePath(context_.device_path) ||
            !context_.allow_raw_physical_write ||
            !last_committed_xid_.has_value() ||
            last_commit_blob_address_.has_value() ||
            last_commit_blob_bytes_.has_value() ||
            last_replay_checkpoint_candidate_present_ ||
            loaded_superblock_checkpoint_xid_ == std::numeric_limits<std::uint64_t>::max() ||
            last_committed_xid_.value() != (loaded_superblock_checkpoint_xid_ + 1))
        {
            return false;
        }

        set_replay_stage("orphan-native-checkpoint-integrity");
        if (!VerifyIntegrity())
        {
            return fail_recovery(L"ReplayOrphanNativeCheckpointIntegrityFailed");
        }

        const auto target_xid = last_committed_xid_.value();
        if (!AllowCommitStage("replay-before-orphan-checkpoint-switch"))
        {
            return fail_recovery(L"ReplayInterruptedBeforeCheckpointSwitch");
        }

        if (!PersistCheckpointSuperblock(target_xid))
        {
            return fail_recovery(L"ReplayCheckpointWriteFailed");
        }

        if (!AllowCommitStage("replay-before-orphan-checkpoint-flush"))
        {
            return fail_recovery(L"ReplayInterruptedBeforeCheckpointFlush");
        }

        if (!device_.Flush())
        {
            return fail_recovery(L"ReplayCheckpointFlushFailed");
        }

        checkpoint_xid_ = target_xid;
        loaded_superblock_checkpoint_xid_ = target_xid;
        ClearRecoveryRequired();
        commit_path_ready_ = native_write_ready_ && write_device_allowed_ && !recovery_required_;
        canonical_state_loaded_ = native_write_ready_ && !recovery_required_;
        canonical_commit_ready_ = CanReportCanonicalCommitReady(
            canonical_state_loaded_,
            commit_path_ready_,
            recovery_required_,
            legacy_fixture_fallback_used_);
        SyncCommitBlobTelemetryWithMode();
        set_replay_stage("complete-orphan-native-checkpoint");
        return true;
    };

    const auto superblock_in_sync = loaded_superblock_checkpoint_xid_ == checkpoint_xid_;
    if (superblock_in_sync &&
        last_committed_xid_.has_value() &&
        last_committed_xid_.value() == checkpoint_xid_)
    {
        set_replay_stage("integrity-fastpath");
        if (VerifyIntegrity())
        {
            ClearRecoveryRequired();
            commit_path_ready_ = native_write_ready_ && write_device_allowed_ && !recovery_required_;
            canonical_state_loaded_ = native_write_ready_ && !recovery_required_;
            canonical_commit_ready_ = CanReportCanonicalCommitReady(
                canonical_state_loaded_,
                commit_path_ready_,
                recovery_required_,
                legacy_fixture_fallback_used_);
            SyncCommitBlobTelemetryWithMode();
            set_replay_stage("complete-fastpath");
            return true;
        }

        return fail_recovery(L"ReplayIntegrityCheckFailed");
    }

    if (maybe_roll_forward_orphan_native_checkpoint())
    {
        return true;
    }

    if (!last_committed_xid_.has_value() ||
        !last_commit_blob_address_.has_value() ||
        !last_commit_blob_bytes_.has_value())
    {
        if (RequiresCanonicalNonFixtureCommitPath())
        {
            if (last_replay_checkpoint_candidate_present_ &&
                !last_replay_checkpoint_pending_window_)
            {
                return fail_recovery(L"ReplayCheckpointNotPendingWindow");
            }
            return fail_recovery(L"ReplayCanonicalCandidateMissing");
        }
        return fail_recovery(L"ReplayMetadataStateMissing");
    }

    const auto on_disk_checkpoint_xid = loaded_superblock_checkpoint_xid_;
    if (last_committed_xid_.value() <= on_disk_checkpoint_xid)
    {
        return fail_recovery(L"ReplayXidWindowInvalid");
    }

    if ((last_committed_xid_.value() - on_disk_checkpoint_xid) != 1)
    {
        return fail_recovery(L"ReplayXidWindowInvalid");
    }

    if (!ValidateCommitBlobLocation(
            last_commit_blob_address_.value(),
            last_commit_blob_bytes_.value()))
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }

    set_replay_stage("read-commit-blob");
    std::vector<std::byte> commit_blob;
    if (!device_.Read(last_commit_blob_address_.value(), static_cast<std::size_t>(last_commit_blob_bytes_.value()), commit_blob))
    {
        return fail_recovery(L"ReplayCommitBlobReadFailed");
    }

    if (commit_blob.size() < static_cast<std::size_t>(last_commit_blob_bytes_.value()))
    {
        return fail_recovery(L"ReplayCommitBlobReadFailed");
    }

    constexpr std::array<char, 13> kCommitBlobMagicCanonicalV3 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'C', 'A', 'N', 'O', 'N', '3', '\0'
    };
    constexpr std::array<char, 13> kCommitBlobMagicScaffoldV2 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '2', '\0'
    };
    constexpr std::array<char, 13> kCommitBlobMagicScaffoldV3 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '3', '\0'
    };
    constexpr std::size_t kCommitBlobBaseHeaderBytes = 13 + 8 + 8 + 4 + 4 + 4 + 4 + 4;
    constexpr std::size_t kCommitBlobChecksumFieldOffset = kCommitBlobBaseHeaderBytes;
    constexpr std::size_t kCommitBlobHeaderBytesV3 = kCommitBlobBaseHeaderBytes + sizeof(std::uint32_t);
    if (commit_blob.size() < kCommitBlobBaseHeaderBytes)
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }

    const auto matches_magic = [&](const std::array<char, 13>& magic) -> bool
    {
        for (std::size_t index = 0; index < magic.size(); ++index)
        {
            if (std::to_integer<unsigned char>(commit_blob[index]) != static_cast<unsigned char>(magic[index]))
            {
                return false;
            }
        }
        return true;
    };

    enum class CommitBlobMagicKind
    {
        Unknown,
        CanonicalV3,
        ScaffoldV3,
        ScaffoldV2,
    };
    const auto detected_magic = [&]() -> CommitBlobMagicKind
    {
        if (matches_magic(kCommitBlobMagicCanonicalV3))
        {
            return CommitBlobMagicKind::CanonicalV3;
        }
        if (matches_magic(kCommitBlobMagicScaffoldV3))
        {
            return CommitBlobMagicKind::ScaffoldV3;
        }
        if (matches_magic(kCommitBlobMagicScaffoldV2))
        {
            return CommitBlobMagicKind::ScaffoldV2;
        }
        return CommitBlobMagicKind::Unknown;
    }();
    if (detected_magic == CommitBlobMagicKind::Unknown)
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }

    const auto observed_scaffold_commit_blob =
        detected_magic == CommitBlobMagicKind::ScaffoldV3 ||
        detected_magic == CommitBlobMagicKind::ScaffoldV2;
    last_commit_blob_magic_ = detected_magic == CommitBlobMagicKind::CanonicalV3
        ? "APFSRWCANON3"
        : detected_magic == CommitBlobMagicKind::ScaffoldV3
            ? "APFSRWSCAFF3"
            : "APFSRWSCAFF2";
    uses_scaffold_commit_blob_ = observed_scaffold_commit_blob;

    const auto require_canonical_replay_candidate = RequiresCanonicalNonFixtureCommitPath();
    if (require_canonical_replay_candidate &&
        detected_magic != CommitBlobMagicKind::CanonicalV3)
    {
        return fail_recovery(L"ScaffoldCommitBlobActive");
    }
    const auto allow_scaffold_commit_blob = ShouldAcceptScaffoldCommitBlobForCurrentContext();
    if ((detected_magic == CommitBlobMagicKind::ScaffoldV3 ||
         detected_magic == CommitBlobMagicKind::ScaffoldV2) &&
        !allow_scaffold_commit_blob)
    {
        return fail_recovery(L"ScaffoldCommitBlobActive");
    }
    const bool commit_blob_has_checksum =
        detected_magic == CommitBlobMagicKind::CanonicalV3 ||
        detected_magic == CommitBlobMagicKind::ScaffoldV3;

    const auto commit_blob_header_bytes =
        commit_blob_has_checksum ? kCommitBlobHeaderBytesV3 : kCommitBlobBaseHeaderBytes;
    if (commit_blob.size() < commit_blob_header_bytes)
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }

    set_replay_stage("parse-commit-blob");
    auto source_xid = ReadLe64(commit_blob, 13);
    auto target_xid = ReadLe64(commit_blob, 21);
    auto mutation_count = ReadLe32(commit_blob, 29);
    auto object_map_updates = ReadLe32(commit_blob, 33);
    auto spaceman_allocations = ReadLe32(commit_blob, 37);
    auto spaceman_deallocations = ReadLe32(commit_blob, 41);
    auto btree_records = ReadLe32(commit_blob, 45);

    const auto mutation_component_total =
        static_cast<std::uint64_t>(object_map_updates) +
        static_cast<std::uint64_t>(spaceman_allocations) +
        static_cast<std::uint64_t>(spaceman_deallocations) +
        static_cast<std::uint64_t>(btree_records);
    if (mutation_count == 0 || mutation_component_total == 0 ||
        mutation_count > mutation_component_total)
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }

    if (source_xid != on_disk_checkpoint_xid ||
        target_xid != last_committed_xid_.value())
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }

    const auto commit_blob_payload_checksum =
        commit_blob_has_checksum ? ReadLe32(commit_blob, kCommitBlobChecksumFieldOffset) : 0;
    const auto payload_capacity = static_cast<std::uint64_t>(commit_blob.size() - commit_blob_header_bytes);
    const auto checked_multiply = [](std::uint32_t value, std::uint64_t unit_bytes, std::uint64_t& out_bytes) -> bool
    {
        if (unit_bytes == 0)
        {
            out_bytes = 0;
            return true;
        }
        if (value > (std::numeric_limits<std::uint64_t>::max() / unit_bytes))
        {
            return false;
        }
        out_bytes = static_cast<std::uint64_t>(value) * unit_bytes;
        return true;
    };
    const auto checked_add = [](std::uint64_t lhs, std::uint64_t rhs, std::uint64_t& out_sum) -> bool
    {
        if (lhs > (std::numeric_limits<std::uint64_t>::max() - rhs))
        {
            return false;
        }
        out_sum = lhs + rhs;
        return true;
    };
    std::uint64_t object_map_min_bytes = 0;
    std::uint64_t spaceman_allocation_min_bytes = 0;
    std::uint64_t spaceman_deallocation_min_bytes = 0;
    std::uint64_t btree_min_bytes = 0;
    if (!checked_multiply(object_map_updates, 32ull, object_map_min_bytes) ||
        !checked_multiply(spaceman_allocations, 16ull, spaceman_allocation_min_bytes) ||
        !checked_multiply(spaceman_deallocations, 16ull, spaceman_deallocation_min_bytes) ||
        !checked_multiply(btree_records, 17ull, btree_min_bytes))
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }
    std::uint64_t minimum_payload_bytes = 0;
    if (!checked_add(object_map_min_bytes, spaceman_allocation_min_bytes, minimum_payload_bytes))
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }
    if (!checked_add(minimum_payload_bytes, spaceman_deallocation_min_bytes, minimum_payload_bytes))
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }
    if (!checked_add(minimum_payload_bytes, btree_min_bytes, minimum_payload_bytes))
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }
    if (minimum_payload_bytes > payload_capacity)
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }

    std::size_t cursor = commit_blob_header_bytes;
    std::vector<ObjectMapUpdate> parsed_object_map_updates;
    std::vector<SpacemanAllocation> parsed_spaceman_allocations;
    std::vector<SpacemanAllocation> parsed_spaceman_deallocations;
    std::vector<BtreeRecord> parsed_btree_records;
    std::unordered_set<std::uint64_t> parsed_object_map_object_ids;
    try
    {
        parsed_object_map_updates.reserve(object_map_updates);
        parsed_spaceman_allocations.reserve(spaceman_allocations);
        parsed_spaceman_deallocations.reserve(spaceman_deallocations);
        parsed_btree_records.reserve(btree_records);
        parsed_object_map_object_ids.reserve(object_map_updates);
    }
    catch (...)
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }
    const auto advance = [&](std::uint64_t bytes) -> bool
    {
        if (bytes > (std::numeric_limits<std::size_t>::max() - cursor))
        {
            return false;
        }
        const auto next = cursor + static_cast<std::size_t>(bytes);
        if (next > commit_blob.size())
        {
            return false;
        }
        cursor = next;
        return true;
    };

    for (std::uint32_t index = 0; index < object_map_updates; ++index)
    {
        if (cursor > commit_blob.size() || 32 > (commit_blob.size() - cursor))
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }

        ObjectMapUpdate update{};
        update.object_id = ReadLe64(commit_blob, cursor + 0);
        update.physical_address = ReadLe64(commit_blob, cursor + 8);
        update.logical_size = ReadLe64(commit_blob, cursor + 16);
        update.xid = ReadLe64(commit_blob, cursor + 24);
        cursor += 32;

        if (update.object_id == 0 ||
            update.xid != target_xid ||
            (update.physical_address == 0) != (update.logical_size == 0))
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }
        if (!parsed_object_map_object_ids.insert(update.object_id).second)
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }
        parsed_object_map_updates.push_back(update);
    }

    for (std::uint32_t index = 0; index < spaceman_allocations; ++index)
    {
        if (cursor > commit_blob.size() || 16 > (commit_blob.size() - cursor))
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }

        SpacemanAllocation allocation{};
        allocation.physical_address = ReadLe64(commit_blob, cursor + 0);
        allocation.bytes = ReadLe64(commit_blob, cursor + 8);
        cursor += 16;
        if (allocation.physical_address == 0 || allocation.bytes == 0)
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }

        const auto aligned_bytes = AlignExtentBytes(allocation.bytes);
        if (aligned_bytes == 0 ||
            aligned_bytes != allocation.bytes ||
            ExtentOverlapsReservedMetadata(allocation.physical_address, allocation.bytes))
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }

        parsed_spaceman_allocations.push_back(allocation);
    }

    for (std::uint32_t index = 0; index < spaceman_deallocations; ++index)
    {
        if (cursor > commit_blob.size() || 16 > (commit_blob.size() - cursor))
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }

        SpacemanAllocation deallocation{};
        deallocation.physical_address = ReadLe64(commit_blob, cursor + 0);
        deallocation.bytes = ReadLe64(commit_blob, cursor + 8);
        cursor += 16;
        if (deallocation.physical_address == 0 || deallocation.bytes == 0)
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }

        const auto aligned_bytes = AlignExtentBytes(deallocation.bytes);
        if (aligned_bytes == 0 || aligned_bytes != deallocation.bytes)
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }

        parsed_spaceman_deallocations.push_back(deallocation);
    }

    if (cursor > commit_blob.size())
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }

    for (std::uint32_t index = 0; index < btree_records; ++index)
    {
        if (cursor > commit_blob.size() || 16 > (commit_blob.size() - cursor))
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }

        const auto kind_value = ReadLe32(commit_blob, cursor + 0);
        const auto tombstone_flag = ReadLe32(commit_blob, cursor + 4);
        const auto key_size = ReadLe32(commit_blob, cursor + 8);
        const auto value_size = ReadLe32(commit_blob, cursor + 12);
        cursor += 16;

        if (kind_value < static_cast<std::uint32_t>(BtreeRecordKind::Inode) ||
            kind_value > static_cast<std::uint32_t>(BtreeRecordKind::FileExtent) ||
            tombstone_flag > 1)
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }

        const auto payload_size = static_cast<std::uint64_t>(key_size) + static_cast<std::uint64_t>(value_size);
        const auto payload_start = cursor;
        if (!advance(payload_size))
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }

        BtreeRecord record{};
        record.kind = static_cast<BtreeRecordKind>(kind_value);
        record.tombstone = tombstone_flag != 0;
        if (key_size > 0)
        {
            record.key.insert(
                record.key.end(),
                commit_blob.begin() + static_cast<std::vector<std::byte>::difference_type>(payload_start),
                commit_blob.begin() + static_cast<std::vector<std::byte>::difference_type>(payload_start + key_size));
        }
        if (value_size > 0)
        {
            const auto value_start = payload_start + key_size;
            record.value.insert(
                record.value.end(),
                commit_blob.begin() + static_cast<std::vector<std::byte>::difference_type>(value_start),
                commit_blob.begin() + static_cast<std::vector<std::byte>::difference_type>(value_start + value_size));
        }
        if (record.key.empty())
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }
        if (std::to_integer<unsigned char>(record.key.front()) !=
            static_cast<unsigned char>(record.kind))
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }
        parsed_btree_records.push_back(std::move(record));
    }

    if (commit_blob_has_checksum)
    {
        const auto payload_bytes = cursor - commit_blob_header_bytes;
        const auto computed_payload_checksum = UpdateFnv1a(
            kCheckpointChecksumSeed,
            commit_blob.data() + static_cast<std::vector<std::byte>::difference_type>(commit_blob_header_bytes),
            payload_bytes);
        if (commit_blob_payload_checksum != computed_payload_checksum)
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }
    }

    if (cursor > commit_blob.size())
    {
        return fail_recovery(L"ReplayCommitBlobInvalid");
    }
    for (std::size_t index = cursor; index < commit_blob.size(); ++index)
    {
        if (commit_blob[index] != std::byte{0})
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }
    }

    if (!VerifyIntegrity())
    {
        return fail_recovery(L"ReplayIntegrityCheckFailed");
    }

    set_replay_stage("apply-replay-mutations");
    {
        std::unordered_map<std::uint64_t, ObjectMapUpdate> final_object_map_updates;
        final_object_map_updates.reserve(parsed_object_map_updates.size());
        for (const auto& update : parsed_object_map_updates)
        {
            final_object_map_updates[update.object_id] = update;
        }

        struct RawInodeMutationState
        {
            bool tombstone = false;
            bool is_directory = false;
            std::uint64_t logical_size = 0;
            std::uint64_t data_physical_address = 0;
        };

        auto canonical_blob_btree_records = CanonicalizeBtreeRecords(parsed_btree_records);
        std::unordered_map<std::uint64_t, DecodedBtreeInode> parsed_inodes_by_object;
        std::unordered_map<std::uint64_t, std::vector<DecodedBtreeExtent>> parsed_extents_by_object;
        std::unordered_map<std::wstring, DecodedBtreeDirectoryEntry> canonical_directory_entries_by_key;
        std::unordered_map<std::uint64_t, RawInodeMutationState> raw_inode_mutations_by_object;
        parsed_inodes_by_object.reserve(canonical_blob_btree_records.size());
        parsed_extents_by_object.reserve(canonical_blob_btree_records.size());
        canonical_directory_entries_by_key.reserve(canonical_blob_btree_records.size());
        raw_inode_mutations_by_object.reserve(parsed_btree_records.size());

        const auto canonical_name_key = [](const std::wstring& name)
        {
            std::wstring key = name;
            std::transform(key.begin(), key.end(), key.begin(), [](wchar_t ch)
            {
                return static_cast<wchar_t>(std::towlower(ch));
            });
            return key;
        };
        const auto build_directory_entry_triplet_key = [&](std::uint64_t parent_object_id, const std::wstring& entry_name, std::uint64_t child_object_id)
        {
            auto key = std::to_wstring(parent_object_id);
            key.push_back(L'|');
            key.append(canonical_name_key(entry_name));
            key.push_back(L'|');
            key.append(std::to_wstring(child_object_id));
            return key;
        };
        const auto build_extent_key = [](std::uint64_t physical_address, std::uint64_t bytes)
        {
            return std::to_wstring(physical_address) + L":" + std::to_wstring(bytes);
        };

        std::unordered_set<std::wstring> raw_directory_tombstone_triplets;
        std::unordered_set<std::wstring> raw_inode_tombstone_triplets;
        std::unordered_map<std::wstring, std::size_t> raw_extent_tombstone_counts;
        raw_directory_tombstone_triplets.reserve(parsed_btree_records.size());
        raw_inode_tombstone_triplets.reserve(parsed_btree_records.size());
        raw_extent_tombstone_counts.reserve(parsed_btree_records.size());

        for (const auto& raw_record : parsed_btree_records)
        {
            switch (raw_record.kind)
            {
            case BtreeRecordKind::Inode:
            {
                if (raw_record.key.size() != (1 + 8 + 8))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }

                std::uint64_t parent_object_id = 0;
                std::uint64_t object_id = 0;
                if (!TryReadLe64(raw_record.key, 1, parent_object_id) ||
                    !TryReadLe64(raw_record.key, 9, object_id) ||
                    parent_object_id == 0 ||
                    object_id == 0)
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }

                std::size_t cursor_in_value = 0;
                std::uint64_t xid = 0;
                std::uint32_t flags = 0;
                std::uint64_t logical_size = 0;
                std::uint64_t data_physical_address = 0;
                std::uint64_t timestamp_utc = 0;
                std::wstring inode_name;
                if (!TryReadLe64(raw_record.value, cursor_in_value, xid))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                cursor_in_value += 8;
                if (!TryReadLe32(raw_record.value, cursor_in_value, flags))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                cursor_in_value += 4;
                if (!TryReadLe64(raw_record.value, cursor_in_value, logical_size))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                cursor_in_value += 8;
                if (!TryReadLe64(raw_record.value, cursor_in_value, data_physical_address))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                cursor_in_value += 8;
                if ((flags & 0x4u) != 0)
                {
                    if (!TryReadLe64(raw_record.value, cursor_in_value, timestamp_utc))
                    {
                        return fail_recovery(L"ReplayCommitBlobInvalid");
                    }
                    cursor_in_value += 8;
                }
                if (!TryReadWideStringWithLength(raw_record.value, cursor_in_value, inode_name) ||
                    cursor_in_value != raw_record.value.size())
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }

                const auto value_tombstone = (flags & 0x2u) != 0;
                (void)timestamp_utc;
                if (xid != target_xid ||
                    (flags & ~0x7u) != 0 ||
                    value_tombstone != raw_record.tombstone ||
                    (raw_record.tombstone && inode_name.empty() && parent_object_id != object_id) ||
                    ((flags & 0x1u) != 0 && (logical_size != 0 || data_physical_address != 0)) ||
                    ((flags & 0x1u) == 0 &&
                     logical_size > 0 &&
                     data_physical_address == 0 &&
                     !committed_read_extents_.contains(object_id)))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }

                if (raw_record.tombstone &&
                    object_id != RootDirectoryObjectId())
                {
                    raw_inode_tombstone_triplets.insert(
                        build_directory_entry_triplet_key(parent_object_id, inode_name, object_id));
                }

                raw_inode_mutations_by_object.insert_or_assign(
                    object_id,
                    RawInodeMutationState
                    {
                        raw_record.tombstone,
                        (flags & 0x1u) != 0,
                        logical_size,
                        data_physical_address,
                    });
                break;
            }
            case BtreeRecordKind::DirectoryEntry:
            {
                if (raw_record.key.size() < (1 + 8 + 4) ||
                    raw_record.value.size() != (8 + 8 + 1))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }

                std::uint64_t parent_object_id = 0;
                if (!TryReadLe64(raw_record.key, 1, parent_object_id) ||
                    parent_object_id == 0)
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                std::size_t key_cursor = 1 + 8;
                std::wstring entry_name;
                if (!TryReadWideStringWithLength(raw_record.key, key_cursor, entry_name) ||
                    key_cursor != raw_record.key.size() ||
                    entry_name.empty())
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }

                const auto xid = ReadLe64(raw_record.value, 0);
                const auto child_object_id = ReadLe64(raw_record.value, 8);
                const auto value_tombstone = std::to_integer<unsigned char>(raw_record.value[16]) != 0;
                if (xid != target_xid ||
                    child_object_id == 0 ||
                    value_tombstone != raw_record.tombstone)
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }

                if (raw_record.tombstone)
                {
                    raw_directory_tombstone_triplets.insert(
                        build_directory_entry_triplet_key(parent_object_id, entry_name, child_object_id));
                }
                break;
            }
            case BtreeRecordKind::FileExtent:
            {
                if (raw_record.key.size() != (1 + 8 + 8) ||
                    raw_record.value.size() != (8 + 8 + 8 + 1))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }

                const auto xid = ReadLe64(raw_record.value, 0);
                const auto physical_address = ReadLe64(raw_record.value, 8);
                const auto extent_bytes = ReadLe64(raw_record.value, 16);
                const auto value_tombstone = std::to_integer<unsigned char>(raw_record.value[24]) != 0;
                if (xid != target_xid ||
                    value_tombstone != raw_record.tombstone ||
                    physical_address == 0 ||
                    extent_bytes == 0)
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                if (raw_record.tombstone)
                {
                    const auto aligned_extent_bytes = AlignExtentBytes(extent_bytes);
                    if (aligned_extent_bytes == 0)
                    {
                        return fail_recovery(L"ReplayCommitBlobInvalid");
                    }
                    ++raw_extent_tombstone_counts[build_extent_key(physical_address, aligned_extent_bytes)];
                }
                break;
            }
            default:
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }

        for (const auto& inode_tombstone_key : raw_inode_tombstone_triplets)
        {
            if (!raw_directory_tombstone_triplets.contains(inode_tombstone_key))
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }

        const auto has_recovered_read_extent_coverage = [this](std::uint64_t object_id, std::uint64_t physical_address, std::uint64_t logical_size) -> bool
        {
            if (object_id == 0 || physical_address == 0 || logical_size == 0)
            {
                return false;
            }

            const auto extents_it = committed_read_extents_.find(object_id);
            if (extents_it == committed_read_extents_.end())
            {
                return false;
            }

            const auto required_bytes = AlignExtentBytes(logical_size);
            if (required_bytes == 0)
            {
                return false;
            }

            for (const auto& extent : extents_it->second)
            {
                if (ConservativePhysicalRangeContains(
                        extent.physical_address,
                        extent.bytes,
                        physical_address,
                        required_bytes,
                        block_size_))
                {
                    return true;
                }
            }

            return false;
        };

        for (const auto& [object_id, update] : final_object_map_updates)
        {
            auto raw_inode_it = raw_inode_mutations_by_object.find(object_id);
            if (raw_inode_it == raw_inode_mutations_by_object.end())
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }

            const auto& raw_inode = raw_inode_it->second;
            if (raw_inode.is_directory &&
                (raw_inode.logical_size != 0 || raw_inode.data_physical_address != 0))
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }

            if (raw_inode.tombstone)
            {
                if (update.logical_size != 0 || update.physical_address != 0)
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                continue;
            }

            if (raw_inode.logical_size != update.logical_size ||
                raw_inode.data_physical_address != update.physical_address)
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }

        for (const auto& record : canonical_blob_btree_records)
        {
            switch (record.kind)
            {
            case BtreeRecordKind::Inode:
            {
                DecodedBtreeInode decoded{};
                if (!DecodeBtreeInodeRecord(record, decoded) ||
                    !parsed_inodes_by_object.emplace(decoded.object_id, std::move(decoded)).second)
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                break;
            }
            case BtreeRecordKind::FileExtent:
            {
                DecodedBtreeExtent decoded{};
                if (!DecodeBtreeExtentRecord(record, decoded))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                parsed_extents_by_object[decoded.object_id].push_back(std::move(decoded));
                break;
            }
            case BtreeRecordKind::DirectoryEntry:
            {
                DecodedBtreeDirectoryEntry decoded{};
                if (!DecodeBtreeDirectoryRecord(record, decoded))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }

                auto key = build_directory_entry_triplet_key(
                    decoded.parent_object_id,
                    decoded.entry_name,
                    decoded.child_object_id);
                if (!canonical_directory_entries_by_key.emplace(std::move(key), std::move(decoded)).second)
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                break;
            }
            default:
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }

        std::unordered_set<std::wstring> committed_directory_triplets;
        committed_directory_triplets.reserve(committed_directory_links_.size());
        for (const auto& link : committed_directory_links_)
        {
            if (link.parent_object_id == 0 ||
                link.child_object_id == 0 ||
                link.entry_name.empty())
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }

            committed_directory_triplets.insert(
                build_directory_entry_triplet_key(
                    link.parent_object_id,
                    link.entry_name,
                    link.child_object_id));
        }

        for (const auto& [object_id, inode] : parsed_inodes_by_object)
        {
            if (object_id == 0 ||
                object_id == RootDirectoryObjectId())
            {
                continue;
            }

            auto entry_key = build_directory_entry_triplet_key(
                inode.parent_object_id,
                inode.name,
                object_id);
            if (!canonical_directory_entries_by_key.contains(entry_key) &&
                !committed_directory_triplets.contains(entry_key))
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }

        for (const auto& [object_id, inode] : parsed_inodes_by_object)
        {
            if (inode.is_directory)
            {
                if (parsed_extents_by_object.contains(object_id))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                continue;
            }

            if (inode.logical_size == 0)
            {
                if (inode.data_physical_address != 0 ||
                    parsed_extents_by_object.contains(object_id))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                continue;
            }

            auto extent_it = parsed_extents_by_object.find(object_id);
            const auto has_recovered_read_extents =
                inode.data_physical_address == 0 &&
                committed_read_extents_.contains(object_id);
            if (has_recovered_read_extents)
            {
                if (extent_it != parsed_extents_by_object.end())
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                continue;
            }
            if (extent_it == parsed_extents_by_object.end())
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
            const auto file_extents = ExtentsFromDecodedBtreeExtents(extent_it->second);
            if (!HasLogicalExtentCoverage(file_extents, inode.logical_size) ||
                file_extents.empty() ||
                file_extents.front().logical_offset != 0 ||
                file_extents.front().physical_address != inode.data_physical_address)
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }

        for (const auto& [object_id, extents] : parsed_extents_by_object)
        {
            auto inode_it = parsed_inodes_by_object.find(object_id);
            if (inode_it == parsed_inodes_by_object.end() ||
                inode_it->second.is_directory)
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
            const auto file_extents = ExtentsFromDecodedBtreeExtents(extents);
            if (!HasLogicalExtentCoverage(file_extents, inode_it->second.logical_size) ||
                file_extents.empty() ||
                file_extents.front().logical_offset != 0 ||
                file_extents.front().physical_address != inode_it->second.data_physical_address)
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }

        for (const auto& [_, directory_entry] : canonical_directory_entries_by_key)
        {
            auto parsed_inode_it = parsed_inodes_by_object.find(directory_entry.child_object_id);
            if (parsed_inode_it == parsed_inodes_by_object.end() ||
                parsed_inode_it->second.parent_object_id != directory_entry.parent_object_id ||
                canonical_name_key(parsed_inode_it->second.name) != canonical_name_key(directory_entry.entry_name))
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }

        const auto has_committed_allocation = [this](std::uint64_t physical_address, std::uint64_t bytes_required) -> bool
        {
            if (physical_address == 0 || bytes_required == 0)
            {
                return false;
            }
            for (const auto& allocation : committed_spaceman_allocations_)
            {
                if (PhysicalRangeContains(
                        allocation.physical_address,
                        allocation.bytes,
                        physical_address,
                        bytes_required))
                {
                    return true;
                }
            }
            return false;
        };
        std::unordered_map<std::uint64_t, std::vector<DecodedBtreeExtent>> committed_extents_by_object;
        committed_extents_by_object.reserve(committed_btree_records_.size());
        for (const auto& record : committed_btree_records_)
        {
            if (record.tombstone || record.kind != BtreeRecordKind::FileExtent)
            {
                continue;
            }

            DecodedBtreeExtent decoded{};
            if (!DecodeBtreeExtentRecord(record, decoded))
            {
                set_replay_stage("validate-replay-fragmented-extent-ownership");
                return fail_recovery(L"ReplayExtentAllocationOwnershipInvalid");
            }
            committed_extents_by_object[decoded.object_id].push_back(std::move(decoded));
        }

        struct ReplayPhysicalExtent
        {
            std::uint64_t physical_address = 0;
            std::uint64_t bytes = 0;
        };
        std::vector<ReplayPhysicalExtent> replay_physical_extents;
        replay_physical_extents.reserve(parsed_btree_records.size());
        for (const auto& [_, decoded_extents] : parsed_extents_by_object)
        {
            for (const auto& extent : ExtentsFromDecodedBtreeExtents(decoded_extents))
            {
                const auto allocation_bytes = AlignExtentBytes(extent.bytes);
                if (extent.physical_address == 0 || allocation_bytes == 0 ||
                    extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - allocation_bytes))
                {
                    set_replay_stage("validate-replay-fragmented-extent-ownership");
                    return fail_recovery(L"ReplayExtentAllocationOwnershipInvalid");
                }
                replay_physical_extents.push_back({ extent.physical_address, allocation_bytes });
            }
        }
        std::sort(
            replay_physical_extents.begin(),
            replay_physical_extents.end(),
            [](const ReplayPhysicalExtent& lhs, const ReplayPhysicalExtent& rhs)
            {
                if (lhs.physical_address != rhs.physical_address)
                {
                    return lhs.physical_address < rhs.physical_address;
                }
                return lhs.bytes < rhs.bytes;
            });
        std::uint64_t previous_replay_extent_end = 0;
        bool has_previous_replay_extent = false;
        for (const auto& extent : replay_physical_extents)
        {
            if (has_previous_replay_extent && extent.physical_address < previous_replay_extent_end)
            {
                set_replay_stage("validate-replay-fragmented-extent-overlap");
                return fail_recovery(L"ReplayExtentPhysicalOverlap");
            }
            previous_replay_extent_end = extent.physical_address + extent.bytes;
            has_previous_replay_extent = true;
        }

        const auto has_canonical_fragmented_allocation_coverage =
            [&](std::uint64_t object_id,
                std::uint64_t physical_address,
                std::uint64_t logical_size) -> bool
        {
            auto extents_it = parsed_extents_by_object.find(object_id);
            if (extents_it == parsed_extents_by_object.end())
            {
                return false;
            }

            const auto file_extents = ExtentsFromDecodedBtreeExtents(extents_it->second);
            if (!HasLogicalExtentCoverage(file_extents, logical_size) ||
                file_extents.empty() ||
                file_extents.front().logical_offset != 0 ||
                file_extents.front().physical_address != physical_address)
            {
                return false;
            }

            auto committed_extents_it = committed_extents_by_object.find(object_id);
            if (committed_extents_it == committed_extents_by_object.end())
            {
                return false;
            }
            const auto committed_file_extents =
                ExtentsFromDecodedBtreeExtents(committed_extents_it->second);
            if (!FileExtentsEqual(file_extents, committed_file_extents))
            {
                return false;
            }

            for (const auto& extent : file_extents)
            {
                const auto allocation_bytes = AlignExtentBytes(extent.bytes);
                if (allocation_bytes == 0)
                {
                    return false;
                }

                bool covered_by_transaction_allocation = false;
                for (const auto& allocation : parsed_spaceman_allocations)
                {
                    if (PhysicalRangeContains(
                            allocation.physical_address,
                            allocation.bytes,
                            extent.physical_address,
                            allocation_bytes))
                    {
                        covered_by_transaction_allocation = true;
                        break;
                    }

                    if (allocation.physical_address >
                            (std::numeric_limits<std::uint64_t>::max() - allocation.bytes) ||
                        extent.physical_address >
                            (std::numeric_limits<std::uint64_t>::max() - allocation_bytes))
                    {
                        return false;
                    }
                    const auto allocation_end = allocation.physical_address + allocation.bytes;
                    const auto extent_end = extent.physical_address + allocation_bytes;
                    if (extent.physical_address < allocation_end &&
                        allocation.physical_address < extent_end)
                    {
                        return false;
                    }
                }

                if (!covered_by_transaction_allocation &&
                    !has_committed_allocation(extent.physical_address, allocation_bytes))
                {
                    return false;
                }
            }
            return true;
        };
        const auto is_covered_by_free_extent = [this](std::uint64_t physical_address, std::uint64_t bytes) -> bool
        {
            if (physical_address == 0 || bytes == 0 ||
                physical_address > (std::numeric_limits<std::uint64_t>::max() - bytes))
            {
                return false;
            }

            const auto end = physical_address + bytes;
            for (const auto& extent : committed_spaceman_free_extents_)
            {
                if (extent.physical_address == 0 || extent.bytes == 0 ||
                    extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
                {
                    continue;
                }
                const auto extent_end = extent.physical_address + extent.bytes;
                if (physical_address >= extent.physical_address && end <= extent_end)
                {
                    return true;
                }
            }
            return false;
        };
        std::unordered_set<std::wstring> seen_allocation_extents;
        seen_allocation_extents.reserve(parsed_spaceman_allocations.size());
        for (const auto& allocation : parsed_spaceman_allocations)
        {
            auto key = build_extent_key(allocation.physical_address, allocation.bytes);
            if (!seen_allocation_extents.insert(std::move(key)).second)
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }

        std::unordered_set<std::wstring> seen_deallocation_extents;
        seen_deallocation_extents.reserve(parsed_spaceman_deallocations.size());
        const auto has_overlapping_extents = [](const std::vector<SpacemanAllocation>& extents)
        {
            if (extents.size() < 2)
            {
                return false;
            }

            std::vector<SpacemanAllocation> sorted_extents = extents;
            std::sort(sorted_extents.begin(), sorted_extents.end(), [](const auto& lhs, const auto& rhs)
            {
                if (lhs.physical_address != rhs.physical_address)
                {
                    return lhs.physical_address < rhs.physical_address;
                }
                return lhs.bytes < rhs.bytes;
            });

            std::uint64_t previous_end = 0;
            bool has_previous = false;
            for (const auto& extent : sorted_extents)
            {
                if (extent.bytes == 0 ||
                    extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
                {
                    return true;
                }

                const auto current_end = extent.physical_address + extent.bytes;
                if (has_previous && extent.physical_address < previous_end)
                {
                    return true;
                }

                previous_end = current_end;
                has_previous = true;
            }

            return false;
        };
        if (has_overlapping_extents(parsed_spaceman_allocations) ||
            has_overlapping_extents(parsed_spaceman_deallocations))
        {
            return fail_recovery(L"ReplayCommitBlobInvalid");
        }
        const auto extents_overlap = [](const SpacemanAllocation& lhs, const SpacemanAllocation& rhs)
        {
            if (lhs.bytes == 0 || rhs.bytes == 0 ||
                lhs.physical_address > (std::numeric_limits<std::uint64_t>::max() - lhs.bytes) ||
                rhs.physical_address > (std::numeric_limits<std::uint64_t>::max() - rhs.bytes))
            {
                return true;
            }

            const auto lhs_end = lhs.physical_address + lhs.bytes;
            const auto rhs_end = rhs.physical_address + rhs.bytes;
            return lhs.physical_address < rhs_end && rhs.physical_address < lhs_end;
        };
        std::unordered_set<std::wstring> exact_overlap_extents;
        exact_overlap_extents.reserve(
            std::min(parsed_spaceman_allocations.size(), parsed_spaceman_deallocations.size()));
        for (const auto& allocation : parsed_spaceman_allocations)
        {
            for (const auto& deallocation : parsed_spaceman_deallocations)
            {
                if (!extents_overlap(allocation, deallocation))
                {
                    continue;
                }

                if (allocation.physical_address == deallocation.physical_address &&
                    allocation.bytes == deallocation.bytes)
                {
                    exact_overlap_extents.insert(
                        build_extent_key(allocation.physical_address, allocation.bytes));
                    continue;
                }

                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }
        for (const auto& [object_id, update] : final_object_map_updates)
        {
            auto parsed_inode_it = parsed_inodes_by_object.find(object_id);
            if (update.logical_size == 0)
            {
                if (update.physical_address != 0)
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                if (parsed_inode_it == parsed_inodes_by_object.end() &&
                    (!raw_inode_mutations_by_object.contains(object_id) ||
                     !raw_inode_mutations_by_object.find(object_id)->second.tombstone))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                if (parsed_inode_it != parsed_inodes_by_object.end() &&
                    (parsed_inode_it->second.logical_size != 0 ||
                     parsed_inode_it->second.data_physical_address != 0))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
            }
            else
            {
                const auto update_has_recovered_read_extents =
                    update.physical_address != 0 &&
                    parsed_inode_it != parsed_inodes_by_object.end() &&
                    parsed_inode_it->second.data_physical_address == 0 &&
                    has_recovered_read_extent_coverage(
                        object_id,
                        update.physical_address,
                        update.logical_size);
                if (parsed_inode_it == parsed_inodes_by_object.end() ||
                    parsed_inode_it->second.is_directory ||
                    parsed_inode_it->second.logical_size != update.logical_size ||
                    (!update_has_recovered_read_extents &&
                     parsed_inode_it->second.data_physical_address != update.physical_address))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
            }

            auto committed_it = committed_object_map_.find(object_id);
            if (HasPhysicalObjectMapping(update))
            {
                if (committed_it == committed_object_map_.end())
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
                if (committed_it->second.physical_address != update.physical_address ||
                    committed_it->second.logical_size != update.logical_size ||
                    committed_it->second.xid != update.xid)
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
            }
            else if (committed_it != committed_object_map_.end())
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }

            set_replay_stage("validate-replay-object-map-allocation");
            if (update.logical_size > 0)
            {
                const auto required_bytes = AlignExtentBytes(update.logical_size);
                bool fragmented_allocation_coverage = false;
                if (parsed_extents_by_object.contains(object_id))
                {
                    set_replay_stage("validate-replay-fragmented-extent-ownership");
                    fragmented_allocation_coverage =
                        has_canonical_fragmented_allocation_coverage(
                            object_id,
                            update.physical_address,
                            update.logical_size);
                    if (!fragmented_allocation_coverage)
                    {
                        return fail_recovery(L"ReplayExtentAllocationOwnershipInvalid");
                    }
                    set_replay_stage("validate-replay-object-map-allocation");
                }
                if (required_bytes == 0 ||
                    (!has_committed_allocation(update.physical_address, required_bytes) &&
                     !has_recovered_read_extent_coverage(object_id, update.physical_address, update.logical_size) &&
                     !fragmented_allocation_coverage))
                {
                    return fail_recovery(L"ReplayCommitBlobInvalid");
                }
            }
        }

        for (const auto& deallocation : parsed_spaceman_deallocations)
        {
            auto key = build_extent_key(deallocation.physical_address, deallocation.bytes);
            const auto is_exact_overlap_extent = exact_overlap_extents.contains(key);
            if (!seen_deallocation_extents.insert(key).second)
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
            if (!is_exact_overlap_extent &&
                !is_covered_by_free_extent(deallocation.physical_address, deallocation.bytes))
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }
        for (const auto& [key, count] : raw_extent_tombstone_counts)
        {
            if (count != 1 || !seen_deallocation_extents.contains(key))
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }
        for (const auto& overlap_key : exact_overlap_extents)
        {
            if (!seen_deallocation_extents.contains(overlap_key))
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
            if (!raw_extent_tombstone_counts.contains(overlap_key))
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }
        for (const auto& deallocation_key : seen_deallocation_extents)
        {
            if (!raw_extent_tombstone_counts.contains(deallocation_key))
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }

        std::unordered_map<std::wstring, std::size_t> committed_allocation_counts;
        committed_allocation_counts.reserve(committed_spaceman_allocations_.size());
        for (const auto& allocation : committed_spaceman_allocations_)
        {
            ++committed_allocation_counts[build_extent_key(allocation.physical_address, allocation.bytes)];
        }

        std::unordered_map<std::wstring, int> net_allocation_delta;
        net_allocation_delta.reserve(parsed_spaceman_allocations.size() + parsed_spaceman_deallocations.size());
        for (const auto& allocation : parsed_spaceman_allocations)
        {
            ++net_allocation_delta[build_extent_key(allocation.physical_address, allocation.bytes)];
        }
        for (const auto& deallocation : parsed_spaceman_deallocations)
        {
            --net_allocation_delta[build_extent_key(deallocation.physical_address, deallocation.bytes)];
        }

        for (const auto& [key, delta] : net_allocation_delta)
        {
            if (delta <= 0)
            {
                continue;
            }
            const auto separator = key.find(L':');
            if (separator == std::wstring::npos)
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
            std::uint64_t physical_address = 0;
            std::uint64_t bytes_required = 0;
            try
            {
                physical_address = std::stoull(key.substr(0, separator));
                bytes_required = std::stoull(key.substr(separator + 1));
            }
            catch (...)
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
            if (bytes_required == 0 ||
                static_cast<std::uint64_t>(delta) != 1 ||
                !has_committed_allocation(physical_address, bytes_required))
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }

        std::unordered_map<std::string, BtreeRecord> committed_btree_by_key;
        committed_btree_by_key.reserve(committed_btree_records_.size());
        for (const auto& record : committed_btree_records_)
        {
            auto key_blob = BuildBtreeKeyBlob(record.key);
            if (!key_blob.empty())
            {
                committed_btree_by_key.insert_or_assign(std::move(key_blob), record);
            }
        }

        for (const auto& record : canonical_blob_btree_records)
        {
            auto key_blob = BuildBtreeKeyBlob(record.key);
            if (key_blob.empty())
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }

            auto committed_it = committed_btree_by_key.find(key_blob);
            if (committed_it == committed_btree_by_key.end() ||
                committed_it->second.kind != record.kind ||
                committed_it->second.tombstone != record.tombstone ||
                committed_it->second.value != record.value)
            {
                return fail_recovery(L"ReplayCommitBlobInvalid");
            }
        }
    }

    if (!AllowCommitStage("replay-before-checkpoint-switch"))
    {
        return fail_recovery(L"ReplayInterruptedBeforeCheckpointSwitch");
    }

    if (!PersistCheckpointSuperblock(target_xid))
    {
        return fail_recovery(L"ReplayCheckpointWriteFailed");
    }

    if (!AllowCommitStage("replay-before-checkpoint-flush"))
    {
        return fail_recovery(L"ReplayInterruptedBeforeCheckpointFlush");
    }

    if (!device_.Flush())
    {
        return fail_recovery(L"ReplayCheckpointFlushFailed");
    }

    checkpoint_xid_ = target_xid;
    loaded_superblock_checkpoint_xid_ = target_xid;
    ClearRecoveryRequired();
    commit_path_ready_ = native_write_ready_ && write_device_allowed_ && !recovery_required_;
    canonical_state_loaded_ = native_write_ready_ && !recovery_required_;
    canonical_commit_ready_ = CanReportCanonicalCommitReady(
        canonical_state_loaded_,
        commit_path_ready_,
        recovery_required_,
        legacy_fixture_fallback_used_);
    set_replay_stage("complete");
    return true;
}

bool MetadataStore::ReplayCanonicalCheckpoint()
{
    if (!canonical_state_loaded_ && !LoadCanonicalState())
    {
        return false;
    }

    const auto replay_result = ReplayOrRecover();
    canonical_state_loaded_ = replay_result &&
                              container_loaded_ &&
                              object_map_loaded_ &&
                              spaceman_loaded_ &&
                              !recovery_required_;
    canonical_commit_ready_ = CanReportCanonicalCommitReady(
        canonical_state_loaded_,
        commit_path_ready_,
        recovery_required_,
        legacy_fixture_fallback_used_);
    return replay_result;
}

bool MetadataStore::VerifyIntegrity() const
{
    last_integrity_failure_reason_.clear();
    last_integrity_failure_object_id_.reset();

    if (!container_loaded_ || !object_map_loaded_ || !spaceman_loaded_)
    {
        RecordIntegrityFailure(L"Prerequisites");
        return false;
    }

    if (!ValidateInodeGraphState(
            committed_inodes_,
            committed_path_index_,
            committed_directory_links_,
            true))
    {
        RecordIntegrityFailure(L"InodeGraph");
        return false;
    }

    for (const auto& [path_key, object_id] : committed_path_index_)
    {
        if (path_key.empty())
        {
            RecordIntegrityFailure(L"PathKeyEmpty");
            return false;
        }

        if (committed_inodes_.find(object_id) == committed_inodes_.end())
        {
            RecordIntegrityFailure(L"PathMissingInode", object_id);
            return false;
        }
    }

    for (const auto& [object_id, inode] : committed_inodes_)
    {
        if (object_id == 0 || inode.object_id != object_id)
        {
            RecordIntegrityFailure(L"InodeIdentity", object_id);
            return false;
        }

        if (!inode.is_directory &&
            inode.logical_size > 0 &&
            inode.data_physical_address == 0 &&
            !committed_read_extents_.contains(object_id))
        {
            RecordIntegrityFailure(L"MissingReadExtent", object_id);
            return false;
        }
    }

    const auto xid_upper_bound = std::max<std::uint64_t>(
        1,
        std::max(checkpoint_xid_, last_committed_xid_.value_or(0)));

    const auto has_allocation_for_physical = [this](std::uint64_t physical_address, std::uint64_t logical_size) -> bool
    {
        if (physical_address == 0 || logical_size == 0)
        {
            return false;
        }

        const auto required_bytes = AlignExtentBytes(logical_size);
        if (required_bytes == 0)
        {
            return false;
        }

        for (const auto& allocation : committed_spaceman_allocations_)
        {
            if (allocation.physical_address > physical_address ||
                allocation.bytes < required_bytes)
            {
                continue;
            }
            const auto requested_end = physical_address + required_bytes;
            const auto allocation_end = allocation.physical_address + allocation.bytes;
            if (requested_end >= physical_address &&
                allocation_end >= allocation.physical_address &&
                requested_end <= allocation_end)
            {
                return true;
            }
        }
        return false;
    };
    const auto has_recovered_read_extent_coverage = [this](std::uint64_t object_id, std::uint64_t physical_address, std::uint64_t logical_size) -> bool
    {
        if (!context_.allow_raw_physical_write ||
            physical_address == 0 ||
            logical_size == 0)
        {
            return false;
        }

        const auto extents_it = committed_read_extents_.find(object_id);
        if (extents_it == committed_read_extents_.end())
        {
            return false;
        }

        const auto* extents = &extents_it->second;
        if (!HasLogicalExtentCoverage(*extents, logical_size) ||
            extents->empty() ||
            extents->front().logical_offset != 0 ||
            extents->front().physical_address != physical_address)
        {
            return false;
        }

        for (const auto& extent : *extents)
        {
            if (extent.physical_address == 0 || extent.bytes == 0)
            {
                return false;
            }

            const auto required_bytes = AlignExtentBytes(extent.bytes);
            if (required_bytes == 0)
            {
                return false;
            }

            if (ConservativePhysicalRangeContains(
                    extent.physical_address,
                    extent.bytes,
                    extent.physical_address,
                    required_bytes,
                    block_size_))
            {
                continue;
            }

            return false;
        }

        return true;
    };
    const auto relax_physical_read_projection =
        IsLikelyRawDevicePath(context_.device_path) &&
        !context_.allow_raw_physical_write &&
        !committed_read_extents_.empty();

    std::unordered_set<std::string> projected_btree_keys;
    projected_btree_keys.reserve(committed_btree_records_.size());
    for (const auto& record : committed_btree_records_)
    {
        if (record.key.empty() ||
            record.kind < BtreeRecordKind::Inode ||
            record.kind > BtreeRecordKind::FileExtent)
        {
            RecordIntegrityFailure(L"ProjectedBtreeInvalid");
            return false;
        }
        if (record.tombstone)
        {
            RecordIntegrityFailure(L"ProjectedBtreeTombstone");
            return false;
        }
        if (std::to_integer<unsigned char>(record.key.front()) != static_cast<unsigned char>(record.kind))
        {
            RecordIntegrityFailure(L"ProjectedBtreeKindPrefix");
            return false;
        }

        auto key_blob = BuildBtreeKeyBlob(record.key);
        if (key_blob.empty() || !projected_btree_keys.insert(std::move(key_blob)).second)
        {
            RecordIntegrityFailure(L"ProjectedBtreeDuplicate");
            return false;
        }
    }

    std::unordered_set<std::string> expected_btree_keys;
    expected_btree_keys.reserve(
        committed_inodes_.size() +
        committed_directory_links_.size() +
        committed_inodes_.size());
    const auto committed_btree_extents_for_inode = [this](const InodeRecord& inode) -> std::optional<std::vector<FileExtent>>
    {
        if (inode.is_directory ||
            inode.logical_size == 0 ||
            inode.data_physical_address == 0)
        {
            return std::nullopt;
        }

        if (auto extents_it = committed_read_extents_.find(inode.object_id);
            extents_it != committed_read_extents_.end())
        {
            const auto* extents = &extents_it->second;
            if (HasLogicalExtentCoverage(*extents, inode.logical_size) &&
                !extents->empty() &&
                extents->front().logical_offset == 0 &&
                extents->front().physical_address == inode.data_physical_address)
            {
                return *extents;
            }
        }

        return std::vector<FileExtent>{ FileExtent{ 0, inode.data_physical_address, inode.logical_size } };
    };

    for (const auto& [object_id, inode] : committed_inodes_)
    {
        if (IsRootPath(inode.full_path))
        {
            continue;
        }

        auto inode_key_record = BtreeMutationCodec::EncodeInodeRecord(
            object_id,
            inode.parent_object_id,
            inode.name,
            inode.is_directory,
            inode.logical_size,
            inode.data_physical_address,
            inode.timestamp_utc,
            xid_upper_bound,
            false);
        auto inode_key = BuildBtreeKeyBlob(inode_key_record.key);
        if (inode_key.empty() || !expected_btree_keys.insert(std::move(inode_key)).second)
        {
            RecordIntegrityFailure(L"ExpectedBtreeInodeDuplicate", object_id);
            return false;
        }

        if (!inode.is_directory &&
            inode.logical_size > 0)
        {
            if (auto expected_extents = committed_btree_extents_for_inode(inode);
                expected_extents.has_value())
            {
                for (const auto& extent : expected_extents.value())
                {
                    auto extent_key_record = BtreeMutationCodec::EncodeExtentRecord(
                        object_id,
                        extent.logical_offset,
                        extent.physical_address,
                        extent.bytes,
                        xid_upper_bound,
                        false);
                    auto extent_key = BuildBtreeKeyBlob(extent_key_record.key);
                    if (extent_key.empty() || !expected_btree_keys.insert(std::move(extent_key)).second)
                    {
                        RecordIntegrityFailure(L"ExpectedBtreeExtentDuplicate", object_id);
                        return false;
                    }
                }
            }
        }
    }

    for (const auto& link : committed_directory_links_)
    {
        auto directory_key_record = BtreeMutationCodec::EncodeDirectoryRecord(
            link.parent_object_id,
            link.entry_name,
            link.child_object_id,
            xid_upper_bound,
            false);
        auto directory_key = BuildBtreeKeyBlob(directory_key_record.key);
        if (directory_key.empty() || !expected_btree_keys.insert(std::move(directory_key)).second)
        {
            RecordIntegrityFailure(L"ExpectedBtreeDirectoryDuplicate", link.child_object_id);
            return false;
        }
    }

    if (projected_btree_keys.size() != expected_btree_keys.size())
    {
        RecordIntegrityFailure(L"ProjectedBtreeSize");
        return false;
    }
    for (const auto& expected_key : expected_btree_keys)
    {
        if (!projected_btree_keys.contains(expected_key))
        {
            RecordIntegrityFailure(L"ProjectedBtreeMissingKey");
            return false;
        }
    }

    std::unordered_map<std::uint64_t, DecodedBtreeInode> decoded_inodes_by_object;
    std::unordered_map<std::wstring, DecodedBtreeDirectoryEntry> decoded_directory_entries;
    std::unordered_map<std::uint64_t, std::vector<DecodedBtreeExtent>> decoded_extents_by_object;
    decoded_inodes_by_object.reserve(committed_btree_records_.size());
    decoded_directory_entries.reserve(committed_btree_records_.size());
    decoded_extents_by_object.reserve(committed_btree_records_.size());

    for (const auto& record : committed_btree_records_)
    {
        switch (record.kind)
        {
        case BtreeRecordKind::Inode:
        {
            DecodedBtreeInode decoded{};
            if (!DecodeBtreeInodeRecord(record, decoded))
            {
                RecordIntegrityFailure(L"DecodeInode");
                return false;
            }
            if (!decoded_inodes_by_object.emplace(decoded.object_id, std::move(decoded)).second)
            {
                return false;
            }
            break;
        }
        case BtreeRecordKind::DirectoryEntry:
        {
            DecodedBtreeDirectoryEntry decoded{};
            if (!DecodeBtreeDirectoryRecord(record, decoded))
            {
                RecordIntegrityFailure(L"DecodeDirectory");
                return false;
            }
            auto key = BuildDirectoryEntryIndexKey(decoded.parent_object_id, decoded.entry_name);
            if (!decoded_directory_entries.emplace(std::move(key), std::move(decoded)).second)
            {
                return false;
            }
            break;
        }
        case BtreeRecordKind::FileExtent:
        {
            DecodedBtreeExtent decoded{};
            if (!DecodeBtreeExtentRecord(record, decoded))
            {
                RecordIntegrityFailure(L"DecodeExtent");
                return false;
            }
            decoded_extents_by_object[decoded.object_id].push_back(std::move(decoded));
            break;
        }
        default:
            return false;
        }
    }

    std::size_t expected_non_root_inode_count = 0;
    for (const auto& [object_id, inode] : committed_inodes_)
    {
        (void)object_id;
        if (!IsRootPath(inode.full_path))
        {
            ++expected_non_root_inode_count;
        }
    }
    if (decoded_inodes_by_object.size() != expected_non_root_inode_count)
    {
        RecordIntegrityFailure(L"InodeCount");
        return false;
    }

    for (const auto& [object_id, inode] : committed_inodes_)
    {
        if (IsRootPath(inode.full_path))
        {
            continue;
        }

        auto decoded_it = decoded_inodes_by_object.find(object_id);
        if (decoded_it == decoded_inodes_by_object.end())
        {
            RecordIntegrityFailure(L"MissingDecodedInode", object_id);
            return false;
        }
        const auto& decoded = decoded_it->second;
        if (decoded.parent_object_id != inode.parent_object_id ||
            decoded.is_directory != inode.is_directory ||
            decoded.logical_size != inode.logical_size ||
            decoded.data_physical_address != inode.data_physical_address ||
            decoded.timestamp_utc != inode.timestamp_utc ||
            decoded.name != inode.name)
        {
            RecordIntegrityFailure(L"DecodedInodeMismatch", object_id);
            return false;
        }
        if (decoded.xid == 0 || decoded.xid > xid_upper_bound)
        {
            RecordIntegrityFailure(L"InodeXid", object_id);
            return false;
        }
        if (decoded.parent_object_id == 0 || !committed_inodes_.contains(decoded.parent_object_id))
        {
            RecordIntegrityFailure(L"InodeParentMissing", object_id);
            return false;
        }
        if (auto parent_it = committed_inodes_.find(decoded.parent_object_id);
            parent_it == committed_inodes_.end() || !parent_it->second.is_directory)
        {
            RecordIntegrityFailure(L"InodeParentDirectory", object_id);
            return false;
        }

        if (inode.is_directory || inode.logical_size == 0)
        {
            if (decoded_extents_by_object.contains(object_id))
            {
                RecordIntegrityFailure(L"UnexpectedExtentForZeroOrDir", object_id);
                return false;
            }
        }
        else if (inode.data_physical_address == 0)
        {
            if (!committed_read_extents_.contains(object_id))
            {
                RecordIntegrityFailure(L"MissingCommittedReadExtents", object_id);
                return false;
            }
        }
        else
        {
            auto extent_it = decoded_extents_by_object.find(object_id);
            if (extent_it == decoded_extents_by_object.end())
            {
                RecordIntegrityFailure(L"MissingExtentRecord", object_id);
                return false;
            }
            if (!relax_physical_read_projection)
            {
                if (auto expected_extents = committed_btree_extents_for_inode(inode);
                    expected_extents.has_value())
                {
                    if (!ExtentsMatchDecodedBtreeExtents(
                            expected_extents.value(),
                            extent_it->second,
                            inode.logical_size,
                            inode.data_physical_address,
                            xid_upper_bound))
                    {
                        TraceExtentMismatchDetail(
                            object_id,
                            expected_extents.value(),
                            extent_it->second,
                            inode.logical_size,
                            inode.data_physical_address,
                            xid_upper_bound);
                        RecordIntegrityFailure(L"ExtentMismatch", object_id);
                        return false;
                    }
                }
            }

            auto mapped = committed_object_map_.find(object_id);
            if (mapped == committed_object_map_.end())
            {
                RecordIntegrityFailure(L"MissingObjectMap", object_id);
                return false;
            }
        if (mapped->second.xid == 0 ||
            mapped->second.xid > xid_upper_bound ||
                (!relax_physical_read_projection &&
                 (mapped->second.physical_address != inode.data_physical_address ||
                  mapped->second.logical_size != inode.logical_size)))
            {
                RecordIntegrityFailure(L"ObjectMapMismatch", object_id);
                return false;
            }
            if (context_.allow_raw_physical_write &&
                !has_allocation_for_physical(mapped->second.physical_address, mapped->second.logical_size) &&
                !has_recovered_read_extent_coverage(
                    object_id,
                    mapped->second.physical_address,
                    mapped->second.logical_size))
            {
                if (IsReadTraceEnabled())
                {
                    std::wcerr << L"[MetadataStore] MissingAllocation detail"
                               << L" object=" << object_id
                               << L" physical=" << mapped->second.physical_address
                               << L" logical=" << mapped->second.logical_size
                               << L" allocations=" << committed_spaceman_allocations_.size()
                               << L" freeExtents=" << committed_spaceman_free_extents_.size()
                               << std::endl;
                }
                RecordIntegrityFailure(L"MissingAllocation", object_id);
                return false;
            }
        }
    }

    if (decoded_directory_entries.size() != committed_directory_links_.size())
    {
        RecordIntegrityFailure(L"DirectoryEntryCount");
        return false;
    }
    for (const auto& link : committed_directory_links_)
    {
        auto entry_key = BuildDirectoryEntryIndexKey(link.parent_object_id, link.entry_name);
        auto decoded_it = decoded_directory_entries.find(entry_key);
        if (decoded_it == decoded_directory_entries.end())
        {
            RecordIntegrityFailure(L"MissingDecodedDirectory", link.child_object_id);
            return false;
        }
        const auto& decoded = decoded_it->second;
        if (decoded.child_object_id != link.child_object_id ||
            decoded.xid == 0 ||
            decoded.xid > xid_upper_bound)
        {
            RecordIntegrityFailure(L"DirectoryMismatch", link.child_object_id);
            return false;
        }

        auto parent_it = committed_inodes_.find(link.parent_object_id);
        auto child_it = committed_inodes_.find(link.child_object_id);
        if (parent_it == committed_inodes_.end() ||
            child_it == committed_inodes_.end() ||
            !parent_it->second.is_directory ||
            child_it->second.parent_object_id != link.parent_object_id ||
            child_it->second.name != link.entry_name)
        {
            RecordIntegrityFailure(L"DirectoryLinkMismatch", link.child_object_id);
            return false;
        }
    }

    return true;
}

std::size_t MetadataStore::PendingMutationCount() const noexcept
{
    return pending_mutations_.size();
}

bool MetadataStore::PendingMutationsAreContentWritesOnly() const noexcept
{
    return !pending_mutations_.empty() &&
           pending_close_delay_write_count_ == pending_mutations_.size();
}

bool MetadataStore::PendingMutationsAreDeletesOnly() const noexcept
{
    return !pending_mutations_.empty() &&
           std::all_of(
               pending_mutations_.begin(),
               pending_mutations_.end(),
               [](const MutationRequest& mutation)
               {
                   return mutation.operation == MutationOperation::Delete;
               });
}

bool MetadataStore::PendingMutationsCanSkipPreflightInodeGraphValidation() const noexcept
{
    if (pending_mutations_.empty())
    {
        return false;
    }

    if (PendingMutationsAreContentWritesOnly())
    {
        return true;
    }

    if (!pending_close_delay_mixed_valid_)
    {
        return false;
    }

    for (const auto& mutation : pending_mutations_)
    {
        switch (mutation.operation)
        {
        case MutationOperation::CreateFile:
        case MutationOperation::Write:
        case MutationOperation::SetFileSize:
        case MutationOperation::SetBasicInfo:
            break;
        case MutationOperation::CreateDirectory:
        case MutationOperation::Rename:
        case MutationOperation::Delete:
            return false;
        }
    }

    if (pending_close_delay_metadata_only_count_ == pending_mutations_.size())
    {
        return true;
    }

    return pending_close_delay_payload_write_count_ > 0 &&
           !pending_close_delay_created_file_object_ids_.empty();
}

bool MetadataStore::PendingMutationsCanSkipPreflightProjectedBtreeValidation() const noexcept
{
    if (pending_mutations_.empty() ||
        pending_spaceman_deallocations_.size() != 0 ||
        pending_spaceman_untracked_free_extent_delta_ ||
        pending_spaceman_released_existing_allocation_)
    {
        return false;
    }

    if (!pending_close_delay_mixed_valid_ ||
        pending_close_delay_payload_write_count_ == 0 ||
        pending_close_delay_created_file_object_ids_.empty())
    {
        return false;
    }

    for (const auto& mutation : pending_mutations_)
    {
        switch (mutation.operation)
        {
        case MutationOperation::CreateFile:
        case MutationOperation::Write:
        case MutationOperation::SetFileSize:
        case MutationOperation::SetBasicInfo:
            break;
        case MutationOperation::CreateDirectory:
        case MutationOperation::Rename:
        case MutationOperation::Delete:
            return false;
        }
    }

    return PendingBtreeRecordSummaryMatchesFreshIngest();
}

bool MetadataStore::PendingBtreeRecordSummaryMatchesFreshIngest() const noexcept
{
    if (pending_btree_records_.empty() ||
        pending_btree_tombstone_record_count_ != 0 ||
        pending_btree_directory_inode_record_count_ != 0 ||
        pending_btree_untracked_record_count_ != 0)
    {
        return false;
    }

    std::size_t tracked_records = 0;
    for (const auto& [object_id, record_count] : pending_btree_inode_record_count_by_object_)
    {
        if (record_count == 0 ||
            !pending_close_delay_created_file_object_ids_.contains(object_id))
        {
            return false;
        }
        tracked_records += record_count;
    }

    for (const auto& [object_id, record_count] : pending_btree_file_extent_record_count_by_object_)
    {
        if (record_count == 0 ||
            !pending_close_delay_created_file_object_ids_.contains(object_id))
        {
            return false;
        }
        tracked_records += record_count;
    }

    for (const auto& [object_id, record_count] : pending_btree_directory_record_count_by_child_object_)
    {
        if (record_count == 0 ||
            !pending_close_delay_created_file_object_ids_.contains(object_id))
        {
            return false;
        }
        tracked_records += record_count;
    }

    return tracked_records == pending_btree_records_.size();
}

bool MetadataStore::PendingMutationsCanContinueDeferredClose() const
{
    if (pending_mutations_.empty())
    {
        return false;
    }

    return pending_close_delay_continue_valid_;
}

bool MetadataStore::PendingMutationsCanDelayClose() const
{
    if (pending_mutations_.empty())
    {
        return false;
    }

    if (PendingMutationsAreContentWritesOnly())
    {
        return true;
    }

    if (pending_close_delay_mixed_valid_ &&
        pending_close_delay_metadata_only_count_ == pending_mutations_.size())
    {
        return true;
    }

    return pending_close_delay_mixed_valid_ &&
           pending_close_delay_payload_write_count_ > 0 &&
           !pending_close_delay_created_file_object_ids_.empty();
}

std::size_t MetadataStore::PendingObjectMapUpdateCount() const noexcept
{
    return pending_object_map_updates_.size();
}

std::size_t MetadataStore::PendingAllocationCount() const noexcept
{
    return pending_spaceman_allocations_.size();
}

std::size_t MetadataStore::PendingSpacemanAllocationIndexCount() const noexcept
{
    return pending_spaceman_allocation_index_.size();
}

std::size_t MetadataStore::PendingDeallocationCount() const noexcept
{
    return pending_spaceman_deallocations_.size();
}

std::size_t MetadataStore::PendingBtreeRecordCount() const noexcept
{
    return pending_btree_records_.size();
}

std::uint64_t MetadataStore::PendingWriteCoalesceScanCount() const noexcept
{
    return pending_write_coalesce_scan_count_.load(std::memory_order_relaxed);
}

std::uint64_t MetadataStore::PendingBasicInfoCoalescePathFallbackCount() const noexcept
{
    return pending_basic_info_coalesce_path_fallback_count_.load(std::memory_order_relaxed);
}

std::uint64_t MetadataStore::PendingSetFileSizeCoalescePathFallbackCount() const noexcept
{
    return pending_set_file_size_coalesce_path_fallback_count_.load(std::memory_order_relaxed);
}

std::uint64_t MetadataStore::DirectoryRenameDescendantPathLookupCount() const noexcept
{
    return directory_rename_descendant_path_lookup_count_.load(std::memory_order_relaxed);
}

std::uint64_t MetadataStore::DirectoryRenameDescendantDirectoryLinkUpdateCount() const noexcept
{
    return directory_rename_descendant_directory_link_update_count_.load(std::memory_order_relaxed);
}

std::uint64_t MetadataStore::PendingPayloadRenamePathScanCount() const noexcept
{
    return pending_payload_rename_path_scan_count_.load(std::memory_order_relaxed);
}

std::uint64_t MetadataStore::PendingPayloadDeletePathScanCount() const noexcept
{
    return pending_payload_delete_path_scan_count_.load(std::memory_order_relaxed);
}

std::uint64_t MetadataStore::PendingPayloadSummaryPathScanCount() const noexcept
{
    return pending_payload_summary_path_scan_count_.load(std::memory_order_relaxed);
}

std::uint64_t MetadataStore::PendingObjectMapUpdateScanCount() const noexcept
{
    return pending_object_map_update_scan_count_.load(std::memory_order_relaxed);
}

std::uint64_t MetadataStore::PendingBtreeFileMetadataScanCount() const noexcept
{
    return pending_btree_file_metadata_scan_count_.load(std::memory_order_relaxed);
}

std::uint64_t MetadataStore::PendingCloseDelaySummaryRebuildCount() const noexcept
{
    return pending_close_delay_summary_rebuild_count_.load(std::memory_order_relaxed);
}

std::uint64_t MetadataStore::WorkingFreeExtentSanitizeCount() const noexcept
{
    return working_free_extent_sanitize_count_.load(std::memory_order_relaxed);
}

std::uint64_t MetadataStore::WorkingFreeExtentSanitizeSkipCount() const noexcept
{
    return working_free_extent_sanitize_skip_count_.load(std::memory_order_relaxed);
}

std::uint64_t MetadataStore::FreeExtentSanitizeCount() const noexcept
{
    return free_extent_sanitize_count_.load(std::memory_order_relaxed);
}

std::uint64_t MetadataStore::FreeExtentSanitizeSkipCount() const noexcept
{
    return free_extent_sanitize_skip_count_.load(std::memory_order_relaxed);
}

std::uint64_t MetadataStore::CommitRestoreDedupeLinearScanCount() const noexcept
{
    return commit_restore_dedupe_linear_scan_count_.load(std::memory_order_relaxed);
}

std::uint64_t MetadataStore::CommitBtreeFullSnapshotCount() const noexcept
{
    return commit_btree_full_snapshot_count_.load(std::memory_order_relaxed);
}

std::uint64_t MetadataStore::CommittedSpacemanFullSnapshotCount() const noexcept
{
    return committed_spaceman_full_snapshot_count_.load(std::memory_order_relaxed);
}

std::size_t MetadataStore::PendingPayloadObjectSummaryCount() const noexcept
{
    return pending_payload_object_ids_.size();
}

std::uint64_t MetadataStore::PendingPayloadByteEstimate() const
{
    last_raw_mutation_count_.store(
        static_cast<std::uint64_t>(pending_mutations_.size()),
        std::memory_order_relaxed);
    last_compacted_mutation_count_.store(
        static_cast<std::uint64_t>(pending_payload_object_ids_.size()),
        std::memory_order_relaxed);
    return pending_payload_total_bytes_;
}

std::uint64_t MetadataStore::PendingPayloadDirtyByteEstimate() const noexcept
{
    return pending_payload_dirty_bytes_;
}

std::uint64_t MetadataStore::PendingPayloadRangeLocalMergeCount() const noexcept
{
    return pending_payload_range_local_merge_count_.load(std::memory_order_relaxed);
}

std::uint64_t MetadataStore::PendingPayloadRangeFullMergeCount() const noexcept
{
    return pending_payload_range_full_merge_count_.load(std::memory_order_relaxed);
}

std::optional<std::uint64_t> MetadataStore::LastCommittedXid() const noexcept
{
    return last_committed_xid_;
}

std::size_t MetadataStore::CommittedObjectCount() const noexcept
{
    return committed_object_map_.size();
}

std::size_t MetadataStore::CommittedAllocationCount() const noexcept
{
    return committed_spaceman_allocations_.size();
}

std::size_t MetadataStore::CommittedFreeExtentCount() const noexcept
{
    return committed_spaceman_free_extents_.size();
}

std::size_t MetadataStore::CommittedBtreeRecordCount() const noexcept
{
    return committed_btree_records_.size();
}

std::optional<MetadataStore::ObjectMapUpdate> MetadataStore::LookupCommittedObject(std::uint64_t object_id) const
{
    if (auto it = committed_object_map_.find(object_id); it != committed_object_map_.end())
    {
        return it->second;
    }

    return std::nullopt;
}

std::size_t MetadataStore::CommittedInodeCount() const noexcept
{
    return committed_inodes_.size();
}

std::size_t MetadataStore::DebugWorkingDirectoryChildCount(std::uint64_t parent_object_id) const
{
    const auto count = working_child_count_by_parent_.find(parent_object_id);
    return count == working_child_count_by_parent_.end() ? 0 : count->second;
}

std::size_t MetadataStore::DebugWorkingDirectoryDescendantCount(std::uint64_t parent_object_id) const
{
    return SnapshotWorkingDirectoryDescendantObjectIds(parent_object_id).size();
}

std::uint64_t MetadataStore::DebugWorkingDirectoryChildLinearScanCount() const noexcept
{
    return working_directory_child_linear_scan_count_.load(std::memory_order_relaxed);
}

std::size_t MetadataStore::DebugWorkingInodeCount() const noexcept
{
    return working_inodes_.size();
}

std::optional<MetadataStore::InodeRecord> MetadataStore::DebugLookupWorkingInodeByPath(const std::wstring& path) const
{
    return LookupWorkingInode(NormalizePath(path));
}

CheckpointDelta MetadataStore::DebugBuildPendingCheckpointDelta() const
{
    CheckpointDelta delta;
    delta.volume_identity =
        NarrowForCheckpointIdentity(context_.device_path) + ":" +
        NarrowForCheckpointIdentity(context_.volume_name);
    delta.base_xid = checkpoint_xid_;
    delta.target_xid = checkpoint_xid_ == std::numeric_limits<std::uint64_t>::max()
        ? checkpoint_xid_
        : checkpoint_xid_ + 1;

    delta.object_map_updates.reserve(pending_object_map_updates_.size());
    for (const auto& update : pending_object_map_updates_)
    {
        delta.object_map_updates.push_back(CheckpointDeltaObjectMapUpdate
        {
            update.object_id,
            update.physical_address,
            update.logical_size,
            delta.target_xid,
            !HasPhysicalObjectMapping(update),
        });
    }

    delta.spaceman_allocations.reserve(pending_spaceman_allocations_.size());
    for (const auto& allocation : pending_spaceman_allocations_)
    {
        delta.spaceman_allocations.push_back(allocation);
    }

    delta.spaceman_deallocations.reserve(pending_spaceman_deallocations_.size());
    for (const auto& deallocation : pending_spaceman_deallocations_)
    {
        delta.spaceman_deallocations.push_back(deallocation);
    }

    std::vector<std::uint64_t> touched_inode_ids;
    touched_inode_ids.reserve(pending_object_map_updates_.size() + pending_btree_records_.size());
    for (const auto& update : pending_object_map_updates_)
    {
        if (update.object_id != 0)
        {
            touched_inode_ids.push_back(update.object_id);
        }
    }
    for (const auto& record : pending_btree_records_)
    {
        DecodedBtreeInode inode{};
        if (DecodeBtreeInodeRecord(record, inode))
        {
            touched_inode_ids.push_back(inode.object_id);
        }
        DecodedBtreeDirectoryEntry link{};
        if (DecodeBtreeDirectoryRecord(record, link))
        {
            touched_inode_ids.push_back(link.child_object_id);
        }
    }
    std::sort(touched_inode_ids.begin(), touched_inode_ids.end());
    touched_inode_ids.erase(std::unique(touched_inode_ids.begin(), touched_inode_ids.end()), touched_inode_ids.end());

    delta.inode_updates.reserve(touched_inode_ids.size());
    for (const auto object_id : touched_inode_ids)
    {
        const auto working_inode = working_inodes_.find(object_id);
        if (working_inode == working_inodes_.end())
        {
            delta.inode_updates.push_back(CheckpointDeltaInodeUpdate
            {
                object_id,
                0,
                {},
                {},
                false,
                0,
                0,
                delta.target_xid,
                0,
                true,
            });
            continue;
        }

        const auto& inode = working_inode->second;
        delta.inode_updates.push_back(CheckpointDeltaInodeUpdate
        {
            inode.object_id,
            inode.parent_object_id,
            inode.name,
            inode.full_path,
            inode.is_directory,
            inode.logical_size,
            inode.data_physical_address,
            delta.target_xid,
            inode.timestamp_utc,
            false,
        });
    }

    for (const auto& record : pending_btree_records_)
    {
        DecodedBtreeDirectoryEntry decoded{};
        if (!DecodeBtreeDirectoryRecord(record, decoded))
        {
            continue;
        }

        delta.directory_link_updates.push_back(CheckpointDeltaDirectoryLinkUpdate
        {
            decoded.parent_object_id,
            decoded.entry_name,
            decoded.child_object_id,
            delta.target_xid,
            record.tombstone,
        });
    }

    delta.btree_records = pending_btree_records_;
    return delta;
}

void MetadataStore::ObserveCheckpointDeltaShadow(const CheckpointDelta& delta)
{
    const auto encoded = CheckpointDeltaCodec::Encode(delta);
    if (encoded.empty())
    {
        return;
    }

    const auto record_count =
        static_cast<std::uint64_t>(delta.object_map_updates.size()) +
        static_cast<std::uint64_t>(delta.spaceman_allocations.size()) +
        static_cast<std::uint64_t>(delta.spaceman_deallocations.size()) +
        static_cast<std::uint64_t>(delta.inode_updates.size()) +
        static_cast<std::uint64_t>(delta.directory_link_updates.size()) +
        static_cast<std::uint64_t>(delta.btree_records.size());

    checkpoint_delta_shadow_count_.fetch_add(1, std::memory_order_relaxed);
    checkpoint_delta_shadow_record_count_.store(record_count, std::memory_order_relaxed);
    checkpoint_delta_shadow_bytes_.store(static_cast<std::uint64_t>(encoded.size()), std::memory_order_relaxed);
    checkpoint_delta_shadow_full_bytes_.store(
        EstimateFullCheckpointFamilyBytes(delta.target_xid),
        std::memory_order_relaxed);
}

std::uint64_t MetadataStore::EstimateFullCheckpointFamilyBytes(std::uint64_t target_xid) const
{
    if (block_size_ == 0)
    {
        return 0;
    }

    const auto block_size = static_cast<std::size_t>(block_size_);
    const auto aligned_bytes_for = [&](std::uint64_t raw_bytes) -> std::uint64_t
    {
        if (raw_bytes == 0)
        {
            return 0;
        }
        if (raw_bytes > (std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(block_size - 1)))
        {
            return 0;
        }

        return ((raw_bytes + static_cast<std::uint64_t>(block_size - 1)) / static_cast<std::uint64_t>(block_size)) *
            static_cast<std::uint64_t>(block_size);
    };
    const auto bounded_add = [](std::uint64_t current, std::uint64_t value) -> std::uint64_t
    {
        if (value > (std::numeric_limits<std::uint64_t>::max() - current))
        {
            return std::numeric_limits<std::uint64_t>::max();
        }
        return current + value;
    };

    std::uint64_t total = 0;

    std::uint64_t object_map_entries = 0;
    for (const auto& [_, update] : committed_object_map_)
    {
        if (HasPhysicalObjectMapping(update))
        {
            ++object_map_entries;
        }
    }
    total = bounded_add(total, aligned_bytes_for(
        static_cast<std::uint64_t>(kCheckpointHeaderBytes) + (object_map_entries * 32ull)));

    const auto spaceman_entries =
        static_cast<std::uint64_t>(committed_spaceman_allocations_.size()) +
        static_cast<std::uint64_t>(committed_spaceman_free_extents_.size());
    total = bounded_add(total, aligned_bytes_for(
        static_cast<std::uint64_t>(kCheckpointHeaderBytes) + (spaceman_entries * 16ull)));

    std::uint64_t inode_bytes = static_cast<std::uint64_t>(kCheckpointHeaderBytes);
    constexpr std::uint64_t kInodeRecordFixedBytes = 60;
    for (const auto& [_, inode] : committed_inodes_)
    {
        std::uint64_t path_chars = 0;
        const auto persist_full_path = ShouldPersistCommittedInodeFullPath(inode);
        if (persist_full_path)
        {
            path_chars = static_cast<std::uint64_t>(inode.full_path.size());
        }

        const auto name_bytes = static_cast<std::uint64_t>(inode.name.size() * sizeof(wchar_t));
        const auto path_bytes = path_chars * static_cast<std::uint64_t>(sizeof(wchar_t));
        inode_bytes = bounded_add(inode_bytes, kInodeRecordFixedBytes);
        inode_bytes = bounded_add(inode_bytes, name_bytes);
        inode_bytes = bounded_add(inode_bytes, path_bytes);
    }
    total = bounded_add(total, aligned_bytes_for(inode_bytes));

    std::uint64_t btree_bytes = static_cast<std::uint64_t>(kCheckpointHeaderBytes);
    constexpr std::uint64_t kBtreeRecordHeaderBytes = 16;
    for (const auto& record : committed_btree_records_)
    {
        btree_bytes = bounded_add(btree_bytes, kBtreeRecordHeaderBytes);
        btree_bytes = bounded_add(btree_bytes, static_cast<std::uint64_t>(record.key.size()));
        btree_bytes = bounded_add(btree_bytes, static_cast<std::uint64_t>(record.value.size()));
    }
    total = bounded_add(total, aligned_bytes_for(btree_bytes));

    (void)target_xid;
    return total;
}

std::optional<MetadataStore::PayloadIdentity> MetadataStore::LookupWorkingPayloadIdentityByPath(const std::wstring& path) const
{
    return LookupWorkingPayloadIdentityByCanonicalPathKey(CanonicalPathKeyFromPath(path));
}

std::optional<MetadataStore::PayloadIdentity> MetadataStore::LookupWorkingPayloadIdentityByCanonicalPathKey(
    const std::wstring& canonical_path_key) const
{
    const auto* inode = LookupWorkingInodeByCanonicalPathKeyView(canonical_path_key);
    if (inode == nullptr || inode->is_directory)
    {
        return std::nullopt;
    }
    return PayloadIdentity{
        inode->object_id,
        inode->xid == 0 ? inode->object_id : inode->xid,
    };
}

std::size_t MetadataStore::DebugWorkingFreeExtentCount() const noexcept
{
    return working_spaceman_free_extents_.size();
}

std::uint64_t MetadataStore::DebugWorkingFreeExtentTotalBytes() const noexcept
{
    std::uint64_t total = 0;
    for (const auto& extent : working_spaceman_free_extents_)
    {
        if (extent.bytes > (std::numeric_limits<std::uint64_t>::max() - total))
        {
            return std::numeric_limits<std::uint64_t>::max();
        }
        total += extent.bytes;
    }
    return total;
}

const MetadataStore::InodeRecord* MetadataStore::LookupCommittedInodeByPathView(const std::wstring& path) const
{
    return LookupCommittedInodeByCanonicalPathKeyView(CanonicalPathKeyFromPath(path));
}

const MetadataStore::InodeRecord* MetadataStore::LookupCommittedInodeByCanonicalPathKeyView(
    const std::wstring& canonical_path_key) const
{
    auto it = committed_path_index_.find(canonical_path_key);
    if (it == committed_path_index_.end())
    {
        return nullptr;
    }

    auto inode = committed_inodes_.find(it->second);
    if (inode == committed_inodes_.end())
    {
        return nullptr;
    }

    return &inode->second;
}

std::optional<MetadataStore::InodeRecord> MetadataStore::LookupCommittedInodeByPath(const std::wstring& path) const
{
    const auto* inode = LookupCommittedInodeByPathView(path);
    return inode == nullptr
        ? std::nullopt
        : std::optional<InodeRecord>(*inode);
}

std::optional<MetadataStore::InodeRecord> MetadataStore::LookupCommittedInodeByObjectId(std::uint64_t object_id) const
{
    const auto inode = committed_inodes_.find(object_id);
    return inode == committed_inodes_.end()
        ? std::nullopt
        : std::optional<InodeRecord>(inode->second);
}

std::optional<std::vector<MetadataStore::InodeRecord>> MetadataStore::SnapshotCommittedDirectoryChildInodes(
    std::uint64_t parent_object_id) const
{
    if (parent_object_id == 0)
    {
        return std::nullopt;
    }

    const auto parent_it = committed_inodes_.find(parent_object_id);
    if (parent_it == committed_inodes_.end() || !parent_it->second.is_directory)
    {
        return std::nullopt;
    }

    const auto children_it = committed_child_object_ids_by_parent_.find(parent_object_id);
    if (children_it == committed_child_object_ids_by_parent_.end())
    {
        return std::vector<InodeRecord>{};
    }

    std::vector<InodeRecord> result;
    result.reserve(children_it->second.size());
    for (const auto child_object_id : children_it->second)
    {
        const auto child_it = committed_inodes_.find(child_object_id);
        if (child_it == committed_inodes_.end() ||
            child_it->second.parent_object_id != parent_object_id)
        {
            return std::nullopt;
        }
        result.push_back(child_it->second);
    }
    return result;
}

std::vector<MetadataStore::InodeRecord> MetadataStore::SnapshotCommittedInodes() const
{
    ScopedPerfTimer perf_scope(snapshot_committed_inodes_perf_);
    const auto* ordered_entries = OrderedCommittedInodeEntries();
    if (!ordered_entries)
    {
        return {};
    }

    std::vector<InodeRecord> result;
    result.reserve(ordered_entries->size());
    for (const auto& entry : *ordered_entries)
    {
        if (entry.inode == nullptr)
        {
            return {};
        }
        result.push_back(*entry.inode);
    }
    return result;
}

std::vector<MetadataStore::CommittedInodeChange> MetadataStore::SnapshotLastCommittedInodeChanges() const
{
    return last_committed_inode_changes_;
}

std::vector<MetadataStore::CommittedInodeChange> MetadataStore::TakeLastCommittedInodeChanges()
{
    ScopedPerfTimer perf_scope(take_last_committed_inode_changes_perf_);
    return std::exchange(last_committed_inode_changes_, {});
}

bool MetadataStore::SetCommittedReadExtents(std::uint64_t object_id, std::vector<FileExtent> extents)
{
    if (object_id == 0)
    {
        return false;
    }
    if (extents.empty())
    {
        committed_read_extents_[object_id] = {};
        working_read_extents_[object_id] = {};
        InvalidateCommittedReadExtentSnapshotCacheForObject(object_id);
        return true;
    }

    std::vector<FileExtent> normalized;
    std::vector<FileExtent> sorted_extents_storage;
    const auto* sorted_extents = SortedOrCopiedFileExtents(extents, sorted_extents_storage);
    normalized.reserve(sorted_extents->size());
    std::uint64_t previous_end = 0;
    bool has_previous = false;
    for (const auto& extent : *sorted_extents)
    {
        if (extent.bytes == 0)
        {
            return false;
        }
        if (extent.logical_offset > (std::numeric_limits<std::uint64_t>::max() - extent.bytes) ||
            extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
        {
            return false;
        }
        if (!normalized.empty())
        {
            const auto& previous = normalized.back();
            if (extent.logical_offset == previous.logical_offset &&
                extent.bytes == previous.bytes &&
                extent.physical_address == previous.physical_address)
            {
                continue;
            }
        }
        if (has_previous && extent.logical_offset < previous_end)
        {
            return false;
        }

        previous_end = extent.logical_offset + extent.bytes;
        has_previous = true;
        normalized.push_back(extent);
    }

    if (normalized.empty())
    {
        committed_read_extents_[object_id] = {};
        working_read_extents_[object_id] = {};
    }
    else
    {
        committed_read_extents_[object_id] = std::move(normalized);
        working_read_extents_[object_id] = committed_read_extents_[object_id];
    }
    InvalidateCommittedReadExtentSnapshotCacheForObject(object_id);
    return true;
}

bool MetadataStore::DebugMergeNativeProjectionReadExtents(std::uint64_t object_id, std::vector<FileExtent> extents)
{
    if (object_id == 0)
    {
        return false;
    }

    auto inode_it = committed_inodes_.find(object_id);
    if (inode_it != committed_inodes_.end() &&
        !inode_it->second.is_directory &&
        inode_it->second.logical_size > 0)
    {
        std::vector<DecodedBtreeExtent> decoded_btree_extents;
        for (const auto& record : committed_btree_records_)
        {
            if (record.tombstone || record.kind != BtreeRecordKind::FileExtent)
            {
                continue;
            }

            DecodedBtreeExtent decoded{};
            if (!DecodeBtreeExtentRecord(record, decoded))
            {
                continue;
            }
            if (decoded.object_id == object_id)
            {
                decoded_btree_extents.push_back(std::move(decoded));
            }
        }

        if (!decoded_btree_extents.empty())
        {
            auto canonical_extents = ExtentsFromDecodedBtreeExtents(decoded_btree_extents);
            if (HasLogicalExtentCoverage(canonical_extents, inode_it->second.logical_size) &&
                !canonical_extents.empty() &&
                canonical_extents.front().logical_offset == 0 &&
                canonical_extents.front().physical_address == inode_it->second.data_physical_address)
            {
                std::vector<FileExtent> candidate_storage;
                const auto* candidate = SortedOrCopiedFileExtents(extents, candidate_storage);
                if (HasLogicalExtentCoverage(*candidate, inode_it->second.logical_size) &&
                    !FileExtentsEqual(canonical_extents, *candidate))
                {
                    return true;
                }
            }
        }
    }

    return SetCommittedReadExtents(object_id, std::move(extents));
}

bool ExtentEndsBeforeOrAt(const MetadataStore::FileExtent& extent, std::uint64_t logical_offset)
{
    return extent.logical_offset + extent.bytes <= logical_offset;
}

bool MetadataStore::ReadCommittedFileRange(
    const std::wstring& path,
    std::uint64_t offset,
    std::size_t bytes_to_read,
    std::vector<std::byte>& out_payload) const
{
    out_payload.clear();
    if (bytes_to_read == 0)
    {
        std::size_t bytes_read = 0;
        return ReadCommittedFileRangeInto(path, offset, bytes_to_read, nullptr, 0, bytes_read);
    }

    out_payload.resize(bytes_to_read);
    std::size_t bytes_read = 0;
    if (!ReadCommittedFileRangeInto(
            path,
            offset,
            bytes_to_read,
            out_payload.data(),
            out_payload.size(),
            bytes_read))
    {
        out_payload.clear();
        return false;
    }

    out_payload.resize(bytes_read);
    return true;
}

bool MetadataStore::ReadCommittedFileRangeInto(
    const std::wstring& path,
    std::uint64_t offset,
    std::size_t bytes_to_read,
    std::byte* destination,
    std::size_t destination_size,
    std::size_t& out_bytes_read) const
{
    return ReadCommittedFileRangeIntoCanonicalPathKey(
        CanonicalPathKeyFromPath(path),
        path,
        offset,
        bytes_to_read,
        destination,
        destination_size,
        out_bytes_read);
}

std::optional<MetadataStore::CommittedFileReadPlan>
MetadataStore::SnapshotCommittedFileReadPlan(
    const std::wstring& canonical_path_key) const
{
    const auto* inode = LookupCommittedInodeByCanonicalPathKeyView(canonical_path_key);
    if (inode == nullptr || inode->is_directory)
    {
        return std::nullopt;
    }

    CommittedFileReadPlan plan{};
    plan.object_id = inode->object_id;
    plan.logical_size = inode->logical_size;
    plan.data_physical_address = inode->data_physical_address;
    if (auto extents_it = committed_read_extents_.find(inode->object_id);
        extents_it != committed_read_extents_.end())
    {
        const auto& extents = extents_it->second;
        if (extents.size() == 1 &&
            extents.front().logical_offset == 0 &&
            extents.front().bytes >= inode->logical_size)
        {
            plan.single_extent = extents.front();
            plan.has_single_extent = true;
        }
        else
        {
            auto cache_it = committed_read_extent_snapshot_cache_.find(inode->object_id);
            if (cache_it != committed_read_extent_snapshot_cache_.end() &&
                cache_it->second.extents != nullptr)
            {
                cache_it->second.last_use = ++committed_read_extent_snapshot_cache_use_;
                plan.extents_snapshot = cache_it->second.extents;
                committed_read_extent_snapshot_cache_hit_count_.fetch_add(
                    1,
                    std::memory_order_relaxed);
            }
            else
            {
                auto snapshot = std::make_shared<const std::vector<FileExtent>>(extents);
                plan.extents_snapshot = snapshot;
                committed_read_extent_snapshot_cache_miss_count_.fetch_add(
                    1,
                    std::memory_order_relaxed);

                const auto snapshot_bytes = static_cast<std::uint64_t>(
                    extents.size() * sizeof(FileExtent));
                if (snapshot_bytes <= kCommittedReadExtentSnapshotCacheMaxBytes)
                {
                    while (!committed_read_extent_snapshot_cache_.empty() &&
                           (committed_read_extent_snapshot_cache_.size() >=
                                kCommittedReadExtentSnapshotCacheMaxEntries ||
                            committed_read_extent_snapshot_cache_bytes_ >
                                kCommittedReadExtentSnapshotCacheMaxBytes - snapshot_bytes))
                    {
                        const auto oldest = std::min_element(
                            committed_read_extent_snapshot_cache_.begin(),
                            committed_read_extent_snapshot_cache_.end(),
                            [](const auto& left, const auto& right)
                            {
                                return left.second.last_use < right.second.last_use;
                            });
                        if (oldest == committed_read_extent_snapshot_cache_.end())
                        {
                            break;
                        }
                        committed_read_extent_snapshot_cache_bytes_ -= static_cast<std::uint64_t>(
                            oldest->second.extents != nullptr
                                ? oldest->second.extents->size() * sizeof(FileExtent)
                                : 0);
                        committed_read_extent_snapshot_cache_.erase(oldest);
                    }

                    const auto cache_entry = committed_read_extent_snapshot_cache_.emplace(
                        inode->object_id,
                        CommittedReadExtentSnapshotCacheEntry{
                            snapshot,
                            ++committed_read_extent_snapshot_cache_use_});
                    if (cache_entry.second)
                    {
                        committed_read_extent_snapshot_cache_bytes_ += snapshot_bytes;
                    }
                    else
                    {
                        cache_entry.first->second.extents = snapshot;
                        cache_entry.first->second.last_use =
                            ++committed_read_extent_snapshot_cache_use_;
                    }
                }
            }
        }
    }
    return plan;
}

bool MetadataStore::ReadCommittedFileRangeIntoCanonicalPathKey(
    const std::wstring& canonical_path_key,
    const std::wstring& trace_path,
    std::uint64_t offset,
    std::size_t bytes_to_read,
    std::byte* destination,
    std::size_t destination_size,
    std::size_t& out_bytes_read) const
{
    const auto plan = SnapshotCommittedFileReadPlan(canonical_path_key);
    if (!plan.has_value())
    {
        out_bytes_read = 0;
        TraceReadFailure(trace_path, 0, offset, bytes_to_read, L"InodeMissingOrDirectory");
        return false;
    }
    return ReadCommittedFileRangeFromPlan(
        *plan,
        trace_path,
        offset,
        bytes_to_read,
        destination,
        destination_size,
        out_bytes_read);
}

bool MetadataStore::ReadCommittedFileRangeFromPlan(
    const CommittedFileReadPlan& plan,
    const std::wstring& path,
    std::uint64_t offset,
    std::size_t bytes_to_read,
    std::byte* destination,
    std::size_t destination_size,
    std::size_t& out_bytes_read) const
{
    ScopedPerfTimer perf_scope(read_committed_range_perf_);

    out_bytes_read = 0;
    if (bytes_to_read > destination_size || (bytes_to_read > 0 && destination == nullptr))
    {
        return false;
    }

    if (bytes_to_read == 0 || offset >= plan.logical_size)
    {
        return true;
    }

    const auto available_u64 = plan.logical_size - offset;
    const auto available_bytes = available_u64 > static_cast<std::uint64_t>(bytes_to_read)
        ? bytes_to_read
        : static_cast<std::size_t>(available_u64);

    out_bytes_read = available_bytes;

    if (plan.has_single_extent ||
        (plan.extents_snapshot != nullptr && !plan.extents_snapshot->empty()))
    {
        const auto request_begin = offset;
        const auto request_end = offset + static_cast<std::uint64_t>(available_bytes);

        // Most ordinary small files are represented by one extent covering
        // the whole logical file. Avoid entering the fragmented extent state
        // machine for that common read shape.
        if (plan.has_single_extent)
        {
            const auto& extent = plan.single_extent;
            if (extent.physical_address == 0)
            {
                std::fill_n(destination, available_bytes, std::byte{0});
                committed_single_extent_read_fast_path_count_.fetch_add(
                    1,
                    std::memory_order_relaxed);
                return true;
            }
            if (extent.physical_address >
                (std::numeric_limits<std::uint64_t>::max() - offset))
            {
                TraceReadFailure(
                    path,
                    plan.object_id,
                    offset,
                    available_bytes,
                    L"SingleExtentPhysicalOverflow");
                return false;
            }

            const auto physical_offset = extent.physical_address + offset;
            std::size_t bytes_read = 0;
            if (!device_.ReadInto(
                    physical_offset,
                    destination,
                    available_bytes,
                    bytes_read))
            {
                TraceReadFailure(
                    path,
                    plan.object_id,
                    physical_offset,
                    available_bytes,
                    L"SingleExtentDeviceReadFailed");
                return false;
            }
            if (bytes_read < available_bytes)
            {
                TraceReadFailure(
                    path,
                    plan.object_id,
                    physical_offset,
                    available_bytes,
                    L"SingleExtentDeviceShortRead");
                return false;
            }
            committed_single_extent_read_fast_path_count_.fetch_add(
                1,
                std::memory_order_relaxed);
            return true;
        }

        const auto& extents = *plan.extents_snapshot;

        auto extent_it = std::lower_bound(
            extents.begin(),
            extents.end(),
            request_begin,
            ExtentEndsBeforeOrAt);
        auto zero_fill_range = [&](std::uint64_t begin, std::uint64_t end) -> bool
        {
            if (begin >= end)
            {
                return begin == end;
            }
            if (begin < request_begin || end > request_end)
            {
                return false;
            }
            const auto destination_offset = static_cast<std::size_t>(begin - request_begin);
            const auto zero_bytes = static_cast<std::size_t>(end - begin);
            if (destination_offset > available_bytes ||
                zero_bytes > (available_bytes - destination_offset))
            {
                return false;
            }
            std::fill_n(destination + destination_offset, zero_bytes, std::byte{0});
            return true;
        };
        struct ReadRun
        {
            std::uint64_t physical_offset = 0;
            std::uint64_t logical_end = 0;
            std::size_t destination_offset = 0;
            std::size_t bytes = 0;
            bool active = false;
        } read_run;
        const auto flush_read_run = [&]() -> bool
        {
            if (!read_run.active)
            {
                return true;
            }

            std::size_t run_read = 0;
            if (!device_.ReadInto(
                    read_run.physical_offset,
                    destination + read_run.destination_offset,
                    read_run.bytes,
                    run_read) ||
                run_read > read_run.bytes)
            {
                TraceReadFailure(
                    path,
                    plan.object_id,
                    read_run.physical_offset,
                    read_run.bytes,
                    L"ExtentDeviceReadFailed");
                return false;
            }
            if (run_read < read_run.bytes)
            {
                TraceReadFailure(
                    path,
                    plan.object_id,
                    read_run.physical_offset,
                    read_run.bytes,
                    L"ExtentDeviceShortRead");
                return false;
            }

            read_run.active = false;
            return true;
        };
        std::uint64_t covered_until = request_begin;
        for (; extent_it != extents.end(); ++extent_it)
        {
            const auto& extent = *extent_it;
            const auto extent_begin = extent.logical_offset;
            if (extent.bytes > (std::numeric_limits<std::uint64_t>::max() - extent_begin))
            {
                TraceReadFailure(path, plan.object_id, offset, available_bytes, L"ExtentLogicalOverflow");
                return false;
            }
            const auto extent_end = extent.logical_offset + extent.bytes;
            if (extent_begin >= request_end)
            {
                break;
            }

            const auto chunk_begin = std::max(request_begin, extent_begin);
            const auto chunk_end = std::min(request_end, extent_end);
            if (chunk_end <= chunk_begin)
            {
                continue;
            }
            if (chunk_begin > covered_until &&
                (!flush_read_run() || !zero_fill_range(covered_until, chunk_begin)))
            {
                return false;
            }
            const auto chunk_bytes = static_cast<std::size_t>(chunk_end - chunk_begin);
            if (extent.physical_address == 0)
            {
                if (!flush_read_run())
                {
                    return false;
                }
                const auto zero_begin = (std::max)(chunk_begin, covered_until);
                if (!zero_fill_range(zero_begin, chunk_end))
                {
                    return false;
                }
                covered_until = (std::max)(covered_until, chunk_end);
                continue;
            }
            if (extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - (chunk_begin - extent_begin)))
            {
                TraceReadFailure(path, plan.object_id, offset, available_bytes, L"ExtentPhysicalOverflow");
                return false;
            }
            const auto physical_offset = extent.physical_address + (chunk_begin - extent_begin);
            if (physical_offset > (std::numeric_limits<std::uint64_t>::max() - chunk_bytes))
            {
                TraceReadFailure(path, plan.object_id, physical_offset, chunk_bytes, L"ExtentPhysicalOverflow");
                return false;
            }

            const auto destination_offset = static_cast<std::size_t>(chunk_begin - request_begin);
            if (destination_offset > available_bytes ||
                chunk_bytes > (available_bytes - destination_offset))
            {
                return false;
            }

            const auto can_extend_read_run =
                read_run.active &&
                chunk_begin == read_run.logical_end &&
                read_run.physical_offset <= (std::numeric_limits<std::uint64_t>::max() - read_run.bytes) &&
                physical_offset == read_run.physical_offset + read_run.bytes &&
                read_run.destination_offset <= available_bytes &&
                read_run.bytes <= (available_bytes - read_run.destination_offset) &&
                chunk_bytes <= (available_bytes - read_run.destination_offset - read_run.bytes);
            if (can_extend_read_run)
            {
                read_run.bytes += chunk_bytes;
                read_run.logical_end = chunk_end;
            }
            else
            {
                if (!flush_read_run())
                {
                    return false;
                }
                read_run.physical_offset = physical_offset;
                read_run.logical_end = chunk_end;
                read_run.destination_offset = destination_offset;
                read_run.bytes = chunk_bytes;
                read_run.active = true;
            }
            covered_until = (std::max)(covered_until, chunk_end);
        }
        if (!flush_read_run())
        {
            return false;
        }
        if (covered_until < request_end &&
            !zero_fill_range(covered_until, request_end))
        {
            return false;
        }
        return true;
    }

    if (plan.data_physical_address == 0 || plan.logical_size == 0)
    {
        TraceReadFailure(path, plan.object_id, offset, available_bytes, L"NoDataExtent");
        return false;
    }

    if (plan.data_physical_address > (std::numeric_limits<std::uint64_t>::max() - offset))
    {
        TraceReadFailure(path, plan.object_id, offset, available_bytes, L"SingleExtentPhysicalOverflow");
        return false;
    }
    const auto physical_offset = plan.data_physical_address + offset;

    std::size_t bytes_read = 0;
    if (!device_.ReadInto(physical_offset, destination, available_bytes, bytes_read))
    {
        TraceReadFailure(path, plan.object_id, physical_offset, available_bytes, L"SingleExtentDeviceReadFailed");
        return false;
    }

    if (bytes_read < available_bytes)
    {
        TraceReadFailure(path, plan.object_id, physical_offset, available_bytes, L"SingleExtentDeviceShortRead");
        return false;
    }

    return true;
}

bool MetadataStore::WritePreparedFileRange(
    const std::wstring& path,
    std::uint64_t offset,
    std::span<const std::byte> payload)
{
    if (payload.empty())
    {
        return true;
    }
    if (!IsNativeWriteReady() || !commit_path_ready_ || !write_device_allowed_)
    {
        return false;
    }
    if (payload.size() > static_cast<std::size_t>(std::numeric_limits<std::uint64_t>::max() - offset))
    {
        return false;
    }

    const auto normalized_path = NormalizePath(path);
    const auto path_key = CanonicalPathKeyFromNormalizedPath(normalized_path);
    auto inode = LookupWorkingInodeByCanonicalPathKey(path_key);
    if (!inode.has_value() ||
        inode->is_directory ||
        inode->logical_size == 0 ||
        offset > inode->logical_size ||
        static_cast<std::uint64_t>(payload.size()) > (inode->logical_size - offset))
    {
        return false;
    }

    std::vector<FileExtent> selected_extents;
    const std::vector<FileExtent>* extents = nullptr;
    if (auto pending_extents_it = pending_read_extent_updates_.find(inode->object_id);
        pending_extents_it != pending_read_extent_updates_.end())
    {
        extents = &pending_extents_it->second;
    }
    else if (auto working_extents_it = working_read_extents_.find(inode->object_id);
             working_extents_it != working_read_extents_.end())
    {
        extents = &working_extents_it->second;
    }
    else if (auto committed_extents_it = committed_read_extents_.find(inode->object_id);
             committed_extents_it != committed_read_extents_.end())
    {
        extents = &committed_extents_it->second;
    }
    else if (inode->data_physical_address != 0)
    {
        selected_extents.push_back(FileExtent{ 0, inode->data_physical_address, inode->logical_size });
        extents = &selected_extents;
    }

    if (extents == nullptr)
    {
        return false;
    }

    return WritePreparedFileRangeFromExtents(inode->object_id, *extents, offset, payload);
}

bool MetadataStore::WritePreparedFileRangeFromExtents(
    std::uint64_t object_id,
    const std::vector<FileExtent>& extents,
    std::uint64_t offset,
    std::span<const std::byte> payload)
{
    if (payload.empty())
    {
        return true;
    }

    const auto request_begin = offset;
    if (payload.size() > static_cast<std::size_t>(
            (std::numeric_limits<std::uint64_t>::max)() - request_begin))
    {
        return false;
    }
    const auto request_end = offset + static_cast<std::uint64_t>(payload.size());
    auto extent_it = std::lower_bound(
        extents.begin(),
        extents.end(),
        request_begin,
        ExtentEndsBeforeOrAt);

    // Most Explorer writes stay within the file's single physical extent.
    // Avoid building the general fragmented-write vectors for that case.
    if (extent_it != extents.end())
    {
        const auto& extent = *extent_it;
        if (extent.bytes != 0 &&
            extent.logical_offset <= request_begin &&
            extent.logical_offset <= (std::numeric_limits<std::uint64_t>::max() - extent.bytes) &&
            request_end <= (extent.logical_offset + extent.bytes) &&
            extent.physical_address != 0 &&
            extent.physical_address <= (std::numeric_limits<std::uint64_t>::max() -
                                        (request_begin - extent.logical_offset)))
        {
            const auto physical_offset = extent.physical_address + (request_begin - extent.logical_offset);
            if (device_.Write(physical_offset, payload))
            {
                prepared_payload_single_extent_direct_write_count_.fetch_add(1, std::memory_order_relaxed);
                RememberPreparedPayloadRange(object_id, offset, static_cast<std::uint64_t>(payload.size()));
                return true;
            }
            return false;
        }
    }

    auto cursor = request_begin;
    constexpr std::size_t kInlineWriteSpanCount = 8;
    std::array<BlockDevice::WriteSpan, kInlineWriteSpanCount> inline_block_writes{};
    std::vector<BlockDevice::WriteSpan> block_writes;
    std::size_t block_write_count = 0;
    bool block_writes_use_heap = false;
    const auto remaining_extent_count = static_cast<std::size_t>(extents.end() - extent_it);
    const auto append_block_write = [&](BlockDevice::WriteSpan write)
    {
        if (!block_writes_use_heap && block_write_count < inline_block_writes.size())
        {
            inline_block_writes[block_write_count++] = write;
            return;
        }

        if (!block_writes_use_heap)
        {
            block_writes.reserve(std::min<std::size_t>(remaining_extent_count, 16));
            block_writes.insert(
                block_writes.end(),
                inline_block_writes.begin(),
                inline_block_writes.begin() + static_cast<std::ptrdiff_t>(block_write_count));
            block_writes_use_heap = true;
        }
        block_writes.push_back(write);
        ++block_write_count;
    };
    for (; extent_it != extents.end() && cursor < request_end; ++extent_it)
    {
        const auto& extent = *extent_it;
        if (extent.bytes == 0)
        {
            continue;
        }
        if (extent.logical_offset > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
        {
            return false;
        }

        const auto extent_begin = extent.logical_offset;
        const auto extent_end = extent.logical_offset + extent.bytes;
        if (extent_begin > cursor)
        {
            return false;
        }
        if (extent_end <= cursor)
        {
            continue;
        }
        if (extent.physical_address == 0)
        {
            return false;
        }

        const auto chunk_begin = std::max(cursor, extent_begin);
        const auto chunk_end = std::min(request_end, extent_end);
        if (chunk_end <= chunk_begin)
        {
            continue;
        }
        if (extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - (chunk_begin - extent_begin)))
        {
            return false;
        }

        const auto source_offset = static_cast<std::size_t>(chunk_begin - request_begin);
        const auto chunk_bytes = static_cast<std::size_t>(chunk_end - chunk_begin);
        if (source_offset > payload.size() ||
            chunk_bytes > (payload.size() - source_offset))
        {
            return false;
        }

        const auto physical_offset = extent.physical_address + (chunk_begin - extent_begin);
        if (physical_offset > (std::numeric_limits<std::uint64_t>::max() - chunk_bytes))
        {
            return false;
        }

        append_block_write(BlockDevice::WriteSpan{
            physical_offset,
            payload.subspan(source_offset, chunk_bytes),
            payload.data(),
        });

        cursor = chunk_end;
    }

    if (cursor != request_end)
    {
        return false;
    }

    if (block_write_count == 1)
    {
        const auto& write = block_writes_use_heap
            ? block_writes.front()
            : inline_block_writes.front();
        if (!device_.Write(write.offset_bytes, write.buffer))
        {
            return false;
        }
    }
    else if (block_write_count != 0)
    {
        // BlockDevice::WriteBatch owns the same ordering and overlap decision:
        // it reorders only disjoint spans and retains logical order for aliases.
        // Avoid rebuilding a second physical-range vector here.
        const auto write_span = block_writes_use_heap
            ? std::span<const BlockDevice::WriteSpan>(block_writes.data(), block_writes.size())
            : std::span<const BlockDevice::WriteSpan>(inline_block_writes.data(), block_write_count);
        if (!device_.WriteBatch(write_span))
        {
            return false;
        }
    }

    RememberPreparedPayloadRange(object_id, offset, static_cast<std::uint64_t>(payload.size()));
    return true;
}

MetadataStore::PayloadRangeByteDelta MetadataStore::RememberPayloadRange(
    std::unordered_map<std::uint64_t, std::vector<PreparedPayloadRange>>& ranges_by_object,
    std::uint64_t object_id,
    std::uint64_t offset,
    std::uint64_t bytes)
{
    if (object_id == 0 || bytes == 0)
    {
        return {};
    }
    if (offset > (std::numeric_limits<std::uint64_t>::max() - bytes))
    {
        return {};
    }

    auto& ranges = ranges_by_object[object_id];
    const auto range_end = offset + bytes;
    const auto full_merge = [&]() -> PayloadRangeByteDelta
    {
        const auto previous_bytes = SumPayloadRangeBytes(ranges);
        pending_payload_range_full_merge_count_.fetch_add(1, std::memory_order_relaxed);
        ranges.push_back(PreparedPayloadRange{ offset, bytes });
        std::sort(
            ranges.begin(),
            ranges.end(),
            [](const PreparedPayloadRange& lhs, const PreparedPayloadRange& rhs)
            {
                if (lhs.offset == rhs.offset)
                {
                    return lhs.bytes < rhs.bytes;
                }
                return lhs.offset < rhs.offset;
            });

        std::size_t merged_count = 0;
        for (std::size_t read_index = 0; read_index < ranges.size(); ++read_index)
        {
            const auto range = ranges[read_index];
            if (range.bytes == 0 ||
                range.offset > (std::numeric_limits<std::uint64_t>::max() - range.bytes))
            {
                continue;
            }
            if (merged_count == 0)
            {
                ranges[merged_count++] = range;
                continue;
            }

            auto& previous = ranges[merged_count - 1];
            const auto previous_end = previous.offset + previous.bytes;
            const auto candidate_end = range.offset + range.bytes;
            if (range.offset <= previous_end)
            {
                if (candidate_end > previous_end)
                {
                    previous.bytes = candidate_end - previous.offset;
                }
                continue;
            }

            ranges[merged_count++] = range;
        }

        ranges.resize(merged_count);
        const auto updated_bytes = SumPayloadRangeBytes(ranges);
        if (updated_bytes >= previous_bytes)
        {
            return PayloadRangeByteDelta{ updated_bytes - previous_bytes, 0 };
        }
        return PayloadRangeByteDelta{ 0, previous_bytes - updated_bytes };
    };
    if (ranges.empty())
    {
        ranges.push_back(PreparedPayloadRange{ offset, bytes });
        pending_payload_range_local_merge_count_.fetch_add(1, std::memory_order_relaxed);
        return PayloadRangeByteDelta{ bytes, 0 };
    }

    auto& last = ranges.back();
    if (last.bytes != 0 &&
        last.offset <= offset &&
        last.offset <= (std::numeric_limits<std::uint64_t>::max() - last.bytes))
    {
        const auto last_end = last.offset + last.bytes;
        if (offset > last_end)
        {
            ranges.push_back(PreparedPayloadRange{ offset, bytes });
            pending_payload_range_local_merge_count_.fetch_add(1, std::memory_order_relaxed);
            return PayloadRangeByteDelta{ bytes, 0 };
        }
        const auto added_bytes = range_end > last_end ? range_end - last_end : 0;
        if (range_end > last_end)
        {
            last.bytes = range_end - last.offset;
        }
        pending_payload_range_local_merge_count_.fetch_add(1, std::memory_order_relaxed);
        return PayloadRangeByteDelta{ added_bytes, 0 };
    }

    bool sorted_and_valid = true;
    std::uint64_t previous_offset = 0;
    std::uint64_t previous_end = 0;
    bool have_previous = false;
    for (const auto& range : ranges)
    {
        if (range.bytes == 0 ||
            range.offset > (std::numeric_limits<std::uint64_t>::max() - range.bytes) ||
            (have_previous && (range.offset < previous_offset || range.offset <= previous_end)))
        {
            sorted_and_valid = false;
            break;
        }

        previous_offset = range.offset;
        previous_end = range.offset + range.bytes;
        have_previous = true;
    }
    if (!sorted_and_valid)
    {
        return full_merge();
    }

    auto insert_it = std::lower_bound(
        ranges.begin(),
        ranges.end(),
        offset,
        [](const PreparedPayloadRange& candidate, std::uint64_t candidate_offset)
        {
            return candidate.offset < candidate_offset;
        });
    auto merge_offset = offset;
    auto merge_end = range_end;
    if (insert_it != ranges.begin())
    {
        auto previous = insert_it;
        --previous;
        if (previous->bytes != 0 &&
            previous->offset <= (std::numeric_limits<std::uint64_t>::max() - previous->bytes))
        {
            const auto previous_range_end = previous->offset + previous->bytes;
            if (previous_range_end >= offset)
            {
                merge_offset = previous->offset;
                merge_end = std::max(merge_end, previous_range_end);
                insert_it = previous;
            }
        }
    }

    auto erase_end = insert_it;
    while (erase_end != ranges.end())
    {
        if (erase_end->bytes == 0 ||
            erase_end->offset > (std::numeric_limits<std::uint64_t>::max() - erase_end->bytes))
        {
            break;
        }

        const auto candidate_end = erase_end->offset + erase_end->bytes;
        if (erase_end->offset > merge_end)
        {
            break;
        }

        merge_end = std::max(merge_end, candidate_end);
        ++erase_end;
    }

    std::uint64_t removed_bytes = 0;
    for (auto current = insert_it; current != erase_end; ++current)
    {
        if (current->bytes > (std::numeric_limits<std::uint64_t>::max() - removed_bytes))
        {
            removed_bytes = std::numeric_limits<std::uint64_t>::max();
            break;
        }
        removed_bytes += current->bytes;
    }

    const auto replacement = PreparedPayloadRange{ merge_offset, merge_end - merge_offset };
    if (insert_it == erase_end)
    {
        ranges.insert(insert_it, replacement);
    }
    else
    {
        *insert_it = replacement;
        ranges.erase(std::next(insert_it), erase_end);
    }
    pending_payload_range_local_merge_count_.fetch_add(1, std::memory_order_relaxed);
    if (replacement.bytes >= removed_bytes)
    {
        return PayloadRangeByteDelta{ replacement.bytes - removed_bytes, 0 };
    }
    return PayloadRangeByteDelta{ 0, removed_bytes - replacement.bytes };
}

void MetadataStore::RememberPreparedPayloadRange(
    std::uint64_t object_id,
    std::uint64_t offset,
    std::uint64_t bytes)
{
    (void)RememberPayloadRange(prepared_payload_ranges_, object_id, offset, bytes);
}

void MetadataStore::RememberPendingWrittenRange(
    std::uint64_t object_id,
    std::uint64_t offset,
    std::uint64_t bytes)
{
    const auto delta = RememberPayloadRange(pending_written_ranges_, object_id, offset, bytes);
    if (delta.added_bytes > (std::numeric_limits<std::uint64_t>::max() - pending_payload_dirty_bytes_))
    {
        pending_payload_dirty_bytes_ = std::numeric_limits<std::uint64_t>::max();
    }
    else
    {
        pending_payload_dirty_bytes_ += delta.added_bytes;
    }
    pending_payload_dirty_bytes_ = pending_payload_dirty_bytes_ >= delta.removed_bytes
        ? pending_payload_dirty_bytes_ - delta.removed_bytes
        : 0;
}

std::uint64_t MetadataStore::SumPayloadRangeBytes(
    const std::vector<PreparedPayloadRange>& ranges) noexcept
{
    std::uint64_t total = 0;
    for (const auto& range : ranges)
    {
        if (range.bytes > (std::numeric_limits<std::uint64_t>::max() - total))
        {
            return std::numeric_limits<std::uint64_t>::max();
        }
        total += range.bytes;
    }
    return total;
}

void MetadataStore::ReplacePendingWrittenRanges(
    std::uint64_t object_id,
    std::optional<std::vector<PreparedPayloadRange>> ranges)
{
    const auto existing = pending_written_ranges_.find(object_id);
    const auto previous_bytes = existing == pending_written_ranges_.end()
        ? 0
        : SumPayloadRangeBytes(existing->second);
    if (ranges.has_value() && !ranges->empty())
    {
        pending_written_ranges_[object_id] = std::move(ranges.value());
    }
    else
    {
        pending_written_ranges_.erase(object_id);
    }

    const auto updated = pending_written_ranges_.find(object_id);
    const auto updated_bytes = updated == pending_written_ranges_.end()
        ? 0
        : SumPayloadRangeBytes(updated->second);
    if (updated_bytes >= previous_bytes)
    {
        const auto delta = updated_bytes - previous_bytes;
        if (delta > (std::numeric_limits<std::uint64_t>::max() - pending_payload_dirty_bytes_))
        {
            pending_payload_dirty_bytes_ = std::numeric_limits<std::uint64_t>::max();
        }
        else
        {
            pending_payload_dirty_bytes_ += delta;
        }
    }
    else
    {
        const auto delta = previous_bytes - updated_bytes;
        pending_payload_dirty_bytes_ = pending_payload_dirty_bytes_ >= delta
            ? pending_payload_dirty_bytes_ - delta
            : 0;
    }
}

void MetadataStore::ClearPendingWrittenRanges(std::uint64_t object_id)
{
    ReplacePendingWrittenRanges(object_id, std::nullopt);
}

void MetadataStore::ClearPreparedPayloadRanges(std::uint64_t object_id)
{
    prepared_payload_ranges_.erase(object_id);
}

void MetadataStore::SetCommitStageHook(
    std::function<bool(std::string_view stage)> hook,
    bool require_strict_verification)
{
    commit_stage_hook_ = std::move(hook);
    commit_stage_hook_requires_strict_verification_ =
        commit_stage_hook_ && require_strict_verification;
}

void MetadataStore::SetFilePayloadProvider(
    std::function<std::optional<std::vector<std::byte>>(const std::wstring& path, std::uint64_t logical_size)> provider)
{
    file_payload_provider_ = std::move(provider);
}

void MetadataStore::SetFilePayloadRangeProvider(
    std::function<bool(
        const std::wstring& path,
        PayloadIdentity identity,
        std::uint64_t offset,
        std::span<std::byte> destination)> provider)
{
    file_payload_range_provider_ = std::move(provider);
}

std::optional<std::uint64_t> MetadataStore::AllocateExtent(std::uint64_t bytes)
{
    if (!SanitizeWorkingFreeExtents())
    {
        return std::nullopt;
    }
    return AllocateExtentFromSanitizedWorkingFreeExtents(bytes);
}

std::optional<std::uint64_t> MetadataStore::AllocateExtentFromSanitizedWorkingFreeExtents(std::uint64_t bytes)
{
    return AllocateExtentFromSanitizedWorkingFreeExtents(bytes, nullptr);
}

std::optional<std::uint64_t> MetadataStore::AllocateExtentFromSanitizedWorkingFreeExtents(
    std::uint64_t bytes,
    ExtentAllocator::ContiguousAllocationUndo* undo)
{
    ScopedPerfTimer perf_scope(allocation_lookup_perf_);

    if (!container_loaded_ || !spaceman_loaded_)
    {
        return std::nullopt;
    }

    std::optional<std::uint64_t> container_bytes;
    if (total_blocks_ != 0)
    {
        if (block_size_ == 0 ||
            total_blocks_ > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
        {
            return std::nullopt;
        }
        container_bytes = total_blocks_ * static_cast<std::uint64_t>(block_size_);
    }

    const auto aligned_bytes = AlignExtentBytes(bytes);
    if (aligned_bytes == 0)
    {
        return std::nullopt;
    }

    ExtentAllocator::AllocationPolicy policy
    {
        container_bytes,
        this,
        [](const void* context, std::uint64_t physical_address, std::uint64_t required_bytes)
        {
            const auto* store = static_cast<const MetadataStore*>(context);
            return store->ExtentOverlapsReservedMetadata(physical_address, required_bytes) ||
                   store->ExtentOverlapsLiveAllocation(physical_address, required_bytes);
        },
        [](const void* context, std::uint64_t physical_address, std::uint64_t required_bytes)
            -> std::optional<std::uint64_t>
        {
            return static_cast<const MetadataStore*>(context)->AdvancePastUnavailableExtent(
                physical_address,
                required_bytes);
        },
    };

    ScopedPerfTimer free_list_perf_scope(free_list_lookup_perf_);
    return ExtentAllocator::AllocateContiguous(
        working_spaceman_free_extents_,
        working_next_ephemeral_extent_,
        aligned_bytes,
        policy,
        undo);
}

std::optional<std::vector<MetadataStore::FileExtent>> MetadataStore::AllocateFileExtents(std::uint64_t logical_size)
{
    ScopedPerfTimer perf_scope(allocation_lookup_perf_);

    if (!container_loaded_ || !spaceman_loaded_)
    {
        return std::nullopt;
    }
    if (logical_size == 0)
    {
        return std::vector<FileExtent>{};
    }

    const auto aligned_total = AlignExtentBytes(logical_size);
    if (aligned_total == 0)
    {
        return std::nullopt;
    }
    if (!SanitizeWorkingFreeExtents())
    {
        return std::nullopt;
    }

    std::optional<std::uint64_t> container_bytes;
    if (total_blocks_ != 0)
    {
        if (block_size_ == 0 ||
            total_blocks_ > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
        {
            return std::nullopt;
        }
        container_bytes = total_blocks_ * static_cast<std::uint64_t>(block_size_);
    }

    ExtentAllocator::AllocationPolicy policy
    {
        container_bytes,
        this,
        [](const void* context, std::uint64_t physical_address, std::uint64_t bytes)
        {
            const auto* store = static_cast<const MetadataStore*>(context);
            return store->ExtentOverlapsReservedMetadata(physical_address, bytes) ||
                   store->ExtentOverlapsLiveAllocation(physical_address, bytes);
        },
        [](const void* context, std::uint64_t physical_address, std::uint64_t bytes)
            -> std::optional<std::uint64_t>
        {
            return static_cast<const MetadataStore*>(context)->AdvancePastUnavailableExtent(
                physical_address,
                bytes);
        },
    };

    ScopedPerfTimer free_list_perf_scope(free_list_lookup_perf_);
    auto allocator_extents = ExtentAllocator::AllocateFileExtents(
        working_spaceman_free_extents_,
        working_next_ephemeral_extent_,
        logical_size,
        aligned_total,
        static_cast<std::uint64_t>(std::max<std::uint32_t>(1u, block_size_)),
        policy);
    if (!allocator_extents.has_value())
    {
        return std::nullopt;
    }

    std::vector<FileExtent> file_extents;
    file_extents.reserve(allocator_extents->size());
    for (const auto& extent : allocator_extents.value())
    {
        file_extents.push_back(FileExtent
        {
            extent.logical_offset,
            extent.physical_address,
            extent.bytes,
        });
    }

    if (!HasLogicalExtentCoverage(file_extents, logical_size))
    {
        return std::nullopt;
    }
    return file_extents;
}

std::uint64_t MetadataStore::StreamingGrowthReservationBytes(
    std::uint64_t current_aligned_bytes,
    std::uint64_t required_aligned_bytes) const noexcept
{
    constexpr std::uint64_t kMinimumStreamingReservation = 64ull * 1024ull;
    constexpr std::uint64_t kMaximumStreamingReservation = 8ull * 1024ull * 1024ull;

    if (required_aligned_bytes == 0)
    {
        return 0;
    }

    const auto block = static_cast<std::uint64_t>(std::max<std::uint32_t>(1u, block_size_));
    auto reservation = std::max(required_aligned_bytes, block);
    if (current_aligned_bytes >= block &&
        current_aligned_bytes <= (std::numeric_limits<std::uint64_t>::max() / 2ull))
    {
        reservation = std::max(reservation, current_aligned_bytes * 2ull);
    }

    reservation = std::max<std::uint64_t>(
        reservation,
        AlignExtentBytes(kMinimumStreamingReservation));
    reservation = std::min<std::uint64_t>(
        reservation,
        AlignExtentBytes(kMaximumStreamingReservation));
    if (reservation < required_aligned_bytes)
    {
        reservation = required_aligned_bytes;
    }

    return AlignExtentBytes(reservation);
}

bool MetadataStore::FreeExtent(std::uint64_t physical_address, std::uint64_t bytes)
{
    return FreeExtent(physical_address, bytes, nullptr);
}

bool MetadataStore::FreeExtent(
    std::uint64_t physical_address,
    std::uint64_t bytes,
    ExtentAllocator::AddFreeExtentUndo* undo)
{
    if (!container_loaded_ || !spaceman_loaded_ || physical_address == 0 || bytes == 0)
    {
        return false;
    }

    const auto aligned_bytes = AlignExtentBytes(bytes);
    if (aligned_bytes == 0)
    {
        return false;
    }
    if (physical_address > (std::numeric_limits<std::uint64_t>::max() - aligned_bytes))
    {
        return false;
    }

    if (total_blocks_ != 0)
    {
        if (block_size_ == 0 ||
            total_blocks_ > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
        {
            return false;
        }

        const auto container_bytes = total_blocks_ * static_cast<std::uint64_t>(block_size_);
        if ((physical_address + aligned_bytes) > container_bytes)
        {
            return false;
        }
    }
    if (ExtentOverlapsReservedMetadata(physical_address, aligned_bytes))
    {
        return false;
    }

    if (!ExtentAllocator::AddFreeExtent(
            working_spaceman_free_extents_,
            SpacemanAllocation{ physical_address, aligned_bytes },
            undo))
    {
        return false;
    }
    if (!tracking_spaceman_free_extent_delta_)
    {
        pending_spaceman_untracked_free_extent_delta_ = true;
    }

    if (!ExtentOverlapsEffectiveLiveAllocation(physical_address, aligned_bytes))
    {
        free_extent_sanitize_skip_count_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    working_free_extents_sanitized_ = false;
    free_extent_sanitize_count_.fetch_add(1, std::memory_order_relaxed);
    return SanitizeWorkingFreeExtents();
}

std::uint64_t MetadataStore::StableObjectIdFromPath(const std::wstring& path)
{
    constexpr std::uint64_t kFnvOffset = 1469598103934665603ull;
    constexpr std::uint64_t kFnvPrime = 1099511628211ull;

    std::uint64_t hash = kFnvOffset;
    for (const auto ch : path)
    {
        const auto lower = static_cast<std::uint16_t>(std::towlower(ch));
        const auto lo = static_cast<std::uint8_t>(lower & 0xffu);
        const auto hi = static_cast<std::uint8_t>((lower >> 8) & 0xffu);
        hash ^= lo;
        hash *= kFnvPrime;
        hash ^= hi;
        hash *= kFnvPrime;
    }

    return hash == 0 ? 1 : hash;
}

std::wstring MetadataStore::NormalizePath(const std::wstring& path)
{
    if (path.empty())
    {
        return {};
    }

    std::wstring normalized;
    normalized.reserve(path.size() + 1);

    if (path.front() != L'\\' && path.front() != L'/')
    {
        normalized.push_back(L'\\');
    }

    bool previous_separator = false;
    for (const auto ch : path)
    {
        const auto mapped = (ch == L'/') ? L'\\' : ch;
        if (mapped == L'\\')
        {
            if (previous_separator)
            {
                continue;
            }
            previous_separator = true;
            normalized.push_back(mapped);
            continue;
        }

        previous_separator = false;
        normalized.push_back(mapped);
    }

    while (normalized.size() > 1 && normalized.back() == L'\\')
    {
        normalized.pop_back();
    }

    if (normalized.empty())
    {
        return {};
    }

    if (normalized.front() != L'\\')
    {
        normalized.insert(normalized.begin(), L'\\');
    }

    return normalized;
}

std::wstring MetadataStore::CanonicalPathKey(const std::wstring& normalized_path)
{
    auto key = NormalizePath(normalized_path);
    std::transform(key.begin(), key.end(), key.begin(), [](wchar_t ch)
    {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return key;
}

std::wstring MetadataStore::CanonicalPathKeyFromPath(const std::wstring& path)
{
    if (path.empty())
    {
        return {};
    }

    std::wstring key;
    key.reserve(path.size() + 1);
    if (path.front() != L'\\' && path.front() != L'/')
    {
        key.push_back(L'\\');
    }

    bool previous_separator = false;
    for (const auto ch : path)
    {
        const auto mapped = (ch == L'/') ? L'\\' : ch;
        if (mapped == L'\\')
        {
            if (previous_separator)
            {
                continue;
            }
            previous_separator = true;
            key.push_back(mapped);
            continue;
        }

        previous_separator = false;
        key.push_back(static_cast<wchar_t>(std::towlower(mapped)));
    }

    while (key.size() > 1 && key.back() == L'\\')
    {
        key.pop_back();
    }

    if (key.empty())
    {
        return {};
    }
    if (key.front() != L'\\')
    {
        key.insert(key.begin(), L'\\');
    }
    return key;
}

std::wstring MetadataStore::CanonicalPathKeyFromNormalizedPath(const std::wstring& normalized_path)
{
    std::wstring key = normalized_path;
    std::transform(key.begin(), key.end(), key.begin(), [](wchar_t ch)
    {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return key;
}

bool MetadataStore::IsRootPath(const std::wstring& normalized_path)
{
    return normalized_path == L"\\";
}

bool MetadataStore::IsDescendantPath(const std::wstring& candidate_path, const std::wstring& parent_path)
{
    const auto candidate_key = CanonicalPathKey(candidate_path);
    const auto parent_key = CanonicalPathKey(parent_path);
    if (candidate_key.empty() || parent_key.empty())
    {
        return false;
    }
    if (candidate_key == parent_key)
    {
        return false;
    }

    auto parent_prefix = parent_key;
    if (!parent_prefix.empty() && parent_prefix.back() != L'\\')
    {
        parent_prefix.push_back(L'\\');
    }

    return candidate_key.rfind(parent_prefix, 0) == 0;
}

bool MetadataStore::IsDescendantPathKey(const std::wstring& candidate_key, const std::wstring& parent_key)
{
    if (candidate_key.empty() || parent_key.empty())
    {
        return false;
    }
    if (candidate_key == parent_key)
    {
        return false;
    }

    auto parent_prefix = parent_key;
    if (!parent_prefix.empty() && parent_prefix.back() != L'\\')
    {
        parent_prefix.push_back(L'\\');
    }

    return candidate_key.rfind(parent_prefix, 0) == 0;
}

std::wstring MetadataStore::ParentPath(const std::wstring& normalized_path)
{
    if (normalized_path.empty() || IsRootPath(normalized_path))
    {
        return L"\\";
    }

    const auto last_separator = normalized_path.find_last_of(L'\\');
    if (last_separator == std::wstring::npos || last_separator == 0)
    {
        return L"\\";
    }

    return normalized_path.substr(0, last_separator);
}

std::wstring MetadataStore::LeafName(const std::wstring& normalized_path)
{
    if (normalized_path.empty() || IsRootPath(normalized_path))
    {
        return {};
    }

    const auto last_separator = normalized_path.find_last_of(L'\\');
    if (last_separator == std::wstring::npos)
    {
        return normalized_path;
    }

    return normalized_path.substr(last_separator + 1);
}

bool MetadataStore::EnsureRootState()
{
    const auto root_path = std::wstring(L"\\");
    const auto root_object_id = RootDirectoryObjectId();

    if (committed_path_index_.empty() && !committed_inodes_.empty())
    {
        for (const auto& [object_id, inode] : committed_inodes_)
        {
            if (!inode.full_path.empty())
            {
                committed_path_index_[CanonicalPathKeyFromNormalizedPath(inode.full_path)] = object_id;
            }
        }
    }

    auto root_path_it = committed_path_index_.find(CanonicalPathKeyFromNormalizedPath(root_path));
    if (root_path_it == committed_path_index_.end())
    {
        InodeRecord root_inode{};
        root_inode.object_id = root_object_id;
        root_inode.parent_object_id = root_object_id;
        root_inode.name = L"";
        root_inode.full_path = root_path;
        root_inode.is_directory = true;
        root_inode.logical_size = 0;
        root_inode.data_physical_address = 0;
        root_inode.xid = checkpoint_xid_;
        committed_inodes_[root_inode.object_id] = root_inode;
        InvalidateCommittedInodeOrderCache();
        committed_path_index_[CanonicalPathKeyFromNormalizedPath(root_inode.full_path)] = root_inode.object_id;
    }
    else if (auto inode_it = committed_inodes_.find(root_path_it->second); inode_it == committed_inodes_.end())
    {
        InodeRecord root_inode{};
        root_inode.object_id = root_path_it->second;
        root_inode.parent_object_id = root_path_it->second;
        root_inode.name = L"";
        root_inode.full_path = root_path;
        root_inode.is_directory = true;
        root_inode.logical_size = 0;
        root_inode.data_physical_address = 0;
        root_inode.xid = checkpoint_xid_;
        committed_inodes_[root_inode.object_id] = root_inode;
        InvalidateCommittedInodeOrderCache();
    }

    committed_directory_links_.clear();
    committed_directory_links_.reserve(committed_inodes_.size());
    for (const auto& [object_id, inode] : committed_inodes_)
    {
        if (IsRootPath(inode.full_path))
        {
            continue;
        }

        committed_directory_links_.push_back(DirectoryLink
        {
            inode.parent_object_id,
            inode.name,
            object_id,
            inode.xid
        });
    }
    RebuildCommittedDirectoryLinkIndex();

    const auto graph_state_valid = ValidateInodeGraphState(
        committed_inodes_,
        committed_path_index_,
        committed_directory_links_,
        /*require_root_object=*/true);
    if (graph_state_valid)
    {
        SyncWorkingStateFromCommitted();
        RefreshObjectIdAllocator();
    }
    return graph_state_valid;
}

bool MetadataStore::ValidateInodeGraphState(
    const std::unordered_map<std::uint64_t, InodeRecord>& inode_table,
    const std::unordered_map<std::wstring, std::uint64_t>& path_index,
    const std::vector<DirectoryLink>& directory_links,
    bool require_root_object
) const
{
    ScopedPerfTimer perf_scope(validate_inode_graph_perf_);

    if (inode_table.empty())
    {
        return !require_root_object;
    }

    const auto allow_unresolved_raw_read_extent =
        context_.allow_raw_physical_write &&
        IsLikelyRawDevicePath(context_.device_path);
    const auto canonical_name_key = [](const std::wstring& name)
    {
        std::wstring key = name;
        std::transform(key.begin(), key.end(), key.begin(), [](wchar_t ch)
        {
            return static_cast<wchar_t>(std::towlower(ch));
        });
        return key;
    };
    const auto make_link_key = [&](std::uint64_t parent_object_id, const std::wstring& entry_name)
    {
        auto key = std::to_wstring(parent_object_id);
        key.push_back(L'|');
        key.append(canonical_name_key(entry_name));
        return key;
    };

    std::size_t root_count = 0;
    if (path_index.size() != inode_table.size())
    {
        TraceGraphFailure(L"PathIndexSize");
        return false;
    }
    for (const auto& [object_id, inode] : inode_table)
    {
        if (object_id == 0 || inode.full_path.empty())
        {
            TraceGraphFailure(L"InodeEmpty", object_id);
            return false;
        }

        const auto normalized_path = NormalizePath(inode.full_path);
        if (normalized_path != inode.full_path)
        {
            TraceGraphFailure(L"PathNotNormalized", object_id);
            return false;
        }

        const auto path_key = CanonicalPathKeyFromNormalizedPath(inode.full_path);
        if (path_key.empty())
        {
            TraceGraphFailure(L"PathKeyEmpty", object_id);
            return false;
        }

        auto indexed_it = path_index.find(path_key);
        if (indexed_it == path_index.end() || indexed_it->second != object_id)
        {
            TraceGraphFailure(L"PathIndexMismatch", object_id);
            return false;
        }

        const auto is_root = IsRootPath(inode.full_path);
        if (is_root)
        {
            ++root_count;
            if (!inode.is_directory ||
                inode.parent_object_id != object_id ||
                !inode.name.empty() ||
                inode.data_physical_address != 0 ||
                inode.logical_size != 0)
            {
                TraceGraphFailure(L"RootInodeInvalid", object_id);
                return false;
            }
        }
        else
        {
            if (inode.name.empty() ||
                LeafName(inode.full_path) != inode.name ||
                inode.parent_object_id == object_id)
            {
                TraceGraphFailure(L"NonRootNameParentInvalid", object_id);
                return false;
            }

            auto parent_it = inode_table.find(inode.parent_object_id);
            if (parent_it == inode_table.end() || !parent_it->second.is_directory)
            {
                TraceGraphFailure(L"MissingParentDirectory", object_id);
                return false;
            }

            const auto parent_path_key = CanonicalPathKeyFromNormalizedPath(ParentPath(inode.full_path));
            const auto parent_full_path_key = CanonicalPathKeyFromNormalizedPath(parent_it->second.full_path);
            if (parent_path_key != parent_full_path_key)
            {
                TraceGraphFailure(L"ParentPathMismatch", object_id);
                return false;
            }
        }

        if (inode.is_directory)
        {
            if (inode.data_physical_address != 0 || inode.logical_size != 0)
            {
                TraceGraphFailure(L"DirectoryHasData", object_id);
                return false;
            }
        }
        else
        {
            if ((inode.logical_size == 0 && inode.data_physical_address != 0) ||
                (inode.logical_size > 0 &&
                 inode.data_physical_address == 0 &&
                 !committed_read_extents_.contains(object_id) &&
                 !allow_unresolved_raw_read_extent))
            {
                TraceGraphFailure(L"FileExtentMissing", object_id);
                return false;
            }
        }
    }

    enum class AncestryState : std::uint8_t
    {
        Visiting = 1,
        Valid = 2
    };

    std::unordered_map<std::uint64_t, AncestryState> ancestry_state;
    ancestry_state.reserve(inode_table.size());
    const auto validate_ancestry = [&](std::uint64_t object_id) -> bool
    {
        if (auto cached_it = ancestry_state.find(object_id); cached_it != ancestry_state.end())
        {
            return cached_it->second == AncestryState::Valid;
        }

        std::vector<std::uint64_t> visited;
        visited.reserve(8);
        auto cursor = object_id;
        while (true)
        {
            auto [state_it, inserted] = ancestry_state.emplace(cursor, AncestryState::Visiting);
            if (!inserted)
            {
                if (state_it->second == AncestryState::Valid)
                {
                    break;
                }

                TraceGraphFailure(L"AncestryCycle", object_id);
                return false;
            }

            visited.push_back(cursor);

            auto current_it = inode_table.find(cursor);
            if (current_it == inode_table.end())
            {
                TraceGraphFailure(L"AncestryMissingInode", object_id);
                return false;
            }

            if (IsRootPath(current_it->second.full_path))
            {
                break;
            }

            cursor = current_it->second.parent_object_id;
        }

        for (const auto visited_object_id : visited)
        {
            ancestry_state[visited_object_id] = AncestryState::Valid;
        }
        if (auto cursor_it = ancestry_state.find(cursor); cursor_it != ancestry_state.end())
        {
            cursor_it->second = AncestryState::Valid;
        }
        return true;
    };

    if (require_root_object && root_count != 1)
    {
        TraceGraphFailure(L"RootCount");
        return false;
    }

    std::unordered_map<std::wstring, std::uint64_t> expected_links;
    expected_links.reserve(inode_table.size());
    for (const auto& [object_id, inode] : inode_table)
    {
        if (IsRootPath(inode.full_path))
        {
            continue;
        }

        auto [it, inserted] = expected_links.emplace(
            make_link_key(inode.parent_object_id, inode.name),
            object_id);
        if (!inserted && it->second != object_id)
        {
            TraceGraphFailure(L"ExpectedLinkCollision", object_id);
            return false;
        }
    }

    if (directory_links.size() != expected_links.size())
    {
        TraceGraphFailure(L"DirectoryLinkSize");
        return false;
    }
    std::unordered_set<std::wstring> seen_links;
    seen_links.reserve(directory_links.size());
    for (const auto& link : directory_links)
    {
        if (link.parent_object_id == 0 || link.child_object_id == 0 || link.entry_name.empty())
        {
            TraceGraphFailure(L"DirectoryLinkInvalid", link.child_object_id);
            return false;
        }

        auto parent_it = inode_table.find(link.parent_object_id);
        auto child_it = inode_table.find(link.child_object_id);
        if (parent_it == inode_table.end() ||
            child_it == inode_table.end() ||
            !parent_it->second.is_directory)
        {
            TraceGraphFailure(L"DirectoryLinkParentChildMissing", link.child_object_id);
            return false;
        }

        if (child_it->second.parent_object_id != link.parent_object_id)
        {
            TraceGraphFailure(L"DirectoryLinkParentMismatch", link.child_object_id);
            return false;
        }

        if (canonical_name_key(link.entry_name) != canonical_name_key(child_it->second.name))
        {
            TraceGraphFailure(L"DirectoryLinkNameMismatch", link.child_object_id);
            return false;
        }

        const auto link_key = make_link_key(link.parent_object_id, link.entry_name);
        auto expected_it = expected_links.find(link_key);
        if (expected_it == expected_links.end() || expected_it->second != link.child_object_id)
        {
            TraceGraphFailure(L"DirectoryLinkExpectedMismatch", link.child_object_id);
            return false;
        }

        if (!seen_links.emplace(link_key).second)
        {
            TraceGraphFailure(L"DirectoryLinkDuplicate", link.child_object_id);
            return false;
        }
    }

    for (const auto& [object_id, inode] : inode_table)
    {
        if (!validate_ancestry(object_id))
        {
            return false;
        }
    }

    return true;
}

void MetadataStore::RefreshObjectIdAllocator()
{
    std::uint64_t highest_object_id = 0;
    const auto consider_object_id = [&](std::uint64_t object_id)
    {
        if (object_id > highest_object_id)
        {
            highest_object_id = object_id;
        }
    };

    consider_object_id(RootDirectoryObjectId());
    for (const auto& [object_id, _] : committed_object_map_)
    {
        consider_object_id(object_id);
    }
    for (const auto& [object_id, _] : committed_inodes_)
    {
        consider_object_id(object_id);
    }
    for (const auto& [object_id, _] : working_inodes_)
    {
        consider_object_id(object_id);
    }
    for (const auto& update : pending_object_map_updates_)
    {
        consider_object_id(update.object_id);
    }

    if (highest_object_id == std::numeric_limits<std::uint64_t>::max())
    {
        next_generated_object_id_ = 1;
        return;
    }

    const auto candidate = highest_object_id + 1;
    if (candidate == 0)
    {
        next_generated_object_id_ = 1;
        return;
    }

    if (next_generated_object_id_ < candidate)
    {
        next_generated_object_id_ = candidate;
    }
}

std::uint64_t MetadataStore::ResolveUniqueObjectId(const std::wstring& normalized_path)
{
    const auto object_id_is_in_use = [&](std::uint64_t object_id)
    {
        if (object_id == 0 ||
            committed_object_map_.contains(object_id) ||
            committed_inodes_.contains(object_id) ||
            working_inodes_.contains(object_id))
        {
            return true;
        }

        for (const auto& update : pending_object_map_updates_)
        {
            if (update.object_id == object_id)
            {
                return true;
            }
        }
        return false;
    };

    auto candidate = next_generated_object_id_;
    if (candidate == 0)
    {
        candidate = 1;
    }
    if (candidate <= RootDirectoryObjectId())
    {
        candidate = RootDirectoryObjectId() + 1;
        if (candidate == 0)
        {
            candidate = 1;
        }
    }

    constexpr std::uint32_t kMonotonicProbeLimit = 65536;
    for (std::uint32_t probe = 0; probe < kMonotonicProbeLimit; ++probe)
    {
        if (!object_id_is_in_use(candidate))
        {
            next_generated_object_id_ = candidate + 1;
            if (next_generated_object_id_ == 0)
            {
                next_generated_object_id_ = 1;
            }
            return candidate;
        }

        ++candidate;
        if (candidate == 0)
        {
            candidate = 1;
        }
    }

    candidate = StableObjectIdFromPath(normalized_path);
    if (candidate == 0)
    {
        candidate = 1;
    }

    constexpr std::uint32_t kFallbackProbeLimit = 4096;
    const auto normalized_key = CanonicalPathKeyFromNormalizedPath(normalized_path);
    for (std::uint32_t probe = 0; probe < kFallbackProbeLimit; ++probe)
    {
        auto existing = working_inodes_.find(candidate);
        if ((existing == working_inodes_.end() ||
             CanonicalPathKeyFromNormalizedPath(existing->second.full_path) == normalized_key) &&
            !object_id_is_in_use(candidate))
        {
            next_generated_object_id_ = candidate + 1;
            if (next_generated_object_id_ == 0)
            {
                next_generated_object_id_ = 1;
            }
            return candidate;
        }

        ++candidate;
        if (candidate == 0)
        {
            candidate = 1;
        }
    }

    const auto stable_candidate = StableObjectIdFromPath(normalized_path);
    next_generated_object_id_ = stable_candidate + 1;
    if (next_generated_object_id_ == 0)
    {
        next_generated_object_id_ = 1;
    }
    return stable_candidate == 0 ? 1 : stable_candidate;
}

bool MetadataStore::IsDirectoryInWorkingState(const std::wstring& normalized_path) const
{
    auto inode = LookupWorkingInodeByCanonicalPathKeyView(CanonicalPathKeyFromNormalizedPath(normalized_path));
    return inode != nullptr && inode->is_directory;
}

std::optional<MetadataStore::InodeRecord> MetadataStore::LookupWorkingInode(const std::wstring& normalized_path) const
{
    auto inode = LookupWorkingInodeByCanonicalPathKeyView(CanonicalPathKeyFromNormalizedPath(normalized_path));
    if (inode == nullptr)
    {
        return std::nullopt;
    }

    return *inode;
}

std::optional<MetadataStore::InodeRecord> MetadataStore::LookupWorkingInodeByCanonicalPathKey(const std::wstring& canonical_path_key) const
{
    auto inode = LookupWorkingInodeByCanonicalPathKeyView(canonical_path_key);
    if (inode == nullptr)
    {
        return std::nullopt;
    }

    return *inode;
}

const MetadataStore::InodeRecord* MetadataStore::LookupWorkingInodeByCanonicalPathKeyView(const std::wstring& canonical_path_key) const
{
    auto index = working_path_index_.find(canonical_path_key);
    if (index == working_path_index_.end())
    {
        return nullptr;
    }

    auto inode = working_inodes_.find(index->second);
    if (inode == working_inodes_.end())
    {
        return nullptr;
    }

    return &inode->second;
}

bool MetadataStore::HasWorkingChildren(std::uint64_t parent_object_id) const
{
    const auto count = working_child_count_by_parent_.find(parent_object_id);
    return count != working_child_count_by_parent_.end() && count->second != 0;
}

MetadataStore::DirectoryLinkIndexKey MetadataStore::BuildWorkingDirectoryLinkIndexKey(
    std::uint64_t parent_object_id,
    const std::wstring& entry_name) const
{
    std::wstring normalized_entry_name = entry_name;
    std::transform(
        normalized_entry_name.begin(),
        normalized_entry_name.end(),
        normalized_entry_name.begin(),
        [](wchar_t ch)
        {
            return static_cast<wchar_t>(std::towlower(ch));
        });
    return DirectoryLinkIndexKey{parent_object_id, std::move(normalized_entry_name)};
}

void MetadataStore::RebuildWorkingDirectoryIndexes()
{
    working_child_count_by_parent_.clear();
    working_child_object_ids_by_parent_.clear();
    working_child_index_by_parent_child_.clear();
    working_directory_link_index_.clear();
    working_child_count_by_parent_.reserve(working_directory_links_.size());
    working_child_object_ids_by_parent_.reserve(working_directory_links_.size());
    working_child_index_by_parent_child_.reserve(working_directory_links_.size());
    working_directory_link_index_.reserve(working_directory_links_.size());
    for (std::size_t index = 0; index < working_directory_links_.size(); ++index)
    {
        const auto& link = working_directory_links_[index];
        AddWorkingDirectoryChild(link.parent_object_id, link.child_object_id);
        working_directory_link_index_[BuildWorkingDirectoryLinkIndexKey(link.parent_object_id, link.entry_name)] = index;
    }
}

void MetadataStore::ClearCommittedDirectoryLinkIndexes()
{
    committed_directory_link_index_.clear();
    committed_child_object_ids_by_parent_.clear();
    committed_child_index_by_parent_child_.clear();
}

void MetadataStore::RebuildCommittedDirectoryLinkIndex()
{
    committed_directory_link_index_rebuild_count_.fetch_add(1, std::memory_order_relaxed);
    ClearCommittedDirectoryLinkIndexes();
    committed_directory_link_index_.reserve(committed_directory_links_.size());
    committed_child_object_ids_by_parent_.reserve(committed_directory_links_.size());
    committed_child_index_by_parent_child_.reserve(committed_directory_links_.size());
    for (std::size_t index = 0; index < committed_directory_links_.size(); ++index)
    {
        const auto& link = committed_directory_links_[index];
        AddCommittedDirectoryChild(link.parent_object_id, link.child_object_id);
        committed_directory_link_index_[BuildWorkingDirectoryLinkIndexKey(link.parent_object_id, link.entry_name)] = index;
    }
}

void MetadataStore::AddCommittedDirectoryChild(std::uint64_t parent_object_id, std::uint64_t child_object_id)
{
    if (parent_object_id == 0 || child_object_id == 0)
    {
        return;
    }

    auto& children = committed_child_object_ids_by_parent_[parent_object_id];
    const WorkingDirectoryChildKey key{ parent_object_id, child_object_id };
    if (committed_child_index_by_parent_child_.find(key) == committed_child_index_by_parent_child_.end())
    {
        committed_child_index_by_parent_child_[key] = children.size();
        children.push_back(child_object_id);
    }
}

void MetadataStore::RemoveCommittedDirectoryChild(std::uint64_t parent_object_id, std::uint64_t child_object_id)
{
    auto children_it = committed_child_object_ids_by_parent_.find(parent_object_id);
    if (children_it == committed_child_object_ids_by_parent_.end())
    {
        committed_child_index_by_parent_child_.erase(WorkingDirectoryChildKey{ parent_object_id, child_object_id });
        return;
    }

    auto& children = children_it->second;
    const WorkingDirectoryChildKey key{ parent_object_id, child_object_id };
    auto index_it = committed_child_index_by_parent_child_.find(key);
    if (index_it == committed_child_index_by_parent_child_.end() ||
        index_it->second >= children.size() ||
        children[index_it->second] != child_object_id)
    {
        const auto found = std::find(children.begin(), children.end(), child_object_id);
        if (found == children.end())
        {
            committed_child_index_by_parent_child_.erase(key);
            return;
        }
        index_it = committed_child_index_by_parent_child_.insert_or_assign(
            key,
            static_cast<std::size_t>(std::distance(children.begin(), found))).first;
    }

    const auto removed_index = index_it->second;
    const auto last_index = children.size() - 1;
    if (removed_index != last_index)
    {
        const auto moved_child_object_id = children[last_index];
        children[removed_index] = moved_child_object_id;
        committed_child_index_by_parent_child_[WorkingDirectoryChildKey{ parent_object_id, moved_child_object_id }] = removed_index;
    }
    children.pop_back();
    committed_child_index_by_parent_child_.erase(key);
    if (children.empty())
    {
        committed_child_object_ids_by_parent_.erase(children_it);
    }
}

bool MetadataStore::RebuildCommittedBtreeIndex()
{
    committed_btree_index_rebuild_count_.fetch_add(1, std::memory_order_relaxed);
    committed_btree_index_by_key_.clear();
    committed_btree_inode_key_by_object_id_.clear();
    committed_btree_index_by_key_.reserve(committed_btree_records_.size());
    committed_btree_inode_key_by_object_id_.reserve(committed_btree_records_.size());

    for (std::size_t index = 0; index < committed_btree_records_.size(); ++index)
    {
        const auto& record = committed_btree_records_[index];
        if (record.key.empty() ||
            record.kind < BtreeRecordKind::Inode ||
            record.kind > BtreeRecordKind::FileExtent ||
            std::to_integer<unsigned char>(record.key.front()) != static_cast<unsigned char>(record.kind))
        {
            return false;
        }

        auto key_blob = BuildBtreeKeyBlob(record.key);
        if (key_blob.empty())
        {
            return false;
        }

        if (record.kind == BtreeRecordKind::Inode)
        {
            const auto object_id = DecodeBtreeInodeObjectIdFromKey(record);
            if (!object_id.has_value())
            {
                return false;
            }
            committed_btree_inode_key_by_object_id_[*object_id] = key_blob;
        }

        if (!committed_btree_index_by_key_.emplace(std::move(key_blob), index).second)
        {
            return false;
        }
    }

    return true;
}

void MetadataStore::AddWorkingDirectoryChild(std::uint64_t parent_object_id, std::uint64_t child_object_id)
{
    if (parent_object_id == 0 || child_object_id == 0)
    {
        return;
    }

    auto& children = working_child_object_ids_by_parent_[parent_object_id];
    const WorkingDirectoryChildKey key{ parent_object_id, child_object_id };
    if (working_child_index_by_parent_child_.find(key) == working_child_index_by_parent_child_.end())
    {
        working_child_index_by_parent_child_[key] = children.size();
        children.push_back(child_object_id);
    }
    working_child_count_by_parent_[parent_object_id] = children.size();
}

void MetadataStore::RemoveWorkingDirectoryChild(std::uint64_t parent_object_id, std::uint64_t child_object_id)
{
    auto children_it = working_child_object_ids_by_parent_.find(parent_object_id);
    if (children_it == working_child_object_ids_by_parent_.end())
    {
        working_child_count_by_parent_.erase(parent_object_id);
        working_child_index_by_parent_child_.erase(WorkingDirectoryChildKey{ parent_object_id, child_object_id });
        return;
    }

    auto& children = children_it->second;
    const WorkingDirectoryChildKey key{ parent_object_id, child_object_id };
    auto index_it = working_child_index_by_parent_child_.find(key);
    if (index_it == working_child_index_by_parent_child_.end() ||
        index_it->second >= children.size() ||
        children[index_it->second] != child_object_id)
    {
        working_directory_child_linear_scan_count_.fetch_add(1, std::memory_order_relaxed);
        const auto found = std::find(children.begin(), children.end(), child_object_id);
        if (found == children.end())
        {
            working_child_index_by_parent_child_.erase(key);
            working_child_count_by_parent_[parent_object_id] = children.size();
            return;
        }
        index_it = working_child_index_by_parent_child_.insert_or_assign(
            key,
            static_cast<std::size_t>(std::distance(children.begin(), found))).first;
    }

    const auto removed_index = index_it->second;
    const auto last_index = children.size() - 1;
    if (removed_index != last_index)
    {
        const auto moved_child_object_id = children[last_index];
        children[removed_index] = moved_child_object_id;
        working_child_index_by_parent_child_[WorkingDirectoryChildKey{ parent_object_id, moved_child_object_id }] = removed_index;
    }
    children.pop_back();
    working_child_index_by_parent_child_.erase(key);
    if (children.empty())
    {
        working_child_object_ids_by_parent_.erase(children_it);
        working_child_count_by_parent_.erase(parent_object_id);
    }
    else
    {
        working_child_count_by_parent_[parent_object_id] = children.size();
    }
}

std::vector<std::uint64_t> MetadataStore::SnapshotWorkingDirectoryChildObjectIds(std::uint64_t parent_object_id) const
{
    auto children_it = working_child_object_ids_by_parent_.find(parent_object_id);
    if (children_it == working_child_object_ids_by_parent_.end())
    {
        return {};
    }
    return children_it->second;
}

std::vector<std::uint64_t> MetadataStore::SnapshotWorkingDirectoryDescendantObjectIds(std::uint64_t parent_object_id) const
{
    std::vector<std::uint64_t> descendants;
    std::unordered_set<std::uint64_t> seen;
    std::vector<std::uint64_t> pending;
    if (auto children_it = working_child_object_ids_by_parent_.find(parent_object_id);
        children_it != working_child_object_ids_by_parent_.end())
    {
        pending.reserve(children_it->second.size());
        pending.insert(pending.end(), children_it->second.begin(), children_it->second.end());
        seen.reserve(children_it->second.size());
        descendants.reserve(children_it->second.size());
    }
    for (std::size_t index = 0; index < pending.size(); ++index)
    {
        const auto child_object_id = pending[index];
        if (!seen.emplace(child_object_id).second)
        {
            continue;
        }
        descendants.push_back(child_object_id);

        auto inode_it = working_inodes_.find(child_object_id);
        if (inode_it == working_inodes_.end() || !inode_it->second.is_directory)
        {
            continue;
        }

        if (auto grandchildren_it = working_child_object_ids_by_parent_.find(child_object_id);
            grandchildren_it != working_child_object_ids_by_parent_.end())
        {
            pending.insert(pending.end(), grandchildren_it->second.begin(), grandchildren_it->second.end());
        }
    }

    return descendants;
}

void MetadataStore::UpsertWorkingDirectoryLink(
    std::uint64_t parent_object_id,
    const std::wstring& entry_name,
    std::uint64_t child_object_id,
    std::uint64_t xid
)
{
    const auto key = BuildWorkingDirectoryLinkIndexKey(parent_object_id, entry_name);
    auto index_it = working_directory_link_index_.find(key);
    if (index_it != working_directory_link_index_.end() &&
        index_it->second < working_directory_links_.size())
    {
        auto& link = working_directory_links_[index_it->second];
        if (link.child_object_id != child_object_id)
        {
            RemoveWorkingDirectoryChild(parent_object_id, link.child_object_id);
            AddWorkingDirectoryChild(parent_object_id, child_object_id);
        }
        link.entry_name = entry_name;
        link.child_object_id = child_object_id;
        link.xid = xid;
        return;
    }

    const auto new_index = working_directory_links_.size();
    working_directory_links_.push_back(DirectoryLink
    {
        parent_object_id,
        entry_name,
        child_object_id,
        xid
    });
    AddWorkingDirectoryChild(parent_object_id, child_object_id);
    working_directory_link_index_[key] = new_index;
}

void MetadataStore::RemoveWorkingDirectoryLink(std::uint64_t parent_object_id, const std::wstring& entry_name)
{
    const auto key = BuildWorkingDirectoryLinkIndexKey(parent_object_id, entry_name);
    auto index_it = working_directory_link_index_.find(key);
    if (index_it == working_directory_link_index_.end() ||
        index_it->second >= working_directory_links_.size())
    {
        RebuildWorkingDirectoryIndexes();
        index_it = working_directory_link_index_.find(key);
        if (index_it == working_directory_link_index_.end())
        {
            return;
        }
    }

    const auto removed_index = index_it->second;
    const auto removed_child_object_id = working_directory_links_[removed_index].child_object_id;
    const auto last_index = working_directory_links_.size() - 1;
    if (removed_index != last_index)
    {
        working_directory_links_[removed_index] = std::move(working_directory_links_[last_index]);
        working_directory_link_index_[
            BuildWorkingDirectoryLinkIndexKey(
                working_directory_links_[removed_index].parent_object_id,
                working_directory_links_[removed_index].entry_name)] = removed_index;
    }
    working_directory_links_.pop_back();
    working_directory_link_index_.erase(key);
    RemoveWorkingDirectoryChild(parent_object_id, removed_child_object_id);
}

bool MetadataStore::IsLikelyRawDevicePath(const std::wstring& path)
{
    if (path.empty())
    {
        return false;
    }

    std::wstring normalized = path;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](wchar_t c)
    {
        return static_cast<wchar_t>(std::towlower(c));
    });

    return normalized.rfind(LR"(\\.\physicaldrive)", 0) == 0 ||
           normalized.rfind(LR"(\\?\physicaldrive)", 0) == 0;
}

bool MetadataStore::IsFixtureImagePath(const std::wstring& path)
{
    if (path.empty() || IsLikelyRawDevicePath(path))
    {
        return false;
    }

    std::wstring normalized = path;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](wchar_t c)
    {
        return static_cast<wchar_t>(std::towlower(c));
    });

    const auto has_suffix = [&normalized](std::wstring_view suffix) -> bool
    {
        if (normalized.size() < suffix.size())
        {
            return false;
        }
        return normalized.compare(normalized.size() - suffix.size(), suffix.size(), suffix.data(), suffix.size()) == 0;
    };

    if (has_suffix(L".apfs.img") ||
        has_suffix(L".img") ||
        has_suffix(L".apfs.fixture"))
    {
        return true;
    }

    std::filesystem::path device_path(path);
    auto extension = device_path.extension().wstring();
    std::transform(extension.begin(), extension.end(), extension.begin(), [](wchar_t c)
    {
        return static_cast<wchar_t>(std::towlower(c));
    });
    if (extension == L".img" || extension == L".apfs" || extension == L".fixture")
    {
        return true;
    }

    // Do not infer fixture mode from parent-directory naming (for example,
    // "...\\fixtures\\volume.bin"). Production/non-fixture eligibility must be
    // determined by explicit image naming, not incidental folder segments.
    return false;
}

std::uint64_t MetadataStore::RootDirectoryObjectId() const
{
    if (IsLikelyRawDevicePath(context_.device_path))
    {
        return kApfsRootDirectoryObjectId;
    }

    const auto root_path = std::wstring(L"\\");
    return volume_root_block_ != 0 ? volume_root_block_ : StableObjectIdFromPath(root_path);
}

bool MetadataStore::StageObjectMapUpdate(
    std::uint64_t object_id,
    std::uint64_t physical_address,
    std::uint64_t logical_size
)
{
    if (!IsNativeWriteReady() || object_id == 0)
    {
        return false;
    }

    ObjectMapUpdate next_update
    {
        object_id,
        physical_address,
        logical_size,
        checkpoint_xid_ + 1
    };

    auto existing = pending_object_map_update_index_.find(object_id);
    if (existing != pending_object_map_update_index_.end() &&
        existing->second < pending_object_map_updates_.size())
    {
        pending_object_map_updates_[existing->second] = next_update;
        return true;
    }

    if (existing != pending_object_map_update_index_.end())
    {
        pending_object_map_update_index_.erase(existing);
        pending_object_map_update_scan_count_.fetch_add(1, std::memory_order_relaxed);
        RebuildPendingObjectMapUpdateIndex();
        if (auto rebuilt = pending_object_map_update_index_.find(object_id);
            rebuilt != pending_object_map_update_index_.end() &&
            rebuilt->second < pending_object_map_updates_.size())
        {
            pending_object_map_updates_[rebuilt->second] = next_update;
            return true;
        }
    }

    pending_object_map_update_index_[object_id] = pending_object_map_updates_.size();
    pending_object_map_updates_.push_back(next_update);
    return true;
}

void MetadataStore::RebuildPendingObjectMapUpdateIndex()
{
    pending_object_map_update_index_.clear();
    pending_object_map_update_index_.reserve(pending_object_map_updates_.size());
    for (std::size_t index = 0; index < pending_object_map_updates_.size(); ++index)
    {
        pending_object_map_update_index_[pending_object_map_updates_[index].object_id] = index;
    }
}

void MetadataStore::RebuildPendingSpacemanAllocationIndex()
{
    pending_spaceman_allocation_index_rebuild_count_.fetch_add(1, std::memory_order_relaxed);
    pending_spaceman_allocation_index_.clear();
    for (std::size_t index = 0; index < pending_spaceman_allocations_.size(); ++index)
    {
        pending_spaceman_allocation_index_.emplace(
            pending_spaceman_allocations_[index].physical_address,
            index);
    }
}

void MetadataStore::ErasePendingSpacemanAllocationAt(std::size_t index)
{
    if (index >= pending_spaceman_allocations_.size())
    {
        return;
    }

    const auto erased_physical_address = pending_spaceman_allocations_[index].physical_address;
    if (index + 1 == pending_spaceman_allocations_.size())
    {
        pending_spaceman_allocations_.pop_back();
        pending_spaceman_allocation_index_.erase(erased_physical_address);
        pending_spaceman_allocation_index_local_erase_count_.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    pending_spaceman_allocations_.erase(
        pending_spaceman_allocations_.begin() + static_cast<std::ptrdiff_t>(index));
    pending_spaceman_allocation_index_.erase(erased_physical_address);
    for (auto& [_, tracked_index] : pending_spaceman_allocation_index_)
    {
        if (tracked_index > index)
        {
            --tracked_index;
        }
    }
    pending_spaceman_allocation_index_local_erase_count_.fetch_add(1, std::memory_order_relaxed);
}

void MetadataStore::ResizePendingSpacemanAllocationAt(std::size_t index, std::uint64_t bytes)
{
    if (index >= pending_spaceman_allocations_.size())
    {
        return;
    }

    pending_spaceman_allocations_[index].bytes = bytes;
    pending_spaceman_allocation_index_local_resize_count_.fetch_add(1, std::memory_order_relaxed);
}

void MetadataStore::RebuildPendingBtreeFileMetadataIndex()
{
    pending_btree_file_metadata_rebuild_count_.fetch_add(1, std::memory_order_relaxed);
    pending_btree_inode_record_count_by_object_.clear();
    pending_btree_file_inode_index_.clear();
    pending_btree_file_extent_index_.clear();
    pending_btree_file_extent_offsets_by_object_.clear();
    pending_btree_file_extent_record_count_by_object_.clear();
    pending_btree_directory_record_count_by_child_object_.clear();
    pending_btree_tombstone_record_count_ = 0;
    pending_btree_directory_inode_record_count_ = 0;
    pending_btree_untracked_record_count_ = 0;
    pending_btree_inode_record_count_by_object_.reserve(pending_btree_records_.size());
    pending_btree_file_inode_index_.reserve(pending_btree_records_.size());
    pending_btree_file_extent_index_.reserve(pending_btree_records_.size());
    pending_btree_file_extent_offsets_by_object_.reserve(pending_btree_records_.size());
    pending_btree_file_extent_record_count_by_object_.reserve(pending_btree_records_.size());
    pending_btree_directory_record_count_by_child_object_.reserve(pending_btree_records_.size());
    for (std::size_t index = 0; index < pending_btree_records_.size(); ++index)
    {
        TrackPendingBtreeRecordIndex(pending_btree_records_[index], index);
    }
}

void MetadataStore::UntrackPendingBtreeRecordIndex(const BtreeRecord& record, std::size_t index)
{
    if (record.tombstone && pending_btree_tombstone_record_count_ > 0)
    {
        --pending_btree_tombstone_record_count_;
    }

    switch (record.kind)
    {
    case BtreeRecordKind::Inode:
    {
        DecodedBtreeInode decoded{};
        if (!DecodeBtreeInodeRecord(record, decoded))
        {
            if (pending_btree_untracked_record_count_ > 0)
            {
                --pending_btree_untracked_record_count_;
            }
            return;
        }
        if (auto count_it = pending_btree_inode_record_count_by_object_.find(decoded.object_id);
            count_it != pending_btree_inode_record_count_by_object_.end())
        {
            if (count_it->second <= 1)
            {
                pending_btree_inode_record_count_by_object_.erase(count_it);
            }
            else
            {
                --count_it->second;
            }
        }
        if (decoded.is_directory)
        {
            if (pending_btree_directory_inode_record_count_ > 0)
            {
                --pending_btree_directory_inode_record_count_;
            }
            return;
        }
        if (auto inode_it = pending_btree_file_inode_index_.find(decoded.object_id);
            inode_it != pending_btree_file_inode_index_.end() && inode_it->second == index)
        {
            pending_btree_file_inode_index_.erase(inode_it);
        }
        return;
    }
    case BtreeRecordKind::FileExtent:
    {
        DecodedBtreeExtent decoded{};
        if (!DecodeBtreeExtentRecord(record, decoded))
        {
            if (pending_btree_untracked_record_count_ > 0)
            {
                --pending_btree_untracked_record_count_;
            }
            return;
        }

        if (auto count_it = pending_btree_file_extent_record_count_by_object_.find(decoded.object_id);
            count_it != pending_btree_file_extent_record_count_by_object_.end())
        {
            if (count_it->second <= 1)
            {
                pending_btree_file_extent_record_count_by_object_.erase(count_it);
            }
            else
            {
                --count_it->second;
            }
        }

        const PendingBtreeExtentKey key{ decoded.object_id, decoded.logical_offset };
        if (auto extent_it = pending_btree_file_extent_index_.find(key);
            extent_it != pending_btree_file_extent_index_.end() && extent_it->second == index)
        {
            pending_btree_file_extent_index_.erase(extent_it);
            if (auto offsets_it = pending_btree_file_extent_offsets_by_object_.find(decoded.object_id);
                offsets_it != pending_btree_file_extent_offsets_by_object_.end())
            {
                offsets_it->second.erase(decoded.logical_offset);
                if (offsets_it->second.empty())
                {
                    pending_btree_file_extent_offsets_by_object_.erase(offsets_it);
                }
            }
        }
        return;
    }
    case BtreeRecordKind::DirectoryEntry:
    {
        DecodedBtreeDirectoryEntry decoded{};
        if (!DecodeBtreeDirectoryRecord(record, decoded))
        {
            if (pending_btree_untracked_record_count_ > 0)
            {
                --pending_btree_untracked_record_count_;
            }
            return;
        }

        if (auto count_it = pending_btree_directory_record_count_by_child_object_.find(decoded.child_object_id);
            count_it != pending_btree_directory_record_count_by_child_object_.end())
        {
            if (count_it->second <= 1)
            {
                pending_btree_directory_record_count_by_child_object_.erase(count_it);
            }
            else
            {
                --count_it->second;
            }
        }
        return;
    }
    default:
        if (pending_btree_untracked_record_count_ > 0)
        {
            --pending_btree_untracked_record_count_;
        }
        return;
    }
}

void MetadataStore::TrackPendingBtreeRecordIndex(const BtreeRecord& record, std::size_t index)
{
    if (record.tombstone)
    {
        ++pending_btree_tombstone_record_count_;
    }

    switch (record.kind)
    {
    case BtreeRecordKind::Inode:
    {
        DecodedBtreeInode decoded{};
        if (!DecodeBtreeInodeRecord(record, decoded))
        {
            ++pending_btree_untracked_record_count_;
            return;
        }
        ++pending_btree_inode_record_count_by_object_[decoded.object_id];
        if (decoded.is_directory)
        {
            ++pending_btree_directory_inode_record_count_;
            return;
        }
        if (record.tombstone)
        {
            pending_btree_file_inode_index_.erase(decoded.object_id);
            return;
        }
        pending_btree_file_inode_index_[decoded.object_id] = index;
        return;
    }
    case BtreeRecordKind::FileExtent:
    {
        DecodedBtreeExtent decoded{};
        if (!DecodeBtreeExtentRecord(record, decoded))
        {
            ++pending_btree_untracked_record_count_;
            return;
        }
        PendingBtreeExtentKey key{ decoded.object_id, decoded.logical_offset };
        ++pending_btree_file_extent_record_count_by_object_[decoded.object_id];
        if (record.tombstone)
        {
            pending_btree_file_extent_index_.erase(key);
            if (auto offsets_it = pending_btree_file_extent_offsets_by_object_.find(decoded.object_id);
                offsets_it != pending_btree_file_extent_offsets_by_object_.end())
            {
                offsets_it->second.erase(decoded.logical_offset);
                if (offsets_it->second.empty())
                {
                    pending_btree_file_extent_offsets_by_object_.erase(offsets_it);
                }
            }
            return;
        }
        pending_btree_file_extent_index_[key] = index;
        pending_btree_file_extent_offsets_by_object_[decoded.object_id].insert(decoded.logical_offset);
        return;
    }
    case BtreeRecordKind::DirectoryEntry:
    {
        DecodedBtreeDirectoryEntry decoded{};
        if (!DecodeBtreeDirectoryRecord(record, decoded))
        {
            ++pending_btree_untracked_record_count_;
            return;
        }
        ++pending_btree_directory_record_count_by_child_object_[decoded.child_object_id];
        return;
    }
    default:
        ++pending_btree_untracked_record_count_;
        return;
    }
}

void MetadataStore::StagePendingBtreeRecord(BtreeRecord record)
{
    const auto index = pending_btree_records_.size();
    pending_btree_records_.push_back(std::move(record));
    TrackPendingBtreeRecordIndex(pending_btree_records_.back(), index);
}

std::optional<std::size_t> MetadataStore::FindPendingSpacemanAllocationIndex(
    std::uint64_t physical_address) const
{
    if (pending_spaceman_allocation_index_.size() != pending_spaceman_allocations_.size())
    {
        return std::nullopt;
    }

    const auto index_it = pending_spaceman_allocation_index_.find(physical_address);
    if (index_it == pending_spaceman_allocation_index_.end() ||
        index_it->second >= pending_spaceman_allocations_.size())
    {
        return std::nullopt;
    }

    if (pending_spaceman_allocations_[index_it->second].physical_address != physical_address)
    {
        return std::nullopt;
    }
    return index_it->second;
}

bool MetadataStore::PendingSpacemanAllocationsOverlap(
    std::uint64_t physical_address,
    std::uint64_t bytes) const
{
    if (physical_address == 0 || bytes == 0 ||
        physical_address > (std::numeric_limits<std::uint64_t>::max() - bytes))
    {
        return true;
    }
    if (pending_spaceman_allocation_index_.size() != pending_spaceman_allocations_.size())
    {
        return true;
    }
    if (pending_spaceman_allocations_.empty())
    {
        return false;
    }

    const auto range_end = physical_address + bytes;
    const auto overlaps_indexed_allocation =
        [&](std::map<std::uint64_t, std::size_t>::const_iterator index_it)
    {
        if (index_it == pending_spaceman_allocation_index_.end())
        {
            return false;
        }
        if (index_it->second >= pending_spaceman_allocations_.size())
        {
            return true;
        }

        const auto& allocation = pending_spaceman_allocations_[index_it->second];
        if (allocation.physical_address != index_it->first ||
            allocation.physical_address == 0 ||
            allocation.bytes == 0 ||
            allocation.physical_address > (std::numeric_limits<std::uint64_t>::max() - allocation.bytes))
        {
            return true;
        }

        const auto allocation_end = allocation.physical_address + allocation.bytes;
        return physical_address < allocation_end && allocation.physical_address < range_end;
    };

    const auto next_it = pending_spaceman_allocation_index_.lower_bound(physical_address);
    if (overlaps_indexed_allocation(next_it))
    {
        return true;
    }
    if (next_it != pending_spaceman_allocation_index_.begin())
    {
        auto previous_it = next_it;
        --previous_it;
        if (overlaps_indexed_allocation(previous_it))
        {
            return true;
        }
    }

    return false;
}

bool MetadataStore::StageSpacemanAllocation(std::uint64_t physical_address, std::uint64_t bytes)
{
    if (!IsNativeWriteReady() || physical_address == 0 || bytes == 0)
    {
        return false;
    }

    const auto aligned_bytes = AlignExtentBytes(bytes);
    if (aligned_bytes == 0)
    {
        return false;
    }
    if (physical_address > (std::numeric_limits<std::uint64_t>::max() - aligned_bytes))
    {
        return false;
    }
    if (total_blocks_ != 0)
    {
        if (block_size_ == 0 ||
            total_blocks_ > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
        {
            return false;
        }
        const auto container_bytes = total_blocks_ * static_cast<std::uint64_t>(block_size_);
        if ((physical_address + aligned_bytes) > container_bytes)
        {
            return false;
        }
    }
    if (ExtentOverlapsReservedMetadata(physical_address, aligned_bytes))
    {
        return false;
    }
    if (ExtentOverlapsLiveAllocation(physical_address, aligned_bytes))
    {
        return false;
    }

    const auto allocation_index = pending_spaceman_allocations_.size();
    pending_spaceman_allocations_.push_back(SpacemanAllocation
    {
        physical_address,
        aligned_bytes
    });
    const auto insert_result = pending_spaceman_allocation_index_.emplace(physical_address, allocation_index);
    if (!insert_result.second)
    {
        pending_spaceman_allocations_.pop_back();
        RebuildPendingSpacemanAllocationIndex();
        return false;
    }
    return true;
}

bool MetadataStore::StageSpacemanDeallocation(std::uint64_t physical_address, std::uint64_t bytes)
{
    if (!IsNativeWriteReady() || physical_address == 0 || bytes == 0)
    {
        return false;
    }

    const auto aligned_bytes = AlignExtentBytes(bytes);
    if (aligned_bytes == 0)
    {
        return false;
    }
    if (physical_address > (std::numeric_limits<std::uint64_t>::max() - aligned_bytes))
    {
        return false;
    }
    if (total_blocks_ != 0)
    {
        if (block_size_ == 0 ||
            total_blocks_ > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
        {
            return false;
        }
        const auto container_bytes = total_blocks_ * static_cast<std::uint64_t>(block_size_);
        if ((physical_address + aligned_bytes) > container_bytes)
        {
            return false;
        }
    }
    if (ExtentOverlapsReservedMetadata(physical_address, aligned_bytes))
    {
        return false;
    }

    pending_spaceman_deallocations_.push_back(SpacemanAllocation
    {
        physical_address,
        aligned_bytes
    });
    return true;
}

std::optional<MetadataStore::FileMutationExtents> MetadataStore::CommittedFileExtentsForMutation(const InodeRecord& inode) const
{
    FileMutationExtents result{};
    if (inode.is_directory || inode.logical_size == 0)
    {
        return result;
    }

    // Pending and committed extent maps are normalized at ingress and every
    // mutation builder preserves logical order. Keep validation below, but do
    // not sort a fresh projection for each delete/overwrite decision.
    const auto build_from_read_extents =
        [&](const std::vector<FileExtent>& read_extents) -> std::optional<FileMutationExtents>
    {
        FileMutationExtents projected{};
        projected.file_extents.reserve(read_extents.size());
        projected.allocations.reserve(read_extents.size() + (inode.data_physical_address == 0 ? 0 : 1));
        for (const auto& extent : read_extents)
        {
            if (extent.bytes == 0 ||
                extent.logical_offset > (std::numeric_limits<std::uint64_t>::max() - extent.bytes) ||
                extent.logical_offset >= inode.logical_size)
            {
                return std::nullopt;
            }

            const auto logical_tail = inode.logical_size - extent.logical_offset;
            const auto logical_bytes = std::min(extent.bytes, logical_tail);
            if (logical_bytes == 0)
            {
                return std::nullopt;
            }

            projected.file_extents.push_back(
                {
                    extent.logical_offset,
                    extent.physical_address,
                    extent.bytes,
                });

            if (extent.physical_address == 0)
            {
                continue;
            }

            const auto aligned_bytes = AlignExtentBytes(extent.bytes);
            if (aligned_bytes == 0 ||
                extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - aligned_bytes))
            {
                return std::nullopt;
            }
            projected.allocations.push_back({ extent.physical_address, aligned_bytes });
        }

        std::uint64_t previous_end = 0;
        bool has_contiguous_logical_coverage = true;
        bool has_previous = false;
        for (const auto& extent : projected.file_extents)
        {
            const auto extent_end = extent.logical_offset + extent.bytes;
            if (has_previous && extent.logical_offset < previous_end)
            {
                return std::nullopt;
            }
            if (extent.logical_offset != previous_end)
            {
                has_contiguous_logical_coverage = false;
            }
            previous_end = extent_end;
            has_previous = true;
        }

        if (projected.file_extents.empty() && inode.data_physical_address == 0)
        {
            return projected;
        }

        if (!projected.file_extents.empty())
        {
            if (projected.file_extents.front().logical_offset != 0 ||
                !has_contiguous_logical_coverage ||
                previous_end < inode.logical_size)
            {
                // A partial projection cannot be safely replaced by a
                // synthetic physical span: fragmented allocations may have
                // arbitrary gaps between their extents.
                return std::nullopt;
            }
        }
        else if (inode.data_physical_address != 0)
        {
            const auto aligned_bytes = AlignExtentBytes(inode.logical_size);
            if (aligned_bytes == 0 ||
                inode.data_physical_address > (std::numeric_limits<std::uint64_t>::max() - aligned_bytes))
            {
                return std::nullopt;
            }
            projected.file_extents.push_back(
                {
                    0,
                    inode.data_physical_address,
                    inode.logical_size,
                });
            projected.allocations.push_back({ inode.data_physical_address, aligned_bytes });
        }

        if (!NormalizeSpacemanExtents(projected.allocations))
        {
            return std::nullopt;
        }
        return projected;
    };

    if (auto pending_extents_it = pending_read_extent_updates_.find(inode.object_id);
        pending_extents_it != pending_read_extent_updates_.end())
    {
        return build_from_read_extents(pending_extents_it->second);
    }

    if (auto extents_it = committed_read_extents_.find(inode.object_id);
        extents_it != committed_read_extents_.end())
    {
        return build_from_read_extents(extents_it->second);
    }

    if (inode.data_physical_address == 0)
    {
        return result;
    }

    const auto aligned_bytes = AlignExtentBytes(inode.logical_size);
    if (aligned_bytes == 0 ||
        inode.data_physical_address > (std::numeric_limits<std::uint64_t>::max() - aligned_bytes))
    {
        return std::nullopt;
    }

    result.file_extents.push_back(
        {
            0,
            inode.data_physical_address,
            inode.logical_size,
        });
    result.allocations.push_back({ inode.data_physical_address, aligned_bytes });
    return result;
}

bool MetadataStore::StageCommittedFileExtentDeallocations(const FileMutationExtents& extents)
{
    for (const auto& allocation : extents.allocations)
    {
        if (!StageSpacemanDeallocation(allocation.physical_address, allocation.bytes))
        {
            return false;
        }
    }

    return true;
}

bool MetadataStore::HasPendingSpacemanAllocation(std::uint64_t physical_address, std::uint64_t bytes) const
{
    if (physical_address == 0 || bytes == 0)
    {
        return false;
    }

    const auto aligned_bytes = AlignExtentBytes(bytes);
    if (aligned_bytes == 0)
    {
        return false;
    }

    const auto allocation_index = FindPendingSpacemanAllocationIndex(physical_address);
    return allocation_index.has_value() &&
           pending_spaceman_allocations_[allocation_index.value()].bytes == aligned_bytes;
}

bool MetadataStore::ReleasePendingSpacemanAllocation(std::uint64_t physical_address, std::uint64_t bytes)
{
    if (!IsNativeWriteReady() || physical_address == 0 || bytes == 0)
    {
        return false;
    }

    const auto aligned_bytes = AlignExtentBytes(bytes);
    if (aligned_bytes == 0)
    {
        return false;
    }

    const auto allocation_index = FindPendingSpacemanAllocationIndex(physical_address);
    if (!allocation_index.has_value() ||
        pending_spaceman_allocations_[allocation_index.value()].bytes != aligned_bytes)
    {
        return false;
    }

    ErasePendingSpacemanAllocationAt(allocation_index.value());
    tracking_spaceman_free_extent_delta_ = true;
    ScopeExit clear_tracking_spaceman_free_extent_delta{
        [&]()
        {
            tracking_spaceman_free_extent_delta_ = false;
        }};
    return FreeExtent(physical_address, aligned_bytes);
}

bool MetadataStore::PendingReadExtentsCoverLogicalRange(
    std::uint64_t object_id,
    std::uint64_t offset,
    std::uint64_t length) const
{
    if (length == 0)
    {
        return true;
    }

    if (offset > (std::numeric_limits<std::uint64_t>::max() - length))
    {
        return false;
    }

    auto extents_it = pending_read_extent_updates_.find(object_id);
    if (extents_it == pending_read_extent_updates_.end())
    {
        return false;
    }

    const auto pending_allocation_contains_range =
        [&](std::uint64_t physical_address, std::uint64_t bytes) -> bool
    {
        if (physical_address == 0 ||
            bytes == 0 ||
            physical_address > (std::numeric_limits<std::uint64_t>::max() - bytes) ||
            pending_spaceman_allocation_index_.size() != pending_spaceman_allocations_.size())
        {
            return false;
        }

        auto allocation_it = pending_spaceman_allocation_index_.upper_bound(physical_address);
        if (allocation_it == pending_spaceman_allocation_index_.begin())
        {
            return false;
        }
        --allocation_it;
        if (allocation_it->second >= pending_spaceman_allocations_.size())
        {
            return false;
        }

        const auto& allocation = pending_spaceman_allocations_[allocation_it->second];
        return allocation.physical_address == allocation_it->first &&
               PhysicalRangeContains(allocation.physical_address, allocation.bytes, physical_address, bytes);
    };

    const auto* extents = &extents_it->second;
    const auto range_end = offset + length;
    auto covered_until = offset;
    for (const auto& extent : *extents)
    {
        if (extent.bytes == 0 ||
            extent.logical_offset > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
        {
            return false;
        }

        const auto extent_end = extent.logical_offset + extent.bytes;
        if (extent_end <= covered_until)
        {
            continue;
        }
        if (extent.logical_offset > covered_until)
        {
            return false;
        }

        const auto next_covered = std::min(extent_end, range_end);
        const auto physical_offset = covered_until - extent.logical_offset;
        if (extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - physical_offset) ||
            !pending_allocation_contains_range(
                extent.physical_address + physical_offset,
                next_covered - covered_until))
        {
            return false;
        }

        covered_until = next_covered;
        if (covered_until >= range_end)
        {
            return true;
        }
    }

    return false;
}

bool MetadataStore::CoalescePendingWriteMutation(std::uint64_t object_id, const MutationRequest& request)
{
    return CoalescePendingWriteMutation(object_id, request, nullptr);
}

bool MetadataStore::CoalescePendingWriteMutation(
    std::uint64_t object_id,
    const MutationRequest& request,
    const std::wstring* canonical_path_key,
    const std::wstring* normalized_path)
{
    if (!pending_write_object_ids_.contains(object_id))
    {
        pending_write_object_ids_.insert(object_id);
        pending_write_mutation_index_by_object_id_[object_id] = pending_mutations_.size();
        pending_mutations_.push_back(request);
        pending_mutation_path_key_cache_.emplace_back();
        return false;
    }

    auto index_it = pending_write_mutation_index_by_object_id_.find(object_id);
    if (index_it == pending_write_mutation_index_by_object_id_.end() ||
        index_it->second >= pending_mutations_.size())
    {
        RebuildPendingWriteObjectIds();
        index_it = pending_write_mutation_index_by_object_id_.find(object_id);
    }

    if (index_it == pending_write_mutation_index_by_object_id_.end() ||
        index_it->second >= pending_mutations_.size())
    {
        pending_write_object_ids_.insert(object_id);
        pending_write_mutation_index_by_object_id_[object_id] = pending_mutations_.size();
        pending_mutations_.push_back(request);
        pending_mutation_path_key_cache_.emplace_back();
        return false;
    }

    const auto remove_index = index_it->second;
    const auto indexed_inode = pending_mutations_[remove_index].operation == MutationOperation::Write
        ? [&]() -> const InodeRecord*
        {
            if (canonical_path_key != nullptr)
            {
                return LookupWorkingInodeByCanonicalPathKeyView(*canonical_path_key);
            }
            return LookupWorkingInodeByCanonicalPathKeyView(
                CanonicalPathKeyFromNormalizedPath(NormalizePath(pending_mutations_[remove_index].path)));
        }()
        : nullptr;
    if (indexed_inode == nullptr || indexed_inode->object_id != object_id)
    {
        RebuildPendingWriteObjectIds();
        index_it = pending_write_mutation_index_by_object_id_.find(object_id);
        if (index_it == pending_write_mutation_index_by_object_id_.end() ||
            index_it->second >= pending_mutations_.size())
        {
            pending_write_object_ids_.insert(object_id);
            pending_write_mutation_index_by_object_id_[object_id] = pending_mutations_.size();
            pending_mutations_.push_back(request);
            pending_mutation_path_key_cache_.emplace_back();
            return false;
        }
    }

    const auto indexed_remove = pending_write_mutation_index_by_object_id_.at(object_id);
    UntrackPendingCloseDelaySummaryWriteMutation(pending_mutations_[indexed_remove]);
    if (indexed_remove + 1 == pending_mutations_.size())
    {
        pending_mutations_[indexed_remove] = request;
        if (indexed_remove < pending_mutation_path_key_cache_.size())
        {
            pending_mutation_path_key_cache_[indexed_remove] = {};
        }
        TrackPendingCloseDelaySummaryMutation(
            request,
            normalized_path != nullptr ? *normalized_path : NormalizePath(request.path),
            object_id,
            canonical_path_key);
        return true;
    }

    pending_mutations_.erase(pending_mutations_.begin() + static_cast<std::ptrdiff_t>(indexed_remove));
    if (indexed_remove < pending_mutation_path_key_cache_.size())
    {
        pending_mutation_path_key_cache_.erase(
            pending_mutation_path_key_cache_.begin() + static_cast<std::ptrdiff_t>(indexed_remove));
    }
    pending_write_mutation_index_by_object_id_.erase(object_id);
    for (auto& entry : pending_write_mutation_index_by_object_id_)
    {
        auto& index = entry.second;
        if (index > indexed_remove)
        {
            --index;
        }
    }
    for (auto& entry : pending_basic_info_mutation_index_by_object_id_)
    {
        auto& index = entry.second;
        if (index > indexed_remove)
        {
            --index;
        }
    }

    pending_write_mutation_index_by_object_id_[object_id] = pending_mutations_.size();
    pending_mutations_.push_back(request);
    pending_mutation_path_key_cache_.emplace_back();
    TrackPendingCloseDelaySummaryMutation(
        request,
        normalized_path != nullptr ? *normalized_path : NormalizePath(request.path),
        object_id,
        canonical_path_key);
    return true;
}

void MetadataStore::RebuildPendingBasicInfoMutationIndex()
{
    pending_basic_info_mutation_index_by_object_id_.clear();
    pending_basic_info_mutation_index_by_object_id_.reserve(pending_mutations_.size());
    for (std::size_t index = 0; index < pending_mutations_.size(); ++index)
    {
        const auto& mutation = pending_mutations_[index];
        if (mutation.operation != MutationOperation::SetBasicInfo)
        {
            continue;
        }

        const auto inode = LookupWorkingInode(NormalizePath(mutation.path));
        if (inode.has_value())
        {
            pending_basic_info_mutation_index_by_object_id_[inode->object_id] = index;
        }
    }
}

bool MetadataStore::CoalescePendingSetFileSizeMutation(
    std::uint64_t object_id,
    const MutationRequest& request,
    const std::wstring* canonical_path_key)
{
    if (object_id == 0 ||
        pending_mutations_.empty() ||
        !pending_close_delay_created_file_object_ids_.contains(object_id))
    {
        return false;
    }

    const auto last_index = pending_mutations_.size() - 1;
    auto& last_mutation = pending_mutations_.back();
    if (last_mutation.operation != MutationOperation::SetFileSize)
    {
        return false;
    }

    const auto request_key = canonical_path_key != nullptr
        ? *canonical_path_key
        : CanonicalPathKeyFromNormalizedPath(NormalizePath(request.path));
    if (canonical_path_key == nullptr)
    {
        pending_set_file_size_coalesce_path_fallback_count_.fetch_add(1, std::memory_order_relaxed);
    }
    const auto last_key = canonical_path_key != nullptr && last_mutation.path == request.path
        ? *canonical_path_key
        : CanonicalPathKeyFromNormalizedPath(NormalizePath(last_mutation.path));
    if (canonical_path_key == nullptr || last_mutation.path != request.path)
    {
        pending_set_file_size_coalesce_path_fallback_count_.fetch_add(1, std::memory_order_relaxed);
    }
    if (request_key.empty() || last_key != request_key)
    {
        return false;
    }

    const auto* indexed_inode = LookupWorkingInodeByCanonicalPathKeyView(last_key);
    if (indexed_inode == nullptr || indexed_inode->object_id != object_id)
    {
        return false;
    }

    last_mutation = request;
    if (last_index < pending_mutation_path_key_cache_.size())
    {
        pending_mutation_path_key_cache_[last_index] = {};
    }
    return true;
}

bool MetadataStore::CoalescePendingBasicInfoMutation(
    std::uint64_t object_id,
    const MutationRequest& request,
    const std::wstring* canonical_path_key)
{
    auto index_it = pending_basic_info_mutation_index_by_object_id_.find(object_id);
    if (index_it == pending_basic_info_mutation_index_by_object_id_.end() ||
        index_it->second >= pending_mutations_.size())
    {
        RebuildPendingBasicInfoMutationIndex();
        index_it = pending_basic_info_mutation_index_by_object_id_.find(object_id);
    }

    if (index_it == pending_basic_info_mutation_index_by_object_id_.end() ||
        index_it->second >= pending_mutations_.size())
    {
        return false;
    }

    auto& indexed_mutation = pending_mutations_[index_it->second];
    std::optional<std::wstring> request_key_storage;
    const auto& request_key = canonical_path_key != nullptr
        ? *canonical_path_key
        : request_key_storage.emplace(CanonicalPathKeyFromNormalizedPath(NormalizePath(request.path)));
    if (canonical_path_key == nullptr)
    {
        pending_basic_info_coalesce_path_fallback_count_.fetch_add(1, std::memory_order_relaxed);
    }
    const auto indexed_key = canonical_path_key != nullptr && indexed_mutation.path == request.path
        ? *canonical_path_key
        : CanonicalPathKeyFromNormalizedPath(NormalizePath(indexed_mutation.path));
    if (canonical_path_key == nullptr || indexed_mutation.path != request.path)
    {
        pending_basic_info_coalesce_path_fallback_count_.fetch_add(1, std::memory_order_relaxed);
    }
    const auto* indexed_inode = indexed_mutation.operation == MutationOperation::SetBasicInfo
        ? LookupWorkingInodeByCanonicalPathKeyView(indexed_key)
        : nullptr;
    if (indexed_inode == nullptr ||
        indexed_inode->object_id != object_id ||
        indexed_key != request_key)
    {
        RebuildPendingBasicInfoMutationIndex();
        index_it = pending_basic_info_mutation_index_by_object_id_.find(object_id);
        if (index_it == pending_basic_info_mutation_index_by_object_id_.end() ||
            index_it->second >= pending_mutations_.size())
        {
            return false;
        }

        auto& rebuilt_mutation = pending_mutations_[index_it->second];
        pending_basic_info_coalesce_path_fallback_count_.fetch_add(1, std::memory_order_relaxed);
        const auto rebuilt_key = CanonicalPathKeyFromNormalizedPath(NormalizePath(rebuilt_mutation.path));
        const auto* rebuilt_inode = rebuilt_mutation.operation == MutationOperation::SetBasicInfo
            ? LookupWorkingInodeByCanonicalPathKeyView(rebuilt_key)
            : nullptr;
        if (rebuilt_inode == nullptr ||
            rebuilt_inode->object_id != object_id ||
            rebuilt_key != request_key)
        {
            return false;
        }

        rebuilt_mutation = request;
        if (index_it->second < pending_mutation_path_key_cache_.size())
        {
            pending_mutation_path_key_cache_[index_it->second] = {};
        }
        return true;
    }

    indexed_mutation = request;
    if (index_it->second < pending_mutation_path_key_cache_.size())
    {
        pending_mutation_path_key_cache_[index_it->second] = {};
    }
    return true;
}

const std::wstring& MetadataStore::CachedPendingMutationPathKey(std::size_t index)
{
    static const std::wstring kEmptyKey;
    if (index >= pending_mutations_.size())
    {
        return kEmptyKey;
    }

    if (pending_mutation_path_key_cache_.size() < pending_mutations_.size())
    {
        pending_mutation_path_key_cache_.resize(pending_mutations_.size());
    }

    const auto& pending = pending_mutations_[index];
    auto& cache = pending_mutation_path_key_cache_[index];
    if (cache.path_key_valid && cache.path == pending.path)
    {
        pending_rename_path_key_cache_hit_count_.fetch_add(1, std::memory_order_relaxed);
        return cache.path_key;
    }

    pending_rename_path_key_cache_miss_count_.fetch_add(1, std::memory_order_relaxed);
    cache.path = pending.path;
    cache.path_key = CanonicalPathKeyFromNormalizedPath(NormalizePath(pending.path));
    cache.path_key_valid = true;
    return cache.path_key;
}

const std::wstring& MetadataStore::CachedPendingMutationSecondaryPathKey(std::size_t index)
{
    static const std::wstring kEmptyKey;
    if (index >= pending_mutations_.size())
    {
        return kEmptyKey;
    }

    if (pending_mutation_path_key_cache_.size() < pending_mutations_.size())
    {
        pending_mutation_path_key_cache_.resize(pending_mutations_.size());
    }

    const auto& pending = pending_mutations_[index];
    auto& cache = pending_mutation_path_key_cache_[index];
    if (cache.secondary_path_key_valid && cache.secondary_path == pending.secondary_path)
    {
        pending_rename_path_key_cache_hit_count_.fetch_add(1, std::memory_order_relaxed);
        return cache.secondary_path_key;
    }

    pending_rename_path_key_cache_miss_count_.fetch_add(1, std::memory_order_relaxed);
    cache.secondary_path = pending.secondary_path;
    cache.secondary_path_key = CanonicalPathKeyFromNormalizedPath(NormalizePath(pending.secondary_path));
    cache.secondary_path_key_valid = true;
    return cache.secondary_path_key;
}

bool MetadataStore::CoalescePendingRenameMutation(
    std::uint64_t object_id,
    const MutationRequest& request,
    const std::wstring& source_path_key,
    const std::wstring& destination_path_key)
{
    if (object_id == 0 ||
        request.replace_if_exists ||
        source_path_key.empty() ||
        destination_path_key.empty() ||
        source_path_key == destination_path_key)
    {
        return false;
    }

    for (auto reverse_it = pending_mutations_.rbegin(); reverse_it != pending_mutations_.rend(); ++reverse_it)
    {
        const auto pending_index = static_cast<std::size_t>(
            std::distance(reverse_it, pending_mutations_.rend()) - 1);
        const auto& pending = *reverse_it;
        if (pending.operation == MutationOperation::Rename)
        {
            const auto& pending_source_key = CachedPendingMutationPathKey(pending_index);
            const auto& pending_destination_key = CachedPendingMutationSecondaryPathKey(pending_index);
            if (pending_source_key.empty() || pending_destination_key.empty())
            {
                return false;
            }

            if (pending_destination_key == source_path_key &&
                !pending.replace_if_exists)
            {
                const auto* current_inode = LookupWorkingInodeByCanonicalPathKeyView(destination_path_key);
                if (current_inode == nullptr ||
                    current_inode->object_id != object_id ||
                    current_inode->is_directory ||
                    pending_source_key == destination_path_key)
                {
                    return false;
                }

                auto compacted = request;
                compacted.path = pending.path;
                compacted.secondary_path = request.secondary_path;
                pending_mutations_[pending_index] = std::move(compacted);
                if (pending_index < pending_mutation_path_key_cache_.size())
                {
                    auto& cache = pending_mutation_path_key_cache_[pending_index];
                    cache.secondary_path.clear();
                    cache.secondary_path_key.clear();
                    cache.secondary_path_key_valid = false;
                }
                return true;
            }

            if (pending_source_key == source_path_key ||
                pending_destination_key == source_path_key ||
                pending_source_key == destination_path_key ||
                pending_destination_key == destination_path_key)
            {
                return false;
            }

            continue;
        }

        if (pending.operation == MutationOperation::CreateFile ||
            pending.operation == MutationOperation::CreateDirectory ||
            pending.operation == MutationOperation::Write ||
            pending.operation == MutationOperation::SetFileSize ||
            pending.operation == MutationOperation::Delete ||
            pending.operation == MutationOperation::SetBasicInfo)
        {
            const auto& pending_path_key = CachedPendingMutationPathKey(pending_index);
            if (pending_path_key == source_path_key ||
                pending_path_key == destination_path_key)
            {
                return false;
            }

            if (pending.operation == MutationOperation::CreateFile ||
                pending.operation == MutationOperation::CreateDirectory ||
                pending.operation == MutationOperation::Delete)
            {
                if (IsDescendantPathKey(source_path_key, pending_path_key) ||
                    IsDescendantPathKey(destination_path_key, pending_path_key) ||
                    IsDescendantPathKey(pending_path_key, source_path_key) ||
                    IsDescendantPathKey(pending_path_key, destination_path_key))
                {
                    return false;
                }
            }
        }
    }

    return false;
}

void MetadataStore::RebuildPendingWriteObjectIds()
{
    pending_write_object_ids_.clear();
    pending_write_mutation_index_by_object_id_.clear();
    pending_write_object_ids_.reserve(pending_mutations_.size());
    pending_write_mutation_index_by_object_id_.reserve(pending_mutations_.size());
    for (std::size_t index = 0; index < pending_mutations_.size(); ++index)
    {
        const auto& mutation = pending_mutations_[index];
        if (mutation.operation != MutationOperation::Write)
        {
            continue;
        }

        auto inode = LookupWorkingInode(NormalizePath(mutation.path));
        if (inode.has_value())
        {
            pending_write_object_ids_.insert(inode->object_id);
            pending_write_mutation_index_by_object_id_[inode->object_id] = index;
        }
    }
}

const std::vector<MetadataStore::FileExtent>* MetadataStore::LookupSortedReadExtents(std::uint64_t object_id) const
{
    // These internal maps only receive vectors from SetCommittedReadExtents,
    // RebuildReadExtentsFromBtreeRecords, or mutation builders that preserve
    // logical order. Do not rescan every extent on the commit hot path just to
    // re-prove that invariant; external vectors are normalized at ingress.
    const auto pending_extents_it = pending_read_extent_updates_.find(object_id);
    if (pending_extents_it != pending_read_extent_updates_.end())
    {
        return &pending_extents_it->second;
    }

    const auto working_extents_it = working_read_extents_.find(object_id);
    if (working_extents_it != working_read_extents_.end())
    {
        return &working_extents_it->second;
    }

    const auto committed_extents_it = committed_read_extents_.find(object_id);
    if (committed_extents_it != committed_read_extents_.end())
    {
        return &committed_extents_it->second;
    }

    return nullptr;
}

void MetadataStore::ClearPendingPayloadSummary()
{
    ClearPendingPayloadPathKeys();
    ClearPendingPayloadObjectSummary();
}

void MetadataStore::ClearPendingPayloadPathKeys()
{
    pending_payload_path_keys_.clear();
    pending_payload_path_key_order_.clear();
    pending_payload_path_key_order_valid_ = true;
}

void MetadataStore::InsertPendingPayloadPathKey(
    const std::wstring& path_key,
    std::uint64_t object_id)
{
    if (path_key.empty())
    {
        return;
    }

    auto [it, inserted] = pending_payload_path_keys_.try_emplace(path_key, object_id);
    if (!inserted)
    {
        if (it->second == object_id)
        {
            return;
        }
        it->second = object_id;
        InvalidatePendingPayloadPathKeyOrder();
        return;
    }

    InvalidatePendingPayloadPathKeyOrder();
}

void MetadataStore::InsertPendingPayloadPathKey(
    std::wstring&& path_key,
    std::uint64_t object_id)
{
    if (path_key.empty())
    {
        return;
    }

    auto [it, inserted] = pending_payload_path_keys_.try_emplace(std::move(path_key), object_id);
    if (!inserted)
    {
        if (it->second == object_id)
        {
            return;
        }
        it->second = object_id;
    }
    InvalidatePendingPayloadPathKeyOrder();
}

void MetadataStore::ErasePendingPayloadPathKey(const std::wstring& path_key)
{
    if (pending_payload_path_keys_.erase(path_key) == 0)
    {
        return;
    }

    if (pending_payload_path_key_order_valid_)
    {
        pending_payload_path_key_order_.erase(path_key);
    }
    else
    {
        InvalidatePendingPayloadPathKeyOrder();
    }
}

std::optional<std::uint64_t> MetadataStore::LookupPendingPayloadPathObjectId(const std::wstring& path_key) const
{
    const auto it = pending_payload_path_keys_.find(path_key);
    if (it == pending_payload_path_keys_.end())
    {
        return std::nullopt;
    }

    return it->second;
}

void MetadataStore::InvalidatePendingPayloadPathKeyOrder()
{
    if (pending_payload_path_key_order_valid_)
    {
        pending_payload_path_key_order_valid_ = false;
        pending_payload_path_key_order_.clear();
    }
}

void MetadataStore::EnsurePendingPayloadPathKeyOrder()
{
    if (pending_payload_path_key_order_valid_ &&
        pending_payload_path_key_order_.size() == pending_payload_path_keys_.size())
    {
        return;
    }

    pending_payload_path_key_order_.clear();
    for (const auto& [payload_path, payload_object_id] : pending_payload_path_keys_)
    {
        pending_payload_path_key_order_.emplace(payload_path, payload_object_id);
    }
    pending_payload_path_key_order_valid_ = true;
    pending_payload_path_order_build_count_.fetch_add(1, std::memory_order_relaxed);
}

void MetadataStore::ClearPendingPayloadObjectSummary()
{
    pending_payload_object_ids_.clear();
    pending_payload_object_order_.clear();
    pending_payload_object_order_index_.clear();
    pending_payload_object_bytes_by_id_.clear();
    pending_payload_total_bytes_ = 0;
}

void MetadataStore::RefreshPendingPayloadSummaryForObject(std::uint64_t object_id)
{
    const auto inode_it = working_inodes_.find(object_id);
    if (inode_it == working_inodes_.end() ||
        inode_it->second.is_directory ||
        inode_it->second.data_physical_address == 0 ||
        inode_it->second.logical_size == 0)
    {
        RemovePendingPayloadSummaryForObject(object_id);
        return;
    }

    const auto bytes = inode_it->second.logical_size;
    if (auto bytes_it = pending_payload_object_bytes_by_id_.find(object_id);
        bytes_it != pending_payload_object_bytes_by_id_.end())
    {
        if (bytes_it->second == bytes)
        {
            TrackPendingPayloadSummaryObject(object_id);
            return;
        }

        pending_payload_total_bytes_ -= bytes_it->second;
        bytes_it->second = bytes;
    }
    else
    {
        pending_payload_object_bytes_by_id_[object_id] = bytes;
    }

    TrackPendingPayloadSummaryObject(object_id);
    pending_payload_total_bytes_ += bytes;
}

void MetadataStore::RemovePendingPayloadSummaryForObject(std::uint64_t object_id)
{
    pending_payload_object_ids_.erase(object_id);
    if (auto bytes_it = pending_payload_object_bytes_by_id_.find(object_id);
        bytes_it != pending_payload_object_bytes_by_id_.end())
    {
        pending_payload_total_bytes_ -= bytes_it->second;
        pending_payload_object_bytes_by_id_.erase(bytes_it);
    }
}

void MetadataStore::TrackPendingPayloadSummaryObject(std::uint64_t object_id)
{
    if (object_id == 0)
    {
        return;
    }

    pending_payload_object_ids_.insert(object_id);
    if (pending_payload_object_order_index_.contains(object_id))
    {
        return;
    }

    pending_payload_object_order_index_[object_id] = pending_payload_object_order_.size();
    pending_payload_object_order_.push_back(object_id);
}

void MetadataStore::CompactPendingPayloadSummaryObjectOrder()
{
    if (pending_payload_object_order_.size() == pending_payload_object_ids_.size() &&
        pending_payload_object_order_index_.size() == pending_payload_object_ids_.size())
    {
        return;
    }

    pending_payload_object_order_index_.clear();
    std::size_t compacted_size = 0;
    for (std::size_t read_index = 0;
         read_index < pending_payload_object_order_.size();
         ++read_index)
    {
        const auto object_id = pending_payload_object_order_[read_index];
        if (!pending_payload_object_ids_.contains(object_id) ||
            pending_payload_object_order_index_.contains(object_id))
        {
            continue;
        }

        pending_payload_object_order_index_[object_id] = compacted_size;
        pending_payload_object_order_[compacted_size++] = object_id;
    }

    for (const auto object_id : pending_payload_object_ids_)
    {
        if (pending_payload_object_order_index_.contains(object_id))
        {
            continue;
        }

        pending_payload_object_order_index_[object_id] = compacted_size;
        if (compacted_size == pending_payload_object_order_.size())
        {
            pending_payload_object_order_.push_back(object_id);
        }
        else
        {
            pending_payload_object_order_[compacted_size] = object_id;
        }
        ++compacted_size;
    }

    pending_payload_object_order_.resize(compacted_size);
    pending_payload_object_order_compaction_count_.fetch_add(1, std::memory_order_relaxed);
}

void MetadataStore::RebuildPendingPayloadSummary()
{
    ClearPendingPayloadSummary();
    pending_payload_path_keys_.reserve(pending_mutations_.size());
    for (const auto& mutation : pending_mutations_)
    {
        TrackPendingPayloadSummaryMutation(mutation);
    }
    CompactPendingPayloadSummaryObjectOrder();
}

void MetadataStore::TrackPendingPayloadSummaryMutation(const MutationRequest& request)
{
    const auto normalized_path = NormalizePath(request.path);
    const auto normalized_secondary_path = NormalizePath(request.secondary_path);
    TrackPendingPayloadSummaryMutation(request, normalized_path, normalized_secondary_path);
}

void MetadataStore::TrackPendingPayloadSummaryMutation(
    const MutationRequest& request,
    const std::wstring& normalized_path,
    const std::wstring& normalized_secondary_path,
    std::optional<std::uint64_t> known_object_id,
    const std::wstring* canonical_path_key,
    const std::wstring* canonical_secondary_path_key)
{
    const auto path_key = canonical_path_key != nullptr
        ? *canonical_path_key
        : CanonicalPathKeyFromNormalizedPath(normalized_path);
    const auto resolve_working_object_id = [&]() -> std::optional<std::uint64_t>
    {
        if (known_object_id.has_value() && *known_object_id != 0)
        {
            return known_object_id;
        }

        const auto inode = LookupWorkingInodeByCanonicalPathKey(path_key);
        if (inode.has_value() && !inode->is_directory)
        {
            return inode->object_id;
        }

        return std::nullopt;
    };
    const auto sync_payload_object_ids = [&]()
    {
        ClearPendingPayloadObjectSummary();
        for (const auto& [payload_path, payload_object_id] : pending_payload_path_keys_)
        {
            pending_payload_summary_path_scan_count_.fetch_add(1, std::memory_order_relaxed);
            if (payload_object_id != 0)
            {
                RefreshPendingPayloadSummaryForObject(payload_object_id);
                continue;
            }

            auto inode = LookupWorkingInodeByCanonicalPathKey(payload_path);
            if (inode.has_value() && !inode->is_directory)
            {
                RefreshPendingPayloadSummaryForObject(inode->object_id);
            }
        }
    };
    const auto descendant_prefix_for_path_key = [](const std::wstring& parent_key) -> std::wstring
    {
        auto prefix = parent_key;
        if (!prefix.empty() && prefix.back() != L'\\')
        {
            prefix.push_back(L'\\');
        }
        return prefix;
    };
    const auto for_each_pending_payload_subtree_entry =
        [&](const std::wstring& subtree_key,
            std::atomic<std::uint64_t>& scan_counter,
            auto&& visitor)
    {
        if (subtree_key.empty())
        {
            return;
        }

        EnsurePendingPayloadPathKeyOrder();

        if (const auto exact = pending_payload_path_key_order_.find(subtree_key);
            exact != pending_payload_path_key_order_.end())
        {
            scan_counter.fetch_add(1, std::memory_order_relaxed);
            visitor(exact->first, exact->second);
        }

        const auto prefix = descendant_prefix_for_path_key(subtree_key);
        for (auto it = pending_payload_path_key_order_.lower_bound(prefix);
             it != pending_payload_path_key_order_.end() && it->first.rfind(prefix, 0) == 0;
             ++it)
        {
            if (it->first == subtree_key)
            {
                continue;
            }
            scan_counter.fetch_add(1, std::memory_order_relaxed);
            visitor(it->first, it->second);
        }
    };

    switch (request.operation)
    {
    case MutationOperation::CreateFile:
    case MutationOperation::CreateDirectory:
        if (request.replace_if_exists && !path_key.empty())
        {
            std::optional<std::uint64_t> replaced_object_id = known_object_id;
            if (!replaced_object_id.has_value() || *replaced_object_id == 0)
            {
                if (auto tracked_object_id = LookupPendingPayloadPathObjectId(path_key);
                    tracked_object_id.has_value())
                {
                    replaced_object_id = *tracked_object_id;
                }
            }
            ErasePendingPayloadPathKey(path_key);
            if (replaced_object_id.has_value() && *replaced_object_id != 0)
            {
                RemovePendingPayloadSummaryForObject(*replaced_object_id);
            }
            else
            {
                sync_payload_object_ids();
            }
        }
        break;
    case MutationOperation::Write:
        if (request.length > 0)
        {
            const auto object_id = resolve_working_object_id();
            InsertPendingPayloadPathKey(path_key, object_id.value_or(0));
            if (object_id.has_value() && *object_id != 0)
            {
                RefreshPendingPayloadSummaryForObject(*object_id);
            }
        }
        break;
    case MutationOperation::SetFileSize:
        if (request.length > 0)
        {
            const auto object_id = resolve_working_object_id();
            const bool has_pending_payload_state =
                object_id.has_value() &&
                *object_id != 0 &&
                (pending_read_extent_updates_.contains(*object_id) ||
                 pending_written_ranges_.contains(*object_id) ||
                 prepared_payload_ranges_.contains(*object_id));
            if (has_pending_payload_state)
            {
                InsertPendingPayloadPathKey(path_key, *object_id);
                RefreshPendingPayloadSummaryForObject(*object_id);
            }
        }
        else
        {
            std::optional<std::uint64_t> object_id = known_object_id;
            if (!object_id.has_value() || *object_id == 0)
            {
                if (auto tracked_object_id = LookupPendingPayloadPathObjectId(path_key);
                    tracked_object_id.has_value())
                {
                    object_id = *tracked_object_id;
                }
            }
            ErasePendingPayloadPathKey(path_key);
            if (object_id.has_value() && *object_id != 0)
            {
                RemovePendingPayloadSummaryForObject(*object_id);
            }
            else if (auto inode = LookupWorkingInodeByCanonicalPathKey(path_key); inode.has_value())
            {
                RemovePendingPayloadSummaryForObject(inode->object_id);
            }
            else
            {
                sync_payload_object_ids();
            }
        }
        break;
    case MutationOperation::Rename:
    {
        const auto destination_key = canonical_secondary_path_key != nullptr
            ? *canonical_secondary_path_key
            : CanonicalPathKeyFromNormalizedPath(normalized_secondary_path);
        if (path_key.empty() || destination_key.empty())
        {
            break;
        }

        if (request.replace_if_exists &&
            known_object_id.has_value() &&
            *known_object_id != 0)
        {
            const auto source_inode_it = working_inodes_.find(*known_object_id);
            if (source_inode_it != working_inodes_.end() && !source_inode_it->second.is_directory)
            {
                auto source_payload_object_id = LookupPendingPayloadPathObjectId(path_key);
                if (path_key == destination_key)
                {
                    if (source_payload_object_id.has_value())
                    {
                        const auto resolved_source_payload_object_id =
                            *source_payload_object_id == 0 ? *known_object_id : *source_payload_object_id;
                        InsertPendingPayloadPathKey(path_key, resolved_source_payload_object_id);
                        RefreshPendingPayloadSummaryForObject(resolved_source_payload_object_id);
                    }
                    break;
                }

                auto destination_payload_object_id = LookupPendingPayloadPathObjectId(destination_key);
                if (!destination_payload_object_id.has_value() || *destination_payload_object_id != 0)
                {
                    std::optional<std::uint64_t> replaced_payload_object_id;
                    if (destination_payload_object_id.has_value())
                    {
                        replaced_payload_object_id = *destination_payload_object_id;
                        ErasePendingPayloadPathKey(destination_key);
                    }

                    source_payload_object_id = LookupPendingPayloadPathObjectId(path_key);
                    if (source_payload_object_id.has_value())
                    {
                        const auto resolved_source_payload_object_id =
                            *source_payload_object_id == 0 ? *known_object_id : *source_payload_object_id;
                        ErasePendingPayloadPathKey(path_key);
                        InsertPendingPayloadPathKey(destination_key, resolved_source_payload_object_id);
                        source_payload_object_id = resolved_source_payload_object_id;
                        RefreshPendingPayloadSummaryForObject(resolved_source_payload_object_id);
                    }

                    if (replaced_payload_object_id.has_value() &&
                        (!source_payload_object_id.has_value() ||
                         *replaced_payload_object_id != *source_payload_object_id))
                    {
                        RemovePendingPayloadSummaryForObject(*replaced_payload_object_id);
                    }
                    break;
                }
            }
        }

        if (!request.replace_if_exists &&
            known_object_id.has_value() &&
            *known_object_id != 0)
        {
            const auto source_inode_it = working_inodes_.find(*known_object_id);
            if (source_inode_it != working_inodes_.end() && !source_inode_it->second.is_directory)
            {
                std::uint64_t payload_object_id = *known_object_id;
                if (auto tracked_object_id = LookupPendingPayloadPathObjectId(path_key);
                    tracked_object_id.has_value())
                {
                    if (*tracked_object_id != 0)
                    {
                        payload_object_id = *tracked_object_id;
                    }
                    ErasePendingPayloadPathKey(path_key);
                    InsertPendingPayloadPathKey(destination_key, payload_object_id);
                }
                break;
            }
        }

        std::vector<std::wstring> pending_removals;
        std::vector<std::pair<std::wstring, std::uint64_t>> pending_additions;
        bool needs_summary_resync = false;
        if (request.replace_if_exists && destination_key != path_key)
        {
            for_each_pending_payload_subtree_entry(
                destination_key,
                pending_payload_rename_path_scan_count_,
                [&](const std::wstring& payload_path, std::uint64_t payload_object_id)
            {
                pending_removals.push_back(payload_path);
                if (payload_object_id != 0)
                {
                    RemovePendingPayloadSummaryForObject(payload_object_id);
                }
                else
                {
                    needs_summary_resync = true;
                }
            });
        }

        for_each_pending_payload_subtree_entry(
            path_key,
            pending_payload_rename_path_scan_count_,
            [&](const std::wstring& payload_path, std::uint64_t payload_object_id)
        {
            if (payload_path == path_key)
            {
                pending_removals.push_back(payload_path);
                pending_additions.emplace_back(destination_key, payload_object_id);
                if (payload_object_id == 0)
                {
                    needs_summary_resync = true;
                }
                return;
            }
            auto remapped_path = destination_key;
            remapped_path.append(payload_path.substr(path_key.size()));
            pending_removals.push_back(payload_path);
            pending_additions.emplace_back(std::move(remapped_path), payload_object_id);
            if (payload_object_id == 0)
            {
                needs_summary_resync = true;
            }
        });

        for (const auto& payload_path : pending_removals)
        {
            ErasePendingPayloadPathKey(payload_path);
        }
        for (auto& [payload_path, payload_object_id] : pending_additions)
        {
            if (!payload_path.empty())
            {
                InsertPendingPayloadPathKey(std::move(payload_path), payload_object_id);
                if (payload_object_id != 0)
                {
                    RefreshPendingPayloadSummaryForObject(payload_object_id);
                }
            }
        }
        if (needs_summary_resync)
        {
            sync_payload_object_ids();
        }
        break;
    }
    case MutationOperation::Delete:
    {
        if (path_key.empty())
        {
            break;
        }

        if (known_object_id.has_value() && *known_object_id != 0)
        {
            ErasePendingPayloadPathKey(path_key);
            RemovePendingPayloadSummaryForObject(*known_object_id);
            break;
        }

        std::vector<std::wstring> pending_removals;
        bool needs_summary_resync = false;
        for_each_pending_payload_subtree_entry(
            path_key,
            pending_payload_delete_path_scan_count_,
            [&](const std::wstring& payload_path, std::uint64_t payload_object_id)
        {
            pending_removals.push_back(payload_path);
            if (payload_object_id != 0)
            {
                RemovePendingPayloadSummaryForObject(payload_object_id);
            }
            else
            {
                needs_summary_resync = true;
            }
        });

        for (const auto& payload_path : pending_removals)
        {
            ErasePendingPayloadPathKey(payload_path);
        }
        if (needs_summary_resync)
        {
            sync_payload_object_ids();
        }
        break;
    }
    case MutationOperation::SetBasicInfo:
        break;
    }
}

void MetadataStore::ClearPendingCloseDelaySummary()
{
    pending_close_delay_created_file_object_ids_.clear();
    pending_close_delay_write_count_ = 0;
    pending_close_delay_payload_write_count_ = 0;
    pending_close_delay_metadata_only_count_ = 0;
    pending_close_delay_mixed_valid_ = true;
    pending_close_delay_continue_valid_ = true;
}

void MetadataStore::UntrackPendingCloseDelaySummaryWriteMutation(const MutationRequest& request)
{
    if (request.operation != MutationOperation::Write)
    {
        return;
    }

    if (pending_close_delay_write_count_ > 0)
    {
        --pending_close_delay_write_count_;
    }
    if (request.length > 0 && pending_close_delay_payload_write_count_ > 0)
    {
        --pending_close_delay_payload_write_count_;
    }
}

void MetadataStore::TrackPendingCloseDelaySummaryMutation(const MutationRequest& request)
{
    const auto normalized_path = NormalizePath(request.path);
    TrackPendingCloseDelaySummaryMutation(request, normalized_path);
}

void MetadataStore::TrackPendingCloseDelaySummaryMutation(
    const MutationRequest& request,
    const std::wstring& normalized_path,
    std::optional<std::uint64_t> known_object_id,
    const std::wstring* canonical_path_key)
{
    if (!pending_close_delay_mixed_valid_)
    {
        if (request.operation == MutationOperation::Write)
        {
            ++pending_close_delay_write_count_;
            if (request.length > 0)
            {
                ++pending_close_delay_payload_write_count_;
            }
        }
        return;
    }

    const auto path_key = canonical_path_key != nullptr
        ? *canonical_path_key
        : CanonicalPathKeyFromNormalizedPath(normalized_path);
    const auto resolve_object_id = [&]() -> std::optional<std::uint64_t>
    {
        if (known_object_id.has_value())
        {
            return known_object_id;
        }

        const auto inode = LookupWorkingInodeByCanonicalPathKey(path_key);
        if (inode.has_value())
        {
            return inode->object_id;
        }

        return std::nullopt;
    };
    switch (request.operation)
    {
    case MutationOperation::CreateFile:
    {
        const auto object_id = resolve_object_id();
        if (!object_id.has_value())
        {
            pending_close_delay_mixed_valid_ = false;
            return;
        }
        pending_close_delay_created_file_object_ids_.insert(*object_id);
        break;
    }
    case MutationOperation::Write:
    {
        ++pending_close_delay_write_count_;
        const auto object_id = resolve_object_id();
        if (!object_id.has_value() ||
            !pending_close_delay_created_file_object_ids_.contains(*object_id))
        {
            pending_close_delay_mixed_valid_ = false;
            return;
        }
        if (request.length > 0)
        {
            ++pending_close_delay_payload_write_count_;
        }
        break;
    }
    case MutationOperation::SetBasicInfo:
    {
        ++pending_close_delay_metadata_only_count_;
        const auto object_id = resolve_object_id();
        if (!object_id.has_value() ||
            !pending_close_delay_created_file_object_ids_.contains(*object_id))
        {
            break;
        }
        break;
    }
    case MutationOperation::SetFileSize:
    {
        const auto object_id = resolve_object_id();
        if (!object_id.has_value() ||
            !pending_close_delay_created_file_object_ids_.contains(*object_id))
        {
            pending_close_delay_mixed_valid_ = false;
            pending_close_delay_continue_valid_ = false;
        }
        break;
    }
    case MutationOperation::CreateDirectory:
        if (path_key.empty())
        {
            pending_close_delay_mixed_valid_ = false;
            return;
        }
        ++pending_close_delay_metadata_only_count_;
        break;
    case MutationOperation::Rename:
    case MutationOperation::Delete:
        pending_close_delay_mixed_valid_ = false;
        break;
    }
}

void MetadataStore::RebuildPendingCloseDelaySummary()
{
    pending_close_delay_summary_rebuild_count_.fetch_add(1, std::memory_order_relaxed);
    ClearPendingCloseDelaySummary();
    pending_close_delay_created_file_object_ids_.reserve(pending_mutations_.size());
    for (const auto& mutation : pending_mutations_)
    {
        TrackPendingCloseDelaySummaryMutation(mutation);
    }
}

MutationCompactor::Summary MetadataStore::SummarizePendingMutations() const
{
    const auto map_kind = [](MutationOperation operation)
    {
        switch (operation)
        {
        case MutationOperation::CreateFile:
            return MutationCompactor::MutationKind::CreateFile;
        case MutationOperation::CreateDirectory:
            return MutationCompactor::MutationKind::CreateDirectory;
        case MutationOperation::Write:
            return MutationCompactor::MutationKind::Write;
        case MutationOperation::SetFileSize:
            return MutationCompactor::MutationKind::SetFileSize;
        case MutationOperation::Rename:
            return MutationCompactor::MutationKind::Rename;
        case MutationOperation::Delete:
            return MutationCompactor::MutationKind::Delete;
        case MutationOperation::SetBasicInfo:
            return MutationCompactor::MutationKind::SetBasicInfo;
        }

        return MutationCompactor::MutationKind::SetBasicInfo;
    };

    std::vector<MutationCompactor::MutationView> mutations;
    mutations.reserve(pending_mutations_.size());
    for (const auto& mutation : pending_mutations_)
    {
        mutations.push_back(MutationCompactor::MutationView{
            map_kind(mutation.operation),
            mutation.path,
            mutation.secondary_path,
            mutation.length,
        });
    }

    auto summary = MutationCompactor::Summarize(mutations);
    last_raw_mutation_count_.store(
        static_cast<std::uint64_t>(summary.raw_mutation_count),
        std::memory_order_relaxed);
    last_compacted_mutation_count_.store(
        static_cast<std::uint64_t>(summary.compacted_mutation_count),
        std::memory_order_relaxed);
    return summary;
}

void MetadataStore::CoalescePendingBtreeFileMetadata(std::uint64_t object_id)
{
    const auto tracked_inode = pending_btree_file_inode_index_.find(object_id);
    bool index_valid = tracked_inode == pending_btree_file_inode_index_.end();
    if (tracked_inode != pending_btree_file_inode_index_.end() &&
        tracked_inode->second < pending_btree_records_.size())
    {
        DecodedBtreeInode decoded{};
        const auto& record = pending_btree_records_[tracked_inode->second];
        index_valid = !record.tombstone &&
                      record.kind == BtreeRecordKind::Inode &&
                      DecodeBtreeInodeRecord(record, decoded) &&
                      !decoded.is_directory &&
                      decoded.object_id == object_id;
    }
    if (auto offsets_it = pending_btree_file_extent_offsets_by_object_.find(object_id);
        offsets_it != pending_btree_file_extent_offsets_by_object_.end())
    {
        if (const auto record_count_it = pending_btree_file_extent_record_count_by_object_.find(object_id);
            record_count_it == pending_btree_file_extent_record_count_by_object_.end() ||
            record_count_it->second != offsets_it->second.size())
        {
            index_valid = false;
        }
        for (const auto logical_offset : offsets_it->second)
        {
            const PendingBtreeExtentKey key{ object_id, logical_offset };
            const auto extent_it = pending_btree_file_extent_index_.find(key);
            DecodedBtreeExtent decoded{};
            if (extent_it == pending_btree_file_extent_index_.end() ||
                extent_it->second >= pending_btree_records_.size() ||
                pending_btree_records_[extent_it->second].tombstone ||
                pending_btree_records_[extent_it->second].kind != BtreeRecordKind::FileExtent ||
                !DecodeBtreeExtentRecord(pending_btree_records_[extent_it->second], decoded) ||
                decoded.object_id != object_id ||
                decoded.logical_offset != logical_offset)
            {
                index_valid = false;
                break;
            }
        }
    }
    else if (pending_btree_file_extent_record_count_by_object_.contains(object_id))
    {
        index_valid = false;
    }
    if (index_valid)
    {
        return;
    }

    pending_btree_file_metadata_scan_count_.fetch_add(1, std::memory_order_relaxed);

    const auto is_live_file_metadata_for_object = [&](const BtreeRecord& record)
    {
        if (record.tombstone)
        {
            return false;
        }

        if (record.kind == BtreeRecordKind::Inode)
        {
            DecodedBtreeInode decoded{};
            return DecodeBtreeInodeRecord(record, decoded) &&
                   !decoded.is_directory &&
                   decoded.object_id == object_id;
        }
        if (record.kind == BtreeRecordKind::FileExtent)
        {
            DecodedBtreeExtent decoded{};
            return DecodeBtreeExtentRecord(record, decoded) &&
                   decoded.object_id == object_id;
        }
        return false;
    };

    bool kept_inode = false;
    std::unordered_set<std::uint64_t> kept_extent_offsets;
    if (auto offsets_it = pending_btree_file_extent_offsets_by_object_.find(object_id);
        offsets_it != pending_btree_file_extent_offsets_by_object_.end())
    {
        kept_extent_offsets.reserve(offsets_it->second.size());
    }
    std::vector<std::size_t> removal_indices;
    for (auto it = pending_btree_records_.rbegin(); it != pending_btree_records_.rend();)
    {
        if (!is_live_file_metadata_for_object(*it))
        {
            ++it;
            continue;
        }

        bool keep = false;
        if (it->kind == BtreeRecordKind::Inode)
        {
            keep = !std::exchange(kept_inode, true);
        }
        else if (it->kind == BtreeRecordKind::FileExtent)
        {
            DecodedBtreeExtent decoded{};
            keep = DecodeBtreeExtentRecord(*it, decoded) &&
                   kept_extent_offsets.insert(decoded.logical_offset).second;
        }

        if (keep)
        {
            ++it;
            continue;
        }

        const auto record_index = static_cast<std::size_t>(std::distance(
            pending_btree_records_.begin(),
            std::next(it).base()));
        removal_indices.push_back(record_index);
        ++it;
    }

    if (!removal_indices.empty())
    {
        std::sort(removal_indices.begin(), removal_indices.end());
        std::size_t removal_cursor = 0;
        std::size_t output_index = 0;
        for (std::size_t input_index = 0; input_index < pending_btree_records_.size(); ++input_index)
        {
            if (removal_cursor < removal_indices.size() &&
                removal_indices[removal_cursor] == input_index)
            {
                ++removal_cursor;
                continue;
            }

            if (output_index != input_index)
            {
                pending_btree_records_[output_index] = std::move(pending_btree_records_[input_index]);
            }
            ++output_index;
        }
        pending_btree_records_.resize(output_index);
    }
    RebuildPendingBtreeFileMetadataIndex();
}

std::uint64_t MetadataStore::AlignExtentBytes(std::uint64_t bytes) const noexcept
{
    if (bytes == 0)
    {
        return 0;
    }

    const auto block = static_cast<std::uint64_t>(std::max<std::uint32_t>(1u, block_size_));
    auto aligned_bytes = std::max<std::uint64_t>(bytes, block);
    const auto remainder = aligned_bytes % block;
    if (remainder != 0)
    {
        if (aligned_bytes > (std::numeric_limits<std::uint64_t>::max() - (block - remainder)))
        {
            return 0;
        }
        aligned_bytes += block - remainder;
    }
    return aligned_bytes;
}

bool MetadataStore::ExtentOverlapsReservedMetadata(
    std::uint64_t physical_address,
    std::uint64_t bytes) const
{
    if (physical_address == 0 || bytes == 0)
    {
        return true;
    }

    const auto block_bytes = static_cast<std::uint64_t>(std::max<std::uint32_t>(1u, block_size_));
    if ((physical_address % block_bytes) != 0 || (bytes % block_bytes) != 0)
    {
        return true;
    }
    if (physical_address > (std::numeric_limits<std::uint64_t>::max() - bytes))
    {
        return true;
    }

    const auto first_block = physical_address / block_bytes;
    const auto block_count = bytes / block_bytes;
    if (block_count == 0)
    {
        return true;
    }
    if (first_block > (std::numeric_limits<std::uint64_t>::max() - (block_count - 1)))
    {
        return true;
    }

    const auto replay_checkpoint_blocks = ResolveReplayCheckpointBlockIndices();
    for (std::uint64_t index = 0; index < block_count; ++index)
    {
        const auto block = first_block + index;
        if (IsReservedMetadataBlock(block) ||
            std::find(replay_checkpoint_blocks.begin(), replay_checkpoint_blocks.end(), block) != replay_checkpoint_blocks.end())
        {
            return true;
        }
    }
    return false;
}

bool MetadataStore::ExtentOverlapsLiveAllocation(
    std::uint64_t physical_address,
    std::uint64_t bytes) const
{
    if (physical_address == 0 || bytes == 0 ||
        physical_address > (std::numeric_limits<std::uint64_t>::max() - bytes))
    {
        return true;
    }

    const auto range_end = physical_address + bytes;
    const auto overlaps_allocation = [&](const SpacemanAllocation& allocation)
    {
        if (allocation.physical_address == 0 || allocation.bytes == 0 ||
            allocation.physical_address > (std::numeric_limits<std::uint64_t>::max() - allocation.bytes))
        {
            return false;
        }

        const auto allocation_end = allocation.physical_address + allocation.bytes;
        return physical_address < allocation_end && allocation.physical_address < range_end;
    };

    return std::any_of(
               committed_spaceman_allocations_.begin(),
               committed_spaceman_allocations_.end(),
               overlaps_allocation) ||
           PendingSpacemanAllocationsOverlap(physical_address, bytes);
}

bool MetadataStore::ExtentOverlapsEffectiveLiveAllocation(
    std::uint64_t physical_address,
    std::uint64_t bytes) const
{
    if (physical_address == 0 || bytes == 0 ||
        physical_address > (std::numeric_limits<std::uint64_t>::max() - bytes))
    {
        return true;
    }

    const auto range_end = physical_address + bytes;
    const auto overlaps_range = [&](const SpacemanAllocation& allocation)
    {
        if (allocation.physical_address == 0 || allocation.bytes == 0 ||
            allocation.physical_address > (std::numeric_limits<std::uint64_t>::max() - allocation.bytes))
        {
            return false;
        }

        const auto allocation_end = allocation.physical_address + allocation.bytes;
        return physical_address < allocation_end && allocation.physical_address < range_end;
    };
    const auto removed_by_pending_deallocation = [&](const SpacemanAllocation& allocation)
    {
        return std::any_of(
            pending_spaceman_deallocations_.begin(),
            pending_spaceman_deallocations_.end(),
            [&](const SpacemanAllocation& deallocation)
            {
                return PhysicalRangeContains(
                    deallocation.physical_address,
                    deallocation.bytes,
                    allocation.physical_address,
                    allocation.bytes);
            });
    };

    const auto overlaps_effective_allocation = [&](const SpacemanAllocation& allocation)
    {
        return overlaps_range(allocation) && !removed_by_pending_deallocation(allocation);
    };

    return std::any_of(
               committed_spaceman_allocations_.begin(),
               committed_spaceman_allocations_.end(),
               overlaps_effective_allocation) ||
           std::any_of(
               pending_spaceman_allocations_.begin(),
               pending_spaceman_allocations_.end(),
               overlaps_effective_allocation);
}

std::optional<std::uint64_t> MetadataStore::AdvancePastReservedMetadata(
    std::uint64_t physical_address,
    std::uint64_t bytes) const
{
    if (physical_address == 0 || bytes == 0 || block_size_ == 0)
    {
        return std::nullopt;
    }

    const auto block_bytes = static_cast<std::uint64_t>(block_size_);
    if ((physical_address % block_bytes) != 0 || (bytes % block_bytes) != 0)
    {
        return std::nullopt;
    }
    if (physical_address > (std::numeric_limits<std::uint64_t>::max() - bytes))
    {
        return std::nullopt;
    }

    const auto required_blocks = bytes / block_bytes;
    if (required_blocks == 0)
    {
        return std::nullopt;
    }

    auto candidate_block = physical_address / block_bytes;
    const auto replay_checkpoint_blocks = ResolveReplayCheckpointBlockIndices();
    while (true)
    {
        if (candidate_block > (std::numeric_limits<std::uint64_t>::max() - (required_blocks - 1)))
        {
            return std::nullopt;
        }
        if (total_blocks_ != 0 &&
            (required_blocks > total_blocks_ || candidate_block > (total_blocks_ - required_blocks)))
        {
            return std::nullopt;
        }
        if (candidate_block > (std::numeric_limits<std::uint64_t>::max() / block_bytes))
        {
            return std::nullopt;
        }

        const auto candidate_address = candidate_block * block_bytes;
        if (!ExtentOverlapsReservedMetadata(candidate_address, bytes))
        {
            return candidate_address;
        }

        std::optional<std::uint64_t> next_candidate_block;
        for (std::uint64_t index = 0; index < required_blocks; ++index)
        {
            const auto block = candidate_block + index;
            if (IsReservedMetadataBlock(block) ||
                std::find(replay_checkpoint_blocks.begin(), replay_checkpoint_blocks.end(), block) != replay_checkpoint_blocks.end())
            {
                if (block == std::numeric_limits<std::uint64_t>::max())
                {
                    return std::nullopt;
                }
                next_candidate_block = block + 1;
                break;
            }
        }

        if (!next_candidate_block.has_value() || next_candidate_block.value() <= candidate_block)
        {
            return std::nullopt;
        }
        candidate_block = next_candidate_block.value();
    }
}

std::optional<std::uint64_t> MetadataStore::AdvancePastUnavailableExtent(
    std::uint64_t physical_address,
    std::uint64_t bytes) const
{
    if (physical_address == 0 || bytes == 0 || block_size_ == 0)
    {
        return std::nullopt;
    }

    const auto block_bytes = static_cast<std::uint64_t>(block_size_);
    if ((physical_address % block_bytes) != 0 || (bytes % block_bytes) != 0)
    {
        return std::nullopt;
    }

    auto candidate = physical_address;
    while (true)
    {
        if (candidate > (std::numeric_limits<std::uint64_t>::max() - bytes))
        {
            return std::nullopt;
        }
        if (total_blocks_ != 0)
        {
            if (total_blocks_ > (std::numeric_limits<std::uint64_t>::max() / block_bytes))
            {
                return std::nullopt;
            }
            const auto container_bytes = total_blocks_ * block_bytes;
            if ((candidate + bytes) > container_bytes)
            {
                return std::nullopt;
            }
        }

        if (ExtentOverlapsReservedMetadata(candidate, bytes))
        {
            const auto advanced = AdvancePastReservedMetadata(candidate, bytes);
            if (!advanced.has_value() || advanced.value() <= candidate)
            {
                return std::nullopt;
            }
            candidate = advanced.value();
            continue;
        }

        std::optional<std::uint64_t> next_candidate;
        const auto range_end = candidate + bytes;
        const auto consider_allocation = [&](const SpacemanAllocation& allocation)
        {
            if (allocation.physical_address == 0 || allocation.bytes == 0 ||
                allocation.physical_address > (std::numeric_limits<std::uint64_t>::max() - allocation.bytes))
            {
                return;
            }

            const auto allocation_end = allocation.physical_address + allocation.bytes;
            if (candidate < allocation_end && allocation.physical_address < range_end)
            {
                if (!next_candidate.has_value() || allocation_end < next_candidate.value())
                {
                    next_candidate = allocation_end;
                }
            }
        };

        for (const auto& allocation : committed_spaceman_allocations_)
        {
            consider_allocation(allocation);
        }
        for (const auto& allocation : pending_spaceman_allocations_)
        {
            consider_allocation(allocation);
        }

        if (!next_candidate.has_value())
        {
            return candidate;
        }
        if (next_candidate.value() <= candidate)
        {
            return std::nullopt;
        }
        candidate = next_candidate.value();
    }
}

bool MetadataStore::SanitizeWorkingFreeExtents()
{
    if (IsWorkingFreeExtentSanitizeCacheEnabled() && working_free_extents_sanitized_)
    {
        working_free_extent_sanitize_skip_count_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    working_free_extent_sanitize_count_.fetch_add(1, std::memory_order_relaxed);
    if (working_spaceman_free_extents_.empty())
    {
        working_free_extents_sanitized_ = true;
        return true;
    }

    std::vector<SpacemanAllocation> live_allocations;
    live_allocations.reserve(committed_spaceman_allocations_.size() + pending_spaceman_allocations_.size());
    live_allocations.insert(
        live_allocations.end(),
        committed_spaceman_allocations_.begin(),
        committed_spaceman_allocations_.end());
    live_allocations.insert(
        live_allocations.end(),
        pending_spaceman_allocations_.begin(),
        pending_spaceman_allocations_.end());

    if (!NormalizeSpacemanExtents(live_allocations))
    {
        return false;
    }
    if (!SubtractExtentsFromAllocations(live_allocations, pending_spaceman_deallocations_))
    {
        return false;
    }

    if (!SubtractAllocationsFromFreeExtents(working_spaceman_free_extents_, live_allocations))
    {
        return false;
    }

    working_free_extents_sanitized_ = true;
    return true;
}

bool MetadataStore::ValidateCommitBlobLocation(
    std::uint64_t physical_address,
    std::uint64_t bytes) const
{
    if (physical_address == 0 ||
        bytes < 64 ||
        bytes > (16ull * 1024ull * 1024ull))
    {
        return false;
    }

    const auto aligned_bytes = AlignExtentBytes(bytes);
    if (aligned_bytes == 0 ||
        aligned_bytes != bytes ||
        physical_address > (std::numeric_limits<std::uint64_t>::max() - aligned_bytes))
    {
        return false;
    }

    const auto block_bytes = static_cast<std::uint64_t>(std::max<std::uint32_t>(1u, block_size_));
    if ((physical_address % block_bytes) != 0 ||
        (aligned_bytes % block_bytes) != 0)
    {
        return false;
    }

    if (total_blocks_ != 0)
    {
        if (block_size_ == 0 ||
            total_blocks_ > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
        {
            return false;
        }

        const auto container_bytes = total_blocks_ * static_cast<std::uint64_t>(block_size_);
        if ((physical_address + aligned_bytes) > container_bytes)
        {
            return false;
        }
    }

    return !ExtentOverlapsReservedMetadata(physical_address, aligned_bytes);
}

bool MetadataStore::ValidateCommitExtentStage(
    std::uint64_t physical_address,
    std::uint64_t bytes) const
{
    if (!ValidateCommitBlobLocation(physical_address, bytes))
    {
        return false;
    }

    const auto aligned_bytes = AlignExtentBytes(bytes);
    const auto index_it = pending_spaceman_allocation_index_.find(physical_address);
    if (pending_spaceman_allocation_index_.size() != pending_spaceman_allocations_.size() ||
        index_it == pending_spaceman_allocation_index_.end() ||
        index_it->second >= pending_spaceman_allocations_.size())
    {
        return false;
    }

    const auto& staged = pending_spaceman_allocations_[index_it->second];
    if (staged.physical_address != physical_address ||
        staged.bytes != aligned_bytes)
    {
        return false;
    }

    const auto extent_end = physical_address + aligned_bytes;
    const auto overlaps_candidate = [&](const SpacemanAllocation& allocation)
    {
        if (allocation.bytes == 0 ||
            allocation.physical_address > (std::numeric_limits<std::uint64_t>::max() - allocation.bytes))
        {
            return true;
        }

        const auto allocation_end = allocation.physical_address + allocation.bytes;
        return physical_address < allocation_end && allocation.physical_address < extent_end;
    };

    for (const auto& allocation : committed_spaceman_allocations_)
    {
        if (overlaps_candidate(allocation))
        {
            return false;
        }
    }

    for (const auto& allocation : pending_spaceman_allocations_)
    {
        if (allocation.physical_address == physical_address &&
            allocation.bytes == aligned_bytes)
        {
            continue;
        }
        if (overlaps_candidate(allocation))
        {
            return false;
        }
    }

    for (const auto& free_extent : working_spaceman_free_extents_)
    {
        if (free_extent.bytes == 0 ||
            free_extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - free_extent.bytes))
        {
            return false;
        }

        const auto free_end = free_extent.physical_address + free_extent.bytes;
        if (physical_address < free_end && free_extent.physical_address < extent_end)
        {
            return false;
        }
    }

    commit_extent_fast_validation_count_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

bool MetadataStore::IsLegacyFixtureFallbackAllowedForCurrentContext() const noexcept
{
    return context_.allow_legacy_scaffold_for_fixtures &&
           IsFixtureImagePath(context_.device_path);
}

bool MetadataStore::RequiresCanonicalNonFixtureCommitPath() const noexcept
{
    if (IsFixtureImagePath(context_.device_path))
    {
        return false;
    }

    // All non-fixture media uses canonical commit/replay semantics. Fixture-only
    // compatibility controls must never relax production non-fixture safety paths.
    return true;
}

bool MetadataStore::CanLoadNativeCheckpointXid(std::uint64_t persisted_xid) const noexcept
{
    if (persisted_xid <= loaded_superblock_checkpoint_xid_)
    {
        return true;
    }

    if (replay_checkpoint_load_xid_.has_value())
    {
        return persisted_xid == replay_checkpoint_load_xid_.value();
    }

    if (IsLikelyRawDevicePath(context_.device_path))
    {
        return false;
    }

    if (!RequiresCanonicalNonFixtureCommitPath() ||
        loaded_superblock_checkpoint_xid_ == std::numeric_limits<std::uint64_t>::max())
    {
        return false;
    }

    return persisted_xid == (loaded_superblock_checkpoint_xid_ + 1);
}

bool MetadataStore::ShouldAcceptScaffoldCommitBlobForCurrentContext() const noexcept
{
    const auto is_fixture_image = IsFixtureImagePath(context_.device_path);
    if (!is_fixture_image)
    {
        // Legacy scaffold replay compatibility is fixture-only.
        return false;
    }

    if (!IsLegacyFixtureFallbackAllowedForCurrentContext())
    {
        return false;
    }

    // Fixture media keeps legacy scaffold replay compatibility to recover older
    // interrupted fixture commits during test/image migration workflows.
    return legacy_fixture_fallback_used_ || is_fixture_image;
}

bool MetadataStore::ShouldUseScaffoldCommitBlobForCurrentContext() const noexcept
{
    const auto is_fixture_image = IsFixtureImagePath(context_.device_path);
    if (!is_fixture_image)
    {
        // Non-fixture commits always emit canonical commit blobs. Relaxed
        // compatibility flags only affect replay acceptance for fixture/debug flows.
        return false;
    }

    return IsLegacyFixtureFallbackAllowedForCurrentContext() &&
           legacy_fixture_fallback_used_;
}

void MetadataStore::SyncCommitBlobTelemetryWithMode() noexcept
{
    uses_scaffold_commit_blob_ = ShouldUseScaffoldCommitBlobForCurrentContext();
    last_commit_blob_magic_ = uses_scaffold_commit_blob_
        ? "APFSRWSCAFF3"
        : "APFSRWCANON3";
}

bool MetadataStore::ValidateReplayCommitBlobCandidate(
    std::uint64_t physical_address,
    std::uint64_t bytes,
    std::uint64_t expected_source_xid,
    std::uint64_t expected_target_xid) const
{
    if (!ValidateCommitBlobLocation(physical_address, bytes))
    {
        return false;
    }

    std::vector<std::byte> commit_blob;
    if (!device_.Read(physical_address, static_cast<std::size_t>(bytes), commit_blob))
    {
        return false;
    }
    if (commit_blob.size() < static_cast<std::size_t>(bytes))
    {
        return false;
    }

    constexpr std::array<char, 13> kCommitBlobMagicCanonicalV3 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'C', 'A', 'N', 'O', 'N', '3', '\0'
    };
    constexpr std::array<char, 13> kCommitBlobMagicScaffoldV2 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '2', '\0'
    };
    constexpr std::array<char, 13> kCommitBlobMagicScaffoldV3 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '3', '\0'
    };
    constexpr std::size_t kCommitBlobBaseHeaderBytes = 13 + 8 + 8 + 4 + 4 + 4 + 4 + 4;
    constexpr std::size_t kCommitBlobChecksumFieldOffset = kCommitBlobBaseHeaderBytes;
    constexpr std::size_t kCommitBlobHeaderBytesV3 = kCommitBlobBaseHeaderBytes + sizeof(std::uint32_t);

    if (commit_blob.size() < kCommitBlobBaseHeaderBytes)
    {
        return false;
    }

    const auto matches_magic = [&](const std::array<char, 13>& magic) -> bool
    {
        for (std::size_t index = 0; index < magic.size(); ++index)
        {
            if (std::to_integer<unsigned char>(commit_blob[index]) != static_cast<unsigned char>(magic[index]))
            {
                return false;
            }
        }
        return true;
    };

    enum class CommitBlobMagicKind
    {
        Unknown,
        CanonicalV3,
        ScaffoldV3,
        ScaffoldV2,
    };
    const auto detected_magic = [&]() -> CommitBlobMagicKind
    {
        if (matches_magic(kCommitBlobMagicCanonicalV3))
        {
            return CommitBlobMagicKind::CanonicalV3;
        }
        if (matches_magic(kCommitBlobMagicScaffoldV3))
        {
            return CommitBlobMagicKind::ScaffoldV3;
        }
        if (matches_magic(kCommitBlobMagicScaffoldV2))
        {
            return CommitBlobMagicKind::ScaffoldV2;
        }
        return CommitBlobMagicKind::Unknown;
    }();
    if (detected_magic == CommitBlobMagicKind::Unknown)
    {
        return false;
    }
    const auto require_canonical_replay_candidate = RequiresCanonicalNonFixtureCommitPath();
    if (require_canonical_replay_candidate &&
        detected_magic != CommitBlobMagicKind::CanonicalV3)
    {
        return false;
    }
    const auto allow_scaffold_commit_blob = ShouldAcceptScaffoldCommitBlobForCurrentContext();
    if ((detected_magic == CommitBlobMagicKind::ScaffoldV3 ||
         detected_magic == CommitBlobMagicKind::ScaffoldV2) &&
        !allow_scaffold_commit_blob)
    {
        return false;
    }
    const bool commit_blob_has_checksum =
        detected_magic == CommitBlobMagicKind::CanonicalV3 ||
        detected_magic == CommitBlobMagicKind::ScaffoldV3;

    const auto commit_blob_header_bytes =
        commit_blob_has_checksum ? kCommitBlobHeaderBytesV3 : kCommitBlobBaseHeaderBytes;
    if (commit_blob.size() < commit_blob_header_bytes)
    {
        return false;
    }

    const auto source_xid = ReadLe64(commit_blob, 13);
    const auto target_xid = ReadLe64(commit_blob, 21);
    if (source_xid != expected_source_xid ||
        target_xid != expected_target_xid)
    {
        return false;
    }

    const auto mutation_count = ReadLe32(commit_blob, 29);
    const auto object_map_updates = ReadLe32(commit_blob, 33);
    const auto spaceman_allocations = ReadLe32(commit_blob, 37);
    const auto spaceman_deallocations = ReadLe32(commit_blob, 41);
    const auto btree_records = ReadLe32(commit_blob, 45);

    const auto mutation_component_total =
        static_cast<std::uint64_t>(object_map_updates) +
        static_cast<std::uint64_t>(spaceman_allocations) +
        static_cast<std::uint64_t>(spaceman_deallocations) +
        static_cast<std::uint64_t>(btree_records);
    if (mutation_count == 0 || mutation_component_total == 0 ||
        mutation_count > mutation_component_total)
    {
        return false;
    }

    const auto commit_blob_payload_checksum =
        commit_blob_has_checksum ? ReadLe32(commit_blob, kCommitBlobChecksumFieldOffset) : 0;
    const auto payload_capacity = static_cast<std::uint64_t>(commit_blob.size() - commit_blob_header_bytes);
    const auto checked_multiply = [](std::uint32_t value, std::uint64_t unit_bytes, std::uint64_t& out_bytes) -> bool
    {
        if (unit_bytes == 0)
        {
            out_bytes = 0;
            return true;
        }
        if (value > (std::numeric_limits<std::uint64_t>::max() / unit_bytes))
        {
            return false;
        }
        out_bytes = static_cast<std::uint64_t>(value) * unit_bytes;
        return true;
    };
    const auto checked_add = [](std::uint64_t lhs, std::uint64_t rhs, std::uint64_t& out_sum) -> bool
    {
        if (lhs > (std::numeric_limits<std::uint64_t>::max() - rhs))
        {
            return false;
        }
        out_sum = lhs + rhs;
        return true;
    };

    std::uint64_t object_map_min_bytes = 0;
    std::uint64_t spaceman_allocation_min_bytes = 0;
    std::uint64_t spaceman_deallocation_min_bytes = 0;
    std::uint64_t btree_min_bytes = 0;
    if (!checked_multiply(object_map_updates, 32ull, object_map_min_bytes) ||
        !checked_multiply(spaceman_allocations, 16ull, spaceman_allocation_min_bytes) ||
        !checked_multiply(spaceman_deallocations, 16ull, spaceman_deallocation_min_bytes) ||
        !checked_multiply(btree_records, 17ull, btree_min_bytes))
    {
        return false;
    }
    std::uint64_t minimum_payload_bytes = 0;
    if (!checked_add(object_map_min_bytes, spaceman_allocation_min_bytes, minimum_payload_bytes) ||
        !checked_add(minimum_payload_bytes, spaceman_deallocation_min_bytes, minimum_payload_bytes) ||
        !checked_add(minimum_payload_bytes, btree_min_bytes, minimum_payload_bytes))
    {
        return false;
    }
    if (minimum_payload_bytes > payload_capacity)
    {
        return false;
    }

    std::unordered_set<std::uint64_t> parsed_object_map_object_ids;
    struct ReplayExtent
    {
        std::uint64_t physical_address = 0;
        std::uint64_t bytes = 0;
    };
    std::vector<ReplayExtent> parsed_spaceman_allocations;
    std::vector<ReplayExtent> parsed_spaceman_deallocations;
    try
    {
        parsed_object_map_object_ids.reserve(object_map_updates);
        parsed_spaceman_allocations.reserve(spaceman_allocations);
        parsed_spaceman_deallocations.reserve(spaceman_deallocations);
    }
    catch (...)
    {
        return false;
    }

    std::size_t cursor = commit_blob_header_bytes;
    const auto advance = [&](std::uint64_t delta_bytes) -> bool
    {
        if (delta_bytes > (std::numeric_limits<std::size_t>::max() - cursor))
        {
            return false;
        }
        const auto next = cursor + static_cast<std::size_t>(delta_bytes);
        if (next > commit_blob.size())
        {
            return false;
        }
        cursor = next;
        return true;
    };

    for (std::uint32_t index = 0; index < object_map_updates; ++index)
    {
        if (cursor > commit_blob.size() || 32 > (commit_blob.size() - cursor))
        {
            return false;
        }
        const auto object_id = ReadLe64(commit_blob, cursor + 0);
        const auto object_physical = ReadLe64(commit_blob, cursor + 8);
        const auto object_logical = ReadLe64(commit_blob, cursor + 16);
        const auto object_xid = ReadLe64(commit_blob, cursor + 24);
        cursor += 32;
        if (object_id == 0 ||
            object_xid != expected_target_xid ||
            ((object_physical == 0) != (object_logical == 0)))
        {
            return false;
        }
        if (!parsed_object_map_object_ids.insert(object_id).second)
        {
            return false;
        }
    }

    for (std::uint32_t index = 0; index < spaceman_allocations; ++index)
    {
        if (cursor > commit_blob.size() || 16 > (commit_blob.size() - cursor))
        {
            return false;
        }
        const auto allocation_address = ReadLe64(commit_blob, cursor + 0);
        const auto allocation_bytes = ReadLe64(commit_blob, cursor + 8);
        cursor += 16;
        if (allocation_address == 0 || allocation_bytes == 0)
        {
            return false;
        }
        const auto aligned_bytes = AlignExtentBytes(allocation_bytes);
        if (aligned_bytes == 0 ||
            aligned_bytes != allocation_bytes ||
            ExtentOverlapsReservedMetadata(allocation_address, allocation_bytes))
        {
            return false;
        }
        parsed_spaceman_allocations.push_back({allocation_address, allocation_bytes});
    }

    for (std::uint32_t index = 0; index < spaceman_deallocations; ++index)
    {
        if (cursor > commit_blob.size() || 16 > (commit_blob.size() - cursor))
        {
            return false;
        }
        const auto deallocation_address = ReadLe64(commit_blob, cursor + 0);
        const auto deallocation_bytes = ReadLe64(commit_blob, cursor + 8);
        cursor += 16;
        if (deallocation_address == 0 || deallocation_bytes == 0)
        {
            return false;
        }
        const auto aligned_bytes = AlignExtentBytes(deallocation_bytes);
        if (aligned_bytes == 0 || aligned_bytes != deallocation_bytes)
        {
            return false;
        }
        parsed_spaceman_deallocations.push_back({deallocation_address, deallocation_bytes});
    }

    for (std::uint32_t index = 0; index < btree_records; ++index)
    {
        if (cursor > commit_blob.size() || 16 > (commit_blob.size() - cursor))
        {
            return false;
        }

        const auto kind_value = ReadLe32(commit_blob, cursor + 0);
        const auto tombstone_flag = ReadLe32(commit_blob, cursor + 4);
        const auto key_size = ReadLe32(commit_blob, cursor + 8);
        const auto value_size = ReadLe32(commit_blob, cursor + 12);
        cursor += 16;

        if (kind_value < static_cast<std::uint32_t>(BtreeRecordKind::Inode) ||
            kind_value > static_cast<std::uint32_t>(BtreeRecordKind::FileExtent) ||
            tombstone_flag > 1)
        {
            return false;
        }

        const auto payload_size = static_cast<std::uint64_t>(key_size) + static_cast<std::uint64_t>(value_size);
        const auto key_offset = cursor;
        if (!advance(payload_size))
        {
            return false;
        }
        if (key_size == 0)
        {
            return false;
        }
        if (std::to_integer<unsigned char>(commit_blob[key_offset]) != static_cast<unsigned char>(kind_value))
        {
            return false;
        }
    }

    const auto validate_no_overlap = [](std::vector<ReplayExtent>& extents) -> bool
    {
        if (extents.empty())
        {
            return true;
        }

        std::sort(
            extents.begin(),
            extents.end(),
            [](const ReplayExtent& lhs, const ReplayExtent& rhs)
            {
                if (lhs.physical_address == rhs.physical_address)
                {
                    return lhs.bytes < rhs.bytes;
                }
                return lhs.physical_address < rhs.physical_address;
            });

        std::optional<std::uint64_t> previous_end;
        for (const auto& extent : extents)
        {
            if (extent.physical_address == 0 || extent.bytes == 0)
            {
                return false;
            }
            if (extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
            {
                return false;
            }
            const auto extent_end = extent.physical_address + extent.bytes;
            if (previous_end.has_value() && extent.physical_address < previous_end.value())
            {
                return false;
            }
            previous_end = extent_end;
        }
        return true;
    };

    if (!validate_no_overlap(parsed_spaceman_allocations) ||
        !validate_no_overlap(parsed_spaceman_deallocations))
    {
        return false;
    }

    if (!parsed_spaceman_allocations.empty() && !parsed_spaceman_deallocations.empty())
    {
        std::size_t allocation_index = 0;
        std::size_t deallocation_index = 0;
        while (allocation_index < parsed_spaceman_allocations.size() &&
               deallocation_index < parsed_spaceman_deallocations.size())
        {
            const auto& allocation = parsed_spaceman_allocations[allocation_index];
            const auto& deallocation = parsed_spaceman_deallocations[deallocation_index];
            const auto allocation_end = allocation.physical_address + allocation.bytes;
            const auto deallocation_end = deallocation.physical_address + deallocation.bytes;

            if (allocation_end <= deallocation.physical_address)
            {
                ++allocation_index;
                continue;
            }
            if (deallocation_end <= allocation.physical_address)
            {
                ++deallocation_index;
                continue;
            }

            if (allocation.physical_address == deallocation.physical_address &&
                allocation.bytes == deallocation.bytes)
            {
                ++allocation_index;
                ++deallocation_index;
                continue;
            }

            if (allocation.physical_address < deallocation_end &&
                deallocation.physical_address < allocation_end)
            {
                return false;
            }
        }
    }

    if (commit_blob_has_checksum)
    {
        const auto payload_bytes = cursor - commit_blob_header_bytes;
        const auto computed_payload_checksum = UpdateFnv1a(
            kCheckpointChecksumSeed,
            commit_blob.data() + static_cast<std::vector<std::byte>::difference_type>(commit_blob_header_bytes),
            payload_bytes);
        if (commit_blob_payload_checksum != computed_payload_checksum)
        {
            return false;
        }
    }

    if (cursor > commit_blob.size())
    {
        return false;
    }
    for (std::size_t index = cursor; index < commit_blob.size(); ++index)
    {
        if (commit_blob[index] != std::byte{0})
        {
            return false;
        }
    }

    return true;
}

bool MetadataStore::ValidatePendingCommitState(
    bool validate_inode_graphs,
    bool validate_projected_btree_state) const
{
    const auto record_failure = [this](
        std::wstring_view reason,
        std::uint64_t object_id,
        std::wstring detail) -> bool
    {
        TracePendingCommitFailure(reason, object_id);
        last_commit_failure_reason_.assign(reason);
        last_commit_failure_detail_ = std::move(detail);
        last_commit_failure_object_id_ = object_id == 0
            ? std::nullopt
            : std::optional<std::uint64_t>(object_id);
        return false;
    };
    const auto fail_pending = [&](std::wstring_view reason, std::uint64_t object_id = 0) -> bool
    {
        return record_failure(reason, object_id, {});
    };

    if (pending_mutations_.empty())
    {
        return fail_pending(L"NoPendingMutations");
    }
    if (validate_inode_graphs)
    {
        if (!ValidateInodeGraphState(
                committed_inodes_,
                committed_path_index_,
                committed_directory_links_,
                /*require_root_object=*/true))
        {
            return fail_pending(L"CommittedInodeGraph");
        }
        if (!ValidateInodeGraphState(
                working_inodes_,
                working_path_index_,
                working_directory_links_,
                /*require_root_object=*/true))
        {
            return fail_pending(L"WorkingInodeGraph");
        }
    }

    std::optional<std::uint64_t> container_bytes;
    if (total_blocks_ != 0)
    {
        if (block_size_ == 0 ||
            total_blocks_ > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
        {
            return fail_pending(L"ContainerSizeOverflow");
        }
        container_bytes = total_blocks_ * static_cast<std::uint64_t>(block_size_);
    }

    const auto is_valid_extent = [this, &container_bytes](const SpacemanAllocation& extent) -> bool
    {
        if (extent.physical_address == 0 || extent.bytes == 0)
        {
            return false;
        }
        if (ExtentOverlapsReservedMetadata(extent.physical_address, extent.bytes))
        {
            return false;
        }
        if (AlignExtentBytes(extent.bytes) != extent.bytes)
        {
            return false;
        }
        if (extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
        {
            return false;
        }
        if (container_bytes.has_value() && (extent.physical_address + extent.bytes) > container_bytes.value())
        {
            return false;
        }
        return true;
    };

    const auto overlaps = [](const SpacemanAllocation& lhs, const SpacemanAllocation& rhs) -> bool
    {
        const auto lhs_begin = lhs.physical_address;
        const auto lhs_end = lhs.physical_address + lhs.bytes;
        const auto rhs_begin = rhs.physical_address;
        const auto rhs_end = rhs.physical_address + rhs.bytes;
        return lhs_begin < rhs_end && rhs_begin < lhs_end;
    };

    std::vector<SpacemanAllocation> sorted_committed_allocations_storage;
    const std::vector<SpacemanAllocation>* sorted_committed_allocations = &committed_spaceman_allocations_;
    bool pending_allocation_validation_can_use_sorted =
        SpacemanExtentsAreSortedNonOverlapping(committed_spaceman_allocations_);
    const bool committed_sorted_reused = pending_allocation_validation_can_use_sorted;
    if (!pending_allocation_validation_can_use_sorted)
    {
        sorted_committed_allocations_storage = committed_spaceman_allocations_;
        pending_allocation_validation_can_use_sorted =
            SortNonOverlappingSpacemanExtents(sorted_committed_allocations_storage);
        sorted_committed_allocations = &sorted_committed_allocations_storage;
    }

    std::map<std::uint64_t, std::uint64_t> committed_allocation_index;
    bool committed_allocation_index_built = false;
    bool committed_allocation_index_complete = false;
    const auto ensure_committed_allocation_index = [&]() -> bool
    {
        if (committed_allocation_index_built)
        {
            return committed_allocation_index_complete;
        }

        committed_allocation_index_built = true;
        committed_allocation_index_complete = true;
        pending_allocation_validation_committed_index_fallback_count_.fetch_add(1, std::memory_order_relaxed);
        for (const auto& allocation : committed_spaceman_allocations_)
        {
            if (!committed_allocation_index.emplace(allocation.physical_address, allocation.bytes).second)
            {
                committed_allocation_index_complete = false;
            }
        }
        return committed_allocation_index_complete;
    };

    const auto pending_allocation_contains_bytes = [&](std::uint64_t physical_address, std::uint64_t bytes) -> bool
    {
        if (physical_address == 0 || bytes == 0 ||
            physical_address > (std::numeric_limits<std::uint64_t>::max() - bytes) ||
            pending_spaceman_allocation_index_.size() != pending_spaceman_allocations_.size())
        {
            return false;
        }

        auto index_it = pending_spaceman_allocation_index_.upper_bound(physical_address);
        if (index_it == pending_spaceman_allocation_index_.begin())
        {
            return false;
        }
        --index_it;
        if (index_it->second >= pending_spaceman_allocations_.size())
        {
            return false;
        }

        const auto& allocation = pending_spaceman_allocations_[index_it->second];
        return allocation.physical_address == index_it->first &&
               PhysicalRangeContains(allocation.physical_address, allocation.bytes, physical_address, bytes);
    };

    const auto committed_allocation_contains_bytes = [&](std::uint64_t physical_address, std::uint64_t bytes) -> bool
    {
        if (physical_address == 0 || bytes == 0 ||
            physical_address > (std::numeric_limits<std::uint64_t>::max() - bytes))
        {
            return false;
        }

        if (pending_allocation_validation_can_use_sorted)
        {
            auto index_it = std::upper_bound(
                sorted_committed_allocations->begin(),
                sorted_committed_allocations->end(),
                physical_address,
                [](std::uint64_t physical_address, const SpacemanAllocation& candidate)
                {
                    return physical_address < candidate.physical_address;
                });
            if (index_it == sorted_committed_allocations->begin())
            {
                return false;
            }
            --index_it;
            return PhysicalRangeContains(
                index_it->physical_address,
                index_it->bytes,
                physical_address,
                bytes);
        }

        if (ensure_committed_allocation_index())
        {
            auto index_it = committed_allocation_index.upper_bound(physical_address);
            if (index_it == committed_allocation_index.begin())
            {
                return false;
            }
            --index_it;
            return PhysicalRangeContains(index_it->first, index_it->second, physical_address, bytes);
        }

        for (const auto& allocation : committed_spaceman_allocations_)
        {
            if (PhysicalRangeContains(allocation.physical_address, allocation.bytes, physical_address, bytes))
            {
                return true;
            }
        }
        return false;
    };

    const auto has_pending_allocation_for_physical = [&](std::uint64_t physical_address, std::uint64_t logical_size) -> bool
    {
        if (physical_address == 0 || logical_size == 0)
        {
            return false;
        }

        const auto required_bytes = AlignExtentBytes(logical_size);
        if (required_bytes == 0)
        {
            return false;
        }

        return pending_allocation_contains_bytes(physical_address, required_bytes);
    };
    const auto has_recovered_extent_coverage = [this](std::uint64_t physical_address, std::uint64_t logical_size) -> bool
    {
        if (!context_.allow_raw_physical_write ||
            physical_address == 0 ||
            logical_size == 0)
        {
            return false;
        }

        const auto required_bytes = AlignExtentBytes(logical_size);
        if (required_bytes == 0 ||
            physical_address > (std::numeric_limits<std::uint64_t>::max() - required_bytes))
        {
            return false;
        }

        for (const auto& [_, extents] : committed_read_extents_)
        {
            for (const auto& extent : extents)
            {
                if (ConservativePhysicalRangeContains(
                        extent.physical_address,
                        extent.bytes,
                        physical_address,
                        required_bytes,
                        block_size_))
                {
                    return true;
                }
            }
        }

        return false;
    };

    const auto has_committed_allocation_for_physical = [&](std::uint64_t physical_address, std::uint64_t logical_size) -> bool
    {
        if (physical_address == 0 || logical_size == 0)
        {
            return false;
        }

        const auto required_bytes = AlignExtentBytes(logical_size);
        if (required_bytes == 0)
        {
            return false;
        }

        return committed_allocation_contains_bytes(physical_address, required_bytes);
    };
    const auto has_allocation_for_physical = [&](std::uint64_t physical_address, std::uint64_t logical_size) -> bool
    {
        return has_pending_allocation_for_physical(physical_address, logical_size) ||
               has_committed_allocation_for_physical(physical_address, logical_size);
    };

    const auto describe_extent_coverage = [&](std::uint64_t physical_address, std::uint64_t extent_bytes)
    {
        const auto aligned_bytes = AlignExtentBytes(extent_bytes);
        const auto find_covering = [&](const std::vector<SpacemanAllocation>& allocations)
            -> std::optional<SpacemanAllocation>
        {
            for (const auto& allocation : allocations)
            {
                if (PhysicalRangeContains(
                        allocation.physical_address,
                        allocation.bytes,
                        physical_address,
                        aligned_bytes))
                {
                    return allocation;
                }
            }
            return std::nullopt;
        };
        const auto pending_cover = find_covering(pending_spaceman_allocations_);
        const auto committed_cover = find_covering(committed_spaceman_allocations_);
        const auto recovered_cover = [&]() -> std::optional<FileExtent>
        {
            for (const auto& [_, extents] : committed_read_extents_)
            {
                for (const auto& extent : extents)
                {
                    if (ConservativePhysicalRangeContains(
                            extent.physical_address,
                            extent.bytes,
                            physical_address,
                            aligned_bytes,
                            block_size_))
                    {
                        return extent;
                    }
                }
            }
            return std::nullopt;
        }();

        std::wstring detail = L"physical=" + std::to_wstring(physical_address) +
            L",extentBytes=" + std::to_wstring(extent_bytes) +
            L",alignedBytes=" + std::to_wstring(aligned_bytes) +
            L",pendingAllocations=" + std::to_wstring(pending_spaceman_allocations_.size()) +
            L",committedAllocations=" + std::to_wstring(committed_spaceman_allocations_.size()) +
            L",pendingExtentObjects=" + std::to_wstring(pending_read_extent_updates_.size()) +
            L",workingExtentObjects=" + std::to_wstring(working_read_extents_.size()) +
            L",recoveredExtentObjects=" + std::to_wstring(committed_read_extents_.size());
        const auto append_coverage = [&](std::wstring_view label, const auto& coverage)
        {
            detail.append(L",");
            detail.append(label);
            if (coverage.has_value())
            {
                detail.append(L"=");
                detail.append(std::to_wstring(coverage->physical_address));
                detail.append(L"/");
                detail.append(std::to_wstring(coverage->bytes));
            }
            else
            {
                detail.append(L"none");
            }
        };
        append_coverage(L"pendingCover", pending_cover);
        append_coverage(L"committedCover", committed_cover);
        append_coverage(L"recoveredCover", recovered_cover);
        return detail;
    };

    if (pending_object_map_update_index_.size() != pending_object_map_updates_.size())
    {
        return fail_pending(L"PendingObjectMapIndexMismatch");
    }
    for (std::size_t index = 0; index < pending_object_map_updates_.size(); ++index)
    {
        const auto& update = pending_object_map_updates_[index];
        if (update.object_id == 0 ||
            update.xid != checkpoint_xid_ + 1)
        {
            return fail_pending(L"PendingObjectMapInvalid", update.object_id);
        }

        const auto indexed_update = pending_object_map_update_index_.find(update.object_id);
        if (indexed_update == pending_object_map_update_index_.end() ||
            indexed_update->second != index)
        {
            return fail_pending(L"PendingObjectMapIndexMismatch", update.object_id);
        }
    }
    const bool fresh_ingest_overlay_preflight =
        !validate_inode_graphs &&
        !validate_projected_btree_state &&
        PendingMutationsCanSkipPreflightProjectedBtreeValidation();

    const auto pending_object_map_update_for = [&](std::uint64_t object_id) -> const ObjectMapUpdate*
    {
        const auto pending = pending_object_map_update_index_.find(object_id);
        if (pending == pending_object_map_update_index_.end())
        {
            return nullptr;
        }
        if (pending->second >= pending_object_map_updates_.size())
        {
            return nullptr;
        }
        commit_object_map_preflight_index_lookup_count_.fetch_add(1, std::memory_order_relaxed);
        return &pending_object_map_updates_[pending->second];
    };
    const auto effective_object_map_update_for = [&](std::uint64_t object_id) -> const ObjectMapUpdate*
    {
        if (const auto* pending = pending_object_map_update_for(object_id); pending != nullptr)
        {
            return HasPhysicalObjectMapping(*pending) ? pending : nullptr;
        }

        const auto committed = committed_object_map_.find(object_id);
        return committed == committed_object_map_.end() ? nullptr : &committed->second;
    };
    const auto effective_read_extents_for = [&](std::uint64_t object_id) -> const std::vector<FileExtent>*
    {
        const auto pending = pending_read_extent_updates_.find(object_id);
        if (pending != pending_read_extent_updates_.end())
        {
            return pending->second.empty() ? nullptr : &pending->second;
        }

        if (const auto* pending_object = pending_object_map_update_for(object_id);
            pending_object != nullptr &&
            !HasPhysicalObjectMapping(*pending_object))
        {
            return nullptr;
        }

        const auto committed = committed_read_extents_.find(object_id);
        return committed == committed_read_extents_.end() ? nullptr : &committed->second;
    };
    const auto append_object_map_entry = [](std::vector<ApfsObjectMapEntry>& entries, const ObjectMapUpdate& update)
    {
        if (!HasPhysicalObjectMapping(update))
        {
            return;
        }
        entries.push_back(
            {
                update.object_id,
                update.physical_address,
                update.logical_size,
                update.xid,
            });
    };

    const auto committed_read_extents_cover_inode =
        [&](std::uint64_t object_id, std::uint64_t physical_address, std::uint64_t logical_size) -> bool
    {
        if (object_id == 0 || physical_address == 0 || logical_size == 0)
        {
            return false;
        }

        const auto* extents_for_object = effective_read_extents_for(object_id);
        if (extents_for_object == nullptr)
        {
            return false;
        }

        const auto inode_it = working_inodes_.find(object_id);
        if (inode_it == working_inodes_.end() ||
            inode_it->second.is_directory ||
            inode_it->second.data_physical_address != physical_address ||
            inode_it->second.logical_size != logical_size)
        {
            return false;
        }

        const auto* extents = extents_for_object;
        if (!HasLogicalExtentCoverage(*extents, logical_size))
        {
            return false;
        }

        for (const auto& extent : *extents)
        {
            if (extent.physical_address == 0 || extent.bytes == 0)
            {
                continue;
            }
            if (!has_allocation_for_physical(extent.physical_address, extent.bytes) &&
                !has_recovered_extent_coverage(extent.physical_address, extent.bytes))
            {
                return false;
            }
        }

        return true;
    };
    const auto canonical_extents_for_inode = [&](const InodeRecord& inode) -> std::optional<std::vector<FileExtent>>
    {
        if (inode.is_directory ||
            inode.logical_size == 0 ||
            inode.data_physical_address == 0)
        {
            return std::nullopt;
        }

        const auto* extents_for_object = effective_read_extents_for(inode.object_id);
        if (extents_for_object == nullptr)
        {
            return std::vector<FileExtent>{ FileExtent{ 0, inode.data_physical_address, inode.logical_size } };
        }

        const auto* extents = extents_for_object;
        const auto has_pending_extent_update = pending_read_extent_updates_.contains(inode.object_id);
        if (HasLogicalExtentCoverage(*extents, inode.logical_size) &&
            !extents->empty() &&
            extents->front().logical_offset == 0 &&
            extents->front().physical_address == inode.data_physical_address)
        {
            return *extents;
        }

        if (has_pending_extent_update)
        {
            return std::nullopt;
        }

        return std::vector<FileExtent>{ FileExtent{ 0, inode.data_physical_address, inode.logical_size } };
    };
    const auto has_projection_only_read_coverage = [&](const InodeRecord& inode) -> bool
    {
        if (inode.is_directory ||
            inode.logical_size == 0 ||
            inode.data_physical_address != 0)
        {
            return false;
        }

        const auto* extents_for_object = effective_read_extents_for(inode.object_id);
        if (extents_for_object == nullptr)
        {
            return false;
        }

        const auto* extents = extents_for_object;
        std::uint64_t covered_until = 0;
        for (const auto& extent : *extents)
        {
            if (extent.bytes == 0 ||
                extent.logical_offset != covered_until ||
                extent.logical_offset > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
            {
                return false;
            }

            covered_until = extent.logical_offset + extent.bytes;
            if (covered_until >= inode.logical_size)
            {
                return true;
            }
        }

        return false;
    };

    if (fresh_ingest_overlay_preflight)
    {
        bool pending_physical_addresses_are_ordered = true;
        bool have_previous_pending_physical_address = false;
        std::uint64_t previous_pending_physical_address = 0;
        for (const auto& update : pending_object_map_updates_)
        {
            const auto object_id = update.object_id;
            if (!pending_close_delay_created_file_object_ids_.contains(object_id))
            {
                return fail_pending(L"FreshIngestObjectMapUnexpectedObject", object_id);
            }
            if (committed_object_map_.contains(object_id))
            {
                return fail_pending(L"FreshIngestObjectMapOverwritesCommitted", object_id);
            }
            if ((update.physical_address == 0) != (update.logical_size == 0))
            {
                return fail_pending(L"FreshIngestObjectMapInvalidMapping", object_id);
            }
            if (update.physical_address != 0 &&
                pending_physical_addresses_are_ordered &&
                have_previous_pending_physical_address &&
                update.physical_address <= previous_pending_physical_address)
            {
                pending_physical_addresses_are_ordered = false;
            }
            if (update.physical_address != 0)
            {
                previous_pending_physical_address = update.physical_address;
                have_previous_pending_physical_address = true;
            }
            if (HasPhysicalObjectMapping(update))
            {
                const auto inode_it = working_inodes_.find(object_id);
                const bool update_matches_working_inode =
                    inode_it != working_inodes_.end() &&
                    !inode_it->second.is_directory &&
                    inode_it->second.logical_size == update.logical_size &&
                    inode_it->second.data_physical_address == update.physical_address;
                if (!update_matches_working_inode)
                {
                    return fail_pending(L"FreshIngestObjectMapMissingExtentCoverage", object_id);
                }
                const auto canonical_extents = canonical_extents_for_inode(inode_it->second);
                if (!canonical_extents.has_value())
                {
                    return fail_pending(L"FreshIngestObjectMapMissingExtentCoverage", object_id);
                }
                for (const auto& extent : canonical_extents.value())
                {
                    if (extent.physical_address != 0 &&
                        extent.bytes != 0 &&
                        !has_pending_allocation_for_physical(extent.physical_address, extent.bytes) &&
                        !has_recovered_extent_coverage(extent.physical_address, extent.bytes))
                    {
                        return fail_pending(L"FreshIngestObjectMapMissingAllocation", object_id);
                    }
                }
            }
        }
        if (pending_physical_addresses_are_ordered)
        {
            commit_fresh_ingest_physical_order_fast_path_count_.fetch_add(1, std::memory_order_relaxed);
        }
        else
        {
            std::unordered_set<std::uint64_t> pending_physical_addresses;
            pending_physical_addresses.reserve(pending_object_map_updates_.size());
            for (const auto& update : pending_object_map_updates_)
            {
                if (update.physical_address != 0 &&
                    !pending_physical_addresses.insert(update.physical_address).second)
                {
                    return fail_pending(L"FreshIngestObjectMapDuplicatePhysical", update.object_id);
                }
            }
            commit_fresh_ingest_physical_set_fallback_count_.fetch_add(1, std::memory_order_relaxed);
        }
        commit_fresh_ingest_overlay_preflight_count_.fetch_add(1, std::memory_order_relaxed);
    }
    else
    {
        std::vector<ApfsObjectMapEntry> effective_object_entries;
        effective_object_entries.reserve(
            committed_object_map_.size() + pending_object_map_updates_.size());
        for (const auto& [object_id, update] : committed_object_map_)
        {
            if (pending_object_map_update_for(object_id) != nullptr)
            {
                continue;
            }
            append_object_map_entry(effective_object_entries, update);
        }
        for (const auto& update : pending_object_map_updates_)
        {
            append_object_map_entry(effective_object_entries, update);
        }
        ApfsObjectMapStore object_map_store;
        if (!object_map_store.ValidateEntries(effective_object_entries))
        {
            return fail_pending(L"ObjectMapValidateEntries");
        }
    }

    if (pending_spaceman_allocation_index_.size() != pending_spaceman_allocations_.size())
    {
        return fail_pending(L"PendingAllocationIndexMismatch");
    }
    for (const auto& [physical_address, index] : pending_spaceman_allocation_index_)
    {
        if (index >= pending_spaceman_allocations_.size() ||
            pending_spaceman_allocations_[index].physical_address != physical_address)
        {
            return fail_pending(L"PendingAllocationIndexMismatch", physical_address);
        }
    }

    bool pending_allocations_are_sorted = true;
    bool have_previous_pending_allocation = false;
    std::uint64_t previous_pending_allocation_end = 0;

    for (const auto& allocation : pending_spaceman_allocations_)
    {
        if (!is_valid_extent(allocation))
        {
            return fail_pending(L"PendingAllocationInvalid", allocation.physical_address);
        }
        const auto allocation_end = allocation.physical_address + allocation.bytes;
        if (have_previous_pending_allocation &&
            allocation.physical_address < previous_pending_allocation_end)
        {
            pending_allocations_are_sorted = false;
        }
        previous_pending_allocation_end = allocation_end;
        have_previous_pending_allocation = true;
    }

    const std::vector<SpacemanAllocation>* sorted_pending_allocations = &pending_spaceman_allocations_;
    bool use_pending_allocation_index_order = false;
    if (pending_allocations_are_sorted)
    {
        pending_allocation_validation_pending_sorted_reuse_count_.fetch_add(1, std::memory_order_relaxed);
    }
    else
    {
        use_pending_allocation_index_order = true;
        pending_allocation_validation_pending_index_reuse_count_.fetch_add(1, std::memory_order_relaxed);
    }

    const auto indexed_pending_allocation_at =
        [&](std::map<std::uint64_t, std::size_t>::const_iterator index_it) -> const SpacemanAllocation&
    {
        return pending_spaceman_allocations_[index_it->second];
    };
    const auto validate_sorted_pending_allocation =
        [&](const SpacemanAllocation& allocation, const SpacemanAllocation* previous_allocation) -> bool
    {
        if (RangeOverlapsSorted(*sorted_committed_allocations, allocation))
        {
            return fail_pending(L"PendingAllocationOverlapsCommitted", allocation.physical_address);
        }
        if (previous_allocation != nullptr && overlaps(*previous_allocation, allocation))
        {
            return fail_pending(L"PendingAllocationOverlap", allocation.physical_address);
        }

        return true;
    };

    if (pending_allocation_validation_can_use_sorted)
    {
        const SpacemanAllocation* previous_allocation = nullptr;
        if (use_pending_allocation_index_order)
        {
            for (auto index_it = pending_spaceman_allocation_index_.begin();
                 index_it != pending_spaceman_allocation_index_.end();
                 ++index_it)
            {
                const auto& allocation = indexed_pending_allocation_at(index_it);
                if (!validate_sorted_pending_allocation(allocation, previous_allocation))
                {
                    return false;
                }
                previous_allocation = &allocation;
            }
        }
        else
        {
            for (const auto& allocation : *sorted_pending_allocations)
            {
                if (!validate_sorted_pending_allocation(allocation, previous_allocation))
                {
                    return false;
                }
                previous_allocation = &allocation;
            }
        }

        pending_allocation_validation_sorted_count_.fetch_add(1, std::memory_order_relaxed);
        if (committed_sorted_reused)
        {
            pending_allocation_validation_committed_sorted_reuse_count_.fetch_add(1, std::memory_order_relaxed);
        }
    }
    else
    {
        pending_allocation_validation_fallback_scan_count_.fetch_add(1, std::memory_order_relaxed);
        for (const auto& allocation : pending_spaceman_allocations_)
        {
            for (const auto& committed_allocation : committed_spaceman_allocations_)
            {
                if (overlaps(allocation, committed_allocation))
                {
                    return fail_pending(L"PendingAllocationOverlapsCommitted", allocation.physical_address);
                }
            }
        }
        for (std::size_t i = 0; i < pending_spaceman_allocations_.size(); ++i)
        {
            for (std::size_t j = i + 1; j < pending_spaceman_allocations_.size(); ++j)
            {
                if (overlaps(pending_spaceman_allocations_[i], pending_spaceman_allocations_[j]))
                {
                    return fail_pending(L"PendingAllocationOverlap", pending_spaceman_allocations_[i].physical_address);
                }
            }
        }
    }

    for (const auto& deallocation : pending_spaceman_deallocations_)
    {
        if (deallocation.physical_address == 0 ||
            deallocation.bytes == 0 ||
            deallocation.physical_address > (std::numeric_limits<std::uint64_t>::max() - deallocation.bytes))
        {
            continue;
        }

        const auto deallocation_end = deallocation.physical_address + deallocation.bytes;
        const auto validate_deallocation_overlap = [&](const SpacemanAllocation& allocation) -> std::optional<bool>
        {
            if (allocation.physical_address >= deallocation_end)
            {
                return true;
            }
            if (!overlaps(allocation, deallocation))
            {
                return std::nullopt;
            }
            if (allocation.physical_address == deallocation.physical_address &&
                allocation.bytes == deallocation.bytes)
            {
                return std::nullopt;
            }

            return fail_pending(L"PendingAllocationDeallocationPartialOverlap", allocation.physical_address);
        };

        if (use_pending_allocation_index_order)
        {
            auto allocation_it = pending_spaceman_allocation_index_.lower_bound(deallocation.physical_address);
            if (allocation_it != pending_spaceman_allocation_index_.begin())
            {
                --allocation_it;
            }

            for (; allocation_it != pending_spaceman_allocation_index_.end(); ++allocation_it)
            {
                const auto result = validate_deallocation_overlap(indexed_pending_allocation_at(allocation_it));
                if (result.has_value())
                {
                    if (!result.value())
                    {
                        return false;
                    }
                    break;
                }
            }
        }
        else
        {
            auto allocation_it = std::lower_bound(
                sorted_pending_allocations->begin(),
                sorted_pending_allocations->end(),
                deallocation.physical_address,
                [](const SpacemanAllocation& candidate, std::uint64_t physical_address)
                {
                    return candidate.physical_address < physical_address;
                });
            if (allocation_it != sorted_pending_allocations->begin())
            {
                --allocation_it;
            }

            for (; allocation_it != sorted_pending_allocations->end(); ++allocation_it)
            {
                const auto result = validate_deallocation_overlap(*allocation_it);
                if (result.has_value())
                {
                    if (!result.value())
                    {
                        return false;
                    }
                    break;
                }
            }
        }
    }

    std::set<std::uint64_t> live_extent_addresses;
    if (!fresh_ingest_overlay_preflight)
    {
        for (const auto& [object_id, inode] : working_inodes_)
        {
            if (inode.is_directory ||
                inode.data_physical_address == 0 ||
                inode.logical_size == 0)
            {
                continue;
            }

            const auto* mapped = effective_object_map_update_for(object_id);
            if (mapped == nullptr)
            {
                return fail_pending(L"LiveExtentMissingObjectMap", object_id);
            }
            if (mapped->physical_address != inode.data_physical_address ||
                mapped->logical_size != inode.logical_size)
            {
                return fail_pending(L"LiveExtentObjectMapMismatch", object_id);
            }
            auto live_extents = canonical_extents_for_inode(inode);
            if (!live_extents.has_value())
            {
                return fail_pending(L"LiveExtentCoverageInvalid", object_id);
            }

            for (const auto& extent : live_extents.value())
            {
                if (!has_allocation_for_physical(extent.physical_address, extent.bytes) &&
                    !has_recovered_extent_coverage(extent.physical_address, extent.bytes))
                {
                    return record_failure(
                        L"LiveExtentMissingAllocation",
                        object_id,
                        describe_extent_coverage(extent.physical_address, extent.bytes));
                }

                live_extent_addresses.insert(extent.physical_address);
            }
        }
    }

    const auto validate_effective_object_mapping = [&](const ObjectMapUpdate& update) -> bool
    {
        if (update.physical_address == 0 || update.logical_size == 0)
        {
            return true;
        }
        const auto committed_it = committed_object_map_.find(update.object_id);
        const auto update_matches_committed =
            committed_it != committed_object_map_.end() &&
            committed_it->second.physical_address == update.physical_address &&
            committed_it->second.logical_size == update.logical_size;
        if (update_matches_committed)
        {
            if (!has_committed_allocation_for_physical(update.physical_address, update.logical_size) &&
                !committed_read_extents_cover_inode(update.object_id, update.physical_address, update.logical_size) &&
                !has_recovered_extent_coverage(update.physical_address, update.logical_size))
            {
                return fail_pending(L"ObjectMapMissingCommittedAllocation", update.object_id);
            }
        }
        else
        {
            auto inode_it = working_inodes_.find(update.object_id);
            const auto read_extents_cover_update =
                inode_it != working_inodes_.end() &&
                !inode_it->second.is_directory &&
                inode_it->second.logical_size == update.logical_size &&
                inode_it->second.data_physical_address == update.physical_address &&
                canonical_extents_for_inode(inode_it->second).has_value();
            if (!read_extents_cover_update &&
                !has_pending_allocation_for_physical(update.physical_address, update.logical_size) &&
                !has_recovered_extent_coverage(update.physical_address, update.logical_size))
            {
                return fail_pending(L"ObjectMapMissingAllocation", update.object_id);
            }
        }

        return true;
    };
    if (fresh_ingest_overlay_preflight)
    {
        commit_fresh_ingest_mapping_recheck_skip_count_.fetch_add(1, std::memory_order_relaxed);
    }
    else
    {
        commit_full_object_preflight_sweep_count_.fetch_add(1, std::memory_order_relaxed);
        for (const auto& [object_id, update] : committed_object_map_)
        {
            if (pending_object_map_update_for(object_id) != nullptr)
            {
                continue;
            }
            if (!validate_effective_object_mapping(update))
            {
                return false;
            }
        }
        for (const auto& update : pending_object_map_updates_)
        {
            if (!validate_effective_object_mapping(update))
            {
                return false;
            }
        }
    }

    std::set<std::pair<std::uint64_t, std::uint64_t>> seen_deallocations;
    for (const auto& deallocation : pending_spaceman_deallocations_)
    {
        if (!is_valid_extent(deallocation))
        {
            return fail_pending(L"PendingDeallocationInvalid", deallocation.physical_address);
        }
        if (!seen_deallocations.emplace(deallocation.physical_address, deallocation.bytes).second)
        {
            return fail_pending(L"PendingDeallocationDuplicate", deallocation.physical_address);
        }
        if (live_extent_addresses.contains(deallocation.physical_address))
        {
            return fail_pending(L"PendingDeallocationStillLive", deallocation.physical_address);
        }

        bool matched = committed_allocation_contains_bytes(deallocation.physical_address, deallocation.bytes);
        if (!matched)
        {
            for (const auto& allocation : pending_spaceman_allocations_)
            {
                if (allocation.physical_address == deallocation.physical_address &&
                    allocation.bytes == deallocation.bytes)
                {
                    matched = true;
                    break;
                }
            }
        }
        if (!matched)
        {
            if (has_recovered_extent_coverage(deallocation.physical_address, deallocation.bytes))
            {
                matched = true;
            }
        }
        if (!matched)
        {
            return fail_pending(L"DeallocationMissingSourceAllocation", deallocation.physical_address);
        }
    }

    const auto validate_free_extents_do_not_overlap_allocations =
        [&](const std::vector<SpacemanAllocation>& free_extents) -> bool
    {
        const auto is_valid_spaceman_state_extent = [](const SpacemanAllocation& extent) noexcept -> bool
        {
            return extent.physical_address != 0 &&
                   extent.bytes != 0 &&
                   extent.physical_address <= (std::numeric_limits<std::uint64_t>::max() - extent.bytes);
        };

        for (const auto& free_extent : free_extents)
        {
            if (!is_valid_spaceman_state_extent(free_extent))
            {
                return fail_pending(L"ProjectedSpacemanInvalid", free_extent.physical_address);
            }
            if (RangeOverlapsSorted(*sorted_committed_allocations, free_extent))
            {
                return fail_pending(L"ProjectedSpacemanInvalid", free_extent.physical_address);
            }
            if (use_pending_allocation_index_order)
            {
                auto allocation_it = pending_spaceman_allocation_index_.lower_bound(free_extent.physical_address);
                if (allocation_it != pending_spaceman_allocation_index_.begin())
                {
                    --allocation_it;
                }

                for (; allocation_it != pending_spaceman_allocation_index_.end(); ++allocation_it)
                {
                    const auto& allocation = indexed_pending_allocation_at(allocation_it);
                    if (allocation.physical_address >= free_extent.physical_address + free_extent.bytes)
                    {
                        break;
                    }
                    if (overlaps(allocation, free_extent))
                    {
                        return fail_pending(L"ProjectedSpacemanInvalid", free_extent.physical_address);
                    }
                }
            }
            else if (RangeOverlapsSorted(*sorted_pending_allocations, free_extent))
            {
                return fail_pending(L"ProjectedSpacemanInvalid", free_extent.physical_address);
            }
        }

        return true;
    };

    const auto can_use_projected_spaceman_fast_path =
        pending_spaceman_deallocations_.empty() &&
        pending_allocation_validation_can_use_sorted &&
        SpacemanExtentsAreSortedNonOverlapping(working_spaceman_free_extents_);
    if (can_use_projected_spaceman_fast_path)
    {
        if (!validate_free_extents_do_not_overlap_allocations(working_spaceman_free_extents_))
        {
            return false;
        }
        projected_spaceman_validation_fast_count_.fetch_add(1, std::memory_order_relaxed);
    }
    else
    {
        auto projected_spaceman_allocations = committed_spaceman_allocations_;
        projected_spaceman_allocations.insert(
            projected_spaceman_allocations.end(),
            pending_spaceman_allocations_.begin(),
            pending_spaceman_allocations_.end());
        if (!SubtractExtentsFromAllocations(projected_spaceman_allocations, pending_spaceman_deallocations_))
        {
            return fail_pending(L"ProjectedAllocationDeallocationInvalid");
        }

        std::vector<ApfsExtent> projected_allocations;
        projected_allocations.reserve(projected_spaceman_allocations.size());
        for (const auto& allocation : projected_spaceman_allocations)
        {
            projected_allocations.push_back(
                {
                    allocation.physical_address,
                    allocation.bytes,
                });
        }

        std::vector<ApfsExtent> projected_free_extents;
        projected_free_extents.reserve(working_spaceman_free_extents_.size());
        for (const auto& extent : working_spaceman_free_extents_)
        {
            projected_free_extents.push_back(
                {
                    extent.physical_address,
                    extent.bytes,
                });
        }

        ApfsSpacemanStore spaceman_store;
        if (!spaceman_store.ValidateState(projected_allocations, projected_free_extents))
        {
            return fail_pending(L"ProjectedSpacemanInvalid");
        }
        projected_spaceman_validation_full_count_.fetch_add(1, std::memory_order_relaxed);
    }

    for (const auto& record : pending_btree_records_)
    {
        if (record.key.empty() ||
            record.kind < BtreeRecordKind::Inode ||
            record.kind > BtreeRecordKind::FileExtent)
        {
            return fail_pending(L"PendingBtreeRecordInvalidKind");
        }
        if (std::to_integer<unsigned char>(record.key.front()) != static_cast<unsigned char>(record.kind))
        {
            return fail_pending(L"PendingBtreeRecordKindPrefix");
        }
    }

    if (!validate_projected_btree_state)
    {
        if (!PendingMutationsCanSkipPreflightProjectedBtreeValidation())
        {
            return fail_pending(L"ProjectedBtreeFastPathUnsafe");
        }

        return true;
    }

    auto projected_btree_records = committed_btree_records_;
    if (!ApplyBtreeRecordDeltas(projected_btree_records, pending_btree_records_))
    {
        return fail_pending(L"ProjectedBtreeDeltaApplyFailed");
    }

    std::size_t expected_non_root_inode_count = 0;
    std::size_t expected_extent_count = 0;
    for (const auto& [_, inode] : working_inodes_)
    {
        if (IsRootPath(inode.full_path))
        {
            continue;
        }

        ++expected_non_root_inode_count;
        if (!inode.is_directory &&
            inode.logical_size > 0)
        {
            if (auto canonical_extents = canonical_extents_for_inode(inode);
                canonical_extents.has_value())
            {
                expected_extent_count += canonical_extents->size();
            }
        }
    }

    ApfsVolumeTreeStore volume_tree_store;
    ApfsVolumeTreeProjection volume_tree_projection{};
    std::wstring volume_tree_error;
    if (!volume_tree_store.TryProjectFromBtreeRecords(
            projected_btree_records,
            volume_tree_projection,
            volume_tree_error))
    {
        return fail_pending(volume_tree_error.empty() ? L"ProjectedVolumeTreeInvalid" : volume_tree_error);
    }
    const auto count_mismatch_reason = [](std::wstring_view label, std::size_t actual, std::size_t expected)
    {
        std::wstring reason(L"ProjectedVolumeTree");
        reason.append(label);
        reason.append(L"CountMismatch:");
        reason.append(std::to_wstring(actual));
        reason.push_back(L'/');
        reason.append(std::to_wstring(expected));
        return reason;
    };
    if (volume_tree_projection.inode_record_count != expected_non_root_inode_count)
    {
        return fail_pending(count_mismatch_reason(
            L"Inode",
            volume_tree_projection.inode_record_count,
            expected_non_root_inode_count));
    }
    if (volume_tree_projection.directory_entry_record_count != working_directory_links_.size())
    {
        return fail_pending(count_mismatch_reason(
            L"Directory",
            volume_tree_projection.directory_entry_record_count,
            working_directory_links_.size()));
    }
    if (volume_tree_projection.extent_record_count != expected_extent_count)
    {
        return fail_pending(count_mismatch_reason(
            L"Extent",
            volume_tree_projection.extent_record_count,
            expected_extent_count));
    }

    std::unordered_set<std::string> projected_btree_keys;
    projected_btree_keys.reserve(projected_btree_records.size());
    for (const auto& record : projected_btree_records)
    {
        if (record.key.empty() ||
            record.kind < BtreeRecordKind::Inode ||
            record.kind > BtreeRecordKind::FileExtent)
        {
            return fail_pending(L"ProjectedBtreeRecordInvalidKind");
        }
        if (std::to_integer<unsigned char>(record.key.front()) != static_cast<unsigned char>(record.kind))
        {
            return fail_pending(L"ProjectedBtreeRecordKindPrefix");
        }

        auto key_blob = BuildBtreeKeyBlob(record.key);
        if (key_blob.empty() || !projected_btree_keys.insert(std::move(key_blob)).second)
        {
            return fail_pending(L"ProjectedBtreeDuplicateKey");
        }
    }

    const auto target_xid = checkpoint_xid_ + 1;
    std::unordered_set<std::string> expected_btree_keys;
    expected_btree_keys.reserve(
        working_inodes_.size() +
        working_directory_links_.size() +
        working_inodes_.size());

    for (const auto& [object_id, inode] : working_inodes_)
    {
        if (IsRootPath(inode.full_path))
        {
            continue;
        }

        auto inode_key_record = BtreeMutationCodec::EncodeInodeRecord(
            object_id,
            inode.parent_object_id,
            inode.name,
            inode.is_directory,
            inode.logical_size,
            inode.data_physical_address,
            inode.timestamp_utc,
            target_xid,
            false);
        auto inode_key = BuildBtreeKeyBlob(inode_key_record.key);
        if (inode_key.empty() || !expected_btree_keys.insert(std::move(inode_key)).second)
        {
            return fail_pending(L"ExpectedBtreeInodeDuplicate", object_id);
        }

        if (!inode.is_directory &&
            inode.logical_size > 0)
        {
            auto expected_extents = canonical_extents_for_inode(inode);
            if (!expected_extents.has_value())
            {
                if (has_projection_only_read_coverage(inode))
                {
                    continue;
                }
                return fail_pending(L"ExpectedBtreeExtentCoverage", object_id);
            }

            for (const auto& extent : expected_extents.value())
            {
                auto extent_key_record = BtreeMutationCodec::EncodeExtentRecord(
                    object_id,
                    extent.logical_offset,
                    extent.physical_address,
                    extent.bytes,
                    target_xid,
                    false);
                auto extent_key = BuildBtreeKeyBlob(extent_key_record.key);
                if (extent_key.empty() || !expected_btree_keys.insert(std::move(extent_key)).second)
                {
                    return fail_pending(L"ExpectedBtreeExtentDuplicate", object_id);
                }
            }
        }
    }

    for (const auto& link : working_directory_links_)
    {
        auto directory_key_record = BtreeMutationCodec::EncodeDirectoryRecord(
            link.parent_object_id,
            link.entry_name,
            link.child_object_id,
            target_xid,
            false);
        auto directory_key = BuildBtreeKeyBlob(directory_key_record.key);
        if (directory_key.empty() || !expected_btree_keys.insert(std::move(directory_key)).second)
        {
            return fail_pending(L"ExpectedBtreeDirectoryDuplicate", link.child_object_id);
        }
    }

    if (projected_btree_keys.size() != expected_btree_keys.size())
    {
        return fail_pending(L"ProjectedBtreeSizeMismatch");
    }
    for (const auto& expected_key : expected_btree_keys)
    {
        if (!projected_btree_keys.contains(expected_key))
        {
            return fail_pending(L"ProjectedBtreeMissingExpectedKey");
        }
    }

    std::unordered_map<std::uint64_t, DecodedBtreeInode> decoded_inodes_by_object;
    std::unordered_map<std::wstring, DecodedBtreeDirectoryEntry> decoded_directory_entries;
    std::unordered_map<std::uint64_t, std::vector<DecodedBtreeExtent>> decoded_extents_by_object;
    decoded_inodes_by_object.reserve(projected_btree_records.size());
    decoded_directory_entries.reserve(projected_btree_records.size());
    decoded_extents_by_object.reserve(projected_btree_records.size());

    for (const auto& record : projected_btree_records)
    {
        if (record.tombstone)
        {
            return fail_pending(L"ProjectedBtreeTombstone");
        }

        switch (record.kind)
        {
        case BtreeRecordKind::Inode:
        {
            DecodedBtreeInode decoded{};
            if (!DecodeBtreeInodeRecord(record, decoded))
            {
                return fail_pending(L"ProjectedBtreeDecodeInode");
            }
            if (!decoded_inodes_by_object.emplace(decoded.object_id, std::move(decoded)).second)
            {
                return fail_pending(L"ProjectedBtreeDuplicateInode", decoded.object_id);
            }
            break;
        }
        case BtreeRecordKind::DirectoryEntry:
        {
            DecodedBtreeDirectoryEntry decoded{};
            if (!DecodeBtreeDirectoryRecord(record, decoded))
            {
                return fail_pending(L"ProjectedBtreeDecodeDirectory");
            }
            auto key = BuildDirectoryEntryIndexKey(decoded.parent_object_id, decoded.entry_name);
            if (!decoded_directory_entries.emplace(std::move(key), std::move(decoded)).second)
            {
                return fail_pending(L"ProjectedBtreeDuplicateDirectory", decoded.child_object_id);
            }
            break;
        }
        case BtreeRecordKind::FileExtent:
        {
            DecodedBtreeExtent decoded{};
            if (!DecodeBtreeExtentRecord(record, decoded))
            {
                return fail_pending(L"ProjectedBtreeDecodeExtent");
            }
            decoded_extents_by_object[decoded.object_id].push_back(std::move(decoded));
            break;
        }
        default:
            return fail_pending(L"ProjectedBtreeUnknownKind");
        }
    }

    if (decoded_inodes_by_object.size() != expected_non_root_inode_count)
    {
        return fail_pending(L"ProjectedBtreeInodeCountMismatch");
    }

    for (const auto& [object_id, inode] : working_inodes_)
    {
        if (IsRootPath(inode.full_path))
        {
            continue;
        }

        auto decoded_it = decoded_inodes_by_object.find(object_id);
        if (decoded_it == decoded_inodes_by_object.end())
        {
            return fail_pending(L"ProjectedBtreeMissingDecodedInode", object_id);
        }
        const auto& decoded = decoded_it->second;
        if (decoded.parent_object_id != inode.parent_object_id ||
            decoded.is_directory != inode.is_directory ||
            decoded.logical_size != inode.logical_size ||
            decoded.data_physical_address != inode.data_physical_address ||
            decoded.name != inode.name)
        {
            return fail_pending(L"ProjectedBtreeDecodedInodeMismatch", object_id);
        }
        if (decoded.xid == 0 || decoded.xid > target_xid)
        {
            return fail_pending(L"ProjectedBtreeDecodedInodeXid", object_id);
        }
        if (decoded.parent_object_id == 0 || !working_inodes_.contains(decoded.parent_object_id))
        {
            return fail_pending(L"ProjectedBtreeDecodedParentMissing", object_id);
        }
        if (auto parent_it = working_inodes_.find(decoded.parent_object_id);
            parent_it == working_inodes_.end() || !parent_it->second.is_directory)
        {
            return fail_pending(L"ProjectedBtreeDecodedParentNotDirectory", object_id);
        }

        if (inode.is_directory || inode.logical_size == 0)
        {
            if (decoded_extents_by_object.contains(object_id) ||
                (!inode.is_directory &&
                 inode.logical_size > 0 &&
                 inode.data_physical_address == 0 &&
                 effective_read_extents_for(object_id) == nullptr))
            {
                return fail_pending(L"ProjectedBtreeUnexpectedOrMissingExtent", object_id);
            }
        }
        else
        {
            if (has_projection_only_read_coverage(inode))
            {
                if (decoded_extents_by_object.contains(object_id))
                {
                    return fail_pending(L"ProjectedBtreeUnexpectedProjectionExtent", object_id);
                }
                continue;
            }

            auto extent_it = decoded_extents_by_object.find(object_id);
            if (extent_it == decoded_extents_by_object.end())
            {
                return fail_pending(L"ProjectedBtreeMissingExtent", object_id);
            }
            if (auto canonical_extents = canonical_extents_for_inode(inode);
                canonical_extents.has_value())
            {
                if (!ExtentsMatchDecodedBtreeExtents(
                    canonical_extents.value(),
                    extent_it->second,
                    inode.logical_size,
                    inode.data_physical_address,
                    target_xid))
                {
                    TraceExtentMismatchDetail(
                        object_id,
                        canonical_extents.value(),
                        extent_it->second,
                        inode.logical_size,
                        inode.data_physical_address,
                        target_xid);
                    return fail_pending(L"ProjectedBtreeExtentMismatch", object_id);
                }
            }
            else
            {
                return fail_pending(L"ProjectedBtreeExtentMismatch", object_id);
            }

            const auto* mapped = effective_object_map_update_for(object_id);
            if (mapped == nullptr)
            {
                return fail_pending(L"ProjectedBtreeMissingObjectMap", object_id);
            }
            if (mapped->physical_address != inode.data_physical_address ||
                mapped->logical_size != inode.logical_size)
            {
                return fail_pending(L"ProjectedBtreeObjectMapMismatch", object_id);
            }
        }
    }

    if (decoded_directory_entries.size() != working_directory_links_.size())
    {
        return fail_pending(L"ProjectedBtreeDirectoryCountMismatch");
    }
    for (const auto& link : working_directory_links_)
    {
        auto entry_key = BuildDirectoryEntryIndexKey(link.parent_object_id, link.entry_name);
        auto decoded_it = decoded_directory_entries.find(entry_key);
        if (decoded_it == decoded_directory_entries.end())
        {
            return fail_pending(L"ProjectedBtreeMissingDirectory", link.child_object_id);
        }
        const auto& decoded = decoded_it->second;
        if (decoded.child_object_id != link.child_object_id ||
            decoded.xid == 0 ||
            decoded.xid > target_xid)
        {
            return fail_pending(L"ProjectedBtreeDirectoryMismatch", link.child_object_id);
        }

        auto parent_it = working_inodes_.find(link.parent_object_id);
        auto child_it = working_inodes_.find(link.child_object_id);
        if (parent_it == working_inodes_.end() ||
            child_it == working_inodes_.end() ||
            !parent_it->second.is_directory ||
            child_it->second.parent_object_id != link.parent_object_id ||
            child_it->second.name != link.entry_name)
        {
            return fail_pending(L"ProjectedBtreeDirectoryLinkMismatch", link.child_object_id);
        }
    }

    return true;
}

bool MetadataStore::AllowCommitStage(std::string_view stage)
{
    if (stage.rfind("before-recovery-", 0) == 0 || stage.rfind("replay-", 0) == 0)
    {
        last_replay_stage_ = std::string(stage);
    }
    else
    {
        last_commit_stage_ = std::string(stage);
    }

    if (!commit_stage_hook_)
    {
        return true;
    }

    return commit_stage_hook_(stage);
}

bool MetadataStore::PersistObjectMapCheckpoint(std::uint64_t target_xid)
{
    ScopedPerfTimer perf_scope(persist_object_map_checkpoint_perf_);

    auto object_map_blocks = ResolveObjectMapCheckpointBlockIndices();
    if (object_map_blocks.empty())
    {
        return false;
    }

    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'O', 'M', 'A', 'P', '3', '\0'
    };
    constexpr std::size_t kHeaderBytes = kCheckpointHeaderBytes;
    constexpr std::size_t kEntryBytes = 32;

    const auto* object_entries = OrderedCommittedObjectMapEntries();
    if (!object_entries)
    {
        return false;
    }

    const auto required_bytes = kHeaderBytes + (object_entries->size() * kEntryBytes);
    if (block_size_ == 0 ||
        object_map_blocks.size() > (std::numeric_limits<std::size_t>::max() / static_cast<std::size_t>(block_size_)))
    {
        return false;
    }
    const auto checkpoint_capacity = object_map_blocks.size() * static_cast<std::size_t>(block_size_);
    if (required_bytes > checkpoint_capacity ||
        required_bytes < kHeaderBytes ||
        (required_bytes - kHeaderBytes) > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
    {
        return false;
    }

    auto target_slots = SelectWritableChunkedCheckpointBlocks(
        object_map_blocks,
        target_xid,
        (required_bytes + static_cast<std::size_t>(block_size_) - 1) / static_cast<std::size_t>(block_size_));
    if (target_slots.empty())
    {
        return false;
    }

    std::vector<std::byte> local_block;
    auto prepared_block = PrepareCheckpointSerializationBuffer(
        object_map_checkpoint_serialization_buffer_,
        local_block,
        required_bytes,
        target_slots.size() * static_cast<std::size_t>(block_size_));
    auto& block = *prepared_block.bytes;
    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        block[index] = static_cast<std::byte>(kMagic[index]);
    }
    WriteLe64(block, 12, target_xid);
    WriteLe32(block, 20, static_cast<std::uint32_t>(object_entries->size()));

    std::size_t cursor = kHeaderBytes;
    for (const auto& entry : *object_entries)
    {
        if (entry.update == nullptr)
        {
            return false;
        }

        WriteLe64(block, cursor + 0, entry.update->object_id);
        WriteLe64(block, cursor + 8, entry.update->physical_address);
        WriteLe64(block, cursor + 16, entry.update->logical_size);
        WriteLe64(block, cursor + 24, entry.update->xid);
        cursor += kEntryBytes;
    }

    const auto payload_bytes = cursor - kHeaderBytes;
    WriteLe32(block, 24, static_cast<std::uint32_t>(payload_bytes));
    WriteLe32(block, kCheckpointChecksumOffset, ComputeCheckpointChecksum(block, payload_bytes));
    if (!PadCheckpointWriteDataToBlockBoundary(block))
    {
        return false;
    }
    return WritePreparedCheckpointBlocks(target_slots, prepared_block);
}

bool MetadataStore::PersistSpacemanCheckpoint(std::uint64_t target_xid)
{
    ScopedPerfTimer perf_scope(persist_spaceman_checkpoint_perf_);

    auto spaceman_blocks = ResolveSpacemanCheckpointBlockIndices();
    if (spaceman_blocks.empty())
    {
        return false;
    }

    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'P', 'M', '3', '\0', '\0'
    };
    constexpr std::size_t kHeaderBytes = kCheckpointHeaderBytes;
    constexpr std::size_t kEntryBytes = 16;

    const auto* allocations = &committed_spaceman_allocations_;
    const auto* free_extents = &committed_spaceman_free_extents_;
    std::vector<SpacemanAllocation> normalized_allocations;
    std::vector<SpacemanAllocation> normalized_free_extents;
    if (!IsCanonicalSpacemanExtents(*allocations) ||
        !IsCanonicalSpacemanExtents(*free_extents))
    {
        normalized_allocations = *allocations;
        normalized_free_extents = *free_extents;
        if (!NormalizeSpacemanExtents(normalized_allocations) ||
            !NormalizeSpacemanExtents(normalized_free_extents))
        {
            return false;
        }
        allocations = &normalized_allocations;
        free_extents = &normalized_free_extents;
        spaceman_checkpoint_normalize_fallback_count_.fetch_add(1, std::memory_order_relaxed);
    }
    else
    {
        spaceman_checkpoint_fast_path_count_.fetch_add(1, std::memory_order_relaxed);
    }

    const auto required_entries = allocations->size() + free_extents->size();
    if (required_entries > ((std::numeric_limits<std::size_t>::max() - kHeaderBytes) / kEntryBytes) ||
        required_entries > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
    {
        return false;
    }
    const auto required_bytes = kHeaderBytes + (required_entries * kEntryBytes);
    if (block_size_ == 0 ||
        spaceman_blocks.size() > (std::numeric_limits<std::size_t>::max() / static_cast<std::size_t>(block_size_)))
    {
        return false;
    }
    constexpr std::size_t kCompactSpacemanCheckpointBlocks =
        static_cast<std::size_t>(kNativeInodeCheckpointOffset - kNativeSpacemanCheckpointOffset);
    if (spaceman_blocks.size() >= kCompactSpacemanCheckpointBlocks &&
        required_bytes <= (kCompactSpacemanCheckpointBlocks * static_cast<std::size_t>(block_size_)))
    {
        spaceman_blocks.resize(kCompactSpacemanCheckpointBlocks);
    }
    const auto checkpoint_capacity = spaceman_blocks.size() * static_cast<std::size_t>(block_size_);
    if (required_bytes > checkpoint_capacity)
    {
        return false;
    }

    auto target_slots = SelectWritableChunkedCheckpointBlocks(
        spaceman_blocks,
        target_xid,
        (required_bytes + static_cast<std::size_t>(block_size_) - 1) / static_cast<std::size_t>(block_size_));
    if (target_slots.empty())
    {
        return false;
    }

    std::vector<std::byte> local_block;
    auto prepared_block = PrepareCheckpointSerializationBuffer(
        spaceman_checkpoint_serialization_buffer_,
        local_block,
        required_bytes,
        target_slots.size() * static_cast<std::size_t>(block_size_));
    auto& block = *prepared_block.bytes;
    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        block[index] = static_cast<std::byte>(kMagic[index]);
    }
    WriteLe64(block, 12, target_xid);
    WriteLe32(block, 20, static_cast<std::uint32_t>(allocations->size()));
    WriteLe32(block, 24, static_cast<std::uint32_t>(free_extents->size()));

    std::size_t cursor = kHeaderBytes;
    for (const auto& allocation : *allocations)
    {
        WriteLe64(block, cursor + 0, allocation.physical_address);
        WriteLe64(block, cursor + 8, allocation.bytes);
        cursor += kEntryBytes;
    }
    for (const auto& extent : *free_extents)
    {
        WriteLe64(block, cursor + 0, extent.physical_address);
        WriteLe64(block, cursor + 8, extent.bytes);
        cursor += kEntryBytes;
    }

    const auto payload_bytes = cursor - kHeaderBytes;
    WriteLe32(block, kCheckpointChecksumOffset, ComputeCheckpointChecksum(block, payload_bytes));
    if (!PadCheckpointWriteDataToBlockBoundary(block))
    {
        return false;
    }
    return WritePreparedCheckpointBlocks(target_slots, prepared_block);
}

bool MetadataStore::PersistInodeCheckpoint(std::uint64_t target_xid)
{
    ScopedPerfTimer perf_scope(persist_inode_checkpoint_perf_);

    auto inode_blocks = ResolveInodeCheckpointBlockIndices();
    if (inode_blocks.empty())
    {
        return false;
    }

    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'I', 'N', 'O', 'D', '6', '\0'
    };
    constexpr std::size_t kHeaderBytes = kCheckpointHeaderBytes;
    constexpr std::size_t kRecordFixedBytes = 60;
    const auto* ordered_entries = OrderedCommittedInodeEntries();
    if (!ordered_entries)
    {
        return false;
    }

    auto required_bytes_cache = CommittedInodeCheckpointRequiredBytesFromCache();
    std::size_t required_bytes = required_bytes_cache.value_or(kHeaderBytes);
    if (required_bytes_cache.has_value())
    {
        inode_checkpoint_size_cache_hit_count_.fetch_add(1, std::memory_order_relaxed);
    }
    else
    {
        for (const auto& entry : *ordered_entries)
        {
            if (entry.inode == nullptr)
            {
                return false;
            }
            const auto& inode = *entry.inode;
            const auto name_bytes = inode.name.size() * sizeof(wchar_t);
            const auto path_bytes = entry.persist_full_path
                ? inode.full_path.size() * sizeof(wchar_t)
                : 0;
            if (required_bytes > (std::numeric_limits<std::size_t>::max() - kRecordFixedBytes - name_bytes - path_bytes))
            {
                return false;
            }
            required_bytes += kRecordFixedBytes + name_bytes + path_bytes;
        }
    }
    if (block_size_ == 0 ||
        inode_blocks.size() > (std::numeric_limits<std::size_t>::max() / static_cast<std::size_t>(block_size_)))
    {
        return false;
    }
    const auto checkpoint_capacity = inode_blocks.size() * static_cast<std::size_t>(block_size_);
    if (required_bytes > checkpoint_capacity ||
        required_bytes < kHeaderBytes ||
        (required_bytes - kHeaderBytes) > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
    {
        return false;
    }

    auto target_slots = SelectWritableChunkedCheckpointBlocks(
        inode_blocks,
        target_xid,
        (required_bytes + static_cast<std::size_t>(block_size_) - 1) / static_cast<std::size_t>(block_size_));
    if (target_slots.empty())
    {
        return false;
    }

    std::vector<std::byte> local_block;
    auto prepared_block = PrepareCheckpointSerializationBuffer(
        inode_checkpoint_serialization_buffer_,
        local_block,
        required_bytes,
        target_slots.size() * static_cast<std::size_t>(block_size_));
    auto& block = *prepared_block.bytes;
    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        block[index] = static_cast<std::byte>(kMagic[index]);
    }
    WriteLe64(block, 12, target_xid);
    WriteLe32(block, 20, static_cast<std::uint32_t>(ordered_entries->size()));

    std::size_t cursor = kHeaderBytes;
    for (const auto& entry : *ordered_entries)
    {
        if (entry.inode == nullptr)
        {
            return false;
        }
        const auto& inode = *entry.inode;
        WriteLe64(block, cursor + 0, inode.object_id);
        WriteLe64(block, cursor + 8, inode.parent_object_id);
        WriteLe64(block, cursor + 16, inode.logical_size);
        WriteLe64(block, cursor + 24, inode.data_physical_address);
        WriteLe64(block, cursor + 32, inode.xid);
        WriteLe64(block, cursor + 40, inode.timestamp_utc);
        WriteLe32(block, cursor + 48, inode.is_directory ? 1u : 0u);
        WriteLe32(block, cursor + 52, static_cast<std::uint32_t>(inode.name.size()));
        WriteLe32(block, cursor + 56, entry.persist_full_path ? static_cast<std::uint32_t>(inode.full_path.size()) : 0u);
        cursor += kRecordFixedBytes;

        const auto name_bytes = inode.name.size() * sizeof(wchar_t);
        if (name_bytes > 0)
        {
            std::memcpy(block.data() + cursor, inode.name.data(), name_bytes);
            cursor += name_bytes;
        }

        const auto path_bytes = entry.persist_full_path ? inode.full_path.size() * sizeof(wchar_t) : 0;
        if (path_bytes > 0)
        {
            std::memcpy(block.data() + cursor, inode.full_path.data(), path_bytes);
            cursor += path_bytes;
        }
    }

    const auto payload_bytes = cursor - kHeaderBytes;
    WriteLe32(block, 24, static_cast<std::uint32_t>(payload_bytes));
    WriteLe32(block, kCheckpointChecksumOffset, ComputeCheckpointChecksum(block, payload_bytes));
    if (!PadCheckpointWriteDataToBlockBoundary(block))
    {
        return false;
    }
    return WritePreparedCheckpointBlocks(target_slots, prepared_block);
}

bool MetadataStore::PersistBtreeCheckpoint(std::uint64_t target_xid)
{
    ScopedPerfTimer perf_scope(persist_btree_checkpoint_perf_);

    auto btree_blocks = ResolveBtreeCheckpointBlockIndices();
    if (btree_blocks.empty())
    {
        return false;
    }

    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'B', 'T', 'R', '5', '\0', '\0'
    };
    constexpr std::size_t kHeaderBytes = kCheckpointHeaderBytes;
    constexpr std::size_t kRecordHeaderBytes = 16;

    if (block_size_ == 0 ||
        btree_blocks.size() > (std::numeric_limits<std::size_t>::max() / static_cast<std::size_t>(block_size_)))
    {
        return false;
    }
    std::vector<std::byte> local_block;
    const auto checkpoint_capacity = btree_blocks.size() * static_cast<std::size_t>(block_size_);
    const auto estimated_record_bytes = kRecordHeaderBytes + 96;
    const auto estimated_bytes =
        committed_btree_records_.size() > ((std::numeric_limits<std::size_t>::max() - kHeaderBytes) / estimated_record_bytes)
            ? checkpoint_capacity
            : kHeaderBytes + (committed_btree_records_.size() * estimated_record_bytes);
    const auto reserve_capacity = std::min<std::size_t>(checkpoint_capacity, estimated_bytes);
    auto prepared_block = PrepareCheckpointSerializationBuffer(
        btree_checkpoint_serialization_buffer_,
        local_block,
        0,
        reserve_capacity);
    auto& block = *prepared_block.bytes;
    block.resize(kHeaderBytes, std::byte{0});
    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        block[index] = static_cast<std::byte>(kMagic[index]);
    }
    WriteLe64(block, 12, target_xid);
    if (committed_btree_records_.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
    {
        return false;
    }
    WriteLe32(block, 20, static_cast<std::uint32_t>(committed_btree_records_.size()));

    for (const auto& record : committed_btree_records_)
    {
        if (record.key.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()) ||
            record.value.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()) ||
            block.size() > (std::numeric_limits<std::size_t>::max() - kRecordHeaderBytes - record.key.size() - record.value.size()))
        {
            return false;
        }

        const auto cursor = block.size();
        block.resize(cursor + kRecordHeaderBytes + record.key.size() + record.value.size(), std::byte{0});
        WriteLe32(block, cursor + 0, static_cast<std::uint32_t>(record.kind));
        WriteLe32(block, cursor + 4, record.tombstone ? 1u : 0u);
        WriteLe32(block, cursor + 8, static_cast<std::uint32_t>(record.key.size()));
        WriteLe32(block, cursor + 12, static_cast<std::uint32_t>(record.value.size()));

        auto payload_cursor = cursor + kRecordHeaderBytes;
        if (!record.key.empty())
        {
            std::memcpy(block.data() + payload_cursor, record.key.data(), record.key.size());
            payload_cursor += record.key.size();
        }
        if (!record.value.empty())
        {
            std::memcpy(block.data() + payload_cursor, record.value.data(), record.value.size());
        }
    }
    const auto required_bytes = block.size();
    if (required_bytes > checkpoint_capacity ||
        required_bytes < kHeaderBytes ||
        (required_bytes - kHeaderBytes) > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
    {
        return false;
    }

    auto target_slots = SelectWritableChunkedCheckpointBlocks(
        btree_blocks,
        target_xid,
        (required_bytes + static_cast<std::size_t>(block_size_) - 1) / static_cast<std::size_t>(block_size_));
    if (target_slots.empty())
    {
        return false;
    }

    const auto payload_bytes = required_bytes - kHeaderBytes;
    WriteLe32(block, 24, static_cast<std::uint32_t>(payload_bytes));
    WriteLe32(block, kCheckpointChecksumOffset, ComputeCheckpointChecksum(block, payload_bytes));
    if (!PadCheckpointWriteDataToBlockBoundary(block))
    {
        return false;
    }
    return WritePreparedCheckpointBlocks(target_slots, prepared_block);
}

bool MetadataStore::PersistReplayCheckpoint(std::uint64_t target_xid, bool validate_commit_blob_candidate)
{
    ScopedPerfTimer perf_scope(persist_replay_checkpoint_perf_);

    auto replay_blocks = ResolveReplayCheckpointBlockIndices();
    if (replay_blocks.empty() ||
        !AreNativeCheckpointBlocksWritable(replay_blocks) ||
        target_xid == 0 ||
        !last_commit_blob_address_.has_value() ||
        !last_commit_blob_bytes_.has_value() ||
        last_commit_blob_address_.value() == 0 ||
        last_commit_blob_bytes_.value() == 0 ||
        !ValidateCommitBlobLocation(
            last_commit_blob_address_.value(),
            last_commit_blob_bytes_.value()))
    {
        return false;
    }
    const auto source_xid = target_xid - 1;
    if (validate_commit_blob_candidate &&
        !ValidateReplayCommitBlobCandidate(
            last_commit_blob_address_.value(),
            last_commit_blob_bytes_.value(),
            source_xid,
            target_xid))
    {
        return false;
    }

    const auto target_slot = replay_blocks[
        static_cast<std::size_t>(target_xid % static_cast<std::uint64_t>(replay_blocks.size()))];

    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'R', 'P', 'L', '1', '\0', '\0'
    };
    constexpr std::size_t kHeaderBytes = kCheckpointHeaderBytes;
    constexpr std::size_t kReplayPayloadBytes = 24;
    if ((kHeaderBytes + kReplayPayloadBytes) > static_cast<std::size_t>(block_size_))
    {
        return false;
    }

    std::vector<std::byte> local_block;
    auto prepared_block = PrepareCheckpointSerializationBuffer(
        replay_checkpoint_serialization_buffer_,
        local_block,
        static_cast<std::size_t>(block_size_),
        static_cast<std::size_t>(block_size_));
    auto& block = *prepared_block.bytes;
    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        block[index] = static_cast<std::byte>(kMagic[index]);
    }

    WriteLe64(block, 12, target_xid);
    WriteLe32(block, 20, 1);
    WriteLe32(block, 24, static_cast<std::uint32_t>(kReplayPayloadBytes));
    WriteLe64(block, kHeaderBytes + 0, source_xid);
    WriteLe64(block, kHeaderBytes + 8, last_commit_blob_address_.value());
    WriteLe64(block, kHeaderBytes + 16, last_commit_blob_bytes_.value());
    WriteLe32(block, kCheckpointChecksumOffset, ComputeCheckpointChecksum(block, kReplayPayloadBytes));
    if (active_checkpoint_write_batch_)
    {
        if (block_size_ == 0 ||
            target_slot == 0 ||
            target_slot > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)) ||
            (total_blocks_ != 0 && target_slot >= total_blocks_))
        {
            return false;
        }
        const auto block_offset = target_slot * static_cast<std::uint64_t>(block_size_);
        if (prepared_block.reusable)
        {
            ObserveCheckpointSerializationBuffer(prepared_block);
            active_checkpoint_write_batch_->writes.push_back(BlockDevice::WriteSpan{
                block_offset,
                std::span<const std::byte>(block.data(), block.size()),
            });
            return true;
        }
        auto& queued_block = active_checkpoint_write_batch_->storage.emplace_back(std::move(block));
        if (queued_block.size() < static_cast<std::size_t>(block_size_))
        {
            queued_block.resize(static_cast<std::size_t>(block_size_), std::byte{0});
        }
        active_checkpoint_write_batch_->writes.push_back(BlockDevice::WriteSpan{
            block_offset,
            std::span<const std::byte>(queued_block.data(), queued_block.size()),
        });
        return true;
    }
    return WriteBlockByIndexDirect(target_slot, std::move(block));
}

bool MetadataStore::PersistCheckpointSuperblock(std::uint64_t target_xid)
{
    ScopedPerfTimer perf_scope(persist_superblock_checkpoint_perf_);

    if (!container_loaded_)
    {
        return false;
    }

    // NXSB superblock field offsets used by the native APFS metadata writer.
    constexpr std::size_t kSuperblockBytes = 0x570;
    constexpr std::size_t kMagicOffset = 0x20;
    constexpr std::size_t kBlockSizeOffset = 0x24;
    constexpr std::size_t kCheckpointXidOffset = 0x10;
    constexpr std::uint32_t kNxsbMagic = 0x4253584E; // 'NXSB'

    const auto resolve_target_offset = [&]() -> std::optional<std::uint64_t>
    {
        auto candidate = alternate_superblock_offset_;
        if (candidate == active_superblock_offset_)
        {
            candidate = active_superblock_offset_ == 0
                ? static_cast<std::uint64_t>(block_size_)
                : 0;
        }
        if (candidate > (std::numeric_limits<std::uint64_t>::max() - kSuperblockBytes))
        {
            return std::nullopt;
        }
        if (total_blocks_ != 0)
        {
            if (total_blocks_ > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
            {
                return std::nullopt;
            }
            const auto total_bytes = total_blocks_ * static_cast<std::uint64_t>(block_size_);
            if (candidate + kSuperblockBytes > total_bytes)
            {
                return std::nullopt;
            }
        }
        return candidate;
    };

    auto target_offset = resolve_target_offset();
    if (!target_offset.has_value())
    {
        return false;
    }

    std::vector<std::byte> superblock;
    auto source_offset = active_superblock_offset_;
    if (active_superblock_bytes_.size() >= static_cast<std::size_t>(block_size_))
    {
        superblock = active_superblock_bytes_;
    }
    else if (!device_.Read(source_offset, static_cast<std::size_t>(block_size_), superblock) ||
             superblock.size() < kSuperblockBytes)
    {
        source_offset = 0;
        if (!device_.Read(source_offset, static_cast<std::size_t>(block_size_), superblock) ||
            superblock.size() < kSuperblockBytes)
        {
            return false;
        }
    }
    if (superblock.size() > static_cast<std::size_t>(block_size_))
    {
        superblock.resize(static_cast<std::size_t>(block_size_));
    }
    if (ReadLe32(superblock, kMagicOffset) != kNxsbMagic)
    {
        return false;
    }

    if (ReadLe32(superblock, kBlockSizeOffset) != block_size_)
    {
        return false;
    }

    if (!AllowCommitStage("before-checkpoint-write"))
    {
        return false;
    }

    WriteLe64(superblock, kCheckpointXidOffset, target_xid);
    const auto checksum = ComputeApfsObjectChecksum(superblock);
    if (!checksum.has_value())
    {
        return false;
    }
    WriteLe64(superblock, 0, checksum.value());
    if (!device_.Write(*target_offset, superblock))
    {
        return false;
    }

    active_superblock_offset_ = *target_offset;
    alternate_superblock_offset_ = source_offset;
    active_superblock_bytes_ = std::move(superblock);
    return true;
}

bool MetadataStore::LoadPersistentState()
{
    persistent_state_path_ = BuildPersistentStatePath(context_);
    persistent_state_loaded_ = true;
    working_free_extents_sanitized_ = false;
    recovery_required_ = false;
    recovery_reason_.clear();
    auto disk_loaded_object_map = committed_object_map_;
    auto disk_loaded_allocations = committed_spaceman_allocations_;
    auto disk_loaded_free_extents = committed_spaceman_free_extents_;
    const auto disk_loaded_btree_records = committed_btree_records_;
    auto disk_loaded_last_committed_xid = last_committed_xid_;
    auto disk_loaded_next_extent = next_ephemeral_extent_;
    auto disk_loaded_checkpoint_xid = checkpoint_xid_;
    const auto native_loaded_inodes = committed_inodes_;
    const auto native_loaded_path_index = committed_path_index_;
    const auto native_loaded_directory_links = committed_directory_links_;
    committed_object_map_.clear();
    InvalidateCommittedObjectMapOrderCache();
    committed_spaceman_allocations_.clear();
    committed_spaceman_free_extents_.clear();
    committed_inodes_.clear();
    InvalidateCommittedInodeOrderCache();
    committed_path_index_.clear();
    committed_directory_links_.clear();
    ClearCommittedDirectoryLinkIndexes();
    committed_btree_records_.clear();
    committed_btree_index_by_key_.clear();
    committed_btree_inode_key_by_object_id_.clear();
    working_inodes_.clear();
    working_path_index_.clear();
    working_directory_links_.clear();
    RebuildWorkingDirectoryIndexes();
    working_spaceman_free_extents_.clear();
    last_commit_blob_address_.reset();
    last_commit_blob_bytes_.reset();
    pending_mutations_.clear();
    pending_mutation_path_key_cache_.clear();
    pending_write_object_ids_.clear();
    pending_write_mutation_index_by_object_id_.clear();
    pending_basic_info_mutation_index_by_object_id_.clear();
    ClearPendingPayloadPathKeys();
    ClearPendingPayloadObjectSummary();
    ClearPendingCloseDelaySummary();
    pending_object_map_updates_.clear();
    pending_object_map_update_index_.clear();
    pending_spaceman_allocations_.clear();
    pending_spaceman_allocation_index_.clear();
    pending_spaceman_deallocations_.clear();
    tracking_spaceman_free_extent_delta_ = false;
    pending_spaceman_untracked_free_extent_delta_ = false;
    pending_spaceman_released_existing_allocation_ = false;
    pending_btree_records_.clear();
    pending_btree_inode_record_count_by_object_.clear();
    pending_btree_file_inode_index_.clear();
    pending_btree_file_extent_index_.clear();
    pending_btree_file_extent_offsets_by_object_.clear();
    pending_btree_file_extent_record_count_by_object_.clear();
    pending_btree_directory_record_count_by_child_object_.clear();
    pending_btree_tombstone_record_count_ = 0;
    pending_btree_directory_inode_record_count_ = 0;
    pending_btree_untracked_record_count_ = 0;
    prepared_payload_ranges_.clear();
    pending_written_ranges_.clear();
    pending_payload_dirty_bytes_ = 0;

    std::unordered_map<std::uint64_t, InodeRecord> disk_loaded_inodes;
    std::unordered_map<std::wstring, std::uint64_t> disk_loaded_path_index;
    std::vector<DirectoryLink> disk_loaded_directory_links;
    std::vector<BtreeRecord> disk_loaded_btree_checkpoint_records;
    std::optional<std::uint64_t> disk_loaded_btree_last_committed_xid;
    std::optional<std::uint64_t> disk_loaded_inode_last_committed_xid;
    std::optional<std::uint64_t> disk_loaded_replay_target_xid;
    std::optional<std::uint64_t> disk_loaded_replay_commit_blob_address;
    std::optional<std::uint64_t> disk_loaded_replay_commit_blob_bytes;
    std::optional<int> disk_loaded_replay_priority;
    last_replay_checkpoint_candidate_present_ = false;
    last_replay_checkpoint_pending_window_ = false;
    const auto reconcile_inode_state_from_btree = [&]() -> bool
    {
        if (disk_loaded_btree_checkpoint_records.empty())
        {
            return false;
        }

        std::unordered_map<std::uint64_t, InodeRecord> rebuilt_inodes;
        std::unordered_map<std::wstring, std::uint64_t> rebuilt_path_index;
        std::vector<DirectoryLink> rebuilt_directory_links;
        if (!RebuildInodeStateFromBtreeRecords(
                disk_loaded_btree_checkpoint_records,
                rebuilt_inodes,
                rebuilt_path_index,
                rebuilt_directory_links))
        {
            return false;
        }

        if (!disk_loaded_inodes.empty() &&
            rebuilt_inodes.size() <= disk_loaded_inodes.size() &&
            rebuilt_path_index.size() <= disk_loaded_path_index.size() &&
            rebuilt_directory_links.size() <= disk_loaded_directory_links.size())
        {
            return false;
        }

        disk_loaded_inodes = std::move(rebuilt_inodes);
        disk_loaded_path_index = std::move(rebuilt_path_index);
        disk_loaded_directory_links = std::move(rebuilt_directory_links);
        std::unordered_map<std::uint64_t, std::vector<FileExtent>> rebuilt_read_extents;
        if (RebuildReadExtentsFromBtreeRecords(
                disk_loaded_btree_checkpoint_records,
                disk_loaded_inodes,
                rebuilt_read_extents))
        {
            committed_read_extents_ = std::move(rebuilt_read_extents);
            InvalidateCommittedReadExtentSnapshotCache();
        }
        if (disk_loaded_btree_last_committed_xid.has_value())
        {
            disk_loaded_inode_last_committed_xid = std::max(
                disk_loaded_inode_last_committed_xid.value_or(0),
                disk_loaded_btree_last_committed_xid.value());
        }
        return true;
    };
    const auto reconcile_inode_state_from_native_projection = [&]() -> bool
    {
        if (!IsLikelyRawDevicePath(context_.device_path))
        {
            return false;
        }

        NativeApfsVolumeProjection projection{};
        std::wstring projection_error;
        if (!NativeApfsReader::TryLoadVolumeProjection(
                device_,
                0,
                projection,
                projection_error))
        {
            if (IsReadTraceEnabled())
            {
                std::wcerr << L"[MetadataStore] Native projection rebuild failed"
                           << L" reason=" << (projection_error.empty() ? L"Unknown" : projection_error)
                           << std::endl;
            }
            return false;
        }
        if (projection.inodes.empty() || projection.btree_records.empty())
        {
            return false;
        }

        std::unordered_map<std::uint64_t, InodeRecord> projected_inodes;
        std::unordered_map<std::wstring, std::uint64_t> projected_path_index;
        std::vector<DirectoryLink> projected_directory_links;
        projected_inodes.reserve(projection.inodes.size());
        projected_path_index.reserve(projection.inodes.size());
        projected_directory_links.reserve(projection.inodes.size() > 0 ? projection.inodes.size() - 1 : 0);
        for (const auto& inode : projection.inodes)
        {
            if (inode.object_id == 0 || inode.full_path.empty())
            {
                return false;
            }

            projected_inodes[inode.object_id] = inode;
            projected_path_index[CanonicalPathKeyFromNormalizedPath(inode.full_path)] = inode.object_id;
            if (!IsRootPath(inode.full_path))
            {
                projected_directory_links.push_back(DirectoryLink
                {
                    inode.parent_object_id,
                    inode.name,
                    inode.object_id,
                    inode.xid
                });
            }
        }

        const auto read_extents_snapshot = committed_read_extents_;
        committed_read_extents_.clear();
        InvalidateCommittedReadExtentSnapshotCache();
        for (auto& [object_id, extents] : projection.read_extents_by_inode)
        {
            if (!SetCommittedReadExtents(object_id, std::move(extents)))
            {
                committed_read_extents_.erase(object_id);
                InvalidateCommittedReadExtentSnapshotCacheForObject(object_id);
            }
        }

        if (!ValidateInodeGraphState(
                projected_inodes,
                projected_path_index,
                projected_directory_links,
                /*require_root_object=*/true))
        {
            committed_read_extents_ = read_extents_snapshot;
            InvalidateCommittedReadExtentSnapshotCache();
            return false;
        }

        if (!disk_loaded_inodes.empty() &&
            projected_inodes.size() <= disk_loaded_inodes.size() &&
            projection.btree_records.size() <= disk_loaded_btree_checkpoint_records.size())
        {
            committed_read_extents_ = read_extents_snapshot;
            InvalidateCommittedReadExtentSnapshotCache();
            return false;
        }

        disk_loaded_inodes = std::move(projected_inodes);
        disk_loaded_path_index = std::move(projected_path_index);
        disk_loaded_directory_links = std::move(projected_directory_links);
        disk_loaded_btree_checkpoint_records = std::move(projection.btree_records);
        disk_loaded_btree_last_committed_xid = std::max(
            disk_loaded_btree_last_committed_xid.value_or(0),
            projection.checkpoint_xid);
        disk_loaded_inode_last_committed_xid = std::max(
            disk_loaded_inode_last_committed_xid.value_or(0),
            projection.checkpoint_xid);

        disk_loaded_object_map.clear();
        for (const auto& [object_id, inode] : disk_loaded_inodes)
        {
            if (!inode.is_directory &&
                inode.data_physical_address != 0 &&
                inode.logical_size != 0)
            {
                disk_loaded_object_map[object_id] = ObjectMapUpdate
                {
                    object_id,
                    inode.data_physical_address,
                    inode.logical_size,
                    projection.checkpoint_xid
                };
            }
        }
        return true;
    };

    struct ObjectMapCheckpointCandidate
    {
        std::uint64_t xid = 0;
        std::unordered_map<std::uint64_t, ObjectMapUpdate> object_map;
        std::optional<std::uint64_t> last_committed_xid;
    };
    struct SpacemanCheckpointCandidate
    {
        std::uint64_t xid = 0;
        std::vector<SpacemanAllocation> allocations;
        std::vector<SpacemanAllocation> free_extents;
        std::uint64_t next_extent = 0;
        std::uint64_t working_next_extent = 0;
        std::optional<std::uint64_t> last_committed_xid;
    };
    struct InodeCheckpointCandidate
    {
        std::uint64_t xid = 0;
        std::unordered_map<std::uint64_t, InodeRecord> inodes;
        std::unordered_map<std::wstring, std::uint64_t> path_index;
        std::vector<DirectoryLink> directory_links;
        std::optional<std::uint64_t> last_committed_xid;
    };
    struct BtreeCheckpointCandidate
    {
        std::uint64_t xid = 0;
        std::vector<BtreeRecord> records;
        std::optional<std::uint64_t> last_committed_xid;
    };

    const auto clear_checkpoint_load_scratch = [&]()
    {
        committed_object_map_.clear();
        InvalidateCommittedObjectMapOrderCache();
        committed_spaceman_allocations_.clear();
        committed_spaceman_free_extents_.clear();
        committed_btree_records_.clear();
        committed_btree_index_by_key_.clear();
        committed_btree_inode_key_by_object_id_.clear();
        committed_inodes_.clear();
        InvalidateCommittedInodeOrderCache();
        committed_path_index_.clear();
        committed_directory_links_.clear();
        ClearCommittedDirectoryLinkIndexes();
        working_inodes_.clear();
        working_path_index_.clear();
        working_directory_links_.clear();
        RebuildWorkingDirectoryIndexes();
        working_spaceman_free_extents_.clear();
        next_ephemeral_extent_ = disk_loaded_next_extent;
        working_next_ephemeral_extent_ = disk_loaded_next_extent;
        last_committed_xid_.reset();
    };

    const auto require_coherent_native_checkpoint_set = RequiresCanonicalNonFixtureCommitPath();
    bool coherent_native_checkpoint_selected = false;
    if (require_coherent_native_checkpoint_set)
    {
        std::vector<ObjectMapCheckpointCandidate> object_map_candidates;
        std::vector<SpacemanCheckpointCandidate> spaceman_candidates;
        std::vector<InodeCheckpointCandidate> inode_candidates;
        std::vector<BtreeCheckpointCandidate> btree_candidates;

        for (const auto object_map_block : ResolveObjectMapCheckpointBlockIndices())
        {
            std::vector<std::byte> object_map_bytes;
            if (!ReadBlockByIndexDirect(object_map_block, object_map_bytes))
            {
                continue;
            }

            clear_checkpoint_load_scratch();
            if (!LoadObjectMapCheckpointBlock(object_map_block, object_map_bytes))
            {
                continue;
            }

            const auto candidate_xid = ReadLe64(object_map_bytes, 12);
            if (candidate_xid == 0)
            {
                continue;
            }
            object_map_candidates.push_back(
                ObjectMapCheckpointCandidate
                {
                    candidate_xid,
                    committed_object_map_,
                    last_committed_xid_,
                });
        }

        for (const auto spaceman_checkpoint_block : ResolveSpacemanCheckpointBlockIndices())
        {
            std::vector<std::byte> spaceman_checkpoint_bytes;
            if (!ReadBlockByIndexDirect(spaceman_checkpoint_block, spaceman_checkpoint_bytes))
            {
                continue;
            }

            clear_checkpoint_load_scratch();
            if (!LoadSpacemanCheckpointBlock(spaceman_checkpoint_block, spaceman_checkpoint_bytes))
            {
                continue;
            }

            const auto candidate_xid = ReadLe64(spaceman_checkpoint_bytes, 12);
            if (candidate_xid == 0)
            {
                continue;
            }
            spaceman_candidates.push_back(
                SpacemanCheckpointCandidate
                {
                    candidate_xid,
                    committed_spaceman_allocations_,
                    committed_spaceman_free_extents_,
                    next_ephemeral_extent_,
                    working_next_ephemeral_extent_,
                    last_committed_xid_,
                });
        }

        for (const auto inode_checkpoint_block : ResolveInodeCheckpointBlockIndices())
        {
            std::vector<std::byte> inode_checkpoint_bytes;
            if (!ReadBlockByIndexDirect(inode_checkpoint_block, inode_checkpoint_bytes))
            {
                continue;
            }

            clear_checkpoint_load_scratch();
            if (!LoadInodeCheckpointBlock(inode_checkpoint_block, inode_checkpoint_bytes))
            {
                continue;
            }

            const auto candidate_xid = ReadLe64(inode_checkpoint_bytes, 12);
            if (candidate_xid == 0)
            {
                continue;
            }
            inode_candidates.push_back(
                InodeCheckpointCandidate
                {
                    candidate_xid,
                    committed_inodes_,
                    committed_path_index_,
                    committed_directory_links_,
                    last_committed_xid_,
                });
        }

        for (const auto btree_checkpoint_block : ResolveBtreeCheckpointBlockIndices())
        {
            std::vector<std::byte> btree_checkpoint_bytes;
            if (!ReadBlockByIndexDirect(btree_checkpoint_block, btree_checkpoint_bytes))
            {
                continue;
            }

            clear_checkpoint_load_scratch();
            if (!LoadBtreeCheckpointBlock(btree_checkpoint_block, btree_checkpoint_bytes))
            {
                continue;
            }

            const auto candidate_xid = ReadLe64(btree_checkpoint_bytes, 12);
            if (candidate_xid == 0)
            {
                continue;
            }
            btree_candidates.push_back(
                BtreeCheckpointCandidate
                {
                    candidate_xid,
                    committed_btree_records_,
                    last_committed_xid_,
                });
        }

        clear_checkpoint_load_scratch();

        const auto find_object_map_candidate = [&](std::uint64_t xid) -> const ObjectMapCheckpointCandidate*
        {
            for (const auto& candidate : object_map_candidates)
            {
                if (candidate.xid == xid)
                {
                    return &candidate;
                }
            }
            return nullptr;
        };
        const auto find_spaceman_candidate = [&](std::uint64_t xid) -> const SpacemanCheckpointCandidate*
        {
            for (const auto& candidate : spaceman_candidates)
            {
                if (candidate.xid == xid)
                {
                    return &candidate;
                }
            }
            return nullptr;
        };
        const auto find_inode_candidate = [&](std::uint64_t xid) -> const InodeCheckpointCandidate*
        {
            for (const auto& candidate : inode_candidates)
            {
                if (candidate.xid == xid)
                {
                    return &candidate;
                }
            }
            return nullptr;
        };
        const auto find_btree_candidate = [&](std::uint64_t xid) -> const BtreeCheckpointCandidate*
        {
            for (const auto& candidate : btree_candidates)
            {
                if (candidate.xid == xid)
                {
                    return &candidate;
                }
            }
            return nullptr;
        };

        std::set<std::uint64_t> candidate_xids;
        for (const auto& candidate : object_map_candidates)
        {
            candidate_xids.insert(candidate.xid);
        }
        for (const auto& candidate : spaceman_candidates)
        {
            candidate_xids.insert(candidate.xid);
        }
        for (const auto& candidate : inode_candidates)
        {
            candidate_xids.insert(candidate.xid);
        }
        for (const auto& candidate : btree_candidates)
        {
            candidate_xids.insert(candidate.xid);
        }

        std::uint64_t selected_coherent_xid = 0;
        const ObjectMapCheckpointCandidate* selected_object_map = nullptr;
        const SpacemanCheckpointCandidate* selected_spaceman = nullptr;
        const InodeCheckpointCandidate* selected_inode = nullptr;
        const BtreeCheckpointCandidate* selected_btree = nullptr;
        for (auto it = candidate_xids.rbegin(); it != candidate_xids.rend(); ++it)
        {
            const auto xid = *it;
            const auto object_map_candidate = find_object_map_candidate(xid);
            const auto spaceman_candidate = find_spaceman_candidate(xid);
            const auto inode_candidate = find_inode_candidate(xid);
            const auto btree_candidate = find_btree_candidate(xid);
            if (object_map_candidate == nullptr ||
                spaceman_candidate == nullptr ||
                inode_candidate == nullptr ||
                btree_candidate == nullptr)
            {
                continue;
            }

            selected_coherent_xid = xid;
            selected_object_map = object_map_candidate;
            selected_spaceman = spaceman_candidate;
            selected_inode = inode_candidate;
            selected_btree = btree_candidate;
            break;
        }

        if (selected_coherent_xid != 0 &&
            selected_object_map != nullptr &&
            selected_spaceman != nullptr &&
            selected_inode != nullptr &&
            selected_btree != nullptr)
        {
            disk_loaded_object_map = selected_object_map->object_map;
            disk_loaded_allocations = selected_spaceman->allocations;
            disk_loaded_free_extents = selected_spaceman->free_extents;
            disk_loaded_next_extent = std::max(disk_loaded_next_extent, selected_spaceman->next_extent);
            disk_loaded_inodes = selected_inode->inodes;
            disk_loaded_path_index = selected_inode->path_index;
            disk_loaded_directory_links = selected_inode->directory_links;
            disk_loaded_btree_checkpoint_records = selected_btree->records;
            disk_loaded_checkpoint_xid = selected_coherent_xid;
            disk_loaded_last_committed_xid = selected_coherent_xid;
            disk_loaded_inode_last_committed_xid = selected_inode->last_committed_xid.value_or(selected_coherent_xid);
            disk_loaded_btree_last_committed_xid = selected_btree->last_committed_xid.value_or(selected_coherent_xid);
            coherent_native_checkpoint_selected = true;
            reconcile_inode_state_from_btree();
        }
        else
        {
            disk_loaded_object_map.clear();
            disk_loaded_allocations.clear();
            disk_loaded_free_extents.clear();
            disk_loaded_inodes.clear();
            disk_loaded_path_index.clear();
            disk_loaded_directory_links.clear();
            disk_loaded_btree_checkpoint_records.clear();
            disk_loaded_btree_last_committed_xid.reset();
            disk_loaded_inode_last_committed_xid.reset();
            disk_loaded_last_committed_xid.reset();
        }

        if (IsReadTraceEnabled())
        {
            std::wcerr << L"[MetadataStore] Coherent native checkpoint selection"
                       << L" selectedXid=" << selected_coherent_xid
                       << L" objectMapCandidates=" << object_map_candidates.size()
                       << L" spacemanCandidates=" << spaceman_candidates.size()
                       << L" inodeCandidates=" << inode_candidates.size()
                       << L" btreeCandidates=" << btree_candidates.size()
                       << std::endl;
        }
    }

    auto btree_checkpoint_blocks = ResolveBtreeCheckpointBlockIndices();
    if (!require_coherent_native_checkpoint_set && !btree_checkpoint_blocks.empty())
    {
        std::uint64_t selected_checkpoint_xid = 0;
        bool selected_checkpoint_valid = false;
        std::vector<BtreeRecord> selected_btree_records;
        std::optional<std::uint64_t> selected_last_committed_xid;

        for (const auto btree_checkpoint_block : btree_checkpoint_blocks)
        {
            std::vector<std::byte> btree_checkpoint_bytes;
            if (!ReadBlockByIndexDirect(btree_checkpoint_block, btree_checkpoint_bytes))
            {
                continue;
            }

            committed_btree_records_.clear();
            committed_btree_index_by_key_.clear();
            committed_btree_inode_key_by_object_id_.clear();
            last_committed_xid_ = disk_loaded_last_committed_xid;
            if (!LoadBtreeCheckpointBlock(btree_checkpoint_block, btree_checkpoint_bytes))
            {
                continue;
            }

            const auto candidate_xid = ReadLe64(btree_checkpoint_bytes, 12);
            if (!selected_checkpoint_valid || candidate_xid > selected_checkpoint_xid)
            {
                selected_checkpoint_xid = candidate_xid;
                selected_btree_records = committed_btree_records_;
                selected_last_committed_xid = last_committed_xid_;
                selected_checkpoint_valid = true;
            }
        }

        if (selected_checkpoint_valid)
        {
            disk_loaded_btree_checkpoint_records = std::move(selected_btree_records);
            disk_loaded_btree_last_committed_xid = selected_last_committed_xid;
        }
        committed_btree_records_.clear();
        committed_btree_index_by_key_.clear();
        committed_btree_inode_key_by_object_id_.clear();
    }

    auto inode_checkpoint_blocks = ResolveInodeCheckpointBlockIndices();
    if (!require_coherent_native_checkpoint_set && !inode_checkpoint_blocks.empty())
    {
        std::uint64_t selected_checkpoint_xid = 0;
        bool selected_checkpoint_valid = false;
        std::unordered_map<std::uint64_t, InodeRecord> selected_inodes;
        std::unordered_map<std::wstring, std::uint64_t> selected_path_index;
        std::vector<DirectoryLink> selected_directory_links;
        std::optional<std::uint64_t> selected_last_committed_xid;

        for (const auto inode_checkpoint_block : inode_checkpoint_blocks)
        {
            std::vector<std::byte> inode_checkpoint_bytes;
            if (!ReadBlockByIndexDirect(inode_checkpoint_block, inode_checkpoint_bytes))
            {
                continue;
            }

            committed_inodes_.clear();
            InvalidateCommittedInodeOrderCache();
            committed_path_index_.clear();
            committed_directory_links_.clear();
            ClearCommittedDirectoryLinkIndexes();
            working_inodes_.clear();
            working_path_index_.clear();
            working_directory_links_.clear();
            RebuildWorkingDirectoryIndexes();
            last_committed_xid_ = disk_loaded_last_committed_xid;

            if (!LoadInodeCheckpointBlock(inode_checkpoint_block, inode_checkpoint_bytes))
            {
                continue;
            }

            const auto candidate_xid = ReadLe64(inode_checkpoint_bytes, 12);
            if (!selected_checkpoint_valid || candidate_xid > selected_checkpoint_xid)
            {
                selected_checkpoint_xid = candidate_xid;
                selected_inodes = committed_inodes_;
                selected_path_index = committed_path_index_;
                selected_directory_links = committed_directory_links_;
                selected_last_committed_xid = last_committed_xid_;
                selected_checkpoint_valid = true;
            }
        }

        if (selected_checkpoint_valid)
        {
            disk_loaded_inodes = std::move(selected_inodes);
            disk_loaded_path_index = std::move(selected_path_index);
            disk_loaded_directory_links = std::move(selected_directory_links);
            disk_loaded_inode_last_committed_xid = selected_last_committed_xid;
        }
        committed_inodes_.clear();
        InvalidateCommittedInodeOrderCache();
        committed_path_index_.clear();
        committed_directory_links_.clear();
        ClearCommittedDirectoryLinkIndexes();
        working_inodes_.clear();
        working_path_index_.clear();
        working_directory_links_.clear();
        RebuildWorkingDirectoryIndexes();
    }

    if (!require_coherent_native_checkpoint_set || !coherent_native_checkpoint_selected)
    {
        reconcile_inode_state_from_btree();
        reconcile_inode_state_from_native_projection();
    }
    if (disk_loaded_inodes.empty() &&
        !native_loaded_inodes.empty())
    {
        disk_loaded_inodes = native_loaded_inodes;
        disk_loaded_path_index = native_loaded_path_index;
        disk_loaded_directory_links = native_loaded_directory_links;
    }

    auto replay_checkpoint_blocks = ResolveReplayCheckpointBlockIndices();
    if (!replay_checkpoint_blocks.empty())
    {
        std::uint64_t selected_replay_target_xid = 0;
        std::uint64_t selected_replay_commit_blob_address = 0;
        std::uint64_t selected_replay_commit_blob_bytes = 0;
        int selected_replay_priority = 0;
        bool selected_replay_valid = false;
        const auto can_advance_superblock_xid =
            loaded_superblock_checkpoint_xid_ < std::numeric_limits<std::uint64_t>::max();
        for (const auto replay_checkpoint_block : replay_checkpoint_blocks)
        {
            std::vector<std::byte> replay_checkpoint_bytes;
            if (!ReadBlockByIndexDirect(replay_checkpoint_block, replay_checkpoint_bytes))
            {
                continue;
            }

            std::uint64_t candidate_target_xid = 0;
            std::uint64_t candidate_source_xid = 0;
            std::uint64_t candidate_commit_blob_address = 0;
            std::uint64_t candidate_commit_blob_bytes = 0;
            if (!LoadReplayCheckpointBlock(
                    replay_checkpoint_block,
                    replay_checkpoint_bytes,
                    candidate_target_xid,
                    candidate_source_xid,
                    candidate_commit_blob_address,
                    candidate_commit_blob_bytes))
            {
                continue;
            }

            const auto matches_pending_window =
                can_advance_superblock_xid &&
                candidate_source_xid == loaded_superblock_checkpoint_xid_ &&
                candidate_target_xid == (loaded_superblock_checkpoint_xid_ + 1);
            const auto matches_applied_window =
                candidate_target_xid == loaded_superblock_checkpoint_xid_;
            if (!matches_pending_window && !matches_applied_window)
            {
                continue;
            }
            if (!ValidateReplayCommitBlobCandidate(
                    candidate_commit_blob_address,
                    candidate_commit_blob_bytes,
                    candidate_source_xid,
                    candidate_target_xid))
            {
                continue;
            }

            const int candidate_priority = matches_pending_window ? 2 : 1;
            if (!selected_replay_valid ||
                candidate_priority > selected_replay_priority ||
                (candidate_priority == selected_replay_priority &&
                 candidate_target_xid > selected_replay_target_xid))
            {
                selected_replay_target_xid = candidate_target_xid;
                selected_replay_commit_blob_address = candidate_commit_blob_address;
                selected_replay_commit_blob_bytes = candidate_commit_blob_bytes;
                selected_replay_priority = candidate_priority;
                selected_replay_valid = true;
            }
        }

        if (selected_replay_valid)
        {
            disk_loaded_replay_target_xid = selected_replay_target_xid;
            disk_loaded_replay_commit_blob_address = selected_replay_commit_blob_address;
            disk_loaded_replay_commit_blob_bytes = selected_replay_commit_blob_bytes;
            disk_loaded_replay_priority = selected_replay_priority;
        }
    }

    const auto has_disk_replay_commit_blob_metadata_for_checkpoint_load =
        disk_loaded_replay_target_xid.has_value() &&
        disk_loaded_replay_commit_blob_address.has_value() &&
        disk_loaded_replay_commit_blob_bytes.has_value() &&
        disk_loaded_replay_commit_blob_address.value() > 0 &&
        disk_loaded_replay_commit_blob_bytes.value() > 0;
    const auto can_advance_superblock_xid_for_checkpoint_load =
        loaded_superblock_checkpoint_xid_ < std::numeric_limits<std::uint64_t>::max();
    const auto disk_replay_pending_window_for_checkpoint_load =
        has_disk_replay_commit_blob_metadata_for_checkpoint_load &&
        can_advance_superblock_xid_for_checkpoint_load &&
        disk_loaded_replay_priority.value_or(0) >= 2 &&
        disk_loaded_replay_target_xid.value() == (loaded_superblock_checkpoint_xid_ + 1);

    std::optional<std::uint64_t> disk_loaded_native_pending_xid;
    const auto remember_native_pending_xid = [&](std::uint64_t persisted_xid)
    {
        if (can_advance_superblock_xid_for_checkpoint_load &&
            persisted_xid == (loaded_superblock_checkpoint_xid_ + 1))
        {
            disk_loaded_native_pending_xid = std::max(
                disk_loaded_native_pending_xid.value_or(0),
                persisted_xid);
        }
    };
    const auto block_matches_magic = [](const std::vector<std::byte>& block, const std::array<char, 12>& magic)
    {
        if (block.size() < kCheckpointHeaderBytes)
        {
            return false;
        }
        for (std::size_t index = 0; index < magic.size(); ++index)
        {
            if (std::to_integer<unsigned char>(block[index]) != static_cast<unsigned char>(magic[index]))
            {
                return false;
            }
        }
        return true;
    };
    const auto scan_native_pending_xids = [&](const std::vector<std::uint64_t>& blocks, const std::vector<std::array<char, 12>>& magics)
    {
        for (const auto block_index : blocks)
        {
            std::vector<std::byte> block;
            if (!ReadBlockByIndexDirect(block_index, block))
            {
                continue;
            }
            for (const auto& magic : magics)
            {
                if (block_matches_magic(block, magic))
                {
                    remember_native_pending_xid(ReadLe64(block, 12));
                    break;
                }
            }
        }
    };
    scan_native_pending_xids(
        ResolveObjectMapCheckpointBlockIndices(),
        { { { 'A', 'P', 'F', 'S', 'R', 'W', 'O', 'M', 'A', 'P', '3', '\0' } } });
    scan_native_pending_xids(
        ResolveSpacemanCheckpointBlockIndices(),
        { { { 'A', 'P', 'F', 'S', 'R', 'W', 'S', 'P', 'M', '3', '\0', '\0' } } });
    scan_native_pending_xids(
        ResolveInodeCheckpointBlockIndices(),
        {
            { { 'A', 'P', 'F', 'S', 'R', 'W', 'I', 'N', 'O', 'D', '4', '\0' } },
            { { 'A', 'P', 'F', 'S', 'R', 'W', 'I', 'N', 'O', 'D', '5', '\0' } },
        });
    scan_native_pending_xids(
        ResolveBtreeCheckpointBlockIndices(),
        { { { 'A', 'P', 'F', 'S', 'R', 'W', 'B', 'T', 'R', '5', '\0', '\0' } } });

    if (disk_replay_pending_window_for_checkpoint_load)
    {
        const auto target_xid = disk_loaded_replay_target_xid.value();
        replay_checkpoint_load_xid_ = target_xid;

        std::unordered_map<std::uint64_t, ObjectMapUpdate> selected_object_map;
        bool selected_object_map_valid = false;
        for (const auto object_map_block : ResolveObjectMapCheckpointBlockIndices())
        {
            std::vector<std::byte> object_map_bytes;
            if (!ReadBlockByIndexDirect(object_map_block, object_map_bytes))
            {
                continue;
            }

            committed_object_map_.clear();
            InvalidateCommittedObjectMapOrderCache();
            last_committed_xid_ = disk_loaded_last_committed_xid;
            if (!LoadObjectMapCheckpointBlock(object_map_block, object_map_bytes) ||
                ReadLe64(object_map_bytes, 12) != target_xid)
            {
                continue;
            }

            selected_object_map = committed_object_map_;
            selected_object_map_valid = true;
            break;
        }
        if (selected_object_map_valid)
        {
            disk_loaded_object_map = std::move(selected_object_map);
        }
        committed_object_map_.clear();
        InvalidateCommittedObjectMapOrderCache();

        std::vector<SpacemanAllocation> selected_allocations;
        std::vector<SpacemanAllocation> selected_free_extents;
        std::uint64_t selected_next_extent = disk_loaded_next_extent;
        bool selected_spaceman_valid = false;
        for (const auto spaceman_checkpoint_block : ResolveSpacemanCheckpointBlockIndices())
        {
            std::vector<std::byte> spaceman_checkpoint_bytes;
            if (!ReadBlockByIndexDirect(spaceman_checkpoint_block, spaceman_checkpoint_bytes))
            {
                continue;
            }

            committed_spaceman_allocations_.clear();
            committed_spaceman_free_extents_.clear();
            working_spaceman_free_extents_.clear();
            next_ephemeral_extent_ = disk_loaded_next_extent;
            working_next_ephemeral_extent_ = disk_loaded_next_extent;
            last_committed_xid_ = disk_loaded_last_committed_xid;
            if (!LoadSpacemanCheckpointBlock(spaceman_checkpoint_block, spaceman_checkpoint_bytes) ||
                ReadLe64(spaceman_checkpoint_bytes, 12) != target_xid)
            {
                continue;
            }

            selected_allocations = committed_spaceman_allocations_;
            selected_free_extents = committed_spaceman_free_extents_;
            selected_next_extent = next_ephemeral_extent_;
            selected_spaceman_valid = true;
            break;
        }
        if (selected_spaceman_valid)
        {
            disk_loaded_allocations = std::move(selected_allocations);
            disk_loaded_free_extents = std::move(selected_free_extents);
            disk_loaded_next_extent = std::max(disk_loaded_next_extent, selected_next_extent);
        }
        committed_spaceman_allocations_.clear();
        committed_spaceman_free_extents_.clear();
        working_spaceman_free_extents_.clear();

        std::vector<BtreeRecord> selected_btree_records;
        std::optional<std::uint64_t> selected_btree_last_committed_xid;
        bool selected_btree_valid = false;
        for (const auto btree_checkpoint_block : ResolveBtreeCheckpointBlockIndices())
        {
            std::vector<std::byte> btree_checkpoint_bytes;
            if (!ReadBlockByIndexDirect(btree_checkpoint_block, btree_checkpoint_bytes))
            {
                continue;
            }

            committed_btree_records_.clear();
            committed_btree_index_by_key_.clear();
            committed_btree_inode_key_by_object_id_.clear();
            last_committed_xid_ = disk_loaded_last_committed_xid;
            if (!LoadBtreeCheckpointBlock(btree_checkpoint_block, btree_checkpoint_bytes) ||
                ReadLe64(btree_checkpoint_bytes, 12) != target_xid)
            {
                continue;
            }

            selected_btree_records = committed_btree_records_;
            selected_btree_last_committed_xid = last_committed_xid_;
            selected_btree_valid = true;
            break;
        }
        if (selected_btree_valid)
        {
            disk_loaded_btree_checkpoint_records = std::move(selected_btree_records);
            disk_loaded_btree_last_committed_xid = selected_btree_last_committed_xid;
        }
        committed_btree_records_.clear();
        committed_btree_index_by_key_.clear();
        committed_btree_inode_key_by_object_id_.clear();

        std::unordered_map<std::uint64_t, InodeRecord> selected_inodes;
        std::unordered_map<std::wstring, std::uint64_t> selected_path_index;
        std::vector<DirectoryLink> selected_directory_links;
        std::optional<std::uint64_t> selected_inode_last_committed_xid;
        bool selected_inode_valid = false;
        for (const auto inode_checkpoint_block : ResolveInodeCheckpointBlockIndices())
        {
            std::vector<std::byte> inode_checkpoint_bytes;
            if (!ReadBlockByIndexDirect(inode_checkpoint_block, inode_checkpoint_bytes))
            {
                continue;
            }

            committed_inodes_.clear();
            InvalidateCommittedInodeOrderCache();
            committed_path_index_.clear();
            committed_directory_links_.clear();
            ClearCommittedDirectoryLinkIndexes();
            working_inodes_.clear();
            working_path_index_.clear();
            working_directory_links_.clear();
            RebuildWorkingDirectoryIndexes();
            last_committed_xid_ = disk_loaded_last_committed_xid;

            if (!LoadInodeCheckpointBlock(inode_checkpoint_block, inode_checkpoint_bytes) ||
                ReadLe64(inode_checkpoint_bytes, 12) != target_xid)
            {
                continue;
            }

            selected_inodes = committed_inodes_;
            selected_path_index = committed_path_index_;
            selected_directory_links = committed_directory_links_;
            selected_inode_last_committed_xid = last_committed_xid_;
            selected_inode_valid = true;
            break;
        }
        if (selected_inode_valid)
        {
            disk_loaded_inodes = std::move(selected_inodes);
            disk_loaded_path_index = std::move(selected_path_index);
            disk_loaded_directory_links = std::move(selected_directory_links);
            disk_loaded_inode_last_committed_xid = selected_inode_last_committed_xid;
        }
        committed_inodes_.clear();
        InvalidateCommittedInodeOrderCache();
        committed_path_index_.clear();
        committed_directory_links_.clear();
        ClearCommittedDirectoryLinkIndexes();
        working_inodes_.clear();
        working_path_index_.clear();
        working_directory_links_.clear();
        RebuildWorkingDirectoryIndexes();

        reconcile_inode_state_from_btree();
        reconcile_inode_state_from_native_projection();

        replay_checkpoint_load_xid_.reset();
    }

    const auto apply_disk_fallback = [&](bool persistent_state_corrupt) -> bool
    {
        const auto require_canonical_non_fixture_commit_path = RequiresCanonicalNonFixtureCommitPath();
        const auto has_disk_replay_commit_blob_metadata =
            disk_loaded_replay_target_xid.has_value() &&
            disk_loaded_replay_commit_blob_address.has_value() &&
            disk_loaded_replay_commit_blob_bytes.has_value() &&
            disk_loaded_replay_commit_blob_address.value() > 0 &&
            disk_loaded_replay_commit_blob_bytes.value() > 0;
        const auto can_advance_superblock_xid =
            loaded_superblock_checkpoint_xid_ < std::numeric_limits<std::uint64_t>::max();
        const auto disk_replay_pending_window =
            has_disk_replay_commit_blob_metadata &&
            can_advance_superblock_xid &&
            disk_loaded_replay_priority.value_or(0) >= 2 &&
            disk_loaded_replay_target_xid.value() == (loaded_superblock_checkpoint_xid_ + 1);
        last_replay_checkpoint_candidate_present_ = has_disk_replay_commit_blob_metadata;
        last_replay_checkpoint_pending_window_ = disk_replay_pending_window;

        if (persistent_state_corrupt && !persistent_state_path_.empty())
        {
            std::error_code fs_ec;
            auto corrupt_path = persistent_state_path_;
            corrupt_path += L".corrupt";
            std::filesystem::remove(corrupt_path, fs_ec);
            fs_ec.clear();
            std::filesystem::rename(persistent_state_path_, corrupt_path, fs_ec);
            if (fs_ec)
            {
                fs_ec.clear();
                std::filesystem::remove(persistent_state_path_, fs_ec);
            }
        }

        checkpoint_xid_ = disk_loaded_checkpoint_xid;
        recovery_required_ = false;
        recovery_reason_.clear();
        committed_object_map_ = disk_loaded_object_map;
        InvalidateCommittedObjectMapOrderCache();
        committed_spaceman_allocations_ = disk_loaded_allocations;
        committed_spaceman_free_extents_ = disk_loaded_free_extents;
        committed_btree_records_ = disk_loaded_btree_checkpoint_records.empty()
            ? disk_loaded_btree_records
            : disk_loaded_btree_checkpoint_records;
        if (!RebuildCommittedBtreeIndex())
        {
            return false;
        }
        last_committed_xid_ = disk_loaded_last_committed_xid;
        if (disk_loaded_btree_last_committed_xid.has_value())
        {
            last_committed_xid_ = std::max(last_committed_xid_.value_or(0), disk_loaded_btree_last_committed_xid.value());
        }
        if (disk_loaded_inode_last_committed_xid.has_value())
        {
            last_committed_xid_ = std::max(last_committed_xid_.value_or(0), disk_loaded_inode_last_committed_xid.value());
        }
        if (disk_loaded_replay_target_xid.has_value() &&
            (!require_canonical_non_fixture_commit_path || disk_replay_pending_window))
        {
            last_committed_xid_ = std::max(last_committed_xid_.value_or(0), disk_loaded_replay_target_xid.value());
        }
        else if (disk_loaded_native_pending_xid.has_value() &&
                 !IsLikelyRawDevicePath(context_.device_path))
        {
            last_committed_xid_ = std::max(last_committed_xid_.value_or(0), disk_loaded_native_pending_xid.value());
        }
        committed_inodes_ = disk_loaded_inodes;
        InvalidateCommittedInodeOrderCache();
        committed_path_index_ = disk_loaded_path_index;
        committed_directory_links_ = disk_loaded_directory_links;
        RebuildCommittedDirectoryLinkIndex();
        if (!committed_btree_records_.empty())
        {
            std::unordered_map<std::uint64_t, std::vector<FileExtent>> btree_read_extents;
            if (RebuildReadExtentsFromBtreeRecords(
                    committed_btree_records_,
                    committed_inodes_,
                    btree_read_extents))
            {
                committed_read_extents_ = std::move(btree_read_extents);
                InvalidateCommittedReadExtentSnapshotCache();
            }
        }
        next_ephemeral_extent_ = std::max(next_ephemeral_extent_, disk_loaded_next_extent);
        last_commit_blob_address_.reset();
        last_commit_blob_bytes_.reset();
        if (disk_loaded_replay_commit_blob_address.has_value() &&
            disk_loaded_replay_commit_blob_bytes.has_value() &&
            disk_loaded_replay_commit_blob_address.value() > 0 &&
            disk_loaded_replay_commit_blob_bytes.value() > 0 &&
            (!require_canonical_non_fixture_commit_path || disk_replay_pending_window))
        {
            last_commit_blob_address_ = disk_loaded_replay_commit_blob_address.value();
            last_commit_blob_bytes_ = disk_loaded_replay_commit_blob_bytes.value();
            if (disk_loaded_replay_commit_blob_address.value() <=
                (std::numeric_limits<std::uint64_t>::max() - disk_loaded_replay_commit_blob_bytes.value()))
            {
                const auto commit_end = disk_loaded_replay_commit_blob_address.value() +
                                        disk_loaded_replay_commit_blob_bytes.value();
                if (commit_end > next_ephemeral_extent_)
                {
                    next_ephemeral_extent_ = commit_end;
                }
            }
        }
        working_inodes_ = committed_inodes_;
        working_path_index_ = committed_path_index_;
        working_directory_links_ = committed_directory_links_;
        working_spaceman_free_extents_ = committed_spaceman_free_extents_;
        working_read_extents_ = committed_read_extents_;
        pending_read_extent_updates_.clear();
        prepared_payload_ranges_.clear();
        pending_written_ranges_.clear();
        pending_payload_dirty_bytes_ = 0;
        working_next_ephemeral_extent_ = next_ephemeral_extent_;
        RebuildWorkingDirectoryIndexes();
        bool persistent_state_file_present = false;
        if (!persistent_state_path_.empty())
        {
            std::error_code exists_ec;
            persistent_state_file_present = std::filesystem::exists(persistent_state_path_, exists_ec) && !exists_ec;
        }
        if (!require_canonical_non_fixture_commit_path)
        {
            if (last_committed_xid_.has_value() && last_committed_xid_.value() > loaded_superblock_checkpoint_xid_)
            {
                recovery_required_ = true;
                recovery_reason_ = L"PersistentStateAheadOfSuperblock";
            }
            else if (last_committed_xid_.has_value() &&
                     last_committed_xid_.value() > 0 &&
                     last_committed_xid_.value() < loaded_superblock_checkpoint_xid_)
            {
                recovery_required_ = true;
                recovery_reason_ = L"PersistentStateBehindSuperblock";
            }
        }
        if (require_canonical_non_fixture_commit_path &&
            disk_replay_pending_window)
        {
            recovery_required_ = true;
            recovery_reason_ = L"ReplayCheckpointPendingWindow";
        }
        else if (require_canonical_non_fixture_commit_path &&
                 !persistent_state_file_present &&
                 last_committed_xid_.has_value() &&
                 last_committed_xid_.value() > loaded_superblock_checkpoint_xid_)
        {
            recovery_required_ = true;
            recovery_reason_ = L"PersistentStateAheadOfSuperblock";
        }
        if (!EnsureRootState())
        {
            return false;
        }
        if (IsLikelyRawDevicePath(context_.device_path))
        {
            const auto read_extents_snapshot = committed_read_extents_;
            if (!RefreshNativeReadExtentProjection())
            {
                committed_read_extents_ = read_extents_snapshot;
                InvalidateCommittedReadExtentSnapshotCache();
            }
        }
        return true;
    };

    if (RequiresCanonicalNonFixtureCommitPath())
    {
        // Production non-fixture mounts are disk/replay-checkpoint authoritative.
        // Sidecar payload parsing is fixture/test-only and bypassed.
        return apply_disk_fallback(false);
    }

    if (persistent_state_path_.empty() || !std::filesystem::exists(persistent_state_path_))
    {
        return apply_disk_fallback(false);
    }

    const auto load_persistent_state_file = [&]() -> bool
    {
        constexpr std::uint32_t kMaxPersistentRecordCount = 1u << 20; // 1,048,576
        constexpr std::uint32_t kMaxPersistentNameChars = 1024;
        constexpr std::uint32_t kMaxPersistentPathChars = 32u * 1024u;
        constexpr std::uint32_t kMaxPersistentBlobBytes = 4u * 1024u * 1024u;
        std::ifstream input(persistent_state_path_, std::ios::binary);
        if (!input.good())
        {
            return false;
        }

        std::uint32_t persistent_state_checksum = 0;
        std::uint32_t computed_state_checksum = kCheckpointChecksumSeed;
        const auto update_state_checksum_raw = [&computed_state_checksum](const unsigned char* bytes, std::size_t length)
        {
            if (bytes == nullptr || length == 0)
            {
                return;
            }
            computed_state_checksum = UpdateFnv1a(
                computed_state_checksum,
                reinterpret_cast<const std::byte*>(bytes),
                length);
        };
        const auto update_state_checksum_bytes = [&computed_state_checksum](const std::byte* bytes, std::size_t length)
        {
            if (bytes == nullptr || length == 0)
            {
                return;
            }
            computed_state_checksum = UpdateFnv1a(computed_state_checksum, bytes, length);
        };

        auto read_u32 = [&](std::uint32_t& value, bool include_checksum = true) -> bool
        {
            std::array<unsigned char, 4> bytes{};
            input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
            if (!input.good())
            {
                return false;
            }
            if (include_checksum)
            {
                update_state_checksum_raw(bytes.data(), bytes.size());
            }

            value = static_cast<std::uint32_t>(bytes[0]) |
                    (static_cast<std::uint32_t>(bytes[1]) << 8) |
                    (static_cast<std::uint32_t>(bytes[2]) << 16) |
                    (static_cast<std::uint32_t>(bytes[3]) << 24);
            return true;
        };

        auto read_u64 = [&](std::uint64_t& value, bool include_checksum = true) -> bool
        {
            std::array<unsigned char, 8> bytes{};
            input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
            if (!input.good())
            {
                return false;
            }
            if (include_checksum)
            {
                update_state_checksum_raw(bytes.data(), bytes.size());
            }

            value = static_cast<std::uint64_t>(bytes[0]) |
                    (static_cast<std::uint64_t>(bytes[1]) << 8) |
                    (static_cast<std::uint64_t>(bytes[2]) << 16) |
                    (static_cast<std::uint64_t>(bytes[3]) << 24) |
                    (static_cast<std::uint64_t>(bytes[4]) << 32) |
                    (static_cast<std::uint64_t>(bytes[5]) << 40) |
                    (static_cast<std::uint64_t>(bytes[6]) << 48) |
                    (static_cast<std::uint64_t>(bytes[7]) << 56);
            return true;
        };

        auto read_wstring = [&](std::uint32_t length, std::wstring& value, bool include_checksum = true) -> bool
        {
            value.clear();
            if (length == 0)
            {
                return true;
            }
            if (length > kMaxPersistentPathChars)
            {
                return false;
            }

            std::vector<wchar_t> buffer(length);
            input.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(sizeof(wchar_t) * length));
            if (!input.good())
            {
                return false;
            }
            if (include_checksum)
            {
                update_state_checksum_raw(
                    reinterpret_cast<const unsigned char*>(buffer.data()),
                    static_cast<std::size_t>(sizeof(wchar_t) * length));
            }

            value.assign(buffer.begin(), buffer.end());
            return true;
        };
        auto read_bytes = [&](std::uint32_t length, std::vector<std::byte>& value, bool include_checksum = true) -> bool
        {
            value.clear();
            if (length == 0)
            {
                return true;
            }
            if (length > kMaxPersistentBlobBytes)
            {
                return false;
            }

            value.resize(length);
            input.read(reinterpret_cast<char*>(value.data()), static_cast<std::streamsize>(length));
            if (!input.good())
            {
                return false;
            }
            if (include_checksum)
            {
                update_state_checksum_bytes(value.data(), value.size());
            }
            return true;
        };
        auto is_block_aligned_extent = [this](std::uint64_t physical_address, std::uint64_t bytes) -> bool
        {
            const auto block_bytes = static_cast<std::uint64_t>(std::max<std::uint32_t>(1u, block_size_));
            return (physical_address % block_bytes) == 0 &&
                   (bytes % block_bytes) == 0;
        };

        std::array<char, 16> magic{};
        input.read(magic.data(), static_cast<std::streamsize>(magic.size()));
        if (!input.good())
        {
            return false;
        }

        constexpr std::array<char, 16> kExpectedMagic =
        {
            'A', 'P', 'F', 'S', 'R', 'W', 'S', 'T', 'A', 'T', 'E', '2', '\0', '\0', '\0', '\0'
        };
        if (magic != kExpectedMagic)
        {
            return false;
        }
        update_state_checksum_raw(
            reinterpret_cast<const unsigned char*>(magic.data()),
            magic.size());

        std::uint32_t version = 0;
        std::uint32_t object_count = 0;
        std::uint32_t allocation_count = 0;
        std::uint32_t inode_count = 0;
        std::uint32_t btree_record_count = 0;
        std::uint32_t free_extent_count = 0;
        std::uint64_t persisted_checkpoint_xid = 0;
        std::uint64_t persisted_last_commit_xid = 0;
        std::uint64_t persisted_next_extent = 0;
        std::uint64_t persisted_next_object_id = 0;
        std::uint64_t persisted_last_commit_blob_address = 0;
        std::uint64_t persisted_last_commit_blob_bytes = 0;

        if (!read_u32(version))
        {
            return false;
        }
        if (version >= 6 && !read_u32(persistent_state_checksum, false))
        {
            return false;
        }
        if (!read_u64(persisted_checkpoint_xid) ||
            !read_u64(persisted_last_commit_xid) ||
            !read_u64(persisted_next_extent) ||
            !read_u64(persisted_last_commit_blob_address) ||
            !read_u64(persisted_last_commit_blob_bytes) ||
            !read_u32(object_count) ||
            !read_u32(allocation_count))
        {
            return false;
        }
        if (version != 1 &&
            version != 2 &&
            version != 3 &&
            version != 4 &&
            version != 5 &&
            version != 6 &&
            version != 7)
        {
            return false;
        }
        if (version >= 2 && !read_u32(inode_count))
        {
            return false;
        }
        if (version >= 3 && !read_u32(btree_record_count))
        {
            return false;
        }
        if (version >= 4 && !read_u32(free_extent_count))
        {
            return false;
        }
        if (version >= 5 && !read_u64(persisted_next_object_id))
        {
            return false;
        }
    if (object_count > kMaxPersistentRecordCount ||
        allocation_count > kMaxPersistentRecordCount ||
        inode_count > kMaxPersistentRecordCount ||
        btree_record_count > kMaxPersistentRecordCount ||
        free_extent_count > kMaxPersistentRecordCount)
    {
        return false;
    }
    if (total_blocks_ != 0)
    {
        const auto bounded_block_records = std::min<std::uint64_t>(
            total_blocks_,
            static_cast<std::uint64_t>(kMaxPersistentRecordCount));
        if (static_cast<std::uint64_t>(object_count) > bounded_block_records ||
            static_cast<std::uint64_t>(allocation_count) > bounded_block_records ||
            static_cast<std::uint64_t>(free_extent_count) > bounded_block_records)
        {
            return false;
        }
    }

    for (std::uint32_t index = 0; index < object_count; ++index)
    {
        ObjectMapUpdate entry{};
        if (!read_u64(entry.object_id) ||
            !read_u64(entry.physical_address) ||
            !read_u64(entry.logical_size) ||
            !read_u64(entry.xid))
        {
            return false;
        }
        if (entry.object_id == 0)
        {
            return false;
        }
        if (HasPhysicalObjectMapping(entry))
        {
            auto [_, inserted] = committed_object_map_.emplace(entry.object_id, entry);
            if (!inserted)
            {
                return false;
            }
        }
    }
    InvalidateCommittedObjectMapOrderCache();

    committed_spaceman_allocations_.reserve(allocation_count);
    for (std::uint32_t index = 0; index < allocation_count; ++index)
    {
        SpacemanAllocation allocation{};
        if (!read_u64(allocation.physical_address) ||
            !read_u64(allocation.bytes))
        {
            return false;
        }
        if (allocation.physical_address == 0 || allocation.bytes == 0)
        {
            return false;
        }
        const auto aligned_bytes = AlignExtentBytes(allocation.bytes);
        if (aligned_bytes == 0 || aligned_bytes != allocation.bytes)
        {
            return false;
        }
        allocation.bytes = aligned_bytes;
        if (!is_block_aligned_extent(allocation.physical_address, allocation.bytes))
        {
            return false;
        }
        if (total_blocks_ != 0)
        {
            if (block_size_ == 0 ||
                total_blocks_ > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
            {
                return false;
            }

            const auto container_bytes = total_blocks_ * static_cast<std::uint64_t>(block_size_);
            if (allocation.physical_address > (std::numeric_limits<std::uint64_t>::max() - allocation.bytes) ||
                (allocation.physical_address + allocation.bytes) > container_bytes)
            {
                return false;
            }
        }
        if (allocation.physical_address > (std::numeric_limits<std::uint64_t>::max() - allocation.bytes))
        {
            return false;
        }
        committed_spaceman_allocations_.push_back(allocation);
    }
    for (std::size_t i = 0; i < committed_spaceman_allocations_.size(); ++i)
    {
        const auto& lhs = committed_spaceman_allocations_[i];
        if (lhs.physical_address > (std::numeric_limits<std::uint64_t>::max() - lhs.bytes))
        {
            return false;
        }
        const auto lhs_end = lhs.physical_address + lhs.bytes;
        for (std::size_t j = i + 1; j < committed_spaceman_allocations_.size(); ++j)
        {
            const auto& rhs = committed_spaceman_allocations_[j];
            if (rhs.physical_address > (std::numeric_limits<std::uint64_t>::max() - rhs.bytes))
            {
                return false;
            }
            const auto rhs_end = rhs.physical_address + rhs.bytes;
            if (lhs.physical_address < rhs_end && rhs.physical_address < lhs_end)
            {
                return false;
            }
        }
    }

    if (version >= 2)
    {
        for (std::uint32_t index = 0; index < inode_count; ++index)
        {
            InodeRecord inode{};
            std::uint32_t flags = 0;
            std::uint32_t name_length = 0;
            std::uint32_t path_length = 0;
            if (!read_u64(inode.object_id) ||
                !read_u64(inode.parent_object_id) ||
                !read_u64(inode.logical_size) ||
                !read_u64(inode.data_physical_address) ||
                !read_u64(inode.xid) ||
                (version >= 7 && !read_u64(inode.timestamp_utc)) ||
                !read_u32(flags) ||
                !read_u32(name_length) ||
                !read_u32(path_length) ||
                !read_wstring(name_length, inode.name) ||
                !read_wstring(path_length, inode.full_path))
            {
                return false;
            }
            if (name_length > kMaxPersistentNameChars ||
                path_length == 0 ||
                path_length > kMaxPersistentPathChars)
            {
                return false;
            }

            if (inode.object_id == 0 || inode.full_path.empty())
            {
                return false;
            }
            const auto normalized_path = NormalizePath(inode.full_path);
            if (normalized_path != inode.full_path)
            {
                return false;
            }
            if (committed_inodes_.contains(inode.object_id))
            {
                return false;
            }

            inode.is_directory = (flags & 0x1u) != 0;
            committed_inodes_.emplace(inode.object_id, inode);
            const auto path_key = CanonicalPathKeyFromNormalizedPath(inode.full_path);
            if (!path_key.empty())
            {
                auto [path_it, inserted] = committed_path_index_.emplace(path_key, inode.object_id);
                if (!inserted && path_it->second != inode.object_id)
                {
                    return false;
                }
            }
        }
    }
    if (version >= 3)
    {
        committed_btree_records_.reserve(btree_record_count);
        for (std::uint32_t index = 0; index < btree_record_count; ++index)
        {
            std::uint32_t kind_value = 0;
            std::uint32_t tombstone_flag = 0;
            std::uint32_t key_length = 0;
            std::uint32_t value_length = 0;
            BtreeRecord record{};
            if (!read_u32(kind_value) ||
                !read_u32(tombstone_flag) ||
                !read_u32(key_length) ||
                !read_u32(value_length) ||
                !read_bytes(key_length, record.key) ||
                !read_bytes(value_length, record.value))
            {
                return false;
            }
            if (key_length == 0 ||
                key_length > kMaxPersistentBlobBytes ||
                value_length > kMaxPersistentBlobBytes)
            {
                return false;
            }

            if (kind_value < static_cast<std::uint32_t>(BtreeRecordKind::Inode) ||
                kind_value > static_cast<std::uint32_t>(BtreeRecordKind::FileExtent))
            {
                return false;
            }

            record.kind = static_cast<BtreeRecordKind>(kind_value);
            record.tombstone = tombstone_flag != 0;
            committed_btree_records_.push_back(std::move(record));
        }
        committed_btree_records_ = CanonicalizeBtreeRecords(committed_btree_records_);
        if (!RebuildCommittedBtreeIndex())
        {
            return false;
        }
        if (!committed_btree_records_.empty())
        {
            std::unordered_map<std::uint64_t, std::vector<FileExtent>> btree_read_extents;
            if (RebuildReadExtentsFromBtreeRecords(
                    committed_btree_records_,
                    committed_inodes_,
                    btree_read_extents))
            {
                committed_read_extents_ = std::move(btree_read_extents);
                InvalidateCommittedReadExtentSnapshotCache();
            }
        }
    }
        if (version >= 4)
        {
            committed_spaceman_free_extents_.reserve(free_extent_count);
            working_spaceman_free_extents_.clear();
            tracking_spaceman_free_extent_delta_ = true;
            ScopeExit clear_tracking_spaceman_free_extent_delta{
                [&]()
                {
                    tracking_spaceman_free_extent_delta_ = false;
                }};
            for (std::uint32_t index = 0; index < free_extent_count; ++index)
            {
                SpacemanAllocation free_extent{};
                if (!read_u64(free_extent.physical_address) ||
                    !read_u64(free_extent.bytes) ||
                    free_extent.physical_address == 0 ||
                    free_extent.bytes == 0)
                {
                    return false;
                }
                const auto aligned_bytes = AlignExtentBytes(free_extent.bytes);
                if (aligned_bytes == 0 ||
                    aligned_bytes != free_extent.bytes ||
                    !is_block_aligned_extent(free_extent.physical_address, free_extent.bytes))
                {
                    return false;
                }
                if (!FreeExtent(free_extent.physical_address, free_extent.bytes))
                {
                    return false;
                }
            }
            committed_spaceman_free_extents_ = working_spaceman_free_extents_;
        }

        if (version >= 6 && persistent_state_checksum != computed_state_checksum)
        {
            return false;
        }
        if (input.peek() != std::char_traits<char>::eof())
        {
            return false;
        }

    const auto require_canonical_non_fixture_commit_path = RequiresCanonicalNonFixtureCommitPath();

    checkpoint_xid_ = std::max(checkpoint_xid_, persisted_checkpoint_xid);
    if (!require_canonical_non_fixture_commit_path &&
        persisted_checkpoint_xid > 0)
    {
        if (persisted_checkpoint_xid > loaded_superblock_checkpoint_xid_)
        {
            recovery_required_ = true;
            recovery_reason_ = L"PersistentStateAheadOfSuperblock";
        }
        else if (persisted_checkpoint_xid < loaded_superblock_checkpoint_xid_)
        {
            recovery_required_ = true;
            recovery_reason_ = L"PersistentStateBehindSuperblock";
        }
    }
    if (!require_canonical_non_fixture_commit_path &&
        persisted_next_extent > next_ephemeral_extent_)
    {
        next_ephemeral_extent_ = persisted_next_extent;
    }
    RefreshObjectIdAllocator();
    if (!require_canonical_non_fixture_commit_path &&
        version >= 5 &&
        persisted_next_object_id > next_generated_object_id_)
    {
        next_generated_object_id_ = persisted_next_object_id;
        if (next_generated_object_id_ == 0)
        {
            next_generated_object_id_ = 1;
        }
    }
    const auto persisted_commit_blob_valid =
        !require_canonical_non_fixture_commit_path &&
        persisted_last_commit_blob_address > 0 &&
        persisted_last_commit_blob_bytes > 0 &&
        persisted_last_commit_xid > 0 &&
        ValidateReplayCommitBlobCandidate(
            persisted_last_commit_blob_address,
            persisted_last_commit_blob_bytes,
            loaded_superblock_checkpoint_xid_,
            persisted_last_commit_xid);
    const auto has_disk_replay_commit_blob_metadata =
        disk_loaded_replay_target_xid.has_value() &&
        disk_loaded_replay_commit_blob_address.has_value() &&
        disk_loaded_replay_commit_blob_bytes.has_value() &&
        disk_loaded_replay_commit_blob_address.value() > 0 &&
        disk_loaded_replay_commit_blob_bytes.value() > 0;
    const auto can_advance_superblock_xid =
        loaded_superblock_checkpoint_xid_ < std::numeric_limits<std::uint64_t>::max();
    const auto disk_replay_pending_window =
        has_disk_replay_commit_blob_metadata &&
        can_advance_superblock_xid &&
        disk_loaded_replay_priority.value_or(0) >= 2 &&
        disk_loaded_replay_target_xid.value() == (loaded_superblock_checkpoint_xid_ + 1);
    last_replay_checkpoint_candidate_present_ = has_disk_replay_commit_blob_metadata;
    last_replay_checkpoint_pending_window_ = disk_replay_pending_window;
    if (require_canonical_non_fixture_commit_path &&
        disk_replay_pending_window)
    {
        // Canonical non-fixture recovery reason should prioritize pending
        // replay-checkpoint metadata over sidecar checkpoint drift markers.
        recovery_required_ = true;
        recovery_reason_ = L"ReplayCheckpointPendingWindow";
    }

    const auto apply_commit_blob_metadata = [this](std::uint64_t address, std::uint64_t bytes)
    {
        last_commit_blob_address_ = address;
        last_commit_blob_bytes_ = bytes;
        if (address <= (std::numeric_limits<std::uint64_t>::max() - bytes))
        {
            const auto commit_end = address + bytes;
            if (commit_end > next_ephemeral_extent_)
            {
                next_ephemeral_extent_ = commit_end;
            }
        }
    };

    last_committed_xid_.reset();
    last_commit_blob_address_.reset();
    last_commit_blob_bytes_.reset();

    if (require_canonical_non_fixture_commit_path)
    {
        // Canonical non-fixture replay prefers on-disk replay-checkpoint metadata.
        if (disk_replay_pending_window)
        {
            last_committed_xid_ = disk_loaded_replay_target_xid.value();
            apply_commit_blob_metadata(
                disk_loaded_replay_commit_blob_address.value(),
                disk_loaded_replay_commit_blob_bytes.value());
        }
    }
    else
    {
        if (persisted_commit_blob_valid)
        {
            apply_commit_blob_metadata(
                persisted_last_commit_blob_address,
                persisted_last_commit_blob_bytes);
        }

        if (persisted_last_commit_xid > 0 &&
            (persisted_commit_blob_valid || !disk_loaded_replay_target_xid.has_value()))
        {
            last_committed_xid_ = persisted_last_commit_xid;
        }
        if (disk_loaded_replay_target_xid.has_value())
        {
            last_committed_xid_ = std::max(last_committed_xid_.value_or(0), disk_loaded_replay_target_xid.value());
        }

        const auto prefer_replay_commit_blob =
            !persisted_commit_blob_valid ||
            (disk_loaded_replay_target_xid.has_value() &&
             disk_loaded_replay_target_xid.value() >= persisted_last_commit_xid);
        if ((prefer_replay_commit_blob ||
             !last_commit_blob_address_.has_value() ||
             !last_commit_blob_bytes_.has_value()) &&
            has_disk_replay_commit_blob_metadata)
        {
            apply_commit_blob_metadata(
                disk_loaded_replay_commit_blob_address.value(),
                disk_loaded_replay_commit_blob_bytes.value());
        }
    }

    if (require_canonical_non_fixture_commit_path)
    {
        // Canonical non-fixture mounts keep committed metadata state sourced from
        // on-disk checkpoints/superblock state, not sidecar payload fields.
        committed_object_map_ = disk_loaded_object_map;
        InvalidateCommittedObjectMapOrderCache();
        committed_spaceman_allocations_ = disk_loaded_allocations;
        committed_spaceman_free_extents_ = disk_loaded_free_extents;
        committed_btree_records_ = disk_loaded_btree_checkpoint_records.empty()
            ? disk_loaded_btree_records
            : disk_loaded_btree_checkpoint_records;
        if (!RebuildCommittedBtreeIndex())
        {
            return false;
        }
        committed_inodes_ = disk_loaded_inodes;
        InvalidateCommittedInodeOrderCache();
        committed_path_index_ = disk_loaded_path_index;
        committed_directory_links_ = disk_loaded_directory_links;
        RebuildCommittedDirectoryLinkIndex();
        checkpoint_xid_ = disk_loaded_checkpoint_xid;
        next_ephemeral_extent_ = std::max(next_ephemeral_extent_, disk_loaded_next_extent);
        RefreshObjectIdAllocator();
        // Canonical non-fixture mounts derive runtime xid progression strictly from
        // on-disk canonical sources (container/btree/inode/replay checkpoints).
        if (disk_loaded_last_committed_xid.has_value())
        {
            last_committed_xid_ = std::max(last_committed_xid_.value_or(0), disk_loaded_last_committed_xid.value());
        }
        if (disk_loaded_btree_last_committed_xid.has_value())
        {
            last_committed_xid_ = std::max(last_committed_xid_.value_or(0), disk_loaded_btree_last_committed_xid.value());
        }
        if (disk_loaded_inode_last_committed_xid.has_value())
        {
            last_committed_xid_ = std::max(last_committed_xid_.value_or(0), disk_loaded_inode_last_committed_xid.value());
        }
        if (disk_replay_pending_window && disk_loaded_replay_target_xid.has_value())
        {
            last_committed_xid_ = std::max(last_committed_xid_.value_or(0), disk_loaded_replay_target_xid.value());
        }
        if (checkpoint_xid_ > 0)
        {
            last_committed_xid_ = std::max(last_committed_xid_.value_or(0), checkpoint_xid_);
        }
    }

    working_spaceman_free_extents_ = committed_spaceman_free_extents_;
    working_next_ephemeral_extent_ = next_ephemeral_extent_;

        if (!EnsureRootState())
        {
            return false;
        }
        if (IsLikelyRawDevicePath(context_.device_path))
        {
            const auto read_extents_snapshot = committed_read_extents_;
            if (!RefreshNativeReadExtentProjection())
            {
                committed_read_extents_ = read_extents_snapshot;
                InvalidateCommittedReadExtentSnapshotCache();
            }
        }

        return ValidateInodeGraphState(
            committed_inodes_,
            committed_path_index_,
            committed_directory_links_,
            /*require_root_object=*/true);
    };

    if (!load_persistent_state_file())
    {
        // Non-fixture canonical mounts keep sidecar payload parse failures
        // non-fatal and avoid sidecar corruption marker churn. Disk/replay
        // checkpoint reconciliation remains authoritative.
        const auto parse_failure_corrupts_sidecar = !RequiresCanonicalNonFixtureCommitPath();
        return apply_disk_fallback(parse_failure_corrupts_sidecar);
    }

    return true;
}

bool MetadataStore::PersistPersistentState(std::uint64_t commit_blob_address, std::uint64_t commit_blob_bytes)
{
    if (!ValidateCommitBlobLocation(commit_blob_address, commit_blob_bytes))
    {
        return false;
    }

    if (RequiresCanonicalNonFixtureCommitPath())
    {
        // Production non-fixture commit/replay state is disk-authoritative.
        // Sidecar persistence is fixture/test-only and intentionally skipped.
        return true;
    }

    if (persistent_state_path_.empty())
    {
        persistent_state_path_ = BuildPersistentStatePath(context_);
    }
    if (persistent_state_path_.empty())
    {
        return false;
    }

    std::error_code ec;
    std::filesystem::create_directories(persistent_state_path_.parent_path(), ec);
    if (ec)
    {
        return false;
    }

    auto tmp_path = persistent_state_path_;
    tmp_path += L".tmp";
    std::ofstream output(tmp_path, std::ios::binary | std::ios::trunc);
    if (!output.good())
    {
        return false;
    }

    constexpr std::array<char, 16> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'T', 'A', 'T', 'E', '2', '\0', '\0', '\0', '\0'
    };
    constexpr std::streamoff kPersistentStateChecksumOffset =
        static_cast<std::streamoff>(kMagic.size() + sizeof(std::uint32_t));

    std::uint32_t persistent_state_checksum = kCheckpointChecksumSeed;
    const auto update_state_checksum = [&persistent_state_checksum](const void* data, std::size_t bytes)
    {
        if (data == nullptr || bytes == 0)
        {
            return;
        }
        persistent_state_checksum = UpdateFnv1a(
            persistent_state_checksum,
            reinterpret_cast<const std::byte*>(data),
            bytes);
    };
    const auto write_raw = [&](const void* data, std::size_t bytes, bool include_checksum = true) -> bool
    {
        if (bytes == 0)
        {
            return true;
        }

        output.write(
            reinterpret_cast<const char*>(data),
            static_cast<std::streamsize>(bytes));
        if (!output.good())
        {
            return false;
        }
        if (include_checksum)
        {
            update_state_checksum(data, bytes);
        }
        return true;
    };

    const auto write_u32 = [&](std::uint32_t value, bool include_checksum = true) -> bool
    {
        std::array<unsigned char, 4> bytes
        {
            static_cast<unsigned char>(value & 0xffu),
            static_cast<unsigned char>((value >> 8) & 0xffu),
            static_cast<unsigned char>((value >> 16) & 0xffu),
            static_cast<unsigned char>((value >> 24) & 0xffu),
        };
        return write_raw(bytes.data(), bytes.size(), include_checksum);
    };

    const auto write_u64 = [&](std::uint64_t value, bool include_checksum = true) -> bool
    {
        std::array<unsigned char, 8> bytes
        {
            static_cast<unsigned char>(value & 0xffu),
            static_cast<unsigned char>((value >> 8) & 0xffu),
            static_cast<unsigned char>((value >> 16) & 0xffu),
            static_cast<unsigned char>((value >> 24) & 0xffu),
            static_cast<unsigned char>((value >> 32) & 0xffu),
            static_cast<unsigned char>((value >> 40) & 0xffu),
            static_cast<unsigned char>((value >> 48) & 0xffu),
            static_cast<unsigned char>((value >> 56) & 0xffu),
        };
        return write_raw(bytes.data(), bytes.size(), include_checksum);
    };

    const auto write_wstring = [&](const std::wstring& value, bool include_checksum = true) -> bool
    {
        if (value.empty())
        {
            return true;
        }

        return write_raw(
            value.data(),
            value.size() * sizeof(wchar_t),
            include_checksum);
    };

    const auto* persisted_object_entries = OrderedCommittedObjectMapEntries();
    if (!persisted_object_entries)
    {
        output.close();
        std::filesystem::remove(tmp_path, ec);
        return false;
    }

    if (!write_raw(kMagic.data(), kMagic.size()) ||
        !write_u32(7) ||
        !write_u32(0, false) ||
        !write_u64(checkpoint_xid_) ||
        !write_u64(last_committed_xid_.value_or(0)) ||
        !write_u64(next_ephemeral_extent_) ||
        !write_u64(commit_blob_address) ||
        !write_u64(commit_blob_bytes) ||
        !write_u32(static_cast<std::uint32_t>(persisted_object_entries->size())) ||
        !write_u32(static_cast<std::uint32_t>(committed_spaceman_allocations_.size())) ||
        !write_u32(static_cast<std::uint32_t>(committed_inodes_.size())) ||
        !write_u32(static_cast<std::uint32_t>(committed_btree_records_.size())) ||
        !write_u32(static_cast<std::uint32_t>(committed_spaceman_free_extents_.size())) ||
        !write_u64(next_generated_object_id_))
    {
        output.close();
        std::filesystem::remove(tmp_path, ec);
        return false;
    }

    for (const auto& entry : *persisted_object_entries)
    {
        if (entry.update == nullptr)
        {
            output.close();
            std::filesystem::remove(tmp_path, ec);
            return false;
        }
        if (!write_u64(entry.update->object_id) ||
            !write_u64(entry.update->physical_address) ||
            !write_u64(entry.update->logical_size) ||
            !write_u64(entry.update->xid))
        {
            output.close();
            std::filesystem::remove(tmp_path, ec);
            return false;
        }
    }

    for (const auto& allocation : committed_spaceman_allocations_)
    {
        if (!write_u64(allocation.physical_address) ||
            !write_u64(allocation.bytes))
        {
            output.close();
            std::filesystem::remove(tmp_path, ec);
            return false;
        }
    }

    for (const auto& [object_id, inode] : committed_inodes_)
    {
        const std::uint32_t flags = inode.is_directory ? 0x1u : 0u;
        if (!write_u64(object_id) ||
            !write_u64(inode.parent_object_id) ||
            !write_u64(inode.logical_size) ||
            !write_u64(inode.data_physical_address) ||
            !write_u64(inode.xid) ||
            !write_u64(inode.timestamp_utc) ||
            !write_u32(flags) ||
            !write_u32(static_cast<std::uint32_t>(inode.name.size())) ||
            !write_u32(static_cast<std::uint32_t>(inode.full_path.size())) ||
            !write_wstring(inode.name) ||
            !write_wstring(inode.full_path))
        {
            output.close();
            std::filesystem::remove(tmp_path, ec);
            return false;
        }
    }
    for (const auto& record : committed_btree_records_)
    {
        if (!write_u32(static_cast<std::uint32_t>(record.kind)) ||
            !write_u32(record.tombstone ? 1u : 0u) ||
            !write_u32(static_cast<std::uint32_t>(record.key.size())) ||
            !write_u32(static_cast<std::uint32_t>(record.value.size())))
        {
            output.close();
            std::filesystem::remove(tmp_path, ec);
            return false;
        }

        if (!record.key.empty())
        {
            if (!write_raw(record.key.data(), record.key.size()))
            {
                output.close();
                std::filesystem::remove(tmp_path, ec);
                return false;
            }
        }
        if (!record.value.empty())
        {
            if (!write_raw(record.value.data(), record.value.size()))
            {
                output.close();
                std::filesystem::remove(tmp_path, ec);
                return false;
            }
        }
    }
    for (const auto& free_extent : committed_spaceman_free_extents_)
    {
        if (!write_u64(free_extent.physical_address) ||
            !write_u64(free_extent.bytes))
        {
            output.close();
            std::filesystem::remove(tmp_path, ec);
            return false;
        }
    }

    if (!output.seekp(kPersistentStateChecksumOffset, std::ios::beg) ||
        !write_u32(persistent_state_checksum, false) ||
        !output.seekp(0, std::ios::end))
    {
        output.close();
        std::filesystem::remove(tmp_path, ec);
        return false;
    }

    output.flush();
    if (!output.good())
    {
        output.close();
        std::filesystem::remove(tmp_path, ec);
        return false;
    }
    output.close();

    std::filesystem::rename(tmp_path, persistent_state_path_, ec);
    if (ec)
    {
        std::filesystem::remove(persistent_state_path_, ec);
        ec.clear();
        std::filesystem::rename(tmp_path, persistent_state_path_, ec);
    }
    if (ec)
    {
        std::filesystem::remove(tmp_path, ec);
        return false;
    }

    return true;
}

std::filesystem::path MetadataStore::BuildPersistentStatePath(const VolumeContext& context)
{
    std::error_code ec;
    auto root = std::filesystem::temp_directory_path(ec);
    if (ec)
    {
        return {};
    }

    root /= "ApfsAccess";
    root /= "rw-state";

    const auto key = context.device_path + L"|" + context.volume_name;
    const auto stable_id = StableObjectIdFromPath(key);
    return root / (std::to_wstring(stable_id) + L".bin");
}

bool MetadataStore::BuildCommitBlob(std::uint64_t target_xid)
{
    ScopedPerfTimer perf_scope(build_commit_blob_perf_);

    if (!IsNativeWriteReady())
    {
        return false;
    }

    constexpr std::array<char, 13> kScaffoldMagicV3 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '3', '\0'
    };
    constexpr std::array<char, 13> kCanonicalMagicV3 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'C', 'A', 'N', 'O', 'N', '3', '\0'
    };
    constexpr std::size_t kCommitBlobChecksumOffset = 13 + 8 + 8 + 4 + 4 + 4 + 4 + 4;
    constexpr std::size_t kCommitBlobPayloadOffset = kCommitBlobChecksumOffset + sizeof(std::uint32_t);

    const auto checked_add_size = [](std::size_t lhs, std::size_t rhs, std::size_t& out_sum) -> bool
    {
        if (lhs > (std::numeric_limits<std::size_t>::max() - rhs))
        {
            return false;
        }
        out_sum = lhs + rhs;
        return true;
    };
    const auto checked_multiply_size = [](std::size_t lhs, std::size_t rhs, std::size_t& out_product) -> bool
    {
        if (lhs != 0 && rhs > (std::numeric_limits<std::size_t>::max() / lhs))
        {
            return false;
        }
        out_product = lhs * rhs;
        return true;
    };
    const auto align_blob_reserve = [this](std::size_t bytes) -> std::optional<std::size_t>
    {
        if (block_size_ == 0)
        {
            return std::nullopt;
        }
        const auto block_size = static_cast<std::size_t>(block_size_);
        const auto remainder = bytes % block_size;
        if (remainder == 0)
        {
            return bytes;
        }
        const auto padding = block_size - remainder;
        if (bytes > (std::numeric_limits<std::size_t>::max() - padding))
        {
            return std::nullopt;
        }
        return bytes + padding;
    };

    std::size_t reserve_bytes = kCommitBlobPayloadOffset;
    std::size_t object_map_bytes = 0;
    std::size_t spaceman_allocation_bytes = 0;
    std::size_t spaceman_deallocation_bytes = 0;
    std::size_t unpadded_blob_bytes = 0;
    bool precise_reserve = checked_multiply_size(pending_object_map_updates_.size(), 32u, object_map_bytes) &&
        checked_add_size(reserve_bytes, object_map_bytes, reserve_bytes) &&
        checked_multiply_size(pending_spaceman_allocations_.size(), 16u, spaceman_allocation_bytes) &&
        checked_add_size(reserve_bytes, spaceman_allocation_bytes, reserve_bytes) &&
        checked_multiply_size(pending_spaceman_deallocations_.size(), 16u, spaceman_deallocation_bytes) &&
        checked_add_size(reserve_bytes, spaceman_deallocation_bytes, reserve_bytes);
    if (precise_reserve)
    {
        for (const auto& record : pending_btree_records_)
        {
            std::size_t record_bytes = 16;
            precise_reserve =
                checked_add_size(record_bytes, record.key.size(), record_bytes) &&
                checked_add_size(record_bytes, record.value.size(), record_bytes) &&
                checked_add_size(reserve_bytes, record_bytes, reserve_bytes);
            if (!precise_reserve)
            {
                break;
            }
        }
    }
    if (precise_reserve)
    {
        unpadded_blob_bytes = reserve_bytes;
        if (auto aligned_reserve = align_blob_reserve(reserve_bytes); aligned_reserve.has_value())
        {
            reserve_bytes = aligned_reserve.value();
        }
        else
        {
            precise_reserve = false;
        }
    }
    if (!precise_reserve)
    {
        reserve_bytes = static_cast<std::size_t>(block_size_);
        commit_blob_reserve_fallback_count_.fetch_add(1, std::memory_order_relaxed);
    }
    else
    {
        reserve_bytes = std::max<std::size_t>(reserve_bytes, static_cast<std::size_t>(block_size_));
        commit_blob_precise_reserve_count_.fetch_add(1, std::memory_order_relaxed);
    }

    const bool reusing_commit_blob_storage =
        commit_blob_serialization_buffer_.capacity() >= reserve_bytes;
    if (reusing_commit_blob_storage)
    {
        commit_blob_serialization_buffer_.clear();
    }
    else
    {
        commit_blob_serialization_buffer_.clear();
        commit_blob_serialization_buffer_.reserve(reserve_bytes);
    }

    const auto use_scaffold_blob = ShouldUseScaffoldCommitBlobForCurrentContext();
    uses_scaffold_commit_blob_ = use_scaffold_blob;
    const auto& selected_magic = use_scaffold_blob ? kScaffoldMagicV3 : kCanonicalMagicV3;
    last_commit_blob_magic_ = use_scaffold_blob ? "APFSRWSCAFF3" : "APFSRWCANON3";

    if (precise_reserve)
    {
        auto& direct_blob = commit_blob_serialization_buffer_;
        direct_blob.resize(reserve_bytes, std::byte{0});
        std::fill(direct_blob.begin(), direct_blob.end(), std::byte{0});
        if (reserve_bytes < kCommitBlobPayloadOffset)
        {
            return false;
        }

        for (std::size_t index = 0; index < selected_magic.size(); ++index)
        {
            direct_blob[index] = static_cast<std::byte>(selected_magic[index]);
        }
        WriteLe64(direct_blob, 13, checkpoint_xid_);
        WriteLe64(direct_blob, 21, target_xid);
        WriteLe32(direct_blob, 29, static_cast<std::uint32_t>(pending_mutations_.size()));
        WriteLe32(direct_blob, 33, static_cast<std::uint32_t>(pending_object_map_updates_.size()));
        WriteLe32(direct_blob, 37, static_cast<std::uint32_t>(pending_spaceman_allocations_.size()));
        WriteLe32(direct_blob, 41, static_cast<std::uint32_t>(pending_spaceman_deallocations_.size()));
        WriteLe32(direct_blob, 45, static_cast<std::uint32_t>(pending_btree_records_.size()));

        std::size_t cursor = kCommitBlobPayloadOffset;
        const auto write_u32 = [&](std::uint32_t value) -> bool
        {
            if (cursor > (direct_blob.size() - sizeof(std::uint32_t)))
            {
                return false;
            }
            WriteLe32(direct_blob, cursor, value);
            cursor += sizeof(std::uint32_t);
            return true;
        };
        const auto write_u64 = [&](std::uint64_t value) -> bool
        {
            if (cursor > (direct_blob.size() - sizeof(std::uint64_t)))
            {
                return false;
            }
            WriteLe64(direct_blob, cursor, value);
            cursor += sizeof(std::uint64_t);
            return true;
        };
        const auto write_bytes = [&](const std::vector<std::byte>& bytes) -> bool
        {
            if (bytes.empty())
            {
                return true;
            }
            if (cursor > (direct_blob.size() - bytes.size()))
            {
                return false;
            }
            std::memcpy(direct_blob.data() + cursor, bytes.data(), bytes.size());
            cursor += bytes.size();
            return true;
        };

        for (const auto& update : pending_object_map_updates_)
        {
            if (!write_u64(update.object_id) ||
                !write_u64(update.physical_address) ||
                !write_u64(update.logical_size) ||
                !write_u64(update.xid))
            {
                return false;
            }
        }

        for (const auto& allocation : pending_spaceman_allocations_)
        {
            if (!write_u64(allocation.physical_address) ||
                !write_u64(allocation.bytes))
            {
                return false;
            }
        }
        for (const auto& deallocation : pending_spaceman_deallocations_)
        {
            if (!write_u64(deallocation.physical_address) ||
                !write_u64(deallocation.bytes))
            {
                return false;
            }
        }
        for (const auto& record : pending_btree_records_)
        {
            if (record.key.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()) ||
                record.value.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()) ||
                !write_u32(static_cast<std::uint32_t>(record.kind)) ||
                !write_u32(record.tombstone ? 1u : 0u) ||
                !write_u32(static_cast<std::uint32_t>(record.key.size())) ||
                !write_u32(static_cast<std::uint32_t>(record.value.size())) ||
                !write_bytes(record.key) ||
                !write_bytes(record.value))
            {
                return false;
            }
        }

        if (cursor != unpadded_blob_bytes || cursor < kCommitBlobPayloadOffset)
        {
            return false;
        }
        const auto payload_bytes = cursor - kCommitBlobPayloadOffset;
        const auto payload_checksum = UpdateFnv1a(
            kCheckpointChecksumSeed,
            direct_blob.data() + static_cast<std::vector<std::byte>::difference_type>(kCommitBlobPayloadOffset),
            payload_bytes);
        WriteLe32(direct_blob, kCommitBlobChecksumOffset, payload_checksum);
        commit_blob_direct_fill_count_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    auto& blob = commit_blob_serialization_buffer_;

    for (const auto c : selected_magic)
    {
        blob.push_back(static_cast<std::byte>(c));
    }

    AppendLe64(blob, checkpoint_xid_);
    AppendLe64(blob, target_xid);
    AppendLe32(blob, static_cast<std::uint32_t>(pending_mutations_.size()));
    AppendLe32(blob, static_cast<std::uint32_t>(pending_object_map_updates_.size()));
    AppendLe32(blob, static_cast<std::uint32_t>(pending_spaceman_allocations_.size()));
    AppendLe32(blob, static_cast<std::uint32_t>(pending_spaceman_deallocations_.size()));
    AppendLe32(blob, static_cast<std::uint32_t>(pending_btree_records_.size()));
    AppendLe32(blob, 0); // placeholder for payload checksum (v3 format)

    for (const auto& update : pending_object_map_updates_)
    {
        AppendLe64(blob, update.object_id);
        AppendLe64(blob, update.physical_address);
        AppendLe64(blob, update.logical_size);
        AppendLe64(blob, update.xid);
    }

    for (const auto& allocation : pending_spaceman_allocations_)
    {
        AppendLe64(blob, allocation.physical_address);
        AppendLe64(blob, allocation.bytes);
    }
    for (const auto& deallocation : pending_spaceman_deallocations_)
    {
        AppendLe64(blob, deallocation.physical_address);
        AppendLe64(blob, deallocation.bytes);
    }
    for (const auto& record : pending_btree_records_)
    {
        AppendLe32(blob, static_cast<std::uint32_t>(record.kind));
        AppendLe32(blob, record.tombstone ? 1u : 0u);
        AppendLe32(blob, static_cast<std::uint32_t>(record.key.size()));
        AppendLe32(blob, static_cast<std::uint32_t>(record.value.size()));
        blob.insert(blob.end(), record.key.begin(), record.key.end());
        blob.insert(blob.end(), record.value.begin(), record.value.end());
    }

    if (blob.size() < kCommitBlobPayloadOffset)
    {
        return false;
    }
    const auto payload_bytes = blob.size() - kCommitBlobPayloadOffset;
    const auto payload_checksum = UpdateFnv1a(
        kCheckpointChecksumSeed,
        blob.data() + static_cast<std::vector<std::byte>::difference_type>(kCommitBlobPayloadOffset),
        payload_bytes);
    WriteLe32(blob, kCommitBlobChecksumOffset, payload_checksum);

    auto remainder = blob.size() % block_size_;
    if (remainder != 0)
    {
        blob.resize(blob.size() + (block_size_ - remainder), std::byte{});
    }

    return true;
}

void MetadataStore::AppendLe32(std::vector<std::byte>& blob, std::uint32_t value)
{
    blob.push_back(static_cast<std::byte>(value & 0xffu));
    blob.push_back(static_cast<std::byte>((value >> 8) & 0xffu));
    blob.push_back(static_cast<std::byte>((value >> 16) & 0xffu));
    blob.push_back(static_cast<std::byte>((value >> 24) & 0xffu));
}

void MetadataStore::AppendLe64(std::vector<std::byte>& blob, std::uint64_t value)
{
    for (int i = 0; i < 8; ++i)
    {
        blob.push_back(static_cast<std::byte>((value >> (8 * i)) & 0xffu));
    }
}

void MetadataStore::WriteLe32(std::vector<std::byte>& buffer, std::size_t offset, std::uint32_t value)
{
    if (offset + sizeof(std::uint32_t) > buffer.size())
    {
        return;
    }

    buffer[offset + 0] = static_cast<std::byte>(value & 0xffu);
    buffer[offset + 1] = static_cast<std::byte>((value >> 8) & 0xffu);
    buffer[offset + 2] = static_cast<std::byte>((value >> 16) & 0xffu);
    buffer[offset + 3] = static_cast<std::byte>((value >> 24) & 0xffu);
}

void MetadataStore::WriteLe64(std::vector<std::byte>& buffer, std::size_t offset, std::uint64_t value)
{
    if (offset + sizeof(std::uint64_t) > buffer.size())
    {
        return;
    }

    for (int i = 0; i < 8; ++i)
    {
        buffer[offset + static_cast<std::size_t>(i)] = static_cast<std::byte>((value >> (8 * i)) & 0xffu);
    }
}

std::uint32_t MetadataStore::ReadLe32(const std::vector<std::byte>& buffer, std::size_t offset)
{
    if (offset + sizeof(std::uint32_t) > buffer.size())
    {
        return 0;
    }

    const auto* p = reinterpret_cast<const unsigned char*>(buffer.data() + offset);
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint64_t MetadataStore::ReadLe64(const std::vector<std::byte>& buffer, std::size_t offset)
{
    if (offset + sizeof(std::uint64_t) > buffer.size())
    {
        return 0;
    }

    const auto* p = reinterpret_cast<const unsigned char*>(buffer.data() + offset);
    return static_cast<std::uint64_t>(p[0]) |
           (static_cast<std::uint64_t>(p[1]) << 8) |
           (static_cast<std::uint64_t>(p[2]) << 16) |
           (static_cast<std::uint64_t>(p[3]) << 24) |
           (static_cast<std::uint64_t>(p[4]) << 32) |
           (static_cast<std::uint64_t>(p[5]) << 40) |
           (static_cast<std::uint64_t>(p[6]) << 48) |
           (static_cast<std::uint64_t>(p[7]) << 56);
}
} // namespace apfsaccess::rw
