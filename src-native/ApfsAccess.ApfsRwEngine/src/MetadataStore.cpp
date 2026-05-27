#include "MetadataStore.h"
#include "ApfsObjectMapStore.h"
#include "ApfsSpacemanStore.h"
#include "ApfsVolumeTreeStore.h"
#include "NativeApfsReader.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <cwctype>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <set>
#include <limits>
#include <memory>
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
constexpr std::uint64_t kNativeObjectMapOverflowBlocks = 16;
constexpr std::uint64_t kNativeInodeOverflowOffset = kNativeOverflowCheckpointOffset + kNativeObjectMapOverflowBlocks;
constexpr std::uint64_t kNativeCheckpointExtensionBlocks = 192;
constexpr std::uint64_t kNativeBtreeExtensionOffset = 0;

std::uint32_t UpdateFnv1a(std::uint32_t hash, const std::byte* bytes, std::size_t length)
{
    for (std::size_t index = 0; index < length; ++index)
    {
        hash ^= static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[index]));
        hash *= kCheckpointChecksumPrime;
    }
    return hash;
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
        return chars > 0 && value[0] != L'\0' && value[0] != L'0';
    }();
    return enabled;
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

    auto sorted_file_extents = SortFileExtents(file_extents);
    auto sorted_decoded_extents = decoded_extents;
    std::sort(sorted_decoded_extents.begin(), sorted_decoded_extents.end(), [](const DecodedBtreeExtent& lhs, const DecodedBtreeExtent& rhs)
    {
        if (lhs.logical_offset == rhs.logical_offset)
        {
            return lhs.physical_address < rhs.physical_address;
        }
        return lhs.logical_offset < rhs.logical_offset;
    });

    for (std::size_t index = 0; index < sorted_file_extents.size(); ++index)
    {
        const auto& expected = sorted_file_extents[index];
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

    return !sorted_file_extents.empty() &&
           sorted_file_extents.front().logical_offset == 0 &&
           sorted_file_extents.front().physical_address == anchor_physical_address;
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
        return false;
    }

    ParsedSuperblock primary{};
    if (!parse_superblock(primary_superblock, primary))
    {
        container_loaded_ = false;
        return false;
    }

    ParsedSuperblock selected = primary;
    std::uint64_t selected_offset = 0;
    std::uint64_t secondary_offset = static_cast<std::uint64_t>(primary.block_size);

    std::vector<std::byte> secondary_superblock;
    ParsedSuperblock secondary{};
    const auto has_secondary = device_.Read(secondary_offset, kSuperblockBytes, secondary_superblock) &&
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
    committed_object_map_.clear();
    committed_inodes_.clear();
    committed_path_index_.clear();
    committed_directory_links_.clear();
    committed_btree_records_.clear();
    committed_read_extents_.clear();
    working_read_extents_.clear();
    pending_read_extent_updates_.clear();
    working_inodes_.clear();
    working_path_index_.clear();
    working_directory_links_.clear();
    RebuildWorkingDirectoryIndexes();
    committed_spaceman_allocations_.clear();
    committed_spaceman_free_extents_.clear();
    working_spaceman_free_extents_.clear();
    pending_object_map_updates_.clear();
    pending_spaceman_allocations_.clear();
    pending_spaceman_deallocations_.clear();
    pending_btree_records_.clear();
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
        last_committed_xid_ = selected_last_committed_xid;
        object_map_loaded_ = true;
    }
    else
    {
        committed_object_map_ = baseline_object_map;
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
            committed_inodes_.clear();
            committed_path_index_.clear();
            committed_directory_links_.clear();
            committed_btree_records_ = std::move(projection.btree_records);
            committed_read_extents_.clear();
            for (const auto& inode : projection.inodes)
            {
                committed_inodes_[inode.object_id] = inode;
                committed_path_index_[CanonicalPathKey(inode.full_path)] = inode.object_id;
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

bool MetadataStore::WriteBlockByIndexDirect(std::uint64_t block_index, const std::vector<std::byte>& block)
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

    auto payload = block;
    if (payload.size() < static_cast<std::size_t>(block_size_))
    {
        payload.resize(static_cast<std::size_t>(block_size_), std::byte{0});
    }

    const auto block_offset = block_index * static_cast<std::uint64_t>(block_size_);
    return device_.Write(block_offset, payload);
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

    std::size_t index = 0;
    while (index < block_count)
    {
        std::size_t run_blocks = 1;
        while (index + run_blocks < block_count &&
               selected_blocks[index + run_blocks] == selected_blocks[index] + static_cast<std::uint64_t>(run_blocks))
        {
            ++run_blocks;
        }

        std::vector<std::byte> blocks(run_blocks * block_size, std::byte{0});
        const auto begin_index = index * block_size;
        const auto end_index = std::min(data.size(), (index + run_blocks) * block_size);
        std::copy(
            data.begin() + static_cast<std::vector<std::byte>::difference_type>(begin_index),
            data.begin() + static_cast<std::vector<std::byte>::difference_type>(end_index),
            blocks.begin());

        if (!WriteContiguousBlocksDirect(selected_blocks[index], blocks))
        {
            return false;
        }

        index += run_blocks;
    }

    return true;
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

        std::vector<std::byte> combined;
        combined.reserve(required_blocks * block_size);
        bool read_failed = false;
        for (std::size_t index = 0; index < required_blocks; ++index)
        {
            std::vector<std::byte> block;
            if (!ReadBlockByIndexDirect(ordered_blocks[index], block) ||
                block.size() < block_size)
            {
                read_failed = true;
                break;
            }
            combined.insert(combined.end(), block.begin(), block.begin() + static_cast<std::vector<std::byte>::difference_type>(block_size));
        }
        if (read_failed)
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

    if (band_start.value() >= kNativeCheckpointExtensionBlocks)
    {
        const auto extension_start = band_start.value() - kNativeCheckpointExtensionBlocks;
        if (block_index >= extension_start && block_index < band_start.value())
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

    for (const auto block_index : block_indices)
    {
        if (!IsNativeCheckpointBandBlock(block_index) ||
            block_index > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size_)))
        {
            return false;
        }

        const auto physical_address = block_index * static_cast<std::uint64_t>(block_size_);
        const auto overlaps = [&](const std::vector<SpacemanAllocation>& extents)
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

        if (overlaps(committed_spaceman_allocations_) ||
            overlaps(pending_spaceman_allocations_))
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
    std::vector<std::uint64_t> candidates;
    const auto band_start = ResolveNativeCheckpointBandStartBlock();
    if (!band_start.has_value() ||
        band_start.value() > (std::numeric_limits<std::uint64_t>::max() - kNativeObjectMapCheckpointOffset))
    {
        return candidates;
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
    return candidates;
}

std::vector<std::uint64_t> MetadataStore::ResolveSpacemanCheckpointBlockIndices() const
{
    std::vector<std::uint64_t> candidates;
    const auto band_start = ResolveNativeCheckpointBandStartBlock();
    if (!band_start.has_value() ||
        band_start.value() > (std::numeric_limits<std::uint64_t>::max() - kNativeSpacemanCheckpointOffset))
    {
        return candidates;
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
    return candidates;
}

std::vector<std::uint64_t> MetadataStore::ResolveInodeCheckpointBlockIndices() const
{
    std::vector<std::uint64_t> candidates;
    const auto band_start = ResolveNativeCheckpointBandStartBlock();
    if (!band_start.has_value() ||
        band_start.value() > (std::numeric_limits<std::uint64_t>::max() - kNativeInodeCheckpointOffset))
    {
        return candidates;
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

    return candidates;
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
    std::vector<std::uint64_t> candidates;
    const auto band_start = ResolveNativeCheckpointBandStartBlock();
    if (!band_start.has_value() ||
        band_start.value() > (std::numeric_limits<std::uint64_t>::max() - kNativeBtreeCheckpointOffset))
    {
        return candidates;
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

    if (band_start.value() >= kNativeCheckpointExtensionBlocks)
    {
        const auto extension_start = band_start.value() - kNativeCheckpointExtensionBlocks;
        for (std::uint64_t index = 0; index < kNativeCheckpointExtensionBlocks; ++index)
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

    return candidates;
}

std::vector<std::uint64_t> MetadataStore::ResolveReplayCheckpointBlockIndices() const
{
    std::vector<std::uint64_t> candidates;
    const auto band_start = ResolveNativeCheckpointBandStartBlock();
    if (!band_start.has_value() ||
        band_start.value() > (std::numeric_limits<std::uint64_t>::max() - kNativeReplayCheckpointOffset))
    {
        return candidates;
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

    return candidates;
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
    return true;
}

bool MetadataStore::LoadSpacemanCheckpointBlock(std::uint64_t block_index, const std::vector<std::byte>& block)
{
    (void)block_index;
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

        const auto path_key = CanonicalPathKey(native_inode.full_path);
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
            const auto canonical_path = CanonicalPathKey(inode.full_path);
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
        loaded_path_index.emplace(CanonicalPathKey(root_it->second.full_path), root_it->first);

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
                else if (CanonicalPathKey(child_it->second.full_path) != CanonicalPathKey(child_path))
                {
                    return false;
                }
                const auto canonical_path = CanonicalPathKey(child_it->second.full_path);
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
    committed_path_index_ = std::move(loaded_path_index);
    committed_directory_links_ = std::move(loaded_directory_links);
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
    out_path_index.emplace(CanonicalPathKey(root_inode.full_path), root_inode.object_id);

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

            const auto child_path_key = CanonicalPathKey(child_path);
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
    working_next_ephemeral_extent_ = next_ephemeral_extent_;
    RebuildWorkingDirectoryIndexes();
    pending_mutations_.clear();
    pending_object_map_updates_.clear();
    pending_spaceman_allocations_.clear();
    pending_spaceman_deallocations_.clear();
    pending_btree_records_.clear();
    pending_read_extent_updates_.clear();
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

MetadataStore::MutationStatus MetadataStore::StageMutation(const MutationRequest& request)
{
    return ApplyMutation(request);
}

void MetadataStore::SyncWorkingStateFromCommitted()
{
    working_inodes_ = committed_inodes_;
    working_path_index_ = committed_path_index_;
    working_directory_links_ = committed_directory_links_;
    working_read_extents_ = committed_read_extents_;
    working_spaceman_free_extents_ = committed_spaceman_free_extents_;
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
    append_counter(buffer, "buildCommitBlob", build_commit_blob_perf_);
    buffer << ",";
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
    buffer << ",\"blockDevice\":" << device_.PerformanceJson();
    buffer << "}";
    return buffer.str();
}

MetadataStore::MutationStatus MetadataStore::ApplyMutation(const MutationRequest& request)
{
    ScopedPerfTimer perf_scope(apply_mutation_perf_);

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
    if (!IsNativeWriteReady())
    {
        return MutationStatus::NotReady;
    }
    const auto normalized_path = NormalizePath(request.path);
    if (normalized_path.empty())
    {
        return reject(L"EmptyPath");
    }
    const auto normalized_secondary = NormalizePath(request.secondary_path);
    const auto target_xid = checkpoint_xid_ + 1;
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
    struct PendingAllocationRestoreEntry
    {
        std::size_t index = 0;
        SpacemanAllocation allocation;
    };
    struct MutationUndoLog
    {
        std::size_t pending_mutations_size = 0;
        std::size_t pending_object_map_updates_size = 0;
        std::size_t pending_spaceman_allocations_size = 0;
        std::size_t pending_spaceman_deallocations_size = 0;
        std::size_t pending_btree_records_size = 0;
        std::uint64_t working_next_ephemeral_extent = 0;
        std::vector<InodeRestoreEntry> inode_restores;
        std::vector<PathIndexRestoreEntry> path_index_restores;
        std::vector<PendingObjectMapRestoreEntry> pending_object_map_restores;
        std::vector<ReadExtentRestoreEntry> read_extent_restores;
        std::vector<DirectoryLinkRestoreEntry> directory_link_restores;
        std::vector<SpacemanAllocation> appended_pending_allocations;
        std::vector<PendingAllocationRestoreEntry> erased_pending_allocations;
        std::optional<std::vector<SpacemanAllocation>> working_spaceman_free_extents;
    } undo_log
    {
        pending_mutations_.size(),
        pending_object_map_updates_.size(),
        pending_spaceman_allocations_.size(),
        pending_spaceman_deallocations_.size(),
        pending_btree_records_.size(),
        working_next_ephemeral_extent_,
    };
    const auto remember_inode = [&](std::uint64_t object_id)
    {
        if (std::any_of(
                undo_log.inode_restores.begin(),
                undo_log.inode_restores.end(),
                [&](const InodeRestoreEntry& entry) { return entry.object_id == object_id; }))
        {
            return;
        }

        auto existing = working_inodes_.find(object_id);
        undo_log.inode_restores.push_back(
            {
                object_id,
                existing == working_inodes_.end() ? std::optional<InodeRecord>{} : existing->second,
            });
    };
    const auto remember_path_index = [&](const std::wstring& key)
    {
        if (std::any_of(
                undo_log.path_index_restores.begin(),
                undo_log.path_index_restores.end(),
                [&](const PathIndexRestoreEntry& entry) { return entry.key == key; }))
        {
            return;
        }

        auto existing = working_path_index_.find(key);
        undo_log.path_index_restores.push_back(
            {
                key,
                existing == working_path_index_.end() ? std::optional<std::uint64_t>{} : existing->second,
            });
    };
    const auto remember_pending_object_map_update = [&](std::uint64_t object_id)
    {
        if (std::any_of(
                undo_log.pending_object_map_restores.begin(),
                undo_log.pending_object_map_restores.end(),
                [&](const PendingObjectMapRestoreEntry& entry) { return entry.object_id == object_id; }))
        {
            return;
        }

        auto existing = std::find_if(
            pending_object_map_updates_.begin(),
            pending_object_map_updates_.end(),
            [&](const ObjectMapUpdate& update) { return update.object_id == object_id; });
        undo_log.pending_object_map_restores.push_back(
            {
                object_id,
                existing == pending_object_map_updates_.end() ? std::optional<ObjectMapUpdate>{} : *existing,
            });
    };
    const auto remember_read_extents = [&](std::uint64_t object_id)
    {
        if (std::any_of(
                undo_log.read_extent_restores.begin(),
                undo_log.read_extent_restores.end(),
                [&](const ReadExtentRestoreEntry& entry) { return entry.object_id == object_id; }))
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
    };
    const auto remember_directory_link = [&](std::uint64_t parent_object_id, const std::wstring& entry_name)
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
    };
    const auto remember_working_free_extents = [&]()
    {
        if (!undo_log.working_spaceman_free_extents.has_value())
        {
            undo_log.working_spaceman_free_extents = working_spaceman_free_extents_;
        }
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
        remember_working_free_extents();
        return AllocateExtent(bytes);
    };
    const auto allocate_file_extents = [&](std::uint64_t bytes) -> std::optional<std::vector<FileExtent>>
    {
        remember_working_free_extents();
        return AllocateFileExtents(bytes);
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

        for (auto it = pending_spaceman_allocations_.begin(); it != pending_spaceman_allocations_.end(); ++it)
        {
            if (it->physical_address != physical_address || it->bytes != aligned_bytes)
            {
                continue;
            }

            const auto index = static_cast<std::size_t>(std::distance(pending_spaceman_allocations_.begin(), it));
            if (index < undo_log.pending_spaceman_allocations_size)
            {
                undo_log.erased_pending_allocations.push_back({ index, *it });
            }
            pending_spaceman_allocations_.erase(it);
            remember_working_free_extents();
            return FreeExtent(physical_address, aligned_bytes);
        }

        return false;
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
    const auto release_pending_file_extents = [&](std::uint64_t object_id)
    {
        auto extents_it = pending_read_extent_updates_.find(object_id);
        if (extents_it == pending_read_extent_updates_.end())
        {
            return true;
        }

        remember_read_extents(object_id);
        const auto extents = extents_it->second;
        std::vector<SpacemanAllocation> released_allocations;
        released_allocations.reserve(extents.size());
        for (const auto& extent : extents)
        {
            const auto aligned_bytes = AlignExtentBytes(extent.bytes);
            if (!release_pending_spaceman_allocation(extent.physical_address, extent.bytes))
            {
                for (const auto& released : released_allocations)
                {
                    (void)StageSpacemanAllocation(released.physical_address, released.bytes);
                }
                return false;
            }
            released_allocations.push_back({ extent.physical_address, aligned_bytes });
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
            auto existing = std::find_if(
                pending_spaceman_allocations_.begin(),
                pending_spaceman_allocations_.end(),
                [&](const SpacemanAllocation& allocation)
                {
                    return allocation.physical_address == append_it->physical_address &&
                           allocation.bytes == append_it->bytes;
                });
            if (existing != pending_spaceman_allocations_.end())
            {
                pending_spaceman_allocations_.erase(existing);
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
        if (pending_spaceman_allocations_.size() > undo_log.pending_spaceman_allocations_size)
        {
            pending_spaceman_allocations_.resize(undo_log.pending_spaceman_allocations_size);
        }
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
            }
            if (pending_object_map_updates_.size() > undo_log.pending_object_map_updates_size)
            {
                pending_object_map_updates_.resize(undo_log.pending_object_map_updates_size);
            }
            restore_pending_allocations();
            if (pending_spaceman_deallocations_.size() > undo_log.pending_spaceman_deallocations_size)
            {
                pending_spaceman_deallocations_.resize(undo_log.pending_spaceman_deallocations_size);
            }
            if (pending_btree_records_.size() > undo_log.pending_btree_records_size)
            {
                pending_btree_records_.resize(undo_log.pending_btree_records_size);
            }
            for (const auto& restore : undo_log.pending_object_map_restores)
            {
                auto existing = std::find_if(
                    pending_object_map_updates_.begin(),
                    pending_object_map_updates_.end(),
                    [&](const ObjectMapUpdate& update) { return update.object_id == restore.object_id; });
                if (restore.previous.has_value())
                {
                    if (existing != pending_object_map_updates_.end())
                    {
                        *existing = restore.previous.value();
                    }
                    else
                    {
                        pending_object_map_updates_.push_back(restore.previous.value());
                    }
                }
                else if (existing != pending_object_map_updates_.end())
                {
                    pending_object_map_updates_.erase(existing);
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
            if (undo_log.working_spaceman_free_extents.has_value())
            {
                working_spaceman_free_extents_ = std::move(*undo_log.working_spaceman_free_extents);
            }
            working_next_ephemeral_extent_ = undo_log.working_next_ephemeral_extent;
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
        }};
    const auto stage_inode_record = [&](const InodeRecord& inode, bool tombstone)
    {
        pending_btree_records_.push_back(BtreeMutationCodec::EncodeInodeRecord(
            inode.object_id,
            inode.parent_object_id,
            inode.name,
            inode.is_directory,
            inode.logical_size,
            inode.data_physical_address,
            inode.timestamp_utc,
            inode.xid,
            tombstone));
    };
    const auto stage_directory_record = [&](std::uint64_t parent_object_id, const std::wstring& name, std::uint64_t child_object_id, bool tombstone)
    {
        pending_btree_records_.push_back(BtreeMutationCodec::EncodeDirectoryRecord(
            parent_object_id,
            name,
            child_object_id,
            target_xid,
            tombstone));
    };
    const auto stage_extent_record = [&](std::uint64_t object_id, std::uint64_t logical_offset, std::uint64_t physical_address, std::uint64_t extent_bytes, bool tombstone)
    {
        pending_btree_records_.push_back(BtreeMutationCodec::EncodeExtentRecord(
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
        if (extents.empty())
        {
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
    const auto stage_committed_file_extents_for_removal = [&](const InodeRecord& inode) -> bool
    {
        remember_read_extents(inode.object_id);
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
        const auto parent_inode = LookupWorkingInode(parent_path);
        if (!parent_inode.has_value() || !parent_inode->is_directory)
        {
            return reject(L"CreateParentMissingOrNotDirectory:" + parent_path);
        }

        const auto leaf_name = LeafName(normalized_path);
        if (leaf_name.empty())
        {
            return reject(L"CreateLeafNameEmpty");
        }

        auto existing = LookupWorkingInode(normalized_path);
        std::optional<std::uint64_t> replacement_id;
        if (existing.has_value())
        {
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

            replacement_id = existing->object_id;
            remove_working_directory_link(existing->parent_object_id, existing->name);
            erase_working_path_index(CanonicalPathKey(normalized_path));
            erase_working_inode(existing->object_id);
            stage_directory_record(existing->parent_object_id, existing->name, existing->object_id, true);
            if (!existing->is_directory && existing->logical_size > 0)
            {
                if (!stage_committed_file_extents_for_removal(*existing))
                {
                    return MutationStatus::AllocationFailed;
                }
            }
            stage_inode_record(*existing, true);
            if (!stage_object_map_update(existing->object_id, 0, 0))
            {
                return MutationStatus::AllocationFailed;
            }
        }

        InodeRecord inode{};
        inode.object_id = replacement_id.value_or(ResolveUniqueObjectId(normalized_path));
        inode.parent_object_id = parent_inode->object_id;
        inode.name = leaf_name;
        inode.full_path = normalized_path;
        inode.is_directory = request.operation == MutationOperation::CreateDirectory;
        inode.logical_size = 0;
        inode.data_physical_address = 0;
        inode.xid = target_xid;

        set_working_inode(inode);
        set_working_path_index(CanonicalPathKey(inode.full_path), inode.object_id);
        upsert_working_directory_link(inode.parent_object_id, inode.name, inode.object_id, target_xid);

        if (!stage_object_map_update(inode.object_id, inode.data_physical_address, inode.logical_size))
        {
            return MutationStatus::AllocationFailed;
        }
        stage_inode_record(inode, false);
        stage_directory_record(inode.parent_object_id, inode.name, inode.object_id, false);
        break;
    }
    case MutationOperation::Write:
    {
        if (request.length == 0)
        {
            break;
        }
        auto inode = LookupWorkingInode(normalized_path);
        if (!inode.has_value() || inode->is_directory)
        {
            return reject(L"WriteTargetMissingOrDirectory");
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
        if (next_physical == 0 ||
            target_logical_size > previous_size ||
            (!previous_extent_is_pending && !pending_extents_cover_request))
        {
            const auto old_extents_were_pending = pending_read_extent_updates_.contains(inode_ref.object_id);
            if (old_extents_were_pending &&
                !release_pending_file_extents(inode_ref.object_id))
            {
                return MutationStatus::AllocationFailed;
            }
            const auto old_committed_extents_need_removal =
                previous_physical != 0 &&
                previous_size > 0 &&
                !old_extents_were_pending &&
                !previous_extent_is_pending;
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
            next_physical = extents->front().physical_address;
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
        CoalescePendingWriteMutation(inode_ref.object_id, request);
        CoalescePendingBtreeFileMetadata(inode_ref.object_id);
        mutation_applied = true;
        return MutationStatus::Applied;
        break;
    }
    case MutationOperation::SetFileSize:
    {
        auto inode = LookupWorkingInode(normalized_path);
        if (!inode.has_value() || inode->is_directory)
        {
            return reject(L"SetFileSizeTargetMissingOrDirectory");
        }

        auto& inode_ref = mutable_working_inode(inode->object_id);
        const auto previous_physical = inode_ref.data_physical_address;
        const auto previous_size = inode_ref.logical_size;
        if (request.length == 0)
        {
            if (previous_physical != 0 && previous_size > 0)
            {
                if (!stage_committed_file_extents_for_removal(*inode))
                {
                    return MutationStatus::AllocationFailed;
                }
            }
            inode_ref.data_physical_address = 0;
        }
        else
        {
            const auto old_extents_were_pending = pending_read_extent_updates_.contains(inode_ref.object_id);
            if (old_extents_were_pending &&
                !release_pending_file_extents(inode_ref.object_id))
            {
                return MutationStatus::AllocationFailed;
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
        inode_ref.logical_size = request.length;
        inode_ref.xid = target_xid;
        if (!stage_object_map_update(inode_ref.object_id, inode_ref.data_physical_address, inode_ref.logical_size))
        {
            return MutationStatus::AllocationFailed;
        }
        stage_inode_record(inode_ref, false);
        break;
    }
    case MutationOperation::Rename:
    {
        if (normalized_secondary.empty() || IsRootPath(normalized_path))
        {
            return reject(normalized_secondary.empty() ? L"RenameDestinationEmpty" : L"RenameRootPath");
        }

        auto inode = LookupWorkingInode(normalized_path);
        if (!inode.has_value())
        {
            return reject(L"RenameSourceMissing");
        }
        const auto source_path_key = CanonicalPathKey(normalized_path);
        const auto destination_path_key = CanonicalPathKey(normalized_secondary);

        const auto destination_parent_path = ParentPath(normalized_secondary);
        const auto destination_parent = LookupWorkingInode(destination_parent_path);
        if (!destination_parent.has_value() || !destination_parent->is_directory)
        {
            return reject(L"RenameDestinationParentMissingOrNotDirectory:" + destination_parent_path);
        }
        if (LeafName(normalized_secondary).empty())
        {
            return reject(L"RenameDestinationLeafNameEmpty");
        }
        if (inode->is_directory &&
            (IsDescendantPath(destination_parent_path, normalized_path) ||
             CanonicalPathKey(destination_parent_path) == CanonicalPathKey(normalized_path)))
        {
            return reject(L"RenameDirectoryIntoSelf");
        }

        auto destination_inode = LookupWorkingInode(normalized_secondary);
        const auto destination_is_same_object = destination_inode.has_value() &&
                                                destination_inode->object_id == inode->object_id;
        if (destination_is_same_object &&
            source_path_key == destination_path_key &&
            normalized_secondary == normalized_path)
        {
            // No-op rename request.
            return MutationStatus::Applied;
        }
        if (destination_inode.has_value())
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
                remove_working_directory_link(destination_inode->parent_object_id, destination_inode->name);
                erase_working_path_index(CanonicalPathKey(normalized_secondary));
                erase_working_inode(destination_inode->object_id);
                stage_directory_record(destination_inode->parent_object_id, destination_inode->name, destination_inode->object_id, true);
                if (!destination_inode->is_directory &&
                    destination_inode->logical_size > 0)
                {
                    if (!stage_committed_file_extents_for_removal(*destination_inode))
                    {
                        return MutationStatus::AllocationFailed;
                    }
                }
                stage_inode_record(*destination_inode, true);
                if (!stage_object_map_update(destination_inode->object_id, 0, 0))
                {
                    return MutationStatus::AllocationFailed;
                }
            }
        }

        const auto source_prefix = IsRootPath(normalized_path) ? normalized_path : normalized_path + L"\\";
        const auto source_prefix_key = CanonicalPathKey(source_prefix);
        std::vector<std::pair<std::wstring, std::wstring>> descendant_renames;
        if (inode->is_directory)
        {
            descendant_renames.reserve(working_inodes_.size());
            for (const auto& [object_id, child_inode] : working_inodes_)
            {
                if (object_id == inode->object_id)
                {
                    continue;
                }

                const auto child_path = child_inode.full_path;
                const auto child_path_key = CanonicalPathKey(child_path);
                if (child_path_key.rfind(source_prefix_key, 0) == 0 &&
                    child_path.size() >= source_prefix.size())
                {
                    descendant_renames.emplace_back(
                        child_path,
                        normalized_secondary + L"\\" + child_path.substr(source_prefix.size()));
                }
            }
            std::sort(descendant_renames.begin(), descendant_renames.end(), [](const auto& lhs, const auto& rhs)
            {
                return lhs.first.size() < rhs.first.size();
            });
        }

        const auto old_path = inode->full_path;
        const auto old_parent_object_id = inode->parent_object_id;
        const auto old_name = inode->name;
        remove_working_directory_link(inode->parent_object_id, inode->name);
        erase_working_path_index(CanonicalPathKey(old_path));
        stage_directory_record(old_parent_object_id, old_name, inode->object_id, true);

        auto& inode_ref = mutable_working_inode(inode->object_id);
        inode_ref.parent_object_id = destination_parent->object_id;
        inode_ref.name = LeafName(normalized_secondary);
        inode_ref.full_path = normalized_secondary;
        inode_ref.xid = target_xid;
        set_working_path_index(CanonicalPathKey(inode_ref.full_path), inode_ref.object_id);
        upsert_working_directory_link(inode_ref.parent_object_id, inode_ref.name, inode_ref.object_id, target_xid);
        stage_directory_record(inode_ref.parent_object_id, inode_ref.name, inode_ref.object_id, false);
        stage_inode_record(inode_ref, false);

        for (const auto& [old_descendant_path, new_descendant_path] : descendant_renames)
        {
            auto descendant_it = working_path_index_.find(CanonicalPathKey(old_descendant_path));
            if (descendant_it == working_path_index_.end())
            {
                continue;
            }
            const auto descendant_object_id = descendant_it->second;
            erase_working_path_index(CanonicalPathKey(old_descendant_path));
            auto& descendant_inode = mutable_working_inode(descendant_object_id);
            const auto descendant_old_parent_object_id = descendant_inode.parent_object_id;
            const auto descendant_old_name = descendant_inode.name;
            const auto new_parent_path = ParentPath(new_descendant_path);
            descendant_inode.full_path = new_descendant_path;
            descendant_inode.name = LeafName(new_descendant_path);
            if (new_parent_path == inode_ref.full_path)
            {
                descendant_inode.parent_object_id = inode_ref.object_id;
            }
            else if (auto parent_it = working_path_index_.find(CanonicalPathKey(new_parent_path)); parent_it != working_path_index_.end())
            {
                descendant_inode.parent_object_id = parent_it->second;
            }
            descendant_inode.xid = target_xid;
            set_working_path_index(CanonicalPathKey(new_descendant_path), descendant_object_id);
            remove_working_directory_link(descendant_old_parent_object_id, descendant_old_name);
            stage_directory_record(descendant_old_parent_object_id, descendant_old_name, descendant_object_id, true);
            upsert_working_directory_link(descendant_inode.parent_object_id, descendant_inode.name, descendant_object_id, target_xid);
            stage_directory_record(descendant_inode.parent_object_id, descendant_inode.name, descendant_object_id, false);
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
        break;
    }
    case MutationOperation::Delete:
    {
        if (IsRootPath(normalized_path))
        {
            return reject(L"DeleteRootPath");
        }

        auto inode = LookupWorkingInode(normalized_path);
        if (!inode.has_value())
        {
            return reject(L"DeleteTargetMissing");
        }
        if (inode->is_directory && HasWorkingChildren(inode->object_id))
        {
            return reject(L"DeleteDirectoryNotEmpty");
        }

        remove_working_directory_link(inode->parent_object_id, inode->name);
        erase_working_path_index(CanonicalPathKey(normalized_path));
        erase_working_inode(inode->object_id);
        stage_directory_record(inode->parent_object_id, inode->name, inode->object_id, true);
        if (!inode->is_directory && inode->logical_size > 0)
        {
            if (!stage_committed_file_extents_for_removal(*inode))
            {
                return MutationStatus::AllocationFailed;
            }
        }
        stage_inode_record(*inode, true);

        if (!stage_object_map_update(inode->object_id, 0, 0))
        {
            return MutationStatus::AllocationFailed;
        }
        break;
    }
    case MutationOperation::SetBasicInfo:
    {
        auto inode = LookupWorkingInode(normalized_path);
        if (!inode.has_value())
        {
            return reject(L"SetBasicInfoTargetMissing");
        }

        auto& inode_ref = mutable_working_inode(inode->object_id);
        inode_ref.xid = target_xid;
        inode_ref.timestamp_utc = request.timestamp_utc;
        if (!stage_object_map_update(inode_ref.object_id, inode_ref.data_physical_address, inode_ref.logical_size))
        {
            return MutationStatus::AllocationFailed;
        }
        stage_inode_record(inode_ref, false);
        break;
    }
    default:
        return MutationStatus::UnsupportedOperation;
    }

    pending_mutations_.push_back(request);
    mutation_applied = true;
    return MutationStatus::Applied;
}

MetadataStore::CommitStatus MetadataStore::CommitPendingMutations()
{
    ScopedPerfTimer perf_scope(commit_pending_perf_);

    last_commit_stage_ = "start";
    last_commit_failure_reason_.clear();
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
    if (!ValidatePendingCommitState())
    {
        return fail_commit(CommitStatus::InvariantFailed, "preflight-validation-failed");
    }

    const auto target_xid = checkpoint_xid_ + 1;
    auto commit_blob = BuildCommitBlob(target_xid);
    if (commit_blob.empty())
    {
        return fail_commit(CommitStatus::PersistFailed, "commit-blob-build-failed");
    }
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

    const auto working_free_extents_snapshot = working_spaceman_free_extents_;
    const auto working_next_extent_snapshot = working_next_ephemeral_extent_;
    auto commit_extent = AllocateExtent(commit_blob_persist_bytes);
    if (!commit_extent.has_value())
    {
        return fail_commit(CommitStatus::AllocationFailed, "commit-extent-allocate-failed");
    }
    if (!StageSpacemanAllocation(*commit_extent, commit_blob_persist_bytes))
    {
        working_spaceman_free_extents_ = working_free_extents_snapshot;
        working_next_ephemeral_extent_ = working_next_extent_snapshot;
        return fail_commit(CommitStatus::AllocationFailed, "commit-extent-stage-allocation-failed");
    }
    const auto rollback_commit_extent_stage = [&]()
    {
        if (!pending_spaceman_allocations_.empty() &&
            pending_spaceman_allocations_.back().physical_address == *commit_extent)
        {
            pending_spaceman_allocations_.pop_back();
        }
        working_spaceman_free_extents_ = working_free_extents_snapshot;
        working_next_ephemeral_extent_ = working_next_extent_snapshot;
    };
    if (!ValidatePendingCommitState())
    {
        rollback_commit_extent_stage();
        return fail_commit(CommitStatus::InvariantFailed, "post-allocation-preflight-failed");
    }

    struct PendingPayloadWriteView
    {
        std::uint64_t physical_address = 0;
        std::wstring path;
        std::shared_ptr<std::vector<std::byte>> payload;
        std::uint64_t logical_offset = 0;
        std::uint64_t logical_size = 0;
        std::size_t offset = 0;
        std::size_t length = 0;
    };

    std::unordered_set<std::wstring> payload_paths;
    payload_paths.reserve(pending_mutations_.size());
    const auto remap_payload_subtree = [&payload_paths](const std::wstring& source_key, const std::wstring& destination_key)
    {
        if (source_key.empty() || destination_key.empty())
        {
            return;
        }

        std::vector<std::wstring> pending_removals;
        std::vector<std::wstring> pending_additions;
        pending_removals.reserve(payload_paths.size());
        pending_additions.reserve(payload_paths.size());

        for (const auto& payload_path : payload_paths)
        {
            if (payload_path == source_key)
            {
                pending_removals.push_back(payload_path);
                pending_additions.push_back(destination_key);
                continue;
            }

            if (!IsDescendantPath(payload_path, source_key))
            {
                continue;
            }

            auto remapped_path = destination_key;
            remapped_path.append(payload_path.substr(source_key.size()));
            pending_removals.push_back(payload_path);
            pending_additions.push_back(std::move(remapped_path));
        }

        for (const auto& payload_path : pending_removals)
        {
            payload_paths.erase(payload_path);
        }
        for (const auto& payload_path : pending_additions)
        {
            if (!payload_path.empty())
            {
                payload_paths.insert(payload_path);
            }
        }
    };

    for (const auto& mutation : pending_mutations_)
    {
        const auto normalized_path = NormalizePath(mutation.path);
        const auto normalized_key = CanonicalPathKey(normalized_path);
        switch (mutation.operation)
        {
        case MutationOperation::Write:
            if (mutation.length > 0)
            {
                payload_paths.insert(normalized_key);
            }
            break;
        case MutationOperation::SetFileSize:
            if (mutation.length > 0)
            {
                payload_paths.insert(normalized_key);
            }
            else
            {
                payload_paths.erase(normalized_key);
            }
            break;
        case MutationOperation::Rename:
        {
            const auto normalized_secondary = NormalizePath(mutation.secondary_path);
            const auto normalized_secondary_key = CanonicalPathKey(normalized_secondary);
            remap_payload_subtree(normalized_key, normalized_secondary_key);
            break;
        }
        case MutationOperation::Delete:
            payload_paths.erase(normalized_key);
            break;
        default:
            break;
        }
    }

    std::vector<PendingPayloadWriteView> pending_payload_writes;
    pending_payload_writes.reserve(payload_paths.size());
    for (const auto& payload_path : payload_paths)
    {
        auto inode = LookupWorkingInode(payload_path);
        if (!inode.has_value() ||
            inode->is_directory ||
            inode->data_physical_address == 0 ||
            inode->logical_size == 0)
        {
            continue;
        }

        if (inode->logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
        {
            rollback_commit_extent_stage();
            return fail_commit(CommitStatus::PersistFailed, "payload-size-overflow");
        }

        if (!file_payload_provider_ && !file_payload_range_provider_)
        {
            rollback_commit_extent_stage();
            return fail_commit(CommitStatus::PersistFailed, "payload-provider-missing");
        }

        std::shared_ptr<std::vector<std::byte>> payload_bytes;
        if (!file_payload_range_provider_)
        {
            auto resolved = file_payload_provider_(inode->full_path, inode->logical_size);
            if (!resolved.has_value())
            {
                rollback_commit_extent_stage();
                return fail_commit(CommitStatus::PersistFailed, "payload-provider-unresolved");
            }
            payload_bytes = std::make_shared<std::vector<std::byte>>(std::move(resolved.value()));

            const auto logical_size = static_cast<std::size_t>(inode->logical_size);
            if (payload_bytes->size() < logical_size)
            {
                payload_bytes->resize(logical_size, std::byte{0});
            }
            else if (payload_bytes->size() > logical_size)
            {
                payload_bytes->resize(logical_size);
            }
        }

        std::vector<FileExtent> payload_extents;
        if (auto pending_extents_it = pending_read_extent_updates_.find(inode->object_id);
            pending_extents_it != pending_read_extent_updates_.end())
        {
            payload_extents = pending_extents_it->second;
        }
        else if (auto working_extents_it = working_read_extents_.find(inode->object_id);
                 working_extents_it != working_read_extents_.end())
        {
            payload_extents = working_extents_it->second;
        }
        else if (auto committed_extents_it = committed_read_extents_.find(inode->object_id);
                 committed_extents_it != committed_read_extents_.end())
        {
            payload_extents = committed_extents_it->second;
        }
        else
        {
            payload_extents.push_back(FileExtent{ 0, inode->data_physical_address, inode->logical_size });
        }
        payload_extents = SortFileExtents(std::move(payload_extents));
        if (!HasLogicalExtentCoverage(payload_extents, inode->logical_size))
        {
            rollback_commit_extent_stage();
            return fail_commit(CommitStatus::PersistFailed, "payload-extent-coverage-invalid");
        }

        for (const auto& extent : payload_extents)
        {
            if (extent.logical_offset >= inode->logical_size)
            {
                continue;
            }

            const auto logical_tail = inode->logical_size - extent.logical_offset;
            const auto extent_logical_bytes = std::min(extent.bytes, logical_tail);
            if (extent_logical_bytes == 0 ||
                extent_logical_bytes > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()) ||
                extent.logical_offset > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
            {
                rollback_commit_extent_stage();
                return fail_commit(CommitStatus::PersistFailed, "payload-extent-size-invalid");
            }

            const auto slice_offset = static_cast<std::size_t>(extent.logical_offset);
            const auto slice_bytes = static_cast<std::size_t>(extent_logical_bytes);
            if (payload_bytes &&
                (slice_offset > payload_bytes->size() ||
                 slice_bytes > (payload_bytes->size() - slice_offset)))
            {
                rollback_commit_extent_stage();
                return fail_commit(CommitStatus::PersistFailed, "payload-extent-slice-invalid");
            }

            pending_payload_writes.push_back(PendingPayloadWriteView{
                extent.physical_address,
                inode->full_path,
                payload_bytes,
                extent.logical_offset,
                inode->logical_size,
                slice_offset,
                slice_bytes,
            });
        }
    }

    std::sort(
        pending_payload_writes.begin(),
        pending_payload_writes.end(),
        [](const PendingPayloadWriteView& lhs, const PendingPayloadWriteView& rhs)
        {
            if (lhs.physical_address == rhs.physical_address)
            {
                return lhs.length < rhs.length;
            }
            return lhs.physical_address < rhs.physical_address;
        });

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

        if (!file_payload_range_provider_ ||
            segment.logical_offset > (std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(segment.length)))
        {
            return false;
        }

        destination.resize(original_size + segment.length);
        if (file_payload_range_provider_(
                segment.path,
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

        auto fallback_payload = file_payload_provider_(segment.path, segment.logical_size);
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

    std::vector<std::byte> merged_payload_scratch;
    for (std::size_t write_index = 0; write_index < pending_payload_writes.size();)
    {
        const auto& first_write = pending_payload_writes[write_index];
        if (first_write.length > static_cast<std::size_t>(std::numeric_limits<std::uint64_t>::max() - first_write.physical_address))
        {
            rollback_commit_extent_stage();
            return fail_commit(CommitStatus::PersistFailed, "payload-device-write-failed");
        }

        auto physical_end = first_write.physical_address + static_cast<std::uint64_t>(first_write.length);
        std::size_t merge_end = write_index + 1;
        while (merge_end < pending_payload_writes.size())
        {
            const auto& next_write = pending_payload_writes[merge_end];
            if (next_write.physical_address != physical_end ||
                next_write.length > static_cast<std::size_t>(std::numeric_limits<std::uint64_t>::max() - physical_end))
            {
                break;
            }
            const auto next_physical_end = physical_end + static_cast<std::uint64_t>(next_write.length);
            if ((next_physical_end - first_write.physical_address) > static_cast<std::uint64_t>(std::numeric_limits<DWORD>::max()))
            {
                break;
            }
            physical_end = next_physical_end;
            ++merge_end;
        }

        bool wrote_payload = false;
        if (merge_end == write_index + 1)
        {
            if (first_write.payload &&
                first_write.offset <= first_write.payload->size() &&
                first_write.length <= (first_write.payload->size() - first_write.offset))
            {
                wrote_payload = device_.Write(
                    first_write.physical_address,
                    std::span<const std::byte>(
                        first_write.payload->data() + static_cast<std::ptrdiff_t>(first_write.offset),
                        first_write.length));
            }
            else
            {
                merged_payload_scratch.clear();
                if (append_payload_segment(first_write, merged_payload_scratch) &&
                    merged_payload_scratch.size() == first_write.length)
                {
                    wrote_payload = device_.Write(first_write.physical_address, merged_payload_scratch);
                }
            }
        }
        else
        {
            const auto merged_bytes_u64 = physical_end - first_write.physical_address;
            if (merged_bytes_u64 <= static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
            {
                merged_payload_scratch.clear();
                merged_payload_scratch.reserve(static_cast<std::size_t>(merged_bytes_u64));
                for (std::size_t current = write_index; current < merge_end; ++current)
                {
                    if (!append_payload_segment(pending_payload_writes[current], merged_payload_scratch))
                    {
                        merged_payload_scratch.clear();
                        break;
                    }
                }
                if (merged_payload_scratch.size() == static_cast<std::size_t>(merged_bytes_u64))
                {
                    wrote_payload = device_.Write(first_write.physical_address, merged_payload_scratch);
                }
            }
        }

        if (!wrote_payload)
        {
            rollback_commit_extent_stage();
            return fail_commit(CommitStatus::PersistFailed, "payload-device-write-failed");
        }

        write_index = merge_end;
    }

    if (!AllowCommitStage("before-commit-blob-device-write"))
    {
        rollback_commit_extent_stage();
        return CommitStatus::PersistFailed;
    }
    if (!device_.Write(*commit_extent, commit_blob))
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
        return fail_commit(CommitStatus::FlushFailed, "device-flush-failed");
    }

    auto committed_object_map_snapshot = committed_object_map_;
    auto committed_allocations_snapshot = committed_spaceman_allocations_;
    auto committed_free_extents_snapshot = committed_spaceman_free_extents_;
    auto committed_inodes_snapshot = committed_inodes_;
    auto committed_path_index_snapshot = committed_path_index_;
    auto committed_directory_links_snapshot = committed_directory_links_;
    auto committed_btree_snapshot = committed_btree_records_;
    auto committed_read_extents_snapshot = committed_read_extents_;
    auto last_commit_blob_snapshot = last_commit_blob_address_;
    auto last_commit_blob_bytes_snapshot = last_commit_blob_bytes_;
    auto checkpoint_xid_snapshot = checkpoint_xid_;
    auto last_committed_xid_snapshot = last_committed_xid_;
    const auto rollback_committed_state = [&]()
    {
        committed_object_map_ = committed_object_map_snapshot;
        committed_spaceman_allocations_ = committed_allocations_snapshot;
        committed_spaceman_free_extents_ = committed_free_extents_snapshot;
        committed_inodes_ = committed_inodes_snapshot;
        committed_path_index_ = committed_path_index_snapshot;
        committed_directory_links_ = committed_directory_links_snapshot;
        committed_btree_records_ = committed_btree_snapshot;
        committed_read_extents_ = committed_read_extents_snapshot;
        last_commit_blob_address_ = last_commit_blob_snapshot;
        last_commit_blob_bytes_ = last_commit_blob_bytes_snapshot;
        checkpoint_xid_ = checkpoint_xid_snapshot;
        last_committed_xid_ = last_committed_xid_snapshot;
        next_ephemeral_extent_ = working_next_extent_snapshot;
    };

    for (const auto& update : pending_object_map_updates_)
    {
        if (HasPhysicalObjectMapping(update))
        {
            committed_object_map_[update.object_id] = update;
        }
        else
        {
            committed_object_map_.erase(update.object_id);
        }
        if (auto pending_extents = pending_read_extent_updates_.find(update.object_id);
            pending_extents != pending_read_extent_updates_.end())
        {
            committed_read_extents_[update.object_id] = pending_extents->second;
        }
        else
        {
            if (committed_object_map_.contains(update.object_id))
            {
                committed_read_extents_.erase(update.object_id);
            }
        }
    }
    committed_spaceman_allocations_.insert(
        committed_spaceman_allocations_.end(),
        pending_spaceman_allocations_.begin(),
        pending_spaceman_allocations_.end()
    );
    if (!NormalizeSpacemanExtents(committed_spaceman_allocations_))
    {
        rollback_commit_extent_stage();
        rollback_committed_state();
        return fail_commit(CommitStatus::InvariantFailed, "committed-allocation-normalize-failed");
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
            rollback_committed_state();
            return fail_commit(CommitStatus::InvariantFailed, "committed-allocation-deallocation-normalize-failed");
        }
        if (!FreeExtent(deallocation.physical_address, deallocation.bytes))
        {
            rollback_commit_extent_stage();
            rollback_committed_state();
            return fail_commit(CommitStatus::AllocationFailed, "deallocation-free-extent-failed");
        }
    }
    committed_inodes_ = working_inodes_;
    committed_path_index_ = working_path_index_;
    committed_directory_links_ = working_directory_links_;
    auto merged_btree_records = committed_btree_records_;
    merged_btree_records.insert(
        merged_btree_records.end(),
        pending_btree_records_.begin(),
        pending_btree_records_.end());
    committed_btree_records_ = CanonicalizeBtreeRecords(merged_btree_records);
    committed_spaceman_free_extents_ = working_spaceman_free_extents_;
    if (!NormalizeSpacemanExtents(committed_spaceman_free_extents_))
    {
        rollback_commit_extent_stage();
        rollback_committed_state();
        return fail_commit(CommitStatus::InvariantFailed, "committed-free-extents-normalize-failed");
    }
    next_ephemeral_extent_ = working_next_ephemeral_extent_;

    checkpoint_xid_ = target_xid;
    last_committed_xid_ = target_xid;
    last_commit_blob_address_ = *commit_extent;
    last_commit_blob_bytes_ = commit_blob_persist_bytes;
    const auto verify_commit_roundtrips = commit_stage_hook_ || IsStrictCommitVerificationEnabled();
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

            std::vector<std::byte> checkpoint_block;
            if (!ReadBlockByIndexDirect(checkpoint_slots.front(), checkpoint_block) ||
                checkpoint_block.size() < kCheckpointHeaderBytes ||
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
        const auto next_extent_snapshot = next_ephemeral_extent_;
        const auto working_next_extent_snapshot = working_next_ephemeral_extent_;
        const auto last_committed_xid_snapshot = last_committed_xid_;
        const auto loaded_superblock_checkpoint_xid_snapshot = loaded_superblock_checkpoint_xid_;
        const auto restore_state = [&]()
        {
            committed_spaceman_allocations_ = committed_allocations_snapshot;
            committed_spaceman_free_extents_ = committed_free_extents_snapshot;
            working_spaceman_free_extents_ = working_free_extents_snapshot;
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
        const auto working_inodes_snapshot = working_inodes_;
        const auto working_path_index_snapshot = working_path_index_;
        const auto working_directory_links_snapshot = working_directory_links_;
        const auto working_child_count_snapshot = working_child_count_by_parent_;
        const auto working_directory_link_index_snapshot = working_directory_link_index_;
        const auto last_committed_xid_snapshot = last_committed_xid_;
        const auto loaded_superblock_checkpoint_xid_snapshot = loaded_superblock_checkpoint_xid_;

        const auto restore_state = [&]()
        {
            committed_inodes_ = committed_inodes_snapshot;
            committed_path_index_ = committed_path_index_snapshot;
            committed_directory_links_ = committed_directory_links_snapshot;
            working_inodes_ = working_inodes_snapshot;
            working_path_index_ = working_path_index_snapshot;
            working_directory_links_ = working_directory_links_snapshot;
            working_child_count_by_parent_ = working_child_count_snapshot;
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
        const auto last_committed_xid_snapshot = last_committed_xid_;
        const auto loaded_superblock_checkpoint_xid_snapshot = loaded_superblock_checkpoint_xid_;

        const auto restore_state = [&]()
        {
            committed_btree_records_ = committed_btree_snapshot;
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
    if (!PersistReplayCheckpoint(target_xid))
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

    const auto require_canonical_non_fixture_commit_path = RequiresCanonicalNonFixtureCommitPath();
    const auto allow_state_persist_stage = AllowCommitStage("before-state-persist");
    if (!allow_state_persist_stage)
    {
        if (!require_canonical_non_fixture_commit_path)
        {
            rollback_commit_extent_stage();
            rollback_committed_state();
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
            rollback_committed_state();
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

    ClearRecoveryRequired();
    pending_mutations_.clear();
    pending_object_map_updates_.clear();
    pending_spaceman_allocations_.clear();
    pending_spaceman_deallocations_.clear();
    pending_btree_records_.clear();
    pending_read_extent_updates_.clear();
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

            if (update.logical_size > 0)
            {
                const auto required_bytes = AlignExtentBytes(update.logical_size);
                if (required_bytes == 0 ||
                    (!has_committed_allocation(update.physical_address, required_bytes) &&
                     !has_recovered_read_extent_coverage(object_id, update.physical_address, update.logical_size)))
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
            auto extents = SortFileExtents(extents_it->second);
            if (HasLogicalExtentCoverage(extents, inode.logical_size) &&
                !extents.empty() &&
                extents.front().logical_offset == 0 &&
                extents.front().physical_address == inode.data_physical_address)
            {
                return extents;
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

std::size_t MetadataStore::PendingObjectMapUpdateCount() const noexcept
{
    return pending_object_map_updates_.size();
}

std::size_t MetadataStore::PendingAllocationCount() const noexcept
{
    return pending_spaceman_allocations_.size();
}

std::size_t MetadataStore::PendingDeallocationCount() const noexcept
{
    return pending_spaceman_deallocations_.size();
}

std::size_t MetadataStore::PendingBtreeRecordCount() const noexcept
{
    return pending_btree_records_.size();
}

std::uint64_t MetadataStore::PendingPayloadByteEstimate() const
{
    if (pending_mutations_.empty())
    {
        return 0;
    }

    std::unordered_set<std::wstring> payload_paths;
    payload_paths.reserve(pending_mutations_.size());
    const auto remap_payload_subtree = [&payload_paths](const std::wstring& source_key, const std::wstring& destination_key)
    {
        if (source_key.empty() || destination_key.empty())
        {
            return;
        }

        std::vector<std::wstring> pending_removals;
        std::vector<std::wstring> pending_additions;
        pending_removals.reserve(payload_paths.size());
        pending_additions.reserve(payload_paths.size());

        for (const auto& payload_path : payload_paths)
        {
            if (payload_path == source_key)
            {
                pending_removals.push_back(payload_path);
                pending_additions.push_back(destination_key);
                continue;
            }

            if (!IsDescendantPath(payload_path, source_key))
            {
                continue;
            }

            auto remapped_path = destination_key;
            remapped_path.append(payload_path.substr(source_key.size()));
            pending_removals.push_back(payload_path);
            pending_additions.push_back(std::move(remapped_path));
        }

        for (const auto& payload_path : pending_removals)
        {
            payload_paths.erase(payload_path);
        }
        for (const auto& payload_path : pending_additions)
        {
            if (!payload_path.empty())
            {
                payload_paths.insert(payload_path);
            }
        }
    };

    for (const auto& mutation : pending_mutations_)
    {
        const auto normalized_path = NormalizePath(mutation.path);
        const auto normalized_key = CanonicalPathKey(normalized_path);
        switch (mutation.operation)
        {
        case MutationOperation::Write:
            if (mutation.length > 0)
            {
                payload_paths.insert(normalized_key);
            }
            break;
        case MutationOperation::SetFileSize:
            if (mutation.length > 0)
            {
                payload_paths.insert(normalized_key);
            }
            else
            {
                payload_paths.erase(normalized_key);
            }
            break;
        case MutationOperation::Rename:
        {
            const auto normalized_secondary = NormalizePath(mutation.secondary_path);
            const auto normalized_secondary_key = CanonicalPathKey(normalized_secondary);
            remap_payload_subtree(normalized_key, normalized_secondary_key);
            break;
        }
        case MutationOperation::Delete:
            payload_paths.erase(normalized_key);
            break;
        default:
            break;
        }
    }

    std::uint64_t estimated_bytes = 0;
    for (const auto& payload_path : payload_paths)
    {
        auto inode = LookupWorkingInode(payload_path);
        if (!inode.has_value() ||
            inode->is_directory ||
            inode->data_physical_address == 0 ||
            inode->logical_size == 0)
        {
            continue;
        }

        if (inode->logical_size > std::numeric_limits<std::uint64_t>::max() - estimated_bytes)
        {
            return std::numeric_limits<std::uint64_t>::max();
        }

        estimated_bytes += inode->logical_size;
    }

    return estimated_bytes;
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

std::size_t MetadataStore::DebugWorkingInodeCount() const noexcept
{
    return working_inodes_.size();
}

std::optional<MetadataStore::InodeRecord> MetadataStore::DebugLookupWorkingInodeByPath(const std::wstring& path) const
{
    return LookupWorkingInode(NormalizePath(path));
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

std::optional<MetadataStore::InodeRecord> MetadataStore::LookupCommittedInodeByPath(const std::wstring& path) const
{
    const auto normalized = NormalizePath(path);
    auto it = committed_path_index_.find(CanonicalPathKey(normalized));
    if (it == committed_path_index_.end())
    {
        return std::nullopt;
    }

    auto inode = committed_inodes_.find(it->second);
    if (inode == committed_inodes_.end())
    {
        return std::nullopt;
    }

    return inode->second;
}

std::vector<MetadataStore::InodeRecord> MetadataStore::SnapshotCommittedInodes() const
{
    ScopedPerfTimer perf_scope(snapshot_committed_inodes_perf_);

    struct SnapshotEntry
    {
        std::wstring path_key;
        const InodeRecord* inode = nullptr;
    };

    std::vector<SnapshotEntry> snapshot;
    snapshot.reserve(committed_inodes_.size());
    for (const auto& [_, inode] : committed_inodes_)
    {
        snapshot.push_back(SnapshotEntry{ CanonicalPathKey(inode.full_path), &inode });
    }

    std::sort(snapshot.begin(), snapshot.end(), [](const SnapshotEntry& lhs, const SnapshotEntry& rhs)
    {
        if (lhs.path_key == rhs.path_key)
        {
            return lhs.inode->object_id < rhs.inode->object_id;
        }
        return lhs.path_key < rhs.path_key;
    });

    std::vector<InodeRecord> result;
    result.reserve(snapshot.size());
    for (auto& item : snapshot)
    {
        result.push_back(*item.inode);
    }
    return result;
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
        return true;
    }

    std::sort(extents.begin(), extents.end(), [](const FileExtent& lhs, const FileExtent& rhs)
    {
        if (lhs.logical_offset == rhs.logical_offset)
        {
            return lhs.physical_address < rhs.physical_address;
        }
        return lhs.logical_offset < rhs.logical_offset;
    });

    std::vector<FileExtent> normalized;
    normalized.reserve(extents.size());
    std::uint64_t previous_end = 0;
    bool has_previous = false;
    for (const auto& extent : extents)
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
                auto candidate = SortFileExtents(extents);
                if (HasLogicalExtentCoverage(candidate, inode_it->second.logical_size) &&
                    !FileExtentsEqual(canonical_extents, candidate))
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
    ScopedPerfTimer perf_scope(read_committed_range_perf_);

    out_bytes_read = 0;
    if (bytes_to_read > destination_size || (bytes_to_read > 0 && destination == nullptr))
    {
        return false;
    }

    auto inode = LookupCommittedInodeByPath(path);
    if (!inode.has_value() || inode->is_directory)
    {
        TraceReadFailure(path, 0, offset, bytes_to_read, L"InodeMissingOrDirectory");
        return false;
    }

    if (bytes_to_read == 0 || offset >= inode->logical_size)
    {
        return true;
    }

    const auto available_u64 = inode->logical_size - offset;
    const auto available_bytes = available_u64 > static_cast<std::uint64_t>(bytes_to_read)
        ? bytes_to_read
        : static_cast<std::size_t>(available_u64);

    std::fill_n(destination, available_bytes, std::byte{0});
    out_bytes_read = available_bytes;

    if (auto extents_it = committed_read_extents_.find(inode->object_id);
        extents_it != committed_read_extents_.end())
    {
        const auto request_begin = offset;
        const auto request_end = offset + static_cast<std::uint64_t>(available_bytes);
        const auto& extents = extents_it->second;
        auto extent_it = std::lower_bound(
            extents.begin(),
            extents.end(),
            request_begin,
            ExtentEndsBeforeOrAt);
        for (; extent_it != extents.end(); ++extent_it)
        {
            const auto& extent = *extent_it;
            const auto extent_begin = extent.logical_offset;
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
            const auto chunk_bytes = static_cast<std::size_t>(chunk_end - chunk_begin);
            if (extent.physical_address == 0)
            {
                continue;
            }
            if (extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - (chunk_begin - extent_begin)))
            {
                TraceReadFailure(path, inode->object_id, offset, available_bytes, L"ExtentPhysicalOverflow");
                return false;
            }
            const auto physical_offset = extent.physical_address + (chunk_begin - extent_begin);

            std::size_t chunk_read = 0;
            const auto destination_offset = static_cast<std::size_t>(chunk_begin - request_begin);
            if (destination_offset > available_bytes ||
                chunk_bytes > (available_bytes - destination_offset))
            {
                return false;
            }

            if (!device_.ReadInto(
                    physical_offset,
                    destination + destination_offset,
                    chunk_bytes,
                    chunk_read) ||
                chunk_read > chunk_bytes)
            {
                TraceReadFailure(path, inode->object_id, physical_offset, chunk_bytes, L"ExtentDeviceReadFailed");
                return false;
            }
            if (chunk_read < chunk_bytes)
            {
                TraceReadFailure(path, inode->object_id, physical_offset, chunk_bytes, L"ExtentDeviceShortRead");
                return false;
            }
        }
        return true;
    }

    if (inode->data_physical_address == 0 || inode->logical_size == 0)
    {
        TraceReadFailure(path, inode->object_id, offset, available_bytes, L"NoDataExtent");
        return false;
    }

    if (inode->data_physical_address > (std::numeric_limits<std::uint64_t>::max() - offset))
    {
        TraceReadFailure(path, inode->object_id, offset, available_bytes, L"SingleExtentPhysicalOverflow");
        return false;
    }
    const auto physical_offset = inode->data_physical_address + offset;

    std::size_t bytes_read = 0;
    if (!device_.ReadInto(physical_offset, destination, available_bytes, bytes_read))
    {
        TraceReadFailure(path, inode->object_id, physical_offset, available_bytes, L"SingleExtentDeviceReadFailed");
        return false;
    }

    if (bytes_read < available_bytes)
    {
        TraceReadFailure(path, inode->object_id, physical_offset, available_bytes, L"SingleExtentDeviceShortRead");
        return false;
    }

    return true;
}

void MetadataStore::SetCommitStageHook(std::function<bool(std::string_view stage)> hook)
{
    commit_stage_hook_ = std::move(hook);
}

void MetadataStore::SetFilePayloadProvider(
    std::function<std::optional<std::vector<std::byte>>(const std::wstring& path, std::uint64_t logical_size)> provider)
{
    file_payload_provider_ = std::move(provider);
}

void MetadataStore::SetFilePayloadRangeProvider(
    std::function<bool(
        const std::wstring& path,
        std::uint64_t offset,
        std::span<std::byte> destination)> provider)
{
    file_payload_range_provider_ = std::move(provider);
}

std::optional<std::uint64_t> MetadataStore::AllocateExtent(std::uint64_t bytes)
{
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

    for (auto it = working_spaceman_free_extents_.begin(); it != working_spaceman_free_extents_.end(); ++it)
    {
        if (it->bytes < aligned_bytes)
        {
            continue;
        }

        const auto allocation_address = it->physical_address;
        if (allocation_address > (std::numeric_limits<std::uint64_t>::max() - aligned_bytes))
        {
            continue;
        }
        const auto allocation_end = allocation_address + aligned_bytes;
        if (container_bytes.has_value() && allocation_end > container_bytes.value())
        {
            continue;
        }
        if (ExtentOverlapsReservedMetadata(allocation_address, aligned_bytes))
        {
            continue;
        }
        it->physical_address += aligned_bytes;
        it->bytes -= aligned_bytes;
        if (it->bytes == 0)
        {
            working_spaceman_free_extents_.erase(it);
        }
        return allocation_address;
    }

    auto current = working_next_ephemeral_extent_;
    if (current > (std::numeric_limits<std::uint64_t>::max() - aligned_bytes))
    {
        return std::nullopt;
    }

    const auto allocation_end = current + aligned_bytes;
    if (container_bytes.has_value() && allocation_end > container_bytes.value())
    {
        return std::nullopt;
    }
    if (ExtentOverlapsReservedMetadata(current, aligned_bytes))
    {
        return std::nullopt;
    }

    working_next_ephemeral_extent_ = allocation_end;
    return current;
}

std::optional<std::vector<MetadataStore::FileExtent>> MetadataStore::AllocateFileExtents(std::uint64_t logical_size)
{
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

    const auto is_usable_extent = [&](const SpacemanAllocation& extent, std::uint64_t bytes)
    {
        if (extent.bytes < bytes ||
            extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - bytes))
        {
            return false;
        }
        if (container_bytes.has_value() && (extent.physical_address + bytes) > container_bytes.value())
        {
            return false;
        }
        return !ExtentOverlapsReservedMetadata(extent.physical_address, bytes);
    };

    for (auto it = working_spaceman_free_extents_.begin(); it != working_spaceman_free_extents_.end(); ++it)
    {
        if (!is_usable_extent(*it, aligned_total))
        {
            continue;
        }

        const auto physical_address = it->physical_address;
        it->physical_address += aligned_total;
        it->bytes -= aligned_total;
        if (it->bytes == 0)
        {
            working_spaceman_free_extents_.erase(it);
        }
        return std::vector<FileExtent>{ FileExtent{ 0, physical_address, logical_size } };
    }

    std::uint64_t available_fragmented_bytes = 0;
    for (const auto& extent : working_spaceman_free_extents_)
    {
        if (extent.bytes == 0 ||
            extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - extent.bytes) ||
            (container_bytes.has_value() && (extent.physical_address + extent.bytes) > container_bytes.value()) ||
            ExtentOverlapsReservedMetadata(extent.physical_address, extent.bytes))
        {
            continue;
        }
        if (available_fragmented_bytes > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
        {
            return std::nullopt;
        }
        available_fragmented_bytes += extent.bytes;
        if (available_fragmented_bytes >= aligned_total)
        {
            break;
        }
    }

    if (available_fragmented_bytes >= aligned_total)
    {
        std::vector<FileExtent> file_extents;
        std::uint64_t remaining_logical = logical_size;
        std::uint64_t logical_offset = 0;

        for (auto it = working_spaceman_free_extents_.begin();
             it != working_spaceman_free_extents_.end() && remaining_logical > 0;)
        {
            if (it->bytes == 0 ||
                it->physical_address > (std::numeric_limits<std::uint64_t>::max() - it->bytes) ||
                (container_bytes.has_value() && (it->physical_address + it->bytes) > container_bytes.value()) ||
                ExtentOverlapsReservedMetadata(it->physical_address, it->bytes))
            {
                ++it;
                continue;
            }

            const auto remaining_aligned = AlignExtentBytes(remaining_logical);
            if (remaining_aligned == 0)
            {
                return std::nullopt;
            }
            const auto allocation_bytes = std::min(it->bytes, remaining_aligned);
            const auto logical_bytes = std::min(remaining_logical, allocation_bytes);
            if (logical_bytes == 0)
            {
                return std::nullopt;
            }

            const auto physical_address = it->physical_address;
            file_extents.push_back(FileExtent{ logical_offset, physical_address, logical_bytes });
            logical_offset += logical_bytes;
            remaining_logical -= logical_bytes;

            it->physical_address += allocation_bytes;
            it->bytes -= allocation_bytes;
            if (it->bytes == 0)
            {
                it = working_spaceman_free_extents_.erase(it);
            }
            else
            {
                ++it;
            }
        }

        if (remaining_logical == 0 && HasLogicalExtentCoverage(file_extents, logical_size))
        {
            return file_extents;
        }
        return std::nullopt;
    }

    auto extent = AllocateExtent(logical_size);
    if (!extent.has_value())
    {
        return std::nullopt;
    }
    return std::vector<FileExtent>{ FileExtent{ 0, *extent, logical_size } };
}

bool MetadataStore::FreeExtent(std::uint64_t physical_address, std::uint64_t bytes)
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

    working_spaceman_free_extents_.push_back(SpacemanAllocation
    {
        physical_address,
        aligned_bytes
    });
    std::sort(
        working_spaceman_free_extents_.begin(),
        working_spaceman_free_extents_.end(),
        [](const SpacemanAllocation& lhs, const SpacemanAllocation& rhs)
        {
            return lhs.physical_address < rhs.physical_address;
        });

    std::vector<SpacemanAllocation> merged;
    merged.reserve(working_spaceman_free_extents_.size());
    for (const auto& extent : working_spaceman_free_extents_)
    {
        if (extent.bytes == 0)
        {
            continue;
        }

        if (merged.empty())
        {
            merged.push_back(extent);
            continue;
        }

        auto& last = merged.back();
        const auto last_end = last.physical_address + last.bytes;
        const auto extent_end = extent.physical_address + extent.bytes;
        if (extent.physical_address <= last_end)
        {
            if (extent_end > last_end)
            {
                last.bytes = extent_end - last.physical_address;
            }
            continue;
        }

        merged.push_back(extent);
    }

    working_spaceman_free_extents_ = std::move(merged);
    return true;
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
                committed_path_index_[CanonicalPathKey(inode.full_path)] = object_id;
            }
        }
    }

    auto root_path_it = committed_path_index_.find(CanonicalPathKey(root_path));
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
        committed_path_index_[CanonicalPathKey(root_inode.full_path)] = root_inode.object_id;
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

    std::unordered_map<std::wstring, std::uint64_t> canonical_paths;
    canonical_paths.reserve(inode_table.size());
    std::unordered_map<std::uint64_t, std::wstring> path_keys_by_object_id;
    path_keys_by_object_id.reserve(inode_table.size());
    std::size_t root_count = 0;
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

        const auto path_key = CanonicalPathKey(inode.full_path);
        if (path_key.empty())
        {
            TraceGraphFailure(L"PathKeyEmpty", object_id);
            return false;
        }

        auto [path_it, inserted] = canonical_paths.emplace(path_key, object_id);
        if (!inserted && path_it->second != object_id)
        {
            TraceGraphFailure(L"CanonicalPathCollision", object_id);
            return false;
        }
        path_keys_by_object_id.emplace(object_id, path_key);

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

            const auto parent_path_key = CanonicalPathKey(ParentPath(inode.full_path));
            const auto parent_full_path_key = CanonicalPathKey(parent_it->second.full_path);
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

    if (path_index.size() != canonical_paths.size())
    {
        TraceGraphFailure(L"PathIndexSize");
        return false;
    }
    for (const auto& [path_key, object_id] : path_index)
    {
        auto inode_it = inode_table.find(object_id);
        if (inode_it == inode_table.end())
        {
            TraceGraphFailure(L"PathIndexMissingInode", object_id);
            return false;
        }

        const auto path_key_it = path_keys_by_object_id.find(object_id);
        if (path_key_it == path_keys_by_object_id.end() ||
            path_key != path_key_it->second)
        {
            TraceGraphFailure(L"PathIndexKeyMismatch", object_id);
            return false;
        }
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
    const auto normalized_key = CanonicalPathKey(normalized_path);
    for (std::uint32_t probe = 0; probe < kFallbackProbeLimit; ++probe)
    {
        auto existing = working_inodes_.find(candidate);
        if ((existing == working_inodes_.end() ||
             CanonicalPathKey(existing->second.full_path) == normalized_key) &&
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
    auto inode = LookupWorkingInode(normalized_path);
    return inode.has_value() && inode->is_directory;
}

std::optional<MetadataStore::InodeRecord> MetadataStore::LookupWorkingInode(const std::wstring& normalized_path) const
{
    auto index = working_path_index_.find(CanonicalPathKey(normalized_path));
    if (index == working_path_index_.end())
    {
        return std::nullopt;
    }

    auto inode = working_inodes_.find(index->second);
    if (inode == working_inodes_.end())
    {
        return std::nullopt;
    }

    return inode->second;
}

bool MetadataStore::HasWorkingChildren(std::uint64_t parent_object_id) const
{
    const auto count = working_child_count_by_parent_.find(parent_object_id);
    return count != working_child_count_by_parent_.end() && count->second != 0;
}

std::wstring MetadataStore::BuildWorkingDirectoryLinkIndexKey(
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
    return BuildDirectoryEntryIndexKey(parent_object_id, normalized_entry_name);
}

void MetadataStore::RebuildWorkingDirectoryIndexes()
{
    working_child_count_by_parent_.clear();
    working_directory_link_index_.clear();
    working_child_count_by_parent_.reserve(working_directory_links_.size());
    working_directory_link_index_.reserve(working_directory_links_.size());
    for (std::size_t index = 0; index < working_directory_links_.size(); ++index)
    {
        const auto& link = working_directory_links_[index];
        ++working_child_count_by_parent_[link.parent_object_id];
        working_directory_link_index_[BuildWorkingDirectoryLinkIndexKey(link.parent_object_id, link.entry_name)] = index;
    }
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
    ++working_child_count_by_parent_[parent_object_id];
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

    auto count_it = working_child_count_by_parent_.find(parent_object_id);
    if (count_it != working_child_count_by_parent_.end())
    {
        if (count_it->second <= 1)
        {
            working_child_count_by_parent_.erase(count_it);
        }
        else
        {
            --count_it->second;
        }
    }
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

    for (auto& pending : pending_object_map_updates_)
    {
        if (pending.object_id == object_id)
        {
            pending = next_update;
            return true;
        }
    }

    pending_object_map_updates_.push_back(next_update);
    return true;
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

    pending_spaceman_allocations_.push_back(SpacemanAllocation
    {
        physical_address,
        aligned_bytes
    });
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

    if (auto extents_it = committed_read_extents_.find(inode.object_id);
        extents_it != committed_read_extents_.end())
    {
        result.file_extents.reserve(extents_it->second.size());
        result.allocations.reserve(extents_it->second.size() + (inode.data_physical_address == 0 ? 0 : 1));
        for (const auto& extent : extents_it->second)
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

            result.file_extents.push_back(
                {
                    extent.logical_offset,
                    extent.physical_address,
                    logical_bytes,
                });

            if (extent.physical_address == 0)
            {
                continue;
            }

            const auto aligned_bytes = AlignExtentBytes(logical_bytes);
            if (aligned_bytes == 0 ||
                extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - aligned_bytes))
            {
                return std::nullopt;
            }
            result.allocations.push_back({ extent.physical_address, aligned_bytes });
        }

        if (!result.file_extents.empty())
        {
            std::sort(
                result.file_extents.begin(),
                result.file_extents.end(),
                [](const FileExtent& lhs, const FileExtent& rhs)
                {
                    if (lhs.logical_offset == rhs.logical_offset)
                    {
                        return lhs.physical_address < rhs.physical_address;
                    }
                    return lhs.logical_offset < rhs.logical_offset;
                });
        }

        std::uint64_t previous_end = 0;
        bool has_previous = false;
        for (const auto& extent : result.file_extents)
        {
            const auto extent_end = extent.logical_offset + extent.bytes;
            if (has_previous && extent.logical_offset < previous_end)
            {
                return std::nullopt;
            }
            previous_end = extent_end;
            has_previous = true;
        }

        if (result.file_extents.empty() && inode.data_physical_address == 0)
        {
            return result;
        }

        if (inode.data_physical_address != 0)
        {
            const auto aligned_bytes = AlignExtentBytes(inode.logical_size);
            if (aligned_bytes == 0 ||
                inode.data_physical_address > (std::numeric_limits<std::uint64_t>::max() - aligned_bytes))
            {
                return std::nullopt;
            }

            const auto covered_by_projection = std::any_of(
                result.allocations.begin(),
                result.allocations.end(),
                [&](const SpacemanAllocation& allocation)
                {
                    return PhysicalRangeContains(
                        allocation.physical_address,
                        allocation.bytes,
                        inode.data_physical_address,
                        aligned_bytes);
                });
            if (!covered_by_projection)
            {
                result.file_extents.push_back(
                    {
                        0,
                        inode.data_physical_address,
                        inode.logical_size,
                    });
                result.allocations.push_back({ inode.data_physical_address, aligned_bytes });
            }
        }

        if (!NormalizeSpacemanExtents(result.allocations))
        {
            return std::nullopt;
        }
        return result;
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

    return std::any_of(
        pending_spaceman_allocations_.begin(),
        pending_spaceman_allocations_.end(),
        [&](const SpacemanAllocation& allocation)
        {
            return allocation.physical_address == physical_address &&
                   allocation.bytes == aligned_bytes;
        });
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

    for (auto it = pending_spaceman_allocations_.begin(); it != pending_spaceman_allocations_.end(); ++it)
    {
        if (it->physical_address != physical_address || it->bytes != aligned_bytes)
        {
            continue;
        }

        pending_spaceman_allocations_.erase(it);
        return FreeExtent(physical_address, aligned_bytes);
    }

    return false;
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

    const auto extents = SortFileExtents(extents_it->second);
    const auto range_end = offset + length;
    auto covered_until = offset;
    for (const auto& extent : extents)
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

        covered_until = std::min(extent_end, range_end);
        if (covered_until >= range_end)
        {
            return true;
        }
    }

    return false;
}

void MetadataStore::CoalescePendingWriteMutation(std::uint64_t object_id, const MutationRequest& request)
{
    pending_mutations_.erase(
        std::remove_if(
            pending_mutations_.begin(),
            pending_mutations_.end(),
            [&](const MutationRequest& pending)
            {
                if (pending.operation != MutationOperation::Write)
                {
                    return false;
                }

                auto inode = LookupWorkingInode(NormalizePath(pending.path));
                return inode.has_value() && inode->object_id == object_id;
            }),
        pending_mutations_.end());

    pending_mutations_.push_back(request);
}

void MetadataStore::CoalescePendingBtreeFileMetadata(std::uint64_t object_id)
{
    const auto is_live_file_metadata_for_object = [&](const BtreeRecord& record)
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
            return DecodeBtreeInodeRecord(record, decoded) &&
                   !decoded.is_directory &&
                   decoded.object_id == object_id;
        }
        case BtreeRecordKind::FileExtent:
        {
            DecodedBtreeExtent decoded{};
            return DecodeBtreeExtentRecord(record, decoded) &&
                   decoded.object_id == object_id;
        }
        default:
            return false;
        }
    };

    bool kept_inode = false;
    std::unordered_set<std::uint64_t> kept_extent_offsets;
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

        it = std::reverse_iterator(pending_btree_records_.erase(std::next(it).base()));
    }
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

bool MetadataStore::ValidatePendingCommitState() const
{
    const auto fail_pending = [this](std::wstring_view reason, std::uint64_t object_id = 0) -> bool
    {
        TracePendingCommitFailure(reason, object_id);
        last_commit_failure_reason_.assign(reason);
        last_commit_failure_object_id_ = object_id == 0
            ? std::nullopt
            : std::optional<std::uint64_t>(object_id);
        return false;
    };

    if (pending_mutations_.empty())
    {
        return fail_pending(L"NoPendingMutations");
    }
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

        for (const auto& allocation : pending_spaceman_allocations_)
        {
            if (allocation.physical_address == physical_address &&
                allocation.bytes >= required_bytes &&
                PhysicalRangeContains(allocation.physical_address, allocation.bytes, physical_address, required_bytes))
            {
                return true;
            }
        }
        return false;
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

        for (const auto& allocation : committed_spaceman_allocations_)
        {
            if (PhysicalRangeContains(allocation.physical_address, allocation.bytes, physical_address, required_bytes))
            {
                return true;
            }
        }
        return false;
    };

    const auto has_allocation_for_physical = [&](std::uint64_t physical_address, std::uint64_t logical_size) -> bool
    {
        return has_pending_allocation_for_physical(physical_address, logical_size) ||
               has_committed_allocation_for_physical(physical_address, logical_size);
    };

    std::unordered_map<std::uint64_t, ObjectMapUpdate> effective_object_map = committed_object_map_;
    auto effective_read_extents = committed_read_extents_;

    for (const auto& update : pending_object_map_updates_)
    {
        if (update.object_id == 0 ||
            update.xid != checkpoint_xid_ + 1)
        {
            return fail_pending(L"PendingObjectMapInvalid", update.object_id);
        }
        if (HasPhysicalObjectMapping(update))
        {
            effective_object_map[update.object_id] = update;
        }
        else
        {
            effective_object_map.erase(update.object_id);
            effective_read_extents.erase(update.object_id);
        }
    }
    for (const auto& [object_id, extents] : pending_read_extent_updates_)
    {
        if (extents.empty())
        {
            effective_read_extents.erase(object_id);
        }
        else
        {
            effective_read_extents[object_id] = SortFileExtents(extents);
        }
    }
    const auto canonical_extents_for_inode = [&](const InodeRecord& inode) -> std::optional<std::vector<FileExtent>>
    {
        if (inode.is_directory ||
            inode.logical_size == 0 ||
            inode.data_physical_address == 0)
        {
            return std::nullopt;
        }

        const auto extents_it = effective_read_extents.find(inode.object_id);
        if (extents_it == effective_read_extents.end())
        {
            return std::vector<FileExtent>{ FileExtent{ 0, inode.data_physical_address, inode.logical_size } };
        }

        auto extents = SortFileExtents(extents_it->second);
        const auto has_pending_extent_update = pending_read_extent_updates_.contains(inode.object_id);
        if (HasLogicalExtentCoverage(extents, inode.logical_size) &&
            !extents.empty() &&
            extents.front().logical_offset == 0 &&
            extents.front().physical_address == inode.data_physical_address)
        {
            return extents;
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

        const auto extents_it = effective_read_extents.find(inode.object_id);
        if (extents_it == effective_read_extents.end())
        {
            return false;
        }

        auto extents = SortFileExtents(extents_it->second);
        std::uint64_t covered_until = 0;
        for (const auto& extent : extents)
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

    std::vector<ApfsObjectMapEntry> effective_object_entries;
    effective_object_entries.reserve(effective_object_map.size());
    for (const auto& [_, update] : effective_object_map)
    {
        if (!HasPhysicalObjectMapping(update))
        {
            continue;
        }
        effective_object_entries.push_back(
            {
                update.object_id,
                update.physical_address,
                update.logical_size,
                update.xid,
            });
    }
    ApfsObjectMapStore object_map_store;
    if (!object_map_store.ValidateEntries(effective_object_entries))
    {
        return fail_pending(L"ObjectMapValidateEntries");
    }

    for (const auto& allocation : pending_spaceman_allocations_)
    {
        if (!is_valid_extent(allocation))
        {
            return fail_pending(L"PendingAllocationInvalid", allocation.physical_address);
        }
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
    for (const auto& allocation : pending_spaceman_allocations_)
    {
        for (const auto& deallocation : pending_spaceman_deallocations_)
        {
            if (!overlaps(allocation, deallocation))
            {
                continue;
            }

            if (allocation.physical_address == deallocation.physical_address &&
                allocation.bytes == deallocation.bytes)
            {
                continue;
            }

            return fail_pending(L"PendingAllocationDeallocationPartialOverlap", allocation.physical_address);
        }
    }

    std::set<std::uint64_t> live_extent_addresses;
    for (const auto& [object_id, inode] : working_inodes_)
    {
        if (inode.is_directory ||
            inode.data_physical_address == 0 ||
            inode.logical_size == 0)
        {
            continue;
        }

        const auto mapped = effective_object_map.find(object_id);
        if (mapped == effective_object_map.end())
        {
            return fail_pending(L"LiveExtentMissingObjectMap", object_id);
        }
        if (mapped->second.physical_address != inode.data_physical_address ||
            mapped->second.logical_size != inode.logical_size)
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
                return fail_pending(L"LiveExtentMissingAllocation", object_id);
            }

            live_extent_addresses.insert(extent.physical_address);
        }
    }

    for (const auto& entry : effective_object_map)
    {
        const auto& update = entry.second;
        if (update.physical_address == 0 || update.logical_size == 0)
        {
            continue;
        }
        const auto committed_it = committed_object_map_.find(update.object_id);
        const auto update_matches_committed =
            committed_it != committed_object_map_.end() &&
            committed_it->second.physical_address == update.physical_address &&
            committed_it->second.logical_size == update.logical_size;
        if (update_matches_committed)
        {
            if (!has_committed_allocation_for_physical(update.physical_address, update.logical_size) &&
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

        bool matched = false;
        for (const auto& allocation : committed_spaceman_allocations_)
        {
            if (PhysicalRangeContains(
                    allocation.physical_address,
                    allocation.bytes,
                    deallocation.physical_address,
                    deallocation.bytes))
            {
                matched = true;
                break;
            }
        }
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

    std::vector<ApfsExtent> projected_allocations;
    projected_allocations.reserve(committed_spaceman_allocations_.size() + pending_spaceman_allocations_.size());
    for (const auto& allocation : committed_spaceman_allocations_)
    {
        bool removed_by_deallocation = false;
        for (const auto& deallocation : pending_spaceman_deallocations_)
        {
            if (allocation.physical_address == deallocation.physical_address &&
                allocation.bytes == deallocation.bytes)
            {
                removed_by_deallocation = true;
                break;
            }
        }
        if (!removed_by_deallocation)
        {
            projected_allocations.push_back(
                {
                    allocation.physical_address,
                    allocation.bytes,
                });
        }
    }
    for (const auto& allocation : pending_spaceman_allocations_)
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

    auto projected_btree_records = committed_btree_records_;
    projected_btree_records.insert(
        projected_btree_records.end(),
        pending_btree_records_.begin(),
        pending_btree_records_.end());
    projected_btree_records = CanonicalizeBtreeRecords(projected_btree_records);

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
    if (volume_tree_projection.inode_record_count != expected_non_root_inode_count ||
        volume_tree_projection.directory_entry_record_count != working_directory_links_.size() ||
        volume_tree_projection.extent_record_count != expected_extent_count)
    {
        return fail_pending(L"ProjectedVolumeTreeCountMismatch");
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
                 !effective_read_extents.contains(object_id)))
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

            auto mapped = effective_object_map.find(object_id);
            if (mapped == effective_object_map.end())
            {
                return fail_pending(L"ProjectedBtreeMissingObjectMap", object_id);
            }
            if (mapped->second.physical_address != inode.data_physical_address ||
                mapped->second.logical_size != inode.logical_size)
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

    std::vector<std::uint64_t> object_ids;
    object_ids.reserve(committed_object_map_.size());
    for (const auto& [object_id, update] : committed_object_map_)
    {
        if (HasPhysicalObjectMapping(update))
        {
            object_ids.push_back(object_id);
        }
    }
    std::sort(object_ids.begin(), object_ids.end());

    const auto required_bytes = kHeaderBytes + (object_ids.size() * kEntryBytes);
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

    std::vector<std::byte> block(required_bytes, std::byte{0});
    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        block[index] = static_cast<std::byte>(kMagic[index]);
    }
    WriteLe64(block, 12, target_xid);
    WriteLe32(block, 20, static_cast<std::uint32_t>(object_ids.size()));

    std::size_t cursor = kHeaderBytes;
    for (const auto object_id : object_ids)
    {
        auto it = committed_object_map_.find(object_id);
        if (it == committed_object_map_.end())
        {
            return false;
        }

        WriteLe64(block, cursor + 0, it->second.object_id);
        WriteLe64(block, cursor + 8, it->second.physical_address);
        WriteLe64(block, cursor + 16, it->second.logical_size);
        WriteLe64(block, cursor + 24, it->second.xid);
        cursor += kEntryBytes;
    }

    const auto payload_bytes = cursor - kHeaderBytes;
    WriteLe32(block, 24, static_cast<std::uint32_t>(payload_bytes));
    WriteLe32(block, kCheckpointChecksumOffset, ComputeCheckpointChecksum(block, payload_bytes));
    return WriteChunkedCheckpointBlocks(object_map_blocks, target_xid, block);
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

    auto allocations = committed_spaceman_allocations_;
    auto free_extents = committed_spaceman_free_extents_;
    if (!NormalizeSpacemanExtents(allocations) ||
        !NormalizeSpacemanExtents(free_extents))
    {
        return false;
    }

    const auto required_entries = allocations.size() + free_extents.size();
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

    std::vector<std::byte> block(required_bytes, std::byte{0});
    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        block[index] = static_cast<std::byte>(kMagic[index]);
    }
    WriteLe64(block, 12, target_xid);
    WriteLe32(block, 20, static_cast<std::uint32_t>(allocations.size()));
    WriteLe32(block, 24, static_cast<std::uint32_t>(free_extents.size()));

    std::size_t cursor = kHeaderBytes;
    for (const auto& allocation : allocations)
    {
        WriteLe64(block, cursor + 0, allocation.physical_address);
        WriteLe64(block, cursor + 8, allocation.bytes);
        cursor += kEntryBytes;
    }
    for (const auto& extent : free_extents)
    {
        WriteLe64(block, cursor + 0, extent.physical_address);
        WriteLe64(block, cursor + 8, extent.bytes);
        cursor += kEntryBytes;
    }

    const auto payload_bytes = cursor - kHeaderBytes;
    WriteLe32(block, kCheckpointChecksumOffset, ComputeCheckpointChecksum(block, payload_bytes));
    return WriteChunkedCheckpointBlocks(spaceman_blocks, target_xid, block);
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

    struct SnapshotEntry
    {
        std::wstring path_key;
        const InodeRecord* inode = nullptr;
        bool persist_full_path = false;
    };

    std::vector<SnapshotEntry> snapshot;
    snapshot.reserve(committed_inodes_.size());
    for (const auto& [_, inode] : committed_inodes_)
    {
        SnapshotEntry entry{};
        entry.path_key = CanonicalPathKey(inode.full_path);
        entry.inode = &inode;

        if (!IsRootPath(inode.full_path))
        {
            auto parent_it = committed_inodes_.find(inode.parent_object_id);
            if (parent_it == committed_inodes_.end())
            {
                entry.persist_full_path = true;
                snapshot.push_back(std::move(entry));
                continue;
            }

            auto reconstructed_path = parent_it->second.full_path;
            if (!IsRootPath(reconstructed_path))
            {
                reconstructed_path.push_back(L'\\');
            }
            reconstructed_path.append(inode.name);
            reconstructed_path = NormalizePath(reconstructed_path);
            entry.persist_full_path = reconstructed_path != inode.full_path;
        }

        snapshot.push_back(std::move(entry));
    }

    std::sort(snapshot.begin(), snapshot.end(), [](const SnapshotEntry& lhs, const SnapshotEntry& rhs)
    {
        if (lhs.path_key == rhs.path_key)
        {
            return lhs.inode->object_id < rhs.inode->object_id;
        }
        return lhs.path_key < rhs.path_key;
    });

    std::size_t required_bytes = kHeaderBytes;
    for (const auto& entry : snapshot)
    {
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

    std::vector<std::byte> block(required_bytes, std::byte{0});
    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        block[index] = static_cast<std::byte>(kMagic[index]);
    }
    WriteLe64(block, 12, target_xid);
    WriteLe32(block, 20, static_cast<std::uint32_t>(snapshot.size()));

    std::size_t cursor = kHeaderBytes;
    for (const auto& entry : snapshot)
    {
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
    return WriteChunkedCheckpointBlocks(inode_blocks, target_xid, block);
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

    std::size_t required_bytes = kHeaderBytes;
    for (const auto& record : committed_btree_records_)
    {
        if (required_bytes > (std::numeric_limits<std::size_t>::max() - kRecordHeaderBytes - record.key.size() - record.value.size()))
        {
            return false;
        }
        required_bytes += kRecordHeaderBytes + record.key.size() + record.value.size();
    }
    if (block_size_ == 0 ||
        btree_blocks.size() > (std::numeric_limits<std::size_t>::max() / static_cast<std::size_t>(block_size_)))
    {
        return false;
    }
    const auto checkpoint_capacity = btree_blocks.size() * static_cast<std::size_t>(block_size_);
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

    std::vector<std::byte> block(required_bytes, std::byte{0});
    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        block[index] = static_cast<std::byte>(kMagic[index]);
    }
    WriteLe64(block, 12, target_xid);
    WriteLe32(block, 20, static_cast<std::uint32_t>(committed_btree_records_.size()));

    std::size_t cursor = kHeaderBytes;
    for (const auto& record : committed_btree_records_)
    {
        WriteLe32(block, cursor + 0, static_cast<std::uint32_t>(record.kind));
        WriteLe32(block, cursor + 4, record.tombstone ? 1u : 0u);
        WriteLe32(block, cursor + 8, static_cast<std::uint32_t>(record.key.size()));
        WriteLe32(block, cursor + 12, static_cast<std::uint32_t>(record.value.size()));
        cursor += kRecordHeaderBytes;

        if (!record.key.empty())
        {
            std::memcpy(block.data() + cursor, record.key.data(), record.key.size());
            cursor += record.key.size();
        }
        if (!record.value.empty())
        {
            std::memcpy(block.data() + cursor, record.value.data(), record.value.size());
            cursor += record.value.size();
        }
    }

    const auto payload_bytes = cursor - kHeaderBytes;
    WriteLe32(block, 24, static_cast<std::uint32_t>(payload_bytes));
    WriteLe32(block, kCheckpointChecksumOffset, ComputeCheckpointChecksum(block, payload_bytes));
    return WriteChunkedCheckpointBlocks(btree_blocks, target_xid, block);
}

bool MetadataStore::PersistReplayCheckpoint(std::uint64_t target_xid)
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
    if (!ValidateReplayCommitBlobCandidate(
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

    std::vector<std::byte> block(static_cast<std::size_t>(block_size_), std::byte{0});
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
    return WriteBlockByIndexDirect(target_slot, block);
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

    auto source_offset = active_superblock_offset_;
    std::vector<std::byte> superblock;
    if (!device_.Read(source_offset, kSuperblockBytes, superblock) || superblock.size() < kSuperblockBytes)
    {
        source_offset = 0;
        if (!device_.Read(source_offset, kSuperblockBytes, superblock) || superblock.size() < kSuperblockBytes)
        {
            return false;
        }
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
    if (!device_.Write(*target_offset, superblock))
    {
        return false;
    }

    active_superblock_offset_ = *target_offset;
    alternate_superblock_offset_ = source_offset;
    return true;
}

bool MetadataStore::LoadPersistentState()
{
    persistent_state_path_ = BuildPersistentStatePath(context_);
    persistent_state_loaded_ = true;
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
    committed_spaceman_allocations_.clear();
    committed_spaceman_free_extents_.clear();
    committed_inodes_.clear();
    committed_path_index_.clear();
    committed_directory_links_.clear();
    committed_btree_records_.clear();
    working_inodes_.clear();
    working_path_index_.clear();
    working_directory_links_.clear();
    RebuildWorkingDirectoryIndexes();
    working_spaceman_free_extents_.clear();
    last_commit_blob_address_.reset();
    last_commit_blob_bytes_.reset();
    pending_mutations_.clear();
    pending_object_map_updates_.clear();
    pending_spaceman_allocations_.clear();
    pending_spaceman_deallocations_.clear();
    pending_btree_records_.clear();

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
            projected_path_index[CanonicalPathKey(inode.full_path)] = inode.object_id;
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
        for (auto& [object_id, extents] : projection.read_extents_by_inode)
        {
            if (!SetCommittedReadExtents(object_id, std::move(extents)))
            {
                committed_read_extents_.erase(object_id);
            }
        }

        if (!ValidateInodeGraphState(
                projected_inodes,
                projected_path_index,
                projected_directory_links,
                /*require_root_object=*/true))
        {
            committed_read_extents_ = read_extents_snapshot;
            return false;
        }

        if (!disk_loaded_inodes.empty() &&
            projected_inodes.size() <= disk_loaded_inodes.size() &&
            projection.btree_records.size() <= disk_loaded_btree_checkpoint_records.size())
        {
            committed_read_extents_ = read_extents_snapshot;
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
        committed_spaceman_allocations_.clear();
        committed_spaceman_free_extents_.clear();
        committed_btree_records_.clear();
        committed_inodes_.clear();
        committed_path_index_.clear();
        committed_directory_links_.clear();
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
            committed_path_index_.clear();
            committed_directory_links_.clear();
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
        committed_path_index_.clear();
        committed_directory_links_.clear();
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
            committed_path_index_.clear();
            committed_directory_links_.clear();
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
        committed_path_index_.clear();
        committed_directory_links_.clear();
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
        committed_spaceman_allocations_ = disk_loaded_allocations;
        committed_spaceman_free_extents_ = disk_loaded_free_extents;
        committed_btree_records_ = disk_loaded_btree_checkpoint_records.empty()
            ? disk_loaded_btree_records
            : disk_loaded_btree_checkpoint_records;
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
        committed_path_index_ = disk_loaded_path_index;
        committed_directory_links_ = disk_loaded_directory_links;
        if (!committed_btree_records_.empty())
        {
            std::unordered_map<std::uint64_t, std::vector<FileExtent>> btree_read_extents;
            if (RebuildReadExtentsFromBtreeRecords(
                    committed_btree_records_,
                    committed_inodes_,
                    btree_read_extents))
            {
                committed_read_extents_ = std::move(btree_read_extents);
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
            const auto path_key = CanonicalPathKey(inode.full_path);
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
        if (!committed_btree_records_.empty())
        {
            std::unordered_map<std::uint64_t, std::vector<FileExtent>> btree_read_extents;
            if (RebuildReadExtentsFromBtreeRecords(
                    committed_btree_records_,
                    committed_inodes_,
                    btree_read_extents))
            {
                committed_read_extents_ = std::move(btree_read_extents);
            }
        }
    }
        if (version >= 4)
        {
            committed_spaceman_free_extents_.reserve(free_extent_count);
            working_spaceman_free_extents_.clear();
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
        committed_spaceman_allocations_ = disk_loaded_allocations;
        committed_spaceman_free_extents_ = disk_loaded_free_extents;
        committed_btree_records_ = disk_loaded_btree_checkpoint_records.empty()
            ? disk_loaded_btree_records
            : disk_loaded_btree_checkpoint_records;
        committed_inodes_ = disk_loaded_inodes;
        committed_path_index_ = disk_loaded_path_index;
        committed_directory_links_ = disk_loaded_directory_links;
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

    std::vector<std::uint64_t> persisted_object_ids;
    persisted_object_ids.reserve(committed_object_map_.size());
    for (const auto& [object_id, entry] : committed_object_map_)
    {
        if (HasPhysicalObjectMapping(entry))
        {
            persisted_object_ids.push_back(object_id);
        }
    }
    std::sort(persisted_object_ids.begin(), persisted_object_ids.end());

    if (!write_raw(kMagic.data(), kMagic.size()) ||
        !write_u32(7) ||
        !write_u32(0, false) ||
        !write_u64(checkpoint_xid_) ||
        !write_u64(last_committed_xid_.value_or(0)) ||
        !write_u64(next_ephemeral_extent_) ||
        !write_u64(commit_blob_address) ||
        !write_u64(commit_blob_bytes) ||
        !write_u32(static_cast<std::uint32_t>(persisted_object_ids.size())) ||
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

    for (const auto object_id : persisted_object_ids)
    {
        const auto entry = committed_object_map_.find(object_id);
        if (entry == committed_object_map_.end())
        {
            output.close();
            std::filesystem::remove(tmp_path, ec);
            return false;
        }
        if (!write_u64(object_id) ||
            !write_u64(entry->second.physical_address) ||
            !write_u64(entry->second.logical_size) ||
            !write_u64(entry->second.xid))
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

std::vector<std::byte> MetadataStore::BuildCommitBlob(std::uint64_t target_xid)
{
    ScopedPerfTimer perf_scope(build_commit_blob_perf_);

    if (!IsNativeWriteReady())
    {
        return {};
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

    std::vector<std::byte> blob;
    blob.reserve(static_cast<std::size_t>(block_size_));

    const auto use_scaffold_blob = ShouldUseScaffoldCommitBlobForCurrentContext();
    uses_scaffold_commit_blob_ = use_scaffold_blob;
    const auto& selected_magic = use_scaffold_blob ? kScaffoldMagicV3 : kCanonicalMagicV3;
    last_commit_blob_magic_ = use_scaffold_blob ? "APFSRWSCAFF3" : "APFSRWCANON3";
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
        return {};
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

    return blob;
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
