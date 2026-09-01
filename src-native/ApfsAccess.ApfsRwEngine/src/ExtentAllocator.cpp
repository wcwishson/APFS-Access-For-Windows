#include "ExtentAllocator.h"

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <limits>
#include <utility>

namespace apfsaccess::rw
{
namespace
{
bool RangeEnd(std::uint64_t physical_address, std::uint64_t bytes, std::uint64_t& end) noexcept
{
    if (physical_address == 0 || bytes == 0 ||
        physical_address > (std::numeric_limits<std::uint64_t>::max() - bytes))
    {
        return false;
    }

    end = physical_address + bytes;
    return true;
}

bool FitsContainer(
    std::uint64_t physical_address,
    std::uint64_t bytes,
    const ExtentAllocator::AllocationPolicy& policy) noexcept
{
    std::uint64_t end = 0;
    if (!RangeEnd(physical_address, bytes, end))
    {
        return false;
    }
    return !policy.container_bytes.has_value() || end <= policy.container_bytes.value();
}

bool OverlapsUnavailable(
    std::uint64_t physical_address,
    std::uint64_t bytes,
    const ExtentAllocator::AllocationPolicy& policy)
{
    return policy.overlaps_unavailable &&
           policy.overlaps_unavailable(policy.context, physical_address, bytes);
}

std::uint64_t AlignBytes(std::uint64_t bytes, std::uint64_t block_size) noexcept
{
    if (bytes == 0 || block_size == 0)
    {
        return 0;
    }

    auto aligned = std::max(bytes, block_size);
    const auto remainder = aligned % block_size;
    if (remainder == 0)
    {
        return aligned;
    }
    if (aligned > (std::numeric_limits<std::uint64_t>::max() - (block_size - remainder)))
    {
        return 0;
    }
    return aligned + (block_size - remainder);
}

bool HasLogicalExtentCoverage(
    const std::vector<ExtentAllocator::FileExtent>& extents,
    std::uint64_t logical_size) noexcept
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

bool IsSortedAndValid(const std::vector<ExtentAllocator::Extent>& extents) noexcept
{
    std::uint64_t previous_end = 0;
    bool have_previous = false;
    for (const auto& extent : extents)
    {
        std::uint64_t extent_end = 0;
        if (!RangeEnd(extent.physical_address, extent.bytes, extent_end))
        {
            return false;
        }
        if (have_previous && extent.physical_address <= previous_end)
        {
            return false;
        }

        previous_end = extent_end;
        have_previous = true;
    }

    return true;
}

bool CoalesceSorted(std::vector<ExtentAllocator::Extent>& extents)
{
    std::vector<ExtentAllocator::Extent> merged;
    merged.reserve(extents.size());

    for (const auto& extent : extents)
    {
        if (extent.physical_address == 0 || extent.bytes == 0)
        {
            continue;
        }

        std::uint64_t extent_end = 0;
        if (!RangeEnd(extent.physical_address, extent.bytes, extent_end))
        {
            return false;
        }

        if (merged.empty())
        {
            merged.push_back(extent);
            continue;
        }

        auto& previous = merged.back();
        std::uint64_t previous_end = 0;
        if (!RangeEnd(previous.physical_address, previous.bytes, previous_end))
        {
            return false;
        }

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

bool IsCleanWholeExtent(
    const ExtentAllocator::Extent& extent,
    const ExtentAllocator::AllocationPolicy& policy)
{
    std::uint64_t extent_end = 0;
    return RangeEnd(extent.physical_address, extent.bytes, extent_end) &&
           FitsContainer(extent.physical_address, extent.bytes, policy) &&
           !OverlapsUnavailable(extent.physical_address, extent.bytes, policy);
}
} // namespace

bool ExtentAllocator::Normalize(std::vector<Extent>& extents)
{
    if (extents.empty())
    {
        return true;
    }

    std::sort(
        extents.begin(),
        extents.end(),
        [](const Extent& lhs, const Extent& rhs)
        {
            if (lhs.physical_address == rhs.physical_address)
            {
                return lhs.bytes < rhs.bytes;
            }
            return lhs.physical_address < rhs.physical_address;
        });

    return CoalesceSorted(extents);
}

bool ExtentAllocator::AddFreeExtent(std::vector<Extent>& free_extents, Extent extent)
{
    return AddFreeExtent(free_extents, extent, nullptr);
}

bool ExtentAllocator::AddFreeExtent(std::vector<Extent>& free_extents, Extent extent, AddFreeExtentUndo* undo)
{
    std::uint64_t extent_end = 0;
    if (!RangeEnd(extent.physical_address, extent.bytes, extent_end))
    {
        return false;
    }

    if (!IsSortedAndValid(free_extents))
    {
        if (undo != nullptr)
        {
            undo->valid = false;
        }
        free_extents.push_back(extent);
        return Normalize(free_extents);
    }

    const auto insertion = std::lower_bound(
        free_extents.begin(),
        free_extents.end(),
        extent.physical_address,
        [](const Extent& candidate, std::uint64_t physical_address)
        {
            return candidate.physical_address < physical_address;
        });

    auto merge_start = extent.physical_address;
    auto merge_end = extent_end;
    auto erase_begin = static_cast<std::size_t>(std::distance(free_extents.begin(), insertion));
    auto erase_end = erase_begin;

    while (erase_begin > 0)
    {
        const auto& previous = free_extents[erase_begin - 1];
        std::uint64_t previous_end = 0;
        if (!RangeEnd(previous.physical_address, previous.bytes, previous_end))
        {
            return false;
        }
        if (previous_end < merge_start)
        {
            break;
        }

        --erase_begin;
        merge_start = previous.physical_address;
        merge_end = std::max(merge_end, previous_end);
    }

    while (erase_end < free_extents.size())
    {
        const auto& candidate = free_extents[erase_end];
        if (candidate.physical_address > merge_end)
        {
            break;
        }

        std::uint64_t candidate_end = 0;
        if (!RangeEnd(candidate.physical_address, candidate.bytes, candidate_end))
        {
            return false;
        }

        merge_end = std::max(merge_end, candidate_end);
        ++erase_end;
    }

    const Extent merged{ merge_start, merge_end - merge_start };
    AddFreeExtentUndo local_undo{};
    if (undo != nullptr)
    {
        local_undo.valid = true;
        local_undo.erase_begin = erase_begin;
        local_undo.erased_count = erase_end - erase_begin;
        local_undo.inserted_without_erasing = erase_begin == erase_end;
        local_undo.erased_extents.reserve(local_undo.erased_count);
        for (auto index = erase_begin; index < erase_end; ++index)
        {
            local_undo.erased_extents.push_back(free_extents[index]);
        }
    }
    if (erase_begin == erase_end)
    {
        free_extents.insert(free_extents.begin() + static_cast<std::ptrdiff_t>(erase_begin), merged);
        if (undo != nullptr)
        {
            *undo = std::move(local_undo);
        }
        return true;
    }

    auto replacement = free_extents.begin() + static_cast<std::ptrdiff_t>(erase_begin);
    *replacement = merged;
    free_extents.erase(
        replacement + 1,
        free_extents.begin() + static_cast<std::ptrdiff_t>(erase_end));
    if (undo != nullptr)
    {
        *undo = std::move(local_undo);
    }
    return true;
}

bool ExtentAllocator::RollbackAddFreeExtent(std::vector<Extent>& free_extents, const AddFreeExtentUndo& undo)
{
    if (!undo.valid)
    {
        return false;
    }

    if (undo.erase_begin >= free_extents.size())
    {
        return false;
    }
    free_extents.erase(free_extents.begin() + static_cast<std::ptrdiff_t>(undo.erase_begin));
    if (!undo.erased_extents.empty())
    {
        free_extents.insert(
            free_extents.begin() + static_cast<std::ptrdiff_t>(std::min(undo.erase_begin, free_extents.size())),
            undo.erased_extents.begin(),
            undo.erased_extents.end());
    }

    return IsSortedAndValid(free_extents);
}

bool ExtentAllocator::RemoveAllocatedExtent(std::vector<Extent>& free_extents, Extent extent)
{
    std::uint64_t extent_end = 0;
    if (!RangeEnd(extent.physical_address, extent.bytes, extent_end))
    {
        return false;
    }

    if (!IsSortedAndValid(free_extents))
    {
        if (!Normalize(free_extents))
        {
            return false;
        }
    }

    std::vector<Extent> adjusted;
    adjusted.reserve(free_extents.size() + 1);
    for (const auto& free_extent : free_extents)
    {
        std::uint64_t free_end = 0;
        if (!RangeEnd(free_extent.physical_address, free_extent.bytes, free_end))
        {
            return false;
        }

        if (free_end <= extent.physical_address ||
            extent_end <= free_extent.physical_address)
        {
            adjusted.push_back(free_extent);
            continue;
        }

        if (free_extent.physical_address < extent.physical_address)
        {
            adjusted.push_back(
                {
                    free_extent.physical_address,
                    extent.physical_address - free_extent.physical_address,
                });
        }
        if (extent_end < free_end)
        {
            adjusted.push_back(
                {
                    extent_end,
                    free_end - extent_end,
                });
        }
    }

    free_extents = std::move(adjusted);
    return true;
}

bool ExtentAllocator::RemoveAllocatedExtents(
    std::vector<Extent>& free_extents,
    const std::vector<Extent>& extents)
{
    if (free_extents.empty() || extents.empty())
    {
        return true;
    }

    if (!IsSortedAndValid(free_extents) &&
        !Normalize(free_extents))
    {
        return false;
    }

    auto removals = extents;
    if (!Normalize(removals))
    {
        return false;
    }
    if (removals.empty())
    {
        return true;
    }

    std::vector<Extent> adjusted;
    adjusted.reserve(free_extents.size());
    auto removal_it = removals.begin();
    for (const auto& free_extent : free_extents)
    {
        std::uint64_t free_end = 0;
        if (!RangeEnd(free_extent.physical_address, free_extent.bytes, free_end))
        {
            return false;
        }

        while (removal_it != removals.end())
        {
            std::uint64_t removal_end = 0;
            if (!RangeEnd(removal_it->physical_address, removal_it->bytes, removal_end))
            {
                return false;
            }
            if (removal_end > free_extent.physical_address)
            {
                break;
            }
            ++removal_it;
        }

        auto cursor = free_extent.physical_address;
        for (auto it = removal_it; it != removals.end(); ++it)
        {
            std::uint64_t removal_end = 0;
            if (!RangeEnd(it->physical_address, it->bytes, removal_end))
            {
                return false;
            }
            if (it->physical_address >= free_end)
            {
                break;
            }
            if (it->physical_address > cursor)
            {
                adjusted.push_back({ cursor, it->physical_address - cursor });
            }
            cursor = std::max(cursor, std::min(removal_end, free_end));
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

    free_extents = std::move(adjusted);
    return IsSortedAndValid(free_extents);
}

std::optional<std::uint64_t> ExtentAllocator::AllocateContiguousFromFree(
    std::vector<Extent>& free_extents,
    std::uint64_t bytes,
    const AllocationPolicy& policy,
    ContiguousAllocationUndo* undo)
{
    if (bytes == 0)
    {
        return std::nullopt;
    }

    for (auto it = free_extents.begin(); it != free_extents.end(); ++it)
    {
        if (it->bytes < bytes)
        {
            continue;
        }

        std::uint64_t extent_end = 0;
        if (!RangeEnd(it->physical_address, it->bytes, extent_end))
        {
            continue;
        }

        auto allocation_address = it->physical_address;
        if (allocation_address > (std::numeric_limits<std::uint64_t>::max() - bytes))
        {
            continue;
        }

        if (!FitsContainer(allocation_address, bytes, policy))
        {
            continue;
        }

        const auto free_extent_index =
            static_cast<std::size_t>(std::distance(free_extents.begin(), it));
        const auto previous_free_extent = *it;
        if (OverlapsUnavailable(allocation_address, bytes, policy))
        {
            if (!policy.advance_past_unavailable)
            {
                continue;
            }

            const auto advanced = policy.advance_past_unavailable(policy.context, allocation_address, bytes);
            if (!advanced.has_value() ||
                advanced.value() < allocation_address ||
                advanced.value() > extent_end ||
                advanced.value() > (std::numeric_limits<std::uint64_t>::max() - bytes) ||
                (advanced.value() + bytes) > extent_end)
            {
                continue;
            }

            allocation_address = advanced.value();
            it->physical_address = allocation_address;
            it->bytes = extent_end - allocation_address;

            if (!FitsContainer(allocation_address, bytes, policy))
            {
                continue;
            }
        }

        const auto allocation_end = allocation_address + bytes;
        it->physical_address = allocation_end;
        it->bytes = extent_end - allocation_end;
        const auto free_extent_erased = it->bytes == 0;
        if (it->bytes == 0)
        {
            free_extents.erase(it);
        }
        if (undo != nullptr)
        {
            undo->source = ContiguousAllocationUndo::Source::FreeExtent;
            undo->free_extent_index = free_extent_index;
            undo->previous_free_extent = previous_free_extent;
            undo->free_extent_erased = free_extent_erased;
            undo->previous_next_ephemeral_extent = 0;
            undo->previous_ephemeral_free_extents.clear();
        }
        return allocation_address;
    }

    return std::nullopt;
}

std::optional<std::uint64_t> ExtentAllocator::AllocateContiguous(
    std::vector<Extent>& free_extents,
    std::uint64_t& next_ephemeral_extent,
    std::uint64_t bytes,
    const AllocationPolicy& policy,
    ContiguousAllocationUndo* undo)
{
    auto from_free = AllocateContiguousFromFree(free_extents, bytes, policy, undo);
    if (from_free.has_value())
    {
        return from_free;
    }

    auto current = next_ephemeral_extent;
    if (current == 0 || current > (std::numeric_limits<std::uint64_t>::max() - bytes))
    {
        return std::nullopt;
    }

    if (OverlapsUnavailable(current, bytes, policy))
    {
        if (!policy.advance_past_unavailable)
        {
            return std::nullopt;
        }

        const auto advanced = policy.advance_past_unavailable(policy.context, current, bytes);
        if (!advanced.has_value() || advanced.value() < current)
        {
            return std::nullopt;
        }
        current = advanced.value();
        if (current == 0 || current > (std::numeric_limits<std::uint64_t>::max() - bytes))
        {
            return std::nullopt;
        }
    }

    if (!FitsContainer(current, bytes, policy))
    {
        return std::nullopt;
    }

    auto previous_free_extents = free_extents;
    if (!RemoveAllocatedExtent(free_extents, Extent{ current, bytes }))
    {
        free_extents = std::move(previous_free_extents);
        return std::nullopt;
    }

    const auto previous_next_ephemeral_extent = next_ephemeral_extent;
    next_ephemeral_extent = current + bytes;
    if (undo != nullptr)
    {
        undo->source = ContiguousAllocationUndo::Source::EphemeralTail;
        undo->free_extent_index = 0;
        undo->previous_free_extent = {};
        undo->free_extent_erased = false;
        undo->previous_next_ephemeral_extent = previous_next_ephemeral_extent;
        undo->previous_ephemeral_free_extents = std::move(previous_free_extents);
    }
    return current;
}

bool ExtentAllocator::RollbackContiguousAllocation(
    std::vector<Extent>& free_extents,
    std::uint64_t& next_ephemeral_extent,
    const ContiguousAllocationUndo& undo)
{
    switch (undo.source)
    {
    case ContiguousAllocationUndo::Source::FreeExtent:
        if (undo.free_extent_erased)
        {
            const auto insert_index = std::min(undo.free_extent_index, free_extents.size());
            free_extents.insert(
                free_extents.begin() + static_cast<std::ptrdiff_t>(insert_index),
                undo.previous_free_extent);
        }
        else if (undo.free_extent_index < free_extents.size())
        {
            free_extents[undo.free_extent_index] = undo.previous_free_extent;
        }
        else
        {
            return false;
        }
        return IsSortedAndValid(free_extents);
    case ContiguousAllocationUndo::Source::EphemeralTail:
        free_extents = undo.previous_ephemeral_free_extents;
        next_ephemeral_extent = undo.previous_next_ephemeral_extent;
        return IsSortedAndValid(free_extents);
    case ContiguousAllocationUndo::Source::None:
    default:
        return false;
    }
}

bool ExtentAllocator::CanAllocateFromFragmentedFreeExtents(
    const std::vector<Extent>& free_extents,
    std::uint64_t aligned_total,
    const AllocationPolicy& policy)
{
    if (aligned_total == 0)
    {
        return false;
    }

    std::uint64_t available_fragmented_bytes = 0;
    for (const auto& extent : free_extents)
    {
        if (!IsCleanWholeExtent(extent, policy))
        {
            continue;
        }
        if (available_fragmented_bytes > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
        {
            return false;
        }
        available_fragmented_bytes += extent.bytes;
        if (available_fragmented_bytes >= aligned_total)
        {
            return true;
        }
    }

    return false;
}

std::optional<std::vector<ExtentAllocator::FileExtent>> ExtentAllocator::AllocateFileExtents(
    std::vector<Extent>& free_extents,
    std::uint64_t& next_ephemeral_extent,
    std::uint64_t logical_size,
    std::uint64_t aligned_total,
    std::uint64_t block_size,
    const AllocationPolicy& policy)
{
    if (logical_size == 0)
    {
        return std::vector<FileExtent>{};
    }
    if (aligned_total == 0 || block_size == 0)
    {
        return std::nullopt;
    }

    AllocationPolicy clean_prefix_policy = policy;
    clean_prefix_policy.advance_past_unavailable = {};
    auto contiguous = AllocateContiguousFromFree(free_extents, aligned_total, clean_prefix_policy);
    if (contiguous.has_value())
    {
        return std::vector<FileExtent>{ FileExtent{ 0, contiguous.value(), logical_size } };
    }

    std::vector<Extent> staged_free_extents;
    staged_free_extents.reserve(free_extents.size());
    std::vector<FileExtent> file_extents;
    file_extents.reserve(free_extents.size());
    std::uint64_t remaining_logical = logical_size;
    std::uint64_t logical_offset = 0;
    for (const auto& extent : free_extents)
    {
        if (remaining_logical == 0 || !IsCleanWholeExtent(extent, policy))
        {
            staged_free_extents.push_back(extent);
            continue;
        }

        const auto remaining_aligned = AlignBytes(remaining_logical, block_size);
        if (remaining_aligned == 0)
        {
            return std::nullopt;
        }

        const auto allocation_bytes = std::min(extent.bytes, remaining_aligned);
        const auto logical_bytes = std::min(remaining_logical, allocation_bytes);
        if (logical_bytes == 0 ||
            extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - allocation_bytes))
        {
            return std::nullopt;
        }

        file_extents.push_back(FileExtent{ logical_offset, extent.physical_address, logical_bytes });
        logical_offset += logical_bytes;
        remaining_logical -= logical_bytes;

        if (allocation_bytes < extent.bytes)
        {
            staged_free_extents.push_back(
                {
                    extent.physical_address + allocation_bytes,
                    extent.bytes - allocation_bytes,
                });
        }
    }

    if (remaining_logical == 0 && HasLogicalExtentCoverage(file_extents, logical_size))
    {
        free_extents = std::move(staged_free_extents);
        return file_extents;
    }

    auto fallback = AllocateContiguous(free_extents, next_ephemeral_extent, aligned_total, policy);
    if (!fallback.has_value())
    {
        return std::nullopt;
    }

    return std::vector<FileExtent>{ FileExtent{ 0, fallback.value(), logical_size } };
}
} // namespace apfsaccess::rw
