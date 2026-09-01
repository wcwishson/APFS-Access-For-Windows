#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>
#include <vector>

namespace apfsaccess::rw
{
class ExtentAllocator
{
public:
    struct Extent
    {
        std::uint64_t physical_address = 0;
        std::uint64_t bytes = 0;

        friend bool operator==(const Extent&, const Extent&) = default;
    };

    struct FileExtent
    {
        std::uint64_t logical_offset = 0;
        std::uint64_t physical_address = 0;
        std::uint64_t bytes = 0;

        friend bool operator==(const FileExtent&, const FileExtent&) = default;
    };

    struct AllocationPolicy
    {
        using OverlapsUnavailableFn = bool (*)(const void* context, std::uint64_t physical_address, std::uint64_t bytes);
        using AdvancePastUnavailableFn = std::optional<std::uint64_t> (*)(
            const void* context,
            std::uint64_t physical_address,
            std::uint64_t bytes);

        std::optional<std::uint64_t> container_bytes;
        const void* context = nullptr;
        OverlapsUnavailableFn overlaps_unavailable = nullptr;
        AdvancePastUnavailableFn advance_past_unavailable = nullptr;
    };

    struct ContiguousAllocationUndo
    {
        enum class Source
        {
            None,
            FreeExtent,
            EphemeralTail,
        };

        Source source = Source::None;
        std::size_t free_extent_index = 0;
        Extent previous_free_extent{};
        bool free_extent_erased = false;
        std::uint64_t previous_next_ephemeral_extent = 0;
        std::vector<Extent> previous_ephemeral_free_extents;
    };

    struct AddFreeExtentUndo
    {
        bool valid = false;
        std::size_t erase_begin = 0;
        std::size_t erased_count = 0;
        std::vector<Extent> erased_extents;
        bool inserted_without_erasing = false;
    };

    [[nodiscard]] static bool Normalize(std::vector<Extent>& extents);
    [[nodiscard]] static bool AddFreeExtent(std::vector<Extent>& free_extents, Extent extent);
    [[nodiscard]] static bool AddFreeExtent(
        std::vector<Extent>& free_extents,
        Extent extent,
        AddFreeExtentUndo* undo);
    [[nodiscard]] static bool RollbackAddFreeExtent(std::vector<Extent>& free_extents, const AddFreeExtentUndo& undo);
    [[nodiscard]] static bool RemoveAllocatedExtent(std::vector<Extent>& free_extents, Extent extent);
    [[nodiscard]] static bool RemoveAllocatedExtents(
        std::vector<Extent>& free_extents,
        const std::vector<Extent>& extents);

    [[nodiscard]] static std::optional<std::uint64_t> AllocateContiguousFromFree(
        std::vector<Extent>& free_extents,
        std::uint64_t bytes,
        const AllocationPolicy& policy,
        ContiguousAllocationUndo* undo = nullptr);

    [[nodiscard]] static std::optional<std::uint64_t> AllocateContiguous(
        std::vector<Extent>& free_extents,
        std::uint64_t& next_ephemeral_extent,
        std::uint64_t bytes,
        const AllocationPolicy& policy,
        ContiguousAllocationUndo* undo = nullptr);
    [[nodiscard]] static bool RollbackContiguousAllocation(
        std::vector<Extent>& free_extents,
        std::uint64_t& next_ephemeral_extent,
        const ContiguousAllocationUndo& undo);
    [[nodiscard]] static bool CanAllocateFromFragmentedFreeExtents(
        const std::vector<Extent>& free_extents,
        std::uint64_t aligned_total,
        const AllocationPolicy& policy);

    [[nodiscard]] static std::optional<std::vector<FileExtent>> AllocateFileExtents(
        std::vector<Extent>& free_extents,
        std::uint64_t& next_ephemeral_extent,
        std::uint64_t logical_size,
        std::uint64_t aligned_total,
        std::uint64_t block_size,
        const AllocationPolicy& policy);
};
} // namespace apfsaccess::rw
