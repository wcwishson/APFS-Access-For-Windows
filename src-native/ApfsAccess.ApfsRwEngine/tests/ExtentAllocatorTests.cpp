#include "ExtentAllocator.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string_view>
#include <vector>

namespace
{
using apfsaccess::rw::ExtentAllocator;

bool Require(bool condition, const char* message)
{
    if (!condition)
    {
        std::cerr << "[FAIL] " << message << std::endl;
        return false;
    }
    return true;
}

ExtentAllocator::AllocationPolicy BasicPolicy(std::optional<std::uint64_t> container_bytes = std::nullopt)
{
    return ExtentAllocator::AllocationPolicy
    {
        container_bytes,
        nullptr,
        nullptr,
        nullptr,
    };
}

bool TestNormalizeMergesOverlappingAndAdjacentExtents()
{
    std::vector<ExtentAllocator::Extent> free_extents
    {
        { 4096, 4096 },
        { 12288, 4096 },
        { 8192, 4096 },
        { 32768, 4096 },
        { 0, 4096 },
    };

    const auto ok = ExtentAllocator::Normalize(free_extents);

    return Require(ok, "normalize should succeed") &&
           Require(free_extents.size() == 2, "normalize should merge adjacent extents") &&
           Require(free_extents[0] == ExtentAllocator::Extent{ 4096, 12288 }, "first merged extent should cover contiguous run") &&
           Require(free_extents[1] == ExtentAllocator::Extent{ 32768, 4096 }, "second extent should remain separate");
}

bool TestAddFreeExtentKeepsSortedCoalescedList()
{
    std::vector<ExtentAllocator::Extent> free_extents
    {
        { 4096, 4096 },
        { 16384, 4096 },
    };

    bool ok = ExtentAllocator::AddFreeExtent(free_extents, { 8192, 8192 });

    return Require(ok, "add free extent should succeed") &&
           Require(free_extents.size() == 1, "add should coalesce neighboring extents") &&
           Require(free_extents[0] == ExtentAllocator::Extent{ 4096, 16384 }, "coalesced extent should cover full range");
}

bool TestAddFreeExtentMergesLeftNeighborOnly()
{
    std::vector<ExtentAllocator::Extent> free_extents
    {
        { 4096, 4096 },
        { 16384, 4096 },
    };

    const auto ok = ExtentAllocator::AddFreeExtent(free_extents, { 8192, 4096 });

    return Require(ok, "left merge add should succeed") &&
           Require(free_extents.size() == 2, "left merge should keep unrelated right extent") &&
           Require(free_extents[0] == ExtentAllocator::Extent{ 4096, 8192 }, "left merge should extend previous extent") &&
           Require(free_extents[1] == ExtentAllocator::Extent{ 16384, 4096 }, "right extent should stay unchanged");
}

bool TestAddFreeExtentMergesRightNeighborOnly()
{
    std::vector<ExtentAllocator::Extent> free_extents
    {
        { 4096, 4096 },
        { 16384, 4096 },
    };

    const auto ok = ExtentAllocator::AddFreeExtent(free_extents, { 12288, 4096 });

    return Require(ok, "right merge add should succeed") &&
           Require(free_extents.size() == 2, "right merge should keep unrelated left extent") &&
           Require(free_extents[0] == ExtentAllocator::Extent{ 4096, 4096 }, "left extent should stay unchanged") &&
           Require(free_extents[1] == ExtentAllocator::Extent{ 12288, 8192 }, "right merge should extend next extent");
}

bool TestAddFreeExtentInsertsMiddleWithoutMerging()
{
    std::vector<ExtentAllocator::Extent> free_extents
    {
        { 4096, 4096 },
        { 20480, 4096 },
    };

    const auto ok = ExtentAllocator::AddFreeExtent(free_extents, { 12288, 4096 });

    return Require(ok, "middle add should succeed") &&
           Require(free_extents.size() == 3, "middle add should insert without merging") &&
           Require(free_extents[0] == ExtentAllocator::Extent{ 4096, 4096 }, "first extent should stay unchanged") &&
           Require(free_extents[1] == ExtentAllocator::Extent{ 12288, 4096 }, "new extent should be inserted in order") &&
           Require(free_extents[2] == ExtentAllocator::Extent{ 20480, 4096 }, "last extent should stay unchanged");
}

bool TestAddFreeExtentFallsBackForUnsortedList()
{
    std::vector<ExtentAllocator::Extent> free_extents
    {
        { 16384, 4096 },
        { 4096, 4096 },
    };

    const auto ok = ExtentAllocator::AddFreeExtent(free_extents, { 8192, 8192 });

    return Require(ok, "unsorted fallback add should succeed") &&
           Require(free_extents.size() == 1, "unsorted fallback should normalize and merge") &&
           Require(free_extents[0] == ExtentAllocator::Extent{ 4096, 16384 }, "unsorted fallback should cover full range");
}

bool TestAddFreeExtentUndoRestoresCoalescedWindow()
{
    std::vector<ExtentAllocator::Extent> free_extents
    {
        { 4096, 4096 },
        { 16384, 4096 },
        { 32768, 4096 },
    };
    const auto original_free_extents = free_extents;
    ExtentAllocator::AddFreeExtentUndo undo{};

    bool ok = ExtentAllocator::AddFreeExtent(free_extents, { 8192, 8192 }, &undo);
    ok &= Require(free_extents.size() == 2, "undo add setup should merge the first two extents");
    ok &= Require(ExtentAllocator::RollbackAddFreeExtent(free_extents, undo), "undo add rollback should succeed");

    return Require(ok, "undo add should succeed") &&
           Require(free_extents == original_free_extents, "undo add rollback should restore exact free list");
}

bool TestRemoveAllocatedExtentSplitsFreeRun()
{
    std::vector<ExtentAllocator::Extent> free_extents
    {
        { 4096, 16384 },
        { 32768, 4096 },
    };

    const auto ok = ExtentAllocator::RemoveAllocatedExtent(free_extents, { 8192, 4096 });

    return Require(ok, "remove allocated extent should succeed") &&
           Require(free_extents.size() == 3, "remove should split containing free run") &&
           Require(free_extents[0] == ExtentAllocator::Extent{ 4096, 4096 }, "left remainder should stay free") &&
           Require(free_extents[1] == ExtentAllocator::Extent{ 12288, 8192 }, "right remainder should stay free") &&
           Require(free_extents[2] == ExtentAllocator::Extent{ 32768, 4096 }, "unrelated free extent should stay unchanged");
}

bool TestRemoveAllocatedExtentsSubtractsBatchInOnePass()
{
    std::vector<ExtentAllocator::Extent> free_extents
    {
        { 4096, 16384 },
        { 32768, 16384 },
        { 49152, 8192 },
    };

    const std::vector<ExtentAllocator::Extent> allocations
    {
        { 8192, 4096 },
        { 12288, 4096 },
        { 36864, 8192 },
        { 98304, 4096 },
    };

    const auto ok = ExtentAllocator::RemoveAllocatedExtents(free_extents, allocations);

    return Require(ok, "batch remove allocated extents should succeed") &&
           Require(free_extents.size() == 4, "batch remove should keep all remaining free runs") &&
           Require(free_extents[0] == ExtentAllocator::Extent{ 4096, 4096 }, "batch remove should keep left remainder") &&
           Require(free_extents[1] == ExtentAllocator::Extent{ 16384, 4096 }, "batch remove should keep right remainder") &&
           Require(free_extents[2] == ExtentAllocator::Extent{ 32768, 4096 }, "batch remove should keep second-run prefix") &&
           Require(free_extents[3] == ExtentAllocator::Extent{ 45056, 12288 }, "batch remove should merge second-run suffix with adjacent third run");
}

bool TestRemoveAllocatedExtentsPreservesCanonicalOutputWithoutFinalNormalize()
{
    std::vector<ExtentAllocator::Extent> free_extents
    {
        { 4096, 32768 },
    };

    const std::vector<ExtentAllocator::Extent> allocations
    {
        { 8192, 4096 },
        { 12288, 4096 },
        { 16384, 4096 },
    };

    const auto ok = ExtentAllocator::RemoveAllocatedExtents(free_extents, allocations);

    return Require(ok, "batch remove adjacent allocated extents should succeed") &&
           Require(free_extents.size() == 2, "batch remove should not leave adjacent fragments requiring normalization") &&
           Require(free_extents[0] == ExtentAllocator::Extent{ 4096, 4096 }, "batch remove should keep prefix run") &&
           Require(free_extents[1] == ExtentAllocator::Extent{ 20480, 16384 }, "batch remove should keep suffix run");
}

bool TestAllocateContiguousSkipsUnavailableRangeInsideFreeExtent()
{
    std::vector<ExtentAllocator::Extent> free_extents
    {
        { 4096, 32768 },
    };
    auto policy = BasicPolicy();
    policy.overlaps_unavailable = [](const void*, std::uint64_t physical_address, std::uint64_t bytes)
    {
        const auto end = physical_address + bytes;
        return physical_address < 12288 && 8192 < end;
    };
    policy.advance_past_unavailable = [](const void*, std::uint64_t, std::uint64_t)
        -> std::optional<std::uint64_t>
    {
        return 12288;
    };

    const auto allocation = ExtentAllocator::AllocateContiguousFromFree(free_extents, 8192, policy);

    return Require(allocation.has_value(), "allocation should succeed after unavailable range") &&
           Require(allocation.value() == 12288, "allocation should start after unavailable range") &&
           Require(free_extents.size() == 1, "free list should keep trailing remainder") &&
           Require(free_extents[0] == ExtentAllocator::Extent{ 20480, 16384 }, "free list should consume skipped and allocated bytes");
}

bool TestAllocateContiguousUndoRestoresUnavailableTrim()
{
    std::vector<ExtentAllocator::Extent> free_extents
    {
        { 4096, 32768 },
    };
    const auto original_free_extents = free_extents;
    auto policy = BasicPolicy();
    policy.overlaps_unavailable = [](const void*, std::uint64_t physical_address, std::uint64_t bytes)
    {
        const auto end = physical_address + bytes;
        return physical_address < 12288 && 8192 < end;
    };
    policy.advance_past_unavailable = [](const void*, std::uint64_t, std::uint64_t)
        -> std::optional<std::uint64_t>
    {
        return 12288;
    };
    ExtentAllocator::ContiguousAllocationUndo undo{};

    const auto allocation = ExtentAllocator::AllocateContiguousFromFree(free_extents, 8192, policy, &undo);
    bool ok = Require(allocation.has_value(), "undo allocation should succeed after unavailable range");
    ok &= Require(allocation.value() == 12288, "undo allocation should start after unavailable range");
    if (undo.source == ExtentAllocator::ContiguousAllocationUndo::Source::FreeExtent)
    {
        if (undo.free_extent_erased)
        {
            free_extents.insert(
                free_extents.begin() + static_cast<std::ptrdiff_t>(std::min(undo.free_extent_index, free_extents.size())),
                undo.previous_free_extent);
        }
        else if (undo.free_extent_index < free_extents.size())
        {
            free_extents[undo.free_extent_index] = undo.previous_free_extent;
        }
        else
        {
            ok = false;
        }
    }
    else
    {
        ok = false;
    }

    return Require(ok, "undo allocation rollback should be applicable") &&
           Require(free_extents == original_free_extents, "undo allocation should restore skipped prefix and free tail");
}

bool TestAllocateContiguousFallsBackToEphemeralCursor()
{
    std::vector<ExtentAllocator::Extent> free_extents;
    std::uint64_t next_ephemeral = 4096;
    auto policy = BasicPolicy(32768);
    policy.overlaps_unavailable = [](const void*, std::uint64_t physical_address, std::uint64_t)
    {
        return physical_address == 4096;
    };
    policy.advance_past_unavailable = [](const void*, std::uint64_t, std::uint64_t)
        -> std::optional<std::uint64_t>
    {
        return 8192;
    };

    const auto allocation = ExtentAllocator::AllocateContiguous(free_extents, next_ephemeral, 4096, policy);

    return Require(allocation.has_value(), "ephemeral allocation should succeed") &&
           Require(allocation.value() == 8192, "ephemeral allocation should advance past unavailable range") &&
           Require(next_ephemeral == 12288, "ephemeral cursor should advance by allocation size");
}

bool TestEphemeralContiguousAllocationRollbackRestoresFreeLedger()
{
    std::vector<ExtentAllocator::Extent> free_extents
    {
        { 4096, 4096 },
        { 16384, 4096 },
    };
    const auto original_free_extents = free_extents;
    std::uint64_t next_ephemeral = 4096;
    ExtentAllocator::ContiguousAllocationUndo undo{};

    const auto allocation = ExtentAllocator::AllocateContiguous(
        free_extents,
        next_ephemeral,
        12288,
        BasicPolicy(32768),
        &undo);

    return Require(allocation.has_value(), "ephemeral undo allocation should succeed") &&
           Require(allocation.value() == 4096, "ephemeral undo allocation should use the cursor range") &&
           Require(free_extents == std::vector<ExtentAllocator::Extent>{ { 16384, 4096 } }, "ephemeral undo allocation should be removed from the free ledger") &&
           Require(ExtentAllocator::RollbackContiguousAllocation(free_extents, next_ephemeral, undo), "ephemeral allocation rollback should succeed") &&
           Require(free_extents == original_free_extents, "ephemeral allocation rollback should restore the free ledger") &&
           Require(next_ephemeral == 4096, "ephemeral allocation rollback should restore the cursor");
}

bool TestAllocateFileExtentsUsesFragmentedFreeSpaceBeforeEphemeral()
{
    std::vector<ExtentAllocator::Extent> free_extents
    {
        { 4096, 4096 },
        { 16384, 4096 },
    };
    std::uint64_t next_ephemeral = 65536;

    const auto file_extents = ExtentAllocator::AllocateFileExtents(
        free_extents,
        next_ephemeral,
        8192,
        8192,
        4096,
        BasicPolicy());

    return Require(file_extents.has_value(), "fragmented file allocation should succeed") &&
           Require(file_extents->size() == 2, "fragmented file allocation should use two extents") &&
           Require((*file_extents)[0] == ExtentAllocator::FileExtent{ 0, 4096, 4096 }, "first file extent should use first free run") &&
           Require((*file_extents)[1] == ExtentAllocator::FileExtent{ 4096, 16384, 4096 }, "second file extent should use second free run") &&
           Require(free_extents.empty(), "fragmented allocation should consume free runs") &&
           Require(next_ephemeral == 65536, "fragmented allocation should not advance ephemeral cursor");
}

bool TestAllocateFileExtentsRollsBackOnInvalidFragmentedCoverage()
{
    std::vector<ExtentAllocator::Extent> free_extents
    {
        { 4096, 4096 },
        { 16384, 4096 },
    };
    const auto original_free_extents = free_extents;
    std::uint64_t next_ephemeral = 65536;

    const auto file_extents = ExtentAllocator::AllocateFileExtents(
        free_extents,
        next_ephemeral,
        8192,
        8192,
        0,
        BasicPolicy());

    return Require(!file_extents.has_value(), "invalid block size should fail") &&
           Require(free_extents == original_free_extents, "failed fragmented allocation should restore free list") &&
           Require(next_ephemeral == 65536, "failed fragmented allocation should not advance ephemeral cursor");
}

bool TestEphemeralFileAllocationIsRemovedFromFreeLedger()
{
    constexpr std::uint64_t kFailureFreeExtentAddress = 24658288640ull;
    constexpr std::uint64_t kAllocationBytes = 1024ull * 1024ull * 1024ull;
    constexpr std::uint64_t kLedgerExtentBytes = 64ull * 1024ull * 1024ull;
    std::vector<ExtentAllocator::Extent> free_extents
    {
        { kFailureFreeExtentAddress, kLedgerExtentBytes },
        { kFailureFreeExtentAddress + (2ull * kAllocationBytes), kLedgerExtentBytes },
    };
    std::uint64_t next_ephemeral = kFailureFreeExtentAddress;

    const auto file_extents = ExtentAllocator::AllocateFileExtents(
        free_extents,
        next_ephemeral,
        kAllocationBytes,
        kAllocationBytes,
        4096,
        BasicPolicy(128ull * kAllocationBytes));

    return Require(file_extents.has_value(), "ephemeral file allocation should succeed") &&
           Require(file_extents->size() == 1, "ephemeral file allocation should remain contiguous") &&
           Require((*file_extents)[0] == ExtentAllocator::FileExtent{ 0, kFailureFreeExtentAddress, kAllocationBytes }, "ephemeral file allocation should use the cursor range") &&
           Require(free_extents == std::vector<ExtentAllocator::Extent>{ { kFailureFreeExtentAddress + (2ull * kAllocationBytes), kLedgerExtentBytes } }, "ephemeral file allocation should be removed from the free ledger") &&
           Require(next_ephemeral == kFailureFreeExtentAddress + kAllocationBytes, "ephemeral cursor should advance past the file allocation");
}

template <typename Work>
void ReportBenchmark(const char* workload, std::size_t operations, Work&& work)
{
    const auto started = std::chrono::steady_clock::now();
    work();
    const auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - started).count();
    const auto operations_per_second = elapsed_us > 0
        ? static_cast<double>(operations) * 1000000.0 / static_cast<double>(elapsed_us)
        : 0.0;
    std::cout << std::fixed << std::setprecision(3)
              << "[BENCH] {\"kind\":\"extent-allocator\",\"workload\":\""
              << workload
              << "\",\"operations\":" << operations
              << ",\"elapsedUs\":" << elapsed_us
              << ",\"operationsPerSecond\":" << operations_per_second
              << "}" << std::endl;
}

bool RunAllocatorBenchmarks()
{
    constexpr std::uint64_t block_size = 4096;
    constexpr std::size_t extent_count = 100000;
    constexpr std::size_t operation_count = 1000;
    const auto policy = BasicPolicy();
    bool ok = true;

    std::vector<ExtentAllocator::Extent> sequential_free
    {
        { block_size, static_cast<std::uint64_t>(operation_count + 1) * block_size },
    };
    ReportBenchmark("sequential-growth", operation_count, [&]()
    {
        for (std::size_t index = 0; index < operation_count; ++index)
        {
            if (!ExtentAllocator::AllocateContiguousFromFree(sequential_free, block_size, policy).has_value())
            {
                ok = false;
                return;
            }
        }
    });

    std::vector<ExtentAllocator::Extent> small_file_free;
    small_file_free.reserve(extent_count);
    for (std::size_t index = 0; index < extent_count; ++index)
    {
        small_file_free.push_back({
            block_size + static_cast<std::uint64_t>(index) * block_size * 2,
            block_size,
        });
    }
    ReportBenchmark("many-small-files", operation_count, [&]()
    {
        for (std::size_t index = 0; index < operation_count; ++index)
        {
            if (!ExtentAllocator::AllocateContiguousFromFree(small_file_free, block_size, policy).has_value())
            {
                ok = false;
                return;
            }
        }
    });

    std::vector<ExtentAllocator::Extent> fragmented_free;
    fragmented_free.reserve(extent_count);
    for (std::size_t index = 0; index < extent_count; ++index)
    {
        fragmented_free.push_back({
            block_size + static_cast<std::uint64_t>(index) * block_size * 2,
            block_size,
        });
    }
    std::uint64_t next_ephemeral =
        block_size + static_cast<std::uint64_t>(extent_count) * block_size * 2;
    ReportBenchmark("fragmented-contiguous-miss", operation_count, [&]()
    {
        for (std::size_t index = 0; index < operation_count; ++index)
        {
            if (!ExtentAllocator::AllocateContiguous(
                    fragmented_free,
                    next_ephemeral,
                    block_size * 2,
                    policy).has_value())
            {
                ok = false;
                return;
            }
        }
    });

    return Require(ok, "allocator benchmark workloads should complete");
}
} // namespace

int main(int argc, char** argv)
{
    if (argc == 2 && std::string_view(argv[1]) == "--benchmark")
    {
        return RunAllocatorBenchmarks() ? 0 : 1;
    }

    bool ok = true;
    ok &= TestNormalizeMergesOverlappingAndAdjacentExtents();
    ok &= TestAddFreeExtentKeepsSortedCoalescedList();
    ok &= TestAddFreeExtentMergesLeftNeighborOnly();
    ok &= TestAddFreeExtentMergesRightNeighborOnly();
    ok &= TestAddFreeExtentInsertsMiddleWithoutMerging();
    ok &= TestAddFreeExtentFallsBackForUnsortedList();
    ok &= TestAddFreeExtentUndoRestoresCoalescedWindow();
    ok &= TestRemoveAllocatedExtentSplitsFreeRun();
    ok &= TestRemoveAllocatedExtentsSubtractsBatchInOnePass();
    ok &= TestRemoveAllocatedExtentsPreservesCanonicalOutputWithoutFinalNormalize();
    ok &= TestAllocateContiguousSkipsUnavailableRangeInsideFreeExtent();
    ok &= TestAllocateContiguousUndoRestoresUnavailableTrim();
    ok &= TestAllocateContiguousFallsBackToEphemeralCursor();
    ok &= TestEphemeralContiguousAllocationRollbackRestoresFreeLedger();
    ok &= TestAllocateFileExtentsUsesFragmentedFreeSpaceBeforeEphemeral();
    ok &= TestAllocateFileExtentsRollsBackOnInvalidFragmentedCoverage();
    ok &= TestEphemeralFileAllocationIsRemovedFromFreeLedger();

    if (!ok)
    {
        return 1;
    }

    std::cout << "ExtentAllocatorTests passed" << std::endl;
    return 0;
}
