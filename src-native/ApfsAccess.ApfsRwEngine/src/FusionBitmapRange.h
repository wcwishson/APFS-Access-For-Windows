#pragma once

#include "RandomAccessSource.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>

namespace apfsaccess::rw::fusion_bitmap {

// Evidence for one already selected chunk only. The caller still proves member,
// chunk, reserved-range and historical ownership constraints. Reserve the whole
// byte-inspection bound up front; a clear bit may conservatively stop it early.
inline bool RangeAllocated(std::span<const std::byte> bitmap, std::uint64_t start_bit,
    std::uint64_t count, const std::shared_ptr<catalog::ApfsReadBudget>& budget, std::string& error) {
    error.clear();
    const auto fail = [&](const char* reason) { error = reason; return false; };
    if (!budget) return fail("FusionBitmapBudgetRequired");
    if (budget->Failed()) return fail(budget->Failure());
    if (!count || count > UINT64_MAX - start_bit) return fail("FusionBitmapRangeInvalid");
    const auto first = start_bit / 8;
    const auto final_bit = start_bit + count - 1;
    const auto last = final_bit / 8;
    if (last >= bitmap.size()) return fail("FusionBitmapRangeInvalid");
    const auto covered_bytes = last - first + 1;
    if (!budget->Materialize(covered_bytes, 0)) return fail(budget->Failure());

    const auto head = (0xffu << static_cast<unsigned>(start_bit % 8)) & 0xffu;
    const auto tail = 0xffu >> (7u - static_cast<unsigned>(final_bit % 8));
    const auto contains = [&](std::uint64_t index, unsigned mask) {
        return (std::to_integer<unsigned>(bitmap[static_cast<std::size_t>(index)]) & mask) == mask;
    };
    if (first == last) {
        if (!contains(first, head & tail)) return fail("FusionVolumeOwnerFree");
    } else {
        if (!contains(first, head)) return fail("FusionVolumeOwnerFree");
        for (auto byte = first + 1; byte < last; ++byte)
            if (bitmap[static_cast<std::size_t>(byte)] != std::byte{0xff}) return fail("FusionVolumeOwnerFree");
        if (!contains(last, tail)) return fail("FusionVolumeOwnerFree");
    }
    return true;
}
}
