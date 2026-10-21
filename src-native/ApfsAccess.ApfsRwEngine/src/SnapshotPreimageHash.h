#pragma once

#include "RandomAccessSource.h"
#include <array>
#include <set>

namespace apfsaccess::rw::snapshot_detail {
// Hashes observed bytes only; callers retain source and owner admission.
bool HashPreimageBlocks(const catalog::RandomAccessSource& source,
    std::uint32_t block_size, std::uint64_t block_count,
    const std::set<std::uint64_t>& blocks, std::array<std::uint8_t,32>& hash);
}
