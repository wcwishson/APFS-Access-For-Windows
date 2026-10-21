#pragma once
#include "ApfsFormat.h"

namespace apfsaccess::catalog
{
// Existing factory body admission. Callers authenticate the entire native
// envelope, checksum, generation, mapping and member window first.
[[nodiscard]] inline bool CheckAppleFusionEmptyWritebackBody(
    const std::vector<std::byte>& cache, std::string& error)
{
    const auto fail = [&](const char* text) { error = text; return false; };
    if (cache.size() < 4096 || cache.size() > 65536 || (cache.size() & (cache.size() - 1)))
        return fail("FusionWritebackMultiBlockUnsupported");
    if (ReadU64LE(cache, 0x20) != 0x70) return fail("FusionWritebackVersionUnsupported");
    if (ReadU32LE(cache, 0x4C) != 0u) return fail("FusionWritebackReservedFieldUnsupported");
    if (ReadU64LE(cache, 0x28) != 0 || ReadU64LE(cache, 0x30) != 0 ||
        ReadU64LE(cache, 0x38) != 0 || ReadU64LE(cache, 0x40) != 0 ||
        ReadU32LE(cache, 0x48) != 0u || ReadU64LE(cache, 0x50) != 0 ||
        ReadU64LE(cache, 0x58) != 0 || ReadU64LE(cache, 0x60) != 0)
        return fail("FusionNonemptyWritebackRoutingUnestablished");
    error.clear(); return true;
}
}
