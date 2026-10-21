#pragma once
#include "ApfsFormat.h"
#include <algorithm>
#include <span>
#include <string>

namespace apfsaccess::rw::fusion_ids {
inline constexpr std::uint64_t Limit = (1ull << 60) - 1;

// Inputs are the canonical records read through the held Fusion source. This
// selects identifiers only; it grants no allocation or publication authority.
inline bool Next(std::uint64_t next, std::uint64_t root,
    std::span<const catalog::BtreeRecord> old_records,
    std::span<const catalog::BtreeRecord> requested_records,
    std::span<const catalog::BtreeRecord> object_map,
    std::uint64_t& result, std::string& error)
{
    result = 0;
    if (!next || next > Limit || !root || root >= Limit) {
        error = "FusionVolumeObjectIdExhausted"; return false;
    }
    auto maximum = root;
    for (auto records : {old_records, requested_records}) for (const auto& record : records) {
        const auto key = catalog::ReadU64LE(record.key, 0);
        if (!key) { error = "FusionVolumeObjectIdRecordInvalid"; return false; }
        maximum = (std::max)(maximum, *key & Limit);
    }
    for (const auto& record : object_map) {
        if (record.key.size() != 16 || record.value.size() != 16) {
            error = "FusionVolumeObjectIdMapInvalid"; return false;
        }
        const auto oid = catalog::ReadU64LE(record.key, 0).value_or(0);
        if (!oid || oid >= Limit) { error = "FusionVolumeObjectIdExhausted"; return false; }
        maximum = (std::max)(maximum, oid);
    }
    if (maximum >= Limit) { error = "FusionVolumeObjectIdExhausted"; return false; }
    result = (std::max)(next, maximum + 1);
    return true;
}

inline bool Range(std::uint64_t first, std::size_t children, std::string& error)
{
    if (!first || first > Limit || children > Limit - first) {
        error = "FusionVolumeObjectIdExhausted"; return false;
    }
    return true;
}
}
