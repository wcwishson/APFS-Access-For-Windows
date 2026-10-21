#pragma once

#include "ApfsFusionStore.h"
#include "ApfsTransactionWriter.h"
#include <algorithm>
#include <limits>
#include <new>
#include <stdexcept>
#include <type_traits>

namespace apfsaccess::rw::fusion_compact {
namespace detail {
inline constexpr std::uint64_t Mask = 0x0fffffffffffffffULL;
inline constexpr std::uint64_t LengthMask = 0x00ffffffffffffffULL;
inline constexpr auto Removed = (std::numeric_limits<std::size_t>::max)();
inline bool Fail(std::string& error, const char* reason) { error = reason; return false; }
inline void PutLength(catalog::BtreeRecord& record, std::uint64_t value) noexcept {
    for (unsigned i = 0; i < 8; ++i) record.value[i] = std::byte(value >> (8 * i));
}
template<class Extent> struct Entry {
    std::size_t index = 0;
    Extent extent;
    bool removed = false;
};
template<class Extent>
inline void Commit(std::vector<catalog::BtreeRecord>& records, std::vector<Entry<Extent>>& entries) noexcept {
    std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) { return a.index < b.index; });
    std::size_t next = 0, written = 0;
    for (std::size_t i = 0; i < records.size(); ++i) {
        if (next < entries.size() && entries[next].index == i) {
            const auto& entry = entries[next++];
            if (entry.removed) continue;
            if constexpr (std::is_same_v<Extent, AppleFileExtentRecord>) PutLength(records[i], entry.extent.length_bytes);
            else PutLength(records[i], (std::uint64_t(entry.extent.kind) << 60) | entry.extent.block_count);
        }
        if (written != i) records[written] = std::move(records[i]);
        ++written;
    }
    records.resize(written);
}
inline bool SameMember(std::uint64_t first, std::uint64_t end, std::uint64_t tier) {
    return (first < tier && end <= tier) || first >= tier;
}
}

// V8 only: invoke after canonical ownership/release checks and normalization,
// before either estimated or actual new per-block payload records are appended.
// This is a representation change, not allocation, ownership or replay authority.
inline bool FileRecords(std::vector<catalog::BtreeRecord>& records, std::uint32_t block_size,
    std::string& error, const std::shared_ptr<catalog::ApfsReadBudget>& budget = {}) try {
    error.clear();
    if (block_size < 4096 || block_size > 65536 || (block_size & (block_size - 1)))
        return detail::Fail(error, "FusionCompactBlockSizeInvalid");
    using Entry = detail::Entry<AppleFileExtentRecord>;
    std::size_t count = 0;
    for (const auto& record : records)
        if ((catalog::ReadU64LE(record.key, 0).value_or(0) >> 60) == 8) ++count;
    if (count > UINT64_MAX / sizeof(Entry)) return detail::Fail(error, "FusionCompactSizeOverflow");
    if (budget && !budget->Materialize(count, count * sizeof(Entry))) return detail::Fail(error, budget->Failure());
    std::vector<Entry> entries; entries.reserve(count);
    for (std::size_t i = 0; i < records.size(); ++i) {
        if ((catalog::ReadU64LE(records[i].key, 0).value_or(0) >> 60) != 8) continue;
        AppleFileExtentRecord extent;
        if (!DecodeAppleFileExtentRecord(records[i], block_size, extent, error)) return false;
        entries.push_back({i, extent, false});
    }
    std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
        if (a.extent.object_id != b.extent.object_id) return a.extent.object_id < b.extent.object_id;
        return a.extent.logical_address < b.extent.logical_address;
    });
    const auto tier = catalog::kFusionTier2ByteAddress / block_size;
    std::size_t prior = detail::Removed;
    for (std::size_t i = 0; i < entries.size(); ++i) {
        auto& current = entries[i].extent;
        if (prior != detail::Removed) {
            auto& previous = entries[prior].extent;
            const auto end = previous.logical_address + previous.length_bytes;
            if (previous.object_id == current.object_id && end > current.logical_address)
                return detail::Fail(error, "FusionCompactFileOverlap");
            // Nonzero crypto IDs can encode per-extent tweak bases. Equal IDs
            // alone do not prove that merging preserves their block semantics.
            if (previous.object_id == current.object_id && end == current.logical_address &&
                previous.physical_block && current.physical_block && !previous.crypto_id && !current.crypto_id &&
                previous.physical_block + previous.length_bytes / block_size == current.physical_block &&
                current.length_bytes <= detail::LengthMask - previous.length_bytes &&
                detail::SameMember(previous.physical_block,
                    current.physical_block + current.length_bytes / block_size, tier)) {
                previous.length_bytes += current.length_bytes;
                entries[i].removed = true;
                continue;
            }
        }
        prior = i;
    }
    detail::Commit(records, entries);
    return true;
} catch (const std::bad_alloc&) { return detail::Fail(error, "FusionCompactAllocationLimit"); }
  catch (const std::length_error&) { return detail::Fail(error, "FusionCompactAllocationLimit"); }

// Physical extentrefs use the runtime's exact 4 KiB Fusion address convention.
inline bool PhysicalRecords(std::vector<catalog::BtreeRecord>& records, std::string& error,
    const std::shared_ptr<catalog::ApfsReadBudget>& budget = {}) try {
    error.clear();
    using Entry = detail::Entry<ApplePhysicalExtentRecord>;
    std::size_t count = 0;
    for (const auto& record : records)
        if ((catalog::ReadU64LE(record.key, 0).value_or(0) >> 60) == 2) ++count;
    if (count > UINT64_MAX / sizeof(Entry)) return detail::Fail(error, "FusionCompactSizeOverflow");
    if (budget && !budget->Materialize(count, count * sizeof(Entry))) return detail::Fail(error, budget->Failure());
    std::vector<Entry> entries; entries.reserve(count);
    for (std::size_t i = 0; i < records.size(); ++i) {
        if ((catalog::ReadU64LE(records[i].key, 0).value_or(0) >> 60) != 2) continue;
        ApplePhysicalExtentRecord extent;
        if (!DecodeApplePhysicalExtentRecord(records[i], extent, error)) return false;
        entries.push_back({i, extent, false});
    }
    std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
        return a.extent.physical_block < b.extent.physical_block;
    });
    constexpr auto tier = catalog::kFusionTier2ByteAddress / 4096;
    std::size_t prior = detail::Removed;
    for (std::size_t i = 0; i < entries.size(); ++i) {
        auto& current = entries[i].extent;
        if (prior != detail::Removed) {
            auto& previous = entries[prior].extent;
            const auto end = previous.physical_block + previous.block_count;
            if (end > current.physical_block) return detail::Fail(error, "FusionCompactPhysicalOverlap");
            if (end == current.physical_block && previous.owning_object_id == current.owning_object_id &&
                previous.kind == current.kind && previous.reference_count == current.reference_count &&
                current.block_count <= detail::Mask - previous.block_count &&
                detail::SameMember(previous.physical_block, current.physical_block + current.block_count, tier)) {
                previous.block_count += current.block_count;
                entries[i].removed = true;
                continue;
            }
        }
        prior = i;
    }
    detail::Commit(records, entries);
    return true;
} catch (const std::bad_alloc&) { return detail::Fail(error, "FusionCompactAllocationLimit"); }
  catch (const std::length_error&) { return detail::Fail(error, "FusionCompactAllocationLimit"); }
}
