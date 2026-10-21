#pragma once
#include "ApfsEncryptedMutation.h"
#include "ApfsTransactionWriter.h"
#include "ApfsCrypto.h"
#include <algorithm>
#include <functional>
#include <set>

namespace apfsaccess::catalog::encrypted_delta
{
constexpr std::uint64_t block_bytes = 4096;
struct DataPlan
{
    std::uint64_t old_size = 0, size = 0, stream = 0;
    std::vector<rw::AppleEncryptedFileExtentRecord> original, preserved;
    std::vector<std::uint64_t> changed;
};
inline bool Failure(std::string& error, const char* text) { error = text; return false; }
inline std::uint64_t Blocks(std::uint64_t size)
{ return size / block_bytes + (size % block_bytes != 0); }

// Limits concern work in this transaction, never total file plaintext size.
inline bool PlanData(std::span<const rw::AppleEncryptedFileExtentRecord> extents,
    std::uint64_t stream, std::uint64_t old_size, const EncryptedMutationRequest& request,
    std::size_t max_changed, DataPlan& output, std::string& error)
{
    output = {}; error.clear();
    const auto kind = request.kind;
    const bool create = kind == EncryptedMutationKind::Create;
    const bool write = kind == EncryptedMutationKind::Write || kind == EncryptedMutationKind::Overwrite;
    const bool resize = kind == EncryptedMutationKind::Resize;
    if ((!create && !write && !resize) || !stream || !max_changed ||
        old_size > UINT64_MAX - (block_bytes - 1) ||
        ((create || write) && request.data.size() > UINT64_MAX - request.offset) ||
        (resize && (!request.data.empty() || request.offset)) ||
        (create && (old_size || !extents.empty() || request.offset)) ||
        (write && request.data.empty())) return Failure(error, "EncryptedDeltaArgumentsInvalid");
    DataPlan plan; plan.old_size = old_size; plan.size = old_size; plan.stream = stream;
    if (create) plan.size = request.data.size();
    else if (resize) plan.size = request.size;
    else plan.size = (std::max)(old_size, request.offset + request.data.size());
    if (plan.size > UINT64_MAX - (block_bytes - 1) ||
        (kind == EncryptedMutationKind::Overwrite && plan.size != old_size))
        return Failure(error, "EncryptedDeltaRangeOverflow");
    std::uint64_t covered = 0;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> physical_ranges, crypto_ranges;
    for (const auto& record : extents)
    {
        const auto& e = record.extent;
        BtreeRecord encoded;
        if (e.object_id != stream || e.logical_address != covered || e.block_size != block_bytes ||
            !e.physical_block || !e.length_bytes || e.length_bytes % block_bytes ||
            e.length_bytes > UINT64_MAX - covered ||
            e.physical_block > UINT64_MAX - e.length_bytes / block_bytes ||
            e.crypto_id > UINT64_MAX / (block_bytes / 512) - e.length_bytes / block_bytes ||
            !rw::EncodeAppleEncryptedFileExtentRecord(record, rw::AppleEncryptedExtentProfile::OneKeyGenerationZero, encoded, error))
            return Failure(error, "EncryptedDeltaExactDenseExtentRequired");
        const auto count = e.length_bytes / block_bytes;
        physical_ranges.emplace_back(e.physical_block, e.physical_block + count);
        crypto_ranges.emplace_back(e.crypto_id, e.crypto_id + count);
        covered += e.length_bytes; plan.original.push_back(record);
    }
    if (covered != Blocks(old_size) * block_bytes)
        return Failure(error, "EncryptedDeltaExactDenseExtentRequired");
    const auto overlaps = [](auto& ranges) {
        std::sort(ranges.begin(), ranges.end());
        for (std::size_t i = 1; i < ranges.size(); ++i)
            if (ranges[i].first < ranges[i - 1].second) return true;
        return false;
    };
    if (overlaps(physical_ranges) || overlaps(crypto_ranges))
        return Failure(error, "EncryptedDeltaOriginalExtentOverlap");
    std::set<std::uint64_t> changed;
    const auto add_range = [&](std::uint64_t begin, std::uint64_t end) {
        if (end < begin || end - begin > max_changed) return false;
        for (auto i = begin; i < end; ++i) if (changed.insert(i).second && changed.size() > max_changed) return false;
        return true;
    };
    if ((write || create) && !request.data.empty() &&
        !add_range(request.offset / block_bytes, Blocks(request.offset + request.data.size())))
        return Failure(error, "EncryptedDeltaChangedBlockCapacityLimit");
    if (plan.size > old_size)
    {
        if (!add_range(Blocks(old_size), Blocks(plan.size)) ||
            (old_size % block_bytes && !add_range(old_size / block_bytes, old_size / block_bytes + 1)))
            return Failure(error, "EncryptedDeltaChangedBlockCapacityLimit");
    }
    if (resize && plan.size < old_size && plan.size % block_bytes &&
        !add_range(plan.size / block_bytes, plan.size / block_bytes + 1))
        return Failure(error, "EncryptedDeltaChangedBlockCapacityLimit");
    plan.changed.assign(changed.begin(), changed.end());
    for (const auto& record : plan.original)
    {
        const auto& e = record.extent;
        auto begin = e.logical_address / block_bytes;
        const auto end = (std::min)(begin + e.length_bytes / block_bytes, Blocks(plan.size));
        auto mark = changed.lower_bound(begin);
        while (begin < end)
        {
            if (mark != changed.end() && *mark == begin) { ++begin; ++mark; continue; }
            const auto stop = mark == changed.end() ? end : (std::min)(end, *mark);
            auto keep = record;
            const auto delta = begin - e.logical_address / block_bytes;
            keep.extent.logical_address = begin * block_bytes;
            keep.extent.length_bytes = (stop - begin) * block_bytes;
            keep.extent.physical_block += delta; keep.extent.crypto_id += delta;
            plan.preserved.push_back(keep); begin = stop;
        }
    }
    output = std::move(plan); return true;
}

using OldBlockReader = std::function<bool(const rw::AppleFileExtentRecord&, std::uint64_t,
    crypto::SecureBytes&, std::string&)>;
inline bool RenderBlock(const DataPlan& plan, const EncryptedMutationRequest& request,
    std::uint64_t logical_block, crypto::SecureBytes& locked, const OldBlockReader& read,
    std::string& error)
{
    error.clear();
    if (!locked.IsLocked() || locked.Size() != block_bytes) {
        locked.Clear();
        return Failure(error, "EncryptedDeltaLockedBlockRequired");
    }
    std::fill(locked.Bytes().begin(), locked.Bytes().end(), std::byte{});
    if (plan.size > UINT64_MAX - (block_bytes - 1) || plan.old_size > UINT64_MAX - (block_bytes - 1) ||
        request.data.size() > UINT64_MAX - request.offset || logical_block >= Blocks(plan.size) ||
        !std::binary_search(plan.changed.begin(), plan.changed.end(), logical_block))
        return Failure(error, "EncryptedDeltaRenderRangeInvalid");
    const auto at = logical_block * block_bytes;
    if (at < plan.old_size)
    {
        const auto old = std::find_if(plan.original.begin(), plan.original.end(), [&](const auto& value) {
            return at >= value.extent.logical_address && at - value.extent.logical_address < value.extent.length_bytes;
        });
        if (old == plan.original.end() || !read(old->extent, (at - old->extent.logical_address) / block_bytes, locked, error) ||
            !locked.IsLocked() || locked.Size() != block_bytes)
        {
            if (locked.IsLocked() && locked.Size() == block_bytes)
                std::fill(locked.Bytes().begin(), locked.Bytes().end(), std::byte{});
            else locked.Clear();
            if (error.empty()) error = "EncryptedDeltaOldBlockReadFailed";
            return false;
        }
        const auto keep = (std::min)(block_bytes, plan.old_size - at);
        std::fill(locked.Bytes().begin() + static_cast<std::size_t>(keep), locked.Bytes().end(), std::byte{});
    }
    if (!request.data.empty())
    {
        const auto begin = (std::max)(at, request.offset);
        const auto end = (std::min)(at + block_bytes, request.offset + request.data.size());
        if (begin < end) std::copy_n(request.data.begin() + static_cast<std::size_t>(begin - request.offset),
            static_cast<std::size_t>(end - begin), locked.Bytes().begin() + static_cast<std::size_t>(begin - at));
    }
    if (plan.size - at < block_bytes)
        std::fill(locked.Bytes().begin() + static_cast<std::size_t>(plan.size - at), locked.Bytes().end(), std::byte{});
    return true;
}

inline bool BindData(const DataPlan& plan, std::span<const std::uint64_t> physical,
    std::span<const std::uint64_t> crypto_ids, std::uint8_t flags,
    std::vector<rw::AppleEncryptedFileExtentRecord>& output, std::string& error)
{
    output.clear();
    if (physical.size() != plan.changed.size() || crypto_ids.size() != physical.size())
        return Failure(error, "EncryptedDeltaReservationCoverageInvalid");
    std::set<std::uint64_t> blocks, units;
    auto bound = plan.preserved;
    for (std::size_t i = 0; i != physical.size(); ++i)
    {
        const bool old_owner = std::any_of(plan.original.begin(), plan.original.end(), [&](const auto& e) {
            const auto count = e.extent.length_bytes / block_bytes;
            return (physical[i] >= e.extent.physical_block && physical[i] - e.extent.physical_block < count) ||
                (crypto_ids[i] >= e.extent.crypto_id && crypto_ids[i] - e.extent.crypto_id < count);
        });
        if (!physical[i] || !crypto_ids[i] || old_owner || !blocks.insert(physical[i]).second || !units.insert(crypto_ids[i]).second)
            return Failure(error, "EncryptedDeltaSourceOrTweakReused");
        rw::AppleEncryptedFileExtentRecord e;
        e.flags = flags; e.extent = {plan.stream, plan.changed[i] * block_bytes, block_bytes, physical[i], crypto_ids[i], 4096};
        BtreeRecord encoded;
        if (!rw::EncodeAppleEncryptedFileExtentRecord(e, rw::AppleEncryptedExtentProfile::OneKeyGenerationZero, encoded, error)) return false;
        bound.push_back(e);
    }
    std::sort(bound.begin(), bound.end(), [](const auto& a, const auto& b) { return a.extent.logical_address < b.extent.logical_address; });
    std::uint64_t covered = 0;
    for (const auto& e : bound)
    {
        if (e.extent.logical_address != covered) return Failure(error, "EncryptedDeltaBoundCoverageInvalid");
        covered += e.extent.length_bytes;
    }
    if (covered != Blocks(plan.size) * block_bytes) return Failure(error, "EncryptedDeltaBoundCoverageInvalid");
    output = std::move(bound); return true;
}
}
