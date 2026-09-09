#include "ApfsSharedSpace.h"

#include <algorithm>
#include <limits>
#include <unordered_set>

namespace apfsaccess::catalog
{
bool TryProjectAppleSharedSpace(const AppleCheckpointView& checkpoint,
    ApfsSharedSpaceProjection& out, std::string& error)
{
    out = {};
    error.clear();
    const auto fail = [&error](const char* reason) { error = reason; return false; };
    const auto& nx = checkpoint.container.superblock;
    const auto& sm = checkpoint.spaceman;
    const auto& device = sm.devices[0];
    const auto& tier2 = sm.devices[1];
    if (nx.uuid_hex.size() != 32 || nx.xid == 0 || nx.block_count == 0 ||
        nx.block_size < 4096 || nx.block_size > 65536 ||
        (nx.block_size & (nx.block_size - 1)) != 0 ||
        checkpoint.container.checkpoint_map_blocks.empty() ||
        nx.spaceman_oid == 0 || sm.object.object_id != nx.spaceman_oid ||
        sm.object.xid != nx.xid || device.block_count != nx.block_count ||
        device.free_count > device.block_count)
        return fail("SharedSpaceCheckpointInvalid");
    if (tier2.block_count || tier2.chunk_count || tier2.free_count ||
        tier2.cib_count || tier2.cab_count)
        return fail("SharedSpaceMultiStoreUnsupported");
    if (checkpoint.volumes.empty() || checkpoint.volumes.size() != nx.fs_oids.size())
        return fail("SharedSpaceVolumeSetInvalid");

    ApfsSharedSpaceProjection candidate;
    candidate.container_uuid_hex = nx.uuid_hex;
    candidate.checkpoint_xid = nx.xid;
    candidate.allocation_unit_bytes = nx.block_size;
    const auto amount = [&nx](std::uint64_t blocks, ApfsSpaceAmount& value) {
        if (blocks > (std::numeric_limits<std::uint64_t>::max)() / nx.block_size) return false;
        value = {blocks, blocks * nx.block_size};
        return true;
    };
    if (!amount(nx.block_count, candidate.total) ||
        !amount(device.free_count, candidate.free) ||
        !amount(nx.block_count - device.free_count, candidate.used))
        return fail("SharedSpaceByteOverflow");

    std::uint64_t unmet_reserves = 0;
    std::unordered_set<std::uint64_t> oids;
    for (std::size_t i = 0; i < checkpoint.volumes.size(); ++i)
    {
        const auto& volume = checkpoint.volumes[i];
        const auto& sb = volume.superblock;
        if (!sb.object_id || sb.object_id != nx.fs_oids[i] || !oids.insert(sb.object_id).second ||
            sb.xid == 0 || sb.xid > nx.xid || volume.superblock_object.object_id != sb.object_id ||
            volume.superblock_object.xid != sb.xid)
            return fail("SharedSpaceVolumeIdentityInvalid");
        const auto& s = sb.space;
        if (s.allocated_block_count > candidate.used.blocks || s.reserve_block_count > nx.block_count ||
            (s.quota_block_count && s.reserve_block_count > s.quota_block_count))
            return fail("SharedSpaceVolumeCountersInvalid");
        const auto unmet = s.reserve_block_count > s.allocated_block_count
            ? s.reserve_block_count - s.allocated_block_count : 0;
        if (unmet > (std::numeric_limits<std::uint64_t>::max)() - unmet_reserves)
            return fail("SharedSpaceReserveOverflow");
        unmet_reserves += unmet;
    }
    if (unmet_reserves > device.free_count)
        return fail("SharedSpaceReservesExceedFree");

    for (const auto& volume : checkpoint.volumes)
    {
        const auto& s = volume.superblock.space;
        ApfsVolumeSpaceProjection result;
        result.object_id = volume.superblock.object_id;
        const auto own_unmet = s.reserve_block_count > s.allocated_block_count
            ? s.reserve_block_count - s.allocated_block_count : 0;
        const auto siblings = unmet_reserves - own_unmet;
        auto available = device.free_count - siblings;
        if (s.quota_block_count)
        {
            const auto remaining = s.quota_block_count > s.allocated_block_count
                ? s.quota_block_count - s.allocated_block_count : 0;
            available = (std::min)(available, remaining);
            result.quota.emplace();
            if (!amount(s.quota_block_count, *result.quota)) return fail("SharedSpaceByteOverflow");
        }
        if (s.reserve_block_count)
        {
            result.reserve.emplace();
            if (!amount(s.reserve_block_count, *result.reserve)) return fail("SharedSpaceByteOverflow");
        }
        if (!amount(s.allocated_block_count, result.allocated) ||
            !amount(siblings, result.sibling_reserve_remaining) || !amount(available, result.available))
            return fail("SharedSpaceByteOverflow");
        candidate.volumes.push_back(std::move(result));
    }
    out = std::move(candidate);
    return true;
}
}
