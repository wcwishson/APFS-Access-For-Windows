#include "AppleTransactionCommit.h"

#include "ApfsTransactionWriter.h"

#include <algorithm>
#include <limits>
#include <unordered_map>
#include <unordered_set>

namespace apfsaccess::rw
{
namespace
{

bool Fail(std::string& out_error, const char* error)
{
    out_error = error;
    return false;
}

void PutU64(std::vector<std::byte>& bytes, std::size_t offset,
    std::uint64_t value)
{
    for (std::size_t index = 0; index < 8; ++index)
    {
        bytes[offset + index] =
            static_cast<std::byte>((value >> (index * 8)) & 0xffu);
    }
}

bool ReadBlock(const catalog::RandomAccessSource& source,
    std::uint64_t block, std::uint32_t block_size,
    std::vector<std::byte>& out_bytes)
{
    if (block > std::numeric_limits<std::uint64_t>::max() / block_size)
    {
        return false;
    }
    return source.Read(block * static_cast<std::uint64_t>(block_size),
        block_size, out_bytes) && out_bytes.size() == block_size;
}

bool ReadMappedObject(const catalog::RandomAccessSource& source,
    const catalog::NxSuperblock& nxsb,
    const catalog::CheckpointMapping& mapping,
    std::vector<std::byte>& out_bytes)
{
    out_bytes.clear();
    if (mapping.size_bytes == 0 ||
        mapping.size_bytes % nxsb.block_size != 0 ||
        mapping.physical_block < nxsb.xp_data_base_block ||
        mapping.physical_block - nxsb.xp_data_base_block >=
            nxsb.xp_data_block_count)
    {
        return false;
    }
    out_bytes.resize(mapping.size_bytes);
    const auto first = mapping.physical_block - nxsb.xp_data_base_block;
    const auto blocks = mapping.size_bytes / nxsb.block_size;
    for (std::uint32_t ordinal = 0; ordinal < blocks; ++ordinal)
    {
        const auto relative = static_cast<std::uint32_t>(
            (first + ordinal) % nxsb.xp_data_block_count);
        std::vector<std::byte> block;
        if (!ReadBlock(source, nxsb.xp_data_base_block + relative,
                nxsb.block_size, block))
        {
            out_bytes.clear();
            return false;
        }
        std::copy(block.begin(), block.end(), out_bytes.begin() +
            static_cast<std::ptrdiff_t>(ordinal * nxsb.block_size));
    }
    return true;
}

bool AddStableGuard(const catalog::RandomAccessSource& source,
    std::uint64_t block, std::uint32_t block_size,
    std::vector<AppleCheckpointGuardBlock>& guards)
{
    if (std::any_of(guards.begin(), guards.end(), [block](const auto& guard) {
            return guard.physical_block == block;
        }))
    {
        return true;
    }
    AppleCheckpointGuardBlock guard;
    guard.physical_block = block;
    if (!ReadBlock(source, block, block_size, guard.bytes))
    {
        return false;
    }
    guards.push_back(std::move(guard));
    return true;
}

bool AddEphemeral(
    AppleCheckpointEphemeralObject object,
    std::unordered_map<std::uint64_t, AppleCheckpointEphemeralObject>& objects,
    std::string& out_error)
{
    if (object.object.object_id == 0 ||
        !objects.emplace(object.object.object_id, std::move(object)).second)
    {
        return Fail(out_error, "AppleTransactionEphemeralDuplicate");
    }
    return true;
}

bool ValidateMainWriteCoverage(const AppleSpacemanAllocationPlan& allocation,
    const std::vector<AppleCheckpointPhysicalWrite>& writes,
    std::uint32_t block_size, std::string& out_error)
{
    std::unordered_set<std::uint64_t> allocated;
    for (const auto block : allocation.allocated_main_blocks)
    {
        if (block == 0 || !allocated.insert(block).second)
        {
            return Fail(out_error, "AppleTransactionMainAllocationInvalid");
        }
    }
    std::unordered_set<std::uint64_t> covered;
    for (const auto& write : writes)
    {
        if (write.physical_block == 0 || write.bytes.empty() ||
            write.bytes.size() % block_size != 0)
        {
            return Fail(out_error, "AppleTransactionMainWriteInvalid");
        }
        const auto blocks = write.bytes.size() / block_size;
        if (write.physical_block >
            std::numeric_limits<std::uint64_t>::max() - blocks)
        {
            return Fail(out_error, "AppleTransactionMainWriteInvalid");
        }
        for (std::size_t ordinal = 0; ordinal < blocks; ++ordinal)
        {
            const auto block = write.physical_block + ordinal;
            if (allocated.find(block) == allocated.end() ||
                !covered.insert(block).second)
            {
                return Fail(out_error, "AppleTransactionMainWriteInvalid");
            }
        }
    }
    return covered.size() == allocated.size()
        ? true
        : Fail(out_error, "AppleTransactionMainWriteIncomplete");
}

} // namespace

bool PlanAppleTransactionCommit(
    const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    const AppleTransactionCommitRequest& request,
    AppleTransactionCommitPlan& out_plan,
    std::string& out_error)
{
    out_plan = {};
    out_error.clear();
    const auto& nxsb = checkpoint.container.superblock;
    const auto& allocation = request.allocation_plan;
    if (allocation.expected_checkpoint_xid != nxsb.xid ||
        allocation.transaction_xid != nxsb.next_xid ||
        allocation.updated_spaceman.object.object_id !=
            checkpoint.spaceman.object.object_id ||
        allocation.updated_spaceman.object.type !=
            checkpoint.spaceman.object.type ||
        allocation.updated_spaceman.object.subtype !=
            checkpoint.spaceman.object.subtype ||
        allocation.updated_spaceman.object.xid != allocation.transaction_xid ||
        request.next_object_id < nxsb.next_oid)
    {
        return Fail(out_error, "AppleTransactionAllocationIdentityInvalid");
    }
    if (!ValidateMainWriteCoverage(allocation,
            request.allocated_main_writes, nxsb.block_size, out_error))
    {
        return false;
    }

    AppleCheckpointPublicationRequest publication;
    publication.expected_checkpoint_xid = nxsb.xid;
    publication.transaction_xid = allocation.transaction_xid;
    publication.next_object_id = request.next_object_id;
    publication.container_object_map_oid = request.container_object_map_oid;
    publication.allocator_owned_writes = request.allocated_main_writes;

    std::unordered_map<std::uint64_t, AppleCheckpointEphemeralObject> objects;
    for (const auto& object : request.additional_ephemeral_objects)
    {
        if (!AddEphemeral(object, objects, out_error))
        {
            return false;
        }
    }
    AppleCheckpointEphemeralObject spaceman;
    spaceman.object = allocation.updated_spaceman.object;
    spaceman.object.physical_block = 0;
    spaceman.object.size_bytes = static_cast<std::uint32_t>(
        allocation.updated_spaceman.bytes.size());
    spaceman.bytes = allocation.updated_spaceman.bytes;
    if (!AddEphemeral(std::move(spaceman), objects, out_error))
    {
        return false;
    }

    std::unordered_set<std::uint64_t> rebuilt_queue_roots;
    for (const auto& write : allocation.writes)
    {
        if (write.kind == AppleSpacemanWriteKind::FreeQueueTree)
        {
            if (!write.object_location.has_value() || write.physical_block != 0)
            {
                return Fail(out_error,
                    "AppleTransactionAllocatorWriteInvalid");
            }
            AppleCheckpointEphemeralObject object;
            object.object = write.object_location.value();
            object.object.physical_block = 0;
            object.bytes = write.bytes;
            if (!AddEphemeral(std::move(object), objects, out_error))
            {
                return false;
            }
        }
        else
        {
            if (write.physical_block == 0 ||
                write.bytes.size() != nxsb.block_size ||
                write.object_location.has_value())
            {
                return Fail(out_error,
                    "AppleTransactionAllocatorWriteInvalid");
            }
            publication.allocator_owned_writes.push_back(
                {write.physical_block, write.bytes});
        }
    }
    for (const auto& queue : allocation.updated_spaceman.free_queues)
    {
        if (queue.tree_oid != 0 && objects.find(queue.tree_oid) != objects.end())
        {
            rebuilt_queue_roots.insert(queue.tree_oid);
        }
    }

    std::unordered_set<std::uint64_t> retired;
    for (const auto& old_queue : checkpoint.spaceman.free_queues)
    {
        if (old_queue.tree_oid == 0 ||
            rebuilt_queue_roots.find(old_queue.tree_oid) ==
                rebuilt_queue_roots.end())
        {
            continue;
        }
        for (const auto physical_block : old_queue.tree_blocks)
        {
            const auto mapping = std::find_if(
                checkpoint.container.mappings.begin(),
                checkpoint.container.mappings.end(),
                [physical_block](const auto& candidate) {
                    return candidate.physical_block == physical_block;
                });
            if (mapping == checkpoint.container.mappings.end())
            {
                return Fail(out_error,
                    "AppleTransactionOldQueueMappingMissing");
            }
            if (objects.find(mapping->object_id) == objects.end())
            {
                retired.insert(mapping->object_id);
            }
        }
    }

    for (const auto& mapping : checkpoint.container.mappings)
    {
        if (objects.find(mapping.object_id) != objects.end() ||
            retired.find(mapping.object_id) != retired.end())
        {
            continue;
        }
        AppleCheckpointEphemeralObject object;
        object.file_system_oid = mapping.file_system_oid;
        object.object.object_id = mapping.object_id;
        object.object.xid = allocation.transaction_xid;
        object.object.type = mapping.type;
        object.object.subtype = mapping.subtype;
        object.object.size_bytes = mapping.size_bytes;
        if (!ReadMappedObject(source, nxsb, mapping, object.bytes))
        {
            return Fail(out_error, "AppleTransactionEphemeralReadFailed");
        }
        PutU64(object.bytes, 0x10, allocation.transaction_xid);
        if (!FinalizeAppleObjectChecksum(object.bytes, out_error) ||
            !AddEphemeral(std::move(object), objects, out_error))
        {
            return false;
        }
    }

    publication.retired_ephemeral_object_ids.assign(
        retired.begin(), retired.end());
    std::sort(publication.retired_ephemeral_object_ids.begin(),
        publication.retired_ephemeral_object_ids.end());
    publication.ephemeral_objects.reserve(objects.size());
    for (auto& [object_id, object] : objects)
    {
        (void)object_id;
        publication.ephemeral_objects.push_back(std::move(object));
    }
    std::sort(publication.ephemeral_objects.begin(),
        publication.ephemeral_objects.end(), [](const auto& left,
                                                 const auto& right) {
            return left.object.object_id < right.object.object_id;
        });

    AppleTransactionCommitPlan plan;
    if (!PlanAppleCheckpointPublication(source, checkpoint.container,
            publication, plan.publication, out_error))
    {
        return false;
    }
    const auto add_guard = [&](std::uint64_t block) {
        return AddStableGuard(source, block, nxsb.block_size,
            plan.publication.guard_blocks);
    };
    for (const auto& cab : checkpoint.spaceman.devices[0].cabs)
    {
        if (!add_guard(cab.object.physical_block))
        {
            return Fail(out_error, "AppleTransactionGuardUnreadable");
        }
    }
    for (const auto& cib : checkpoint.spaceman.devices[0].cibs)
    {
        if (!add_guard(cib.object.physical_block))
        {
            return Fail(out_error, "AppleTransactionGuardUnreadable");
        }
    }
    for (const auto& chunk : checkpoint.spaceman.chunks)
    {
        if (chunk.bitmap_block != 0 && !add_guard(chunk.bitmap_block))
        {
            return Fail(out_error, "AppleTransactionGuardUnreadable");
        }
    }
    for (const auto& bitmap :
         checkpoint.spaceman.internal_pool.active_bitmaps)
    {
        if (!add_guard(bitmap.physical_block))
        {
            return Fail(out_error, "AppleTransactionGuardUnreadable");
        }
    }
    out_plan = std::move(plan);
    return true;
}

} // namespace apfsaccess::rw
