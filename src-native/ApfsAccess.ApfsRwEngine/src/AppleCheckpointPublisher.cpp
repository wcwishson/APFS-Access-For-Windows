#include "AppleCheckpointPublisher.h"
#include "AppleCapacityPreviewInternal.h"

#include "ApfsTransactionWriter.h"
#include "BlockDevice.h"

#include <algorithm>
#include <limits>
#include <unordered_map>
#include <unordered_set>

namespace apfsaccess::rw
{
namespace
{

constexpr std::size_t kCheckpointMappingBytes = 0x28;
constexpr std::size_t kCheckpointReadbackBytes = 1024 * 1024;

bool Fail(std::string& out_error, const char* error)
{
    out_error = error;
    return false;
}

bool AllowStage(const AppleCheckpointStageHook& hook,
    std::string_view stage, std::string& out_error)
{
    if (hook && !hook(stage))
    {
        out_error = "AppleCheckpointPublicationInterrupted:";
        out_error.append(stage.data(), stage.size());
        return false;
    }
    return true;
}

void PutU32(std::vector<std::byte>& bytes, std::size_t offset,
    std::uint32_t value)
{
    for (std::size_t index = 0; index < 4; ++index)
    {
        bytes[offset + index] =
            static_cast<std::byte>((value >> (index * 8)) & 0xffu);
    }
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

bool RingFieldsValid(std::uint32_t index, std::uint32_t length,
    std::uint32_t next, std::uint32_t count)
{
    return count != 0 && index < count && length <= count && next < count &&
        next == static_cast<std::uint32_t>(
            (static_cast<std::uint64_t>(index) + length) % count);
}

bool RingRangesOverlap(std::uint32_t first_index, std::uint32_t first_length,
    std::uint32_t second_index, std::uint32_t second_length,
    std::uint32_t count)
{
    std::vector<bool> occupied(count, false);
    for (std::uint32_t offset = 0; offset < first_length; ++offset)
    {
        occupied[(first_index + offset) % count] = true;
    }
    for (std::uint32_t offset = 0; offset < second_length; ++offset)
    {
        if (occupied[(second_index + offset) % count])
        {
            return true;
        }
    }
    return false;
}

bool SameMapping(const catalog::CheckpointMapping& left,
    const catalog::CheckpointMapping& right)
{
    return left.type == right.type && left.subtype == right.subtype &&
        left.size_bytes == right.size_bytes &&
        left.file_system_oid == right.file_system_oid &&
        left.object_id == right.object_id &&
        left.physical_block == right.physical_block;
}

bool SameCheckpoint(const catalog::ContainerCheckpointView& left,
    const catalog::ContainerCheckpointView& right)
{
    return left.superblock.xid == right.superblock.xid &&
        left.superblock_physical_block == right.superblock_physical_block &&
        left.superblock_bytes == right.superblock_bytes &&
        left.checkpoint_map_blocks == right.checkpoint_map_blocks &&
        left.mappings.size() == right.mappings.size() &&
        std::equal(left.mappings.begin(), left.mappings.end(),
            right.mappings.begin(), SameMapping);
}

bool ReadBlock(const catalog::RandomAccessSource& source,
    std::uint64_t physical_block, std::uint32_t block_size,
    std::vector<std::byte>& out_bytes)
{
    if (physical_block >
        std::numeric_limits<std::uint64_t>::max() / block_size)
    {
        return false;
    }
    return source.Read(physical_block * static_cast<std::uint64_t>(block_size),
        block_size, out_bytes) && out_bytes.size() == block_size;
}

bool AddGuard(const catalog::RandomAccessSource& source,
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

bool AreaContains(std::uint64_t base, std::uint32_t count,
    std::uint64_t block)
{
    return block >= base && block - base < count;
}

bool AddCheckpointGuards(const catalog::RandomAccessSource& source,
    const catalog::ContainerCheckpointView& checkpoint,
    std::vector<AppleCheckpointGuardBlock>& guards)
{
    const auto& nxsb = checkpoint.superblock;
    if (!AddGuard(source, checkpoint.superblock_physical_block,
            nxsb.block_size, guards))
    {
        return false;
    }
    for (const auto block : checkpoint.checkpoint_map_blocks)
    {
        if (!AddGuard(source, block, nxsb.block_size, guards))
        {
            return false;
        }
    }
    for (const auto& mapping : checkpoint.mappings)
    {
        const auto first = mapping.physical_block - nxsb.xp_data_base_block;
        for (std::uint32_t ordinal = 0;
             ordinal < mapping.size_bytes / nxsb.block_size; ++ordinal)
        {
            const auto block = nxsb.xp_data_base_block +
                (first + ordinal) % nxsb.xp_data_block_count;
            if (!AddGuard(source, block, nxsb.block_size, guards))
            {
                return false;
            }
        }
    }
    return true;
}

bool ValidateEphemeralObject(
    const AppleCheckpointEphemeralObject& object,
    std::uint32_t block_size,
    std::uint64_t transaction_xid)
{
    const auto& location = object.object;
    if (location.object_id == 0 || location.xid != transaction_xid ||
        location.physical_block != 0 || location.size_bytes == 0 ||
        location.size_bytes != object.bytes.size() ||
        location.size_bytes % block_size != 0 ||
        (location.type & catalog::kObjectStorageTypeMask) !=
            catalog::kObjectEphemeral ||
        (location.type & catalog::kObjectNoHeader) != 0 ||
        (location.subtype & catalog::kObjectStorageTypeMask) != 0 ||
        catalog::ReadU64LE(object.bytes, 0x08).value_or(0) !=
            location.object_id ||
        catalog::ReadU64LE(object.bytes, 0x10).value_or(0) !=
            transaction_xid ||
        catalog::ReadU32LE(object.bytes, 0x18).value_or(0) !=
            location.type ||
        catalog::ReadU32LE(object.bytes, 0x1C).value_or(0) !=
            location.subtype)
    {
        return false;
    }
    return catalog::VerifyObjectChecksum(object.bytes, object.bytes.size());
}

bool WriteAndVerify(AppleCheckpointWriteTarget& target,
    const AppleCheckpointPlannedWrite& write, std::uint32_t block_size,
    std::string& out_error)
{
    if (write.bytes.size() != block_size ||
        !target.WriteBlock(write.physical_block, write.bytes))
    {
        return Fail(out_error, "AppleCheckpointWriteFailed");
    }
    std::vector<std::byte> readback;
    if (!target.ReadBlock(write.physical_block, block_size, readback) ||
        readback != write.bytes)
    {
        return Fail(out_error, "AppleCheckpointReadbackFailed");
    }
    return true;
}

bool VerifyBatchAfterFlush(AppleCheckpointWriteTarget& target,
    std::span<const AppleCheckpointPlannedWrite> writes,
    std::uint32_t block_size, std::string& out_error)
{
    if (writes.empty() || block_size == 0 || std::any_of(writes.begin(), writes.end(),
            [block_size](const auto& write) {
                return write.bytes.size() != block_size;
            }))
    {
        return Fail(out_error, "AppleCheckpointWriteFailed");
    }
    std::vector<std::byte> readback;
    const auto blocks_per_read = (std::max<std::size_t>)(
        1, kCheckpointReadbackBytes / block_size);
    for (std::size_t first = 0; first < writes.size();)
    {
        std::size_t count = 1;
        while (count < blocks_per_read && count < writes.size() - first &&
            writes[first + count - 1].physical_block !=
                std::numeric_limits<std::uint64_t>::max() &&
            writes[first + count].physical_block ==
                writes[first + count - 1].physical_block + 1)
        {
            ++count;
        }
        // Planner block sizes are at most 64 KiB. Keep the old single-block
        // behavior for larger caller-supplied blocks without enlarging ranges.
        const bool read = target.ReadBlockRangeForVerification(
            writes[first].physical_block, block_size, count, readback);
        if (!read || readback.empty() || readback.size() % block_size != 0 ||
            readback.size() / block_size > count)
        {
            return Fail(out_error, "AppleCheckpointReadbackFailed");
        }
        const auto blocks_read = readback.size() / block_size;
        for (std::size_t index = 0; index < blocks_read; ++index)
        {
            if (!std::equal(writes[first + index].bytes.begin(),
                    writes[first + index].bytes.end(), readback.begin() +
                        static_cast<std::ptrdiff_t>(index * block_size)))
            {
                return Fail(out_error, "AppleCheckpointReadbackFailed");
            }
        }
        first += blocks_read;
    }
    return true;
}

bool VerifyGuards(AppleCheckpointWriteTarget& target,
    const AppleCheckpointPublicationPlan& plan)
{
    for (const auto& guard : plan.guard_blocks)
    {
        std::vector<std::byte> current;
        if (!target.ReadBlock(guard.physical_block, plan.block_size, current) ||
            current != guard.bytes)
        {
            return false;
        }
    }
    return true;
}

class BlockDeviceCheckpointTarget final : public AppleCheckpointWriteTarget
{
public:
    explicit BlockDeviceCheckpointTarget(BlockDevice& device)
        : device_(device)
    {
    }

    bool ReadBlock(std::uint64_t physical_block, std::uint32_t block_size,
        std::vector<std::byte>& out_bytes) override
    {
        return physical_block <=
                std::numeric_limits<std::uint64_t>::max() / block_size &&
            device_.Read(physical_block * static_cast<std::uint64_t>(block_size),
                block_size, out_bytes);
    }

    bool ReadBlockRange(std::uint64_t physical_block, std::uint32_t block_size,
        std::size_t max_blocks, std::vector<std::byte>& out_bytes) override
    {
        if (block_size == 0 || max_blocks == 0 ||
            max_blocks > kCheckpointReadbackBytes / block_size ||
            physical_block >
                std::numeric_limits<std::uint64_t>::max() / block_size)
        {
            return false;
        }
        const auto offset = physical_block * static_cast<std::uint64_t>(block_size);
        const auto size = max_blocks * block_size;
        return size <= std::numeric_limits<std::uint64_t>::max() - offset &&
            device_.Read(offset, size, out_bytes) && out_bytes.size() == size;
    }

    bool WriteBlock(std::uint64_t physical_block,
        std::span<const std::byte> bytes) override
    {
        return !bytes.empty() && physical_block <=
                std::numeric_limits<std::uint64_t>::max() / bytes.size() &&
            device_.Write(physical_block * static_cast<std::uint64_t>(bytes.size()),
                bytes);
    }

    bool ReadBlockRangeForVerification(std::uint64_t physical_block,
        std::uint32_t block_size, std::size_t max_blocks,
        std::vector<std::byte>& out_bytes) override
    {
        if (block_size == 0 || max_blocks == 0 ||
            max_blocks > (std::max<std::size_t>)(1, kCheckpointReadbackBytes / block_size) ||
            max_blocks > std::numeric_limits<std::size_t>::max() / block_size ||
            physical_block > std::numeric_limits<std::uint64_t>::max() / block_size)
            return false;
        return device_.ReadForVerification(physical_block * static_cast<std::uint64_t>(block_size),
            max_blocks * block_size, out_bytes);
    }

    bool WriteBlocks(
        std::span<const AppleCheckpointPlannedWrite> writes) override
    {
        std::vector<BlockDevice::WriteSpan> spans;
        spans.reserve(writes.size());
        for (const auto& write : writes)
        {
            if (write.bytes.empty() || write.physical_block >
                    std::numeric_limits<std::uint64_t>::max() /
                        write.bytes.size())
            {
                return false;
            }
            spans.push_back({write.physical_block *
                    static_cast<std::uint64_t>(write.bytes.size()),
                write.bytes, &write});
        }
        return !spans.empty() && device_.WriteBatch(spans);
    }

    bool Flush() override
    {
        return device_.Flush();
    }

private:
    BlockDevice& device_;
};

} // namespace

static bool PlanAppleCheckpointPublicationWithKeylocker(
    const catalog::RandomAccessSource& source,
    const catalog::ContainerCheckpointView& checkpoint,
    const AppleCheckpointPublicationRequest& request,
    AppleCheckpointPublicationPlan& out_plan,
    std::string& out_error,
    const AppleCheckpointKeylockerReplacement& keylocker,
    bool initialize_keylocker,
    std::span<const std::uint64_t> capacity_payload = {}, bool capacity_only = false)
{
    out_plan = {};
    out_error.clear();
    const auto& nxsb = checkpoint.superblock;
    if (request.expected_checkpoint_xid == 0 ||
        request.expected_checkpoint_xid != nxsb.xid)
    {
        return Fail(out_error, "AppleCheckpointCheckpointDrift");
    }
    std::string current_error;
    const auto current = catalog::LoadContainerCheckpointView(
        source, 0, source.SizeBytes(), current_error);
    if (!current.has_value() || !SameCheckpoint(current.value(), checkpoint))
    {
        return Fail(out_error, "AppleCheckpointCheckpointDrift");
    }
    if (nxsb.block_size < 4096 || nxsb.block_size > 65536 ||
        (nxsb.block_size & (nxsb.block_size - 1)) != 0 ||
        checkpoint.superblock_bytes.size() != nxsb.block_size ||
        nxsb.xp_desc_noncontiguous || nxsb.xp_data_noncontiguous ||
        !RingFieldsValid(nxsb.xp_desc_index, nxsb.xp_desc_len,
            nxsb.xp_desc_next, nxsb.xp_desc_block_count) ||
        !RingFieldsValid(nxsb.xp_data_index, nxsb.xp_data_len,
            nxsb.xp_data_next, nxsb.xp_data_block_count))
    {
        return Fail(out_error, "AppleCheckpointGeometryInvalid");
    }
    if (nxsb.next_xid == 0 || request.transaction_xid != nxsb.next_xid ||
        request.transaction_xid <= nxsb.xid ||
        request.transaction_xid == std::numeric_limits<std::uint64_t>::max())
    {
        return Fail(out_error, "AppleCheckpointTransactionXidInvalid");
    }
    std::vector<catalog::ContainerCheckpointView> retained;
    std::unordered_set<std::uint64_t> required;
    for (const auto xid : request.required_checkpoint_xids)
    {
        if (xid == 0 || xid > nxsb.xid)
        {
            return Fail(out_error, "AppleCheckpointRetentionInvalid");
        }
        if (xid == nxsb.xid || !required.insert(xid).second)
        {
            continue;
        }
        auto historical = catalog::LoadContainerCheckpointView(
            source, 0, source.SizeBytes(), current_error, xid);
        if (!historical.has_value())
        {
            return Fail(out_error, "AppleCheckpointRetentionUnavailable");
        }
        const auto& old = historical->superblock;
        if (old.uuid_hex != nxsb.uuid_hex || old.block_size != nxsb.block_size ||
            old.block_count != nxsb.block_count ||
            old.xp_desc_base_block != nxsb.xp_desc_base_block ||
            old.xp_desc_block_count != nxsb.xp_desc_block_count ||
            old.xp_data_base_block != nxsb.xp_data_base_block ||
            old.xp_data_block_count != nxsb.xp_data_block_count ||
            !RingFieldsValid(old.xp_desc_index, old.xp_desc_len,
                old.xp_desc_next, old.xp_desc_block_count) ||
            !RingFieldsValid(old.xp_data_index, old.xp_data_len,
                old.xp_data_next, old.xp_data_block_count))
        {
            return Fail(out_error, "AppleCheckpointRetentionIdentityMismatch");
        }
        retained.push_back(std::move(*historical));
    }
    if (nxsb.next_oid == 0 || request.next_object_id < nxsb.next_oid ||
        request.next_object_id == 0)
    {
        return Fail(out_error, "AppleCheckpointNextObjectIdInvalid");
    }
    const auto locker_start = keylocker.start_block;
    const auto locker_count = keylocker.block_count;
    const auto original_locker_start = catalog::ReadU64LE(checkpoint.superblock_bytes, 0x510).value_or(0);
    const auto original_locker_count = catalog::ReadU64LE(checkpoint.superblock_bytes, 0x518).value_or(0);
    if (initialize_keylocker && (original_locker_start || original_locker_count || !locker_start || !locker_count))
        return Fail(out_error, "AppleCheckpointKeylockerInitializationRequiresEmpty");
    if ((locker_start == 0) != (locker_count == 0))
        return Fail(out_error, "AppleCheckpointKeylockerRangeInvalid");
    if (locker_start != 0)
    {
        if ((!initialize_keylocker && (!original_locker_start || !original_locker_count ||
            original_locker_start >= nxsb.block_count || original_locker_count > nxsb.block_count - original_locker_start ||
            locker_count != original_locker_count)) || locker_count > 16 || locker_start >= nxsb.block_count ||
            locker_count > nxsb.block_count - locker_start)
            return Fail(out_error, "AppleCheckpointKeylockerRangeInvalid");
        const auto overlaps = [&](const auto& prior) {
            const auto start = catalog::ReadU64LE(prior.superblock_bytes, 0x510).value_or(0);
            const auto count = catalog::ReadU64LE(prior.superblock_bytes, 0x518).value_or(0);
            return count && start < nxsb.block_count && count <= nxsb.block_count - start &&
                locker_start < start + count && start < locker_start + locker_count;
        };
        if (overlaps(checkpoint) || std::any_of(retained.begin(), retained.end(), overlaps))
            return Fail(out_error, "AppleCheckpointKeylockerRetentionOverlap");
        for (const auto& prior : retained)
        {
            const auto start = catalog::ReadU64LE(prior.superblock_bytes, 0x510).value_or(0);
            const auto count = catalog::ReadU64LE(prior.superblock_bytes, 0x518).value_or(0);
            if ((start == 0) != (count == 0) || count > 16 ||
                start >= nxsb.block_count || count > nxsb.block_count - start)
                return Fail(out_error, "AppleCheckpointKeylockerRangeInvalid");
        }
    }
    if (request.container_object_map_oid != 0)
    {
        const auto replacement = std::find_if(
            request.allocator_owned_writes.begin(),
            request.allocator_owned_writes.end(),
            [&request](const auto& write) {
                return write.physical_block == request.container_object_map_oid;
            });
        if (request.container_object_map_oid >= nxsb.block_count ||
            replacement == request.allocator_owned_writes.end() ||
            replacement->bytes.size() < nxsb.block_size ||
            catalog::ReadU64LE(replacement->bytes, 0x08).value_or(0) !=
                request.container_object_map_oid ||
            catalog::ReadU64LE(replacement->bytes, 0x10).value_or(0) !=
                request.transaction_xid ||
            catalog::ReadU32LE(replacement->bytes, 0x18).value_or(0) !=
                (catalog::kObjectPhysical | catalog::kObjectTypeOmap) ||
            !catalog::VerifyObjectChecksum(
                replacement->bytes, nxsb.block_size))
        {
            return Fail(out_error, "AppleCheckpointContainerOmapInvalid");
        }
    }

    std::unordered_map<std::uint64_t, const catalog::CheckpointMapping*>
        old_mappings;
    for (const auto& mapping : checkpoint.mappings)
    {
        if (!old_mappings.emplace(mapping.object_id, &mapping).second)
        {
            return Fail(out_error, "AppleCheckpointExistingMappingInvalid");
        }
    }
    std::unordered_set<std::uint64_t> retired;
    for (const auto object_id : request.retired_ephemeral_object_ids)
    {
        if (object_id == 0 || object_id == nxsb.spaceman_oid ||
            object_id == nxsb.reaper_oid ||
            old_mappings.find(object_id) == old_mappings.end() ||
            !retired.insert(object_id).second)
        {
            return Fail(out_error,
                "AppleCheckpointEphemeralRetirementInvalid");
        }
    }
    std::unordered_map<std::uint64_t, const AppleCheckpointEphemeralObject*>
        supplied;
    for (const auto& object : request.ephemeral_objects)
    {
        if (!supplied.emplace(object.object.object_id, &object).second ||
            retired.find(object.object.object_id) != retired.end())
        {
            return Fail(out_error,
                retired.find(object.object.object_id) != retired.end()
                    ? "AppleCheckpointEphemeralRetirementInvalid"
                    : "AppleCheckpointEphemeralObjectDuplicate");
        }
        if (!ValidateEphemeralObject(
                object, nxsb.block_size, request.transaction_xid))
        {
            return Fail(out_error, "AppleCheckpointEphemeralObjectInvalid");
        }
        const auto old = old_mappings.find(object.object.object_id);
        if (old != old_mappings.end())
        {
            if (old->second->type != object.object.type ||
                old->second->subtype != object.object.subtype ||
                old->second->file_system_oid != object.file_system_oid)
            {
                return Fail(out_error, "AppleCheckpointEphemeralIdentityChanged");
            }
        }
        else if (object.object.object_id < nxsb.next_oid ||
                 object.object.object_id >= request.next_object_id)
        {
            return Fail(out_error, "AppleCheckpointNewObjectIdUnreserved");
        }
    }
    for (const auto& [object_id, mapping] : old_mappings)
    {
        (void)mapping;
        if (supplied.find(object_id) == supplied.end() &&
            retired.find(object_id) == retired.end())
        {
            return Fail(out_error, "AppleCheckpointEphemeralSetIncomplete");
        }
    }
    if (supplied.empty() || supplied.find(nxsb.spaceman_oid) == supplied.end() ||
        (nxsb.reaper_oid != 0 && supplied.find(nxsb.reaper_oid) == supplied.end()))
    {
        return Fail(out_error, "AppleCheckpointEphemeralSetIncomplete");
    }

    std::vector<const AppleCheckpointEphemeralObject*> ordered;
    ordered.reserve(supplied.size());
    for (const auto& mapping : checkpoint.mappings)
    {
        const auto object = supplied.find(mapping.object_id);
        if (object != supplied.end())
        {
            ordered.push_back(object->second);
        }
    }
    std::vector<const AppleCheckpointEphemeralObject*> additions;
    for (const auto& object : request.ephemeral_objects)
    {
        if (old_mappings.find(object.object.object_id) == old_mappings.end())
        {
            additions.push_back(&object);
        }
    }
    std::sort(additions.begin(), additions.end(), [](const auto* left,
                                                       const auto* right) {
        return left->object.object_id < right->object.object_id;
    });
    ordered.insert(ordered.end(), additions.begin(), additions.end());

    std::uint64_t data_blocks64 = 0;
    for (const auto* object : ordered)
    {
        const auto blocks = object->bytes.size() / nxsb.block_size;
        if (blocks > std::numeric_limits<std::uint32_t>::max() - data_blocks64)
        {
            return Fail(out_error, "AppleCheckpointDataRingExhausted");
        }
        data_blocks64 += blocks;
    }
    if (data_blocks64 == 0 || data_blocks64 > nxsb.xp_data_block_count ||
        data_blocks64 > nxsb.xp_data_block_count - nxsb.xp_data_len)
    {
        return Fail(out_error, "AppleCheckpointDataRingExhausted");
    }
    const auto data_blocks = static_cast<std::uint32_t>(data_blocks64);
    const auto data_index = nxsb.xp_data_next;
    if (RingRangesOverlap(data_index, data_blocks, nxsb.xp_data_index,
            nxsb.xp_data_len, nxsb.xp_data_block_count))
    {
        return Fail(out_error, "AppleCheckpointDataRingOverlap");
    }
    for (const auto& historical : retained)
    {
        const auto& old = historical.superblock;
        if (RingRangesOverlap(data_index, data_blocks, old.xp_data_index,
                old.xp_data_len, nxsb.xp_data_block_count))
        {
            return Fail(out_error, "AppleCheckpointDataRetentionExhausted");
        }
    }

    const auto mappings_per_block = static_cast<std::uint32_t>(
        (nxsb.block_size - 0x28) / kCheckpointMappingBytes);
    const auto map_blocks64 =
        (ordered.size() + mappings_per_block - 1) / mappings_per_block;
    if (mappings_per_block == 0 || map_blocks64 == 0 ||
        map_blocks64 >= nxsb.xp_desc_block_count)
    {
        return Fail(out_error, "AppleCheckpointDescriptorRingExhausted");
    }
    const auto descriptor_length = static_cast<std::uint32_t>(map_blocks64 + 1);
    if (descriptor_length > nxsb.xp_desc_block_count - nxsb.xp_desc_len)
    {
        return Fail(out_error, "AppleCheckpointDescriptorRingExhausted");
    }
    const auto descriptor_index = nxsb.xp_desc_next;
    if (RingRangesOverlap(descriptor_index, descriptor_length,
            nxsb.xp_desc_index, nxsb.xp_desc_len,
            nxsb.xp_desc_block_count))
    {
        return Fail(out_error, "AppleCheckpointDescriptorRingOverlap");
    }
    for (const auto& historical : retained)
    {
        const auto& old = historical.superblock;
        if (RingRangesOverlap(descriptor_index, descriptor_length,
                old.xp_desc_index, old.xp_desc_len, nxsb.xp_desc_block_count))
        {
            return Fail(out_error, "AppleCheckpointDescriptorRetentionExhausted");
        }
    }

    AppleCheckpointPublicationPlan plan;
    plan.block_size = nxsb.block_size;
    plan.expected_checkpoint_xid = request.expected_checkpoint_xid;
    plan.transaction_xid = request.transaction_xid;
    plan.next_object_id = request.next_object_id;
    if (!AddGuard(source, 0, nxsb.block_size, plan.guard_blocks) ||
        !AddCheckpointGuards(source, checkpoint, plan.guard_blocks))
    {
        return Fail(out_error, "AppleCheckpointGuardUnreadable");
    }
    for (const auto& historical : retained)
    {
        if (!AddCheckpointGuards(source, historical, plan.guard_blocks))
        {
            return Fail(out_error, "AppleCheckpointGuardUnreadable");
        }
    }
    if (locker_start != 0)
    {
        for (std::uint64_t i = 0; i < original_locker_count; ++i)
            if (!AddGuard(source, original_locker_start + i, nxsb.block_size, plan.guard_blocks))
                return Fail(out_error, "AppleCheckpointKeylockerGuardUnreadable");
        for (const auto& prior : retained)
            for (std::uint64_t i = 0,
                start = catalog::ReadU64LE(prior.superblock_bytes, 0x510).value_or(0),
                count = catalog::ReadU64LE(prior.superblock_bytes, 0x518).value_or(0); i < count; ++i)
                if (!AddGuard(source, start + i, nxsb.block_size, plan.guard_blocks))
                    return Fail(out_error, "AppleCheckpointKeylockerGuardUnreadable");
    }

    std::unordered_set<std::uint64_t> planned_blocks;
    for (const auto block : capacity_payload)
    {
        if (!capacity_only || block == 0 || block >= nxsb.block_count ||
            AreaContains(nxsb.xp_desc_base_block, nxsb.xp_desc_block_count, block) ||
            AreaContains(nxsb.xp_data_base_block, nxsb.xp_data_block_count, block) ||
            !planned_blocks.insert(block).second)
            return Fail(out_error, "AppleCheckpointAllocatedWriteInvalid");
    }
    for (const auto& allocation : request.allocator_owned_writes)
    {
        if (allocation.physical_block == 0 || allocation.bytes.empty() ||
            allocation.bytes.size() % nxsb.block_size != 0)
        {
            return Fail(out_error, "AppleCheckpointAllocatedWriteInvalid");
        }
        const auto blocks = allocation.bytes.size() / nxsb.block_size;
        if (allocation.physical_block >= nxsb.block_count ||
            blocks > nxsb.block_count - allocation.physical_block)
        {
            return Fail(out_error, "AppleCheckpointAllocatedWriteInvalid");
        }
        for (std::size_t ordinal = 0; ordinal < blocks; ++ordinal)
        {
            const auto block = allocation.physical_block + ordinal;
            if (AreaContains(nxsb.xp_desc_base_block,
                    nxsb.xp_desc_block_count, block) ||
                AreaContains(nxsb.xp_data_base_block,
                    nxsb.xp_data_block_count, block) ||
                !planned_blocks.insert(block).second)
            {
                return Fail(out_error, "AppleCheckpointAllocatedWriteInvalid");
            }
            AppleCheckpointPlannedWrite write;
            write.kind = AppleCheckpointWriteKind::AllocatorOwned;
            write.physical_block = block;
            const auto begin = allocation.bytes.begin() +
                static_cast<std::ptrdiff_t>(ordinal * nxsb.block_size);
            write.bytes.assign(begin, begin + nxsb.block_size);
            plan.before_superblock_writes.push_back(std::move(write));
        }
    }

    if (locker_start != 0)
        for (std::uint64_t i = 0; i < locker_count; ++i)
            if (!planned_blocks.contains(locker_start + i))
                return Fail(out_error, "AppleCheckpointKeylockerUnstaged");
    plan.published_checkpoint.mappings.reserve(ordered.size());
    std::uint32_t data_cursor = 0;
    for (const auto* object : ordered)
    {
        const auto first_relative = static_cast<std::uint32_t>(
            (static_cast<std::uint64_t>(data_index) + data_cursor) %
            nxsb.xp_data_block_count);
        catalog::CheckpointMapping mapping;
        mapping.type = object->object.type;
        mapping.subtype = object->object.subtype;
        mapping.size_bytes = object->object.size_bytes;
        mapping.file_system_oid = object->file_system_oid;
        mapping.object_id = object->object.object_id;
        mapping.physical_block = nxsb.xp_data_base_block + first_relative;
        plan.published_checkpoint.mappings.push_back(mapping);
        const auto blocks = object->bytes.size() / nxsb.block_size;
        for (std::size_t ordinal = 0; ordinal < blocks; ++ordinal)
        {
            const auto relative = static_cast<std::uint32_t>(
                (static_cast<std::uint64_t>(first_relative) + ordinal) %
                nxsb.xp_data_block_count);
            AppleCheckpointPlannedWrite write;
            write.kind = AppleCheckpointWriteKind::CheckpointData;
            write.physical_block = nxsb.xp_data_base_block + relative;
            write.object_id = object->object.object_id;
            const auto begin = object->bytes.begin() +
                static_cast<std::ptrdiff_t>(ordinal * nxsb.block_size);
            write.bytes.assign(begin, begin + nxsb.block_size);
            plan.before_superblock_writes.push_back(std::move(write));
            ++data_cursor;
        }
    }

    plan.published_checkpoint.checkpoint_map_blocks.reserve(map_blocks64);
    for (std::size_t map_index = 0; map_index < map_blocks64; ++map_index)
    {
        const auto relative = static_cast<std::uint32_t>(
            (static_cast<std::uint64_t>(descriptor_index) + map_index) %
            nxsb.xp_desc_block_count);
        const auto physical_block = nxsb.xp_desc_base_block + relative;
        std::vector<std::byte> bytes(nxsb.block_size, std::byte{0});
        PutU64(bytes, 0x08, physical_block);
        PutU64(bytes, 0x10, request.transaction_xid);
        PutU32(bytes, 0x18,
            catalog::kObjectPhysical | catalog::kObjectTypeCheckpointMap);
        PutU32(bytes, 0x20, map_index + 1 == map_blocks64 ? 1u : 0u);
        const auto first = map_index * mappings_per_block;
        const auto count = (std::min<std::size_t>)(
            mappings_per_block,
            plan.published_checkpoint.mappings.size() - first);
        PutU32(bytes, 0x24, static_cast<std::uint32_t>(count));
        for (std::size_t index = 0; index < count; ++index)
        {
            const auto& mapping =
                plan.published_checkpoint.mappings[first + index];
            const auto offset = 0x28 + index * kCheckpointMappingBytes;
            PutU32(bytes, offset, mapping.type);
            PutU32(bytes, offset + 0x04, mapping.subtype);
            PutU32(bytes, offset + 0x08, mapping.size_bytes);
            PutU64(bytes, offset + 0x10, mapping.file_system_oid);
            PutU64(bytes, offset + 0x18, mapping.object_id);
            PutU64(bytes, offset + 0x20, mapping.physical_block);
        }
        if (!FinalizeAppleObjectChecksum(bytes, out_error))
        {
            return false;
        }
        AppleCheckpointPlannedWrite write;
        write.kind = AppleCheckpointWriteKind::CheckpointMap;
        write.physical_block = physical_block;
        write.object_id = physical_block;
        write.bytes = std::move(bytes);
        plan.before_superblock_writes.push_back(std::move(write));
        plan.published_checkpoint.checkpoint_map_blocks.push_back(physical_block);
    }

    auto superblock = checkpoint.superblock_bytes;
    PutU64(superblock, 0x10, request.transaction_xid);
    PutU64(superblock, 0x58, request.next_object_id);
    PutU64(superblock, 0x60, request.transaction_xid + 1);
    if (request.container_object_map_oid != 0)
    {
        PutU64(superblock, 0xA0, request.container_object_map_oid);
    }
    if (locker_start != 0)
    {
        PutU64(superblock, 0x510, locker_start);
        PutU64(superblock, 0x518, locker_count);
    }
    PutU32(superblock, 0x80, (descriptor_index + descriptor_length) %
        nxsb.xp_desc_block_count);
    PutU32(superblock, 0x84,
        (data_index + data_blocks) % nxsb.xp_data_block_count);
    PutU32(superblock, 0x88, descriptor_index);
    PutU32(superblock, 0x8C, descriptor_length);
    PutU32(superblock, 0x90, data_index);
    PutU32(superblock, 0x94, data_blocks);
    if (!FinalizeAppleObjectChecksum(superblock, out_error))
    {
        return false;
    }
    const auto parsed = catalog::ParseNxSuperblock(superblock);
    const auto expected_container_omap = request.container_object_map_oid != 0 ?
        request.container_object_map_oid : nxsb.omap_oid;
    if (!parsed.has_value() || parsed->omap_oid != expected_container_omap ||
        catalog::ReadU64LE(superblock, 0x510).value_or(0) != (locker_start ? locker_start : original_locker_start) ||
        catalog::ReadU64LE(superblock, 0x518).value_or(0) != (locker_start ? locker_count : original_locker_count))
    {
        return Fail(out_error, "AppleCheckpointSuperblockInvalid");
    }
    const auto superblock_relative = static_cast<std::uint32_t>(
        (static_cast<std::uint64_t>(descriptor_index) + map_blocks64) %
        nxsb.xp_desc_block_count);
    plan.superblock_write.kind = AppleCheckpointWriteKind::CheckpointSuperblock;
    plan.superblock_write.physical_block =
        nxsb.xp_desc_base_block + superblock_relative;
    plan.superblock_write.object_id = parsed->object_id;
    plan.superblock_write.bytes = superblock;
    plan.published_checkpoint.superblock = parsed.value();
    plan.published_checkpoint.superblock_physical_block =
        plan.superblock_write.physical_block;
    plan.published_checkpoint.superblock_bytes = std::move(superblock);
    if (locker_start != 0)
    {
        const auto protected_destination = [&](std::uint64_t block) {
            if (AreaContains(original_locker_start, static_cast<std::uint32_t>(original_locker_count), block)) return true;
            return std::any_of(retained.begin(), retained.end(), [&](const auto& prior) {
                return AreaContains(catalog::ReadU64LE(prior.superblock_bytes, 0x510).value_or(0),
                    static_cast<std::uint32_t>(catalog::ReadU64LE(prior.superblock_bytes, 0x518).value_or(0)), block);
            });
        };
        // Guards detect source drift; they cannot make a write into an old
        // owner's bag safe. Exclude allocator and generated ring destinations
        // alike before exposing any executable publication.
        if (protected_destination(plan.superblock_write.physical_block) ||
            std::any_of(plan.before_superblock_writes.begin(), plan.before_superblock_writes.end(),
                [&](const auto& write) { return protected_destination(write.physical_block); }))
            return Fail(out_error, "AppleCheckpointKeylockerDestinationOverlap");
    }
    if (capacity_only)
    {
        // Execute rejects this before reading guards or issuing any I/O.
        plan.superblock_write.bytes.clear();
    }
    out_plan = std::move(plan);
    return true;
}

bool capacity_detail::PlanPublication(const catalog::RandomAccessSource& source,
    const catalog::ContainerCheckpointView& checkpoint,
    const AppleCheckpointPublicationRequest& request,
    std::span<const std::uint64_t> payload_blocks,
    AppleCheckpointPublicationPlan& out_plan, std::string& error)
{
    return PlanAppleCheckpointPublicationWithKeylocker(source, checkpoint, request,
        out_plan, error, {}, false, payload_blocks, true);
}

bool PlanAppleCheckpointPublication(
    const catalog::RandomAccessSource& source,
    const catalog::ContainerCheckpointView& checkpoint,
    const AppleCheckpointPublicationRequest& request,
    AppleCheckpointPublicationPlan& out_plan,
    std::string& out_error,
    const AppleCheckpointKeylockerReplacement& keylocker)
{
    return PlanAppleCheckpointPublicationWithKeylocker(source, checkpoint, request, out_plan,
        out_error, keylocker, false);
}

bool PlanAppleCheckpointKeylockerInitialization(
    const catalog::RandomAccessSource& source,
    const catalog::ContainerCheckpointView& checkpoint,
    const AppleCheckpointPublicationRequest& request,
    AppleCheckpointPublicationPlan& out_plan,
    std::string& out_error,
    const AppleCheckpointKeylockerInitialization& keylocker)
{
    return PlanAppleCheckpointPublicationWithKeylocker(source, checkpoint, request, out_plan,
        out_error, {keylocker.start_block, keylocker.block_count}, true);
}

bool PlanAppleCheckpointPublication(
    const catalog::RandomAccessSource& source,
    const catalog::ContainerCheckpointView& checkpoint,
    const AppleCheckpointPublicationRequest& request,
    AppleCheckpointPublicationPlan& out_plan,
    std::string& out_error)
{
    return PlanAppleCheckpointPublication(source, checkpoint, request, out_plan, out_error, {});
}

bool ExecuteAppleCheckpointPublication(
    AppleCheckpointWriteTarget& target,
    const AppleCheckpointPublicationPlan& plan,
    std::string& out_error,
    const AppleCheckpointStageHook& stage_hook)
{
    out_error.clear();
    if (plan.block_size == 0 || plan.transaction_xid == 0 ||
        plan.before_superblock_writes.empty() ||
        plan.superblock_write.kind !=
            AppleCheckpointWriteKind::CheckpointSuperblock ||
        plan.superblock_write.bytes.size() != plan.block_size)
    {
        return Fail(out_error, "AppleCheckpointPublicationPlanInvalid");
    }
    if (!VerifyGuards(target, plan))
    {
        return Fail(out_error, "AppleCheckpointGuardChanged");
    }
    if (!AllowStage(stage_hook, "before-apple-device-write", out_error))
    {
        return false;
    }
    if (std::any_of(plan.before_superblock_writes.begin(), plan.before_superblock_writes.end(),
            [&](const auto& write) { return write.bytes.size() != plan.block_size; }) ||
        !target.WriteBlocks(plan.before_superblock_writes))
    {
        return Fail(out_error, "AppleCheckpointWriteFailed");
    }
    if (!AllowStage(
            stage_hook, "before-apple-prepublication-flush", out_error))
    {
        return false;
    }
    if (!target.Flush())
    {
        return Fail(out_error, "AppleCheckpointPrepublicationFlushFailed");
    }
    if (!VerifyBatchAfterFlush(target, plan.before_superblock_writes, plan.block_size, out_error))
        return false;
    if (!VerifyGuards(target, plan))
    {
        return Fail(out_error, "AppleCheckpointGuardChanged");
    }
    // Fusion tier-2 anchor mirror, when the plan carries one: written and
    // verified after the prepublication flush, then flushed again before the
    // main switch. Crash order is deliberate: an interruption here leaves the
    // tier-2 anchor at most one generation ahead, which the bind layer
    // tolerates by selecting the main anchor; the main switch stays last so
    // a main-ahead skew (unrecoverable without repair) cannot occur.
    if (plan.fusion_tier2_anchor_write.has_value())
    {
        if (!AllowStage(stage_hook, "before-apple-fusion-anchor-mirror", out_error))
        {
            return false;
        }
        if (!WriteAndVerify(target, *plan.fusion_tier2_anchor_write, plan.block_size, out_error))
        {
            return false;
        }
        if (!target.Flush())
        {
            return Fail(out_error, "AppleCheckpointFusionAnchorFlushFailed");
        }
        if (!VerifyBatchAfterFlush(target, std::span(&*plan.fusion_tier2_anchor_write, 1), plan.block_size, out_error))
            return false;
    }
    if (!AllowStage(
            stage_hook, "before-apple-checkpoint-switch", out_error))
    {
        return false;
    }
    if (!WriteAndVerify(
            target, plan.superblock_write, plan.block_size, out_error))
    {
        return false;
    }
    // Fusion main anchor: the same new superblock bytes at block 0. Fusion
    // rebinds require the anchor to match the selected checkpoint, while
    // single-store selection ignores block-zero content; this write runs only
    // for Fusion plans (mirror present), so single-store behavior is
    // unchanged. It shares the switch's flush barrier: a crash before the
    // barrier leaves the old generation rebindable, and anything after is
    // forward-recovery territory (journal replay re-issues the identical
    // bytes). The tier-2 anchor was already mirrored and flushed pre-switch.
    if (plan.fusion_tier2_anchor_write.has_value())
    {
        auto anchor = plan.superblock_write;
        anchor.physical_block = 0;
        if (!WriteAndVerify(target, anchor, plan.block_size, out_error))
        {
            return false;
        }
    }
    if (!AllowStage(stage_hook, "before-apple-final-flush", out_error))
    {
        return false;
    }
    if (!target.Flush())
    {
        return Fail(out_error, "AppleCheckpointFinalFlushFailed");
    }
    if (!VerifyBatchAfterFlush(target, plan.before_superblock_writes, plan.block_size, out_error) ||
        !VerifyBatchAfterFlush(target, std::span(&plan.superblock_write, 1), plan.block_size, out_error))
        return false;
    if (plan.fusion_tier2_anchor_write)
    {
        auto anchor = plan.superblock_write;
        anchor.physical_block = 0;
        if (!VerifyBatchAfterFlush(target, std::span(&*plan.fusion_tier2_anchor_write, 1), plan.block_size, out_error) ||
            !VerifyBatchAfterFlush(target, std::span(&anchor, 1), plan.block_size, out_error))
            return false;
    }
    return true;
}

bool ExecuteAppleCheckpointPublication(
    BlockDevice& device,
    const AppleCheckpointPublicationPlan& plan,
    std::string& out_error,
    const AppleCheckpointStageHook& stage_hook)
{
    BlockDeviceCheckpointTarget target(device);
    return ExecuteAppleCheckpointPublication(
        target, plan, out_error, stage_hook);
}

} // namespace apfsaccess::rw
