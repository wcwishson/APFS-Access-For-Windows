#include "ApfsFusionSpaceman.h"

namespace apfsaccess::catalog
{
namespace
{
bool Fail(std::string& error, const char* reason) { error = reason; return false; }
} // namespace

bool LoadFusionSpacemanOwnership(const ApfsFusionStore& store,
    FusionSpacemanOwnership& out_ownership, std::string& out_error)
{
    out_ownership = {};
    out_error.clear();
    const auto& checkpoint = store.Checkpoint();
    const auto& nx = checkpoint.superblock;
    const auto bs = nx.block_size;
    if (!bs || (bs & (bs - 1)) || bs < 4096 || bs > 65536 || !nx.xid ||
        !nx.spaceman_oid || !nx.block_count)
        return Fail(out_error, "FusionOwnershipCheckpointInvalid");
    const auto& members = store.Members();
    const auto main_blocks = members[0].total_blocks;
    const auto tier2_blocks = members[1].total_blocks;
    if (!main_blocks || !tier2_blocks ||
        tier2_blocks > nx.block_count - main_blocks ||
        main_blocks + tier2_blocks != nx.block_count)
        return Fail(out_error, "FusionOwnershipCombinedBlockCountMismatch");
    const CheckpointMapping* spaceman_mapping = nullptr;
    for (const auto& mapping : checkpoint.mappings)
    {
        if (mapping.object_id == nx.spaceman_oid)
        {
            spaceman_mapping = &mapping;
            break;
        }
    }
    if (!spaceman_mapping ||
        spaceman_mapping->type != (kObjectEphemeral | kObjectTypeSpaceman) ||
        spaceman_mapping->subtype != 0 || spaceman_mapping->file_system_oid != 0 ||
        spaceman_mapping->size_bytes != bs)
        return Fail(out_error, "FusionOwnershipSpacemanMappingInvalid");
    std::vector<std::byte> bytes;
    std::string read_error;
    if (!store.ReadMetadata(spaceman_mapping->physical_block,
            kObjectEphemeral | kObjectTypeSpaceman, 0, nx.spaceman_oid, nx.xid,
            bytes, read_error))
    {
        out_error = "FusionOwnershipSpacemanUnreadable:" + read_error;
        return false;
    }
    // Header geometry uses the exact bind-time formulas: only genuinely
    // formatted spaceman objects validate, never zero-filled shapes.
    if (ReadU32LE(bytes, 0x20).value_or(0) != bs)
        return Fail(out_error, "FusionOwnershipSpacemanBlockSizeMismatch");
    const auto chunk_blocks = ReadU32LE(bytes, 0x24).value_or(0);
    const auto chunks_per_cib = ReadU32LE(bytes, 0x28).value_or(0);
    const auto entries_per_cab = ReadU32LE(bytes, 0x2C).value_or(0);
    if (chunk_blocks != std::uint64_t(bs) * 8 ||
        chunks_per_cib != (bs - 0x28) / 0x20 ||
        entries_per_cab != (bs - 0x28) / 8)
        return Fail(out_error, "FusionOwnershipSpacemanChunkGeometryInvalid");
    if ((ReadU32LE(bytes, 0x90).value_or(~0u) & ~1u) != 0)
        return Fail(out_error, "FusionOwnershipSpacemanStructureUnsupported");
    FusionSpacemanOwnership view;
    view.block_size = bs;
    view.checkpoint_xid = nx.xid;
    view.combined_block_count = nx.block_count;
    const std::uint64_t expected_blocks[2] = {main_blocks, tier2_blocks};
    for (std::size_t i = 0; i < 2; ++i)
    {
        const auto base = 0x30 + i * 0x30;
        auto& device = i ? view.tier2_ : view.main_;
        device.block_count = ReadU64LE(bytes, base).value_or(0);
        device.chunk_count = ReadU64LE(bytes, base + 8).value_or(0);
        device.cib_count = ReadU32LE(bytes, base + 0x10).value_or(0);
        device.cab_count = ReadU32LE(bytes, base + 0x14).value_or(0);
        device.free_count = ReadU64LE(bytes, base + 0x18).value_or(UINT64_MAX);
        if (device.block_count != expected_blocks[i])
            return Fail(out_error, "FusionOwnershipMemberGeometryMismatch");
        const auto chunks = device.block_count / chunk_blocks +
            (device.block_count % chunk_blocks != 0);
        const auto cibs = chunks / chunks_per_cib + (chunks % chunks_per_cib != 0);
        const auto cibs_per_cab = (bs - 0x28) / 8;
        const auto cab_groups = cibs / cibs_per_cab + (cibs % cibs_per_cab != 0);
        const auto cabs = cab_groups == 1 ? 0 : cab_groups;
        if (device.chunk_count != chunks || device.cib_count != cibs ||
            device.cab_count != cabs || device.free_count > device.block_count)
            return Fail(out_error, "FusionOwnershipMemberGeometryMismatch");
        if (ReadU32LE(bytes, base + 0x24).value_or(~0u) != 0u ||
            ReadU64LE(bytes, base + 0x28).value_or(UINT64_MAX) != 0)
            return Fail(out_error, "FusionOwnershipMemberReservedFieldsUnsupported");
    }
    // Checkpoint areas stay main-local and disjoint: tier-2 never hosts
    // checkpoint metadata, so a torn member cannot alias it.
    const auto desc_base = nx.xp_desc_base_block;
    const auto desc_count = nx.xp_desc_block_count;
    const auto data_base = nx.xp_data_base_block;
    const auto data_count = nx.xp_data_block_count;
    const auto main_local = [&](std::uint64_t block, std::uint64_t count) {
        return count && count <= 65536 && block && block < main_blocks &&
            count <= main_blocks - block; };
    if (!main_local(desc_base, desc_count) || !main_local(data_base, data_count))
        return Fail(out_error, "FusionOwnershipCheckpointAreaInvalid");
    const auto overlaps = [](std::uint64_t a, std::uint64_t ac, std::uint64_t b, std::uint64_t bc) {
        return a <= b ? b - a < ac : a - b < bc; };
    if (overlaps(desc_base, desc_count, data_base, data_count))
        return Fail(out_error, "FusionOwnershipCheckpointAreasOverlap");
    view.desc_base_block = desc_base;
    view.desc_block_count = desc_count;
    view.data_base_block = data_base;
    view.data_block_count = data_count;
    out_ownership = view;
    return true;
}
} // namespace apfsaccess::catalog
