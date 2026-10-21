bool ReclaimFusionTier2Range(catalog::AppleSpacemanView& view,
    std::uint64_t physical_block, std::uint64_t block_count,
    std::uint64_t transaction_xid, std::set<std::size_t>& touched_chunks, std::string& error)
{
    const auto block_size = catalog::ReadU32LE(view.bytes,0x20).value_or(0);
    if (!block_size || catalog::kFusionTier2ByteAddress % block_size)
        return Fail(error,"FusionReclaimBlockSizeInvalid");
    const auto base = catalog::kFusionTier2ByteAddress / block_size;
    auto& device = view.devices[1];
    if (!device.block_count || physical_block < base ||
        !RangeFits(physical_block-base,block_count,device.block_count))
        return Fail(error,"FusionReclaimTier2RangeInvalid");
    for (std::uint64_t i = 0; i < block_count; ++i) {
        const auto block = physical_block+i;
        std::size_t chunk_index = 0;
        if (!FindChunkIndex(view,block,chunk_index)) return Fail(error,"FusionReclaimTier2ChunkMissing");
        auto& chunk = view.chunks[chunk_index];
        if (chunk.device_index != 1 || block-base < chunk.start_block)
            return Fail(error,"FusionReclaimTier2OwnerMismatch");
        const auto bit = block-base-chunk.start_block;
        if (bit >= chunk.block_count || chunk.allocation_bitmap.empty() || !BitSet(chunk.allocation_bitmap,bit) ||
            chunk.free_count >= chunk.block_count || device.free_count >= device.block_count)
            return Fail(error,"FusionReclaimTier2OwnerMismatch");
        ClearBit(chunk.allocation_bitmap,bit);
        ++chunk.free_count; ++device.free_count;
        chunk.xid = transaction_xid;
        touched_chunks.insert(chunk_index);
    }
    return true;
}
