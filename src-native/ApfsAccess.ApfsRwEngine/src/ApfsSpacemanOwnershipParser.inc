// Included only inside ApfsFormat.cpp's private namespace. Both entry points
// share checksum, object identity, ephemeral B-tree, bitmap and budget machinery.
bool ValidateFusionAllocationGraph(const ApfsFusionStore& store,
    const AppleSpacemanView& view, const std::unordered_set<std::uint64_t>& live,
    std::string& error)
{
    const auto& nx = store.Checkpoint().superblock;
    const auto& pool = view.internal_pool;
    const auto tier_base = kFusionTier2ByteAddress / nx.block_size;
    const auto allocated = [&](std::uint64_t encoded) {
        const std::size_t device = encoded >= tier_base ? 1 : 0;
        const auto local = encoded - (device ? tier_base : 0);
        if (local >= view.devices[device].block_count) return false;
        const auto index = (device ? view.devices[0].chunk_count : 0) + local / view.blocks_per_chunk;
        if (index >= view.chunks.size()) return false;
        const auto& chunk = view.chunks[static_cast<std::size_t>(index)];
        return chunk.device_index == device && local >= chunk.start_block &&
            local - chunk.start_block < chunk.block_count &&
            BitmapBitSet(chunk.allocation_bitmap, local - chunk.start_block);
    };
    // These ranges cannot contain allocator metadata or deferred main/tier frees.
    std::vector<std::pair<std::uint64_t, std::uint64_t>> reserved = {
        {0, 1}, {tier_base, 1},
        {nx.xp_desc_base_block, nx.xp_desc_block_count},
        {nx.xp_data_base_block, nx.xp_data_block_count},
        {nx.fusion_writeback_start, nx.fusion_writeback_blocks},
        {nx.fusion_middle_tree_oid, 1},
        {pool.bitmap_base_block, pool.bitmap_block_count},
        {pool.base_block, pool.block_count}
    };
    std::sort(reserved.begin(), reserved.end());
    for (std::size_t i = 0; i < reserved.size(); ++i)
    {
        const auto [base, count] = reserved[i];
        FusionRoute route;
        if (count > UINT64_MAX / nx.block_size ||
            !store.MapPhysical(base, 0, count * nx.block_size, route, error))
        { error = "FusionAllocationReservedRangeInvalid"; return false; }
        if (i && base - reserved[i - 1].first < reserved[i - 1].second)
        { error = "FusionAllocationReservedRangeOverlap"; return false; }
        if (!Materialize(store, count, 0)) return false;
        for (std::uint64_t block = base; block < base + count; ++block)
            if (!allocated(block))
            { error = "FusionAllocationReservedBlockFree"; return false; }
    }
    for (const auto block : live)
        if (!allocated(block))
        { error = "FusionAllocationMetadataBlockFree"; return false; }
    for (const auto& bitmap : pool.active_bitmaps)
        if (live.contains(bitmap.physical_block))
        { error = "FusionAllocationBitmapOwnershipOverlap"; return false; }
    for (std::size_t q = 0; q < view.free_queues.size(); ++q)
        for (const auto& entry : view.free_queues[q].entries)
            for (const auto& [base, count] : reserved)
            {
                if (q == 0 && base == pool.base_block) continue;
                if (entry.physical_block < base + count && base < entry.physical_block + entry.block_count)
                { error = "FusionAllocationFreeQueueReservedOverlap"; return false; }
            }
    return true;
}

bool LoadAppleSpacemanOwnershipViewImpl(
    const RandomAccessSource& source,
    const ContainerCheckpointView& checkpoint,
    AppleSpacemanView& out_view,
    std::string& out_error,
    const ApfsFusionStore* fusion = nullptr)
{
    out_view = AppleSpacemanView{};
    const auto& nxsb = checkpoint.superblock;
    if (nxsb.block_size < 4096 || nxsb.block_count == 0 ||
        nxsb.spaceman_oid == 0 || nxsb.xid == 0)
    {
        out_error = "AppleSpacemanCheckpointInvalid";
        return false;
    }
    const CheckpointMapping* spaceman_mapping =
        FindCheckpointMapping(checkpoint, nxsb.spaceman_oid);
    if (spaceman_mapping == nullptr)
    {
        out_error = "AppleSpacemanUnmapped";
        return false;
    }
    if (spaceman_mapping->file_system_oid != 0 ||
        spaceman_mapping->type != (kObjectEphemeral | kObjectTypeSpaceman) ||
        spaceman_mapping->subtype != 0)
    {
        out_error = "AppleSpacemanMappingInvalid";
        return false;
    }
    if (!ReadAppleObject(source, nxsb.block_size,
            spaceman_mapping->physical_block, spaceman_mapping->size_bytes,
            nxsb.spaceman_oid, nxsb.xid, kObjectEphemeral,
            kObjectTypeSpaceman, 0, "AppleSpaceman", out_view.object,
            out_view.bytes, out_error, fusion != nullptr))
    {
        return false;
    }
    if (out_view.bytes.size() < 0x158 ||
        ReadU32LE(out_view.bytes, 0x20).value_or(0) != nxsb.block_size)
    {
        out_error = "AppleSpacemanBlockSizeMismatch";
        return false;
    }

    out_view.blocks_per_chunk = ReadU32LE(out_view.bytes, 0x24).value_or(0);
    out_view.chunks_per_cib = ReadU32LE(out_view.bytes, 0x28).value_or(0);
    out_view.cibs_per_cab = ReadU32LE(out_view.bytes, 0x2C).value_or(0);
    out_view.flags = ReadU32LE(out_view.bytes, 0x90).value_or(0xFFFFFFFFu);
    out_view.internal_pool_bitmap_transaction_multiplier =
        ReadU32LE(out_view.bytes, 0x94).value_or(0);
    out_view.version = ReadU32LE(out_view.bytes, 0x150).value_or(0);
    out_view.structure_size = ReadU32LE(out_view.bytes, 0x154).value_or(0);
    const std::uint64_t bitmap_capacity =
        static_cast<std::uint64_t>(nxsb.block_size) * 8;
    const std::uint32_t max_chunks_per_cib =
        (nxsb.block_size - 0x28u) / 0x20u;
    const std::uint32_t max_cibs_per_cab =
        (nxsb.block_size - 0x28u) / sizeof(std::uint64_t);
    if (out_view.blocks_per_chunk == 0 ||
        out_view.blocks_per_chunk > bitmap_capacity ||
        out_view.chunks_per_cib == 0 ||
        out_view.chunks_per_cib > max_chunks_per_cib ||
        out_view.cibs_per_cab == 0 ||
        out_view.cibs_per_cab > max_cibs_per_cab ||
        (out_view.flags & ~1u) != 0 ||
        out_view.structure_size < 0x158 ||
        out_view.structure_size > out_view.bytes.size())
    {
        out_error = "AppleSpacemanGeometryInvalid";
        return false;
    }

    for (std::size_t device_index = 0; device_index < out_view.devices.size(); ++device_index)
    {
        auto& device = out_view.devices[device_index];
        const std::size_t base = 0x30 + device_index * 0x30;
        device.block_count = ReadU64LE(out_view.bytes, base).value_or(0);
        device.chunk_count = ReadU64LE(out_view.bytes, base + 0x08).value_or(0);
        device.cib_count = ReadU32LE(out_view.bytes, base + 0x10).value_or(0);
        device.cab_count = ReadU32LE(out_view.bytes, base + 0x14).value_or(0);
        device.free_count = ReadU64LE(out_view.bytes, base + 0x18).value_or(0);
        device.address_offset = ReadU32LE(out_view.bytes, base + 0x20).value_or(0);
    }
    const auto& tier2 = out_view.devices[1];
    if (!fusion && (tier2.block_count != 0 || tier2.chunk_count != 0 ||
        tier2.cib_count != 0 || tier2.cab_count != 0 ||
        tier2.free_count != 0))
    {
        out_error = "AppleSpacemanTier2Unsupported";
        return false;
    }
    auto& main_device = out_view.devices[0];
    const std::size_t device_count = fusion ? 2 : 1;
    for (std::size_t index = 0; index < device_count; ++index)
    {
        const auto& device = out_view.devices[index];
        const auto chunks = device.block_count / out_view.blocks_per_chunk +
            (device.block_count % out_view.blocks_per_chunk != 0);
        const auto cibs = chunks / out_view.chunks_per_cib +
            (chunks % out_view.chunks_per_cib != 0);
        const auto expected_blocks = fusion ? fusion->Members()[index].total_blocks : nxsb.block_count;
        if (device.block_count != expected_blocks || device.chunk_count != chunks ||
            device.cib_count != cibs || !cibs || device.free_count > device.block_count)
        {
            out_error = "AppleSpacemanDeviceGeometryInvalid";
            return false;
        }
    }

    auto& pool = out_view.internal_pool;
    pool.block_count = ReadU64LE(out_view.bytes, 0x98).value_or(0);
    pool.bitmap_size_blocks = ReadU32LE(out_view.bytes, 0xA0).value_or(0);
    pool.bitmap_block_count = ReadU32LE(out_view.bytes, 0xA4).value_or(0);
    pool.bitmap_base_block = ReadU64LE(out_view.bytes, 0xA8).value_or(0);
    pool.base_block = ReadU64LE(out_view.bytes, 0xB0).value_or(0);
    pool.bitmap_free_head = ReadU16LE(out_view.bytes, 0x140).value_or(0xFFFFu);
    pool.bitmap_free_tail = ReadU16LE(out_view.bytes, 0x142).value_or(0xFFFFu);
    pool.bitmap_xid_offset = ReadU32LE(out_view.bytes, 0x144).value_or(0);
    pool.bitmap_index_offset = ReadU32LE(out_view.bytes, 0x148).value_or(0);
    pool.bitmap_free_next_offset = ReadU32LE(out_view.bytes, 0x14C).value_or(0);
    const std::uint64_t expected_bitmap_size =
        (pool.block_count + bitmap_capacity - 1) / bitmap_capacity;
    const std::uint64_t expected_rotation_blocks = expected_bitmap_size *
        out_view.internal_pool_bitmap_transaction_multiplier;
    if (pool.block_count == 0 || pool.bitmap_size_blocks == 0 ||
        pool.bitmap_size_blocks != expected_bitmap_size ||
        pool.bitmap_block_count == 0 || pool.bitmap_block_count > 0xFFFEu ||
        expected_rotation_blocks != pool.bitmap_block_count ||
        !BlockRangeFits(pool.base_block, pool.block_count, main_device.block_count) ||
        !BlockRangeFits(pool.bitmap_base_block, pool.bitmap_block_count,
            main_device.block_count) ||
        !ByteRangeFits(pool.bitmap_xid_offset, pool.bitmap_size_blocks,
            sizeof(std::uint64_t), out_view.bytes.size()) ||
        !ByteRangeFits(pool.bitmap_index_offset, pool.bitmap_size_blocks,
            sizeof(std::uint16_t), out_view.bytes.size()) ||
        !ByteRangeFits(pool.bitmap_free_next_offset, pool.bitmap_block_count,
            sizeof(std::uint16_t), out_view.bytes.size()))
    {
        out_error = "AppleSpacemanInternalPoolGeometryInvalid";
        return false;
    }

    // Fusion variable arrays must lie after the fixed structure, be aligned,
    // and be disjoint. The older single-device parser keeps its existing profile.
    const auto in_pool = [&](std::uint64_t block) {
        return block >= pool.base_block && block - pool.base_block < pool.block_count;
    };
    if (fusion)
    {
        std::uint64_t allocation_objects = 0;
        for (const auto& device : out_view.devices)
            allocation_objects += device.chunk_count + device.cib_count + device.cab_count;
        if (out_view.internal_pool_bitmap_transaction_multiplier != 16 ||
            allocation_objects > UINT64_MAX / 3 || pool.block_count != allocation_objects * 3)
        { out_error = "FusionAllocationInternalPoolProfileUnsupported"; return false; }
        if (out_view.version > 1 ||
            ReadU64LE(out_view.bytes, 0xB8).value_or(1) ||
            ReadU64LE(out_view.bytes, 0xC0).value_or(1) ||
            std::any_of(out_view.bytes.begin() + 0x158,
                out_view.bytes.begin() + out_view.structure_size,
                [](std::byte value) { return value != std::byte{0}; }))
        { out_error = "FusionAllocationExtendedProfileUnsupported"; return false; }
        std::vector<std::pair<std::uint64_t, std::uint64_t>> tables;
        const auto table = [&](std::uint64_t offset, std::uint64_t count, std::uint64_t width) {
            if (!count || offset < out_view.structure_size || offset % width ||
                !ByteRangeFits(offset, count, width, out_view.bytes.size())) return false;
            tables.emplace_back(offset, offset + count * width);
            return true;
        };
        for (const auto& device : out_view.devices)
            if (!table(device.address_offset, device.cab_count ? device.cab_count : device.cib_count, 8))
            { out_error = "FusionAllocationAddressTableInvalid"; return false; }
        if (!table(pool.bitmap_xid_offset, pool.bitmap_size_blocks, 8) ||
            !table(pool.bitmap_index_offset, pool.bitmap_size_blocks, 2) ||
            !table(pool.bitmap_free_next_offset, pool.bitmap_block_count, 2))
        { out_error = "FusionAllocationBitmapTableInvalid"; return false; }
        std::sort(tables.begin(), tables.end());
        for (std::size_t i = 1; i < tables.size(); ++i)
            if (tables[i].first < tables[i - 1].second)
            { out_error = "FusionAllocationTableOverlap"; return false; }
        if (pool.base_block < pool.bitmap_base_block + pool.bitmap_block_count &&
            pool.bitmap_base_block < pool.base_block + pool.block_count)
        { out_error = "FusionAllocationPoolOverlap"; return false; }
    }

    std::unordered_set<std::uint16_t> active_bitmap_indices;
    for (std::uint32_t index = 0; index < pool.bitmap_size_blocks; ++index)
    {
        if (!Materialize(source, 1, sizeof(AppleSpacemanInternalPoolBitmapView) + sizeof(std::uint16_t))) return false;
        AppleSpacemanInternalPoolBitmapView bitmap;
        bitmap.xid = ReadU64LE(out_view.bytes,
            pool.bitmap_xid_offset + static_cast<std::size_t>(index) * 8).value_or(
                std::numeric_limits<std::uint64_t>::max());
        bitmap.rotation_index = ReadU16LE(out_view.bytes,
            pool.bitmap_index_offset + static_cast<std::size_t>(index) * 2).value_or(0xFFFFu);
        if (bitmap.xid == 0 || bitmap.xid > nxsb.xid ||
            bitmap.rotation_index >= pool.bitmap_block_count ||
            !active_bitmap_indices.insert(bitmap.rotation_index).second)
        {
            out_error = "AppleSpacemanInternalPoolActiveBitmapInvalid";
            return false;
        }
        bitmap.physical_block = pool.bitmap_base_block + bitmap.rotation_index;
        if (!ReadRawAppleBlock(source, nxsb.block_size, main_device.block_count,
                bitmap.physical_block, bitmap.bytes))
        {
            out_error = "AppleSpacemanInternalPoolBitmapUnreadable";
            return false;
        }
        if (fusion)
        {
            const auto used_bits = (std::min)(bitmap_capacity,
                pool.block_count - static_cast<std::uint64_t>(index) * bitmap_capacity);
            if (CountBitmapBits(bitmap.bytes, static_cast<std::uint32_t>(bitmap_capacity)) !=
                CountBitmapBits(bitmap.bytes, static_cast<std::uint32_t>(used_bits)))
            { out_error = "FusionAllocationInternalBitmapPadding"; return false; }
        }
        pool.active_bitmaps.push_back(std::move(bitmap));
    }

    if (!Materialize(source, pool.bitmap_block_count,
            static_cast<std::uint64_t>(pool.bitmap_block_count) * 2 * sizeof(std::uint16_t))) return false;
    pool.bitmap_free_next.reserve(pool.bitmap_block_count);
    for (std::uint32_t index = 0; index < pool.bitmap_block_count; ++index)
    {
        pool.bitmap_free_next.push_back(ReadU16LE(out_view.bytes,
            pool.bitmap_free_next_offset + static_cast<std::size_t>(index) * 2).value_or(0xFFFFu));
    }
    for (const auto index : active_bitmap_indices)
    {
        if (pool.bitmap_free_next[index] != 0xFFFFu)
        {
            out_error = "AppleSpacemanInternalPoolActiveBitmapLinked";
            return false;
        }
    }
    std::unordered_set<std::uint16_t> free_bitmap_indices;
    std::uint16_t cursor = pool.bitmap_free_head;
    std::uint16_t last = 0xFFFFu;
    while (cursor != 0xFFFFu)
    {
        if (cursor >= pool.bitmap_block_count ||
            active_bitmap_indices.find(cursor) != active_bitmap_indices.end() ||
            !free_bitmap_indices.insert(cursor).second)
        {
            out_error = "AppleSpacemanInternalPoolFreeListInvalid";
            return false;
        }
        last = cursor;
        cursor = pool.bitmap_free_next[cursor];
    }
    if ((free_bitmap_indices.empty() &&
            (pool.bitmap_free_head != 0xFFFFu || pool.bitmap_free_tail != 0xFFFFu)) ||
        (!free_bitmap_indices.empty() && last != pool.bitmap_free_tail) ||
        free_bitmap_indices.size() + active_bitmap_indices.size() !=
            pool.bitmap_block_count)
    {
        out_error = "AppleSpacemanInternalPoolFreeListIncomplete";
        return false;
    }

    constexpr std::size_t kFreeQueueBase = 0xC8;
    constexpr std::size_t kFreeQueueSize = 0x28;
    for (std::size_t index = 0; index < out_view.free_queues.size(); ++index)
    {
        auto& queue = out_view.free_queues[index];
        const std::size_t base = kFreeQueueBase + index * kFreeQueueSize;
        queue.block_count = ReadU64LE(out_view.bytes, base).value_or(0);
        queue.tree_oid = ReadU64LE(out_view.bytes, base + 0x08).value_or(0);
        queue.oldest_xid = ReadU64LE(out_view.bytes, base + 0x10).value_or(0);
        queue.tree_node_limit = ReadU16LE(out_view.bytes, base + 0x18).value_or(0);
        if (fusion && (ReadU16LE(out_view.bytes, base + 0x1A).value_or(1) ||
            ReadU32LE(out_view.bytes, base + 0x1C).value_or(1) ||
            ReadU64LE(out_view.bytes, base + 0x20).value_or(1)))
        { out_error = "FusionAllocationFreeQueueReservedFields"; return false; }
        out_view.free_queue_oids[index] = queue.tree_oid;
        if (queue.tree_oid == 0)
        {
            if (queue.block_count != 0 || queue.oldest_xid != 0)
            {
                out_error = "AppleSpacemanFreeQueueDescriptorInvalid";
                return false;
            }
            continue;
        }
        if (queue.oldest_xid > nxsb.xid || queue.tree_node_limit == 0)
        {
            out_error = "AppleSpacemanFreeQueueDescriptorInvalid";
            return false;
        }
        const CheckpointMapping* mapping = FindCheckpointMapping(checkpoint, queue.tree_oid);
        if (mapping == nullptr)
        {
            out_error = "AppleSpacemanFreeQueueUnmapped";
            return false;
        }
        if (mapping->file_system_oid != 0 ||
            mapping->type != (kObjectEphemeral | kObjectTypeBtree) ||
            mapping->subtype != kObjectTypeSpacemanFreeQueue)
        {
            out_error = "AppleSpacemanFreeQueueMappingInvalid";
            return false;
        }
        std::vector<std::byte> queue_bytes;
        if (!ReadAppleObject(source, nxsb.block_size, mapping->physical_block,
                mapping->size_bytes, queue.tree_oid, nxsb.xid,
                kObjectEphemeral, kObjectTypeBtree,
                kObjectTypeSpacemanFreeQueue, "AppleSpacemanFreeQueue",
                queue.root, queue_bytes, out_error, fusion != nullptr))
        {
            return false;
        }
        constexpr std::uint32_t kSupportedBtreeFlags =
            0x00000001u | 0x00000002u | 0x00000004u | 0x00000008u |
            0x00000010u | 0x00000040u;
        const std::size_t tree_info = queue_bytes.size() - 40;
        queue.tree_flags = ReadU32LE(queue_bytes, tree_info).value_or(0);
        queue.fixed_key_size = ReadU32LE(queue_bytes, tree_info + 0x08).value_or(0);
        queue.fixed_value_size = ReadU32LE(queue_bytes, tree_info + 0x0C).value_or(0);
        queue.longest_key = ReadU32LE(queue_bytes, tree_info + 0x10).value_or(0);
        queue.longest_value = ReadU32LE(queue_bytes, tree_info + 0x14).value_or(0);
        if (ReadU32LE(queue_bytes, tree_info + 0x04).value_or(0) !=
             nxsb.block_size ||
            (queue.tree_flags & ~kSupportedBtreeFlags) != 0 ||
            (queue.tree_flags & 0x0000000Eu) != 0x0000000Eu ||
            (queue.tree_flags & 0x00000010u) != 0 ||
            queue.fixed_key_size != 16 || queue.fixed_value_size != 8 ||
            queue.longest_key < 16 || queue.longest_value < 8)
        {
            out_error = "AppleSpacemanFreeQueueTreeInfoInvalid";
            return false;
        }
        BtreeReadPolicy queue_policy;
        queue_policy.enforce_object_identity = true;
        queue_policy.root_object_id = queue.tree_oid;
        queue_policy.storage_type = kObjectEphemeral;
        queue_policy.subtype = kObjectTypeSpacemanFreeQueue;
        queue_policy.include_ghost_records = true;
        queue_policy.ephemeral_checkpoint = &checkpoint;
        queue_policy.visited_physical_blocks = &queue.tree_blocks;
        std::vector<BtreeRecord> queue_records;
        if (!ReadBtreeLeafRecords(source, nxsb.block_size,
                mapping->physical_block, false, 0, nxsb.xid, queue_policy,
                queue_records, out_error))
        {
            out_error = "AppleSpacemanFreeQueueTreeInvalid:" + out_error;
            return false;
        }
        if (queue.tree_blocks.empty() ||
            queue.tree_blocks.size() > queue.tree_node_limit)
        {
            out_error = "AppleSpacemanFreeQueueNodeLimitInvalid";
            return false;
        }
        std::uint64_t queued_block_count = 0;
        std::pair<std::uint64_t, std::uint64_t> previous_key{};
        bool have_previous = false;
        for (const auto& record : queue_records)
        {
            if (record.key.size() != 16 ||
                (!record.value.empty() && record.value.size() != 8))
            {
                out_error = "AppleSpacemanFreeQueueRecordInvalid";
                return false;
            }
            AppleSpacemanFreeQueueEntry entry;
            entry.xid = ReadU64LE(record.key, 0).value_or(0);
            entry.physical_block = ReadU64LE(record.key, 8).value_or(0);
            entry.block_count = record.value.empty()
                ? 1
                : ReadU64LE(record.value, 0).value_or(0);
            const auto key = std::make_pair(entry.xid, entry.physical_block);
            if (entry.xid == 0 || entry.xid > nxsb.xid ||
                entry.physical_block == 0 || entry.block_count == 0 ||
                (!record.value.empty() && entry.block_count <= 1) ||
                (have_previous && !(previous_key < key)) ||
                entry.block_count > std::numeric_limits<std::uint64_t>::max() -
                    queued_block_count)
            {
                out_error = "AppleSpacemanFreeQueueRecordInvalid";
                return false;
            }
            queued_block_count += entry.block_count;
            previous_key = key;
            have_previous = true;
            if (!Materialize(source, 1, sizeof(entry))) return false;
            queue.entries.push_back(entry);
        }
        if (queued_block_count != queue.block_count)
        {
            out_error = "AppleSpacemanFreeQueueCountMismatch";
            return false;
        }
        if ((queue.entries.empty() && queue.oldest_xid != 0) ||
            (!queue.entries.empty() &&
                queue.oldest_xid != queue.entries.front().xid))
        {
            out_error = "AppleSpacemanFreeQueueOldestXidMismatch";
            return false;
        }
        if (!Materialize(source, 1, sizeof(queue.root))) return false;
        out_view.free_queue_roots.push_back(queue.root);
    }

    std::unordered_set<std::uint64_t> ownership_blocks;
    if (!Materialize(source, 0, sizeof(std::uint64_t))) return false;
    ownership_blocks.insert(out_view.object.physical_block);
    for (const auto& queue : out_view.free_queues)
    {
        for (const auto block : queue.tree_blocks)
        {
            if (!Materialize(source, 0, sizeof(std::uint64_t))) return false;
            if (!ownership_blocks.insert(block).second)
            {
                out_error = "AppleSpacemanOwnershipOverlap";
                return false;
            }
        }
    }

    for (std::size_t device_index = 0; device_index < device_count; ++device_index)
    {
    auto& device = out_view.devices[device_index];
    const auto first_chunk = out_view.chunks.size();
    std::vector<std::uint64_t> cib_blocks;
    if (!Materialize(source, device.cib_count,
            static_cast<std::uint64_t>(device.cib_count) * sizeof(std::uint64_t))) return false;
    if (device.cab_count == 0)
    {
        if (!ByteRangeFits(device.address_offset, device.cib_count,
                sizeof(std::uint64_t), out_view.bytes.size()))
        {
            out_error = "AppleSpacemanCibAddressTableInvalid";
            return false;
        }
        cib_blocks.reserve(device.cib_count);
        for (std::uint32_t index = 0; index < device.cib_count; ++index)
        {
            cib_blocks.push_back(ReadU64LE(out_view.bytes,
                device.address_offset + static_cast<std::size_t>(index) * 8).value_or(0));
        }
    }
    else
    {
        const std::uint64_t expected_cab_count =
            (static_cast<std::uint64_t>(device.cib_count) +
                out_view.cibs_per_cab - 1) / out_view.cibs_per_cab;
        if (device.cab_count != expected_cab_count ||
            !ByteRangeFits(device.address_offset, device.cab_count,
                sizeof(std::uint64_t), fusion ? out_view.bytes.size() : out_view.structure_size))
        {
            out_error = "AppleSpacemanCabAddressTableInvalid";
            return false;
        }
        cib_blocks.reserve(device.cib_count);
        for (std::uint32_t cab_index = 0; cab_index < device.cab_count; ++cab_index)
        {
            if (!Materialize(source, 1, sizeof(AppleSpacemanCabView) + sizeof(std::uint64_t))) return false;
            const auto cab_block = ReadU64LE(out_view.bytes,
                device.address_offset + static_cast<std::size_t>(cab_index) * 8).value_or(0);
            if (cab_block == 0 || (fusion && !in_pool(cab_block)) || !ownership_blocks.insert(cab_block).second)
            {
                out_error = "AppleSpacemanCabAddressInvalid";
                return false;
            }
            AppleSpacemanCabView cab;
            if (!ReadAppleObject(source, nxsb.block_size, cab_block,
                    nxsb.block_size, cab_block, nxsb.xid, kObjectPhysical,
                    kObjectTypeSpacemanCab, 0, "AppleSpacemanCab",
                    cab.object, cab.bytes, out_error, fusion != nullptr))
            {
                return false;
            }
            cab.index = ReadU32LE(cab.bytes, 0x20).value_or(0xFFFFFFFFu);
            const std::uint32_t count = ReadU32LE(cab.bytes, 0x24).value_or(0);
            const std::uint32_t expected_count = static_cast<std::uint32_t>(
                (std::min)(static_cast<std::uint64_t>(out_view.cibs_per_cab),
                    static_cast<std::uint64_t>(device.cib_count) -
                        cib_blocks.size()));
            if (cab.index != cab_index || count == 0 || count != expected_count ||
                !ByteRangeFits(0x28, count, sizeof(std::uint64_t), cab.bytes.size()))
            {
                out_error = "AppleSpacemanCabGeometryInvalid";
                return false;
            }
            for (std::uint32_t index = 0; index < count; ++index)
            {
                if (!Materialize(source, 0, sizeof(std::uint64_t))) return false;
                const auto cib_block = ReadU64LE(cab.bytes,
                    0x28 + static_cast<std::size_t>(index) * 8).value_or(0);
                cab.cib_blocks.push_back(cib_block);
                cib_blocks.push_back(cib_block);
            }
            device.cabs.push_back(std::move(cab));
        }
    }
    if (cib_blocks.size() != device.cib_count)
    {
        out_error = "AppleSpacemanCibAddressCountInvalid";
        return false;
    }

    std::uint64_t expected_chunk_start = 0;
    std::uint64_t total_free_count = 0;
    for (std::uint32_t cib_index = 0; cib_index < device.cib_count; ++cib_index)
    {
        if (!Materialize(source, 1, sizeof(AppleSpacemanCibView) + sizeof(std::uint64_t))) return false;
        const auto cib_block = cib_blocks[cib_index];
        if (cib_block == 0 || (fusion && !in_pool(cib_block)) || !ownership_blocks.insert(cib_block).second)
        {
            out_error = "AppleSpacemanCibAddressInvalid";
            return false;
        }
        AppleSpacemanCibView cib;
        if (!ReadAppleObject(source, nxsb.block_size, cib_block, nxsb.block_size,
                cib_block, nxsb.xid, kObjectPhysical,
                kObjectTypeSpacemanCib, 0, "AppleSpacemanCib", cib.object,
                cib.bytes, out_error, fusion != nullptr))
        {
            return false;
        }
        cib.index = ReadU32LE(cib.bytes, 0x20).value_or(0xFFFFFFFFu);
        const std::uint32_t chunk_count = ReadU32LE(cib.bytes, 0x24).value_or(0);
        const std::uint64_t remaining_chunks =
            device.chunk_count - (out_view.chunks.size() - first_chunk);
        const std::uint32_t expected_in_cib = static_cast<std::uint32_t>(
            (std::min)(remaining_chunks,
                static_cast<std::uint64_t>(out_view.chunks_per_cib)));
        if (cib.index != cib_index || chunk_count == 0 ||
            chunk_count != expected_in_cib ||
            !ByteRangeFits(0x28, chunk_count, 0x20, cib.bytes.size()))
        {
            out_error = "AppleSpacemanCibGeometryInvalid";
            return false;
        }
        std::uint64_t max_chunk_xid = 0;
        for (std::uint32_t chunk_index = 0; chunk_index < chunk_count; ++chunk_index)
        {
            if (!Materialize(source, 1, sizeof(AppleSpacemanChunkView) +
                    sizeof(std::size_t) + sizeof(std::uint64_t))) return false;
            const std::size_t base = 0x28 + static_cast<std::size_t>(chunk_index) * 0x20;
            AppleSpacemanChunkView chunk;
            chunk.xid = ReadU64LE(cib.bytes, base).value_or(0);
            max_chunk_xid = (std::max)(max_chunk_xid, chunk.xid);
            chunk.start_block = ReadU64LE(cib.bytes, base + 0x08).value_or(0);
            chunk.block_count = ReadU32LE(cib.bytes, base + 0x10).value_or(0);
            chunk.free_count = ReadU32LE(cib.bytes, base + 0x14).value_or(0);
            chunk.bitmap_block = ReadU64LE(cib.bytes, base + 0x18).value_or(0);
            chunk.device_index = static_cast<std::uint32_t>(device_index);
            chunk.cib_index = cib_index;
            chunk.index_in_cib = chunk_index;
            const std::uint32_t expected_blocks = static_cast<std::uint32_t>(
                (std::min)(static_cast<std::uint64_t>(out_view.blocks_per_chunk),
                    device.block_count - expected_chunk_start));
            if (chunk.xid == 0 || chunk.xid > nxsb.xid || (fusion && chunk.xid > cib.object.xid) ||
                chunk.start_block != expected_chunk_start ||
                chunk.block_count != expected_blocks ||
                chunk.free_count > chunk.block_count)
            {
                out_error = "AppleSpacemanChunkGeometryInvalid";
                return false;
            }
            if (chunk.bitmap_block == 0)
            {
                if (chunk.free_count != chunk.block_count)
                {
                    out_error = "AppleSpacemanAllFreeChunkCountInvalid";
                    return false;
                }
            }
            else
            {
                if ((fusion && !in_pool(chunk.bitmap_block)) ||
                    !ownership_blocks.insert(chunk.bitmap_block).second ||
                    !ReadRawAppleBlock(source, nxsb.block_size,
                        main_device.block_count, chunk.bitmap_block,
                        chunk.allocation_bitmap))
                {
                    out_error = "AppleSpacemanChunkBitmapInvalid";
                    return false;
                }
                const std::uint32_t allocated =
                    CountBitmapBits(chunk.allocation_bitmap, fusion ? nxsb.block_size * 8 : chunk.block_count);
                if (allocated != chunk.block_count - chunk.free_count)
                {
                    out_error = "AppleSpacemanChunkFreeCountMismatch";
                    return false;
                }
            }
            total_free_count += chunk.free_count;
            expected_chunk_start += chunk.block_count;
            cib.chunk_indices.push_back(out_view.chunks.size());
            out_view.chunks.push_back(std::move(chunk));
        }
        if (fusion && max_chunk_xid != cib.object.xid)
        { out_error = "FusionAllocationCibGenerationMismatch"; return false; }
        if (fusion && device.cab_count &&
            cib.object.xid > device.cabs[cib_index / out_view.cibs_per_cab].object.xid)
        { out_error = "FusionAllocationCibNewerThanCab"; return false; }
        device.cibs.push_back(std::move(cib));
    }
    if (expected_chunk_start != device.block_count ||
        out_view.chunks.size() - first_chunk != device.chunk_count ||
        total_free_count != device.free_count)
    {
        out_error = "AppleSpacemanDeviceFreeCountMismatch";
        return false;
    }
    if (fusion)
        for (const auto& cab : device.cabs)
        {
            std::uint64_t max_cib_xid = 0;
            for (std::size_t i = 0; i < cab.cib_blocks.size(); ++i)
                max_cib_xid = (std::max)(max_cib_xid,
                    device.cibs[static_cast<std::size_t>(cab.index) * out_view.cibs_per_cab + i].object.xid);
            if (max_cib_xid != cab.object.xid)
            { out_error = "FusionAllocationCabGenerationMismatch"; return false; }
        }
    }
    std::vector<std::pair<std::uint64_t, std::uint64_t>> queued_ranges;
    for (std::size_t queue_index = 0;
         queue_index < out_view.free_queues.size(); ++queue_index)
    {
        for (const auto& entry : out_view.free_queues[queue_index].entries)
        {
            const auto tier_base = kFusionTier2ByteAddress / nxsb.block_size;
            const std::size_t device_index = fusion && entry.physical_block >= tier_base ? 1 : 0;
            const auto local_start = entry.physical_block - (device_index ? tier_base : 0);
            const auto& device = out_view.devices[device_index];
            if (entry.physical_block > std::numeric_limits<std::uint64_t>::max() - entry.block_count ||
                !BlockRangeFits(local_start, entry.block_count, device.block_count))
            { out_error = "AppleSpacemanFreeQueueRangeInvalid"; return false; }
            const auto range_end = entry.physical_block + entry.block_count;
            const bool in_internal_pool = !device_index && in_pool(local_start) &&
                entry.block_count <= pool.base_block + pool.block_count - local_start;
            const bool overlaps_pool = !device_index && local_start < pool.base_block + pool.block_count &&
                pool.base_block < local_start + entry.block_count;
            if ((queue_index == 0 && !in_internal_pool) ||
                (queue_index == 1 && (device_index || overlaps_pool)) ||
                (queue_index == 2 && (!fusion || device_index != 1)))
            { out_error = "AppleSpacemanFreeQueuePoolMismatch"; return false; }
            // Charge the per-block ownership walk, including ranges represented by one record.
            if (fusion && !Materialize(source, entry.block_count, 0)) return false;
            for (std::uint64_t block = entry.physical_block;
                 block < range_end; ++block)
            {
                bool marked_allocated = false;
                if (queue_index == 0)
                {
                    marked_allocated = InternalPoolMarksAllocated(
                        pool, nxsb.block_size, block);
                }
                else
                {
                    const auto local = block - (device_index ? tier_base : 0);
                    const auto chunk_index = (device_index ? main_device.chunk_count : 0) +
                        local / out_view.blocks_per_chunk;
                    if (chunk_index < out_view.chunks.size())
                    {
                        const auto& chunk = out_view.chunks[static_cast<std::size_t>(chunk_index)];
                        marked_allocated = chunk.device_index == device_index &&
                            local >= chunk.start_block && local - chunk.start_block < chunk.block_count &&
                            BitmapBitSet(chunk.allocation_bitmap, local - chunk.start_block);
                    }
                }
                if (!marked_allocated || ownership_blocks.find(block) !=
                        ownership_blocks.end())
                {
                    out_error = "AppleSpacemanFreeQueueOwnershipMismatch";
                    return false;
                }
            }
            if (!Materialize(source, 0, 2 * sizeof(std::uint64_t))) return false;
            queued_ranges.emplace_back(entry.physical_block, range_end);
        }
    }
    std::sort(queued_ranges.begin(), queued_ranges.end());
    for (std::size_t index = 1; index < queued_ranges.size(); ++index)
    {
        if (queued_ranges[index].first < queued_ranges[index - 1].second)
        {
            out_error = "AppleSpacemanFreeQueueOverlap";
            return false;
        }
    }
    for (const std::uint64_t block : ownership_blocks)
    {
        if (block >= pool.base_block && block - pool.base_block < pool.block_count &&
            !InternalPoolMarksAllocated(pool, nxsb.block_size, block))
        {
            out_error = "AppleSpacemanInternalPoolOwnershipMismatch";
            return false;
        }
    }
    if (fusion && !ValidateFusionAllocationGraph(*fusion, out_view, ownership_blocks, out_error)) return false;
    return true;
}
