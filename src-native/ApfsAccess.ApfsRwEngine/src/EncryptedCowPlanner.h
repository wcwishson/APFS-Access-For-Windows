// Included only after the protected session implementation is complete.
// Every helper is private to that session; candidate sources cannot be supplied
// by callers, and neither a key nor a general decryption capability escapes.
struct ApfsEncryptedReadSession::Impl::CowPlanner
{
    static constexpr std::uint32_t bs = 4096;
    static constexpr auto profile = rw::AppleEncryptedExtentProfile::OneKeyGenerationZero;
    Impl& owner;
    std::string& error;
    bool scalable = false;
    bool Fail(const char* reason) { error = reason; return false; }
    static void Put(std::vector<std::byte>& bytes, std::size_t at, std::uint64_t n, unsigned width = 8)
    { for (unsigned i = 0; i < width; ++i) bytes[at + i] = static_cast<std::byte>(n >> (8 * i)); }

    struct Source final : RandomAccessSource
    {
        Impl& owner;
        mutable std::map<std::uint64_t, std::vector<std::byte>> guards;
        explicit Source(Impl& value) : owner(value) {}
        std::uint64_t SizeBytes() const override { return owner.SizeBytes(); }
        std::shared_ptr<ApfsReadBudget> ReadBudget() const override { return owner.ReadBudget(); }
        bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override
        {
            out.clear();
            if (!owner.Check() || offset > SizeBytes() || size > SizeBytes() - offset) return false;
            std::vector<std::byte> result(size);
            for (std::size_t done = 0; done < size;) {
                const auto block = (offset + done) / bs;
                std::vector<std::byte> bytes;
                if (!owner.Read(block * bs, bs, bytes)) return false;
                const auto old = guards.find(block);
                if (old != guards.end() && old->second != bytes) return false;
                if (old == guards.end()) {
                    if (!owner.Charge(1, bs + 96)) return false;
                    guards.emplace(block, bytes);
                }
                const auto within = static_cast<std::size_t>((offset + done) % bs);
                const auto count = (std::min)(size - done, bs - within);
                std::copy_n(bytes.begin() + within, count, result.begin() + done);
                done += count;
            }
            if (!owner.Check()) return false;
            out = std::move(result);
            return true;
        }
    } source;

    struct Candidate final : RandomAccessSource
    {
        const Source& base;
        std::map<std::uint64_t, const std::vector<std::byte>*> blocks;
        Candidate(const Source& input, const rw::AppleCheckpointPublicationPlan& plan) : base(input)
        {
            for (const auto& write : plan.before_superblock_writes)
                if (write.bytes.size() != bs || !blocks.emplace(write.physical_block, &write.bytes).second)
                    throw std::runtime_error("EncryptedCandidateDuplicateBlock");
            if (!blocks.emplace(plan.superblock_write.physical_block, &plan.superblock_write.bytes).second)
                throw std::runtime_error("EncryptedCandidateDuplicateSwitch");
        }
        std::uint64_t SizeBytes() const override { return base.SizeBytes(); }
        std::shared_ptr<ApfsReadBudget> ReadBudget() const override { return base.ReadBudget(); }
        bool Read(std::uint64_t at, std::size_t size, std::vector<std::byte>& out) const override
        {
            out.clear();
            if (!base.owner.Check() || at > SizeBytes() || size > SizeBytes() - at) return false;
            if (!ReadBudget()->Read(size)) return false;
            std::vector<std::byte> result(size);
            for (std::size_t done = 0; done < size;) {
                const auto block = (at + done) / bs;
                const auto found = blocks.find(block);
                std::vector<std::byte> raw;
                if (found == blocks.end() && !base.Read(block * bs, bs, raw)) return false;
                const auto& bytes = found == blocks.end() ? raw : *found->second;
                const auto within = static_cast<std::size_t>((at + done) % bs);
                const auto count = (std::min)(size - done, bs - within);
                std::copy_n(bytes.begin() + within, count, result.begin() + done);
                done += count;
            }
            if (!base.owner.Check()) return false;
            out = std::move(result);
            return true;
        }
    };

    struct Nodes final : BtreeNodeReadContext
    {
        Impl& owner;
        const RandomAccessSource& source;
        const ApsbVolume& volume;
        std::vector<std::byte> cipher;
        crypto::SecureBytes plain;
        std::set<std::pair<std::uint64_t, std::uint64_t>> observed;
        Nodes(Impl& session, const RandomAccessSource& input, const ApsbVolume& selected)
            : owner(session), source(input), volume(selected) {}
        ~Nodes() override { ReleaseNode(); }
        void ReleaseNode() noexcept override { plain.Clear(); Wipe(cipher); }
        bool ReadNode(std::uint64_t oid, std::uint64_t physical, bool root,
            std::span<const std::byte>& bytes, std::string& error) override
        {
            auto map = ResolveOmapValue(source, bs, volume.omap_oid, oid, volume.xid, error, true);
            if (!map) return false;
            return ReadMappedNode(oid, {physical, map->xid, map->flags, map->size}, root, bytes, error);
        }
        bool ReadMappedNode(std::uint64_t oid, const BtreeVirtualChildMapping& selected, bool root,
            std::span<const std::byte>& bytes, std::string& error) override
        {
            bytes = {}; ReleaseNode();
            if (!owner.Check()) return false;
            auto map = ResolveOmapValue(source, bs, volume.omap_oid, oid, volume.xid, error, true);
            if (!map || map->physical_block != selected.physical_block || map->xid != selected.xid ||
                map->flags != selected.flags || map->size != selected.size || map->flags != 4 ||
                map->size != bs || !map->xid || map->xid > volume.xid ||
                map->physical_block >= source.SizeBytes() / bs) {
                error = "EncryptedCowMappingBindingMismatch"; return false;
            }
            if (!source.Read(map->physical_block * bs, bs, cipher)) return false;
            auto buffer = crypto::SecureBytes::Allocate(bs);
            if (!buffer) { error = "EncryptedCowSecureAllocationFailed"; return false; }
            plain = std::move(buffer.bytes);
            if (!owner.Transform(cipher, map->physical_block * (bs / 512), plain.Bytes())) return false;
            const auto view = std::span<const std::byte>(plain.Bytes());
            if (!VerifyObjectChecksum(view, bs) || ReadU64LE(view, 8) != oid ||
                ReadU64LE(view, 16) != map->xid ||
                ReadU32LE(view, 24) != (0x10000000u | (root ? kObjectTypeBtree : kObjectTypeBtreeNode)) ||
                ReadU32LE(view, 28) != kObjectTypeFsTree) {
                error = "EncryptedCowNodeIntegrityFailure"; return false;
            }
            bytes = view;
            observed.emplace(oid, map->xid);
            return owner.Check();
        }
    };

    struct Tree
    {
        Records records;
        rw::AppleBtreeOptions shape;
        std::vector<std::uint64_t> blocks;
        std::set<std::pair<std::uint64_t, std::uint64_t>> mappings;
    };
    std::set<std::uint64_t> metadata, payload, crypto_ids;
    std::vector<std::uint64_t> retained_xids;
    std::vector<std::uint16_t> bitmap_indices;

    bool Remember(std::set<std::uint64_t>& values, std::uint64_t value)
    {
        if (values.contains(value)) return owner.Check();
        // Covers the set node and its retained-owner comparison copy.
        if (!owner.Charge(1, 96)) return Fail("EncryptedCowOwnershipProofCapacityLimit");
        values.insert(value);
        return true;
    }

    CowPlanner(Impl& session, std::string& detail, bool delta = false)
        : owner(session), error(detail), scalable(delta), source(session) {}
    bool Block(const RandomAccessSource& input, std::uint64_t paddr, std::vector<std::byte>& bytes)
    { return paddr < input.SizeBytes() / bs && input.Read(paddr * bs, bs, bytes) && bytes.size() == bs; }
    bool ReadTree(const RandomAccessSource& input, const AppleObjectLocation& root,
        std::uint64_t xid, Tree& tree, Nodes* nodes = nullptr)
    {
        BtreeReadPolicy policy;
        policy.enforce_object_identity = true; policy.require_complete_traversal = true;
        policy.reject_unsupported_flags = true; policy.root_object_id = root.object_id;
        policy.storage_type = root.type; policy.subtype = root.subtype;
        policy.visited_physical_blocks = &tree.blocks;
        const auto physical = (root.type & kObjectStorageTypeMask) == kObjectPhysical;
        std::vector<std::byte> raw;
        std::span<const std::byte> view;
        if (nodes) {
            nodes->observed.clear();
            if (!nodes->ReadNode(root.object_id, root.physical_block, true, view, error)) return false;
        } else {
            if (!Block(input, root.physical_block, raw)) return Fail("EncryptedCowTreeUnreadable");
            view = raw;
        }
        if (!VerifyObjectChecksum(view, bs) || (!scalable && ReadU16LE(view, 34) != 0) || ReadU32LE(view, bs - 36) != bs)
            return Fail("EncryptedCowLeafGeometryUnsupported");
        tree.shape.block_size = bs; tree.shape.storage_type = physical ? kObjectPhysical : 0;
        tree.shape.subtype = root.subtype; tree.shape.tree_flags = ReadU32LE(view, bs - 40).value();
        tree.shape.fixed_key_size = ReadU32LE(view, bs - 32).value();
        tree.shape.fixed_value_size = ReadU32LE(view, bs - 28).value();
        tree.shape.minimum_longest_key = ReadU32LE(view, bs - 24).value();
        tree.shape.minimum_longest_value = ReadU32LE(view, bs - 20).value();
        if (nodes) nodes->ReleaseNode();
        if (!ReadBtreeLeafRecords(input, bs, root.physical_block, physical,
                nodes ? nodes->volume.omap_oid : 0, xid, policy, tree.records.bytes, error, nodes)) return false;
        if (nodes) tree.mappings = nodes->observed;
        return (scalable ? tree.blocks.size() <= 256 : tree.blocks.size() == 1) || Fail("EncryptedCowTreeCapacityUnsupported");
    }
    bool Allocated(const AppleSpacemanView& spaceman, std::uint64_t block) const
    {
        for (const auto& chunk : spaceman.chunks) {
            if (block < chunk.start_block || block - chunk.start_block >= chunk.block_count) continue;
            const auto bit = block - chunk.start_block;
            return !chunk.allocation_bitmap.empty() &&
                (std::to_integer<unsigned>(chunk.allocation_bitmap[bit / 8]) & (1u << (bit % 8))) != 0;
        }
        return false;
    }
    bool NotQueued(const AppleSpacemanView& sm, std::uint64_t block) const
    {
        for (const auto& q : sm.free_queues) for (const auto& e : q.entries)
            if (block >= e.physical_block && block - e.physical_block < e.block_count) return false;
        return true;
    }
    bool Load(const RandomAccessSource& input, const ContainerCheckpointView& cp,
        AppleCheckpointView& out, Tree& fs, Tree& refs, Tree& vomap, Tree& comap,
        const AppleSpacemanView* current_allocator = nullptr, bool protect_bitmap = true)
    {
        const auto& nx = cp.superblock;
        if (nx.block_size != bs || nx.block_count != owner.checkpoint.superblock.block_count ||
            nx.uuid_hex != owner.checkpoint.superblock.uuid_hex || nx.fs_oids.size() != 1 ||
            nx.fs_oids.front() != owner.volume.object_id || nx.xp_desc_noncontiguous || nx.xp_data_noncontiguous)
            return Fail("EncryptedCowRetainedContainerProfileUnsupported");
        if (ReadU64LE(cp.superblock_bytes, 0x510) != ReadU64LE(owner.checkpoint.superblock_bytes, 0x510) ||
            ReadU64LE(cp.superblock_bytes, 0x518) != ReadU64LE(owner.checkpoint.superblock_bytes, 0x518)) {
            auto proof = SoftwareKeybagEraAuthority::Prove(*owner.source, source, owner.identity, owner.revision,
                owner.key, owner.checkpoint, owner.volume, nx.xid, error);
            if (!proof || proof->checkpoint_.superblock_bytes != cp.superblock_bytes)
                return error.empty() ? Fail("EncryptedCowRetainedKeybagIdentityChanged") : false;
            if (!Remember(metadata, proof->container_block_) || !Remember(metadata, proof->volume_block_) ||
                !Remember(metadata, proof->current_container_block_) || !Remember(metadata, proof->current_volume_block_)) return false;
        }
        auto read = LoadAppleReadOnlyVolumeView(input, cp, error);
        if (!read || read->volumes.size() != 1) return false;
        const auto selected = read->volumes.front().superblock;
        if (selected.uuid_hex != owner.volume.uuid_hex || selected.fs_flags != kFsFlagOneKey ||
            selected.features != owner.volume.features || selected.readonly_features ||
            selected.incompatible_features != owner.volume.incompatible_features || selected.fext_tree_oid ||
            selected.snap_meta_ext_oid || selected.role_raw != owner.volume.role_raw)
            return Fail("EncryptedCowRetainedKeyProfileUnsupported");
        Nodes selected_nodes(owner, input, selected);
        auto exact = AppleEncryptedMetadataReadContext::LoadCanonical(input, cp, selected, selected_nodes, error, !current_allocator);
        if (!exact || exact->volumes.size() != 1) return false;
        const auto& allocator = current_allocator ? *current_allocator : exact->spaceman;
        const auto& v = exact->volumes.front();
        if (exact->container_object_map.flags != 1u || v.object_map.flags != 0u)
            return Fail("EncryptedCowOmapRoleUnsupported");
        std::vector<std::byte> apsb;
        if (!Block(input, v.superblock_object.physical_block, apsb)) return false;
        if (ReadU64LE(apsb, 0xD8) != 0 || v.object_map.snapshot_tree_oid ||
            exact->container_object_map.snapshot_tree_oid || !v.extentref_tree ||
            ReadU64LE(apsb, 0xA0) != 0 || ReadU64LE(apsb, 0xA8) != 0 ||
            ReadU64LE(apsb, 0x3D0) != 0)
            return Fail("EncryptedCowSnapshotOrRollingUnsupported");
        auto current_volume = LoadAppleReadOnlyVolumeView(source, owner.checkpoint, error);
        std::vector<std::byte> current_apsb;
        if (!current_volume || current_volume->volumes.size() != 1 ||
            !Block(source, current_volume->volumes.front().superblock_object.physical_block, current_apsb) ||
            !std::equal(apsb.begin() + 0x60, apsb.begin() + 0x78, current_apsb.begin() + 0x60))
            return Fail("EncryptedCowRetainedCryptoStateChanged");
        if (!ReadTree(input, v.root_tree, v.superblock.xid, fs, &selected_nodes) ||
            !ReadTree(input, *v.extentref_tree, nx.xid, refs) ||
            !ReadTree(input, v.object_map.tree, nx.xid, vomap) ||
            !ReadTree(input, exact->container_object_map.tree, nx.xid, comap)) return false;
        // This admitted profile has no hidden container OMAP versions. Older
        // volume mappings would require their own complete ownership closure.
        if (comap.records.bytes.size() != 1 ||
            ReadU64LE(comap.records.bytes.front().key, 0) != selected.object_id ||
            ReadU64LE(comap.records.bytes.front().key, 8) != selected.xid ||
            ReadU32LE(comap.records.bytes.front().value, 0) != 0u ||
            ReadU32LE(comap.records.bytes.front().value, 4) != bs ||
            ReadU64LE(comap.records.bytes.front().value, 8) != v.superblock_object.physical_block)
            return Fail("EncryptedCowContainerHistoryProfileUnsupported");
        if (v.snapshot_metadata_tree) {
            Tree snapshots;
            if (!ReadTree(input, *v.snapshot_metadata_tree, nx.xid, snapshots) || !snapshots.records.bytes.empty())
                return Fail("EncryptedCowSnapshotsUnsupported");
            for (const auto block : snapshots.blocks) if (!Remember(metadata, block)) return false;
        }
        std::vector<rw::ApplePhysicalExtentRecord> extents;
        if (!rw::ValidateAppleEncryptedPayloadExtentGraph(fs.records.bytes, refs.records.bytes,
                bs, nx.block_count, extents, error)) return false;
        for (const auto& r : fs.records.bytes) {
            if ((ReadU64LE(r.key, 0).value_or(0) >> 60) == 4 &&
                (ReadU16LE(r.value, 0).value_or(0) & rw::kAppleXattrDataStream))
                return Fail("EncryptedCowHistoricalExternalStreamUnsupported");
            if ((ReadU64LE(r.key, 0).value_or(0) >> 60) != 8) continue;
            rw::AppleEncryptedFileExtentRecord decoded;
            if (!rw::DecodeAppleEncryptedFileExtentRecord(r, bs, profile, decoded, error)) return false;
            const auto& e = decoded.extent;
            if (!e.physical_block || e.length_bytes / bs > 65536) return Fail("EncryptedCowHoleOrExtentLimitUnsupported");
            for (std::uint64_t i = 0; i < e.length_bytes / bs; ++i)
                if (!Remember(crypto_ids, e.crypto_id + i)) return false;
        }
        for (const auto& extent : extents) {
            if (extent.reference_count != 1 || extent.block_count > 65536)
                return Fail("EncryptedCowSharedExtentUnsupported");
            for (std::uint64_t i = 0; i < extent.block_count; ++i) {
                const auto block = extent.physical_block + i;
                const auto within = [block](std::uint64_t start, std::uint64_t count) {
                    return block >= start && block - start < count;
                };
                const auto& pool = allocator.internal_pool;
                if (!block || within(nx.xp_desc_base_block, nx.xp_desc_block_count) ||
                    within(nx.xp_data_base_block, nx.xp_data_block_count) ||
                    within(pool.base_block, pool.block_count) || within(pool.bitmap_base_block, pool.bitmap_block_count))
                    return Fail("EncryptedCowPayloadReservedOverlap");
                if (!Allocated(allocator, block) || (!current_allocator && !NotQueued(allocator, block)))
                    return Fail("EncryptedCowPayloadOwnershipUnproven");
                if (!Remember(payload, block)) return false;
            }
        }
        for (const auto* tree : {&fs, &refs, &vomap, &comap})
            for (const auto block : tree->blocks) if (!Remember(metadata, block)) return false;
        if (!Remember(metadata, v.superblock_object.physical_block) ||
            !Remember(metadata, v.object_map.object.physical_block) ||
            !Remember(metadata, exact->container_object_map.object.physical_block)) return false;
        // Every retained OMAP version is an owner, even when not selected by
        // the current APSB. This leaf profile admits only the known FS root OID.
        for (const auto& r : vomap.records.bytes) {
            const auto oid = ReadU64LE(r.key, 0).value_or(0);
            const auto xid = ReadU64LE(r.key, 8).value_or(0);
            const auto flags = ReadU32LE(r.value, 0).value_or(~0u);
            const auto block = ReadU64LE(r.value, 8).value_or(0);
            if (flags == 1) continue;
            if (scalable) {
                if (flags != 4 || ReadU32LE(r.value, 4) != bs || !fs.mappings.contains({oid, xid}))
                    return Fail("EncryptedDeltaUnprovedOmapVersionUnsupported");
                continue;
            }
            if (oid != v.root_tree.object_id || flags != 4 || ReadU32LE(r.value, 4) != bs || !xid || xid > selected.xid)
                return Fail("EncryptedCowRetainedOmapProfileUnsupported");
            ApsbVolume version = selected; version.xid = xid;
            Nodes historical(owner, input, version);
            AppleObjectLocation root = v.root_tree; root.xid = xid; root.physical_block = block;
            Tree old;
            if (!ReadTree(input, root, xid, old, &historical)) return false;
            if (!Remember(metadata, block)) return false;
            for (const auto& row : old.records.bytes) {
                if ((ReadU64LE(row.key, 0).value_or(0) >> 60) != 8) continue;
                rw::AppleEncryptedFileExtentRecord e;
                if (!rw::DecodeAppleEncryptedFileExtentRecord(row, bs, profile, e, error) ||
                    !e.extent.physical_block || e.extent.length_bytes / bs > 65536) return false;
                for (std::uint64_t i = 0; i < e.extent.length_bytes / bs; ++i) {
                    if (!Remember(crypto_ids, e.extent.crypto_id + i) ||
                        !Remember(payload, e.extent.physical_block + i)) return false;
                }
            }
        }
        if (current_allocator && protect_bitmap) {
            AppleSpacemanView historical_ownership;
            if (!LoadAppleSpacemanOwnershipView(input, cp, historical_ownership, error))
                return false; // A validated prefix is not a complete required owner walk.
            AppleSpacemanInternalPoolView pins;
            if (!LoadAppleSpacemanRetentionBitmaps(input, cp, pins, error) ||
                pins.base_block != allocator.internal_pool.base_block || pins.block_count != allocator.internal_pool.block_count ||
                pins.bitmap_base_block != allocator.internal_pool.bitmap_base_block ||
                pins.bitmap_block_count != allocator.internal_pool.bitmap_block_count)
                return Fail("EncryptedCowRetainedBitmapGeometryUnsupported");
            for (const auto& bitmap : pins.active_bitmaps) bitmap_indices.push_back(bitmap.rotation_index);
            exact->spaceman = std::move(historical_ownership);
        } else if (!current_allocator)
            for (const auto& bitmap : allocator.internal_pool.active_bitmaps) bitmap_indices.push_back(bitmap.rotation_index);
        out = std::move(*exact);
        return owner.Check();
    }
    bool Serialize(Tree& tree, rw::AppleBtreeKeyOrder order, std::uint64_t oid,
        std::uint64_t paddr, std::uint64_t xid, std::vector<std::byte>& out)
    {
        auto options = tree.shape; options.key_order = order;
        options.root_object_id = oid; options.root_physical_block = paddr;
        options.first_child_object_id = oid + 1; options.first_child_physical_block = paddr + 1;
        options.xid = xid; options.max_nodes = 1;
        rw::AppleSerializedBtree serialized;
        if (!rw::SerializeAppleBtree(tree.records.bytes, options, serialized, error) || serialized.objects.size() != 1) {
            error = "EncryptedCowLeafSerializationFailed:" + error; return false;
        }
        out = std::move(serialized.objects.front().bytes);
        return true;
    }
    bool Mapping(Tree& tree, std::uint64_t oid, std::uint64_t xid, std::uint64_t block, std::uint32_t flags)
    {
        rw::AppleOmapRecord map; map.object_id = oid; map.xid = xid;
        map.flags = flags; map.size_bytes = bs; map.physical_block = block;
        BtreeRecord row;
        if (!rw::EncodeAppleOmapRecord(map, row, error)) return false;
#ifdef APFSACCESS_ENCRYPTED_COW_TESTING
        if (flags == 4 && encrypted_cow_testing::fault == 3) Put(row.value, 0, 8, 4);
#endif
        std::erase_if(tree.records.bytes, [oid](const auto& old) { return ReadU64LE(old.key, 0) == oid; });
        tree.records.bytes.push_back(std::move(row));
        return true;
    }
    bool InstallData(Tree& fs, Tree& refs, std::uint64_t stream,
        const std::vector<rw::AppleEncryptedFileExtentRecord>& extents)
    {
        std::erase_if(fs.records.bytes, [stream](auto& row) {
            if (RowType(row) != 8 || RowId(row) != stream) return false;
            Wipe(row.key); Wipe(row.value); return true;
        });
        for (auto& row : refs.records.bytes) {
            rw::ApplePhysicalExtentRecord e;
            if (!rw::DecodeApplePhysicalExtentRecord(row, e, error)) return false;
            if (e.owning_object_id != stream) continue;
            if (e.reference_count != 1 || e.kind != rw::kApplePhysicalExtentKindNew)
                return Fail("EncryptedCowExactReferenceRequired");
            Wipe(row.key); Wipe(row.value);
        }
        std::erase_if(refs.records.bytes, [](const auto& row) { return row.key.empty(); });
        for (const auto& e : extents) {
            fs.records.bytes.emplace_back();
            if (!rw::EncodeAppleEncryptedFileExtentRecord(e, profile, fs.records.bytes.back(), error)) return false;
            refs.records.bytes.emplace_back();
            if (!rw::EncodeApplePhysicalExtentRecord({e.extent.physical_block, e.extent.length_bytes / bs,
                rw::kApplePhysicalExtentKindNew, stream, 1}, refs.records.bytes.back(), error)) return false;
        }
        return true;
    }
    bool Compose(const AppleCheckpointView& checkpoint, const rw::AppleSpacemanAllocationPlan& allocation,
        std::uint64_t container_omap, const std::vector<rw::AppleCheckpointPhysicalWrite>& writes,
        rw::AppleCheckpointPublicationPlan& output)
    {
        const auto& nx = checkpoint.container.superblock;
        rw::AppleCheckpointPublicationRequest request;
        request.expected_checkpoint_xid = nx.xid; request.transaction_xid = nx.next_xid;
        request.next_object_id = nx.next_oid; request.container_object_map_oid = container_omap;
        request.required_checkpoint_xids = retained_xids; request.allocator_owned_writes = writes;
        std::map<std::uint64_t, rw::AppleCheckpointEphemeralObject> objects;
        rw::AppleCheckpointEphemeralObject sm;
        sm.object = allocation.updated_spaceman.object; sm.object.physical_block = 0;
        sm.object.size_bytes = static_cast<std::uint32_t>(allocation.updated_spaceman.bytes.size());
        sm.bytes = allocation.updated_spaceman.bytes;
        objects.emplace(sm.object.object_id, std::move(sm));
        for (const auto& write : allocation.writes) {
            if (write.kind == rw::AppleSpacemanWriteKind::FreeQueueTree) {
                if (!write.object_location || write.physical_block) return Fail("EncryptedCowAllocatorObjectInvalid");
                rw::AppleCheckpointEphemeralObject object;
                object.object = *write.object_location; object.object.physical_block = 0; object.bytes = write.bytes;
                if (!objects.emplace(object.object.object_id, std::move(object)).second)
                    return Fail("EncryptedCowAllocatorObjectDuplicate");
                request.next_object_id = (std::max)(request.next_object_id, write.object_location->object_id + 1);
            } else {
                if (!write.physical_block || write.object_location || write.bytes.size() != bs)
                    return Fail("EncryptedCowAllocatorWriteInvalid");
                request.allocator_owned_writes.push_back({write.physical_block, write.bytes});
            }
        }
        for (const auto& mapping : checkpoint.container.mappings) {
            if (objects.contains(mapping.object_id)) continue;
            // An old free-queue child can disappear only when its root is rebuilt.
            bool retired = false;
            for (const auto& queue : checkpoint.spaceman.free_queues)
                if (objects.contains(queue.tree_oid) &&
                    std::find(queue.tree_blocks.begin(), queue.tree_blocks.end(), mapping.physical_block) != queue.tree_blocks.end())
                    retired = true;
            if (retired) { request.retired_ephemeral_object_ids.push_back(mapping.object_id); continue; }
            if (mapping.size_bytes != bs) return Fail("EncryptedCowEphemeralGeometryUnsupported");
            rw::AppleCheckpointEphemeralObject object;
            object.file_system_oid = mapping.file_system_oid;
            object.object = {mapping.object_id, nx.next_xid, 0, mapping.type, mapping.subtype, mapping.size_bytes};
            if (!Block(source, mapping.physical_block, object.bytes)) return false;
            Put(object.bytes, 16, nx.next_xid);
            if (!rw::FinalizeAppleObjectChecksum(object.bytes, error)) return false;
            objects.emplace(mapping.object_id, std::move(object));
        }
        for (auto& [oid, object] : objects) { (void)oid; request.ephemeral_objects.push_back(std::move(object)); }
        return rw::PlanAppleCheckpointPublication(source, checkpoint.container, request, output, error);
    }

    bool PreviewRing(const AppleCheckpointView& current, rw::AppleCheckpointPublicationPlan& out,
        std::span<const std::uint64_t> pins = {})
    {
        const auto& nx = current.container.superblock;
        rw::AppleCheckpointPublicationRequest request;
        request.expected_checkpoint_xid = nx.xid; request.transaction_xid = nx.next_xid;
        request.next_object_id = nx.next_oid;
        request.required_checkpoint_xids.assign(pins.begin(), pins.end());
        for (const auto& mapping : current.container.mappings) {
            if (mapping.size_bytes != bs) return Fail("EncryptedCowControlGeometryUnsupported");
            rw::AppleCheckpointEphemeralObject object;
            object.file_system_oid = mapping.file_system_oid;
            object.object = {mapping.object_id, nx.next_xid, 0, mapping.type, mapping.subtype, mapping.size_bytes};
            if (!Block(source, mapping.physical_block, object.bytes)) return false;
            Put(object.bytes, 16, nx.next_xid);
            if (!rw::FinalizeAppleObjectChecksum(object.bytes, error)) return false;
            request.ephemeral_objects.push_back(std::move(object));
        }
        // Geometry preview only. It has no data writes, allocation proof or
        // externally accessible capability and is never passed to an executor.
        return rw::PlanAppleCheckpointPublication(source, current.container, request, out, error);
    }

    static bool SameRecords(const auto& left, const auto& right)
    {
        return left.size() == right.size() && std::equal(left.begin(), left.end(), right.begin(),
            [](const auto& x, const auto& y) { return x.key == y.key && x.value == y.value; });
    }
    static bool SameAllocator(const AppleSpacemanView& a, const AppleSpacemanView& b)
    {
        if (a.bytes != b.bytes || a.devices.size() != b.devices.size() || a.chunks.size() != b.chunks.size() ||
            a.internal_pool.active_bitmaps.size() != b.internal_pool.active_bitmaps.size()) return false;
        for (std::size_t d = 0; d < a.devices.size(); ++d) {
            const auto& x = a.devices[d]; const auto& y = b.devices[d];
            if (x.cibs.size() != y.cibs.size() || x.cabs.size() != y.cabs.size()) return false;
            for (std::size_t i = 0; i < x.cibs.size(); ++i)
                if (x.cibs[i].object.physical_block != y.cibs[i].object.physical_block || x.cibs[i].bytes != y.cibs[i].bytes) return false;
            for (std::size_t i = 0; i < x.cabs.size(); ++i)
                if (x.cabs[i].object.physical_block != y.cabs[i].object.physical_block || x.cabs[i].bytes != y.cabs[i].bytes) return false;
        }
        for (std::size_t i = 0; i < a.chunks.size(); ++i)
            if (a.chunks[i].bitmap_block != b.chunks[i].bitmap_block ||
                a.chunks[i].allocation_bitmap != b.chunks[i].allocation_bitmap) return false;
        for (std::size_t i = 0; i < a.internal_pool.active_bitmaps.size(); ++i) {
            const auto& x = a.internal_pool.active_bitmaps[i]; const auto& y = b.internal_pool.active_bitmaps[i];
            if (x.physical_block != y.physical_block || x.rotation_index != y.rotation_index ||
                x.xid != y.xid || x.bytes != y.bytes) return false;
        }
        for (std::size_t i = 0; i < a.free_queues.size(); ++i) {
            const auto& x = a.free_queues[i]; const auto& y = b.free_queues[i];
            if (x.tree_blocks != y.tree_blocks || x.entries.size() != y.entries.size()) return false;
            for (std::size_t j = 0; j < x.entries.size(); ++j)
                if (x.entries[j].xid != y.entries[j].xid || x.entries[j].physical_block != y.entries[j].physical_block ||
                    x.entries[j].block_count != y.entries[j].block_count) return false;
        }
        return true;
    }
    bool CopyRecords(const Records& from, Records& to)
    {
        for (const auto& row : from.bytes) {
            if (!owner.Charge(1, sizeof(BtreeRecord) + row.key.size() + row.value.size())) return false;
            to.bytes.emplace_back();
            to.bytes.back().key = row.key; to.bytes.back().value = row.value;
        }
        return true;
    }

#include "EncryptedMutationRecords.h"
    bool RenderDelta(const MutationState& mutation, const EncryptedMutationRequest& request,
        std::size_t index, crypto::SecureBytes& plain)
    {
        return encrypted_delta::RenderBlock(mutation.delta, request, mutation.delta.changed[index], plain,
            [&](const auto& extent, auto delta, auto& out, auto&) {
                std::vector<std::byte> cipher;
                return Block(source, extent.physical_block + delta, cipher) &&
                    owner.Transform(cipher, (extent.crypto_id + delta) * (bs / 512), out.Bytes());
            }, error);
    }
    #include "EncryptedCowTransitionRetention.inc"

    std::unique_ptr<EncryptedCowOverwrite> Prepare(const EncryptedMutationRequest& request,
        std::span<const std::uint64_t> required, std::span<const std::uint64_t> read_pins = {})
    {
        if (!owner.Check() || owner.checkpoint.superblock.block_size != bs || !owner.namespace_ready)
            { Fail("EncryptedCowSourceOrGeometryUnsupported"); return {}; }
        AppleCheckpointView current;
        Tree fs, refs, vomap, comap;
        UnlockError bag_error;
        auto bags = InspectPasswordKeybagMetadata(source, owner.volume.object_id, KeybagLength::IncludesHeader, bag_error);
        if (!bags || bags->selection.checkpoint_xid != owner.key.checkpoint_xid ||
            bags->selection.volume_uuid != owner.key.volume_uuid || bags->selection.container_uuid != owner.key.container_uuid)
            { Fail("EncryptedCowKeybagBindingMismatch"); return {}; }
        std::set<std::uint64_t> keybag_owners;
        for (const auto& [block, bytes] : source.guards) { (void)bytes; keybag_owners.insert(block); }
        if (!Load(source, owner.checkpoint, current, fs, refs, vomap, comap)) return {};
        const auto nx = current.container.superblock;
        const auto selected_volume = current.volumes.front();
        if (!nx.next_xid || nx.next_xid <= nx.xid || nx.block_count >= (1ULL << 51))
            { Fail("EncryptedCowTransactionOrTweakRangeUnsupported"); return {}; }
        // Exact retained generations, including complete descriptor candidates
        // outside the current generation's ring window. No caller-supplied pin.
        std::set<std::uint64_t> xids{nx.xid};
        for (std::uint64_t i = 0; i < nx.xp_desc_block_count; ++i) {
            std::vector<std::byte> bytes;
            if (!Block(source, nx.xp_desc_base_block + i, bytes)) return {};
            auto old = ParseNxSuperblock(bytes);
            if (old && old->uuid_hex == nx.uuid_hex && old->xid <= nx.xid) xids.insert(old->xid);
        }
        if (required.size() > nx.xp_desc_block_count || std::any_of(required.begin(), required.end(),
                [&](auto xid) { return !xid || xid > nx.xid || !xids.contains(xid); }))
            { Fail("EncryptedCowRequiredGenerationUnavailable"); return {}; }
        if (read_pins.size() > nx.xp_desc_block_count || std::any_of(read_pins.begin(), read_pins.end(),
                [&](auto xid) { return !xid || xid > nx.xid || !xids.contains(xid); }))
            { Fail("EncryptedCowReadGenerationUnavailable"); return {}; }
        std::set<std::uint64_t> preview_pin_set(required.begin(), required.end());
        preview_pin_set.insert(read_pins.begin(), read_pins.end());
        std::vector<std::uint64_t> preview_pins(preview_pin_set.begin(), preview_pin_set.end());
        rw::AppleCheckpointPublicationPlan preview;
        if (!PreviewRing(current, preview, read_pins.empty() ? std::span<const std::uint64_t>{} : preview_pins)) return {};
        Candidate preview_source(source, preview);
        std::size_t retired_count = 0;
        std::size_t survivor_metadata_walks = 0;
        std::map<std::uint64_t, AppleSpacemanView> required_allocators;
        struct ReadRecords { Records fs, refs; };
        std::map<std::uint64_t, std::unique_ptr<ReadRecords>> read_records;
        std::set<std::uint64_t> preview_retired;
        for (const auto xid : xids) {
            if (xid == nx.xid) continue;
            std::string detail;
            auto cp = LoadContainerCheckpointView(source, 0, source.SizeBytes(), detail, xid);
            if (!cp) { error = "EncryptedCowHistoricalCheckpointUnavailable:" + detail; return {}; }
            const auto survives = LoadContainerCheckpointView(preview_source, 0, preview_source.SizeBytes(), detail, xid);
            const bool recovery_pin = std::find(required.begin(), required.end(), xid) != required.end();
            const bool read_pin = std::find(read_pins.begin(), read_pins.end(), xid) != read_pins.end();
            const bool pinned = recovery_pin || read_pin;
            if (!survives && !pinned) { ++retired_count; preview_retired.insert(xid); continue; }
            const auto transition = AdmitTransitionGeneration(*cp, pinned);
            if (transition == SoftwareEncryptedRetentionAuthority::Admission::Refused) return {};
            if (transition == SoftwareEncryptedRetentionAuthority::Admission::Opaque) continue;
            AppleCheckpointView historical;
            Tree a, b, c, d;
            if (!Load(source, *cp, historical, a, b, c, d, &current.spaceman, pinned)) {
                error += ":retained-xid-" + std::to_string(xid); return {};
            }
            if (pinned) {
                if (recovery_pin && (!SameRecords(a.records.bytes, fs.records.bytes) || !SameRecords(b.records.bytes, refs.records.bytes)))
                    { Fail("EncryptedCowChangedRecoveryGenerationUnsupported"); return {}; }
                required_allocators.emplace(xid, std::move(historical.spaceman));
                if (read_pin && !recovery_pin) {
                    auto records = std::make_unique<ReadRecords>();
                    if (!CopyRecords(a.records, records->fs) || !CopyRecords(b.records, records->refs)) return {};
                    read_records.emplace(xid, std::move(records));
                }
            }
            ++survivor_metadata_walks;
            if (pinned) retained_xids.push_back(xid);
        }
        // Recovered filesystem metadata and payload must remain allocated.
        // Only eligible internal-pool queue entries can be reclaimed; main-pool
        // queues and every promised generation's allocator bytes are preserved.
        for (const auto block : payload)
            if (!Allocated(current.spaceman, block)) { Fail("EncryptedCowRetainedPayloadNotAllocated"); return {}; }
        for (const auto block : metadata)
            if (!Allocated(current.spaceman, block) || payload.contains(block))
                { Fail("EncryptedCowMetadataOwnershipUnproven"); return {}; }

        Records preimage_fs, preimage_refs;
        if (!CopyRecords(fs.records, preimage_fs) || !CopyRecords(refs.records, preimage_refs)) return {};
        MutationState mutation;
        if (!PrepareRecords(request, current, fs, mutation)) return {};
        if (mutation.replaced_inode && !InstallData(fs, refs, mutation.replaced_stream, {})) return {};
        const auto order = owner.name_policy.UsesHashedDirectoryKeys()
            ? rw::AppleBtreeKeyOrder::FileSystemHashedDirectory : rw::AppleBtreeKeyOrder::FileSystemCaseSensitive;
        std::size_t fs_count = 1, ref_count = 1, vomap_count = 1, comap_count = 1;
        std::uint64_t first_child_oid = 0;
        if (scalable) {
            if (mutation.rewrite_data || request.kind == EncryptedMutationKind::Unlink) {
                auto estimated = mutation.delta.preserved;
                for (std::size_t i = 0; i < mutation.delta.changed.size(); ++i) {
                    rw::AppleEncryptedFileExtentRecord extent;
                    extent.flags = mutation.extent_flags;
                    extent.extent = {mutation.stream, mutation.delta.changed[i] * bs, bs,
                        nx.block_count + i + 1, (1ULL << 51) + i, bs};
                    estimated.push_back(extent);
                }
                if (!InstallData(fs, refs, mutation.stream, estimated)) return {};
            }
            encrypted_delta::TreeSize count;
            if (!encrypted_delta::SizeTree(fs.records.bytes, fs.shape, order, 256, count, error)) return {};
            fs_count = count.nodes;
            if (!encrypted_delta::SizeTree(refs.records.bytes, refs.shape, rw::AppleBtreeKeyOrder::PhysicalExtent, 256, count, error)) return {};
            ref_count = count.nodes;
            first_child_oid = mutation.next_oid;
            for (const auto& row : fs.records.bytes)
                if (RowId(row) >= mutation.next_oid) { Fail("EncryptedDeltaNextOidAuthorityUnproved"); return {}; }
            for (const auto& row : vomap.records.bytes) {
                const auto oid = ReadU64LE(row.key, 0).value_or(UINT64_MAX);
                if (oid >= 0x0fffffffffffffffULL) { Fail("EncryptedDeltaVirtualOidExhausted"); return {}; }
                first_child_oid = (std::max)(first_child_oid, oid + 1);
            }
            if (fs_count - 1 > 0x0fffffffffffffffULL - first_child_oid)
                { Fail("EncryptedDeltaVirtualOidExhausted"); return {}; }
            if (fs_count > 1) mutation.next_oid = first_child_oid + fs_count - 1;
            std::set<std::uint64_t> active_oids;
            for (const auto& mapping : fs.mappings) active_oids.insert(mapping.first);
            std::erase_if(vomap.records.bytes, [&](auto& row) {
                if (!active_oids.contains(ReadU64LE(row.key, 0).value_or(0))) return false;
                Wipe(row.key); Wipe(row.value); return true;
            });
            for (std::size_t i = 0; i < fs_count; ++i)
                if (!Mapping(vomap, i ? first_child_oid + i - 1 : selected_volume.root_tree.object_id,
                    nx.next_xid, nx.block_count + mutation.blocks + i + 1, 4)) return {};
            if (!encrypted_delta::SizeTree(vomap.records.bytes, vomap.shape, rw::AppleBtreeKeyOrder::ObjectMap, 256, count, error)) return {};
            vomap_count = count.nodes;
            if (!encrypted_delta::SizeTree(comap.records.bytes, comap.shape, rw::AppleBtreeKeyOrder::ObjectMap, 256, count, error)) return {};
            comap_count = count.nodes;
        }
        const auto main_count = mutation.blocks + fs_count + ref_count + vomap_count + comap_count + 3;
        rw::AppleSpacemanAllocationRequest allocate;
        allocate.expected_checkpoint_xid = nx.xid; allocate.transaction_xid = nx.next_xid;
        allocate.oldest_required_checkpoint_xid = nx.xid;
        for (const auto xid : retained_xids)
            allocate.oldest_required_checkpoint_xid = (std::min)(allocate.oldest_required_checkpoint_xid, xid);
        allocate.reclaim_internal_pool_only = true;
        allocate.first_ephemeral_object_id = nx.next_oid; allocate.main_block_count = static_cast<std::size_t>(main_count);
        allocate.protected_internal_pool_bitmap_indices = bitmap_indices;
        rw::AppleSpacemanAllocationPlan allocation;
        if (!rw::PlanAppleSpacemanAllocation(current.spaceman, allocate, allocation, error)) return {};
        if (allocation.allocated_main_blocks.size() != main_count ||
            std::any_of(allocation.deferred_frees.begin(), allocation.deferred_frees.end(),
                [](const auto& free) { return free.queue_index != 0; }))
            { Fail("EncryptedCowAllocationCoverageInvalid"); return {}; }
        if (allocation.updated_spaceman.free_queues[1].entries.size() != current.spaceman.free_queues[1].entries.size())
            { Fail("EncryptedCowMainQueueChanged"); return {}; }
        for (std::size_t i = 0; i < current.spaceman.free_queues[1].entries.size(); ++i) {
            const auto& before = current.spaceman.free_queues[1].entries[i];
            const auto& after = allocation.updated_spaceman.free_queues[1].entries[i];
            if (before.xid != after.xid || before.physical_block != after.physical_block || before.block_count != after.block_count)
                { Fail("EncryptedCowMainQueueChanged"); return {}; }
        }
        for (const auto block : allocation.allocated_main_blocks)
            if (metadata.contains(block) || payload.contains(block) || keybag_owners.contains(block) || Allocated(current.spaceman, block))
                { Fail("EncryptedCowRetainedOwnerReused"); return {}; }
        for (const auto block : allocation.allocated_internal_pool_blocks)
            if (source.guards.contains(block))
                { Fail("EncryptedCowRequiredInternalOwnerReused"); return {}; }
        const auto& blocks = allocation.allocated_main_blocks;
        const auto n = static_cast<std::size_t>(mutation.blocks);
        const auto data_block = n ? blocks[0] : 0;
        const auto fs_start = n, ref_start = fs_start + fs_count, vomap_start = ref_start + ref_count;
        const auto comap_start = vomap_start + vomap_count;
        const auto fs_block = blocks[fs_start], ref_block = blocks[ref_start];
        const auto vomap_tree_block = blocks[vomap_start], comap_tree_block = blocks[comap_start];
        const auto vomap_block = blocks[comap_start + comap_count], apsb_block = blocks[comap_start + comap_count + 1];
        const auto comap_block = blocks[comap_start + comap_count + 2];
        std::vector<std::uint64_t> new_crypto_ids;
        std::vector<rw::AppleCheckpointPhysicalWrite> writes;
        // ONEKEY IDs are XTS data-unit addresses. Reserve a disjoint high range
        // above every metadata paddr, with 51 random bits and exact exclusions
        // for all observed current/retained data units. Never reuse the old ID
        // for changed plaintext. Unknown discarded history has a probabilistic
        // bound of H / 2^51 per draw for H earlier units in this reserved range.
        // ID * 4096 also fits uint64, including independent readers that
        // multiply by block bytes before dividing by sector bytes.
        if (!scalable && (mutation.rewrite_data || request.kind == EncryptedMutationKind::Unlink)) {
            bool flags_seen = false;
            for (auto& row : fs.records.bytes) if (RowType(row) == 8 && RowId(row) == mutation.stream) {
                rw::AppleEncryptedFileExtentRecord old_extent;
                if (!rw::DecodeAppleEncryptedFileExtentRecord(row, bs, profile, old_extent, error)) return {};
                if (flags_seen && mutation.extent_flags != old_extent.flags)
                    { Fail("EncryptedCowMixedExtentFlagsUnsupported"); return {}; }
                mutation.extent_flags = old_extent.flags; flags_seen = true;
                Wipe(row.key); Wipe(row.value);
            }
            std::erase_if(fs.records.bytes, [](const auto& row) { return row.key.empty(); });
            for (auto& row : refs.records.bytes) {
                rw::ApplePhysicalExtentRecord extent;
                if (!rw::DecodeApplePhysicalExtentRecord(row, extent, error)) return {};
                if (extent.owning_object_id != mutation.stream) continue;
                if (extent.reference_count != 1 || extent.kind != rw::kApplePhysicalExtentKindNew)
                    { Fail("EncryptedCowExactReferenceRequired"); return {}; }
                Wipe(row.key); Wipe(row.value);
            }
            std::erase_if(refs.records.bytes, [](const auto& row) { return row.key.empty(); });
        }
        auto locked_delta = scalable && n ? crypto::SecureBytes::Allocate(bs) : crypto::CryptoResult{};
        if (scalable && n && !locked_delta) { error = "EncryptedDeltaLockedBlockCapacityLimit:" + std::to_string(locked_delta.os_status); return {}; }
        for (std::size_t block_index = 0; block_index < n; ++block_index) {
            std::uint64_t crypto_id = 0;
            for (unsigned attempt = 0; attempt < 64; ++attempt) {
                if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&crypto_id), sizeof(crypto_id), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
                    { Fail("EncryptedCowRandomIdFailure"); return {}; }
                crypto_id = (crypto_id & ((1ULL << 51) - 1)) | (1ULL << 51);
                if (!crypto_ids.contains(crypto_id)) break;
                crypto_id = 0;
            }
            if (!crypto_id) { Fail("EncryptedCowCryptoIdCollisionLimit"); return {}; }
            if (!Remember(crypto_ids, crypto_id)) return {};
            new_crypto_ids.push_back(crypto_id);
            if (scalable && !RenderDelta(mutation, request, block_index, locked_delta.bytes)) return {};
            const auto plain = scalable ? locked_delta.bytes.Bytes() : mutation.plain.Bytes().subspan(block_index * bs, bs);
            std::vector<std::byte> cipher(bs);
            for (std::size_t at = 0; at < bs; at += 512) {
                std::array<std::byte, 16> tweak{};
                const auto unit = crypto_id * (bs / 512) + at / 512;
                for (unsigned i = 0; i < 8; ++i) tweak[i] = static_cast<std::byte>(unit >> (8 * i));
                auto sector = crypto::XtsTransform(owner.key.xts_key.Bytes(), tweak,
                    plain.subspan(at, 512), crypto::XtsDirection::Encrypt);
                if (!sector) { Fail("EncryptedCowDataEncryptionFailed"); return {}; }
                std::copy(sector.bytes.Bytes().begin(), sector.bytes.Bytes().end(), cipher.begin() + at);
            }
            writes.push_back({blocks[block_index], std::move(cipher)});
            if (scalable) continue;
            rw::AppleEncryptedFileExtentRecord extent;
            extent.flags = mutation.extent_flags;
            extent.extent = {mutation.stream, block_index * bs, bs, blocks[block_index], crypto_id, bs};
            fs.records.bytes.emplace_back();
            if (!rw::EncodeAppleEncryptedFileExtentRecord(extent, profile, fs.records.bytes.back(), error)) return {};
            rw::ApplePhysicalExtentRecord reference{blocks[block_index], 1, rw::kApplePhysicalExtentKindNew, mutation.stream, 1};
            refs.records.bytes.emplace_back();
            if (!rw::EncodeApplePhysicalExtentRecord(reference, refs.records.bytes.back(), error)) return {};
        }
        locked_delta.bytes.Clear();
        if (scalable && (mutation.rewrite_data || request.kind == EncryptedMutationKind::Unlink)) {
            std::vector<rw::AppleEncryptedFileExtentRecord> exact;
            if (mutation.rewrite_data && !encrypted_delta::BindData(mutation.delta, std::span(blocks).first(n),
                new_crypto_ids, mutation.extent_flags, exact, error)) return {};
            if (!InstallData(fs, refs, mutation.stream, exact)) return {};
        }
        if (mutation.rewrite_data && request.kind != EncryptedMutationKind::Overwrite) {
            bool has_stream = false;
            for (const auto& row : fs.records.bytes) if (RowType(row) == 6 && RowId(row) == mutation.stream) has_stream = true;
            if (!has_stream) {
                fs.records.bytes.emplace_back();
                if (!rw::EncodeAppleDataStreamIdRecord({mutation.stream, 1}, fs.records.bytes.back(), error)) return {};
            }
        }
        std::vector<rw::ApplePhysicalExtentRecord> candidate_refs;
        if (!rw::ValidateAppleEncryptedPayloadExtentGraph(fs.records.bytes, refs.records.bytes,
                bs, nx.block_count, candidate_refs, error)) return {};
        std::vector<std::byte> bytes;
        const auto serialize_allocated = [&](Tree& tree, rw::AppleBtreeKeyOrder key_order,
            std::size_t start, std::size_t count, bool file_system) {
            std::vector<encrypted_delta::NodeReservation> reserved;
            for (std::size_t i = 0; i < count; ++i)
                reserved.push_back({file_system ? (i ? first_child_oid + i - 1 : selected_volume.root_tree.object_id) : blocks[start + i], blocks[start + i]});
            auto shape = tree.shape; shape.xid = nx.next_xid;
            rw::AppleSerializedBtree serialized;
            if (!encrypted_delta::SerializeReservedTree(tree.records.bytes, shape, key_order, reserved, serialized, error)) return false;
            encrypted_delta::ScopedTreeErase clear{serialized};
            for (auto& object : serialized.objects) {
                if (file_system) {
                    Put(object.bytes, 24, ReadU32LE(object.bytes, 24).value() | 0x10000000u, 4);
                    if (!rw::FinalizeAppleObjectChecksum(object.bytes, error)) return false;
                    auto encrypted = EncryptAppleMetadataBlock(owner.key.xts_key.Bytes(), object.location.physical_block, object.bytes);
                    if (!encrypted) return Fail("EncryptedCowMetadataEncryptionFailed");
                    writes.push_back({object.location.physical_block, std::move(encrypted.bytes)});
                } else writes.push_back({object.location.physical_block, std::move(object.bytes)});
            }
            return true;
        };
        if (scalable) {
            if (!serialize_allocated(fs, order, fs_start, fs_count, true) ||
                !serialize_allocated(refs, rw::AppleBtreeKeyOrder::PhysicalExtent, ref_start, ref_count, false)) return {};
            for (std::size_t i = 0; i < fs_count; ++i)
                if (!Mapping(vomap, i ? first_child_oid + i - 1 : selected_volume.root_tree.object_id,
                    nx.next_xid, blocks[fs_start + i], 4)) return {};
            if (!serialize_allocated(vomap, rw::AppleBtreeKeyOrder::ObjectMap, vomap_start, vomap_count, false)) return {};
        } else {
            std::vector<std::byte> fs_plain; Cleanup clear_fs{fs_plain};
            if (!Serialize(fs, order, selected_volume.root_tree.object_id, fs_block, nx.next_xid, fs_plain)) return {};
            Put(fs_plain, 24, 0x10000000u | kObjectTypeBtree, 4);
            if (!rw::FinalizeAppleObjectChecksum(fs_plain, error)) return {};
            auto encrypted = EncryptAppleMetadataBlock(owner.key.xts_key.Bytes(), fs_block, fs_plain);
            if (!encrypted) { Fail("EncryptedCowMetadataEncryptionFailed"); return {}; }
            writes.push_back({fs_block, std::move(encrypted.bytes)});
            if (!Serialize(refs, rw::AppleBtreeKeyOrder::PhysicalExtent, ref_block, ref_block, nx.next_xid, bytes)) return {};
            writes.push_back({ref_block, std::move(bytes)});
            if (!Mapping(vomap, selected_volume.root_tree.object_id, nx.next_xid, fs_block, 4) ||
                !Serialize(vomap, rw::AppleBtreeKeyOrder::ObjectMap, vomap_tree_block, vomap_tree_block, nx.next_xid, bytes)) return {};
            writes.push_back({vomap_tree_block, std::move(bytes)});
        }
        std::vector<std::byte> original;
        if (!Block(source, selected_volume.object_map.object.physical_block, original) ||
            !rw::PatchAppleObjectMap(original, vomap_block, nx.next_xid, vomap_tree_block, bytes, error)) return {};
        writes.push_back({vomap_block, std::move(bytes)});
        if (!Block(source, selected_volume.superblock_object.physical_block, original)) return {};
        const auto charge = ReadU64LE(original, 0x58).value_or(UINT64_MAX);
        const auto total = ReadU64LE(original, 0xE0).value_or(UINT64_MAX);
        const auto quota = selected_volume.superblock.space.quota_block_count;
        const auto volume_blocks = mutation.blocks + fs_count + ref_count + vomap_count + 2;
        if (charge > UINT64_MAX - volume_blocks || total > UINT64_MAX - volume_blocks || (quota && charge + volume_blocks > quota))
            { Fail("EncryptedCowVolumeCapacityUnsupported"); return {}; }
        // Keep all source ownership charged. Only new volume blocks are added;
        // container OMAP blocks are not charged to this volume. Source volume
        // metadata/payload stays allocated; allocator metadata uses its queues.
        bytes = original; Put(bytes, 16, nx.next_xid); Put(bytes, 0x58, charge + volume_blocks);
        Put(bytes, 0x80, vomap_block); Put(bytes, 0x90, ref_block); Put(bytes, 0xE0, total + volume_blocks);
        Put(bytes, 0xB0, mutation.next_oid); Put(bytes, 0xB8, mutation.file_count);
        Put(bytes, 0xC0, mutation.directory_count);
        if (!rw::FinalizeAppleObjectChecksum(bytes, error)) return {};
        writes.push_back({apsb_block, std::move(bytes)});
        if (!Mapping(comap, selected_volume.superblock.object_id, nx.next_xid, apsb_block, 0)) return {};
        if (scalable) {
            if (!serialize_allocated(comap, rw::AppleBtreeKeyOrder::ObjectMap, comap_start, comap_count, false)) return {};
        } else {
            if (!Serialize(comap, rw::AppleBtreeKeyOrder::ObjectMap, comap_tree_block, comap_tree_block, nx.next_xid, bytes)) return {};
            writes.push_back({comap_tree_block, std::move(bytes)});
        }
        if (!Block(source, current.container_object_map.object.physical_block, original) ||
            !rw::PatchAppleObjectMap(original, comap_block, nx.next_xid, comap_tree_block, bytes, error)) return {};
        writes.push_back({comap_block, std::move(bytes)});
        auto result = std::unique_ptr<EncryptedCowOverwrite>(new EncryptedCowOverwrite);
        if (!Compose(current, allocation, comap_block, writes, result->publication_)) return {};
#ifdef APFSACCESS_ENCRYPTED_COW_TESTING
        for (auto& write : result->publication_.before_superblock_writes)
            if ((encrypted_cow_testing::fault == 1 && write.physical_block == fs_block) ||
                (encrypted_cow_testing::fault == 2 && write.physical_block == data_block)) write.bytes[0] ^= std::byte{1};
#endif
        const auto source_metadata = metadata;
        const auto source_payload = payload;
        for (const auto& write : result->publication_.before_superblock_writes)
            if (source_metadata.contains(write.physical_block) || source_payload.contains(write.physical_block))
                { Fail("EncryptedCowSourceOwnerOverwrite"); return {}; }

        // This exact ciphertext overlay is created here, used here, and never
        // accepted through the immutable current-read capability.
        Candidate candidate(source, result->publication_);
        if (!read_pins.empty()) for (const auto xid : preview_retired) {
            std::string detail;
            if (LoadContainerCheckpointView(candidate, 0, candidate.SizeBytes(), detail, xid))
                { Fail("EncryptedCowRetirementPreviewChanged"); return {}; }
        }
        auto cp = LoadContainerCheckpointView(candidate, 0, candidate.SizeBytes(), error);
        if (!cp || cp->superblock.xid != nx.next_xid) { Fail("EncryptedCowCandidateSelectionFailed"); return {}; }
        for (const auto xid : retained_xids) {
            auto preserved = LoadContainerCheckpointView(candidate, 0, candidate.SizeBytes(), error, xid);
            auto original_cp = LoadContainerCheckpointView(source, 0, source.SizeBytes(), error, xid);
            if (!preserved || !original_cp || preserved->superblock_bytes != original_cp->superblock_bytes)
                { Fail("EncryptedCowRequiredGenerationLost"); return {}; }
        }
        AppleCheckpointView after;
        Tree after_fs, after_refs, after_vomap, after_comap;
        if (!Load(candidate, *cp, after, after_fs, after_refs, after_vomap, after_comap)) return {};
        // Control-ring survival alone is not a recovery proof. Reopen every
        // promised generation, including the source current checkpoint, with
        // its complete original allocator and exact bitmap bytes still present.
        auto promised = retained_xids; promised.push_back(nx.xid);
        for (const auto xid : promised) {
            auto preserved = LoadContainerCheckpointView(candidate, 0, candidate.SizeBytes(), error, xid);
            if (!preserved) { Fail("EncryptedCowRequiredGenerationUnavailableAfterCommit"); return {}; }
            AppleCheckpointView old_view; Tree a, b, c, d;
            if (!Load(candidate, *preserved, old_view, a, b, c, d, &after.spaceman, true)) return {};
            const auto& expected_allocator = xid == nx.xid ? current.spaceman : required_allocators.at(xid);
            const auto read_record = read_records.find(xid);
            const auto& expected_fs = read_record == read_records.end() ? preimage_fs : read_record->second->fs;
            const auto& expected_refs = read_record == read_records.end() ? preimage_refs : read_record->second->refs;
            if (!SameAllocator(expected_allocator, old_view.spaceman) ||
                !SameRecords(expected_fs.bytes, a.records.bytes) || !SameRecords(expected_refs.bytes, b.records.bytes))
                { Fail("EncryptedCowRequiredGenerationBytesChanged"); return {}; }
        }
        if (!rw::SortAppleBtreeRecords(fs.records.bytes, order, error) ||
            !rw::SortAppleBtreeRecords(after_fs.records.bytes, order, error) ||
            fs.records.bytes.size() != after_fs.records.bytes.size()) return {};
        for (std::size_t i = 0; i < fs.records.bytes.size(); ++i)
            if (fs.records.bytes[i].key != after_fs.records.bytes[i].key ||
                fs.records.bytes[i].value != after_fs.records.bytes[i].value)
                { Fail("EncryptedCowCandidateRecordMismatch"); return {}; }
        Impl namespace_check;
        namespace_check.source = owner.source; namespace_check.identity = owner.identity;
        namespace_check.revision = owner.revision; namespace_check.source_size = owner.source_size;
        namespace_check.budget = owner.budget; namespace_check.operation_budget = owner.operation_budget;
        namespace_check.checkpoint = *cp; namespace_check.volume = after.volumes.front().superblock;
        namespace_check.name_policy = owner.name_policy;
        if (!namespace_check.Project(after_fs.records.bytes))
            { Fail("EncryptedCowCandidateNamespaceInvalid"); return {}; }
        if (mutation.replaced_inode && namespace_check.nodes.contains(mutation.replaced_inode))
            { Fail("EncryptedCowReplacementTargetSurvived"); return {}; }
        const auto effective_mode = request.kind == EncryptedMutationKind::Unlink
            ? owner.nodes.at(mutation.inode).mode : namespace_check.nodes.at(mutation.inode).mode;
        const auto expected_mode = mutation.effective_mode;
        if (effective_mode != expected_mode) { Fail("EncryptedCowCandidateModeMismatch"); return {}; }
        auto expected_delta = scalable && n ? crypto::SecureBytes::Allocate(bs) : crypto::CryptoResult{};
        if (scalable && n && !expected_delta) { error = "EncryptedDeltaLockedBlockCapacityLimit:" + std::to_string(expected_delta.os_status); return {}; }
        for (std::size_t i = 0; i < n; ++i) {
            std::vector<std::byte> candidate_cipher;
            if (scalable && !RenderDelta(mutation, request, i, expected_delta.bytes)) return {};
            const auto expected = scalable ? expected_delta.bytes.Bytes() : mutation.plain.Bytes().subspan(i * bs, bs);
            auto reopened = crypto::SecureBytes::Allocate(bs);
            if (!reopened || !Block(candidate, blocks[i], candidate_cipher) ||
                !owner.Transform(candidate_cipher, new_crypto_ids[i] * (bs / 512), reopened.bytes.Bytes()) ||
                !std::equal(expected.begin(), expected.end(), reopened.bytes.Bytes().begin()))
                { Fail("EncryptedCowCandidateDataMismatch"); return {}; }
        }
        for (const auto block : source_payload)
            if (!Allocated(after.spaceman, block)) { Fail("EncryptedCowCandidateRetainedOwnershipLost"); return {}; }
        for (const auto block : source_metadata)
            if (!Allocated(after.spaceman, block)) { Fail("EncryptedCowCandidateMetadataOwnershipLost"); return {}; }
        // Raw source guards cover every observed ownership/keybag/control block
        // that is not a staged destination. The publisher checks them both
        // before writes and after flushed readback, before the NXSB switch.
        if (!VerifyTransitionRetention(candidate, allocation, result->publication_)) return {};
        std::set<std::uint64_t> guard_index;
        for (const auto& guard : result->publication_.guard_blocks) guard_index.insert(guard.physical_block);
        for (const auto& [block, raw] : source.guards) {
            if (candidate.blocks.contains(block) && block != result->publication_.superblock_write.physical_block) continue;
            if (guard_index.insert(block).second) result->publication_.guard_blocks.push_back({block, raw});
        }
        if (!owner.Check()) return {};
        result->source_identity_ = owner.identity;
        result->old_block_ = mutation.old_block; result->new_block_ = data_block;
        result->old_crypto_id_ = mutation.old_crypto; result->new_crypto_id_ = n ? new_crypto_ids[0] : 0;
        result->intent_kind_ = request.kind; result->requested_inode_ = mutation.inode;
        result->requested_offset_ = request.offset; result->replacement_length_ = request.data.size();
        result->parent_ = request.parent; result->destination_parent_ = request.destination_parent;
        result->requested_permissions_ = request.permissions; result->effective_mode_ = effective_mode;
        result->result_size_ = mutation.size; result->source_container_ = nx;
        result->published_container_ = cp->superblock; result->volume_oid_ = owner.volume.object_id;
        result->volume_uuid_ = owner.volume.uuid_hex;
        result->replaced_inode_ = mutation.replaced_inode; result->replaced_private_id_ = mutation.replaced_stream;
        result->replaced_size_ = mutation.replaced_size; result->replaced_mode_ = mutation.replaced_mode;
        if (mutation.replaced_inode && !Digest(std::as_bytes(std::span(mutation.replaced_name)), result->replaced_name_sha256_)) return {};
        if (!Digest(request.data, result->replacement_sha256_) ||
            !Digest(std::as_bytes(std::span(request.name)), result->name_sha256_) ||
            !Digest(std::as_bytes(std::span(request.destination_name)), result->destination_name_sha256_)) return {};
        result->retained_checkpoints_ = retained_xids.size();
        result->retired_checkpoints_ = retired_count;
        result->required_generations_proved_ = promised.size();
        std::set<std::uint64_t> recovery_proved(required.begin(), required.end()); recovery_proved.insert(nx.xid);
        result->required_recovery_checkpoint_xids_.assign(recovery_proved.begin(), recovery_proved.end());
        std::set<std::uint64_t> reads_proved(read_pins.begin(), read_pins.end());
        result->required_read_checkpoint_xids_.assign(reads_proved.begin(), reads_proved.end());
        result->required_checkpoint_xids_ = std::move(promised);
        result->metadata_survivors_walked_ = survivor_metadata_walks;
        return result;
    }
};
