#pragma once

#include "VolumeManagementTestFixture.h"
#include <tuple>

namespace {
AppleCheckpointView AllocationCheckpoint(const std::filesystem::path& image) {
    const auto bytes = Bytes(image);
    VectorRandomAccessSource source(bytes);
    std::string error;
    auto checkpoint = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    Check(!!checkpoint, "allocation checkpoint: " + error);
    return *checkpoint;
}

void AllocationTrail(const std::filesystem::path& image, const char* operation) {
    const auto checkpoint = AllocationCheckpoint(image);
    std::cout << "allocation operation=" << operation
              << " xid=" << checkpoint.container.superblock.xid;
    for (const auto& volume : checkpoint.volumes)
        std::cout << " oid=" << volume.superblock.object_id
                  << " charged=" << volume.superblock.space.allocated_block_count;
    std::cout << '\n';
}

void AllocationOwnership(const std::filesystem::path& image) {
    const auto bytes = Bytes(image);
    VectorRandomAccessSource source(bytes);
    const auto checkpoint = AllocationCheckpoint(image);
    const auto block_size = checkpoint.container.superblock.block_size;
    std::string error;
    for (const auto& volume : checkpoint.volumes) {
        std::vector<std::uint64_t> owned{volume.superblock_object.physical_block,
            volume.object_map.object.physical_block};
        const auto read = [&](const auto& root, std::uint64_t omap,
                              std::vector<apfsaccess::catalog::BtreeRecord>& records) {
            BtreeReadPolicy policy;
            policy.enforce_object_identity = true;
            policy.root_object_id = root.object_id;
            policy.storage_type = root.type;
            policy.subtype = root.subtype;
            policy.require_complete_traversal = true;
            policy.reject_unsupported_flags = true;
            policy.ephemeral_checkpoint = &checkpoint.container;
            std::vector<std::uint64_t> visited;
            policy.visited_physical_blocks = &visited;
            const bool physical = (root.type & kObjectStorageTypeMask) == kObjectPhysical;
            Check(ReadBtreeLeafRecords(source, block_size, root.physical_block, physical,
                physical ? 0 : omap, checkpoint.container.superblock.xid, policy,
                records, error), "complete allocation tree: " + error);
            owned.insert(owned.end(), visited.begin(), visited.end());
        };
        std::vector<apfsaccess::catalog::BtreeRecord> omap, fs, refs, snapshots;
        read(volume.object_map.tree, 0, omap);
        read(volume.root_tree, volume.superblock.omap_oid, fs);
        Check(volume.extentref_tree.has_value(), "allocation extent root");
        read(*volume.extentref_tree, 0, refs);
        if (volume.snapshot_metadata_tree)
            read(*volume.snapshot_metadata_tree, volume.superblock.omap_oid, snapshots);
        Check(snapshots.empty() && !volume.object_map.snapshot_tree_oid,
            "final snapshot inventory is empty");
        std::vector<ApplePhysicalExtentRecord> payload;
        Check(ValidateApplePayloadExtentGraph(fs, refs, block_size,
            checkpoint.container.superblock.block_count, payload, error),
            "final ordinary payload graph: " + error);
        Check(ValidateAppleCheckpointPayloadOwnership(source, checkpoint, payload, error),
            "final payload ownership: " + error);
        std::sort(owned.begin(), owned.end());
        owned.erase(std::unique(owned.begin(), owned.end()), owned.end());
        std::uint64_t payload_blocks = 0;
        for (const auto& extent : payload) payload_blocks += extent.block_count;
        std::cout << "ownership oid=" << volume.superblock.object_id
                  << " metadata=" << owned.size() << " payload=" << payload_blocks
                  << " charged=" << volume.superblock.space.allocated_block_count
                  << " omap_records=" << omap.size() << '\n';
        Check(volume.superblock.space.allocated_block_count == owned.size() + payload_blocks,
            "fresh ordinary charge equals complete owned metadata plus payload");
    }
}

void AllocationManagementAdmission(VolumeManagementRequest request, const char* phase) {
    apfsaccess::volume_management_test::RefreshManagementRequest(request);
    const auto before = Bytes(request.image);
    std::map<std::uint64_t, std::vector<std::byte>> wals;
    for (const auto& [oid, path] : request.sibling_wals) wals[oid] = Bytes(path);
    const auto result = PrepareVolumeCreate(request);
    std::cout << "management phase=" << phase << " outcome="
              << static_cast<unsigned>(result.outcome) << " error=" << result.error << '\n';
    Check(Bytes(request.image) == before, "management preview preserves image");
    for (const auto& [oid, path] : request.sibling_wals)
        Check(Bytes(path) == wals.at(oid), "management preview preserves original WAL");
    if (result.outcome == VolumeManagementOutcome::Prepared) {
        const auto cancelled = CancelVolumeManagement(request, result.confirmation_token);
        Check(cancelled.outcome == VolumeManagementOutcome::Cancelled,
            "cancel prepared management preview: " + cancelled.error);
    }
    Check(result.outcome == VolumeManagementOutcome::Prepared,
        std::string("management admission ") + phase + ": " + result.error);
}

VolumeManagementRequest AllocationFixture(const std::filesystem::path& image,
    std::uint64_t debt = 0, std::uint64_t quota = 0, std::uint64_t sibling_reserve = 0,
    bool sparse = false, unsigned owners = 1) {
    auto spec = RuntimeSpec(owners);
    std::string error;
    if (sparse) {
        for (auto& record : spec.volumes[0].filesystem_records) {
            if (Type(record) != 3 || Id(record) != 17) continue;
            AppleInodeRecord inode;
            Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), "sparse seed inode");
            inode.internal_flags |= kAppleInodeSparseFlag;
            inode.uncompressed_size = 8 * kBlockSize;
            for (auto& field : inode.extended_fields)
                if (field.type == 8) PutU64LE(field.data, 0, 8 * kBlockSize);
            AppleExtendedField field; field.type = kAppleInodeSparseBytesField; field.data.resize(8);
            PutU64LE(field.data, 0, 4 * kBlockSize); inode.extended_fields.push_back(std::move(field));
            Check(EncodeAppleInodeRecord(inode, record, error), "sparse seed encodes");
        }
        apfsaccess::catalog::BtreeRecord hole;
        Check(EncodeAppleFileExtentRecord({17, 4 * kBlockSize, 4 * kBlockSize, 0, 0, kBlockSize},
            hole, error), "explicit physical-zero hole seed");
        spec.volumes[0].filesystem_records.push_back(std::move(hole));
    }
    for (auto& volume : spec.volumes)
        Check(SortAppleBtreeRecords(volume.filesystem_records,
            AppleBtreeKeyOrder::FileSystemHashedDirectory, error),
            "ordinary allocation fixture key order: " + error);
    auto fixture = Fresh(image, spec);
    // Builder defaults model unrelated count damage. This regression starts
    // with a complete ordinary management profile and original durable WALs.
    for (std::size_t i = 0; i < fixture.checkpoint.volumes.size(); ++i) {
        const auto block = fixture.checkpoint.volumes[i].superblock_object.physical_block;
        std::vector<std::byte> apsb(fixture.image.begin() + block * kBlockSize,
            fixture.image.begin() + (block + 1) * kBlockSize);
        PutU32LE(apsb, 0x24, static_cast<std::uint32_t>(i));
        PutU64LE(apsb, 0xb8, 1);
        PutU64LE(apsb, 0xc0, 1);
        if (!i) {
            PutU64LE(apsb, 0x58, ReadU64LE(apsb, 0x58).value() + debt);
            PutU64LE(apsb, 0x50, quota);
        } else PutU64LE(apsb, 0x48, sibling_reserve);
        Check(FinalizeAppleObjectChecksum(apsb, error), "ordinary fixture counts");
        std::copy(apsb.begin(), apsb.end(), fixture.image.begin() + block * kBlockSize);
    }
    for (std::size_t at = 0; at < fixture.image.size(); at += kBlockSize) {
        std::vector<std::byte> nx(fixture.image.begin() + at,
            fixture.image.begin() + at + kBlockSize);
        if (!ParseNxSuperblock(nx)) continue;
        PutU32LE(nx, 0xb4, 100);
        Check(FinalizeAppleObjectChecksum(nx, error), "ordinary fixture management slots");
        std::copy(nx.begin(), nx.end(), fixture.image.begin() + at);
    }
    ::Save(image, fixture.image);
    const auto wal_directory = image.parent_path() / (image.stem().string() + "-wals");
    std::filesystem::create_directory(wal_directory);
    auto request = apfsaccess::volume_management_test::Request(wal_directory, true, fixture.image);
    request.image = image;
    apfsaccess::volume_management_test::ProvisionOriginalWals(request);
    return request;
}

bool AllocationBit(const AppleCheckpointView& cp, std::uint64_t block) {
    for (const auto& chunk : cp.spaceman.chunks) {
        if (chunk.device_index || block < chunk.start_block || block - chunk.start_block >= chunk.block_count) continue;
        const auto bit = block - chunk.start_block;
        return (std::to_integer<unsigned>(chunk.allocation_bitmap.at(bit / 8)) & (1u << (bit % 8))) != 0;
    }
    throw std::runtime_error("retired candidate has no main bitmap");
}

void AllocationDeferredPreserved(const std::filesystem::path& image, const std::vector<std::byte>& before) {
    const auto after = Bytes(image);
    const auto cp = AllocationCheckpoint(image);
    unsigned queued = 0;
    for (const auto& entry : cp.spaceman.free_queues[1].entries) {
        if (entry.xid != cp.container.superblock.xid) continue;
        for (auto b = entry.physical_block; b < entry.physical_block + entry.block_count; ++b) {
            Check(AllocationBit(cp, b), "new retirement remains allocated until a later floor");
            Check(std::equal(before.begin() + b * kBlockSize, before.begin() + (b + 1) * kBlockSize,
                after.begin() + b * kBlockSize), "new retirement bytes never immediately reused");
            ++queued;
        }
    }
    Check(queued > 0, "public operation queues proven retirements");
}

void SnapshotAllocationManagementCycles(unsigned cycles = 3) {
    const auto image = std::filesystem::absolute("image.apfs");
    auto request = AllocationFixture(image);
    AllocationOwnership(image);
    AllocationManagementAdmission(request, "before-snapshots");
    if (!cycles) return;

    {
        Tx journal(L"Strict");
        Configure(journal, request.sibling_wals.at(101));
        auto owner = Open(image, journal);
        auto* sibling = owner->FindSessionStore(102);
        const auto sibling_inode = sibling->LookupCommittedInodeByPath(L"\\clone0");
        Check(!!sibling_inode, "sibling allocation inode");
        std::vector<std::byte> sibling_before;
        Check(sibling->ReadCommittedFileRange(L"\\clone0", 0,
            sibling_inode->logical_size, sibling_before), "sibling allocation payload");
        std::vector<std::byte> expected = LiveBytes(*owner, L"\\clone0");
        const auto operation = [&](const auto& action) {
            const auto before = Bytes(image);
            action();
            AllocationDeferredPreserved(image, before);
        };
        for (unsigned cycle = 0; cycle < cycles; ++cycle) {
            AllocationTrail(image, "before-cycle");
            const auto older_payload = expected;
            operation([&] {Create(*owner, journal, "older");});
            Observe(*owner, 0, older_payload, {std::byte{1}, std::byte{2}, std::byte{3}});
            AllocationTrail(image, "create-older");
            Store::MutationRequest write;
            write.operation = Store::MutationOperation::Write;
            write.path = L"\\clone0";
            write.length = expected.size();
            expected.assign(expected.size(), std::byte(0x50 + cycle));
            operation([&] {Live(*owner, journal, write, expected);});
            Observe(*owner, 0, older_payload, {std::byte{1}, std::byte{2}, std::byte{3}});
            AllocationTrail(image, "write-older");
            const auto newer_payload = expected;
            operation([&] {Create(*owner, journal, "newer");});
            Observe(*owner, 1, newer_payload, {std::byte{1}, std::byte{2}, std::byte{3}});
            AllocationTrail(image, "create-newer");
            expected.assign(expected.size(), std::byte(0x60 + cycle));
            operation([&] {Live(*owner, journal, write, expected);});
            Observe(*owner, 0, older_payload, {std::byte{1}, std::byte{2}, std::byte{3}});
            Observe(*owner, 1, newer_payload, {std::byte{1}, std::byte{2}, std::byte{3}});
            AllocationTrail(image, "write-newer");
            const auto inventory = List(*owner);
            operation([&] {Delete(*owner, journal, inventory.at(cycle % 2).identity);});
            Observe(*owner, 0, cycle % 2 ? older_payload : newer_payload,
                {std::byte{1}, std::byte{2}, std::byte{3}});
            AllocationTrail(image, "delete-first");
            operation([&] {Delete(*owner, journal, List(*owner).at(0).identity);});
            AllocationTrail(image, "delete-last");
            Check(List(*owner).empty(), "all snapshots removed");
            Check(LiveBytes(*owner, L"\\clone0") == expected, "cycle live payload exact");
            Check(owner->DrainAndStop(std::chrono::seconds(2)).clean,
                "cycle owner cleanly drained");
            owner.reset();
            owner = Open(image, journal);
            Check(List(*owner).empty() && LiveBytes(*owner, L"\\clone0") == expected,
                "cycle actual remount preserves inventory and payload");
            std::vector<std::byte> sibling_after;
            Check(owner->FindSessionStore(102)->ReadCommittedFileRange(L"\\clone0", 0,
                sibling_before.size(), sibling_after) && sibling_after == sibling_before,
                "cycle remount preserves sibling payload");
            AllocationOwnership(image);
        }
        Check(owner->DrainAndStop(std::chrono::seconds(2)).clean,
            "final owner cleanly drained before management");
    }
    AllocationManagementAdmission(request, "after-repeated-public-snapshot-cycles");
    std::cout << "PASS repeated public snapshot/write/delete/remount management admission\n";
}

void SnapshotAllocationReaderFloor() {
    const auto image = std::filesystem::absolute("floor.apfs");
    auto request = AllocationFixture(image);
    Tx journal(L"Strict"); Configure(journal, request.sibling_wals.at(101));
    auto owner = Open(image, journal);
    const auto original = LiveBytes(*owner, L"\\clone0");
    Create(*owner, journal, "held");
    const auto held = AllocationCheckpoint(image);
    const auto candidate = held.volumes[0].superblock_object.physical_block;
    const auto preimage = Bytes(image);
    std::string error;
    auto reader = owner->AcquireSnapshotReader(List(*owner)[0].identity, error);
    Check(!!reader, "retention floor reader acquired: " + error);
    Store::MutationRequest write; write.operation = Store::MutationOperation::Write;
    write.path = L"\\clone0"; write.length = original.size();
    const auto queued_at = [&](const AppleCheckpointView& cp) {
        for (const auto& e : cp.spaceman.free_queues[1].entries)
            if (candidate >= e.physical_block && candidate - e.physical_block < e.block_count) return e.xid;
        return std::uint64_t{0};
    };
    Live(*owner, journal, write, std::vector<std::byte>(original.size(), std::byte{0x71}));
    const auto first = AllocationCheckpoint(image);
    const auto retired_xid = queued_at(first);
    Check(retired_xid > held.container.superblock.xid && AllocationBit(first, candidate),
        "candidate queued strictly above held reader checkpoint");
    Live(*owner, journal, write, std::vector<std::byte>(original.size(), std::byte{0x72}));
    const auto pinned = AllocationCheckpoint(image);
    Check(queued_at(pinned) == retired_xid && AllocationBit(pinned, candidate),
        "reader holds queue and bitmap through later WAL cleanup");
    const auto pinned_bytes = Bytes(image);
    Check(std::equal(preimage.begin() + candidate * kBlockSize, preimage.begin() + (candidate + 1) * kBlockSize,
        pinned_bytes.begin() + candidate * kBlockSize), "reader checkpoint candidate remains byte exact");
    std::vector<std::byte> payload;
    Check(reader->Read(17, 0, original.size(), payload) && payload == original,
        "retained reader reads exact payload after multiple live publications and WAL cleanup");
    reader.reset();
    Live(*owner, journal, write, std::vector<std::byte>(original.size(), std::byte{0x73}));
    const auto reclaimed = AllocationCheckpoint(image);
    const auto reclaimed_bytes = Bytes(image);
    Check(!queued_at(reclaimed), "released reader allows candidate to cross retention floor");
    Check(!AllocationBit(reclaimed, candidate) ||
        !std::equal(preimage.begin() + candidate * kBlockSize, preimage.begin() + (candidate + 1) * kBlockSize,
            reclaimed_bytes.begin() + candidate * kBlockSize), "candidate physically reclaimed or safely reused after floor");
    Observe(*owner, 0, original, {std::byte{1}, std::byte{2}, std::byte{3}});
    Delete(*owner, journal, List(*owner)[0].identity);
    Check(owner->DrainAndStop(std::chrono::seconds(2)).clean, "reader floor owner drains");
    std::cout << "PASS reader floor candidate=" << candidate << " retired_xid=" << retired_xid
              << " held_xid=" << held.container.superblock.xid << " reclaimed_at="
              << reclaimed.container.superblock.xid << '\n';
}

void AllocationSerializeQueue(AppleSpacemanAllocationPlan& allocation, std::size_t index) {
    auto& queue = allocation.updated_spaceman.free_queues[index];
    std::sort(queue.entries.begin(), queue.entries.end(), [](const auto& a, const auto& b) {
        return std::tie(a.xid, a.physical_block) < std::tie(b.xid, b.physical_block);
    });
    std::vector<apfsaccess::catalog::BtreeRecord> records;
    queue.block_count = 0;
    for (const auto& entry : queue.entries) {
        apfsaccess::catalog::BtreeRecord record; record.key.resize(16);
        PutU64LE(record.key, 0, entry.xid); PutU64LE(record.key, 8, entry.physical_block);
        if (entry.block_count != 1) {record.value.resize(8); PutU64LE(record.value, 0, entry.block_count);}
        records.push_back(record);
        queue.block_count += entry.block_count;
    }
    AppleBtreeOptions options; options.block_size = kBlockSize; options.xid = allocation.transaction_xid;
    options.root_object_id = queue.tree_oid; options.root_physical_block = 1;
    options.storage_type = kObjectEphemeral; options.subtype = kObjectTypeSpacemanFreeQueue;
    options.tree_flags = queue.tree_flags; options.fixed_key_size = queue.fixed_key_size;
    options.fixed_value_size = queue.fixed_value_size; options.key_order = AppleBtreeKeyOrder::SpacemanFreeQueue;
    options.minimum_longest_key = queue.longest_key; options.minimum_longest_value = queue.longest_value;
    options.max_nodes = 1;
    AppleSerializedBtree tree; std::string error;
    const auto serialized = SerializeAppleBtree(records, options, tree, error);
    Check(serialized && tree.objects.size() == 1,
        "serialized forged queue is a complete checksummed tree: " + error);
    bool replaced = false;
    for (auto& write : allocation.writes)
        if (write.kind == AppleSpacemanWriteKind::FreeQueueTree && write.object_location &&
            write.object_location->object_id == queue.tree_oid) {write.bytes = tree.objects[0].bytes; replaced = true;}
    Check(replaced, "forged queue root exists in allocator writes");
    queue.oldest_xid = queue.entries.empty() ? 0 : queue.entries.front().xid;
    PutU64LE(allocation.updated_spaceman.bytes, 0xc8 + index * 0x28, queue.block_count);
    PutU64LE(allocation.updated_spaceman.bytes, 0xd8 + index * 0x28, queue.oldest_xid);
    Check(FinalizeAppleObjectChecksum(allocation.updated_spaceman.bytes, error), "forged spaceman checksum");
}

AppleTransactionCommitRequest AllocationComposeRequest(const AppleSnapshotCreatePlan& plan) {
    AppleTransactionCommitRequest request;
    request.allocation_plan = plan.allocation; request.snapshot_retirement_volume_oid = 101;
    const auto nx = ParseNxSuperblock(plan.commit.publication.superblock_write.bytes).value();
    request.next_object_id = nx.next_oid; request.container_object_map_oid = nx.omap_oid;
    for (const auto& w : plan.commit.publication.before_superblock_writes)
        if (std::find(plan.allocation.allocated_main_blocks.begin(), plan.allocation.allocated_main_blocks.end(),
            w.physical_block) != plan.allocation.allocated_main_blocks.end()) request.allocated_main_writes.push_back({w.physical_block, w.bytes});
    return request;
}

void SnapshotAllocationComposerProof() {
    const auto image = std::filesystem::absolute("composer.apfs");
    AllocationFixture(image);
    auto bytes = Bytes(image);
    VectorRandomAccessSource source(bytes);
    const auto cp = AllocationCheckpoint(image);
    std::string error;
    AppleSnapshotCreateRequest create; create.volume_object_id = 101; create.name_utf8 = "proof"; create.creation_time_ns = 1;
    AppleSnapshotCreatePlan plan;
    Check(PlanAppleSnapshotCreate(source, cp, create, plan, error), "composer proof create: " + error);
    auto request = AllocationComposeRequest(plan);
    AppleSnapshotInventoryChange change; change.created = plan.identity;
    AppleTransactionCommitPlan composed;
    Check(PlanAppleSnapshotInventoryCommit(source, cp, request, change, composed, error), "independent typed compose valid control: " + error);
    for (const auto offset : {0x58u, 0xe0u, 0xe8u}) {
        auto forged = request;
        for (auto& w : forged.allocated_main_writes) {
            if (ReadU32LE(w.bytes, 0x18) != kObjectTypeFs || ReadU64LE(w.bytes, 8) != 101) continue;
            PutU64LE(w.bytes, offset, ReadU64LE(w.bytes, offset).value() - 1);
            Check(FinalizeAppleObjectChecksum(w.bytes, error), "forged counter checksum");
        }
        Check(!PlanAppleSnapshotInventoryCommit(source, cp, forged, change, composed, error) &&
            error == "AppleSnapshotRetirementCounterUnproven", "typed composer rejects forged counter: " + error);
    }
    auto missing = request;
    missing.allocation_plan.deferred_frees.erase(std::remove_if(missing.allocation_plan.deferred_frees.begin(),
        missing.allocation_plan.deferred_frees.end(), [](const auto& r) {return r.queue_index == 1;}), missing.allocation_plan.deferred_frees.end());
    Check(!PlanAppleSnapshotInventoryCommit(source, cp, missing, change, composed, error), "typed composer rejects missing metadata release");
    {
        auto forged = missing;
        forged.snapshot_retirement_volume_oid = 0;
        for (auto& w : forged.allocated_main_writes) {
            if (ReadU32LE(w.bytes, 0x18) != kObjectTypeFs || ReadU64LE(w.bytes, 8) != 101) continue;
            for (const auto offset : {0x58u, 0xe0u, 0xe8u})
                PutU64LE(w.bytes, offset, ReadU64LE(w.bytes, offset).value() - 1);
            Check(FinalizeAppleObjectChecksum(w.bytes, error), "opt-out forged counters checksum");
        }
        Check(!PlanAppleSnapshotInventoryCommit(source, cp, forged, change, composed, error) &&
            error == "AppleSnapshotRetirementSerializedQueueUnproven",
            "clearing metadata retirement field cannot bypass serialized queue proof: " + error);
    }
    {
        auto forged = request;
        bool changed = false;
        for (auto& entry : forged.allocation_plan.updated_spaceman.free_queues[1].entries)
            if (entry.xid == forged.allocation_plan.transaction_xid) {entry.xid = cp.container.superblock.xid; changed = true;}
        Check(changed, "serialized retirement entries available to backdate");
        AllocationSerializeQueue(forged.allocation_plan, 1);
        const auto ok = PlanAppleSnapshotInventoryCommit(source, cp, forged, change, composed, error);
        Check(!ok && error == "AppleSnapshotRetirementSerializedQueueUnproven",
            "typed composer rejects serialized backdating with unchanged correct release summary: " + error);
    }
    {
        auto forged = request;
        const auto candidate = cp.volumes[0].superblock_object.physical_block;
        auto& allocation = forged.allocation_plan;
        auto& queue = allocation.updated_spaceman.free_queues[1].entries;
        std::vector<AppleSpacemanFreeQueueEntry> entries;
        bool removed = false;
        for (const auto& entry : queue) {
            if (candidate < entry.physical_block || candidate - entry.physical_block >= entry.block_count) entries.push_back(entry);
            else {
                removed = true;
                if (candidate > entry.physical_block) entries.push_back({entry.xid, entry.physical_block, candidate - entry.physical_block});
                const auto end = entry.physical_block + entry.block_count;
                if (candidate + 1 < end) entries.push_back({entry.xid, candidate + 1, end - candidate - 1});
            }
        }
        Check(removed, "preimage APSB has an exact queued retirement"); queue = std::move(entries);
        for (auto& chunk : allocation.updated_spaceman.chunks) {
            if (candidate < chunk.start_block || candidate - chunk.start_block >= chunk.block_count) continue;
            const auto bit = candidate - chunk.start_block;
            chunk.allocation_bitmap[bit / 8] &= static_cast<std::byte>(~(1u << (bit % 8)) & 0xffu);
            ++chunk.free_count; ++allocation.updated_spaceman.devices[0].free_count;
            auto& cib = allocation.updated_spaceman.devices[0].cibs[chunk.cib_index];
            PutU32LE(cib.bytes, 0x28 + chunk.index_in_cib * 0x20 + 0x14, chunk.free_count);
            Check(FinalizeAppleObjectChecksum(cib.bytes, error), "freed preimage CIB checksum");
            for (auto& write : allocation.writes) {
                if (write.kind == AppleSpacemanWriteKind::ChunkBitmap && write.physical_block == chunk.bitmap_block)
                    write.bytes = chunk.allocation_bitmap;
                if (write.kind == AppleSpacemanWriteKind::ChunkInfoBlock && write.physical_block == cib.object.physical_block)
                    write.bytes = cib.bytes;
            }
        }
        PutU64LE(allocation.updated_spaceman.bytes, 0x48, allocation.updated_spaceman.devices[0].free_count);
        AllocationSerializeQueue(allocation, 1);
        const auto ok = PlanAppleSnapshotInventoryCommit(source, cp, forged, change, composed, error);
        Check(!ok && error == "AppleSnapshotRetirementSerializedQueueUnproven",
            "typed composer rejects missing serialized retirement plus consistently freed preimage bitmap: " + error);
    }
    auto ordinary = request;
    Check(!PlanAppleTransactionCommit(source, cp, ordinary, composed, error) &&
        error == "AppleSnapshotRetirementTypedComposerRequired", "ordinary composer cannot authorize retirement");
    create.required_checkpoint_xids = {1};
    Check(!PlanAppleSnapshotCreate(source, cp, create, plan, error), "unavailable recovery pin refuses before publication");
    create.required_checkpoint_xids.clear();
    for (const bool corrupt : {false, true}) {
        auto unknown = bytes;
        const auto& map = cp.volumes[0].object_map;
        if (corrupt) unknown.at(map.tree.physical_block * kBlockSize + 100) ^= std::byte{1};
        else {
            BtreeReadPolicy policy; policy.enforce_object_identity = true; policy.root_object_id = map.tree.object_id;
            policy.storage_type = kObjectPhysical; policy.subtype = kObjectTypeOmap;
            policy.require_complete_traversal = true; policy.reject_unsupported_flags = true;
            std::vector<BtreeRecord> records;
            Check(ReadBtreeLeafRecords(source, kBlockSize, map.tree.physical_block, true, 0,
                cp.container.superblock.xid, policy, records, error), "unknown history map read");
            auto alias = records.front(); PutU64LE(alias.key, 0, 999999); records.push_back(alias);
            AppleBtreeOptions options; options.block_size = kBlockSize; options.xid = map.tree.xid;
            options.root_object_id = options.root_physical_block = map.tree.physical_block;
            options.storage_type = kObjectPhysical; options.subtype = kObjectTypeOmap;
            options.tree_flags = kAppleBtreePhysical; options.key_order = AppleBtreeKeyOrder::ObjectMap;
            options.fixed_key_size = options.fixed_value_size = 16;
            AppleSerializedBtree tree;
            Check(SerializeAppleBtree(records, options, tree, error) && tree.objects.size() == 1, "checksum valid unknown map alias");
            std::copy(tree.objects[0].bytes.begin(), tree.objects[0].bytes.end(), unknown.begin() + map.tree.physical_block * kBlockSize);
        }
        VectorRandomAccessSource unknown_source(unknown);
        const auto unknown_cp = LoadAppleCheckpointView(unknown_source, 0, unknown.size(), error);
        Check(!unknown_cp || !PlanAppleSnapshotCreate(unknown_source, *unknown_cp, create, plan, error),
            corrupt ? "corrupt complete OMAP refuses" : "unknown OMAP alias cannot invent ownership");
    }
    Check(Bytes(image) == bytes, "composer negatives preserve image");
    std::cout << "PASS independent typed composer counter/release/recovery enforcement\n";
}

void SnapshotAllocationHiddenHistory() {
    const auto image = std::filesystem::absolute("hidden-history.apfs");
    auto management = AllocationFixture(image);
    Tx journal(L"Strict"); Configure(journal, management.sibling_wals.at(101));
    auto owner = Open(image, journal);
    Create(*owner, journal, "older");
    Store::MutationRequest write; write.operation = Store::MutationOperation::Write;
    write.path = L"\\clone0"; write.length = 4 * kBlockSize;
    Live(*owner, journal, write, std::vector<std::byte>(write.length, std::byte{0x81}));
    Create(*owner, journal, "newer");
    Live(*owner, journal, write, std::vector<std::byte>(write.length, std::byte{0x82}));
    Delete(*owner, journal, List(*owner)[0].identity);
    const auto pin = AllocationCheckpoint(image);
    const auto pin_bytes = Bytes(image); VectorRandomAccessSource source(pin_bytes);
    std::string error;
    AppleSnapshotRetentionView logical;
    Check(LoadAppleSnapshotRetention(source, pin, logical, error), "public hidden-history control: " + error);
    AppleSnapshotCreateRequest create; create.volume_object_id = 101; create.name_utf8 = "next"; create.creation_time_ns = 1;
    AppleSnapshotCreatePlan planned;
    Check(PlanAppleSnapshotCreate(source, pin, create, planned, error), "full hidden-history control plan: " + error);
    AppleSnapshotRetirementProof proof;
    Check(ProveAppleSnapshotRetirement(source, pin, planned.commit.publication, 101, {}, proof, error),
        "full hidden-history control closure: " + error);
    std::uint64_t hidden_owner = 0;
    for (const auto block : proof.source_metadata_blocks) {
        if (ReadU32LE(pin_bytes, block * kBlockSize + 0x18) != (kObjectPhysical | kObjectTypeFs) ||
            std::find(logical.metadata_blocks.begin(), logical.metadata_blocks.end(), block) != logical.metadata_blocks.end()) continue;
        hidden_owner = block; break;
    }
    Check(hidden_owner != 0, "historical inventory retains an APSB absent from public snapshot census");
    std::vector<std::pair<AppleCheckpointPhysicalWrite,std::string>> hidden_payload_forgeries;
    {
        const auto extent_block = ReadU64LE(pin_bytes, hidden_owner * kBlockSize + 0x90).value();
        Check(std::find(logical.metadata_blocks.begin(), logical.metadata_blocks.end(), extent_block) ==
            logical.metadata_blocks.end(), "historical extent root is outside public snapshot census");
        BtreeReadPolicy policy; policy.enforce_object_identity = true; policy.require_complete_traversal = true;
        policy.reject_unsupported_flags = true; policy.root_object_id = extent_block;
        policy.storage_type = kObjectPhysical; policy.subtype = kObjectTypeBlockRefTree;
        std::vector<apfsaccess::catalog::BtreeRecord> refs;
        Check(ReadBtreeLeafRecords(source, kBlockSize, extent_block, true, 0,
            pin.container.superblock.xid, policy, refs, error), "hidden extent-reference records read");
        Check(refs.size() == 1, "hidden fixture has one exact NEW payload reference");
        BtreeReadPolicy fs_policy = policy;
        fs_policy.storage_type = 0; fs_policy.subtype = kObjectTypeFsTree;
        fs_policy.root_object_id = pin.volumes[0].root_tree.object_id;
        std::vector<apfsaccess::catalog::BtreeRecord> fs;
        Check(ReadBtreeLeafRecords(source, kBlockSize, pin.volumes[0].root_tree.physical_block,
            false, pin.volumes[0].superblock.omap_oid, pin.container.superblock.xid, fs_policy, fs, error),
            "live allocated payload source for hidden forgery");
        std::uint64_t live_block = 0;
        for (const auto& record : fs) if (Type(record) == 8) {
            AppleFileExtentRecord extent;
            Check(DecodeAppleFileExtentRecord(record, kBlockSize, extent, error), "live forgery extent decodes");
            if (extent.physical_block) {live_block = extent.physical_block; break;}
        }
        Check(live_block && live_block != (ReadU64LE(refs[0].key, 0).value() & 0x0fffffffffffffffull),
            "hidden unmatched payload is a distinct currently owned allocation");
        for (const bool wrong_count : {false, true}) {
            const std::string expected_error=wrong_count ? "AppleVolumePhysicalExtentRefcountMismatch" : "AppleVolumePhysicalExtentMissing";
            auto forged = refs;
            if (wrong_count) PutU32LE(forged[0].value, 16, 2);
            else PutU64LE(forged[0].key, 0, (2ull << 60) | live_block);
            AppleBtreeOptions options; options.block_size = kBlockSize;
            options.xid = ReadU64LE(pin_bytes, extent_block * kBlockSize + 0x10).value();
            options.root_object_id = options.root_physical_block = extent_block;
            options.storage_type = kObjectPhysical; options.subtype = kObjectTypeBlockRefTree;
            options.tree_flags = kAppleBtreePhysical; options.key_order = AppleBtreeKeyOrder::PhysicalExtent;
            options.max_nodes = 1;
            AppleSerializedBtree tree;
            Check(SerializeAppleBtree(forged, options, tree, error) && tree.objects.size() == 1,
                "hidden extent forgery is checksum valid");
            auto corrupt = pin_bytes;
            std::copy(tree.objects[0].bytes.begin(), tree.objects[0].bytes.end(), corrupt.begin() + extent_block * kBlockSize);
            VectorRandomAccessSource held(corrupt);
            const auto current = LoadAppleCheckpointView(held, 0, corrupt.size(), error);
            Check(!!current && LoadAppleSnapshotRetention(held, *current, logical, error),
                "hidden payload forgery is outside public logical proof: " + error);
            const bool accepted_forgery = PlanAppleSnapshotCreate(held, *current, create, planned, error);
            Check(!accepted_forgery &&
                error == expected_error,
                "hidden NEW payload coverage and exact refcount cannot invent ownership: " + error);
            std::vector<std::uint64_t> bad_metadata;
            std::vector<ApplePhysicalExtentRecord> bad_payload;
            Check(!LoadAppleSnapshotCheckpointOwners(held, *current, bad_metadata, bad_payload, error) &&
                error == expected_error && bad_metadata.empty() && bad_payload.empty(),
                "current recovery owner census rejects hidden unproven payload ownership: " + error);
            std::vector<AppleRecoveryCheckpointView> current_only;
            Check(!LoadAppleSnapshotRecoveryCheckpoints(held, *current,
                {current->container.superblock.xid}, current_only, error) &&
                error == expected_error && current_only.empty(),
                "current-only required checkpoint cannot bypass hidden payload proof: " + error);
            hidden_payload_forgeries.push_back({{extent_block, tree.objects[0].bytes},expected_error});
        }
    }
    bool forged_inventory = false;
    for (const auto block : proof.source_metadata_blocks) {
        if (ReadU32LE(pin_bytes, block * kBlockSize + 0x18) != kObjectTypeBtree ||
            ReadU32LE(pin_bytes, block * kBlockSize + 0x1c) != kObjectTypeSnapMetaTree) continue;
        BtreeReadPolicy policy; policy.enforce_object_identity = true; policy.require_complete_traversal = true;
        policy.reject_unsupported_flags = true; policy.root_object_id = ReadU64LE(pin_bytes, block * kBlockSize + 8).value();
        policy.storage_type = 0; policy.subtype = kObjectTypeSnapMetaTree;
        std::vector<apfsaccess::catalog::BtreeRecord> records;
        Check(ReadBtreeLeafRecords(source, kBlockSize, block, false, pin.volumes[0].superblock.omap_oid,
            pin.container.superblock.xid, policy, records, error), "hidden inventory leaf read: " + error);
        bool changed = false;
        for (auto& record : records) {
            if ((ReadU64LE(record.key, 0).value() >> 60) != 1 || ReadU64LE(record.value, 8) != hidden_owner) continue;
            PutU64LE(record.value, 0, pin.volumes[1].superblock.extentref_tree_oid); changed = true;
        }
        if (!changed) continue;
        AppleBtreeOptions options; options.block_size = kBlockSize;
        options.xid = ReadU64LE(pin_bytes, block * kBlockSize + 0x10).value();
        options.root_object_id = policy.root_object_id; options.root_physical_block = block;
        options.storage_type = 0; options.subtype = kObjectTypeSnapMetaTree;
        options.key_order = AppleBtreeKeyOrder::FileSystemCaseSensitive; options.max_nodes = 1;
        AppleSerializedBtree tree;
        Check(SerializeAppleBtree(records, options, tree, error) && tree.objects.size() == 1,
            "hidden inventory forged reference has a valid checksum: " + error);
        auto corrupt = pin_bytes;
        std::copy(tree.objects[0].bytes.begin(), tree.objects[0].bytes.end(), corrupt.begin() + block * kBlockSize);
        VectorRandomAccessSource corrupt_source(corrupt);
        const auto corrupt_cp = LoadAppleCheckpointView(corrupt_source, 0, corrupt.size(), error);
        Check(!!corrupt_cp && LoadAppleSnapshotRetention(corrupt_source, *corrupt_cp, logical, error),
            "hidden forged edge is outside current public inventory validation: " + error);
        const auto ok = PlanAppleSnapshotCreate(corrupt_source, *corrupt_cp, create, planned, error);
        Check(!ok && error == "AppleSnapshotRetirementInventoryRootUnproven",
            "full closure rejects hidden extent root disagreement: " + error);
        forged_inventory = true; break;
    }
    Check(forged_inventory, "hidden inventory negative exercised an actual retained edge");
    Delete(*owner, journal, List(*owner)[0].identity);
    Check(owner->UpdateRequiredCheckpointXids(102, {pin.container.superblock.xid}, error),
        "sibling recovery retains full older hidden checkpoint: " + error);
    Create(*owner, journal, "after-delete");
    const auto tip = AllocationCheckpoint(image);
    const auto bytes = Bytes(image); VectorRandomAccessSource tip_source(bytes);
    for (const auto& [forgery,expected_error] : hidden_payload_forgeries) {
        auto corrupt = bytes;
        std::copy(forgery.bytes.begin(), forgery.bytes.end(), corrupt.begin() + forgery.physical_block * kBlockSize);
        VectorRandomAccessSource held(corrupt);
        const auto current = LoadAppleCheckpointView(held, 0, corrupt.size(), error);
        Check(!!current, "accepted-history payload negative has a valid current endpoint");
        std::vector<AppleRecoveryCheckpointView> rejected;
        Check(!LoadAppleSnapshotRecoveryCheckpoints(held, *current, {pin.container.superblock.xid}, rejected, error) &&
            error == expected_error && rejected.empty(),
            "accepted historical payload proof rejects hidden NEW coverage/refcount forgery: " + error);
    }
    std::vector<AppleRecoveryCheckpointView> history;
    Check(LoadAppleSnapshotRecoveryCheckpoints(tip_source, tip, {pin.container.superblock.xid}, history, error),
        "accepted hidden history continuity control: " + error);
    const auto retained = std::find_if(history.begin(), history.end(), [&](const auto& old) {
        return old.checkpoint.container.superblock.xid == pin.container.superblock.xid;
    });
    Check(retained != history.end() && std::find(retained->metadata_blocks.begin(), retained->metadata_blocks.end(),
        hidden_owner) != retained->metadata_blocks.end(), "recovery census includes hidden APSB owner");
    AppleSpacemanAllocationPlan forged; forged.updated_spaceman = tip.spaceman;
    forged.transaction_xid = tip.container.superblock.xid;
    auto& queue = forged.updated_spaceman.free_queues[1];
    std::vector<AppleSpacemanFreeQueueEntry> entries;
    bool changed = false;
    for (const auto& entry : queue.entries) {
        if (hidden_owner < entry.physical_block || hidden_owner - entry.physical_block >= entry.block_count) entries.push_back(entry);
        else {
            Check(entry.xid > pin.container.superblock.xid && entry.xid < tip.container.superblock.xid,
                "hidden retirement has a later accepted checkpoint to forge");
            if (hidden_owner > entry.physical_block) entries.push_back({entry.xid, entry.physical_block, hidden_owner - entry.physical_block});
            entries.push_back({tip.container.superblock.xid, hidden_owner, 1});
            const auto end = entry.physical_block + entry.block_count;
            if (hidden_owner + 1 < end) entries.push_back({entry.xid, hidden_owner + 1, end - hidden_owner - 1});
            changed = true;
        }
    }
    Check(changed && AllocationBit(tip, hidden_owner), "hidden owner stays allocated while queue continuity is forged");
    queue.entries = std::move(entries);
    forged.writes.push_back({AppleSpacemanWriteKind::FreeQueueTree, 0, queue.root, {}});
    AllocationSerializeQueue(forged, 1);
    auto corrupt = bytes;
    std::copy(forged.writes[0].bytes.begin(), forged.writes[0].bytes.end(), corrupt.begin() + queue.root.physical_block * kBlockSize);
    std::copy(forged.updated_spaceman.bytes.begin(), forged.updated_spaceman.bytes.end(),
        corrupt.begin() + tip.spaceman.object.physical_block * kBlockSize);
    VectorRandomAccessSource corrupt_source(corrupt);
    const auto corrupt_cp = LoadAppleCheckpointView(corrupt_source, 0, corrupt.size(), error);
    Check(!!corrupt_cp && AllocationBit(*corrupt_cp, hidden_owner), "forged hidden queue remains checksummed and allocated: " + error);
    const auto ok = LoadAppleSnapshotRecoveryCheckpoints(corrupt_source, *corrupt_cp,
        {pin.container.superblock.xid}, history, error);
    Check(!ok && error == "AppleCheckpointRetentionContinuityUnavailable",
        "full recovery closure rejects changed hidden retirement XID despite final bit set: " + error);
    Check(Bytes(image) == bytes, "hidden-history negatives preserve source image");
    Check(owner->UpdateRequiredCheckpointXids(102, {}, error), "release synthetic sibling recovery pin");
    Check(owner->DrainAndStop(std::chrono::seconds(2)).clean, "hidden-history owner drains");
    std::cout << "PASS hidden inventory edge and accepted queue continuity owner=" << hidden_owner << '\n';
}

void SnapshotAllocationSparseCycle() {
    {
        const auto image = std::filesystem::absolute("shared-sparse-refused.apfs");
        auto management = AllocationFixture(image, 0, 0, 0, true, 2);
        Tx journal(L"Strict"); Configure(journal, management.sibling_wals.at(101));
        auto owner = Open(image, journal);
        Create(*owner, journal, "shared-sparse-retained-boundary");
        const auto before = Bytes(image);
        const auto wal = Bytes(management.sibling_wals.at(101));
        const auto accepted = journal.Watermarks().accepted_sequence;
        Store::MutationRequest resize; resize.operation = Store::MutationOperation::SetFileSize;
        resize.path = L"\\clone0"; resize.length = 12 * kBlockSize;
        bool acceptance_called = false;
        const auto result = owner->Commit(101, {resize}, [&](const auto&, const auto&, auto, auto&, std::string&) {
            acceptance_called = true; return false;
        });
        Check(!result.committed && !result.commit_recovery_required && result.clean_prepublication_refusal &&
            !owner->IsRecoveryRequired() && result.commit_stage == "mutation-staging" &&
            result.mutation_staging_status == Store::MutationStatus::UnsupportedOperation &&
            result.error.find("status=4") != std::string::npos, "shared sparse resize with retained snapshot refuses unsupported ownership: " + result.error);
        Check(!acceptance_called && journal.Watermarks().accepted_sequence == accepted &&
            Bytes(image) == before && Bytes(management.sibling_wals.at(101)) == wal,
            "shared sparse refusal precedes acceptance and preserves image WAL");
        Check(owner->DrainAndStop(std::chrono::seconds(2)).clean, "shared sparse refusal owner drains");
    }
    const auto image = std::filesystem::absolute("sparse-accounting.apfs");
    auto management = AllocationFixture(image, 0, 0, 0, true);
    {
    Tx journal(L"Strict"); Configure(journal, management.sibling_wals.at(101));
    auto owner = Open(image, journal);
    const auto original = LiveBytes(*owner, L"\\clone0");
    const auto checkpoint = AllocationCheckpoint(image);
    const auto bytes = Bytes(image); VectorRandomAccessSource source(bytes);
    const auto& root = checkpoint.volumes[0].root_tree;
    BtreeReadPolicy policy; policy.enforce_object_identity = true; policy.require_complete_traversal = true;
    policy.reject_unsupported_flags = true; policy.root_object_id = root.object_id;
    policy.storage_type = root.type; policy.subtype = root.subtype;
    std::vector<apfsaccess::catalog::BtreeRecord> records; std::string error;
    Check(ReadBtreeLeafRecords(source, kBlockSize, root.physical_block, false,
        checkpoint.volumes[0].superblock.omap_oid, checkpoint.container.superblock.xid, policy, records, error),
        "sparse public filesystem census: " + error);
    unsigned holes = 0;
    for (const auto& record : records) {
        if ((ReadU64LE(record.key, 0).value() >> 60) != 8) continue;
        AppleFileExtentRecord extent;
        Check(DecodeAppleFileExtentRecord(record, kBlockSize, extent, error), "sparse extent decodes strictly");
        if (!extent.physical_block) ++holes;
    }
    Check(holes > 0, "fixture contains an actual physical-zero sparse extent");
    Check(original.size() == 8 * kBlockSize && std::all_of(original.begin() + 4 * kBlockSize,
        original.end(), [](auto b) { return b == std::byte{0}; }), "sparse source bytes are exact");
    Store::MutationRequest unsupported_clone;
    const auto accepted = journal.Watermarks().accepted_sequence;
    Check(!owner->FindSessionStore(101)->PrepareNativeClone(L"\\clone0", L"\\sparse-copy", unsupported_clone),
        "existing sparse clone profile remains refused");
    Check(Bytes(image) == bytes && journal.Watermarks().accepted_sequence == accepted,
        "unsupported sparse clone preserves image and accepted watermark");
    Create(*owner, journal, "with-hole");
    Store::MutationRequest resize; resize.operation = Store::MutationOperation::SetFileSize;
    resize.path = L"\\clone0"; resize.length = 12 * kBlockSize; Live(*owner, journal, resize);
    auto grown = original; grown.resize(resize.length, std::byte{0});
    Check(LiveBytes(*owner, L"\\clone0") == grown, "public sparse-owner growth preserves payload and zero fills");
    Create(*owner, journal, "grown-hole");
    Observe(*owner, 0, original, {std::byte{1}, std::byte{2}, std::byte{3}});
    Observe(*owner, 1, grown, {std::byte{1}, std::byte{2}, std::byte{3}});
    resize.path = L"\\clone0"; resize.length = 4 * kBlockSize; Live(*owner, journal, resize);
    Observe(*owner, 1, grown, {std::byte{1}, std::byte{2}, std::byte{3}});
    Delete(*owner, journal, List(*owner)[0].identity);
    Delete(*owner, journal, List(*owner)[0].identity);
    Check(owner->DrainAndStop(std::chrono::seconds(2)).clean, "sparse cycle drains"); owner.reset();
    auto reopened = Open(image, journal);
    auto truncated = original; truncated.resize(4 * kBlockSize);
    Check(LiveBytes(*reopened, L"\\clone0") == truncated,
        "sparse cycle reopens with exact truncated payload");
    Check(reopened->DrainAndStop(std::chrono::seconds(2)).clean, "sparse reopened owner drains"); reopened.reset();
    }
    AllocationOwnership(image);
    apfsaccess::volume_management_test::RefreshManagementRequest(management);
    AllocationManagementAdmission(management, "after-sparse-snapshot-cycle");
    std::cout << "PASS physical-zero holes contribute no allocated ownership or charge\n";
}

void SnapshotAllocationSourceDeficit() {
    const auto patch_charge = [](auto& bytes, const auto& cp, std::size_t index, std::uint64_t quota) {
        const auto b = cp.volumes[index].superblock_object.physical_block;
        std::vector<std::byte> apsb(bytes.begin() + b * kBlockSize, bytes.begin() + (b + 1) * kBlockSize);
        PutU64LE(apsb, 0x58, 4); PutU64LE(apsb, 0x50, quota);
        std::string error; Check(FinalizeAppleObjectChecksum(apsb, error), "source deficit checksum");
        std::copy(apsb.begin(), apsb.end(), bytes.begin() + b * kBlockSize);
    };
    for (const auto [index, quota] : {std::pair{0u, 0ull}, std::pair{0u, 10ull}, std::pair{1u, 0ull}}) {
        const auto image = std::filesystem::absolute("deficit-" + std::to_string(index) + "-" + std::to_string(quota) + ".apfs");
        auto management = AllocationFixture(image);
        auto bytes = Bytes(image); VectorRandomAccessSource source(bytes);
        const auto cp = AllocationCheckpoint(image);
        AppleSnapshotCreateRequest create; create.volume_object_id = 101; create.name_utf8 = "deficit"; create.creation_time_ns = 1;
        AppleSnapshotCreatePlan control; std::string error;
        Check(PlanAppleSnapshotCreate(source, cp, create, control, error), "source deficit valid control: " + error);
        auto forged = bytes; patch_charge(forged, cp, index, quota);
        VectorRandomAccessSource bad_source(forged);
        const auto bad_cp = LoadAppleCheckpointView(bad_source, 0, forged.size(), error);
        Check(!!bad_cp, "checksummed deficit checkpoint parses");
        AppleSnapshotCreatePlan refused;
        Check(!PlanAppleSnapshotCreate(bad_source, *bad_cp, create, refused, error) &&
            error == "AppleSnapshotRetirementSourceChargeUnproven", "source deficit refuses before create: " + error);
        Check(refused.commit.publication.before_superblock_writes.empty() &&
            refused.commit.publication.superblock_write.bytes.empty(), "deficit create emits no publication");
        auto request = AllocationComposeRequest(control);
        for (auto& write : request.allocated_main_writes) {
            if (index || ReadU32LE(write.bytes, 0x18) != kObjectTypeFs || ReadU64LE(write.bytes, 8) != 101) continue;
            PutU64LE(write.bytes, 0x50, quota); PutU64LE(write.bytes, 0x58, 10);
            Check(FinalizeAppleObjectChecksum(write.bytes, error), "deficit bypass final charge checksum");
        }
        AppleSnapshotInventoryChange change; change.created = control.identity;
        for (const auto retire : {true, false}) {
            auto typed = request;
            typed.snapshot_retirement_volume_oid = retire ? 101 : 0;
            AppleTransactionCommitPlan composed;
            const auto ok = PlanAppleSnapshotInventoryCommit(bad_source, *bad_cp, typed, change, composed, error);
            const auto expected = retire ? "AppleSnapshotRetirementSourceChargeUnproven" : "AppleSnapshotInventoryReleaseNotProven";
            Check(!ok && error == expected,
                std::string(retire ? "typed composer rejects source deficit" : "cleared marker retains earlier metadata release refusal") +
                " index=" + std::to_string(index) +
                " quota=" + std::to_string(quota) + " retire=" + std::to_string(retire) +
                " ok=" + std::to_string(ok) + ": " + error);
            Check(composed.publication.superblock_write.bytes.empty() && composed.publication.before_superblock_writes.empty(),
                "deficit typed composer emits no executable publication");
        }
        Save(image, forged);
        {
            Tx journal(L"Strict"); Configure(journal, management.sibling_wals.at(101));
            auto owner = Open(image, journal); const auto wal = Bytes(management.sibling_wals.at(101));
            const auto accepted = journal.Watermarks().accepted_sequence;
            SnapshotRuntimePlan runtime;
            Check(!PrepareSnapshotCreate(*owner, 101, "deficit", 1, 0, runtime, error) &&
                error == "AppleSnapshotRetirementSourceChargeUnproven", "public deficit prepare refuses: " + error);
            Check(runtime.request.inline_payload.empty() && !runtime.owner, "deficit emits no owner-bound runtime plan");
            Check(Bytes(image) == forged && Bytes(management.sibling_wals.at(101)) == wal &&
                journal.Watermarks().accepted_sequence == accepted, "deficit refusal preserves image WAL and acceptance");
            Check(owner->DrainAndStop(std::chrono::seconds(2)).clean, "deficit owner drains");
        }
    }
    const auto image = std::filesystem::absolute("deficit-history.apfs");
    auto management = AllocationFixture(image);
    {
        Tx journal(L"Strict"); Configure(journal, management.sibling_wals.at(101));
        auto owner = Open(image, journal); Create(*owner, journal, "history");
        Check(owner->DrainAndStop(std::chrono::seconds(2)).clean, "deficit history owner drains");
    }
    auto bytes = Bytes(image); const auto cp = AllocationCheckpoint(image); patch_charge(bytes, cp, 0, 0);
    VectorRandomAccessSource source(bytes); std::string error;
    const auto bad_cp = LoadAppleCheckpointView(source, 0, bytes.size(), error);
    Check(!!bad_cp, "snapshot-bearing deficit checkpoint parses");
    ApfsSnapshotScope scope{0, bytes.size(), bad_cp->container.superblock.uuid_hex,
        bad_cp->volumes[0].superblock.uuid_hex, 101, bad_cp->container.superblock.xid};
    std::vector<ApfsSnapshotInfo> inventory;
    Check(ApfsSnapshotStore::Enumerate(source, scope, inventory, error) && inventory.size() == 1, "deficit retained snapshot inventory");
    AppleSnapshotDeleteRequest deletion; deletion.expected = inventory[0].identity; deletion.modification_time_ns = 1;
    AppleSnapshotDeletePlan deleted;
    Check(!PlanAppleSnapshotDelete(source, *bad_cp, deletion, deleted, error) &&
        error == "AppleSnapshotRetirementSourceChargeUnproven", "source deficit refuses snapshot delete: " + error);
    Check(deleted.commit.publication.superblock_write.bytes.empty(), "deficit delete emits no publication");
    for (const auto index : {0u, 1u}) {
        const auto& v = bad_cp->volumes[index]; const auto& root = v.root_tree;
        BtreeReadPolicy policy; policy.enforce_object_identity = true; policy.require_complete_traversal = true;
        policy.reject_unsupported_flags = true; policy.root_object_id = root.object_id;
        policy.storage_type = root.type; policy.subtype = root.subtype;
        AppleVolumeTransactionRequest mutation; mutation.volume_object_id = v.superblock.object_id;
        Check(ReadBtreeLeafRecords(source, kBlockSize, root.physical_block, false,
            v.superblock.omap_oid, bad_cp->container.superblock.xid, policy, mutation.filesystem_records, error), "deficit ordinary records");
        mutation.last_modification_time = 1; AppleVolumeTransactionPlan plan;
        const auto ok = index ? PlanAppleSnapshotSiblingTransaction(source, *bad_cp, mutation, plan, error)
            : PlanAppleSnapshotLiveTransaction(source, *bad_cp, mutation, plan, error);
        Check(!ok && error == "AppleSnapshotRetirementSourceChargeUnproven",
            "same source deficit proof protects live and ordinary sibling composition: " + error);
        Check(plan.commit.publication.superblock_write.bytes.empty(), "deficit mutation emits no publication");
    }
    std::cout << "PASS source charge deficit and quota bypass refuse without publication or acceptance\n";
}

void SnapshotAllocationAdmissionNegatives() {
    for (const auto quota : {15ull, 16ull}) {
        const auto image = std::filesystem::absolute("quota-" + std::to_string(quota) + ".apfs");
        auto management = AllocationFixture(image, 0, quota);
        const auto bytes = Bytes(image); VectorRandomAccessSource source(bytes);
        auto cp = AllocationCheckpoint(image);
        AppleSnapshotCreateRequest request; request.volume_object_id = 101; request.name_utf8 = "quota"; request.creation_time_ns = 1;
        AppleSnapshotCreatePlan plan; std::string error;
        const auto ok = PlanAppleSnapshotCreate(source, cp, request, plan, error);
        Check(ok == (quota == 16), "quota uses exact final charge: " + error);
        if (!ok) Check(error == "AppleVolumeQuotaExceeded", "quota refusal reason");
        Check(Bytes(image) == bytes, "quota preflight preserves source");
    }
    {
        const auto image = std::filesystem::absolute("reserve.apfs");
        AllocationFixture(image);
        auto bytes = Bytes(image); auto cp = AllocationCheckpoint(image);
        const auto b = cp.volumes[1].superblock_object.physical_block;
        std::vector<std::byte> apsb(bytes.begin() + b * kBlockSize, bytes.begin() + (b + 1) * kBlockSize);
        PutU64LE(apsb, 0x48, cp.volumes[1].superblock.space.allocated_block_count + cp.spaceman.devices[0].free_count);
        std::string error; Check(FinalizeAppleObjectChecksum(apsb, error), "reserve negative checksum");
        std::copy(apsb.begin(), apsb.end(), bytes.begin() + b * kBlockSize);
        VectorRandomAccessSource source(bytes);
        const auto protected_cp = LoadAppleCheckpointView(source, 0, bytes.size(), error);
        Check(!!protected_cp, "reserve protected source checkpoint");
        AppleSnapshotCreateRequest request; request.volume_object_id = 101; request.name_utf8 = "reserve"; request.creation_time_ns = 1;
        AppleSnapshotCreatePlan plan;
        const auto planned = PlanAppleSnapshotCreate(source, *protected_cp, request, plan, error);
        Check(!planned && error == "AppleVolumeSiblingReserveProtected",
            "deferred retirement cannot fund sibling reserve: " + error);
    }
    const auto image = std::filesystem::absolute("debt.apfs");
    auto management = AllocationFixture(image, 42);
    Tx journal(L"Strict"); Configure(journal, management.sibling_wals.at(101));
    auto owner = Open(image, journal);
    Create(*owner, journal, "debt");
    Store::MutationRequest write; write.operation = Store::MutationOperation::Write; write.path = L"\\clone0"; write.length = 4 * kBlockSize;
    Live(*owner, journal, write, std::vector<std::byte>(write.length, std::byte{0x75}));
    Delete(*owner, journal, List(*owner)[0].identity);
    Check(AllocationCheckpoint(image).volumes[0].superblock.space.allocated_block_count == 52,
        "exact deltas preserve existing unproven 42 block surplus");
    Check(owner->DrainAndStop(std::chrono::seconds(2)).clean, "debt owner drains"); owner.reset();
    apfsaccess::volume_management_test::RefreshManagementRequest(management);
    const auto refused = PrepareVolumeCreate(management);
    Check(refused.outcome != VolumeManagementOutcome::Prepared && refused.error == "VolumeManagementHistoricalChargeUnproven",
        "preexisting debt remains truthful management refusal: " + refused.error);
    std::cout << "PASS exact quota boundary and historical debt refusal\n";
}
}
