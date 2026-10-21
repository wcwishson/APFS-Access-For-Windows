#include "ApfsSpaceAccounting.h"
#include "ApfsExtendedRecordCodec.h"
#define APFS_RETAINED_OWNERSHIP_FIXTURES_ONLY
#include "ApfsVerifierRetainedOwnershipTests.cpp"
#undef APFS_RETAINED_OWNERSHIP_FIXTURES_ONLY

namespace
{
std::vector<std::uint64_t> Pins(const Fixture& f)
{
    std::vector<std::uint64_t> pins;
    for (const auto& cp : f.generations) pins.push_back(cp.container.superblock.xid);
    return pins;
}

void Seed(Fixture& f, bool clone, bool attribute, std::uint64_t blocks = 1)
{
    BuilderStore spec; spec.block_size = f.bs; spec.block_count = 512; spec.xid = 20;
    spec.authoritative_internal_pool_blocks = 32; spec.authoritative_checkpoint_ring_blocks = 32;
    auto& volume = spec.volumes[0]; volume.uuid_hex = std::string(32, 'b');
    VectorRandomAccessSource source(f.image); std::string error;
    Check(ReadAppleVolumeFileSystemRecords(source, f.checkpoint.container, f.checkpoint.volumes[0],
        volume.filesystem_records, error), error);
    auto& fs = volume.filesystem_records;
    if (blocks != 1)
        for (auto& record : fs)
        {
            const auto kind = ReadU64LE(record.key, 0).value_or(0) >> 60;
            if (kind == 3)
            {
                AppleInodeRecord inode; Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), error);
                if (inode.object_id != 30) continue;
                inode.uncompressed_size = blocks * f.bs;
                PutU64LE(inode.extended_fields[0].data, 0, blocks * f.bs);
                PutU64LE(inode.extended_fields[0].data, 8, blocks * f.bs);
                record = Encode(inode, EncodeAppleInodeRecord);
            }
            else if (kind == 8) record = Encode(AppleFileExtentRecord{30, 0, blocks * f.bs, 220, 0, f.bs}, EncodeAppleFileExtentRecord);
        }
    if (clone)
    {
        for (auto& record : fs)
            if (ReadU64LE(record.key, 0).value_or(0) >> 60 == 3)
            {
                AppleInodeRecord inode; Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), error);
                if (inode.object_id == 2) { inode.children_or_links = 2; record = Encode(inode, EncodeAppleInodeRecord); }
            }
        const auto original = fs;
        for (const auto& record : original)
        {
            const auto key = ReadU64LE(record.key, 0).value_or(0), kind = key >> 60;
            if ((key & 0x0fffffffffffffffull) != 30) continue;
            if (kind == 3)
            {
                AppleInodeRecord inode; Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), error);
                inode.object_id = inode.private_id = 31; fs.push_back(Encode(inode, EncodeAppleInodeRecord));
            }
        }
        AppleDirectoryRecord entry; entry.parent_id = 2; entry.file_id = 31; entry.flags = 8; entry.name_utf8 = "clone.bin";
        Record record; Check(EncodeAppleDirectoryRecord(entry, record, error), error); fs.push_back(std::move(record));
        fs.push_back(Encode(AppleDataStreamIdRecord{31, 1}, EncodeAppleDataStreamIdRecord));
        fs.push_back(Encode(AppleFileExtentRecord{31, 0, blocks * f.bs, 220, 0, f.bs}, EncodeAppleFileExtentRecord));
    }
    volume.extentref_records = {Encode(ApplePhysicalExtentRecord{220, blocks, kApplePhysicalExtentKindNew, 30, clone ? 2 : 1}, EncodeApplePhysicalExtentRecord)};
    volume.additional_file_system_allocated_blocks = blocks + (attribute ? 1 : 0);
    for (std::uint64_t i = 0; i < blocks; ++i)
        spec.authoritative_seeded_main_blocks.emplace_back(220 + i, Bytes(f.bs, std::byte{0x42}));
    if (attribute)
    {
        AppleXattrRecord xattr{30, "user.external", kAppleXattrDataStream, Bytes(48)};
        PutU64LE(xattr.data, 0, 50); PutU64LE(xattr.data, 8, f.bs); PutU64LE(xattr.data, 16, f.bs);
        fs.push_back(Encode(xattr, EncodeAppleXattrRecord));
        fs.push_back(Encode(AppleDataStreamIdRecord{50, 1}, EncodeAppleDataStreamIdRecord));
        fs.push_back(Encode(AppleFileExtentRecord{50, 0, f.bs, 220 + blocks, 0, f.bs}, EncodeAppleFileExtentRecord));
        volume.extentref_records.push_back(Encode(ApplePhysicalExtentRecord{220 + blocks, 1, kApplePhysicalExtentKindNew, 30, 1}, EncodeApplePhysicalExtentRecord));
        spec.authoritative_seeded_main_blocks.emplace_back(220 + blocks, Bytes(f.bs, std::byte{0x43}));
    }
    Check(SortAppleBtreeRecords(fs, AppleBtreeKeyOrder::FileSystemCaseSensitive, error), error);
    f.image = BuildAuthoritativeStoreImage(spec);
    f.Edit(4, [&](auto& bytes) { PutU64LE(bytes, 0xB8, clone ? 2 : 1); PutU64LE(bytes, 0xC0, 1); });
    f.Reload(); f.generations = {f.checkpoint}; f.payload_blocks.clear();
    for (std::uint64_t i = 0; i < blocks + (attribute ? 1 : 0); ++i) f.payload_blocks.push_back(220 + i);
}

void GrowMetadata(Fixture& f)
{
    VectorRandomAccessSource source(f.image); std::string error;
    AppleVolumeTransactionRequest request; request.volume_object_id = 101; request.required_checkpoint_xids = Pins(f);
    Check(ReadAppleVolumeFileSystemRecords(source, f.checkpoint.container, f.checkpoint.volumes[0], request.filesystem_records, error), error);
    for (auto& record : request.filesystem_records)
        if (ReadU64LE(record.key, 0).value_or(0) == (3ull << 60 | 2))
        {
            AppleInodeRecord inode; Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), error);
            inode.children_or_links += 40; record = Encode(inode, EncodeAppleInodeRecord);
        }
    for (std::uint64_t id = 60; id < 100; ++id)
    {
        AppleInodeRecord inode; inode.object_id = inode.private_id = id; inode.parent_id = 2;
        inode.mode = 0100644; inode.children_or_links = 1;
        request.filesystem_records.push_back(Encode(inode, EncodeAppleInodeRecord));
        AppleDirectoryRecord entry; entry.parent_id = 2; entry.file_id = id; entry.flags = 8;
        entry.name_utf8 = "metadata-file-" + std::to_string(id);
        Record record; Check(EncodeAppleDirectoryRecord(entry, record, error), error);
        request.filesystem_records.push_back(std::move(record));
    }
    Check(SortAppleBtreeRecords(request.filesystem_records, AppleBtreeKeyOrder::FileSystemCaseSensitive, error), error);
    AppleVolumeTransactionPlan plan;
    Check(PlanAppleVolumeTransaction(source, f.checkpoint, request, plan, error), "grow metadata: " + error);
    f.Publish(plan.commit.publication);
}

ApfsSnapshotSpaceAttribution Attribute(Fixture& f)
{
    TracedSource source(f.image); const auto before = f.image;
    std::optional<ApfsSnapshotSpaceAttribution> out; std::string error;
    const auto complete = TryAttributeAppleSnapshotSpace(source, f.scope, out, error);
    Check(complete, "attribute: " + error);
    Check(out && out->complete && out->read_budget && error.empty() && out->scope == f.scope.exact && out->source_identity == f.scope.source_identity,
        "complete exact identity-bound attribution");
    Check(f.image == before, "attribution is read-only");
    for (const auto block : f.payload_blocks)
        Check(std::none_of(source.reads.begin(), source.reads.end(), [&](auto read) {
            return read.first < (block + 1) * f.bs && block * f.bs < read.first + read.second;
        }), "no file/attribute payload byte read");
    for (const auto& row : out->snapshots)
    {
        Check(!row.apple_purgeable && !row.reclaimable && !row.purgeable_marked_payload.blocks,
            "no purge policy or deletion savings promotion");
        for (const auto* amount : {&row.metadata, &row.payload})
        {
            Check(amount->referenced.blocks == amount->shared_with_live.blocks + amount->absent_from_live.blocks,
                "live/absent exact partition");
            Check(amount->potential_reclaim_upper_bound.blocks <= amount->unique_in_visible_inventory.blocks &&
                amount->unique_in_visible_inventory.blocks <= amount->absent_from_live.blocks &&
                amount->shared_with_other_snapshots.blocks <= amount->referenced.blocks &&
                amount->retained_or_peer_protected.blocks <= amount->referenced.blocks, "overlapping measures bounded");
            for (const auto* value : {&amount->referenced, &amount->shared_with_live, &amount->absent_from_live,
                &amount->shared_with_other_snapshots, &amount->unique_in_visible_inventory,
                &amount->retained_or_peer_protected, &amount->potential_reclaim_upper_bound})
                Check(value->bytes == value->blocks * f.bs, "physical units exact");
        }
        std::cout << "ATTR xid=" << row.snapshot_xid << " name=" << row.name_utf8
            << " metadata=" << row.metadata.referenced.blocks << " metadataSharedLive=" << row.metadata.shared_with_live.blocks
            << " payload=" << row.payload.referenced.blocks << " payloadSharedLive=" << row.payload.shared_with_live.blocks
            << " payloadSharedSnapshots=" << row.payload.shared_with_other_snapshots.blocks
            << " payloadProtected=" << row.payload.retained_or_peer_protected.blocks
            << " metadataPotentialBound=" << row.metadata.potential_reclaim_upper_bound.blocks
            << " payloadPotentialBound=" << row.payload.potential_reclaim_upper_bound.blocks << '\n';
    }
    return std::move(*out);
}

void Refused(Fixture& f, const std::string& expected)
{
    VectorRandomAccessSource source(f.image);
    std::optional<ApfsSnapshotSpaceAttribution> out{ApfsSnapshotSpaceAttribution{}};
    std::string error;
    const auto complete = TryAttributeAppleSnapshotSpace(source, f.scope, out, error);
    Check(!complete && !out && error.find(expected) != std::string::npos,
        "failure leaves no complete attribution: " + error);
}

void Cases()
{
    for (const auto bs : {4096u, 8192u})
    {
        Fixture f(bs); const auto empty = Attribute(f);
        Check(empty.snapshots.empty() && !empty.referenced_metadata.blocks && !empty.referenced_payload.blocks &&
            empty.catalog_metadata.blocks > 0 && empty.retained_checkpoint_xids == std::vector<std::uint64_t>{20}, "empty inventory known zero, live scaffolding separate");
        Pass("empty inventory " + std::to_string(bs));
        const auto identity = f.Create("shared", Pins(f)); const auto out = Attribute(f);
        const auto& row = out.snapshots.at(0);
        Check(row.snapshot_xid == identity.snapshot_xid && row.name_utf8 == "shared" &&
            row.payload.referenced.blocks == 1 && row.payload.shared_with_live.blocks == 1 &&
            !row.payload.unique_in_visible_inventory.blocks && !row.payload.potential_reclaim_upper_bound.blocks,
            "shared snapshot exact physical payload");
        Check(row.metadata.referenced.blocks >= 5 && row.metadata.absent_from_live.blocks > 0,
            "snapshot APSB/OMAP/FS/extentref metadata are attributed separately: referenced=" +
                std::to_string(row.metadata.referenced.blocks) + " absent=" + std::to_string(row.metadata.absent_from_live.blocks));
        const std::set<std::uint64_t> exact_metadata{identity.superblock_physical_block, identity.omap_physical_block,
            identity.omap_tree_physical_block, identity.root_physical_block, identity.extentref_physical_block};
        Check(row.metadata.referenced.blocks == exact_metadata.size(), "single-node snapshot exact five canonical dependency identities");
        Check(row.metadata.potential_reclaim_upper_bound.blocks > 0 && !row.reclaimable,
            "potential metadata bound does not claim hidden-owner release authority");
        Pass("shared payload and metadata " + std::to_string(bs));
    }
    {
        Fixture f; Seed(f, true, false); f.Create("clones", Pins(f)); const auto out = Attribute(f);
        Check(out.snapshots[0].payload.referenced.blocks == 1 && out.referenced_payload.blocks == 1,
            "two clone refcounts still reference one physical block"); Pass("shared clone union");
    }
    {
        Fixture f; Seed(f, false, true); f.Create("attribute", Pins(f)); const auto out = Attribute(f);
        Check(out.snapshots[0].payload.referenced.blocks == 2 && out.snapshots[0].payload.shared_with_live.blocks == 2,
            "external attribute stream participates in payload union"); Pass("external xattr payload");
    }
    {
        Fixture f; f.Create("before-cow", Pins(f)); f.Cow(true, Pins(f));
        const auto out = Attribute(f); const auto& row = out.snapshots[0];
        Check(row.payload.absent_from_live.blocks == 1 && row.payload.unique_in_visible_inventory.blocks == 1 &&
            row.payload.retained_or_peer_protected.blocks == 1 && !row.payload.potential_reclaim_upper_bound.blocks,
            "retained checkpoint protects live-absent payload"); Pass("retained ownership prevents reclaim promotion");
    }
    {
        Fixture f; Seed(f, false, false, 4); f.Create("partial", Pins(f));
        VectorRandomAccessSource source(f.image); std::string error;
        AppleVolumeTransactionRequest request; request.volume_object_id = 101; request.required_checkpoint_xids = Pins(f);
        Check(ReadAppleVolumeFileSystemRecords(source, f.checkpoint.container, f.checkpoint.volumes[0], request.filesystem_records, error), error);
        std::erase_if(request.filesystem_records, [](const auto& r) { return ReadU64LE(r.key, 0).value_or(0) >> 60 == 8; });
        request.filesystem_records.push_back(Encode(AppleFileExtentRecord{30, 0, f.bs, 220, 0, f.bs}, EncodeAppleFileExtentRecord));
        request.filesystem_records.push_back(Encode(AppleFileExtentRecord{30, 3ull * f.bs, f.bs, 223, 0, f.bs}, EncodeAppleFileExtentRecord));
        request.released_data_blocks = {{221, 2}};
        request.data_writes.push_back({30, f.bs, 0, Bytes(2ull * f.bs, std::byte{0x61})});
        AppleVolumeTransactionPlan plan;
        const auto planned = PlanAppleSnapshotLiveTransaction(source, f.checkpoint, request, plan, error);
        Check(planned, "partial COW producer: " + error); f.Publish(plan.commit.publication);
        const auto out = Attribute(f); const auto& row = out.snapshots[0];
        Check(row.payload.referenced.blocks == 4 && row.payload.shared_with_live.blocks == 2 &&
            row.payload.absent_from_live.blocks == 2 && row.payload.retained_or_peer_protected.blocks == 4 &&
            !row.payload.potential_reclaim_upper_bound.blocks, "two disjoint live intersections split snapshot range exactly");
        Pass("partial COW physical interval overlap");
    }
    {
        Fixture f; f.Create("first", Pins(f)); f.Create("second", Pins(f)); f.Cow(true, Pins(f));
        const auto out = Attribute(f);
        Check(out.snapshots.size() == 2 && out.referenced_payload.blocks == 1 &&
            out.snapshots[0].payload.referenced.blocks + out.snapshots[1].payload.referenced.blocks == 2,
            "inventory union is not row sum");
        for (const auto& row : out.snapshots)
            Check(row.payload.shared_with_other_snapshots.blocks == 1 && row.payload.absent_from_live.blocks == 1 &&
                !row.payload.unique_in_visible_inventory.blocks && !row.payload.potential_reclaim_upper_bound.blocks,
                "multiple snapshot sharing independent of live absence");
        Check(out.referenced_metadata.blocks <= out.snapshots[0].metadata.referenced.blocks + out.snapshots[1].metadata.referenced.blocks,
            "metadata shared blocks are unioned too"); Pass("multiple snapshot overlap and signed history");
    }
    {
        Fixture f; GrowMetadata(f); const auto id = f.Create("multi-node", Pins(f));
        VectorRandomAccessSource source(f.image); AppleSnapshotCatalogRecords catalog; std::string error;
        Check(LoadAppleSnapshotCatalog(source, f.checkpoint, 101, catalog, error), error);
        Check(catalog.snapshots[0].filesystem_blocks.size() > 1, "actual multi-node filesystem fixture");
        const auto out = Attribute(f);
        Check(out.snapshots[0].snapshot_xid == id.snapshot_xid &&
            out.snapshots[0].metadata.referenced.blocks >= catalog.snapshots[0].filesystem_blocks.size() + 4,
            "all filesystem nodes plus descriptor/OMAP/extentref dependencies counted"); Pass("multi-node metadata attribution");
    }
    {
        Fixture f; AddPeer(f, 221); f.Create("peer-retained", Pins(f)); const auto out = Attribute(f);
        Check(out.snapshots.size() == 1 && out.referenced_payload.blocks == 1 &&
            out.snapshots[0].payload.retained_or_peer_protected.blocks == 1, "peer payload is not charged to selected snapshots");
        Pass("canonical peer plus retained ownership");
    }
    { auto f = Ordinary(); BreakNextLink(f); Refused(f, "AppleCheckpointRetentionUnavailable"); Pass("unknown history remains incomplete"); }
    { Fixture f; AllocateOrphan(f, 300); Refused(f, "VerifierOrphanAllocation"); Pass("orphan prevents attribution"); }
    {
        Fixture f;
        VectorRandomAccessSource source(f.image); AppleSnapshotCatalogRecords catalog; std::string error;
        Check(LoadAppleSnapshotCatalog(source, f.checkpoint, 101, catalog, error), error);
        auto records = catalog.live.extentref;
        PutU64LE(records[0].value, 0, 3ull << 60 | 1); // DEAD is not an on-disk owner kind.
        std::vector<Bytes> keys, values; for (const auto& record : records) { keys.push_back(record.key); values.push_back(record.value); }
        const auto& tree = *f.checkpoint.volumes[0].extentref_tree;
        f.Put(tree.physical_block, BuildRawLeafNode(keys, values, tree.xid, f.bs, 0, tree.object_id, tree.type, tree.subtype));
        Refused(f, "ApplePhysicalExtentRecordInvalid"); Pass("unknown physical kind leaves accounting unknown");
    }
    {
        Fixture f; f.Create("bad-update", Pins(f)); f.Cow(true, Pins(f));
        VectorRandomAccessSource source(f.image); AppleSnapshotCatalogRecords catalog; std::string error;
        Check(LoadAppleSnapshotCatalog(source, f.checkpoint, 101, catalog, error), error);
        auto records = catalog.live.extentref; bool changed = false;
        for (auto& record : records)
        {
            ApplePhysicalExtentRecord extent; Check(DecodeApplePhysicalExtentRecord(record, extent, error), error);
            if (extent.kind == kApplePhysicalExtentKindUpdate) { PutU32LE(record.value, 16, 1); changed = true; }
        }
        Check(changed, "actual signed UPDATE layer corrupted");
        std::vector<Bytes> keys, values; for (const auto& record : records) { keys.push_back(record.key); values.push_back(record.value); }
        const auto& tree = *f.checkpoint.volumes[0].extentref_tree;
        f.Put(tree.physical_block, BuildRawLeafNode(keys, values, tree.xid, f.bs, 0, tree.object_id, tree.type, tree.subtype));
        Refused(f, "AppleVolume"); Pass("incorrect signed reference history refused");
    }
    {
        Fixture f; auto scope = f.scope; scope.require_whole_volume = true; f.scope = scope;
        Refused(f, "ScopeUnsupported"); Pass("broader verification scope refused");
    }
    {
        Fixture f; const auto root = f.checkpoint.volumes[0].root_tree.physical_block;
        VectorRandomAccessSource source(f.image); std::vector<Record> records; std::string error;
        Check(ReadAppleVolumeFileSystemRecords(source, f.checkpoint.container, f.checkpoint.volumes[0], records, error), error);
        for (auto& record : records)
            if (ReadU64LE(record.key, 0).value_or(0) == (3ull << 60 | 30))
            {
                AppleInodeRecord inode; Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), error);
                inode.internal_flags |= 0x80000; record = Encode(inode, EncodeAppleInodeRecord);
            }
        std::vector<Bytes> keys, values; for (const auto& record : records) { keys.push_back(record.key); values.push_back(record.value); }
        const auto& tree = f.checkpoint.volumes[0].root_tree;
        f.Put(root, BuildRawLeafNode(keys, values, tree.xid, f.bs, 0, tree.object_id, tree.type, tree.subtype));
        Refused(f, "VerifierInodeFlagsUnsupported"); Pass("purgeable mark is unsupported rather than known zero");
    }
    {
        Fixture f; f.Create("budget", Pins(f)); TracedSource traced(f.image);
        std::optional<ApfsSnapshotSpaceAttribution> out; std::string error;
        auto budget = std::make_shared<ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
        BudgetedRandomAccessSource source(traced, budget);
        Check(TryAttributeAppleSnapshotSpace(source, f.scope, out, error), error);
        const auto used = budget->Consumed(); f.scope.max_records = used.records - 1;
        Refused(f, "ApfsReadBudgetRecordLimit");
        auto spent = std::make_shared<ApfsReadBudget>(1, 1, 1, 1); BudgetedRandomAccessSource limited(traced, spent);
        Check(!TryAttributeAppleSnapshotSpace(limited, f.scope, out, error) && !out && spent->Failed(), "spent budget clears result");
        Check(!TryAttributeAppleSnapshotSpace(limited, f.scope, out, error) && !out, "retry cannot replenish budget");
        Pass("late budget and sticky retry");
    }
    {
        Fixture f; unsigned calls = 0; VectorRandomAccessSource source(f.image);
        std::optional<ApfsSnapshotSpaceAttribution> out; std::string error;
        Check(TryAttributeAppleSnapshotSpace(source, f.scope, out, error, [&] { ++calls; return true; }), error);
        unsigned current = 0;
        Check(!TryAttributeAppleSnapshotSpace(source, f.scope, out, error, [&] { return ++current < calls; }) &&
            !out && error.find("Deadline") != std::string::npos, "late deadline clears complete result"); Pass("late cooperative deadline");
    }
    {
        Fixture f; f.Create("io", Pins(f)); TracedSource control(f.image); std::string error;
        std::optional<ApfsSnapshotSpaceAttribution> out;
        Check(TryAttributeAppleSnapshotSpace(control, f.scope, out, error), "I/O control succeeds");
        TracedSource failing(f.image); failing.fail_at = control.reads.size(); failing.short_read = true;
        Check(!TryAttributeAppleSnapshotSpace(failing, f.scope, out, error) && !out, "late short read cannot escape as complete attribution");
        f.scope.exact.volume_uuid_hex = std::string(32, 'c'); Refused(f, "Identity");
        Pass("late I/O and wrong exact identity clear output");
    }
}
}

#ifndef APFS_SNAPSHOT_ATTRIBUTION_FIXTURES_ONLY
int main()
{
    try { Cases(); std::cout << "PASS " << cases << " cases, " << checks << " checks\n"; return 0; }
    catch (const std::exception& e) { std::cerr << "FAIL " << e.what() << '\n'; return 1; }
}
#endif
