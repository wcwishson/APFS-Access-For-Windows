#include "ApfsVerifier.h"
#define main HistoricalFusionFixtureMain
#include "ApfsFusionImageWriteSessionTests.cpp"
#undef main

namespace
{
VerificationScope CurrentScope(const Files& f)
{
    VerificationScope scope;
    scope.source_identity = "held-private-fusion-verifier";
    scope.exact = {f.prefix, 512ull * f.bs, f.request.container_uuid_hex, std::string(32, 'c'), 101, 20};
    return scope;
}
CurrentProfileVerificationReport VerifyCurrent(Files& f, VerificationScope scope,
    const std::function<bool()>& deadline = [] { return true; })
{
    std::string error;
    auto store = ApfsFusionStore::BindImages(f.request, error);
    Check(static_cast<bool>(store), "bind verifier image: " + error);
    return ApfsVerifier::VerifyFusionCurrent(*store, scope,
        {"apfs-store:test-main", "apfs-store:test-tier2"}, deadline);
}
void NoComplete(const CurrentProfileVerificationReport& report)
{
    Check(report.outcome != VerificationOutcome::Complete && !report.findings.empty(), "failure did not publish finding");
    Check(report.covered_volume_count == 0 && report.covered_filesystem_records == 0 &&
        report.covered_physical_extents == 0 && report.current_metadata_blocks == 0, "failure published partial counts");
    Check(!report.apple_purgeable_bytes && !report.reclaimable_bytes && !report.snapshot_allocation_charge_bytes,
        "policy/charge invented");
}
void FreeFixtureBlock(Files& f, unsigned device, std::uint64_t local)
{
    auto bitmap = f.Block(0, 258 + device);
    bitmap[local / 8] &= std::byte(255u ^ (1u << (local % 8)));
    f.Place(0, 258 + device, bitmap);
    f.Edit(0, 256 + device, [&](auto& b) { Put(b, 0x3C, (device ? 128 : 512) - Population(bitmap), 4); });
    f.Edit(0, 160, [&](auto& b) { Put(b, device ? 0x78 : 0x48, (device ? 128 : 512) - Population(bitmap)); });
    Persist(f);
}
void ChangePhysical(Files& f, unsigned member, std::uint64_t fs_block, std::uint64_t refs_block,
    std::uint64_t before, std::uint64_t after, std::uint64_t owner)
{
    OffsetRandomAccessSource source(f.sources[member].get(), f.prefix, f.sources[member]->SizeBytes() - f.prefix);
    std::vector<BtreeRecord> records;
    std::string error;
    Check(ReadBtreeLeafRecords(source, f.bs, fs_block, false, 0, 20, records, error), error);
    for (auto& r : records) if ((ReadU64LE(r.key, 0).value_or(0) >> 60) == 8)
    {
        AppleFileExtentRecord e;
        Check(DecodeAppleFileExtentRecord(r, f.bs, e, error), error);
        if (e.physical_block == before) { e.physical_block = after; Check(EncodeAppleFileExtentRecord(e, r, error), error); }
    }
    AppleBtreeOptions options;
    options.block_size = f.bs; options.xid = 20; options.root_object_id = fs_block == 47 ? 2000 : 1000;
    options.root_physical_block = fs_block; options.subtype = kObjectTypeFsTree;
    options.key_order = AppleBtreeKeyOrder::FileSystemCaseSensitive;
    AppleSerializedBtree tree;
    Check(SerializeAppleBtree(records, options, tree, error), error); f.Place(member, fs_block, tree.objects.front().bytes);
    records.clear();
    if (owner == 30) records.push_back(Enc(ApplePhysicalExtentRecord{f.TierBlock() + 20, 1, kApplePhysicalExtentKindNew, owner, 1}, EncodeApplePhysicalExtentRecord));
    records.push_back(Enc(ApplePhysicalExtentRecord{after, 1, kApplePhysicalExtentKindNew, owner, 1}, EncodeApplePhysicalExtentRecord));
    options.root_object_id = options.root_physical_block = refs_block;
    options.storage_type = kObjectPhysical; options.tree_flags = kAppleBtreePhysical;
    options.subtype = kObjectTypeBlockRefTree; options.key_order = AppleBtreeKeyOrder::PhysicalExtent;
    Check(SerializeAppleBtree(records, options, tree, error), error); f.Place(member, refs_block, tree.objects.front().bytes);
    Persist(f);
}
void MultipleNodes(Files& f)
{
    OffsetRandomAccessSource source(f.sources[0].get(), f.prefix, 512ull * f.bs);
    std::vector<BtreeRecord> records;
    std::string error;
    Check(ReadBtreeLeafRecords(source, f.bs, 30, false, 0, 20, records, error), error);
    for (unsigned n = 0; n < 16; ++n)
        records.push_back(Enc(AppleXattrRecord{30, "user.pad." + std::to_string(n), kAppleXattrDataEmbedded,
            Bytes(600, std::byte(n))}, EncodeAppleXattrRecord));
    AppleBtreeOptions options;
    options.block_size = f.bs; options.xid = 20; options.root_object_id = 1000; options.root_physical_block = 30;
    options.first_child_object_id = 1001; options.first_child_physical_block = 32;
    options.subtype = kObjectTypeFsTree; options.key_order = AppleBtreeKeyOrder::FileSystemCaseSensitive;
    AppleSerializedBtree tree;
    Check(SerializeAppleBtree(records, options, tree, error) && tree.height > 0 && tree.objects.size() > 1, "multi-node canonical producer: " + error);
    std::vector<tf::OmapRecordSpec> mappings;
    auto bitmap = f.Block(0, 258);
    for (const auto& item : tree.objects)
    {
        f.Place(0, item.location.physical_block, item.bytes); Bit(bitmap, item.location.physical_block);
        mappings.push_back({item.location.object_id, item.location.physical_block, 0, 20});
    }
    std::sort(mappings.begin(), mappings.end(), [](const auto& a, const auto& b) { return a.oid < b.oid; });
    f.Place(1, 6, tf::BuildBtreeNode(mappings, 20, f.bs, 0, f.TierBlock() + 6, kObjectPhysical | kObjectTypeBtree, kObjectTypeOmap));
    f.Place(0, 258, bitmap);
    f.Edit(0, 256, [&](auto& b) { Put(b, 0x3C, 512 - Population(bitmap), 4); });
    f.Edit(0, 160, [&](auto& b) { Put(b, 0x48, 512 - Population(bitmap)); });
    Persist(f);
}
}

int main(int argc, char** argv) try
{
    Check(argc == 2, "private evidence directory required");
    const auto root = fs::absolute(argv[1]).lexically_normal();
    Check(root.wstring().starts_with(L"D:\\ApfsAccessScratch\\"), "D-only private evidence");
    Check(fs::create_directories(root), "new evidence directory required");
    Run("complete current two-member graph and warm repeat", [&] {
        Files f(root); VolumePlanFixture(f); std::string error;
        auto store = ApfsFusionStore::BindImages(f.request, error); Check(static_cast<bool>(store), error);
        for (unsigned repeat = 0; repeat < 3; ++repeat)
        {
            const auto r = ApfsVerifier::VerifyFusionCurrent(*store, CurrentScope(f),
                {"apfs-store:test-main", "apfs-store:test-tier2"}, [] { return true; });
            Check(r.outcome == VerificationOutcome::Complete, r.findings.empty() ? "no complete" : r.findings.front().detail);
            Check(r.selected && r.selected->root_oid == 1000 && r.covered_volume_count == 1 &&
                r.covered_filesystem_records == 6 && r.covered_physical_extents == 2 && r.current_metadata_blocks == 7,
                "exact current graph partitions");
            Check(r.stores.size() == 2 && r.stores[0].size_bytes == 512 * f.bs && r.stores[1].size_bytes == 128 * f.bs,
                "encoded span used as physical capacity");
            for (const auto& row : r.coverage) if (row.required) Check(row.state == VerificationCheckState::Verified, "coverage incomplete");
            Check(!r.apple_purgeable_bytes && !r.reclaimable_bytes && !r.snapshot_allocation_charge_bytes, "unknown charges promoted");
        }
    });
    Run("all peer graphs and exact nonzero member windows", [&] {
        Files f(root, 3); VolumePlanFixture(f); AddSiblingVolume(f);
        const auto r = VerifyCurrent(f, CurrentScope(f));
        Check(r.outcome == VerificationOutcome::Complete, r.findings.empty() ? "peer incomplete" : r.findings.front().detail);
        Check(r.covered_volume_count == 2 && r.covered_filesystem_records == 11 && r.covered_physical_extents == 3 &&
            r.current_metadata_blocks == 12 && r.stores[1].offset_bytes == f.prefix, "peer graph omitted");
    });
    Run("exact member identity refuses", [&] {
        Files f(root); VolumePlanFixture(f); std::string error;
        auto store = ApfsFusionStore::BindImages(f.request, error); Check(static_cast<bool>(store), error);
        auto r = ApfsVerifier::VerifyFusionCurrent(*store, CurrentScope(f), {"wrong", "apfs-store:test-tier2"}, [] { return true; });
        NoComplete(r); Check(r.outcome == VerificationOutcome::Refused && r.findings.front().code == VerificationCode::IdentityMismatch, "member mismatch classification");
    });
    for (unsigned n = 0; n < 5; ++n) Run("exact volume/checkpoint/window refuses", [&] {
        Files f(root); VolumePlanFixture(f); auto scope = CurrentScope(f);
        if (n == 0) scope.exact.container_uuid_hex[0] = 'e';
        if (n == 1) scope.exact.volume_uuid_hex[0] = 'e';
        if (n == 2) scope.exact.volume_oid = 999;
        if (n == 3) scope.exact.checkpoint_xid = 19;
        if (n == 4) scope.exact.store_size_bytes -= f.bs;
        NoComplete(VerifyCurrent(f, scope));
    });
    for (unsigned n = 0; n < 5; ++n) Run("broader request does not promote current profile", [&] {
        Files f(root); VolumePlanFixture(f); auto scope = CurrentScope(f);
        if (n == 0) scope.require_whole_volume = true;
        if (n == 1) scope.require_payload_content_hashes = true;
        if (n == 2) scope.observe_payload_content = true;
        if (n == 3) scope.account_retained_ownership = true;
        if (n == 4) scope.retained_from_xid = 19;
        NoComplete(VerifyCurrent(f, scope));
    });
    for (unsigned n = 0; n < 3; ++n) Run("canonical allocated-bit ownership negative", [&] {
        Files f(root); VolumePlanFixture(f); FreeFixtureBlock(f, n == 1 ? 1 : 0, n == 2 ? 30 : 20);
        const auto r = VerifyCurrent(f, CurrentScope(f)); NoComplete(r);
        Check(r.findings.front().detail == "VerifierFusionOwnerNotAllocated", "owner bit was not independently checked");
    });
    Run("peer payload collision", [&] {
        Files f(root); VolumePlanFixture(f); AddSiblingVolume(f);
        ChangePhysical(f, 0, 47, 48, f.TierBlock() + 40, f.TierBlock() + 20, 50);
        const auto r = VerifyCurrent(f, CurrentScope(f)); NoComplete(r);
        Check(r.findings.front().code == VerificationCode::CrossVolumePayloadOverlap, "peer overlap not found");
    });
    Run("payload collides with validated metadata", [&] {
        Files f(root); VolumePlanFixture(f); ChangePhysical(f, 0, 30, 31, 20, 30, 30);
        const auto r = VerifyCurrent(f, CurrentScope(f)); NoComplete(r);
        Check(r.findings.front().code == VerificationCode::PayloadMetadataOverlap, "metadata overlap not found");
    });
    Run("deadline and sticky budget", [&] {
        Files f(root); VolumePlanFixture(f);
        auto r = VerifyCurrent(f, CurrentScope(f), [] { return false; }); NoComplete(r);
        Check(r.findings.front().code == VerificationCode::BudgetExceeded, "deadline classification");
        f.Refresh(20); auto scope = CurrentScope(f); scope.max_reads = 1;
        r = VerifyCurrent(f, scope); NoComplete(r); Check(r.findings.front().code == VerificationCode::BudgetExceeded, "read budget classification");
    });
    Run("warm canonical binding cancellation", [&] {
        Files f(root); VolumePlanFixture(f); std::string error;
        auto store = ApfsFusionStore::BindImages(f.request, error); Check(static_cast<bool>(store), error);
        auto r = ApfsVerifier::VerifyFusionCurrent(*store, CurrentScope(f), {"apfs-store:test-main", "apfs-store:test-tier2"}, [] { return true; });
        Check(r.outcome == VerificationOutcome::Complete, "cold graph failed"); store->Cancel();
        r = ApfsVerifier::VerifyFusionCurrent(*store, CurrentScope(f), {"apfs-store:test-main", "apfs-store:test-tier2"}, [] { return true; }); NoComplete(r);
    });
    Run("complete multi-node FS and external member metadata", [&] {
        Files f(root); VolumePlanFixture(f); MultipleNodes(f);
        const auto r = VerifyCurrent(f, CurrentScope(f));
        Check(r.outcome == VerificationOutcome::Complete, r.findings.empty() ? "multi-node incomplete" : r.findings.front().detail);
        Check(r.covered_filesystem_records == 22 && r.current_metadata_blocks > 7 && r.covered_physical_extents == 2,
            "multi-node graph missing children");
    });
    Run("multi-node separator corruption with checksum", [&] {
        Files f(root); VolumePlanFixture(f); MultipleNodes(f);
        AppleInodeRecord inode; inode.object_id = inode.private_id = inode.parent_id = 2; inode.mode = 0040755;
        const auto original_key = Enc(inode, EncodeAppleInodeRecord).key;
        f.Edit(0, 30, [&](auto& b) {
            const auto at = std::search(b.begin() + 0x38, b.end() - 40, original_key.begin(), original_key.end());
            Check(at != b.end() - 40, "root separator fixture key absent");
            *at ^= std::byte{1};
        });
        Persist(f); const auto r = VerifyCurrent(f, CurrentScope(f)); NoComplete(r);
        Check(r.findings.front().code == VerificationCode::TreeOrderInconsistent, "separator routing not independently checked");
    });
    Run("current tier payload queued for retirement", [&] {
        Files f(root); VolumePlanFixture(f);
        f.Place(0, 162, Queue(f, 80, 162, {{19, f.TierBlock() + 20, 1}}));
        f.Edit(0, 160, [](auto& b) { Put(b, 0x118, 1); }); Persist(f);
        const auto r = VerifyCurrent(f, CurrentScope(f)); NoComplete(r);
        Check(r.findings.front().detail == "VerifierFusionOwnerQueued", "queue ownership not independently checked");
    });
    Run("snapshot tree remains outside current profile", [&] {
        Files f(root); VolumePlanFixture(f);
        f.Edit(1, 4, [](auto& b) { Put(b, 0x7C, kObjectPhysical | kObjectTypeBtree, 4); Put(b, 0x98, 35); });
        f.Place(0, 35, tf::BuildRawLeafNode({}, {}, 20, f.bs, 0, 35, kObjectPhysical | kObjectTypeBtree, kObjectTypeSnapMetaTree));
        Persist(f); NoComplete(VerifyCurrent(f, CurrentScope(f)));
    });
    std::cout << "PASS " << cases << " cases, " << checks << " checks; actual private paired-image current verification\n";
    return 0;
}
catch (const std::exception& e) { std::cout << "FAIL " << e.what() << '\n'; return 1; }
