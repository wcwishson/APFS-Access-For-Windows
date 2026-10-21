#define APFS_FUSION_STORE_TESTING
#include "ApfsProfileSnapshotGraph.h"
#include "AppleReadOnlyRecordGraph.h"
#include "ApfsSpaceAccounting.h"
#include <filesystem>
#include <fstream>
#define APFS_FUSION_SNAPSHOT_CATALOG_FIXTURES_ONLY
#include "ApfsFusionSnapshotCatalogTests.cpp"
#undef APFS_FUSION_SNAPSHOT_CATALOG_FIXTURES_ONLY

namespace
{
void SetBit(Bytes& bytes, std::uint64_t bit, bool value = true)
{
    const auto mask = std::byte(1u << (bit % 8));
    if (value) bytes.at(bit / 8) |= mask; else bytes.at(bit / 8) &= ~mask;
}
std::uint32_t CountBits(const Bytes& bytes)
{
    std::uint32_t result = 0;
    for (const auto byte : bytes) for (unsigned n = 0; n < 8; ++n)
        result += (std::to_integer<unsigned>(byte) >> n) & 1;
    return result;
}
Bytes EmptyQueue(Fixture& f, std::uint64_t oid, std::uint64_t block)
{
    AppleBtreeOptions options;
    options.block_size = f.bs; options.xid = 20;
    options.root_object_id = oid; options.root_physical_block = block;
    options.storage_type = kObjectEphemeral; options.subtype = kObjectTypeSpacemanFreeQueue;
    options.tree_flags = kAppleBtreeEphemeral | kAppleBtreeAllowGhosts |
        kAppleBtreeUint64Keys | kAppleBtreeSequentialInsert;
    options.fixed_key_size = options.minimum_longest_key = 16;
    options.fixed_value_size = options.minimum_longest_value = 8;
    options.key_order = AppleBtreeKeyOrder::SpacemanFreeQueue;
    AppleSerializedBtree tree; std::string error;
    Check(SerializeAppleBtree({}, options, tree, error) && tree.objects.size() == 1, error);
    return tree.objects.front().bytes;
}
void UpdateAllocationCounts(Fixture& f, const Bytes& main, const Bytes& tier)
{
    f.Place(0, 258, main); f.Place(0, 259, tier);
    f.Edit(0, 256, [&](auto& bytes) { Put(bytes, 0x3C, 512 - CountBits(main), 4); });
    f.Edit(0, 257, [&](auto& bytes) { Put(bytes, 0x3C, 128 - CountBits(tier), 4); });
    f.Edit(0, 160, [&](auto& bytes) {
        Put(bytes, 0x48, 512 - CountBits(main)); Put(bytes, 0x78, 128 - CountBits(tier));
    });
}
// Extend the shared canonical catalog fixture with independently encoded
// spaceman/CIB/bitmap/queue objects. No file I/O or mutation engine is used.
void AllocatedCatalog(Fixture& f)
{
    f.sources[0]->bytes.resize(f.prefix + 512 * f.bs);
    f.sources[1]->bytes.resize(f.prefix + 128 * f.bs);
    CatalogFixture(f);
    auto nx = f.Block(0, 0);
    Put(nx, 0x28, 640); Put(nx, 0x58, 10000);
    Put(nx, 0x68, 16, 4); Put(nx, 0x6C, 32, 4); Put(nx, 0x70, 128); Put(nx, 0x78, 160);
    Put(nx, 0x80, 2, 4); Put(nx, 0x84, 4, 4); Put(nx, 0x88, 0, 4);
    Put(nx, 0x8C, 2, 4); Put(nx, 0x90, 0, 4); Put(nx, 0x94, 4, 4);
    Seal(nx); f.Place(0, 0, nx); f.Place(0, 129, nx);
    nx[0x50F] |= std::byte{1}; Seal(nx); f.Place(1, 0, nx);
    auto mapping = f.Block(0, 1); Put(mapping, 8, 128); Put(mapping, 0x24, 4, 4);
    for (unsigned n = 0; n < 4; ++n)
    {
        const auto at = 0x28 + 0x28 * n;
        if (n >= 2) {
            Put(mapping, at, kObjectEphemeral | kObjectTypeBtree, 4);
            Put(mapping, at + 4, kObjectTypeSpacemanFreeQueue, 4);
            Put(mapping, at + 8, f.bs, 4); Put(mapping, at + 24, 78 + n);
        }
        Put(mapping, at + 32, 160 + n);
    }
    Seal(mapping); f.Place(0, 128, mapping);
    f.Place(0, 160, f.Block(0, 8)); f.Place(0, 161, f.Block(0, 9));
    f.Place(0, 162, EmptyQueue(f, 80, 162)); f.Place(0, 163, EmptyQueue(f, 81, 163));
    Bytes main(f.bs), tier(f.bs), internal(f.bs);
    for (const auto block : {0, 15, 17, 18, 24, 25, 26, 27, 30, 31, 35, 36, 38, 40, 41, 42, 43}) SetBit(main, block);
    for (unsigned block = 128; block < 208; ++block) SetBit(main, block);
    for (unsigned block = 256; block < 268; ++block) SetBit(main, block);
    for (const auto block : {0, 4, 5, 6, 8, 9, 10, 11, 14, 20}) SetBit(tier, block);
    for (unsigned block = 0; block < 4; ++block) SetBit(internal, block);
    f.Place(0, 192, internal);
    for (unsigned device = 0; device < 2; ++device)
    {
        auto cib = Object(f.bs, 256 + device, kObjectPhysical | kObjectTypeSpacemanCib);
        Put(cib, 0x24, 1, 4); Put(cib, 0x28, 20); Put(cib, 0x38, device ? 128 : 512, 4);
        Put(cib, 0x40, 258 + device); Seal(cib); f.Place(0, 256 + device, cib);
    }
    f.Edit(0, 160, [&](auto& sm) {
        Put(sm, 0x30, 512); Put(sm, 0x60, 128);
        Put(sm, 0x50, 0x158, 4); Put(sm, 0x80, 0x160, 4);
        Put(sm, 0x94, 16, 4); Put(sm, 0x98, 12); Put(sm, 0xA0, 1, 4); Put(sm, 0xA4, 16, 4);
        Put(sm, 0xA8, 192); Put(sm, 0xB0, 256);
        Put(sm, 0xF8, 81); Put(sm, 0x108, 64, 2); Put(sm, 0x120, 80); Put(sm, 0x130, 64, 2);
        Put(sm, 0x140, 1, 2); Put(sm, 0x142, 15, 2);
        Put(sm, 0x144, 0x168, 4); Put(sm, 0x148, 0x170, 4); Put(sm, 0x14C, 0x172, 4);
        Put(sm, 0x154, 0x158, 4); Put(sm, 0x158, 256); Put(sm, 0x160, 257); Put(sm, 0x168, 20);
        for (unsigned n = 0; n < 16; ++n) Put(sm, 0x172 + 2 * n, n == 0 || n == 15 ? 0xFFFF : n + 1, 2);
    });
    UpdateAllocationCounts(f, main, tier);
    for (auto& member : f.request.members) {
        const auto index = member.role == FusionMemberRole::Main ? 0 : 1;
        member.store_size = (index ? 128ull : 512ull) * f.bs;
        member.exact_identity.size_bytes = f.sources[index]->SizeBytes();
    }
    f.Budget(100000, 256ull << 20, 2000000, 256ull << 20);
}
VerificationScope GraphScope(const Fixture& f)
{
    VerificationScope scope; scope.source_identity = "memory-fusion-visible-snapshots";
    scope.exact = {f.prefix, 512ull * f.bs, f.request.container_uuid_hex, std::string(32, 'c'), 101, 20};
    return scope;
}
void HistoricalCatalog(Fixture& f)
{
    AllocatedCatalog(f);
    // Keep immutable physical/virtual tree nodes from generation 19; publish
    // distinct generation-bound checkpoint maps, ephemeral objects and APSBs.
    for (const auto block : {17, 31, 35, 36, 38, 40, 42, 43})
        f.Edit(0, block, [](auto& bytes) { Put(bytes, 16, 19); });
    for (const auto block : {5, 8, 9, 11, 14})
        f.Edit(1, block, [](auto& bytes) { Put(bytes, 16, 19); });
    FileTree(f, 0, 30, 19);
    f.Place(1, 6, tf::BuildBtreeNode({{1000, 30, 0, 19}}, 19, f.bs, 0,
        f.TierBlock() + 6, kObjectPhysical | kObjectTypeBtree, kObjectTypeOmap));
    f.Place(0, 44, tf::BuildOmap(45, 19, f.bs, 44,
        kObjectPhysical | kObjectTypeOmap, kObjectPhysical | kObjectTypeBtree, 1));
    f.Place(0, 45, tf::BuildBtreeNode({{101, 47, 0, 19}}, 19, f.bs, 0, 45,
        kObjectPhysical | kObjectTypeBtree, kObjectTypeOmap));
    auto apsb = f.Block(1, 4); Put(apsb, 16, 19); Seal(apsb); f.Place(0, 47, apsb);
    auto main = f.Block(0, 258), tier = f.Block(0, 259), internal = f.Block(0, 192);
    for (const auto block : {44, 45, 47}) SetBit(main, block);
    for (unsigned n = 4; n < 8; ++n) SetBit(internal, n);
    f.Place(0, 192, internal);
    UpdateAllocationCounts(f, main, tier);
    f.Edit(0, 160, [](auto& bytes) { Put(bytes, 0x168, 19); });
    for (unsigned n = 0; n < 2; ++n) {
        auto cib = f.Block(0, 256 + n); Put(cib, 8, 260 + n); Put(cib, 16, 19);
        Put(cib, 0x28, 19); Put(cib, 0x40, 262 + n); Seal(cib); f.Place(0, 260 + n, cib);
        f.Place(0, 262 + n, n ? tier : main);
    }
    for (unsigned n = 0; n < 4; ++n) {
        auto object = f.Block(0, 160 + n); Put(object, 16, 19);
        if (n == 0) {
            Put(object, 0x158, 260); Put(object, 0x160, 261); Put(object, 0x168, 19);
        }
        Seal(object); f.Place(0, 164 + n, object);
    }
    auto map = f.Block(0, 128); Put(map, 8, 130); Put(map, 16, 19);
    for (unsigned n = 0; n < 4; ++n) Put(map, 0x28 + 0x28 * n + 32, 164 + n);
    Seal(map); f.Place(0, 130, map);
    auto nx = f.Block(0, 129); Put(nx, 16, 19); Put(nx, 0x60, 20); Put(nx, 0xA0, 44);
    Put(nx, 0x80, 4, 4); Put(nx, 0x88, 2, 4); Put(nx, 0x84, 8, 4); Put(nx, 0x90, 4, 4);
    Seal(nx); f.Place(0, 131, nx);
}
ProfileSnapshotGraphReport VerifyGraph(Fixture& f, VerificationScope scope, bool expired = false)
{
    auto store = f.Good();
    return VerifyFusionSnapshotProfile(*store, scope, {"apfs-store:test-main", "apfs-store:test-tier2"},
        {}, [expired] { return !expired; });
}
void GraphFailed(const ProfileSnapshotGraphReport& report)
{
    Check(report.outcome != VerificationOutcome::Complete && !report.findings.empty(), "negative graph published complete");
    Check(!report.selected && report.stores.empty() && report.chain_xids.empty() && report.checkpoints.empty() &&
        !report.allocation_unit_bytes, "failure published a partial graph");
    Check(!report.snapshot_allocation_charge_bytes && !report.apple_purgeable_bytes && !report.reclaimable_bytes,
        "failure invented Apple charges");
}
void MultiNodeSnapshot(Fixture& f)
{
    std::vector<CatalogRecord> records; std::string error;
    auto source = f.Good();
    Check(ReadBtreeLeafRecords(*source, f.bs, f.TierBlock() + 10, false, f.TierBlock() + 9, 18, records, error), error);
    source.reset();
    for (unsigned n = 0; n < 16; ++n)
        records.push_back(Enc(AppleXattrRecord{30, "user.pad." + std::to_string(n), kAppleXattrDataEmbedded,
            Bytes(600, std::byte(n))}, EncodeAppleXattrRecord));
    AppleBtreeOptions options; options.block_size = f.bs; options.xid = 18;
    options.root_object_id = 1000; options.root_physical_block = f.TierBlock() + 10;
    options.first_child_object_id = 1001; options.first_child_physical_block = f.TierBlock() + 50;
    options.subtype = kObjectTypeFsTree; options.key_order = AppleBtreeKeyOrder::FileSystemCaseSensitive;
    AppleSerializedBtree tree;
    Check(SerializeAppleBtree(records, options, tree, error) && tree.height && tree.objects.size() > 1, error);
    std::vector<tf::OmapRecordSpec> mappings; auto tier = f.Block(0, 259);
    for (const auto& item : tree.objects) {
        Check(item.location.physical_block >= f.TierBlock(), "snapshot node escaped member");
        f.Place(1, item.location.physical_block - f.TierBlock(), item.bytes);
        SetBit(tier, item.location.physical_block - f.TierBlock());
        mappings.push_back({item.location.object_id, item.location.physical_block, 0, 18});
    }
    std::sort(mappings.begin(), mappings.end(), [](const auto& a, const auto& b) { return a.oid < b.oid; });
    f.Place(1, 11, tf::BuildBtreeNode(mappings, 20, f.bs, 0, f.TierBlock() + 11,
        kObjectPhysical | kObjectTypeBtree, kObjectTypeOmap));
    UpdateAllocationCounts(f, f.Block(0, 258), tier);
}
void RunGraphs()
{
    // Historical fixture/admission gate is opt-in until the shared canonical
    // empty-WBC validator extraction is coordinated; current tests stay intact.
    {
        Fixture f(4096, 3); AllocatedCatalog(f);
        const auto before_main = f.sources[0]->bytes, before_tier = f.sources[1]->bytes;
        auto store = f.Good(); std::string error;
        for (unsigned repeat = 0; repeat < 3; ++repeat)
        {
            const auto report = VerifyFusionSnapshotProfile(*store, GraphScope(f),
                {"apfs-store:test-main", "apfs-store:test-tier2"}, {}, [] { return true; });
            Check(report.outcome == VerificationOutcome::Complete,
                report.findings.empty() ? "no complete snapshot graph" : report.findings.front().detail);
            Check(report.selected && report.chain_xids == std::vector<std::uint64_t>{20} &&
                report.checkpoints.size() == 1 && report.stores.size() == 2 && report.allocation_unit_bytes == 4096,
                "exact source/checkpoint/member partition");
            const auto& graph = report.checkpoints.front();
            Check(graph.views.size() == 3 && graph.views[0].view_xid == 18 && graph.views[1].view_xid == 19 &&
                graph.views[2].view_xid == 20 && graph.views[2].current, "all visible snapshots and live namespace");
            Check(graph.protected_graph.payload_ranges.size() == 1 &&
                graph.protected_graph.payload_ranges.front().physical_block == f.TierBlock() + 20 &&
                graph.protected_graph.payload_ranges.front().block_count == 1, "shared history was summed as allocation");
            for (const auto& view : graph.views) Check(view.payload_ranges.size() == 1 &&
                view.payload_ranges.front().block_count == 1 && view.filesystem_record_count == 5,
                "per-view inherited payload or namespace missing");
            Check(!report.snapshot_allocation_charge_bytes && !report.apple_purgeable_bytes && !report.reclaimable_bytes,
                "referenced footprint became an Apple charge");
            std::optional<ApfsProfileSnapshotSpaceAttribution> amounts;
            Check(TryAttributeVerifiedProfileSnapshotSpace(report, amounts, error, [] { return true; }), error);
            Check(amounts && amounts->complete && amounts->snapshots.size() == 2 &&
                amounts->referenced_snapshot_metadata.blocks == 10 && amounts->referenced_snapshot_payload.blocks == 1 &&
                amounts->live_metadata.blocks == 6 && amounts->live_payload.blocks == 1, "exact per-view metadata and physical unions");
            for (const auto& row : amounts->snapshots)
                Check(row.metadata.referenced.blocks == 5 && row.payload.referenced.blocks == 1 &&
                    row.payload.shared_with_live.blocks == 1 && row.payload.shared_with_other_snapshots.blocks == 1 &&
                    row.payload.unique_in_visible_inventory.blocks == 0 && row.payload.potential_reclaim_upper_bound.blocks == 0,
                    "same tier payload across snapshots/live is charged once with explicit overlap");
            AppleSnapshotCatalogRecords ignored; std::vector<AppleSnapshotMetadataClaim> claims;
            auto cp = LoadAppleReadOnlyVolumeView(*store, store->Checkpoint(), error); Check(cp.has_value(), error);
            AppleCheckpointView strict; strict.container = cp->container; strict.container_object_map = cp->container_object_map;
            strict.volumes = cp->volumes;
            Check(!LoadAppleSnapshotCatalog(*store, strict, 101, ignored, claims, error), "observational success promoted mutation");
        }
        Check(f.sources[0]->bytes == before_main && f.sources[1]->bytes == before_tier, "read-only graph changed source bytes");
        ++cases;
    }
    {
        Fixture f; AllocatedCatalog(f); MultiNodeSnapshot(f);
        const auto report = VerifyGraph(f, GraphScope(f));
        Check(report.outcome == VerificationOutcome::Complete,
            report.findings.empty() ? "multi-node snapshot graph incomplete" : report.findings.front().detail);
        Check(report.checkpoints.front().views.front().filesystem_record_count == 21, "snapshot children omitted");
        ++cases;
    }
    for (unsigned fault = 0; fault < 10; ++fault)
    {
        Fixture f; AllocatedCatalog(f);
        if (fault == 0) f.sources[1]->bytes[f.prefix + 10 * f.bs + 100] ^= std::byte{1};
        if (fault == 1) f.Edit(1, 10, [](auto& bytes) { Put(bytes, 16, 19); });
        if (fault == 2) {
            auto main = f.Block(0, 258), tier = f.Block(0, 259); SetBit(tier, 20, false);
            UpdateAllocationCounts(f, main, tier);
        }
        if (fault == 3) {
            auto main = f.Block(0, 258), tier = f.Block(0, 259); SetBit(tier, 10, false);
            UpdateAllocationCounts(f, main, tier);
        }
        if (fault == 4) f.Place(1, 14, tf::BuildRawLeafNode({}, {}, 20, f.bs, 0,
            f.TierBlock() + 14, kObjectPhysical | kObjectTypeBtree, 0x777));
        if (fault == 5) f.Edit(1, 8, [](auto& bytes) { Put(bytes, 0x58, 641); });
        if (fault == 6) f.Place(1, 11, tf::BuildBtreeNode({{1000, 600, 0, 18}}, 20, f.bs, 0,
            f.TierBlock() + 11, kObjectPhysical | kObjectTypeBtree, kObjectTypeOmap));
        if (fault == 7) f.Edit(0, 38, [](auto& bytes) { Put(bytes, 16, 21); });
        auto store = f.Good();
        if (fault == 8) f.sources[1]->present = false;
        if (fault == 9) f.sources[1]->after_read = [&] {
            if (f.sources[1]->reads.back().first == f.prefix + 10 * f.bs) f.sources[0]->present = false;
        };
        const auto report = VerifyFusionSnapshotProfile(*store, GraphScope(f),
            {"apfs-store:test-main", "apfs-store:test-tier2"}, {}, [] { return true; });
        GraphFailed(report); ++cases;
    }
    for (unsigned fault = 0; fault < 5; ++fault)
    {
        Fixture f; AllocatedCatalog(f); auto scope = GraphScope(f);
        if (fault == 0) scope.exact.volume_uuid_hex[0] = 'd';
        if (fault == 1) scope.exact.store_offset_bytes += f.bs;
        if (fault == 2) scope.require_whole_volume = true;
        if (fault == 3) scope.max_reads = 1;
        GraphFailed(VerifyGraph(f, scope, fault == 4)); ++cases;
    }
}
}
int main(int argc, char** argv) try
{
    if (argc == 2 && std::string_view(argv[1]) == "--retained") {
        Fixture f(4096, 3); HistoricalCatalog(f); auto store = f.Good();
        const auto report = VerifyFusionSnapshotProfile(*store, GraphScope(f),
            {"apfs-store:test-main", "apfs-store:test-tier2"}, 19, [] { return true; });
        Check(report.outcome == VerificationOutcome::Complete,
            report.findings.empty() ? "retained Fusion graph missing" : report.findings.front().detail);
        Check(report.chain_xids == std::vector<std::uint64_t>{19, 20} && report.checkpoints.size() == 2 &&
            report.checkpoints[0].views.size() == 3 && report.checkpoints[1].views.size() == 3,
            "every nonempty current/snapshot parent namespace required");
        std::optional<ApfsProfileSnapshotSpaceAttribution> amounts; std::string error;
        Check(TryAttributeVerifiedProfileSnapshotSpace(report, amounts, error, [] { return true; }), error);
        Check(amounts && amounts->complete && amounts->snapshots.size() == 2 &&
            amounts->snapshots[0].payload.referenced.blocks == 1 &&
            amounts->snapshots[0].payload.retained_or_peer_protected.blocks == 1 &&
            !amounts->snapshots[0].payload.potential_reclaim_upper_bound.blocks,
            "retained parent payload was not protected from potential release");
        for (unsigned fault = 0; fault < 8; ++fault) {
            Fixture bad; HistoricalCatalog(bad);
            if (fault == 0) bad.Edit(0, 165, [](auto& bytes) { Put(bytes, 0x28, 1); });
            if (fault == 1) bad.Edit(0, 165, [](auto& bytes) { Put(bytes, 0x4C, 1, 4); });
            if (fault == 2) bad.Edit(0, 165, [](auto& bytes) { Put(bytes, 0x20, 0x71); });
            if (fault == 3) bad.sources[0]->bytes[165 * bad.bs + 100] ^= std::byte{1};
            if (fault == 4) bad.Edit(0, 165, [](auto& bytes) { Put(bytes, 16, 20); });
            if (fault == 5) bad.Edit(0, 130, [](auto& bytes) { Put(bytes, 0x50 + 32, 600); });
            auto bound = bad.Good(); auto scope = GraphScope(bad);
            if (fault == 6) scope.max_reads = 1;
            GraphFailed(VerifyFusionSnapshotProfile(*bound, scope,
                {"apfs-store:test-main", "apfs-store:test-tier2"}, 19, [fault] { return fault != 7; }));
        }
        std::cout << "PASS retained nonempty Fusion graph and independent attribution / " << checks << " checks\n"; return 0;
    }
    if (argc == 3 && (std::string_view(argv[1]) == "--export" || std::string_view(argv[1]) == "--export-retained")) {
        const auto root = std::filesystem::absolute(argv[2]).lexically_normal();
        Check(root.wstring().starts_with(L"D:\\ApfsAccessScratch\\") && std::filesystem::create_directories(root), "new D-only synthetic fixture folder");
        Fixture f(4096, 3);
        if (std::string_view(argv[1]) == "--export-retained") HistoricalCatalog(f); else AllocatedCatalog(f);
        for (unsigned member = 0; member < 2; ++member) {
            const auto& bytes = f.sources[member]->bytes;
            std::ofstream file(root / (member ? "tier.apfs" : "main.apfs"), std::ios::binary);
            file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
            Check(static_cast<bool>(file), "bounded canonical Fusion fixture export");
        }
        std::cout << "PASS canonical synthetic Fusion snapshot images exported\n"; return 0;
    }
    Check(argc == 1, "known focused selector required");
    RunGraphs();
    std::cout << "PASS " << cases << " cases / " << checks << " checks; in-memory allocated Fusion snapshot graphs\n";
    return 0;
}
catch (const std::exception& error)
{ std::cerr << "FAIL " << error.what() << " after " << checks << " checks\n"; return 1; }
