#include "ApfsReadOnlyMetadataAdmission.h"
#define main ExistingInactiveTreeHistoryMain
#include "ApfsVerifierHistoryTests.cpp"
#undef main

namespace
{
constexpr auto default_tree_type = kObjectPhysical | kObjectTypeBtree;

Bytes ApsbBytes(const Fixture& f, std::uint64_t block)
{
    return Bytes(f.image.begin() + block * f.bs, f.image.begin() + (block + 1) * f.bs);
}

bool Empty(const AppleSnapshotCatalogRecords& catalog)
{
    return catalog.inventory.empty() && catalog.snapshots.empty() && catalog.metadata_blocks.empty() &&
        catalog.live.filesystem.empty() && catalog.live.extentref.empty() && catalog.live.metadata_blocks.empty();
}

bool SameRecords(const std::vector<BtreeRecord>& a, const std::vector<BtreeRecord>& b)
{
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](const auto& x, const auto& y) {
        return x.key == y.key && x.value == y.value;
    });
}

void Defaults(Fixture& f, std::uint32_t fext, std::uint32_t reserved)
{
    VectorRandomAccessSource source(f.image); AppleSnapshotCatalogRecords catalog; std::string error;
    Check(LoadAppleSnapshotCatalog(source, f.checkpoint, 101, catalog, error), "original strict fixture: " + error);
    std::set<std::uint64_t> blocks{f.checkpoint.volumes[0].superblock_object.physical_block};
    for (const auto& row : catalog.inventory) blocks.insert(row.volume.superblock_object.physical_block);
    for (const auto block : blocks) f.Edit(block, [&](auto& bytes) {
        PutU32LE(bytes, 0x410, fext); PutU32LE(bytes, 0x414, reserved);
    });
    f.Reload();
}

void StrictRefused(Fixture& f)
{
    VectorRandomAccessSource source(f.image); std::string error;
    AppleSnapshotCatalogRecords catalog; catalog.metadata_blocks = {999};
    Check(!LoadAppleSnapshotCatalog(source, f.checkpoint, 101, catalog, error) && Empty(catalog) &&
        error == "SnapshotVolumeStateOrReservedFieldsUnsupported", "old catalog stays strict: " + error);
    std::vector<AppleSnapshotMetadataClaim> claims(1); catalog.metadata_blocks = {999};
    Check(!LoadAppleSnapshotCatalog(source, f.checkpoint, 101, catalog, claims, error) && Empty(catalog) && claims.empty(),
        "old claim catalog clears every refused result");
    std::vector<AppleSnapshotRecord> records(1); AppleSnapshotTreeRecords trees; trees.metadata_blocks = {999};
    Check(!LoadAppleSnapshotRecords(source, f.checkpoint, 101, records, error) && records.empty(), "old inventory export stays strict");
    records.resize(1);
    Check(!LoadAppleSnapshotRecords(source, f.checkpoint, 101, records, error, 0, trees) &&
        records.empty() && trees.metadata_blocks.empty(), "old selected-record export stays strict");
}

void PositiveAndStrictCases()
{
    for (const auto bs : {4096u, 8192u})
        for (unsigned combination = 0; combination < 4; ++combination)
        {
            Fixture f(bs); VectorRandomAccessSource before(f.image); std::string error;
            AppleSnapshotCatalogRecords original;
            Check(LoadAppleSnapshotCatalog(before, f.checkpoint, 101, original, error), error);
            Defaults(f, combination & 1 ? default_tree_type : 0, combination & 2 ? default_tree_type : 0);
            const auto unchanged = f.image;
            auto budget = std::make_shared<ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
            VectorRandomAccessSource raw(f.image); BudgetedRandomAccessSource source(raw, budget);
            AppleSnapshotCatalogRecords catalog; std::vector<AppleSnapshotMetadataClaim> claims;
            Check(LoadAppleReadOnlySnapshotCatalog(source, f.checkpoint, 101, catalog, claims, error), "read-only defaults: " + error);
            Check(catalog.inventory.empty() && catalog.snapshots.empty() && catalog.metadata_blocks == original.metadata_blocks &&
                SameRecords(catalog.live.filesystem, original.live.filesystem) && SameRecords(catalog.live.extentref, original.live.extentref),
                "same canonical graph, footprint and records under tail defaults");
            std::set<std::uint64_t> owned;
            for (const auto& claim : claims) owned.insert(claim.physical_block);
            Check(std::vector<std::uint64_t>(owned.begin(), owned.end()) == catalog.metadata_blocks &&
                budget->Consumed().reads && !budget->Failed(), "exact typed ownership footprint under shared allowance");
            Check(LoadAppleReadOnlySnapshotCatalog(source, f.checkpoint, 101, catalog, error), "read-only catalog without claims: " + error);
            if (combination) StrictRefused(f);
            else Check(LoadAppleSnapshotCatalog(source, f.checkpoint, 101, catalog, error), "old zero-default control");
            Check(unchanged == f.image, "catalog admission never rewrites original bytes");
            Pass("read-only default combination " + std::to_string(combination) + " geometry " + std::to_string(bs));
        }
    for (const auto bs : {4096u, 8192u})
    {
        Fixture f(bs); const auto identity = f.Create("inactive-default", {20});
        Defaults(f, default_tree_type, default_tree_type);
        VectorRandomAccessSource source(f.image); AppleSnapshotCatalogRecords catalog; std::string error;
        Check(LoadAppleReadOnlySnapshotCatalog(source, f.checkpoint, 101, catalog, error) && catalog.inventory.size() == 1 &&
            catalog.inventory[0].xid == identity.snapshot_xid && catalog.inventory[0].name_utf8 == identity.name_utf8,
            "read-only complete snapshot inventory: " + error);
        const auto descriptor = catalog.inventory[0].volume.superblock_object.physical_block;
        Check(LoadAppleReadOnlySnapshotDescriptorCatalog(source, f.checkpoint, 101, descriptor, identity.snapshot_xid, catalog, error),
            "read-only physical descriptor uses original checked APSB: " + error);
        Check(!LoadAppleSnapshotDescriptorCatalog(source, f.checkpoint, 101, descriptor, identity.snapshot_xid, catalog, error) && Empty(catalog) &&
            error == "SnapshotVolumeStateOrReservedFieldsUnsupported", "old descriptor export stays strict: " + error);
        StrictRefused(f);
        AppleSnapshotCreateRequest request; request.volume_object_id = 101; request.name_utf8 = "must-refuse";
        request.creation_time_ns = f.checkpoint.container.superblock.next_xid; request.required_checkpoint_xids = {20};
        AppleSnapshotCreatePlan plan;
        Check(!PlanAppleSnapshotCreate(source, f.checkpoint, request, plan, error), "actual snapshot mutation still refuses widened profile");
        Pass("snapshot descriptor and strict mutation separation " + std::to_string(bs));
    }
}

void NegativeCases()
{
    struct Mutation { const char* name; std::size_t offset; unsigned width; std::uint64_t value; };
    const Mutation mutations[] = {
        {"virtual fext type",0x410,4,kObjectTypeBtree},
        {"ephemeral fext type",0x410,4,kObjectEphemeral | kObjectTypeBtree},
        {"node fext type",0x410,4,kObjectPhysical | kObjectTypeBtreeNode},
        {"headerless fext type",0x410,4,kObjectPhysical | kObjectNoHeader | kObjectTypeBtree},
        {"extra fext flag",0x410,4,0x50000002},
        {"virtual reserved type",0x414,4,kObjectTypeBtree},
        {"ephemeral reserved type",0x414,4,kObjectEphemeral | kObjectTypeBtree},
        {"node reserved type",0x414,4,kObjectPhysical | kObjectTypeBtreeNode},
        {"headerless reserved type",0x414,4,kObjectPhysical | kObjectNoHeader | kObjectTypeBtree},
        {"extra reserved flag",0x414,4,0x50000002},
        {"active fext OID",0x408,8,220}, {"active reserved OID",0x418,8,220},
        {"out-of-container fext OID",0x408,8,512}, {"out-of-container reserved OID",0x418,8,512},
        {"integrity metadata OID",0x400,8,220}, {"sealed feature",0x38,8,0x20},
        {"unknown optional feature",0x28,8,1ull << 63}, {"read-only feature",0x30,8,1},
        {"encrypted fs flag",0x108,8,kFsFlagOneKey},
        {"revert XID",0xA0,8,1}, {"revert APSB",0xA8,8,1}, {"reserved16",0x3C6,2,1},
        {"root-to-XID",0x3C8,8,1}, {"encryption-state OID",0x3D0,8,1},
        {"extended snapshot metadata",0x3E8,8,1}, {"future APSB generation",0x10,8,21},
        {"extra APSB object flag",0x18,4,0x1000000D}, {"wrong APSB subtype",0x1C,4,1}
    };
    for (const auto& mutation : mutations)
    {
        Fixture f; Defaults(f, default_tree_type, default_tree_type);
        const auto block = f.checkpoint.volumes[0].superblock_object.physical_block;
        f.Edit(block, [&](auto& bytes) {
            if (mutation.width == 8) PutU64LE(bytes, mutation.offset, mutation.value);
            else if (mutation.width == 4) PutU32LE(bytes, mutation.offset, static_cast<std::uint32_t>(mutation.value));
            else PutU16LE(bytes, mutation.offset, static_cast<std::uint16_t>(mutation.value));
        });
        if (const auto parsed = ParseApsb(ApsbBytes(f, block))) f.checkpoint.volumes[0].superblock = *parsed;
        VectorRandomAccessSource source(f.image); AppleSnapshotCatalogRecords catalog; catalog.metadata_blocks = {999};
        std::vector<AppleSnapshotMetadataClaim> claims(1); std::string error;
        Check(!LoadAppleReadOnlySnapshotCatalog(source, f.checkpoint, 101, catalog, claims, error) && Empty(catalog) &&
            claims.empty() && !error.empty(), std::string("read-only malformed/active state refused: ") + mutation.name);
        Pass(std::string("reject ") + mutation.name);
    }
    {
        Fixture f; Defaults(f, default_tree_type, default_tree_type);
        const auto block = f.checkpoint.volumes[0].superblock_object.physical_block;
        auto bytes = ApsbBytes(f, block); auto expected = f.checkpoint.volumes[0].superblock; std::string error;
        Check(CheckAppleReadOnlyInactiveTreeDefaults(bytes, expected, error), "direct checked-helper control");
        bytes[0x410] ^= std::byte{1};
        Check(!CheckAppleReadOnlyInactiveTreeDefaults(bytes, expected, error), "helper rejects stale checksum");
        bytes = ApsbBytes(f, block); bytes.resize(0x414); FletcherForBlock(bytes, static_cast<std::uint32_t>(bytes.size()));
        Check(!CheckAppleReadOnlyInactiveTreeDefaults(bytes, expected, error), "helper refuses truncated reserved tail with recomputed checksum");
        bytes = ApsbBytes(f, block); ++expected.xid;
        Check(!CheckAppleReadOnlyInactiveTreeDefaults(bytes, expected, error), "helper binds original generation");
        expected = f.checkpoint.volumes[0].superblock; expected.uuid_hex = std::string(32, 'c');
        Check(!CheckAppleReadOnlyInactiveTreeDefaults(bytes, expected, error), "helper binds original volume identity");
        expected = f.checkpoint.volumes[0].superblock; ++expected.extentref_tree_oid;
        Check(!CheckAppleReadOnlyInactiveTreeDefaults(bytes, expected, error), "helper binds original extentref tree");
        expected = f.checkpoint.volumes[0].superblock; expected.root_tree_type ^= kObjectPhysical;
        Check(!CheckAppleReadOnlyInactiveTreeDefaults(bytes, expected, error), "helper binds original root storage type");
        expected = f.checkpoint.volumes[0].superblock; ++expected.space.allocated_block_count;
        Check(!CheckAppleReadOnlyInactiveTreeDefaults(bytes, expected, error), "helper binds original allocation counter");
        f.Edit(block, [](auto& b) { b[0x414] ^= std::byte{1}; }, false);
        VectorRandomAccessSource source(f.image); AppleSnapshotCatalogRecords catalog;
        Check(!LoadAppleReadOnlySnapshotCatalog(source, f.checkpoint, 101, catalog, error) && Empty(catalog), "canonical wrapper rejects checksum failure");
        Pass("checked bounds, checksum and exact identity");
    }
    {
        Fixture f; Defaults(f, default_tree_type, default_tree_type);
        VectorRandomAccessSource raw(f.image); auto budget = std::make_shared<ApfsReadBudget>(0, 0, 0, 0);
        BudgetedRandomAccessSource source(raw, budget); AppleSnapshotCatalogRecords catalog; std::string error;
        Check(!LoadAppleReadOnlySnapshotCatalog(source, f.checkpoint, 101, catalog, error) && Empty(catalog) && budget->Failed(), "read-only shared allowance exhaustion");
        Check(!LoadAppleReadOnlySnapshotCatalog(source, f.checkpoint, 101, catalog, error) && Empty(catalog), "read-only retry keeps exhausted allowance");
        Pass("read-only budget and sticky retry");
    }
}
}

int main()
{
    try
    {
        PositiveAndStrictCases(); NegativeCases();
        std::cout << "PASS " << cases << " cases, " << checks << " checks\n"; return 0;
    }
    catch (const std::exception& e) { std::cerr << "FAIL " << e.what() << '\n'; return 1; }
}
