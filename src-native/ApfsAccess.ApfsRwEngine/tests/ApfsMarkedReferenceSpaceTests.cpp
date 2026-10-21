#include "NativeApfsReader.h"
#include "ApfsVerificationJson.h"
#define APFS_MARKED_RECORD_FIXTURES_ONLY
#include "ApfsMarkedFileExtentRecordTests.cpp"
#undef APFS_MARKED_RECORD_FIXTURES_ONLY
#include <filesystem>
#include <fstream>

namespace
{
void AddReferenceRecords(Fixture& f, unsigned fault = 0)
{
    VectorRandomAccessSource source(f.image); AppleSnapshotCatalogRecords catalog; std::string error;
    Check(LoadAppleReadOnlySnapshotCatalog(source, f.checkpoint, 101, catalog, error), error);
    const auto apply = [&](const AppleSnapshotTreeRecords& trees, const AppleVolumeCheckpointView& volume) {
        Check(trees.filesystem_blocks.size() == 1, "bounded one-node reference fixture");
        auto records = trees.filesystem; std::vector<Record> additions;
        for (const auto& record : records) {
            if ((ReadU64LE(record.key, 0).value_or(0) >> 60) != 3) continue;
            AppleInodeRecord inode; Check(ApfsExtendedRecordCodec::DecodeInodeReadOnly(record, inode, error), error);
            if (!(inode.internal_flags & 0x80000)) continue;
            AppleDirectoryRecord ref; ref.parent_id = 7; ref.file_id = inode.object_id; ref.flags = 8;
            ref.name_utf8 = "opaque-reference-" + std::to_string(inode.object_id);
            if (fault == 1) continue;
            if (fault == 2) ref.file_id = 999;
            if (fault == 3) ref.flags = 4;
            Record encoded; Check(EncodeAppleDirectoryRecord(ref, encoded, error), error);
            additions.push_back(std::move(encoded));
            if (fault == 4) {
                ref.name_utf8 += "-second"; Check(EncodeAppleDirectoryRecord(ref, encoded, error), error);
                additions.push_back(std::move(encoded));
            }
        }
        records.insert(records.end(), additions.begin(), additions.end());
        if (fault == 5) {
            AppleInodeRecord dir; dir.object_id = dir.private_id = 7; dir.parent_id = 2; dir.mode = 0040755;
            records.push_back(Encode(dir, EncodeAppleInodeRecord));
        }
        Check(SortAppleBtreeRecords(records, AppleBtreeKeyOrder::FileSystemCaseSensitive, error), error);
        std::vector<Bytes> keys, values; for (const auto& record : records) { keys.push_back(record.key); values.push_back(record.value); }
        const auto& tree = volume.root_tree;
        f.Put(tree.physical_block, BuildRawLeafNode(keys, values, tree.xid, f.bs, 0, tree.object_id, tree.type, tree.subtype));
    };
    for (std::size_t i = 0; i < catalog.snapshots.size(); ++i) apply(catalog.snapshots[i], catalog.inventory[i].volume);
    apply(catalog.live, f.checkpoint.volumes[0]); f.Reload();
}
ApfsMarkedReferenceSpaceObservation ObserveReferences(Fixture& f)
{
    const auto before = f.image; VectorRandomAccessSource source(f.image); std::string error;
    std::optional<ApfsMarkedReferenceSpaceObservation> result;
    Check(TryObserveAppleMarkedReferenceSpaceReadOnly(source, f.scope, result, error), "marked references: " + error);
    Check(result && result->records.complete && result->namespace_and_directory7_references_verified &&
        result->catalog_metadata_and_payload_allocation_verified && result->records.scope == f.scope.exact &&
        result->records.source_identity == f.scope.source_identity, "complete exact reference subset");
    Check(result->marked_file_payload.size() == result->records.views.size(), "exact marked payload view binding");
    Check(!result->records.apple_purgeable && !result->records.reclaimable && !result->records.snapshot_allocation_charge,
        "marked reference set became OS policy or release authority");
    Check(f.image == before, "read-only reference observation changed source"); return std::move(*result);
}
void ReferenceAttributeOwners()
{
    for (const bool both_marked : {false, true}) {
        Fixture f; Seed(f, true, true, 3);
        SetMarks(f, {{30, both_marked ? 0x80000ull : 0x100000ull}, {31, 0x80000}}); AddReferenceRecords(f);
        const auto result = ObserveReferences(f);
        Check(result.records.views[0].marked_regular_inode_count == (both_marked ? 2 : 1) &&
            result.records.referenced_physical_union.blocks == 3 &&
            result.marked_file_payload_union.blocks == (both_marked ? 4 : 3),
            "external xattr is charged only to a literally marked owning inode; shared marked clones union once");
        Pass(both_marked ? "two marked clones share payload with one marked attribute owner" :
            "WANT-only attribute owner does not charge its stream to a marked clone");
    }
}
void RunReferences()
{
    for (const auto bs : {4096u, 8192u}) {
        Fixture f(bs); Seed(f, true, true, 3); SetMarks(f, {{30, 0x80000}, {31, 0x100000}}); AddReferenceRecords(f);
        const auto result = ObserveReferences(f); const auto& row = result.records.views.back();
        Check(row.marked_regular_inode_count == 1 && row.want_only_regular_inode_count == 1 &&
            row.referenced_physical.blocks == 3 && row.referenced_physical.bytes == 3ull * bs,
            "actual flag+directory7 refs and shared clone count once; attribute-only stream excluded");
        Check(result.marked_file_payload_union.blocks == 4 &&
            result.marked_file_payload.back().referenced_physical.blocks == 4 &&
            result.marked_file_payload.back().ranges == std::vector<VerificationBlockRange>{{220, 4}},
            "marked owning file includes its external attribute stream; clone physical ranges union once");
        VectorRandomAccessSource source(f.image); AppleSnapshotCatalogRecords catalog; std::string error;
        Check(LoadAppleReadOnlySnapshotCatalog(source, f.checkpoint, 101, catalog, error), error);
        auto budget = std::make_shared<ApfsReadBudget>(100000, 256ull << 20, 2000000, 256ull << 20);
        for (unsigned round = 0; round < 3; ++round) {
            NativeApfsVolumeProjection projection;
            Check(!NativeApfsReader::TryProjectObservationalFileSystemRecords(catalog.live.filesystem,
                f.checkpoint.container.superblock, f.checkpoint.volumes[0].superblock, budget, projection, error) && projection.inodes.empty(),
                "old cold/warm observational path remains refused");
            Check(NativeApfsReader::TryProjectMarkedReferenceFileSystemRecords(catalog.live.filesystem,
                f.checkpoint.container.superblock, f.checkpoint.volumes[0].superblock, budget, projection, error), error);
            Check(projection.inodes.size() == 3 && projection.directory_links.size() == 2,
                "reserved references are not user hard links or inode7");
            Check(!NativeApfsReader::TryProjectOrdinaryFileSystemRecords(catalog.live.filesystem,
                f.checkpoint.container.superblock, f.checkpoint.volumes[0].superblock, budget, projection, error) && projection.inodes.empty(),
                "strict mutation-adjacent namespace remains refused after new read-only projection");
        }
        Pass("marked references, shared clone, external stream and strict interleavings block=" + std::to_string(bs));
    }
    ReferenceAttributeOwners();
    {
        Fixture f; f.Create("first", Pins(f)); f.Cow(true, Pins(f)); f.Create("second", Pins(f)); f.Cow(true, Pins(f));
        SetMarks(f, {{30, 0x80000}}); AddReferenceRecords(f); const auto result = ObserveReferences(f);
        Check(result.records.views.size() == 3 && result.records.referenced_physical_union.blocks == 3,
            "three canonical namespace/reference and signed COW generations form a physical union");
        Pass("multiple nonempty snapshots with directory7 references");
    }
    for (unsigned fault = 1; fault <= 5; ++fault) {
        Fixture f; SetMarks(f, {{30, 0x80000}}); AddReferenceRecords(f, fault);
        VectorRandomAccessSource source(f.image); std::string error;
        std::optional<ApfsMarkedReferenceSpaceObservation> result{ApfsMarkedReferenceSpaceObservation{}};
        Check(!TryObserveAppleMarkedReferenceSpaceReadOnly(source, f.scope, result, error) && !result,
            "incorrect reserved references cannot publish namespace/allocation completion: " + error);
        Pass("directory7 missing/foreign/type/duplicate/inode negative=" + std::to_string(fault));
    }
    {
        Fixture f; SetMarks(f, {{30, 0x80000}}); AddReferenceRecords(f);
        const auto& cp = f.checkpoint; const auto& chunk = cp.spaceman.chunks.front();
        const auto bit = f.payload_blocks[0] - chunk.start_block;
        Check(bit < chunk.block_count && (std::to_integer<unsigned>(chunk.allocation_bitmap[bit / 8]) &
            (1u << (bit % 8))), "negative starts with an allocated canonical payload");
        f.Edit(chunk.bitmap_block, [&](auto& bytes) { bytes[bit / 8] &= ~std::byte(1u << (bit % 8)); }, false);
        f.Edit(cp.spaceman.devices[0].cibs[0].object.physical_block,
            [&](auto& bytes) { PutU32LE(bytes, 0x3C, chunk.free_count + 1); });
        f.Edit(cp.spaceman.object.physical_block,
            [&](auto& bytes) { PutU64LE(bytes, 0x48, cp.spaceman.devices[0].free_count + 1); });
        VectorRandomAccessSource source(f.image); std::string error;
        std::optional<ApfsMarkedReferenceSpaceObservation> result;
        Check(!TryObserveAppleMarkedReferenceSpaceReadOnly(source, f.scope, result, error) && !result,
            "canonical signed reference to an unallocated payload cannot publish");
        Pass("free payload is not marked ownership");
    }
    {
        Fixture f; SetMarks(f, {{30, 0x80000}}); AddReferenceRecords(f); VectorRandomAccessSource source(f.image);
        std::optional<ApfsMarkedReferenceSpaceObservation> result; std::string error;
        Check(!TryObserveAppleMarkedReferenceSpaceReadOnly(source, f.scope, result, error, [] { return false; }) && !result,
            "deadline clears the stronger result");
        auto budget = std::make_shared<ApfsReadBudget>(1, 1, 1, 1); BudgetedRandomAccessSource spent(source, budget);
        for (unsigned i = 0; i < 2; ++i) Check(!TryObserveAppleMarkedReferenceSpaceReadOnly(spent, f.scope, result, error) && !result && budget->Failed(),
            "shared budget remains refused");
        Pass("deadline and sticky allowance refuse stronger references");
    }
}

void ReferenceWireCases()
{
    for (unsigned fault = 0; fault < 18; ++fault) {
        Fixture f; Seed(f, true, true, 3); SetMarks(f, {{30, 0x80000}, {31, 0x100000}}); AddReferenceRecords(f);
        std::optional<ApfsMarkedReferenceSpaceObservation> result = ObserveReferences(f);
        auto scope = f.scope; std::string json = "must clear"; payload::Reason failure;
        if (fault == 1) result.reset();
        if (fault == 2) result->records.complete = false;
        if (fault == 3) result->namespace_and_directory7_references_verified = false;
        if (fault == 4) result->catalog_metadata_and_payload_allocation_verified = false;
        if (fault == 5) result->records.source_identity += "-wrong";
        if (fault == 6) ++scope.exact.checkpoint_xid;
        if (fault == 7) ++result->marked_file_payload_union.blocks;
        if (fault == 8) ++result->marked_file_payload[0].referenced_physical.bytes;
        if (fault == 9) result->marked_file_payload[0].ranges.push_back({220, 1});
        if (fault == 10) result->marked_file_payload[0].ranges[0] = {511, 4};
        if (fault == 11) result->records.referenced_physical_union = {5, 5ull * f.bs};
        if (fault == 12) result->records.views[0].marked_regular_inode_count = 0;
        if (fault == 13) result->records.apple_purgeable = ApfsSpaceAmount{1, f.bs};
        if (fault == 14) scope.account_retained_ownership = true;
        if (fault == 15) (void)result->records.read_budget->Refuse("deliberately exhausted allowance");
        const auto encoded = SerializeMarkedReferenceSpace(result, scope, "D:\\wire\\marked-\"image\".apfs",
            [fault] { return fault != 16; }, fault == 17 ? 64 : MaxImageVerificationJsonBytes, json, failure);
        if (fault) Check(!encoded && json.empty() && failure != payload::Reason::None,
            "malformed/incomplete/deadline/budget/refused result emits no complete marked reference document");
        else Check(encoded && failure == payload::Reason::None &&
            json.starts_with("{\"format\":\"apfs-access-marked-reference-space\",\"version\":1,") &&
            json.find("\"literalRecordUnion\":{\"blocks\":\"3\",\"bytes\":\"12288\"}") != std::string::npos &&
            json.find("\"filePayloadUnion\":{\"blocks\":\"4\",\"bytes\":\"16384\"}") != std::string::npos &&
            json.find("\"markedRegularInodes\":\"1\",\"wantOnlyRegularInodes\":\"1\"") != std::string::npos &&
            json.find("\"filePayloadRanges\":[{\"physicalBlock\":\"220\",\"blockCount\":\"4\"}]") != std::string::npos &&
            json.find("\"snapshotAllocationChargeBytes\":null,\"applePurgeableBytes\":null,\"reclaimableBytes\":null") != std::string::npos,
            "actual complete encoded marked sets distinguish default fork, full file, WANT-only and OS policy");
    }
    Pass("marked reference bounded serializer positive and seventeen meaningful refusals");
}
}
#ifndef APFS_MARKED_REFERENCE_FIXTURES_ONLY
int main(int argc, char** argv) try
{
    if (argc == 2 && std::string_view(argv[1]) == "--attribute-owners") {
        ReferenceAttributeOwners();
        std::cout << "PASS " << cases << " cases / " << checks << " checks; marked attribute owner subset\n"; return 0;
    }
    if (argc == 3 && (std::string_view(argv[1]) == "--export" || std::string_view(argv[1]) == "--export-history")) {
        const auto path = std::filesystem::absolute(argv[2]).lexically_normal();
        Check(path.wstring().starts_with(L"D:\\ApfsAccessScratch\\") && !std::filesystem::exists(path), "new D-only marked fixture path");
        const bool history = std::string_view(argv[1]) == "--export-history";
        Fixture f;
        if (history) { f.Create("first", Pins(f)); f.Cow(true, Pins(f)); f.Create("second", Pins(f)); f.Cow(true, Pins(f)); }
        else Seed(f, true, true, 3);
        SetMarks(f, {{30, 0x80000}, {31, 0x100000}}); AddReferenceRecords(f);
        const auto proof = ObserveReferences(f); Check(proof.records.referenced_physical_union.blocks == 3 &&
            proof.marked_file_payload_union.blocks == (history ? 3 : 4), "exported nonzero proof");
        std::ofstream file(path, std::ios::binary); file.write(reinterpret_cast<const char*>(f.image.data()), static_cast<std::streamsize>(f.image.size()));
        Check(static_cast<bool>(file), "bounded canonical marked-reference image export");
        std::cout << "EXPORT xid=" << f.scope.exact.checkpoint_xid << " views=" << proof.records.views.size()
            << " markedFileUnion=" << proof.marked_file_payload_union.blocks << '\n'; return 0;
    }
    Check(argc == 1, "known reference-test selector"); RunReferences(); ReferenceWireCases();
    std::cout << "PASS " << cases << " cases / " << checks << " checks; canonical marked namespace/reference subset\n"; return 0;
}
catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << " after " << checks << " checks\n"; return 1; }
#endif
