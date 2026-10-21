#include "ApfsVerifier.h"
#include "ApfsVerificationJson.h"
#include "ApfsExtendedRecordCodec.h"
#include "SnapshotTestFixture.h"

#include <functional>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

using namespace apfsaccess::catalog;
using namespace apfsaccess::rw;
using namespace apfsaccess::testfixture;
using Record = apfsaccess::catalog::BtreeRecord;
#ifdef APFS_PAYLOAD_PRIVATE_BASELINE
namespace apfsaccess::catalog {
VerificationReport VerifyLegacyBaseline(const RandomAccessSource&, const VerificationScope&);
}
#endif
namespace
{
unsigned cases = 0, checks = 0;
void Check(bool ok, const std::string& message) { ++checks; if (!ok) throw std::runtime_error(message); }
void Pass(const std::string& name) { ++cases; std::cout << "PASS " << name << '\n'; }
template<class T, class Encoder> Record Encode(const T& value, Encoder encoder)
{
    Record out; std::string error;
    Check(encoder(value, out, error), "fixture encode: " + error); return out;
}
Record Inode(std::uint64_t id, std::uint64_t size, unsigned links, bool directory, std::uint32_t bs)
{
    AppleInodeRecord inode;
    inode.object_id = inode.private_id = id; inode.parent_id = 2;
    inode.children_or_links = static_cast<std::int32_t>(links); inode.mode = directory ? 0040755 : 0100644;
    if (!directory)
    {
        inode.uncompressed_size = size;
        AppleExtendedField stream{8, 0, Bytes(40)};
        PutU64LE(stream.data, 0, size); PutU64LE(stream.data, 8, size ? bs : 0);
        inode.extended_fields.push_back(stream);
    }
    return Encode(inode, EncodeAppleInodeRecord);
}
Record Drec(std::uint64_t id, const std::string& name)
{
    AppleDirectoryRecord entry; entry.parent_id = 2; entry.file_id = id; entry.name_utf8 = name; entry.flags = 8;
    Record out; std::string error; Check(EncodeAppleDirectoryRecord(entry, out, error), "drec encode"); return out;
}
struct Fixture
{
    std::uint32_t bs;
    BuilderStore spec;
    Bytes image;
    VerificationScope scope;
    std::vector<Record> fs, refs;
    explicit Fixture(std::uint32_t block_size = 4096) : bs(block_size)
    {
        spec.block_size = bs; spec.block_count = 512; spec.xid = 20;
        spec.volumes[0].uuid_hex = std::string(32, 'b');
        spec.volumes[0].additional_file_system_allocated_blocks = 1;
        spec.authoritative_seeded_main_blocks.emplace_back(220, Bytes(bs, std::byte{0x42}));
        fs = {Inode(2, 0, 1, true, bs), Drec(30, "file.txt"), Inode(30, 8, 1, false, bs),
            Encode(AppleFileExtentRecord{30, 0, bs, 220, 0, bs}, EncodeAppleFileExtentRecord),
            Encode(AppleDataStreamIdRecord{30, 1}, EncodeAppleDataStreamIdRecord)};
        refs = {Encode(ApplePhysicalExtentRecord{220, 1, 1, 30, 1}, EncodeApplePhysicalExtentRecord)};
        scope.source_identity = "fixture-image-512";
        scope.exact = {0, std::uint64_t(bs) * 512, std::string(32, 'a'), std::string(32, 'b'), 101, 20};
        Rebuild();
    }
    void Rebuild()
    {
        auto sorted = fs; std::string error;
        Check(SortAppleBtreeRecords(sorted, AppleBtreeKeyOrder::FileSystemCaseSensitive, error), "fixture order: " + error);
        spec.volumes[0].filesystem_records = std::move(sorted); spec.volumes[0].extentref_records = refs;
        image = BuildAuthoritativeStoreImage(spec);
        Edit(2, [](auto& bytes) { PutU32LE(bytes, 0x20, 1); });
    }
    void Edit(std::uint64_t block, const std::function<void(Bytes&)>& mutate, bool checksum = true)
    {
        Bytes bytes(image.begin() + block * bs, image.begin() + (block + 1) * bs);
        mutate(bytes); if (checksum) FletcherForBlock(bytes, bs);
        std::copy(bytes.begin(), bytes.end(), image.begin() + block * bs);
    }
    void PutTree(std::uint64_t block, const std::vector<Record>& records,
        std::uint64_t oid, std::uint32_t type, std::uint32_t subtype)
    {
        std::vector<Bytes> keys, values;
        for (const auto& record : records) { keys.push_back(record.key); values.push_back(record.value); }
        const auto bytes = BuildRawLeafNode(keys, values, 20, bs, 0, oid, type, subtype);
        std::copy(bytes.begin(), bytes.end(), image.begin() + block * bs);
    }
    std::vector<std::uint64_t> Multilevel(bool hashed = false)
    {
        fs[0] = Inode(2, 0, 81, true, bs);
        for (unsigned i = 0; i < 80; ++i)
        {
            fs.push_back(Inode(100 + i, 0, 1, false, bs));
            fs.push_back(Drec(100 + i, "child-" + std::to_string(i)));
        }
        if (hashed)
        {
            spec.volumes[0].incompat = 9;
            const auto policy = ApfsNamePolicy::FromIncompatibleFeatures(9);
            for (auto& record : fs)
                if ((ReadU64LE(record.key, 0).value() >> 60) == 9)
                {
                    AppleDirectoryRecord d; d.parent_id = 2; d.file_id = ReadU64LE(record.value, 0).value(); d.flags = 8;
                    d.name_utf8.assign(reinterpret_cast<const char*>(record.key.data() + 10), record.key.size() - 11);
                    if (d.file_id == 30) d.name_utf8 = "Café.txt";
                    std::string error; Check(EncodeAppleDirectoryRecord(d, policy, record, error), error);
                }
        }
        AppleBtreeOptions options;
        options.block_size = bs; options.xid = 20; options.root_object_id = 0x2000 + 101;
        options.root_physical_block = 7; options.first_child_object_id = 0x7000;
        options.first_child_physical_block = 230; options.subtype = kObjectTypeFsTree;
        options.key_order = hashed ? AppleBtreeKeyOrder::FileSystemHashedDirectory : AppleBtreeKeyOrder::FileSystemCaseSensitive;
        AppleSerializedBtree tree; std::string error;
        Check(SerializeAppleBtree(fs, options, tree, error) && tree.height > 0, "multilevel fixture: " + error);
        std::vector<OmapRecordSpec> mappings{{0x2000 + 101, 7, 0, 20}, {0x3000 + 101, 9, 0, 20}};
        std::vector<std::uint64_t> children;
        for (const auto& object : tree.objects)
            if (object.location.physical_block != 7)
            {
                spec.authoritative_seeded_main_blocks.emplace_back(object.location.physical_block, object.bytes);
                mappings.push_back({object.location.object_id, object.location.physical_block, 0, 20});
                children.push_back(object.location.physical_block);
            }
        spec.volumes[0].additional_file_system_allocated_blocks += children.size();
        image = BuildAuthoritativeStoreImage(spec);
        Edit(2, [](auto& b) { PutU32LE(b, 0x20, 1); });
        for (const auto& object : tree.objects)
            std::copy(object.bytes.begin(), object.bytes.end(), image.begin() + object.location.physical_block * bs);
        const auto map = BuildBtreeNode(mappings, 20, bs, 0, 6, kObjectPhysical | kObjectTypeBtree, kObjectTypeOmap);
        std::copy(map.begin(), map.end(), image.begin() + 6 * bs);
        return children;
    }
};
class TracedSource final : public RandomAccessSource
{
public:
    const Bytes& image;
    std::uint64_t fail_at = 0;
    bool short_read = false;
    std::optional<std::uint64_t> fail_offset;
    bool throw_read = false;
    mutable std::vector<std::pair<std::uint64_t, std::size_t>> reads;
    explicit TracedSource(const Bytes& bytes) : image(bytes) {}
    std::uint64_t SizeBytes() const override { return image.size(); }
    bool Read(std::uint64_t offset, std::size_t size, Bytes& out) const override
    {
        out.clear(); reads.emplace_back(offset, size);
        if (fail_at == reads.size() || fail_offset == offset) {
            if (throw_read) throw std::runtime_error("fixture source exception");
            if (short_read) out.resize(1); return short_read;
        }
        if (offset > image.size() || size > image.size() - offset) return false;
        out.assign(image.begin() + offset, image.begin() + offset + size); return true;
    }
    bool Touched(std::uint64_t offset, std::uint64_t size) const
    {
        for (const auto& [at, count] : reads) if (at < offset + size && offset < at + count) return true;
        return false;
    }
};
std::string Detail(const VerificationReport& report)
{
    return report.findings.empty() ? "no findings" : report.findings.front().detail;
}
bool Has(const VerificationReport& report, VerificationCode code)
{
    return std::any_of(report.findings.begin(), report.findings.end(),
        [code](const auto& finding) { return finding.code == code; });
}
VerificationReport Verify(Fixture& fixture)
{
    const auto before = fixture.image;
    TracedSource source(fixture.image);
    auto report = ApfsVerifier::Verify(source, fixture.scope);
    Check(before == fixture.image, "input bytes unchanged");
    Check(!report.whole_volume_verified && !report.payload_content_hashes_verified, "no whole-volume or payload hash claim");
    Check(report.source_reads == source.reads.size(), "actual source read accounting");
    Check(report.repair.requested_identity == fixture.scope.exact, "repair binds exact requested identity");
    Check(report.repair.observed_identity == report.selected && report.repair.findings == report.findings,
        "repair binds observed identity and findings");
    return report;
}
void Reject(const std::string& name, const std::function<void(Fixture&)>& change, VerificationCode code)
{
    Fixture fixture; change(fixture);
    auto first = Verify(fixture); auto second = Verify(fixture);
    Check(first.outcome != VerificationOutcome::Complete && Has(first, code), name + ": " + Detail(first));
    Check(first.covered_filesystem_records == 0 && first.covered_physical_extents == 0, name + ": partial proof escaped");
    Check(first.findings == second.findings && first.coverage == second.coverage && first.repair == second.repair,
        name + ": nondeterministic findings or refusal");
    Pass(name);
}
void ProducerOmapRoles()
{
    for (const auto bs : {4096u, 8192u})
    {
        Fixture fixture(bs);
        fixture.spec.volumes.push_back(BuilderVolume{});
        fixture.spec.volumes.back().oid = 102;
        fixture.spec.volumes.back().uuid_hex = std::string(32, 'c');
        for (auto& volume : fixture.spec.volumes) volume.projectable = true;

        fixture.spec.authoritative_checkpoint = false;
        const auto legacy = BuildStoreImage(fixture.spec);
        Check(ReadU32LE(legacy, kOmapOid * bs + 0x20).value() == 1,
            "legacy producer must set mandatory container OMAP flag");
        for (const auto block : {kOmapOid, 32ull, 35ull})
        {
            Bytes map(legacy.begin() + block * bs, legacy.begin() + (block + 1) * bs);
            Check(VerifyObjectChecksum(map, bs), "legacy producer OMAP checksum");
            if (block != kOmapOid)
                Check(ReadU32LE(map, 0x20).value() == 0, "legacy volume OMAP flags remain zero");
        }
        Pass("legacy producer OMAP roles " + std::to_string(bs));

        fixture.spec.authoritative_checkpoint = true;
        // Rebuild directly: Fixture::Rebuild's historical flag patch must not
        // hide a missing mandatory bit in the shared producer.
        fixture.image = BuildStoreImage(fixture.spec);
        TracedSource source(fixture.image); std::string error;
        const auto checkpoint = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        Check(checkpoint.has_value(), "authoritative producer checkpoint: " + error);
        Check(checkpoint->container_object_map.flags == 1, "authoritative producer container OMAP flags");
        for (const auto& volume : checkpoint->volumes)
        {
            Check(volume.object_map.flags == 0, "authoritative producer volume OMAP flags");
            std::vector<AppleSnapshotRecord> inventory;
            Check(LoadAppleSnapshotRecords(source, *checkpoint, volume.superblock.object_id, inventory, error)
                && inventory.empty(), "unpatched producer strict empty inventory: " + error);
        }
        const auto report = Verify(fixture);
        Check(report.outcome == VerificationOutcome::Complete && report.findings.empty(),
            "unpatched producer strict covered-metadata verification: " + Detail(report));
        Pass("authoritative producer strict OMAP roles " + std::to_string(bs));
    }
    for (const auto flags : {0u, 2u, 3u, 4u, 8u, 16u, 0x80000001u})
        Reject("strict container OMAP flags " + std::to_string(flags), [flags](auto& f) {
            f.Edit(kOmapOid, [flags](auto& b) { PutU32LE(b, 0x20, flags); });
        }, VerificationCode::UnsupportedFeature);
    for (const auto flags : {1u, 2u, 0x80000000u})
        Reject("strict volume OMAP flags " + std::to_string(flags), [flags](auto& f) {
            f.Edit(5, [flags](auto& b) { PutU32LE(b, 0x20, flags); });
        }, VerificationCode::UnsupportedFeature);
    for (const auto offset : {0x48u, 0x50u})
        Reject("strict container OMAP pending revert " + std::to_string(offset), [offset](auto& f) {
            f.Edit(kOmapOid, [offset](auto& b) { PutU64LE(b, offset, 1); });
        }, VerificationCode::UnsupportedFeature);
    for (const auto flags : {0u, 1u, 0x80000001u})
    {
        auto original = BuildOmap(3, 20, 4096, 2, kObjectPhysical | kObjectTypeOmap,
            kObjectPhysical | kObjectTypeBtree);
        PutU32LE(original, 0x20, flags); FletcherForBlock(original, original.size());
        Bytes moved; std::string error;
        Check(PatchAppleObjectMap(original, 24, 21, 25, moved, error), "writer OMAP COW: " + error);
        Check(ReadU32LE(moved, 0x20).value() == flags && VerifyObjectChecksum(moved, moved.size()),
            "writer preserves input flags with valid checksum");
        bool preserved = true;
        for (std::size_t i = 24; i < original.size(); ++i)
            if ((i < 0x30 || i >= 0x38) && original[i] != moved[i]) preserved = false;
        Check(preserved, "writer preserves all fields except checksum, OID, XID and tree pointer");
        Pass("writer preserves OMAP flags " + std::to_string(flags));
    }
}
void Healthy()
{
    for (const auto bs : {4096u, 8192u})
    {
        Fixture fixture(bs); const auto report = Verify(fixture);
        Check(report.outcome == VerificationOutcome::Complete && report.findings.empty(), "healthy exact: " + Detail(report));
        Check(report.selected && report.selected->exact == fixture.scope.exact &&
            report.selected->checkpoint_physical_block == 12 && report.selected->volume_superblock_physical_block == 4 &&
            report.selected->root_physical_block == 7 && report.covered_filesystem_records == fixture.fs.size() &&
            report.covered_physical_extents == 1, "exact observed roots and covered graph");
        Check(report.repair.refusal == ApfsRepairRefusal::NoIndependentReconstructionEvidence, "concrete no-truth refusal");
        const auto repeated = Verify(fixture);
        Check(report.findings == repeated.findings && report.coverage == repeated.coverage && report.repair == repeated.repair,
            "deterministic healthy refusal");
        TracedSource source(fixture.image); (void)ApfsVerifier::Verify(source, fixture.scope);
        Check(!source.Touched(220ull * bs, bs), "payload contents never read or hashed");
        Pass("healthy exact " + std::to_string(bs));
    }
    { Fixture fixture; fixture.image.insert(fixture.image.begin(), 8192, std::byte{0xEE}); fixture.scope.exact.store_offset_bytes = 8192;
      const auto report = Verify(fixture); Check(report.outcome == VerificationOutcome::Complete, "offset: " + Detail(report));
      Check(report.selected->root_physical_block == 7, "observed locations stay store relative"); Pass("nonzero exact store window"); }
    { Fixture fixture; auto report = Verify(fixture); const auto first = report.repair.plan_id;
      fixture.scope.source_identity = "different-held-file"; report = Verify(fixture);
      Check(first != report.repair.plan_id, "source identity changes refusal binding"); Pass("source identity refusal binding"); }
    { Fixture fixture; const auto children = fixture.Multilevel(); TracedSource source(fixture.image);
      const auto report = ApfsVerifier::Verify(source, fixture.scope);
      Check(report.outcome == VerificationOutcome::Complete && report.covered_filesystem_records == fixture.fs.size(),
          "multilevel verifier: " + Detail(report));
      for (const auto block : children) Check(source.Touched(block * fixture.bs, fixture.bs), "every virtual child actually read");
      Check(!source.Touched(220ull * fixture.bs, fixture.bs), "multilevel walk still excludes payload bytes");
      Pass("complete multilevel virtual object graph walk"); }
    { Fixture fixture; fixture.spec.volumes.push_back(BuilderVolume{});
      fixture.spec.volumes[1].oid = 102; fixture.spec.volumes[1].uuid_hex = std::string(32, 'c'); fixture.Rebuild();
      fixture.scope.exact.volume_oid = 102; fixture.scope.exact.volume_uuid_hex = std::string(32, 'c');
      const auto report = Verify(fixture);
      Check(report.outcome == VerificationOutcome::Complete && report.selected->volume_superblock_physical_block == 5 &&
          report.covered_filesystem_records == 1, "exact sibling volume selection: " + Detail(report));
      Pass("exact second volume in shared single-store container"); }
    { Fixture fixture; fixture.spec.volumes[0].role = 0x0180; fixture.Rebuild();
      const auto report = Verify(fixture);
      Check(report.outcome != VerificationOutcome::Complete && Has(report, VerificationCode::UnsupportedFeature),
          "backup role must refuse ordinary verification: " + Detail(report));
      Check(report.covered_filesystem_records == 0 && report.covered_physical_extents == 0,
          "backup refusal publishes no partial proof");
      Pass("backup role refuses ordinary verification with typed reason"); }
}
void Corruptions()
{
    Reject("wrong container UUID", [](auto& f) { f.scope.exact.container_uuid_hex = std::string(32, 'c'); }, VerificationCode::IdentityMismatch);
    Reject("wrong volume UUID", [](auto& f) { f.scope.exact.volume_uuid_hex = std::string(32, 'c'); }, VerificationCode::IdentityMismatch);
    Reject("wrong volume OID", [](auto& f) { f.scope.exact.volume_oid = 102; }, VerificationCode::IdentityMismatch);
    Reject("missing exact XID never falls back", [](auto& f) { f.scope.exact.checkpoint_xid = 19; }, VerificationCode::CheckpointUnavailable);
    Reject("invalid zero XID", [](auto& f) { f.scope.exact.checkpoint_xid = 0; }, VerificationCode::InvalidScope);
    Reject("selected APSB checksum", [](auto& f) { f.Edit(4, [](auto& b) { b[0] ^= std::byte{1}; }, false); }, VerificationCode::ChecksumMismatch);
    Reject("FS checksum", [](auto& f) { f.Edit(7, [](auto& b) { b[0] ^= std::byte{1}; }, false); }, VerificationCode::ChecksumMismatch);
    Reject("dangling namespace entry", [](auto& f) { f.fs[1] = Drec(31, "file.txt"); f.Rebuild(); }, VerificationCode::NamespaceOrLinkInconsistent);
    Reject("inode link count mismatch", [](auto& f) { f.fs[2] = Inode(30, 8, 2, false, f.bs); f.Rebuild(); }, VerificationCode::NamespaceOrLinkInconsistent);
    Reject("directory child count mismatch", [](auto& f) { f.fs[0] = Inode(2, 0, 2, true, f.bs); f.Rebuild(); }, VerificationCode::NamespaceOrLinkInconsistent);
    Reject("physical reference count mismatch", [](auto& f) {
        f.refs[0] = Encode(ApplePhysicalExtentRecord{220, 1, 1, 30, 2}, EncodeApplePhysicalExtentRecord); f.Rebuild();
    }, VerificationCode::ExtentReferenceInconsistent);
    Reject("logical extent overlap", [](auto& f) {
        f.fs[3] = Encode(AppleFileExtentRecord{30, 0, 8192, 220, 0, f.bs}, EncodeAppleFileExtentRecord);
        f.fs.push_back(Encode(AppleFileExtentRecord{30, 4096, 4096, 221, 0, f.bs}, EncodeAppleFileExtentRecord)); f.Rebuild();
    }, VerificationCode::ExtentReferenceInconsistent);
    Reject("payload overlaps current FS metadata", [](auto& f) {
        f.fs[3] = Encode(AppleFileExtentRecord{30, 0, f.bs, 7, 0, f.bs}, EncodeAppleFileExtentRecord);
        f.refs[0] = Encode(ApplePhysicalExtentRecord{7, 1, 1, 30, 1}, EncodeApplePhysicalExtentRecord); f.Rebuild();
    }, VerificationCode::PayloadMetadataOverlap);
    Reject("payload references unallocated blocks", [](auto& f) {
        f.spec.authoritative_seeded_main_blocks.clear(); f.Rebuild();
    }, VerificationCode::PayloadAllocationInconsistent);
    Reject("spaceman bitmap free counter mismatch", [](auto& f) {
        VectorRandomAccessSource source(f.image); std::string error;
        const auto checkpoint = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error, 20);
        Check(checkpoint.has_value(), error);
        f.Edit(checkpoint->spaceman.chunks[0].bitmap_block, [](auto& b) { b[30] ^= std::byte{1}; }, false);
    }, VerificationCode::SpacemanInconsistent);
    Reject("late allocated quota overrun", [](auto& f) { f.spec.volumes[0].quota_block_count = 1; f.Rebuild(); }, VerificationCode::QuotaOrReserveInconsistent);
    Reject("reserve exceeds quota", [](auto& f) { f.spec.volumes[0].quota_block_count = 8; f.spec.volumes[0].reserve_block_count = 9; f.Rebuild(); }, VerificationCode::QuotaOrReserveInconsistent);
    Reject("leaf order cannot be sorted clean", [](auto& f) {
        auto records = f.spec.volumes[0].filesystem_records; std::swap(records[0], records[1]);
        f.PutTree(7, records, 0x2000 + 101, kObjectTypeBtree, kObjectTypeFsTree);
    }, VerificationCode::TreeOrderInconsistent);
    Reject("malformed OMAP duplicate key", [](auto& f) {
        const auto block = BuildBtreeNode({OmapRecordSpec{0x2000 + 101, 7, 0, 20},
            OmapRecordSpec{0x2000 + 101, 7, 0, 20}, OmapRecordSpec{0x3000 + 101, 9, 0, 20}},
            20, f.bs, 0, 6, kObjectPhysical | kObjectTypeBtree, kObjectTypeOmap);
        std::copy(block.begin(), block.end(), f.image.begin() + 6 * f.bs);
    }, VerificationCode::StructuralInconsistency);
    Reject("root header newer than OMAP mapping", [](auto& f) {
        const auto block = BuildBtreeNode({OmapRecordSpec{0x2000 + 101, 7, 0, 19},
            OmapRecordSpec{0x3000 + 101, 9, 0, 20}}, 20, f.bs, 0, 6, kObjectPhysical | kObjectTypeBtree, kObjectTypeOmap);
        std::copy(block.begin(), block.end(), f.image.begin() + 6 * f.bs);
    }, VerificationCode::StructuralInconsistency);
    Reject("APSB header newer than container OMAP mapping", [](auto& f) {
        const auto block = BuildBtreeNode({OmapRecordSpec{101, 4, 0, 19}}, 20, f.bs, 0, 3,
            kObjectPhysical | kObjectTypeBtree, kObjectTypeOmap);
        std::copy(block.begin(), block.end(), f.image.begin() + 3 * f.bs);
    }, VerificationCode::StructuralInconsistency);
    Reject("FS graph cycle", [](auto& f) {
        Record child{f.fs[0].key, Bytes(8)}; PutU64LE(child.value, 0, 0x2000 + 101);
        f.PutTree(7, {child}, 0x2000 + 101, kObjectTypeBtree, kObjectTypeFsTree);
        f.Edit(7, [](auto& b) { PutU16LE(b, 0x20, 1); PutU16LE(b, 0x22, 1); });
    }, VerificationCode::StructuralInconsistency);
    Reject("multilevel child checksum", [](auto& f) {
        const auto children = f.Multilevel();
        f.Edit(children.back(), [](auto& b) { b[0] ^= std::byte{1}; }, false);
    }, VerificationCode::ChecksumMismatch);
    Reject("physical extent reference overlap", [](auto& f) {
        f.refs[0] = Encode(ApplePhysicalExtentRecord{220, 2, 1, 30, 1}, EncodeApplePhysicalExtentRecord);
        f.refs.push_back(Encode(ApplePhysicalExtentRecord{221, 1, 1, 30, 1}, EncodeApplePhysicalExtentRecord)); f.Rebuild();
    }, VerificationCode::ExtentReferenceInconsistent);
}
void Unsupported()
{
    Reject("encrypted volume refused", [](auto& f) { f.spec.volumes[0].fs_flags = 0; f.Rebuild(); }, VerificationCode::CryptoUnsupported);
    Reject("unknown volume feature", [](auto& f) { f.spec.volumes[0].features |= 1ull << 63; f.Rebuild(); }, VerificationCode::UnsupportedFeature);
    Reject("Fusion NX feature", [](auto& f) { f.Edit(12, [](auto& b) { PutU64LE(b, 0x40, 0x100); }); }, VerificationCode::FusionUnsupported);
    Reject("snapshot metadata root unavailable", [](auto& f) { f.Edit(4, [](auto& b) { PutU64LE(b, 0x98, 0); }); }, VerificationCode::SnapshotCoverageUnavailable);
    Reject("unknown extended snapshot metadata", [](auto& f) { f.Edit(4, [](auto& b) { PutU64LE(b, 0x3E8, 190); }); }, VerificationCode::UnsupportedFeature);
    Reject("unknown FS tree flags", [](auto& f) { f.Edit(7, [](auto& b) { PutU32LE(b, b.size() - 40, 0x80000000); }); }, VerificationCode::UnsupportedFeature);
    Reject("unknown inode extended metadata", [](auto& f) {
        AppleInodeRecord inode; std::string error; Check(ApfsExtendedRecordCodec::DecodeInode(f.fs[2], inode, error), error);
        inode.extended_fields.push_back({42, 0, Bytes(8)}); f.fs[2] = Encode(inode, EncodeAppleInodeRecord); f.Rebuild();
    }, VerificationCode::UnsupportedFeature);
    Reject("unknown inode flags", [](auto& f) {
        AppleInodeRecord inode; std::string error; Check(ApfsExtendedRecordCodec::DecodeInode(f.fs[2], inode, error), error);
        inode.internal_flags |= 1ull << 63; f.fs[2] = Encode(inode, EncodeAppleInodeRecord); f.Rebuild();
    }, VerificationCode::UnsupportedFeature);
    Reject("unknown directory extended metadata", [](auto& f) {
        f.fs[1].value.push_back(std::byte{1}); f.Rebuild();
    }, VerificationCode::UnsupportedFeature);
    Reject("unknown filesystem record", [](auto& f) {
        Record unknown{Bytes(8), Bytes(8)}; PutU64LE(unknown.key, 0, (7ull << 60) | 30);
        f.fs.push_back(unknown); f.Rebuild();
    }, VerificationCode::UnsupportedFeature);
    Reject("encrypted extent unsupported", [](auto& f) {
        f.fs[3] = Encode(AppleFileExtentRecord{30, 0, f.bs, 220, 9, f.bs}, EncodeAppleFileExtentRecord); f.Rebuild();
    }, VerificationCode::CryptoUnsupported);
    Reject("spaceman second physical store unsupported", [](auto& f) {
        f.Edit(19, [](auto& b) { PutU64LE(b, 0x60, 100); });
    }, VerificationCode::FusionUnsupported);
    Reject("whole volume request cannot pass subset", [](auto& f) { f.scope.require_whole_volume = true; }, VerificationCode::CoverageMissing);
    Reject("unread payload hashes cannot pass", [](auto& f) { f.scope.require_payload_content_hashes = true; }, VerificationCode::CoverageMissing);
    { SnapshotFixture fixture; const auto before = fixture.image;
      VerificationScope scope; scope.source_identity = "snapshot-fixture"; scope.exact = fixture.scope;
      TracedSource source(fixture.image); const auto report = ApfsVerifier::Verify(source, scope);
      Check(report.outcome == VerificationOutcome::Incomplete && Has(report, VerificationCode::MetadataAllocationInconsistent),
          "nonempty snapshot: " + Detail(report));
      Check(before == fixture.image && report.selected && report.covered_filesystem_records == 0, "snapshot refusal preserves input and exact binding");
      Pass("snapshot fixture unallocated historical metadata detected"); }
}
std::pair<std::size_t, std::size_t> KeyRegion(const Bytes& bytes, unsigned index)
{
    const bool fixed = (ReadU16LE(bytes, 0x20).value() & 4) != 0;
    const auto table = 0x38 + ReadU16LE(bytes, 0x28).value();
    const auto entry = table + index * (fixed ? 4 : 8);
    const auto start = table + ReadU16LE(bytes, 0x2A).value() + ReadU16LE(bytes, entry).value();
    const auto length = fixed ? ReadU32LE(bytes, bytes.size() - 32).value() : ReadU16LE(bytes, entry + 2).value();
    return {start, length};
}
void ClearMainAllocation(Fixture& f, std::uint64_t block)
{
    VectorRandomAccessSource source(f.image); std::string error;
    const auto cp = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error, 20);
    Check(cp.has_value(), "metadata corruption setup: " + error);
    const auto& chunk = cp->spaceman.chunks[0];
    f.Edit(chunk.bitmap_block, [&](auto& b) { b[block / 8] &= ~std::byte(1u << (block % 8)); }, false);
    f.Edit(cp->spaceman.devices[0].cibs[0].object.physical_block,
        [&](auto& b) { PutU32LE(b, 0x3C, chunk.free_count + 1); });
    f.Edit(cp->spaceman.object.physical_block,
        [&](auto& b) { PutU64LE(b, 0x48, cp->spaceman.devices[0].free_count + 1); });
}
void AddSiblingPayload(Fixture& f, std::uint64_t block)
{
    BuilderVolume sibling; sibling.oid = 102; sibling.uuid_hex = std::string(32, 'c');
    sibling.additional_file_system_allocated_blocks = 1;
    sibling.filesystem_records = f.spec.volumes[0].filesystem_records;
    for (auto& record : sibling.filesystem_records)
        if ((ReadU64LE(record.key, 0).value() >> 60) == 8)
            record = Encode(AppleFileExtentRecord{30, 0, f.bs, block, 0, f.bs}, EncodeAppleFileExtentRecord);
    sibling.extentref_records = {Encode(ApplePhysicalExtentRecord{block, 1, 1, 30, 1}, EncodeApplePhysicalExtentRecord)};
    f.spec.volumes.push_back(sibling);
    if (block != 220) f.spec.authoritative_seeded_main_blocks.emplace_back(block, Bytes(f.bs, std::byte{0x43}));
    f.Rebuild();
}
void QueueMainBlock(Fixture& f, std::uint64_t block)
{
    VectorRandomAccessSource source(f.image); std::string error;
    const auto cp = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error, 20);
    Check(cp.has_value(), error);
    const auto& queue = cp->spaceman.free_queues[1];
    Record record{Bytes(16), {}}; PutU64LE(record.key, 0, 20); PutU64LE(record.key, 8, block);
    AppleBtreeOptions options; options.block_size = f.bs; options.xid = 20;
    options.root_object_id = queue.tree_oid; options.root_physical_block = queue.root.physical_block;
    options.storage_type = kObjectEphemeral; options.subtype = kObjectTypeSpacemanFreeQueue;
    options.key_order = AppleBtreeKeyOrder::SpacemanFreeQueue;
    options.fixed_key_size = 16; options.fixed_value_size = 8;
    options.tree_flags = kAppleBtreeEphemeral | kAppleBtreeSequentialInsert | kAppleBtreeAllowGhosts;
    options.minimum_longest_key = 16; options.minimum_longest_value = 8;
    AppleSerializedBtree tree;
    Check(SerializeAppleBtree({record}, options, tree, error), "queue fixture: " + error);
    for (const auto& object : tree.objects)
        std::copy(object.bytes.begin(), object.bytes.end(), f.image.begin() + object.location.physical_block * f.bs);
    f.Edit(cp->spaceman.object.physical_block, [](auto& b) { PutU64LE(b, 0xF0, 1); PutU64LE(b, 0x100, 20); });
}
void CurrentMetadataIncrement()
{
    { Fixture f; f.Multilevel(true); const auto report = Verify(f);
      Check(report.outcome == VerificationOutcome::Complete, "hashed multilevel: " + Detail(report));
      Pass("hashed Unicode multilevel routing uses exact FS comparator"); }
    Reject("hashed separator hash cannot misroute intact leaves", [](auto& f) {
        f.Multilevel(true); f.Edit(7, [](auto& b) {
            bool changed = false;
            for (unsigned i = 0; i < ReadU32LE(b, 0x24).value(); ++i)
            {
                const auto [at, n] = KeyRegion(b, i); (void)n;
                if ((ReadU64LE(b, at).value() >> 60) == 9)
                { b[at + 11] ^= std::byte{0x40}; changed = true; break; }
            }
            Check(changed, "hashed separator exists");
        });
    }, VerificationCode::TreeOrderInconsistent);
    Reject("parent minimum below child leaves cannot hide wrong routing", [](auto& f) {
        f.Multilevel(); f.Edit(7, [](auto& b) { const auto [at, length] = KeyRegion(b, 0); (void)length;
            PutU64LE(b, at, (3ull << 60) | 1); });
    }, VerificationCode::TreeOrderInconsistent);
    Reject("parent minimum above child leaves", [](auto& f) {
        f.Multilevel(); f.Edit(7, [](auto& b) { const auto [at, length] = KeyRegion(b, 0); (void)length;
            PutU64LE(b, at, (3ull << 60) | 3); });
    }, VerificationCode::TreeOrderInconsistent);
    Reject("internal separator duplicate despite sorted leaves", [](auto& f) {
        f.Multilevel(); f.Edit(7, [](auto& b) { const auto [first, n] = KeyRegion(b, 0); const auto [second, m] = KeyRegion(b, 1);
            Check(n <= m, "separator fixture key widths"); std::copy_n(b.begin() + first, n, b.begin() + second);
            const auto table = 0x38 + ReadU16LE(b, 0x28).value(); PutU16LE(b, table + 8 + 2, static_cast<std::uint16_t>(n)); });
    }, VerificationCode::TreeOrderInconsistent);
    Reject("malformed internal FS key never treated as equal", [](auto& f) {
        f.Multilevel(); f.Edit(7, [](auto& b) { const auto [at, length] = KeyRegion(b, 0); (void)length; PutU64LE(b, at, 0); });
    }, VerificationCode::StructuralInconsistency);
    for (const auto block : {0ull, 2ull, 3ull, 4ull, 5ull, 6ull, 7ull, 8ull, 9ull, 11ull, 12ull, 19ull, 20ull, 21ull})
        Reject("current metadata bit clear with matching counters block " + std::to_string(block),
            [block](auto& f) { ClearMainAllocation(f, block); }, VerificationCode::MetadataAllocationInconsistent);
    Reject("unallocated multilevel FS child", [](auto& f) { const auto children = f.Multilevel(); ClearMainAllocation(f, children.back()); },
        VerificationCode::MetadataAllocationInconsistent);
    Reject("overlapping payload owners across volumes", [](auto& f) { AddSiblingPayload(f, 220); }, VerificationCode::CrossVolumePayloadOverlap);
    Reject("sibling payload allocation is checked", [](auto& f) { AddSiblingPayload(f, 221); ClearMainAllocation(f, 221); },
        VerificationCode::PayloadAllocationInconsistent);
    Reject("sibling namespace must validate", [](auto& f) { AddSiblingPayload(f, 221);
        for (auto& record : f.spec.volumes[1].filesystem_records)
            if (ReadU64LE(record.key, 0).value() == ((9ull << 60) | 2)) PutU64LE(record.value, 0, 999);
        f.Rebuild(); }, VerificationCode::NamespaceOrLinkInconsistent);
    Reject("current metadata in singleton deferred free queue", [](auto& f) { QueueMainBlock(f, 7); }, VerificationCode::MetadataAllocationInconsistent);
    Reject("payload in singleton deferred free queue", [](auto& f) { QueueMainBlock(f, 220); }, VerificationCode::PayloadAllocationInconsistent);
    { Fixture f; AddSiblingPayload(f, 221); const auto report = Verify(f);
      Check(report.outcome == VerificationOutcome::Complete, "adjacent cross-volume ranges: " + Detail(report));
      for (const auto check : {VerificationCheck::InternalSeparatorRouting, VerificationCheck::MetadataAllocatorOwnership,
            VerificationCheck::CrossVolumePayloadOwnership})
          Check(std::any_of(report.coverage.begin(), report.coverage.end(), [check](const auto& c) {
              return c.check == check && c.implemented && c.required && c.state == VerificationCheckState::Verified;
          }), "new proof coverage published");
      Pass("adjacent payload ranges and explicit new coverage"); }
    { Fixture f; f.spec.authoritative_seeded_main_blocks.emplace_back(221, Bytes(f.bs, std::byte{0x42})); f.Rebuild(); QueueMainBlock(f, 221);
      const auto report = Verify(f); Check(report.outcome == VerificationOutcome::Complete, "valid singleton queue: " + Detail(report));
      Pass("authoritative ghost singleton free queue supported"); }
    { Fixture f; f.spec.authoritative_seeded_main_blocks.emplace_back(221, Bytes(f.bs, std::byte{0x42})); f.Rebuild();
      const auto report = Verify(f); Check(report.outcome == VerificationOutcome::Complete, "unreferenced allocation subset");
      Check(std::any_of(report.coverage.begin(), report.coverage.end(), [](const auto& c) {
          return c.check == VerificationCheck::CompleteAllocationAccounting && !c.implemented && c.state == VerificationCheckState::Unproven;
      }), "unreferenced allocations never certified or offered for reclaim");
      Check(report.repair.refusal == ApfsRepairRefusal::NoIndependentReconstructionEvidence, "no invented orphan repair");
      Pass("unreferenced allocation remains explicitly unproven"); }
}

void BudgetsAndFailures()
{
    Reject("bounded source reads", [](auto& f) { f.scope.max_reads = 1; }, VerificationCode::BudgetExceeded);
    Reject("bounded source bytes", [](auto& f) { f.scope.max_read_bytes = 4096; }, VerificationCode::BudgetExceeded);
    Reject("bounded materialized records", [](auto& f) { f.scope.max_records = 1; }, VerificationCode::BudgetExceeded);
    Reject("bounded record bytes", [](auto& f) { f.scope.max_record_bytes = 128; }, VerificationCode::BudgetExceeded);
    { Fixture f; TracedSource source(f.image); auto budget = std::make_shared<ApfsReadBudget>(1, 4096, 1000000, 1ull << 28);
      BudgetedRandomAccessSource inherited(source, budget); auto report = ApfsVerifier::Verify(inherited, f.scope);
      Check(Has(report, VerificationCode::BudgetExceeded) && source.reads.size() == 1 && budget->Failed(), "preserve stricter caller allowance");
      const auto calls = source.reads.size(); report = ApfsVerifier::Verify(inherited, f.scope);
      Check(Has(report, VerificationCode::BudgetExceeded) && calls == source.reads.size(), "sticky caller budget never reset");
      Pass("inherited stricter sticky budget"); }
    { Fixture f; TracedSource source(f.image); auto budget = std::make_shared<ApfsReadBudget>(1000000, 1ull << 30, 1000000, 1ull << 30);
      BudgetedRandomAccessSource inherited(source, budget); f.scope.max_reads = 2;
      auto report = ApfsVerifier::Verify(inherited, f.scope);
      Check(Has(report, VerificationCode::BudgetExceeded) && source.reads.size() == 2, "scope tightens caller read budget"); Pass("scope constrains broader caller budget"); }
    { Fixture f; TracedSource source(f.image); auto budget = std::make_shared<ApfsReadBudget>(1000000, 1ull << 30, 1000000, 1ull << 30);
      BudgetedRandomAccessSource inherited(source, budget); f.scope.max_records = 1;
      const auto report = ApfsVerifier::Verify(inherited, f.scope);
      Check(Has(report, VerificationCode::BudgetExceeded) && budget->Failed(), "scope tightens inherited materialization allowance");
      Pass("scope constrains inherited record budget"); }
    Fixture f; TracedSource control(f.image); const auto healthy = ApfsVerifier::Verify(control, f.scope);
    Check(healthy.outcome == VerificationOutcome::Complete, "late failure control");
    for (const auto fail_at : {1ull, std::uint64_t(control.reads.size())})
        for (const auto short_read : {false, true})
        {
            TracedSource source(f.image); source.fail_at = fail_at; source.short_read = short_read;
            auto report = healthy; report = ApfsVerifier::Verify(source, f.scope);
            Check(report.outcome == VerificationOutcome::Incomplete && Has(report, VerificationCode::ReadFailure), "I/O class: " + Detail(report));
            Check(report.covered_filesystem_records == 0 && report.covered_physical_extents == 0 &&
                report.repair.refusal == ApfsRepairRefusal::VerificationNotComplete && report.repair.plan_id != healthy.repair.plan_id,
                "late failure clears completed output and repair binding");
            Check(source.reads.size() == fail_at, "no retry after source failure");
            Check(report.findings[0].failed_source_offset_bytes == source.reads.back().first,
                "exact I/O failure byte offset recorded");
            Pass(std::string(short_read ? "short read " : "I/O failure ") + std::to_string(fail_at));
        }
}

void MetadataDeadlines()
{
    Fixture f;
    const auto original = f.image;
    TracedSource control(f.image);
    const auto ordinary = ApfsVerifier::Verify(control, f.scope);
    Check(ordinary.outcome == VerificationOutcome::Complete, "metadata deadline healthy control");
    TracedSource expired_source(f.image);
    const auto expired = ApfsVerifier::Verify(expired_source, f.scope, [] { return false; });
    Check(expired.outcome == VerificationOutcome::Incomplete && Has(expired, VerificationCode::BudgetExceeded) &&
        expired.read_budget && expired.read_budget->Failed() && expired_source.reads.empty(),
        "metadata deadline refuses before any backing read");
    Check(!expired.allocation_census && expired.covered_filesystem_records == 0 && expired.covered_physical_extents == 0,
        "expired metadata verification cannot publish completed observations");
    Pass("metadata verification honors an already expired deadline");

    TracedSource bounded_source(f.image);
    unsigned calls = 0;
    std::size_t stopped_at = 0;
    const auto stopped = ApfsVerifier::Verify(bounded_source, f.scope, [&] {
        if (++calls < 8) return true;
        stopped_at = bounded_source.reads.size(); return false;
    });
    Check(Has(stopped, VerificationCode::BudgetExceeded) && stopped.outcome == VerificationOutcome::Incomplete &&
        stopped_at > 0 && stopped_at == bounded_source.reads.size() && stopped_at < control.reads.size(),
        "metadata cancellation stops subsequent source I/O");
    Check(!stopped.allocation_census && stopped.covered_filesystem_records == 0, "partial metadata proof stays incomplete");
    Pass("metadata walk cancellation is sticky and stops I/O");

    TracedSource callback_source(f.image);
    const auto callback_failure = ApfsVerifier::Verify(callback_source, f.scope, []() -> bool {
        throw std::runtime_error("private callback failure");
    });
    Check(Has(callback_failure, VerificationCode::BudgetExceeded) && callback_source.reads.empty() &&
        callback_failure.read_budget && std::string(callback_failure.read_budget->Failure()) == "VerifierDeadlineCallbackFailed",
        "metadata callback failure returns typed incomplete proof without escaping");
    Pass("metadata deadline callback exceptions fail closed");

    TracedSource completed_source(f.image);
    unsigned completed_calls = 0;
    const auto completed = ApfsVerifier::Verify(completed_source, f.scope, [&] { ++completed_calls; return true; });
    Check(completed.outcome == VerificationOutcome::Complete && completed_calls > completed_source.reads.size() &&
        completed.findings == ordinary.findings && completed.coverage == ordinary.coverage &&
        completed.selected == ordinary.selected && completed.allocation_census == ordinary.allocation_census &&
        completed.source_reads == ordinary.source_reads && completed.source_read_bytes == ordinary.source_read_bytes,
        "nonexpired metadata verification preserves proof, coverage and I/O allowance");
    Pass("nonexpired metadata verification retains the ordinary contract");

    TracedSource late_source(f.image);
    calls = 0;
    const auto late = ApfsVerifier::Verify(late_source, f.scope, [&] { return ++calls < completed_calls; });
    Check(late.outcome == VerificationOutcome::Incomplete && Has(late, VerificationCode::BudgetExceeded) &&
        !late.allocation_census && late.covered_filesystem_records == 0 && late.covered_physical_extents == 0 &&
        late_source.reads == completed_source.reads, "late CPU-only deadline clears terminal metadata success without more I/O");
    Pass("late metadata deadline cannot publish completed census");

    TracedSource census_source(f.image);
    calls = 0;
    const auto census_expired = ApfsVerifier::Verify(census_source, f.scope, [&] { return ++calls < completed_calls - 1; });
    Check(census_expired.outcome == VerificationOutcome::Incomplete && Has(census_expired, VerificationCode::BudgetExceeded) &&
        census_expired.findings.front().check == VerificationCheck::CurrentOwnershipCensus &&
        census_source.reads == completed_source.reads && !census_expired.allocation_census,
        "allocation census observes the deadline after all backing reads have completed");
    Pass("allocation census has a cooperative CPU-only deadline");

    TracedSource shared_source(f.image);
    auto shared_budget = std::make_shared<ApfsReadBudget>(f.scope.max_reads, f.scope.max_read_bytes,
        f.scope.max_records, f.scope.max_record_bytes);
    BudgetedRandomAccessSource shared(shared_source, shared_budget);
    calls = 0;
    const auto poisoned = ApfsVerifier::Verify(shared, f.scope, [&] {
        if (++calls == completed_calls) shared_budget->Refuse("PrivateDeadlineCallbackPoisonedBudget");
        return true;
    });
    Check(poisoned.outcome == VerificationOutcome::Incomplete && Has(poisoned, VerificationCode::BudgetExceeded) &&
        shared_budget->Failed() && std::string(shared_budget->Failure()) == "PrivateDeadlineCallbackPoisonedBudget" &&
        !poisoned.allocation_census && poisoned.covered_filesystem_records == 0 && poisoned.covered_physical_extents == 0,
        "shared callback poisoning must prevent terminal completion");
    const auto stopped_reads = shared_source.reads.size();
    calls = 0;
    const auto retry = ApfsVerifier::Verify(shared, f.scope, [&] { ++calls; return true; });
    Check(retry.outcome == VerificationOutcome::Incomplete && shared_source.reads.size() == stopped_reads && calls == 0 &&
        std::string(shared_budget->Failure()) == "PrivateDeadlineCallbackPoisonedBudget",
        "callback cannot revive an exhausted inherited budget on retry");
    Check(f.image == original, "all metadata deadline cases preserve the exact image");
    Pass("callback-induced shared budget failure stays authoritative");
}

Bytes Ascii(std::string_view text)
{
    const auto* bytes = reinterpret_cast<const std::byte*>(text.data());
    return {bytes, bytes + text.size()};
}

Fixture PayloadFixture()
{
    Fixture f;
    f.fs[0] = Inode(2, 0, 6, true, f.bs);
    f.fs[2] = Inode(30, 3, 2, false, f.bs);
    for (const auto& [name, id] : {std::pair{"file.txt", 1010ull}, std::pair{"alias.txt", 1011ull}})
    {
        AppleDirectoryRecord entry;
        entry.parent_id = 2; entry.file_id = 30; entry.name_utf8 = name; entry.flags = 8;
        AppleExtendedField sibling{1, 0, Bytes(8)}; PutU64LE(sibling.data, 0, id);
        entry.extended_fields.push_back(std::move(sibling));
        Record record; std::string error;
        Check(EncodeAppleDirectoryRecord(entry, record, error), "payload sibling directory entry: " + error);
        if (id == 1010) f.fs[1] = std::move(record);
        else f.fs.push_back(std::move(record));
        f.fs.push_back(Encode(AppleSiblingLinkRecord{30, id, 2, name}, EncodeAppleSiblingLinkRecord));
        f.fs.push_back(Encode(AppleSiblingMapRecord{id, 30}, EncodeAppleSiblingMapRecord));
    }
    f.fs.push_back(Inode(40, 0, 1, false, f.bs)); f.fs.push_back(Drec(40, "empty.txt"));
    AppleInodeRecord sparse; std::string error;
    Check(ApfsExtendedRecordCodec::DecodeInode(Inode(50, f.bs + 3, 1, false, f.bs), sparse, error), error);
    sparse.internal_flags |= kAppleInodeSparseFlag;
    AppleExtendedField holes{13, 0, Bytes(8)}; PutU64LE(holes.data, 0, f.bs); sparse.extended_fields.push_back(holes);
    f.fs.push_back(Encode(sparse, EncodeAppleInodeRecord)); f.fs.push_back(Drec(50, "sparse.txt"));
    f.fs.push_back(Encode(AppleFileExtentRecord{50, 0, f.bs, 0, 0, f.bs}, EncodeAppleFileExtentRecord));
    f.fs.push_back(Encode(AppleFileExtentRecord{50, f.bs, f.bs, 221, 0, f.bs}, EncodeAppleFileExtentRecord));
    f.fs.push_back(Encode(AppleDataStreamIdRecord{50, 1}, EncodeAppleDataStreamIdRecord));
    AppleInodeRecord symlink; symlink.object_id = symlink.private_id = 60; symlink.parent_id = 2;
    symlink.children_or_links = 1; symlink.mode = 0120777;
    symlink.internal_flags = kAppleInodeHasUncompressedSize; symlink.uncompressed_size = 8;
    f.fs.push_back(Encode(symlink, EncodeAppleInodeRecord));
    AppleDirectoryRecord link; link.parent_id = 2; link.file_id = 60; link.name_utf8 = "link"; link.flags = 10;
    Record directory_record;
    Check(EncodeAppleDirectoryRecord(link, directory_record, error), error); f.fs.push_back(directory_record);
    AppleInodeRecord device; device.object_id = device.private_id = 70; device.parent_id = 2;
    device.children_or_links = 1; device.mode = 0020600;
    f.fs.push_back(Encode(device, EncodeAppleInodeRecord));
    link.file_id = 70; link.name_utf8 = "device"; link.flags = 2;
    Check(EncodeAppleDirectoryRecord(link, directory_record, error), error); f.fs.push_back(directory_record);
    Bytes embedded; for (unsigned i = 0; i < 10; ++i) embedded.push_back(std::byte(i));
    for (const auto& attr : {
        AppleXattrRecord{30, "user.embedded", kAppleXattrDataEmbedded, embedded},
        AppleXattrRecord{2, "user.empty", kAppleXattrDataEmbedded, {}},
        AppleXattrRecord{60, "com.apple.fs.symlink", kAppleXattrDataEmbedded, Ascii("file.txt")},
        AppleXattrRecord{70, "user.device", kAppleXattrDataEmbedded, Ascii("abc")}})
        f.fs.push_back(Encode(attr, EncodeAppleXattrRecord));
    AppleXattrRecord external{30, "user.external", kAppleXattrDataStream, Bytes(48)};
    PutU64LE(external.data, 0, 900); PutU64LE(external.data, 8, 14); PutU64LE(external.data, 16, f.bs);
    f.fs.push_back(Encode(external, EncodeAppleXattrRecord));
    f.fs.push_back(Encode(AppleFileExtentRecord{900, 0, f.bs, 222, 0, f.bs}, EncodeAppleFileExtentRecord));
    f.fs.push_back(Encode(AppleDataStreamIdRecord{900, 1}, EncodeAppleDataStreamIdRecord));
    for (const auto& [block, owner] : {std::pair{221ull, 50ull}, std::pair{222ull, 30ull}})
        f.refs.push_back(Encode(ApplePhysicalExtentRecord{block, 1, 1, owner, 1}, EncodeApplePhysicalExtentRecord));
    f.spec.volumes[0].additional_file_system_allocated_blocks = 3;
    f.spec.authoritative_seeded_main_blocks[0].second.assign(f.bs, std::byte{0xee});
    const auto abc = Ascii("abc"); std::copy(abc.begin(), abc.end(), f.spec.authoritative_seeded_main_blocks[0].second.begin());
    f.spec.authoritative_seeded_main_blocks.emplace_back(221, f.spec.authoritative_seeded_main_blocks[0].second);
    Bytes external_bytes(f.bs, std::byte{0xdd}); const auto value = Ascii("external-value");
    std::copy(value.begin(), value.end(), external_bytes.begin());
    f.spec.authoritative_seeded_main_blocks.emplace_back(222, external_bytes);
    f.scope.observe_payload_content = true; f.scope.exact.store_offset_bytes = 2 * f.bs;
    f.Rebuild(); return f;
}

Bytes PrefixStore(const Fixture& f)
{
    Bytes bytes(f.scope.exact.store_offset_bytes, std::byte{0x19});
    bytes.insert(bytes.end(), f.image.begin(), f.image.end());
    bytes.resize(bytes.size() + f.bs, std::byte{0x29}); return bytes;
}

VerificationCheckState PayloadState(const VerificationReport& report)
{
    const auto c = std::find_if(report.coverage.begin(), report.coverage.end(), [](const auto& value) {
        return value.check == VerificationCheck::CurrentPayloadObservation;
    });
    Check(c != report.coverage.end() && c->implemented && c->required, "check 21 required/implemented");
    return c->state;
}

void PayloadObservation(const std::filesystem::path& evidence = {})
{
    const auto save = [&](const char* name, const VerificationReport& report) {
        std::string output; payload::Reason reason = payload::Reason::None;
        const bool serialized = SerializeImageVerificationReport(report, "memory-fixture.apfs", [] { return true; },
            MaxImageVerificationJsonBytes, output, reason);
        Check(serialized, "image serialization: " + std::string(payload::Name(reason)));
        if (!evidence.empty()) {
            std::ofstream file(evidence / name, std::ios::binary); file << output;
            Check(file.good(), "save focused wire evidence");
        }
        return output;
    };
    Fixture f = PayloadFixture(); auto bytes = PrefixStore(f); const auto before = bytes;
    TracedSource source(bytes);
    const auto healthy = ApfsVerifier::Verify(source, f.scope);
    Check(healthy.outcome == VerificationOutcome::Complete, "payload admission: " + Detail(healthy));
    Check(healthy.coverage.size() == 21 && PayloadState(healthy) == VerificationCheckState::Verified &&
        healthy.payload_inventory && healthy.payload_inventory->exactComplete(), "complete current observation");
    const auto& inventory = *healthy.payload_inventory;
    Check(inventory.entries.size() == 8 && inventory.logicalBytesRead == 4137, "entire selected inventory and logical sum");
    // These digests come from independent .NET input bytes, never this helper.
    const std::vector<std::string> expected = {
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "2b73c1655bca24857b549babad8d54a61f4f69e98453375d689130056cfbf94e",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "1f825aa2f0020ef7cf91dfa30da4668d791c5d4824fc8e41354b89ec05795ab3",
        "65ad54746ea1b7910eaac17afbd525e815de7fcd1820697502d0e0c2ec2b2304",
        "aadf327c8267c09d6fffd87a1a80ad3c798469ff332b7a57b9e8c045d46b2af7",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"};
    for (std::size_t i = 0; i < expected.size(); ++i)
        Check(inventory.entries[i].observedSha256 == expected[i] &&
            inventory.entries[i].readOutcome == payload::ReadOutcome::Complete, "independent ordered byte SHA " + std::to_string(i));
    Check(inventory.entries[0].inodeOid == 30 && inventory.entries[1].inodeOid == 40 && inventory.entries[2].inodeOid == 50 &&
        inventory.entries[3].inodeOid == 2 && inventory.entries[4].nameUtf8 == "user.embedded" &&
        inventory.entries[5].streamOid == 900 && inventory.entries[6].inodeOid == 60 && inventory.entries[7].inodeOid == 70,
        "numeric stream order; device/symlink appear only as xattrs");
    Check(std::count_if(inventory.aliases.begin(), inventory.aliases.end(), [](const auto& link) { return link.child_object_id == 30; }) == 2,
        "hardlink aliases preserved with one file-data row");
    Check(inventory.sharedBudget == healthy.read_budget && healthy.payload_projection && bytes == before &&
        !healthy.whole_volume_verified && !healthy.payload_content_hashes_verified, "owned backing, budget and read-only truth");
    const auto base = f.scope.exact.store_offset_bytes;
    const auto exact_read = [&](const auto& reads, std::uint64_t block, std::size_t count) {
        return std::count(reads.begin(), reads.end(), std::pair<std::uint64_t, std::size_t>{base + block * f.bs, count}) == 1;
    };
    Check(exact_read(source.reads, 220, 3) && exact_read(source.reads, 221, 3) && exact_read(source.reads, 222, 14),
        "regular and external xattr caller adds nonzero parent prefix once and clips padding");
    for (const auto& [at, count] : source.reads) {
        Check(at >= base && at + count <= base + f.image.size(), "no prefix/tail backing reads");
        if (at >= base + 219ull * f.bs && at < base + 224ull * f.bs)
            Check((at == base + 220ull * f.bs && count == 3) || (at == base + 221ull * f.bs && count == 3) ||
                (at == base + 222ull * f.bs && count == 14), "no wrong-origin or payload padding reads");
    }
    const auto healthy_wire = save("healthy-v3.json", healthy);
    Pass("real verifier store-origin pairing, aliases, empty/sparse/clipped data and xattrs");

    { auto legacy_scope = f.scope; legacy_scope.observe_payload_content = false;
      TracedSource legacy_source(bytes); const auto legacy = ApfsVerifier::Verify(legacy_source, legacy_scope);
      Check(legacy.outcome == VerificationOutcome::Complete && legacy.coverage.size() == 20 && !legacy.payload_inventory &&
          !legacy.payload_projection && legacy.repair.plan_id.starts_with("apfs-verifier-refusal-v1|"), "legacy metadata contract");
      Check(!legacy_source.Touched(base + 220ull * f.bs, 3) && !legacy_source.Touched(base + 222ull * f.bs, 14), "legacy no payload reads");
#ifdef APFS_PAYLOAD_PRIVATE_BASELINE
      TracedSource baseline_source(bytes); const auto baseline = VerifyLegacyBaseline(baseline_source, legacy_scope);
      Check(baseline.repair == legacy.repair && baseline.coverage == legacy.coverage && baseline_source.reads == legacy_source.reads &&
          baseline.covered_filesystem_records == legacy.covered_filesystem_records,
          "compiled frozen preintegration verifier has identical legacy refusal bytes, checks and backing reads");
#endif
      const auto wire = save("legacy-v2.json", legacy);
      Check(wire.find("observePayloadContent") == wire.npos && wire.find("payloadInventory") == wire.npos &&
          wire.find("maxPayloadLogicalBytes") == wire.npos && wire.find("\"version\":2") != wire.npos, "legacy image v2 exact additions absent");
      Pass("metadata-only old checks and image v2 remain opt-in compatible"); }

    for (const auto block : {220ull, 222ull}) {
        auto damaged = bytes; damaged[base + block * f.bs] ^= std::byte{1}; TracedSource changed_source(damaged);
        const auto changed = ApfsVerifier::Verify(changed_source, f.scope);
        Check(changed.outcome == VerificationOutcome::Complete && changed.payload_inventory->exactComplete() &&
            changed.repair.plan_id == healthy.repair.plan_id, "payload mutation supplies no independent mismatch or content-bound plan ID");
        const auto row = block == 220 ? 0 : 5;
        Check(changed.payload_inventory->entries[row].observedSha256 != expected[row] &&
            !changed.payload_content_hashes_verified && !changed.whole_volume_verified, "observed mutation is truthful");
        save(block == 220 ? "corrupt-file-v3.json" : "corrupt-xattr-v3.json", changed);
        Pass("payload corruption observed, independent baseline still absent block " + std::to_string(block));
    }
    for (const auto block : {220ull, 222ull}) for (const bool short_read : {false, true}) {
        TracedSource failed_source(bytes); failed_source.fail_offset = base + block * f.bs; failed_source.short_read = short_read;
        const auto failed = ApfsVerifier::Verify(failed_source, f.scope);
        const auto row = block == 220 ? 0 : 5;
        Check(failed.outcome == VerificationOutcome::Incomplete && Has(failed, VerificationCode::ReadFailure) &&
            PayloadState(failed) == VerificationCheckState::Unproven && failed.covered_filesystem_records == 0 &&
            !failed.allocation_census && failed.payload_inventory->enumerationComplete && !failed.payload_inventory->hashesObserved,
            "partial payload failure clears global proof");
        Check(failed.payload_inventory->failedSourceOffset == block * f.bs &&
            failed.findings[0].failed_source_offset_bytes == base + block * f.bs &&
            failed.findings[0].object_id == 30, "view failure offset translated to parent once with correct owner");
        Check(!failed.payload_inventory->entries[row].observedSha256 && failed.payload_inventory->entries[row].logicalBytesRead == 0 &&
            failed_source.reads.back().first == base + block * f.bs, "failed/short chunk discarded with no retry");
        if (row) Check(failed.payload_inventory->entries[0].observedSha256 == expected[0], "prior completed digest retained in partial census");
        save(block == 220 ? "file-read-failure-v3.json" : "xattr-read-failure-v3.json", failed);
        Pass(std::string(short_read ? "short payload read " : "failed payload read ") + std::to_string(block));
    }
    { TracedSource thrown_source(bytes); thrown_source.fail_offset = base + 222ull * f.bs; thrown_source.throw_read = true;
      const auto report = ApfsVerifier::Verify(thrown_source, f.scope);
      Check(Has(report, VerificationCode::ReadFailure) && report.findings[0].failed_source_offset_bytes == base + 222ull * f.bs &&
          report.payload_inventory->failedSourceOffset == 222ull * f.bs, "thrown I/O retains checked caller translation");
      save("xattr-thrown-read-v3.json", report); Pass("exceptional backing failure has exact parent offset"); }

    for (const unsigned damage : {0u, 1u, 2u}) {
        auto refused_fixture = PayloadFixture();
        if (damage == 0) refused_fixture.Edit(7, [](auto& b) { b[100] ^= std::byte{1}; }, false);
        else if (damage == 1) ClearMainAllocation(refused_fixture, 222);
        else {
            for (auto& record : refused_fixture.fs) if (ReadU64LE(record.key, 0).value() == ((3ull << 60) | 30)) {
                AppleInodeRecord inode; std::string error; Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), error);
                inode.bsd_flags |= kAppleBsdCompressedFlag; record = Encode(inode, EncodeAppleInodeRecord);
            }
            refused_fixture.Rebuild();
        }
        const auto image = PrefixStore(refused_fixture); TracedSource refused_source(image);
        const auto refused = ApfsVerifier::Verify(refused_source, refused_fixture.scope);
        Check(refused.outcome != VerificationOutcome::Complete && !refused.payload_inventory->enumerationComplete &&
            refused.payload_inventory->entries.empty() && !refused.payload_projection && PayloadState(refused) == VerificationCheckState::Unproven,
            "admission gate refuses without complete payload or retained admitted projection: " + Detail(refused));
        Check(!refused_source.Touched(base + 220ull * f.bs, 3) && !refused_source.Touched(base + 222ull * f.bs, 14), "admission before any payload reads");
        save(damage == 0 ? "metadata-corrupt-v3.json" : damage == 1 ? "allocator-refusal-v3.json" : "compressed-refusal-v3.json", refused);
        Pass("existing metadata/allocator/unsupported admission gate " + std::to_string(damage));
    }
    { auto broader_scope = f.scope; broader_scope.require_payload_content_hashes = true; TracedSource broader_source(bytes);
      const auto broader = ApfsVerifier::Verify(broader_source, broader_scope);
      Check(broader.outcome == VerificationOutcome::Incomplete && Has(broader, VerificationCode::CoverageMissing) &&
          broader.payload_inventory->exactComplete() && PayloadState(broader) == VerificationCheckState::Verified &&
          !broader.allocation_census && broader.covered_filesystem_records == 0, "observed hashes cannot satisfy expected hash check 14");
      save("expected-not-supplied-v3.json", broader); Pass("broader independent expected request remains unproven after observation"); }

    { Fixture sibling; AddSiblingPayload(sibling, 221); sibling.scope.observe_payload_content = true;
      TracedSource traced(sibling.image); const auto report = ApfsVerifier::Verify(traced, sibling.scope);
      Check(report.outcome == VerificationOutcome::Complete && report.payload_inventory->entries.size() == 1 &&
          report.payload_inventory->logicalBytesRead == 8 && traced.Touched(220ull * sibling.bs, 8) &&
          !traced.Touched(221ull * sibling.bs, 8), "sibling ownership admitted but only exact selected current volume hashed: " + Detail(report));
      Pass("two-volume admission observes only the selected current volume"); }
    { Fixture large; constexpr std::uint64_t size = 2 * payload::ChunkBytes + 3;
      const std::uint64_t blocks = (size + large.bs - 1) / large.bs;
      AppleInodeRecord inode; std::string error;
      Check(ApfsExtendedRecordCodec::DecodeInode(Inode(30, size, 1, false, large.bs), inode, error), error);
      PutU64LE(inode.extended_fields[0].data, 8, blocks * large.bs);
      large.fs[2] = Encode(inode, EncodeAppleInodeRecord);
      large.fs[3] = Encode(AppleFileExtentRecord{30, 0, blocks * large.bs, 220, 0, large.bs}, EncodeAppleFileExtentRecord);
      large.refs = {Encode(ApplePhysicalExtentRecord{220, blocks, 1, 30, 1}, EncodeApplePhysicalExtentRecord)};
      for (std::uint64_t at = 1; at < blocks; ++at)
          large.spec.authoritative_seeded_main_blocks.emplace_back(220 + at, Bytes(large.bs, std::byte{0x42}));
      large.spec.volumes[0].additional_file_system_allocated_blocks = blocks;
      large.scope.observe_payload_content = true; large.scope.exact.store_offset_bytes = 2 * large.bs; large.Rebuild();
      const auto image = PrefixStore(large); TracedSource traced(image);
      const auto offset = large.scope.exact.store_offset_bytes + 220ull * large.bs + payload::ChunkBytes;
      traced.fail_offset = offset; traced.short_read = true;
      const auto partial = ApfsVerifier::Verify(traced, large.scope);
      Check(Has(partial, VerificationCode::ReadFailure) && partial.payload_inventory->entries.size() == 1 &&
          partial.payload_inventory->entries[0].logicalBytesRead == payload::ChunkBytes &&
          partial.payload_inventory->logicalBytesRead == payload::ChunkBytes && !partial.payload_inventory->entries[0].observedSha256 &&
          partial.findings[0].failed_source_offset_bytes == offset && traced.reads.back().second == payload::ChunkBytes,
          "short second 64 KiB chunk preserves only fed prefix and exact parent coordinate: " + Detail(partial));
      Pass("multi-chunk truncated payload keeps a truthful unhashed prefix"); }

    for (const bool bytes_limit : {false, true}) {
        auto scope = f.scope;
        if (bytes_limit) scope.max_read_bytes = healthy.source_read_bytes - 14;
        else scope.max_reads = healthy.source_reads - 1;
        TracedSource limited_source(bytes);
        auto budget = std::make_shared<ApfsReadBudget>(65536, 1ull << 28, 1000000, 1ull << 28);
        BudgetedRandomAccessSource inherited(limited_source, budget);
        const auto limited = ApfsVerifier::Verify(inherited, scope);
        Check(Has(limited, VerificationCode::BudgetExceeded) && budget->Failed() && limited.read_budget == budget &&
            limited.payload_inventory->sharedBudget == budget && limited.payload_inventory->enumerationComplete &&
            !limited.payload_inventory->hashesObserved && !limited.payload_inventory->entries[5].observedSha256,
            "original inherited payload allowance failed sticky");
        const auto calls = limited_source.reads.size(); const auto spent = budget->Consumed();
        (void)ApfsVerifier::Verify(inherited, scope);
        Check(calls == limited_source.reads.size() && budget->Consumed().reads == spent.reads, "retry cannot replenish source budget");
        std::string output = "old"; payload::Reason reason;
        Check(!SerializeImageVerificationReport(limited, "fixture", [] { return true; }, MaxImageVerificationJsonBytes, output, reason) &&
            output.empty() && reason == payload::Reason::SharedBudget, "exhausted budget becomes explicit transport failure without fabricated JSON");
        Pass(bytes_limit ? "source byte limit and sticky transport refusal" : "source read limit and sticky transport refusal");
    }
    { TracedSource limited_source(bytes); auto budget = std::make_shared<ApfsReadBudget>(65536, 1ull << 28, 1000000, 1ull << 28);
      BudgetedRandomAccessSource inherited(limited_source, budget); bool first = true;
      const auto limited = ApfsVerifier::Verify(inherited, f.scope, [&] {
          if (first) { first = false; budget->LimitRemainingTo(UINT64_MAX, UINT64_MAX, 0, 0); } return true;
      });
      Check(Has(limited, VerificationCode::BudgetExceeded) && budget->Failed() && limited.payload_inventory->entries.empty() &&
          !limited_source.Touched(base + 220ull * f.bs, 3), "enumeration materialization limit stops before payload I/O");
      Pass("inherited materialization limit remains sticky at actual payload boundary"); }

    const auto hole_fixture = [&](std::uint64_t size) {
        Fixture hole; AppleInodeRecord inode; std::string error;
        Check(ApfsExtendedRecordCodec::DecodeInode(Inode(30, size, 1, false, hole.bs), inode, error), error);
        inode.internal_flags |= kAppleInodeSparseFlag; PutU64LE(inode.extended_fields[0].data, 8, 0);
        AppleExtendedField sparse{13, 0, Bytes(8)};
        PutU64LE(sparse.data, 0, (size + hole.bs - 1) / hole.bs * hole.bs); inode.extended_fields.push_back(sparse);
        hole.fs[2] = Encode(inode, EncodeAppleInodeRecord); hole.fs.erase(hole.fs.begin() + 3); hole.refs.clear();
        hole.scope.observe_payload_content = true; hole.Rebuild(); return hole;
    };
    { auto hole = hole_fixture(4 * payload::ChunkBytes + 3); TracedSource control(hole.image); unsigned calls = 0;
      const auto full = ApfsVerifier::Verify(control, hole.scope, [&] { ++calls; return true; });
      Check(full.outcome == VerificationOutcome::Complete && calls > 10 && full.payload_inventory->logicalBytesRead == 4 * payload::ChunkBytes + 3,
          "reader authenticated implicit all-hole tail: " + Detail(full));
      TracedSource expired_source(hole.image); unsigned checks = 0;
      const auto expired = ApfsVerifier::Verify(expired_source, hole.scope, [&] { return ++checks < calls - 4; });
      Check(Has(expired, VerificationCode::BudgetExceeded) && expired.read_budget->Failed() &&
          expired.payload_inventory->reason == payload::Reason::Deadline && expired.payload_inventory->logicalBytesRead > 0 &&
          !expired.payload_inventory->entries[0].observedSha256 && expired_source.reads == control.reads,
          "deadline stops hole-only hashing after a fed prefix without physical block zero reads");
      Pass("cooperative hole-only chunk deadline at actual verifier caller"); }
    { auto huge = hole_fixture(payload::MaxLogicalBytes + 1); TracedSource huge_source(huge.image);
      const auto refused = ApfsVerifier::Verify(huge_source, huge.scope);
      Check(Has(refused, VerificationCode::BudgetExceeded) && refused.payload_inventory->reason == payload::Reason::LogicalLimit &&
          refused.payload_inventory->entries.empty() && refused.read_budget->Failed(), "oversized sparse EOF refused before row publication");
      Pass("fixed 256 MiB logical cap includes authenticated holes"); }
    { Fixture many;
      for (unsigned i = 0; i < 1024; ++i)
          many.fs.push_back(Encode(AppleXattrRecord{30, "user.row-" + std::to_string(i), kAppleXattrDataEmbedded, {}}, EncodeAppleXattrRecord));
      many.Multilevel(); many.scope.observe_payload_content = true; TracedSource many_source(many.image);
      const auto refused = ApfsVerifier::Verify(many_source, many.scope);
      Check(Has(refused, VerificationCode::BudgetExceeded) && refused.payload_inventory->reason == payload::Reason::EntryLimit &&
          refused.payload_inventory->entries.empty() && refused.read_budget->Failed() && !many_source.Touched(220ull * many.bs, 8),
          "1024 row limit on actual authoritative multilevel projection: " + Detail(refused));
      Pass("fixed entry cap after actual namespace census"); }
    { auto embedded_only = hole_fixture(0);
      embedded_only.fs = {Inode(2, 0, 0, true, embedded_only.bs)};
      embedded_only.fs.push_back(Encode(AppleXattrRecord{2, "user.only", kAppleXattrDataEmbedded, Ascii("abc")}, EncodeAppleXattrRecord));
      embedded_only.Rebuild(); TracedSource control(embedded_only.image); unsigned calls = 0;
      const auto full = ApfsVerifier::Verify(control, embedded_only.scope, [&] { ++calls; return true; });
      Check(full.outcome == VerificationOutcome::Complete && full.payload_inventory->entries.size() == 1, "embedded-only control");
      TracedSource expired_source(embedded_only.image); unsigned at = 0;
      const auto expired = ApfsVerifier::Verify(expired_source, embedded_only.scope, [&] { return ++at < calls - 1; });
      Check(Has(expired, VerificationCode::BudgetExceeded) && expired.payload_inventory->reason == payload::Reason::Deadline &&
          !expired.payload_inventory->entries[0].observedSha256 && expired_source.reads == control.reads,
          "embedded-only deadline clears completed digest without backing I/O");
      Pass("embedded-only cooperative deadline"); }
    { auto empty = hole_fixture(0); empty.fs = {Inode(2, 0, 0, true, empty.bs)}; empty.Rebuild();
      TracedSource traced(empty.image); const auto report = ApfsVerifier::Verify(traced, empty.scope);
      Check(report.outcome == VerificationOutcome::Complete && report.payload_inventory->exactComplete() &&
          report.payload_inventory->entries.empty() && report.payload_inventory->logicalBytesRead == 0 &&
          PayloadState(report) == VerificationCheckState::Verified, "complete admitted empty namespace is a valid zero-row observation");
      Pass("empty admitted current volume census"); }

    { auto report = healthy; report.whole_volume_verified = true; std::string output = "old"; payload::Reason reason;
      Check(!SerializeImageVerificationReport(report, "fixture", [] { return true; }, MaxImageVerificationJsonBytes, output, reason) &&
          output.empty() && reason == payload::Reason::InvalidProjection, "serializer refuses invented whole-volume authority");
      report = healthy; report.payload_inventory->entries[0].observedSha256.reset();
      Check(!SerializeImageVerificationReport(report, "fixture", [] { return true; }, MaxImageVerificationJsonBytes, output, reason) &&
          output.empty() && reason == payload::Reason::InvalidProjection, "serializer refuses complete row without exact hash");
      Pass("response validation rejects false proof and invalid complete row"); }
    { TracedSource capped_source(bytes); const auto report = ApfsVerifier::Verify(capped_source, f.scope);
      std::string output = "old"; payload::Reason reason;
      Check(!SerializeImageVerificationReport(report, "memory-fixture.apfs", [] { return true; }, healthy_wire.size() - 1, output, reason) &&
          output.empty() && reason == payload::Reason::OutputLimit && report.read_budget->Failed(), "whole response cap counts envelope and nested inventory");
      Check(!SerializeImageVerificationReport(report, "fixture", [] { return true; }, MaxImageVerificationJsonBytes, output, reason) &&
          reason == payload::Reason::SharedBudget && output.empty(), "response limit cannot be reset for retry");
      Pass("bounded response fails without truncation and retains original failed allowance"); }
    { VectorRandomAccessSource store(f.image); std::string error;
      const auto checkpoint = LoadAppleCheckpointView(store, 0, store.SizeBytes(), error, 20);
      Check(checkpoint.has_value(), "wrapper fixture checkpoint: " + error);
      auto budget = std::make_shared<ApfsReadBudget>(65536, 1ull << 28, 1000000, 1ull << 28);
      NativeApfsVolumeProjection projection;
      Check(NativeApfsReader::TryProjectOrdinaryFileSystemRecords(f.spec.volumes[0].filesystem_records,
          checkpoint->container.superblock, checkpoint->volumes[0].superblock, budget, projection, error), "strict wrapper: " + error);
      Check(projection.read_extents_by_inode.at(30)[0].physical_address == 220ull * f.bs &&
          projection.attribute_stream_extents.at(900)->at(0).physical_address == 222ull * f.bs,
          "source-free wrapper retains store-relative addresses for both stream types");
      auto malformed = f.spec.volumes[0].filesystem_records; malformed.push_back(malformed.front());
      Check(!NativeApfsReader::TryProjectOrdinaryFileSystemRecords(malformed, checkpoint->container.superblock,
          checkpoint->volumes[0].superblock, budget, projection, error) && projection.inodes.empty() &&
          projection.read_extents_by_inode.empty(), "same validators reject malformed projection input and clear stale output");
      Pass("source-free admitted wrapper reuses validators and clears malformed output"); }
}

void WideOrdinaryNamespaceBudget()
{
    Fixture f;
    constexpr unsigned count = 2048;
    VectorRandomAccessSource source(f.image);
    std::string error;
    const auto checkpoint = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error, 20);
    Check(checkpoint.has_value(), "wide namespace checkpoint");
    std::vector<Record> records{Inode(2, 0, count, true, f.bs)};
    for (unsigned i = 0; i < count; ++i)
    {
        const auto id = 30ull + i;
        const auto name = "wide-file-" + std::to_string(id);
        AppleInodeRecord inode;
        Check(ApfsExtendedRecordCodec::DecodeInode(Inode(id, 0, 1, false, f.bs), inode, error), "wide inode decode");
        auto primary_name = Ascii(name); primary_name.push_back(std::byte{0});
        inode.extended_fields.push_back({4, 0, std::move(primary_name)});
        records.push_back(Encode(inode, EncodeAppleInodeRecord));
        records.push_back(Drec(id, name));
    }
    auto budget = std::make_shared<ApfsReadBudget>(65536, 1ull << 28, 1000000, 64ull << 20);
    NativeApfsVolumeProjection projection;
    const bool valid = NativeApfsReader::TryProjectOrdinaryFileSystemRecords(records, checkpoint->container.superblock,
        checkpoint->volumes[0].superblock, budget, projection, error);
    const auto used = budget->Consumed();
    std::cout << "WIDE_NAMESPACE records=" << records.size() << " charged_records=" << used.records
        << " charged_bytes=" << used.record_bytes << " valid=" << valid << " error=" << error << '\n';
    Check(valid && !budget->Failed() && projection.inodes.size() == count + 1 &&
        projection.directory_links.size() == count, "wide namespace fits unchanged 64 MiB allowance: " + error);
    Pass("wide ordinary namespace fits cumulative materialization budget");
}

void OrdinaryPrimaryLinkControls()
{
    Fixture f;
    VectorRandomAccessSource source(f.image);
    std::string error;
    const auto checkpoint = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error, 20);
    Check(checkpoint.has_value(), "primary controls checkpoint");
    AppleInodeRecord inode;
    Check(ApfsExtendedRecordCodec::DecodeInode(Inode(30, 0, 2, false, f.bs), inode, error), "primary controls inode");
    auto name = Ascii("primary"); name.push_back(std::byte{0});
    inode.extended_fields.push_back({4, 0, name});
    const auto sibling_drec = [&](const std::string& entry_name, std::uint64_t sibling_id) {
        AppleDirectoryRecord entry;
        entry.parent_id = 2; entry.file_id = 30; entry.name_utf8 = entry_name; entry.flags = 8;
        AppleExtendedField sibling{1, 0, Bytes(8)}; PutU64LE(sibling.data, 0, sibling_id);
        entry.extended_fields.push_back(std::move(sibling));
        Record record;
        const bool encoded = EncodeAppleDirectoryRecord(entry, record, error);
        Check(encoded, "primary controls sibling directory entry: " + error);
        return record;
    };
    std::vector<Record> records{Inode(2, 0, 2, true, f.bs), sibling_drec("alias", 50), sibling_drec("primary", 51),
        Encode(inode, EncodeAppleInodeRecord),
        Encode(AppleSiblingLinkRecord{30, 50, 2, "alias"}, EncodeAppleSiblingLinkRecord),
        Encode(AppleSiblingLinkRecord{30, 51, 2, "primary"}, EncodeAppleSiblingLinkRecord),
        Encode(AppleSiblingMapRecord{50, 30}, EncodeAppleSiblingMapRecord),
        Encode(AppleSiblingMapRecord{51, 30}, EncodeAppleSiblingMapRecord)};
    const auto validate = [&](const std::vector<Record>& input, bool expected, const char* label) {
        auto budget = std::make_shared<ApfsReadBudget>(65536, 1ull << 28, 1000000, 1ull << 28);
        NativeApfsVolumeProjection projection;
        projection.inodes.emplace_back(); // A late refusal must not preserve old projection state.
        const bool valid = NativeApfsReader::TryProjectOrdinaryFileSystemRecords(input, checkpoint->container.superblock,
            checkpoint->volumes[0].superblock, budget, projection, error);
        Check(valid == expected, std::string(label) + ": " + error);
        if (expected) Check(projection.inodes.size() == 2 && projection.directory_links.size() == 2 &&
            projection.inodes.back().full_path == L"\\primary", "hardlink retains declared primary path");
        else Check(projection.inodes.empty() && projection.directory_links.empty(), "refusal clears stale projection");
        Pass(label);
    };
    validate(records, true, "hardlink alias before declared primary remains valid");
    auto bad = records;
    bad[1] = Drec(30, "alias"); bad[2] = Drec(30, "primary");
    validate(bad, false, "hardlink directory entries without sibling IDs are refused");
    bad = records; bad[1] = sibling_drec("alias", 51); bad[2] = sibling_drec("primary", 50);
    validate(bad, false, "hardlink directory sibling IDs cannot be exchanged");
    bad = records;
    inode.extended_fields.back().data = Ascii("missing"); inode.extended_fields.back().data.push_back(std::byte{0});
    bad[3] = Encode(inode, EncodeAppleInodeRecord);
    validate(bad, false, "hardlink missing declared primary is refused");
    inode.extended_fields.back().data = name;
    inode.parent_id = 99;
    bad[3] = Encode(inode, EncodeAppleInodeRecord);
    validate(bad, false, "primary link under a different parent is refused");
    bad = records; bad.pop_back();
    validate(bad, false, "missing sibling map remains refused");
    bad = records; bad[2] = sibling_drec("alias", 51);
    validate(bad, false, "duplicate directory name remains refused");
    bad = records; bad[0] = Inode(2, 0, 1, true, f.bs);
    validate(bad, false, "directory child count remains exact");
    bad = records; bad.push_back(records[3]);
    validate(bad, false, "duplicate inode remains refused");
}

void FragmentedNamespaceBudget()
{
    Fixture f;
    constexpr std::uint64_t extent_count = 4096;
    AppleInodeRecord inode;
    std::string error;
    Check(ApfsExtendedRecordCodec::DecodeInode(f.fs[2], inode, error), "fragmented inode decode");
    inode.internal_flags |= kAppleInodeSparseFlag;
    inode.uncompressed_size = extent_count * f.bs;
    PutU64LE(inode.extended_fields.front().data, 0, inode.uncompressed_size);
    PutU64LE(inode.extended_fields.front().data, 8, 0);
    AppleExtendedField sparse{13, 0, Bytes(8)};
    PutU64LE(sparse.data, 0, inode.uncompressed_size);
    inode.extended_fields.push_back(std::move(sparse));
    f.fs[2] = Encode(inode, EncodeAppleInodeRecord);
    f.fs.erase(f.fs.begin() + 3);
    f.refs.clear();
    f.spec.volumes[0].extentref_records.clear();
    for (std::uint64_t i = 0; i < extent_count; ++i)
        f.fs.push_back(Encode(AppleFileExtentRecord{30, i * f.bs, f.bs, 0, 0, f.bs}, EncodeAppleFileExtentRecord));
    f.Multilevel();
    f.scope.max_record_bytes = 32ull * 1024 * 1024;
    TracedSource source(f.image);
    const auto before = f.image;
    const auto report = ApfsVerifier::Verify(source, f.scope);
    Check(report.outcome == VerificationOutcome::Complete && report.findings.empty(),
        "fragmented namespace within unchanged 32 MiB budget: " + Detail(report));
    Check(report.covered_filesystem_records >= extent_count && f.image == before &&
        !report.whole_volume_verified && !report.payload_content_hashes_verified,
        "fragmented coverage, source preservation and truthful subset");
    Pass("fragmented namespace scalar materialization");

    auto budget = std::make_shared<ApfsReadBudget>(65536, 1ull << 28, 1000000, 1ull << 20);
    BudgetedRandomAccessSource limited(source, budget);
    const auto refused = ApfsVerifier::Verify(limited, f.scope);
    Check(Has(refused, VerificationCode::BudgetExceeded) && budget->Failed() &&
        refused.covered_filesystem_records == 0 && refused.covered_physical_extents == 0,
        "stricter inherited namespace bytes still refuse without partial success");
    const auto reads = source.reads.size();
    (void)ApfsVerifier::Verify(limited, f.scope);
    Check(source.reads.size() == reads, "exhausted namespace budget remains sticky");
    Pass("fragmented namespace retains byte and sticky limits");
}
}
int main(int argc, char** argv)
{
    try {
        if (argc == 2 && std::string(argv[1]) == "--metadata-deadline-only")
        {
            MetadataDeadlines();
            std::cout << "PASS " << cases << " cases, " << checks << " checks\n"; return 0;
        }
        if (argc == 2 && std::string(argv[1]) == "--ordinary-namespace-budget-only")
        {
            WideOrdinaryNamespaceBudget();
            std::cout << "PASS " << cases << " cases, " << checks << " checks\n"; return 0;
        }
        if (argc == 2 && std::string(argv[1]) == "--namespace-controls-only")
        {
            OrdinaryPrimaryLinkControls(); Corruptions(); Unsupported(); BudgetsAndFailures(); FragmentedNamespaceBudget();
            std::cout << "PASS " << cases << " cases, " << checks << " checks\n"; return 0;
        }
        if ((argc == 2 || argc == 3) && std::string(argv[1]) == "--payload-observation-only")
        {
            PayloadObservation(argc == 3 ? std::filesystem::path(argv[2]) : std::filesystem::path{});
            std::cout << "PASS " << cases << " cases, " << checks << " checks\n"; return 0;
        }
        if (argc == 2 && std::string(argv[1]) == "--namespace-budget-only")
        {
            FragmentedNamespaceBudget();
            std::cout << "PASS " << cases << " cases, " << checks << " checks\n"; return 0;
        }
        if (argc == 2 && std::string(argv[1]) == "--producer-omap-only")
        {
            ProducerOmapRoles();
            std::cout << "PASS " << cases << " cases, " << checks << " checks\n"; return 0;
        }
        Healthy(); Corruptions(); Unsupported(); CurrentMetadataIncrement(); BudgetsAndFailures(); ProducerOmapRoles(); FragmentedNamespaceBudget();
        WideOrdinaryNamespaceBudget(); OrdinaryPrimaryLinkControls(); MetadataDeadlines();
        if (argc == 2)
        {
            const auto save = [&](const char* name, const Fixture& f) {
                std::ofstream file(std::filesystem::path(argv[1]) / name, std::ios::binary);
                file.write(reinterpret_cast<const char*>(f.image.data()), f.image.size());
                Check(file.good(), "write private CLI fixture");
            };
            Fixture healthy; save("healthy.apfs", healthy);
            Fixture damaged; ClearMainAllocation(damaged, 7); save("metadata-free.apfs", damaged);
            Fixture overlap; AddSiblingPayload(overlap, 220); save("cross-volume.apfs", overlap);
        }
        std::cout << "PASS " << cases << " cases, " << checks << " checks\n"; return 0; }
    catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
