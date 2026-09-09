#include "ApfsVerifier.h"
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
    mutable std::vector<std::pair<std::uint64_t, std::size_t>> reads;
    explicit TracedSource(const Bytes& bytes) : image(bytes) {}
    std::uint64_t SizeBytes() const override { return image.size(); }
    bool Read(std::uint64_t offset, std::size_t size, Bytes& out) const override
    {
        out.clear(); reads.emplace_back(offset, size);
        if (fail_at == reads.size()) { if (short_read) out.resize(1); return short_read; }
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
      Check(report.outcome == VerificationOutcome::Refused && Has(report, VerificationCode::SnapshotAccountingUnsupported),
          "nonempty snapshot: " + Detail(report));
      Check(before == fixture.image && report.selected && report.covered_filesystem_records == 0, "snapshot refusal preserves input and exact binding");
      Pass("authoritative nonempty snapshot inventory refused for ownership"); }
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
}
int main(int argc, char** argv)
{
    try { Healthy(); Corruptions(); Unsupported(); CurrentMetadataIncrement(); BudgetsAndFailures();
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
