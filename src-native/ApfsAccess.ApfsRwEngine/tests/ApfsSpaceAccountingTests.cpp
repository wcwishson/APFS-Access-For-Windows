#include "ApfsSpaceAccounting.h"
#include "ApfsTransactionWriter.h"
#include "SnapshotTestFixture.h"

#include <iostream>
#include <stdexcept>

using namespace apfsaccess::catalog;
using namespace apfsaccess::rw;
using namespace apfsaccess::testfixture;
using Record = apfsaccess::catalog::BtreeRecord;

namespace
{
unsigned checks = 0;
void Check(bool ok, const std::string& message)
{
    ++checks;
    if (!ok) throw std::runtime_error(message);
}
template<class T, class Encoder> Record Encode(const T& value, Encoder encoder)
{
    Record record;
    std::string error;
    Check(encoder(value, record, error), "fixture encoding: " + error);
    return record;
}
std::vector<Record> Files(std::uint32_t bs, std::uint64_t physical,
    std::uint64_t blocks, bool clone = false)
{
    AppleInodeRecord root;
    root.object_id = root.private_id = root.parent_id = 2;
    root.mode = 0040755;
    root.children_or_links = clone ? 2 : 1;
    std::vector<Record> records{Encode(root, EncodeAppleInodeRecord)};
    for (std::uint64_t id = 30; id <= (clone ? 31u : 30u); ++id)
    {
        AppleInodeRecord inode;
        inode.object_id = inode.private_id = id;
        inode.parent_id = 2;
        inode.mode = 0100644;
        inode.children_or_links = 1;
        inode.uncompressed_size = blocks * bs;
        AppleExtendedField stream{8, 0, Bytes(40)};
        PutU64LE(stream.data, 0, blocks * bs);
        PutU64LE(stream.data, 8, blocks * bs);
        inode.extended_fields.push_back(stream);
        AppleDirectoryRecord entry;
        entry.parent_id = 2;
        entry.file_id = id;
        entry.name_utf8 = "file-" + std::to_string(id);
        entry.flags = 8;
        records.push_back(Encode(inode, EncodeAppleInodeRecord));
        records.push_back(Encode(entry, [](const auto& value, auto& out, auto& error) {
            return EncodeAppleDirectoryRecord(value, out, error);
        }));
        records.push_back(Encode(AppleFileExtentRecord{id, 0, blocks * bs, physical, 0, bs},
            EncodeAppleFileExtentRecord));
        records.push_back(Encode(AppleDataStreamIdRecord{id, 1}, EncodeAppleDataStreamIdRecord));
    }
    std::string error;
    Check(SortAppleBtreeRecords(records, AppleBtreeKeyOrder::FileSystemCaseSensitive, error), error);
    return records;
}
void Tree(SnapshotFixture& f, std::uint64_t block, std::uint64_t xid,
    std::uint64_t oid, std::uint32_t type, std::uint32_t subtype,
    const std::vector<Record>& records)
{
    std::vector<Bytes> keys, values;
    for (const auto& record : records) { keys.push_back(record.key); values.push_back(record.value); }
    f.Put(block, BuildRawLeafNode(keys, values, xid, f.bs, 0, oid, type, subtype));
}
void Refs(SnapshotFixture& f, std::uint64_t block, std::uint64_t xid,
    const std::vector<ApplePhysicalExtentRecord>& extents)
{
    std::vector<Record> records;
    for (const auto& extent : extents) records.push_back(Encode(extent, EncodeApplePhysicalExtentRecord));
    Tree(f, block, xid, block, kObjectPhysical | kObjectTypeBtree, kObjectTypeBlockRefTree, records);
}
void Payload(SnapshotFixture& f, std::uint64_t fs_block, std::uint64_t xid,
    std::uint64_t physical, std::uint64_t blocks, bool clone = false)
{
    Tree(f, fs_block, xid, SnapshotFixture::root_oid, kObjectTypeBtree, kObjectTypeFsTree,
        Files(static_cast<std::uint32_t>(f.bs), physical, blocks, clone));
}
void Allocate(SnapshotFixture& f, const std::vector<std::uint64_t>& blocks)
{
    VectorRandomAccessSource source(f.image);
    std::string error;
    const auto checkpoint = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error, 20);
    Check(checkpoint.has_value(), "fixture allocator: " + error);
    const auto& chunk = checkpoint->spaceman.chunks.front();
    std::uint32_t added = 0;
    f.Edit(chunk.bitmap_block, [&](auto& bytes) {
        for (const auto block : blocks)
        {
            const auto bit = block - chunk.start_block;
            const auto mask = std::byte(1u << (bit % 8));
            if ((bytes[bit / 8] & mask) == std::byte{0}) { bytes[bit / 8] |= mask; ++added; }
        }
    }, false);
    f.Edit(checkpoint->spaceman.devices[0].cibs[0].object.physical_block,
        [&](auto& bytes) { PutU32LE(bytes, 0x3C, chunk.free_count - added); });
    f.Edit(checkpoint->spaceman.object.physical_block,
        [&](auto& bytes) { PutU64LE(bytes, 0x48, checkpoint->spaceman.devices[0].free_count - added); });
    f.Edit(4, [](auto& bytes) { PutU64LE(bytes, 0x58, 32); });
}
VerificationScope Scope(const SnapshotFixture& f)
{
    VerificationScope scope;
    scope.source_identity = "snapshot-space-memory-image";
    scope.exact = f.scope;
    return scope;
}
class TracedSource final : public RandomAccessSource
{
public:
    const Bytes& image;
    std::uint64_t block_size;
    mutable bool read_payload = false;
    std::optional<std::uint64_t> fail_offset;
    explicit TracedSource(const Bytes& bytes, std::uint64_t bs = 4096) : image(bytes), block_size(bs) {}
    std::uint64_t SizeBytes() const override { return image.size(); }
    bool Read(std::uint64_t offset, std::size_t size, Bytes& out) const override
    {
        if (offset < 228 * block_size && 220 * block_size < offset + size) read_payload = true;
        out.clear();
        if (fail_offset == offset || offset > image.size() || size > image.size() - offset) return false;
        out.assign(image.begin() + offset, image.begin() + offset + size);
        return true;
    }
};
ApfsSnapshotPayloadSpaceObservation Observe(const SnapshotFixture& f)
{
    TracedSource source(f.image, f.bs);
    const auto before = f.image;
    std::optional<ApfsSnapshotPayloadSpaceObservation> out;
    std::string error;
    Check(TryObserveAppleSnapshotPayloadSpace(source, Scope(f), out, error), error);
    Check(out.has_value() && error.empty(), "successful observation published");
    Check(before == f.image && !source.read_payload, "read-only metadata operation; no payload I/O");
    Check(out->scope == f.scope && out->allocation_unit_bytes == f.bs &&
        out->source_identity == Scope(f).source_identity, "observation binds exact source/window/checkpoint identity");
    Check(out->referenced_payload.blocks == out->shared_with_live_payload.blocks + out->absent_from_live_payload.blocks &&
        out->referenced_payload.bytes == out->referenced_payload.blocks * f.bs, "physical payload partition and units");
    return *out;
}
void Unknown(const SnapshotFixture& f, VerificationScope scope, const std::string& expected = {})
{
    VectorRandomAccessSource source(f.image);
    std::optional<ApfsSnapshotPayloadSpaceObservation> out{ApfsSnapshotPayloadSpaceObservation{}};
    std::string error;
    Check(!TryObserveAppleSnapshotPayloadSpace(source, scope, out, error), "invalid scope unexpectedly counted");
    Check(!out && !error.empty() && (expected.empty() || error.find(expected) != std::string::npos),
        "failed result must be unknown: " + error);
}
SnapshotFixture Shared(std::size_t bs = 4096, bool clone = false)
{
    SnapshotFixture f(bs);
    Payload(f, 183, 10, 220, 4, clone);
    Refs(f, 184, 10, {{220, 4, kApplePhysicalExtentKindNew, 30, clone ? 2 : 1}});
    Payload(f, 7, 20, 220, 4, clone);
    Refs(f, 8, 20, {});
    Allocate(f, {180, 181, 183, 184, 185, 220, 221, 222, 223});
    return f;
}
void SharedAndClones()
{
    for (const bool clone : {false, true})
    {
        const auto out = Observe(Shared(4096, clone));
        Check(out.snapshot_count == 1 && out.referenced_payload.blocks == 4 &&
            out.shared_with_live_payload.blocks == 4 && out.absent_from_live_payload.blocks == 0,
            "clones and live sharing must count physical blocks once");
    }
}
void PartialOverlap()
{
    auto f = Shared();
    Payload(f, 7, 20, 222, 4);
    Refs(f, 8, 20, {{220, 2, kApplePhysicalExtentKindUpdate, 30, -1},
        {224, 2, kApplePhysicalExtentKindNew, 30, 1}});
    Allocate(f, {224, 225});
    const auto out = Observe(f);
    Check(out.referenced_payload.blocks == 4 && out.shared_with_live_payload.blocks == 2 &&
        out.absent_from_live_payload.blocks == 2, "split UPDATE interval partitions actual physical union");
}
void MultipleSnapshots()
{
    auto f = Shared();
    f.SecondSnapshot();
    std::string error;
    Check(SortAppleBtreeRecords(f.snapshots, AppleBtreeKeyOrder::FileSystemCaseSensitive, error), error);
    f.Inventory({10, 11});
    f.Put(6, BuildBtreeNode({{SnapshotFixture::root_oid, 183, 0, 10},
        {SnapshotFixture::root_oid, 188, 0, 11}, {SnapshotFixture::root_oid, 7, 0, 20},
        {SnapshotFixture::snap_oid, 9, 0, 20}}, 20, f.bs, 0, 6,
        kObjectPhysical | kObjectTypeBtree, kObjectTypeOmap));
    Payload(f, 188, 11, 222, 4);
    Refs(f, 191, 11, {{220, 2, kApplePhysicalExtentKindUpdate, 30, -1},
        {224, 2, kApplePhysicalExtentKindNew, 30, 1}});
    Payload(f, 7, 20, 224, 4);
    Refs(f, 8, 20, {{222, 2, kApplePhysicalExtentKindUpdate, 30, -1},
        {226, 2, kApplePhysicalExtentKindNew, 30, 1}});
    Allocate(f, {188, 190, 191, 224, 225, 226, 227});
    const auto out = Observe(f);
    Check(out.snapshot_count == 2 && out.referenced_payload.blocks == 6 &&
        out.shared_with_live_payload.blocks == 2 && out.absent_from_live_payload.blocks == 4,
        "overlapping snapshot views are unioned before counting");
}
void SnapshotOnly()
{
    auto f = Shared();
    f.Put(7, BuildRootFsLeaf(20, f.bs, SnapshotFixture::root_oid, kObjectTypeBtree, kObjectTypeFsTree));
    Refs(f, 8, 20, {{220, 4, kApplePhysicalExtentKindUpdate, 30, -1}});
    const auto out = Observe(f);
    Check(out.referenced_payload.blocks == 4 && out.shared_with_live_payload.blocks == 0 &&
        out.absent_from_live_payload.blocks == 4, "snapshot-only reachability is observed without reclaim claims");
}
void KnownZerosAndUnits()
{
    for (const auto bs : {4096u, 16384u, 65536u})
    {
        SnapshotFixture f(bs);
        Allocate(f, {180, 181, 183, 184, 185});
        const auto empty_payload = Observe(f);
        Check(empty_payload.snapshot_count == 1 && empty_payload.referenced_payload.bytes == 0,
            "existing empty snapshot has known zero payload");
        f.snapshots.clear();
        f.Inventory({});
        f.Edit(5, [](auto& bytes) { PutU32LE(bytes, 0x2C, 0); PutU64LE(bytes, 0x38, 0); });
        const auto empty_inventory = Observe(f);
        Check(empty_inventory.snapshot_count == 0 && empty_inventory.referenced_payload.bytes == 0,
            "authenticated empty inventory yields known zero");
        const auto nonempty = Observe(Shared(bs));
        Check(nonempty.referenced_payload.bytes == 4ull * bs, "bytes use authenticated allocation unit");
    }
}
void Refusals()
{
    auto f = Shared();
    {
        VectorRandomAccessSource raw(f.image);
        std::string error;
        const auto cp = LoadAppleCheckpointView(raw, 0, raw.SizeBytes(), error, 20);
        Check(cp.has_value(), error);
        const auto& chunk = cp->spaceman.chunks.front();
        f.Edit(chunk.bitmap_block, [&](auto& bytes) {
            const auto bit = 181ull - chunk.start_block;
            bytes[bit / 8] &= ~std::byte(1u << (bit % 8));
        }, false);
        f.Edit(cp->spaceman.devices[0].cibs[0].object.physical_block,
            [&](auto& bytes) { PutU32LE(bytes, 0x3C, chunk.free_count + 1); });
        f.Edit(cp->spaceman.object.physical_block,
            [&](auto& bytes) { PutU64LE(bytes, 0x48, cp->spaceman.devices[0].free_count + 1); });
        const auto before = f.image;
        TracedSource source(f.image);
        std::optional<ApfsSnapshotPayloadSpaceObservation> out{ApfsSnapshotPayloadSpaceObservation{}};
        Check(!TryObserveAppleSnapshotPayloadSpace(source, Scope(f), out, error) && !out &&
            error.find("VerifierMetadataMainAllocationBitClear") != std::string::npos,
            "unallocated historical OMAP cannot publish snapshot-space totals: " + error);
        Check(before == f.image && !source.read_payload, "missing OMAP allocation preserves input and skips payload I/O");
    }
    f = Shared();
    auto scope = Scope(f);
    ++scope.exact.checkpoint_xid;
    Unknown(f, scope);
    scope = Scope(f); scope.exact.volume_uuid_hex = std::string(32, 'c'); Unknown(f, scope);
    scope = Scope(f); scope.require_whole_volume = true; Unknown(f, scope, "ScopeUnsupported");
    scope = Scope(f); scope.require_payload_content_hashes = true; Unknown(f, scope, "ScopeUnsupported");
    scope = Scope(f); scope.observe_payload_content = true; Unknown(f, scope, "ScopeUnsupported");
    f.Edit(183, [](auto& bytes) { bytes[64] ^= std::byte{1}; }, false);
    Unknown(f, Scope(f));
    f = Shared();
    Refs(f, 8, 20, {{220, 4, kApplePhysicalExtentKindUpdate, 30, -2}});
    Unknown(f, Scope(f));
    f = Shared();
    Payload(f, 183, 10, 230, 4);
    Refs(f, 184, 10, {{230, 4, kApplePhysicalExtentKindNew, 30, 1}});
    Refs(f, 8, 20, {{220, 4, kApplePhysicalExtentKindNew, 30, 1},
        {230, 4, kApplePhysicalExtentKindUpdate, 30, -1}});
    Unknown(f, Scope(f), "NotAllocated");
    f = Shared();
    f.Edit(4, [](auto& bytes) { PutU16LE(bytes, 0x3C4, 0x180); });
    Unknown(f, Scope(f));
}
void BudgetsAndReadFailures()
{
    auto f = Shared();
    auto scope = Scope(f);
    scope.max_reads = 1;
    Unknown(f, scope, "Budget");
    scope = Scope(f);
    VectorRandomAccessSource raw(f.image);
    auto budget = std::make_shared<ApfsReadBudget>(scope.max_reads, scope.max_read_bytes,
        scope.max_records, scope.max_record_bytes);
    BudgetedRandomAccessSource source(raw, budget);
    std::optional<ApfsSnapshotPayloadSpaceObservation> out;
    std::string error;
    Check(TryObserveAppleSnapshotPayloadSpace(source, scope, out, error), error);
    const auto reads = budget->Consumed().reads;
    scope.max_reads = reads - 1;
    Unknown(f, scope, "Budget");
    scope = Scope(f);
    scope.max_record_bytes = budget->Consumed().record_bytes - 1;
    Unknown(f, scope, "Budget");
    Check(budget->Refuse("test-sticky-failure") == false, "fixture budget refusal");
    Check(!TryObserveAppleSnapshotPayloadSpace(source, Scope(f), out, error) && !out &&
        error == "test-sticky-failure", "caller budget is never replaced or replenished");
    TracedSource failed(f.image);
    failed.fail_offset = 183 * f.bs;
    out.emplace();
    Check(!TryObserveAppleSnapshotPayloadSpace(failed, Scope(f), out, error) && !out,
        "historical read failure cannot publish prior output");
}
void MultipleVolumesStayUnknown()
{
    SnapshotFixture f;
    BuilderStore spec;
    spec.block_count = 512;
    spec.xid = 20;
    spec.volumes.resize(2);
    spec.volumes[0].uuid_hex = std::string(32, 'b');
    spec.volumes[1].oid = 102;
    spec.volumes[1].uuid_hex = std::string(32, 'c');
    f.image = BuildAuthoritativeStoreImage(spec);
    f.Edit(2, [](auto& bytes) { PutU32LE(bytes, 0x20, 1); });
    Unknown(f, Scope(f), "MultipleVolumesUnsupported");
}
void OffsetWindowAndUnknownTotals()
{
    auto f = Shared();
    const auto expected = Observe(f);
    const auto image = f.image;
    f.image.assign(2 * f.bs, std::byte{0});
    f.image.insert(f.image.end(), image.begin(), image.end());
    f.image.resize(f.image.size() + f.bs);
    f.scope.store_offset_bytes = 2 * f.bs;
    VectorRandomAccessSource source(f.image);
    std::optional<ApfsSnapshotPayloadSpaceObservation> out;
    std::string error;
    Check(TryObserveAppleSnapshotPayloadSpace(source, Scope(f), out, error), error);
    Check(out->scope == f.scope && out->referenced_payload.blocks == expected.referenced_payload.blocks,
        "nonzero store window counted once");
    VectorRandomAccessSource store(image);
    const auto checkpoint = LoadAppleCheckpointView(store, 0, store.SizeBytes(), error, 20);
    ApfsSharedSpaceProjection shared;
    Check(checkpoint && TryProjectAppleSharedSpace(*checkpoint, shared, error), error);
    Check(!shared.volumes.front().snapshot && !shared.volumes.front().purgeable,
        "payload observation never upgrades unknown total snapshot or purgeable accounting");
}
}
int main()
{
    const std::vector<std::pair<const char*, void(*)()>> tests = {
        {"SharedAndClones", SharedAndClones}, {"PartialOverlap", PartialOverlap},
        {"MultipleSnapshots", MultipleSnapshots}, {"SnapshotOnly", SnapshotOnly},
        {"KnownZerosAndUnits", KnownZerosAndUnits}, {"Refusals", Refusals},
        {"BudgetsAndReadFailures", BudgetsAndReadFailures},
        {"MultipleVolumesStayUnknown", MultipleVolumesStayUnknown},
        {"OffsetWindowAndUnknownTotals", OffsetWindowAndUnknownTotals}};
    unsigned failed = 0;
    for (const auto& [name, test] : tests)
    {
        try { test(); std::cout << "PASS " << name << '\n'; }
        catch (const std::exception& e) { ++failed; std::cerr << "FAIL " << name << ": " << e.what() << '\n'; }
    }
    std::cout << tests.size() - failed << '/' << tests.size() << " cases passed; " << checks << " checks\n";
    return failed ? 1 : 0;
}
