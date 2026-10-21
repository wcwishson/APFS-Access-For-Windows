#include "ApfsVerifier.h"
#include "AppleVolumeTransaction.h"
#include "TestFixtureBuilder.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <set>
#include <stdexcept>
#include <tuple>

using namespace apfsaccess::catalog;
using namespace apfsaccess::rw;
using namespace apfsaccess::testfixture;
using Record = apfsaccess::catalog::BtreeRecord;
using Bytes = std::vector<std::byte>;

namespace
{
unsigned checks = 0, cases = 0;
void Check(bool value, const std::string& message)
{
    ++checks;
    if (!value) throw std::runtime_error(message);
}
void Pass(const std::string& name) { ++cases; std::cout << "PASS " << name << '\n'; }
std::string Detail(const VerificationReport& report)
{
    return report.findings.empty() ? "no findings" : report.findings.front().detail;
}
const VerificationCoverage& Coverage(const VerificationReport& report, VerificationCheck check)
{
    const auto found = std::find_if(report.coverage.begin(), report.coverage.end(),
        [&](const auto& row) { return row.check == check; });
    Check(found != report.coverage.end(), "coverage row exists");
    return *found;
}
bool Has(const VerificationReport& report, VerificationCode code)
{
    return std::any_of(report.findings.begin(), report.findings.end(),
        [&](const auto& finding) { return finding.code == code; });
}
template<class T, class Encoder> Record Encode(const T& value, Encoder encoder)
{
    Record record; std::string error;
    Check(encoder(value, record, error), "fixture record: " + error);
    return record;
}

// The verifier sees only this read interface. Publication below targets a
// separate byte vector, with no file/device API anywhere in the fixture path.
class TracedSource final : public RandomAccessSource
{
public:
    explicit TracedSource(const Bytes& image) : image_(image) {}
    std::uint64_t SizeBytes() const override { return image_.size(); }
    bool Read(std::uint64_t offset, std::size_t size, Bytes& out) const override
    {
        out.clear(); reads.emplace_back(offset, size);
        if (reads.size() == fail_at) { if (short_read) out.resize(1); return short_read; }
        if (offset > image_.size() || size > image_.size() - offset) return false;
        out.assign(image_.begin() + offset, image_.begin() + offset + size);
        if (reads.size() == change_at && !out.empty()) out[0] ^= std::byte{1};
        return true;
    }
    mutable std::vector<std::pair<std::uint64_t, std::size_t>> reads;
    std::uint64_t fail_at = 0, change_at = 0;
    bool short_read = false;
private:
    const Bytes& image_;
};

class MemoryTarget final : public AppleCheckpointWriteTarget
{
public:
    MemoryTarget(const Bytes& source, std::uint32_t block_size) : image(source), bs(block_size) {}
    bool ReadBlock(std::uint64_t block, std::uint32_t size, Bytes& out) override
    {
        if (size != bs || block >= image.size() / bs) return false;
        out.assign(image.begin() + block * bs, image.begin() + (block + 1) * bs);
        return true;
    }
    bool WriteBlock(std::uint64_t block, std::span<const std::byte> bytes) override
    {
        if (bytes.size() != bs || block >= image.size() / bs) return false;
        std::copy(bytes.begin(), bytes.end(), image.begin() + block * bs);
        return true;
    }
    bool Flush() override { return true; }
    Bytes image;
    std::uint32_t bs;
};

struct Fixture
{
    std::uint32_t bs;
    Bytes image;
    AppleCheckpointView checkpoint;
    VerificationScope scope;
    std::vector<AppleCheckpointView> generations;
    std::vector<std::uint64_t> payload_blocks{220};

    explicit Fixture(std::uint32_t block_size = 4096, std::uint64_t next_xid = 21) : bs(block_size)
    {
        BuilderStore spec;
        spec.block_size = bs; spec.block_count = 512; spec.xid = 20; spec.next_xid = next_xid;
        spec.authoritative_internal_pool_blocks = 32; spec.authoritative_checkpoint_ring_blocks = 32;
        spec.volumes[0].uuid_hex = std::string(32, 'b');
        spec.volumes[0].additional_file_system_allocated_blocks = 1;
        spec.authoritative_seeded_main_blocks.emplace_back(220, Bytes(bs, std::byte{0x42}));
        AppleInodeRecord root; root.object_id = root.private_id = root.parent_id = 2;
        root.children_or_links = 1; root.mode = 0040755;
        AppleInodeRecord file; file.object_id = file.private_id = 30; file.parent_id = 2;
        file.children_or_links = 1; file.mode = 0100644; file.uncompressed_size = bs;
        AppleExtendedField stream{8, 0, Bytes(40)};
        PutU64LE(stream.data, 0, bs); PutU64LE(stream.data, 8, bs);
        file.extended_fields.push_back(stream);
        AppleDirectoryRecord entry; entry.parent_id = 2; entry.file_id = 30;
        entry.flags = 8; entry.name_utf8 = "history.bin";
        Record drec; std::string error;
        Check(EncodeAppleDirectoryRecord(entry, drec, error), "fixture directory: " + error);
        auto& records = spec.volumes[0].filesystem_records;
        records = {Encode(root, EncodeAppleInodeRecord), Encode(file, EncodeAppleInodeRecord), drec,
            Encode(AppleDataStreamIdRecord{30, 1}, EncodeAppleDataStreamIdRecord),
            Encode(AppleFileExtentRecord{30, 0, bs, 220, 0, bs}, EncodeAppleFileExtentRecord)};
        Check(SortAppleBtreeRecords(records, AppleBtreeKeyOrder::FileSystemCaseSensitive, error), error);
        spec.volumes[0].extentref_records = {
            Encode(ApplePhysicalExtentRecord{220, 1, kApplePhysicalExtentKindNew, 30, 1}, EncodeApplePhysicalExtentRecord)};
        image = BuildAuthoritativeStoreImage(spec);
        Edit(4, [](auto& bytes) { PutU64LE(bytes, 0xB8, 1); PutU64LE(bytes, 0xC0, 1); });
        scope.source_identity = "verifier-history-memory-image";
        scope.exact = {0, image.size(), std::string(32, 'a'), std::string(32, 'b'), 101, 20};
        Reload();
        generations.push_back(checkpoint);
    }
    void Put(std::uint64_t block, const Bytes& bytes)
    {
        Check(bytes.size() == bs && block < image.size() / bs, "fixture block write bounded");
        std::copy(bytes.begin(), bytes.end(), image.begin() + block * bs);
    }
    void Edit(std::uint64_t block, const std::function<void(Bytes&)>& mutate, bool checksum = true)
    {
        Check(block < image.size() / bs, "fixture edit bounded");
        Bytes bytes(image.begin() + block * bs, image.begin() + (block + 1) * bs);
        mutate(bytes); if (checksum) FletcherForBlock(bytes, bs);
        Put(block, bytes);
    }
    void Reload()
    {
        VectorRandomAccessSource source(image); std::string error;
        auto loaded = LoadAppleCheckpointView(source, 0, image.size(), error);
        Check(loaded.has_value(), "fixture checkpoint: " + error);
        checkpoint = std::move(*loaded);
        scope.exact.checkpoint_xid = checkpoint.container.superblock.xid;
    }
    template<class Publication> void Publish(const Publication& publication)
    {
        MemoryTarget target(image, bs); std::string error;
        Check(ExecuteAppleCheckpointPublication(target, publication, error), "fixture publication: " + error);
        image = std::move(target.image); Reload(); generations.push_back(checkpoint);
    }
    void Cow(bool snapshots, std::vector<std::uint64_t> pins = {})
    {
        VectorRandomAccessSource source(image); std::string error;
        AppleVolumeTransactionRequest request; request.volume_object_id = 101;
        request.required_checkpoint_xids = std::move(pins);
        Check(ReadAppleVolumeFileSystemRecords(source, checkpoint.container, checkpoint.volumes[0],
            request.filesystem_records, error), "fixture live records: " + error);
        for (const auto& record : request.filesystem_records)
            if (ReadU64LE(record.key, 0).value_or(0) >> 60 == 8)
            {
                AppleFileExtentRecord extent;
                Check(DecodeAppleFileExtentRecord(record, bs, extent, error), "fixture payload decode: " + error);
                request.released_data_blocks.push_back({extent.physical_block, extent.length_bytes / bs});
            }
        std::erase_if(request.filesystem_records,
            [](const auto& record) { return ReadU64LE(record.key, 0).value_or(0) >> 60 == 8; });
        request.data_writes.push_back({30, 0, 0, Bytes(bs, std::byte{0x53})});
        AppleVolumeTransactionPlan plan;
        const bool planned = snapshots ? PlanAppleSnapshotLiveTransaction(source, checkpoint, request, plan, error)
            : PlanAppleVolumeTransaction(source, checkpoint, request, plan, error);
        Check(planned, "fixture live COW: " + error);
        Publish(plan.commit.publication);
        VectorRandomAccessSource after(image); std::vector<Record> records;
        Check(ReadAppleVolumeFileSystemRecords(after, checkpoint.container, checkpoint.volumes[0], records, error), error);
        for (const auto& record : records)
            if (ReadU64LE(record.key, 0).value_or(0) >> 60 == 8)
            {
                AppleFileExtentRecord extent;
                Check(DecodeAppleFileExtentRecord(record, bs, extent, error), error);
                payload_blocks.push_back(extent.physical_block);
            }
    }
    ApfsSnapshotIdentity Create(const std::string& name, std::vector<std::uint64_t> pins = {})
    {
        VectorRandomAccessSource source(image); std::string error;
        AppleSnapshotCreateRequest request; request.volume_object_id = 101;
        request.name_utf8 = name; request.creation_time_ns = checkpoint.container.superblock.next_xid;
        request.required_checkpoint_xids = std::move(pins);
        AppleSnapshotCreatePlan plan;
        Check(PlanAppleSnapshotCreate(source, checkpoint, request, plan, error), "fixture snapshot create: " + error);
        Publish(plan.commit.publication); return plan.identity;
    }
    void DeleteOldest()
    {
        VectorRandomAccessSource source(image); std::string error;
        AppleSnapshotRetentionView retained;
        Check(LoadAppleSnapshotRetention(source, checkpoint, retained, error) && retained.identities.size() == 2,
            "fixture delete inventory: " + error);
        AppleSnapshotDeleteRequest request; request.expected = retained.identities.front();
        request.modification_time_ns = checkpoint.container.superblock.next_xid;
        AppleSnapshotDeletePlan plan;
        Check(PlanAppleSnapshotDelete(source, checkpoint, request, plan, error), "fixture snapshot delete: " + error);
        Check(plan.released_payload_blocks == 0, "hidden payload retained on oldest deletion");
        Publish(plan.commit.publication);
    }
};

void Contract(const VerificationReport& report, bool requested)
{
    Check(!report.whole_volume_verified && !report.payload_content_hashes_verified, "no broad success claim");
    for (const auto check : {VerificationCheck::CompleteAllocationAccounting,
        VerificationCheck::HistoricalReachability, VerificationCheck::PayloadContentHashes})
        Check(!Coverage(report, check).implemented && Coverage(report, check).state == VerificationCheckState::Unproven,
            "full coverage remains unproven");
    for (const auto check : {VerificationCheck::Crypto, VerificationCheck::Fusion})
        Check(Coverage(report, check).state == VerificationCheckState::Unsupported, "encrypted and Fusion admission unchanged");
    const auto rows = std::count_if(report.coverage.begin(), report.coverage.end(), [](const auto& row) {
        return row.check == VerificationCheck::RequestedHistoryOwnership;
    });
    Check(rows == (requested ? 1 : 0), "history row exists only on opt-in");
    if (requested)
    {
        Check(Coverage(report, VerificationCheck::RequestedHistoryOwnership).implemented &&
            Coverage(report, VerificationCheck::RequestedHistoryOwnership).required, "history check implemented and required");
        Check(report.requested_history.has_value() == (report.outcome == VerificationOutcome::Complete), "atomic history result");
        Check((Coverage(report, VerificationCheck::RequestedHistoryOwnership).state == VerificationCheckState::Verified) ==
            (report.outcome == VerificationOutcome::Complete), "no partially verified history row");
        Check(report.repair.plan_id.starts_with("apfs-verifier-refusal-history-v1|"), "distinct history refusal encoding");
    }
    else Check(!report.requested_history && report.repair.plan_id.starts_with("apfs-verifier-refusal-v1|"), "legacy report contract");
    if (report.outcome != VerificationOutcome::Complete)
        Check(!report.allocation_census && !report.covered_filesystem_records && !report.covered_physical_extents,
            "failure clears census and counts");
    for (const auto& finding : report.findings)
        if (finding.check == VerificationCheck::RequestedHistoryOwnership)
            Check(finding.code != VerificationCode::AllocatedCountUnderstated &&
                finding.code != VerificationCode::MetadataOwnerConflict &&
                finding.code != VerificationCode::VolumeFileCountInconsistent &&
                finding.code != VerificationCode::SnapshotAccountingUnsupported, "history findings use generic codes");
}
VerificationReport Verify(const Fixture& fixture, const VerificationScope& scope)
{
    const auto before = fixture.image;
    TracedSource source(fixture.image);
    auto report = ApfsVerifier::Verify(source, scope);
    Check(fixture.image == before, "verification preserves bytes");
    Check(report.source_reads == source.reads.size(), "exact source read accounting");
    for (const auto block : fixture.payload_blocks)
        for (const auto& [offset, size] : source.reads)
            Check(offset + size <= block * fixture.bs || offset >= (block + 1) * fixture.bs,
                "protected history observes no payload content");
    Contract(report, scope.retained_from_xid.has_value());
    return report;
}
std::set<std::uint64_t> Blocks(const std::vector<VerificationBlockRange>& ranges, std::uint64_t limit)
{
    std::set<std::uint64_t> blocks;
    std::uint64_t end = 0; bool first = true;
    for (const auto& range : ranges)
    {
        Check(range.block_count && range.physical_block < limit && range.block_count <= limit - range.physical_block,
            "protected range within geometry");
        Check(first || range.physical_block > end, "ranges sorted, disjoint and adjacency merged");
        first = false; end = range.physical_block + range.block_count;
        for (auto block = range.physical_block; block < end; ++block) blocks.insert(block);
    }
    return blocks;
}
void Complete(const Fixture& fixture, const VerificationReport& report, const std::vector<std::uint64_t>& chain)
{
    Check(report.outcome == VerificationOutcome::Complete, "history complete: " + Detail(report));
    Check(report.selected && report.allocation_census && report.requested_history, "complete result fields");
    const auto& history = *report.requested_history;
    Check(history.endpoint == *report.selected && history.endpoint.exact == fixture.scope.exact, "exact latest endpoint");
    Check(history.from_xid == chain.front() && history.chain_xids == chain, "actual next-XID chain including endpoint");
    Check(history.checkpoints.size() + 1 == chain.size(), "one historical entry per chain prefix XID");
    for (std::size_t i = 0; i < history.checkpoints.size(); ++i)
    {
        const auto& entry = history.checkpoints[i];
        Check(entry.checkpoint_xid == chain[i] && !entry.metadata_ranges.empty(), "historical metadata present");
        const auto metadata = Blocks(entry.metadata_ranges, fixture.image.size() / fixture.bs);
        const auto payload = Blocks(entry.payload_ranges, fixture.image.size() / fixture.bs);
        for (const auto block : payload) Check(!metadata.contains(block), "per-view metadata and payload disjoint");
    }
    Check(report.repair.refusal == ApfsRepairRefusal::NoIndependentReconstructionEvidence, "completed proof has no repair authority");
}
void HistoryFailure(const Fixture& fixture, std::optional<VerificationCode> code = {}, const char* exact_detail = nullptr)
{
    auto legacy = fixture.scope; legacy.retained_from_xid.reset();
    const auto current = Verify(fixture, legacy);
    Check(current.outcome == VerificationOutcome::Complete, "corrupt control current subset completes: " + Detail(current));
    const auto report = Verify(fixture, fixture.scope);
    Check(report.outcome != VerificationOutcome::Complete, "history must fail");
    Check(report.selected == current.selected, "history corruption preserves current endpoint");
    Check(Coverage(report, VerificationCheck::SharedSpaceAndQuota).state == VerificationCheckState::Verified,
        "all current mandatory checks precede history failure");
    if (code) Check(Has(report, *code), "expected history finding: " + Detail(report));
    if (exact_detail) Check(std::any_of(report.findings.begin(), report.findings.end(), [&](const auto& finding) {
        return finding.check == VerificationCheck::RequestedHistoryOwnership && finding.detail == exact_detail;
    }), "exact retained ownership corruption: " + Detail(report));
    Check(std::any_of(report.findings.begin(), report.findings.end(), [](const auto& finding) {
        return finding.check == VerificationCheck::RequestedHistoryOwnership || finding.check == VerificationCheck::Fusion ||
            finding.check == VerificationCheck::Crypto;
    }), "failure belongs to requested history or explicit feature admission");
    const auto repeat = Verify(fixture, fixture.scope);
    Check(report.findings == repeat.findings && report.coverage == repeat.coverage && report.repair == repeat.repair,
        "deterministic history failure");
}
Fixture Ordinary(std::uint32_t bs = 4096)
{
    Fixture fixture(bs, 30);
    fixture.Cow(false, {20}); fixture.Cow(false, {20});
    fixture.scope.retained_from_xid = 20;
    return fixture;
}
void BreakNextLink(Fixture& fixture)
{
    const auto block = fixture.generations.front().container.superblock_physical_block;
    fixture.Edit(block, [](auto& bytes) { PutU64LE(bytes, 0x60, 29); });
}

void OrdinaryTests()
{
    for (const auto bs : {4096u, 8192u})
    {
        auto fixture = Ordinary(bs);
        const auto report = Verify(fixture, fixture.scope);
        Complete(fixture, report, {20, 30, 31});
        const auto& old = report.requested_history->checkpoints;
        Check(Blocks(old[0].payload_ranges, 512) == std::set<std::uint64_t>{220}, "original payload exact union");
        Check(Blocks(old[1].payload_ranges, 512) == std::set<std::uint64_t>{fixture.payload_blocks[1]}, "next payload exact union");
        for (std::size_t i = 0; i < old.size(); ++i)
        {
            const auto metadata = Blocks(old[i].metadata_ranges, 512);
            Check(metadata.contains(fixture.generations[i].volumes[0].superblock_object.physical_block) &&
                metadata.contains(fixture.generations[i].volumes[0].root_tree.physical_block), "known old roots protected");
        }
        const auto repeat = Verify(fixture, fixture.scope);
        Check(report.requested_history == repeat.requested_history && report.repair == repeat.repair, "deterministic complete history");
        auto shorter = fixture.scope; shorter.retained_from_xid = 30;
        const auto short_report = Verify(fixture, shorter);
        Complete(fixture, short_report, {30, 31});
        Check(short_report.repair.plan_id != report.repair.plan_id, "start XID bound into refusal plan");
        auto legacy = fixture.scope; legacy.retained_from_xid.reset();
        const auto current = Verify(fixture, legacy);
        Check(current.outcome == VerificationOutcome::Complete, "default current verification complete");
        Check(current.allocation_census == report.allocation_census && current.selected == report.selected,
            "history leaves current census and endpoint unchanged");
        Check(current.source_reads < report.source_reads, "history performs additional source authentication");
        if (bs == 4096)
        {
            Bytes framed(2 * bs, std::byte{0xA5});
            framed.insert(framed.end(), fixture.image.begin(), fixture.image.end());
            framed.resize(framed.size() + bs, std::byte{0xA5});
            auto scope = fixture.scope; scope.exact.store_offset_bytes = 2 * bs;
            TracedSource window(framed);
            const auto nested = ApfsVerifier::Verify(window, scope);
            Contract(nested, true);
            Check(nested.outcome == VerificationOutcome::Complete && nested.requested_history && nested.selected,
                "history in exact parent source window: " + Detail(nested));
            Check(nested.requested_history->endpoint.exact == scope.exact &&
                nested.requested_history->endpoint == *nested.selected &&
                nested.requested_history->checkpoints == report.requested_history->checkpoints,
                "endpoint binds source window; protected ranges remain container relative");
            for (const auto& [offset, size] : window.reads)
                Check(offset >= scope.exact.store_offset_bytes &&
                    offset + size <= scope.exact.store_offset_bytes + scope.exact.store_size_bytes,
                    "history source reads stay in the exact window");
        }
        Pass("ordinary actual nonconsecutive chain " + std::to_string(bs));
    }
}

void SnapshotTests()
{
    Fixture fixture;
    const auto first = fixture.Create("older"); fixture.Cow(true);
    const auto second = fixture.Create("newer", {21}); fixture.Cow(true, {21});
    fixture.scope.retained_from_xid = 23;
    const auto shared = Verify(fixture, fixture.scope);
    Complete(fixture, shared, {23, 24});
    const auto metadata = Blocks(shared.requested_history->checkpoints[0].metadata_ranges, 512);
    Check(metadata.contains(first.superblock_physical_block) && metadata.contains(second.superblock_physical_block),
        "snapshot descriptors protected in pinned view");
    Check(Blocks(shared.requested_history->checkpoints[0].payload_ranges, 512) ==
        std::set<std::uint64_t>{220, fixture.payload_blocks[1]}, "shared snapshot/live payload counted once per view");
    Pass("snapshot-bearing recovery chain with shared payload");

    // Save the authenticated descriptor before it leaves the visible inventory.
    VectorRandomAccessSource source(fixture.image); std::string error;
    std::vector<AppleSnapshotRecord> snapshots;
    Check(LoadAppleSnapshotRecords(source, fixture.checkpoint, 101, snapshots, error), error);
    const auto hidden = snapshots.front().volume;
    fixture.DeleteOldest(); fixture.Create("after-delete", {25});
    fixture.scope.retained_from_xid = 25;
    VectorRandomAccessSource deleted(fixture.image);
    AppleSnapshotCatalogRecords visible;
    Check(LoadAppleSnapshotCatalog(deleted, fixture.checkpoint, 101, visible, error), "visible catalog: " + error);
    Check(std::find(visible.metadata_blocks.begin(), visible.metadata_blocks.end(), hidden.superblock_object.physical_block) ==
        visible.metadata_blocks.end(), "deleted descriptor absent from visible inventory census");
    const auto complete = Verify(fixture, fixture.scope);
    Complete(fixture, complete, {25, 26});
    Check(Blocks(complete.requested_history->checkpoints[0].metadata_ranges, 512).contains(hidden.superblock_object.physical_block),
        "hidden historical descriptor included in protected closure");
    Check(Blocks(complete.requested_history->checkpoints[0].payload_ranges, 512).contains(220), "hidden historical payload protected");
    Pass("hidden descriptor retained through inventory deletion");

    Check(hidden.extentref_tree.has_value(), "hidden extent root exists");
    const auto root = *hidden.extentref_tree;
    Check(std::find(visible.metadata_blocks.begin(), visible.metadata_blocks.end(), root.physical_block) ==
        visible.metadata_blocks.end(), "hidden extent root outside visible catalog");
    std::vector<Record> refs; std::vector<std::uint64_t> nodes;
    Check(ReadAppleSnapshotTree(deleted, fixture.bs, root, hidden.object_map, root.xid,
        fixture.checkpoint.container.superblock.xid, refs, nodes, error) && refs.size() == 1, "hidden extent decode: " + error);
    ApplePhysicalExtentRecord extent;
    Check(DecodeApplePhysicalExtentRecord(refs.front(), extent, error), error);
    ++extent.reference_count; refs.front() = Encode(extent, EncodeApplePhysicalExtentRecord);
    AppleBtreeOptions options; options.block_size = fixture.bs; options.xid = root.xid;
    options.root_object_id = root.object_id; options.root_physical_block = root.physical_block;
    options.storage_type = kObjectPhysical; options.subtype = kObjectTypeBlockRefTree;
    options.tree_flags = kAppleBtreePhysical; options.key_order = AppleBtreeKeyOrder::PhysicalExtent; options.max_nodes = 1;
    AppleSerializedBtree tree;
    Check(SerializeAppleBtree(refs, options, tree, error) && tree.objects.size() == 1, "hidden forged tree: " + error);
    fixture.Put(root.physical_block, tree.objects.front().bytes);
    HistoryFailure(fixture, VerificationCode::StructuralInconsistency, "AppleVolumePhysicalExtentRefcountMismatch");
    Pass("checksum-valid hidden descriptor payload reference corruption");
}

void RetimestampQueue(Fixture& fixture)
{
    auto queue = fixture.checkpoint.spaceman.free_queues[1];
    const auto candidate = fixture.generations.front().volumes[0].superblock_object.physical_block;
    bool allocated = false;
    for (const auto& chunk : fixture.checkpoint.spaceman.chunks)
        if (candidate >= chunk.start_block && candidate - chunk.start_block < chunk.block_count)
        {
            const auto bit = candidate - chunk.start_block;
            allocated = (std::to_integer<unsigned>(chunk.allocation_bitmap[bit / 8]) & (1u << (bit % 8))) != 0;
        }
    Check(allocated, "retimestamp control has the final allocation bit set");
    bool changed = false;
    for (auto& entry : queue.entries)
        if (candidate >= entry.physical_block && candidate - entry.physical_block < entry.block_count)
        {
            Check(entry.xid == 30, "old metadata queued at original retirement XID");
            entry.xid = 31; changed = true;
        }
    Check(changed, "queue forgery targets an actual retained owner");
    std::sort(queue.entries.begin(), queue.entries.end(), [](const auto& a, const auto& b) {
        return std::tie(a.xid, a.physical_block) < std::tie(b.xid, b.physical_block);
    });
    std::vector<Record> records;
    for (const auto& entry : queue.entries)
    {
        Record record; record.key.resize(16);
        PutU64LE(record.key, 0, entry.xid); PutU64LE(record.key, 8, entry.physical_block);
        if (entry.block_count != 1) { record.value.resize(8); PutU64LE(record.value, 0, entry.block_count); }
        records.push_back(std::move(record));
    }
    AppleBtreeOptions options; options.block_size = fixture.bs; options.xid = queue.root.xid;
    options.root_object_id = queue.tree_oid; options.root_physical_block = queue.root.physical_block;
    options.storage_type = kObjectEphemeral; options.subtype = kObjectTypeSpacemanFreeQueue;
    options.tree_flags = queue.tree_flags; options.fixed_key_size = queue.fixed_key_size;
    options.fixed_value_size = queue.fixed_value_size; options.key_order = AppleBtreeKeyOrder::SpacemanFreeQueue;
    options.minimum_longest_key = queue.longest_key; options.minimum_longest_value = queue.longest_value; options.max_nodes = 1;
    AppleSerializedBtree tree; std::string error;
    Check(SerializeAppleBtree(records, options, tree, error) && tree.objects.size() == 1, "forged queue tree: " + error);
    fixture.Put(queue.root.physical_block, tree.objects.front().bytes);
    fixture.Edit(fixture.checkpoint.spaceman.object.physical_block,
        [&](auto& bytes) { PutU64LE(bytes, 0xD8 + 0x28, queue.entries.front().xid); });
}

void CorruptionTests()
{
    const auto control = Ordinary();
    {
        auto fixture = control; BreakNextLink(fixture);
        HistoryFailure(fixture, VerificationCode::CheckpointUnavailable);
        Pass("missing next-XID link with intact current endpoint");
    }
    {
        auto fixture = control;
        fixture.Edit(fixture.generations.front().volumes[0].root_tree.physical_block,
            [](auto& bytes) { bytes.back() ^= std::byte{1}; }, false);
        HistoryFailure(fixture);
        Pass("historical tree checksum corruption");
    }
    {
        auto fixture = control;
        fixture.Edit(fixture.generations.front().volumes[0].superblock_object.physical_block,
            [](auto& bytes) { bytes[0xF0] ^= std::byte{1}; });
        HistoryFailure(fixture, VerificationCode::IdentityMismatch);
        Pass("historical selected volume UUID mismatch");
    }
    {
        auto fixture = control; RetimestampQueue(fixture);
        HistoryFailure(fixture, VerificationCode::CheckpointUnavailable);
        Pass("allocated final bits cannot hide retirement queue retimestamp");
    }
    for (const auto from : {0ull, 31ull, 32ull})
    {
        auto scope = control.scope; scope.retained_from_xid = from;
        const auto report = Verify(control, scope);
        Check(report.outcome == VerificationOutcome::Refused && Has(report, VerificationCode::InvalidScope), "invalid start refuses");
        Check(report.source_reads == 0, "invalid start rejected before source reads");
    }
    auto stale = control.scope; stale.exact.checkpoint_xid = 30;
    const auto stale_report = Verify(control, stale);
    Check(stale_report.outcome == VerificationOutcome::Refused && Has(stale_report, VerificationCode::IdentityMismatch),
        "older exact endpoint cannot fall back");
    auto wrong = control.scope; wrong.exact.volume_uuid_hex = std::string(32, 'c');
    Check(Has(Verify(control, wrong), VerificationCode::IdentityMismatch), "endpoint volume identity enforced");
    Pass("scope start and exact latest identity admission");

    // These API-only broad requests must clear even an otherwise valid history.
    for (const bool whole : {false, true})
    {
        auto scope = control.scope;
        scope.require_whole_volume = whole; scope.require_payload_content_hashes = !whole;
        const auto report = Verify(control, scope);
        Check(Has(report, VerificationCode::CoverageMissing), "late broad coverage refusal");
        Check(Coverage(report, VerificationCheck::SharedSpaceAndQuota).state == VerificationCheckState::Verified,
            "late failure follows current checks");
        Check(report.source_reads == Verify(control, control.scope).source_reads, "history proof precedes late broad refusal");
    }
    Pass("late coverage failure clears completed local history");

    {
        auto fixture = control;
        fixture.Edit(fixture.generations.front().container.superblock_physical_block,
            [](auto& bytes) { PutU64LE(bytes, 0x40, ReadU64LE(bytes, 0x40).value_or(0) | 0x100); });
        const auto report = Verify(fixture, fixture.scope);
        Check(report.outcome != VerificationOutcome::Complete, "historical Fusion never admitted");
        for (const auto& finding : report.findings)
            if (finding.code == VerificationCode::FusionUnsupported)
                Check(report.outcome == VerificationOutcome::Refused && finding.severity == VerificationSeverity::Warning &&
                    Coverage(report, finding.check).state == VerificationCheckState::Unsupported, "Fusion protocol classification");
        // Also exercise the common handler without depending on how the exact
        // historical checkpoint loader reports an unsupported candidate.
        fixture = control;
        fixture.Edit(fixture.checkpoint.container.superblock_physical_block,
            [](auto& bytes) { PutU64LE(bytes, 0x40, ReadU64LE(bytes, 0x40).value_or(0) | 0x100); });
        const auto current = Verify(fixture, fixture.scope);
        Check(Has(current, VerificationCode::FusionUnsupported) && current.outcome == VerificationOutcome::Refused,
            "Fusion code 20 always refuses");
        for (const auto& finding : current.findings)
            if (finding.code == VerificationCode::FusionUnsupported)
                Check(finding.severity == VerificationSeverity::Warning &&
                    Coverage(current, finding.check).state == VerificationCheckState::Unsupported, "Fusion warning/unsupported pair");
        Pass("Fusion failure retains protocol refusal classification");
    }
}

void BudgetTests()
{
    auto fixture = Ordinary();
    TracedSource source(fixture.image);
    const auto control = ApfsVerifier::Verify(source, fixture.scope);
    Complete(fixture, control, {20, 30, 31});
    const auto consumed = control.read_budget->Consumed();
    auto legacy = fixture.scope; legacy.retained_from_xid.reset();
    const auto current = Verify(fixture, legacy);
    Check(consumed.records > current.read_budget->Consumed().records &&
        consumed.record_bytes > current.read_budget->Consumed().record_bytes, "history materialization charged");
    for (unsigned dimension = 0; dimension < 4; ++dimension)
    {
        auto scope = fixture.scope;
        if (dimension == 0) scope.max_reads = consumed.reads - 1;
        if (dimension == 1) scope.max_read_bytes = consumed.read_bytes - 1;
        if (dimension == 2) scope.max_records = consumed.records - 1;
        if (dimension == 3) scope.max_record_bytes = consumed.record_bytes - 1;
        const auto report = Verify(fixture, scope);
        Check(Has(report, VerificationCode::BudgetExceeded), "history shares every budget dimension");
        Check(Coverage(report, VerificationCheck::SharedSpaceAndQuota).state == VerificationCheckState::Verified,
            "budget exhausted after current admission");
    }
    Pass("cumulative history read and materialization budgets");

    auto budget = std::make_shared<ApfsReadBudget>(consumed.reads, fixture.scope.max_read_bytes,
        fixture.scope.max_records, fixture.scope.max_record_bytes);
    Check(budget->Read(fixture.bs), "simulate earlier caller work");
    TracedSource raw(fixture.image); BudgetedRandomAccessSource limited(raw, budget);
    const auto first = ApfsVerifier::Verify(limited, fixture.scope);
    Contract(first, true);
    Check(first.read_budget == budget && budget->Failed() && Has(first, VerificationCode::BudgetExceeded),
        "caller allowance preserved rather than reset");
    const auto reads = raw.reads.size();
    const auto retry = ApfsVerifier::Verify(limited, fixture.scope);
    Contract(retry, true);
    Check(Has(retry, VerificationCode::BudgetExceeded) && raw.reads.size() == reads, "sticky budget prevents cached retry success");
    Pass("preconsumed caller budget remains sticky across retry");

    for (const bool short_read : {false, true})
    {
        TracedSource late(fixture.image); late.fail_at = source.reads.size(); late.short_read = short_read;
        const auto report = ApfsVerifier::Verify(late, fixture.scope);
        Contract(report, true);
        Check(Has(report, VerificationCode::ReadFailure), "late backing failure reported");
        Check(Coverage(report, VerificationCheck::SharedSpaceAndQuota).state == VerificationCheckState::Verified,
            "late I/O failure follows current checks");
        Check(report.findings.front().failed_source_offset_bytes == source.reads.back().first, "exact late I/O offset");
    }
    TracedSource changed(fixture.image); changed.change_at = source.reads.size();
    const auto report = ApfsVerifier::Verify(changed, fixture.scope);
    Contract(report, true);
    Check(report.outcome != VerificationOutcome::Complete && !Has(report, VerificationCode::ReadFailure),
        "late changed source bytes invalidate cached ownership");
    Pass("late failure and final source revalidation clear output");
}

void ExportFixtures(const std::filesystem::path& directory)
{
    const auto drive = directory.root_name().wstring();
    Check(directory.is_absolute() && (drive == L"D:" || drive == L"d:"), "fixture export requires an absolute D: directory");
    Check(!std::filesystem::exists(directory), "fixture export directory already exists; evidence preserved");
    auto positive = Ordinary();
    const auto report = Verify(positive, positive.scope);
    Complete(positive, report, {20, 30, 31});
    auto corrupt = positive; BreakNextLink(corrupt);
    HistoryFailure(corrupt, VerificationCode::CheckpointUnavailable);
    Check(std::filesystem::create_directory(directory), "cannot create fresh fixture export directory");
    const auto write = [&](const char* name, const Bytes& bytes) {
        std::ofstream stream(directory / name, std::ios::binary | std::ios::out);
        stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        stream.close(); Check(static_cast<bool>(stream), "fixture image export failed");
    };
    write("ordinary-retained.apfs", positive.image);
    write("history-corrupt.apfs", corrupt.image);
    const auto& exact = positive.scope.exact;
    std::ofstream manifest(directory / "manifest.json", std::ios::binary | std::ios::out);
    manifest << "{\n  \"format\": \"apfs-verifier-history-fixtures-v1\",\n"
        << "  \"sourceIdentity\": \"" << positive.scope.source_identity << "\",\n"
        << "  \"storeOffsetBytes\": " << exact.store_offset_bytes << ",\n"
        << "  \"storeSizeBytes\": " << exact.store_size_bytes << ",\n"
        << "  \"containerUuid\": \"" << exact.container_uuid_hex << "\",\n"
        << "  \"volumeUuid\": \"" << exact.volume_uuid_hex << "\",\n"
        << "  \"volumeOid\": " << exact.volume_oid << ",\n"
        << "  \"fromXid\": 20,\n  \"endpointXid\": " << exact.checkpoint_xid << ",\n"
        << "  \"chainXids\": [20, 30, 31],\n"
        << "  \"positiveImage\": \"ordinary-retained.apfs\",\n"
        << "  \"corruptImage\": \"history-corrupt.apfs\",\n"
        << "  \"corruption\": \"Checkpoint 20 next_xid changed from 30 to absent 29; checksum recomputed\",\n"
        << "  \"currentEndpointUnchanged\": true,\n  \"positiveNativeOutcome\": 1,\n"
        << "  \"corruptNativeCode\": 5\n}\n";
    manifest.close(); Check(static_cast<bool>(manifest), "fixture manifest export failed");
    Pass("exported verified native image fixtures to " + directory.string());
}
}

int main(int argc, char** argv)
{
    try
    {
        std::string group = "all"; std::optional<std::filesystem::path> export_directory;
        for (int i = 1; i < argc; ++i)
        {
            const std::string option = argv[i];
            if (option == "--group" && i + 1 < argc) group = argv[++i];
            else if (option == "--emit-fixtures" && i + 1 < argc && !export_directory) export_directory = argv[++i];
            else throw std::runtime_error("usage: VerifierHistoryTests [--group all|ordinary|snapshot|corrupt|budget] [--emit-fixtures ABSOLUTE_D_DIR]");
        }
        Check(group == "all" || group == "ordinary" || group == "snapshot" || group == "corrupt" || group == "budget", "unknown group");
        if (group == "all" || group == "ordinary") OrdinaryTests();
        if (group == "all" || group == "snapshot") SnapshotTests();
        if (group == "all" || group == "corrupt") CorruptionTests();
        if (group == "all" || group == "budget") BudgetTests();
        if (export_directory) ExportFixtures(*export_directory);
        std::cout << "PASS " << cases << " cases, " << checks << " checks\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
