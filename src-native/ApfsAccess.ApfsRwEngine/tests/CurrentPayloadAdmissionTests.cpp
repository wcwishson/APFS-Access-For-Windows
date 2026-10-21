#include "AppleVolumeTransaction.h"
#include "ApfsExtendedRecordCodec.h"
#include "TestFixtureBuilder.h"
#include "../src/SnapshotPlanningSource.h"

#include <algorithm>
#include <functional>
#include <iostream>
#include <limits>
#include <set>
#include <stdexcept>
#include <string_view>

using namespace apfsaccess::catalog;
using namespace apfsaccess::rw;
using namespace apfsaccess::testfixture;
using Record = apfsaccess::catalog::BtreeRecord;
using Bytes = std::vector<std::byte>;

namespace {
constexpr std::uint32_t bs = 4096;
unsigned checks = 0, cases = 0;
void Check(bool value, const std::string& message) {
    ++checks;
    if (!value) throw std::runtime_error(message);
}
template<class T, class F> Record Encode(const T& value, F encode) {
    Record record; std::string error;
    Check(encode(value, record, error), "fixture encode: " + error);
    return record;
}
void Pass(const std::string& name) { ++cases; std::cout << "PASS " << name << '\n'; }

class MemoryTarget final : public AppleCheckpointWriteTarget {
public:
    explicit MemoryTarget(const Bytes& bytes) : image(bytes) {}
    bool ReadBlock(std::uint64_t block, std::uint32_t size, Bytes& out) override {
        if (size != bs || block >= image.size() / bs) return false;
        out.assign(image.begin() + block * bs, image.begin() + (block + 1) * bs);
        return true;
    }
    bool WriteBlock(std::uint64_t block, std::span<const std::byte> bytes) override {
        if (bytes.size() != bs || block >= image.size() / bs) return false;
        ++writes;
        std::copy(bytes.begin(), bytes.end(), image.begin() + block * bs);
        return true;
    }
    bool Flush() override { ++flushes; return true; }
    Bytes image;
    unsigned writes = 0, flushes = 0;
};

class TracedSource final : public RandomAccessSource {
public:
    explicit TracedSource(const Bytes& bytes) : image(bytes) {}
    std::uint64_t SizeBytes() const override { return image.size(); }
    bool Read(std::uint64_t offset, std::size_t size, Bytes& out) const override {
        out.clear(); reads.emplace_back(offset, size);
        if (reads.size() == fail_at) return false;
        if (offset > image.size() || size > image.size() - offset) return false;
        out.assign(image.begin() + offset, image.begin() + offset + size);
        if (reads.size() == change_at && !out.empty()) out.front() ^= std::byte{1};
        if (after_read) after_read(offset, size);
        return true;
    }
    const Bytes& image;
    mutable std::vector<std::pair<std::uint64_t, std::size_t>> reads;
    std::size_t fail_at = 0, change_at = 0;
    std::function<void(std::uint64_t, std::size_t)> after_read;
};

struct Fixture {
    Bytes image;
    AppleCheckpointView checkpoint;
    explicit Fixture(std::size_t peers = 1) {
        BuilderStore spec;
        spec.block_count = 1024; spec.xid = 20;
        spec.authoritative_checkpoint_ring_blocks = 32;
        spec.authoritative_internal_pool_blocks = 64;
        spec.volumes.resize(peers);
        for (std::size_t i = 0; i < peers; ++i) {
            auto& volume = spec.volumes[i];
            volume.oid = 101 + i; volume.uuid_hex = std::string(32, static_cast<char>('b' + i));
            const auto payload = 256 + i * 32;
            volume.additional_file_system_allocated_blocks = 4;
            volume.filesystem_records = Records(payload);
            volume.extentref_records = {Encode(ApplePhysicalExtentRecord{
                payload, 4, kApplePhysicalExtentKindNew, 31, 1}, EncodeApplePhysicalExtentRecord)};
            for (std::uint64_t b = payload; b < payload + 4; ++b)
                spec.authoritative_seeded_main_blocks.emplace_back(b, Bytes(bs, std::byte{0x63}));
        }
        image = BuildAuthoritativeStoreImage(spec);
        Reload();
        for (const auto& volume : checkpoint.volumes)
            Edit(volume.superblock_object.physical_block, [](auto& bytes) {
                PutU64LE(bytes, 0xB8, 2); PutU64LE(bytes, 0xC0, 1);
            });
        Reload();
    }
    static std::vector<Record> Records(std::uint64_t payload) {
        AppleInodeRecord root;
        root.object_id = root.private_id = root.parent_id = 2;
        root.mode = 0040755; root.children_or_links = 2;
        std::vector<Record> records{Encode(root, EncodeAppleInodeRecord)};
        for (const auto id : {30ull, 31ull}) {
            const bool sparse = id == 30;
            AppleInodeRecord file;
            file.object_id = file.private_id = id; file.parent_id = 2;
            file.mode = 0100644; file.children_or_links = 1;
            file.uncompressed_size = 4ull * bs;
            file.internal_flags = sparse ? kAppleInodeSparseFlag : 0;
            AppleExtendedField stream{8, 0, Bytes(40)};
            PutU64LE(stream.data, 0, 4ull * bs); PutU64LE(stream.data, 8, sparse ? 0 : 4ull * bs);
            file.extended_fields.push_back(stream);
            if (sparse) {
                AppleExtendedField holes{kAppleInodeSparseBytesField, 0, Bytes(8)};
                PutU64LE(holes.data, 0, 4ull * bs); file.extended_fields.push_back(holes);
            }
            records.push_back(Encode(file, EncodeAppleInodeRecord));
            AppleDirectoryRecord directory;
            directory.parent_id = 2; directory.file_id = id; directory.flags = 8;
            directory.name_utf8 = sparse ? "all-hole" : "bystander";
            Record encoded; std::string error;
            Check(EncodeAppleDirectoryRecord(directory, encoded, error), error);
            records.push_back(encoded);
            records.push_back(Encode(AppleDataStreamIdRecord{id, 1}, EncodeAppleDataStreamIdRecord));
        }
        records.push_back(Encode(AppleFileExtentRecord{31, 0, 4ull * bs, payload, 0, bs}, EncodeAppleFileExtentRecord));
        std::string error;
        Check(SortAppleBtreeRecords(records, AppleBtreeKeyOrder::FileSystemCaseSensitive, error), error);
        return records;
    }
    void Edit(std::uint64_t block, const std::function<void(Bytes&)>& edit, bool checksum = true) {
        Check(block < image.size() / bs, "bounded fixture block");
        Bytes bytes(image.begin() + block * bs, image.begin() + (block + 1) * bs);
        edit(bytes); if (checksum) FletcherForBlock(bytes, bs);
        std::copy(bytes.begin(), bytes.end(), image.begin() + block * bs);
    }
    void Reload() {
        VectorRandomAccessSource source(image); std::string error;
        auto view = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        Check(view.has_value(), "strict fixture checkpoint: " + error);
        checkpoint = std::move(*view);
    }
    void RemapBystander(std::size_t peer, std::uint64_t payload) {
        const auto& volume = checkpoint.volumes.at(peer);
        const auto write_tree = [&](const AppleObjectLocation& location, const std::vector<Record>& records) {
            std::vector<Bytes> keys, values;
            for (const auto& record : records) { keys.push_back(record.key); values.push_back(record.value); }
            const auto bytes = BuildRawLeafNode(keys, values, location.xid, bs, 0,
                location.object_id, location.type, location.subtype);
            Edit(location.physical_block, [&](auto& b) { b = bytes; });
        };
        write_tree(volume.root_tree, Records(payload));
        write_tree(*volume.extentref_tree, {Encode(ApplePhysicalExtentRecord{
            payload, 4, kApplePhysicalExtentKindNew, 31, 1}, EncodeApplePhysicalExtentRecord)});
        Reload();
    }
    AppleVolumeTransactionRequest Request(bool pin) const {
        VectorRandomAccessSource source(image); std::string error;
        AppleVolumeTransactionRequest request; request.volume_object_id = 101;
        if (pin) request.required_checkpoint_xids = {checkpoint.container.superblock.xid};
        Check(ReadAppleVolumeFileSystemRecords(source, checkpoint.container, checkpoint.volumes[0],
            request.filesystem_records, error), "read selected records: " + error);
        // An atime edit of an all-hole file has no release that could incidentally
        // catch an unrelated invalid physical extent in the allocator.
        for (auto& record : request.filesystem_records) {
            if (ReadU64LE(record.key, 0).value_or(0) != ((3ull << 60) | 30)) continue;
            AppleInodeRecord inode;
            Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), error);
            ++inode.access_time;
            Check(EncodeAppleInodeRecord(inode, record, error), error);
        }
        return request;
    }
    void Publish(const AppleCheckpointPublicationPlan& plan) {
        MemoryTarget target(image); std::string error;
        Check(ExecuteAppleCheckpointPublication(target, plan, error), "fixture publication: " + error);
        image = std::move(target.image); Reload();
    }
    void CowBystander() {
        auto request = Request(true);
        for (const auto& record : request.filesystem_records) {
            if (ReadU64LE(record.key, 0).value_or(0) >> 60 != 8) continue;
            AppleFileExtentRecord extent; std::string error;
            Check(DecodeAppleFileExtentRecord(record, bs, extent, error), error);
            request.released_data_blocks.push_back({extent.physical_block, extent.length_bytes / bs});
        }
        std::erase_if(request.filesystem_records, [](const auto& r) { return ReadU64LE(r.key, 0).value_or(0) >> 60 == 8; });
        request.data_writes.push_back({31, 0, 0, Bytes(4 * bs, std::byte{0x75})});
        VectorRandomAccessSource source(image); AppleVolumeTransactionPlan plan; std::string error;
        Check(PlanAppleVolumeTransaction(source, checkpoint, request, plan, error), "fixture canonical COW: " + error);
        Publish(plan.commit.publication);
    }
    AppleTransactionCommitRequest CommitRequest() const {
        AppleSpacemanAllocationRequest allocation;
        const auto& nx = checkpoint.container.superblock;
        allocation.expected_checkpoint_xid = nx.xid; allocation.transaction_xid = nx.next_xid;
        allocation.oldest_required_checkpoint_xid = nx.xid; allocation.first_ephemeral_object_id = nx.next_oid;
        allocation.main_block_count = 1;
        AppleTransactionCommitRequest request; std::string error;
        Check(PlanAppleSpacemanAllocation(checkpoint.spaceman, allocation, request.allocation_plan, error), error);
        request.next_object_id = nx.next_oid + 32;
        request.required_checkpoint_xids = {nx.xid};
        request.allocated_main_writes.push_back({request.allocation_plan.allocated_main_blocks.at(0), Bytes(bs, std::byte{0x42})});
        return request;
    }
};

bool Empty(const AppleVolumeTransactionPlan& plan) {
    const auto& p = plan.commit.publication;
    return p.block_size == 0 && p.expected_checkpoint_xid == 0 && p.transaction_xid == 0 &&
        p.before_superblock_writes.empty() && p.guard_blocks.empty() && p.superblock_write.bytes.empty() &&
        p.published_checkpoint.superblock_bytes.empty() && plan.allocation.updated_spaceman.bytes.empty() &&
        plan.payload_blocks.empty() && plan.filesystem_records.empty();
}

void Admission(bool invalid, bool peer, bool pin) {
    Fixture fixture(peer ? 2 : 1);
    if (invalid) fixture.RemapBystander(peer ? 1 : 0, fixture.checkpoint.spaceman.internal_pool.base_block + 29);
    const auto before = fixture.image;
    const auto request = fixture.Request(pin);
    Check(request.data_writes.empty() && request.released_data_blocks.empty(), "no touched physical payload or releases");
    VectorRandomAccessSource source(fixture.image); std::string error;
    AppleVolumeTransactionPlan plan;
    plan.commit.publication.superblock_write.bytes = {std::byte{1}};
    plan.payload_blocks = {999};
    const bool planned = PlanAppleVolumeTransaction(source, fixture.checkpoint, request, plan, error);
    const auto planning_error = error;
    MemoryTarget target(fixture.image);
    const bool published = planned && ExecuteAppleCheckpointPublication(target, plan.commit.publication, error);
    std::uint64_t xid = 0;
    VectorRandomAccessSource after(target.image); std::string reopen_error;
    if (const auto cp = LoadAppleCheckpointView(after, 0, after.SizeBytes(), reopen_error)) xid = cp->container.superblock.xid;
    std::cout << "ADMISSION invalid=" << invalid << " peer=" << peer << " currentPin=" << pin
              << " planned=" << planned << " published=" << published << " xid=" << xid
              << " writes=" << target.writes << " flushes=" << target.flushes
              << " planningError=" << planning_error << " publicationError=" << error << '\n';
    Check(fixture.image == before, "planner preserves source bytes");
    if (invalid) {
        Check(!planned, "invalid untouched payload escaped as executable publication");
        Check(!planning_error.empty() && Empty(plan), "refusal clears every output");
        Check(!published && target.writes == 0 && target.flushes == 0 && target.image == before && xid == 20,
            "invalid preimage refused before any write or flush");
    } else {
        Check(planned && published && xid == 21 && target.writes > 0 && target.flushes > 0,
            "valid ordinary atime publication: " + planning_error + " / " + error);
        const auto block = peer ? 288 : 256;
        Check(std::equal(before.begin() + block * bs, before.begin() + (block + 4) * bs,
            target.image.begin() + block * bs), "untouched bystander payload preserved");
    }
    Pass(std::string(invalid ? "reject" : "publish") + (peer ? " sibling" : " selected") + (pin ? " current pin" : " no pins"));
}

void Refuse(Fixture& fixture, const std::string& label) {
    const auto before = fixture.image;
    VectorRandomAccessSource source(fixture.image); std::string error;
    AppleVolumeTransactionPlan plan;
    plan.commit.publication.superblock_write.bytes = {std::byte{1}};
    plan.payload_blocks = {999};
    const auto request = fixture.Request(true);
    const bool planned = PlanAppleVolumeTransaction(source, fixture.checkpoint, request, plan, error);
    std::cout << "REFUSAL " << label << " planned=" << planned << " error=" << error << '\n';
    Check(!planned && Empty(plan), label + " rejects and clears output: " + error);
    Check(error == "AppleSnapshotRetirementOwnershipUnproven" ||
        error == "AppleSnapshotRetirementPayloadMetadataOverlap" ||
        error == "AppleSnapshotRetirementCrossOwnerOverlap", "precise owner refusal: " + error);
    MemoryTarget target(fixture.image);
    Check(!ExecuteAppleCheckpointPublication(target, plan.commit.publication, error) &&
        target.writes == 0 && target.flushes == 0 && target.image == before && fixture.image == before,
        "refused output cannot write or flush");
    Pass(label);
}

void GeometryTests() {
    for (const bool peer : {false, true}) {
        for (const std::string_view kind : {"descriptor-ring", "data-ring", "bitmap-pool", "allocator-metadata", "filesystem-metadata", "unallocated"}) {
            Fixture fixture(peer ? 2 : 1);
            const auto& nx = fixture.checkpoint.container.superblock;
            const auto& sm = fixture.checkpoint.spaceman;
            const auto block = kind == "descriptor-ring" ? nx.xp_desc_base_block :
                kind == "data-ring" ? nx.xp_data_base_block :
                kind == "bitmap-pool" ? sm.internal_pool.bitmap_base_block :
                kind == "allocator-metadata" ? sm.chunks.front().bitmap_block :
                kind == "filesystem-metadata" ? fixture.checkpoint.volumes[0].root_tree.physical_block : 800;
            fixture.RemapBystander(peer ? 1 : 0, block);
            Refuse(fixture, std::string(peer ? "sibling " : "selected ") + std::string(kind));
        }
    }
    {
        Fixture fixture(2); fixture.RemapBystander(1, 256);
        Refuse(fixture, "cross-volume payload overlap");
    }
    {
        Fixture fixture; fixture.CowBystander();
        const auto& entries = fixture.checkpoint.spaceman.free_queues[1].entries;
        Check(std::any_of(entries.begin(), entries.end(), [](const auto& e) {
            return e.physical_block <= 256 && 256 - e.physical_block < e.block_count;
        }), "canonical allocator queued old bystander");
        fixture.RemapBystander(0, 256);
        const auto& chunk = fixture.checkpoint.spaceman.chunks.front();
        const auto bit = 256 - chunk.start_block;
        Check((std::to_integer<unsigned>(chunk.allocation_bitmap.at(bit / 8)) & (1u << (bit % 8))) != 0,
            "queued negative still has allocated bits");
        Refuse(fixture, "allocated but queued current payload");
    }
}

bool Empty(const AppleTransactionCommitPlan& plan) {
    const auto& p = plan.publication;
    return p.block_size == 0 && p.expected_checkpoint_xid == 0 && p.transaction_xid == 0 &&
        p.guard_blocks.empty() && p.before_superblock_writes.empty() && p.superblock_write.bytes.empty() &&
        p.published_checkpoint.superblock_bytes.empty();
}

void GuardTests() {
    Fixture fixture(2); const auto request = fixture.CommitRequest();
    TracedSource trace(fixture.image); std::string error; AppleTransactionCommitPlan plan;
    Check(PlanAppleTransactionCommit(trace, fixture.checkpoint, request, plan, error), "guard baseline: " + error);
    std::set<std::uint64_t> guards;
    for (const auto& guard : plan.publication.guard_blocks) {
        Check(guards.insert(guard.physical_block).second && guard.bytes.size() == bs &&
            std::equal(guard.bytes.begin(), guard.bytes.end(), fixture.image.begin() + guard.physical_block * bs),
            "indexed guards retain exact source bytes and unique block identities");
    }
    const auto sibling = fixture.checkpoint.volumes[1].root_tree.physical_block;
    for (const auto block : {sibling, fixture.checkpoint.volumes[1].extentref_tree->physical_block}) {
        Check(std::any_of(plan.publication.guard_blocks.begin(), plan.publication.guard_blocks.end(),
            [&](const auto& g) { return g.physical_block == block; }), "untouched sibling tree is guarded");
        MemoryTarget target(fixture.image);
        target.image.at(block * bs + 100) ^= std::byte{1};
        const auto before = target.image;
        Check(!ExecuteAppleCheckpointPublication(target, plan.publication, error) && error == "AppleCheckpointGuardChanged" &&
            target.writes == 0 && target.flushes == 0 && target.image == before, "peer drift refuses before writes");
    }
    Pass("publication guards bind untouched peer filesystem and reference trees");
    for (const bool unreadable : {false, true}) {
        TracedSource changed(fixture.image);
        if (unreadable) changed.fail_at = trace.reads.size();
        else changed.change_at = trace.reads.size();
        AppleTransactionCommitPlan output = plan;
        Check(!PlanAppleTransactionCommit(changed, fixture.checkpoint, request, output, error) && Empty(output),
            "late source failure clears previously populated plan: " + error);
        Check(changed.reads.size() >= trace.reads.size(), "late failure occurs at final observed read");
        MemoryTarget target(fixture.image);
        Check(!ExecuteAppleCheckpointPublication(target, output.publication, error) && target.writes == 0 && target.flushes == 0,
            "late-failure output has no write authority");
        Pass(unreadable ? "late unreadable dependency" : "late changed dependency");
    }
    {
        auto budget = std::make_shared<ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
        TracedSource raw(fixture.image); BudgetedRandomAccessSource bounded(raw, budget);
        SnapshotPlanningSource observed(bounded); std::vector<AppleRecoveryCheckpointView> owners;
        const bool primed = LoadAppleSnapshotRecoveryCheckpoints(observed, fixture.checkpoint,
            {fixture.checkpoint.container.superblock.xid}, owners, error);
        Check(primed, "prime complete owner evidence: " + error);
        const bool dependency_read = std::any_of(raw.reads.begin(), raw.reads.end(), [&](const auto& read) {
            return read.first <= sibling * bs && read.first + read.second >= (sibling + 1) * bs;
        });
        Check(dependency_read, "completed proof observed the current sibling root block");
        Bytes before, after;
        Check(raw.Read(sibling * bs, bs, before), "read actual backing dependency before mutation");
        auto records = Fixture::Records(288);
        for (auto& record : records) if (ReadU64LE(record.key, 0).value_or(0) == ((3ull << 60) | 30)) {
            AppleInodeRecord inode;
            Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), error);
            ++inode.access_time;
            Check(EncodeAppleInodeRecord(inode, record, error), error);
        }
        std::vector<Bytes> keys, values;
        for (const auto& record : records) { keys.push_back(record.key); values.push_back(record.value); }
        const auto& root = fixture.checkpoint.volumes[1].root_tree;
        fixture.Edit(sibling, [&](auto& bytes) {
            bytes = BuildRawLeafNode(keys, values, root.xid, bs, 0, root.object_id, root.type, root.subtype);
        });
        const bool backing_read = raw.Read(sibling * bs, bs, after);
        const bool backing_changed = backing_read && before != after;
        const bool valid_checksum = backing_read && VerifyObjectChecksum(after, bs);
        Check(backing_changed && valid_checksum, "actual reference-backed metadata changed with a valid checksum");
        auto output = plan;
        const bool planned = PlanAppleTransactionCommit(observed, fixture.checkpoint, request, output, error);
        const bool output_empty = Empty(output);
        const bool budget_failed = budget->Failed();
        const std::string budget_failure = budget->Failure();
        std::cout << "CACHED_OWNER dependencyRead=" << dependency_read << " backingRead=" << backing_read
                  << " backingChanged=" << backing_changed << " validChecksum=" << valid_checksum
                  << " planned=" << planned << " outputEmpty=" << output_empty
                  << " budgetFailed=" << budget_failed << " budgetFailure=" << budget_failure
                  << " error=" << error << '\n';
        Check(!planned && output_empty && budget_failed && budget_failure == "AppleSnapshotPlanningSourceChanged" &&
            error == budget_failure,
            "completed cached proof cannot authorize changed source: " + error);
        MemoryTarget target(fixture.image);
        const auto mutated = target.image;
        const bool published = ExecuteAppleCheckpointPublication(target, output.publication, error);
        Check(!published && target.writes == 0 && target.flushes == 0 && target.image == mutated,
            "cached-proof refusal cannot write or flush");
        Pass("cached complete-owner evidence rejects dependency mutation");
    }
}

void BudgetTests() {
    Fixture fixture(2); const auto request = fixture.CommitRequest();
    TracedSource trace(fixture.image);
    auto budget = std::make_shared<ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
    BudgetedRandomAccessSource source(trace, budget); AppleTransactionCommitPlan plan; std::string error;
    Check(PlanAppleTransactionCommit(source, fixture.checkpoint, request, plan, error), "shared budget baseline: " + error);
    const auto used = budget->Consumed();
    Check(used.reads == trace.reads.size() && used.reads > 1, "shared budget counts each original transport read");
    Check(used.reads < 309 && used.read_bytes < 2441632, "ordinary commit improves the pinned B7 read floor");
    std::cout << "CURRENT_OWNER_BUDGET reads=" << used.reads << " bytes=" << used.read_bytes
              << " records=" << used.records << " materialized=" << used.record_bytes << '\n';
    for (unsigned dimension = 0; dimension < 4; ++dimension) {
        auto cap = std::make_shared<ApfsReadBudget>(dimension == 0 ? used.reads - 1 : 65536,
            dimension == 1 ? used.read_bytes - 1 : 256ull << 20,
            dimension == 2 ? used.records - 1 : 1000000,
            dimension == 3 ? used.record_bytes - 1 : 256ull << 20);
        TracedSource raw(fixture.image); BudgetedRandomAccessSource limited(raw, cap);
        auto output = plan;
        Check(!PlanAppleTransactionCommit(limited, fixture.checkpoint, request, output, error) && Empty(output) && cap->Failed() &&
            error == cap->Failure(), "one-less shared allowance refuses atomically: " + error);
        const auto failed_reads = raw.reads.size(); const auto failure = error;
        output = plan;
        Check(!PlanAppleTransactionCommit(limited, fixture.checkpoint, request, output, error) && Empty(output) &&
            error == failure && raw.reads.size() == failed_reads, "retry preserves sticky failure and performs no reads");
        Pass("shared budget dimension " + std::to_string(dimension));
    }
    {
        auto cap = std::make_shared<ApfsReadBudget>(used.reads, 256ull << 20, 1000000, 256ull << 20);
        Check(cap->Read(0), "preconsume caller allowance");
        TracedSource raw(fixture.image); BudgetedRandomAccessSource limited(raw, cap); auto output = plan;
        Check(!PlanAppleTransactionCommit(limited, fixture.checkpoint, request, output, error) && Empty(output) && cap->Failed(),
            "preconsumed allowance is not reset");
        Check(cap->Consumed().reads == raw.reads.size() + 1, "preconsumption remains charged");
        Pass("preconsumed caller allowance");
    }
}

void SnapshotTests() {
    Fixture fixture(2); std::string error;
    {
        VectorRandomAccessSource source(fixture.image);
        AppleSnapshotCreateRequest request{101, "admission-control", 1700000000000000000ull};
        AppleSnapshotCreatePlan plan;
        Check(PlanAppleSnapshotCreate(source, fixture.checkpoint, request, plan, error), "public snapshot create: " + error);
        fixture.Publish(plan.commit.publication);
    }
    AppleSnapshotRetentionView before;
    {
        VectorRandomAccessSource source(fixture.image);
        Check(LoadAppleSnapshotRetention(source, fixture.checkpoint, before, error) && before.identities.size() == 1,
            "created snapshot is public: " + error);
    }
    for (const bool sibling : {false, true}) {
        VectorRandomAccessSource source(fixture.image); auto request = fixture.Request(true);
        if (sibling) {
            request.volume_object_id = 102;
            Check(ReadAppleVolumeFileSystemRecords(source, fixture.checkpoint.container, fixture.checkpoint.volumes[1],
                request.filesystem_records, error), error);
            for (auto& r : request.filesystem_records) if (ReadU64LE(r.key, 0).value_or(0) == ((3ull << 60) | 30)) {
                AppleInodeRecord inode;
                Check(ApfsExtendedRecordCodec::DecodeInode(r, inode, error), error); ++inode.access_time;
                Check(EncodeAppleInodeRecord(inode, r, error), error);
            }
        }
        AppleVolumeTransactionPlan plan;
        const bool planned = sibling ? PlanAppleSnapshotSiblingTransaction(source, fixture.checkpoint, request, plan, error)
            : PlanAppleSnapshotLiveTransaction(source, fixture.checkpoint, request, plan, error);
        Check(planned, "snapshot-aware atime: " + error); fixture.Publish(plan.commit.publication);
        VectorRandomAccessSource after(fixture.image); AppleSnapshotRetentionView retained;
        Check(LoadAppleSnapshotRetention(after, fixture.checkpoint, retained, error) && retained.identities.size() == 1 &&
            retained.identities[0].snapshot_xid == before.identities[0].snapshot_xid,
            "same public snapshot retained: " + error);
        Pass(sibling ? "public snapshot sibling publication preserved" : "public snapshot live publication preserved");
    }
}

Bytes ChangedSiblingRoot(const Fixture& fixture) {
    auto records = Fixture::Records(288); std::string error;
    for (auto& record : records) if (ReadU64LE(record.key, 0).value_or(0) == ((3ull << 60) | 30)) {
        AppleInodeRecord inode;
        Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), error);
        ++inode.access_time;
        Check(EncodeAppleInodeRecord(inode, record, error), error);
    }
    std::vector<Bytes> keys, values;
    for (const auto& record : records) { keys.push_back(record.key); values.push_back(record.value); }
    const auto& root = fixture.checkpoint.volumes[1].root_tree;
    return BuildRawLeafNode(keys, values, root.xid, bs, 0, root.object_id, root.type, root.subtype);
}

void PrimeOwners(const SnapshotPlanningSource& source, const Fixture& fixture) {
    std::string error; std::vector<AppleRecoveryCheckpointView> owners;
    const bool primed = LoadAppleSnapshotRecoveryCheckpoints(source, fixture.checkpoint,
        {fixture.checkpoint.container.superblock.xid}, owners, error);
    Check(primed, "prime complete current owner evidence: " + error);
}

void PublicBorrowRefuses(SnapshotPlanningSource& source, const Fixture& fixture, const std::string& label) {
    std::vector<std::uint64_t> metadata{999};
    std::vector<ApplePhysicalExtentRecord> payload{{999, 1, kApplePhysicalExtentKindNew, 1, 1}};
    std::string error;
    const bool loaded = LoadAppleSnapshotCheckpointOwners(source, fixture.checkpoint, metadata, payload, error);
    const auto budget = source.ReadBudget();
    std::cout << "PUBLIC_BORROW " << label << " loaded=" << loaded << " metadata=" << metadata.size()
              << " payload=" << payload.size() << " sticky=" << budget->Failed() << " error=" << error << '\n';
    Check(!loaded && metadata.empty() && payload.empty() && budget->Failed() &&
        error == "AppleSnapshotPlanningSourceChanged", "public proof borrower revalidates: " + label + ": " + error);
}

void BatchTests() {
    {
        Fixture fixture(2); TracedSource raw(fixture.image);
        auto budget = std::make_shared<ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
        BudgetedRandomAccessSource bounded(raw, budget); SnapshotPlanningSource observed(bounded);
        PrimeOwners(observed, fixture);
        for (unsigned attempt = 0; attempt < 2; ++attempt) {
            const auto start = raw.reads.size(); std::string error;
            std::vector<std::uint64_t> metadata; std::vector<ApplePhysicalExtentRecord> payload;
            const bool loaded = LoadAppleSnapshotCheckpointOwners(observed, fixture.checkpoint, metadata, payload, error);
            Check(loaded && !metadata.empty() && !payload.empty() && raw.reads.size() > start,
                "repeated public completed-proof calls still read original dependencies: " + error);
        }
        const auto changed = ChangedSiblingRoot(fixture);
        fixture.Edit(fixture.checkpoint.volumes[1].root_tree.physical_block, [&](auto& b) { b = changed; });
        PublicBorrowRefuses(observed, fixture, "outside ordinary commit");
        Pass("repeated public borrowers retain uncached source validation");
    }
    for (const bool exception : {false, true}) {
        Fixture fixture(2); auto request = fixture.CommitRequest(); TracedSource raw(fixture.image);
        auto budget = std::make_shared<ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
        BudgetedRandomAccessSource bounded(raw, budget); SnapshotPlanningSource observed(bounded);
        PrimeOwners(observed, fixture); std::string error;
        const auto verify_start = raw.reads.size();
        Check(observed.VerifyUnchanged(error), "measure entry verification");
        const auto verify_reads = raw.reads.size() - verify_start;
        bool injected = false;
        const auto trigger = raw.reads.size() + verify_reads + 1;
        if (exception) raw.after_read = [&](auto, auto) {
            if (raw.reads.size() == trigger) { injected = true; throw std::runtime_error("injected admission read exception"); }
        };
        else ++request.allocation_plan.expected_checkpoint_xid;
        AppleTransactionCommitPlan output; output.publication.superblock_write.bytes = {std::byte{1}};
        bool planned = false, threw = false;
        try { planned = PlanAppleTransactionCommit(observed, fixture.checkpoint, request, output, error); }
        catch (const std::runtime_error& e) { threw = std::string_view(e.what()) == "injected admission read exception"; }
        raw.after_read = {};
        std::cout << "BATCH_UNWIND exception=" << exception << " injected=" << injected << " threw=" << threw
                  << " planned=" << planned << " empty=" << Empty(output) << " error=" << error << '\n';
        Check(!planned && Empty(output) && threw == exception && injected == exception && !budget->Failed(),
            "failed or exceptional operation leaves empty output and reusable observation");
        const auto changed = ChangedSiblingRoot(fixture);
        fixture.Edit(fixture.checkpoint.volumes[1].root_tree.physical_block, [&](auto& b) { b = changed; });
        PublicBorrowRefuses(observed, fixture, exception ? "after exception" : "after failure");
        Pass(exception ? "batch scope restored after transport exception" : "batch scope restored after planner refusal");
    }
    for (const std::string_view kind : {"persistent", "aba-conflict", "aba-restored", "final-exception"}) {
        Fixture fixture(2); const auto original = fixture.image; const auto request = fixture.CommitRequest();
        TracedSource raw(fixture.image);
        auto budget = std::make_shared<ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
        BudgetedRandomAccessSource bounded(raw, budget); SnapshotPlanningSource observed(bounded);
        PrimeOwners(observed, fixture); std::string error; AppleTransactionCommitPlan plan;
        bool planned = PlanAppleTransactionCommit(observed, fixture.checkpoint, request, plan, error);
        Check(planned, "warm complete ordinary proof: " + error);
        const auto warm_start = raw.reads.size();
        planned = PlanAppleTransactionCommit(observed, fixture.checkpoint, request, plan, error);
        Check(planned, "repeat complete ordinary proof: " + error);
        const auto operation_reads = raw.reads.size() - warm_start;
        const auto verify_start = raw.reads.size();
        Check(observed.VerifyUnchanged(error), "measure mandatory final dependency sweep");
        const auto final_reads = raw.reads.size() - verify_start;
        Check(final_reads > 0 && operation_reads > final_reads, "bounded final sweep follows planning reads");
        const auto sibling = fixture.checkpoint.volumes[1].root_tree.physical_block;
        const Bytes before(original.begin() + sibling * bs, original.begin() + (sibling + 1) * bs);
        const auto changed = ChangedSiblingRoot(fixture);
        Check(before != changed && VerifyObjectChecksum(changed, bs), "valid changed current metadata control");
        std::size_t changed_offset = 8;
        while (changed_offset < bs && before[changed_offset] == changed[changed_offset]) ++changed_offset;
        Check(changed_offset < bs, "change includes inode metadata beyond checksum");
        const auto trigger = raw.reads.size() + operation_reads - final_reads + (kind == "final-exception" ? 1 : 0);
        bool injected = false, sampled = false;
        raw.after_read = [&](auto, auto) {
            if (injected || raw.reads.size() != trigger) return;
            injected = true;
            if (kind == "final-exception") throw std::runtime_error("injected final validation exception");
            fixture.Edit(sibling, [&](auto& b) { b = changed; });
            if (kind == "aba-conflict") {
                Bytes byte;
                sampled = observed.Read(sibling * bs + changed_offset, 1, byte) && byte.size() == 1 && byte[0] == changed[changed_offset];
                Check(sampled, "capture new overlapping observation during mutation");
            }
            if (kind != "persistent") fixture.Edit(sibling, [&](auto& b) { b = before; });
        };
        auto output = plan; bool threw = false;
        try { planned = PlanAppleTransactionCommit(observed, fixture.checkpoint, request, output, error); }
        catch (const std::runtime_error& e) { planned = false; threw = std::string_view(e.what()) == "injected final validation exception"; }
        raw.after_read = {};
        const bool restored = fixture.image == original;
        std::cout << "BATCH_FINAL kind=" << kind << " injected=" << injected << " sampled=" << sampled
                  << " restored=" << restored << " planned=" << planned << " empty=" << Empty(output)
                  << " threw=" << threw << " sticky=" << budget->Failed() << " error=" << error << '\n';
        Check(injected && sampled == (kind == "aba-conflict") && threw == (kind == "final-exception"), "injection reaches intended operation boundary");
        MemoryTarget target(fixture.image);
        if (kind == "aba-restored") {
            Check(planned && restored && !budget->Failed(), "restored source agrees with every captured observation");
            const bool published = ExecuteAppleCheckpointPublication(target, output.publication, error);
            Check(published && target.writes > 0, "fully restored coherent proof can publish: " + error);
        } else {
            Check(!planned && Empty(output), "no executable plan escapes failed final capture");
            if (kind != "final-exception") Check(budget->Failed() && error == "AppleSnapshotPlanningSourceChanged",
                "mixed or changed final dependency set is refused");
            const bool published = ExecuteAppleCheckpointPublication(target, output.publication, error);
            Check(!published && target.writes == 0 && target.flushes == 0, "final refusal carries no write authority");
            if (kind == "final-exception") {
                fixture.Edit(sibling, [&](auto& b) { b = changed; });
                PublicBorrowRefuses(observed, fixture, "after final validation exception");
            }
        }
        Pass("operation final capture " + std::string(kind));
    }
}
}

int main(int argc, char** argv) {
    try {
        std::string_view group = "all";
        if (argc == 3 && std::string_view(argv[1]) == "--group") group = argv[2];
        else Check(argc == 1, "usage: --group all|red|positive|geometry|guards|budget|snapshots|batch");
        Check(group == "all" || group == "red" || group == "positive" || group == "geometry" ||
            group == "guards" || group == "budget" || group == "snapshots" || group == "batch", "known group");
        if (group == "all" || group == "positive")
            for (const bool peer : {false, true}) for (const bool pin : {false, true}) Admission(false, peer, pin);
        if (group == "all" || group == "red")
            for (const bool peer : {false, true}) for (const bool pin : {false, true}) Admission(true, peer, pin);
        if (group == "all" || group == "geometry") GeometryTests();
        if (group == "all" || group == "guards") GuardTests();
        if (group == "all" || group == "budget") BudgetTests();
        if (group == "all" || group == "snapshots") SnapshotTests();
        if (group == "all" || group == "batch") BatchTests();
        std::cout << "PASS cases=" << cases << " checks=" << checks << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << " cases=" << cases << " checks=" << checks << '\n';
        return 1;
    }
}
