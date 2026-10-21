#define APPLE_CLONE_TEST_HELPERS_ONLY
#include "AppleCloneCowTests.cpp"
#include "MetadataStore.h"
#include "../src/PlainExtentCoalescing.h"
#include <bcrypt.h>

namespace {
using Store = MetadataStore;
using Bytes = std::vector<std::byte>;
constexpr std::size_t SpanBlocks = 2048;
BuilderStore LargePlainSpec() {
    auto spec = CloneSpec(1);
    spec.block_count = 8192;
    auto& v = spec.volumes.front();
    v.additional_file_system_allocated_blocks = SpanBlocks;
    for (auto& record : v.filesystem_records) {
        std::string error;
        if (Type(record) == 3 && Id(record) == 17) {
            AppleInodeRecord inode;
            Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), error);
            inode.uncompressed_size = SpanBlocks * kBlockSize;
            PutU64LE(inode.extended_fields.front().data, 0, inode.uncompressed_size);
            PutU64LE(inode.extended_fields.front().data, 8, inode.uncompressed_size);
            Check(EncodeAppleInodeRecord(inode, record, error), error);
        }
        if (Type(record) == 8) PutU64LE(record.value, 0, SpanBlocks * kBlockSize);
    }
    PutU64LE(v.extentref_records.front().value, 0, (1ull << 60) | SpanBlocks);
    spec.authoritative_seeded_main_blocks.clear();
    for (std::size_t b = 0; b < SpanBlocks; ++b) {
        Bytes bytes(kBlockSize);
        for (std::size_t i = 0; i < bytes.size(); ++i) bytes[i] = std::byte((i * 13 + b * 47) % 251);
        spec.authoritative_seeded_main_blocks.push_back({kShared + b, std::move(bytes)});
    }
    return spec;
}
std::array<unsigned char, 32> Hash(const Bytes& bytes) {
    std::array<unsigned char, 32> digest{};
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    Check(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0, "SHA256 provider");
    const auto status = BCryptHash(algorithm, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())), static_cast<ULONG>(bytes.size()), digest.data(), 32);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    Check(status >= 0, "independent cold payload digest");
    return digest;
}
void SaveImage(const std::filesystem::path& path, const Bytes& bytes) {
    Check(!std::filesystem::exists(path), "fresh owned image");
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    Check(out.good(), "save generated image");
}
void DirtyBlockCase() {
    Fixture fixture(LargePlainSpec());
    auto expected = Payload(fixture, 17);
    const auto old = expected;
    const auto path = std::filesystem::absolute("large-plain.apfs");
    SaveImage(path, fixture.image);
    Store::VolumeContext context;
    context.device_path = path.wstring(); context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    context.allow_native_snapshot_runtime = true;
    const auto original_xid = fixture.checkpoint.container.superblock.xid;
    for (const auto [offset, count] : {std::pair<std::uint64_t, std::uint64_t>{1024 * kBlockSize, kBlockSize},
        {100 * kBlockSize + 37, 113}, {101 * kBlockSize - 37, 113}, {SpanBlocks * kBlockSize - 113, 113}}) {
        std::string error;
        auto device = BlockDevice::OpenExclusiveManagementImage(path.wstring(), 0, error);
        Check(!!device, "exclusive regular image: " + error);
        Store store(context, device);
        Check(store.PrepareNativeWritePath(), "cold canonical writer");
        Store::MutationRequest request;
        request.path = L"\\clone0"; request.offset = offset; request.length = count;
        Store::PayloadIdentity identity;
        Check(store.StageMutation(request, &identity) == Store::MutationStatus::Applied, "partial ordinary write stages");
        std::fill_n(expected.begin() + offset, count, std::byte{0x9a});
        std::uint64_t supplied = 0, calls = 0;
        store.SetFilePayloadRangeProvider([&](const auto& name, auto actual, auto at, std::span<std::byte> bytes) {
            Check(name == request.path && actual.object_id == identity.object_id && actual.generation == identity.generation,
                "payload incarnation remains bound");
            ++calls; supplied += bytes.size();
            if (at > expected.size() || bytes.size() > expected.size() - at) return false;
            std::copy_n(expected.begin() + at, bytes.size(), bytes.begin()); return true;
        });
        Check(store.CheckPendingAppleCapacity({original_xid}) == Store::CommitStatus::NothingToCommit && supplied == 0,
            "capacity probe borrows no payload");
        const auto status = store.CommitCanonicalTransaction({original_xid});
        Check(status == Store::CommitStatus::Committed, "partial COW publication: " + store.LastCommitStage());
        const auto dirty_bytes = ((offset + count + kBlockSize - 1) / kBlockSize - offset / kBlockSize) * kBlockSize;
        Check(supplied == dirty_bytes && calls == 1, "only rounded dirty blocks, never the full contiguous extent");
        std::cout << "DIRTY offset=" << offset << " length=" << count << " supplied=" << supplied << " calls=" << calls << '\n';
        Bytes actual;
        Check(store.ReadCommittedFileRange(request.path, 0, expected.size(), actual) && actual == expected,
            "every byte outside overwrite preserved");
    }
    {
        std::string error;
        auto device = BlockDevice::OpenExclusiveManagementImage(path.wstring(), 0, error);
        Check(!!device, error);
        Store cold(context, device); Check(cold.PrepareNativeWritePath(), "cold reopen after both COW publications");
        Bytes actual;
        Check(cold.ReadCommittedFileRange(L"\\clone0", 0, expected.size(), actual) && Hash(actual) == Hash(expected),
            "cold full-file hash matches expected partial-block preservation");
        Bytes image; Check(device->ReadForVerification(0, fixture.image.size(), image), "read generated fixture after close");
        fixture.image = std::move(image); fixture.Reload();
        Check(Payload(fixture, 17, original_xid) == old, "retained checkpoint preserves all original payload bytes");
        CheckGraph(fixture);
    }
}

std::size_t ExtentCount(const std::vector<apfsaccess::catalog::BtreeRecord>& records) {
    return std::count_if(records.begin(), records.end(), [](const auto& record) { return Type(record) == 8; });
}
void PublishedEmptyAllocationCase() {
    for (const auto operation : {Store::MutationOperation::SetFileSize, Store::MutationOperation::SetAllocationSize}) {
        auto spec = CloneSpec(1); spec.block_count = 8192;
        Fixture fixture(spec);
        const auto path = std::filesystem::absolute(operation == Store::MutationOperation::SetFileSize ? "empty-resize.apfs" : "empty-preallocate.apfs");
        SaveImage(path, fixture.image);
        Store::VolumeContext context; context.device_path = path.wstring(); context.volume_object_id = 101;
        context.allow_native_snapshot_runtime = true; context.allow_legacy_scaffold_for_fixtures = false;
        std::uint64_t id = 0;
        {
            std::string error; auto device = BlockDevice::OpenExclusiveManagementImage(path.wstring(), 0, error);
            Check(!!device, error); Store store(context, device); Check(store.PrepareNativeWritePath(), "empty create writer");
            Store::MutationRequest create; create.operation = Store::MutationOperation::CreateFile; create.path = L"\\separate.bin";
            Check(store.StageMutation(create) == Store::MutationStatus::Applied &&
                store.CommitCanonicalTransaction() == Store::CommitStatus::Committed, "publish and close empty file independently");
            const auto inode = store.LookupCommittedInodeByPath(create.path);
            Check(inode && !inode->logical_size && !inode->allocation_size.value_or(0), "published empty source has no allocation");
            id = inode->object_id;
        }
        {
            std::string error; auto device = BlockDevice::OpenExclusiveManagementImage(path.wstring(), 0, error);
            Check(!!device, error); Store store(context, device); Check(store.PrepareNativeWritePath(), "fresh size request owner");
            Store::MutationRequest resize; resize.operation = operation; resize.path = L"\\separate.bin";
            resize.length = SpanBlocks * kBlockSize;
            resize.object_id = id; resize.generation = store.CheckpointXid().value() + 1;
            Check(store.StageMutation(resize) == Store::MutationStatus::Applied, "separate incarnation-bound size request stages");
            std::uint64_t supplied = 0;
            store.SetFilePayloadRangeProvider([&](const auto&, auto identity, auto, std::span<std::byte> bytes) {
                Check(identity.object_id == id, "new allocation owner"); supplied += bytes.size();
                std::fill(bytes.begin(), bytes.end(), std::byte{0}); return true;
            });
            Check(store.CheckPendingAppleCapacity({}) == Store::CommitStatus::NothingToCommit && supplied == 0,
                "fresh size admission has no payload reads");
            Check(store.CommitCanonicalTransaction() == Store::CommitStatus::Committed, "fresh size publication: " + store.LastCommitStage());
            Check(device->ReadForVerification(0, fixture.image.size(), fixture.image), "cold-decodable private size image");
        }
        fixture.Reload();
        const auto records = ReadTree(fixture);
        const auto count = std::count_if(records.begin(), records.end(), [&](const auto& record) { return Type(record) == 8 && Id(record) == id; });
        Check(count > 0 && count < 10, "separately published empty file allocates bounded physical runs");
        Check(Hash(Payload(fixture, id)) == Hash(Bytes(SpanBlocks * kBlockSize)), "cold entire allocation hash is zero initialized");
        CheckGraph(fixture);
        std::string error; auto device = BlockDevice::OpenExclusiveManagementImage(path.wstring(), 0, error);
        Check(!!device, error); Store cold(context, device); Check(cold.PrepareNativeWritePath(), "fresh allocated-file owner");
        const auto inode = cold.LookupCommittedInodeByPath(L"\\separate.bin");
        Check(inode && inode->allocation_size == SpanBlocks * kBlockSize &&
            inode->logical_size == (operation == Store::MutationOperation::SetFileSize ? SpanBlocks * kBlockSize : 0), "cold size and allocation remain distinct");
        std::cout << "EMPTY_ALLOCATION operation=" << static_cast<int>(operation) << " blocks=" << SpanBlocks << " runs=" << count << '\n';
    }
}
class CountedSource final : public RandomAccessSource {
public:
    explicit CountedSource(const Bytes& bytes, std::vector<std::uint64_t> payload = {}) : image(bytes), payload_blocks(std::move(payload)) {
        std::sort(payload_blocks.begin(), payload_blocks.end());
    }
    std::uint64_t SizeBytes() const override { return image.size(); }
    bool Read(std::uint64_t offset, std::size_t count, Bytes& out) const override {
        ++calls; bytes += count;
        if (offset > image.size() || count > image.size() - offset) return false;
        const auto block = std::lower_bound(payload_blocks.begin(), payload_blocks.end(), offset / kBlockSize);
        if (count && block != payload_blocks.end() && *block * kBlockSize < offset + count) ++payload_reads;
        out.assign(image.begin() + offset, image.begin() + offset + count);
        if (corrupt_call == calls && !out.empty()) out.front() ^= std::byte{1};
        return true;
    }
    mutable std::uint64_t calls = 0, bytes = 0, payload_reads = 0;
    std::uint64_t corrupt_call = 0;
    const Bytes& image;
    std::vector<std::uint64_t> payload_blocks;
};
void CountedPlannerCase() {
    auto spec = Spec(); spec.block_count = 8192;
    Fixture legacy(spec), compact(spec);
    const auto original_state = State(compact.checkpoint);
    auto request = Request(SpanBlocks);
    std::string error;
    for (auto& record : request.filesystem_records) if (Type(record) == 3 && Id(record) == 100) {
        AppleInodeRecord inode;
        Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), error);
        AppleExtendedField stream; stream.type = 8; stream.flags = 1; stream.data.resize(40);
        PutU64LE(stream.data, 0, SpanBlocks * kBlockSize); PutU64LE(stream.data, 8, SpanBlocks * kBlockSize);
        inode.extended_fields.push_back(std::move(stream));
        Check(EncodeAppleInodeRecord(inode, record, error), error);
    }
    AppleVolumeTransactionPlan old_plan, new_plan;
    CountedSource old_source(legacy.image), new_source(compact.image);
    Check(PlanAppleVolumeTransaction(old_source, legacy.checkpoint, request, old_plan, error), "legacy allocation: " + error);
    Check(PlanApplePlainCompactTransaction(new_source, compact.checkpoint, request, new_plan, error), "compact allocation: " + error);
    Check(State(compact.checkpoint) == original_state, "allocator probe leaves source bitmap/checkpoint unchanged");
    Check(old_plan.payload_blocks == new_plan.payload_blocks && old_plan.payload_blocks.size() == SpanBlocks,
        "metadata budget reduction preserves the real payload allocation prefix");
    std::size_t runs = 0;
    for (std::size_t i = 0; i < new_plan.payload_blocks.size(); ++i)
        runs += i == 0 || new_plan.payload_blocks[i] != new_plan.payload_blocks[i - 1] + 1;
    Check(ExtentCount(old_plan.filesystem_records) == SpanBlocks && ExtentCount(new_plan.filesystem_records) == runs && runs < 8,
        "new records follow actual allocation runs");
    Publish(legacy, old_plan); Publish(compact, new_plan);
    Check(Payload(legacy, 100) == request.data_writes.front().bytes && Payload(compact, 100) == request.data_writes.front().bytes,
        "both layouts cold-decode identical payloads");
    CheckGraph(legacy); CheckGraph(compact);
    const auto count_next = [&](Fixture& f, const auto& blocks) {
        AppleVolumeTransactionRequest metadata;
        metadata.volume_object_id = 101; metadata.filesystem_records = ReadTree(f);
        CountedSource source(f.image, blocks); AppleVolumeTransactionPlan result;
        Check(PlanApplePlainCompactTransaction(source, f.checkpoint, metadata, result, error), "counted next canonical plan: " + error);
        Check(source.payload_reads == 0, "canonical ownership planning never reads ordinary payload blocks");
        return std::pair{source.calls, source.bytes};
    };
    const auto old_reads = count_next(legacy, old_plan.payload_blocks), new_reads = count_next(compact, new_plan.payload_blocks);
    std::cout << "READAMP legacyCalls=" << old_reads.first << " legacyBytes=" << old_reads.second
              << " compactCalls=" << new_reads.first << " compactBytes=" << new_reads.second << " runs=" << runs << '\n';
    Check(new_reads.first * 2 < old_reads.first && new_reads.second * 2 < old_reads.second,
        "compacted on-disk metadata cuts subsequent canonical source reads by at least twofold");

    // Touch one existing legacy 4K record. Untouched mappings are validated in
    // their original shape before normalization merges their exact spans.
    AppleVolumeTransactionRequest touch; touch.volume_object_id = 101;
    for (const auto& record : ReadTree(legacy)) {
        if (Type(record) == 8 && Id(record) == 100 && ReadU64LE(record.key, 8) == 17 * kBlockSize) {
            touch.released_data_blocks.push_back({ReadU64LE(record.value, 8).value(), 1});
        } else touch.filesystem_records.push_back(record);
    }
    touch.data_writes.push_back({100, 17 * kBlockSize, 0, Bytes(kBlockSize, std::byte{0x73})});
    CountedSource touched_source(legacy.image, old_plan.payload_blocks); AppleVolumeTransactionPlan touched;
    Check(PlanApplePlainCompactTransaction(touched_source, legacy.checkpoint, touch, touched, error), "normalize touched legacy records: " + error);
    Check(touched.payload_blocks.size() == 1 && ExtentCount(touched.filesystem_records) < 10 && touched_source.payload_reads == 0,
        "one-block COW normalizes retained old 4K records without payload replay");
    Publish(legacy, touched); CheckGraph(legacy);
    auto expected = request.data_writes.front().bytes;
    std::fill_n(expected.begin() + 17 * kBlockSize, kBlockSize, std::byte{0x73});
    Check(Hash(Payload(legacy, 100)) == Hash(expected), "legacy-normalized publication cold hash");

    CountedSource guarded(compact.image);
    AppleVolumeTransactionRequest metadata; metadata.volume_object_id = 101; metadata.filesystem_records = ReadTree(compact);
    AppleVolumeTransactionPlan guard_plan;
    Check(PlanApplePlainCompactTransaction(guarded, compact.checkpoint, metadata, guard_plan, error, true),
        "host snapshot-aware mode retains source observation: " + error);
    CountedSource changed(compact.image); changed.corrupt_call = guarded.calls;
    Check(!PlanApplePlainCompactTransaction(changed, compact.checkpoint, metadata, guard_plan, error, true) && Empty(guard_plan) &&
        error == "AppleSnapshotPlanningSourceChanged", "last validation reread still rejects changed source and clears output");
    CountedSource limited_source(compact.image);
    auto budget = std::make_shared<ApfsReadBudget>(1, 256ull << 20, 1000000, 256ull << 20);
    BudgetedRandomAccessSource limited(limited_source, budget);
    Check(!PlanApplePlainCompactTransaction(limited, compact.checkpoint, metadata, guard_plan, error, true) && Empty(guard_plan) && budget->Failed(),
        "compact entry preserves caller read budget refusal");
}
void LargeRecordCase() {
    std::vector<apfsaccess::catalog::BtreeRecord> files, references;
    std::string error;
    constexpr std::uint64_t count = 65536, start = 100000;
    for (std::uint64_t i = 0; i < count; ++i) {
        apfsaccess::catalog::BtreeRecord record;
        Check(EncodeAppleFileExtentRecord({17, i * kBlockSize, kBlockSize, start + i, 0, kBlockSize}, record, error), error);
        files.push_back(record);
        Check(EncodeApplePhysicalExtentRecord({start + i, 1, kApplePhysicalExtentKindNew, 17, 1}, record, error), error);
        references.push_back(record);
    }
    Check(plain_compact::Coalesce(files, references, {17}, kBlockSize, error), "65536 records: " + error);
    Check(files.size() == 1 && references.size() == 1 && ReadU64LE(files.front().value, 0) == count * kBlockSize &&
        (ReadU64LE(references.front().value, 0).value() & ((1ull << 60) - 1)) == count, "65536 exact plain spans become one logical and physical run");
    std::cout << "RECORDS old=65536 fileRuns=" << files.size() << " referenceRuns=" << references.size() << '\n';
}
bool SamePublication(const AppleVolumeTransactionPlan& a, const AppleVolumeTransactionPlan& b) {
    const auto& x = a.commit.publication; const auto& y = b.commit.publication;
    if (a.payload_blocks != b.payload_blocks || x.superblock_write.physical_block != y.superblock_write.physical_block ||
        x.superblock_write.bytes != y.superblock_write.bytes || x.before_superblock_writes.size() != y.before_superblock_writes.size()) return false;
    for (std::size_t i = 0; i < x.before_superblock_writes.size(); ++i)
        if (x.before_superblock_writes[i].physical_block != y.before_superblock_writes[i].physical_block ||
            x.before_superblock_writes[i].bytes != y.before_superblock_writes[i].bytes) return false;
    return true;
}
void EligibilityNegatives() {
    for (unsigned fault = 0; fault < 7; ++fault) {
        auto spec = CloneSpec(fault == 0 ? 2 : 1);
        auto& volume = spec.volumes.front();
        for (auto& record : volume.filesystem_records) {
            if (fault == 1 && Type(record) == 8) PutU64LE(record.value, 16, 19);
            if (fault == 2 && Type(record) == 8) PutU64LE(record.value, 0, (1ull << 56) | (4 * kBlockSize));
            if (fault == 3 && Type(record) == 6) PutU32LE(record.value, 0, 2);
            if (fault == 4 && Type(record) == 3 && Id(record) == 17) {
                AppleInodeRecord inode; std::string error;
                Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), error);
                inode.bsd_flags |= kAppleBsdCompressedFlag;
                Check(EncodeAppleInodeRecord(inode, record, error), error);
            }
        }
        if (fault == 5) PutU32LE(volume.extentref_records.front().value, 16, 2);
        if (fault == 6) PutU64LE(volume.extentref_records.front().value, 8, 999);
        Fixture f(spec);
        AppleVolumeTransactionRequest request; request.volume_object_id = 101;
        for (const auto& record : ReadTree(f)) {
            if (Type(record) == 8 && Id(record) == 17) request.released_data_blocks.push_back({kShared, 4});
            else request.filesystem_records.push_back(record);
        }
        request.data_writes.push_back({17, 0, 0, Bytes(4 * kBlockSize, std::byte{0x71})});
        VectorRandomAccessSource source(f.image);
        AppleVolumeTransactionPlan legacy, compact;
        std::string legacy_error, compact_error;
        const auto old_ok = PlanAppleVolumeTransaction(source, f.checkpoint, request, legacy, legacy_error);
        const auto new_ok = PlanApplePlainCompactTransaction(source, f.checkpoint, request, compact, compact_error);
        Check(new_ok == old_ok && compact_error == legacy_error && SamePublication(legacy, compact),
            "shared/crypto/flags/dstream/compressed/refcount/owner keeps legacy proof and layout: " + std::to_string(fault));
        if (fault == 0) {
            Check(new_ok && compact.payload_blocks.size() == 4 && ExtentCount(compact.filesystem_records) == 5,
                "shared COW path retains per-block replacement and peer mapping");
            const auto peer = Payload(f, 18); Publish(f, compact);
            Check(Payload(f, 18) == peer, "shared peer bytes unchanged"); CheckGraph(f);
        }
    }
    auto spec = Spec(2); spec.block_count = 1024;
    Fixture snapshots(spec); std::string error;
    {
        VectorRandomAccessSource source(snapshots.image);
        AppleSnapshotCreatePlan plan;
        Check(PlanAppleSnapshotCreate(source, snapshots.checkpoint, {101, "retained", 123456789}, plan, error), "real snapshot: " + error);
        MemoryTarget target(snapshots.image);
        Check(ExecuteAppleCheckpointPublication(target, plan.commit.publication, error), error);
        snapshots.image = std::move(target.image); snapshots.Reload();
    }
    AppleVolumeTransactionRequest request; request.volume_object_id = 102;
    VectorRandomAccessSource source(snapshots.image);
    Check(ReadAppleVolumeFileSystemRecords(source, snapshots.checkpoint.container, snapshots.checkpoint.volumes[1],
        request.filesystem_records, error), error);
    AppleVolumeTransactionPlan legacy, compact;
    Check(PlanAppleSnapshotSiblingTransaction(source, snapshots.checkpoint, request, legacy, error) &&
        PlanApplePlainCompactTransaction(source, snapshots.checkpoint, request, compact, error, true) && SamePublication(legacy, compact),
        "actual sibling snapshot uses identical legacy publication and retained history: " + error);
    auto encrypted = snapshots.checkpoint; encrypted.volumes[1].superblock.fs_flags &= ~kFsFlagUnencrypted;
    Check(!PlanApplePlainCompactTransaction(source, encrypted, request, compact, error, true) && Empty(compact),
        "encrypted profile never enters ordinary compact planner");
}
}
int main() {
    try {
        DirtyBlockCase();
        CountedPlannerCase();
        PublishedEmptyAllocationCase();
        LargeRecordCase();
        EligibilityNegatives();
        std::cout << "PASS PlainExtentLayoutTests checks=" << checks << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL PlainExtentLayoutTests: " << error.what() << '\n'; return 1;
    }
}
