#include "AppleVolumeTransaction.h"
#include "AppleCapacityPreviewInternal.h"
#include "ApfsExtendedRecordCodec.h"
#include "ApfsSharedSpace.h"
#include "TestFixtureBuilder.h"
#include "WindowsMetadataAttribute.h"
#include <sddl.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <limits>
#include <new>
#include <set>
#include <stdexcept>
#include <type_traits>

namespace allocation_observation {
std::atomic<bool> enabled{false};
std::atomic<std::uint64_t> calls{0}, bytes{0};
void* Allocate(std::size_t count) {
    if (enabled.load(std::memory_order_relaxed)) {
        calls.fetch_add(1, std::memory_order_relaxed);
        bytes.fetch_add(count, std::memory_order_relaxed);
    }
    if (void* p = std::malloc(count ? count : 1)) return p;
    throw std::bad_alloc();
}
}
void* operator new(std::size_t count) { return allocation_observation::Allocate(count); }
void* operator new[](std::size_t count) { return allocation_observation::Allocate(count); }
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }

using namespace apfsaccess::catalog;
using namespace apfsaccess::rw;
using namespace apfsaccess::testfixture;

namespace
{
constexpr std::uint32_t kBlockSize = 4096;
std::size_t checks = 0;
void Check(bool condition, const std::string& message)
{
    ++checks;
    if (!condition) throw std::runtime_error(message);
}

BuilderStore Spec(std::size_t volumes = 1)
{
    BuilderStore spec;
    spec.authoritative_checkpoint = true;
    spec.block_count = 256;
    spec.authoritative_internal_pool_blocks = 16;
    spec.authoritative_checkpoint_ring_blocks = 16;
    spec.volumes.resize(volumes);
    for (std::size_t i = 0; i < volumes; ++i)
    {
        spec.volumes[i].oid = 101 + i;
        spec.volumes[i].incompat = kIncompatCaseInsensitive;
    }
    return spec;
}

std::vector<BtreeRecord> Records(std::size_t payload_blocks)
{
    std::string error;
    std::vector<BtreeRecord> records;
    AppleInodeRecord root;
    root.object_id = 2;
    root.parent_id = 2;
    root.private_id = 9;
    root.children_or_links = payload_blocks ? 1 : 0;
    root.mode = 0040755;
    BtreeRecord encoded;
    Check(EncodeAppleInodeRecord(root, encoded, error), error);
    records.push_back(encoded);
    if (payload_blocks)
    {
        AppleInodeRecord file;
        file.object_id = file.private_id = 100;
        file.parent_id = 2;
        file.children_or_links = 1;
        file.mode = 0100644;
        file.uncompressed_size = payload_blocks * kBlockSize;
        Check(EncodeAppleInodeRecord(file, encoded, error), error);
        records.push_back(encoded);
        AppleDirectoryRecord directory;
        directory.parent_id = 2;
        directory.file_id = 100;
        directory.flags = 8;
        directory.name_utf8 = "quota.bin";
        Check(EncodeAppleDirectoryRecord(directory,
            ApfsNamePolicy::FromIncompatibleFeatures(kIncompatCaseInsensitive), encoded, error), error);
        records.push_back(encoded);
    }
    return records;
}

AppleVolumeTransactionRequest Request(std::size_t payload_blocks = 0)
{
    AppleVolumeTransactionRequest request;
    request.volume_object_id = 101;
    request.filesystem_records = Records(payload_blocks);
    if (payload_blocks)
    {
        request.file_count_delta = 1;
        AppleVolumeDataWrite data;
        data.file_private_id = 100;
        data.bytes.assign(payload_blocks * kBlockSize, std::byte{0x42});
        request.data_writes.push_back(std::move(data));
    }
    return request;
}

struct Fixture
{
    std::vector<std::byte> image;
    AppleCheckpointView checkpoint;
    explicit Fixture(const BuilderStore& spec) : image(BuildStoreImage(spec)) { Reload(); }
    void Reload()
    {
        VectorRandomAccessSource source(image);
        std::string error;
        auto loaded = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        Check(loaded.has_value(), "strict fixture: " + error);
        checkpoint = std::move(*loaded);
    }
};

// Publication is exercised only against this byte-vector target; no file,
// device, mount or operating-system write API is involved.
class MemoryTarget final : public AppleCheckpointWriteTarget
{
public:
    explicit MemoryTarget(const std::vector<std::byte>& original) : image(original) {}
    bool ReadBlock(std::uint64_t block, std::uint32_t size, std::vector<std::byte>& out) override
    {
        ++reads;
        if (size != kBlockSize || block >= image.size() / size) return false;
        const auto start = image.begin() + static_cast<std::ptrdiff_t>(block * size);
        out.assign(start, start + size);
        return true;
    }
    bool WriteBlock(std::uint64_t block, std::span<const std::byte> bytes) override
    {
        if (bytes.size() != kBlockSize || block >= image.size() / kBlockSize) return false;
        ++writes;
        std::copy(bytes.begin(), bytes.end(), image.begin() + static_cast<std::ptrdiff_t>(block * kBlockSize));
        return true;
    }
    bool Flush() override { return true; }
    std::vector<std::byte> image;
    std::size_t writes = 0;
    std::size_t reads = 0;
};

void Publish(Fixture& fixture, const AppleVolumeTransactionPlan& plan)
{
    MemoryTarget target(fixture.image);
    std::string error;
    Check(ExecuteAppleCheckpointPublication(target, plan.commit.publication, error), "memory publication: " + error);
    fixture.image = std::move(target.image);
    fixture.Reload();
}

void SetApsbCounter(Fixture& fixture, std::size_t volume_index, std::size_t offset, std::uint64_t value)
{
    const auto start = fixture.image.begin() + static_cast<std::ptrdiff_t>(
        fixture.checkpoint.volumes[volume_index].superblock_object.physical_block * kBlockSize);
    std::vector<std::byte> block(start, start + kBlockSize);
    PutU64LE(block, offset, value);
    FletcherForBlock(block, block.size());
    std::copy(block.begin(), block.end(), start);
}

std::string State(const AppleCheckpointView& checkpoint)
{
    std::string result;
    const auto bytes = [&](const auto& buffer) {
        result.append(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    };
    const auto number = [&](std::uint64_t value) { result += std::to_string(value) + ";"; };
    bytes(checkpoint.container.superblock_bytes);
    bytes(checkpoint.spaceman.bytes);
    number(checkpoint.container.superblock.xid);
    number(checkpoint.spaceman.devices[0].free_count);
    for (const auto& chunk : checkpoint.spaceman.chunks)
    {
        number(chunk.free_count);
        bytes(chunk.allocation_bitmap);
    }
    for (const auto& volume : checkpoint.volumes)
    {
        number(volume.superblock.object_id);
        number(volume.superblock.xid);
        number(volume.superblock.space.allocated_block_count);
        number(volume.superblock.space.reserve_block_count);
        number(volume.superblock.space.quota_block_count);
    }
    return result;
}

bool Empty(const AppleVolumeTransactionPlan& plan)
{
    const auto& a = plan.allocation;
    const auto& p = plan.commit.publication;
    return a.expected_checkpoint_xid == 0 && a.transaction_xid == 0 &&
        a.allocated_main_blocks.empty() && a.allocated_internal_pool_blocks.empty() &&
        a.deferred_frees.empty() && a.writes.empty() && a.updated_spaceman.bytes.empty() &&
        p.expected_checkpoint_xid == 0 && p.transaction_xid == 0 && p.guard_blocks.empty() &&
        p.before_superblock_writes.empty() && p.superblock_write.bytes.empty() &&
        p.published_checkpoint.superblock_bytes.empty() &&
        plan.payload_blocks.empty() && plan.filesystem_records.empty();
}

AppleVolumeTransactionPlan Plan(Fixture& fixture, const AppleVolumeTransactionRequest& request,
    const std::string& expected_error = {})
{
    const auto image_before = fixture.image;
    const auto state_before = State(fixture.checkpoint);
    VectorRandomAccessSource source(fixture.image);
    AppleVolumeTransactionPlan plan;
    // Failure must clear a reused output, including a previous publication.
    plan.allocation.expected_checkpoint_xid = 999;
    plan.commit.publication.superblock_write.bytes = {std::byte{1}};
    plan.payload_blocks = {999};
    plan.filesystem_records = Records(0);
    std::string error;
    const auto success = PlanAppleVolumeTransaction(source, fixture.checkpoint, request, plan, error);
    Check(fixture.image == image_before && State(fixture.checkpoint) == state_before,
        "planner changed source/checkpoint");
    if (expected_error.empty())
        Check(success && error.empty() && !Empty(plan), "expected plan: " + error);
    else
    {
        Check(!success, "expected refusal " + expected_error + ", planner returned a commit plan");
        Check(error == expected_error, "expected " + expected_error + ", got " + error);
        Check(Empty(plan), "refusal leaked a commit/allocation plan");
    }
    return plan;
}

std::uint64_t ResultAllocated(const AppleVolumeTransactionPlan& plan)
{
    for (const auto& write : plan.commit.publication.before_superblock_writes)
        if (const auto sb = ParseApsb(write.bytes); sb && sb->object_id == 101)
            return sb->space.allocated_block_count;
    throw std::runtime_error("planned APSB missing");
}

BuilderStore PopulatedSpec(std::size_t volumes = 1)
{
    auto spec = Spec(volumes);
    auto& volume = spec.volumes[0];
    volume.filesystem_records = Records(3);
    volume.additional_file_system_allocated_blocks = 3;
    std::string error;
    BtreeRecord record;
    AppleFileExtentRecord extent;
    extent.object_id = 100;
    extent.physical_block = 220;
    extent.length_bytes = 3 * kBlockSize;
    extent.block_size = kBlockSize;
    Check(EncodeAppleFileExtentRecord(extent, record, error), error);
    volume.filesystem_records.push_back(record);
    AppleDataStreamIdRecord stream;
    stream.object_id = 100;
    stream.reference_count = 1;
    Check(EncodeAppleDataStreamIdRecord(stream, record, error), error);
    volume.filesystem_records.push_back(record);
    Check(SortAppleBtreeRecords(volume.filesystem_records,
        AppleBtreeKeyOrder::FileSystemHashedDirectory, error), error);
    ApplePhysicalExtentRecord physical;
    physical.physical_block = 220;
    physical.block_count = 3;
    physical.kind = kApplePhysicalExtentKindNew;
    physical.owning_object_id = 100;
    physical.reference_count = 1;
    Check(EncodeApplePhysicalExtentRecord(physical, record, error), error);
    volume.extentref_records = {record};
    for (std::uint64_t block = 220; block < 223; ++block)
        spec.authoritative_seeded_main_blocks.push_back({block,
            std::vector<std::byte>(kBlockSize, std::byte{0x42})});
    return spec;
}

void QuotaBoundaries()
{
    Fixture unconstrained(Spec());
    const auto request = Request(1);
    const auto baseline = Plan(unconstrained, request);
    const auto allocated = ResultAllocated(baseline);
    Check(allocated == 7 && baseline.allocation.allocated_main_blocks.size() == 8,
        "control must grow by one net volume block but allocate eight COW main blocks");
    auto spec = Spec();
    spec.volumes[0].quota_block_count = allocated;
    Fixture exact(spec);
    Check(ResultAllocated(Plan(exact, request)) == allocated, "exact quota must admit");
    spec.volumes[0].quota_block_count = allocated - 1;
    Fixture exceeded(spec);
    Plan(exceeded, request, "AppleVolumeQuotaExceeded");
    spec.volumes[0].quota_block_count = spec.block_count * 2;
    Fixture large_quota(spec);
    Plan(large_quota, request);
    spec.volumes[0].quota_block_count = (std::numeric_limits<std::uint64_t>::max)();
    Fixture overflow(spec);
    Plan(overflow, request, "SharedSpaceByteOverflow");
}

void OverQuotaNonGrowing()
{
    auto spec = PopulatedSpec();
    spec.volumes[0].quota_block_count = 5;
    Fixture fixture(spec);
    auto unchanged = Request();
    unchanged.filesystem_records = spec.volumes[0].filesystem_records;
    Check(ResultAllocated(Plan(fixture, unchanged)) == 9, "over-quota unchanged must admit");
    auto removal = Request();
    removal.released_data_blocks = {{220, 3}};
    const auto shrunk = Plan(fixture, removal);
    Check(ResultAllocated(shrunk) == 6, "over-quota shrink must admit even while above quota");
    Check(shrunk.allocation.updated_spaceman.devices[0].free_count ==
        fixture.checkpoint.spaceman.devices[0].free_count - shrunk.allocation.allocated_main_blocks.size(),
        "deferred payload/metadata releases must not increase reusable free");
    Check(std::any_of(shrunk.allocation.deferred_frees.begin(), shrunk.allocation.deferred_frees.end(),
        [](const auto& release) { return release.physical_block == 220 && release.block_count == 3; }),
        "shrinking payload must be deferred");
    auto growth = Request(4);
    growth.file_count_delta = 0;
    growth.released_data_blocks = {{220, 3}};
    Plan(fixture, growth, "AppleVolumeQuotaExceeded");
}

void SiblingReserveBoundaries()
{
    auto spec = Spec(3);
    Fixture control(spec);
    auto request = Request(1);
    const auto baseline = Plan(control, request);
    const auto remaining = baseline.allocation.updated_spaceman.devices[0].free_count;
    const auto first = remaining / 2;
    spec.volumes[1].reserve_block_count = 6 + first;
    spec.volumes[2].reserve_block_count = 6 + remaining - first;
    Fixture exact(spec);
    Plan(exact, request);
    ++spec.volumes[2].reserve_block_count;
    Fixture protected_siblings(spec);
    Plan(protected_siblings, request, "AppleVolumeSiblingReserveProtected");
    // Each sibling alone fits; their sum must protect the one shared pool.
    Check(first < remaining && remaining - first + 1 < remaining, "combined reserve case is discriminating");
    spec.volumes[1].reserve_block_count = 6;
    spec.volumes[2].reserve_block_count = 0;
    spec.volumes[0].reserve_block_count = 6 + control.checkpoint.spaceman.devices[0].free_count;
    Fixture own_overhead(spec);
    Plan(own_overhead, request, "AppleVolumeReserveCapacityProtected");
    // Net volume growth consumes its own reserve, while COW also needs real
    // free blocks until retained old objects can be reclaimed.
    spec.volumes[0].reserve_block_count = ResultAllocated(baseline) + remaining;
    Fixture own_reserve(spec);
    const auto own_plan = Plan(own_reserve, request);
    Publish(own_reserve, own_plan);
    ApfsSharedSpaceProjection after;
    std::string error;
    Check(TryProjectAppleSharedSpace(own_reserve.checkpoint, after, error),
        "consuming own reserve must publish a usable shared projection: " + error);
    Check(after.free.blocks == remaining && after.volumes[0].available.blocks == remaining,
        "own reserve remains available to its owner after publication");
}

void CowAndReleasedBlocks()
{
    auto spec = PopulatedSpec(2);
    Fixture control(spec);
    auto removal = Request();
    removal.released_data_blocks = {{220, 3}};
    const auto baseline = Plan(control, removal);
    spec.volumes[1].reserve_block_count = 6 + baseline.allocation.updated_spaceman.devices[0].free_count + 1;
    Fixture reserved(spec);
    Plan(reserved, removal, "AppleVolumeSiblingReserveProtected");
    auto unchanged = Request();
    unchanged.filesystem_records = spec.volumes[0].filesystem_records;
    Fixture unchanged_control(PopulatedSpec(2));
    const auto unchanged_plan = Plan(unchanged_control, unchanged);
    spec.volumes[1].reserve_block_count = 6 + unchanged_plan.allocation.updated_spaceman.devices[0].free_count + 1;
    Fixture unchanged_reserved(spec);
    Plan(unchanged_reserved, unchanged, "AppleVolumeSiblingReserveProtected");
    auto full = Spec();
    full.authoritative_main_free_blocks = 5;
    Fixture tight(full);
    Plan(tight, Request(), "AppleSpacemanMainPoolExhausted");
}

void InvalidEvidence()
{
    const auto request = Request(1);
    Fixture missing(Spec(2));
    missing.checkpoint.volumes.pop_back();
    Plan(missing, request, "SharedSpaceVolumeSetInvalid");
    Fixture identity(Spec(2));
    ++identity.checkpoint.volumes[1].superblock_object.xid;
    Plan(identity, request, "SharedSpaceVolumeIdentityInvalid");
    Fixture absent(Spec());
    auto wrong_request = request;
    wrong_request.volume_object_id = 999;
    Plan(absent, wrong_request, "AppleVolumeTransactionVolumeMissing");
    auto malformed = Spec(2);
    malformed.volumes[1].reserve_block_count = malformed.block_count + 1;
    Fixture bad_reserve(malformed);
    Plan(bad_reserve, request, "SharedSpaceVolumeCountersInvalid");
    malformed = Spec(2);
    malformed.volumes[1].reserve_block_count = 10;
    malformed.volumes[1].quota_block_count = 9;
    Fixture bad_relationship(malformed);
    Plan(bad_relationship, request, "SharedSpaceVolumeCountersInvalid");
    Fixture bad_allocated(Spec());
    bad_allocated.checkpoint.volumes[0].superblock.space.allocated_block_count =
        (std::numeric_limits<std::uint64_t>::max)();
    Plan(bad_allocated, request, "SharedSpaceVolumeCountersInvalid");
    Fixture stale_typed(Spec(2));
    --stale_typed.checkpoint.volumes[1].superblock.xid;
    --stale_typed.checkpoint.volumes[1].superblock_object.xid;
    Plan(stale_typed, request, "AppleVolumeSpaceEvidenceChanged");
    Fixture stale_counters(Spec(2));
    stale_counters.checkpoint.volumes[1].superblock.space.reserve_block_count = 7;
    Plan(stale_counters, request, "AppleVolumeSpaceEvidenceChanged");
    Fixture underflow(Spec());
    SetApsbCounter(underflow, 0, 0x58, 0);
    underflow.Reload();
    Plan(underflow, request, "AppleVolumeTransactionAccountingInvalid");
    Fixture lifetime_overflow(Spec());
    SetApsbCounter(lifetime_overflow, 0, 0xE8, (std::numeric_limits<std::uint64_t>::max)());
    lifetime_overflow.Reload();
    Plan(lifetime_overflow, request, "AppleVolumeTransactionAccountingInvalid");
    auto overcommitted = Spec(2);
    Fixture free_control(overcommitted);
    overcommitted.volumes[1].reserve_block_count =
        6 + free_control.checkpoint.spaceman.devices[0].free_count + 1;
    Fixture bad_total(overcommitted);
    Plan(bad_total, request, "SharedSpaceReservesExceedFree");
    auto older_peer = Spec(2);
    older_peer.volumes[1].xid_offset = -1;
    Fixture valid_older_peer(older_peer);
    Plan(valid_older_peer, request);
}

void ReclaimedVersusPinned()
{
    auto spec = Spec(2);
    Fixture control(spec);
    auto request = Request();
    const auto baseline = Plan(control, request);
    spec.volumes[1].reserve_block_count = 6 + baseline.allocation.updated_spaceman.devices[0].free_count;
    Fixture fixture(spec);
    const auto original = fixture.checkpoint;
    request.required_checkpoint_xids = {original.container.superblock.xid};
    const auto first = Plan(fixture, request);
    Publish(fixture, first);
    const auto remaining = fixture.checkpoint.spaceman.devices[0].free_count;
    Plan(fixture, request, "AppleVolumeSiblingReserveProtected");
    VectorRandomAccessSource after_refusal(fixture.image);
    std::string error;
    const auto retained = LoadAppleCheckpointView(after_refusal, 0, after_refusal.SizeBytes(), error,
        original.container.superblock.xid);
    Check(retained && State(*retained) == State(original), "capacity refusal damaged retained original checkpoint");
    request.required_checkpoint_xids.clear();
    const auto reusable = Plan(fixture, request);
    Check(reusable.allocation.updated_spaceman.devices[0].free_count >= remaining,
        "mature releases must be usable after pin release");
    Check(reusable.allocation.allocated_main_blocks.size() > 0,
        "mature-free admission must still allocate COW blocks");
    Publish(fixture, reusable);
}

void SourceAndPublicationDrift()
{
    Fixture fixture(Spec(2));
    auto request = Request();
    const auto admitted = Plan(fixture, request);
    SetApsbCounter(fixture, 1, 0x48, 7);
    Plan(fixture, request, "AppleVolumeSpaceEvidenceChanged");
    MemoryTarget changed(fixture.image);
    const auto before = changed.image;
    std::string error;
    Check(!ExecuteAppleCheckpointPublication(changed, admitted.commit.publication, error) &&
        error == "AppleCheckpointGuardChanged" && changed.writes == 0 && changed.image == before,
        "changed sibling APSB must stop publication before writes: " + error);

    auto spec = Spec();
    spec.volumes[0].quota_block_count = 6;
    Fixture stale(spec);
    const auto old = stale.checkpoint;
    Publish(stale, Plan(stale, Request()));
    stale.checkpoint = old;
    Plan(stale, Request(1), "AppleSpacemanConcurrentDrift");
}

void ExtendedSnapshotMetadataAdmission()
{
    Fixture control(Spec(2));
    SetApsbCounter(control, 0, 0x430, 0x123456789abcdef0ull);
    control.Reload();
    const auto original = control.image;
    std::string error;
    for (const auto& volume : control.checkpoint.volumes)
        Check(volume.superblock.snap_meta_ext_oid == 0 &&
            CheckAppleVolumeWriteFeatures(control.checkpoint.container.superblock, volume.superblock, error),
            "serialized zero extended OID preserves ordinary write admission: " + error);
    auto request = Request(1);
    const auto admitted = Plan(control, request);
    Publish(control, admitted);
    const auto& published = control.checkpoint.volumes[0];
    const auto offset = published.superblock_object.physical_block * kBlockSize;
    const std::vector<std::byte> apsb(control.image.begin() + offset, control.image.begin() + offset + kBlockSize);
    Check(published.superblock.snap_meta_ext_oid == 0 &&
        ReadU64LE(apsb, 0x430) == 0x123456789abcdef0ull,
        "ordinary COW preserves zero extended OID and opaque APSB bytes");

    for (const auto index : {0u, 1u}) for (const bool reload : {false, true}) {
        Fixture invalid(Spec(2));
        SetApsbCounter(invalid, index, 0x3E8, 0xfedcba9876543210ull);
        if (reload) invalid.Reload();
        const auto block = invalid.checkpoint.volumes[index].superblock_object.physical_block;
        const auto start = invalid.image.begin() + block * kBlockSize;
        const std::vector<std::byte> bytes(start, start + kBlockSize);
        const auto parsed = ParseApsb(bytes);
        Check(parsed && parsed->snap_meta_ext_oid == 0xfedcba9876543210ull,
            "parser retains every bit of serialized extended OID");
        Check(!CheckAppleVolumeWriteFeatures(invalid.checkpoint.container.superblock, *parsed, error) &&
            error == "SnapshotExtendedMetadataUnsupported",
            "parsed extended OID refuses the direct write feature gate");
        Plan(invalid, request, "SnapshotExtendedMetadataUnsupported");
    }
    Check(original != control.image, "zero extended OID control actually published ordinary file data");

    Fixture history(Spec(2));
    const auto old_xid = history.checkpoint.container.superblock.xid;
    auto pinned = Request();
    pinned.required_checkpoint_xids = {old_xid};
    Publish(history, Plan(history, pinned));
    VectorRandomAccessSource source(history.image);
    std::vector<AppleRecoveryCheckpointView> retained;
    Check(LoadAppleRecoveryCheckpoints(source, history.checkpoint, {old_xid}, retained, error) &&
        retained.size() == 1, "zero extended OID historical checkpoint remains recoverable: " + error);
    Plan(history, pinned);
    const auto old_block = retained[0].checkpoint.volumes[0].superblock_object.physical_block;
    Check(old_block != history.checkpoint.volumes[0].superblock_object.physical_block,
        "historical negative changes a retained APSB outside the current volume set");
    auto start = history.image.begin() + old_block * kBlockSize;
    std::vector<std::byte> old_apsb(start, start + kBlockSize);
    PutU64LE(old_apsb, 0x3E8, 999);
    FletcherForBlock(old_apsb, old_apsb.size());
    std::copy(old_apsb.begin(), old_apsb.end(), start);
    const auto unchanged = history.image;
    VectorRandomAccessSource changed(history.image);
    Check(!LoadAppleRecoveryCheckpoints(changed, history.checkpoint, {old_xid}, retained, error) &&
        retained.empty() && error == "SnapshotExtendedMetadataUnsupported",
        "source-bound historical extended OID clears retained recovery evidence: " + error);
    Plan(history, pinned, "SnapshotExtendedMetadataUnsupported");
    Check(history.image == unchanged, "historical refusal preserves every serialized byte");
}

void OmapRoleAdmission()
{
    const auto set_flags = [](Fixture& fixture, bool container, std::size_t index,
        std::uint32_t flags, bool update_view = true) {
        auto& map = container ? fixture.checkpoint.container_object_map : fixture.checkpoint.volumes.at(index).object_map;
        const auto offset = map.object.physical_block * kBlockSize;
        std::vector<std::byte> bytes(fixture.image.begin() + offset, fixture.image.begin() + offset + kBlockSize);
        for (unsigned i = 0; i != 4; ++i) bytes[0x20 + i] = static_cast<std::byte>(flags >> (8 * i));
        std::string error;
        Check(FinalizeAppleObjectChecksum(bytes, error), error);
        std::copy(bytes.begin(), bytes.end(), fixture.image.begin() + offset);
        if (update_view) map.flags = flags;
    };
    Fixture control(Spec(2));
    set_flags(control, true, 0, 1);
    const auto request = Request(1);
    const auto valid = Plan(control, request);
    Publish(control, valid);
    Check(control.checkpoint.container_object_map.flags == 1 &&
        std::all_of(control.checkpoint.volumes.begin(), control.checkpoint.volumes.end(),
            [](const auto& volume) { return volume.object_map.flags == 0; }),
        "publication must preserve canonical container and volume OMAP roles");
    for (const auto flags : {0u, 2u, 3u, 0x80000000u}) {
        Fixture invalid(Spec(2));
        set_flags(invalid, true, 0, flags);
        Plan(invalid, request, "AppleVolumeTransactionOmapRoleFlagsUnsupported");
    }
    for (const auto index : {0u, 1u}) {
        for (const auto flags : {1u, 2u, 3u, 0x80000000u}) {
            Fixture invalid(Spec(2));
            set_flags(invalid, true, 0, 1);
            set_flags(invalid, false, index, flags);
            Plan(invalid, request, "AppleVolumeTransactionOmapRoleFlagsUnsupported");
        }
    }
    for (const auto [container, index] : {std::pair{false, 0u}, std::pair{false, 1u}, std::pair{true, 0u}}) {
        Fixture hidden(Spec(2));
        set_flags(hidden, true, 0, 1);
        set_flags(hidden, container, index, container ? 0u : 1u, false);
        Plan(hidden, request, "AppleVolumeTransactionOmapRoleFlagsChanged");
    }
    Fixture drift(Spec(2));
    set_flags(drift, true, 0, 1);
    const auto admitted = Plan(drift, request);
    set_flags(drift, false, 1, 1, false);
    MemoryTarget changed(drift.image);
    const auto before = changed.image;
    std::string error;
    Check(!ExecuteAppleCheckpointPublication(changed, admitted.commit.publication, error) &&
        error == "AppleCheckpointGuardChanged" && changed.writes == 0 && changed.image == before,
        "changed sibling OMAP must refuse publication before writes: " + error);
}

struct PlanWork { std::uint64_t us = 0, calls = 0, bytes = 0; };
template<class F> auto MeasurePlan(F&& run, PlanWork& work) {
    allocation_observation::calls = 0;
    allocation_observation::bytes = 0;
    const auto start = std::chrono::steady_clock::now();
    allocation_observation::enabled = true;
    auto result = run();
    allocation_observation::enabled = false;
    work.us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now()-start).count();
    work.calls = allocation_observation::calls;
    work.bytes = allocation_observation::bytes;
    return result;
}

AppleVolumeTransactionPlan CapacityPair(const RandomAccessSource& source,
    const AppleCheckpointView& checkpoint, const AppleVolumeTransactionRequest& request,
    bool expected_success, bool report_work = false)
{
    auto geometry = request;
    std::vector<std::uint64_t> sizes;
    for (auto& data : geometry.data_writes) { sizes.push_back(data.bytes.size()); data.bytes.clear(); data.bytes.shrink_to_fit(); }
    AppleVolumeTransactionPlan full;
    AppleVolumeCapacityPreview preview;
    std::string full_error, preview_error;
    PlanWork full_work, preview_work;
    const auto complete = MeasurePlan([&] { return PlanApplePlainCompactTransaction(source, checkpoint, request, full, full_error); }, full_work);
    const auto result = MeasurePlan([&] { return PreviewApplePlainCompactCapacity(source, checkpoint, geometry, sizes, preview, preview_error); }, preview_work);
    Check(complete == expected_success, "full decision: " + full_error);
    Check((result == AppleCapacityPreviewResult::Planned) == complete && result != AppleCapacityPreviewResult::Unsupported,
        "capacity/full decisions differ: " + full_error + " / " + preview_error);
    Check(full_error == preview_error, "capacity/full refusal differs: " + full_error + " / " + preview_error);
    if (complete) {
        Check(preview.payload_blocks == full.payload_blocks, "exact payload allocation prefix");
        Check(preview.allocation.allocated_main_blocks == full.allocation.allocated_main_blocks &&
            preview.allocation.allocated_internal_pool_blocks == full.allocation.allocated_internal_pool_blocks,
            "exact complete allocation");
        Check(preview.allocation.updated_spaceman.bytes == full.allocation.updated_spaceman.bytes &&
            preview.allocation.updated_spaceman.devices[0].free_count == full.allocation.updated_spaceman.devices[0].free_count,
            "exact allocator counters and serialization");
        Check(preview.allocation.writes.size() == full.allocation.writes.size(), "exact allocator write count");
        for (std::size_t i=0;i<full.allocation.writes.size();++i) {
            const auto& a=preview.allocation.writes[i]; const auto& b=full.allocation.writes[i];
            Check(a.kind==b.kind && a.physical_block==b.physical_block && a.bytes==b.bytes, "exact allocator writes");
        }
        Check(preview.allocation.deferred_frees.size()==full.allocation.deferred_frees.size(), "exact deferred release count");
        for (std::size_t i=0;i<full.allocation.deferred_frees.size();++i) {
            const auto& a=preview.allocation.deferred_frees[i]; const auto& b=full.allocation.deferred_frees[i];
            Check(a.physical_block==b.physical_block && a.block_count==b.block_count && a.queue_index==b.queue_index,
                "exact deferred release lifetime");
        }
        Check(preview.filesystem_records.size()==full.filesystem_records.size() &&
            std::equal(preview.filesystem_records.begin(),preview.filesystem_records.end(),full.filesystem_records.begin(),
                [](const auto& a,const auto& b){return a.key==b.key&&a.value==b.value;}),
            "exact filesystem records and extent geometry");
        const std::set<std::uint64_t> payload(full.payload_blocks.begin(),full.payload_blocks.end());
        std::uint64_t metadata_bytes=0;std::size_t metadata_count=0;
        for (const auto& w:full.commit.publication.before_superblock_writes)
            if (!payload.contains(w.physical_block)) {metadata_bytes+=w.bytes.size();++metadata_count;}
        Check(metadata_bytes==preview.metadata_write_bytes && metadata_count==preview.metadata_write_count,
            "exact metadata tree/ring sizes");
    } else Check(preview.payload_blocks.empty() && preview.allocation.allocated_main_blocks.empty() &&
        preview.filesystem_records.empty(), "refused preview output cleared");
    if (report_work) {
        std::uint64_t bytes=0;for(auto size:sizes)bytes+=size;
        std::cout << "CAPACITY_WORK {\"pendingBytes\":" << bytes << ",\"fullUs\":" << full_work.us
            << ",\"previewUs\":" << preview_work.us << ",\"fullNewCalls\":" << full_work.calls
            << ",\"previewNewCalls\":" << preview_work.calls << ",\"fullNewBytes\":" << full_work.bytes
            << ",\"previewNewBytes\":" << preview_work.bytes << "}\n";
        Check(preview_work.bytes < full_work.bytes, "preview removes observed payload allocation/copy work");
    }
    return full;
}

void CapacityBoundariesAndWork()
{
    static_assert(!std::is_convertible_v<AppleVolumeCapacityPreview, AppleCheckpointPublicationPlan>);
    for (const auto blocks : {0u,1u,16u,190u,220u,248u}) {
        Fixture f(Spec());const auto request=Request(blocks);VectorRandomAccessSource source(f.image);
        AppleVolumeTransactionPlan full;std::string error;
        const bool expected=PlanApplePlainCompactTransaction(source,f.checkpoint,request,full,error);
        CapacityPair(source,f.checkpoint,request,expected);
    }
    Fixture control(Spec(2));VectorRandomAccessSource source(control.image);
    const auto full=CapacityPair(source,control.checkpoint,Request(1),true);
    auto spec=Spec(2);spec.volumes[0].quota_block_count=ResultAllocated(full);
    Fixture exact(spec);VectorRandomAccessSource exact_source(exact.image);CapacityPair(exact_source,exact.checkpoint,Request(1),true);
    --spec.volumes[0].quota_block_count;Fixture denied(spec);VectorRandomAccessSource denied_source(denied.image);
    CapacityPair(denied_source,denied.checkpoint,Request(1),false);
    spec=Spec(2);spec.volumes[1].reserve_block_count=6+full.allocation.updated_spaceman.devices[0].free_count;
    Fixture reserve(spec);VectorRandomAccessSource reserve_source(reserve.image);CapacityPair(reserve_source,reserve.checkpoint,Request(1),true);
    ++spec.volumes[1].reserve_block_count;Fixture reserve_denied(spec);VectorRandomAccessSource reserve_denied_source(reserve_denied.image);
    CapacityPair(reserve_denied_source,reserve_denied.checkpoint,Request(1),false);
    auto large=Spec();large.block_count=32768;
    Fixture scaling(large);VectorRandomAccessSource scaling_source(scaling.image);
    for(const auto mib:{1u,4u,16u,64u}) {
        auto request=Request(mib*256u);std::string error;
        for(auto& record:request.filesystem_records)
            if((ReadU64LE(record.key,0).value_or(0)>>60)==3 && (ReadU64LE(record.key,0).value_or(0)&((1ull<<60)-1))==100) {
                AppleInodeRecord inode;Check(ApfsExtendedRecordCodec::DecodeInode(record,inode,error),error);
                AppleExtendedField stream;stream.type=8;stream.flags=1;stream.data.resize(40);
                PutU64LE(stream.data,0,std::uint64_t{mib}<<20);PutU64LE(stream.data,8,std::uint64_t{mib}<<20);
                inode.extended_fields.push_back(std::move(stream));Check(EncodeAppleInodeRecord(inode,record,error),error);
            }
        const auto compact=CapacityPair(scaling_source,scaling.checkpoint,request,true,true);
        Check(std::count_if(compact.filesystem_records.begin(),compact.filesystem_records.end(),
            [](const auto& r){return (ReadU64LE(r.key,0).value_or(0)>>60)==8;})<16,
            "timed pending batches use the admitted compact ordinary layout");
    }
}

void CapacitySourceAndRetention()
{
    for(const bool sibling:{false,true}) {
        Fixture f(Spec(2));SetApsbCounter(f,sibling?1:0,0x48,7);
        VectorRandomAccessSource source(f.image);CapacityPair(source,f.checkpoint,Request(1),false);
    }
    Fixture malformed(Spec());const auto root=malformed.checkpoint.volumes[0].root_tree.physical_block*kBlockSize;
    malformed.image[root+100]^=std::byte{1};VectorRandomAccessSource corrupt(malformed.image);
    CapacityPair(corrupt,malformed.checkpoint,Request(1),false);
    class ByteError final:public RandomAccessSource {
        const RandomAccessSource& source_;std::uint64_t bad_;
    public:ByteError(const RandomAccessSource& s,std::uint64_t bad):source_(s),bad_(bad){}
        std::uint64_t SizeBytes()const override{return source_.SizeBytes();}
        bool Read(std::uint64_t at,std::size_t count,std::vector<std::byte>& out)const override{
            if(at<=bad_ && count>bad_-at){out.clear();return false;}return source_.Read(at,count,out);}
    };
    Fixture unreadable(Spec());VectorRandomAccessSource base(unreadable.image);
    ByteError error_source(base,unreadable.checkpoint.volumes[0].superblock_object.physical_block*kBlockSize);
    CapacityPair(error_source,unreadable.checkpoint,Request(1),false);
    Fixture owned(Spec());const auto chunk=std::find_if(owned.checkpoint.spaceman.chunks.begin(),owned.checkpoint.spaceman.chunks.end(),[](const auto& c){return c.bitmap_block!=0;});
    Check(chunk!=owned.checkpoint.spaceman.chunks.end(),"bitmap source exists");owned.image[chunk->bitmap_block*kBlockSize]^=std::byte{1};
    VectorRandomAccessSource ownership(owned.image);CapacityPair(ownership,owned.checkpoint,Request(1),false);
    Fixture history(Spec());const auto old_xid=history.checkpoint.container.superblock.xid;
    Publish(history,Plan(history,Request()));VectorRandomAccessSource pinned(history.image);
    auto request=Request(1);request.required_checkpoint_xids={old_xid};CapacityPair(pinned,history.checkpoint,request,true);
    request.required_checkpoint_xids={history.checkpoint.container.superblock.next_xid};CapacityPair(pinned,history.checkpoint,request,false);
}

void CapacityPartialCowAndPublishGuard()
{
    const auto spec=PopulatedSpec();Fixture f(spec);auto request=Request(3);request.file_count_delta=0;
    request.data_writes[0].logical_address=kBlockSize;request.data_writes[0].bytes.assign(kBlockSize,std::byte{0xA7});
    request.released_data_blocks={{221,1}};std::string error;BtreeRecord r;
    for(const auto [offset,physical]:{std::pair{0ull,220ull},std::pair{2ull*kBlockSize,222ull}}){
        Check(EncodeAppleFileExtentRecord({100,offset,kBlockSize,physical,0,kBlockSize},r,error),error);request.filesystem_records.push_back(r);}
    Check(EncodeAppleDataStreamIdRecord({100,1},r,error),error);request.filesystem_records.push_back(r);
    VectorRandomAccessSource source(f.image);const auto full=CapacityPair(source,f.checkpoint,request,true);
    AppleTransactionCommitRequest commit;commit.allocation_plan=full.allocation;
    commit.next_object_id=full.commit.publication.next_object_id;commit.container_object_map_oid=full.commit.publication.published_checkpoint.superblock.omap_oid;
    std::set<std::uint64_t> main(full.allocation.allocated_main_blocks.begin(),full.allocation.allocated_main_blocks.end());
    std::set<std::uint64_t> payload(full.payload_blocks.begin(),full.payload_blocks.end());
    for(const auto& w:full.commit.publication.before_superblock_writes)
        if(main.contains(w.physical_block)&&!payload.contains(w.physical_block))commit.allocated_main_writes.push_back({w.physical_block,w.bytes});
    AppleTransactionCommitPlan preview;Check(capacity_detail::PlanCommit(source,f.checkpoint,commit,full.payload_blocks,preview,error),error);
    MemoryTarget target(f.image);Check(!ExecuteAppleCheckpointPublication(target,preview.publication,error)&&
        error=="AppleCheckpointPublicationPlanInvalid"&&target.reads==0&&target.writes==0,"real internal preview cannot execute");
    Check(ExecuteAppleCheckpointPublication(target,full.commit.publication,error),"actual full bytes publish: "+error);
    Check(target.image[220*kBlockSize]==std::byte{0x42}&&target.image[222*kBlockSize]==std::byte{0x42}&&
        target.image[full.payload_blocks[0]*kBlockSize]==std::byte{0xA7},"actual partial COW payload and retained bytes");
    auto unsupported=request;unsupported.clones.push_back({100,200});
    std::vector<std::uint64_t> sizes;for(auto& data:unsupported.data_writes){sizes.push_back(data.bytes.size());data.bytes.clear();}
    AppleVolumeCapacityPreview result;Check(PreviewApplePlainCompactCapacity(source,f.checkpoint,unsupported,sizes,result,error)==AppleCapacityPreviewResult::Unsupported,
        "clone profile retains full path");
    Check(PreviewApplePlainCompactCapacity(source,f.checkpoint,request,{},result,error)==AppleCapacityPreviewResult::Refused,
        "byte-bearing/mismatched geometry is not a preview");
}

std::vector<std::byte> DosBytes(std::uint32_t bits=0x20)
{
    std::vector<std::byte> bytes{std::byte{'D'},std::byte{'O'},std::byte{'S'},std::byte{1}};
    for(unsigned i=0;i<4;++i)bytes.push_back(std::byte((bits>>(8*i))&255));
    return bytes;
}
std::vector<std::byte> SecurityBytes(bool changed=false)
{
    PSECURITY_DESCRIPTOR descriptor=nullptr;ULONG size=0;
    Check(ConvertStringSecurityDescriptorToSecurityDescriptorW(changed
        ? L"O:SYG:BAD:P(A;;FA;;;SY)(A;;FR;;;WD)" : L"O:SYG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",
        SDDL_REVISION_1,&descriptor,&size)!=FALSE,"construct owned in-memory security descriptor");
    std::vector<std::byte> bytes{std::byte{'W'},std::byte{'S'},std::byte{'D'},std::byte{1}};
    bytes.insert(bytes.end(),static_cast<const std::byte*>(descriptor),static_cast<const std::byte*>(descriptor)+size);
    LocalFree(descriptor);
    Check(windows_metadata::ValidSecurityPayload(bytes),"existing security validator admits fixture");
    return bytes;
}
void AddXattr(std::vector<BtreeRecord>& records,std::uint64_t owner,const std::string& name,
    const std::vector<std::byte>& bytes,std::uint16_t flags=kAppleXattrDataEmbedded)
{
    BtreeRecord record;std::string error;
    Check(EncodeAppleXattrRecord({owner,name,flags,bytes},record,error),error);records.push_back(std::move(record));
}
void AddWindows(std::vector<BtreeRecord>& records,std::uint64_t owner,unsigned profile=2)
{
    if(profile!=1)AddXattr(records,owner,"com.apfsaccess.windows.attributes",DosBytes());
    if(profile!=0)AddXattr(records,owner,"com.apfsaccess.windows.security",SecurityBytes());
}
BuilderStore WindowsSpec(unsigned profile=2)
{
    auto spec=PopulatedSpec(2);AddWindows(spec.volumes[0].filesystem_records,100,profile);
    AddWindows(spec.volumes[0].filesystem_records,2,profile);return spec;
}
AppleVolumeTransactionRequest WindowsOverwrite(const BuilderStore& spec)
{
    auto request=Request(3);request.file_count_delta=0;
    request.data_writes[0].logical_address=kBlockSize;request.data_writes[0].bytes.assign(kBlockSize,std::byte{0xA7});
    request.released_data_blocks={{221,1}};std::string error;BtreeRecord record;
    for(const auto [offset,physical]:{std::pair{0ull,220ull},std::pair{2ull*kBlockSize,222ull}}){
        Check(EncodeAppleFileExtentRecord({100,offset,kBlockSize,physical,0,kBlockSize},record,error),error);
        request.filesystem_records.push_back(record);
    }
    Check(EncodeAppleDataStreamIdRecord({100,1},record,error),error);request.filesystem_records.push_back(record);
    for(const auto& r:spec.volumes[0].filesystem_records)
        if((ReadU64LE(r.key,0).value_or(0)>>60)==4)request.filesystem_records.push_back(r);
    return request;
}
AppleCapacityPreviewResult PreviewWindows(const Fixture& fixture,const AppleVolumeTransactionRequest& request)
{
    auto geometry=request;std::vector<std::uint64_t> lengths;
    for(auto& data:geometry.data_writes){lengths.push_back(data.bytes.size());data.bytes.clear();}
    VectorRandomAccessSource source(fixture.image);AppleVolumeCapacityPreview preview;std::string error;
    const auto result=PreviewApplePlainCompactCapacity(source,fixture.checkpoint,geometry,lengths,preview,error);
    if(result!=AppleCapacityPreviewResult::Planned)Check(preview.payload_blocks.empty()&&preview.filesystem_records.empty()&&
        preview.allocation.allocated_main_blocks.empty(),"non-admitted Windows preview has no output");
    return result;
}
std::vector<BtreeRecord> ColdWindowsRecords(const Fixture& fixture)
{
    const auto& volume=fixture.checkpoint.volumes[0];VectorRandomAccessSource source(fixture.image);
    BtreeReadPolicy policy;policy.enforce_object_identity=true;policy.root_object_id=volume.root_tree.object_id;
    policy.storage_type=volume.root_tree.type;policy.subtype=volume.root_tree.subtype;
    std::vector<BtreeRecord> records;std::string error;
    Check(ReadBtreeLeafRecords(source,kBlockSize,volume.root_tree.physical_block,false,volume.superblock.omap_oid,
        fixture.checkpoint.container.superblock.xid,policy,records,error),"cold Windows records: "+error);
    return records;
}
void CheckInlineBytes(const std::vector<BtreeRecord>& before,const std::vector<BtreeRecord>& after)
{
    std::size_t count=0;
    for(const auto& r:before)if((ReadU64LE(r.key,0).value_or(0)>>60)==4){
        ++count;Check(std::count_if(after.begin(),after.end(),[&](const auto& actual){return actual.key==r.key&&actual.value==r.value;})==1,
            "inline Windows xattr key/value bytes remain exact");
    }
    Check(count==std::count_if(after.begin(),after.end(),[](const auto& r){return(ReadU64LE(r.key,0).value_or(0)>>60)==4;}),
        "no inline Windows records omitted or introduced");
}
void WindowsEqualityAndPublication()
{
    for(unsigned profile=0;profile!=3;++profile){
        auto spec=WindowsSpec(profile);Fixture fixture(spec);auto request=WindowsOverwrite(spec);
        Check(PreviewWindows(fixture,request)==AppleCapacityPreviewResult::Planned,"validated Windows profile actually activates geometry");
        VectorRandomAccessSource source(fixture.image);const auto full=CapacityPair(source,fixture.checkpoint,request,true);
        Check(full.payload_blocks.size()==1,"DOS/security inline bytes do not become ordinary file payload blocks");
        AppleTransactionCommitRequest commit;commit.allocation_plan=full.allocation;
        commit.next_object_id=full.commit.publication.next_object_id;commit.container_object_map_oid=full.commit.publication.published_checkpoint.superblock.omap_oid;
        const std::set<std::uint64_t> main(full.allocation.allocated_main_blocks.begin(),full.allocation.allocated_main_blocks.end());
        const std::set<std::uint64_t> payload(full.payload_blocks.begin(),full.payload_blocks.end());
        for(const auto& w:full.commit.publication.before_superblock_writes)
            if(main.contains(w.physical_block)&&!payload.contains(w.physical_block))commit.allocated_main_writes.push_back({w.physical_block,w.bytes});
        AppleTransactionCommitPlan internal;std::string error;
        Check(capacity_detail::PlanCommit(source,fixture.checkpoint,commit,full.payload_blocks,internal,error),error);
        MemoryTarget target(fixture.image);Check(!ExecuteAppleCheckpointPublication(target,internal.publication,error)&&
            error=="AppleCheckpointPublicationPlanInvalid"&&target.reads==0&&target.writes==0,"Windows preview execution refuses with zero I/O");
        Publish(fixture,full);CheckInlineBytes(full.filesystem_records,ColdWindowsRecords(fixture));
        Check(fixture.image[220*kBlockSize]==std::byte{0x42}&&fixture.image[222*kBlockSize]==std::byte{0x42}&&
            std::all_of(fixture.image.begin()+full.payload_blocks[0]*kBlockSize,fixture.image.begin()+(full.payload_blocks[0]+1)*kBlockSize,
                [](auto byte){return byte==std::byte{0xA7};}),"cold partial COW keeps exact real payload and old edges");
        Fixture metadata(spec);AppleVolumeTransactionRequest update;update.volume_object_id=101;update.filesystem_records=spec.volumes[0].filesystem_records;
        for(auto& record:update.filesystem_records)if((ReadU64LE(record.key,0).value_or(0)>>60)==4){
            AppleXattrRecord attribute;Check(ApfsExtendedRecordCodec::DecodeXattr(record,attribute,error),error);
            attribute.data=attribute.name_utf8=="com.apfsaccess.windows.attributes"?DosBytes(1):SecurityBytes(true);
            Check(EncodeAppleXattrRecord(attribute,record,error),error);
        }
        VectorRandomAccessSource metadata_source(metadata.image);const auto metadata_full=CapacityPair(metadata_source,metadata.checkpoint,update,true);
        Check(metadata_full.payload_blocks.empty(),"metadata-only Windows changes have no regular payload");
        Publish(metadata,metadata_full);CheckInlineBytes(update.filesystem_records,ColdWindowsRecords(metadata));
        auto growing=Request(8);growing.file_count_delta=0;growing.released_data_blocks={{220,3}};
        for(const auto& r:spec.volumes[0].filesystem_records)
            if((ReadU64LE(r.key,0).value_or(0)>>60)==4)growing.filesystem_records.push_back(r);
        Fixture growth(spec);VectorRandomAccessSource growth_source(growth.image);
        const auto growth_full=CapacityPair(growth_source,growth.checkpoint,growing,true);
        auto quota=spec;quota.volumes[0].quota_block_count=ResultAllocated(growth_full);Fixture exact(quota);VectorRandomAccessSource exact_source(exact.image);
        CapacityPair(exact_source,exact.checkpoint,growing,true);--quota.volumes[0].quota_block_count;
        Fixture refused(quota);VectorRandomAccessSource refused_source(refused.image);CapacityPair(refused_source,refused.checkpoint,growing,false);
    }
}
void WindowsUnsupportedBoundaries()
{
    const auto spec=WindowsSpec();Fixture fixture(spec);const auto request=WindowsOverwrite(spec);
    auto negative=[&](const std::string& name,std::vector<std::byte> bytes,std::uint16_t flags=kAppleXattrDataEmbedded){
        auto changed=request;
        std::erase_if(changed.filesystem_records,[](const auto& r){return(ReadU64LE(r.key,0).value_or(0)>>60)==4;});
        AddXattr(changed.filesystem_records,100,name,bytes);
        PutU16LE(changed.filesystem_records.back().value,0,flags);
        Check(PreviewWindows(fixture,changed)==AppleCapacityPreviewResult::Unsupported,"unsupported Windows profile: "+name);
    };
    for(const auto size:{7u,9u}){auto bytes=DosBytes();bytes.resize(size);negative("com.apfsaccess.windows.attributes",bytes);}
    auto bytes=DosBytes();bytes[0]=std::byte{0};negative("com.apfsaccess.windows.attributes",bytes);
    bytes=DosBytes();bytes[3]=std::byte{2};negative("com.apfsaccess.windows.attributes",bytes);
    negative("com.apfsaccess.windows.attributes",DosBytes(0x80000000));
    bytes=SecurityBytes();bytes.push_back(std::byte{0xA7});negative("com.apfsaccess.windows.security",bytes);
    bytes=SecurityBytes();bytes.pop_back();negative("com.apfsaccess.windows.security",bytes);
    bytes=SecurityBytes();bytes[3]=std::byte{2};negative("com.apfsaccess.windows.security",bytes);
    bytes=SecurityBytes();bytes[4]=std::byte{0};negative("com.apfsaccess.windows.security",bytes);
    bytes=SecurityBytes();PutU32LE(bytes,8,0xFFFFFFF0);negative("com.apfsaccess.windows.security",bytes);
    for(const auto flags:{std::uint16_t(kAppleXattrDataEmbedded|kAppleXattrDataStream),
        std::uint16_t(kAppleXattrDataEmbedded|kAppleXattrFileSystemOwned),std::uint16_t(kAppleXattrDataEmbedded|0x8000)})
        negative("com.apfsaccess.windows.attributes",DosBytes(),flags);
    for(const auto* name:{"user.test","com.apfsaccess.windows.attributes.extra","com.apfsaccess.unknown",
        "com.apple.ResourceFork","com.apple.decmpfs","com.apple.fs.symlink","com.apfsaccess.windows.directory-symlink"})negative(name,DosBytes());
    auto stream=request;std::erase_if(stream.filesystem_records,[](const auto& r){return(ReadU64LE(r.key,0).value_or(0)>>60)==4;});
    bytes.assign(kAppleXattrDataStreamBytes,std::byte{0});PutU64LE(bytes,0,1000);
    AddXattr(stream.filesystem_records,100,"com.apfsaccess.windows.attributes",bytes,kAppleXattrDataStream);
    Check(PreviewWindows(fixture,stream)==AppleCapacityPreviewResult::Unsupported,"streamed Windows attribute keeps full fallback");
    for(const unsigned kind:{0u,1u,2u}){
        auto changed=request;std::string error;
        for(auto& r:changed.filesystem_records)if((ReadU64LE(r.key,0).value_or(0)>>60)==3){
            AppleInodeRecord inode;Check(ApfsExtendedRecordCodec::DecodeInode(r,inode,error),error);
            if(inode.object_id!=100)continue;
            if(kind==0)inode.mode=0120777;if(kind==1)inode.bsd_flags|=kAppleBsdCompressedFlag;if(kind==2)inode.internal_flags|=kAppleInodeSparseFlag;
            Check(EncodeAppleInodeRecord(inode,r,error),error);
        }
        Check(PreviewWindows(fixture,changed)==AppleCapacityPreviewResult::Unsupported,"symlink/compressed/sparse remains unsupported");
    }
    auto unknown=spec;AddXattr(unknown.volumes[0].filesystem_records,2,"user.unrelated",DosBytes());Fixture old_unknown(unknown);
    Check(PreviewWindows(old_unknown,request)==AppleCapacityPreviewResult::Unsupported,"unrelated old unknown xattr cannot disappear through preview eligibility");
    auto duplicate=request;AddWindows(duplicate.filesystem_records,100,0);
    Check(PreviewWindows(fixture,duplicate)==AppleCapacityPreviewResult::Unsupported,"duplicate xattr key retains full normalization policy");
    auto owner=request;AddWindows(owner.filesystem_records,999,0);
    Check(PreviewWindows(fixture,owner)==AppleCapacityPreviewResult::Unsupported,"orphan xattr owner cannot activate geometry");
    auto malformed=request;for(auto& r:malformed.filesystem_records)if((ReadU64LE(r.key,0).value_or(0)>>60)==4){r.value.pop_back();break;}
    Check(PreviewWindows(fixture,malformed)==AppleCapacityPreviewResult::Unsupported,"malformed embedded length cannot activate geometry");
}
void WindowsSmallFileBatch()
{
    auto spec=Spec();spec.block_count=2048;Fixture fixture(spec);
    AppleVolumeTransactionRequest request;request.volume_object_id=101;request.file_count_delta=32;
    request.filesystem_records=Records(0);std::string error;
    AppleInodeRecord root;Check(ApfsExtendedRecordCodec::DecodeInode(request.filesystem_records[0],root,error),error);
    root.children_or_links=32;Check(EncodeAppleInodeRecord(root,request.filesystem_records[0],error),error);
    for(unsigned i=0;i<32;++i){
        AppleInodeRecord inode;inode.object_id=inode.private_id=100+i;inode.parent_id=2;
        inode.mode=0100644;inode.children_or_links=1;inode.uncompressed_size=kBlockSize;
        AppleExtendedField stream;stream.type=8;stream.flags=1;stream.data.resize(40);
        PutU64LE(stream.data,0,kBlockSize);PutU64LE(stream.data,8,kBlockSize);inode.extended_fields.push_back(stream);
        BtreeRecord record;Check(EncodeAppleInodeRecord(inode,record,error),error);request.filesystem_records.push_back(record);
        AppleDirectoryRecord directory;directory.parent_id=2;directory.file_id=inode.object_id;directory.flags=8;
        directory.name_utf8="windows-"+std::to_string(i)+".bin";
        Check(EncodeAppleDirectoryRecord(directory,ApfsNamePolicy::FromIncompatibleFeatures(kIncompatCaseInsensitive),record,error),error);
        request.filesystem_records.push_back(record);AddWindows(request.filesystem_records,inode.object_id);
        AppleVolumeDataWrite data;data.file_private_id=inode.private_id;data.bytes.assign(kBlockSize,std::byte(128+i));
        request.data_writes.push_back(std::move(data));
    }
    Check(PreviewWindows(fixture,request)==AppleCapacityPreviewResult::Planned,"32 files with 64 validated Windows xattrs activate geometry");
    VectorRandomAccessSource source(fixture.image);std::cout<<"WINDOWS_SMALL_BATCH ";
    const auto full=CapacityPair(source,fixture.checkpoint,request,true,true);
    Check(full.payload_blocks.size()==32,"64 inline records never add regular data payload blocks");
    Publish(fixture,full);CheckInlineBytes(full.filesystem_records,ColdWindowsRecords(fixture));
    for(unsigned i=0;i<32;++i)Check(std::all_of(fixture.image.begin()+full.payload_blocks[i]*kBlockSize,
        fixture.image.begin()+(full.payload_blocks[i]+1)*kBlockSize,[&](auto byte){return byte==std::byte(128+i);}),
        "cold batched ordinary payload byte identity");
}
}

int main(int argc,char** argv)
{
    if(argc==2&&std::string_view(argv[1])=="--old-windows-fallback"){
        const auto spec=WindowsSpec();Fixture fixture(spec);
        Check(PreviewWindows(fixture,WindowsOverwrite(spec))==AppleCapacityPreviewResult::Unsupported,"actual BAD9 rejects valid embedded Windows profile");
        std::cout<<"PASS EXPECTED_BAD9_WINDOWS_FALLBACK checks="<<checks<<'\n';return 0;
    }
    const std::pair<const char*, std::function<void()>> cases[] = {
        {"quota boundaries", QuotaBoundaries},
        {"over-quota non-growing", OverQuotaNonGrowing},
        {"sibling reserve boundaries", SiblingReserveBoundaries},
        {"COW and deferred releases", CowAndReleasedBlocks},
        {"invalid evidence", InvalidEvidence},
        {"reclaimed versus pinned", ReclaimedVersusPinned},
        {"source and publication drift", SourceAndPublicationDrift},
        {"extended snapshot metadata admission", ExtendedSnapshotMetadataAdmission},
        {"OMAP role admission", OmapRoleAdmission},
        {"capacity boundaries and measured work", CapacityBoundariesAndWork},
        {"capacity source and retention", CapacitySourceAndRetention},
        {"capacity partial COW and publication guard", CapacityPartialCowAndPublishGuard},
        {"Windows inline capacity equality and publication", WindowsEqualityAndPublication},
        {"Windows unsupported profile boundaries", WindowsUnsupportedBoundaries},
        {"Windows 32-file attributed batch", WindowsSmallFileBatch},
    };
    std::size_t passed = 0;
    for (const auto& [name, run] : cases)
    {
        try { run(); ++passed; std::cout << "PASS " << name << '\n'; }
        catch (const std::exception& error) { std::cerr << "FAIL " << name << ": " << error.what() << '\n'; }
    }
    std::cout << passed << '/' << std::size(cases) << " groups, " << checks << " checks\n";
    return passed == std::size(cases) ? 0 : 1;
}
