#include "AppleVolumeTransaction.h"
#include "ApfsSharedSpace.h"
#include "TestFixtureBuilder.h"

#include <algorithm>
#include <functional>
#include <iostream>
#include <limits>
#include <stdexcept>

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
}

int main()
{
    const std::pair<const char*, std::function<void()>> cases[] = {
        {"quota boundaries", QuotaBoundaries},
        {"over-quota non-growing", OverQuotaNonGrowing},
        {"sibling reserve boundaries", SiblingReserveBoundaries},
        {"COW and deferred releases", CowAndReleasedBlocks},
        {"invalid evidence", InvalidEvidence},
        {"reclaimed versus pinned", ReclaimedVersusPinned},
        {"source and publication drift", SourceAndPublicationDrift},
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
