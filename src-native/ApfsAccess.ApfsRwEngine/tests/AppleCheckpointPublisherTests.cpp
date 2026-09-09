#include "AppleCheckpointPublisher.h"
#include "AppleSpacemanAllocator.h"
#include "AppleTransactionCommit.h"
#include "AppleVolumeTransaction.h"
#include "ApfsFormat.h"
#include "ApfsTransactionWriter.h"
#include "BlockDevice.h"
#include "NativeApfsReader.h"
#include "TestFixtureBuilder.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace
{

using namespace apfsaccess::catalog;
using namespace apfsaccess::rw;
using namespace apfsaccess::testfixture;

constexpr std::uint32_t kBlockSize = 4096;
int g_failures = 0;

bool Require(bool condition, const std::string& message)
{
    if (!condition)
    {
        std::cerr << "[FAIL] " << message << std::endl;
        ++g_failures;
        return false;
    }
    return true;
}

void PutBlock(std::vector<std::byte>& image, std::uint64_t block,
    const std::vector<std::byte>& bytes, std::size_t source_offset = 0)
{
    const auto destination = static_cast<std::size_t>(block) * kBlockSize;
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(source_offset),
        kBlockSize, image.begin() + static_cast<std::ptrdiff_t>(destination));
}

std::vector<std::byte> ReadMappedObject(const std::vector<std::byte>& image,
    const NxSuperblock& nxsb, const CheckpointMapping& mapping)
{
    std::vector<std::byte> object(mapping.size_bytes, std::byte{0});
    const auto first = mapping.physical_block - nxsb.xp_data_base_block;
    const auto blocks = mapping.size_bytes / nxsb.block_size;
    for (std::uint32_t ordinal = 0; ordinal < blocks; ++ordinal)
    {
        const auto relative = (first + ordinal) % nxsb.xp_data_block_count;
        const auto source = static_cast<std::size_t>(
            nxsb.xp_data_base_block + relative) * nxsb.block_size;
        std::copy_n(image.begin() + static_cast<std::ptrdiff_t>(source),
            nxsb.block_size,
            object.begin() + static_cast<std::ptrdiff_t>(ordinal * nxsb.block_size));
    }
    return object;
}

bool SameMappings(const std::vector<CheckpointMapping>& left,
    const std::vector<CheckpointMapping>& right)
{
    return left.size() == right.size() &&
        std::equal(left.begin(), left.end(), right.begin(),
            [](const auto& lhs, const auto& rhs) {
                return lhs.type == rhs.type && lhs.subtype == rhs.subtype &&
                    lhs.size_bytes == rhs.size_bytes &&
                    lhs.file_system_oid == rhs.file_system_oid &&
                    lhs.object_id == rhs.object_id &&
                    lhs.physical_block == rhs.physical_block;
            });
}

struct PublisherFixture
{
    std::vector<std::byte> image;
    ContainerCheckpointView checkpoint;
};

PublisherFixture BuildWrappedPublisherFixture(
    std::uint32_t descriptor_blocks = 8, std::uint32_t data_blocks = 8,
    bool start_at_zero = false)
{
    constexpr std::uint64_t kBlockCount = 64;
    constexpr std::uint64_t kDescriptorBase = 40;
    constexpr std::uint64_t kDataBase = 48;
    constexpr std::uint64_t kSpacemanOid = 100;
    constexpr std::uint64_t kQueueOid = 101;
    PublisherFixture fixture;
    fixture.image.resize(kBlockCount * kBlockSize, std::byte{0});

    BuilderStore anchor;
    anchor.block_count = kBlockCount;
    anchor.xid = 39;
    anchor.next_oid = 1000;
    anchor.xp_desc_base_blocks = kDescriptorBase;
    anchor.xp_desc_blocks = descriptor_blocks;
    anchor.xp_data_base_blocks = kDataBase;
    anchor.xp_data_blocks = data_blocks;
    anchor.spaceman_oid = kSpacemanOid;
    PutBlock(fixture.image, 0, BuildNxsb(anchor, 39, "", kBlockSize));

    BuilderStore selected = anchor;
    selected.xid = 40;
    selected.xp_desc_index = start_at_zero ? 0 : 5;
    selected.xp_desc_len = 2;
    selected.xp_desc_next = (selected.xp_desc_index + 2) % descriptor_blocks;
    selected.xp_data_index = start_at_zero ? 0 : 4;
    selected.xp_data_len = 3;
    selected.xp_data_next = (selected.xp_data_index + 3) % data_blocks;
    CheckpointMappingSpec spaceman;
    spaceman.type = kObjectEphemeral | kObjectTypeSpaceman;
    spaceman.size = kBlockSize * 2;
    spaceman.object_id = kSpacemanOid;
    spaceman.physical_block = kDataBase + selected.xp_data_index;
    CheckpointMappingSpec queue;
    queue.type = kObjectEphemeral | kObjectTypeBtree;
    queue.subtype = kObjectTypeSpacemanFreeQueue;
    queue.object_id = kQueueOid;
    queue.physical_block = spaceman.physical_block + 2;
    PutBlock(fixture.image, kDescriptorBase + selected.xp_desc_index,
        BuildCheckpointMap(40, {spaceman, queue}, kBlockSize,
            kDescriptorBase + selected.xp_desc_index));
    PutBlock(fixture.image, kDescriptorBase + selected.xp_desc_index + 1,
        BuildNxsb(selected, 40, "", kBlockSize));

    auto spaceman_bytes = BuildEphemeralObject(kSpacemanOid, 40,
        spaceman.type, spaceman.subtype, spaceman.size);
    PutBlock(fixture.image, spaceman.physical_block, spaceman_bytes, 0);
    PutBlock(fixture.image, spaceman.physical_block + 1, spaceman_bytes, kBlockSize);
    auto queue_bytes = BuildEphemeralObject(kQueueOid, 40,
        queue.type, queue.subtype, queue.size);
    PutBlock(fixture.image, queue.physical_block, queue_bytes);

    VectorRandomAccessSource source(fixture.image);
    std::string error;
    const auto checkpoint = LoadContainerCheckpointView(
        source, 0, source.SizeBytes(), error);
    if (checkpoint.has_value())
    {
        fixture.checkpoint = checkpoint.value();
    }
    return fixture;
}

AppleCheckpointPublicationRequest BuildRequest(
    const PublisherFixture& fixture)
{
    AppleCheckpointPublicationRequest request;
    request.expected_checkpoint_xid = fixture.checkpoint.superblock.xid;
    request.transaction_xid = fixture.checkpoint.superblock.next_xid;
    request.next_object_id = fixture.checkpoint.superblock.next_oid;
    for (const auto& mapping : fixture.checkpoint.mappings)
    {
        AppleCheckpointEphemeralObject object;
        object.file_system_oid = mapping.file_system_oid;
        object.object.object_id = mapping.object_id;
        object.object.xid = request.transaction_xid;
        object.object.type = mapping.type;
        object.object.subtype = mapping.subtype;
        object.object.size_bytes = mapping.size_bytes;
        object.bytes = ReadMappedObject(
            fixture.image, fixture.checkpoint.superblock, mapping);
        PutU64LE(object.bytes, 0x10, request.transaction_xid);
        FletcherForBlock(object.bytes, object.bytes.size());
        request.ephemeral_objects.push_back(std::move(object));
    }
    return request;
}

class MemoryWriteTarget final : public AppleCheckpointWriteTarget
{
public:
    explicit MemoryWriteTarget(std::vector<std::byte> image,
        std::optional<std::size_t> fail_at = std::nullopt)
        : image_(std::move(image)), fail_at_(fail_at)
    {
    }

    bool ReadBlock(std::uint64_t physical_block, std::uint32_t block_size,
        std::vector<std::byte>& out_bytes) override
    {
        out_bytes.clear();
        const auto offset = physical_block * static_cast<std::uint64_t>(block_size);
        if (offset > image_.size() || block_size > image_.size() - offset)
        {
            return false;
        }
        const auto begin = image_.begin() + static_cast<std::ptrdiff_t>(offset);
        out_bytes.assign(begin, begin + block_size);
        return true;
    }

    bool WriteBlock(std::uint64_t physical_block,
        std::span<const std::byte> bytes) override
    {
        if (ShouldFail())
        {
            return false;
        }
        const auto offset = physical_block * static_cast<std::uint64_t>(bytes.size());
        if (offset > image_.size() || bytes.size() > image_.size() - offset)
        {
            return false;
        }
        std::copy(bytes.begin(), bytes.end(),
            image_.begin() + static_cast<std::ptrdiff_t>(offset));
        written_blocks_.push_back(physical_block);
        return true;
    }

    bool Flush() override
    {
        if (ShouldFail())
        {
            return false;
        }
        flush_write_counts_.push_back(written_blocks_.size());
        return true;
    }

    const std::vector<std::byte>& Image() const noexcept { return image_; }
    std::vector<std::byte>& MutableImage() noexcept { return image_; }
    std::size_t MutatingOperationCount() const noexcept { return operation_; }
    const std::vector<std::uint64_t>& WrittenBlocks() const noexcept
    {
        return written_blocks_;
    }
    const std::vector<std::size_t>& FlushWriteCounts() const noexcept
    {
        return flush_write_counts_;
    }

private:
    bool ShouldFail()
    {
        const auto current = operation_++;
        return fail_at_.has_value() && current == fail_at_.value();
    }

    std::vector<std::byte> image_;
    std::optional<std::size_t> fail_at_;
    std::size_t operation_ = 0;
    std::vector<std::uint64_t> written_blocks_;
    std::vector<std::size_t> flush_write_counts_;
};

// Exercises the executor with patterned 16 KiB blocks independently of the
// checkpoint parser. Existing fixtures below cover real planned checkpoints.
constexpr std::uint32_t kReadbackBlockSize = 16 * 1024;
constexpr std::size_t kReadbackBlocksPerRange = 64;

AppleCheckpointPublicationPlan BuildReadbackPlan(
    const std::vector<std::uint64_t>& blocks)
{
    AppleCheckpointPublicationPlan plan;
    plan.block_size = kReadbackBlockSize;
    plan.expected_checkpoint_xid = 40;
    plan.transaction_xid = 41;
    plan.guard_blocks.push_back({0,
        std::vector<std::byte>(plan.block_size, std::byte{0})});
    for (const auto block : blocks)
    {
        AppleCheckpointPlannedWrite write;
        write.physical_block = block;
        write.bytes.resize(plan.block_size);
        for (std::size_t byte = 0; byte < write.bytes.size(); ++byte)
        {
            write.bytes[byte] = static_cast<std::byte>(
                (block * 37 + byte * 13 + byte / 256) & 0xffu);
        }
        plan.before_superblock_writes.push_back(std::move(write));
    }
    plan.superblock_write.kind = AppleCheckpointWriteKind::CheckpointSuperblock;
    plan.superblock_write.physical_block =
        *std::max_element(blocks.begin(), blocks.end()) + 1;
    plan.superblock_write.bytes.assign(plan.block_size, std::byte{0xA5});
    return plan;
}

AppleCheckpointPublicationPlan BuildContiguousReadbackPlan()
{
    std::vector<std::uint64_t> blocks;
    for (std::uint64_t block = 1; block <= 2 * kReadbackBlocksPerRange + 2; ++block)
    {
        blocks.push_back(block);
    }
    return BuildReadbackPlan(blocks);
}

class ReadbackWriteTarget final : public AppleCheckpointWriteTarget
{
public:
    enum class Fault { None, Fail, Empty, Short, Extra };

    explicit ReadbackWriteTarget(const AppleCheckpointPublicationPlan& plan,
        bool coalesce = true)
        : memory(std::vector<std::byte>(
              (plan.superblock_write.physical_block + 1) * plan.block_size)),
          coalesce_(coalesce)
    {
    }

    bool ReadBlock(std::uint64_t block, std::uint32_t block_size,
        std::vector<std::byte>& bytes) override
    {
        single_reads.push_back(block);
        if (fail_block == block)
        {
            ++faults_injected;
            return false;
        }
        if (!memory.ReadBlock(block, block_size, bytes)) return false;
        Corrupt(block, block_size, bytes);
        return true;
    }

    bool ReadBlockRange(std::uint64_t block, std::uint32_t block_size,
        std::size_t max_blocks, std::vector<std::byte>& bytes) override
    {
        if (!coalesce_)
        {
            return AppleCheckpointWriteTarget::ReadBlockRange(
                block, block_size, max_blocks, bytes);
        }
        range_reads.emplace_back(block, max_blocks);
        if (fault_range == range_reads.size() - 1 && fault == Fault::Fail)
        {
            ++faults_injected;
            return false;
        }
        const auto offset = block * static_cast<std::uint64_t>(block_size);
        const auto size = max_blocks * block_size;
        if (offset > memory.Image().size() || size > memory.Image().size() - offset)
        {
            return false;
        }
        const auto begin = memory.Image().begin() + static_cast<std::ptrdiff_t>(offset);
        bytes.assign(begin, begin + static_cast<std::ptrdiff_t>(size));
        range_buffers.push_back(bytes.data());
        Corrupt(block, block_size, bytes);
        if (fault_range == range_reads.size() - 1 && fault != Fault::None)
        {
            ++faults_injected;
            if (fault == Fault::Empty) bytes.clear();
            if (fault == Fault::Short) bytes.pop_back();
            if (fault == Fault::Extra) bytes.resize(bytes.size() + block_size);
        }
        return true;
    }

    bool WriteBlock(std::uint64_t block, std::span<const std::byte> bytes) override
    {
        return memory.WriteBlock(block, bytes);
    }

    bool Flush() override { return memory.Flush(); }

    MemoryWriteTarget memory;
    std::vector<std::uint64_t> single_reads;
    std::vector<std::pair<std::uint64_t, std::size_t>> range_reads;
    std::vector<const std::byte*> range_buffers;
    std::optional<std::uint64_t> corrupt_block;
    std::size_t corrupt_byte = 0;
    std::optional<std::uint64_t> fail_block;
    std::optional<std::size_t> fault_range;
    Fault fault = Fault::None;
    std::size_t faults_injected = 0;

private:
    void Corrupt(std::uint64_t first, std::uint32_t block_size,
        std::vector<std::byte>& bytes)
    {
        if (corrupt_block && *corrupt_block >= first &&
            *corrupt_block - first < bytes.size() / block_size &&
            corrupt_byte < block_size)
        {
            bytes[(*corrupt_block - first) * block_size + corrupt_byte] ^= std::byte{1};
            ++faults_injected;
        }
    }

    bool coalesce_;
};

bool RequireReadbackStoppedBeforePublication(const ReadbackWriteTarget& target,
    const AppleCheckpointPublicationPlan& plan, const std::string& label)
{
    std::vector<std::uint64_t> expected_writes;
    for (const auto& write : plan.before_superblock_writes)
    {
        expected_writes.push_back(write.physical_block);
    }
    const auto nxsb_begin = target.memory.Image().begin() +
        static_cast<std::ptrdiff_t>(plan.superblock_write.physical_block * plan.block_size);
    return Require(target.faults_injected == 1 &&
            target.memory.WrittenBlocks() == expected_writes &&
            target.memory.FlushWriteCounts().empty() &&
            std::all_of(nxsb_begin, nxsb_begin + plan.block_size,
                [](std::byte value) { return value == std::byte{0}; }),
        label + ": fault reached after ordered writes, no flush or NXSB publication");
}

bool TestBoundedReadbackCoalescesAndChecksAllBytes()
{
    const auto plan = BuildContiguousReadbackPlan();
    ReadbackWriteTarget target(plan);
    std::string error;
    std::vector<std::string> stages;
    bool ok = Require(ExecuteAppleCheckpointPublication(target, plan, error,
            [&](std::string_view stage) { stages.emplace_back(stage); return true; }),
        "bounded readback executes: " + error);
    const std::vector<std::pair<std::uint64_t, std::size_t>> expected_ranges{
        {1, 64}, {65, 64}, {129, 2}};
    ok &= Require(target.range_reads == expected_ranges &&
            target.range_buffers.size() == 3 &&
            target.range_buffers[0] == target.range_buffers[1] &&
            target.range_buffers[1] == target.range_buffers[2],
        "130 blocks use three bounded ranges and reuse scratch storage");
    std::vector<std::uint64_t> expected_writes;
    for (const auto& write : plan.before_superblock_writes)
    {
        expected_writes.push_back(write.physical_block);
        const auto begin = target.memory.Image().begin() +
            static_cast<std::ptrdiff_t>(write.physical_block * plan.block_size);
        ok &= Require(std::equal(write.bytes.begin(), write.bytes.end(), begin),
            "every patterned byte is stored for block " + std::to_string(write.physical_block));
    }
    expected_writes.push_back(plan.superblock_write.physical_block);
    const auto nxsb_begin = target.memory.Image().begin() +
        static_cast<std::ptrdiff_t>(plan.superblock_write.physical_block * plan.block_size);
    ok &= Require(target.memory.WrittenBlocks() == expected_writes &&
            std::equal(plan.superblock_write.bytes.begin(),
                plan.superblock_write.bytes.end(), nxsb_begin) &&
            target.memory.FlushWriteCounts() == std::vector<std::size_t>{130, 131} &&
            target.single_reads == std::vector<std::uint64_t>{0, 0, 131} &&
            stages == std::vector<std::string>{"before-apple-device-write",
                "before-apple-prepublication-flush", "before-apple-checkpoint-switch",
                "before-apple-final-flush"},
        "write order, both guard passes, NXSB-last verification, hooks and flush barriers remain");

    // Independently damage bytes beyond the header and around word/sector
    // boundaries, even though the underlying stored block remains correct.
    const auto byte_plan = BuildReadbackPlan({1, 2, 3});
    for (const std::size_t byte : {0u, 1u, 7u, 8u, 31u, 32u, 255u, 256u,
             511u, 512u, 4095u, 4096u, 8191u, 8192u, 16382u, 16383u})
    {
        ReadbackWriteTarget corrupt(byte_plan);
        corrupt.corrupt_block = 2;
        corrupt.corrupt_byte = byte;
        error.clear();
        if (!Require(!ExecuteAppleCheckpointPublication(corrupt, byte_plan, error) &&
                error == "AppleCheckpointReadbackFailed",
                "full-block comparison detects changed byte at offset " + std::to_string(byte)) ||
            !RequireReadbackStoppedBeforePublication(corrupt, byte_plan,
                "byte " + std::to_string(byte))) return false;
    }
    return ok;
}

bool TestBoundedReadbackPreservesNonadjacentOrder()
{
    const auto plan = BuildReadbackPlan({10, 11, 4, 5, 7, 6, 20});
    ReadbackWriteTarget target(plan);
    std::string error;
    bool ok = Require(ExecuteAppleCheckpointPublication(target, plan, error),
        "nonadjacent readback executes: " + error);
    const std::vector<std::pair<std::uint64_t, std::size_t>> expected{
        {10, 2}, {4, 2}, {7, 1}, {6, 1}, {20, 1}};
    ok &= Require(target.range_reads == expected &&
            target.memory.WrittenBlocks() ==
                std::vector<std::uint64_t>{10, 11, 4, 5, 7, 6, 20, 21},
        "only forward-adjacent blocks merge in existing order, without bridging gaps");
    return ok;
}

bool TestBoundedReadbackCorruptionAndFailuresStopPublication()
{
    const auto plan = BuildContiguousReadbackPlan();
    bool ok = true;
    for (const auto block : {1ULL, 32ULL, 64ULL, 65ULL, 96ULL, 128ULL, 129ULL, 130ULL})
    {
        for (const std::size_t byte : {std::size_t{0}, std::size_t{kReadbackBlockSize / 2},
                 std::size_t{kReadbackBlockSize - 1}})
        {
            ReadbackWriteTarget target(plan);
            target.corrupt_block = block;
            target.corrupt_byte = byte;
            std::string error;
            std::vector<std::string> stages;
            const auto label = "corrupt block " + std::to_string(block) +
                " byte " + std::to_string(byte);
            ok &= Require(!ExecuteAppleCheckpointPublication(target, plan, error,
                    [&](std::string_view stage) { stages.emplace_back(stage); return true; }) &&
                    error == "AppleCheckpointReadbackFailed" &&
                    target.range_reads.size() == (block - 1) / kReadbackBlocksPerRange + 1 &&
                    stages == std::vector<std::string>{"before-apple-device-write"}, label);
            ok &= RequireReadbackStoppedBeforePublication(target, plan, label);
        }
    }
    for (std::size_t range = 0; range < 3; ++range)
    {
        for (const auto fault : {ReadbackWriteTarget::Fault::Fail,
                 ReadbackWriteTarget::Fault::Empty, ReadbackWriteTarget::Fault::Short,
                 ReadbackWriteTarget::Fault::Extra})
        {
            ReadbackWriteTarget target(plan);
            target.fault_range = range;
            target.fault = fault;
            std::string error;
            const auto label = "range " + std::to_string(range) +
                " fault " + std::to_string(static_cast<int>(fault));
            ok &= Require(!ExecuteAppleCheckpointPublication(target, plan, error) &&
                    error == "AppleCheckpointReadbackFailed" &&
                    target.range_reads.size() == range + 1, label);
            ok &= RequireReadbackStoppedBeforePublication(target, plan, label);
        }
    }
    return ok;
}

bool TestDefaultReadbackPreservesSingleBlockFailureOrder()
{
    const auto plan = BuildReadbackPlan({1, 2, 3, 4, 5});
    ReadbackWriteTarget completed(plan, false);
    std::string error;
    bool ok = Require(ExecuteAppleCheckpointPublication(completed, plan, error) &&
            completed.range_reads.empty() &&
            completed.single_reads == std::vector<std::uint64_t>{0, 1, 2, 3, 4, 5, 0, 6},
        "default range fallback keeps every original single-block read: " + error);
    for (const auto block : {1ULL, 3ULL, 5ULL})
    {
        for (const bool read_failure : {false, true})
        {
            ReadbackWriteTarget target(plan, false);
            if (read_failure) target.fail_block = block;
            else target.corrupt_block = block;
            std::vector<std::uint64_t> expected_reads{0};
            for (std::uint64_t read = 1; read <= block; ++read) expected_reads.push_back(read);
            error.clear();
            ok &= Require(!ExecuteAppleCheckpointPublication(target, plan, error) &&
                    error == "AppleCheckpointReadbackFailed" &&
                    target.single_reads == expected_reads && target.range_reads.empty(),
                "legacy target stops at first bad block " + std::to_string(block));
            ok &= RequireReadbackStoppedBeforePublication(target, plan, "legacy failure");
        }
    }
    return ok;
}

bool TestPlansAndPublishesWrappedCheckpoint()
{
    const auto fixture = BuildWrappedPublisherFixture();
    bool ok = Require(fixture.checkpoint.superblock.xid == 40,
        "wrapped publisher fixture selects its old checkpoint");
    if (!ok)
    {
        return false;
    }
    auto request = BuildRequest(fixture);
    request.container_object_map_oid = 25;
    request.allocator_owned_writes.push_back({25,
        BuildOmap(26, request.transaction_xid, kBlockSize, 25,
            kObjectPhysical | kObjectTypeOmap,
            kObjectPhysical | kObjectTypeBtree)});
    VectorRandomAccessSource source(fixture.image);
    AppleCheckpointPublicationPlan plan;
    std::string error;
    ok &= Require(PlanAppleCheckpointPublication(
            source, fixture.checkpoint, request, plan, error),
        "checkpoint publication plan succeeds: " + error);
    if (!ok)
    {
        return false;
    }
    ok &= Require(plan.published_checkpoint.superblock.xid == 41 &&
            plan.published_checkpoint.superblock.omap_oid == 25 &&
            plan.published_checkpoint.superblock.xp_data_index == 7 &&
            plan.published_checkpoint.superblock.xp_data_len == 3 &&
            plan.published_checkpoint.superblock.xp_data_next == 2 &&
            plan.published_checkpoint.superblock.xp_desc_index == 7 &&
            plan.published_checkpoint.superblock.xp_desc_len == 2 &&
            plan.published_checkpoint.superblock.xp_desc_next == 1,
        "new descriptor and data generations wrap without touching the old one");
    ok &= Require(plan.published_checkpoint.mappings.size() == 2 &&
            plan.published_checkpoint.mappings[0].physical_block == 55 &&
            plan.published_checkpoint.mappings[1].physical_block == 49,
        "multi-block ephemeral objects are packed across the ring boundary");
    const auto map = std::find_if(plan.before_superblock_writes.begin(),
        plan.before_superblock_writes.end(), [](const auto& write) {
            return write.kind == AppleCheckpointWriteKind::CheckpointMap;
        });
    ok &= Require(map != plan.before_superblock_writes.end() &&
            ReadU64LE(map->bytes, 0x08).value_or(0) == map->physical_block &&
            ReadU32LE(map->bytes, 0x18).value_or(0) ==
                (kObjectPhysical | kObjectTypeCheckpointMap),
        "checkpoint map is a physical object with physical identity");

    MemoryWriteTarget target(fixture.image);
    ok &= Require(ExecuteAppleCheckpointPublication(target, plan, error),
        "checkpoint publication executes: " + error);
    VectorRandomAccessSource published_source(target.Image());
    const auto published = LoadContainerCheckpointView(
        published_source, 0, published_source.SizeBytes(), error);
    ok &= Require(published.has_value() &&
            published->superblock.xid == request.transaction_xid &&
            SameMappings(published->mappings,
                plan.published_checkpoint.mappings),
        "independent parser selects the complete new wrapped checkpoint: " + error);
    return ok;
}

bool TestEveryCrashPrefixSelectsOldOrNew()
{
    const auto fixture = BuildWrappedPublisherFixture();
    const auto request = BuildRequest(fixture);
    VectorRandomAccessSource source(fixture.image);
    AppleCheckpointPublicationPlan plan;
    std::string error;
    bool ok = Require(PlanAppleCheckpointPublication(
            source, fixture.checkpoint, request, plan, error),
        "crash-prefix plan succeeds: " + error);
    if (!ok)
    {
        return false;
    }
    MemoryWriteTarget complete(fixture.image);
    ok &= Require(ExecuteAppleCheckpointPublication(complete, plan, error),
        "complete prefix establishes operation count: " + error);
    const auto operation_count = complete.MutatingOperationCount();
    for (std::size_t fail_at = 0; fail_at <= operation_count; ++fail_at)
    {
        MemoryWriteTarget interrupted(fixture.image, fail_at);
        error.clear();
        const bool executed = ExecuteAppleCheckpointPublication(
            interrupted, plan, error);
        ok &= Require(executed == (fail_at == operation_count),
            "crash injection has expected completion state at boundary " +
                std::to_string(fail_at));
        VectorRandomAccessSource interrupted_source(interrupted.Image());
        std::string load_error;
        const auto selected = LoadContainerCheckpointView(interrupted_source,
            0, interrupted_source.SizeBytes(), load_error);
        ok &= Require(selected.has_value() &&
                (selected->superblock.xid == request.expected_checkpoint_xid ||
                 selected->superblock.xid == request.transaction_xid),
            "crash boundary selects one complete checkpoint at " +
                std::to_string(fail_at) + ": " + load_error);
    }
    return ok;
}

bool TestPublishesThroughBlockDevice()
{
    const auto fixture = BuildWrappedPublisherFixture();
    const auto request = BuildRequest(fixture);
    VectorRandomAccessSource source(fixture.image);
    AppleCheckpointPublicationPlan plan;
    std::string error;
    bool ok = Require(PlanAppleCheckpointPublication(
            source, fixture.checkpoint, request, plan, error),
        "block-device publication plan succeeds: " + error);
    if (!ok)
    {
        return false;
    }

    const auto stamp = std::chrono::steady_clock::now()
                           .time_since_epoch()
                           .count();
    const auto path = std::filesystem::temp_directory_path() /
        ("apfs-checkpoint-publisher-" + std::to_string(stamp) + ".img");
    {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output.write(reinterpret_cast<const char*>(fixture.image.data()),
            static_cast<std::streamsize>(fixture.image.size()));
    }
    {
        BlockDevice device(path.wstring());
        ok &= Require(device.IsWritable(),
            "checkpoint image opens through writable BlockDevice");
        error.clear();
        ok &= Require(ExecuteAppleCheckpointPublication(device, plan, error),
            "BlockDevice publication executes and flushes: " + error);
    }
    FileRandomAccessSource reopened(path.string());
    error.clear();
    const auto published = LoadContainerCheckpointView(
        reopened, 0, reopened.SizeBytes(), error);
    ok &= Require(published.has_value() &&
            published->superblock.xid == request.transaction_xid,
        "durably reopened image selects the new checkpoint: " + error);
    std::error_code remove_error;
    std::filesystem::remove(path, remove_error);
    ok &= Require(!remove_error, "publisher fixture image removes cleanly");
    return ok;
}

bool TestComposesSpacemanAllocationAndCrashSafePublication()
{
    BuilderStore store;
    store.authoritative_checkpoint = true;
    store.block_count = 96;
    auto image = BuildStoreImage(store);
    VectorRandomAccessSource source(image);
    std::string error;
    const auto checkpoint = LoadAppleCheckpointView(
        source, 0, source.SizeBytes(), error);
    bool ok = Require(checkpoint.has_value(),
        "composed-transaction fixture loads: " + error);
    if (!checkpoint.has_value())
    {
        return false;
    }

    AppleSpacemanAllocationRequest allocation_request;
    allocation_request.expected_checkpoint_xid =
        checkpoint->container.superblock.xid;
    allocation_request.transaction_xid =
        checkpoint->container.superblock.next_xid;
    allocation_request.main_block_count = 1;
    allocation_request.first_ephemeral_object_id =
        checkpoint->container.superblock.next_oid;
    AppleSpacemanAllocationPlan allocation;
    ok &= Require(PlanAppleSpacemanAllocation(checkpoint->spaceman,
            allocation_request, allocation, error),
        "spaceman allocation for composed transaction succeeds: " + error);
    if (!ok)
    {
        return false;
    }

    AppleTransactionCommitRequest request;
    request.allocation_plan = allocation;
    request.next_object_id = checkpoint->container.superblock.next_oid;
    for (const auto& write : allocation.writes)
    {
        if (write.object_location.has_value() &&
            write.object_location->object_id >= request.next_object_id)
        {
            request.next_object_id = write.object_location->object_id + 1;
        }
    }
    const auto payload_block = allocation.allocated_main_blocks.front();
    std::vector<std::byte> payload(kBlockSize, std::byte{0xA5});
    request.allocated_main_writes.push_back({payload_block, payload});

    AppleTransactionCommitPlan transaction;
    auto missing_write = request;
    missing_write.allocated_main_writes.clear();
    error.clear();
    ok &= Require(!PlanAppleTransactionCommit(source, checkpoint.value(),
            missing_write, transaction, error) &&
            error == "AppleTransactionMainWriteIncomplete",
        "missing allocator-owned write is rejected: " + error);
    auto foreign_write = request;
    foreign_write.allocated_main_writes.push_back(
        {1, std::vector<std::byte>(kBlockSize, std::byte{0x5A})});
    error.clear();
    ok &= Require(!PlanAppleTransactionCommit(source, checkpoint.value(),
            foreign_write, transaction, error) &&
            error == "AppleTransactionMainWriteInvalid",
        "foreign main-pool write is rejected: " + error);
    error.clear();
    ok &= Require(PlanAppleTransactionCommit(
            source, checkpoint.value(), request, transaction, error),
        "spaceman allocation composes into checkpoint publication: " + error);
    if (!ok)
    {
        return false;
    }
    ok &= Require(transaction.publication.transaction_xid ==
            allocation_request.transaction_xid &&
            transaction.publication.published_checkpoint.mappings.size() >= 2,
        "composed publication carries the allocator transaction identity");

    MemoryWriteTarget complete(image);
    ok &= Require(ExecuteAppleCheckpointPublication(
            complete, transaction.publication, error),
        "composed allocator transaction publishes: " + error);
    VectorRandomAccessSource published_source(complete.Image());
    const auto published = LoadAppleCheckpointView(
        published_source, 0, published_source.SizeBytes(), error);
    ok &= Require(published.has_value() &&
            published->container.superblock.xid ==
                allocation_request.transaction_xid &&
            published->spaceman.devices[0].free_count ==
                allocation.updated_spaceman.devices[0].free_count,
        "independent reader selects the new allocator state: " + error);
    const auto payload_offset = static_cast<std::size_t>(payload_block) *
        kBlockSize;
    ok &= Require(std::equal(payload.begin(), payload.end(),
            complete.Image().begin() +
                static_cast<std::ptrdiff_t>(payload_offset)),
        "allocator-owned payload bytes reach their reserved block");

    MemoryWriteTarget ownership_changed(image);
    const auto old_bitmap = checkpoint->spaceman.chunks.front().bitmap_block;
    ownership_changed.MutableImage()[
        static_cast<std::size_t>(old_bitmap) * kBlockSize] ^= std::byte{0x01};
    error.clear();
    ok &= Require(!ExecuteAppleCheckpointPublication(ownership_changed,
            transaction.publication, error) &&
            error == "AppleCheckpointGuardChanged" &&
            ownership_changed.MutatingOperationCount() == 0,
        "allocator ownership drift stops before the first write: " + error);

    const auto operation_count = complete.MutatingOperationCount();
    for (std::size_t fail_at = 0; fail_at <= operation_count; ++fail_at)
    {
        MemoryWriteTarget interrupted(image, fail_at);
        error.clear();
        const bool executed = ExecuteAppleCheckpointPublication(
            interrupted, transaction.publication, error);
        ok &= Require(executed == (fail_at == operation_count),
            "composed crash boundary completion state " +
                std::to_string(fail_at));
        VectorRandomAccessSource interrupted_source(interrupted.Image());
        std::string load_error;
        const auto selected = LoadAppleCheckpointView(interrupted_source, 0,
            interrupted_source.SizeBytes(), load_error);
        ok &= Require(selected.has_value() &&
                (selected->container.superblock.xid ==
                     allocation_request.expected_checkpoint_xid ||
                 selected->container.superblock.xid ==
                     allocation_request.transaction_xid),
            "composed crash boundary selects old or new state " +
                std::to_string(fail_at) + ": " + load_error);
    }
    return ok;
}

bool TestPublishesReachableFileThroughBothObjectMaps()
{
    BuilderStore store;
    store.authoritative_checkpoint = true;
    store.block_count = 192;
    store.volumes[0].incompat = kIncompatCaseInsensitive;
    auto image = BuildStoreImage(store);
    VectorRandomAccessSource source(image);
    std::string error;
    const auto checkpoint = LoadAppleCheckpointView(
        source, 0, source.SizeBytes(), error);
    bool ok = Require(checkpoint.has_value(),
        "reachable-file fixture loads: " + error);
    if (!checkpoint.has_value())
    {
        return false;
    }

    constexpr std::uint64_t kFileId = 100;
    std::vector<apfsaccess::catalog::BtreeRecord> records;
    AppleInodeRecord root;
    root.object_id = 2;
    root.parent_id = 2;
    root.private_id = 9;
    root.children_or_links = 1;
    root.mode = 0040755;
    apfsaccess::catalog::BtreeRecord record;
    ok &= Require(EncodeAppleInodeRecord(root, record, error),
        "encode replacement root inode: " + error);
    records.push_back(std::move(record));

    const std::string payload_text =
        "APFS Access genuine transaction payload";
    AppleInodeRecord file;
    file.object_id = kFileId;
    file.parent_id = 2;
    file.private_id = kFileId;
    file.children_or_links = 1;
    file.mode = 0100644;
    file.uncompressed_size = payload_text.size();
    ok &= Require(EncodeAppleInodeRecord(file, record, error),
        "encode reachable file inode: " + error);
    records.push_back(std::move(record));

    AppleDirectoryRecord directory;
    directory.parent_id = 2;
    directory.file_id = kFileId;
    directory.flags = 8;
    directory.name_utf8 = "hello.bin";
    ok &= Require(EncodeAppleDirectoryRecord(
            directory,
            ApfsNamePolicy::FromIncompatibleFeatures(kIncompatCaseInsensitive),
            record,
            error),
        "encode reachable directory record: " + error);
    records.push_back(std::move(record));

    AppleVolumeTransactionRequest request;
    request.volume_object_id = checkpoint->volumes.front().superblock.object_id;
    request.filesystem_records = records;
    request.file_count_delta = 1;
    AppleVolumeDataWrite data;
    data.file_private_id = kFileId;
    data.bytes.assign(
        reinterpret_cast<const std::byte*>(payload_text.data()),
        reinterpret_cast<const std::byte*>(payload_text.data() +
            payload_text.size()));
    request.data_writes.push_back(std::move(data));

    AppleVolumeTransactionPlan transaction;
    error.clear();
    const bool planned = PlanAppleVolumeTransaction(
        source, checkpoint.value(), request, transaction, error);
    ok &= Require(planned,
        "reachable Apple transaction plans: " + error);
    if (!ok)
    {
        return false;
    }
    AppleDataStreamIdRecord planned_stream;
    const auto planned_stream_count = std::count_if(
        transaction.filesystem_records.begin(),
        transaction.filesystem_records.end(), [&](const auto& candidate) {
            std::string decode_error;
            AppleDataStreamIdRecord stream;
            if (!DecodeAppleDataStreamIdRecord(
                    candidate, stream, decode_error) ||
                stream.object_id != kFileId)
            {
                return false;
            }
            planned_stream = stream;
            return true;
        });
    ok &= Require(planned_stream_count == 1 &&
            planned_stream.reference_count == 1,
        "new payload creates one private data-stream reference record");
      ok &= Require(transaction.payload_blocks.size() == 1 &&
            transaction.commit.publication.published_checkpoint.superblock.omap_oid !=
                checkpoint->container.superblock.omap_oid,
          "transaction replaces the container object map and allocates payload");

      const std::array<std::uint64_t, 4> stable_blocks{
          checkpoint->volumes.front().root_tree.physical_block,
          checkpoint->volumes.front().object_map.object.physical_block,
          checkpoint->volumes.front().superblock_object.physical_block,
          checkpoint->container_object_map.object.physical_block};
      for (const auto stable_block : stable_blocks)
      {
          MemoryWriteTarget changed(image);
          changed.MutableImage()[static_cast<std::size_t>(stable_block) *
              kBlockSize + 0x20] ^= std::byte{0x01};
          error.clear();
          ok &= Require(!ExecuteAppleCheckpointPublication(changed,
                  transaction.commit.publication, error) &&
                  error == "AppleCheckpointGuardChanged" &&
                  changed.MutatingOperationCount() == 0,
              "stable volume metadata drift stops before first write: " +
                  error);
      }

      MemoryWriteTarget complete(image);
      ok &= Require(ExecuteAppleCheckpointPublication(
              complete, transaction.commit.publication, error),
          "reachable Apple transaction publishes: " + error);
      const auto staged_write_count =
          transaction.commit.publication.before_superblock_writes.size();
      ok &= Require(complete.WrittenBlocks().size() == staged_write_count + 1 &&
              complete.WrittenBlocks().back() ==
                  transaction.commit.publication.superblock_write.physical_block &&
              complete.FlushWriteCounts() ==
                  std::vector<std::size_t>{staged_write_count,
                      staged_write_count + 1},
          "publication orders staged writes, barrier, NXSB, final barrier");
      constexpr char private_magic[] = "APFSRW";
      const auto* magic_begin = reinterpret_cast<const std::byte*>(
          private_magic);
      ok &= Require(std::search(complete.Image().begin(),
              complete.Image().end(), magic_begin,
              magic_begin + sizeof(private_magic) - 1) ==
              complete.Image().end(),
          "published Apple transaction contains no private checkpoint magic");
      VectorRandomAccessSource published_source(complete.Image());
    const auto published = LoadAppleCheckpointView(
        published_source, 0, published_source.SizeBytes(), error);
    ok &= Require(published.has_value() &&
            published->container.superblock.xid ==
                checkpoint->container.superblock.next_xid &&
            published->volumes.front().superblock.omap_oid !=
                checkpoint->volumes.front().superblock.omap_oid &&
            published->volumes.front().root_tree.physical_block !=
                checkpoint->volumes.front().root_tree.physical_block,
        "independent checkpoint parser follows both replacement object maps: " +
            error);

    const auto stamp = std::chrono::steady_clock::now()
                           .time_since_epoch().count();
    const auto path = std::filesystem::temp_directory_path() /
        ("apfs-reachable-transaction-" + std::to_string(stamp) + ".img");
      {
          std::ofstream output(path, std::ios::binary | std::ios::trunc);
          output.write(reinterpret_cast<const char*>(image.data()),
              static_cast<std::streamsize>(image.size()));
      }
      {
          BlockDevice device(path.wstring());
          error.clear();
          ok &= Require(device.IsWritable() &&
                  ExecuteAppleCheckpointPublication(
                      device, transaction.commit.publication, error),
              "complete volume transaction publishes through BlockDevice: " +
                  error);
      }
      {
          BlockDevice device(path.wstring());
          NativeApfsVolumeProjection projection;
        std::wstring reader_error;
        ok &= Require(NativeApfsReader::TryLoadVolumeProjection(
                device, request.volume_object_id, projection, reader_error),
            "Windows reader projects published transaction");
        const auto inode = std::find_if(projection.inodes.begin(),
            projection.inodes.end(), [](const auto& candidate) {
                return candidate.full_path == L"\\hello.bin";
            });
        ok &= Require(inode != projection.inodes.end() &&
                inode->logical_size == payload_text.size(),
            "Windows reader resolves the newly published file");
        const auto extents = projection.read_extents_by_inode.find(kFileId);
        ok &= Require(extents != projection.read_extents_by_inode.end() &&
                extents->second.size() == 1,
            "Windows reader resolves the file payload extent");
        if (extents != projection.read_extents_by_inode.end() &&
            extents->second.size() == 1)
        {
            std::vector<std::byte> bytes;
            ok &= Require(device.Read(extents->second.front().physical_address,
                    payload_text.size(), bytes) &&
                    std::equal(bytes.begin(), bytes.end(),
                        reinterpret_cast<const std::byte*>(
                            payload_text.data())),
                "published payload bytes round-trip through the reader extent");
        }
    }
    std::error_code remove_error;
    std::filesystem::remove(path, remove_error);
    ok &= Require(!remove_error,
        "reachable transaction image removes cleanly");

    const auto operation_count = complete.MutatingOperationCount();
    for (std::size_t fail_at = 0; fail_at <= operation_count; ++fail_at)
    {
        MemoryWriteTarget interrupted(image, fail_at);
        error.clear();
        const bool executed = ExecuteAppleCheckpointPublication(
            interrupted, transaction.commit.publication, error);
        ok &= Require(executed == (fail_at == operation_count),
            "reachable transaction crash completion state " +
                std::to_string(fail_at));
        VectorRandomAccessSource interrupted_source(interrupted.Image());
        std::string load_error;
        const auto selected = LoadAppleCheckpointView(interrupted_source, 0,
            interrupted_source.SizeBytes(), load_error);
          ok &= Require(selected.has_value() &&
                (selected->container.superblock.xid ==
                     checkpoint->container.superblock.xid ||
                 selected->container.superblock.xid ==
                     checkpoint->container.superblock.next_xid),
              "reachable transaction crash selects complete old or new graph " +
                  std::to_string(fail_at) + ": " + load_error);
          if (selected.has_value() &&
              selected->container.superblock.xid ==
                  checkpoint->container.superblock.next_xid)
          {
              const auto& selected_volume = selected->volumes.front();
              BtreeReadPolicy policy;
              policy.enforce_object_identity = true;
              policy.root_object_id = selected_volume.root_tree.object_id;
              policy.storage_type = selected_volume.root_tree.type;
              policy.subtype = selected_volume.root_tree.subtype;
              std::vector<apfsaccess::catalog::BtreeRecord> actual_records;
              ok &= Require(ReadBtreeLeafRecords(interrupted_source,
                      selected->container.superblock.block_size,
                      selected_volume.root_tree.physical_block, false,
                      selected_volume.superblock.omap_oid,
                      selected->container.superblock.xid, policy,
                      actual_records, load_error),
                  "new crash-prefix filesystem graph is readable " +
                      std::to_string(fail_at) + ": " + load_error);
              auto expected_records = transaction.filesystem_records;
              ok &= Require(SortAppleBtreeRecords(expected_records,
                              AppleBtreeKeyOrder::FileSystemHashedDirectory,
                              load_error) &&
                      SortAppleBtreeRecords(actual_records,
                          AppleBtreeKeyOrder::FileSystemHashedDirectory,
                          load_error) &&
                      expected_records.size() == actual_records.size() &&
                      std::equal(expected_records.begin(),
                          expected_records.end(), actual_records.begin(),
                          [](const auto& left, const auto& right) {
                              return left.key == right.key &&
                                  left.value == right.value;
                          }),
                  "new crash-prefix filesystem graph is complete " +
                      std::to_string(fail_at) + ": " + load_error);
          }
      }
      return ok;
  }

bool TestVolumeTransactionMaintainsPhysicalExtentReferences()
{
    constexpr std::uint64_t kFirstFile = 100;
    constexpr std::uint64_t kSecondFile = 101;
    constexpr std::uint64_t kThirdFile = 102;
    constexpr std::uint64_t kOwnedPayloadBlock = 148;
    constexpr std::uint64_t kOwnedPayloadBlockCount = 2;
    constexpr std::uint64_t kSharedPayloadBlock = 150;
    constexpr std::uint64_t kObjectIdMask = (1ull << 60) - 1;

    std::string error;
    std::vector<apfsaccess::catalog::BtreeRecord> records;
    const auto add_inode = [&](std::uint64_t object_id, bool directory) {
        AppleInodeRecord inode;
        inode.object_id = object_id;
        inode.parent_id = 2;
        inode.private_id = directory ? 9 : object_id;
        inode.children_or_links = directory ? 3 : 1;
        inode.mode = directory ? 0040755 : 0100644;
        inode.uncompressed_size = directory ? 0 :
            (object_id == kFirstFile ? 2 * kBlockSize : kBlockSize);
        apfsaccess::catalog::BtreeRecord record;
        return EncodeAppleInodeRecord(inode, record, error) &&
            (records.push_back(std::move(record)), true);
    };
    bool ok = Require(add_inode(2, true) &&
            add_inode(kFirstFile, false) &&
            add_inode(kSecondFile, false) &&
            add_inode(kThirdFile, false),
        "shared-extent fixture inode encoding: " + error);
    const auto add_directory = [&](std::uint64_t file_id,
                                   const std::string& name) {
        AppleDirectoryRecord directory;
        directory.parent_id = 2;
        directory.file_id = file_id;
        directory.flags = 8;
        directory.name_utf8 = name;
        apfsaccess::catalog::BtreeRecord record;
        return EncodeAppleDirectoryRecord(
                   directory,
                   ApfsNamePolicy::FromIncompatibleFeatures(
                       kIncompatCaseInsensitive),
                   record,
                   error) &&
            (records.push_back(std::move(record)), true);
    };
    ok &= Require(add_directory(kFirstFile, "first.bin") &&
            add_directory(kSecondFile, "second.bin") &&
            add_directory(kThirdFile, "third.bin"),
        "shared-extent fixture directory encoding: " + error);
    const auto add_file_extent = [&](std::uint64_t object_id,
                                     std::uint64_t logical_address,
                                     std::uint64_t physical_block) {
        AppleFileExtentRecord extent;
        extent.object_id = object_id;
        extent.logical_address = logical_address;
        extent.length_bytes = kBlockSize;
        extent.physical_block = physical_block;
        extent.block_size = kBlockSize;
        apfsaccess::catalog::BtreeRecord record;
        return EncodeAppleFileExtentRecord(extent, record, error) &&
            (records.push_back(std::move(record)), true);
    };
    ok &= Require(add_file_extent(kFirstFile, 0, kOwnedPayloadBlock) &&
            add_file_extent(kFirstFile, kBlockSize,
                kOwnedPayloadBlock + 1) &&
            add_file_extent(kSecondFile, 0, kSharedPayloadBlock) &&
            add_file_extent(kThirdFile, 0, kSharedPayloadBlock),
        "shared-extent fixture file records: " + error);
    const auto add_dstream = [&](std::uint64_t object_id,
                                 std::uint32_t reference_count) {
        AppleDataStreamIdRecord stream;
        stream.object_id = object_id;
        stream.reference_count = reference_count;
        apfsaccess::catalog::BtreeRecord record;
        return EncodeAppleDataStreamIdRecord(stream, record, error) &&
            (records.push_back(std::move(record)), true);
    };
    ok &= Require(add_dstream(kFirstFile, 1) &&
            add_dstream(kSecondFile, 1) &&
            add_dstream(kThirdFile, 1) &&
            SortAppleBtreeRecords(records,
                AppleBtreeKeyOrder::FileSystemHashedDirectory, error),
        "data-stream reference records encode: " + error);

    ApplePhysicalExtentRecord owned_extent;
    owned_extent.physical_block = kOwnedPayloadBlock;
    owned_extent.block_count = kOwnedPayloadBlockCount;
    owned_extent.kind = kApplePhysicalExtentKindNew;
    owned_extent.owning_object_id = kFirstFile;
    owned_extent.reference_count = 1;
    apfsaccess::catalog::BtreeRecord owned_extent_record;
    ok &= Require(EncodeApplePhysicalExtentRecord(
            owned_extent, owned_extent_record, error),
        "owned physical-extent encoding: " + error);

    ApplePhysicalExtentRecord shared_extent;
    shared_extent.physical_block = kSharedPayloadBlock;
    shared_extent.block_count = 1;
    shared_extent.kind = kApplePhysicalExtentKindNew;
    shared_extent.owning_object_id = kSecondFile;
    shared_extent.reference_count = 2;
    apfsaccess::catalog::BtreeRecord shared_extent_record;
    ok &= Require(EncodeApplePhysicalExtentRecord(
            shared_extent, shared_extent_record, error),
        "shared physical-extent encoding: " + error);

    BuilderStore store;
    store.authoritative_checkpoint = true;
    store.block_count = 192;
    store.volumes[0].incompat = kIncompatCaseInsensitive;
    store.volumes[0].filesystem_records = records;
    store.volumes[0].extentref_records = {
        owned_extent_record,
        shared_extent_record,
    };
    store.volumes[0].additional_file_system_allocated_blocks = 3;
    store.authoritative_seeded_main_blocks.push_back({
        kOwnedPayloadBlock,
        std::vector<std::byte>(kBlockSize, std::byte{0x4a}),
    });
    store.authoritative_seeded_main_blocks.push_back({
        kOwnedPayloadBlock + 1,
        std::vector<std::byte>(kBlockSize, std::byte{0x4b}),
    });
    store.authoritative_seeded_main_blocks.push_back({
        kSharedPayloadBlock,
        std::vector<std::byte>(kBlockSize, std::byte{0x5a}),
    });
    const auto image = BuildStoreImage(store);
    VectorRandomAccessSource source(image);
    const auto checkpoint = LoadAppleCheckpointView(
        source, 0, source.SizeBytes(), error);
    ok &= Require(checkpoint.has_value(),
        "shared-extent fixture loads: " + error);
    if (!ok || !checkpoint.has_value())
    {
        return false;
    }

    const auto is_file_extent_for = [](const apfsaccess::catalog::BtreeRecord& record,
                                       std::uint64_t object_id) {
        const auto header = ReadU64LE(record.key, 0).value_or(0);
        return (header >> 60) == 8 &&
            (header & kObjectIdMask) == object_id;
    };
    const auto is_file_extent_at = [&](
                                       const apfsaccess::catalog::BtreeRecord& record,
                                       std::uint64_t object_id,
                                       std::uint64_t logical_address) {
        return is_file_extent_for(record, object_id) &&
            ReadU64LE(record.key, 8).value_or(
                std::numeric_limits<std::uint64_t>::max()) == logical_address;
    };
    const auto is_dstream_for = [](const auto& record,
                                   std::uint64_t object_id) {
        const auto header = ReadU64LE(record.key, 0).value_or(0);
        return (header >> 60) == 6 &&
            (header & kObjectIdMask) == object_id;
    };
    AppleVolumeTransactionRequest rewrite;
    rewrite.volume_object_id =
        checkpoint->volumes.front().superblock.object_id;
    for (const auto& record : records)
    {
        if (!is_file_extent_at(record, kFirstFile, 0))
        {
            rewrite.filesystem_records.push_back(record);
        }
    }
    rewrite.released_data_blocks.push_back({kOwnedPayloadBlock, 1});
    AppleVolumeDataWrite replacement;
    replacement.file_private_id = kFirstFile;
    replacement.bytes.assign(kBlockSize, std::byte{0x33});
    rewrite.data_writes.push_back(std::move(replacement));

    AppleVolumeTransactionPlan rewrite_plan;
    error.clear();
    ok &= Require(PlanAppleVolumeTransaction(source, checkpoint.value(),
            rewrite, rewrite_plan, error),
        "unshared extent rewrite plans: " + error);
    if (!ok)
    {
        return false;
    }
    ok &= Require(std::count_if(rewrite_plan.allocation.deferred_frees.begin(),
            rewrite_plan.allocation.deferred_frees.end(),
            [](const auto& released) {
                return released.physical_block == kOwnedPayloadBlock &&
                    released.block_count == 1;
            }) == 1,
        "unshared old physical extent is queued exactly once");
    ok &= Require(std::none_of(rewrite_plan.allocation.deferred_frees.begin(),
            rewrite_plan.allocation.deferred_frees.end(),
            [](const auto& released) {
                return released.physical_block == kSharedPayloadBlock;
            }),
        "unrelated shared physical extent is never freed");
    const auto old_extentref_block =
        checkpoint->volumes.front().extentref_tree->physical_block;
    ok &= Require(std::any_of(rewrite_plan.allocation.deferred_frees.begin(),
            rewrite_plan.allocation.deferred_frees.end(),
            [old_extentref_block](const auto& released) {
                return released.physical_block == old_extentref_block;
            }),
        "old extent-reference tree is retired through spaceman");

    MemoryWriteTarget rewritten(image);
    ok &= Require(ExecuteAppleCheckpointPublication(
            rewritten, rewrite_plan.commit.publication, error),
        "shared extent rewrite publishes: " + error);
    VectorRandomAccessSource rewritten_source(rewritten.Image());
    const auto rewritten_checkpoint = LoadAppleCheckpointView(
        rewritten_source, 0, rewritten_source.SizeBytes(), error);
    ok &= Require(rewritten_checkpoint.has_value() &&
            rewritten_checkpoint->volumes.front().extentref_tree.has_value() &&
            rewritten_checkpoint->volumes.front().extentref_tree->physical_block !=
                old_extentref_block,
        "published APSB points at a replacement extent-reference tree: " +
            error);
    if (!ok || !rewritten_checkpoint.has_value() ||
        !rewritten_checkpoint->volumes.front().extentref_tree.has_value())
    {
        return false;
    }

    const auto read_extentrefs = [](const RandomAccessSource& input,
                                    const AppleCheckpointView& selected,
                                    std::vector<ApplePhysicalExtentRecord>& out,
                                    std::string& read_error) {
        const auto& volume = selected.volumes.front();
        if (!volume.extentref_tree.has_value())
        {
            return false;
        }
        BtreeReadPolicy policy;
        policy.enforce_object_identity = true;
        policy.root_object_id = volume.extentref_tree->object_id;
        policy.storage_type = volume.extentref_tree->type;
        policy.subtype = volume.extentref_tree->subtype;
        std::vector<apfsaccess::catalog::BtreeRecord> raw;
        if (!ReadBtreeLeafRecords(input,
                selected.container.superblock.block_size,
                volume.extentref_tree->physical_block, true, 0,
                selected.container.superblock.xid, policy, raw, read_error))
        {
            return false;
        }
        out.clear();
        for (const auto& record : raw)
        {
            ApplePhysicalExtentRecord extent;
            if (!DecodeApplePhysicalExtentRecord(record, extent, read_error))
            {
                return false;
            }
            out.push_back(extent);
        }
        return true;
    };
    std::vector<ApplePhysicalExtentRecord> rewritten_extents;
    ok &= Require(read_extentrefs(rewritten_source,
            rewritten_checkpoint.value(), rewritten_extents, error),
        "replacement extent-reference tree round trips: " + error);
    const auto new_payload_block = rewrite_plan.payload_blocks.front();
    ok &= Require(std::none_of(rewritten_extents.begin(),
            rewritten_extents.end(), [](const auto& extent) {
                return extent.physical_block == kOwnedPayloadBlock &&
                    extent.block_count == kOwnedPayloadBlockCount;
            }),
        "partially retired physical extent is absent in its old shape");
    ok &= Require(std::any_of(rewritten_extents.begin(),
            rewritten_extents.end(), [](const auto& extent) {
                return extent.physical_block == kOwnedPayloadBlock + 1 &&
                    extent.block_count == 1 && extent.reference_count == 1 &&
                    extent.owning_object_id == kFirstFile;
            }),
        "unmodified suffix survives as a split physical-extent record");
    ok &= Require(std::any_of(rewritten_extents.begin(),
            rewritten_extents.end(), [](const auto& extent) {
                return extent.physical_block == kSharedPayloadBlock &&
                    extent.block_count == 1 && extent.reference_count == 2 &&
                    extent.owning_object_id == kSecondFile;
            }),
        "unrelated shared extent is retained unchanged");
    ok &= Require(std::any_of(rewritten_extents.begin(),
            rewritten_extents.end(), [new_payload_block](const auto& extent) {
                return extent.physical_block == new_payload_block &&
                    extent.block_count == 1 && extent.reference_count == 1 &&
                    extent.owning_object_id == kFirstFile;
            }),
        "new payload receives its own physical-extent record");

    const auto operation_count = rewritten.MutatingOperationCount();
    for (std::size_t fail_at = 0; fail_at <= operation_count; ++fail_at)
    {
        MemoryWriteTarget interrupted(image, fail_at);
        std::string crash_error;
        const auto completed = ExecuteAppleCheckpointPublication(
            interrupted, rewrite_plan.commit.publication, crash_error);
        ok &= Require(completed == (fail_at == operation_count),
            "extent-reference crash completion state " +
                std::to_string(fail_at));
        VectorRandomAccessSource crash_source(interrupted.Image());
        const auto selected = LoadAppleCheckpointView(crash_source, 0,
            crash_source.SizeBytes(), crash_error);
        ok &= Require(selected.has_value(),
            "extent-reference crash selects a checkpoint " +
                std::to_string(fail_at) + ": " + crash_error);
        if (!selected.has_value())
        {
            continue;
        }
        std::vector<ApplePhysicalExtentRecord> crash_extents;
        ok &= Require(read_extentrefs(crash_source, selected.value(),
                crash_extents, crash_error),
            "extent-reference crash tree is readable " +
                std::to_string(fail_at) + ": " + crash_error);
        const auto has_old = std::any_of(crash_extents.begin(),
            crash_extents.end(), [](const auto& extent) {
                return extent.physical_block == kOwnedPayloadBlock &&
                    extent.block_count == kOwnedPayloadBlockCount &&
                    extent.reference_count == 1;
            });
        const auto has_retained_suffix = std::any_of(crash_extents.begin(),
            crash_extents.end(), [](const auto& extent) {
                return extent.physical_block == kOwnedPayloadBlock + 1 &&
                    extent.block_count == 1 && extent.reference_count == 1;
            });
        const auto has_new = std::any_of(crash_extents.begin(),
            crash_extents.end(), [new_payload_block](const auto& extent) {
                return extent.physical_block == new_payload_block &&
                    extent.reference_count == 1;
            });
        const auto has_shared = std::any_of(crash_extents.begin(),
            crash_extents.end(), [](const auto& extent) {
                return extent.physical_block == kSharedPayloadBlock &&
                    extent.reference_count == 2;
            });
        ok &= Require(((has_old && !has_new && !has_retained_suffix) ||
                          (!has_old && has_new && has_retained_suffix)) &&
                         has_shared,
            "crash selects a complete old or new extent-reference graph " +
                std::to_string(fail_at));
    }

    AppleVolumeTransactionRequest remove_owned;
    remove_owned.volume_object_id = rewrite.volume_object_id;
    for (const auto& record : records)
    {
        if (!is_file_extent_for(record, kFirstFile) &&
            !is_dstream_for(record, kFirstFile))
        {
            remove_owned.filesystem_records.push_back(record);
        }
    }
    remove_owned.released_data_blocks = {
        {kOwnedPayloadBlock, 1},
        {kOwnedPayloadBlock + 1, 1},
    };
    AppleVolumeTransactionPlan removal_plan;
    error.clear();
    ok &= Require(PlanAppleVolumeTransaction(source, checkpoint.value(),
            remove_owned, removal_plan, error),
        "last unshared reference can be removed: " + error);
    for (std::uint64_t ordinal = 0; ordinal < kOwnedPayloadBlockCount; ++ordinal)
        ok &= Require(std::count_if(removal_plan.allocation.deferred_frees.begin(),
                removal_plan.allocation.deferred_frees.end(), [ordinal](const auto& released) {
                    const auto block = kOwnedPayloadBlock + ordinal;
                    return block >= released.physical_block && block - released.physical_block < released.block_count;
                }) == 1, "every unshared block is queued once when its refcount reaches zero");
    ok &= Require(std::none_of(removal_plan.filesystem_records.begin(),
            removal_plan.filesystem_records.end(),
            [&](const auto& candidate) {
                return is_dstream_for(candidate, kFirstFile);
            }),
        "last private extent deletion removes its data-stream reference");

    AppleVolumeTransactionRequest shared_rewrite;
    shared_rewrite.volume_object_id = rewrite.volume_object_id;
    for (const auto& record : records)
    {
        if (!is_file_extent_for(record, kSecondFile))
        {
            shared_rewrite.filesystem_records.push_back(record);
        }
    }
    shared_rewrite.released_data_blocks = {{kSharedPayloadBlock, 1}};
    AppleVolumeDataWrite shared_replacement;
    shared_replacement.file_private_id = kSecondFile;
    shared_replacement.bytes.assign(kBlockSize, std::byte{0x44});
    shared_rewrite.data_writes.push_back(std::move(shared_replacement));
    AppleVolumeTransactionPlan shared_plan;
    error.clear();
    const auto shared_planned = PlanAppleVolumeTransaction(source, checkpoint.value(),
        shared_rewrite, shared_plan, error);
    ok &= Require(shared_planned,
        "shared extent COW uses checked live clone accounting: " + error);
    if (shared_planned)
        ok &= Require(std::none_of(shared_plan.allocation.deferred_frees.begin(),
            shared_plan.allocation.deferred_frees.end(), [](const auto& released) {
                return kSharedPayloadBlock >= released.physical_block &&
                    kSharedPayloadBlock - released.physical_block < released.block_count;
            }), "surviving clone prevents shared payload retirement");

    const auto rejects_invalid_extent_graph = [&](BuilderStore candidate,
                                                   const std::string& expected,
                                                   const std::string& label) {
        const auto candidate_image = BuildStoreImage(candidate);
        VectorRandomAccessSource candidate_source(candidate_image);
        std::string candidate_error;
        const auto candidate_checkpoint = LoadAppleCheckpointView(
            candidate_source, 0, candidate_source.SizeBytes(),
            candidate_error);
        if (!candidate_checkpoint.has_value())
        {
            return Require(false, label + " fixture loads: " + candidate_error);
        }
        AppleVolumeTransactionPlan candidate_plan;
        candidate_error.clear();
        return Require(!PlanAppleVolumeTransaction(candidate_source,
                           candidate_checkpoint.value(), rewrite,
                           candidate_plan, candidate_error) &&
                candidate_error == expected,
            label + ": " + candidate_error);
    };

    auto missing_reference = store;
    missing_reference.volumes[0].extentref_records = {shared_extent_record};
    ok &= rejects_invalid_extent_graph(std::move(missing_reference),
        "AppleVolumePhysicalExtentMissing",
        "missing physical-extent coverage fails closed");

    auto wrong_owner_extent = owned_extent;
    wrong_owner_extent.owning_object_id = kSecondFile;
    apfsaccess::catalog::BtreeRecord wrong_owner_record;
    error.clear();
    ok &= Require(EncodeApplePhysicalExtentRecord(
            wrong_owner_extent, wrong_owner_record, error),
        "wrong-owner physical extent fixture encodes: " + error);
    auto wrong_owner = store;
    wrong_owner.volumes[0].extentref_records = {
        wrong_owner_record,
        shared_extent_record,
    };
    ok &= rejects_invalid_extent_graph(std::move(wrong_owner),
        "AppleVolumePhysicalExtentOwnerMismatch",
        "unshared physical-extent owner mismatch fails closed");

    auto wrong_refcount_extent = owned_extent;
    wrong_refcount_extent.reference_count = 2;
    apfsaccess::catalog::BtreeRecord wrong_refcount_record;
    error.clear();
    ok &= Require(EncodeApplePhysicalExtentRecord(
            wrong_refcount_extent, wrong_refcount_record, error),
        "wrong-refcount physical extent fixture encodes: " + error);
    auto wrong_refcount = store;
    wrong_refcount.volumes[0].extentref_records = {
        wrong_refcount_record,
        shared_extent_record,
    };
    ok &= rejects_invalid_extent_graph(std::move(wrong_refcount),
        "AppleVolumePhysicalExtentRefcountMismatch",
        "physical-extent reference-count mismatch fails closed");

    auto shared_dstream_records = records;
    std::erase_if(shared_dstream_records, [&](const auto& candidate) {
        return is_dstream_for(candidate, kFirstFile);
    });
    AppleDataStreamIdRecord shared_stream;
    shared_stream.object_id = kFirstFile;
    shared_stream.reference_count = 2;
    apfsaccess::catalog::BtreeRecord shared_stream_record;
    error.clear();
    ok &= Require(EncodeAppleDataStreamIdRecord(
            shared_stream, shared_stream_record, error),
        "shared data-stream fixture encodes: " + error);
    shared_dstream_records.push_back(std::move(shared_stream_record));
    ok &= Require(SortAppleBtreeRecords(shared_dstream_records,
            AppleBtreeKeyOrder::FileSystemHashedDirectory, error),
        "shared data-stream fixture sorts: " + error);
    auto shared_dstream_store = store;
    shared_dstream_store.volumes[0].filesystem_records =
        shared_dstream_records;
    const auto shared_dstream_image = BuildStoreImage(shared_dstream_store);
    VectorRandomAccessSource shared_dstream_source(shared_dstream_image);
    const auto shared_dstream_checkpoint = LoadAppleCheckpointView(
        shared_dstream_source, 0, shared_dstream_source.SizeBytes(), error);
    ok &= Require(shared_dstream_checkpoint.has_value(),
        "shared data-stream fixture loads: " + error);
    if (shared_dstream_checkpoint.has_value())
    {
        AppleVolumeTransactionRequest shared_dstream_rewrite = rewrite;
        shared_dstream_rewrite.filesystem_records = shared_dstream_records;
        std::erase_if(shared_dstream_rewrite.filesystem_records,
            [&](const auto& candidate) {
                return is_file_extent_at(candidate, kFirstFile, 0);
            });
        AppleVolumeTransactionPlan shared_dstream_plan;
        error.clear();
        ok &= Require(!PlanAppleVolumeTransaction(shared_dstream_source,
                shared_dstream_checkpoint.value(), shared_dstream_rewrite,
                shared_dstream_plan, error) &&
                error == "AppleVolumeSharedDataStreamUnsupported",
            "touched shared data stream fails closed until clone COW exists: " +
                error);
    }
    return ok;
}

  bool TestVolumeTransactionRejectsSnapshots()
  {
      BuilderStore store;
      store.authoritative_checkpoint = true;
      auto image = BuildStoreImage(store);
      std::vector<std::byte> apsb(image.begin() + 4 * kBlockSize,
          image.begin() + 5 * kBlockSize);
      PutU64LE(apsb, 0xD8, 1);
      FletcherForBlock(apsb, kBlockSize);
      PutBlock(image, 4, apsb);
      VectorRandomAccessSource source(image);
      std::string error;
      const auto checkpoint = LoadAppleCheckpointView(
          source, 0, source.SizeBytes(), error);
      bool ok = Require(checkpoint.has_value(),
          "snapshot-bearing transaction fixture loads: " + error);
      if (!checkpoint.has_value())
      {
          return false;
      }
      AppleInodeRecord root;
      root.object_id = 2;
      root.parent_id = 2;
      root.private_id = 9;
      root.mode = 0040755;
      apfsaccess::catalog::BtreeRecord record;
      ok &= Require(EncodeAppleInodeRecord(root, record, error),
          "snapshot rejection fixture inode encodes: " + error);
      AppleVolumeTransactionRequest request;
      request.volume_object_id =
          checkpoint->volumes.front().superblock.object_id;
      request.filesystem_records.push_back(std::move(record));
      AppleVolumeTransactionPlan plan;
      error.clear();
      ok &= Require(!PlanAppleVolumeTransaction(source, checkpoint.value(),
              request, plan, error) &&
              error == "AppleVolumeSnapshotsUnsupported",
          "snapshot-bearing volume remains fail-closed: " + error);
      return ok;
  }

bool TestVolumeRejectsMissingRecoveryGeneration()
{
    BuilderStore store;
    store.authoritative_checkpoint = true;
    store.block_count = 192;
    store.volumes[0].incompat = kIncompatCaseInsensitive;
    auto image = BuildStoreImage(store);
    VectorRandomAccessSource source(image);
    std::string error;
    const auto checkpoint = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    if (!Require(checkpoint.has_value(), "volume retention fixture loads: " + error))
    {
        return false;
    }
    AppleInodeRecord root;
    root.object_id = 2;
    root.parent_id = 2;
    root.private_id = 9;
    root.mode = 0040755;
    apfsaccess::catalog::BtreeRecord record;
    if (!Require(EncodeAppleInodeRecord(root, record, error), "retention inode encodes"))
    {
        return false;
    }
    AppleVolumeTransactionRequest request;
    request.volume_object_id = checkpoint->volumes.front().superblock.object_id;
    request.filesystem_records = {record};
    AppleVolumeTransactionPlan plan;
    bool ok = Require(PlanAppleVolumeTransaction(source, *checkpoint, request, plan, error),
        "unrestricted control plans: " + error);
    for (const auto xid : {0ULL, store.xid - 1, store.xid + 1})
    {
        request.required_checkpoint_xids = {xid};
        ok &= Require(!PlanAppleVolumeTransaction(source, *checkpoint, request, plan, error) &&
                plan.commit.publication.before_superblock_writes.empty() &&
                plan.allocation.writes.empty(),
            "volume planner refuses invalid/unavailable required checkpoint");
    }
    return ok;
}

bool TestVolumeRetainsExactHistoryUntilPinRelease()
{
    BuilderStore store;
    store.authoritative_checkpoint = true;
    store.authoritative_checkpoint_ring_blocks = 16;
    store.authoritative_internal_pool_blocks = 16;
    store.block_count = 192;
    store.volumes[0].incompat = kIncompatCaseInsensitive;
    auto image = BuildStoreImage(store);
    VectorRandomAccessSource initial_source(image);
    std::string error;
    auto current = LoadAppleCheckpointView(initial_source, 0, initial_source.SizeBytes(), error);
    if (!Require(current.has_value(), "large retention fixture loads: " + error))
    {
        return false;
    }
    const auto original = *current;
    std::vector<std::uint64_t> original_blocks{
        original.container_object_map.object.physical_block,
        original.container_object_map.tree.physical_block,
        original.volumes.front().superblock_object.physical_block,
        original.volumes.front().object_map.object.physical_block,
        original.volumes.front().object_map.tree.physical_block,
        original.volumes.front().root_tree.physical_block};
    for (const auto& cib : original.spaceman.devices[0].cibs)
        original_blocks.push_back(cib.object.physical_block);
    for (const auto& chunk : original.spaceman.chunks)
        if (chunk.bitmap_block) original_blocks.push_back(chunk.bitmap_block);
    for (const auto& bitmap : original.spaceman.internal_pool.active_bitmaps)
        original_blocks.push_back(bitmap.physical_block);
    bool ok = true;
    bool reused = false;
    for (int iteration = 0; iteration < 6; ++iteration)
    {
        AppleInodeRecord root;
        root.object_id = 2;
        root.parent_id = 2;
        root.private_id = 9;
        root.mode = 0040755;
        root.modification_time = 1000 + iteration;
        apfsaccess::catalog::BtreeRecord record;
        if (!Require(EncodeAppleInodeRecord(root, record, error), "history root encodes"))
            return false;
        AppleVolumeTransactionRequest request;
        request.volume_object_id = current->volumes.front().superblock.object_id;
        request.filesystem_records = {record};
        if (iteration < 2) request.required_checkpoint_xids = {store.xid};
        VectorRandomAccessSource source(image);
        AppleVolumeTransactionPlan plan;
        if (!Require(PlanAppleVolumeTransaction(source, *current, request, plan, error),
                "pinned/released volume publication plans: " + error))
            return false;
        if (iteration == 1)
        {
            AppleTransactionCommitRequest composed;
            composed.allocation_plan = plan.allocation;
            composed.next_object_id = plan.commit.publication.next_object_id;
            composed.container_object_map_oid =
                plan.commit.publication.published_checkpoint.superblock.omap_oid;
            composed.required_checkpoint_xids = request.required_checkpoint_xids;
            for (const auto& write : plan.commit.publication.before_superblock_writes)
            {
                if (std::find(plan.allocation.allocated_main_blocks.begin(),
                        plan.allocation.allocated_main_blocks.end(), write.physical_block) !=
                    plan.allocation.allocated_main_blocks.end())
                    composed.allocated_main_writes.push_back({write.physical_block, write.bytes});
            }
            AppleTransactionCommitPlan recomposed;
            ok &= Require(PlanAppleTransactionCommit(source, *current,
                    composed, recomposed, error), "retained allocation recomposes: " + error);
            const auto valid = composed.allocation_plan;
            composed.allocation_plan.effective_oldest_required_checkpoint_xid =
                current->container.superblock.xid;
            ok &= Require(!PlanAppleTransactionCommit(source, *current,
                    composed, recomposed, error) &&
                    error == "AppleTransactionRetentionProtectionMissing" &&
                    recomposed.publication.before_superblock_writes.empty(),
                "composer rejects allocator frontier newer than required history");
            composed.allocation_plan = valid;
            composed.allocation_plan.effective_protected_internal_pool_bitmap_indices.clear();
            ok &= Require(!PlanAppleTransactionCommit(source, *current,
                    composed, recomposed, error) &&
                    error == "AppleTransactionRetentionProtectionMissing" &&
                    recomposed.publication.before_superblock_writes.empty(),
                "composer rejects allocator missing historical bitmap protection");
        }
        for (const auto& write : plan.commit.publication.before_superblock_writes)
        {
            if (std::find(original_blocks.begin(), original_blocks.end(),
                    write.physical_block) != original_blocks.end())
            {
                ok &= Require(iteration >= 2, "no write reuses pinned original metadata");
                reused = true;
            }
        }
        MemoryWriteTarget target(image);
        if (!Require(ExecuteAppleCheckpointPublication(target,
                plan.commit.publication, error), "retained volume publishes: " + error))
            return false;
        image = target.Image();
        VectorRandomAccessSource after(image);
        current = LoadAppleCheckpointView(after, 0, after.SizeBytes(), error);
        if (!Require(current.has_value(), "published volume reloads: " + error))
            return false;
        if (iteration < 2)
        {
            const auto old = LoadAppleCheckpointView(after, 0, after.SizeBytes(), error, store.xid);
            ok &= Require(old.has_value() && old->container.superblock_bytes ==
                    original.container.superblock_bytes,
                "exact original Apple object graph survives publication: " + error);
            for (const auto block : original_blocks)
            {
                const auto offset = block * kBlockSize;
                std::vector<std::byte> original_bytes;
                ok &= Require(initial_source.Read(offset, kBlockSize, original_bytes) &&
                    std::equal(image.begin() + offset,
                        image.begin() + offset + kBlockSize,
                        original_bytes.begin()),
                    "original live metadata bytes remain unchanged");
            }
        }
    }
    VectorRandomAccessSource after(image);
    ok &= Require(reused && !LoadContainerCheckpointView(after, 0,
            after.SizeBytes(), error, store.xid).has_value(),
        "pin release permits block reuse and eventual ring wrap");
    return ok;
}

bool TestLateRecoveryPinRejectsReclaimedDescendants(bool with_payload = false)
{
    BuilderStore store;
    store.authoritative_checkpoint = true;
    store.authoritative_checkpoint_ring_blocks = 16;
    store.authoritative_internal_pool_blocks = 16;
    store.block_count = 512;
    store.volumes[0].incompat = kIncompatCaseInsensitive;
    store.volumes[0].fext_tree_oid = 10;
    const auto root_oid = 0x2000 + store.volumes[0].oid;
    const auto snapshot_oid = 0x3000 + store.volumes[0].oid;
    constexpr std::uint64_t payload_block = 220;
    constexpr std::uint64_t payload_blocks = 20;
    std::string error;
    std::vector<apfsaccess::catalog::BtreeRecord> records;
    for (std::uint64_t oid = 2; oid < 102; ++oid)
    {
        AppleInodeRecord inode;
        inode.object_id = oid;
        inode.parent_id = 2;
        inode.private_id = oid;
        inode.mode = oid == 2 ? 0040755 : 0100644;
        apfsaccess::catalog::BtreeRecord record;
        if (!Require(EncodeAppleInodeRecord(inode, record, error), "late-pin inode encodes"))
            return false;
        records.push_back(std::move(record));
    }
    AppleFileExtentRecord extent{3, 0, kBlockSize * payload_blocks, payload_block, 0, kBlockSize};
    apfsaccess::catalog::BtreeRecord extent_record;
    if (!Require(EncodeAppleFileExtentRecord(extent, extent_record, error), "late-pin extent encodes"))
        return false;
    if (with_payload)
    {
        records.push_back(extent_record);
        apfsaccess::catalog::BtreeRecord stream_record;
        if (!Require(EncodeAppleDataStreamIdRecord({3, 1}, stream_record, error),
                "retained payload stream identity encodes")) return false;
        records.push_back(std::move(stream_record));
        ApplePhysicalExtentRecord physical{payload_block, payload_blocks, kApplePhysicalExtentKindNew, 3, 1};
        apfsaccess::catalog::BtreeRecord physical_record;
        if (!Require(EncodeApplePhysicalExtentRecord(physical, physical_record, error),
                "retained payload ownership fixture encodes")) return false;
        store.volumes[0].extentref_records = {physical_record};
    }
    AppleBtreeOptions options;
    options.block_size = kBlockSize;
    options.xid = store.xid;
    options.root_object_id = root_oid;
    options.root_physical_block = 7;
    options.first_child_object_id = 0x5000;
    options.first_child_physical_block = 160;
    options.subtype = kObjectTypeFsTree;
    options.tree_flags = kAppleBtreeKvNonAligned;
    options.key_order = AppleBtreeKeyOrder::FileSystemHashedDirectory;
    const auto filesystem_options = options;
    AppleSerializedBtree fs_tree;
    if (!Require(SerializeAppleBtree(records, options, fs_tree, error) && fs_tree.height > 0,
            "late-pin multi-node filesystem serializes: " + error))
        return false;
    std::vector<apfsaccess::catalog::BtreeRecord> mappings;
    for (const auto& object : fs_tree.objects)
    {
        store.authoritative_seeded_main_blocks.push_back({object.location.physical_block, object.bytes});
        AppleOmapRecord mapping{object.location.object_id, store.xid, 0,
            kBlockSize, object.location.physical_block};
        apfsaccess::catalog::BtreeRecord record;
        if (!EncodeAppleOmapRecord(mapping, record, error)) return false;
        mappings.push_back(std::move(record));
    }
    for (std::uint64_t oid = 0x7000; oid < 0x70C8; ++oid)
    {
        AppleOmapRecord tombstone{oid, store.xid, kAppleOmapValueDeleted, 0, 0};
        apfsaccess::catalog::BtreeRecord record;
        if (!EncodeAppleOmapRecord(tombstone, record, error)) return false;
        mappings.push_back(std::move(record));
    }
    AppleOmapRecord snapshot{snapshot_oid, store.xid, 0, kBlockSize, 9};
    apfsaccess::catalog::BtreeRecord snapshot_mapping;
    if (!EncodeAppleOmapRecord(snapshot, snapshot_mapping, error)) return false;
    mappings.push_back(snapshot_mapping);
    options.root_object_id = 6;
    options.root_physical_block = 6;
    options.first_child_object_id = 190;
    options.first_child_physical_block = 190;
    options.storage_type = kObjectPhysical;
    options.subtype = kObjectTypeOmap;
    options.tree_flags = kAppleBtreePhysical | kAppleBtreeKvNonAligned;
    options.key_order = AppleBtreeKeyOrder::ObjectMap;
    AppleSerializedBtree omap_tree;
    if (!Require(SerializeAppleBtree(mappings, options, omap_tree, error) && omap_tree.height > 0,
            "late-pin multi-node OMAP serializes: " + error)) return false;
    for (const auto& object : omap_tree.objects)
        store.authoritative_seeded_main_blocks.push_back({object.location.physical_block, object.bytes});
    for (std::uint64_t index = 0; index < payload_blocks; ++index)
        store.authoritative_seeded_main_blocks.push_back({payload_block + index,
            std::vector<std::byte>(kBlockSize, std::byte{0x5A})});
    store.volumes[0].additional_file_system_allocated_blocks =
        fs_tree.objects.size() + omap_tree.objects.size() - 2 + payload_blocks;
    auto image = BuildStoreImage(store);
    VectorRandomAccessSource source(image);
    auto old = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    if (!Require(old.has_value(), "late-pin full graph loads: " + error)) return false;
    AppleVolumeTransactionRequest request;
    request.volume_object_id = store.volumes[0].oid;
    request.filesystem_records = records;
    request.required_checkpoint_xids = {store.xid};
    AppleVolumeTransactionPlan first;
    if (!Require(PlanAppleVolumeTransaction(source, *old, request, first, error),
            "multi-node history publishes a new current generation: " + error)) return false;
    MemoryWriteTarget target(image);
    if (!Require(ExecuteAppleCheckpointPublication(target, first.commit.publication, error),
            "multi-node publication executes: " + error)) return false;
    image = target.Image();
    VectorRandomAccessSource current_source(image);
    auto current = LoadAppleCheckpointView(current_source, 0, current_source.SizeBytes(), error);
    if (!Require(current.has_value(), "multi-node current ownership loads: " + error)) return false;
    AppleVolumeTransactionPlan plan;
    const auto admitted = PlanAppleVolumeTransaction(current_source, *current, request, plan, error);
    bool ok = Require(admitted,
        "still-owned historical descendant pin succeeds: " + error);
    if (!ok) return false;
    std::vector<std::uint64_t> victims{160, 190, 8, 9, 10};
    if (with_payload)
    {
        victims.push_back(payload_block);
        victims.push_back(payload_block + 7);
        victims.push_back(payload_block + payload_blocks - 1);
        ok &= Require(std::none_of(plan.commit.publication.guard_blocks.begin(),
                plan.commit.publication.guard_blocks.end(), [&](const auto& guard) {
                    return guard.physical_block >= payload_block && guard.physical_block < payload_block + payload_blocks;
                }), "payload protection does not materialize payload-byte guards");
        AppleTransactionCommitRequest forged;
        forged.allocation_plan = plan.allocation;
        forged.next_object_id = plan.commit.publication.next_object_id;
        forged.container_object_map_oid = plan.commit.publication.published_checkpoint.superblock.omap_oid;
        forged.required_checkpoint_xids = request.required_checkpoint_xids;
        for (const auto& write : plan.commit.publication.before_superblock_writes)
            if (std::find(plan.allocation.allocated_main_blocks.begin(), plan.allocation.allocated_main_blocks.end(),
                    write.physical_block) != plan.allocation.allocated_main_blocks.end())
                forged.allocated_main_writes.push_back({write.physical_block, write.bytes});
        AppleTransactionCommitPlan recomposed;
        ok &= Require(PlanAppleTransactionCommit(current_source, *current, forged, recomposed, error),
            "payload-protected allocation recomposes normally: " + error);
        for (const auto collision : {payload_block, payload_block + 7, payload_block + payload_blocks - 1})
        {
            auto conflicting = forged;
            const auto replaced_block = conflicting.allocated_main_writes.front().physical_block;
            std::replace(conflicting.allocation_plan.allocated_main_blocks.begin(),
                conflicting.allocation_plan.allocated_main_blocks.end(), replaced_block, collision);
            conflicting.allocated_main_writes.front().physical_block = collision;
            const auto refused = !PlanAppleTransactionCommit(current_source, *current, conflicting, recomposed, error);
            ok &= Require(refused && error == "AppleTransactionRetainedBlockReused" &&
                    recomposed.publication.before_superblock_writes.empty(),
                "composer rejects a claimed allocation over retained file data at " + std::to_string(collision) + ": " + error);
        }
        const auto& nxsb = old->container.superblock;
        const auto& pool = old->spaceman.internal_pool;
        for (const auto overlap : {std::uint64_t{160}, std::uint64_t{190},
                nxsb.xp_desc_base_block + nxsb.xp_desc_block_count - 1,
                nxsb.xp_data_base_block + nxsb.xp_data_block_count - 1,
                pool.base_block + pool.block_count - 1,
                pool.bitmap_base_block + pool.bitmap_block_count - 1})
        {
            auto bad_store = store;
            auto bad_records = records;
            apfsaccess::catalog::BtreeRecord bad_extent;
            if (!EncodeAppleFileExtentRecord({3, 0, kBlockSize, overlap, 0, kBlockSize}, bad_extent, error)) return false;
            for (auto& record : bad_records)
                if (record.key == extent_record.key) record = bad_extent;
            AppleSerializedBtree bad_tree;
            if (!Require(SerializeAppleBtree(bad_records, filesystem_options, bad_tree, error) &&
                    bad_tree.objects.size() == fs_tree.objects.size(), "overlap fixture preserves filesystem tree shape")) return false;
            for (const auto& object : bad_tree.objects)
                for (auto& seeded : bad_store.authoritative_seeded_main_blocks)
                    if (seeded.first == object.location.physical_block) seeded.second = object.bytes;
            if (!EncodeApplePhysicalExtentRecord({overlap, 1, kApplePhysicalExtentKindNew, 3, 1}, bad_extent, error)) return false;
            bad_store.volumes[0].extentref_records = {bad_extent};
            auto bad_image = BuildStoreImage(bad_store);
            VectorRandomAccessSource initial(bad_image);
            const auto initial_view = LoadAppleCheckpointView(initial, 0, initial.SizeBytes(), error);
            if (!Require(initial_view.has_value(), "checksummed overlapping extent graph loads")) return false;
            PublisherFixture fixture{bad_image, initial_view->container};
            AppleCheckpointPublicationPlan advance;
            if (!Require(PlanAppleCheckpointPublication(initial, initial_view->container, BuildRequest(fixture), advance, error),
                    "overlap fixture creates a historical checkpoint")) return false;
            MemoryWriteTarget advance_target(bad_image);
            if (!Require(ExecuteAppleCheckpointPublication(advance_target, advance, error), "overlap fixture advances")) return false;
            bad_image = advance_target.Image();
            VectorRandomAccessSource bad_source(bad_image);
            const auto bad_current = LoadAppleCheckpointView(bad_source, 0, bad_source.SizeBytes(), error);
            if (!Require(bad_current.has_value(), "overlap fixture current checkpoint loads")) return false;
            auto bad_request = request;
            bad_request.filesystem_records = bad_records;
            AppleVolumeTransactionPlan rejected;
            const auto before_probe = bad_image;
            const auto refused = !PlanAppleVolumeTransaction(bad_source, *bad_current, bad_request, rejected, error);
            ok &= Require(refused && error == "AppleCheckpointRetentionPayloadOverlap" &&
                    rejected.allocation.writes.empty() && rejected.commit.publication.before_superblock_writes.empty() &&
                    bad_image == before_probe,
                "retained payload cannot alias metadata/reserved block " + std::to_string(overlap) + ": " + error);
        }
    }
    for (const auto victim : victims)
    {
        if (victim >= payload_block && victim < payload_block + payload_blocks) continue;
        MemoryWriteTarget drifted(image);
        drifted.MutableImage()[victim * kBlockSize + 0x30] ^= std::byte{1};
        ok &= Require(!ExecuteAppleCheckpointPublication(drifted, plan.commit.publication, error) &&
                error == "AppleCheckpointGuardChanged" && drifted.MutatingOperationCount() == 0,
            "retained descendant guard refuses before I/O: " + error);
    }
    for (const bool reallocated : {false, true})
    {
    if (reallocated)
    {
        if (with_payload)
        {
            std::erase_if(request.filesystem_records, [](const auto& record) {
                return (ReadU64LE(record.key, 0).value_or(0) >> 60) == 8;
            });
            request.released_data_blocks = {{payload_block, payload_blocks}};
        }
        VectorRandomAccessSource before(image);
        const auto third_planned = PlanAppleVolumeTransaction(before, *current, request, plan, error);
        if (!Require(third_planned,
                "third generation with continuous pin plans: " + error)) return false;
        MemoryWriteTarget successor(image);
        if (!Require(ExecuteAppleCheckpointPublication(successor, plan.commit.publication, error),
                "third generation publishes: " + error)) return false;
        image = successor.Image();
        VectorRandomAccessSource after(image);
        current = LoadAppleCheckpointView(after, 0, after.SizeBytes(), error);
        if (!Require(current.has_value(), "third generation loads: " + error)) return false;
        if (with_payload)
        {
            request.released_data_blocks.clear();
            const auto fourth_planned = PlanAppleVolumeTransaction(after, *current, request, plan, error);
            if (!Require(fourth_planned,
                    "retired but pinned payload permits another generation: " + error)) return false;
            MemoryWriteTarget following(image);
            if (!Require(ExecuteAppleCheckpointPublication(following, plan.commit.publication, error),
                    "retired payload stays protected through publication: " + error)) return false;
            image = following.Image();
            VectorRandomAccessSource final_source(image);
            current = LoadAppleCheckpointView(final_source, 0, final_source.SizeBytes(), error);
            if (!Require(current.has_value(), "fourth generation reloads: " + error)) return false;
            ok &= Require(std::all_of(image.begin() + payload_block * kBlockSize,
                    image.begin() + (payload_block + payload_blocks) * kBlockSize,
                    [](std::byte value) { return value == std::byte{0x5A}; }),
                "all retired pinned payload bytes survive later metadata publications");
        }
    }
    for (const auto victim : victims)
    {
        if (reallocated && victim != 160 && victim != 190 && victim < payload_block) continue;
        const auto variants = reallocated && with_payload && victim >= payload_block ? 3 : 1;
        for (int queue_variant = 0; queue_variant < variants; ++queue_variant)
        {
        auto reclaimed = image;
        const auto& chunk = current->spaceman.chunks.front();
        const auto bit = victim - chunk.start_block;
        if (!reallocated)
            reclaimed[chunk.bitmap_block * kBlockSize + bit / 8] &=
                static_cast<std::byte>(~(1u << (bit % 8)) & 0xffu);
        auto cib = current->spaceman.devices[0].cibs.front().bytes;
        PutU32LE(cib, 0x28 + chunk.index_in_cib * 0x20 + 0x14, chunk.free_count + (reallocated ? 0 : 1));
        FletcherForBlock(cib, kBlockSize);
        PutBlock(reclaimed, current->spaceman.devices[0].cibs.front().object.physical_block, cib);
        auto spaceman = current->spaceman.bytes;
        PutU64LE(spaceman, 0x48, current->spaceman.devices[0].free_count + (reallocated ? 0 : 1));
        const auto& queue = current->spaceman.free_queues[1];
        std::vector<apfsaccess::catalog::BtreeRecord> queue_records;
        std::uint64_t queued_blocks = 0;
        auto oldest_xid = std::numeric_limits<std::uint64_t>::max();
        for (const auto& entry : queue.entries)
        {
            for (std::uint64_t ordinal = 0; ordinal < entry.block_count; ++ordinal)
            {
                const auto block = entry.physical_block + ordinal;
                if (block == victim && queue_variant == 0) continue;
                const auto retirement_xid = block == victim && queue_variant == 2
                    ? current->container.superblock.xid : entry.xid;
                apfsaccess::catalog::BtreeRecord record;
                record.key.resize(16);
                PutU64LE(record.key, 0, retirement_xid);
                PutU64LE(record.key, 8, block);
                queue_records.push_back(std::move(record));
                ++queued_blocks;
                oldest_xid = (std::min)(oldest_xid, retirement_xid);
            }
        }
        AppleBtreeOptions queue_options;
        queue_options.block_size = kBlockSize;
        queue_options.xid = current->container.superblock.xid;
        queue_options.root_object_id = queue.tree_oid;
        queue_options.root_physical_block = queue.root.physical_block;
        queue_options.storage_type = kObjectEphemeral;
        queue_options.subtype = kObjectTypeSpacemanFreeQueue;
        queue_options.tree_flags = queue.tree_flags;
        queue_options.fixed_key_size = queue.fixed_key_size;
        queue_options.fixed_value_size = queue.fixed_value_size;
        queue_options.minimum_longest_key = queue.longest_key;
        queue_options.minimum_longest_value = queue.longest_value;
        queue_options.key_order = AppleBtreeKeyOrder::SpacemanFreeQueue;
        AppleSerializedBtree queue_tree;
        if (!Require(SerializeAppleBtree(queue_records, queue_options, queue_tree, error) &&
                queue_tree.objects.size() == 1, "reclaimed queue serializes: " + error)) return false;
        PutBlock(reclaimed, queue.root.physical_block, queue_tree.objects.front().bytes);
        PutU64LE(spaceman, 0xF0, queued_blocks);
        PutU64LE(spaceman, 0x100, queued_blocks ? oldest_xid : 0);
        FletcherForBlock(spaceman, kBlockSize);
        PutBlock(reclaimed, current->spaceman.object.physical_block, spaceman);
        VectorRandomAccessSource reclaimed_source(reclaimed);
        const auto still_readable = LoadAppleCheckpointView(reclaimed_source, 0,
            reclaimed_source.SizeBytes(), error, store.xid);
        const auto reclaimed_current = LoadAppleCheckpointView(reclaimed_source, 0,
            reclaimed_source.SizeBytes(), error);
        if (!Require(still_readable.has_value() && reclaimed_current.has_value(),
                "old bytes still parse after current ownership reclamation: " + error)) return false;
        const auto planned = PlanAppleVolumeTransaction(reclaimed_source, *reclaimed_current,
            request, plan, error);
        if (queue_variant == 1)
        {
            ok &= Require(planned, "splitting a retained payload queue preserves continuous ownership: " + error);
            continue;
        }
        ok &= Require(!planned && error == (reallocated ?
                    "AppleCheckpointRetentionContinuityUnavailable" : "AppleCheckpointRetentionReclaimed") &&
                plan.allocation.writes.empty() && plan.commit.publication.before_superblock_writes.empty(),
            "late pin refuses reclaimed live block " + std::to_string(victim) +
                " queue variant=" + std::to_string(queue_variant) + ": " + error);
        }
    }
    }
    return ok;
}

bool TestRecoveryPinRequiresBitmapAndGenerationContinuity()
{
    bool ok = true;
    for (int mode = 0; mode < 3; ++mode)
    {
        BuilderStore store;
        store.authoritative_checkpoint = true;
        store.authoritative_checkpoint_ring_blocks = 16;
        store.block_count = 192;
        auto image = BuildStoreImage(store);
        VectorRandomAccessSource source(image);
        std::string error;
        const auto old = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        if (!Require(old.has_value(), "bitmap-continuity original loads: " + error)) return false;
        PublisherFixture fixture{image, old->container};
        auto request = BuildRequest(fixture);
        if (mode == 1)
        {
            for (auto& object : request.ephemeral_objects)
            {
                if (object.object.object_id != old->spaceman.object.object_id) continue;
                PutU64LE(object.bytes, old->spaceman.internal_pool.bitmap_xid_offset, request.transaction_xid);
                FletcherForBlock(object.bytes, object.bytes.size());
            }
        }
        AppleCheckpointPublicationPlan publication;
        if (!Require(PlanAppleCheckpointPublication(source, old->container, request, publication, error),
                "bitmap-continuity publisher plans: " + error)) return false;
        MemoryWriteTarget target(image);
        if (!Require(ExecuteAppleCheckpointPublication(target, publication, error),
                "bitmap-continuity publisher executes: " + error)) return false;
        image = target.Image();
        if (mode == 2)
        {
            auto disconnected = old->container.superblock_bytes;
            PutU64LE(disconnected, 0x60, request.transaction_xid + 1);
            FletcherForBlock(disconnected, kBlockSize);
            PutBlock(image, old->container.superblock_physical_block, disconnected);
        }
        VectorRandomAccessSource after(image);
        const auto current = LoadAppleCheckpointView(after, 0, after.SizeBytes(), error);
        const auto still_readable = LoadAppleCheckpointView(after, 0, after.SizeBytes(), error, store.xid);
        if (!Require(current.has_value() && still_readable.has_value(),
                "both generations parse despite ambiguous historical continuity: " + error)) return false;
        std::vector<AppleRecoveryCheckpointView> retained;
        const auto admitted = LoadAppleRecoveryCheckpoints(after, *current, {store.xid}, retained, error);
        ok &= Require(mode == 0 ? (admitted && retained.size() == 1) :
                (!admitted && retained.empty() && error == "AppleCheckpointRetentionContinuityUnavailable"),
            "bitmap-slot XID and exact next-generation link must remain continuous: " + error);
    }
    return ok;
}

bool TestRetainedCheckpointRingAdmission()
{
    bool ok = true;
    for (int mode = 0; mode < 3; ++mode)
    {
        auto fixture = BuildWrappedPublisherFixture(mode == 1 ? 4 : 8,
            mode == 0 ? 8 : 12, true);
        const auto original = fixture.checkpoint;
        std::string error;
        auto first_request = BuildRequest(fixture);
        first_request.required_checkpoint_xids = {40};
        AppleCheckpointPublicationPlan first;
        VectorRandomAccessSource initial_source(fixture.image);
        if (!Require(PlanAppleCheckpointPublication(initial_source,
                fixture.checkpoint, first_request, first, error),
                "first pinned publication plans: " + error))
        {
            return false;
        }
        MemoryWriteTarget target(fixture.image);
        if (!Require(ExecuteAppleCheckpointPublication(target, first, error),
                "first pinned publication executes: " + error))
        {
            return false;
        }
        fixture.image = target.Image();
        fixture.checkpoint = first.published_checkpoint;
        auto request = BuildRequest(fixture);
        request.required_checkpoint_xids = {40, 41};
        VectorRandomAccessSource source(fixture.image);
        AppleCheckpointPublicationPlan second;
        const auto planned = PlanAppleCheckpointPublication(source,
            fixture.checkpoint, request, second, error);
        if (mode < 2)
        {
            ok &= Require(!planned && second.before_superblock_writes.empty() &&
                    second.superblock_write.bytes.empty() && error == (mode == 0
                        ? "AppleCheckpointDataRetentionExhausted"
                        : "AppleCheckpointDescriptorRetentionExhausted"),
                "retention capacity refuses a complete plan before I/O: " + error);
            const auto retained = LoadContainerCheckpointView(
                source, 0, source.SizeBytes(), error, 40);
            ok &= Require(retained.has_value() &&
                    retained->superblock_bytes == original.superblock_bytes,
                "capacity refusal keeps the exact original generation: " + error);
            request.required_checkpoint_xids.clear();
            ok &= Require(PlanAppleCheckpointPublication(source,
                    fixture.checkpoint, request, second, error),
                "releasing recovery pin permits ring reuse: " + error);
            continue;
        }
        if (!Require(planned, "sufficient ring retains three generations: " + error))
        {
            return false;
        }
        MemoryWriteTarget completed(fixture.image);
        ok &= Require(ExecuteAppleCheckpointPublication(completed, second, error),
            "second pinned publication executes: " + error);
        VectorRandomAccessSource completed_source(completed.Image());
        for (const auto xid : {40ULL, 41ULL, 42ULL})
        {
            ok &= Require(LoadContainerCheckpointView(completed_source, 0,
                    completed_source.SizeBytes(), error, xid).has_value(),
                "all required container generations reload: " + error);
        }
        for (std::size_t fail_at = 0;
             fail_at < completed.MutatingOperationCount(); ++fail_at)
        {
            MemoryWriteTarget crashed(fixture.image, fail_at);
            error.clear();
            ok &= Require(!ExecuteAppleCheckpointPublication(crashed, second, error),
                "pinned crash prefix interrupts publication");
            VectorRandomAccessSource crash_source(crashed.Image());
            for (const auto xid : {40ULL, 41ULL})
            {
                ok &= Require(LoadContainerCheckpointView(crash_source, 0,
                        crash_source.SizeBytes(), error, xid).has_value(),
                    "crash preserves original and current checkpoints: " + error);
            }
        }
        MemoryWriteTarget stale(fixture.image);
        stale.MutableImage()[original.mappings.front().physical_block *
            kBlockSize + 0x30] ^= std::byte{1};
        error.clear();
        ok &= Require(!ExecuteAppleCheckpointPublication(stale, second, error) &&
                error == "AppleCheckpointGuardChanged" &&
                stale.MutatingOperationCount() == 0,
            "historical guard drift refuses before any write: " + error);
        for (const auto invalid : {0ULL, 39ULL, 42ULL})
        {
            request.required_checkpoint_xids = {invalid};
            ok &= Require(!PlanAppleCheckpointPublication(source,
                    fixture.checkpoint, request, second, error) &&
                    second.before_superblock_writes.empty(),
                "zero, missing and future required generations refuse");
        }
        VectorRandomAccessSource stale_source(stale.Image());
        request.required_checkpoint_xids = {40};
        ok &= Require(!PlanAppleCheckpointPublication(stale_source,
                fixture.checkpoint, request, second, error) &&
                error == "AppleCheckpointRetentionUnavailable",
            "corrupt pinned history cannot be supplied by the caller: " + error);
    }
    return ok;
}

bool TestRejectsUnsafePlansAndStaleExecution()
{
    const auto fixture = BuildWrappedPublisherFixture();
    const auto valid = BuildRequest(fixture);
    VectorRandomAccessSource source(fixture.image);
    AppleCheckpointPublicationPlan plan;
    std::string error;
    bool ok = true;
    const auto rejects = [&](AppleCheckpointPublicationRequest request,
                             const std::string& expected,
                             const std::string& label) {
        AppleCheckpointPublicationPlan rejected;
        error.clear();
        return Require(!PlanAppleCheckpointPublication(
                source, fixture.checkpoint, request, rejected, error) &&
                error == expected && rejected.before_superblock_writes.empty(),
            label + ": " + error);
    };

    auto missing = valid;
    missing.ephemeral_objects.pop_back();
    ok &= rejects(std::move(missing), "AppleCheckpointEphemeralSetIncomplete",
        "missing old ephemeral object rejected");
    auto retired = valid;
    const auto retired_oid = retired.ephemeral_objects.back().object.object_id;
    retired.ephemeral_objects.pop_back();
    retired.retired_ephemeral_object_ids.push_back(retired_oid);
    AppleCheckpointPublicationPlan retired_plan;
    error.clear();
    ok &= Require(PlanAppleCheckpointPublication(source, fixture.checkpoint,
            retired, retired_plan, error) &&
            std::none_of(retired_plan.published_checkpoint.mappings.begin(),
                retired_plan.published_checkpoint.mappings.end(),
                [retired_oid](const auto& mapping) {
                    return mapping.object_id == retired_oid;
                }),
        "explicit old ephemeral retirement succeeds: " + error);
    auto unknown_retirement = valid;
    unknown_retirement.retired_ephemeral_object_ids.push_back(0xBAD0u);
    ok &= rejects(std::move(unknown_retirement),
        "AppleCheckpointEphemeralRetirementInvalid",
        "unknown old ephemeral retirement rejected");
    auto duplicate_retirement = valid;
    duplicate_retirement.retired_ephemeral_object_ids.push_back(
        duplicate_retirement.ephemeral_objects.back().object.object_id);
    ok &= rejects(std::move(duplicate_retirement),
        "AppleCheckpointEphemeralRetirementInvalid",
        "supplied and retired ephemeral identity rejected");
    auto root_retirement = valid;
    root_retirement.ephemeral_objects.erase(
        root_retirement.ephemeral_objects.begin());
    root_retirement.retired_ephemeral_object_ids.push_back(
        fixture.checkpoint.superblock.spaceman_oid);
    ok &= rejects(std::move(root_retirement),
        "AppleCheckpointEphemeralRetirementInvalid",
        "spaceman retirement rejected");
    auto duplicate = valid;
    duplicate.ephemeral_objects.push_back(duplicate.ephemeral_objects.front());
    ok &= rejects(std::move(duplicate), "AppleCheckpointEphemeralObjectDuplicate",
        "duplicate ephemeral object rejected");
    auto corrupt = valid;
    corrupt.ephemeral_objects.front().bytes[64] ^= std::byte{0x01};
    ok &= rejects(std::move(corrupt), "AppleCheckpointEphemeralObjectInvalid",
        "bad ephemeral checksum rejected");
    auto wrong_xid = valid;
    wrong_xid.transaction_xid++;
    ok &= rejects(std::move(wrong_xid), "AppleCheckpointTransactionXidInvalid",
        "non-next transaction XID rejected");
      auto ring_overlap = valid;
    ring_overlap.allocator_owned_writes.push_back({48,
        std::vector<std::byte>(kBlockSize, std::byte{0x22})});
      ok &= rejects(std::move(ring_overlap), "AppleCheckpointAllocatedWriteInvalid",
          "allocator write into checkpoint ring rejected");
      auto invalid_omap = valid;
      invalid_omap.container_object_map_oid = 25;
      invalid_omap.allocator_owned_writes.push_back(
          {25, std::vector<std::byte>(kBlockSize, std::byte{0})});
      ok &= rejects(std::move(invalid_omap),
          "AppleCheckpointContainerOmapInvalid",
          "malformed replacement container object map rejected");

    ok &= Require(PlanAppleCheckpointPublication(
            source, fixture.checkpoint, valid, plan, error),
        "valid guard plan succeeds: " + error);
    MemoryWriteTarget changed(fixture.image);
    changed.MutableImage()[static_cast<std::size_t>(
        fixture.checkpoint.superblock_physical_block) * kBlockSize + 0x30] ^=
        std::byte{0x01};
    error.clear();
    ok &= Require(!ExecuteAppleCheckpointPublication(changed, plan, error) &&
            error == "AppleCheckpointGuardChanged" &&
            changed.MutatingOperationCount() == 0,
        "stale selected checkpoint stops before the first write: " + error);

    MemoryWriteTarget changed_spaceman(fixture.image);
    const auto spaceman_block = fixture.checkpoint.mappings.front().physical_block;
    changed_spaceman.MutableImage()[
        static_cast<std::size_t>(spaceman_block) * kBlockSize + 0x30] ^=
        std::byte{0x01};
    error.clear();
    ok &= Require(!ExecuteAppleCheckpointPublication(
            changed_spaceman, plan, error) &&
            error == "AppleCheckpointGuardChanged" &&
            changed_spaceman.MutatingOperationCount() == 0,
        "stale checkpoint-data object stops before the first write: " + error);
    return ok;
}

} // namespace

int main()
{
    bool ok = true;
    ok &= TestBoundedReadbackCoalescesAndChecksAllBytes();
    ok &= TestBoundedReadbackPreservesNonadjacentOrder();
    ok &= TestBoundedReadbackCorruptionAndFailuresStopPublication();
    ok &= TestDefaultReadbackPreservesSingleBlockFailureOrder();
    ok &= TestPlansAndPublishesWrappedCheckpoint();
    ok &= TestEveryCrashPrefixSelectsOldOrNew();
    ok &= TestPublishesThroughBlockDevice();
    ok &= TestComposesSpacemanAllocationAndCrashSafePublication();
      ok &= TestPublishesReachableFileThroughBothObjectMaps();
      ok &= TestVolumeTransactionMaintainsPhysicalExtentReferences();
      ok &= TestVolumeTransactionRejectsSnapshots();
    ok &= TestRejectsUnsafePlansAndStaleExecution();
    ok &= TestRetainedCheckpointRingAdmission();
    ok &= TestVolumeRejectsMissingRecoveryGeneration();
    ok &= TestVolumeRetainsExactHistoryUntilPinRelease();
    ok &= TestLateRecoveryPinRejectsReclaimedDescendants();
    ok &= TestLateRecoveryPinRejectsReclaimedDescendants(true);
    ok &= TestRecoveryPinRequiresBitmapAndGenerationContinuity();
    if (ok && g_failures == 0)
    {
        std::cout << "APFS APPLE CHECKPOINT PUBLISHER PASS" << std::endl;
        return 0;
    }
    std::cerr << "APFS APPLE CHECKPOINT PUBLISHER FAIL: "
              << g_failures << " check(s)" << std::endl;
    return 1;
}
