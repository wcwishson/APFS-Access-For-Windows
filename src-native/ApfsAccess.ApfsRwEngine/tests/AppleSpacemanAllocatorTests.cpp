#include "ApfsFormat.h"
#include "AppleSpacemanAllocator.h"
#include "ApfsTransactionWriter.h"
#include "TestFixtureBuilder.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace
{

using namespace apfsaccess::catalog;
using namespace apfsaccess::testfixture;

constexpr std::uint32_t kBlockSize = 4096;
constexpr std::uint64_t kBlockCount = 128;
constexpr std::uint64_t kCheckpointXid = 20;
constexpr std::uint64_t kSpacemanOid = 1024;
constexpr std::uint64_t kFreeQueueOid = 1025;
constexpr std::uint64_t kMainFreeQueueOid = 1026;
constexpr std::uint64_t kSpacemanBlock = 100;
constexpr std::uint64_t kFreeQueueBlock = 101;
constexpr std::uint64_t kMainFreeQueueBlock = 110;
constexpr std::uint64_t kCibBlock = 102;
constexpr std::uint64_t kChunkZeroBitmapBlock = 104;
constexpr std::uint64_t kChunkOneBitmapBlock = 105;
constexpr std::uint64_t kIpBitmapBase = 64;
constexpr std::uint64_t kIpBase = 100;
constexpr std::uint64_t kIpBlockCount = 16;
constexpr std::uint64_t kQueuedIpBlock = 106;
constexpr std::uint64_t kQueuedIpBlockCount = 2;

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

void SetBit(std::vector<std::byte>& bitmap, std::uint64_t bit)
{
    const auto byte_index = static_cast<std::size_t>(bit / 8);
    bitmap[byte_index] |= static_cast<std::byte>(1u << (bit % 8));
}

std::uint32_t CountSetBits(
    const std::vector<std::byte>& bitmap,
    std::uint32_t bit_count)
{
    std::uint32_t count = 0;
    for (std::uint32_t bit = 0; bit < bit_count; ++bit)
    {
        if ((std::to_integer<unsigned int>(bitmap[bit / 8]) &
                (1u << (bit % 8))) != 0)
        {
            ++count;
        }
    }
    return count;
}

bool SameQueueEntries(
    const std::vector<AppleSpacemanFreeQueueEntry>& left,
    const std::vector<AppleSpacemanFreeQueueEntry>& right)
{
    return left.size() == right.size() &&
        std::equal(left.begin(), left.end(), right.begin(),
            [](const auto& lhs, const auto& rhs) {
                return lhs.xid == rhs.xid &&
                    lhs.physical_block == rhs.physical_block &&
                    lhs.block_count == rhs.block_count;
            });
}

bool SameReloadedAllocatorState(
    const AppleSpacemanView& left,
    const AppleSpacemanView& right)
{
    if (left.bytes != right.bytes || left.chunks.size() != right.chunks.size() ||
        left.devices[0].free_count != right.devices[0].free_count ||
        left.devices[0].cibs.size() != right.devices[0].cibs.size() ||
        left.devices[0].cabs.size() != right.devices[0].cabs.size() ||
        left.internal_pool.active_bitmaps.size() !=
            right.internal_pool.active_bitmaps.size())
    {
        return false;
    }
    for (std::size_t index = 0; index < left.chunks.size(); ++index)
    {
        const auto& lhs = left.chunks[index];
        const auto& rhs = right.chunks[index];
        if (lhs.xid != rhs.xid || lhs.free_count != rhs.free_count ||
            lhs.bitmap_block != rhs.bitmap_block ||
            lhs.allocation_bitmap != rhs.allocation_bitmap)
        {
            return false;
        }
    }
    for (std::size_t index = 0;
         index < left.devices[0].cibs.size(); ++index)
    {
        const auto& lhs = left.devices[0].cibs[index];
        const auto& rhs = right.devices[0].cibs[index];
        if (lhs.object.physical_block != rhs.object.physical_block ||
            lhs.bytes != rhs.bytes)
        {
            return false;
        }
    }
    for (std::size_t index = 0;
         index < left.devices[0].cabs.size(); ++index)
    {
        const auto& lhs = left.devices[0].cabs[index];
        const auto& rhs = right.devices[0].cabs[index];
        if (lhs.object.physical_block != rhs.object.physical_block ||
            lhs.bytes != rhs.bytes || lhs.cib_blocks != rhs.cib_blocks)
        {
            return false;
        }
    }
    for (std::size_t index = 0;
         index < left.internal_pool.active_bitmaps.size(); ++index)
    {
        const auto& lhs = left.internal_pool.active_bitmaps[index];
        const auto& rhs = right.internal_pool.active_bitmaps[index];
        if (lhs.xid != rhs.xid || lhs.physical_block != rhs.physical_block ||
            lhs.rotation_index != rhs.rotation_index || lhs.bytes != rhs.bytes)
        {
            return false;
        }
    }
    for (std::size_t index = 0; index < left.free_queues.size(); ++index)
    {
        const auto& lhs = left.free_queues[index];
        const auto& rhs = right.free_queues[index];
        if (lhs.block_count != rhs.block_count ||
            lhs.oldest_xid != rhs.oldest_xid ||
            lhs.tree_flags != rhs.tree_flags ||
            lhs.fixed_key_size != rhs.fixed_key_size ||
            lhs.fixed_value_size != rhs.fixed_value_size ||
            lhs.longest_key != rhs.longest_key ||
            lhs.longest_value != rhs.longest_value ||
            lhs.root.physical_block != rhs.root.physical_block ||
            lhs.tree_blocks != rhs.tree_blocks ||
            !SameQueueEntries(lhs.entries, rhs.entries))
        {
            return false;
        }
    }
    return true;
}

void PutBlock(
    std::vector<std::byte>& image,
    std::uint64_t block,
    const std::vector<std::byte>& bytes)
{
    const auto offset = static_cast<std::size_t>(block * kBlockSize);
    std::copy(bytes.begin(), bytes.end(), image.begin() + offset);
}

AppleSpacemanView MaterializeEphemeralQueueWrites(
    std::vector<std::byte>& image,
    ContainerCheckpointView& checkpoint,
    const apfsaccess::rw::AppleSpacemanAllocationPlan& plan,
    std::uint64_t first_block)
{
    auto materialized = plan.updated_spaceman;
    std::vector<std::uint64_t> pending_tree_blocks;
    for (const auto& write : plan.writes)
    {
        if (write.kind != apfsaccess::rw::AppleSpacemanWriteKind::FreeQueueTree ||
            !write.object_location.has_value())
        {
            continue;
        }
        auto location = write.object_location.value();
        location.physical_block = first_block++;
        PutBlock(image, location.physical_block, write.bytes);
        auto mapping = std::find_if(checkpoint.mappings.begin(),
            checkpoint.mappings.end(), [&location](const auto& candidate) {
                return candidate.object_id == location.object_id;
            });
        if (mapping == checkpoint.mappings.end())
        {
            checkpoint.mappings.push_back({location.type, location.subtype,
                location.size_bytes, 0, location.object_id,
                location.physical_block});
        }
        else
        {
            mapping->type = location.type;
            mapping->subtype = location.subtype;
            mapping->size_bytes = location.size_bytes;
            mapping->physical_block = location.physical_block;
        }
        pending_tree_blocks.push_back(location.physical_block);
        auto queue = std::find_if(materialized.free_queues.begin(),
            materialized.free_queues.end(), [&location](const auto& candidate) {
                return candidate.tree_oid == location.object_id;
            });
        if (queue != materialized.free_queues.end())
        {
            queue->root = location;
            queue->tree_blocks = {location.physical_block};
            queue->tree_blocks.insert(queue->tree_blocks.end(),
                pending_tree_blocks.begin(), pending_tree_blocks.end() - 1);
            pending_tree_blocks.clear();
        }
    }
    return materialized;
}

std::vector<std::byte> GetBlock(
    const std::vector<std::byte>& image,
    std::uint64_t block)
{
    const auto offset = static_cast<std::size_t>(block * kBlockSize);
    return std::vector<std::byte>(
        image.begin() + offset, image.begin() + offset + kBlockSize);
}

BtreeRecord MakeFreeQueueRecord(
    std::uint64_t xid,
    std::uint64_t physical_block,
    std::uint64_t block_count)
{
    BtreeRecord record;
    record.key.resize(16, std::byte{0});
    PutU64LE(record.key, 0, xid);
    PutU64LE(record.key, 8, physical_block);
    if (block_count != 1)
    {
        record.value.resize(8, std::byte{0});
        PutU64LE(record.value, 0, block_count);
    }
    return record;
}

template <typename Mutation>
void MutateChecksummedBlock(
    std::vector<std::byte>& image,
    std::uint64_t block,
    Mutation mutation)
{
    auto bytes = GetBlock(image, block);
    mutation(bytes);
    FletcherForBlock(bytes, kBlockSize);
    PutBlock(image, block, bytes);
}

struct OwnershipFixture
{
    std::vector<std::byte> image;
    ContainerCheckpointView checkpoint;
};

OwnershipFixture BuildDirectCibFixture()
{
    OwnershipFixture fixture;
    fixture.image.resize(kBlockCount * kBlockSize, std::byte{0});
    fixture.checkpoint.superblock.block_size = kBlockSize;
    fixture.checkpoint.superblock.block_count = kBlockCount;
    fixture.checkpoint.superblock.xid = kCheckpointXid;
    fixture.checkpoint.superblock.spaceman_oid = kSpacemanOid;
    fixture.checkpoint.mappings = {
        CheckpointMapping{0x80000005, 0, kBlockSize, 0,
            kSpacemanOid, kSpacemanBlock},
        CheckpointMapping{0x80000002, kObjectTypeSpacemanFreeQueue,
            kBlockSize, 0, kFreeQueueOid, kFreeQueueBlock},
        CheckpointMapping{0x80000002, kObjectTypeSpacemanFreeQueue,
            kBlockSize, 0, kMainFreeQueueOid, kMainFreeQueueBlock},
    };

    std::vector<std::byte> chunk_zero_bitmap(kBlockSize, std::byte{0});
    for (const std::uint64_t block : {0ull, 1ull, 2ull, 3ull, 4ull, 32ull,
             33ull, 34ull, 35ull, 40ull, 41ull})
    {
        SetBit(chunk_zero_bitmap, block);
    }
    std::vector<std::byte> chunk_one_bitmap(kBlockSize, std::byte{0});
    for (std::uint64_t block = 64; block <= 81; ++block)
    {
        SetBit(chunk_one_bitmap, block - 64);
    }
    for (std::uint64_t block = kIpBase; block < kIpBase + kIpBlockCount; ++block)
    {
        SetBit(chunk_one_bitmap, block - 64);
    }
    PutBlock(fixture.image, kChunkZeroBitmapBlock, chunk_zero_bitmap);
    PutBlock(fixture.image, kChunkOneBitmapBlock, chunk_one_bitmap);

    std::vector<std::byte> ip_bitmap(kBlockSize, std::byte{0});
    for (const std::uint64_t block : {kSpacemanBlock, kFreeQueueBlock,
             kCibBlock, kChunkZeroBitmapBlock, kChunkOneBitmapBlock,
             kQueuedIpBlock, kQueuedIpBlock + 1, kMainFreeQueueBlock})
    {
        SetBit(ip_bitmap, block - kIpBase);
    }
    PutBlock(fixture.image, kIpBitmapBase, ip_bitmap);

    auto cib = BuildEphemeralObject(kCibBlock, kCheckpointXid,
        kObjectPhysical | 0x00000007u, 0, kBlockSize);
    PutU32LE(cib, 0x20, 0);
    PutU32LE(cib, 0x24, 2);
    PutU64LE(cib, 0x28, kCheckpointXid);
    PutU64LE(cib, 0x30, 0);
    PutU32LE(cib, 0x38, 64);
    PutU32LE(cib, 0x3C, 64 - CountSetBits(chunk_zero_bitmap, 64));
    PutU64LE(cib, 0x40, kChunkZeroBitmapBlock);
    PutU64LE(cib, 0x48, kCheckpointXid);
    PutU64LE(cib, 0x50, 64);
    PutU32LE(cib, 0x58, 64);
    PutU32LE(cib, 0x5C, 64 - CountSetBits(chunk_one_bitmap, 64));
    PutU64LE(cib, 0x60, kChunkOneBitmapBlock);
    FletcherForBlock(cib, kBlockSize);
    PutBlock(fixture.image, kCibBlock, cib);

    auto spaceman = BuildEphemeralObject(kSpacemanOid, kCheckpointXid,
        kObjectEphemeral | kObjectTypeSpaceman, 0, kBlockSize);
    PutU32LE(spaceman, 0x20, kBlockSize);
    PutU32LE(spaceman, 0x24, 64);
    PutU32LE(spaceman, 0x28, 2);
    PutU32LE(spaceman, 0x2C, 64);
    PutU64LE(spaceman, 0x30, kBlockCount);
    PutU64LE(spaceman, 0x38, 2);
    PutU32LE(spaceman, 0x40, 1);
    PutU32LE(spaceman, 0x44, 0);
    const auto main_free_count =
        static_cast<std::uint64_t>(64 - CountSetBits(chunk_zero_bitmap, 64)) +
        static_cast<std::uint64_t>(64 - CountSetBits(chunk_one_bitmap, 64));
    PutU64LE(spaceman, 0x48, main_free_count);
    PutU32LE(spaceman, 0x50, 0x600);
    PutU32LE(spaceman, 0x90, 0);
    PutU32LE(spaceman, 0x94, 16);
    PutU64LE(spaceman, 0x98, kIpBlockCount);
    PutU32LE(spaceman, 0xA0, 1);
    PutU32LE(spaceman, 0xA4, 16);
    PutU64LE(spaceman, 0xA8, kIpBitmapBase);
    PutU64LE(spaceman, 0xB0, kIpBase);
    PutU64LE(spaceman, 0xC8, kQueuedIpBlockCount);
    PutU64LE(spaceman, 0xC0, 0xDEADBEEFDEADBEEFull);
    PutU64LE(spaceman, 0xD0, kFreeQueueOid);
    PutU64LE(spaceman, 0xD8, kCheckpointXid - 1);
    PutU16LE(spaceman, 0xE0, 64);
    PutU64LE(spaceman, 0xF8, kMainFreeQueueOid);
    PutU16LE(spaceman, 0x108, 64);
    PutU16LE(spaceman, 0x140, 1);
    PutU16LE(spaceman, 0x142, 15);
    PutU32LE(spaceman, 0x144, 0x700);
    PutU32LE(spaceman, 0x148, 0x708);
    PutU32LE(spaceman, 0x14C, 0x720);
    PutU32LE(spaceman, 0x150, 1);
    PutU32LE(spaceman, 0x154, 0x800);
    PutU64LE(spaceman, 0x600, kCibBlock);
    PutU64LE(spaceman, 0x700, kCheckpointXid);
    PutU16LE(spaceman, 0x708, 0);
    PutU16LE(spaceman, 0x720, 0xFFFF);
    for (std::uint16_t index = 1; index < 16; ++index)
    {
        PutU16LE(spaceman, 0x720 + index * 2,
            index == 15 ? 0xFFFF : static_cast<std::uint16_t>(index + 1));
    }
    FletcherForBlock(spaceman, kBlockSize);
    PutBlock(fixture.image, kSpacemanBlock, spaceman);

    apfsaccess::rw::AppleBtreeOptions queue_options;
    queue_options.block_size = kBlockSize;
    queue_options.xid = kCheckpointXid;
    queue_options.root_object_id = kFreeQueueOid;
    queue_options.root_physical_block = kFreeQueueBlock;
    queue_options.storage_type = kObjectEphemeral;
    queue_options.subtype = kObjectTypeSpacemanFreeQueue;
    queue_options.tree_flags = apfsaccess::rw::kAppleBtreeEphemeral |
        apfsaccess::rw::kAppleBtreeAllowGhosts |
        apfsaccess::rw::kAppleBtreeUint64Keys |
        apfsaccess::rw::kAppleBtreeSequentialInsert;
    queue_options.fixed_key_size = 16;
    queue_options.fixed_value_size = 8;
    queue_options.minimum_longest_key = 16;
    queue_options.minimum_longest_value = 8;
    queue_options.key_order =
        apfsaccess::rw::AppleBtreeKeyOrder::SpacemanFreeQueue;
    apfsaccess::rw::AppleSerializedBtree queue_tree;
    std::string queue_error;
    if (apfsaccess::rw::SerializeAppleBtree(
            {MakeFreeQueueRecord(kCheckpointXid - 1, kQueuedIpBlock,
                kQueuedIpBlockCount)},
            queue_options, queue_tree, queue_error) &&
        queue_tree.objects.size() == 1)
    {
        PutBlock(fixture.image, kFreeQueueBlock, queue_tree.objects[0].bytes);
    }
    queue_options.root_object_id = kMainFreeQueueOid;
    queue_options.root_physical_block = kMainFreeQueueBlock;
    if (apfsaccess::rw::SerializeAppleBtree(
            {}, queue_options, queue_tree, queue_error) &&
        queue_tree.objects.size() == 1)
    {
        PutBlock(fixture.image, kMainFreeQueueBlock,
            queue_tree.objects[0].bytes);
    }
    return fixture;
}

OwnershipFixture BuildCabFixture()
{
    constexpr std::uint64_t kCabBlock = 103;
    auto fixture = BuildDirectCibFixture();
    MutateChecksummedBlock(fixture.image, kSpacemanBlock,
        [](std::vector<std::byte>& spaceman) {
            PutU32LE(spaceman, 0x44, 1);
            PutU64LE(spaceman, 0x600, kCabBlock);
        });
    auto ip_bitmap = GetBlock(fixture.image, kIpBitmapBase);
    SetBit(ip_bitmap, kCabBlock - kIpBase);
    PutBlock(fixture.image, kIpBitmapBase, ip_bitmap);
    auto cab = BuildEphemeralObject(kCabBlock, kCheckpointXid,
        kObjectPhysical | kObjectTypeSpacemanCab, 0, kBlockSize);
    PutU32LE(cab, 0x20, 0);
    PutU32LE(cab, 0x24, 1);
    PutU64LE(cab, 0x28, kCibBlock);
    FletcherForBlock(cab, kBlockSize);
    PutBlock(fixture.image, kCabBlock, cab);
    return fixture;
}

bool TestLoadsVerifiedDirectCibOwnership()
{
    const auto fixture = BuildDirectCibFixture();
    VectorRandomAccessSource source(fixture.image);
    AppleSpacemanView view;
    std::string error;
    bool ok = true;
    ok &= Require(LoadAppleSpacemanOwnershipView(
            source, fixture.checkpoint, view, error),
        "direct-CIB spaceman ownership loads: " + error);
    if (!ok)
    {
        return false;
    }
    ok &= Require(view.blocks_per_chunk == 64 && view.chunks_per_cib == 2,
        "spaceman geometry retained");
    ok &= Require(view.devices[0].block_count == kBlockCount &&
            view.devices[0].cibs.size() == 1 &&
            view.devices[0].cibs[0].object.physical_block == kCibBlock,
        "main device direct CIB retained");
    ok &= Require(view.chunks.size() == 2 &&
            view.chunks[0].start_block == 0 &&
            view.chunks[1].start_block == 64 &&
            view.chunks[0].allocation_bitmap.size() == kBlockSize &&
            view.chunks[1].allocation_bitmap.size() == kBlockSize,
        "chunk ownership maps retained");
    ok &= Require(view.internal_pool.base_block == kIpBase &&
            view.internal_pool.block_count == kIpBlockCount &&
            view.internal_pool.active_bitmaps.size() == 1 &&
            view.internal_pool.active_bitmaps[0].physical_block == kIpBitmapBase,
        "internal-pool ownership retained");
    ok &= Require(view.free_queues[0].tree_oid == kFreeQueueOid &&
            view.free_queues[0].root.physical_block == kFreeQueueBlock &&
            view.free_queues[0].entries.size() == 1 &&
            view.free_queues[0].entries[0].xid == kCheckpointXid - 1 &&
            view.free_queues[0].entries[0].physical_block == kQueuedIpBlock &&
            view.free_queues[0].entries[0].block_count == kQueuedIpBlockCount &&
            view.free_queues[0].tree_blocks ==
                std::vector<std::uint64_t>{kFreeQueueBlock} &&
            view.free_queues[0].tree_flags == 0x0Fu &&
            view.free_queues[0].fixed_key_size == 16 &&
            view.free_queues[0].fixed_value_size == 8 &&
            view.free_queues[0].longest_key == 16 &&
            view.free_queues[0].longest_value == 8,
        "free queue retains verified records and exact tree ownership");
    ok &= Require(view.free_queues[1].tree_oid == kMainFreeQueueOid &&
            view.free_queues[1].root.physical_block == kMainFreeQueueBlock &&
            view.free_queues[1].entries.empty(),
        "main free queue is independently bound and empty");
    return ok;
}

bool TestLoadsVerifiedCabOwnership()
{
    constexpr std::uint64_t kCabBlock = 103;
    auto fixture = BuildCabFixture();

    VectorRandomAccessSource source(fixture.image);
    AppleSpacemanView view;
    std::string error;
    bool ok = true;
    ok &= Require(LoadAppleSpacemanOwnershipView(
            source, fixture.checkpoint, view, error),
        "CAB spaceman ownership loads: " + error);
    if (!ok)
    {
        return false;
    }
    ok &= Require(view.devices[0].cabs.size() == 1 &&
            view.devices[0].cabs[0].object.physical_block == kCabBlock &&
            view.devices[0].cabs[0].cib_blocks ==
                std::vector<std::uint64_t>{kCibBlock},
        "CAB indirection and CIB addresses retained");
    return ok;
}

bool TestPlansCabHierarchyCow()
{
    constexpr std::uint64_t kCabBlock = 103;
    const auto fixture = BuildCabFixture();
    VectorRandomAccessSource source(fixture.image);
    AppleSpacemanView view;
    std::string error;
    bool ok = Require(LoadAppleSpacemanOwnershipView(
            source, fixture.checkpoint, view, error),
        "CAB allocation source loads: " + error);
    if (!ok)
    {
        return false;
    }

    apfsaccess::rw::AppleSpacemanAllocationRequest request;
    request.expected_checkpoint_xid = kCheckpointXid;
    request.transaction_xid = kCheckpointXid + 1;
    request.main_block_count = 1;
    request.first_ephemeral_object_id = 6000;
    apfsaccess::rw::AppleSpacemanAllocationPlan plan;
    ok &= Require(apfsaccess::rw::PlanAppleSpacemanAllocation(
            view, request, plan, error),
        "CAB allocation plan succeeds: " + error);
    ok &= Require(plan.allocated_internal_pool_blocks ==
            std::vector<std::uint64_t>{106, 107, 108},
        "only the CAB hierarchy consumes verified internal-pool blocks");
    ok &= Require(plan.updated_spaceman.devices[0].cabs[0].object.physical_block == 108 &&
            plan.updated_spaceman.devices[0].cabs[0].cib_blocks ==
                std::vector<std::uint64_t>{107} &&
            ReadU64LE(plan.updated_spaceman.bytes, 0x600).value_or(0) == 108,
        "spaceman, CAB, and CIB ownership point to the new hierarchy");
    ok &= Require(plan.deferred_frees.size() == 3 &&
            plan.deferred_frees[0].physical_block == kChunkZeroBitmapBlock &&
            plan.deferred_frees[1].physical_block == kCibBlock &&
            plan.deferred_frees[2].physical_block == kCabBlock,
        "retired physical CAB hierarchy is queued exactly once");

    auto published_image = fixture.image;
    PutBlock(published_image, kSpacemanBlock,
        plan.updated_spaceman.bytes);
    for (const auto& write : plan.writes)
    {
        if (write.physical_block != 0)
        {
            PutBlock(published_image, write.physical_block, write.bytes);
        }
    }
    auto published_checkpoint = fixture.checkpoint;
    published_checkpoint.superblock.xid = request.transaction_xid;
    const auto materialized = MaterializeEphemeralQueueWrites(
        published_image, published_checkpoint, plan, 82);
    VectorRandomAccessSource published_source(std::move(published_image));
    AppleSpacemanView reloaded;
    ok &= Require(LoadAppleSpacemanOwnershipView(
            published_source, published_checkpoint, reloaded, error),
        "independent parser accepts staged CAB allocator graph: " + error);
    ok &= Require(SameReloadedAllocatorState(
            reloaded, materialized),
        "independent parser reproduces staged CAB allocator state");
    return ok;
}

bool TestRejectsMalformedOwnershipState()
{
    const auto rejects = [](OwnershipFixture fixture,
                            const std::string& expected_error,
                            const std::string& label) {
        VectorRandomAccessSource source(fixture.image);
        AppleSpacemanView view;
        std::string error;
        return Require(!LoadAppleSpacemanOwnershipView(
                source, fixture.checkpoint, view, error) &&
                error == expected_error,
            label + ": " + error);
    };

    bool ok = true;
    {
        auto fixture = BuildDirectCibFixture();
        fixture.image[kCibBlock * kBlockSize + 0x30] ^= std::byte{0x01};
        ok &= rejects(std::move(fixture), "AppleSpacemanCibChecksumInvalid",
            "CIB checksum mismatch rejected");
    }
    {
        auto fixture = BuildDirectCibFixture();
        MutateChecksummedBlock(fixture.image, kCibBlock,
            [](std::vector<std::byte>& cib) {
                PutU64LE(cib, 0x08, kCibBlock + 1);
            });
        ok &= rejects(std::move(fixture), "AppleSpacemanCibObjectIdMismatch",
            "CIB physical identity mismatch rejected");
    }
    {
        auto fixture = BuildDirectCibFixture();
        MutateChecksummedBlock(fixture.image, kCibBlock,
            [](std::vector<std::byte>& cib) {
                PutU64LE(cib, 0x48, kCheckpointXid + 1);
            });
        ok &= rejects(std::move(fixture), "AppleSpacemanChunkGeometryInvalid",
            "future chunk XID rejected");
    }
    {
        auto fixture = BuildDirectCibFixture();
        MutateChecksummedBlock(fixture.image, kCibBlock,
            [](std::vector<std::byte>& cib) {
                PutU32LE(cib, 0x3C, ReadU32LE(cib, 0x3C).value() - 1);
            });
        ok &= rejects(std::move(fixture), "AppleSpacemanChunkFreeCountMismatch",
            "chunk free-count mismatch rejected");
    }
    {
        auto fixture = BuildDirectCibFixture();
        auto ip_bitmap = GetBlock(fixture.image, kIpBitmapBase);
        ip_bitmap[(kChunkOneBitmapBlock - kIpBase) / 8] &=
            static_cast<std::byte>(~(1u << ((kChunkOneBitmapBlock - kIpBase) % 8)));
        PutBlock(fixture.image, kIpBitmapBase, ip_bitmap);
        ok &= rejects(std::move(fixture),
            "AppleSpacemanInternalPoolOwnershipMismatch",
            "unowned chunk bitmap rejected");
    }
    {
        auto fixture = BuildDirectCibFixture();
        MutateChecksummedBlock(fixture.image, kSpacemanBlock,
            [](std::vector<std::byte>& spaceman) {
                PutU16LE(spaceman, 0x722, 1);
            });
        ok &= rejects(std::move(fixture),
            "AppleSpacemanInternalPoolFreeListInvalid",
            "cyclic bitmap free list rejected");
    }
    {
        auto fixture = BuildDirectCibFixture();
        MutateChecksummedBlock(fixture.image, kSpacemanBlock,
            [](std::vector<std::byte>& spaceman) {
                PutU64LE(spaceman, 0xC8, kQueuedIpBlockCount + 1);
            });
        ok &= rejects(std::move(fixture),
            "AppleSpacemanFreeQueueCountMismatch",
            "free-queue descriptor count mismatch rejected");
    }
    {
        auto fixture = BuildDirectCibFixture();
        MutateChecksummedBlock(fixture.image, kFreeQueueBlock,
            [](std::vector<std::byte>& queue) {
                PutU32LE(queue, queue.size() - 40, 0x0000000Bu);
            });
        ok &= rejects(std::move(fixture),
            "AppleSpacemanFreeQueueTreeInfoInvalid",
            "free-queue tree-info without ghost support rejected");
    }
    {
        auto fixture = BuildDirectCibFixture();
        MutateChecksummedBlock(fixture.image, kFreeQueueBlock,
            [](std::vector<std::byte>& queue) {
                PutU32LE(queue, queue.size() - 40, 0x0000000Cu);
            });
        ok &= rejects(std::move(fixture),
            "AppleSpacemanFreeQueueTreeInfoInvalid",
            "free-queue tree-info without sequential insertion rejected");
    }
    return ok;
}

bool TestPlansMainAllocationAndAllocatorMetadataCow()
{
    const auto fixture = BuildDirectCibFixture();
    VectorRandomAccessSource source(fixture.image);
    AppleSpacemanView view;
    std::string error;
    bool ok = true;
    ok &= Require(LoadAppleSpacemanOwnershipView(
            source, fixture.checkpoint, view, error),
        "allocation source loads: " + error);
    if (!ok)
    {
        return false;
    }

    const auto original_spaceman = view.bytes;
    const auto original_cib_block = view.devices[0].cibs[0].object.physical_block;
    apfsaccess::rw::AppleSpacemanAllocationRequest request;
    request.expected_checkpoint_xid = kCheckpointXid;
    request.transaction_xid = kCheckpointXid + 1;
    request.main_block_count = 3;
    request.first_ephemeral_object_id = 5000;
    request.released_blocks.push_back({40, 2});
    apfsaccess::rw::AppleSpacemanAllocationPlan plan;
    ok &= Require(apfsaccess::rw::PlanAppleSpacemanAllocation(
            view, request, plan, error),
        "main allocation plan succeeds: " + error);
    if (!ok)
    {
        return false;
    }
    ok &= Require(plan.allocated_main_blocks ==
            std::vector<std::uint64_t>{5, 6, 7},
        "main allocation chooses verified clear bits deterministically");
    ok &= Require(plan.allocated_internal_pool_blocks ==
            std::vector<std::uint64_t>{103, 106},
        "only physical bitmap and CIB COWs consume internal-pool blocks");
    ok &= Require(plan.updated_spaceman.chunks[0].free_count ==
            view.chunks[0].free_count - 3 &&
            plan.updated_spaceman.devices[0].free_count ==
                view.devices[0].free_count - 3 &&
            plan.updated_spaceman.chunks[0].bitmap_block == 103 &&
            plan.updated_spaceman.devices[0].cibs[0].object.physical_block == 106 &&
            plan.updated_spaceman.free_queues[0].root.physical_block == 0 &&
            plan.updated_spaceman.free_queues[0].block_count == 2 &&
            plan.updated_spaceman.free_queues[1].root.physical_block == 0 &&
            plan.updated_spaceman.free_queues[1].block_count == 2,
        "CIB, chunk, and device accounting updated: chunk-free=" +
            std::to_string(plan.updated_spaceman.chunks[0].free_count) +
            ", device-free=" +
            std::to_string(plan.updated_spaceman.devices[0].free_count) +
            ", bitmap=" +
            std::to_string(plan.updated_spaceman.chunks[0].bitmap_block) +
            ", cib=" + std::to_string(
                plan.updated_spaceman.devices[0].cibs[0].object.physical_block) +
            ", ip-root=" + std::to_string(
                plan.updated_spaceman.free_queues[0].root.physical_block) +
            ", ip-count=" +
            std::to_string(plan.updated_spaceman.free_queues[0].block_count) +
            ", main-root=" + std::to_string(
                plan.updated_spaceman.free_queues[1].root.physical_block) +
            ", main-count=" +
            std::to_string(plan.updated_spaceman.free_queues[1].block_count));
    ok &= Require(plan.deferred_frees.size() == 3 &&
            plan.deferred_frees[0].physical_block == kChunkZeroBitmapBlock &&
            plan.deferred_frees[1].physical_block == kCibBlock &&
            plan.deferred_frees[2].physical_block == 40 &&
            plan.deferred_frees[2].block_count == 2 &&
            plan.deferred_frees[0].queue_index == 0 &&
            plan.deferred_frees[1].queue_index == 0 &&
            plan.deferred_frees[2].queue_index == 1,
        "only retired physical metadata and payload blocks enter free queues");
    ok &= Require(plan.writes.size() == 5 &&
            plan.writes[0].physical_block == 103 &&
            plan.writes[1].physical_block == 106 &&
            plan.writes[2].physical_block == 0 &&
            plan.writes[2].kind ==
                apfsaccess::rw::AppleSpacemanWriteKind::FreeQueueTree &&
            plan.writes[3].physical_block == 0 &&
            plan.writes[3].kind ==
                apfsaccess::rw::AppleSpacemanWriteKind::FreeQueueTree &&
            plan.writes[4].physical_block == 65,
        "physical COW objects and unplaced checkpoint-ephemeral queues are staged");
    ok &= Require(plan.updated_spaceman.internal_pool.active_bitmaps[0].rotation_index == 1 &&
            plan.updated_spaceman.internal_pool.bitmap_free_head == 2 &&
            plan.updated_spaceman.internal_pool.bitmap_free_tail == 0,
        "internal bitmap rotation queue updated");
    ok &= Require(view.bytes == original_spaceman &&
            view.devices[0].cibs[0].object.physical_block == original_cib_block,
        "allocation planning leaves the authoritative input immutable");

    auto published_image = fixture.image;
    PutBlock(published_image, kSpacemanBlock,
        plan.updated_spaceman.bytes);
    for (const auto& write : plan.writes)
    {
        if (write.physical_block != 0)
        {
            PutBlock(published_image, write.physical_block, write.bytes);
        }
    }
    auto published_checkpoint = fixture.checkpoint;
    published_checkpoint.superblock.xid = request.transaction_xid;
    const auto materialized = MaterializeEphemeralQueueWrites(
        published_image, published_checkpoint, plan, 82);
    VectorRandomAccessSource published_source(std::move(published_image));
    AppleSpacemanView reloaded;
    ok &= Require(LoadAppleSpacemanOwnershipView(
            published_source, published_checkpoint, reloaded, error),
        "independent parser accepts the complete staged allocator graph: " + error);
    ok &= Require(SameReloadedAllocatorState(
            reloaded, materialized),
        "independent parser reproduces the planned allocator state exactly");
    return ok;
}

bool TestPartitionsFreeQueuesAtRetentionFloorAndReleasesThemLater()
{
    const auto fixture = BuildDirectCibFixture();
    VectorRandomAccessSource source(fixture.image);
    AppleSpacemanView view;
    std::string error;
    bool ok = Require(LoadAppleSpacemanOwnershipView(
            source, fixture.checkpoint, view, error),
        "free-queue reclaim source loads: " + error);
    if (!ok)
    {
        return false;
    }

    SetBit(view.chunks[0].allocation_bitmap, 5);
    SetBit(view.chunks[0].allocation_bitmap, 6);
    view.chunks[0].free_count -= 2;
    view.devices[0].free_count -= 2;
    view.free_queues[1].entries = {
        {kCheckpointXid - 1, 5, 1},
        {kCheckpointXid, 6, 1},
    };
    view.free_queues[1].block_count = 2;
    view.free_queues[1].oldest_xid = kCheckpointXid - 1;

    apfsaccess::rw::AppleSpacemanAllocationRequest request;
    request.expected_checkpoint_xid = kCheckpointXid;
    request.transaction_xid = kCheckpointXid + 1;
    request.oldest_required_checkpoint_xid = kCheckpointXid - 1;
    request.main_block_count = 1;
    request.first_ephemeral_object_id = 5000;
    apfsaccess::rw::AppleSpacemanAllocationPlan plan;
    ok &= Require(apfsaccess::rw::PlanAppleSpacemanAllocation(
            view, request, plan, error),
        "retention-aware free queues plan: " + error);
    if (!ok)
    {
        return false;
    }
    ok &= Require(plan.allocated_main_blocks ==
            std::vector<std::uint64_t>{5},
        "entry at the retention floor is immediately reusable");
    ok &= Require(plan.effective_oldest_required_checkpoint_xid ==
                kCheckpointXid - 1 &&
            plan.effective_protected_internal_pool_bitmap_indices ==
                std::vector<std::uint16_t>{0},
        "plan records the effective floor and original active bitmap slot");
    ok &= Require(plan.allocated_internal_pool_blocks.size() >= 2 &&
            plan.allocated_internal_pool_blocks[0] == 103 &&
            plan.allocated_internal_pool_blocks[1] == kQueuedIpBlock,
        "mature internal-pool queue blocks are reusable for allocator COW");
    ok &= Require(SameQueueEntries(plan.updated_spaceman.free_queues[1].entries,
                std::vector<AppleSpacemanFreeQueueEntry>{
                    {kCheckpointXid, 6, 1}}) &&
            plan.updated_spaceman.free_queues[1].block_count == 1 &&
            plan.updated_spaceman.free_queues[1].oldest_xid == kCheckpointXid,
        "newer queue entry retains its original XID, range, count, and oldest XID");

    apfsaccess::rw::AppleSpacemanAllocationRequest released_request;
    released_request.expected_checkpoint_xid = request.transaction_xid;
    released_request.transaction_xid = request.transaction_xid + 1;
    released_request.oldest_required_checkpoint_xid = kCheckpointXid;
    released_request.main_block_count = 1;
    released_request.first_ephemeral_object_id = 6000;
    apfsaccess::rw::AppleSpacemanAllocationPlan released_plan;
    error.clear();
    ok &= Require(apfsaccess::rw::PlanAppleSpacemanAllocation(
            plan.updated_spaceman, released_request, released_plan, error),
        "advanced retention floor plan succeeds: " + error);
    ok &= Require(released_plan.allocated_main_blocks ==
                std::vector<std::uint64_t>{6} &&
            released_plan.updated_spaceman.free_queues[1].entries.empty() &&
            released_plan.updated_spaceman.free_queues[1].block_count == 0 &&
            released_plan.updated_spaceman.free_queues[1].oldest_xid == 0,
        "advancing the floor releases the previously retained range");
    return ok;
}

bool TestInternalOnlyReclamationAndHistoricalPrefix()
{
    auto fixture = BuildDirectCibFixture();
    VectorRandomAccessSource source(fixture.image);
    AppleSpacemanView view;
    std::string error;
    bool ok = Require(LoadAppleSpacemanOwnershipView(source, fixture.checkpoint, view, error), error);
    if (!ok) return false;
    SetBit(view.chunks[0].allocation_bitmap, 5);
    --view.chunks[0].free_count; --view.devices[0].free_count;
    view.free_queues[1].entries = {{kCheckpointXid - 1, 5, 1}};
    view.free_queues[1].block_count = 1; view.free_queues[1].oldest_xid = kCheckpointXid - 1;
    apfsaccess::rw::AppleSpacemanAllocationRequest request;
    request.expected_checkpoint_xid = kCheckpointXid; request.transaction_xid = kCheckpointXid + 1;
    request.first_ephemeral_object_id = 5000; request.main_block_count = 1;
    request.reclaim_internal_pool_only = true;
    apfsaccess::rw::AppleSpacemanAllocationPlan plan;
    ok &= Require(apfsaccess::rw::PlanAppleSpacemanAllocation(view, request, plan, error), error);
    ok &= Require(plan.allocated_main_blocks == std::vector<std::uint64_t>{6} &&
        SameQueueEntries(plan.updated_spaceman.free_queues[1].entries, view.free_queues[1].entries) &&
        plan.updated_spaceman.free_queues[1].block_count == 1 &&
        plan.updated_spaceman.free_queues[1].oldest_xid == kCheckpointXid - 1,
        "internal-only reclamation must preserve every main-pool queue field");
    ok &= Require(std::find(plan.allocated_internal_pool_blocks.begin(), plan.allocated_internal_pool_blocks.end(),
        kQueuedIpBlock) != plan.allocated_internal_pool_blocks.end(), "mature internal block remains usable");
    MutateChecksummedBlock(fixture.image, kCibBlock, [](auto& bytes) { PutU64LE(bytes, 16, kCheckpointXid + 1); });
    VectorRandomAccessSource future(fixture.image);
    AppleSpacemanInternalPoolView pins;
    ok &= Require(!LoadAppleSpacemanOwnershipView(future, fixture.checkpoint, view, error) &&
        error == "AppleSpacemanCibFutureXid" && view.bytes.empty(), "future CIB never becomes allocator state");
    ok &= Require(LoadAppleSpacemanRetentionBitmaps(future, fixture.checkpoint, pins, error) &&
        pins.active_bitmaps.size() == 1 && pins.active_bitmaps.front().rotation_index == 0,
        "validated historical prefix supplies rotation pins only");
    MutateChecksummedBlock(fixture.image, kSpacemanBlock, [](auto& bytes) { PutU32LE(bytes, 0x144, 0xFFFFFFF0u); });
    VectorRandomAccessSource incomplete(fixture.image);
    ok &= Require(!LoadAppleSpacemanRetentionBitmaps(incomplete, fixture.checkpoint, pins, error) &&
        pins.active_bitmaps.empty(), "invalid prefix returns no partial pins");
    return ok;
}

bool TestRetentionFloorUsesXidBoundaryAcrossGaps()
{
    const auto fixture = BuildDirectCibFixture();
    VectorRandomAccessSource source(fixture.image);
    AppleSpacemanView view;
    std::string error;
    bool ok = Require(LoadAppleSpacemanOwnershipView(
            source, fixture.checkpoint, view, error),
        "XID-gap retention source loads: " + error);
    if (!ok)
    {
        return false;
    }

    view.object.xid = 100;
    SetBit(view.chunks[0].allocation_bitmap, 5);
    SetBit(view.chunks[0].allocation_bitmap, 6);
    view.chunks[0].free_count -= 2;
    view.devices[0].free_count -= 2;
    view.free_queues[1].entries = {{80, 5, 1}, {90, 6, 1}};
    view.free_queues[1].block_count = 2;
    view.free_queues[1].oldest_xid = 80;

    apfsaccess::rw::AppleSpacemanAllocationRequest request;
    request.expected_checkpoint_xid = 100;
    request.transaction_xid = 101;
    request.oldest_required_checkpoint_xid = 80;
    request.main_block_count = 1;
    request.first_ephemeral_object_id = 5000;
    apfsaccess::rw::AppleSpacemanAllocationPlan plan;
    ok &= Require(apfsaccess::rw::PlanAppleSpacemanAllocation(
            view, request, plan, error),
        "XID-gap retention plan succeeds: " + error);
    ok &= Require(plan.allocated_main_blocks ==
                std::vector<std::uint64_t>{5} &&
            SameQueueEntries(plan.updated_spaceman.free_queues[1].entries,
                std::vector<AppleSpacemanFreeQueueEntry>{{90, 6, 1}}) &&
            plan.updated_spaceman.free_queues[1].block_count == 1 &&
            plan.updated_spaceman.free_queues[1].oldest_xid == 90,
        "retention follows the explicit XID frontier rather than generation distance");
    return ok;
}

bool TestProtectedBitmapHeadIsSkippedAndRemainsSerialized()
{
    const auto fixture = BuildDirectCibFixture();
    VectorRandomAccessSource source(fixture.image);
    AppleSpacemanView view;
    std::string error;
    bool ok = Require(LoadAppleSpacemanOwnershipView(
            source, fixture.checkpoint, view, error),
        "protected bitmap rotation source loads: " + error);
    if (!ok)
    {
        return false;
    }

    apfsaccess::rw::AppleSpacemanAllocationRequest request;
    request.expected_checkpoint_xid = kCheckpointXid;
    request.transaction_xid = kCheckpointXid + 1;
    request.first_ephemeral_object_id = 5000;
    request.protected_internal_pool_bitmap_indices = {1, 1};
    apfsaccess::rw::AppleSpacemanAllocationPlan plan;
    ok &= Require(apfsaccess::rw::PlanAppleSpacemanAllocation(
            view, request, plan, error),
        "protected bitmap head plan succeeds: " + error);
    if (!ok)
    {
        return false;
    }
    ok &= Require(plan.effective_oldest_required_checkpoint_xid ==
                kCheckpointXid &&
            plan.effective_protected_internal_pool_bitmap_indices ==
                std::vector<std::uint16_t>{0, 1},
        "default floor and deduplicated bitmap protection are recorded");
    ok &= Require(plan.updated_spaceman.internal_pool.active_bitmaps[0]
                    .rotation_index == 2 &&
            plan.updated_spaceman.internal_pool.bitmap_free_head == 1 &&
            plan.updated_spaceman.internal_pool.bitmap_free_tail == 0 &&
            plan.updated_spaceman.internal_pool.bitmap_free_next[1] == 3 &&
            plan.updated_spaceman.internal_pool.bitmap_free_next[15] == 0,
        "rotation skips the protected head without unlinking it");

    auto published_image = fixture.image;
    PutBlock(published_image, kSpacemanBlock,
        plan.updated_spaceman.bytes);
    for (const auto& write : plan.writes)
    {
        if (write.physical_block != 0)
        {
            PutBlock(published_image, write.physical_block, write.bytes);
        }
    }
    auto published_checkpoint = fixture.checkpoint;
    published_checkpoint.superblock.xid = request.transaction_xid;
    const auto materialized = MaterializeEphemeralQueueWrites(
        published_image, published_checkpoint, plan, 82);
    VectorRandomAccessSource published_source(std::move(published_image));
    AppleSpacemanView reloaded;
    ok &= Require(LoadAppleSpacemanOwnershipView(
            published_source, published_checkpoint, reloaded, error),
        "protected bitmap free list reloads: " + error);
    ok &= Require(SameReloadedAllocatorState(reloaded, materialized),
        "reloaded allocator preserves the skipped protected free-list slot");
    return ok;
}

bool TestBitmapRetentionExhaustionIsAtomic()
{
    const auto fixture = BuildDirectCibFixture();
    VectorRandomAccessSource source(fixture.image);
    AppleSpacemanView view;
    std::string error;
    bool ok = Require(LoadAppleSpacemanOwnershipView(
            source, fixture.checkpoint, view, error),
        "bitmap retention exhaustion source loads: " + error);
    if (!ok)
    {
        return false;
    }

    apfsaccess::rw::AppleSpacemanAllocationRequest request;
    request.expected_checkpoint_xid = kCheckpointXid;
    request.transaction_xid = kCheckpointXid + 1;
    request.first_ephemeral_object_id = 5000;
    for (std::uint16_t index = 1; index < 16; ++index)
    {
        request.protected_internal_pool_bitmap_indices.push_back(index);
    }
    apfsaccess::rw::AppleSpacemanAllocationPlan plan;
    ok &= Require(!apfsaccess::rw::PlanAppleSpacemanAllocation(
            view, request, plan, error) &&
            error == "AppleSpacemanBitmapRetentionExhausted" &&
            plan.writes.empty() && plan.allocated_main_blocks.empty() &&
            plan.allocated_internal_pool_blocks.empty(),
        "protecting every inactive rotation slot fails atomically: " + error);
    return ok;
}

bool TestMultipleActiveBitmapsCannotReuseOriginalSlotDuringPlan()
{
    const auto fixture = BuildDirectCibFixture();
    VectorRandomAccessSource source(fixture.image);
    AppleSpacemanView view;
    std::string error;
    bool ok = Require(LoadAppleSpacemanOwnershipView(
            source, fixture.checkpoint, view, error),
        "multi-active bitmap source loads: " + error);
    if (!ok)
    {
        return false;
    }

    auto& pool = view.internal_pool;
    // Planner-only two-bitmap state; serialized ownership reload is covered above.
    pool.block_count = 32769;
    pool.bitmap_size_blocks = 2;
    pool.bitmap_block_count = 32;
    pool.bitmap_index_offset = 0x710;
    pool.bitmap_free_next.assign(32, 0xFFFF);
    for (std::uint16_t index = 2; index < 31; ++index)
        pool.bitmap_free_next[index] = index + 1;
    pool.bitmap_free_head = 2;
    pool.bitmap_free_tail = 31;
    PutU64LE(view.bytes, 0x98, pool.block_count);
    PutU32LE(view.bytes, 0xA0, pool.bitmap_size_blocks);
    PutU32LE(view.bytes, 0xA4, pool.bitmap_block_count);
    PutU32LE(view.bytes, 0x148, pool.bitmap_index_offset);
    AppleSpacemanInternalPoolBitmapView second_bitmap;
    second_bitmap.xid = kCheckpointXid;
    second_bitmap.physical_block = kIpBitmapBase + 1;
    second_bitmap.rotation_index = 1;
    second_bitmap.bytes.assign(kBlockSize, std::byte{0});
    SetBit(second_bitmap.bytes, 0);
    pool.active_bitmaps.push_back(std::move(second_bitmap));
    view.free_queues[0].entries.push_back(
        {kCheckpointXid - 1, kIpBase + 32768, 1});
    ++view.free_queues[0].block_count;

    apfsaccess::rw::AppleSpacemanAllocationRequest request;
    request.expected_checkpoint_xid = kCheckpointXid;
    request.transaction_xid = kCheckpointXid + 1;
    request.first_ephemeral_object_id = 5000;
    for (std::uint16_t index = 3; index < 32; ++index)
        request.protected_internal_pool_bitmap_indices.push_back(index);
    apfsaccess::rw::AppleSpacemanAllocationPlan plan;
    const bool planned = apfsaccess::rw::PlanAppleSpacemanAllocation(
        view, request, plan, error);
    ok &= Require(!planned &&
            error == "AppleSpacemanBitmapRetentionExhausted" &&
            plan.writes.empty() && plan.allocated_main_blocks.empty() &&
            plan.allocated_internal_pool_blocks.empty(),
        "second rotation cannot reuse a slot active in the original view: " + error);
    request.protected_internal_pool_bitmap_indices.erase(
        request.protected_internal_pool_bitmap_indices.begin());
    ok &= Require(apfsaccess::rw::PlanAppleSpacemanAllocation(view, request, plan, error) &&
            plan.updated_spaceman.internal_pool.active_bitmaps.size() == 2 &&
            plan.updated_spaceman.internal_pool.active_bitmaps[0].rotation_index == 2 &&
            plan.updated_spaceman.internal_pool.active_bitmaps[1].rotation_index == 3,
        "two available non-original slots permit both bitmap rotations: " + error);
    return ok;
}

bool TestDetectsConcurrentOwnershipDriftBeforeWrite()
{
    BuilderStore spec;
    spec.authoritative_checkpoint = true;
    spec.xid = 33;
    spec.block_count = 128;
    auto image = BuildStoreImage(spec);
    VectorRandomAccessSource source(image);
    std::string error;
    const auto checkpoint = LoadContainerCheckpointView(
        source, 0, source.SizeBytes(), error);
    bool ok = Require(checkpoint.has_value(),
        "authoritative drift fixture selects checkpoint: " + error);
    AppleSpacemanView view;
    if (checkpoint.has_value())
    {
        ok &= Require(LoadAppleSpacemanOwnershipView(
                source, checkpoint.value(), view, error),
            "authoritative drift fixture loads ownership: " + error);
    }
    if (!ok)
    {
        return false;
    }

    ok &= Require(apfsaccess::rw::VerifyAppleSpacemanOwnershipUnchanged(
            source, 0, source.SizeBytes(), checkpoint.value(), view, error),
        "unchanged allocator snapshot revalidates: " + error);

    const auto bitmap_block =
        view.internal_pool.active_bitmaps[0].physical_block;
    const auto bitmap_offset = static_cast<std::size_t>(bitmap_block * kBlockSize);
    image[bitmap_offset] &= static_cast<std::byte>(~1u);
    VectorRandomAccessSource changed_source(std::move(image));
    error.clear();
    ok &= Require(!apfsaccess::rw::VerifyAppleSpacemanOwnershipUnchanged(
            changed_source, 0, changed_source.SizeBytes(), checkpoint.value(),
            view, error) && error == "AppleSpacemanConcurrentDrift",
        "same-XID allocator mutation is rejected before publication: " + error);
    return ok;
}

bool TestPlansMultiNodeFreeQueueWithExplicitMappings()
{
    const auto fixture = BuildDirectCibFixture();
    VectorRandomAccessSource source(fixture.image);
    AppleSpacemanView view;
    std::string error;
    bool ok = Require(LoadAppleSpacemanOwnershipView(
            source, fixture.checkpoint, view, error),
        "multi-node queue source loads: " + error);
    if (!ok)
    {
        return false;
    }

    view.devices[0].block_count = 1024;
    view.devices[0].free_count += 1024 - kBlockCount;
    for (std::uint64_t start = kBlockCount; start < 1024; start += 64)
    {
        AppleSpacemanChunkView chunk;
        chunk.xid = kCheckpointXid;
        chunk.start_block = start;
        chunk.block_count = 64;
        chunk.free_count = 64;
        chunk.allocation_bitmap.assign(kBlockSize, std::byte{0});
        view.chunks.push_back(std::move(chunk));
    }

    apfsaccess::rw::AppleSpacemanAllocationRequest request;
    request.expected_checkpoint_xid = kCheckpointXid;
    request.transaction_xid = kCheckpointXid + 1;
    request.first_ephemeral_object_id = 5000;
    for (std::uint64_t index = 0; index < 201; ++index)
    {
        const std::uint64_t block = 200 + index * 2;
        const auto chunk = std::find_if(view.chunks.begin(), view.chunks.end(),
            [block](const auto& candidate) {
                return block >= candidate.start_block &&
                    block - candidate.start_block < candidate.block_count;
            });
        if (chunk == view.chunks.end())
        {
            return Require(false, "expanded release block has a chunk owner");
        }
        SetBit(chunk->allocation_bitmap, block - chunk->start_block);
        --chunk->free_count;
        --view.devices[0].free_count;
        request.released_blocks.push_back({block, 1});
    }
    apfsaccess::rw::AppleSpacemanAllocationPlan plan;
    ok &= Require(apfsaccess::rw::PlanAppleSpacemanAllocation(
            view, request, plan, error),
        "multi-node queue plan succeeds: " + error);
    if (!ok)
    {
        return false;
    }
    const auto& planned_queue = plan.updated_spaceman.free_queues[1];
    ok &= Require(planned_queue.tree_blocks.empty() &&
            planned_queue.root.physical_block == 0 &&
            planned_queue.entries.size() == 201,
        "main free queue emits an unplaced multi-node tree without losing records");

    auto queue_image = fixture.image;
    auto queue_checkpoint = fixture.checkpoint;
    const auto materialized = MaterializeEphemeralQueueWrites(
        queue_image, queue_checkpoint, plan, 82);
    const auto& updated_queue = materialized.free_queues[1];
    std::size_t queue_write_count = 0;
    for (const auto& write : plan.writes)
    {
        if (write.kind != apfsaccess::rw::AppleSpacemanWriteKind::FreeQueueTree)
        {
            ok &= Require(!write.object_location.has_value(),
                "raw allocator writes do not invent APFS object identity");
            continue;
        }
        ok &= Require(write.object_location.has_value(),
            "every free-queue node exposes its exact checkpoint identity");
        if (!write.object_location.has_value())
        {
            continue;
        }
        ++queue_write_count;
        const auto& location = write.object_location.value();
        ok &= Require(write.physical_block == 0 &&
                location.physical_block == 0,
            "checkpoint-ephemeral queue nodes remain unplaced by spaceman");
    }
    ok &= Require(queue_write_count ==
            materialized.free_queues[0].tree_blocks.size() +
            updated_queue.tree_blocks.size(),
        "write plan exposes one identity for every rebuilt queue node");

    VectorRandomAccessSource queue_source(std::move(queue_image));
    BtreeReadPolicy policy;
    policy.enforce_object_identity = true;
    policy.root_object_id = kMainFreeQueueOid;
    policy.storage_type = kObjectEphemeral;
    policy.subtype = kObjectTypeSpacemanFreeQueue;
    policy.include_ghost_records = true;
    policy.ephemeral_checkpoint = &queue_checkpoint;
    std::vector<std::uint64_t> visited;
    policy.visited_physical_blocks = &visited;
    std::vector<BtreeRecord> records;
    ok &= Require(ReadBtreeLeafRecords(queue_source, kBlockSize,
            updated_queue.root.physical_block, false, 0,
            request.transaction_xid, policy, records, error),
        "independent reader follows planned multi-node queue mappings: " + error);
    ok &= Require(records.size() == updated_queue.entries.size() &&
            visited.size() == updated_queue.tree_blocks.size(),
        "independent reader recovers every planned queue record and node");
    return ok;
}

bool TestAllocationFailsClosedWithoutSpaceOrFreshIdentity()
{
    const auto fixture = BuildDirectCibFixture();
    VectorRandomAccessSource source(fixture.image);
    AppleSpacemanView view;
    std::string error;
    bool ok = true;
    ok &= Require(LoadAppleSpacemanOwnershipView(
            source, fixture.checkpoint, view, error),
        "failure source loads: " + error);
    if (!ok)
    {
        return false;
    }

    apfsaccess::rw::AppleSpacemanAllocationRequest request;
    request.expected_checkpoint_xid = kCheckpointXid - 1;
    request.transaction_xid = kCheckpointXid + 1;
    request.main_block_count = 1;
    apfsaccess::rw::AppleSpacemanAllocationPlan plan;
    ok &= Require(!apfsaccess::rw::PlanAppleSpacemanAllocation(
            view, request, plan, error) &&
            error == "AppleSpacemanCheckpointDrift" && plan.writes.empty(),
        "stale checkpoint identity fails before planning: " + error);

    request.expected_checkpoint_xid = kCheckpointXid;
    request.oldest_required_checkpoint_xid = kCheckpointXid + 1;
    error.clear();
    ok &= Require(!apfsaccess::rw::PlanAppleSpacemanAllocation(
            view, request, plan, error) &&
            error == "AppleSpacemanRetentionFloorInvalid" &&
            plan.writes.empty(),
        "retention floor newer than the current checkpoint fails atomically: " +
            error);

    request.oldest_required_checkpoint_xid = 0;
    request.protected_internal_pool_bitmap_indices = {16};
    error.clear();
    ok &= Require(!apfsaccess::rw::PlanAppleSpacemanAllocation(
            view, request, plan, error) &&
            error == "AppleSpacemanProtectedBitmapIndexInvalid" &&
            plan.writes.empty(),
        "out-of-range protected bitmap slot fails atomically: " + error);

    request.protected_internal_pool_bitmap_indices.clear();
    request.main_block_count = static_cast<std::size_t>(
        view.devices[0].free_count + 1);
    error.clear();
    ok &= Require(!apfsaccess::rw::PlanAppleSpacemanAllocation(
            view, request, plan, error) &&
            error == "AppleSpacemanMainPoolExhausted" && plan.writes.empty(),
        "main-pool exhaustion fails atomically: " + error);

    auto ip_full = view;
    std::fill(ip_full.internal_pool.active_bitmaps[0].bytes.begin(),
        ip_full.internal_pool.active_bitmaps[0].bytes.end(), std::byte{0xFF});
    ip_full.free_queues[0].entries.clear();
    ip_full.free_queues[0].block_count = 0;
    ip_full.free_queues[0].oldest_xid = 0;
    request.main_block_count = 1;
    error.clear();
    ok &= Require(!apfsaccess::rw::PlanAppleSpacemanAllocation(
            ip_full, request, plan, error) &&
            error == "AppleSpacemanInternalPoolExhausted" && plan.writes.empty(),
        "internal-pool exhaustion fails atomically: " + error);

    request.oldest_required_checkpoint_xid = kCheckpointXid - 1;
    ok &= Require(!apfsaccess::rw::PlanAppleSpacemanAllocation(ip_full, request, plan, error) &&
            error == "AppleSpacemanInternalPoolExhausted" && plan.writes.empty(),
        "an old pin does not relabel genuine internal-pool exhaustion as retention pressure");
    auto retained_pool = ip_full;
    retained_pool.free_queues[0].entries = {{kCheckpointXid, kQueuedIpBlock, kQueuedIpBlockCount}};
    retained_pool.free_queues[0].block_count = kQueuedIpBlockCount;
    retained_pool.free_queues[0].oldest_xid = kCheckpointXid;
    request.first_ephemeral_object_id = 5000;
    const auto retained_bitmap = retained_pool.internal_pool.active_bitmaps[0].bytes;
    ok &= Require(!apfsaccess::rw::PlanAppleSpacemanAllocation(retained_pool, request, plan, error) &&
            error == "AppleSpacemanInternalPoolRetentionExhausted" && plan.writes.empty() &&
            retained_pool.internal_pool.active_bitmaps[0].bytes == retained_bitmap &&
            request.oldest_required_checkpoint_xid == kCheckpointXid - 1,
        "retention diagnosis leaves the source bitmap, required floor and output plan unchanged: " + error);
    request.oldest_required_checkpoint_xid = kCheckpointXid;
    ok &= Require(apfsaccess::rw::PlanAppleSpacemanAllocation(retained_pool, request, plan, error),
        "explicit release of the old checkpoint makes the same internal-pool request feasible: " + error);
    request.oldest_required_checkpoint_xid = 0;

    request.main_block_count = 0;
    request.released_blocks = {{5, 1}};
    error.clear();
    ok &= Require(!apfsaccess::rw::PlanAppleSpacemanAllocation(
            view, request, plan, error) &&
            error == "AppleSpacemanReleaseRangeInvalid" && plan.writes.empty(),
        "releasing an unallocated main block fails atomically: " + error);

    auto stale_queue = view;
    stale_queue.free_queues[0].entries[0].physical_block = 103;
    request.released_blocks.clear();
    error.clear();
    ok &= Require(!apfsaccess::rw::PlanAppleSpacemanAllocation(
            stale_queue, request, plan, error) &&
            error == "AppleSpacemanFreeQueueOwnershipMismatch" &&
            plan.writes.empty(),
        "post-parse free-queue ownership drift fails atomically: " + error);
    return ok;
}

} // namespace

int main()
{
    bool ok = true;
    ok &= TestLoadsVerifiedDirectCibOwnership();
    ok &= TestLoadsVerifiedCabOwnership();
    ok &= TestPlansCabHierarchyCow();
    ok &= TestRejectsMalformedOwnershipState();
    ok &= TestPlansMainAllocationAndAllocatorMetadataCow();
    ok &= TestPartitionsFreeQueuesAtRetentionFloorAndReleasesThemLater();
    ok &= TestRetentionFloorUsesXidBoundaryAcrossGaps();
    ok &= TestInternalOnlyReclamationAndHistoricalPrefix();
    ok &= TestProtectedBitmapHeadIsSkippedAndRemainsSerialized();
    ok &= TestBitmapRetentionExhaustionIsAtomic();
    ok &= TestMultipleActiveBitmapsCannotReuseOriginalSlotDuringPlan();
    ok &= TestAllocationFailsClosedWithoutSpaceOrFreshIdentity();
    ok &= TestDetectsConcurrentOwnershipDriftBeforeWrite();
    ok &= TestPlansMultiNodeFreeQueueWithExplicitMappings();
    if (ok && g_failures == 0)
    {
        std::cout << "APFS APPLE SPACEMAN ALLOCATOR PASS" << std::endl;
        return 0;
    }
    std::cerr << "APFS APPLE SPACEMAN ALLOCATOR FAIL: "
              << g_failures << " check(s)" << std::endl;
    return 1;
}
