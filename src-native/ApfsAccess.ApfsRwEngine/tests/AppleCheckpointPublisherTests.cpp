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

PublisherFixture BuildWrappedPublisherFixture()
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
    anchor.xp_desc_blocks = 8;
    anchor.xp_data_base_blocks = kDataBase;
    anchor.xp_data_blocks = 8;
    anchor.spaceman_oid = kSpacemanOid;
    PutBlock(fixture.image, 0, BuildNxsb(anchor, 39, "", kBlockSize));

    BuilderStore selected = anchor;
    selected.xid = 40;
    selected.xp_desc_index = 5;
    selected.xp_desc_len = 2;
    selected.xp_desc_next = 7;
    selected.xp_data_index = 4;
    selected.xp_data_len = 3;
    selected.xp_data_next = 7;
    CheckpointMappingSpec spaceman;
    spaceman.type = kObjectEphemeral | kObjectTypeSpaceman;
    spaceman.size = kBlockSize * 2;
    spaceman.object_id = kSpacemanOid;
    spaceman.physical_block = kDataBase + 4;
    CheckpointMappingSpec queue;
    queue.type = kObjectEphemeral | kObjectTypeBtree;
    queue.subtype = kObjectTypeSpacemanFreeQueue;
    queue.object_id = kQueueOid;
    queue.physical_block = kDataBase + 6;
    PutBlock(fixture.image, kDescriptorBase + 5,
        BuildCheckpointMap(40, {spaceman, queue}, kBlockSize,
            kDescriptorBase + 5));
    PutBlock(fixture.image, kDescriptorBase + 6,
        BuildNxsb(selected, 40, "", kBlockSize));

    auto spaceman_bytes = BuildEphemeralObject(kSpacemanOid, 40,
        spaceman.type, spaceman.subtype, spaceman.size);
    PutBlock(fixture.image, kDataBase + 4, spaceman_bytes, 0);
    PutBlock(fixture.image, kDataBase + 5, spaceman_bytes, kBlockSize);
    auto queue_bytes = BuildEphemeralObject(kQueueOid, 40,
        queue.type, queue.subtype, queue.size);
    PutBlock(fixture.image, kDataBase + 6, queue_bytes);

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
    ok &= Require(std::count_if(removal_plan.allocation.deferred_frees.begin(),
            removal_plan.allocation.deferred_frees.end(),
            [](const auto& released) {
                return (released.physical_block == kOwnedPayloadBlock ||
                           released.physical_block == kOwnedPayloadBlock + 1) &&
                    released.block_count == 1;
            }) == kOwnedPayloadBlockCount,
        "every unshared block is queued once when its refcount reaches zero");
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
    ok &= Require(!PlanAppleVolumeTransaction(source, checkpoint.value(),
            shared_rewrite, shared_plan, error) &&
            error == "AppleVolumeSharedExtentUnsupported",
        "touched shared extent fails closed until clone accounting exists: " +
            error);

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
    ok &= TestPlansAndPublishesWrappedCheckpoint();
    ok &= TestEveryCrashPrefixSelectsOldOrNew();
    ok &= TestPublishesThroughBlockDevice();
    ok &= TestComposesSpacemanAllocationAndCrashSafePublication();
      ok &= TestPublishesReachableFileThroughBothObjectMaps();
      ok &= TestVolumeTransactionMaintainsPhysicalExtentReferences();
      ok &= TestVolumeTransactionRejectsSnapshots();
    ok &= TestRejectsUnsafePlansAndStaleExecution();
    if (ok && g_failures == 0)
    {
        std::cout << "APFS APPLE CHECKPOINT PUBLISHER PASS" << std::endl;
        return 0;
    }
    std::cerr << "APFS APPLE CHECKPOINT PUBLISHER FAIL: "
              << g_failures << " check(s)" << std::endl;
    return 1;
}
