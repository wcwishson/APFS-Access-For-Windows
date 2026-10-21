#pragma once
#include <Windows.h>
#undef CreateFile
#include "VolumeRetiredHistoryCases.h"
#include "VolumeManagement.h"
#include "BlockDevice.h"

namespace apfsaccess::volume_image_test
{
inline Bytes CapacityFixture(std::uint32_t slots)
{
    auto image = Fixture();
    for (std::size_t at = 0; at < image.size(); at += 4096) {
        Bytes block(image.begin() + at, image.begin() + at + 4096);
        if (!ParseNxSuperblock(block)) continue;
        const std::array<std::byte, 16> uuid{std::byte{0x90}, std::byte{0xbc}, std::byte{0xe5}, std::byte{0x6e},
            std::byte{0x6c}, std::byte{0x6a}, std::byte{0x49}, std::byte{0xfc}, std::byte{0x88}, std::byte{0x01},
            std::byte{0x2d}, std::byte{0x9d}, std::byte{0x47}, std::byte{0x08}, std::byte{0x04}, std::byte{0xb0}};
        std::copy(uuid.begin(), uuid.end(), block.begin() + 0x48);
        PutU32LE(block, 0xb4, slots); FletcherForBlock(block, 4096);
        std::copy(block.begin(), block.end(), image.begin() + at);
    }
    return image;
}

inline Bytes ReadHeldCapacityImage(BlockDevice& device)
{
    Bytes bytes;
    Check(device.GetGeometry().total_bytes == 4194304 &&
        device.Read(0, 4194304, bytes) && bytes.size() == 4194304, "held exact regular-image bounds");
    return bytes;
}

inline std::string CapacityPayloadHash(const Bytes& image, std::uint64_t volume_oid, const Bytes& expected)
{
    const auto cp = Checkpoint(image); VectorRandomAccessSource source(image); std::string e;
    const auto volume = std::find_if(cp.volumes.begin(), cp.volumes.end(),
        [&](const auto& v) { return v.superblock.object_id == volume_oid; });
    Check(volume != cp.volumes.end(), "exact surviving volume exists");
    std::vector<BtreeRecord> records;
    Check(ReadBtreeLeafRecords(source, 4096, volume->root_tree.physical_block,
        (volume->root_tree.type & kObjectStorageTypeMask) == kObjectPhysical,
        volume->superblock.omap_oid, cp.container.superblock.xid, records, e), e);
    unsigned extents = 0; Bytes payload;
    for (const auto& record : records) {
        AppleFileExtentRecord extent;
        if (!DecodeAppleFileExtentRecord(record, 4096, extent, e)) continue;
        Check(extent.object_id == 1026 && extent.logical_address == 0 && extent.length_bytes == expected.size(),
            "exact surviving nonempty file extent");
        Check(extent.physical_block < image.size() / 4096 &&
            extent.length_bytes <= image.size() - extent.physical_block * 4096, "payload within image bounds");
        payload.assign(image.begin() + extent.physical_block * 4096,
            image.begin() + extent.physical_block * 4096 + extent.length_bytes); ++extents;
    }
    Check(extents == 1 && payload == expected, "original formatted payload bytes match");
    return RetentionHash(payload);
}

inline void FormatThenCreateCapacity(std::uint32_t slots, VolumeImageOperation operation, bool recover)
{
    const auto name = "capacity-" + std::to_string(slots) + "-" + std::to_string(static_cast<unsigned>(operation));
    auto format = Setup(name, operation, CapacityFixture(slots)); format.case_sensitive = slots == 2;
    format.new_container_uuid = "90bce56e6c6a49fc88012d9d470804b1";
    const auto original = Read(format.image); const auto format_prepared = Prepare(format);
    Check(format_prepared.outcome == VolumeImageOutcome::Prepared, "capacity format prepare: " + format_prepared.error);
    Check(Read(format.image) == original, "format preparation preserves source bytes");
    const auto formatted = Apply(format, format_prepared.token);
    Check(formatted.outcome == VolumeImageOutcome::Committed, "capacity real format publication: " + formatted.error);
    Bytes payload(4096);
    for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = std::byte((i * 29 + slots) % 251);
    Bytes before_create; std::string held_identity;
    {
        std::string e; auto device = BlockDevice::OpenExclusiveManagementImage(format.image.wstring(), 0, e);
        Check(device && device->QueryRegularImageIdentity(held_identity), "format held-source reopen: " + e);
        auto image = ReadHeldCapacityImage(*device); const auto cp = Checkpoint(image);
        Check(cp.volumes.size() == 1 && cp.container.superblock.uuid_hex == format.new_container_uuid &&
            cp.volumes.front().superblock.object_id == 1024 && cp.volumes.front().superblock.uuid_hex == format.new_volume_uuid,
            "held formatted exact container, volume UUID and OID");
        VectorRandomAccessSource source(image); const auto& v = cp.volumes.front();
        AppleVolumeTransactionRequest write; write.volume_object_id = 1024; write.file_count_delta = 1;
        Check(ReadBtreeLeafRecords(source, 4096, v.root_tree.physical_block, false, v.superblock.omap_oid,
            cp.container.superblock.xid, write.filesystem_records, e), e);
        AppleInodeRecord root_inode; root_inode.object_id = root_inode.private_id = 2; root_inode.parent_id = 1;
        root_inode.mode = 0040755; root_inode.children_or_links = 2; BtreeRecord root_record;
        Check(EncodeAppleInodeRecord(root_inode, root_record, e), e); unsigned roots = 0;
        for (auto& record : write.filesystem_records) {
            if (record.key != root_record.key) continue;
            Check(ReadU32LE(record.value, 0x38) == 1, "formatted root originally owns private-dir only");
            record = root_record; ++roots;
        }
        Check(roots == 1, "exact formatted root for payload insertion");
        AppleInodeRecord file; file.object_id = file.private_id = 1026; file.parent_id = 2;
        file.mode = 0100644; file.children_or_links = 1; file.uncompressed_size = payload.size();
        AppleExtendedField stream{8, 0, Bytes(40)}; PutU64LE(stream.data, 0, payload.size());
        PutU64LE(stream.data, 8, payload.size()); file.extended_fields.push_back(stream);
        BtreeRecord record; Check(EncodeAppleInodeRecord(file, record, e), e); write.filesystem_records.push_back(record);
        AppleDirectoryRecord entry; entry.parent_id = 2; entry.file_id = 1026; entry.flags = 8; entry.name_utf8 = "survivor.bin";
        Check(EncodeAppleDirectoryRecord(entry, ApfsNamePolicy::FromIncompatibleFeatures(v.superblock.incompatible_features), record, e), e);
        write.filesystem_records.push_back(record);
        Check(EncodeAppleDataStreamIdRecord({1026, 1}, record, e), e); write.filesystem_records.push_back(record);
        write.data_writes.push_back({1026, 0, 0, payload}); AppleVolumeTransactionPlan plan;
        Check(PlanAppleVolumeTransaction(source, cp, write, plan, e), "canonical formatted payload plan: " + e);
        Check(ExecuteAppleCheckpointPublication(*device, plan.commit.publication, e), "real held payload publication: " + e);
        before_create = ReadHeldCapacityImage(*device);
        const auto written = Checkpoint(before_create); rw::volume_image::Verify(before_create, written); ++checks;
        Check(written.container.superblock.xid == cp.container.superblock.next_xid, "canonical payload generation advances once");
    }
    const auto before_hash = CapacityPayloadHash(before_create, 1024, payload);
    const auto cp = Checkpoint(before_create); VolumeManagementRequest create;
    create.operation = VolumeManagementOperation::Create; create.image = format.image; create.journal_directory = format.journal_directory;
    create.container_uuid = format.new_container_uuid; create.volume_uuid = "77ff4455667748899abbccddeeff0066";
    create.volume_oid = cp.container.superblock.next_oid; create.checkpoint_xid = cp.container.superblock.xid;
    create.sibling_wals[1024] = format.new_volume_wal; create.name_utf8 = "Second Data"; create.case_sensitive = format.case_sensitive;
    const auto prepared = PrepareVolumeCreate(create);
    Check(prepared.outcome == VolumeManagementOutcome::Prepared, "real format-then-create prepare: " + prepared.error);
    Check(Read(create.image) == before_create && prepared.source_identity == held_identity, "create preview preserves held source and identity");
    const auto applied = ApplyVolumeManagement(create, prepared.confirmation_token,
        recover ? AppleCheckpointStageHook([](auto stage) { return stage != "before-volume-management-complete"; }) : AppleCheckpointStageHook{});
    if (recover) {
        Check(applied.outcome == VolumeManagementOutcome::RecoveryRequired, "real accepted create interruption: " + applied.error);
        const auto recovered = RecoverVolumeManagement(create);
        Check(recovered.outcome == VolumeManagementOutcome::Committed, "fresh create recovery: " + recovered.error);
    } else Check(applied.outcome == VolumeManagementOutcome::Committed, "real create publication: " + applied.error);
    const auto post = Read(create.image); const auto after = Checkpoint(post); rw::volume_image::Verify(post, after); ++checks;
    Check(after.container.superblock.uuid_hex == format.new_container_uuid && after.container.superblock.xid == prepared.post_xid &&
        after.volumes.size() == 2 && ReadU32LE(after.container.superblock_bytes, 0xb4) == slots,
        "current graph has exact generation, container and original supported capacity");
    Check(ReadU64LE(after.container.superblock_bytes, 0xb8) == 1024 &&
        ReadU64LE(after.container.superblock_bytes, 0xc0) == create.volume_oid, "distinct exact original and new volume slots");
    for (const auto& v : after.volumes) {
        Check((v.superblock.object_id == 1024 && v.superblock.uuid_hex == format.new_volume_uuid && v.superblock.name_utf8 == format.name_utf8) ||
            (v.superblock.object_id == create.volume_oid && v.superblock.uuid_hex == create.volume_uuid && v.superblock.name_utf8 == create.name_utf8),
            "exact UUID, OID and name of both published volumes");
        Check(v.superblock.incompatible_features == (format.case_sensitive ? 0 : kIncompatCaseInsensitive), "exact source format case policy");
    }
    const auto after_hash = CapacityPayloadHash(post, 1024, payload);
    Check(before_hash == after_hash, "original surviving formatted payload SHA256 unchanged");
    Check(RecoverVolumeManagement(create).outcome == VolumeManagementOutcome::Committed && Read(create.image) == post,
        "completed create recovery remains byte-identical");
    std::cout << "CAPACITY slots=" << slots << " formattedXid=" << format_prepared.post_xid << " currentXid=" << prepared.post_xid
        << " survivingOid=1024 newOid=" << create.volume_oid << " before=" << before_hash << " after=" << after_hash << '\n';
    Pass("real format, held reopen, payload commit, second-volume create and recovery");
}

inline void FormatCapacityRefusals()
{
    for (const auto slots : {0u, 1u, 101u, UINT32_MAX}) {
        auto r = Setup("capacity-refusal-" + std::to_string(slots), VolumeImageOperation::Format, CapacityFixture(100));
        r.new_container_uuid = "90bce56e6c6a49fc88012d9d470804b1";
        const auto malformed = CapacityFixture(slots); Save(r.image, malformed);
        const auto result = Prepare(r);
        Check(result.outcome == VolumeImageOutcome::Refused && !result.error.empty(), "malformed/out-of-bounds NX capacity refusal");
        Check(Read(r.image) == malformed, "invalid profile does not mutate image");
        std::cout << "CAPACITY_REFUSED slots=" << slots << " error=" << result.error << '\n';
    }
    auto r = Setup("capacity-invalid-request-bounds", VolumeImageOperation::Format, CapacityFixture(100));
    r.new_container_uuid = "90bce56e6c6a49fc88012d9d470804b1"; const auto original = Read(r.image);
    r.expected_bytes += 4096;
    Check(Prepare(r).outcome == VolumeImageOutcome::Refused && Read(r.image) == original, "exact original byte bounds remain required");
    r = Setup("capacity-encrypted-profile", VolumeImageOperation::Format, CapacityFixture(100));
    r.new_container_uuid = "90bce56e6c6a49fc88012d9d470804b1"; auto encrypted = Read(r.image);
    const auto cp = Checkpoint(encrypted); const auto at = cp.volumes.front().superblock_object.physical_block * 4096;
    Bytes volume(encrypted.begin() + at, encrypted.begin() + at + 4096); PutU64LE(volume, 0x108, 0);
    FletcherForBlock(volume, 4096); std::copy(volume.begin(), volume.end(), encrypted.begin() + at); Save(r.image, encrypted);
    const auto result = Prepare(r);
    Check(result.outcome == VolumeImageOutcome::Refused && Read(r.image) == encrypted, "encrypted authoritative profile remains refused: " + result.error);
    Pass("format capacity preserves bounds and unsupported-profile refusals");
}

inline void FormatCapacity()
{
    FormatThenCreateCapacity(100, VolumeImageOperation::Format, false);
    FormatThenCreateCapacity(2, VolumeImageOperation::Erase, true);
    FormatCapacityRefusals();
}
}
