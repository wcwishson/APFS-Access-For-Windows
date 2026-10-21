#include "VolumeResizeCases.h"
#include "../src/VolumeFormatEvidence.h"
#include "ApfsExtendedRecordCodec.h"
using namespace apfsaccess::volume_image_test;
namespace vi = apfsaccess::rw::volume_image;
void Headers(const Bytes& image, bool flagged) {
    const auto cp = Checkpoint(image);
    Check(ReadU32LE(image, 24) == (flagged ? kObjectEphemeral : 0) + 1, "block-zero NXSB storage type");
    Check(ReadU32LE(cp.container.superblock_bytes, 24) == (flagged ? kObjectEphemeral : 0) + 1, "selected NXSB storage type");
    Check(cp.container_object_map.object.type == (kObjectPhysical | 11), "physical container OMAP");
    Check(cp.spaceman.object.type == (kObjectEphemeral | 5), "ephemeral spaceman");
    for (const auto& cib : cp.spaceman.devices[0].cibs) Check(cib.object.type == (kObjectPhysical | 7), "physical CIB");
    for (const auto& v : cp.volumes) {
        Check(v.superblock_object.type == 13, "virtual APSB");
        const auto apsb_offset = v.superblock_object.physical_block * 4096;
        Check(ReadU32LE(image, apsb_offset + 0x7c) == ((flagged ? kObjectPhysical : 0) | 2), "snapshot tree storage type");
        Check(v.snapshot_metadata_tree.has_value(), "snapshot metadata root resolved");
        if (flagged) Check(v.snapshot_metadata_tree->object_id == v.snapshot_metadata_tree->physical_block &&
            ReadU64LE(image, apsb_offset + 0x98) == v.snapshot_metadata_tree->physical_block, "physical snapshot root paddr identity");
    }
}
void AddProbe(const VolumeImageRequest& r, std::uint64_t volume_oid = 0, unsigned multiplier = 29, unsigned increment = 17) {
    auto image = Read(r.image); auto cp = Checkpoint(image); VectorRandomAccessSource source(image); std::string error;
    const auto selected = std::find_if(cp.volumes.begin(), cp.volumes.end(), [&](const auto& v) {
        return !volume_oid || v.superblock.object_id == volume_oid;
    }); Check(selected != cp.volumes.end(), "selected probe volume exists");
    AppleVolumeTransactionRequest request; request.volume_object_id = selected->superblock.object_id;
    Check(ReadAppleVolumeFileSystemRecords(source, cp.container, *selected, request.filesystem_records, error), error);
    AppleInodeRecord inode; inode.object_id = inode.private_id = 1030; inode.parent_id = 2; inode.mode = 0100644;
    inode.children_or_links = 1; inode.uncompressed_size = 8192;
    AppleExtendedField stream{8, 0, Bytes(40)}; PutU64LE(stream.data, 0, 8192); PutU64LE(stream.data, 8, 8192); inode.extended_fields.push_back(stream);
    BtreeRecord record; Check(EncodeAppleInodeRecord(inode, record, error), error); request.filesystem_records.push_back(record);
    Check(EncodeAppleDirectoryRecord({2,1030,0,8,"probe.bin"}, ApfsNamePolicy::FromIncompatibleFeatures(selected->superblock.incompatible_features), record, error), error);
    request.filesystem_records.push_back(record); Check(EncodeAppleDataStreamIdRecord({1030,1}, record, error), error); request.filesystem_records.push_back(record);
    for (auto& item : request.filesystem_records) {
        AppleInodeRecord root;
        if (ApfsExtendedRecordCodec::DecodeInode(item, root, error) && root.object_id == 2) {
            ++root.children_or_links; Check(EncodeAppleInodeRecord(root, item, error), error);
        }
    }
    Bytes payload(8192); for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = std::byte((i * multiplier + increment) & 255);
    request.file_count_delta = 1; request.data_writes.push_back({1030,0,0,payload}); AppleVolumeTransactionPlan plan;
    Check(PlanAppleVolumeTransaction(source, cp, request, plan, error), error);
    for (const auto& w : plan.commit.publication.before_superblock_writes)
        std::copy(w.bytes.begin(), w.bytes.end(), image.begin() + w.physical_block * 4096);
    const auto& nx = plan.commit.publication.superblock_write;
    std::copy(nx.bytes.begin(), nx.bytes.end(), image.begin() + nx.physical_block * 4096);
    const auto after = Checkpoint(image); const auto found = std::find_if(after.volumes.begin(), after.volumes.end(),
        [&](const auto& v) { return v.superblock.object_id == request.volume_object_id; });
    Save(r.image, image); Check(found != after.volumes.end() && found->superblock.file_count == 1, "ordinary canonical probe published");
}
int wmain(int argc, wchar_t** argv) {
    try {
        Check(argc == 3, "mode and private D evidence root required"); root = argv[2]; Check(root.wstring().starts_with(L"D:\\"), "D-only evidence");
        const std::wstring_view mode(argv[1]); auto original = Fixture();
        const bool erase = mode == L"erase"; auto r = Request(root, erase ? VolumeImageOperation::Erase : VolumeImageOperation::Format, original);
        std::filesystem::create_directories(root);
        if (mode == L"setup") { Save(r.image, original); }
        else if (mode == L"cut" || mode == L"erase") {
            Save(r.image, original); const auto p = Prepare(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
            const auto done = Apply(r, p.token, [](auto stage) { return stage != "after-image-anchor"; });
            Check(done.outcome == VolumeImageOutcome::RecoveryRequired, done.error);
        } else if (mode == L"recover" || mode == L"legacy-recover") {
            Check(Recover(r).outcome == VolumeImageOutcome::Committed, "fresh original recovery");
            Headers(Read(r.image), mode != L"legacy-recover");
        } else if (mode == L"read-probe") { AddProbe(r); Headers(Read(r.image), true); }
#ifndef APFS_FORMAT_LEGACY_TEST
        else if (mode == L"plans") {
            VectorRandomAccessSource source(original); const auto cp = Checkpoint(original);
            auto old = vi::BuildFormatPublication(source, r, cp), next = vi::BuildFormatPublicationV2(source, r, cp);
            Check(ReadU32LE(old.anchor, 24) == 1 && ReadU32LE(next.anchor, 24) == (kObjectEphemeral | 1), "explicit legacy/new policy");
            Check(old.publication.before_superblock_writes.size() == next.publication.before_superblock_writes.size(), "same COW destinations");
            unsigned changed = 0;
            for (std::size_t i = 0; i < old.publication.before_superblock_writes.size(); ++i) {
                const auto& a = old.publication.before_superblock_writes[i]; const auto& b = next.publication.before_superblock_writes[i];
                Check(a.physical_block == b.physical_block, "same bootstrap COW destination");
                if (a.bytes != b.bytes) {
                    const auto type = ReadU32LE(b.bytes, 24).value_or(0), subtype = ReadU32LE(b.bytes, 28).value_or(0);
                    Check(type == 13 || (type == (kObjectPhysical | 2) && (subtype == 11 || subtype == 16)), "only snapshot root, its mapping and APSB change");
                    ++changed;
                }
            }
            Check(changed == 3, "exactly three bootstrap objects change beside NXSB");
            vi::FinishPlan(original, r, next); Check(next.after.volumes.size() == 1, "new pure publication proof");
        }
#endif
        else throw std::runtime_error("known mode required");
        std::cout << "PASS checks=" << checks << '\n'; return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL checks=" << checks << ' ' << error.what() << '\n'; return 1; }
}
