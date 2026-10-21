#pragma once
#include "VolumeFormat.h"
#include "TestFixtureBuilder.h"
#include <fstream>
#include <stdexcept>
namespace apfsaccess::volume_image_test
{
using namespace catalog; using namespace rw; using namespace testfixture;
using Bytes = std::vector<std::byte>;
inline Bytes Fixture(std::uint64_t free_blocks = 0, std::uint64_t payload_base = 240)
{
    BuilderStore spec; spec.authoritative_checkpoint = true; spec.block_count = 1024;
    spec.authoritative_checkpoint_ring_blocks = 32; spec.authoritative_internal_pool_blocks = 64;
    spec.authoritative_main_free_blocks = free_blocks;
    spec.uuid_hex = "22aa4455667748899abbccddeeff0011"; spec.volumes.resize(2);
    for (unsigned i = 0; i < 2; ++i) {
        auto& v = spec.volumes[i]; v.oid = 201 + i; v.incompat = 0;
        v.uuid_hex = i == 0 ? "55dd4455667748899abbccddeeff0044" : "66ee4455667748899abbccddeeff0055";
        AppleInodeRecord root; root.object_id = root.private_id = 2; root.parent_id = 1; root.mode = 0040755; root.children_or_links = 1;
        BtreeRecord rec; std::string e;
        if (!EncodeAppleInodeRecord(root, rec, e)) throw std::runtime_error(e); v.filesystem_records.push_back(rec);
        const auto block = payload_base + i * 8;
        AppleInodeRecord file; file.object_id = file.private_id = 30; file.parent_id = 2; file.mode = 0100644;
        file.children_or_links = 1; file.uncompressed_size = 4096;
        AppleExtendedField stream{8, 0, Bytes(40)}; PutU64LE(stream.data, 0, 4096); PutU64LE(stream.data, 8, 4096); file.extended_fields.push_back(stream);
        if (!EncodeAppleInodeRecord(file, rec, e)) throw std::runtime_error(e); v.filesystem_records.push_back(rec);
        AppleDirectoryRecord entry; entry.parent_id = 2; entry.file_id = 30; entry.name_utf8 = "owned.bin"; entry.flags = 8;
        if (!EncodeAppleDirectoryRecord(entry, rec, e)) throw std::runtime_error(e); v.filesystem_records.push_back(rec);
        if (!EncodeAppleFileExtentRecord({30, 0, 4096, block, 0, 4096}, rec, e)) throw std::runtime_error(e); v.filesystem_records.push_back(rec);
        if (!EncodeAppleDataStreamIdRecord({30, 1}, rec, e)) throw std::runtime_error(e); v.filesystem_records.push_back(rec);
        if (!EncodeApplePhysicalExtentRecord({block, 1, 1, 30, 1}, rec, e)) throw std::runtime_error(e); v.extentref_records.push_back(rec);
        v.additional_file_system_allocated_blocks = 1; spec.authoritative_seeded_main_blocks.emplace_back(block, Bytes(4096, std::byte(0x71 + i)));
        if (!SortAppleBtreeRecords(v.filesystem_records, AppleBtreeKeyOrder::FileSystemCaseSensitive, e)) throw std::runtime_error(e);
    }
    auto image = BuildStoreImage(spec);
    for (std::size_t at = 0; at < image.size(); at += 4096) {
        Bytes block(image.begin() + at, image.begin() + at + 4096);
        if (ParseNxSuperblock(block)) { PutU32LE(block, 0xb4, 100); FletcherForBlock(block, 4096); std::copy(block.begin(), block.end(), image.begin() + at); }
    }
    {
        Bytes omap(image.begin() + kOmapOid * 4096, image.begin() + (kOmapOid + 1) * 4096);
        PutU32LE(omap, 0x20, 1); FletcherForBlock(omap, 4096); std::copy(omap.begin(), omap.end(), image.begin() + kOmapOid * 4096);
    }
    for (unsigned i = 0; i < 2; ++i) {
        const auto at = (kFirstVolumeBlock + i) * 4096; Bytes sb(image.begin() + at, image.begin() + at + 4096);
        PutU64LE(sb, 0xb8, 1); PutU64LE(sb, 0xc0, 1); PutU32LE(sb, 0x24, i); FletcherForBlock(sb, 4096);
        std::copy(sb.begin(), sb.end(), image.begin() + at);
    }
    {
        VectorRandomAccessSource source(image); std::string e;
        const auto cp = LoadAppleCheckpointView(source, 0, image.size(), e);
        if (!cp) throw std::runtime_error(e);
        auto sm = cp->spaceman.bytes;
        const auto cib = ReadU64LE(sm, cp->spaceman.devices[0].address_offset).value();
        const auto xid = ReadU64LE(sm, ReadU32LE(sm, 0x144).value()).value();
        const auto index = ReadU16LE(sm, ReadU32LE(sm, 0x148).value()).value();
        const auto links_at = ReadU32LE(sm, 0x14c).value();
        std::vector<std::uint16_t> links;
        for (unsigned i = 0; i < 16; ++i) links.push_back(ReadU16LE(sm, links_at + i * 2).value());
        std::fill(sm.begin() + 0x158, sm.end(), std::byte{});
        PutU32LE(sm, 0x50, 0xa00); PutU32LE(sm, 0x90, 1); PutU64LE(sm, 0xc0, 0);
        PutU32LE(sm, 0x144, 0xa08); PutU32LE(sm, 0x148, 0xa10); PutU32LE(sm, 0x14c, 0xa20);
        PutU32LE(sm, 0x150, 1); PutU32LE(sm, 0x154, 4096); PutU64LE(sm, 0xa00, cib); PutU64LE(sm, 0xa08, xid);
        PutU16LE(sm, 0xa10, index);
        for (unsigned i = 0; i < 16; ++i) PutU16LE(sm, 0xa20 + i * 2, links[i]);
        FletcherForBlock(sm, 4096); std::copy(sm.begin(), sm.end(), image.begin() + cp->spaceman.object.physical_block * 4096);
    }
    return image;
}
inline std::filesystem::path FixtureIoPath(const std::filesystem::path& p)
{
    auto native = p; native.make_preferred(); const auto path = native.wstring();
    return native.is_absolute() && !path.starts_with(L"\\\\?\\") ? std::filesystem::path(L"\\\\?\\" + path) : native;
}
inline void Save(const std::filesystem::path& p, const Bytes& b)
{
    std::ofstream f(FixtureIoPath(p), std::ios::binary | std::ios::trunc); f.write(reinterpret_cast<const char*>(b.data()), b.size());
    if (!f) throw std::runtime_error("fixture save failed");
}
inline Bytes Read(const std::filesystem::path& p)
{
    std::ifstream f(FixtureIoPath(p), std::ios::binary); if (!f) throw std::runtime_error("fixture read failed");
    std::vector<char> chars((std::istreambuf_iterator<char>(f)), {}); Bytes b(chars.size()); std::memcpy(b.data(), chars.data(), chars.size()); return b;
}
inline AppleCheckpointView Checkpoint(const Bytes& b)
{
    VectorRandomAccessSource source(b); std::string e; auto cp = LoadAppleCheckpointView(source, 0, b.size(), e);
    if (!cp) throw std::runtime_error(e); return *cp;
}
inline VolumeImageRequest Request(const std::filesystem::path& dir, VolumeImageOperation op, const Bytes& image)
{
    const auto cp = Checkpoint(image); VolumeImageRequest r; r.operation = op; r.image = dir / "image.apfs"; r.journal_directory = dir;
    r.container_uuid = cp.container.superblock.uuid_hex; r.volume_uuid = cp.volumes.front().superblock.uuid_hex;
    r.volume_oid = cp.volumes.front().superblock.object_id; r.checkpoint_xid = cp.container.superblock.xid; r.expected_bytes = image.size();
    r.target_bytes = op == VolumeImageOperation::Grow ? image.size() + 128 * 4096 : op == VolumeImageOperation::Shrink ? image.size() - 128 * 4096 : image.size();
    for (const auto& v : cp.volumes) r.sibling_wals[v.superblock.object_id] = dir / (std::to_string(v.superblock.object_id) + ".wal");
    if (op == VolumeImageOperation::Format || op == VolumeImageOperation::Erase) {
        r.new_container_uuid = "33bb4455667748899abbccddeeff0022"; r.new_volume_uuid = "44cc4455667748899abbccddeeff0033";
        r.name_utf8 = "Fresh Data"; r.new_volume_wal = dir / "destination.wal";
    }
    return r;
}
}
