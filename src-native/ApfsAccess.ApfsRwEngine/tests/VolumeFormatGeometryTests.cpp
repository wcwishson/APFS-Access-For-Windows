#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4310) // Existing refusal fixture deliberately casts an invalid enum.
#endif
#include "VolumeFormatMultichunkCases.h"
#ifdef _MSC_VER
#pragma warning(pop)
#endif

using namespace apfsaccess::volume_image_test;
namespace mc = apfsaccess::volume_image_test::multichunk;
namespace vi = apfsaccess::rw::volume_image;

class SparseImageTarget final : public RandomAccessSource, public AppleCheckpointWriteTarget
{
public:
    explicit SparseImageTarget(const std::filesystem::path& path)
    {
        file_ = CreateFileW(FixtureIoPath(path).c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        Check(file_ != INVALID_HANDLE_VALUE, "exclusive sparse-image target");
        LARGE_INTEGER length{};
        Check(GetFileSizeEx(file_, &length) && length.QuadPart > 0, "actual sparse-image length");
        bytes_ = static_cast<std::uint64_t>(length.QuadPart);
    }
    ~SparseImageTarget() { CloseHandle(file_); }
    std::uint64_t SizeBytes() const override { return bytes_; }
    bool Read(std::uint64_t offset, std::size_t size, Bytes& out) const override
    {
        out.clear();
        if (offset > bytes_ || size > bytes_ - offset || size > MAXDWORD) return false;
        LARGE_INTEGER at{}; at.QuadPart = static_cast<LONGLONG>(offset); DWORD read = 0;
        out.resize(size);
        if (!SetFilePointerEx(file_, at, nullptr, FILE_BEGIN) ||
            !ReadFile(file_, out.data(), static_cast<DWORD>(size), &read, nullptr) || read != size) {
            out.clear(); return false;
        }
        return true;
    }
    bool ReadBlock(std::uint64_t block, std::uint32_t size, Bytes& out) override
    { return size == 4096 && block < bytes_ / 4096 && Read(block * 4096, size, out); }
    bool WriteBlock(std::uint64_t block, std::span<const std::byte> bytes) override
    {
        if (block >= bytes_ / 4096 || bytes.size() != 4096) return false;
        LARGE_INTEGER at{}; at.QuadPart = static_cast<LONGLONG>(block * 4096); DWORD written = 0;
        return SetFilePointerEx(file_, at, nullptr, FILE_BEGIN) &&
            WriteFile(file_, bytes.data(), 4096, &written, nullptr) && written == 4096;
    }
    bool Flush() override { return FlushFileBuffers(file_) != FALSE; }
private:
    HANDLE file_ = INVALID_HANDLE_VALUE;
    std::uint64_t bytes_ = 0;
};

mc::SparseStore GeneralSource(std::uint64_t count)
{
    const auto original = Fixture(); const auto old = Checkpoint(original);
    mc::SparseStore source; source.block_count = count;
    for (std::size_t at = 0; at < original.size(); at += 4096) {
        Bytes block(original.begin() + at, original.begin() + at + 4096);
        if (ParseNxSuperblock(block)) { vi::Put(block, 0x28, count); vi::Checksum(block); }
        if (std::any_of(block.begin(), block.end(), [](auto b) { return b != std::byte{}; }))
            source.blocks[at / 4096] = std::move(block);
    }
    constexpr std::uint64_t per_cib = (4096 - 40) / 32;
    const auto chunks = (count + mc::ChunkBlocks - 1) / mc::ChunkBlocks;
    const auto cibs = (chunks + per_cib - 1) / per_cib;
    Check(cibs && cibs <= 16, "bounded source fixture CIB count");
    const auto allocated = old.spaceman.devices[0].block_count - old.spaceman.devices[0].free_count;
    const auto& ip = old.spaceman.internal_pool;
    Check(ip.active_bitmaps.size() == 1 && ip.block_count >= cibs + 2, "fixture internal pool");
    auto pool_bitmap = ip.active_bitmaps.front().bytes;
    std::vector<std::uint64_t> addresses{old.spaceman.devices[0].cibs.front().object.physical_block};
    for (std::uint64_t i = 0; addresses.size() < cibs && i < ip.block_count; ++i) {
        if (vi::Bit(pool_bitmap, i)) continue;
        vi::SetBit(pool_bitmap, i, true); addresses.push_back(ip.base_block + i);
    }
    Check(addresses.size() == cibs, "source fixture CIB slots");
    source.blocks[ip.active_bitmaps.front().physical_block] = std::move(pool_bitmap);
    for (std::uint64_t index = 0; index < cibs; ++index) {
        auto cib = old.spaceman.devices[0].cibs.front().bytes;
        vi::Put(cib, 8, addresses[index]); vi::Put(cib, 0x20, index, 4);
        const auto entries = (std::min)(per_cib, chunks - index * per_cib);
        vi::Put(cib, 0x24, entries, 4); std::fill(cib.begin() + 0x28, cib.end(), std::byte{});
        for (std::uint64_t j = 0; j < entries; ++j) {
            const auto chunk = index * per_cib + j, start = chunk * mc::ChunkBlocks;
            const auto length = (std::min)(mc::ChunkBlocks, count - start), at = 0x28 + j * 0x20;
            vi::Put(cib, at, old.container.superblock.xid); vi::Put(cib, at + 8, start);
            vi::Put(cib, at + 16, length, 4); vi::Put(cib, at + 20, length - (chunk == 0 ? allocated : 0), 4);
            vi::Put(cib, at + 24, chunk == 0 ? old.spaceman.chunks.front().bitmap_block : 0);
        }
        vi::Checksum(cib); source.blocks[addresses[index]] = std::move(cib);
    }
    auto sm = old.spaceman.bytes;
    const auto old_xid_offset = ReadU32LE(sm, 0x144).value(), old_head_offset = ReadU32LE(sm, 0x148).value();
    const auto old_link_offset = ReadU32LE(sm, 0x14c).value();
    const auto bitmap_xid = ReadU64LE(sm, old_xid_offset).value();
    const auto head = ReadU16LE(sm, old_head_offset).value();
    std::vector<std::uint16_t> links;
    for (unsigned i = 0; i < 16; ++i) links.push_back(ReadU16LE(sm, old_link_offset + i * 2).value());
    const auto xid_offset = 0xa00 + cibs * 8, head_offset = xid_offset + 8, link_offset = head_offset + 16;
    std::fill(sm.begin() + 0xa00, sm.end(), std::byte{});
    vi::Put(sm, 0x30, count); vi::Put(sm, 0x38, chunks); vi::Put(sm, 0x40, cibs, 4); vi::Put(sm, 0x48, count - allocated);
    vi::Put(sm, 0x144, xid_offset, 4); vi::Put(sm, 0x148, head_offset, 4); vi::Put(sm, 0x14c, link_offset, 4);
    for (std::uint64_t i = 0; i < cibs; ++i) vi::Put(sm, 0xa00 + i * 8, addresses[i]);
    vi::Put(sm, xid_offset, bitmap_xid); vi::Put(sm, head_offset, head, 2);
    for (unsigned i = 0; i < 16; ++i) vi::Put(sm, link_offset + i * 2, links[i], 2);
    vi::Checksum(sm); source.blocks[old.spaceman.object.physical_block] = std::move(sm);
    return source;
}

void Geometry(std::uint64_t chunks)
{
    auto source = GeneralSource(chunks * mc::ChunkBlocks - 17);
    const auto before = mc::Load(source); mc::Verify(source, before);
    const auto original = source.blocks;
    auto request = mc::RequestFor(source, before);
    auto plan = vi::BuildFormatPublication(source, request, before);
    const auto refusal = [&](vi::Plan candidate, const VolumeImageRequest& input, std::string_view expected) {
        bool refused = false; std::string actual;
        try { vi::FinishFormatSource(source, input, candidate); }
        catch (const std::exception& ex) { actual=ex.what(); refused = std::string_view(ex.what()).starts_with(expected); }
        Check(refused && source.blocks == original && source.writes == 0, "streamed proof refuses before target I/O: expected="+
            std::string(expected)+" actual="+actual);
    };
    auto duplicate = plan;
    duplicate.publication.before_superblock_writes.push_back(plan.publication.superblock_write);
    refusal(std::move(duplicate), request, "VolumeFormatOverlayOverlap");
    auto resized = request; resized.operation = VolumeImageOperation::Grow;
    refusal(plan, resized, "VolumeStreamedFormatOperationRequired");
    auto erased = request; erased.operation = VolumeImageOperation::Erase;
    auto erased_plan = plan;
    vi::FinishFormatSource(source, erased, erased_plan);
    Check(erased_plan.postimage.empty() && erased_plan.cleanup.empty() &&
        source.blocks == original && source.writes == 0,
        "supported streamed erase proves its source without whole-image staging or target writes");
    auto foreign = request; foreign.container_uuid = std::string(32, 'e');
    refusal(plan, foreign, "VolumeImageIdentityOrGeometryMismatch");
    auto damaged = plan; damaged.anchor[0x40] ^= std::byte{1};
    refusal(std::move(damaged), request, "VolumeFormatStreamedNewCheckpointInvalid");
    vi::FinishFormatSource(source, request, plan);
    Check(plan.postimage.empty() && plan.after.container.superblock.uuid_hex == request.new_container_uuid &&
        plan.destinations.contains(0), "streamed old and new proof without an image-sized postimage");
    Check(source.blocks == original && source.writes == 0, "format preparation is read only");
    auto after = mc::Publish(source, plan); const auto cp = mc::Load(after); mc::Verify(after, cp);
    const auto expected_cibs = (chunks + 125) / 126;
    Check(cp.spaceman.devices[0].cibs.size() == expected_cibs && cp.spaceman.chunks.size() == chunks &&
        cp.spaceman.devices[0].block_count == source.block_count, "complete multi-CIB target geometry");
    Check(cp.volumes.size() == 1 && cp.volumes.front().superblock.uuid_hex == request.new_volume_uuid &&
        cp.container.superblock.uuid_hex == request.new_container_uuid, "fresh canonical identities");
    std::size_t populated = 0;
    for (const auto& chunk : cp.spaceman.chunks) {
        if (chunk.bitmap_block) ++populated;
        else Check(chunk.free_count == chunk.block_count, "null bitmap is completely free");
    }
    Check(populated <= 3 && cp.spaceman.internal_pool.block_count >= expected_cibs + populated + 24,
        "bounded bitmap storage with internal-pool spare capacity");
    Check(source.largest_read <= 4096 && after.largest_read <= 4096, "no whole-image read");
    // A fresh ordinary transaction must consume the resulting real allocator,
    // rather than merely accepting the newly serialized metadata in the parser.
    mc::NativeWrite(after);
    if (chunks == 701) {
        const auto path = root / L"format-701-chunks.apfs";
        mc::SparseFile(path, source);
        {
            SparseImageTarget target(path); std::string error;
            Check(ExecuteAppleCheckpointPublication(target, plan.publication, error), "actual sparse-image staging: " + error);
            const auto staged = mc::Load(target);
            Check(staged.container.superblock.uuid_hex == before.container.superblock.uuid_hex &&
                staged.container.superblock.xid == before.container.superblock.xid, "actual old checkpoint before anchor");
            Check(target.WriteBlock(0, plan.anchor) && target.Flush(), "actual sparse-image anchor publication");
            const auto formatted = mc::Load(target); mc::Verify(target, formatted);
            Check(formatted.spaceman.devices[0].cibs.size() == expected_cibs &&
                formatted.container.superblock.uuid_hex == request.new_container_uuid, "actual new checkpoint");
            mc::NativeWrite(target);
        }
        HeldFileSource reopened(path.string());
        Check(reopened.IsOpen(), "fresh held-file reopening");
        const auto final = mc::Load(reopened); mc::Verify(reopened, final);
        Check(final.container.superblock.xid == before.container.superblock.next_xid + 1 &&
            final.spaceman.devices[0].cibs.size() == expected_cibs, "fresh larger-file geometry and write");
    }
    ++groups;
}

int wmain(int argc, wchar_t** argv)
{
    try {
        Check(argc == 2, "fresh D evidence directory required"); root = argv[1]; std::filesystem::create_directories(root);
        Geometry(8); Geometry(127); Geometry(701);
        std::cout << "PASS groups=" << groups << " checks=" << checks << '\n'; return 0;
    } catch (const std::exception& ex) {
        std::cerr << "FAIL checks=" << checks << ' ' << ex.what() << '\n'; return 1;
    }
}
