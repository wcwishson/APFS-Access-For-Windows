#pragma once
#include "VolumeResizeCases.h"
#include "ApfsVerifier.h"
#include <winioctl.h>

namespace apfsaccess::volume_image_test
{
namespace multichunk
{
namespace vi = rw::volume_image;
constexpr std::uint64_t ChunkBlocks = 32768;

// Only populated 4 KiB blocks are resident, even for the 256 MiB geometry.
class SparseStore final : public RandomAccessSource, public AppleCheckpointWriteTarget
{
public:
    std::uint64_t block_count = 0, writes = 0, flushes = 0;
    mutable std::size_t largest_read = 0;
    std::map<std::uint64_t, Bytes> blocks;
    std::uint64_t SizeBytes() const override { return block_count * 4096; }
    bool Read(std::uint64_t offset, std::size_t size, Bytes& out) const override
    {
        out.clear();
        if (offset > SizeBytes() || size > SizeBytes() - offset) return false;
        largest_read = (std::max)(largest_read, size); out.assign(size, std::byte{});
        for (std::size_t at = 0; at < size;) {
            const auto address = offset + at, in_block = address % 4096;
            const auto count = (std::min)(size - at, static_cast<std::size_t>(4096 - in_block));
            if (const auto found = blocks.find(address / 4096); found != blocks.end())
                std::copy_n(found->second.begin() + in_block, count, out.begin() + at);
            at += count;
        }
        return true;
    }
    bool ReadBlock(std::uint64_t block, std::uint32_t size, Bytes& out) override
    { return size == 4096 && Read(block * size, size, out); }
    bool WriteBlock(std::uint64_t block, std::span<const std::byte> bytes) override
    {
        if (block >= block_count || bytes.size() != 4096) return false;
        blocks[block] = Bytes(bytes.begin(), bytes.end()); ++writes; return true;
    }
    bool Flush() override { ++flushes; return true; }
};

inline AppleCheckpointView Load(const RandomAccessSource& source)
{
    std::string e; auto cp = LoadAppleCheckpointView(source, 0, source.SizeBytes(), e);
    Check(cp.has_value(), "sparse checkpoint: " + e); return *cp;
}
inline void Verify(const RandomAccessSource& source, const AppleCheckpointView& cp)
{
    for (const auto& v : cp.volumes) {
        VerificationScope scope; scope.source_identity = "private-sparse-format-fixture";
        scope.exact = {0, source.SizeBytes(), cp.container.superblock.uuid_hex, v.superblock.uuid_hex,
            v.superblock.object_id, cp.container.superblock.xid};
        const auto report = ApfsVerifier::Verify(source, scope);
        const auto detail = report.findings.empty() ? "" : report.findings.front().detail;
        Check(report.outcome == VerificationOutcome::Complete && report.allocation_census.has_value(),
            "covered ownership/quota verification: " + detail);
    }
}
inline SparseStore Source(std::uint64_t count)
{
    const auto fixture_bytes = Fixture(); const auto cp = Checkpoint(fixture_bytes);
    SparseStore store; store.block_count = count;
    for (std::size_t at = 0; at < fixture_bytes.size(); at += 4096) {
        Bytes b(fixture_bytes.begin() + at, fixture_bytes.begin() + at + 4096);
        if (ParseNxSuperblock(b)) { vi::Put(b, 0x28, count); vi::Checksum(b); }
        if (std::any_of(b.begin(), b.end(), [](auto v) { return v != std::byte{}; })) store.blocks[at / 4096] = std::move(b);
    }
    const auto& old = cp.spaceman; const auto chunks = (count + ChunkBlocks - 1) / ChunkBlocks;
    const auto allocated = old.devices[0].block_count - old.devices[0].free_count;
    auto sm = old.bytes; vi::Put(sm, 0x30, count); vi::Put(sm, 0x38, chunks); vi::Put(sm, 0x48, count - allocated);
    vi::Checksum(sm); store.blocks[old.object.physical_block] = std::move(sm);
    auto cib = old.devices[0].cibs.front().bytes; vi::Put(cib, 0x24, chunks, 4);
    const auto first = (std::min)(count, ChunkBlocks);
    vi::Put(cib, 0x38, first, 4); vi::Put(cib, 0x3c, first - allocated, 4);
    if (chunks == 2) {
        vi::Put(cib, 0x48, cp.container.superblock.xid); vi::Put(cib, 0x50, ChunkBlocks);
        vi::Put(cib, 0x58, count - ChunkBlocks, 4); vi::Put(cib, 0x5c, count - ChunkBlocks, 4);
        vi::Put(cib, 0x60, 0); // Existing parser's canonical all-free chunk representation.
    }
    vi::Checksum(cib); store.blocks[old.devices[0].cibs.front().object.physical_block] = std::move(cib);
    return store;
}
inline VolumeImageRequest RequestFor(const SparseStore& source, const AppleCheckpointView& cp)
{
    auto r = Request(root, VolumeImageOperation::Format, Fixture());
    r.expected_bytes = r.target_bytes = source.SizeBytes(); r.checkpoint_xid = cp.container.superblock.xid;
    return r;
}
inline SparseStore Publish(SparseStore source, const vi::Plan& plan)
{
    std::string e; Check(ExecuteAppleCheckpointPublication(source, plan.publication, e), "format ordered publication: " + e);
    const auto old = Load(source);
    Check(old.container.superblock.xid == plan.before.container.superblock.xid &&
        old.container.superblock.uuid_hex == plan.before.container.superblock.uuid_hex,
        "pre-anchor writes preserve the original selected checkpoint");
    Check(source.WriteBlock(0, plan.anchor) && source.Flush(), "format anchor switch and flush");
    Bytes readback; Check(source.Read(0, 4096, readback) && readback == plan.anchor, "format anchor readback");
    return source;
}
inline void SparseFile(const std::filesystem::path& path, const SparseStore& source)
{
    const auto handle = CreateFileW(FixtureIoPath(path).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    Check(handle != INVALID_HANDLE_VALUE, "create private regular file");
    DWORD returned = 0;
    const bool sparse = DeviceIoControl(handle, FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &returned, nullptr) != 0;
    LARGE_INTEGER length{}; length.QuadPart = source.SizeBytes();
    bool ok = sparse && SetFilePointerEx(handle, length, nullptr, FILE_BEGIN) && SetEndOfFile(handle);
    for (const auto& [block, bytes] : source.blocks) {
        LARGE_INTEGER at{}; at.QuadPart = block * 4096; DWORD written = 0;
        ok = ok && SetFilePointerEx(handle, at, nullptr, FILE_BEGIN) &&
            WriteFile(handle, bytes.data(), 4096, &written, nullptr) && written == 4096;
    }
    ok = ok && FlushFileBuffers(handle); CloseHandle(handle); Check(ok, "sparse regular file block writes and flush");
}
template<class Store> inline void NativeWrite(Store& store)
{
    const auto cp = Load(store); AppleVolumeTransactionRequest r; r.volume_object_id = cp.volumes.front().superblock.object_id;
    std::string e; const auto& v = cp.volumes.front();
    Check(ReadBtreeLeafRecords(store, 4096, v.root_tree.physical_block, false, v.superblock.omap_oid,
        cp.container.superblock.xid, r.filesystem_records, e), "fresh filesystem records: " + e);
    AppleInodeRecord inode; inode.object_id = inode.private_id = 1030; inode.parent_id = 2; inode.mode = 0100644;
    inode.children_or_links = 1; inode.uncompressed_size = 8192;
    AppleExtendedField stream{8, 0, Bytes(40)}; PutU64LE(stream.data, 0, 8192); PutU64LE(stream.data, 8, 8192);
    inode.extended_fields.push_back(stream); catalog::BtreeRecord record; Check(EncodeAppleInodeRecord(inode, record, e), e);
    r.filesystem_records.push_back(record); AppleDirectoryRecord entry{2, 1030, 0, 8, "cross-chunk.bin"};
    Check(EncodeAppleDirectoryRecord(entry, ApfsNamePolicy::FromIncompatibleFeatures(v.superblock.incompatible_features), record, e), e);
    r.filesystem_records.push_back(record);
    AppleInodeRecord root_inode; root_inode.object_id = root_inode.private_id = 2; root_inode.parent_id = 1;
    root_inode.mode = 0040755; root_inode.children_or_links = 2; catalog::BtreeRecord root_record;
    Check(EncodeAppleInodeRecord(root_inode, root_record, e), e); unsigned roots = 0;
    for (auto& item : r.filesystem_records) {
        if (item.key != root_record.key) continue;
        Check(ReadU32LE(item.value, 0x38) == 1, "fresh root owns only private-dir"); item = root_record; ++roots;
    }
    Check(roots == 1, "exact root inode updated");
    Check(EncodeAppleDataStreamIdRecord({1030, 1}, record, e), e); r.filesystem_records.push_back(record);
    r.file_count_delta = 1; r.data_writes.push_back({1030, 0, 0, Bytes(8192, std::byte{0x59})});
    AppleVolumeTransactionPlan plan; Check(PlanAppleVolumeTransaction(store, cp, r, plan, e), "post-format native allocation: " + e);
    Check(!plan.payload_blocks.empty() && plan.allocation.allocated_main_blocks.size() > 2, "native payload and metadata allocated");
    Check(ExecuteAppleCheckpointPublication(store, plan.commit.publication, e), "post-format native publication: " + e);
    const auto after = Load(store); Check(after.container.superblock.xid == cp.container.superblock.next_xid,
        "reopened native write advances one checkpoint"); Verify(store, after);
    for (auto block : plan.payload_blocks) {
        Bytes bytes; Check(store.Read(block * 4096, 4096, bytes) &&
            std::all_of(bytes.begin(), bytes.end(), [](auto b) { return b == std::byte{0x59}; }), "native payload readback");
    }
}
inline void CrossBoundaryAllocation(SparseStore& store)
{
    const auto cp = Load(store); const auto before = store.blocks; std::string e;
    AppleSpacemanAllocationRequest request; request.expected_checkpoint_xid = cp.container.superblock.xid;
    request.transaction_xid = cp.container.superblock.next_xid; request.oldest_required_checkpoint_xid = 1;
    request.first_ephemeral_object_id = cp.container.superblock.next_oid; request.main_block_count = 2; request.search_from_end = true;
    AppleSpacemanAllocationPlan allocation;
    Check(cp.spaceman.chunks[1].free_count == 1, "boundary fixture leaves exactly one free block in final chunk");
    Check(PlanAppleSpacemanAllocation(cp.spaceman, request, allocation, e), "canonical cross-chunk allocator: " + e);
    Check(store.blocks == before && allocation.allocated_main_blocks == std::vector<std::uint64_t>{32768, 32767},
        "two-block allocation crosses chunk boundary without source mutation");
    for (auto old_block : {cp.spaceman.chunks[0].bitmap_block, cp.spaceman.chunks[1].bitmap_block,
        cp.spaceman.devices[0].cibs.front().object.physical_block}) {
        Check(vi::Bit(allocation.updated_spaceman.internal_pool.active_bitmaps.front().bytes,
            old_block - cp.spaceman.internal_pool.base_block) &&
            std::any_of(allocation.deferred_frees.begin(), allocation.deferred_frees.end(), [&](const auto& entry) {
                return entry.queue_index == 0 && old_block >= entry.physical_block && old_block - entry.physical_block < entry.block_count;
            }) && std::any_of(allocation.updated_spaceman.free_queues[0].entries.begin(),
                allocation.updated_spaceman.free_queues[0].entries.end(), [&](const auto& entry) {
                return entry.xid == request.transaction_xid && old_block >= entry.physical_block &&
                    old_block - entry.physical_block < entry.block_count;
            }), "original CIB and both bitmaps remain allocated with deferred retirement");
    }
    AppleTransactionCommitRequest commit; commit.allocation_plan = allocation; commit.next_object_id = cp.container.superblock.next_oid;
    for (auto block : allocation.allocated_main_blocks) commit.allocated_main_writes.push_back({block, Bytes(4096)});
    AppleTransactionCommitPlan planned;
    Check(PlanAppleTransactionCommit(store, cp, commit, planned, e), "cross-chunk allocator commit proof: " + e);
    Check(ExecuteAppleCheckpointPublication(store, planned.publication, e), "cross-chunk allocator publication: " + e);
    const auto after = Load(store); Verify(store, after);
    Check(after.spaceman.chunks[0].free_count + 1 == cp.spaceman.chunks[0].free_count &&
        after.spaceman.chunks[1].free_count == 0 &&
        after.spaceman.devices[0].free_count + 2 == cp.spaceman.devices[0].free_count,
        "reopened allocator independently accounts for one reservation from each chunk");
    Check(vi::Bit(after.spaceman.chunks[0].allocation_bitmap, 32767) && vi::Bit(after.spaceman.chunks[1].allocation_bitmap, 0),
        "both COW chunk bitmaps survive checkpoint reopen");
}
inline void Boundaries()
{
    for (auto count : {32767ull, 32768ull, 32769ull, 33111ull, 33112ull, 33113ull, 65536ull}) {
        auto source = Source(count); const auto before = source.blocks; const auto cp = Load(source); Verify(source, cp);
        const auto r = RequestFor(source, cp); const auto plan = vi::BuildFormatPublication(source, r, cp);
        Check(source.blocks == before && source.writes == 0, "planning preserves all sparse preimage bytes");
        auto post = Publish(source, plan); const auto fresh = Load(post); Verify(post, fresh);
        const auto chunks = (count + ChunkBlocks - 1) / ChunkBlocks;
        Check(fresh.spaceman.chunks.size() == chunks && fresh.spaceman.devices[0].cibs.size() == 1 &&
            fresh.spaceman.devices[0].cabs.empty(), "bounded two-chunk one-CIB geometry");
        Check(fresh.spaceman.devices[0].free_count == count - 345 && fresh.volumes.size() == 1 &&
            fresh.container.superblock.uuid_hex == r.new_container_uuid && fresh.volumes.front().superblock.uuid_hex == r.new_volume_uuid,
            "fresh identities and exact aggregate allocation count");
        Check(ReadU32LE(fresh.container.superblock_bytes, 0xb4) == 100 && fresh.volumes.front().superblock.space.allocated_block_count == 6,
            "max slots and initial volume ownership preserved");
        const auto base = plan.publication.superblock_write.physical_block - 1;
        std::uint64_t observed = 0;
        for (const auto& c : fresh.spaceman.chunks) {
            Check(c.start_block % ChunkBlocks == 0 && c.block_count == (std::min)(ChunkBlocks, count - c.start_block),
                "partial final chunk has exact start and length");
            std::uint64_t allocated = 0;
            for (std::uint64_t bit = 0; bit < c.block_count; ++bit) {
                const auto block = c.start_block + bit;
                const bool expected = block == 0 || (block >= base && block - base < 344);
                if (vi::Bit(c.allocation_bitmap, bit) != expected) throw std::runtime_error("chunk-relative ownership bit mismatch");
                allocated += expected;
            }
            ++checks; observed += allocated;
            Check(c.free_count == c.block_count - allocated && c.bitmap_block != 0, "per-chunk bitmap and free count agree");
            Check(vi::Bit(fresh.spaceman.internal_pool.active_bitmaps.front().bytes,
                c.bitmap_block - fresh.spaceman.internal_pool.base_block), "main bitmap is owned in internal pool");
        }
        Check(observed == 345 && post.blocks.size() * 4096 < 2 * 1024 * 1024 && post.largest_read <= 4096,
            "metadata-only resident storage and bounded individual reads");
        const auto path = root / ("multichunk-" + std::to_string(count) + ".apfs"); SparseFile(path, post);
        HeldFileSource reopened(path.string()); Check(reopened.IsOpen(), "reopen ordinary sparse image");
        const auto reopened_cp = Load(reopened); Verify(reopened, reopened_cp);
        std::string e; Check(reopened.VerifyUnchanged(e), "held regular-file source remains unchanged: " + e);
        if (count == 33113) CrossBoundaryAllocation(post);
        NativeWrite(post);
        std::cout << "GEOMETRY blocks=" << count << " chunks=" << chunks << " sparse_bytes=" << before.size() * 4096
            << " format_resident_bytes=" << plan.publication.before_superblock_writes.size() * 4096 << '\n';
    }
    Pass("multichunk boundaries sparse-file reopen ownership and native allocation");
}
inline void CorruptionAndGuards()
{
    auto source = Source(33113); const auto cp = Load(source); const auto r = RequestFor(source, cp);
    const auto plan = vi::BuildFormatPublication(source, r, cp); const auto post = Publish(source, plan); const auto fresh = Load(post);
    const auto cib_block = fresh.spaceman.devices[0].cibs.front().object.physical_block;
    const auto damage = [&](const char* why, const char* expected, const std::function<void(SparseStore&)>& alter) {
        auto broken = post; alter(broken); const auto before = broken.blocks;
        AppleSpacemanView ignored; std::string e;
        Check(!LoadAppleSpacemanOwnershipView(broken, fresh.container, ignored, e) && e == expected,
            std::string(why) + ": " + e);
        Check(broken.blocks == before && broken.writes == post.writes, "corruption proof is read only");
    };
    const auto cib_damage = [&](const char* why, const char* expected, std::size_t at, std::uint64_t value, unsigned width) {
        damage(why, expected, [&](auto& broken) { auto& b = broken.blocks.at(cib_block); vi::Put(b, at, value, width); vi::Checksum(b); });
    };
    cib_damage("wrong second start", "AppleSpacemanChunkGeometryInvalid", 0x50, ChunkBlocks + 1, 8);
    cib_damage("missing second CIB entry", "AppleSpacemanCibGeometryInvalid", 0x24, 1, 4);
    cib_damage("oversized final chunk", "AppleSpacemanChunkGeometryInvalid", 0x58, 346, 4);
    cib_damage("future chunk XID", "AppleSpacemanChunkGeometryInvalid", 0x48, fresh.container.superblock.xid + 1, 8);
    cib_damage("wrong chunk free count", "AppleSpacemanChunkFreeCountMismatch", 0x5c, 2, 4);
    cib_damage("aliased chunk bitmap", "AppleSpacemanChunkBitmapInvalid", 0x60, fresh.spaceman.chunks[0].bitmap_block, 8);
    cib_damage("out of range bitmap", "AppleSpacemanChunkBitmapInvalid", 0x60, post.block_count, 8);
    damage("bitmap main ownership bit", "AppleSpacemanChunkFreeCountMismatch", [&](auto& broken) {
        vi::SetBit(broken.blocks.at(fresh.spaceman.chunks[1].bitmap_block), 0, true);
    });
    damage("bitmap missing internal owner", "AppleSpacemanInternalPoolOwnershipMismatch", [&](auto& broken) {
        const auto& pool = fresh.spaceman.internal_pool;
        vi::SetBit(broken.blocks.at(pool.active_bitmaps[0].physical_block), fresh.spaceman.chunks[1].bitmap_block - pool.base_block, false);
    });
    damage("tier-2 geometry", "AppleSpacemanTier2Unsupported", [&](auto& broken) {
        auto& sm = broken.blocks.at(fresh.spaceman.object.physical_block); vi::Put(sm, 0x60, 1); vi::Checksum(sm);
    });
    auto changed = source; changed.blocks.at(0)[100] ^= std::byte{1}; const auto before = changed.blocks; std::string e;
    Check(!ExecuteAppleCheckpointPublication(changed, plan.publication, e) && changed.blocks == before && changed.writes == 0,
        "source guard drift refuses before any publication write: " + e);
    for (auto stage : {"before-apple-device-write", "before-apple-checkpoint-switch"}) {
        auto cancelled = source; bool hit = false;
        Check(!ExecuteAppleCheckpointPublication(cancelled, plan.publication, e, [&](auto at) {
            if (at != stage) return true; hit = true; return false;
        }) && hit, "multichunk publication interruption reaches requested boundary");
        const auto selected = Load(cancelled); Verify(cancelled, selected);
        Check(selected.container.superblock.xid == cp.container.superblock.xid && cancelled.blocks.at(0) == source.blocks.at(0),
            "interrupted multichunk publication preserves original anchor and complete selected checkpoint");
        if (std::string_view(stage) == "before-apple-device-write")
            Check(cancelled.blocks == source.blocks && cancelled.writes == 0, "pre-write cancellation is byte identical");
    }
    auto budget = std::make_shared<ApfsReadBudget>(0, 0, 0, 0); BudgetedRandomAccessSource bounded(source, budget);
    bool refused = false;
    try { (void)vi::BuildFormatPublication(bounded, r, cp); } catch (const std::runtime_error&) { refused = true; }
    Check(refused && budget->Failed() && source.writes == 0, "sticky exhausted source allowance refuses layout");
    Bytes ignored; Check(!bounded.Read(0, 4096, ignored) && budget->Failed(), "layout failure cannot replenish source budget");
    bool no_authority = false;
    try { (void)vi::PlanFormat(Fixture(), r); } catch (const std::runtime_error& ex) {
        no_authority = std::string_view(ex.what()) == "VolumeImageRetentionAuthorityRequired";
    }
    Check(no_authority, "internal builder does not authorize the public keeper planner");
    Pass("multichunk corruption identity guard CLEAN authority and sticky budget refusals");
}
inline void SourceSpacePolicy()
{
    for (bool quota : {false, true}) {
        auto bytes = Fixture(); const auto cp = Checkpoint(bytes); const auto at = cp.volumes.front().superblock_object.physical_block * 4096;
        Bytes apsb(bytes.begin() + at, bytes.begin() + at + 4096);
        vi::Put(apsb, quota ? 0x50 : 0x48, quota ? 1 : cp.container.superblock.block_count + 1); vi::Checksum(apsb);
        std::copy(apsb.begin(), apsb.end(), bytes.begin() + at);
        auto r = Setup(quota ? "multichunk-control-quota" : "multichunk-control-reserve", VolumeImageOperation::Format, bytes);
        const auto result = Prepare(r);
        Check(result.outcome == VolumeImageOutcome::Refused && !result.error.empty() && Read(r.image) == bytes,
            "source quota/reserve inconsistency refuses before intent or publication: " + result.error);
    }
    Pass("format source quota and reserve admission remains strict");
}
}
inline void FormatMultichunk() { multichunk::Boundaries(); multichunk::CorruptionAndGuards(); }
}
