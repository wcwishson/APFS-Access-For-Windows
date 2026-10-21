#include "VolumeRetiredHistoryCases.h"
#include <bcrypt.h>
#include <iomanip>
#include <sstream>

using namespace apfsaccess::volume_image_test;
namespace rw = apfsaccess::rw;
namespace
{
Bytes GeometryFixture(std::uint64_t blocks, std::uint32_t per_chunk = 1024,
    bool explicit_second_bitmap = false, std::uint64_t payload = 240)
{
    auto image = Fixture(0, payload); const auto before = Checkpoint(image);
    Check(blocks >= 1024 && blocks <= 65536 && blocks <= 2ull * per_chunk, "bounded geometry fixture");
    const auto old_bitmap = before.spaceman.chunks.front().allocation_bitmap;
    const auto chunks = (blocks + per_chunk - 1) / per_chunk;
    auto sm = before.spaceman.bytes; auto cib = before.spaceman.devices[0].cibs.front().bytes;
    auto ip = before.spaceman.internal_pool.active_bitmaps.front().bytes;
    image.resize(blocks * 4096);
    const auto put = [&](std::uint64_t block, const Bytes& bytes) {
        std::copy(bytes.begin(), bytes.end(), image.begin() + block * 4096);
    };
    std::uint64_t total_free = 0;
    std::fill(cib.begin() + 0x28, cib.end(), std::byte{});
    PutU32LE(cib, 0x24, static_cast<std::uint32_t>(chunks));
    for (std::uint64_t i = 0; i < chunks; ++i) {
        const auto start = i * per_chunk; const auto count = (std::min<std::uint64_t>)(per_chunk, blocks - start);
        Bytes bitmap(4096); std::uint64_t used = 0;
        for (auto n = 0ull; n < count; ++n) {
            const bool bit = start + n < 1024 && rw::volume_image::Bit(old_bitmap, start + n);
            rw::volume_image::SetBit(bitmap, n, bit); used += bit;
        }
        for (auto n = count; n < 32768; ++n) rw::volume_image::SetBit(bitmap, n, true);
        const auto bitmap_block = i == 0 ? before.spaceman.chunks[0].bitmap_block :
            (explicit_second_bitmap || used ? before.spaceman.internal_pool.base_block + 2 : 0);
        if (bitmap_block) { put(bitmap_block, bitmap); rw::volume_image::SetBit(ip, bitmap_block - before.spaceman.internal_pool.base_block, true); }
        const auto at = 0x28 + i * 0x20;
        PutU64LE(cib, at, before.container.superblock.xid); PutU64LE(cib, at + 8, start);
        PutU32LE(cib, at + 0x10, static_cast<std::uint32_t>(count));
        PutU32LE(cib, at + 0x14, static_cast<std::uint32_t>(count - used)); PutU64LE(cib, at + 0x18, bitmap_block);
        total_free += count - used;
    }
    PutU32LE(sm, 0x24, per_chunk); PutU64LE(sm, 0x30, blocks); PutU64LE(sm, 0x38, chunks); PutU64LE(sm, 0x48, total_free);
    FletcherForBlock(sm, 4096); FletcherForBlock(cib, 4096);
    put(before.spaceman.object.physical_block, sm); put(before.spaceman.devices[0].cibs[0].object.physical_block, cib);
    put(before.spaceman.internal_pool.active_bitmaps[0].physical_block, ip);
    for (auto b = 0ull; b < 1024; ++b) {
        Bytes nx(image.begin() + b * 4096, image.begin() + (b + 1) * 4096);
        if (ParseNxSuperblock(nx)) { PutU64LE(nx, 0x28, blocks); FletcherForBlock(nx, 4096); put(b, nx); }
    }
    rw::volume_image::Verify(image, Checkpoint(image)); ++checks;
    return image;
}

std::string Sha(const Bytes& bytes)
{
    std::array<unsigned char, 32> digest{};
    Check(BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())),
        static_cast<ULONG>(bytes.size()), digest.data(), static_cast<ULONG>(digest.size())) >= 0, "SHA256");
    std::ostringstream out; out << std::hex << std::setfill('0'); for (const auto b : digest) out << std::setw(2) << unsigned(b); return out.str();
}

void Geometry(const Bytes& image, std::uint64_t blocks, std::size_t chunks)
{
    const auto cp = Checkpoint(image); const auto& sm = cp.spaceman; const auto& dev = sm.devices[0];
    Check(image.size() == blocks * 4096 && cp.container.superblock.block_count == blocks && dev.block_count == blocks &&
        dev.chunk_count == chunks && sm.chunks.size() == chunks && dev.cib_count == 1 && dev.cabs.empty(), "all device/NX geometry agrees");
    Check(ReadU32LE(dev.cibs[0].bytes, 0x24) == chunks && ReadU64LE(sm.bytes, dev.address_offset) == dev.cibs[0].object.physical_block,
        "CIB address and entry count agree");
    std::uint64_t free = 0;
    for (std::size_t i = 0; i < chunks; ++i) {
        const auto& c = sm.chunks[i]; const auto at = 0x28 + i * 0x20;
        Check(c.start_block == i * sm.blocks_per_chunk && c.block_count == (std::min<std::uint64_t>)(sm.blocks_per_chunk, blocks - c.start_block) &&
            ReadU64LE(dev.cibs[0].bytes, at + 8) == c.start_block && ReadU32LE(dev.cibs[0].bytes, at + 0x10) == c.block_count &&
            ReadU32LE(dev.cibs[0].bytes, at + 0x14) == c.free_count && ReadU64LE(dev.cibs[0].bytes, at + 0x18) == c.bitmap_block,
            "chunk counters addresses and parsed CIB state agree");
        std::uint64_t used = 0; for (auto n = 0ull; n < c.block_count; ++n) used += rw::volume_image::Bit(c.allocation_bitmap, n);
        Check(used + c.free_count == c.block_count, "bitmap count agrees without invented ownership"); free += c.free_count;
    }
    Check(free == dev.free_count, "sum of chunk free counts agrees"); rw::volume_image::Verify(image, cp); ++checks;
}

bool Allocated(const AppleCheckpointView& cp, std::uint64_t block)
{
    for (const auto& c : cp.spaceman.chunks)
        if (block >= c.start_block && block - c.start_block < c.block_count) return rw::volume_image::Bit(c.allocation_bitmap, block - c.start_block);
    throw std::runtime_error("allocation comparison outside parsed geometry");
}

void Preserve(const Bytes& original, const Bytes& post)
{
    const auto old = Checkpoint(original); const auto now = Checkpoint(post);
    const auto common = (std::min)(old.container.superblock.block_count, now.container.superblock.block_count);
    for (auto b = 0ull; b < common; ++b) {
        const auto was = Allocated(old, b); const auto is = Allocated(now, b);
        Check(was == is || (!was && is && b == now.container_object_map.object.physical_block), "only the genuine allocated OMAP changes an existing main bit");
    }
    for (auto b = old.container.superblock.block_count; b < now.container.superblock.block_count; ++b) Check(!Allocated(now, b), "every added block is free");
    VectorRandomAccessSource source(original); std::string error;
    std::vector<std::uint64_t> metadata; std::vector<ApplePhysicalExtentRecord> payload;
    Check(LoadAppleSnapshotCheckpointOwners(source, old, metadata, payload, error) && !metadata.empty() && !payload.empty(), "nonvacuous owner census: " + error);
    const auto equal = [&](std::uint64_t block, std::uint64_t count) {
        Check(block < post.size() / 4096 && count <= post.size() / 4096 - block &&
            std::equal(original.begin() + block * 4096, original.begin() + (block + count) * 4096, post.begin() + block * 4096), "every actual peer/retained owner stays byte identical");
    };
    for (const auto b : metadata) if (b) equal(b, 1);
    for (const auto& x : payload) equal(x.physical_block, x.block_count);
    for (const auto& c : old.spaceman.chunks) if (c.bitmap_block) {
        equal(c.bitmap_block, 1);
        const bool replaced = std::none_of(now.spaceman.chunks.begin(), now.spaceman.chunks.end(), [&](const auto& n) { return n.bitmap_block == c.bitmap_block; });
        if (replaced) {
            const auto& ip = now.spaceman.internal_pool; const auto bit = c.bitmap_block - ip.base_block;
            Check(rw::volume_image::Bit(ip.active_bitmaps.at(bit / 32768).bytes, bit % 32768), "retired bitmap remains allocated for old checkpoint");
            Check(std::any_of(now.spaceman.free_queues[0].entries.begin(), now.spaceman.free_queues[0].entries.end(), [&](const auto& x) {
                return x.xid == now.container.superblock.xid && c.bitmap_block >= x.physical_block && c.bitmap_block - x.physical_block < x.block_count;
            }), "old bitmap is retired exactly at the new transaction XID");
        }
    }
}

void Across(VolumeImageOperation op, std::uint32_t per_chunk = 1024, bool explicit_bitmap = false)
{
    const bool grow = op == VolumeImageOperation::Grow;
    const auto blocks = grow ? (per_chunk == 32768 ? per_chunk - 32ull : per_chunk) : per_chunk + 128ull;
    const auto original = GeometryFixture(blocks, per_chunk, explicit_bitmap);
    const auto label = std::string(grow ? "grow-" : "shrink-") + std::to_string(per_chunk) + (explicit_bitmap ? "-bitmap" : "-implicit");
    auto r = Setup(label, op, original); r.target_bytes = (grow ? per_chunk + 128ull : per_chunk - 32ull) * 4096;
    const auto p = Prepare(r); Check(p.outcome == VolumeImageOutcome::Prepared, "two-chunk prepare: " + p.error);
    Check(Read(r.image) == original, "geometry prepare is byte identical");
    const auto done = Apply(r, p.token); Check(done.outcome == VolumeImageOutcome::Committed, "geometry commit: " + done.error);
    const auto post = Read(r.image); Geometry(post, r.target_bytes / 4096, grow ? 2 : 1);
    Preserve(original, post);
    const auto old = Checkpoint(original); const auto now = Checkpoint(post);
    Check(old.volumes.size() == now.volumes.size(), "peer inventory survives");
    for (std::size_t i = 0; i < old.volumes.size(); ++i) {
        const auto a = old.volumes[i].superblock_object.physical_block * 4096;
        const auto b = now.volumes[i].superblock_object.physical_block * 4096;
        Check(std::equal(original.begin() + a, original.begin() + a + 4096, post.begin() + b), "peer APSB unchanged");
    }
    for (const auto block : {240ull, 248ull}) Check(std::equal(original.begin() + block * 4096, original.begin() + (block + 1) * 4096,
        post.begin() + block * 4096), "both actual payloads unchanged");
    Check(Recover(r).outcome == VolumeImageOutcome::Committed && Read(r.image) == post, "new geometry terminal recovery");
    std::cout << "IMAGE " << label << " oldSHA=" << Sha(original) << " newSHA=" << Sha(post) << '\n';
    Pass("actual two-chunk grow/shrink image geometry and peers");
}

void WithinTwo(VolumeImageOperation op)
{
    const bool grow = op == VolumeImageOperation::Grow;
    const auto original = GeometryFixture(1152, 1024, true);
    auto r = Setup(grow ? "two-to-two-grow" : "two-to-two-shrink", op, original);
    r.target_bytes = (grow ? 1280ull : 1088ull) * 4096;
    const auto p = Prepare(r); Check(p.outcome == VolumeImageOutcome::Prepared, "second chunk bitmap COW: " + p.error);
    const auto done = Apply(r, p.token); Check(done.outcome == VolumeImageOutcome::Committed, done.error);
    const auto post = Read(r.image); Geometry(post, r.target_bytes / 4096, 2); Preserve(original, post);
    Check(Recover(r).outcome == VolumeImageOutcome::Committed && Read(r.image) == post, "second-chunk bitmap recovery");
    Pass("existing second chunk bitmap COW and exact deferred retirement");
}

void Boundaries(VolumeImageOperation op)
{
    const bool grow = op == VolumeImageOperation::Grow; const std::string name = grow ? "boundary-grow-" : "boundary-shrink-";
    const auto original = GeometryFixture(grow ? 1024 : 1152, 1024, !grow);
    auto control = Setup(name + "control", op, original); control.target_bytes = (grow ? 1152ull : 992ull) * 4096;
    const auto plan = Prepare(control); Check(plan.outcome == VolumeImageOutcome::Prepared, plan.error);
    unsigned writes = 0; const auto done = Apply(control, plan.token, [&](auto at) { if (at == "before-apple-device-write") ++writes; return true; });
    Check(done.outcome == VolumeImageOutcome::Committed && writes == 1, "one batch device-write hook: " + done.error);
    const auto expected = Read(control.image); const auto expected_hash = Sha(expected); const auto old_hash = Sha(original);
    std::vector<std::pair<std::string, unsigned>> cuts;
    for (const std::string stage : {"after-image-accept", "after-image-grow", "before-apple-prepublication-flush", "before-apple-checkpoint-switch",
        "before-apple-final-flush", "before-image-anchor", "after-image-anchor", "after-image-cleanup", "after-image-truncate", "before-image-complete"}) cuts.emplace_back(stage, 0);
    for (unsigned i = 0; i < writes; ++i) cuts.emplace_back("before-apple-device-write", i);
    unsigned index = 0;
    for (const auto& [stage, ordinal] : cuts) {
        auto r = Setup(name + std::to_string(index++), op, original); r.target_bytes = control.target_bytes;
        const auto p = Prepare(r); Check(p.outcome == VolumeImageOutcome::Prepared, "interruption prepare: " + p.error);
        unsigned seen = 0; bool hit = false;
        const auto partial = Apply(r, p.token, [&](auto at) { if (at == stage && seen++ == ordinal) { hit = true; return false; } return true; });
        Check(hit && partial.outcome == VolumeImageOutcome::RecoveryRequired, "actual interrupted boundary: " + partial.error);
        const auto interrupted = Read(r.image); const auto selected = Checkpoint(interrupted);
        Check(selected.container.superblock.xid == p.pre_xid || selected.container.superblock.xid == p.post_xid, "old or new complete checkpoint selected");
        const bool old = selected.container.superblock.xid == p.pre_xid;
        Check(selected.container.superblock.block_count * 4096 == (old ? r.expected_bytes : r.target_bytes), "selected generation has its own old/new geometry");
        rw::volume_image::Verify(interrupted, selected); ++checks;
        if (stage == "after-image-accept") Check(Sha(interrupted) == old_hash, "accept interruption exact old-image SHA");
        if (stage == "after-image-truncate" || stage == "before-image-complete") Check(Sha(interrupted) == expected_hash, "new geometry exact full-image SHA");
        const auto recovered = Recover(r); Check(recovered.outcome == VolumeImageOutcome::Committed, "original keeper geometry recovery: " + recovered.error);
        const auto post = Read(r.image); Check(post == expected && Sha(post) == expected_hash, "all replay paths match exact independently committed postimage SHA");
        Preserve(original, post); Check(Recover(r).outcome == VolumeImageOutcome::Committed && Read(r.image) == post, "recovery remains idempotent");
        std::cout << "RECOVERY " << name << stage << " ordinal=" << ordinal << " selected=" << (old ? "old" : "new") << " oldSHA=" << old_hash << " newSHA=" << expected_hash << '\n';
    }
    Pass("all eleven exposed publication boundaries select old/new geometry and recover exact SHA");
}

void Refused()
{
    auto image = GeometryFixture(1024, 512, true, 900);
    auto r = Setup("real-allocated-tail", VolumeImageOperation::Shrink, image); r.target_bytes = 512 * 4096;
    Check(Prepare(r).error == "VolumeResizeAllocatedTailRequiresRelocation" && Read(r.image) == image, "real second-chunk payload cannot be discarded");
    image = GeometryFixture(1152, 1024, true);
    r = Setup("stale-two-chunk", VolumeImageOperation::Shrink, image); r.target_bytes = 992 * 4096;
    auto p = Prepare(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
    auto changed = image; changed[240 * 4096] ^= std::byte{1}; Save(r.image, changed);
    Check(Apply(r, p.token).error == "VolumeImageStaleSource" && Read(r.image) == changed, "stale source refuses and preserves external change");
    r = Setup("busy-two-chunk-peer", VolumeImageOperation::Shrink, image); r.target_bytes = 992 * 4096;
    p = Prepare(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
    {
        WriteAheadLog lease({r.sibling_wals.at(202), "apfs-vol:" + r.container_uuid + ":202"}); Check(lease.AcquireWriterLeaseOnly(), "actual peer WAL lease");
        Check(Apply(r, p.token).error == "VolumeImageWalBusy" && Read(r.image) == image, "peer pins prohibit publication");
    }
    Check(Apply(r, p.token).outcome == VolumeImageOutcome::Committed, "same intent succeeds once peer releases");
    r = Setup("missing-two-chunk-authority", VolumeImageOperation::Shrink, image); r.target_bytes = 992 * 4096;
    bool missing = false; try { (void)rw::volume_image::PlanResize(image, r); } catch (const std::exception& e) { missing = std::string(e.what()) == "VolumeImageRetentionAuthorityRequired"; }
    Check(missing && Read(r.image) == image, "pure planner never creates its own keeper authority");
    r = Setup("two-chunk-recovery-conflict", VolumeImageOperation::Shrink, image); r.target_bytes = 992 * 4096;
    p = Prepare(r); Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
    Check(Apply(r, p.token, [](auto at) { return at != "after-image-accept"; }).outcome == VolumeImageOutcome::RecoveryRequired, "accepted corruption fixture");
    const auto accepted = Read(p.journal); changed = image; changed[248 * 4096] ^= std::byte{1}; Save(r.image, changed);
    const auto failed = Recover(r); Check(failed.outcome == VolumeImageOutcome::RecoveryRequired && failed.error == "VolumeImageRecoveryUnrelatedBytesChanged" &&
        Read(r.image) == changed && Read(p.journal) == accepted, "actual peer payload corruption preserves accepted evidence");
    auto pressure = GeometryFixture(1152, 1024, true); const auto cp = Checkpoint(pressure);
    auto apsb = Bytes(pressure.begin() + cp.volumes[0].superblock_object.physical_block * 4096,
        pressure.begin() + (cp.volumes[0].superblock_object.physical_block + 1) * 4096);
    PutU64LE(apsb, 0x48, cp.spaceman.devices[0].free_count + cp.volumes[0].superblock.space.allocated_block_count - 16);
    FletcherForBlock(apsb, 4096); std::copy(apsb.begin(), apsb.end(), pressure.begin() + cp.volumes[0].superblock_object.physical_block * 4096);
    rw::volume_image::Verify(pressure, Checkpoint(pressure)); ++checks;
    r = Setup("two-chunk-reserve-pressure", VolumeImageOperation::Shrink, pressure); r.target_bytes = 992 * 4096;
    const auto low = Prepare(r);
    Check(low.outcome == VolumeImageOutcome::Refused && low.error == "VolumeImageVerificationIncomplete:SharedSpaceReservesExceedFree" && Read(r.image) == pressure,
        "insufficient post-shrink reserve capacity refuses unchanged: " + low.error);
    Pass("allocated tail stale source missing authority peer WAL lease and accepted payload conflict refuse");
}

void HiddenOwners()
{
    auto original = GeometryFixture(1152, 1024, true); const auto initial = Checkpoint(original);
    std::string error; HistoryMemoryTarget target(original); VectorRandomAccessSource source(original);
    AppleVolumeTransactionRequest mutation; mutation.volume_object_id = 201;
    mutation.preserve_source_metadata = true; mutation.last_modification_time = 1700000000000000000ull;
    Check(ReadAppleVolumeFileSystemRecords(source, initial.container, initial.volumes[0], mutation.filesystem_records, error), error);
    AppleVolumeTransactionPlan published;
    Check(PlanAppleVolumeTransaction(source, initial, mutation, published, error), "actual metadata-preserving COW: " + error);
    Check(ExecuteAppleCheckpointPublication(target, published.commit.publication, error), error);
    const auto historical_root = initial.volumes[0].root_tree;
    // Author an older OMAP version referencing the real preserved source tree.
    // No allocation bits, queue entries, or snapshot-absence fields are edited.
    {
        const auto before = Checkpoint(original); VectorRandomAccessSource seed(original);
        const auto& map = before.volumes[0].object_map; std::vector<BtreeRecord> mappings;
        Check(ReadBtreeLeafRecords(seed, 4096, map.tree.physical_block, true, 0, before.container.superblock.xid, mappings, error), error);
        AppleOmapRecord old{historical_root.object_id, historical_root.xid, 0, 4096, historical_root.physical_block};
        BtreeRecord encoded; Check(EncodeAppleOmapRecord(old, encoded, error), error);
        if (std::none_of(mappings.begin(), mappings.end(), [&](const auto& r) { return r.key == encoded.key; })) mappings.push_back(encoded);
        Check(SortAppleBtreeRecords(mappings, AppleBtreeKeyOrder::ObjectMap, error), error);
        AppleBtreeOptions options; options.block_size = 4096; options.xid = map.tree.xid;
        options.root_object_id = map.tree.object_id; options.root_physical_block = map.tree.physical_block;
        options.storage_type = kObjectPhysical; options.subtype = kObjectTypeOmap;
        options.tree_flags = kAppleBtreePhysical; options.key_order = AppleBtreeKeyOrder::ObjectMap;
        options.fixed_key_size = options.fixed_value_size = 16; options.max_nodes = 1;
        AppleSerializedBtree tree; Check(SerializeAppleBtree(mappings, options, tree, error) && tree.objects.size() == 1, error);
        std::copy(tree.objects[0].bytes.begin(), tree.objects[0].bytes.end(), original.begin() + map.tree.physical_block * 4096);
    }
    const auto cp = Checkpoint(original); VectorRandomAccessSource changed(original);
    std::vector<std::uint64_t> metadata; std::vector<ApplePhysicalExtentRecord> payload;
    Check(LoadAppleSnapshotCheckpointOwners(changed, cp, metadata, payload, error) && !metadata.empty() && !payload.empty(), error);
    AppleSnapshotRetentionView visible;
    Check(LoadAppleSnapshotRetention(changed, cp, visible, error) && visible.identities.empty(), "current public snapshot inventory is empty");
    Check(cp.volumes[0].root_tree.physical_block != historical_root.physical_block &&
        std::find(visible.metadata_blocks.begin(), visible.metadata_blocks.end(), historical_root.physical_block) == visible.metadata_blocks.end() &&
        std::find(metadata.begin(), metadata.end(), historical_root.physical_block) != metadata.end(), "non-live historical root is absent from public census and present in complete hidden-owner census");
    Check(std::any_of(payload.begin(), payload.end(), [](const auto& x) { return x.physical_block == 240; }), "real original payload remains owned through the historical graph");
    for (const auto op : {VolumeImageOperation::Grow, VolumeImageOperation::Shrink}) {
        auto r = Setup(op == VolumeImageOperation::Grow ? "hidden-owner-grow" : "hidden-owner-shrink", op, original);
        r.target_bytes = (op == VolumeImageOperation::Grow ? 1280ull : 992ull) * 4096;
        const auto p = Prepare(r); Check(p.outcome == VolumeImageOutcome::Prepared, "hidden-owner resize: " + p.error);
        Check(Apply(r, p.token, [](auto at) { return at != "after-image-anchor"; }).outcome == VolumeImageOutcome::RecoveryRequired, "hidden-owner durable interruption");
        const auto recovered = Recover(r); Check(recovered.outcome == VolumeImageOutcome::Committed, recovered.error);
        const auto post = Read(r.image); Preserve(original, post); Check(Recover(r).outcome == VolumeImageOutcome::Committed && Read(r.image) == post, "hidden owner terminal recovery");
    }
    Pass("real preserved filesystem root behind an authored historical OMAP edge survives two-chunk grow/shrink recovery");
}

void KeeperChain()
{
    const auto original = GeometryFixture(1024);
    auto grow = Setup("keeper-cross-geometry-chain", VolumeImageOperation::Grow, original); grow.target_bytes = 1152 * 4096;
    const auto p = Prepare(grow); Check(p.outcome == VolumeImageOutcome::Prepared, p.error);
    const auto grown = Apply(grow, p.token); Check(grown.outcome == VolumeImageOutcome::Committed, grown.error);
    const auto middle = Read(grow.image); const auto old_frame = Read(p.journal);
    auto shrink = Request(grow.journal_directory, VolumeImageOperation::Shrink, middle); shrink.target_bytes = 992 * 4096;
    const auto q = Prepare(shrink); Check(q.outcome == VolumeImageOutcome::Prepared, "new keeper admits old single-chunk original geometry: " + q.error);
    bool archive = false;
    for (const auto& entry : std::filesystem::directory_iterator(grow.journal_directory))
        if (entry.path().filename().wstring().ends_with(L".completed")) archive |= Read(entry.path()) == old_frame;
    Check(archive, "original grow keeper frame archived byte-identically with its own original geometry");
    Check(Apply(shrink, q.token, [](auto at) { return at != "after-image-anchor"; }).outcome == VolumeImageOutcome::RecoveryRequired, "new two-chunk original interrupted after anchor");
    const auto recovered = Recover(shrink); Check(recovered.outcome == VolumeImageOutcome::Committed, "new keeper original geometry recovery: " + recovered.error);
    const auto final = Read(grow.image); Geometry(final, 992, 1); Preserve(middle, final);
    const auto historical = Recover(grow);
    Check(historical.outcome == VolumeImageOutcome::RecoveryRequired && historical.error == "VolumeImageJournalBindingMismatch" && Read(grow.image) == final,
        "old request cannot select the newer canonical keeper or roll back smaller geometry: " + historical.error);
    Check(Recover(shrink).outcome == VolumeImageOutcome::Committed && Read(grow.image) == final, "current keeper recovery remains exact");
    std::cout << "CHAIN oldSHA=" << Sha(original) << " middleSHA=" << Sha(middle) << " newSHA=" << Sha(final) << '\n';
    Pass("old and new keeper originals keep distinct one/two-chunk geometry across restart recovery");
}
}

int wmain(int argc, wchar_t** argv)
{
    try {
        Check(argc == 3, "fresh scratch evidence directory and selector required"); root = argv[1]; std::filesystem::create_directories(root);
        const std::wstring mode = argv[2];
        if (mode == L"--grow") Across(VolumeImageOperation::Grow);
        else if (mode == L"--shrink") Across(VolumeImageOperation::Shrink, 1024, true);
        else if (mode == L"--large") { Across(VolumeImageOperation::Grow, 32768); Across(VolumeImageOperation::Shrink, 32768, true); }
        else if (mode == L"--large-grow") Across(VolumeImageOperation::Grow, 32768);
        else if (mode == L"--large-shrink") Across(VolumeImageOperation::Shrink, 32768, true);
        else if (mode == L"--all") { Across(VolumeImageOperation::Grow); Across(VolumeImageOperation::Shrink); Across(VolumeImageOperation::Shrink, 1024, true); }
        else if (mode == L"--bitmaps") { WithinTwo(VolumeImageOperation::Grow); WithinTwo(VolumeImageOperation::Shrink); }
        else if (mode == L"--recovery") { Boundaries(VolumeImageOperation::Grow); Boundaries(VolumeImageOperation::Shrink); }
        else if (mode == L"--refusals") Refused();
        else if (mode == L"--hidden") HiddenOwners();
        else if (mode == L"--chain") KeeperChain();
        else if (mode == L"--one-chunk") { Positive(VolumeImageOperation::Grow); Positive(VolumeImageOperation::Shrink); PolicyAndTail(VolumeImageOperation::Shrink); }
        else throw std::runtime_error("unknown selector");
        std::cout << "PASS groups=" << groups << " checks=" << checks << '\n'; return 0;
    } catch (const std::exception& ex) { std::cerr << "FAIL checks=" << checks << " " << ex.what() << '\n'; return 1; }
}
