// Ordered two-store write session gates over file-backed synthetic Fusion
// members (the FusionTestFixture image family), plus ordered checkpoint
// publication through ApfsFusionCheckpointTarget: covers atomic member
// binding, identity-driven role assignment, exact routed placement,
// admission refusals, ordered flush durability, budget/cancellation refusal,
// crash-before-switch safety, and full plan/publish/switch/rebind cycles
// with interruption matrices. Mount-free; regular temp files only.
#include "ApfsFusionWriteSession.h"
#include "ApfsFusionCheckpointTarget.h"
#include "AppleCheckpointPublisher.h"
#include "AppleSpacemanAllocator.h"
#include "AppleVolumeTransaction.h"
#include "FusionTestFixture.h"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

using namespace apfsaccess::catalog;
using namespace apfsaccess::fusiontest;
using namespace apfsaccess::testfixture;
using namespace apfsaccess::rw;
using namespace apfsaccess;
namespace
{
unsigned checks = 0, cases = 0;
void Check(bool ok, const std::string& why) { ++checks; if (!ok) throw std::runtime_error(why); }
void Pass(const std::string& name) { ++cases; std::cout << "PASS " << name << '\n'; }
namespace fs = std::filesystem;
fs::path WorkRoot()
{
    static unsigned long sequence = 0;
    auto dir = fs::temp_directory_path() /
        ("fusion-write-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(++sequence));
    Check(dir.root_name() == L"D:", "Fusion write artifacts require D: TEMP/TMP");
    std::error_code ec;
    Check(fs::create_directory(dir, ec) && !ec, "create unique Fusion write directory");
    return dir;
}
void SaveFile(const fs::path& path, const Bytes& bytes)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    Check(bool(out), "save member file");
}
Bytes LoadFile(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    Check(bool(in), "open member file for re-read");
    Bytes out;
    char ch = 0;
    while (in.get(ch)) out.push_back(static_cast<std::byte>(ch));
    Check(in.eof(), "member file fully read");
    return out;
}
Bytes Pattern(std::size_t bs, std::byte fill)
{
    return Bytes(static_cast<std::size_t>(bs), fill);
}
// Test-only writer lease: read/write access with read sharing, so live file
// sources can observe staged bytes concurrently. Production uses exclusive
// leases; the writer session itself is agnostic to how its handle was
// opened, and identity verification still binds the exact file.
std::shared_ptr<rw::BlockDevice> OpenSharedWriter(const fs::path& path, std::string& error)
{
    const auto handle = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (handle == INVALID_HANDLE_VALUE)
    {
        error = "test writer open failed";
        return {};
    }
    auto device = rw::BlockDevice::AdoptExclusiveRepairImage(path.wstring(), handle, error);
    if (!device) CloseHandle(handle);
    return device;
}
// Live file-backed member source: every read observes current file bytes,
// exactly like production locked-image members. This is what makes
// publication readback verification meaningful.
struct FileSource final : RandomAccessSource
{
    fs::path path;
    std::uint64_t expected_size = 0;
    std::shared_ptr<ApfsReadBudget> budget;
    std::uint64_t SizeBytes() const override { return expected_size; }
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override { return budget; }
    bool Read(std::uint64_t offset, std::size_t size, Bytes& out) const override
    {
        out.clear();
        std::error_code ec;
        const auto actual = fs::file_size(path, ec);
        if (ec || actual != expected_size) return false;
        if (budget && !budget->Read(size)) return false;
        std::ifstream in(path, std::ios::binary);
        if (!in) return false;
        in.seekg(static_cast<std::streamoff>(offset));
        out.resize(size);
        in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(size));
        if (!in || static_cast<std::size_t>(in.gcount()) != size) { out.clear(); return false; }
        return true;
    }
};
// One complete file-backed set: fixture bytes on two temp files, writable
// exclusive leases, a request carrying the REAL file identities, a store
// bound over LIVE file sources (every store read observes current file
// bytes, exactly like production locked-image members), and the writer
// under test. Rebinds always use fresh budgets so one gate never starves
// the next.
struct FileSet
{
    Fixture fixture;
    fs::path dir = WorkRoot();
    fs::path main_path = dir / L"main.apfs";
    fs::path tier2_path = dir / L"tier2.apfs";
    std::shared_ptr<rw::BlockDevice> main_device;
    std::shared_ptr<rw::BlockDevice> tier2_device;
    std::unique_ptr<ApfsFusionStore> store;
    std::unique_ptr<ApfsFusionWriteSession> writer;
    std::array<std::shared_ptr<std::atomic<bool>>, 2> present = {
        std::make_shared<std::atomic<bool>>(true), std::make_shared<std::atomic<bool>>(true)};
    std::shared_ptr<std::function<void()>> availability_hook = std::make_shared<std::function<void()>>();
    explicit FileSet(bool bind_writer = true, std::uint32_t block_size = 4096,
        std::uint64_t prefix_blocks = 0) : fixture(block_size, prefix_blocks)
    {
        SaveFile(main_path, fixture.sources[0]->bytes);
        SaveFile(tier2_path, fixture.sources[1]->bytes);
        std::string error;
        main_device = OpenSharedWriter(main_path, error);
        Check(bool(main_device), "open main writer lease: " + error);
        tier2_device = OpenSharedWriter(tier2_path, error);
        Check(bool(tier2_device), "open tier2 writer lease: " + error);
        for (std::size_t i = 0; i < 2; ++i)
        {
            rw::BlockDevice::StableImageIdentity identity{};
            auto& device = i ? tier2_device : main_device;
            Check(device->QueryHeldImageIdentity(identity), "query member identity");
            fixture.request.members[i].exact_identity = identity;
            fixture.request.members[i].path = (i ? tier2_path : main_path).wstring();
        }
        store = LiveBind(20, error);
        Check(bool(store), "live store binds: " + error);
        if (bind_writer)
        {
            writer = ApfsFusionWriteSession::Bind(*store, main_device, tier2_device, error);
            Check(bool(writer), "writer binds: " + error);
            Check(writer->BlockSize() == fixture.bs, "writer block size");
            Check(writer->MainBlocks() == 64 && writer->Tier2Blocks() == 32, "writer geometry");
            Check(writer->ContainerUuid() == std::string(32, 'a'), "writer container");
            Check(writer->CheckpointXid() == 20, "writer generation");
        }
    }
    ~FileSet()
    {
        writer.reset();
        store.reset();
        main_device.reset();
        tier2_device.reset();
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
    // Bind over live file bytes at the requested generation with a fresh
    // allowance. Used for the initial bind and every post-crash rebind.
    std::unique_ptr<ApfsFusionStore> LiveBind(std::uint64_t xid, std::string& error)
    {
        auto budget = std::make_shared<ApfsReadBudget>(
            10000, 64ULL * 1024 * 1024, 10000, 64ULL * 1024 * 1024);
        std::vector<ApfsFusionStore::TestMember> inputs;
        for (std::size_t i = 0; i < 2; ++i)
        {
            const auto path = i ? tier2_path : main_path;
            auto src = std::make_shared<FileSource>();
            src->path = path;
            src->expected_size = fixture.sources[i]->bytes.size();
            src->budget = budget;
            inputs.push_back({src, [path, available = present[i], hook = availability_hook] {
                if (*hook) (*hook)();
                std::error_code ec;
                return available->load() && fs::exists(path, ec) && !ec;
            }});
        }
        auto request = fixture.request;
        request.checkpoint_xid = xid;
        request.budget = budget;
        return ApfsFusionStore::BindTestSources(request, inputs, error);
    }
    // Crash model: every handle dropped first, then a checkpoint generation
    // is rebound from cold current file bytes. Returns the rebound store.
    std::unique_ptr<ApfsFusionStore> DropAndRebind(std::string& error, std::uint64_t xid = 20)
    {
        writer.reset();
        main_device.reset();
        tier2_device.reset();
        return LiveBind(xid, error);
    }
};
void BindRefusals()
{
    FileSet set(false);
    std::string error;
    unsigned unavailable = 0;
    Check(!ApfsFusionWriteSession::Bind(*set.store, nullptr, set.tier2_device, error, &unavailable),
        "null device accepted");
    Check(error == "FusionWriteDeviceMissing", "null device code: " + error);
    Check(!ApfsFusionWriteSession::Bind(*set.store, set.main_device, set.main_device, error, &unavailable),
        "duplicated device accepted");
    Check(error == "FusionWriteDeviceMissing", "duplicated device code: " + error);
    // A foreign file matches neither bound identity: both roles unclaimed.
    const auto foreign = set.dir / L"foreign.apfs";
    SaveFile(foreign, Bytes(set.fixture.bs * 4, std::byte{0xE5}));
    auto outsider = rw::BlockDevice::OpenExclusiveManagementImage(foreign.wstring(), 0, error);
    Check(bool(outsider), "open foreign lease: " + error);
    Check(!ApfsFusionWriteSession::Bind(*set.store, set.main_device, outsider, error, &unavailable),
        "foreign member accepted");
    Check(error == "FusionWriteDeviceIdentityMismatch", "foreign member code: " + error);
    Check(unavailable == 2, "foreign member masks the tier2 role");
    Pass("binding refuses null, duplicated, and foreign members");
}
void ReorderedBind()
{
    // Devices arrive tier2-first: roles still follow file identity.
    FileSet set(false);
    std::string error;
    auto writer = ApfsFusionWriteSession::Bind(*set.store, set.tier2_device, set.main_device, error);
    Check(bool(writer), "swapped devices bind: " + error);
    const auto pattern = Pattern(set.fixture.bs, std::byte{0xC3});
    Check(writer->WriteBlock(40, pattern, error), "main write after reorder: " + error);
    Check(writer->FlushOrdered(error), "flush after reorder: " + error);
    writer.reset(); set.main_device.reset(); set.tier2_device.reset();
    const auto bytes = LoadFile(set.main_path);
    const auto at = static_cast<std::ptrdiff_t>(40 * set.fixture.bs);
    Check(std::equal(pattern.begin(), pattern.end(), bytes.begin() + at), "reordered write lands on main");
    Pass("swapped devices still route by identity");
}
void RoutingExactness()
{
    FileSet set;
    const auto bs = set.fixture.bs;
    const auto main_block = 40ULL, tier_block = set.fixture.TierBlock() + 10;
    const auto main_pattern = Pattern(bs, std::byte{0xA5});
    const auto tier_pattern = Pattern(bs, std::byte{0x5A});
    std::string error;
    Check(set.writer->WriteBlock(main_block, main_pattern, error), "main write: " + error);
    Check(set.writer->WriteBlock(tier_block, tier_pattern, error), "tier2 write: " + error);
    Check(set.writer->FlushOrdered(error), "ordered flush: " + error);
    const auto counters = set.writer->counters();
    Check(counters.main_blocks_written == 1 && counters.tier2_blocks_written == 1 &&
        counters.main_flushes == 1 && counters.tier2_flushes == 1, "exact write/flush accounting");
    set.writer.reset(); set.main_device.reset(); set.tier2_device.reset();
    const auto main_bytes = LoadFile(set.main_path);
    const auto tier_bytes = LoadFile(set.tier2_path);
    const auto main_at = static_cast<std::ptrdiff_t>(main_block * bs);
    Check(std::equal(main_pattern.begin(), main_pattern.end(), main_bytes.begin() + main_at),
        "main bytes at routed offset");
    const auto tier_at = static_cast<std::ptrdiff_t>(10 * bs);
    Check(std::equal(tier_pattern.begin(), tier_pattern.end(), tier_bytes.begin() + tier_at),
        "tier2 bytes at routed offset");
    // Untouched neighbors still carry fixture bytes.
    Check(std::equal(set.fixture.sources[0]->bytes.begin() + static_cast<std::ptrdiff_t>(41 * bs),
        set.fixture.sources[0]->bytes.begin() + static_cast<std::ptrdiff_t>(42 * bs),
        main_bytes.begin() + static_cast<std::ptrdiff_t>(41 * bs)), "main neighbor preserved");
    Check(std::equal(set.fixture.sources[1]->bytes.begin() + static_cast<std::ptrdiff_t>(11 * bs),
        set.fixture.sources[1]->bytes.begin() + static_cast<std::ptrdiff_t>(12 * bs),
        tier_bytes.begin() + static_cast<std::ptrdiff_t>(11 * bs)), "tier2 neighbor preserved");
    Pass("writes land on the owning member at routed offsets");
}
void AdmissionRefusals()
{
    FileSet set;
    const auto bs = set.fixture.bs;
    std::string error;
    const Bytes overgrown(bs + 512, std::byte{1}), empty, runt(bs - 1, std::byte{1});
    Check(!set.writer->WriteBlock(40, overgrown, error) && error == "FusionWriteBlockUnaligned",
        "oversize write refused: " + error);
    Check(!set.writer->WriteBlock(40, runt, error) && error == "FusionWriteBlockUnaligned",
        "runt write refused: " + error);
    Check(!set.writer->WriteBlock(40, empty, error) && error == "FusionWriteBlockUnaligned",
        "empty write refused: " + error);
    Check(!set.writer->WriteBlock(64, Pattern(bs, std::byte{2}), error), "address gap accepted");
    Check(!set.writer->WriteBlock(set.fixture.TierBlock() + 32, Pattern(bs, std::byte{2}), error),
        "past-end tier2 accepted");
    Check(!set.writer->WriteBlock(UINT64_MAX, Pattern(bs, std::byte{2}), error), "overflow address accepted");
    const auto counters = set.writer->counters();
    Check(counters.main_blocks_written == 0 && counters.tier2_blocks_written == 0, "refusals stage nothing");
    Pass("misaligned and out-of-range writes refuse before any I/O");
}
void CrashBeforeSwitch()
{
    FileSet set;
    const auto bs = set.fixture.bs;
    std::string error;
    // Live metadata reference bytes captured before any write.
    const auto live_main = set.fixture.sources[0]->bytes;
    const auto live_tier = set.fixture.sources[1]->bytes;
    Check(set.writer->WriteBlock(40, Pattern(bs, std::byte{0xD1}), error), "crash write main: " + error);
    Check(set.writer->WriteBlock(set.fixture.TierBlock() + 10, Pattern(bs, std::byte{0xD2}), error),
        "crash write tier2: " + error);
    // Interrupt before any flush: drop every handle without flushing.
    auto rebound = set.DropAndRebind(error);
    Check(bool(rebound), "old checkpoint rebinds after interruption: " + error);
    Check(rebound->Checkpoint().superblock.xid == 20, "interrupted generation stays old");
    auto same = [&](std::size_t member, std::uint64_t first, std::uint64_t last, const Bytes& before) {
        const auto path = member ? set.tier2_path : set.main_path;
        const auto bytes = LoadFile(path);
        for (auto block = first; block < last; ++block)
        {
            const auto at = static_cast<std::ptrdiff_t>(block * bs);
            if (!std::equal(before.begin() + at, before.begin() + at + bs, bytes.begin() + at))
                return false;
        }
        return true;
    };
    Check(same(0, 0, 24, live_main) && same(1, 0, 8, live_tier), "live metadata untouched by interruption");
    Pass("interruption before flush keeps the old checkpoint selectable");
}
void OrderedFlushDurability()
{
    FileSet set;
    const auto bs = set.fixture.bs;
    std::string error;
    const auto live_main = set.fixture.sources[0]->bytes;
    const auto main_pattern = Pattern(bs, std::byte{0xE1});
    const auto tier_pattern = Pattern(bs, std::byte{0xE2});
    Check(set.writer->WriteBlock(40, main_pattern, error), "durable write main: " + error);
    Check(set.writer->WriteBlock(set.fixture.TierBlock() + 10, tier_pattern, error), "durable write tier2: " + error);
    Check(set.writer->FlushOrdered(error), "ordered flush: " + error);
    auto rebound = set.DropAndRebind(error);
    Check(bool(rebound), "checkpoint rebinds after flush: " + error);
    Check(rebound->Checkpoint().superblock.xid == 20, "flushed writes keep the old generation");
    const auto main_bytes = LoadFile(set.main_path);
    const auto tier_bytes = LoadFile(set.tier2_path);
    Check(std::equal(main_pattern.begin(), main_pattern.end(),
        main_bytes.begin() + static_cast<std::ptrdiff_t>(40 * bs)), "flushed main bytes durable");
    Check(std::equal(tier_pattern.begin(), tier_pattern.end(),
        tier_bytes.begin() + static_cast<std::ptrdiff_t>(10 * bs)), "flushed tier2 bytes durable");
    for (auto block : {8ULL, 9ULL, 16ULL, 17ULL})
    {
        const auto at = static_cast<std::ptrdiff_t>(block * bs);
        Check(std::equal(live_main.begin() + at, live_main.begin() + at + bs, main_bytes.begin() + at),
            "live metadata identical after flush");
    }
    Pass("ordered flush makes both members durable without moving the generation");
}
void BudgetAndCancel()
{
    FileSet set;
    std::string error;
    // Exhaust the live shared allowance (not the fixture template budget,
    // which no bound store uses): the next write must refuse.
    Check(bool(set.store->ReadBudget()), "live budget present");
    set.store->ReadBudget()->LimitRemainingTo(0, 0, 0, 0);
    Check(!set.writer->WriteBlock(40, Pattern(set.fixture.bs, std::byte{3}), error),
        "exhausted budget accepted a write");
    Check(!error.empty(), "budget refusal explains itself");
    Pass("exhausted allowance refuses writes");
}

// ---- Ordered checkpoint publication ----
struct AdvanceParts
{
    AppleCheckpointPublicationPlan plan;
    Bytes switch_bytes;
    std::uint64_t switch_slot = 0;
    Bytes descriptor_bytes;
    std::uint64_t descriptor_slot = 0;
    Bytes payload_main;
    Bytes payload_tier;
    std::vector<std::uint64_t> remapped_blocks;
};
static Bytes SliceBytes(const Bytes& bytes, std::uint64_t block, std::uint32_t bs)
{
    return Bytes(bytes.begin() + static_cast<std::ptrdiff_t>(block * bs),
        bytes.begin() + static_cast<std::ptrdiff_t>((block + 1) * bs));
}
// Hand-built generation advance over a FileSet: two allocator-style payload
// blocks (one per tier), a new checkpoint descriptor at the ring's next free
// slot(s), and a new NXSB immediately after. Ring geometry is discovered at
// runtime, so no fixture layout is assumed beyond validity. Descriptors are
// never rewritten in place: the old generation's map stays intact so the old
// NXSB still validates, and the new generation forms a contiguous
// index/len/next range like production PlanAppleCheckpointPublication.
AdvanceParts BuildAdvanceParts(FileSet& set)
{
    AdvanceParts out;
    const auto bs = set.fixture.bs;
    const auto main_bytes = LoadFile(set.main_path);
    out.payload_main = Pattern(bs, std::byte{0xA5});
    out.payload_tier = Pattern(bs, std::byte{0x5A});
    // Live descriptor location from the bound view, never assumed.
    const auto& maps = set.store->Checkpoint().checkpoint_map_blocks;
    Check(!maps.empty(), "live checkpoint has a descriptor");
    const auto old_descriptor_slot = maps[0];
    const auto old_descriptor_bytes = SliceBytes(main_bytes, old_descriptor_slot, bs);
    auto anchor = ParseNxSuperblock(SliceBytes(main_bytes, 0, bs));
    Check(anchor.has_value() && anchor->xid == 20, "live anchor parses at xid 20");
    const auto base = anchor->xp_desc_base_block;
    const auto count = anchor->xp_desc_block_count;
    Check(count && count <= 65536, "sane descriptor ring");
    const auto old_index = anchor->xp_desc_index;
    const auto old_len = anchor->xp_desc_len;
    const auto old_next = anchor->xp_desc_next;
    Check(old_next < count && old_index < count && old_len <= count, "sane ring pointers");
    // Same mappings, next generation: one map block suffices for this fixture
    // family (2 mappings fit in a single 4K block). Production splits larger
    // sets; this hand plan stays exact by requiring the single-block shape.
    const auto entry_count = ReadU32LE(old_descriptor_bytes, 0x24).value_or(0);
    Check(entry_count && entry_count <= 128, "sane mapping count");
    const std::uint32_t mappings_per_block = (bs - 0x28) / 0x28;
    Check(mappings_per_block != 0, "mappings fit in a block");
    const std::uint32_t map_blocks = (entry_count + mappings_per_block - 1) / mappings_per_block;
    Check(map_blocks == 1, "hand plan covers the single-map shape");
    const std::uint32_t descriptor_length = map_blocks + 1;
    Check(descriptor_length <= count, "descriptor fits the ring");
    const std::uint32_t descriptor_index = old_next;
    const std::uint32_t superblock_relative =
        (descriptor_index + map_blocks) % count;
    out.descriptor_slot = base + descriptor_index;
    out.switch_slot = base + superblock_relative;
    // New slots must be reclaimable: no valid NXSB (fresh ring positions in
    // these tests). Never overwrite the live descriptor in place.
    for (std::uint32_t offset = 0; offset < descriptor_length; ++offset)
    {
        const auto slot = base + (descriptor_index + offset) % count;
        Check(!ParseNxSuperblock(SliceBytes(main_bytes, slot, bs)),
            "new ring slots are reclaimable");
    }
    // New descriptor: same mappings COW-copied to the data ring's next free
    // slots, new location/identity/generation. Old blocks stay intact so the
    // old generation remains selectable until the switch.
    const auto dbase = anchor->xp_data_base_block;
    const auto dcount = anchor->xp_data_block_count;
    const auto dindex = anchor->xp_data_index;
    const auto dlen = anchor->xp_data_len;
    const auto dnext = anchor->xp_data_next;
    Check(dcount && dcount <= 65536 && dnext < dcount && dindex < dcount && dlen <= dcount,
        "sane data ring pointers");
    // This fixture family maps two single-block objects; production COWs
    // arbitrary sets via the allocator, proven separately.
    Check(dlen == entry_count, "hand plan covers the flat data shape");
    const std::uint32_t new_data_index = dnext;
    const std::uint32_t new_data_len = dlen;
    const std::uint32_t new_data_next = (new_data_index + new_data_len) % dcount;
    out.descriptor_bytes = old_descriptor_bytes;
    Put(out.descriptor_bytes, 0x08, out.descriptor_slot);
    Put(out.descriptor_bytes, 0x10, std::uint64_t{21});
    for (std::uint32_t index = 0; index < entry_count; ++index)
    {
        const auto at = 0x28 + static_cast<std::size_t>(index) * 0x28;
        const auto old_physical = ReadU64LE(old_descriptor_bytes, at + 0x20).value_or(UINT64_MAX);
        Check(old_physical != UINT64_MAX, "old mapping decodes");
        const auto new_physical = dbase + (new_data_index + index) % dcount;
        Put(out.descriptor_bytes, at + 0x20, new_physical);
    }
    Seal(out.descriptor_bytes);
    out.switch_bytes = SliceBytes(main_bytes, 0, bs);
    Put(out.switch_bytes, 0x10, std::uint64_t{21});
    Put(out.switch_bytes, 0x60, std::uint64_t{22});
    Put(out.switch_bytes, 0x88, static_cast<std::uint64_t>(descriptor_index), 4);
    Put(out.switch_bytes, 0x8C, static_cast<std::uint64_t>(descriptor_length), 4);
    Put(out.switch_bytes, 0x80,
        static_cast<std::uint64_t>((descriptor_index + descriptor_length) % count), 4);
    Put(out.switch_bytes, 0x90, static_cast<std::uint64_t>(new_data_index), 4);
    Put(out.switch_bytes, 0x94, static_cast<std::uint64_t>(new_data_len), 4);
    Put(out.switch_bytes, 0x84, static_cast<std::uint64_t>(new_data_next), 4);
    Seal(out.switch_bytes);
    auto& plan = out.plan;
    plan.block_size = bs;
    plan.expected_checkpoint_xid = 20;
    plan.transaction_xid = 21;
    plan.next_object_id = 100;
    AppleCheckpointPlannedWrite payload_a;
    payload_a.kind = AppleCheckpointWriteKind::AllocatorOwned;
    payload_a.physical_block = 40;
    payload_a.bytes = out.payload_main;
    AppleCheckpointPlannedWrite payload_b;
    payload_b.kind = AppleCheckpointWriteKind::AllocatorOwned;
    payload_b.physical_block = set.fixture.TierBlock() + 10;
    payload_b.bytes = out.payload_tier;
    AppleCheckpointPlannedWrite descriptor;
    descriptor.kind = AppleCheckpointWriteKind::CheckpointMap;
    descriptor.physical_block = out.descriptor_slot;
    descriptor.bytes = out.descriptor_bytes;
    plan.before_superblock_writes = {descriptor, payload_a, payload_b};
    // Mapped objects are COW-copied to the data ring's next free slots with
    // the xid bumped and re-checksummed. (Production placement comes from the
    // allocator, proven separately. What matters here is that old blocks stay
    // intact for pre-switch recovery while every new mapping validates.)
    // Entry layout mirrors ParseCheckpointMapBlock: count at 0x24, records of
    // 0x28 bytes from 0x28, physical block at record +0x20.
    // entry_count was validated above when sizing the new descriptor ring.
    for (std::uint32_t index = 0; index < entry_count; ++index)
    {
        const auto at = 0x28 + static_cast<std::size_t>(index) * 0x28;
        const auto old_block = ReadU64LE(old_descriptor_bytes, at + 0x20).value_or(UINT64_MAX);
        const auto new_block = ReadU64LE(out.descriptor_bytes, at + 0x20).value_or(UINT64_MAX);
        Check(old_block != UINT64_MAX && new_block != UINT64_MAX, "mapping block decodes");
        Check(new_block == dbase + (new_data_index + index) % dcount, "COW placement matches the ring");
        auto object = SliceBytes(main_bytes, old_block, bs);
        PutU64LE(object, 0x10, std::uint64_t{21});
        Seal(object);
        AppleCheckpointPlannedWrite remap;
        remap.kind = AppleCheckpointWriteKind::CheckpointData;
        remap.physical_block = new_block;
        remap.bytes = std::move(object);
        plan.before_superblock_writes.push_back(std::move(remap));
        out.remapped_blocks.push_back(new_block);
    }
    AppleCheckpointPlannedWrite staged;
    staged.kind = AppleCheckpointWriteKind::CheckpointSuperblock;
    staged.physical_block = out.switch_slot;
    staged.object_id = anchor->object_id;
    staged.bytes = out.switch_bytes;
    plan.superblock_write = staged;
    return out;
}
void TargetRoutesAndRefuses()
{
    FileSet set;
    const auto bs = set.fixture.bs;
    ApfsFusionCheckpointTarget target(*set.store, *set.writer, bs);
    std::vector<std::byte> out;
    Check(target.ReadBlock(40, bs, out), "target reads main");
    Check(!target.ReadBlock(40, bs + 512, out) && out.empty(), "wrong block size accepted");
    const auto tier = set.fixture.TierBlock() + 10;
    const auto pattern = Pattern(bs, std::byte{0x71});
    Check(target.WriteBlock(tier, pattern), "target writes tier2");
    std::vector<std::byte> wide(bs * 2, std::byte{0x72});
    Check(target.WriteBlock(41, wide), "multi-block spanning write refused");
    Check(!target.WriteBlock(40, {}), "empty write accepted");
    Check(!target.WriteBlock(UINT64_MAX, pattern), "overflow address accepted");
    Check(target.Flush(), "target flush delegates ordered");
    const auto counters = set.writer->counters();
    Check(counters.tier2_blocks_written == 1 && counters.tier2_flushes == 1 &&
        counters.main_flushes == 1, "target operations accounted per member");
    Pass("checkpoint target routes, splits, and refuses by member geometry");
}
void TargetBindingAndRangeAtomicity()
{
    FileSet set, foreign;
    const auto bs = set.fixture.bs;
    Bytes out;
    ApfsFusionCheckpointTarget wrong_store(*foreign.store, *set.writer, bs);
    Check(!wrong_store.ReadBlock(40, bs, out) && out.empty(), "foreign target read refused");
    Check(!wrong_store.WriteBlock(40, Pattern(bs, std::byte{0x87})), "foreign target write refused");
    Check(!wrong_store.Flush(), "foreign target flush refused");
    std::string error;
    auto duplicate = set.LiveBind(20, error);
    Check(bool(duplicate), "second store binding over the same files");
    ApfsFusionCheckpointTarget wrong_binding(*duplicate, *set.writer, bs);
    Check(!wrong_binding.WriteBlock(40, Pattern(bs, std::byte{0x88})),
        "same files and generation do not authorize another store binding");
    for (const auto size : {0u, bs / 2, bs * 2})
    {
        ApfsFusionCheckpointTarget wrong_size(*set.store, *set.writer, size);
        Check(!wrong_size.ReadBlock(40, size, out) && out.empty(), "wrong target geometry read refused");
        Check(!wrong_size.WriteBlock(40, Pattern(bs, std::byte{0x89})), "wrong target geometry write refused");
        Check(!wrong_size.Flush(), "wrong target geometry flush refused");
    }
    ApfsFusionCheckpointTarget target(*set.store, *set.writer, bs);
    const auto main_before = LoadFile(set.main_path), tier_before = LoadFile(set.tier2_path);
    const auto wide = Pattern(2 * bs, std::byte{0x8A});
    Check(!target.WriteBlock(63, wide), "main end-spanning write refused");
    Check(!target.WriteBlock(set.fixture.TierBlock() + 31, wide), "tier2 end-spanning write refused");
    Check(LoadFile(set.main_path) == main_before && LoadFile(set.tier2_path) == tier_before,
        "invalid range leaves both full files byte-identical");
    Check(set.writer->counters().main_blocks_written == 0 &&
        set.writer->counters().tier2_blocks_written == 0, "range refusal writes no prefix");
    Check(target.WriteBlock(62, wide) && target.WriteBlock(set.fixture.TierBlock() + 30, wide),
        "exact-end spans write successfully after validation refusals");
    Check(target.Flush(), "exact-end spans flush");
    Pass("target binds exact store and validates complete ranges before staging");
}
void HeldWriterContract()
{
    {
        FileSet set(false);
        set.main_device.reset(); set.tier2_device.reset();
        std::string error;
        auto main = BlockDevice::OpenStableReadOnlyImage(set.main_path.wstring(), error);
        auto tier = BlockDevice::OpenStableReadOnlyImage(set.tier2_path.wstring(), error);
        Check(main && tier, "open held read-only members");
        Check(!ApfsFusionWriteSession::Bind(*set.store, main, tier, error) &&
            error == "FusionWriteHeldWriterRequired", "read-only devices cannot bind a writer: " + error);
        Check(!main->HasWriteHandle() && !tier->HasWriteHandle(), "binding does not open writer handles");
    }
    {
        FileSet set(false);
        set.main_device.reset();
        std::string error;
        auto offset = BlockDevice::OpenExclusiveManagementImage(set.main_path.wstring(), 4096, error);
        Check(bool(offset), "open offset device");
        Check(!ApfsFusionWriteSession::Bind(*set.store, offset, set.tier2_device, error) &&
            error == "FusionWriteDeviceBaseOffsetUnsupported", "double-offset device refused: " + error);
    }
    Pass("binding requires held writable image handles and image-relative addressing");
}
void StopOnUnavailableSet()
{
    for (std::size_t missing = 0; missing < 2; ++missing)
    {
        FileSet set;
        std::string error;
        const auto main_before = LoadFile(set.main_path), tier_before = LoadFile(set.tier2_path);
        set.present[missing]->store(false);
        const auto survivor = missing == 0 ? set.fixture.TierBlock() + 10 : 40;
        Check(!set.writer->WriteBlock(survivor, Pattern(set.fixture.bs, std::byte{0x91}), error),
            "missing unused member stops surviving-member write");
        Check(error == "FusionWriteStoreUnavailable:FusionMemberDisappearedOrChanged" &&
            set.writer->LastError() == error, "missing-member diagnostic retained");
        Check(set.store->UnavailableMembers() == (1u << missing), "exact unavailable role mask");
        set.present[missing]->store(true);
        Check(!set.writer->FlushOrdered(error), "returning member does not revive poisoned session");
        const auto counts = set.writer->counters();
        Check(counts.main_flushes == 0 && counts.tier2_flushes == 0, "missing member prevents both flushes");
        Check(LoadFile(set.main_path) == main_before && LoadFile(set.tier2_path) == tier_before,
            "member-loss refusal preserves both files");
    }
    {
        FileSet set;
        std::string error;
        const auto main_before = LoadFile(set.main_path);
        Check(set.tier2_device->Write(32ULL * set.fixture.bs, Pattern(set.fixture.bs, std::byte{0x92})),
            "simulate tier2 resize through held file handle");
        Check(!set.writer->WriteBlock(40, Pattern(set.fixture.bs, std::byte{0x93}), error) &&
            error == "FusionWriteMemberReplaced", "unused writable member resize stops main write: " + error);
        Check(set.writer->LastError() == error, "resize diagnostic propagated to caller");
        Check(LoadFile(set.main_path) == main_before, "resize refusal leaves survivor unchanged");
    }
    Pass("both member leases remain required and failures require a fresh session");
}
void CancellationAndFaults()
{
    {
        FileSet set;
        std::string error;
        set.main_device->SetWriteCacheInvalidationHookForTests([&set] { set.store->Cancel(); });
        Check(!set.writer->WriteBlock(40, Pattern(set.fixture.bs, std::byte{0x94}), error) &&
            error == "FusionWriteStoreUnavailable:FusionReadCancelled",
            "cancellation observed during final write prevents success publication: " + error);
        Check(set.writer->counters().main_blocks_written == 1, "already dispatched bytes remain accounted");
        set.main_device->SetWriteCacheInvalidationHookForTests({});
        Check(!set.writer->FlushOrdered(error), "cancelled in-flight write poisons subsequent barrier");
    }
    {
        FileSet set;
        std::string error;
        set.store->Cancel();
        Check(!set.writer->FlushOrdered(error) && error == "FusionWriteStoreUnavailable:FusionReadCancelled",
            "cancellation stops durability barrier: " + error);
        ApfsFusionCheckpointTarget target(*set.store, *set.writer, set.fixture.bs);
        Bytes out(7, std::byte{1});
        Check(!target.ReadBlock(40, set.fixture.bs, out) && out.empty(), "cancelled target clears read output");
        Check(!target.WriteBlock(40, Pattern(set.fixture.bs, std::byte{2})), "cancelled target refuses write");
        const auto counts = set.writer->counters();
        Check(counts.main_flushes == 0 && counts.tier2_flushes == 0, "cancelled barrier stages no flush");
    }
    {
        FileSet set;
        std::string error;
        SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_FLUSH", L"1");
        const bool flushed = set.writer->FlushOrdered(error);
        SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_FLUSH", nullptr);
        Check(!flushed && error == "FusionTier2FlushFailed", "tier2 flush fault code: " + error);
        Check(set.writer->counters().main_flushes == 0 && set.writer->counters().tier2_flushes == 0,
            "failed tier2 barrier never reaches main");
        Check(!set.writer->WriteBlock(40, Pattern(set.fixture.bs, std::byte{3}), error) &&
            error == "FusionTier2FlushFailed" && set.writer->LastError() == error,
            "flush fault stays fatal after injection removed");
    }
    {
        FileSet set;
        std::string error;
        *set.availability_hook = [&set] {
            if (set.writer->counters().tier2_flushes == 1)
                SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_FLUSH", L"1");
        };
        const bool flushed = set.writer->FlushOrdered(error);
        SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_FLUSH", nullptr);
        *set.availability_hook = {};
        Check(!flushed && error == "FusionMainFlushFailed", "main barrier fault code: " + error);
        Check(set.writer->counters().tier2_flushes == 1 && set.writer->counters().main_flushes == 0,
            "main failure follows successful tier2 barrier");
        Check(!set.writer->FlushOrdered(error) && error == "FusionMainFlushFailed",
            "main barrier failure requires new writer session");
    }
    for (const bool tier2 : {false, true})
    {
        FileSet set;
        std::string error;
        const auto before = LoadFile(set.main_path);
        const auto tier_before = LoadFile(set.tier2_path);
        SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_WRITE", L"fail");
        const bool written = set.writer->WriteBlock(tier2 ? set.fixture.TierBlock() + 10 : 40,
            Pattern(set.fixture.bs, std::byte{4}), error);
        SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_WRITE", nullptr);
        const auto expected = tier2 ? "FusionWriteIoFailure:tier2" : "FusionWriteIoFailure:main";
        Check(!written && error == expected, "member write fault code: " + error);
        Check(!set.writer->FlushOrdered(error) && error == expected,
            "write failure prevents publication barriers");
        Check(LoadFile(set.main_path) == before && LoadFile(set.tier2_path) == tier_before,
            "failed write preserves both files");
    }
    {
        FileSet set;
        const auto main_before = LoadFile(set.main_path), tier_before = LoadFile(set.tier2_path);
        set.store->ReadBudget()->LimitRemainingTo(10000, 64ULL * 1024 * 1024, 1, set.fixture.bs);
        ApfsFusionCheckpointTarget target(*set.store, *set.writer, set.fixture.bs);
        Check(!target.WriteBlock(40, Pattern(2 * set.fixture.bs, std::byte{5})), "whole span reserves allowance");
        Check(LoadFile(set.main_path) == main_before && LoadFile(set.tier2_path) == tier_before,
            "insufficient whole-span allowance writes no prefix");
    }
    Pass("cancellation, write and tier2 barrier failures stay closed with exact diagnostics");
}
void PrefixedLargeBlockFiles()
{
    FileSet set(true, 16384, 2);
    const auto bs = set.fixture.bs;
    std::string error;
    const auto main_before = LoadFile(set.main_path), tier_before = LoadFile(set.tier2_path);
    const auto main = Pattern(2 * bs, std::byte{0xA3}), tier = Pattern(2 * bs, std::byte{0xB3});
    ApfsFusionCheckpointTarget target(*set.store, *set.writer, bs);
    Check(target.WriteBlock(40, main) && target.WriteBlock(set.fixture.TierBlock() + 10, tier),
        "prefixed 16K members receive complete spans");
    Check(target.Flush(), "prefixed members flush");
    Bytes out;
    Check(target.ReadBlock(40, bs, out) && out == Pattern(bs, std::byte{0xA3}), "prefixed main readback");
    Check(target.ReadBlock(set.fixture.TierBlock() + 10, bs, out) && out == Pattern(bs, std::byte{0xB3}),
        "prefixed tier2 readback");
    auto expected_main = main_before, expected_tier = tier_before;
    std::copy(main.begin(), main.end(), expected_main.begin() + set.fixture.prefix + 40ULL * bs);
    std::copy(tier.begin(), tier.end(), expected_tier.begin() + set.fixture.prefix + 10ULL * bs);
    Check(LoadFile(set.main_path) == expected_main && LoadFile(set.tier2_path) == expected_tier,
        "whole-file comparison proves prefix and neighbors unchanged");
    auto rebound = set.DropAndRebind(error);
    Check(bool(rebound), "prefixed complete set rebinds after lease release: " + error);
    Pass("16K file-backed routing preserves nonzero image prefixes and surrounding bytes");
}
void FinalizeDerivesMirror()
{
    FileSet set;
    auto parts = BuildAdvanceParts(set);
    std::string error;
    Check(FinalizeFusionCheckpointPublication(*set.store, parts.plan, error),
        "finalize accepts the hand plan: " + error);
    const auto& mirror = parts.plan.fusion_tier2_anchor_write;
    Check(mirror.has_value(), "mirror attached");
    Check(mirror->kind == AppleCheckpointWriteKind::FusionTier2Anchor, "mirror kind");
    Check(mirror->physical_block == set.fixture.TierBlock(), "mirror targets tier2 anchor");
    Check(mirror->object_id == parts.plan.superblock_write.object_id, "mirror carries the superblock identity");
    auto parsed = ParseNxSuperblock(mirror->bytes);
    Check(parsed.has_value() && parsed->xid == 21, "mirror parses at the new generation");
    Check((mirror->bytes[0x50F] & std::byte{1}) == std::byte{1}, "mirror sets the tier role bit");
    Check(VerifyObjectChecksum(mirror->bytes, set.fixture.bs), "mirror checksum verifies");
    for (std::size_t i = 0; i < parts.switch_bytes.size(); ++i)
    {
        if (i < 8 || i == 0x50F) continue;
        Check(mirror->bytes[i] == parts.switch_bytes[i], "mirror differs outside checksum and role bit");
    }
    Pass("finalize derives an exact tier-2 anchor mirror");
}
void FinalizeRefusals()
{
    FileSet set;
    std::string error;
    {
        auto parts = BuildAdvanceParts(set);
        auto& writes = parts.plan.before_superblock_writes;
        writes[0].kind = AppleCheckpointWriteKind::CheckpointData;
        writes[0].physical_block = set.fixture.TierBlock() + 11;
        Check(!FinalizeFusionCheckpointPublication(*set.store, parts.plan, error) &&
            error == "AppleFusionSnapshotCheckpointNotMainLocal",
            "tier2 checkpoint write admitted: " + error);
    }
    {
        auto parts = BuildAdvanceParts(set);
        parts.plan.superblock_write.physical_block = set.fixture.TierBlock() + 5;
        Check(!FinalizeFusionCheckpointPublication(*set.store, parts.plan, error) &&
            error == "AppleFusionSnapshotCheckpointNotMainLocal",
            "tier2 switch admitted: " + error);
    }
    {
        auto parts = BuildAdvanceParts(set);
        parts.plan.superblock_write.bytes[0x50F] |= std::byte{1};
        Check(!FinalizeFusionCheckpointPublication(*set.store, parts.plan, error) &&
            error == "AppleFusionSnapshotAnchorUuidMismatch",
            "preset role bit admitted: " + error);
    }
    Pass("finalize refuses non-main-local and foreign anchors");
}
// Every block of both member files must match the pristine fixture bytes
// except the listed (member, block) pairs.
void ExpectUnchangedExcept(FileSet& set,
    const std::vector<std::pair<std::size_t, std::uint64_t>>& changed)
{
    const auto bs = set.fixture.bs;
    const std::uint64_t blocks[2] = {64, 32};
    for (std::size_t member = 0; member < 2; ++member)
    {
        const auto bytes = LoadFile(member ? set.tier2_path : set.main_path);
        const auto& pristine = set.fixture.sources[member]->bytes;
        Check(bytes.size() == pristine.size(), "member size stable");
        for (std::uint64_t block = 0; block < blocks[member]; ++block)
        {
            if (std::find(changed.begin(), changed.end(),
                    std::make_pair(member, block)) != changed.end())
                continue;
            const auto at = static_cast<std::ptrdiff_t>(block * bs);
            if (!std::equal(pristine.begin() + at, pristine.begin() + at + bs, bytes.begin() + at))
                throw std::runtime_error("unexpected mutation");
        }
    }
    ++checks;
}
void PublishAdvanceEndToEnd()
{
    FileSet set;
    const auto bs = set.fixture.bs;
    auto parts = BuildAdvanceParts(set);
    std::string error;
    Check(FinalizeFusionCheckpointPublication(*set.store, parts.plan, error),
        "finalize hand plan: " + error);
    ApfsFusionCheckpointTarget target(*set.store, *set.writer, bs);
    Check(ExecuteAppleCheckpointPublication(target, parts.plan, error),
        "publish advance: " + error);
    auto rebound = set.DropAndRebind(error, 21);
    Check(bool(rebound), "rebind new generation: " + error);
    Check(rebound->Checkpoint().superblock.xid == 21, "new generation selected");
    Check(!rebound->TierAheadSkewTolerated(), "clean state carries no skew");
    Bytes out;
    Check(rebound->Read(40ULL * bs, bs, out) && out == parts.payload_main,
        "main payload published");
    Check(rebound->Read((set.fixture.TierBlock() + 10) * bs, bs, out) && out == parts.payload_tier,
        "tier payload published");
    const auto main_bytes = LoadFile(set.main_path);
    const auto tier_bytes = LoadFile(set.tier2_path);
    Check(std::equal(parts.switch_bytes.begin(), parts.switch_bytes.end(),
        main_bytes.begin()), "main anchor carries the switch");
    const auto& mirror = parts.plan.fusion_tier2_anchor_write;
    Check(std::equal(mirror->bytes.begin(), mirror->bytes.end(), tier_bytes.begin()),
        "tier2 anchor carries the mirror");
    std::vector<std::pair<std::size_t, std::uint64_t>> changed = {{0, 0}, {0, parts.descriptor_slot},
        {0, 40}, {0, parts.switch_slot}, {1, 0}, {1, 10}};
    for (const auto block : parts.remapped_blocks) changed.emplace_back(0, block);
    ExpectUnchangedExcept(set, changed);
    Pass("ordered publication advances the generation on both members");
}
void PublishCrashMatrix()
{
    const char* stages[] = {"before-apple-device-write", "before-apple-prepublication-flush",
        "before-apple-fusion-anchor-mirror", "before-apple-checkpoint-switch", "before-apple-final-flush"};
    for (const char* refused : stages)
    {
        FileSet set;
        const auto bs = set.fixture.bs;
        auto parts = BuildAdvanceParts(set);
        std::string error;
        Check(FinalizeFusionCheckpointPublication(*set.store, parts.plan, error),
            "finalize crash plan: " + error);
        ApfsFusionCheckpointTarget target(*set.store, *set.writer, bs);
        const auto refused_stage = std::string(refused);
        const bool published = ExecuteAppleCheckpointPublication(target, parts.plan, error,
            [&](std::string_view stage) { return stage != refused_stage; });
        Check(!published, std::string("interruption at ") + refused + " published");
        if (refused_stage == "before-apple-device-write")
        {
            ExpectUnchangedExcept(set, {});
        }
        else if (refused_stage == "before-apple-checkpoint-switch" ||
            refused_stage == "before-apple-final-flush")
        {
            std::string detail;
            if (refused_stage == "before-apple-checkpoint-switch")
            {
                // Mirror flushed, switch never issued: no new superblock
                // exists, so the old generation stays selectable with the
                // exact tier-ahead skew flagged (mirror-only state, like the
                // dedicated skew gate). The new generation has no anchor.
                auto skewed = set.DropAndRebind(detail, 20);
                Check(bool(skewed), std::string("old rebindable after ") + refused + ": " + detail);
                Check(skewed->Checkpoint().superblock.xid == 20, "main stays authoritative");
                Check(skewed->TierAheadSkewTolerated(), "mirror skew reported");
                // The switch never issued, so the new generation has no
                // superblock in the ring: exact-21 load fails closed without
                // selecting anything.
                Check(!set.DropAndRebind(detail, 21) &&
                    detail == "CheckpointExactGenerationUnavailable",
                    "unswitched generation admitted: " + detail);
            }
            else
            {
                // Switch bytes are file-visible: forward recovery owns the new
                // generation. The old generation must refuse as newer-present.
                Check(!set.DropAndRebind(detail, 20) &&
                    detail == "FusionNewerCheckpointRequiresRecovery",
                    std::string("old rebindable after ") + refused);
                // The switch and both anchors are file-visible; only the
                // durability ordering is unproven. The new generation selects.
                auto forwarded = set.DropAndRebind(detail, 21);
                Check(bool(forwarded), std::string("forward state selects after ") + refused + ": " + detail);
                Check(forwarded->Checkpoint().superblock.xid == 21, "forwarded generation selected");
            }
        }
        else
        {
            auto rebound = set.DropAndRebind(error, 20);
            Check(bool(rebound), std::string("old rebinds after ") + refused + ": " + error);
            Check(rebound->Checkpoint().superblock.xid == 20, "old generation selected");
            Check(!rebound->TierAheadSkewTolerated(), "no skew without a mirror");
        }
    }
    Pass("interruption at every stage refuses or recovers by generation");
}
void SkewTolerance()
{
    FileSet set;
    const auto bs = set.fixture.bs;
    auto parts = BuildAdvanceParts(set);
    std::string error;
    Check(FinalizeFusionCheckpointPublication(*set.store, parts.plan, error),
        "finalize skew plan: " + error);
    // Mirror lands and flushes; the switch never happens: exact tier-ahead
    // skew must still select the main anchor with the skew flagged.
    const auto& mirror = parts.plan.fusion_tier2_anchor_write;
    Check(mirror.has_value(), "mirror present");
    Check(set.writer->WriteBlock(set.fixture.TierBlock(), mirror->bytes, error),
        "mirror-only write: " + error);
    Check(set.writer->FlushOrdered(error), "mirror flush: " + error);
    auto rebound = set.DropAndRebind(error, 20);
    Check(bool(rebound), "skewed set rebinds old: " + error);
    Check(rebound->Checkpoint().superblock.xid == 20, "main stays authoritative");
    Check(rebound->TierAheadSkewTolerated(), "skew is reported, not hidden");
    // Ahead by two and torn mirrors stay refused.
    {
        FileSet ahead;
        auto ahead_parts = BuildAdvanceParts(ahead);
        Check(FinalizeFusionCheckpointPublication(*ahead.store, ahead_parts.plan, error),
            "finalize skew-negative plan: " + error);
        auto over = ahead_parts.plan.fusion_tier2_anchor_write->bytes;
        PutU64LE(over, 0x10, std::uint64_t{22});
        Seal(over);
        Check(ahead.writer->WriteBlock(ahead.fixture.TierBlock(), over, error), "over-advance write: " + error);
        Check(ahead.writer->FlushOrdered(error), "over-advance flush: " + error);
        Check(!ahead.DropAndRebind(error, 20) && error == "FusionMemberAnchorGenerationMismatch",
            "ahead-by-two admitted: " + error);
    }
    {
        FileSet torn;
        std::string setup_error;
        Check(torn.writer->WriteBlock(torn.fixture.TierBlock(), Pattern(bs, std::byte{0x99}), setup_error),
            "torn write stages: " + setup_error);
        Check(torn.writer->FlushOrdered(setup_error), "torn flush: " + setup_error);
        Check(!torn.DropAndRebind(error), "torn tier2 anchor admitted");
        Check(!error.empty(), "torn refusal explains itself");
    }
    Pass("exact tier-ahead skew selects main; anything else refuses");
}
void SnapshotCreateEntryRefusals()
{
    FileSet set(false);
    std::string error;
    AppleSnapshotCreatePlan plan;
    AppleSnapshotCreateRequest bad;
    bad.volume_object_id = 101;
    bad.creation_time_ns = 0;
    Check(!PlanFusionSnapshotCreate(*set.store, bad, plan, error) &&
        error == "AppleSnapshotCreateRequestInvalid", "bad request admitted: " + error);
    AppleSnapshotCreateRequest ghost;
    ghost.volume_object_id = 999;
    ghost.name_utf8 = "ghost";
    ghost.creation_time_ns = 1700000000000000000ull;
    {
        const bool admitted = PlanFusionSnapshotCreate(*set.store, ghost, plan, error);
        // This synthetic fixture carries no Apple volumes/omap, so the rich
        // Apple view cannot load: Unloadable is the correct fail-closed code
        // here. VolumeMissing is proven when the Apple view loads (richer
        // fixtures / integration); both refuse without staging anything.
        Check(!admitted &&
            (error == "AppleSnapshotCreateVolumeMissing" ||
             error == "AppleFusionSnapshotCheckpointUnloadable"),
            "ghost volume admitted: " + error);
    }
    Check(bool(set.store->ReadBudget()), "live budget present");
    set.store->ReadBudget()->LimitRemainingTo(0, 0, 0, 0);
    AppleSnapshotCreateRequest starved = ghost;
    starved.volume_object_id = 101;
    starved.name_utf8 = "starved";
    Check(!PlanFusionSnapshotCreate(*set.store, starved, plan, error) &&
        error == "AppleFusionSnapshotStoreUnavailable", "starved store admitted: " + error);
    Pass("snapshot-create entry refuses bad requests, ghosts, and dead stores");
}
void AllocatorOperatesOnFusionView()
{
    // The single-device spaceman loader correctly refuses the two-tier shape
    // (fail-closed: Tier2Unsupported) because Fusion two-tier ownership needs
    // planner-level format truth (allocation placement, not just storage
    // routing). Full allocator Fusion operation belongs to the planner slice
    // (see remainder: planner/publisher/WAL integration), not this storage
    // publication-mechanics gate. This gate pins the refusal so a future
    // loader change cannot silently admit an unproven two-tier view.
    FileSet set;
    std::string error;
    AppleSpacemanView view;
    Check(!LoadAppleSpacemanOwnershipView(*set.store, set.store->Checkpoint(), view, error) &&
        error == "AppleSpacemanTier2Unsupported",
        "fusion two-tier view admitted: " + error);
    Pass("allocator defers two-tier ownership to the planner slice");
}
} // namespace
int main()
{
    try
    {
        BindRefusals(); ReorderedBind(); RoutingExactness(); AdmissionRefusals();
        CrashBeforeSwitch(); OrderedFlushDurability(); BudgetAndCancel();
        TargetRoutesAndRefuses(); FinalizeDerivesMirror(); FinalizeRefusals();
        TargetBindingAndRangeAtomicity(); HeldWriterContract(); StopOnUnavailableSet();
        CancellationAndFaults(); PrefixedLargeBlockFiles();
        PublishAdvanceEndToEnd(); PublishCrashMatrix(); SkewTolerance();
        SnapshotCreateEntryRefusals(); AllocatorOperatesOnFusionView();
        std::cout << "PASS " << cases << " cases, " << checks << " checks\n";
        return 0;
    }
    catch (const std::exception& e) { std::cerr << "FAIL after " << cases << " cases, " << checks << " checks: " << e.what() << '\n'; return 1; }
}
