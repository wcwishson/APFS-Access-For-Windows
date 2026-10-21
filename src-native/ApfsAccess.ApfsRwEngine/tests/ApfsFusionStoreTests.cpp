#include "ApfsFusionStore.h"
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
#include "FusionTestFixture.h"
using namespace apfsaccess::fusiontest;
namespace
{
unsigned checks = 0, cases = 0;
void Check(bool ok, const std::string& why) { ++checks; if (!ok) throw std::runtime_error(why); }
void Run(const char* name, const std::function<void()>& body)
{ body(); ++cases; std::cout << "PASS " << name << '\n'; }
void Reject(const char* name, const std::function<void(Fixture&)>& mutate, const char* reason,
    bool no_io = false)
{
    Run(name, [&] {
        Fixture f; mutate(f); std::string error;
        const auto before = f.Calls(); auto store = f.Bind(error);
        Check(!store, std::string(name) + " accepted");
        Check(error == reason, std::string(name) + " wrong error: " + error);
        if (no_io) Check(f.Calls() == before, "rejected binding performed I/O");
    });
}
void Routing()
{
    for (const auto bs : {4096U, 8192U, 16384U, 65536U})
    {
        Fixture f(bs, 2); auto s = f.Good(); std::string error; FusionRoute route;
        Check(s->Container().member_store_ids.size() == 2 && s->Container().total_blocks == 96,
            "not one complete logical container");
        Check(s->Members()[0].total_blocks == 64 && s->Members()[1].total_blocks == 32,
            "per-device geometry lost");
        for (std::size_t i = 0; i < 2; ++i)
        {
            const auto block = (i ? f.TierBlock() : 0) + 20;
            Check(s->MapPhysical(block, 3, bs, route, error), error);
            Check(route.image_offset == f.prefix + 20ULL * bs + 3, "wrong store offset");
            Check(route.role == (i ? FusionMemberRole::Tier2 : FusionMemberRole::Main), "wrong tier");
            Bytes out{std::byte{0xFF}};
            Check(s->ReadExtents({{block, bs - 3, 6}}, out, error), error);
            Check(out.size() == 6 && out[0] == std::byte(i ? 0xB1 : 0xA1) &&
                out[5] == std::byte(i ? 0xB2 : 0xA2), "in-member block crossing wrong");
        }
        Bytes out;
        Check(s->ReadExtents({{20, bs - 3, 3}, {f.TierBlock() + 20, 0, 4}}, out, error), error);
        Check(out == Bytes({std::byte{0xA1}, std::byte{0xA1}, std::byte{0xA1},
            std::byte{0xB1}, std::byte{0xB1}, std::byte{0xB1}, std::byte{0xB1}}), "cross-tier extent order wrong");
        Check(s->ReadMetadata(16, kObjectPhysical | kObjectTypeFs, 0, 16, 20, out, error), error);
        Check(s->ReadMetadata(f.TierBlock() + 4, kObjectPhysical | kObjectTypeFs, 0,
            f.TierBlock() + 4, 20, out, error), error);
        Check(!s->ReadMetadata(f.TierBlock() + 4, kObjectPhysical | kObjectTypeFs, 0, 4, 20, out, error) &&
            out.empty(), "wrong metadata identity accepted");
        Check(!s->ReadMetadata(16, kObjectPhysical | kObjectTypeFs, 0, 16, 21, out, error) && out.empty(),
            "future metadata accepted");
        Check(!s->ReadMetadata(16, kObjectPhysical | kObjectTypeFs, 1, 16, 20, out, error) && out.empty(),
            "wrong metadata subtype accepted");
        Check(s->Read((64ULL * bs) - 1, 1, out) && out.size() == 1, "main final byte rejected");
        Check(s->Read(kFusionTier2ByteAddress + 32ULL * bs - 1, 1, out), "tier final byte rejected");
    }
}
void Bounds()
{
    Fixture f; auto s = f.Good(); const auto before = f.Calls();
    std::string error; FusionRoute route; Bytes out(12);
    for (const auto& range : std::vector<std::pair<std::uint64_t, std::size_t>>{
        {64ULL * f.bs, 1}, {64ULL * f.bs - 1, 2},
        {kFusionTier2ByteAddress - 1, 2}, {kFusionTier2ByteAddress + 32ULL * f.bs, 1},
        {kFusionTier2ByteAddress + 32ULL * f.bs - 1, 2}, {UINT64_MAX, 1},
        {2 * kFusionTier2ByteAddress, 1}, {0, 0}, {0, 16 * 1024 * 1024 + 1}})
    { out.resize(12); Check(!s->Read(range.first, range.second, out) && out.empty(), "invalid byte read leaked output"); }
    for (const auto block : {UINT64_MAX, UINT64_MAX / f.bs, 2 * f.TierBlock()})
        Check(!s->MapPhysical(block, 0, 1, route, error), "physical multiply overflow accepted");
    Check(!s->MapPhysical(1, f.bs, 1, route, error), "invalid intra-block offset accepted");
    Check(!s->MapPhysical(0, 0, UINT64_MAX, route, error), "range addition overflow accepted");
    Check(!s->ReadExtents({{20, 0, 1}, {64, 0, 1}}, out, error) && out.empty(), "extent preflight leaked prefix");
    Check(!s->ReadExtents({}, out, error) && out.empty(), "empty extent list accepted");
    Check(!s->ReadExtents({{0, 0, 1}}, out, error) && out.empty() &&
        error == "FusionSparseExtentRequiresHigherLayer", "sparse extent read superblock data");
    Check(f.Calls() == before, "bad range reached backing I/O");
}
void ErrorsAndBudget()
{
    for (const bool short_read : {false, true})
    {
        Fixture f; auto s = f.Good(); f.sources[1]->short_read = short_read;
        f.sources[1]->false_read = !short_read;
        Bytes out(4); std::string error;
        Check(!s->ReadExtents({{20, 0, 2}, {f.TierBlock() + 20, 0, 2}}, out, error) && out.empty(),
            "failed second extent leaked first extent");
        Check(error == "FusionMemberShortReadOrIoFailure", error);
        const auto before = f.Calls(); f.sources[1]->short_read = f.sources[1]->false_read = false;
        Check(!s->Read(20ULL * f.bs, 1, out) && f.Calls() == before, "I/O fault not sticky");
    }
    {
        Fixture f; auto s = f.Good(); f.sources[1]->present = false; auto before = f.Calls(); Bytes out;
        Check(!s->Read(20ULL * f.bs, 1, out) && f.Calls() == before, "missing unused tier not detected");
        f.sources[1]->present = true;
        Check(!s->Read(20ULL * f.bs, 1, out), "disappeared member silently resurrected");
    }
    {
        Fixture f; auto s = f.Good(); f.sources[0]->after_read = [&] { f.sources[1]->present = false; };
        Bytes out; Check(!s->Read(20ULL * f.bs, 1, out) && out.empty(), "removal during I/O leaked bytes");
    }
    {
        Fixture f; auto s = f.Good(); f.sources[1]->bytes.pop_back(); Bytes out;
        Check(!s->Read(20ULL * f.bs, 1, out) && out.empty(), "changed unused member size accepted");
    }
    {
        Fixture probe; auto good = probe.Good(); const auto binding_reads = probe.Calls();
        Fixture f; f.Budget(binding_reads + 1); auto s = f.Good(); Bytes out;
        Check(s->Read(20ULL * f.bs, 1, out), "last budgeted read refused");
        const auto before = f.Calls();
        Check(!s->Read(20ULL * f.bs, 1, out) && out.empty() && f.Calls() == before, "budget exhaustion dispatched I/O");
        Check(s->LastError() == "ApfsReadBudgetSourceLimit", s->LastError());
    }
    {
        Fixture probe; auto good = probe.Good();
        Fixture f; f.Budget(probe.Calls() + 1);
        f.sources[0]->budget = f.request.budget; f.sources[1]->budget = f.request.budget;
        auto s = f.Good(); Bytes out; Check(s->Read(20ULL * f.bs, 1, out), "inherited budget failed");
        auto other = std::make_shared<ApfsReadBudget>(10, 10000, 10, 10000);
        BudgetedRandomAccessSource wrapped(*s, other);
        Check(!wrapped.Read(20ULL * f.bs, 1, out) && out.empty(), "replacement budget accepted");
        Check(!s->Read(20ULL * f.bs, 1, out) && out.empty(), "inherited allowance charged incorrectly");
    }
    {
        Fixture probe; auto good=probe.Good();
        const auto bytes=probe.sources[0]->bytes_read + probe.sources[1]->bytes_read;
        Fixture f; f.Budget(10000,bytes+1); auto s=f.Good(); Bytes out;
        Check(s->Read(20ULL*f.bs,1,out),"last byte allowance refused");
        auto before=f.Calls();
        Check(!s->Read(20ULL*f.bs,1,out) && out.empty() && f.Calls()==before,"byte budget dispatched I/O");
    }
}
void DiskImages()
{
    Fixture f; auto req = f.request;
    const auto folder = std::filesystem::current_path() / "ordinary-images";
    std::filesystem::create_directories(folder);
    for (std::size_t i = 0; i < 2; ++i)
    {
        const auto path = folder / (i ? "tier2.img" : "main.img");
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        const auto& b = f.sources[i]->bytes;
        output.write(reinterpret_cast<const char*>(b.data()), static_cast<std::streamsize>(b.size()));
        output.close(); req.members[i].path = path.wstring(); std::string error;
        Check(ApfsFusionStore::InspectImage(req.members[i].path, req.members[i].exact_identity, error), error);
    }
    std::string error; auto store = ApfsFusionStore::BindImages(req, error);
    Check(bool(store), "ordinary image bind: " + error);
    Bytes bytes; Check(store->Read(kFusionTier2ByteAddress + 20ULL * f.bs, 2, bytes) &&
        bytes == Bytes(2, std::byte{0xB1}), "regular held image route failed");
#ifdef _WIN32
    auto writer = CreateFileW(req.members[0].path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, 0, nullptr);
    Check(writer == INVALID_HANDLE_VALUE, "held image allowed a writer");
    if (writer != INVALID_HANDLE_VALUE) CloseHandle(writer);
    Check(!DeleteFileW(req.members[1].path.c_str()), "held image allowed deletion");
    const auto renamed = folder.parent_path() / "ordinary-images-renamed";
    Check(!MoveFileExW(folder.c_str(), renamed.c_str(), 0), "held ancestor allowed rename");
    FusionImageIdentity reparse_identity;
    Check(!ApfsFusionStore::InspectImage((folder.parent_path()/"reparse-images"/"main.img").wstring(),
        reparse_identity,error), "directory reparse path admitted");
    Check(!ApfsFusionStore::InspectImage(folder.wstring(),reparse_identity,error),"directory admitted as image");
#endif
    auto alias = req; alias.members[1].path = req.members[0].path;
    alias.members[1].exact_identity = req.members[0].exact_identity;
    Check(!ApfsFusionStore::BindImages(alias, error) && error == "FusionDuplicateMemberIdentity", error);
#ifdef _WIN32
    const auto hardlink = folder / "main-alias.img";
    // Rerunnable in the shared CTest working directory: drop any stale alias
    // from a prior invocation before recreating the hardlink.
    (void)DeleteFileW(hardlink.c_str());
    Check(CreateHardLinkW(hardlink.c_str(), req.members[0].path.c_str(), nullptr) != 0, "ordinary image hardlink setup");
    alias.members[1].path = hardlink.wstring();
    Check(ApfsFusionStore::InspectImage(alias.members[1].path, alias.members[1].exact_identity,error),error);
    Check(!ApfsFusionStore::BindImages(alias,error) && error=="FusionDuplicateMemberIdentity", "hardlink identity not rejected");
#endif
    auto wrong = req; wrong.members[0].exact_identity.file_id[15] ^= std::byte{1};
    if (wrong.members[0].exact_identity.file_id == req.members[1].exact_identity.file_id)
        wrong.members[0].exact_identity.file_id[14] ^= std::byte{1};
    Check(!ApfsFusionStore::BindImages(wrong, error) && error == "FusionExactImageIdentityMismatchOrUnavailable", error);
    wrong = req; wrong.members[0].exact_identity.volume_serial ^= 1ULL << 40;
    Check(!ApfsFusionStore::BindImages(wrong, error) && error == "FusionExactImageIdentityMismatchOrUnavailable", error);
    store.reset();
    // Failed second-member acquisition must release the first-member lease.
    wrong = req; wrong.members[1].path += L".missing";
    Check(!ApfsFusionStore::BindImages(wrong,error),"missing second image admitted");
#ifdef _WIN32
    writer = CreateFileW(req.members[0].path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, 0, nullptr);
    Check(writer != INVALID_HANDLE_VALUE,"failed bind retained first lease");
    if (writer != INVALID_HANDLE_VALUE) CloseHandle(writer);
#endif
    auto stale = req; ++stale.members[0].exact_identity.write_time;
    Check(!ApfsFusionStore::BindImages(stale, error), "stale exact file identity accepted");
    FusionImageIdentity id;
    for (const auto* path : {L"relative.img", L"D:relative.img", L"D:\\folder\\..\\main.img",
        L"D:\\main.img:stream", L"D:\\NUL", L"D:\\CON.txt", L"D:\\COM1", L"\\\\?\\D:\\main.img", L"\\\\.\\PhysicalDrive98765"})
        Check(!ApfsFusionStore::InspectImage(path, id, error), "nonordinary path admitted");
}
} // namespace

int main()
{
    try
    {
        Run("routing, cross-tier extents, metadata, four block sizes, partition offsets", Routing);
        Run("subtraction bounds, holes, crossings, overflow, preflight before I/O", Bounds);
        Run("short reads, disappearance, sticky failure, cumulative budgets", ErrorsAndBudget);
        Run("input device reorder preserves role and container member order", [] {
            Fixture f; std::reverse(f.request.members.begin(), f.request.members.end()); auto s = f.Good();
            Check(s->Container().member_store_ids[0] == "apfs-store:test-main", "input order controls main"); });
        Reject("missing member", [](auto& f) { f.request.members.pop_back(); }, "FusionCompleteTwoMemberSetRequired", true);
        Reject("extra member", [](auto& f) { f.request.members.push_back(f.request.members[0]); }, "FusionCompleteTwoMemberSetRequired", true);
        Reject("duplicate exact file", [](auto& f) { f.request.members[1].exact_identity.file_id = f.request.members[0].exact_identity.file_id; }, "FusionDuplicateMemberIdentity", true);
        Reject("duplicate stable store reference", [](auto& f) { f.request.members[1].stable_store_id = f.request.members[0].stable_store_id; }, "FusionDuplicateMemberIdentity", true);
        Reject("duplicate role", [](auto& f) { f.request.members[1].role = FusionMemberRole::Main; }, "FusionDuplicateOrMissingRole", true);
        Reject("unspecified role convention", [](auto& f) { f.request.convention = FusionRoleConvention::Unspecified; }, "FusionRoleConventionUnestablished", true);
        Reject("missing budget", [](auto& f) { f.request.budget.reset(); }, "FusionLiveReadBudgetRequired", true);
        Reject("exhausted read budget", [](auto& f) { f.Budget(0); }, "ApfsReadBudgetSourceLimit", true);
        Reject("short anchor read", [](auto& f) { f.sources[1]->short_read=true; }, "FusionMemberShortReadOrIoFailure");
        Reject("exhausted materialization budget", [](auto& f) { f.Budget(1000, 1000000, 0, 0); }, "ApfsReadBudgetRecordLimit", true);
        Reject("wrong backing budget", [](auto& f) { f.sources[0]->budget = std::make_shared<ApfsReadBudget>(1000,1000000,1000,1000000); }, "FusionReadBudgetIdentityMismatch", true);
        Reject("missing source before bind", [](auto& f) { f.sources[1]->present = false; }, "FusionMemberDisappearedOrChanged", true);
        Reject("wrong expected container UUID", [](auto& f) { f.request.container_uuid_hex[0] = 'c'; }, "FusionContainerUuidMismatch");
        Reject("similar but distinct Fusion IDs", [](auto& f) { f.Edit(1,0,[](auto& b) { b[0x500] = std::byte{0xAC}; }); }, "FusionSetUuidMismatch");
        Reject("reversed on-disk role", [](auto& f) { f.Edit(1,0,[](auto& b) { b[0x50F] &= std::byte{0xFE}; }); }, "FusionRoleBitMismatch");
        Reject("stale member anchor", [](auto& f) { f.Edit(1,0,[](auto& b) { Put(b,16,19); }); }, "FusionMemberAnchorGenerationMismatch");
        Reject("equal UUID/XID but conflicting fields", [](auto& f) { f.Edit(1,0,[](auto& b) { Put(b,0x58,101); }); }, "FusionMemberAnchorContentMismatch");
        Reject("corrupt anchor checksum", [](auto& f) { f.sources[1]->bytes[0x58] ^= std::byte{1}; }, "FusionAnchorChecksumOrFormatInvalid");
        Reject("non-Fusion pair with matching IDs", [](auto& f) { f.EditNx([](auto& b) { Put(b,0x40,2); }); }, "FusionContainerFeatureProfileUnsupported");
        Reject("unknown incompatible feature", [](auto& f) { f.EditNx([](auto& b) { Put(b,0x40,0x106); }); }, "FusionContainerFeatureProfileUnsupported");
        Reject("missing exact checkpoint", [](auto& f) { f.request.checkpoint_xid = 21; }, "CheckpointExactGenerationUnavailable");
        Reject("newer descriptor than pinned anchor requires recovery", [](auto& f) {
            auto nx=f.Block(0,2); Put(nx,16,21); Seal(nx); f.Place(0,3,nx);
        }, "FusionNewerCheckpointRequiresRecovery");
        Reject("invalid NX storage type", [](auto& f) { f.EditNx([](auto& b) { Put(b,24,1,4); }); }, "FusionAnchorObjectStorageOrSubtypeUnsupported");
        Reject("corrupt checkpoint map", [](auto& f) { f.sources[0]->bytes[f.bs + 32] ^= std::byte{2}; }, "CheckpointExactGenerationUnavailable");
        Reject("corrupt checkpoint spaceman", [](auto& f) { f.sources[0]->bytes[8ULL*f.bs+32] ^= std::byte{2}; }, "CheckpointExactGenerationUnavailable");
        Reject("checkpoint descriptor tree", [](auto& f) { f.EditNx([](auto& b) { Put(b,0x68,0x80000004,4); }); }, "FusionCheckpointDescriptorTreeUnsupported");
        Reject("checkpoint data tree", [](auto& f) { f.EditNx([](auto& b) { Put(b,0x6C,0x80000004,4); }); }, "FusionCheckpointDataTreeUnsupported");
        Reject("descriptor scan bounded before traversal", [](auto& f) { f.EditNx([](auto& b) { Put(b,0x68,65537,4); }); }, "FusionCheckpointAreaLimit");
        Reject("checkpoint areas overlap", [](auto& f) { f.EditNx([](auto& b) { Put(b,0x78,3); }); }, "FusionCheckpointAreasOverlap");
        Reject("checkpoint differs from anchors", [](auto& f) { f.Edit(0,2,[](auto& b) { Put(b,0x58,99); }); }, "FusionAnchorCheckpointContentMismatch");
        Reject("next generation cannot wrap backward", [](auto& f) { f.EditNx([](auto& b) { Put(b,0x60,0); }); }, "FusionNextGenerationInvalid");
        Reject("tier2 checkpoint area", [](auto& f) { const auto tier=f.TierBlock(); f.EditNx([&](auto& b) { Put(b,0x78,tier+8); }); }, "FusionCheckpointAreasMustBeMainLocal");
        Reject("wrong combined block count", [](auto& f) { f.EditNx([](auto& b) { Put(b,0x28,64); }); }, "FusionCombinedBlockCountMismatch");
        Reject("wrong spaceman tier size", [](auto& f) { f.Edit(0,8,[](auto& b) { Put(b,0x60,31); }); }, "FusionSpacemanMemberGeometryMismatch");
        Reject("missing spaceman tier", [](auto& f) { f.Edit(0,8,[](auto& b) { Put(b,0x60,0); }); }, "FusionSpacemanMemberGeometryMismatch");
        Reject("unknown spaceman flags", [](auto& f) { f.Edit(0,8,[](auto& b) { Put(b,0x90,2,4); }); }, "FusionSpacemanStructureUnsupported");
        Reject("excess spaceman free count", [](auto& f) { f.Edit(0,8,[](auto& b) { Put(b,0x78,33); }); }, "FusionSpacemanMemberGeometryMismatch");
        Reject("spaceman zero chunk divisor", [](auto& f) { f.Edit(0,8,[](auto& b) { Put(b,0x24,0,4); }); }, "FusionSpacemanChunkGeometryInvalid");
        Reject("missing required middle tree", [](auto& f) { f.EditNx([](auto& b) { Put(b,0x548,0); }); }, "FusionRequiredCacheMetadataMissing");
        Reject("missing required writeback state", [](auto& f) { f.EditNx([](auto& b) { Put(b,0x550,0); }); }, "FusionRequiredCacheMetadataMissing");
        Reject("nonempty middle tree routing is explicit unsupported", [](auto& f) { f.Place(0,17,MiddleTree(f.bs,17,true)); }, "FusionNonemptyMiddleTreeRoutingUnestablished");
        Reject("nonempty writeback routing is explicit unsupported", [](auto& f) { f.Edit(0,9,[](auto& b) { Put(b,0x28,33); }); }, "FusionNonemptyWritebackRoutingUnestablished");
        Reject("unknown writeback version", [](auto& f) { f.Edit(0,9,[](auto& b) { Put(b,0x20,0x71); }); }, "FusionWritebackVersionUnsupported");
        Reject("writeback reserved field", [](auto& f) { f.Edit(0,9,[](auto& b) { Put(b,0x4C,1,4); }); }, "FusionWritebackReservedFieldUnsupported");
        Reject("writeback range on tier2", [](auto& f) { const auto tier=f.TierBlock(); f.EditNx([&](auto& b) { Put(b,0x558,tier+24); }); }, "FusionWritebackRangeInvalid");
        Reject("missing writeback range", [](auto& f) { f.EditNx([](auto& b) { Put(b,0x560,0); }); }, "FusionWritebackRangeInvalid");
        Reject("writeback overlaps checkpoint", [](auto& f) { f.EditNx([](auto& b) { Put(b,0x558,8); }); }, "FusionWritebackOverlapsCheckpoint");
        Reject("writeback unbound OID", [](auto& f) { f.EditNx([](auto& b) { Put(b,0x550,77); }); }, "FusionWritebackMappingInvalid");
        Reject("writeback stash is unsupported", [](auto& f) { f.Edit(0,9,[](auto& b) { Put(b,0x58,25); }); }, "FusionNonemptyWritebackRoutingUnestablished");
        Reject("unknown middle tree layout", [](auto& f) { f.Edit(0,17,[](auto& b) { Put(b,b.size()-32,16,4); }); }, "FusionMiddleTreeLayoutUnsupported");
        Reject("middle tree checksum", [](auto& f) { f.sources[0]->bytes[17ULL*f.bs+8]^=std::byte{1}; }, "FusionMiddleTreeInvalid:CatalogBtreeChecksumInvalid");
        Reject("middle tree future generation", [](auto& f) { f.Edit(0,17,[](auto& b) { Put(b,16,21); }); }, "FusionMiddleTreeInvalid:CatalogBtreeFutureXid");
        Reject("middle tree unknown subtype", [](auto& f) { f.Edit(0,17,[](auto& b) { Put(b,28,0x16,4); }); }, "FusionMiddleTreeInvalid:CatalogBtreeSubtypeMismatch");
        Reject("middle tree unknown flags", [](auto& f) { f.Edit(0,17,[](auto& b) { Put(b,0x20,15,2); }); }, "FusionMiddleTreeInvalid:CatalogBtreeUnsupportedFlagsOrZeroXid");
        Run("native cache B-tree parsing routes metadata on tier2", [] {
            Fixture f; auto root=f.TierBlock()+6;
            f.EditNx([&](auto& b) { Put(b,0x548,root); }); f.Place(1,6,MiddleTree(f.bs,root));
            auto s=f.Good(); Check(s->Checkpoint().superblock.fusion_middle_tree_oid==root,"lost tier2 root"); });
        Reject("partition offset overflow", [](auto& f) { f.request.members[0].store_offset = UINT64_MAX; }, "FusionMemberIdentityOrRangeInvalid", true);
        Reject("member size overflow", [](auto& f) { f.request.members[0].store_size = UINT64_MAX; }, "FusionMemberIdentityOrRangeInvalid", true);
        Run("ordered write entry is closed and dispatches no I/O", [] {
            Fixture f; auto s=f.Good(); auto calls=f.Calls(); std::string error;
            Check(!s->BeginOrderedWriteTransaction(21,error) && error=="FusionDurableMultiStoreWriteOrderingUnestablished",error);
            Check(!s->BeginOrderedWriteTransaction(20,error) && error=="FusionWriteGenerationInvalid",error);
            Check(f.Calls()==calls,"write refusal did I/O"); });
        Run("ordinary D images, exact identity, read-only leases and path rejection", DiskImages);
        Run("all ASCII drive letters accepted by syntax without filesystem access", [] {
            for (wchar_t drive = L'A'; drive <= L'Z'; ++drive)
            {
                std::wstring path = L"X:\\images\\fusion.img"; path[0] = drive;
                Check(ApfsFusionStore::TestOrdinaryLocalImagePathSyntax(path), "uppercase drive rejected");
                path[0] = static_cast<wchar_t>(drive + L'a' - L'A');
                Check(ApfsFusionStore::TestOrdinaryLocalImagePathSyntax(path), "lowercase drive rejected");
            }
        });
        Run("unsafe path spellings refused in memory", [] {
            for (const auto* path : {L"C:relative.img", L"C:\\", L"1:\\image.img", L"C:/image.img",
                L"\\\\server\\share\\image.img", L"\\\\?\\C:\\image.img", L"\\\\.\\PhysicalDrive0",
                L"C:\\folder\\..\\image.img", L"C:\\folder\\.\\image.img", L"C:\\\\image.img",
                L"C:\\image.img:stream", L"C:\\CON", L"C:\\LPT9.txt", L"C:\\COM\u00b9.txt",
                L"C:\\trailing.\\image.img", L"C:\\image.img ", L"C:\\bad|name.img", L"C:\\bad\nname.img"})
                Check(!ApfsFusionStore::TestOrdinaryLocalImagePathSyntax(path), "unsafe syntax accepted");
            std::wstring nul = L"C:\\image.img"; nul.push_back(0); nul += L"tail";
            Check(!ApfsFusionStore::TestOrdinaryLocalImagePathSyntax(nul), "embedded NUL accepted");
        });
        Run("complete 128 bit member IDs and 64 bit volume serials", [] {
            Fixture f;
            f.request.members[1].exact_identity.file_id = f.request.members[0].exact_identity.file_id;
            f.request.members[1].exact_identity.file_id[15] = std::byte{1};
            auto first = f.Good();
            f.request.members[1].exact_identity.file_id = f.request.members[0].exact_identity.file_id;
            f.request.members[1].exact_identity.volume_serial += (1ULL << 40);
            auto second = f.Good();
            Check(first->CapacityBytes() == 96ULL * f.bs && first->SizeBytes() > first->CapacityBytes(),
                "encoded address span confused with capacity");
        });
        Reject("zero full file identity", [](auto& f) { f.request.members[1].exact_identity.file_id = {}; },
            "FusionMemberIdentityOrRangeInvalid", true);
        Reject("undersized chunk bitmap geometry", [](auto& f) { const auto bs=f.bs; f.Edit(0,8,[&](auto& b) { Put(b,0x24,4ULL*bs,4); }); },
            "FusionSpacemanChunkGeometryInvalid");
        Reject("undersized CIB geometry", [](auto& f) { f.Edit(0,8,[](auto& b) { Put(b,0x28,1,4); }); },
            "FusionSpacemanChunkGeometryInvalid");
        Reject("wrong CAB geometry", [](auto& f) { f.Edit(0,8,[](auto& b) { Put(b,0x2C,1,4); }); },
            "FusionSpacemanChunkGeometryInvalid");
        Run("source resize during late extent failure clears output and poisons session", [] {
            Fixture f; auto s=f.Good(); Bytes out(12); std::string error;
            f.sources[1]->after_read = [&] { f.sources[0]->bytes.push_back(std::byte{0}); };
            Check(!s->ReadExtents({{20,0,4},{f.TierBlock()+20,0,4}},out,error) && out.empty(),
                "late size change exposed a prefix");
            Check(error == "FusionMemberDisappearedOrChanged", error);
            f.sources[0]->bytes.pop_back(); const auto calls=f.Calls();
            Check(!s->Read(20ULL*f.bs,1,out) && f.Calls()==calls,"restored size revived session");
        });
        Run("unused member budget replacement during read is sticky and atomic", [] {
            Fixture f; auto s=f.Good(); Bytes out(12);
            f.sources[0]->after_read = [&] { f.sources[1]->budget = std::make_shared<ApfsReadBudget>(100,10000,100,10000); };
            Check(!s->Read(20ULL*f.bs,4,out) && out.empty(), "late budget substitution exposed bytes");
            Check(s->LastError()=="FusionReadBudgetIdentityMismatch",s->LastError());
            f.sources[1]->budget.reset(); const auto calls=f.Calls();
            Check(!s->Read(20ULL*f.bs,1,out) && f.Calls()==calls,"restored budget revived session");
        });
        Reject("middle tree inside writeback reservation", [](auto& f) {
            f.EditNx([](auto& b) { Put(b,0x548,24); }); f.Place(0,24,MiddleTree(f.bs,24));
        }, "FusionMiddleTreeOverlapsReservedArea");
        Reject("middle tree inside descriptor reservation", [](auto& f) {
            f.EditNx([](auto& b) { Put(b,0x548,4); }); f.Place(0,4,MiddleTree(f.bs,4));
        }, "FusionMiddleTreeOverlapsReservedArea");
        Run("extent materialization exhaustion performs no backing read", [] {
            Fixture f; auto s=f.Good(); Bytes out(12); std::string error;
            Check(!f.request.budget->Materialize(0,UINT64_MAX),"material budget failed to exhaust");
            const auto calls=f.Calls();
            Check(!s->ReadExtents({{20,0,4},{f.TierBlock()+20,0,4}},out,error) && out.empty() &&
                f.Calls()==calls,"material exhaustion leaked bytes or performed I/O");
        });
        Run("extent reservation shortage refuses before the first read", [] {
            // Find the binding's minimum logical materialization allowance via
            // the public contract; no implementation-size formula in the test.
            std::uint64_t low=0, high=64*1024*1024;
            while (low < high)
            {
                const auto mid=low+(high-low)/2;
                Fixture probe; probe.Budget(10000,64*1024*1024,10000,mid);
                std::string error; auto result=probe.Bind(error);
                if (result) high=mid; else low=mid+1;
            }
            Fixture f; f.Budget(10000,64*1024*1024,10000,low); auto s=f.Good();
            Bytes out(4); std::string error; const auto calls=f.Calls();
            Check(!s->ReadExtents({{20,0,4},{f.TierBlock()+20,0,4}},out,error) && out.empty(),
                "extent reservation shortage exposed bytes");
            Check(error=="ApfsReadBudgetRecordLimit" && f.Calls()==calls,"extent reservation dispatched I/O");
        });
        Run("exact extent count limit refuses before backing I/O", [] {
            Fixture f; auto s=f.Good(); Bytes out(4); std::string error; const auto calls=f.Calls();
            Check(!s->ReadExtents(std::vector<FusionExtent>(4097,{20,0,1}),out,error) && out.empty() &&
                error=="FusionExtentCountInvalid" && f.Calls()==calls,"extent count limit bypassed");
        });
        Reject("wrong main CAB count", [](auto& f) { f.Edit(0,8,[](auto& b) { Put(b,0x44,1,4); }); },
            "FusionSpacemanMemberGeometryMismatch");
        Reject("wrong tier2 CAB count", [](auto& f) { f.Edit(0,8,[](auto& b) { Put(b,0x74,1,4); }); },
            "FusionSpacemanMemberGeometryMismatch");
        Reject("main spaceman reserved field", [](auto& f) { f.Edit(0,8,[](auto& b) { Put(b,0x54,1,4); }); },
            "FusionSpacemanMemberReservedFieldsUnsupported");
        Reject("tier2 spaceman reserved field", [](auto& f) { f.Edit(0,8,[](auto& b) { Put(b,0x88,1); }); },
            "FusionSpacemanMemberReservedFieldsUnsupported");
        Run("held lease timestamp change is detected and restoration cannot revive it", [] {
            Fixture f; auto req=f.request; std::string error;
            for (std::size_t i=0; i<2; ++i) {
                req.members[i].path=(std::filesystem::current_path()/"ordinary-images"/(i?"tier2.img":"main.img")).wstring();
                Check(ApfsFusionStore::InspectImage(req.members[i].path,req.members[i].exact_identity,error),error);
            }
            auto s=ApfsFusionStore::BindImages(req,error); Check(bool(s),error);
            const auto h=CreateFileW(req.members[1].path.c_str(),FILE_WRITE_ATTRIBUTES,
                FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr);
            Check(h!=INVALID_HANDLE_VALUE,"timestamp-only handle unavailable");
            const auto old=req.members[1].exact_identity.write_time;
            FILETIME before{static_cast<DWORD>(old),static_cast<DWORD>(old>>32)};
            FILETIME after{static_cast<DWORD>(old+10000000),static_cast<DWORD>((old+10000000)>>32)};
            const bool changed=SetFileTime(h,nullptr,nullptr,&after)!=0;
            Bytes out(4); const bool refused=!s->Read(20ULL*f.bs,4,out) && out.empty();
            const bool restored=SetFileTime(h,nullptr,nullptr,&before)!=0;
            CloseHandle(h);
            Check(changed && restored,"timestamp mutation/restore failed");
            Check(refused && s->LastError()=="FusionMemberDisappearedOrChanged","changed unused image was accepted");
            Check(!s->Read(20ULL*f.bs,4,out) && out.empty(),"restored timestamp revived poisoned lease");
        });
        std::cout << "PASS " << cases << " cases, " << checks << " checks; SYNTHETIC SOFTWARE EVIDENCE ONLY\n";
        return 0;
    }
    catch (const std::exception& e) { std::cerr << "FAIL " << e.what() << '\n'; return 1; }
}
