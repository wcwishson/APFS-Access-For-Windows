// Synthetic regular-image software evidence only. The base transport fixture
// lacks ownership; allocation cases add complete canonical spaceman structures.
#define APFS_FUSION_STORE_TESTING
#include "ApfsFusionImageWriteSession.h"
#include "FusionImageRuntime.h"
#include "FusionImageArguments.h"
#include "ApfsFusionCheckpointTarget.h"
#include "ApfsFusionSpaceman.h"
#include "AppleVolumeTransaction.h"
#include "ApfsExtendedRecordCodec.h"
#include "FusionTestFixture.h"
#include "../src/FusionReclamationProof.h"
#include <bcrypt.h>
#include <winioctl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <numeric>
#include <set>
#include <tuple>

namespace apfsaccess::rw
{
struct FusionImageWriteSessionTestAccess
{
    static catalog::ApfsFusionStore& Store(ApfsFusionImageWriteSession& s) { return *s.store_; }
    static catalog::ApfsFusionWriteSession& Writer(ApfsFusionImageWriteSession& s) { return *s.writer_; }
    static BlockDevice& Device(ApfsFusionImageWriteSession& s, unsigned member) { return *s.devices_.at(member); }
};
}
using namespace apfsaccess::rw;
using namespace apfsaccess::catalog;
using namespace apfsaccess::fusiontest;
namespace tf = apfsaccess::testfixture;
namespace fs = std::filesystem;
namespace
{
unsigned cases = 0, checks = 0;
void Check(bool ok, const std::string& why) { ++checks; if (!ok) throw std::runtime_error(why); }
void Save(const fs::path& path, const Bytes& bytes)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    Check(static_cast<bool>(out), "save fixture");
}
Bytes Load(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    Check(static_cast<bool>(in), "open fixture readback");
    Bytes bytes(static_cast<std::size_t>(in.tellg())); in.seekg(0);
    in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    Check(static_cast<bool>(in), "read fixture"); return bytes;
}
template<class T, class F> apfsaccess::catalog::BtreeRecord Enc(const T& value, F encode)
{ apfsaccess::catalog::BtreeRecord out; std::string e; Check(encode(value, out, e), "encode: " + e); return out; }
struct Files : Fixture
{
    fs::path directory, main, tier;
    explicit Files(const fs::path& root, unsigned prefix_blocks = 0) : Fixture(4096, prefix_blocks)
    {
        static unsigned ordinal = 0;
        directory = root / ("case-" + std::to_string(++ordinal));
        Check(fs::create_directory(directory), "new private directory"); main = directory / "main.apfs"; tier = directory / "tier.apfs";
        EditNx([&](auto& bytes) { Put(bytes, 0xB8, 101); });
        Place(0, 15, tf::BuildOmap(18, 20, bs, 15, kObjectPhysical | kObjectTypeOmap, kObjectPhysical | kObjectTypeBtree));
        Place(0, 18, tf::BuildBtreeNode({{101, TierBlock() + 4, 0, 20}}, 20, bs, 0, 18,
            kObjectPhysical | kObjectTypeBtree, kObjectTypeOmap));
        tf::BuilderVolume v; v.oid = 101; v.uuid_hex = std::string(32, 'c'); v.name = "Fusion owner fixture";
        v.vol_omap_oid_override = TierBlock() + 5; v.root_oid_override = 1000; v.incompat = 0;
        Place(1, 4, tf::BuildApsb(v, 20, bs));
        Place(1, 5, tf::BuildOmap(TierBlock() + 6, 20, bs, TierBlock() + 5,
            kObjectPhysical | kObjectTypeOmap, kObjectPhysical | kObjectTypeBtree));
        Place(1, 6, tf::BuildBtreeNode({{1000, 30, 0, 20}}, 20, bs, 0, TierBlock() + 6,
            kObjectPhysical | kObjectTypeBtree, kObjectTypeOmap));
        AppleInodeRecord root_inode; root_inode.object_id = 2; root_inode.parent_id = 2; root_inode.private_id = 2;
        root_inode.mode = 0040755; root_inode.children_or_links = 1;
        AppleInodeRecord inode; inode.object_id = 30; inode.parent_id = 2; inode.private_id = 30;
        inode.mode = 0100644; inode.children_or_links = 1; inode.uncompressed_size = 8192;
        AppleExtendedField stream{8, 0, Bytes(40)}; Put(stream.data, 0, 8192); Put(stream.data, 8, 8192);
        inode.extended_fields.push_back(stream);
        AppleDirectoryRecord dir; dir.parent_id = 2; dir.file_id = 30; dir.name_utf8 = "file.txt"; dir.flags = 8;
        apfsaccess::catalog::BtreeRecord directory_record; std::string error;
        Check(EncodeAppleDirectoryRecord(dir, ApfsNamePolicy::FromIncompatibleFeatures(0), directory_record, error), error);
        std::vector<apfsaccess::catalog::BtreeRecord> records = {Enc(root_inode, EncodeAppleInodeRecord), Enc(inode, EncodeAppleInodeRecord), directory_record,
            Enc(AppleFileExtentRecord{30, 0, 4096, 20, 0, 4096}, EncodeAppleFileExtentRecord),
            Enc(AppleFileExtentRecord{30, 4096, 4096, TierBlock() + 20, 0, 4096}, EncodeAppleFileExtentRecord)};
        Check(SortAppleBtreeRecords(records, AppleBtreeKeyOrder::FileSystemCaseSensitive, error), error);
        std::vector<Bytes> keys, values;
        for (const auto& r : records) { keys.push_back(r.key); values.push_back(r.value); }
        Place(0, 30, tf::BuildRawLeafNode(keys, values, 20, bs, 0, 1000, kObjectTypeBtree, kObjectTypeFsTree));
        Save(main, sources[0]->bytes); Save(tier, sources[1]->bytes); Refresh(20);
    }
    void Refresh(std::uint64_t xid)
    {
        request.checkpoint_xid = xid; Budget(100000, 256ULL << 20, 1000000, 256ULL << 20);
        for (auto& m : request.members)
        {
            m.path = (m.role == FusionMemberRole::Main ? main : tier).wstring();
            std::string error; Check(ApfsFusionStore::InspectImage(m.path, m.exact_identity, error), "inspect: " + error);
        }
    }
    FusionVolumeSelection Selection() const
    { return {request.container_uuid_hex, std::string(32, 'c'), {"apfs-store:test-main", "apfs-store:test-tier2"}, 101, request.checkpoint_xid}; }
    std::unique_ptr<ApfsFusionImageWriteSession> Open()
    {
        std::string error; auto owner = ApfsFusionImageWriteSession::Open(request, Selection(), error);
        Check(static_cast<bool>(owner), "owner open: " + error); return owner;
    }
};
using Access = FusionImageWriteSessionTestAccess;
AppleCheckpointPublicationPlan TransportPlan(ApfsFusionImageWriteSession& owner)
{
    auto& store = Access::Store(owner); const auto& cp = store.Checkpoint();
    AppleCheckpointPublicationRequest request; request.expected_checkpoint_xid = cp.superblock.xid;
    request.transaction_xid = cp.superblock.next_xid; request.next_object_id = cp.superblock.next_oid;
    std::string error;
    for (const auto& mapping : cp.mappings)
    {
        Bytes bytes; Check(store.Read(mapping.physical_block * 4096, mapping.size_bytes, bytes), "read ephemeral source");
        Put(bytes, 16, request.transaction_xid); Seal(bytes);
        AppleObjectLocation object{mapping.object_id, request.transaction_xid, 0,
            mapping.type, mapping.subtype, mapping.size_bytes};
        request.ephemeral_objects.push_back({mapping.file_system_oid, object, bytes});
    }
    AppleCheckpointPublicationPlan plan;
    const bool planned = PlanAppleCheckpointPublication(store, cp, request, plan, error);
    Check(planned, "canonical publication plan: " + error);
    // Deliberate storage-only test payloads. No bitmap ownership is claimed.
    // Only this test TU has access to the owner's private writer.
    plan.before_superblock_writes.push_back({AppleCheckpointWriteKind::AllocatorOwned, 40, 0, Bytes(4096, std::byte{0xA5})});
    plan.before_superblock_writes.push_back({AppleCheckpointWriteKind::AllocatorOwned, kFusionTier2ByteAddress / 4096 + 10, 0, Bytes(4096, std::byte{0x5A})});
    Check(FinalizeFusionCheckpointPublication(store, plan, error), "canonical Fusion finalizer: " + error);
    return plan;
}
bool Execute(ApfsFusionImageWriteSession& owner, const AppleCheckpointPublicationPlan& plan,
    std::string& error, const AppleCheckpointStageHook& hook = {})
{
    ApfsFusionCheckpointTarget target(Access::Store(owner), Access::Writer(owner), 4096);
    return ExecuteAppleCheckpointPublication(target, plan, error, hook);
}
void VerifyWrites(ApfsFusionImageWriteSession& owner, const AppleCheckpointPublicationPlan& plan)
{
    auto& store = Access::Store(owner); Bytes bytes;
    for (const auto& w : plan.before_superblock_writes)
        Check(store.Read(w.physical_block * 4096, w.bytes.size(), bytes) && bytes == w.bytes, "exact staged bytes");
    const auto& mirror = *plan.fusion_tier2_anchor_write;
    Check(store.Read(mirror.physical_block * 4096, 4096, bytes) && bytes == mirror.bytes, "exact mirror");
    Check(store.Read(0, 4096, bytes) && bytes == plan.superblock_write.bytes, "exact main anchor");
    std::string error;
    auto cp = LoadContainerCheckpointView(store, 0, store.SizeBytes(), error, plan.transaction_xid);
    Check(cp && cp->superblock_bytes == plan.superblock_write.bytes, "complete new canonical checkpoint: " + error);
    auto old = LoadContainerCheckpointView(store, 0, store.SizeBytes(), error, plan.expected_checkpoint_xid);
    Check(old && old->superblock.xid == plan.expected_checkpoint_xid, "complete old canonical checkpoint: " + error);
}
template<class F> void Run(const char* name, F body) { body(); ++cases; std::cout << "PASS " << name << '\n'; }
#include "FusionAllocationOwnershipTests.inc"
#include "FusionAllocationCabTests.inc"
#include "FusionVolumePlanTests.inc"
#include "FusionImageRuntimeTests.inc"
#include "FusionReclamationTests.inc"
#include "FusionMountFixture.inc"
#include "FusionNamespaceTests.inc"
#include "FusionTornReplayTests.inc"
#include "FusionRangeTests.inc"
}
int main(int argc, char** argv) try
{
    if(argc==3&&std::string(argv[1])=="--cache-controls") {
        const fs::path root(argv[2]);Check(root.is_absolute()&&root.root_name()==L"D:"&&fs::create_directory(root),"new private cache root");
        for(unsigned member=0;member<2;++member)Run(member?"tier cache generation and main loss":"main cache generation and tier loss",[&] {
            Files f(root);auto owner=f.Open();Bytes before,after;std::string error;
            Check(owner->ReadFile(30,member*4096,4096,before,error),error);
            Check(owner->ReadFile(30,member*4096,4096,after,error)&&after==before,"repeat held parser read");
            const Bytes changed(4096,std::byte{0x39});
            Check(Access::Device(*owner,member).Write(20*4096,changed),"same held device write");
            Check(owner->ReadFile(30,member*4096,4096,after,error)&&after==changed,"write generation invalidates cached payload");
            const auto sibling=1u-member;
            Check(Access::Device(*owner,sibling).Write(f.sources[sibling]->bytes.size(),Bytes(4096)),"private sibling resize");
            Check(!owner->ReadFile(30,member*4096,4096,after,error)&&after.empty(),"cached payload cannot survive sibling loss");
        });
        std::cout<<"PASS "<<cases<<" cache cases, "<<checks<<" checks\n";return 0;
    }
    if(argc>=4&&std::string(argv[1])=="--runtime-child"&&std::string(argv[3]).starts_with("range-"))return FusionRangeChild(fs::path(argv[2]),argv[3],argc>4?argv[4]:"");
    if(argc==3&&std::string(argv[1])=="--ranges") {const fs::path root(argv[2]);Check(root.root_name()==L"D:"&&fs::create_directory(root),"new private range root");RunFusionRangeTests(root);std::cout<<"PASS "<<cases<<" range cases, "<<checks<<" checks\n";return 0;}
    if(argc==3&&std::string(argv[1])=="--mount-fixture")return ExportFusionMountFixture(fs::path(argv[2]));
    if(argc==3&&std::string(argv[1])=="--witness-fixture")return ExportFusionMountFixture(fs::path(argv[2]),true);
    if(argc==3&&std::string(argv[1])=="--witness-cut")return FusionWitnessBoundsChild(fs::path(argv[2]),true);
    if(argc==3&&std::string(argv[1])=="--witness-recover")return FusionWitnessBoundsChild(fs::path(argv[2]),false);
    if(argc==3&&std::string(argv[1])=="--witness-profile")return FusionWitnessBoundsChild(fs::path(argv[2]),false,true);
    if(argc==3&&std::string(argv[1])=="--mount-select")return SelectFusionMountFixture(fs::path(argv[2]));
    if(argc==3&&std::string(argv[1])=="--mount-sequence")return FusionMountSequence(fs::path(argv[2]));
    if(argc==3&&std::string(argv[1])=="--namespace")return FusionNamespaceSequence(fs::path(argv[2]));
    if(argc==3&&std::string(argv[1])=="--name-policies") {const fs::path root(argv[2]);Check(root.root_name()==L"D:"&&fs::create_directory(root),"new private name root");RunFusionNamePolicies(root);std::cout<<"PASS "<<cases<<" name cases, "<<checks<<" checks\n";return 0;}
    if(argc==3&&std::string(argv[1])=="--torn") {const fs::path root(argv[2]);Check(root.root_name()==L"D:"&&fs::create_directory(root),"new private torn root");RunFusionTornTests(root);std::cout<<"PASS "<<cases<<" torn cases, "<<checks<<" checks\n";return 0;}
    if(argc==3&&std::string(argv[1])=="--reclaim-controls"){
        const fs::path root(argv[2]);Check(root.is_absolute()&&root.root_name()==L"D:"&&fs::create_directory(root),"private controls root");
        FusionReclamationControls(root);std::cout<<"PASS "<<cases<<" reclamation cases, "<<checks<<" checks\n";return 0;
    }
    if(argc==4&&std::string(argv[1])=="--mount-cut")return FusionMountCut(fs::path(argv[2]),argv[3]);
    if(argc==3&&std::string(argv[1])=="--mount-inspect")return InspectFusionMountFixture(fs::path(argv[2]));
    if(argc>=4&&std::string(argv[1])=="--runtime-child")return RuntimeChild(fs::path(argv[2]),argv[3],argc>4?argv[4]:"");
    if(argc==3&&std::string(argv[1])=="--runtime") {
        const fs::path root(argv[2]);Check(fs::create_directories(root),"new runtime test root");
        RunFusionRuntimeTests(root);std::cout<<"PASS "<<cases<<" runtime cases, "<<checks<<" checks\n";return 0;
    }
    Check(argc == 2, "private D: output directory required"); const fs::path root(argv[1]);
    Check(root.is_absolute() && root.root_name() == L"D:", "D: output only");
    Check(fs::create_directory(root), "fresh output directory");
    RunAllocationTests(root);
    RunCabTests(root);
    RunVolumePlanTests(root);
    Run("exclusive ordered identity, same held cross-tier reads, release", [&] {
        Files f(root, 2); auto owner = f.Open(); const auto identity = owner->SourceBinding();
        Bytes bytes; std::string error;
        Check(owner->ReadFile(30, 4093, 6, bytes, error) && bytes == Bytes({std::byte{0xA1},std::byte{0xA1},std::byte{0xA1},std::byte{0xB1},std::byte{0xB1},std::byte{0xB1}}), "held unaligned cross-tier read: " + error);
        for (const auto& path : {f.main, f.tier}) {
            HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, 0, nullptr);
            Check(h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION, "exclusive member denies outsider");
        }
        owner->Close(); std::reverse(f.request.members.begin(), f.request.members.end()); f.Refresh(20);
        owner = f.Open(); Check(identity == owner->SourceBinding(), "role ordering independent of request order");
    });
    Run("selection and replaced member refuse, first lease unwinds", [&] {
        Files f(root); auto selection = f.Selection(); selection.member_store_ids[1] = "wrong"; std::string error;
        Check(!ApfsFusionImageWriteSession::Open(f.request, selection, error), "wrong selection accepted");
        const auto copy = f.directory / "replacement.apfs"; fs::copy_file(f.tier, copy); f.request.members[1].path = copy.wstring();
        Check(!ApfsFusionImageWriteSession::Open(f.request, f.Selection(), error) && error == "FusionImageExactIdentityMismatch", "byte-identical replacement accepted: " + error);
        f.Refresh(20); auto owner = f.Open(); Check(owner->CheckAvailable(error), error);
    });
    Run("device path refused before member opening", [&] {
        Files f(root); f.request.members[1].path = L"\\\\.\\PhysicalDrive999"; std::string error;
        Check(!ApfsFusionImageWriteSession::Open(f.request, f.Selection(), error) && error == "FusionImageOrdinaryLocalPathRequired", error);
        f.Refresh(20); Check(static_cast<bool>(f.Open()), "first member leaked");
    });
    Run("canonical ownership refusal preserves both entire images", [&] {
        Files f(root); const auto before_main = Load(f.main), before_tier = Load(f.tier); auto owner = f.Open(); std::string error;
        Check(!owner->CheckAllocatorAdmission(error) && error == "AppleSpacemanInternalPoolGeometryInvalid", "canonical refusal: " + error);
        Check(Access::Writer(*owner).counters().main_blocks_written == 0 && Access::Writer(*owner).counters().tier2_blocks_written == 0, "admission wrote blocks");
        owner->Close(); Check(Load(f.main) == before_main && Load(f.tier) == before_tier, "admission changed image");
    });
    for (const bool external : {false, true}) Run(external ? "external cancellation revokes both members" : "owner cancellation revokes both members", [&] {
        Files f(root); auto token = std::make_shared<std::atomic<bool>>(false); f.request.cancellation = token;
        auto owner = f.Open(); if (external) token->store(true); else owner->Cancel();
        std::string error; Bytes out(1);
        Check(!owner->ReadFile(30, 8192, 1, out, error) && out.empty(), "cancelled EOF exposed");
        Check(!Access::Writer(*owner).WriteBlock(40, Bytes(4096, std::byte{3}), error), "cancelled transport wrote");
        Check(!Access::Writer(*owner).FlushOrdered(error), "cancelled transport flushed");
    });
    Run("held member resize isolates the other member", [&] {
        Files f(root); auto before = Load(f.main); auto owner = f.Open(); std::string error;
        Check(Access::Device(*owner, 1).Write(32 * 4096, Bytes(4096)), "private tier resize");
        Check(!owner->CheckAvailable(error), "changed unused tier accepted");
        Check(!Access::Writer(*owner).WriteBlock(40, Bytes(4096, std::byte{7}), error), "other member mutation after loss");
        Check(owner->Status().unavailable_members == 2, "tier loss mask"); owner->Close(); Check(Load(f.main) == before, "other image changed");
    });
    Run("original accepted inline overwrite survives exact owner and WAL reopen", [&] {
        Files f(root); auto owner = f.Open(); const auto identity = owner->JournalIdentity(); const auto wal = (f.directory / "original.wal").wstring();
        std::uint64_t sequence = 0; std::string error;
        {
            TransactionManager tx(L"Strict"); tx.SetVolumeIdentity(identity); tx.SetJournalPath(wal);
            TransactionManager::MutationIntent m; m.path = L"\\file.txt"; m.object_id = 30; m.generation = 20;
            m.offset = 4093; m.length = m.payload_length = 6; m.inline_payload = Bytes(6, std::byte{0x63});
            Check(BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, reinterpret_cast<PUCHAR>(m.inline_payload.data()), 6,
                m.payload_checksum.data(), 32) >= 0, "intent hash");
            Check(tx.Begin() && tx.RecordMutation(m) && tx.Accept(20), "actual original acceptance"); sequence = tx.Watermarks().accepted_sequence;
            FusionAcceptedOverwriteInspection proof;
            Check(owner->InspectAcceptedOverwrite(tx, sequence, proof, error) && proof.original_payload == m.inline_payload, "accepted inspect: " + error);
            Check(!owner->InspectAcceptedOverwrite(tx, sequence + 1, proof, error) && proof.original_payload.empty(), "wrong boundary accepted");
            Check(tx.Watermarks().apfs_durable_sequence == 0 && tx.Watermarks().cleanup_sequence == 0, "inspection retired original debt");
        }
        owner->Close(); f.Refresh(20); owner = f.Open(); Check(identity == owner->JournalIdentity(), "stable recovered journal identity");
        TransactionManager recovered(L"Strict"); recovered.SetVolumeIdentity(identity); recovered.SetJournalPath(wal);
        FusionAcceptedOverwriteInspection proof;
        Check(owner->InspectAcceptedOverwrite(recovered, sequence, proof, error) && proof.inode == 30 && proof.offset == 4093,
            "original recovery inspection: " + error);
        Check(!owner->CheckAllocatorAdmission(error) && error == "AppleSpacemanInternalPoolGeometryInvalid", "recovery evaded ownership");
        Check(recovered.Watermarks().apfs_durable_sequence == 0 && recovered.Watermarks().cleanup_sequence == 0, "recovery inspection retired debt");
        TransactionManager foreign(L"Strict"); foreign.SetVolumeIdentity(L"wrong"); foreign.SetJournalPath((f.directory / "foreign.wal").wstring());
        Check(!owner->InspectAcceptedOverwrite(foreign, sequence, proof, error) && error == "FusionImageOriginalJournalMismatch", "foreign journal accepted");
    });
    Run("two-image ordered publication transport and independent reopen", [&] {
        Files f(root, 3); auto before_main = Load(f.main), before_tier = Load(f.tier); auto owner = f.Open();
        auto plan = TransportPlan(*owner); std::string error; Check(Execute(*owner, plan, error), "transport publish: " + error);
        Check(Access::Writer(*owner).counters().tier2_flushes >= 3 && Access::Writer(*owner).counters().main_flushes >= 3, "all-member barriers");
        VerifyWrites(*owner, plan); owner->Close(); f.Refresh(21); owner = f.Open(); VerifyWrites(*owner, plan); owner->Close();
        const auto after_main = Load(f.main), after_tier = Load(f.tier);
        Check(std::equal(before_main.begin(), before_main.begin() + static_cast<std::ptrdiff_t>(f.prefix), after_main.begin()) &&
            std::equal(before_tier.begin(), before_tier.begin() + static_cast<std::ptrdiff_t>(f.prefix), after_tier.begin()), "member prefixes changed");
        auto readonly = ApfsFusionStore::BindImages(f.request, error); FusionReadStatus status;
        auto reader = ApfsFusionReadSession::Open(std::move(readonly), f.Selection(), status, error); Bytes data;
        Check(reader && reader->ReadFile(30, 4093, 6, data, error) && data[0] == std::byte{0xA1} && data[3] == std::byte{0xB1}, "independent reader: " + error);
    });
    for (const std::string stage : {"before-apple-device-write", "before-apple-prepublication-flush", "before-apple-fusion-anchor-mirror",
        "before-apple-checkpoint-switch", "before-apple-final-flush"}) Run(stage.c_str(), [&] {
        Files f(root); auto owner = f.Open(); const auto binding = owner->SourceBinding(); auto plan = TransportPlan(*owner); std::string error;
        Check(!Execute(*owner, plan, error, [&](std::string_view at) { return at != stage; }), "stage interruption missed");
        const auto xid = stage == "before-apple-final-flush" ? 21u : 20u;
        owner->Close(); f.Refresh(xid); owner = f.Open(); Check(binding == owner->SourceBinding(), "recovery source binding drift");
        Check(owner->Status().tier_ahead == (stage == "before-apple-checkpoint-switch"), "exact mirror skew classification");
        if (xid == 20) Check(Execute(*owner, plan, error), "transport resume under old checkpoint: " + error);
        else Check(Access::Writer(*owner).FlushOrdered(error), "post-switch both-member barrier");
        VerifyWrites(*owner, plan); owner->Close(); f.Refresh(21); owner = f.Open(); VerifyWrites(*owner, plan);
    });
    std::cout << "PASS " << cases << " cases, " << checks << " checks; canonical regular-image ownership and ordinary planning, original-WAL replay/mount integration remains open\n";
    return 0;
}
catch (const std::exception& e) { std::cerr << "FAIL after " << cases << " cases, " << checks << " checks: " << e.what() << '\n'; return 1; }
