#define wmain FormatStorageTestMain
#include "VolumeFormatStorageTests.cpp"
#undef wmain
#include "../src/VolumeManagementInternal.h"
#include "../src/VolumePhysicalBindingCodec.h"
#include "VolumeManagementTestFixture.h"
namespace vm = apfsaccess::rw::volume_management;
Bytes PrivateFixture() {
    auto image = Fixture(); std::string error;
    const auto uuid = [](Bytes& bytes, std::size_t offset, std::string_view value) {
        const auto hex = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
        for (unsigned i=0;i<16;++i)bytes[offset+i]=std::byte((hex(value[2*i])<<4)|hex(value[2*i+1]));
    };
    for(std::size_t at=0;at<image.size();at+=4096){Bytes block(image.begin()+at,image.begin()+at+4096);bool changed=false;
        if(ParseNxSuperblock(block)){uuid(block,0x48,"68c088bb461c4cf18b0223e8c230f340");changed=true;}
        if(const auto volume=ParseApsb(block)) {uuid(block,0xf0,volume->object_id==201 ? "78c088bb461c4cf18b0223e8c230f341" : "78c088bb461c4cf18b0223e8c230f342");changed=true;}
        if(changed){Check(FinalizeAppleObjectChecksum(block,error),error);std::copy(block.begin(),block.end(),image.begin()+at);}
    }
    return image;
}
VolumeManagementRequest CreateRequest(const std::filesystem::path& dir) {
    auto image = Read(dir / "image.apfs"); const auto cp = Checkpoint(image); VolumeManagementRequest r;
    r.operation = VolumeManagementOperation::Create; r.image = dir / "image.apfs"; r.journal_directory = dir;
    r.container_uuid = cp.container.superblock.uuid_hex; r.volume_uuid = "a8c088bb461c4cf18b0223e8c230f345";
    r.volume_oid = cp.container.superblock.next_oid; r.checkpoint_xid = cp.container.superblock.xid;
    r.name_utf8 = "Beta"; r.case_sensitive = false;
    for (const auto& v : cp.volumes) r.sibling_wals[v.superblock.object_id] = dir / (std::to_string(v.superblock.object_id) + ".wal");
    return r;
}
void SnapshotStorage(const Bytes& image, bool physical) {
    const auto cp = Checkpoint(image); const auto v = std::find_if(cp.volumes.begin(), cp.volumes.end(),
        [](const auto& x) { return x.superblock.uuid_hex == "a8c088bb461c4cf18b0223e8c230f345"; });
    Check(v != cp.volumes.end() && v->snapshot_metadata_tree.has_value(), "created Beta snapshot root exists");
    const auto& tree = *v->snapshot_metadata_tree;
    Check(tree.type == ((physical ? kObjectPhysical : 0) | 2), "exact selected snapshot root storage policy");
    Check(tree.object_id == (physical ? tree.physical_block : 1025), "exact selected snapshot root identity");
    Bytes apsb(image.begin() + v->superblock_object.physical_block * 4096,
        image.begin() + (v->superblock_object.physical_block + 1) * 4096);
    Check(ReadU32LE(apsb, 0x7c) == tree.type && ReadU64LE(apsb, 0x98) == tree.object_id, "APSB exact snapshot type and OID/paddr");
    VectorRandomAccessSource source(image); std::vector<BtreeRecord> records; std::string error;
    Check(ReadBtreeLeafRecords(source, 4096, v->object_map.tree.physical_block, true, 0, cp.container.superblock.xid, records, error), error);
    Check(std::count_if(records.begin(), records.end(), [](const auto& r) { return ReadU64LE(r.key, 0) == 1025; }) == (physical ? 0 : 1),
        "physical snapshot root has no fake virtual OMAP record");
}
int wmain(int argc, wchar_t** argv) {
    try {
        Check(argc == 3, "mode and private D root required"); root = argv[2];
        Check(root.wstring().starts_with(L"D:\\"), "D-only private image"); const std::wstring_view mode(argv[1]);
        auto original = PrivateFixture(); auto format = Request(root, VolumeImageOperation::Format, original);
        if (mode == L"setup") { std::filesystem::create_directories(root); Save(format.image, original); }
        else if (mode == L"alpha") { AddProbe(format, 1024, 29, 17); }
        else if (mode == L"beta") {
            auto r = CreateRequest(root); auto image = Read(format.image); SnapshotStorage(image, true);
            const auto cp = Checkpoint(image); const auto found = std::find_if(cp.volumes.begin(), cp.volumes.end(),
                [&](const auto& v) { return v.superblock.uuid_hex == r.volume_uuid; });
            AddProbe(format, found->superblock.object_id, 31, 9); SnapshotStorage(Read(format.image), true);
        } else if (mode == L"cut") {
            auto r = CreateRequest(root); const auto prepared = PrepareVolumeCreate(r);
            Check(prepared.outcome == VolumeManagementOutcome::Prepared, prepared.error);
            const auto result = ApplyVolumeManagement(r, prepared.confirmation_token, [](auto stage) { return stage != "before-apple-checkpoint-switch"; });
            Check(result.outcome == VolumeManagementOutcome::RecoveryRequired, result.error);
            const auto frame = Read(prepared.journal_path);
#ifdef APFS_TOPOLOGY_LEGACY_TEST
            Check(ReadU64LE(frame, 0) == 0x31544d5653465041ull, "actual old VMT1 accepted original");
#else
            Check(ReadU64LE(frame, 0) == volume_physical::PhysicalSnapshotImageMagic, "new VMT3 accepted original");
#endif
        } else if (mode == L"recover" || mode == L"legacy-recover") {
            auto r = CreateRequest(root); const auto image = Read(format.image); const auto cp = Checkpoint(image);
            // The cut is before selection changes; retain the exact original request.
            Check(cp.volumes.size() == 1, "canonical original checkpoint selected at cut");
            const auto result = RecoverVolumeManagement(r); Check(result.outcome == VolumeManagementOutcome::Committed, result.error);
            SnapshotStorage(Read(format.image), mode != L"legacy-recover");
        }
#ifndef APFS_TOPOLOGY_LEGACY_TEST
        else if (mode == L"plans") {
            const auto r = CreateRequest(root); const auto bytes = Read(format.image); VectorRandomAccessSource source(bytes); std::string error;
            vm::TopologyPlan old, next; Check(vm::PlanTopology(source, r, old, error), error); Check(vm::PlanTopologyV2(source, r, next, error), error);
            Check(old.publication.superblock_write.bytes == next.publication.superblock_write.bytes, "NX selection serialization remains exact");
            Check(old.publication.before_superblock_writes.size() == next.publication.before_superblock_writes.size(), "same complete destination set");
            unsigned changed = 0;
            for (std::size_t i = 0; i < old.publication.before_superblock_writes.size(); ++i) {
                const auto& a=old.publication.before_superblock_writes[i];const auto& b=next.publication.before_superblock_writes[i];
                Check(a.physical_block == b.physical_block, "same COW block");
                if(a.bytes!=b.bytes){const auto type=ReadU32LE(b.bytes,24).value_or(0),subtype=ReadU32LE(b.bytes,28).value_or(0);
                    Check(type==13 || (type==(kObjectPhysical|2) && (subtype==11 || subtype==16)), "only APSB/snapshot root/OMAP differ");++changed;}
            }
            Check(changed==3,"exactly three object changes");
        }
#endif
        else throw std::runtime_error("known mode required");
        std::cout << "PASS checks=" << checks << '\n'; return 0;
    } catch(const std::exception& e){std::cerr << "FAIL checks=" << checks << ' ' << e.what() << '\n';return 1;}
}
