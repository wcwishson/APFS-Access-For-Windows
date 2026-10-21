#include "ApfsSnapshotStore.h"
#include "SnapshotTestFixture.h"
#include <functional>
#include <iostream>
#include <stdexcept>

using namespace apfsaccess::catalog;
using namespace apfsaccess::testfixture;
namespace {
unsigned cases = 0, checks = 0;
void Check(bool value, const std::string& detail) {
    ++checks; if (!value) throw std::runtime_error(detail);
}
using Bytes = std::vector<std::byte>;
using Fixture = apfsaccess::testfixture::SnapshotFixture;
void Pass(const char* label) {++cases;std::cout<<"PASS "<<label<<"\n";}
void Reject(const char* label, const std::function<void(Fixture&)>& mutate,
    const std::string& reason = {}) {
    Fixture f;mutate(f);std::vector<ApfsSnapshotInfo> out(1);std::string error;
    const bool ok=f.Enumerate(out,error);
    Check(!ok,std::string(label)+": accepted malformed input");
    Check(out.empty(),std::string(label)+": partial inventory leaked");
    Check(!error.empty() && (reason.empty() || error.find(reason)!=std::string::npos),
        std::string(label)+": wrong refusal: "+error);
    Pass(label);
}
void Positives() {
    for(auto bs:{4096u,8192u}) {
        Fixture f(bs);std::vector<ApfsSnapshotInfo> out;std::string error;
        Check(f.Enumerate(out,error),"enumerate: "+error);Check(out.size()==1,"one real snapshot");
        const auto& snap=out[0];Check(snap.identity.snapshot_xid==10 && snap.identity.name_utf8=="backup","XID and raw name");
        Check(!snap.snapshot_uuid_hex,"no invented UUID");
        Check(snap.metadata.volume.superblock.uuid_hex==f.scope.volume_uuid_hex,"APSB UUID is volume UUID");
        Check(snap.identity.root_physical_block==183 && snap.identity.omap_physical_block==181,
            "snapshot mapping selected through newer checkpoint OMAP instead of live root");
        Check(snap.metadata.create_time_ns==1234567890123456 && snap.metadata.inum==987,"raw metadata preserved");
        VectorRandomAccessSource source(f.image);ApfsSnapshotInfo exact;
        Check(ApfsSnapshotStore::ValidateExact(source,snap.identity,exact,error),"exact identity accepted: "+error);
        Check(exact.identity==snap.identity,"exact reloaded identity");
        Pass(bs==4096?"snapshot enumeration and exact identity 4K":"snapshot enumeration and exact identity 8K");
    }
    { Fixture f;f.snapshots.clear();f.Inventory({});std::vector<ApfsSnapshotInfo> out(1);std::string e;
      Check(f.Enumerate(out,e)&&out.empty(),"validated empty inventory: "+e);Pass("validated empty metadata tree"); }
    { Fixture f;f.snapshots={Fixture::Metadata(10,"备份 É"),Fixture::Name(10,"备份 É")};f.Inventory();
      std::vector<ApfsSnapshotInfo> out;std::string e;Check(f.Enumerate(out,e),"unicode: "+e);
      Check(out[0].identity.name_utf8=="备份 É","Unicode retained byte for byte");Pass("Unicode exact name preserved"); }
    { Fixture f;auto original=f.image;f.image.insert(f.image.begin(),8192,std::byte{0xEA});
      f.image.insert(f.image.end(),4096,std::byte{0xEB});f.scope.store_offset_bytes=8192;
      std::vector<ApfsSnapshotInfo> out;std::string e;Check(f.Enumerate(out,e)&&out.size()==1,"offset store: "+e);
      Check(std::equal(original.begin(),original.end(),f.image.begin()+8192),"source unchanged");Pass("nonzero bounded store offset"); }
    // Multi-level virtual snapshot tree: historical children resolved through
    // the current OMAP. Child identity and node generation remain historical.
    { Fixture f;Bytes key(8),child(8);PutU64LE(key,0,1ull<<60);PutU64LE(child,0,0x7000);
      auto root=BuildRawLeafNode({key},{child},10,f.bs,0,Fixture::root_oid,2,14);
      PutU16LE(root,0x20,1);PutU16LE(root,0x22,1);PutU64LE(root,f.bs-8,2);f.Put(183,root);
      auto leaf=BuildRootFsLeaf(10,f.bs,0x7000,3,14);
      // A nonroot node has no 40-byte tree-info trailer: move the value to
      // its real end-relative position and return the trailer space to free.
      const auto inode=BuildRootInodeValue(2,9);
      std::move_backward(leaf.begin()+f.bs-40-inode.size(),leaf.begin()+f.bs-40,leaf.end());
      PutU16LE(leaf,0x2E,static_cast<std::uint16_t>(ReadU16LE(leaf,0x2E).value()+40));
      PutU16LE(leaf,0x20,2);f.Put(186,leaf);
      f.SetMappings({{0x7000,186,0,10}});std::vector<ApfsSnapshotInfo> out;std::string e;
      Check(f.Enumerate(out,e),"historical virtual child: "+e);
      BtreeReadPolicy policy;policy.enforce_object_identity=true;policy.root_object_id=Fixture::root_oid;
      policy.subtype=14;policy.require_complete_traversal=true;policy.reject_unsupported_flags=true;
      policy.virtual_child_resolver=[](std::uint64_t oid,std::string&)->std::optional<BtreeVirtualChildMapping>{
          return oid==0x7000?std::optional<BtreeVirtualChildMapping>{{186,10}}:std::nullopt;};
      VectorRandomAccessSource source(f.image);std::vector<BtreeRecord> records;
      Check(ReadBtreeLeafRecords(source,static_cast<std::uint32_t>(f.bs),183,false,5,10,policy,records,e)&&
          records.size()==1&&records[0].value==inode,"child decodes intact Mac inode bytes: "+e);
      Pass("historical multilevel virtual child"); }
    { Fixture f;f.SecondSnapshot();std::vector<ApfsSnapshotInfo> out;std::string e;
      Check(f.Enumerate(out,e)&&out.size()==2,"two snapshots: "+e);
      Check(out[0].identity.snapshot_xid==10&&out[1].identity.snapshot_xid==11,"ordered snapshot identities");
      Check(out[0].identity.root_physical_block==183&&out[1].identity.root_physical_block==188,"distinct historical roots");
      Check(out[0].identity.name_utf8=="backup"&&out[1].identity.name_utf8=="Backup","no Windows case folding");
      VectorRandomAccessSource source(f.image);ApfsSnapshotInfo exact;
      Check(ApfsSnapshotStore::ValidateExact(source,out[1].identity,exact,e),"second exact snapshot");
      Pass("multiple snapshots and exact case-distinct names"); }
    { BuilderStore spec;spec.xid=20;spec.block_count=512;spec.volumes[0].uuid_hex=std::string(32,'b');
      BuilderVolume second;second.oid=102;second.uuid_hex=std::string(32,'c');second.name="Other";spec.volumes.push_back(second);
      auto bytes=BuildAuthoritativeStoreImage(spec);
      Bytes omap(bytes.begin()+2*4096,bytes.begin()+3*4096);PutU32LE(omap,0x20,1);
      FletcherForBlock(omap,4096);std::copy(omap.begin(),omap.end(),bytes.begin()+2*4096);
      VectorRandomAccessSource source(bytes);
      ApfsSnapshotScope scope{0,bytes.size(),std::string(32,'a'),std::string(32,'c'),102,20};
      std::vector<ApfsSnapshotInfo> out;std::string e;
      Check(ApfsSnapshotStore::Enumerate(source,scope,out,e)&&out.empty(),"second volume binding: "+e);
      scope.volume_oid=101;Check(!ApfsSnapshotStore::Enumerate(source,scope,out,e),"crossed volume UUID and OID rejected");
      Pass("selected second volume and crossed identity refusal"); }
}
void IdentityTests() {
    Fixture f;std::vector<ApfsSnapshotInfo> out;std::string error;
    Check(f.Enumerate(out,error),"identity fixture enumerates");const auto original=out[0].identity;
    const std::vector<std::pair<const char*,std::function<void(ApfsSnapshotIdentity&)>>> changes={
        {"exact wrong container",[](auto& x){x.scope.container_uuid_hex=std::string(32,'c');}},
        {"exact wrong volume UUID",[](auto& x){x.scope.volume_uuid_hex=std::string(32,'c');}},
        {"exact wrong volume OID",[](auto& x){++x.scope.volume_oid;}},
        {"exact missing checkpoint no fallback",[](auto& x){--x.scope.checkpoint_xid;}},
        {"exact wrong XID",[](auto& x){++x.snapshot_xid;}},
        {"exact case mismatch",[](auto& x){x.name_utf8="Backup";}},
        {"exact wrong APSB",[](auto& x){++x.superblock_physical_block;}},
        {"exact wrong OMAP",[](auto& x){++x.omap_physical_block;}},
        {"exact wrong OMAP tree",[](auto& x){++x.omap_tree_physical_block;}},
        {"exact wrong root OID",[](auto& x){++x.root_oid;}},
        {"exact wrong root address",[](auto& x){++x.root_physical_block;}},
        {"exact wrong extent root",[](auto& x){++x.extentref_physical_block;}}
    };
    for(const auto& [name,change]:changes) {auto identity=original;change(identity);
        VectorRandomAccessSource source(f.image);ApfsSnapshotInfo result=out[0];
        Check(!ApfsSnapshotStore::ValidateExact(source,identity,result,error),std::string(name)+" refused");
        Check(result.identity.snapshot_xid==0 && !error.empty(),"exact failure clears output");Pass(name);}
    f.Edit(180,[](auto& b){b[0xF0]=std::byte{0xCC};});
    VectorRandomAccessSource changed(f.image);ApfsSnapshotInfo result;
    Check(!ApfsSnapshotStore::ValidateExact(changed,original,result,error),"fresh bytes rechecked");Pass("exact validation rereads changed source");
}
// Review 485: mapping versions bound virtual object headers independently of
// the snapshot lookup XID and the checkpoint generation of the OMAP itself.
void SnapshotRepairRegressions() {
    unsigned failed = 0;
    const auto run = [&](const std::string& label, const std::function<void()>& test) {
        try { test(); Pass(label.c_str()); }
        catch (const std::exception& e) { ++failed; std::cerr << "FAIL " << label << ": " << e.what() << "\n"; }
    };
    run("physical descriptor cannot borrow a nonempty live OMAP index without its own inventory",[] {
        Fixture f;f.Edit(180,[](auto& b){PutU64LE(b,0x80,5);});
        VectorRandomAccessSource source(f.image);std::string error;
        const auto cp=LoadAppleCheckpointView(source,0,source.SizeBytes(),error);
        Check(cp.has_value(),"malformed descriptor retains a parseable current checkpoint");
        AppleSnapshotCatalogRecords out;
        const bool loaded=LoadAppleSnapshotDescriptorCatalog(source,*cp,101,180,10,out,error);
        Check(!loaded&&error=="SnapshotMetadataRootMissing"&&out.live.filesystem.empty()&&out.inventory.empty(),
            "inconsistent descriptor/index refuses without partial catalog: "+error);
    });
    const auto configure = [](Fixture& f, bool child, std::uint64_t xid, bool wrong_oid) {
        if (!child) {
            f.Put(6,BuildBtreeNode({{Fixture::root_oid,183,0,9},
                {Fixture::root_oid,7,0,20},{Fixture::snap_oid,9,0,20}},20,f.bs,0,6,kObjectPhysical|2,11));
            f.Put(183,BuildRootFsLeaf(xid,f.bs,Fixture::root_oid+(wrong_oid?1:0),2,14));
            return;
        }
        Bytes key(8), value(8);PutU64LE(key,0,(3ull<<60)|2);PutU64LE(value,0,0x7000);
        auto root=BuildRawLeafNode({key},{value},10,f.bs,0,Fixture::root_oid,2,14);
        PutU16LE(root,0x20,1);PutU16LE(root,0x22,1);PutU64LE(root,f.bs-8,2);f.Put(183,root);
        auto leaf=BuildRootFsLeaf(xid,f.bs,wrong_oid?0x7001:0x7000,3,14);
        const auto inode=BuildRootInodeValue(2,9);
        std::move_backward(leaf.begin()+f.bs-40-inode.size(),leaf.begin()+f.bs-40,leaf.end());
        PutU16LE(leaf,0x2E,static_cast<std::uint16_t>(ReadU16LE(leaf,0x2E).value()+40));
        PutU16LE(leaf,0x20,2);f.Put(186,leaf);
        f.SetMappings({{0x7000,186,0,9}});
    };
    for (bool child : {false,true}) {
        for (const auto xid : {8ull,9ull,10ull,11ull}) {
            const std::string label=std::string(child?"child":"root")+" mapping9 header"+
                std::to_string(xid)+" snapshot10 checkpoint20";
            run(label,[&] {
                Fixture f;configure(f,child,xid,false);
                std::vector<ApfsSnapshotInfo> out(1);std::string error;
                const bool ok=f.Enumerate(out,error);
                VectorRandomAccessSource source(f.image);
                std::string checkpoint_error;
                auto cp = LoadAppleCheckpointView(source, 0, source.SizeBytes(), checkpoint_error);
                Check(cp.has_value(), "canonical catalog checkpoint");
                AppleSnapshotCatalogRecords catalog;
                std::string catalog_error;
                const bool catalog_ok = LoadAppleSnapshotCatalog(source, *cp, 101, catalog, catalog_error);
                Check(catalog_ok == ok, "owned catalog preserves strict mapping admission: " + catalog_error);
                AppleSnapshotCatalogRecords physical;
                std::string physical_error;
                const bool physical_ok = LoadAppleSnapshotDescriptorCatalog(source, *cp, 101, 180, 10,
                    physical, physical_error);
                Check(physical_ok == ok, "physical descriptor retains snapshot S and checkpoint C: " + physical_error);
                if (xid<=9) {
                    Check(ok,"historical header rejected: "+error);
                    Check(out.size()==1 && out[0].identity.snapshot_xid==10 &&
                        out[0].identity.root_physical_block==183,"historical snapshot identity");
                    Check(catalog.inventory.size() == 1 && catalog.snapshots.size() == 1 &&
                        !catalog.snapshots[0].filesystem.empty(), "canonical catalog retains complete historical trees");
                    Check(!physical.live.filesystem.empty(), "physical descriptor complete filesystem at S10");
                } else {
                    Check(!ok,"header newer than selected mapping accepted");
                    Check(out.empty(),"failed mapping validation leaked inventory");
                    Check(error==(child?"CatalogBtreeFutureXid":"SnapshotFsTreeFutureXid"),
                        "wrong version refusal: "+error);
                    Check(catalog.inventory.empty() && catalog.snapshots.empty() && catalog.live.filesystem.empty(),
                        "failed owned catalog remains empty");
                    Check(catalog_error == error, "owned catalog preserves exact future-XID refusal");
                    Check(physical.live.filesystem.empty() && physical.inventory.empty(), "physical descriptor failure clears output");
                    Check(child ? physical_error == error : physical_error.ends_with("FutureXid"),
                        "physical descriptor preserves mapping bound refusal: " + physical_error);
                }
            });
        }
        run(child?"child mapping9 wrong OID":"root mapping9 wrong OID",[&] {
            Fixture f;configure(f,child,9,true);
            std::vector<ApfsSnapshotInfo> out(1);std::string error;
            Check(!f.Enumerate(out,error),"wrong OID accepted");
            Check(out.empty(),"wrong OID leaked inventory");
            Check(error==(child?"CatalogBtreeObjectIdMismatch":"SnapshotFsTreeObjectIdMismatch"),
                "wrong identity refusal: "+error);
        });
    }
    run("root mapping9 does not bound child mapping10",[&] {
        Fixture f;configure(f,true,10,false);
        f.Edit(183,[](auto& b){PutU64LE(b,0x10,9);});
        f.Put(6,BuildBtreeNode({{Fixture::root_oid,183,0,9},{Fixture::root_oid,7,0,20},
            {Fixture::snap_oid,9,0,20},{0x7000,186,0,10}},20,f.bs,0,6,kObjectPhysical|2,11));
        std::vector<ApfsSnapshotInfo> out;std::string error;
        Check(f.Enumerate(out,error),"independent node mapping versions: "+error);
        Check(out.size()==1,"one independently mapped tree");
        VectorRandomAccessSource source(f.image);
        auto cp = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        Check(cp.has_value(), "independent inverse checkpoint");
        AppleSnapshotCatalogRecords catalog, physical;
        Check(LoadAppleSnapshotCatalog(source, *cp, 101, catalog, error), "inverse owned catalog: " + error);
        Check(LoadAppleSnapshotDescriptorCatalog(source, *cp, 101, 180, 10, physical, error),
            "inverse physical descriptor root M9 child M10 at S10/C20: " + error);
        Check(physical.live.filesystem.size() == 1, "inverse physical descriptor decodes child");
    });
    run("OMAP tree remains checkpoint bounded",[&] {
        Fixture f;configure(f,true,9,false);
        f.Edit(6,[](auto& b){PutU64LE(b,0x10,21);});
        std::vector<ApfsSnapshotInfo> out(1);std::string error;
        Check(!f.Enumerate(out,error),"future checkpoint OMAP accepted");
        Check(out.empty(),"future OMAP leaked inventory");
        Check(error.find("FutureXid")!=std::string::npos,"wrong OMAP refusal: "+error);
        VectorRandomAccessSource source(f.image);
        auto cp = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        Check(!cp || cp->container.superblock.xid == 20, "future OMAP never advances enclosing checkpoint");
        if (cp) {
            AppleSnapshotCatalogRecords catalog;
            Check(!LoadAppleSnapshotDescriptorCatalog(source, *cp, 101, 180, 10, catalog, error),
                "physical descriptor refuses OMAP21 at C20");
            Check(catalog.live.filesystem.empty() && !error.empty(), "future OMAP physical descriptor clears output");
        }
    });
    run("ValidateExact in-place success",[] {
        Fixture f;std::vector<ApfsSnapshotInfo> out;std::string error;
        Check(f.Enumerate(out,error),"alias fixture enumerates");
        const auto expected=out[0].identity;VectorRandomAccessSource source(f.image);
        Check(ApfsSnapshotStore::ValidateExact(source,out[0].identity,out[0],error),
            "stable in-place validation failed: "+error);
        Check(out[0].identity==expected && out[0].metadata.xid==10 && error.empty(),
            "in-place success must reload the complete descriptor");
    });
    run("ValidateExact in-place changed-source failure",[] {
        Fixture f;std::vector<ApfsSnapshotInfo> out;std::string error;
        Check(f.Enumerate(out,error),"changed alias fixture enumerates");
        f.snapshots={Fixture::Metadata(10,"renamed"),Fixture::Name(10,"renamed")};f.Inventory();
        VectorRandomAccessSource changed(f.image);
        Check(!ApfsSnapshotStore::ValidateExact(changed,out[0].identity,out[0],error),
            "changed source passed in-place validation");
        Check(error=="SnapshotExactIdentityMismatchOrMissing","must re-read valid changed source: "+error);
        Check(out[0].identity==ApfsSnapshotIdentity{} && !out[0].snapshot_uuid_hex &&
            out[0].metadata.xid==0 && out[0].metadata.name_utf8.empty() &&
            out[0].metadata.volume.root_tree.physical_block==0,"failed in-place output must remain clear");
    });
    if (failed) throw std::runtime_error("snapshot repair regressions failed="+std::to_string(failed));
}
void Negatives() {
    Reject("metadata short value",[](auto& f){f.snapshots[0].value.resize(49);f.Inventory();},"Malformed");
    Reject("metadata trailing bytes",[](auto& f){f.snapshots[0].value.push_back(std::byte{0});f.Inventory();},"NameMalformed");
    Reject("metadata name length overflow",[](auto& f){PutU16LE(f.snapshots[0].value,48,65535);f.Inventory();},"NameMalformed");
    Reject("metadata missing NUL",[](auto& f){f.snapshots[0].value.back()=std::byte{'x'};f.Inventory();},"NameMalformed");
    Reject("metadata embedded NUL",[](auto& f){f.snapshots[0].value[51]=std::byte{0};f.Inventory();},"NameMalformed");
    Reject("metadata invalid UTF8",[](auto& f){f.snapshots[0].value[50]=std::byte{0xFF};f.Inventory();},"NameMalformed");
    Reject("name short value",[](auto& f){f.snapshots[1].value.resize(7);f.Inventory();},"NameRecordMalformed");
    Reject("name header identity",[](auto& f){PutU64LE(f.snapshots[1].key,0,11ull<<60);f.Inventory();},"NameRecordMalformed");
    Reject("unknown record type",[](auto& f){PutU64LE(f.snapshots[0].key,0,3ull<<60);f.Inventory();},"TypeUnsupported");
    Reject("unknown metadata flags",[](auto& f){PutU32LE(f.snapshots[0].value,44,0x80);f.Inventory();},"FlagsUnsupported");
    Reject("dataless snapshot unsupported",[](auto& f){PutU32LE(f.snapshots[0].value,44,1);f.Inventory();},"FlagsUnsupported");
    Reject("merging snapshot unsupported",[](auto& f){PutU32LE(f.snapshots[0].value,44,2);f.Inventory();},"FlagsUnsupported");
    Reject("duplicate metadata XID",[](auto& f){f.snapshots.push_back(f.snapshots[0]);f.Inventory();},"Duplicate");
    Reject("ambiguous name records",[](auto& f){f.snapshots.push_back(Fixture::Name(11,"backup"));f.Inventory();},"NameAmbiguous");
    Reject("ambiguous metadata names",[](auto& f){f.snapshots.push_back(Fixture::Metadata(11,"backup"));f.Inventory();},"NameAmbiguous");
    Reject("name XID mismatch",[](auto& f){PutU64LE(f.snapshots[1].value,0,11);f.Inventory();},"IdentityMismatch");
    Reject("missing name record",[](auto& f){f.snapshots.pop_back();f.Inventory();},"CountMismatch");
    Reject("orphan name record",[](auto& f){f.snapshots.erase(f.snapshots.begin());f.Inventory();},"CountMismatch");
    Reject("snapshot XID zero",[](auto& f){PutU64LE(f.snapshots[0].key,0,1ull<<60);f.Inventory();},"XidInvalid");
    Reject("snapshot XID future",[](auto& f){PutU64LE(f.snapshots[0].key,0,(1ull<<60)|21);f.Inventory();},"XidInvalid");
    Reject("missing metadata root",[](auto& f){f.Edit(4,[](auto& b){PutU64LE(b,0x98,0);});},"RootMissing");
    Reject("missing snapshot APSB",[](auto& f){PutU64LE(f.snapshots[0].value,8,0);f.Inventory();},"RootMissing");
    Reject("missing snapshot extent root",[](auto& f){PutU64LE(f.snapshots[0].value,0,0);f.Inventory();},"RootMissing");
    Reject("out of bounds APSB",[](auto& f){PutU64LE(f.snapshots[0].value,8,512);f.Inventory();},"Unreadable");
    Reject("overflow APSB address",[](auto& f){PutU64LE(f.snapshots[0].value,8,~0ull);f.Inventory();},"LocationInvalid");
    Reject("snapshot APSB checksum",[](auto& f){f.Edit(180,[](auto& b){b[0]^=std::byte{1};},false);},"ChecksumInvalid");
    Reject("snapshot APSB wrong volume",[](auto& f){f.Edit(180,[](auto& b){b[0xF0]=std::byte{0xCC};});},"IdentityMismatch");
    Reject("snapshot APSB wrong XID",[](auto& f){f.Edit(180,[](auto& b){PutU64LE(b,0x10,9);});},"IdentityMismatch");
    Reject("snapshot APSB wrong OID",[](auto& f){f.Edit(180,[](auto& b){PutU64LE(b,8,181);});},"ObjectIdMismatch");
    Reject("snapshot APSB missing OMAP",[](auto& f){f.Edit(180,[](auto& b){PutU64LE(b,0x80,0);});},"IdentityMismatch");
    Reject("snapshot extent root mismatch",[](auto& f){f.Edit(180,[](auto& b){PutU64LE(b,0x90,8);});},"RootIdentityMismatch");
    Reject("live extended snapshot UUID metadata",[](auto& f){f.Edit(4,[](auto& b){PutU64LE(b,0x3E8,999);});},"ExtendedMetadataUnsupported");
    Reject("snapshot extended metadata",[](auto& f){f.Edit(180,[](auto& b){PutU64LE(b,0x3E8,999);});},"ExtendedMetadataUnsupported");
    Reject("unknown volume feature",[](auto& f){f.Edit(4,[](auto& b){PutU64LE(b,0x28,1ull<<63);});},"FeaturesUnsupported");
    Reject("encrypted volume",[](auto& f){f.Edit(4,[](auto& b){PutU64LE(b,0x108,0);});},"FeaturesUnsupported");
    Reject("reserved volume field",[](auto& f){f.Edit(4,[](auto& b){PutU64LE(b,0x418,1);});},"ReservedFieldsUnsupported");
    Reject("unknown OMAP flags",[](auto& f){f.Edit(5,[](auto& b){PutU32LE(b,0x20,0x8000);});},"FlagsOrRevertUnsupported");
    Reject("missing mandatory container OMAP flag",[](auto& f){f.Edit(2,[](auto& b){PutU32LE(b,0x20,0);});},"FlagsOrRevertUnsupported");
    Reject("OMAP snapshot root missing",[](auto& f){f.Edit(5,[](auto& b){PutU64LE(b,0x38,0);});},"RootMissing");
    Reject("OMAP wrong snapshot count",[](auto& f){f.Edit(5,[](auto& b){PutU32LE(b,0x24,2);});},"CountOrRecentMismatch");
    Reject("APSB wrong snapshot count",[](auto& f){f.Edit(4,[](auto& b){PutU64LE(b,0xD8,2);});},"CountMismatch");
    Reject("empty metadata root with declared keys",[](auto& f){f.snapshots.clear();f.Inventory({});
        f.Edit(9,[&](auto& b){PutU64LE(b,f.bs-16,1);});},"DeclaredCountsMismatch");
    Reject("wrong Btree node count",[](auto& f){f.Edit(9,[&](auto& b){PutU64LE(b,f.bs-8,2);});},"DeclaredCountsMismatch");
    Reject("live root unknown flags",[](auto& f){f.Edit(7,[](auto& b){PutU16LE(b,0x20,0x43);});},"UnsupportedFlags");
    Reject("live extent root missing",[](auto& f){f.Edit(4,[](auto& b){PutU64LE(b,0x90,0);});},"RootMissing");
    Reject("second snapshot failure clears first result",[](auto& f){f.SecondSnapshot();
        f.Edit(190,[](auto& b){b[0]^=std::byte{1};},false);},"ChecksumInvalid");
    Reject("OMAP snapshot identity disagreement",[](auto& f){f.Inventory({11});},"IdentityMismatch");
    Reject("OMAP snapshot reserved padding",[](auto& f){Bytes key(8),val(16);PutU64LE(key,0,10);PutU32LE(val,4,1);
        f.Put(185,BuildRawLeafNode({key},{val},20,f.bs,0,185,kObjectPhysical|2,0x13));},"ReservedUnsupported");
    Reject("deleted OMAP snapshot unsupported",[](auto& f){Bytes key(8),val(16);PutU64LE(key,0,10);PutU32LE(val,0,1);
        f.Put(185,BuildRawLeafNode({key},{val},20,f.bs,0,185,kObjectPhysical|2,0x13));},"DeletedReverted");
    Reject("OMAP future snapshot XID",[](auto& f){f.Inventory({21});},"XidInvalid");
    Reject("unknown OMAP value flags",[](auto& f){f.SetMappings({{0x9000,187,0x8000,10}});},"UnsupportedRecordFlags");
    Reject("encrypted OMAP value",[](auto& f){f.SetMappings({{0x9000,187,4,10}});},"UnsupportedRecordFlags");
    Reject("duplicate OMAP key",[](auto& f){f.SetMappings({{Fixture::root_oid,183,0,10}});},"KeyDuplicate");
    Reject("historical OMAP tombstone shadows root",[](auto& f){f.SetMappings({{Fixture::root_oid,0,1,10-1}});
        // Use a snapshot at 11 so the tombstone at 11 shadows the old mapping.
        f.SetMappings({{Fixture::root_oid,0,1,11}});f.snapshots={Fixture::Metadata(11,"backup"),Fixture::Name(11,"backup")};
        f.Inventory({11});f.Edit(180,[](auto& b){PutU64LE(b,0x10,11);});},"ValueDeleted");
    for(auto block:{9ull,6ull,183ull,184ull,185ull}) {
        std::string label="tree checksum block "+std::to_string(block);
        Reject(label.c_str(),[&](auto& f){f.Edit(block,[](auto& b){b[0]^=std::byte{1};},false);},"Checksum");
    }
    Reject("unknown node flags",[](auto& f){f.Edit(9,[](auto& b){PutU16LE(b,0x20,0x43);});},"UnsupportedFlags");
    Reject("hashed node unsupported",[](auto& f){f.Edit(9,[](auto& b){PutU16LE(b,0x20,0xB);});},"UnsupportedFlags");
    Reject("unknown tree flags",[](auto& f){f.Edit(9,[&](auto& b){PutU32LE(b,f.bs-40,0x80000040);});},"UnsupportedTreeFlags");
    Reject("unknown object flags",[](auto& f){f.Edit(9,[](auto& b){PutU32LE(b,0x18,0x01000002);});},"TypeMismatch");
    Reject("tree table bounds",[](auto& f){f.Edit(9,[](auto& b){PutU16LE(b,0x2A,1);});},"TableInvalid");
    Reject("tree key bounds",[](auto& f){f.Edit(9,[](auto& b){PutU16LE(b,0x3A,65000);});},"EntryInvalid");
    Reject("ghost metadata record",[](auto& f){f.Edit(9,[](auto& b){PutU16LE(b,0x3C,65535);});},"MissingEntry");
    Reject("future snapshot tree",[](auto& f){f.Edit(183,[](auto& b){PutU64LE(b,0x10,11);});},"FutureXid");
    Reject("cycle in metadata tree",[](auto& f){Bytes key(8),child(8);PutU64LE(key,0,1ull<<60);PutU64LE(child,0,Fixture::snap_oid);
        auto root=BuildRawLeafNode({key},{child},20,f.bs,0,Fixture::snap_oid,2,16);
        PutU16LE(root,0x20,1);PutU16LE(root,0x22,1);f.Put(9,root);},"RepeatedNode");
    Reject("cycle in snapshot FS tree",[](auto& f){Bytes key(8),child(8);PutU64LE(key,0,1ull<<60);PutU64LE(child,0,Fixture::root_oid);
        auto root=BuildRawLeafNode({key},{child},10,f.bs,0,Fixture::root_oid,2,14);
        PutU16LE(root,0x20,1);PutU16LE(root,0x22,1);f.Put(183,root);},"RepeatedNode");
    Reject("unmapped snapshot tree child",[](auto& f){Bytes key(8),child(8);PutU64LE(key,0,1ull<<60);PutU64LE(child,0,0x9999);
        auto root=BuildRawLeafNode({key},{child},10,f.bs,0,Fixture::root_oid,2,14);
        PutU16LE(root,0x20,1);PutU16LE(root,0x22,1);f.Put(183,root);},"ValueMissing");
    Reject("strict parser unsupported checkpoint layout",[](auto& f){f.Edit(0,[](auto& b){PutU32LE(b,0x68,0x80000008);});},"Unsupported");
    Reject("truncated source bounds",[](auto& f){f.image.resize(f.image.size()-1);},"ScopeInvalid");
    Reject("snapshot block cannot escape NX geometry into source suffix",[](auto& f){
        auto bytes=f.Block(180);f.image.insert(f.image.end(),bytes.begin(),bytes.end());f.scope.store_size_bytes=f.image.size();
        PutU64LE(f.snapshots[0].value,8,512);f.Inventory();},"Unreadable");
    {Fixture f;VectorRandomAccessSource source(f.image);auto budget=std::make_shared<ApfsReadBudget>(4,65536,100,65536);
     BudgetedRandomAccessSource bounded(source,budget);std::vector<ApfsSnapshotInfo> out(1);std::string e;
     Check(!ApfsSnapshotStore::Enumerate(bounded,f.scope,out,e)&&out.empty()&&budget->Failed(),"budget fails closed");
     Check(e.find("ApfsReadBudget")!=std::string::npos,"explicit budget refusal");Pass("shared sticky read budget");}
}
}
int main(int argc, char** argv) {try {
    if (argc==2 && std::string(argv[1])=="--repair-regressions") SnapshotRepairRegressions();
    else {Positives();IdentityTests();Negatives();SnapshotRepairRegressions();}
    std::cout<<"RESULT PASS cases="<<cases<<" checks="<<checks<<"\n";return 0;
} catch(const std::exception& e) {std::cerr<<"FAIL after cases="<<cases<<" checks="<<checks<<": "<<e.what()<<"\n";return 1;}}
