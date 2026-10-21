#define APFS_FUSION_STORE_TESTING
#include "ApfsFusionSnapshotCatalog.h"
#include "ApfsReadOnlyMetadataAdmission.h"
#include "ApfsExtendedRecordCodec.h"
#include "FusionTestFixture.h"
#include <algorithm>
#include <iostream>

using namespace apfsaccess::catalog;
using namespace apfsaccess::fusiontest;
using namespace apfsaccess::rw;
using CatalogRecord = apfsaccess::catalog::BtreeRecord;
namespace tf = apfsaccess::testfixture;
namespace
{
unsigned cases=0,checks=0;
void Check(bool okay,const std::string& detail){++checks;if(!okay)throw std::runtime_error(detail);}
template<class T,class F>CatalogRecord Enc(T value,F encode){CatalogRecord result;std::string error;Check(encode(value,result,error),error);return result;}
void FileTree(Fixture& f,unsigned member,std::uint64_t local,std::uint64_t xid)
{
    AppleInodeRecord root;root.object_id=root.parent_id=root.private_id=2;root.mode=0040755;root.children_or_links=1;
    AppleInodeRecord file;file.object_id=file.private_id=30;file.parent_id=2;file.mode=0100644;file.children_or_links=1;
    AppleExtendedField stream;stream.type=8;stream.data.resize(40);Put(stream.data,0,4096);Put(stream.data,8,4096);file.extended_fields.push_back(stream);
    AppleDirectoryRecord link;link.parent_id=2;link.file_id=30;link.name_utf8="tier-file";link.flags=8;
    std::vector<CatalogRecord> records{Enc(root,EncodeAppleInodeRecord),Enc(file,EncodeAppleInodeRecord),
        Enc(link,[](const auto& v,auto& r,auto& e){return EncodeAppleDirectoryRecord(v,ApfsNamePolicy::FromIncompatibleFeatures(0),r,e);}),
        Enc(AppleDataStreamIdRecord{30,1},EncodeAppleDataStreamIdRecord),
        Enc(AppleFileExtentRecord{30,0,4096,f.TierBlock()+20,0,4096},EncodeAppleFileExtentRecord)};
    std::string error;Check(SortAppleBtreeRecords(records,AppleBtreeKeyOrder::FileSystemCaseSensitive,error),error);
    std::vector<Bytes> keys,values;for(const auto& r:records){keys.push_back(r.key);values.push_back(r.value);}
    f.Place(member,local,tf::BuildRawLeafNode(keys,values,xid,f.bs,0,1000,kObjectTypeBtree,kObjectTypeFsTree));
}
void Extents(Fixture& f,unsigned member,std::uint64_t local,std::uint64_t xid,bool first=false)
{
    const auto r=Enc(ApplePhysicalExtentRecord{f.TierBlock()+20,1,kApplePhysicalExtentKindNew,30,1},EncodeApplePhysicalExtentRecord);
    f.Place(member,local,tf::BuildRawLeafNode(first?std::vector<Bytes>{r.key}:std::vector<Bytes>{},first?std::vector<Bytes>{r.value}:std::vector<Bytes>{},xid,f.bs,0,(member?f.TierBlock():0)+local,
        kObjectPhysical|kObjectTypeBtree,kObjectTypeBlockRefTree));
}
void CatalogFixture(Fixture& f)
{
    f.EditNx([](auto& b){Put(b,0xB8,101);});
    f.Place(0,15,tf::BuildOmap(18,20,f.bs,15,kObjectPhysical|kObjectTypeOmap,kObjectPhysical|kObjectTypeBtree,1));
    f.Place(0,18,tf::BuildBtreeNode({{101,f.TierBlock()+4,0,20}},20,f.bs,0,18,kObjectPhysical|kObjectTypeBtree,kObjectTypeOmap));
    tf::BuilderVolume v;v.oid=101;v.uuid_hex=std::string(32,'c');v.name="Fusion snapshot catalog";v.incompat=0;
    v.root_oid_override=1000;v.vol_omap_oid_override=f.TierBlock()+5;
    v.extentref_tree_oid=31;v.extentref_tree_type=kObjectPhysical|kObjectTypeBtree;
    v.snap_meta_tree_oid=35;v.snap_meta_tree_type=kObjectPhysical|kObjectTypeBtree;
    auto apsb=tf::BuildApsb(v,20,f.bs);Put(apsb,0xD8,2);Seal(apsb);f.Place(1,4,apsb);
    f.Place(1,5,tf::BuildOmap(f.TierBlock()+6,20,f.bs,f.TierBlock()+5,kObjectPhysical|kObjectTypeOmap,kObjectPhysical|kObjectTypeBtree));
    f.Edit(1,5,[](auto& b){Put(b,0x24,2,4);Put(b,0x2C,kObjectPhysical|kObjectTypeBtree,4);Put(b,0x38,36);Put(b,0x40,19);});
    f.Place(1,6,tf::BuildBtreeNode({{1000,30,0,20}},20,f.bs,0,f.TierBlock()+6,kObjectPhysical|kObjectTypeBtree,kObjectTypeOmap));
    FileTree(f,0,30,20);Extents(f,0,31,20);
    std::vector<Bytes> inventory_keys,inventory_values,index_keys,index_values;
    for(unsigned n=0;n<2;++n)
    {
        const auto xid=18+n;const auto oid=n?40:f.TierBlock()+8;const auto omap=n?42:f.TierBlock()+9;
        const auto extent=n?f.TierBlock()+14:38;const std::string name="snapshot-"+std::to_string(xid);
        Bytes key(8),value(51+name.size());Put(key,0,(1ULL<<60)|xid);Put(value,0,extent);Put(value,8,oid);
        Put(value,40,kObjectPhysical|kObjectTypeBtree,4);Put(value,48,name.size()+1,2);
        std::copy(name.begin(),name.end(),reinterpret_cast<char*>(value.data()+50));
        inventory_keys.push_back(key);inventory_values.push_back(value);
        Bytes name_key(11+name.size()),name_value(8);Put(name_key,0,0xBFFFFFFFFFFFFFFFULL);Put(name_key,8,name.size()+1,2);
        std::copy(name.begin(),name.end(),reinterpret_cast<char*>(name_key.data()+10));Put(name_value,0,xid);
        inventory_keys.push_back(name_key);inventory_values.push_back(name_value);
        Bytes index_key(8);Put(index_key,0,xid);index_keys.push_back(index_key);index_values.emplace_back(16);
        auto snapshot=v;snapshot.oid=oid;snapshot.vol_omap_oid_override=omap;snapshot.extentref_tree_oid=extent;
        auto descriptor=tf::BuildApsb(snapshot,20,f.bs);Put(descriptor,24,kObjectPhysical|kObjectTypeFs,4);Seal(descriptor);
        f.Place(n?0:1,n?40:8,descriptor);
        f.Place(n?0:1,n?42:9,tf::BuildOmap(n?43:f.TierBlock()+11,20,f.bs,omap,kObjectPhysical|kObjectTypeOmap,kObjectPhysical|kObjectTypeBtree));
        f.Place(n?0:1,n?43:11,tf::BuildBtreeNode({{1000,n?41:f.TierBlock()+10,0,xid}},20,f.bs,0,
            n?43:f.TierBlock()+11,kObjectPhysical|kObjectTypeBtree,kObjectTypeOmap));
        FileTree(f,n?0:1,n?41:10,xid);Extents(f,n?1:0,n?14:38,20,n==0);
    }
    std::vector<CatalogRecord> inventory;
    for(std::size_t i=0;i<inventory_keys.size();++i)inventory.push_back({inventory_keys[i],inventory_values[i]});
    std::string error;Check(SortAppleBtreeRecords(inventory,AppleBtreeKeyOrder::FileSystemCaseSensitive,error),error);
    inventory_keys.clear();inventory_values.clear();for(const auto& r:inventory){inventory_keys.push_back(r.key);inventory_values.push_back(r.value);}
    f.Place(0,35,tf::BuildRawLeafNode(inventory_keys,inventory_values,20,f.bs,0,35,kObjectPhysical|kObjectTypeBtree,kObjectTypeSnapMetaTree));
    f.Place(0,36,tf::BuildRawLeafNode(index_keys,index_values,20,f.bs,0,36,kObjectPhysical|kObjectTypeBtree,0x13));
}
void Run()
{
    for(unsigned fault=0;fault<10;++fault)
    {
        Fixture f(4096,3);CatalogFixture(f);auto store=f.Good();std::string error;
        if(fault==1)f.sources[1]->bytes[f.prefix+10*f.bs+100]^=std::byte{1};
        if(fault==2)f.Edit(1,10,[](auto& b){Put(b,16,20);});
        if(fault==3)f.Place(1,11,tf::BuildBtreeNode({{1000,100,0,18}},20,f.bs,0,f.TierBlock()+11,kObjectPhysical|kObjectTypeBtree,kObjectTypeOmap));
        if(fault==4)f.Place(1,11,tf::BuildBtreeNode({{1000,f.TierBlock()+10,4,18}},20,f.bs,0,f.TierBlock()+11,kObjectPhysical|kObjectTypeBtree,kObjectTypeOmap));
        if(fault==5)f.sources[1]->present=false;
        if(fault==6)f.sources[1]->after_read=[&]{if(f.sources[1]->reads.back().first==f.prefix+10*f.bs)f.sources[0]->present=false;};
        if(fault==7)f.request.budget->LimitRemainingTo(1,4096,1000,65536);
        AppleSnapshotCatalogRecords catalog;std::vector<AppleSnapshotMetadataClaim> owners;
        catalog.inventory.emplace_back();catalog.live.filesystem.emplace_back();owners.emplace_back();
        const auto okay=LoadAppleFusionReadOnlySnapshotCatalog(*store,fault==8?19:20,101,fault==9?std::string(32,'d'):std::string(32,'c'),catalog,owners,error);
        Check(okay==(fault==0),"Fusion snapshot result "+std::to_string(fault)+":"+error);
        if(okay)
        {
            Check(catalog.inventory.size()==2&&catalog.snapshots.size()==2&&catalog.live.filesystem.size()==5,"exact complete catalog partitions");
            Check(catalog.inventory[0].xid==18&&catalog.inventory[1].xid==19&&catalog.inventory[0].volume.root_tree.physical_block==f.TierBlock()+10&&
                catalog.inventory[1].volume.root_tree.physical_block==41,"separate snapshot selections and real members");
            Check(std::any_of(owners.begin(),owners.end(),[&](const auto& o){return o.view_xid==18&&o.physical_block==f.TierBlock()+10&&o.object_xid==18;}),"tier snapshot node owner");
            auto view=LoadAppleReadOnlyVolumeView(*store,store->Checkpoint(),error);Check(view.has_value(),error);
            AppleCheckpointView cp;cp.container=std::move(view->container);cp.container_object_map=std::move(view->container_object_map);cp.volumes=std::move(view->volumes);
            for(unsigned repeat=0;repeat<2;++repeat)
            {
                AppleSnapshotCatalogRecords refused;std::vector<AppleSnapshotMetadataClaim> ignored;
                Check(!LoadAppleReadOnlySnapshotCatalog(*store,cp,101,refused,ignored,error)&&refused.inventory.empty(),"ordinary observational parser remains refused for Fusion");
                Check(!LoadAppleSnapshotCatalog(*store,cp,101,refused,ignored,error)&&refused.inventory.empty(),"strict mutation parser remains refused for Fusion");
                Check(LoadAppleFusionReadOnlySnapshotCatalog(*store,20,101,std::string(32,'c'),catalog,owners,error),"warm Fusion catalog after strict refusals:"+error);
            }
        }
        else Check(catalog.inventory.empty()&&catalog.snapshots.empty()&&catalog.live.filesystem.empty()&&owners.empty(),"Fusion catalog failure is atomic");
        ++cases;
    }
    for(unsigned fault=0;fault<5;++fault)
    {
        Fixture f;CatalogFixture(f);
        f.Edit(1,4,[](auto& bytes){Put(bytes,0x98,0);Put(bytes,0xD8,0);});
        f.Place(1,5,tf::BuildOmap(f.TierBlock()+6,20,f.bs,f.TierBlock()+5,
            kObjectPhysical|kObjectTypeOmap,kObjectPhysical|kObjectTypeBtree));
        Extents(f,0,31,20,true);
        if(fault==1)f.Edit(1,4,[](auto& bytes){Put(bytes,0xD8,1);});
        if(fault==2)f.Edit(1,5,[](auto& bytes){Put(bytes,0x24,1,4);Put(bytes,0x2C,kObjectPhysical|kObjectTypeBtree,4);Put(bytes,0x38,36);Put(bytes,0x40,19);});
        if(fault==3)f.Edit(1,4,[](auto& bytes){Put(bytes,0x414,kObjectPhysical|kObjectTypeBtreeNode,4);});
        if(fault==4)f.Edit(1,4,[](auto& bytes){Put(bytes,0x98,35);});
        auto store=f.Good();std::string error;AppleSnapshotCatalogRecords catalog;
        std::vector<AppleSnapshotMetadataClaim> owners(1);catalog.inventory.emplace_back();
        const auto okay=LoadAppleFusionReadOnlySnapshotCatalog(*store,20,101,std::string(32,'c'),catalog,owners,error);
        Check(okay==(fault==0),"absent inventory needs exact zero roots/count/history: "+std::to_string(fault)+":"+error);
        if(okay)Check(catalog.inventory.empty()&&catalog.snapshots.empty()&&catalog.live.filesystem.size()==5&&!owners.empty(),
            "zero snapshot inventory still proves the full current catalog");
        else Check(catalog.inventory.empty()&&catalog.snapshots.empty()&&catalog.live.filesystem.empty()&&owners.empty(),
            "active/malformed absent inventory never publishes partial ownership");
        ++cases;
    }
}
}
#ifndef APFS_FUSION_SNAPSHOT_CATALOG_FIXTURES_ONLY
int main()try{Run();std::cout<<"PASS "<<cases<<" cases / "<<checks<<" checks; in-memory canonical Fusion snapshot catalog\n";return 0;}
catch(const std::exception& error){std::cerr<<"FAIL "<<error.what()<<" after "<<checks<<" checks\n";return 1;}
#endif
