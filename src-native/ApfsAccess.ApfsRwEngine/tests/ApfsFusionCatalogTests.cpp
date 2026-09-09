#define main foundation_main
#include "ApfsFusionStoreTests.cpp"
#undef main
#include "ApfsFusionReadSession.h"
#include "ApfsExtendedRecordCodec.h"
#include "TestFixtureBuilder.h"
#include <type_traits>
namespace tf = apfsaccess::testfixture;
using namespace apfsaccess::rw;
using Record = apfsaccess::catalog::BtreeRecord;
static_assert(!std::is_convertible_v<AppleReadOnlyVolumeView, AppleCheckpointView>);
namespace {
std::string active_filter;
template<class T, class F> Record Enc(const T& value, F encode) {
    Record out; std::string error; if (!encode(value,out,error)) throw std::runtime_error(error); return out;
}
Record FileInode(std::uint64_t id, std::uint64_t size, unsigned links, bool dir=false, bool sparse=false) {
    AppleInodeRecord inode;inode.object_id=id;inode.parent_id=2;inode.private_id=id;
    inode.mode=dir?0040755:0100644;inode.children_or_links=links;
    if(!dir) { inode.uncompressed_size=size;AppleExtendedField stream{8,0,Bytes(40)};
        Put(stream.data,0,size);Put(stream.data,8,sparse?size-4096:size);inode.extended_fields.push_back(stream);
        if(sparse){inode.internal_flags=0x200;AppleExtendedField holes{13,0,Bytes(8)};Put(holes.data,0,4096);inode.extended_fields.push_back(holes);}}
    return Enc(inode,EncodeAppleInodeRecord);
}
struct CatalogFixture : Fixture {
    std::vector<Record> fs;
    bool insensitive=false, sparse=false, swapped=false;
    std::vector<tf::OmapRecordSpec> mappings;
    explicit CatalogFixture(bool multilevel=false,bool fold=false,bool hole=false,bool swap=false)
        : insensitive(fold),sparse(hole),swapped(swap) {
        EditNx([&](auto& b){Put(b,0xB8,101);Put(b,0xC0,102);});
        Place(0,15,tf::BuildOmap(18,20,bs,15,kObjectPhysical|kObjectTypeOmap,kObjectPhysical|kObjectTypeBtree));
        auto cm=tf::BuildBtreeNode({{101,swapped?16:TierBlock()+4,0,20},{102,swapped?TierBlock()+4:16,0,20}},20,bs,0,18,kObjectPhysical|kObjectTypeBtree,kObjectTypeOmap);Place(0,18,cm);
        tf::BuilderVolume v;v.oid=101;v.uuid_hex=std::string(32,'c');v.vol_omap_oid_override=TierBlock()+5;v.root_oid_override=1000;v.incompat=fold?1:0;v.name="Fusion Data";
        Place(swapped?0:1,swapped?16:4,tf::BuildApsb(v,20,bs));
        v.oid=102;v.uuid_hex=std::string(32,'d');v.vol_omap_oid_override=12;v.root_oid_override=2000;v.name="Second";v.incompat=0;
        Place(swapped?1:0,swapped?4:16,tf::BuildApsb(v,20,bs));
        Place(1,5,tf::BuildOmap(TierBlock()+6,20,bs,TierBlock()+5,kObjectPhysical|kObjectTypeOmap,kObjectPhysical|kObjectTypeBtree));
        Place(0,12,tf::BuildOmap(13,20,bs,12,kObjectPhysical|kObjectTypeOmap,kObjectPhysical|kObjectTypeBtree));
        Place(0,13,tf::BuildBtreeNode({{2000,TierBlock()+7,0,20}},20,bs,0,13,kObjectPhysical|kObjectTypeBtree,kObjectTypeOmap));
        auto root=FileInode(2,0,0,true);Place(1,7,tf::BuildRawLeafNode({root.key},{root.value},20,bs,0,2000,kObjectTypeBtree,kObjectTypeFsTree));
        AppleDirectoryRecord d;d.parent_id=2;d.file_id=30;d.name_utf8="Caf\xc3\xa9.txt";d.flags=8;
        const auto encodeDir = [&](const auto& v, auto& r, auto& error) { return EncodeAppleDirectoryRecord(v, ApfsNamePolicy::FromIncompatibleFeatures(fold?1:0), r, error); };
        fs={FileInode(2,0,multilevel?31:1,true),FileInode(30,(sparse?5:4)*4096,1,false,sparse),Enc(d,encodeDir)};
        for(unsigned n=0;n<4;++n) fs.push_back(Enc(AppleFileExtentRecord{30,n*4096ULL,4096,(n%2?TierBlock():0)+20+n/2,0,4096},EncodeAppleFileExtentRecord));
        if(sparse)fs.push_back(Enc(AppleFileExtentRecord{30,4*4096,4096,0,0,4096},EncodeAppleFileExtentRecord));
        fs.push_back(Enc(AppleXattrRecord{30,"com.apple.FinderInfo",kAppleXattrDataEmbedded,Bytes(32,std::byte{0x42})},EncodeAppleXattrRecord));
        Bytes desc(48);Put(desc,0,40);Put(desc,8,8192);Put(desc,16,8192);
        fs.push_back(Enc(AppleXattrRecord{30,"com.apple.ResourceFork",kAppleXattrDataStream,desc},EncodeAppleXattrRecord));
        fs.push_back(Enc(AppleDataStreamIdRecord{40,1},EncodeAppleDataStreamIdRecord));
        fs.push_back(Enc(AppleFileExtentRecord{40,0,4096,22,0,4096},EncodeAppleFileExtentRecord));
        fs.push_back(Enc(AppleFileExtentRecord{40,4096,4096,TierBlock()+22,0,4096},EncodeAppleFileExtentRecord));
        Place(0,22,Bytes(bs,std::byte{'X'}));Place(1,22,Bytes(bs,std::byte{'Y'}));
        if(multilevel)for(unsigned n=0;n<30;++n){fs.push_back(FileInode(100+n,0,1));d.file_id=100+n;d.name_utf8="child-"+std::to_string(n);fs.push_back(Enc(d,encodeDir));}
        Trees(multilevel);
    }
    void Trees(bool multi=false,bool sort=true) {
        std::string error;auto order=insensitive?AppleBtreeKeyOrder::FileSystemHashedDirectory:AppleBtreeKeyOrder::FileSystemCaseSensitive;
        if(sort && !SortAppleBtreeRecords(fs,order,error))throw std::runtime_error(error);
        mappings={{1000,30,0,20}};
        if(multi){AppleBtreeOptions options;options.block_size=bs;options.xid=20;options.root_object_id=1000;options.root_physical_block=30;
            options.first_child_object_id=3000;options.first_child_physical_block=31;options.subtype=14;options.key_order=order;
            AppleSerializedBtree tree;if(!SerializeAppleBtree(fs,options,tree,error)||!tree.height)throw std::runtime_error("multilevel fixture "+error);
            unsigned n=0;for(auto& object:tree.objects){if(object.location.object_id==1000){Place(0,30,object.bytes);continue;}
                const auto tier=n%2;const auto block=(tier?10:31)+n/2;Place(tier,block,object.bytes);
                mappings.push_back({object.location.object_id,(tier?TierBlock():0)+block,0,20});++n;}
        }else{std::vector<Bytes> keys,values;for(auto& r:fs){keys.push_back(r.key);values.push_back(r.value);}Place(0,30,tf::BuildRawLeafNode(keys,values,20,bs,0,1000,kObjectTypeBtree,14));}
        Maps();
    }
    void Maps(){std::sort(mappings.begin(),mappings.end(),[](auto a,auto b){return a.oid<b.oid;});Place(1,6,tf::BuildBtreeNode(mappings,20,bs,0,TierBlock()+6,kObjectPhysical|kObjectTypeBtree,kObjectTypeOmap));}
    FusionVolumeSelection Selection(){return {request.container_uuid_hex,std::string(32,'c'),{request.members[0].stable_store_id,request.members[1].stable_store_id},101,20};}
    std::unique_ptr<ApfsFusionReadSession> Open(){auto store=Good();FusionReadStatus status;std::string error;auto session=ApfsFusionReadSession::Open(std::move(store),Selection(),status,error);Check(bool(session),"open: "+error);return session;}
};
void PositiveCatalog(bool multi,bool fold,bool sparse,bool swapped){
    CatalogFixture f(multi,fold,sparse,swapped);auto s=f.Open();std::string error;ApfsContainerCatalog c;Check(s->GetCatalog(c,error),error);
    Check(c.DiskSizeBytes()==96*4096&&c.Stores()[0].size_bytes==64*4096&&c.Stores()[1].size_bytes==32*4096,"capacity versus routing span");
    Check(c.Containers().size()==1&&c.Containers()[0].volumes.size()==2&&c.Containers()[0].validation==CatalogValidation::ReadOnlyObjects,"readonly catalog");
    Check(!c.TryGetAppleCheckpointView(c.Stores()[0].stable_store_id)&&!c.Containers()[0].volumes[0].space,"no invented allocator authority");
    ApfsSharedSpaceProjection space;Check(!c.TryProjectSharedSpace(f.request.container_uuid_hex,space,error),"Fusion space denied");
    Check(c.Containers()[0].volumes[0].stable_volume_id=="apfs-vol:"+f.request.container_uuid_hex+":101","stable volume ID");
    std::vector<MetadataStore::DirectoryLink> links;Check(s->Enumerate(2,links,error)&&links.size()==(multi?31:1),"enumerate native FS tree");
    std::uint64_t oid=0;Check(s->Lookup(2,fold?L"CAFE\u0301.TXT":L"Caf\u00e9.txt",oid,error)&&oid==30,"Unicode/case name lookup: "+error);
    if(!fold)Check(!s->Lookup(2,L"CAF\u00c9.TXT",oid,error),"sensitive names folded");
    Bytes out;Check(s->ReadFile(30,4093,8198,out,error),"read cross-tier: "+error);
    Bytes expected(3,std::byte{0xA1});expected.insert(expected.end(),4096,std::byte{0xB1});expected.insert(expected.end(),4096,std::byte{0xA2});expected.insert(expected.end(),3,std::byte{0xB2});Check(out==expected,"actual multiple tier extents payload");
    Check(s->ReadFile(30,(sparse?5:4)*4096,1,out,error)&&out.empty(),"EOF");
    Check(s->ReadXattr(30,"com.apple.ResourceFork",4093,6,out,error)&&out==Bytes({std::byte{'X'},std::byte{'X'},std::byte{'X'},std::byte{'Y'},std::byte{'Y'},std::byte{'Y'}}),"cross-tier external xattr");
    Check(s->ReadXattr(30,"com.apple.FinderInfo",0,32,out,error)&&out==Bytes(32,std::byte{0x42}),"embedded attribute");
    if(sparse)Check(s->ReadFile(30,4*4096-2,6,out,error)&&out==Bytes({std::byte{0xB2},std::byte{0xB2},std::byte{0},std::byte{0},std::byte{0},std::byte{0}}),"shared explicit sparse rules");
}
void BadCatalog(const char* name,const std::function<void(CatalogFixture&)>& edit){if(!active_filter.empty() && std::string(name).find(active_filter)==std::string::npos)return;Run(name,[&]{CatalogFixture f;edit(f);auto store=f.Good();ApfsContainerCatalog c;std::string error;Check(!ApfsContainerCatalog::TryLoadFusion(*store,"f","held",c,error)&&c.Containers().empty(),"bad catalog accepted: "+error);});}
void BadSession(const char* name,const std::function<void(CatalogFixture&)>& edit,bool multi=false){if(!active_filter.empty() && std::string(name).find(active_filter)==std::string::npos)return;Run(name,[&]{CatalogFixture f(multi);edit(f);FusionReadStatus status;std::string error;auto store=f.Good();auto s=ApfsFusionReadSession::Open(std::move(store),f.Selection(),status,error);Check(!s,"bad session accepted: "+error);});}
void PublicationBoundary(unsigned fault) {
    const auto load = [&](CatalogFixture& f, std::uint64_t fail_at, std::uint64_t& count,
        ApfsContainerCatalog& out, std::string& error) {
        auto inputs=f.Inputs(); auto armed=std::make_shared<bool>(false);
        for(auto& input:inputs){auto old=input.verify_unchanged;
            input.verify_unchanged=[&,old,fail_at,armed]{if(!*armed)return old(); ++count;if(fail_at && count==fail_at){
                if(fault==0)return false;
                if(fault==1)(void)f.request.budget->Refuse("TestFinalPublicationBudget");
                if(fault==2)f.sources[0]->budget=std::make_shared<ApfsReadBudget>(999,999999,999,999999);
            }return old();};}
        auto store=ApfsFusionStore::BindTestSources(f.request,inputs,error);
        Check(bool(store),"boundary bind: "+error);
        count=0; *armed=true;
        return ApfsContainerCatalog::TryLoadFusion(*store,"boundary","held",out,error);
    };
    CatalogFixture probe;std::uint64_t total=0;ApfsContainerCatalog good;std::string error;
    Check(load(probe,0,total,good,error),"boundary probe: "+error);Check(total>2,"publication verification counted");
    CatalogFixture f;std::uint64_t count=0;ApfsContainerCatalog out=good;
    Check(!load(f,total,count,out,error),"final publication unexpectedly succeeded");
    Check(count==total && out.Containers().empty() && out.Stores().empty() && !out.TryGetReadOnlyVolumeView(),"partial catalog escaped final check");
}

}
int main(int argc, char** argv){try{
    const std::string filter = argc > 1 ? argv[1] : ""; active_filter = filter;
    const auto Run = [&](const char* name, const std::function<void()>& body) {
        if (filter.empty() || std::string(name).find(filter) != std::string::npos) ::Run(name, body);
    };

    for(bool multi:{false,true})for(bool fold:{false,true})Run((std::string("native catalog and payload multi=")+std::to_string(multi)+" fold="+std::to_string(fold)).c_str(),[&]{PositiveCatalog(multi,fold,false,false);});
    Run("native explicit sparse extent",[]{PositiveCatalog(false,false,true,false);});
    Run("APSB locations reversed across tiers",[]{PositiveCatalog(false,false,false,true);});
    BadCatalog("APSB checksum",[](auto& f){f.sources[1]->bytes[4*4096]^=std::byte{1};});
    BadCatalog("APSB identity",[](auto& f){f.Edit(1,4,[](auto& b){Put(b,8,999);});});
    BadCatalog("OMAP key ordering",[](auto& f){f.Place(0,18,tf::BuildBtreeNode({{102,16,0,20},{101,f.TierBlock()+4,0,20}},20,f.bs,0,18,kObjectPhysical|2,11));});
    BadCatalog("mapping version bounds APSB",[](auto& f){f.Place(0,18,tf::BuildBtreeNode({{101,f.TierBlock()+4,0,19},{102,16,0,20}},20,f.bs,0,18,kObjectPhysical|2,11));});
    BadSession("FS checksum",[](auto& f){f.sources[0]->bytes[30*4096]^=std::byte{1};});
    BadSession("FS node ID",[](auto& f){f.Edit(0,30,[](auto& b){Put(b,8,999);});});
    BadSession("FS record order",[](auto& f){std::reverse(f.fs.begin(),f.fs.end());f.Trees(false,false);});
    BadSession("tier child OMAP wrong ID",[](auto& f){f.Edit(1,10,[](auto& b){Put(b,8,999);});},true);
    BadSession("tier child mapping XID",[](auto& f){for(auto& m:f.mappings)if(m.paddr==f.TierBlock()+10)m.xid=19;f.Maps();},true);
    BadSession("extent enters encoded address hole",[](auto& f){for(auto& r:f.fs)if((ReadU64LE(r.key,0).value()>>60)==8&&ReadU64LE(r.key,0).value()% (1ull<<60)==30){Put(r.value,8,80);break;}f.Trees();});
    BadSession("extent crosses member boundary",[](auto& f){for(auto& r:f.fs)if((ReadU64LE(r.key,0).value()>>60)==8){Put(r.value,0,8192);Put(r.value,8,63);break;}f.Trees();});
    Run("typed crypto unsupported",[]{CatalogFixture f;f.Edit(1,4,[](auto& b){Put(b,0x108,0);});auto store=f.Good();std::string error;FusionReadStatus status;auto s=ApfsFusionReadSession::Open(std::move(store),f.Selection(),status,error);Check(!s&&status==FusionReadStatus::EncryptionUnsupported,error);});
    Run("exact selected identity",[]{CatalogFixture f;auto selected=f.Selection();selected.member_store_ids[1]="other";FusionReadStatus status;std::string error;auto s=ApfsFusionReadSession::Open(f.Good(),selected,status,error);Check(!s&&status==FusionReadStatus::SelectionMismatch,error);});
    Run("both members required for cached reads and EOF",[]{CatalogFixture f;auto s=f.Open();ApfsContainerCatalog c;std::string error;Check(s->GetCatalog(c,error),error);f.sources[1]->present=false;Bytes out(9);Check(!s->ReadFile(30,999999,1,out,error)&&out.empty(),"EOF exposed dead session");Check(c.Containers().empty()&&c.Stores().empty()&&!c.TryGetReadOnlyVolumeView(),"cached catalog survived removal");f.sources[1]->present=true;Check(!s->ReadFile(30,0,1,out,error),"poison revived");});
    Run("late payload failure clears all bytes",[]{CatalogFixture f;auto s=f.Open();f.sources[1]->after_read=[&]{f.sources[0]->present=false;};Bytes out(4);std::string error;Check(!s->ReadFile(30,4093,8,out,error)&&out.empty(),"partial cross-tier output");});
    Run("shared budget exhaustion remains sticky",[]{CatalogFixture f;auto s=f.Open();f.request.budget->LimitRemainingTo(1,4096,100,65536);Bytes out;std::string error;Check(s->ReadFile(30,0,1,out,error),error);Check(!s->ReadFile(30,4096,1,out,error)&&out.empty(),"budget escaped");std::vector<MetadataStore::DirectoryLink> links;Check(!s->Enumerate(2,links,error),"cached bypass budget");});
    Run("explicit cancel invalidates retained catalog",[]{CatalogFixture f;auto s=f.Open();ApfsContainerCatalog c;std::string error;Check(s->GetCatalog(c,error),error);s->Cancel();Check(c.Containers().empty(),"cancel catalog");});
    Run("ordinary strict allocator admission unchanged",[]{tf::BuilderStore spec;auto image=tf::BuildAuthoritativeStoreImage(spec);VectorRandomAccessSource source(image);ApfsContainerCatalog c;std::string error;Check(ApfsContainerCatalog::TryLoadImage(source,"ordinary","memory",c,error,CatalogLoadPolicy::StrictApple),error);Check(c.TryGetAppleCheckpointView(c.Stores()[0].stable_store_id)!=nullptr&&c.Containers()[0].validation==CatalogValidation::CompleteAllocator,"ordinary authority lost");CatalogFixture f;VectorRandomAccessSource main(f.sources[0]->bytes);Check(!ApfsContainerCatalog::TryLoadImage(main,"single","memory",c,error,CatalogLoadPolicy::StrictApple),"ordinary admitted Fusion");});

    for(unsigned fault=0;fault<3;++fault)Run(("final catalog publication fault "+std::to_string(fault)).c_str(),[&]{PublicationBoundary(fault);});
    Run("last catalog backing read failure",[]{CatalogFixture f;auto store=f.Good();f.sources[1]->after_read=[&]{if(f.sources[1]->reads.back().first==7*4096)f.sources[0]->present=false;};ApfsContainerCatalog c;std::string error;Check(!ApfsContainerCatalog::TryLoadFusion(*store,"f","held",c,error)&&c.Containers().empty(),"last read exposed catalog");});
    Run("catalog retains both source leases",[]{std::weak_ptr<Source> main,tier;ApfsContainerCatalog c;std::string error;{CatalogFixture f;main=f.sources[0];tier=f.sources[1];auto store=f.Good();Check(ApfsContainerCatalog::TryLoadFusion(*store,"f","held",c,error),error);}Check(!main.expired()&&!tier.expired()&&c.CheckAvailable(error),"source lease ended with store wrapper");c={};Check(main.expired()&&tier.expired(),"lease not released with final owner");});
    Run("selected session owns source lifetime",[]{std::weak_ptr<Source> main,tier;std::unique_ptr<ApfsFusionReadSession> s;{CatalogFixture f;main=f.sources[0];tier=f.sources[1];s=f.Open();}Bytes out;std::string error;Check(!main.expired()&&!tier.expired()&&s->ReadFile(30,4093,8,out,error),"owned session lost sources");s.reset();Check(main.expired()&&tier.expired(),"session did not release leases");});
    Run("unsupported filesystem feature catalogued without probing",[]{CatalogFixture f;f.Edit(1,4,[](auto& b){Put(b,0x38,0x40);Put(b,0x80,0x123456);});auto store=f.Good();ApfsContainerCatalog c;std::string error;Check(ApfsContainerCatalog::TryLoadFusion(*store,"f","held",c,error),error);Check(c.Containers()[0].volumes[0].read_support==VolumeReadSupport::FeaturesUnsupported,"typed catalog feature");FusionReadStatus status;auto s=ApfsFusionReadSession::Open(std::move(store),f.Selection(),status,error);Check(!s&&status==FusionReadStatus::FeaturesUnsupported,error);});
    Run("encrypted volume catalogued without decrypt guessing",[]{CatalogFixture f;f.Edit(1,4,[](auto& b){Put(b,0x108,8);Put(b,0x80,0x123456);});auto store=f.Good();ApfsContainerCatalog c;std::string error;Check(ApfsContainerCatalog::TryLoadFusion(*store,"f","held",c,error),error);Check(c.Containers()[0].volumes[0].read_support==VolumeReadSupport::EncryptionUnsupported,"typed catalog encryption");FusionReadStatus status;auto s=ApfsFusionReadSession::Open(std::move(store),f.Selection(),status,error);Check(!s&&status==FusionReadStatus::EncryptionUnsupported,error);});
    Run("separate file extent tree typed refusal",[]{CatalogFixture f;f.Edit(1,4,[](auto& b){Put(b,0x408,0x555);Put(b,0x410,kObjectPhysical|2,4);});auto store=f.Good();FusionReadStatus status;std::string error;auto s=ApfsFusionReadSession::Open(std::move(store),f.Selection(),status,error);Check(!s&&status==FusionReadStatus::FileExtentTreeUnsupported,error);});
    BadSession("nonzero extent crypto ID unsupported",[](auto& f){for(auto& r:f.fs)if((ReadU64LE(r.key,0).value()>>60)==8){Put(r.value,16,7);break;}f.Trees();});
    BadSession("missing logical extent is never sparse zero",[](auto& f){for(auto i=f.fs.begin();i!=f.fs.end();++i)if((ReadU64LE(i->key,0).value()>>60)==8){f.fs.erase(i);break;}f.Trees();});
    Run("bounded operation refuses without source dispatch",[]{CatalogFixture f;auto s=f.Open();const auto calls=f.Calls();Bytes out(4);std::string error;Check(!s->ReadFile(30,0,16*1024*1024+1,out,error)&&out.empty()&&s->LastStatus()==FusionReadStatus::RangeLimit&&f.Calls()==calls,"per-call bounds");});
    Run("cached catalog materialization shares budget",[]{CatalogFixture f;auto s=f.Open();f.request.budget->LimitRemainingTo(999,999999,0,0);ApfsContainerCatalog c;std::string error;Check(!s->GetCatalog(c,error)&&c.Containers().empty(),"catalog copied past budget");Bytes out;Check(!s->ReadFile(30,0,1,out,error),"record budget poison bypassed");});

    BadCatalog("Task 546 APSB declared encrypted root",[](auto& f){f.Edit(1,4,[](auto& b){Put(b,0x74,0x10000002,4);});});
    BadCatalog("Task 546 APSB declared headerless root",[](auto& f){f.Edit(1,4,[](auto& b){Put(b,0x74,0x20000002,4);});});
    BadCatalog("Task 546 APSB unexpected subtype",[](auto& f){f.Edit(1,4,[](auto& b){Put(b,0x1C,kObjectTypeFsTree,4);});});
    Run("Task 546 catalog retains member-loss diagnostic",[]{CatalogFixture f;auto store=f.Good();
        f.sources[1]->after_read=[&]{if(f.sources[1]->reads.back().first==7*4096)f.sources[0]->present=false;};
        ApfsContainerCatalog c;std::string error;
        Check(!ApfsContainerCatalog::TryLoadFusion(*store,"f","held",c,error)&&c.Containers().empty(),"failed catalog published");
        Check(error=="FusionMemberDisappearedOrChanged"&&error==store->LastError(),"member-loss diagnostic replaced: "+error);});
    BadCatalog("APSB zero XID",[](auto& f){f.Edit(1,4,[](auto& b){Put(b,16,0);});});
    BadCatalog("APSB nonempty crypto object flag",[](auto& f){f.Edit(1,4,[](auto& b){Put(b,24,0x1000000D,4);});});
    BadCatalog("OMAP encryption transition unsupported",[](auto& f){f.Edit(1,5,[](auto& b){Put(b,0x20,4,4);});});
    BadCatalog("OMAP header object flag unsupported",[](auto& f){f.Edit(0,15,[](auto& b){Put(b,24,0x5000000B,4);});});
    BadCatalog("volume UUID missing",[](auto& f){f.Edit(1,4,[](auto& b){std::fill_n(b.begin()+0xF0,16,std::byte{0});});});
    Run("sparse logical size can exceed physical capacity",[]{CatalogFixture f(false,false,true);std::string error;
        for(auto& r:f.fs){const auto key=ReadU64LE(r.key,0).value();if(key==((3ull<<60)|30)){
            AppleInodeRecord inode;Check(ApfsExtendedRecordCodec::DecodeInode(r,inode,error),error);
            for(auto& field:inode.extended_fields){if(field.type==8){Put(field.data,0,128*4096);Put(field.data,8,4*4096);}if(field.type==13)Put(field.data,0,124*4096);}
            r=Enc(inode,EncodeAppleInodeRecord);
        }if(key==((8ull<<60)|30)&&ReadU64LE(r.key,8).value()==4*4096)Put(r.value,0,124*4096);}
        f.Trees();auto s=f.Open();Bytes out;Check(s->ReadFile(30,127*4096,4096,out,error)&&out==Bytes(4096),"sparse logical capacity confused with routed span");});
    Run("held ordinary images selected bytes",[]{CatalogFixture f;auto request=f.request;std::string error;
        const auto directory=std::filesystem::current_path()/"catalog-images";std::filesystem::create_directories(directory);
        for(unsigned n=0;n<2;++n){auto path=directory/(n?"tier2.img":"main.img");std::ofstream output(path,std::ios::binary|std::ios::trunc);
            output.write(reinterpret_cast<const char*>(f.sources[n]->bytes.data()),static_cast<std::streamsize>(f.sources[n]->bytes.size()));output.close();
            request.members[n].path=path.wstring();Check(ApfsFusionStore::InspectImage(request.members[n].path,request.members[n].exact_identity,error),error);}
        auto store=ApfsFusionStore::BindImages(request,error);Check(bool(store),error);FusionReadStatus status;
        auto session=ApfsFusionReadSession::Open(std::move(store),f.Selection(),status,error);Check(bool(session),error);
        Bytes out;Check(session->ReadFile(30,4094,4,out,error)&&out==Bytes({std::byte{0xA1},std::byte{0xA1},std::byte{0xB1},std::byte{0xB1}}),"held production image selected payload");});

    Run("second selected volume has no first-volume fallback",[]{CatalogFixture f;auto selected=f.Selection();selected.volume_oid=102;selected.volume_uuid_hex=std::string(32,'d');FusionReadStatus status;std::string error;
        auto s=ApfsFusionReadSession::Open(f.Good(),selected,status,error);Check(bool(s),error);std::vector<MetadataStore::DirectoryLink> links;Check(s->Enumerate(2,links,error)&&links.empty(),"second volume namespace");Bytes out;Check(!s->ReadFile(30,0,1,out,error)&&out.empty(),"first volume file leaked");});
    Run("selected session preserves roles after input reorder",[]{CatalogFixture f;auto selected=f.Selection();std::reverse(f.request.members.begin(),f.request.members.end());FusionReadStatus status;std::string error;
        auto s=ApfsFusionReadSession::Open(f.Good(),selected,status,error);Check(bool(s),error);Bytes out;Check(s->ReadFile(30,4094,4,out,error)&&out==Bytes({std::byte{0xA1},std::byte{0xA1},std::byte{0xB1},std::byte{0xB1}}),"enumeration order changed selected route");});
    std::cout<<"PASS "<<cases<<" cases, "<<checks<<" checks; CATALOG AND SELECTED BYTES\n";return 0;
}catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}}
