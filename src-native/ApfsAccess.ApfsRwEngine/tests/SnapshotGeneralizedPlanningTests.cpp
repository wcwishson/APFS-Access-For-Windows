#define NOMINMAX
#include <windows.h>
#include "AppleVolumeTransaction.h"
#include "ApfsTransactionWriter.h"
#include "SnapshotTestFixture.h"
#include "../src/SnapshotPlanningSource.h"
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <set>
#include <stdexcept>

using namespace apfsaccess::catalog;
using namespace apfsaccess::rw;
using namespace apfsaccess::testfixture;
namespace {
unsigned checks = 0, groups = 0;
void Check(bool ok, const std::string& why) { ++checks; if (!ok) throw std::runtime_error(why); }
void Call(bool ok,const char* label,const std::string& error) {Check(ok,std::string(label)+": "+error);}
void Pass(const char* label) { ++groups; std::cout << "PASS " << label << std::endl; }
template<class T, class F> BtreeRecord Encode(const T& input, F codec) {
    BtreeRecord r; std::string error; Check(codec(input,r,error),"encode: "+error); return r;
}
struct Cohort {
    static constexpr std::uint32_t bs=4096;
    static constexpr std::uint64_t root=SnapshotFixture::root_oid, meta=SnapshotFixture::snap_oid;
    Bytes image;
    AppleCheckpointView checkpoint;
    std::vector<std::uint64_t> extra;
    AppleSerializedBtree metadata, index, mappings;
    Bytes Block(std::uint64_t at) const { return {image.begin()+at*bs,image.begin()+(at+1)*bs}; }
    void Put(std::uint64_t at, Bytes bytes, bool checksum=true) {
        Check(at<image.size()/bs && bytes.size()==bs,"fixture block bounds");
        if(checksum)FletcherForBlock(bytes,bs);
        std::copy(bytes.begin(),bytes.end(),image.begin()+at*bs); extra.push_back(at);
    }
    template<class F> void Edit(std::uint64_t at,F change) { auto bytes=Block(at);change(bytes);Put(at,std::move(bytes)); }
    void Reload() {
        VectorRandomAccessSource source(image);std::string error;
        auto cp=LoadAppleCheckpointView(source,0,source.SizeBytes(),error);
        Check(cp.has_value(),"checkpoint: "+error);checkpoint=std::move(*cp);
    }
    AppleSerializedBtree Tree(std::vector<BtreeRecord> records, AppleBtreeKeyOrder order,
        std::uint64_t oid,std::uint64_t physical,std::uint64_t child,
        std::uint32_t subtype,bool physical_tree) {
        std::string error;Check(SortAppleBtreeRecords(records,order,error),"fixture sort: "+error);
        AppleBtreeOptions o;o.block_size=bs;o.xid=500;o.root_object_id=oid;
        o.root_physical_block=physical;o.first_child_object_id=physical_tree?child:0x8000;
        o.first_child_physical_block=child;o.storage_type=physical_tree?kObjectPhysical:0;
        o.subtype=subtype;o.key_order=order;
        if(physical_tree)o.tree_flags=kAppleBtreePhysical;
        AppleSerializedBtree out;Check(SerializeAppleBtree(records,o,out,error),"fixture serialize: "+error);
        for(const auto& object:out.objects)Put(object.location.physical_block,object.bytes);
        return out;
    }
    explicit Cohort(unsigned count, bool long_names=true, bool payload=false) {
        BuilderStore spec;spec.block_count=1024;spec.xid=500;spec.next_xid=501;
        spec.authoritative_internal_pool_blocks=32;spec.authoritative_checkpoint_ring_blocks=32;
        spec.volumes[0].uuid_hex=std::string(32,'b');spec.volumes[0].next_object_id=0x10000;
        image=BuildAuthoritativeStoreImage(spec);
        Edit(2,[](auto& b){PutU32LE(b,0x20,1);});
        AppleInodeRecord r;r.object_id=2;r.parent_id=2;r.private_id=9;r.mode=0040755;r.children_or_links=payload?1:0;
        AppleInodeRecord f;f.object_id=30;f.parent_id=2;f.private_id=30;f.mode=0100644;f.children_or_links=1;
        f.uncompressed_size=bs;AppleExtendedField stream{8,0,Bytes(40)};
        PutU64LE(stream.data,0,bs);PutU64LE(stream.data,8,bs);f.extended_fields.push_back(stream);
        AppleDirectoryRecord d;d.parent_id=2;d.file_id=30;d.name_utf8="retained.bin";d.flags=8;
        std::vector<BtreeRecord> fs={Encode(r,EncodeAppleInodeRecord),Encode(f,EncodeAppleInodeRecord),
            Encode(d,static_cast<bool(*)(const AppleDirectoryRecord&,BtreeRecord&,std::string&)>(EncodeAppleDirectoryRecord)),
            Encode(AppleDataStreamIdRecord{30,1},EncodeAppleDataStreamIdRecord),
            Encode(AppleFileExtentRecord{30,0,bs,220,0,bs},EncodeAppleFileExtentRecord)};
        if(!payload)fs={Encode(r,EncodeAppleInodeRecord)};
        std::string error;Check(SortAppleBtreeRecords(fs,AppleBtreeKeyOrder::FileSystemCaseSensitive,error),"FS sort");
        std::vector<Bytes> keys,values;for(const auto& x:fs){keys.push_back(x.key);values.push_back(x.value);}
        Put(183,BuildRawLeafNode(keys,values,1,bs,0,root,kObjectTypeBtree,kObjectTypeFsTree));
        Put(7,Block(183));Edit(7,[](auto& b){PutU64LE(b,0x10,500);});
        const auto ref=Encode(ApplePhysicalExtentRecord{220,1,kApplePhysicalExtentKindNew,30,1},EncodeApplePhysicalExtentRecord);
        Put(184,BuildRawLeafNode(payload?std::vector<Bytes>{ref.key}:std::vector<Bytes>{},
            payload?std::vector<Bytes>{ref.value}:std::vector<Bytes>{},1,bs,0,184,kObjectPhysical|kObjectTypeBtree,kObjectTypeBlockRefTree));
        Put(222,BuildRawLeafNode({}, {},1,bs,0,222,kObjectPhysical|kObjectTypeBtree,kObjectTypeBlockRefTree));
        Put(8,BuildRawLeafNode({}, {},500,bs,0,8,kObjectPhysical|kObjectTypeBtree,kObjectTypeBlockRefTree));
        if(!count&&payload){Put(8,Block(184));Edit(8,[](auto& b){PutU64LE(b,8,8);PutU64LE(b,0x10,500);});}
        Put(221,BuildRawLeafNode({}, {},1,bs,0,meta,kObjectTypeBtree,kObjectTypeSnapMetaTree));
        Put(223,BuildOmap(224,1,bs,223,kObjectPhysical|kObjectTypeOmap,kObjectPhysical|kObjectTypeBtree));
        Put(224,BuildBtreeNode({{root,183,0,1},{meta,221,0,1}},1,bs,0,224,kObjectPhysical|kObjectTypeBtree,kObjectTypeOmap));
        Put(220,Bytes(bs,std::byte{0x53}),false);
        std::vector<BtreeRecord> records,snapshot_records;
        for(unsigned i=1;i<=count;++i){
            auto name=std::string(long_names?220:8,'x')+std::to_string(1000+i);
            auto record=SnapshotFixture::Metadata(i,name);
            PutU64LE(record.value,0,i==1?184:222);PutU64LE(record.value,8,300+i);
            records.push_back(record);records.push_back(SnapshotFixture::Name(i,name));
            BuilderVolume v;v.oid=300+i;v.uuid_hex=std::string(32,'b');v.vol_omap_oid_override=223;
            v.root_oid_override=root;v.snap_meta_tree_oid=meta;v.extentref_tree_oid=i==1?184:222;
            auto apsb=BuildApsb(v,i,bs);PutU32LE(apsb,0x18,kObjectPhysical|kObjectTypeFs);
            PutU64LE(apsb,0xB8,payload?1:0);PutU64LE(apsb,0xC0,1);Put(300+i,std::move(apsb));
            BtreeRecord s{Bytes(8),Bytes(16)};PutU64LE(s.key,0,i);snapshot_records.push_back(s);
        }
        metadata=Tree(std::move(records),AppleBtreeKeyOrder::FileSystemCaseSensitive,meta,9,240,kObjectTypeSnapMetaTree,false);
        index=Tree(std::move(snapshot_records),AppleBtreeKeyOrder::SnapshotObjectMap,185,185,230,0x13,true);
        std::vector<OmapRecordSpec> map={{root,183,0,1},{root,7,0,500}};
        for(const auto& o:metadata.objects)map.push_back({o.location.object_id,o.location.physical_block,0,500});
        std::vector<BtreeRecord> omap;
        for(const auto& m:map){BtreeRecord x{Bytes(16),Bytes(16)};
            PutU64LE(x.key,0,m.oid);PutU64LE(x.key,8,m.xid);PutU32LE(x.value,4,bs);
            PutU64LE(x.value,8,m.paddr);omap.push_back(x);}
        mappings=Tree(std::move(omap),AppleBtreeKeyOrder::ObjectMap,6,6,270,kObjectTypeOmap,true);
        Edit(5,[&](auto& b){PutU32LE(b,0x24,count);PutU32LE(b,0x2C,kObjectPhysical|kObjectTypeBtree);
            PutU64LE(b,0x38,185);PutU64LE(b,0x40,count);});
        if(!count)Edit(5,[](auto& b){PutU32LE(b,0x2C,0);PutU64LE(b,0x38,0);});
        const auto volume_blocks=std::set<std::uint64_t>(extra.begin(),extra.end()).size();
        Edit(4,[&](auto& b){PutU64LE(b,0xD8,count);PutU64LE(b,0xB8,payload?1:0);PutU64LE(b,0xC0,1);
            PutU64LE(b,0x58,volume_blocks);PutU64LE(b,0xE0,volume_blocks);});
        Reload();
        auto bitmap=Block(checkpoint.spaceman.chunks.at(0).bitmap_block);std::uint32_t added=0;
        for(auto at:extra){auto& b=bitmap.at(at/8);const auto mask=1u<<(at%8);
            if(!(std::to_integer<unsigned>(b)&mask)){b|=static_cast<std::byte>(mask);++added;}}
        const auto chunk=checkpoint.spaceman.chunks[0];Put(chunk.bitmap_block,bitmap,false);
        Edit(checkpoint.spaceman.devices[0].cibs[chunk.cib_index].object.physical_block,
            [&](auto& b){PutU32LE(b,0x3C,chunk.free_count-added);});
        Edit(checkpoint.spaceman.object.physical_block,[&](auto& b){PutU64LE(b,0x48,checkpoint.spaceman.devices[0].free_count-added);});
        Reload();
    }
};
class MemoryTarget final: public AppleCheckpointWriteTarget {
public:
    Bytes image;std::size_t writes=0;
    explicit MemoryTarget(const Bytes& bytes):image(bytes){}
    bool ReadBlock(std::uint64_t at,std::uint32_t bs,Bytes& out) override {
        VectorRandomAccessSource source(image);return source.Read(at*bs,bs,out);
    }
    bool WriteBlock(std::uint64_t at,std::span<const std::byte> bytes) override {
        if(bytes.size()!=4096||at>=image.size()/4096)return false;
        std::copy(bytes.begin(),bytes.end(),image.begin()+at*4096);++writes;return true;
    }
    bool Flush() override {return true;}
};
AppleCheckpointView Load(const Bytes& image) {
    VectorRandomAccessSource source(image);std::string error;
    auto cp=LoadAppleCheckpointView(source,0,source.SizeBytes(),error);
    Check(cp.has_value(),"reopen: "+error);return *cp;
}
AppleSnapshotRetentionView Verify(const Bytes& image,std::size_t expected,bool payload=false) {
    VectorRandomAccessSource source(image);const auto cp=Load(image);std::string error;
    AppleSnapshotRetentionView retained;
    Check(LoadAppleSnapshotRetention(source,cp,retained,error),"strict ownership: "+error);
    Check(retained.identities.size()==expected,"exact reopened inventory count");
    for(const auto& id:retained.identities){ApfsSnapshotRecords records;
        Check(ApfsSnapshotStore::LoadExactRecords(source,id,records,error),"exact historical records: "+error);
        bool seen=false;for(const auto& r:records.trees.filesystem)if(ReadU64LE(r.key,0).value()>>60==8){
            AppleFileExtentRecord extent;Check(DecodeAppleFileExtentRecord(r,4096,extent,error),"historical extent");
            Bytes bytes;Check(source.Read(extent.physical_block*4096,4096,bytes)&&bytes==Bytes(4096,std::byte{0x53}),"historical file bytes");seen=true;}
        Check(seen==payload,"historical file presence matches authoritative source");
    }
    return retained;
}
std::vector<std::uint64_t> MetadataBlocks(const Bytes& bytes) {
    const auto cp=Load(bytes);VectorRandomAccessSource source(bytes);std::string error;
    std::vector<BtreeRecord> records;std::vector<std::uint64_t> blocks;
    Check(ReadAppleSnapshotTree(source,4096,*cp.volumes[0].snapshot_metadata_tree,cp.volumes[0].object_map,
        cp.container.superblock.xid,cp.container.superblock.xid,records,blocks,error),"complete metadata walk: "+error);
    return blocks;
}
void MappingInvariant(const Bytes& before,const Bytes& after) {
    const auto cp=Load(after);const auto prior=Load(before);const auto& volume=cp.volumes[0];
    VectorRandomAccessSource source(after);std::string error;std::vector<BtreeRecord> mappings;
    Check(ReadBtreeLeafRecords(source,4096,volume.object_map.tree.physical_block,true,0,
        cp.container.superblock.xid,mappings,error),"serialized OMAP walk: "+error);
    std::set<std::uint64_t> ids;
    for(auto block:MetadataBlocks(after)){
        Bytes bytes;Check(source.Read(block*4096,4096,bytes),"read metadata identity");
        const auto oid=ReadU64LE(bytes,8).value();Check(ids.insert(oid).second,"unique metadata OIDs");
        const auto count=std::count_if(mappings.begin(),mappings.end(),[&](const auto& r){
            return ReadU64LE(r.key,0)==oid && ReadU64LE(r.key,8)==cp.container.superblock.xid && ReadU64LE(r.value,8)==block;});
        Check(count==1,"every new metadata node has one exact published OMAP mapping");
        if(oid!=Cohort::meta)Check(oid>=prior.volumes[0].superblock.next_object_id &&
            oid<volume.superblock.next_object_id,"fresh child OID range and advanced allocation counter");
    }
    for(auto block:MetadataBlocks(before)){
        const auto oid=ReadU64LE(before,block*4096+8).value();
        if(oid!=Cohort::meta)Check(std::none_of(mappings.begin(),mappings.end(),[&](const auto& r){return ReadU64LE(r.key,0)==oid;}),
            "old child mappings are absent from the replacement live OMAP");
    }
}
void RetainedBytes(const Bytes& before,const Bytes& after,const AppleSnapshotRetentionView& retained) {
    for(auto block:retained.metadata_blocks)Check(std::equal(before.begin()+block*4096,before.begin()+(block+1)*4096,
        after.begin()+block*4096),"retained original metadata is immutable");
    for(const auto& r:retained.payload_extents)Check(std::equal(before.begin()+r.physical_block*4096,
        before.begin()+(r.physical_block+r.block_count)*4096,after.begin()+r.physical_block*4096),"retained original payload is immutable");
}
void Canonical(unsigned n,bool long_names) {
    Cohort f(n,long_names);Check(f.metadata.objects.size()>1,"source metadata actually multi-node");
    if(n>=160)Check(f.index.objects.size()>1,"source physical snapshot map actually multi-node");
    const auto old=Verify(f.image,n);const auto unchanged=f.image;
    VectorRandomAccessSource source(f.image);std::string error;AppleSnapshotCreatePlan create;
    AppleSnapshotCreateRequest req{101,"new-wide-snapshot",1700000000000000000ull};
    req.required_checkpoint_xids={500};
    const bool planned=PlanAppleSnapshotCreate(source,f.checkpoint,req,create,error);
    Check(planned,"multi-node create: "+error);Check(f.image==unchanged,"planning leaves original bytes unchanged");
    MemoryTarget target(f.image);Check(ExecuteAppleCheckpointPublication(target,create.commit.publication,error),"publish create: "+error);
    MappingInvariant(f.image,target.image);RetainedBytes(f.image,target.image,old);
    auto retained=Verify(target.image,n+1);Check(retained.identities.back()==create.identity,"created exact identity");
    VectorRandomAccessSource after(target.image);const auto cp=Load(target.image);
    std::vector<AppleRecoveryCheckpointView> recovery;
    Check(LoadAppleSnapshotRecoveryCheckpoints(after,cp,{500},recovery,error)&&recovery.size()==1,"original checkpoint recovery proof: "+error);
    AppleSnapshotDeleteRequest erase;erase.expected=retained.identities[n/2];erase.modification_time_ns=1700000000000000001ull;
    erase.required_checkpoint_xids={500,501};AppleSnapshotDeletePlan removed;
    const bool pinned=PlanAppleSnapshotDelete(after,cp,erase,removed,error);
    Check(!pinned&&error=="AppleSnapshotDeleteRecoveryOwner"&&removed.commit.publication.before_superblock_writes.empty(),
        "retained original checkpoint vetoes retirement before publication");
    erase.required_checkpoint_xids.clear();
    Call(PlanAppleSnapshotDelete(after,cp,erase,removed,error),"multi-node delete",error);
    MemoryTarget deleted(target.image);Check(ExecuteAppleCheckpointPublication(deleted,removed.commit.publication,error),"publish delete: "+error);
    MappingInvariant(target.image,deleted.image);
    auto final=Verify(deleted.image,n);
    Check(std::none_of(final.identities.begin(),final.identities.end(),[&](const auto& id){return id.snapshot_xid==erase.expected.snapshot_xid;}),"only selected identity removed");
    MemoryTarget stale(deleted.image);const auto bytes=stale.image;
    Check(!ExecuteAppleCheckpointPublication(stale,create.commit.publication,error)&&!stale.writes&&stale.image==bytes,"stale publication refuses before writes");
    std::cout<<"cohort "<<n<<" metadata_nodes="<<f.metadata.objects.size()<<" index_nodes="<<f.index.objects.size()<<" create_writes="<<target.writes<<std::endl;
    Pass("canonical multi-node create/delete/reference/recovery");
}
Bytes PublishedPayloadHistory(unsigned count) {
    Cohort seed(0,false,true);auto bytes=seed.image;
    for(unsigned i=0;i<count;++i){
        const auto cp=Load(bytes);VectorRandomAccessSource source(bytes);std::string error;
        AppleSnapshotCreateRequest req{101,std::string(220,'p')+std::to_string(1000+i),i+1};
        AppleSnapshotCreatePlan plan;
        Call(PlanAppleSnapshotCreate(source,cp,req,plan,error),"build canonical payload history",error);
        MemoryTarget target(bytes);Check(ExecuteAppleCheckpointPublication(target,plan.commit.publication,error),"publish payload history: "+error);
        bytes=std::move(target.image);
    }
    Verify(bytes,count,true);return bytes;
}
void ShrinkAndReferences() {
    auto bytes=PublishedPayloadHistory(8);bool saw_branch=false,saw_leaf=false;
    for(std::size_t remaining=8;remaining;--remaining){
        const auto cp=Load(bytes);const auto inventory=Verify(bytes,remaining,true);
        saw_branch|=MetadataBlocks(bytes).size()>1;
        VectorRandomAccessSource source(bytes);std::string error;
        const auto index=remaining%3==0?remaining-1:remaining%3==1?0:remaining/2;
        AppleSnapshotDeleteReferencePlan refs;
        Check(PlanAppleSnapshotDeleteReferences(source,cp,inventory.identities[index],refs,error),"exact reference transition: "+error);
        Check(refs.unreferenced_payload.empty(),"retained/live file keeps its payload through every delete");
        AppleSnapshotDeleteRequest req;req.expected=inventory.identities[index];req.modification_time_ns=1;
        AppleSnapshotDeletePlan plan;Call(PlanAppleSnapshotDelete(source,cp,req,plan,error),"shrink delete",error);
        MemoryTarget target(bytes);Check(ExecuteAppleCheckpointPublication(target,plan.commit.publication,error),"shrink publish: "+error);
        MappingInvariant(bytes,target.image);bytes=std::move(target.image);
        Check(!plan.released_payload_blocks,"no shared payload released");
        Verify(bytes,remaining-1,true);saw_leaf|=MetadataBlocks(bytes).size()==1;
    }
    Check(saw_branch&&saw_leaf,"actual branch-to-leaf-to-empty transition");
    const auto cp=Load(bytes);Check(!cp.volumes[0].object_map.snapshot_tree_oid,"empty snapshot-map root cleared");
    VectorRandomAccessSource source(bytes);std::string error;AppleSnapshotCreatePlan created;
    Check(PlanAppleSnapshotCreate(source,cp,{101,"recreated",1},created,error),"create after empty transition: "+error);
    MemoryTarget target(bytes);Check(ExecuteAppleCheckpointPublication(target,created.commit.publication,error),"recreated publication: "+error);
    Verify(target.image,1,true);Pass("oldest/middle/newest payload reference rebase, shrink, empty and recreate");
}
void Refusals() {
    for(unsigned variant=0;variant<6;++variant){
        Cohort f(12);const auto good=f.image;
        if(variant==0)f.Edit(f.metadata.objects.front().location.physical_block,[](auto& b){PutU64LE(b,8,999);});
        if(variant==1)f.Edit(f.metadata.objects.front().location.physical_block,[](auto& b){PutU32LE(b,0x1C,kObjectTypeFsTree);});
        if(variant==2)f.Edit(4,[](auto& b){PutU64LE(b,0xB0,(1ull<<60)-1);});
        if(variant==3)f.Edit(4,[](auto& b){PutU64LE(b,0x3E8,999);});
        if(variant==4)f.Edit(5,[](auto& b){PutU64LE(b,0x48,1);});
        f.Reload();VectorRandomAccessSource source(f.image);const auto original=f.image;
        std::string error;AppleSnapshotCreatePlan create;
        bool ok=false;
        if(variant==5){auto budget=std::make_shared<ApfsReadBudget>(8,32768,64,32768);BudgetedRandomAccessSource limited(source,budget);
            ok=PlanAppleSnapshotCreate(limited,f.checkpoint,{101,"budget",1},create,error);Check(budget->Failed(),"sticky bounded refusal");}
        else ok=PlanAppleSnapshotCreate(source,f.checkpoint,{101,"refused",1},create,error);
        Check(!ok&&!error.empty()&&create.commit.publication.before_superblock_writes.empty()&&
            create.allocation.allocated_main_blocks.empty()&&f.image==original,"source/budget/OID refusal produces no plan or source mutation: "+error);
        std::cout<<"refusal "<<variant<<" "<<error<<std::endl;
        if(variant!=5){VectorRandomAccessSource good_source(good);const auto inventory=Verify(good,12);
            AppleSnapshotDeleteRequest req;req.expected=inventory.identities[0];req.expected.name_utf8="wrong-exact-identity";
            AppleSnapshotDeletePlan erased;Check(!PlanAppleSnapshotDelete(good_source,Load(good),req,erased,error)&&
                erased.commit.publication.before_superblock_writes.empty(),"wrong exact identity refuses deletion");}
    }
    Pass("strict child/header/history/extended/OID/budget and identity refusals");
}
class FileTarget final: public RandomAccessSource,public AppleCheckpointWriteTarget {
    HANDLE file_=INVALID_HANDLE_VALUE;std::uint64_t size_=0;
public:
    std::optional<std::size_t> fail_after_writes;
    std::size_t writes=0;
    FileTarget(const std::filesystem::path& path,const Bytes* initial) {
        file_=CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,nullptr,
            initial?CREATE_NEW:OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        Check(file_!=INVALID_HANDLE_VALUE,"open private regular image");
        BY_HANDLE_FILE_INFORMATION info{};wchar_t final[1024]{};
        const auto n=GetFinalPathNameByHandleW(file_,final,1024,FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
        const auto expected=L"\\\\?\\"+path.wstring();
        Check(GetFileType(file_)==FILE_TYPE_DISK && GetFileInformationByHandle(file_,&info) &&
            !(info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY)) && info.nNumberOfLinks==1 &&
            n==expected.size() && CompareStringOrdinal(final,static_cast<int>(n),expected.c_str(),static_cast<int>(expected.size()),TRUE)==CSTR_EQUAL,
            "resolved unique regular file remains under pinned D root");
        if(initial){DWORD written=0;Check(initial->size()<=MAXDWORD && WriteFile(file_,initial->data(),static_cast<DWORD>(initial->size()),&written,nullptr)&&
                written==initial->size()&&FlushFileBuffers(file_),"durable fixture seed");}
        LARGE_INTEGER size{};Check(GetFileSizeEx(file_,&size)&&size.QuadPart>0,"image size");size_=size.QuadPart;
    }
    ~FileTarget(){if(file_!=INVALID_HANDLE_VALUE)CloseHandle(file_);}
    std::uint64_t SizeBytes() const override {return size_;}
    bool Read(std::uint64_t at,std::size_t count,Bytes& out) const override {
        out.clear();if(at>size_||count>size_-at||count>MAXDWORD)return false;
        LARGE_INTEGER position{};position.QuadPart=at;DWORD got=0;out.resize(count);
        if(!SetFilePointerEx(file_,position,nullptr,FILE_BEGIN)||!ReadFile(file_,out.data(),static_cast<DWORD>(count),&got,nullptr)||got!=count){out.clear();return false;}
        return true;
    }
    bool ReadBlock(std::uint64_t at,std::uint32_t bs,Bytes& out) override {return Read(at*bs,bs,out);}
    bool WriteBlock(std::uint64_t at,std::span<const std::byte> bytes) override {
        if(fail_after_writes==writes)return false;
        if(bytes.size()!=4096||at>=size_/4096)return false;LARGE_INTEGER position{};position.QuadPart=at*4096;DWORD written=0;
        if(!SetFilePointerEx(file_,position,nullptr,FILE_BEGIN)||!WriteFile(file_,bytes.data(),4096,&written,nullptr)||written!=4096)return false;
        ++writes;return true;
    }
    bool Flush() override {return FlushFileBuffers(file_)!=FALSE;}
    Bytes All() const {Bytes bytes;Check(Read(0,static_cast<std::size_t>(size_),bytes),"read full private image");return bytes;}
};
class FreshRoot {
    std::vector<HANDLE> pins_;
public:
    std::filesystem::path path;
    explicit FreshRoot(const wchar_t* input) {
        const std::filesystem::path requested(input);path=std::filesystem::absolute(requested).lexically_normal();
        Check(requested.is_absolute() && requested==path && path.wstring().size()<160 && path.root_name()==L"D:" &&
            path.has_filename(),"explicit bounded absolute D root");
        auto current=path.root_path();
        for(auto it=++path.begin();it!=path.end();++it){
            if(it->wstring()==L"\\")continue;
            Check(it->wstring().find_first_of(L":*?<>|.")==std::wstring::npos,"simple fixed-local test root components");
            current/=*it;
            if(current==path)Check(CreateDirectoryW(current.c_str(),nullptr)!=FALSE,"fresh caller root must not exist");
            const auto h=CreateFileW(current.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS,nullptr);
            Check(h!=INVALID_HANDLE_VALUE,"pin root ancestors");pins_.push_back(h);
            BY_HANDLE_FILE_INFORMATION info{};wchar_t final[1024]{};const auto n=GetFinalPathNameByHandleW(h,final,1024,FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
            const auto expected=L"\\\\?\\"+current.wstring();
            Check(GetFileInformationByHandle(h,&info)&&!(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)&&
                (info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)&&n==expected.size()&&
                CompareStringOrdinal(final,static_cast<int>(n),expected.c_str(),static_cast<int>(expected.size()),TRUE)==CSTR_EQUAL,"no reparse/resolved root escape");
        }
    }
    ~FreshRoot(){for(auto h:pins_)CloseHandle(h);}
};
void FileRecovery(const std::filesystem::path& root) {
    const auto original_image=PublishedPayloadHistory(8);const auto base=Load(original_image).container.superblock.xid;
    const auto original=Verify(original_image,8,true);AppleSnapshotCreatePlan created;std::string error;
    {
        FileTarget file(root/L"canonical.img",&original_image);auto cp=LoadAppleCheckpointView(file,0,file.SizeBytes(),error);
        Check(cp.has_value(),"actual file canonical checkpoint");AppleSnapshotCreateRequest req{101,"actual-file-create",1};req.required_checkpoint_xids={base};
        Check(PlanAppleSnapshotCreate(file,*cp,req,created,error),"actual file create plan: "+error);
        Check(file.All()==original_image,"actual file planning is read-only");
        Check(ExecuteAppleCheckpointPublication(file,created.commit.publication,error),"actual file create publication: "+error);
    }
    Bytes complete;AppleSnapshotDeletePlan removed;
    {
        FileTarget reopened(root/L"canonical.img",nullptr);complete=reopened.All();const auto inventory=Verify(complete,9,true);
        RetainedBytes(original_image,complete,original);const auto cp=Load(complete);
        std::vector<AppleRecoveryCheckpointView> recovery;
        Check(LoadAppleSnapshotRecoveryCheckpoints(reopened,cp,{base},recovery,error)&&recovery.size()==1,"file reopened original ownership proof: "+error);
        AppleSnapshotDeleteRequest req;req.expected=inventory.identities.front();req.modification_time_ns=2;req.required_checkpoint_xids={base,base+1};
        Check(!PlanAppleSnapshotDelete(reopened,cp,req,removed,error)&&error=="AppleSnapshotDeleteRecoveryOwner",
            "actual file retains strict original checkpoint owner veto");
        req.required_checkpoint_xids.clear();
        Call(PlanAppleSnapshotDelete(reopened,cp,req,removed,error),"file oldest delete plan",error);
        Check(ExecuteAppleCheckpointPublication(reopened,removed.commit.publication,error),"file oldest delete publication: "+error);
    }
    {FileTarget reopened(root/L"canonical.img",nullptr);Verify(reopened.All(),8,true);}
    unsigned cut=0;
    for(const auto* stage:{"before-apple-device-write","before-apple-prepublication-flush","before-apple-checkpoint-switch","before-apple-final-flush"}){
        const auto path=root/(L"cut-"+std::to_wstring(cut++)+L".img");
        {FileTarget file(path,&original_image);Check(!ExecuteAppleCheckpointPublication(file,created.commit.publication,error,
            [&](std::string_view at){return at!=stage;}),"injected file publication cut is never acknowledged");}
        FileTarget reopened(path,nullptr);const auto bytes=reopened.All();const auto cp=Load(bytes);
        Check(cp.container.superblock.xid==base||cp.container.superblock.xid==base+1,"file cut selects exactly old/new checkpoint");
        Verify(bytes,cp.container.superblock.xid==base?8:9,true);RetainedBytes(original_image,bytes,original);
        std::cout<<"CUT "<<stage<<" reopened="<<cp.container.superblock.xid<<std::endl;
    }
    const auto before_delete=Verify(complete,9,true);
    for(const auto* stage:{"before-apple-device-write","before-apple-prepublication-flush","before-apple-checkpoint-switch","before-apple-final-flush"}){
        const auto path=root/(L"delete-cut-"+std::to_wstring(cut++)+L".img");
        {FileTarget file(path,&complete);Check(!ExecuteAppleCheckpointPublication(file,removed.commit.publication,error,
            [&](std::string_view at){return at!=stage;}),"injected deletion cut is never acknowledged");}
        FileTarget reopened(path,nullptr);const auto bytes=reopened.All();const auto cp=Load(bytes);
        Check(cp.container.superblock.xid==base+1||cp.container.superblock.xid==base+2,"deletion cut selects exactly old/new checkpoint");
        Verify(bytes,cp.container.superblock.xid==base+1?9:8,true);RetainedBytes(complete,bytes,before_delete);
        std::cout<<"DELETE CUT "<<stage<<" reopened="<<cp.container.superblock.xid<<std::endl;
    }
    for(bool deletion:{false,true}){
        const auto& plan=deletion?removed.commit.publication:created.commit.publication;
        const auto& image=deletion?complete:original_image;
        const auto path=root/(deletion?L"delete-partial.img":L"create-partial.img");
        {FileTarget file(path,&image);file.fail_after_writes=plan.before_superblock_writes.size()/2;
            Check(!ExecuteAppleCheckpointPublication(file,plan,error)&&file.writes>0,"partial multi-node write refuses before switch");}
        FileTarget reopened(path,nullptr);const auto bytes=reopened.All();const auto cp=Load(bytes);
        Check(cp.container.superblock.xid==base+(deletion?1:0),"partial metadata keeps the exact original checkpoint");
        Verify(bytes,deletion?9:8,true);
    }
    Pass("pinned regular-file create/delete, reopen, retained proof, eight stage cuts and two partial writes");
}
}
int wmain(int argc,wchar_t** argv) {
    try {
        Check(argc>=2,"explicit test mode required");
        const std::wstring mode=argv[1];
        if(mode==L"metadata")Canonical(12,true);
        else if(mode==L"index")Canonical(160,false);
        else if(mode==L"shrink")ShrinkAndReferences();
        else if(mode==L"refusals")Refusals();
        else if(mode==L"file"){Check(argc==3,"fresh absolute caller root required");FreshRoot root(argv[2]);FileRecovery(root.path);}
        else if(mode==L"all"){Check(argc==3,"fresh absolute caller root required");FreshRoot root(argv[2]);
            Canonical(12,true);Canonical(160,false);ShrinkAndReferences();Refusals();FileRecovery(root.path);}
        else throw std::runtime_error("unknown test mode");
        std::cout<<"PASS groups="<<groups<<" assertions="<<checks<<std::endl;return 0;
    }catch(const std::exception& e){std::cerr<<"FAIL groups="<<groups<<" assertions="<<checks<<" "<<e.what()<<std::endl;return 1;}
}
