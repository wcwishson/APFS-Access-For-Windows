#include "NativeApfsReader.h"
#include "ApfsExtendedRecordCodec.h"
#include "SnapshotTestFixture.h"
#include <iostream>
#include <stdexcept>
#include <type_traits>

using namespace apfsaccess::catalog;
using namespace apfsaccess::rw;
using namespace apfsaccess::testfixture;
namespace {
unsigned cases=0, checks=0;
void Check(bool ok, const std::string& message) { ++checks; if(!ok) throw std::runtime_error(message); }
void Pass(const std::string& name) { ++cases; std::cout<<"PASS "<<name<<"\n"; }
using Record = apfsaccess::catalog::BtreeRecord;
using Projection = std::shared_ptr<const NativeApfsSnapshotProjection>;
static_assert(std::is_const_v<std::remove_reference_t<decltype(std::declval<NativeApfsSnapshotProjection>().View())>>);
static_assert(!std::is_convertible_v<NativeApfsSnapshotProjection,NativeApfsVolumeProjection>);

template<class T, class F> Record Encode(const T& value, F encode) {
    Record out; std::string error; Check(encode(value,out,error),"fixture encode: "+error); return out;
}
Record Inode(std::uint64_t id, std::uint64_t size, unsigned links, bool directory=false) {
    AppleInodeRecord inode; inode.object_id=id;inode.parent_id=2;inode.private_id=id;
    inode.mode=directory?0040755:0100644; inode.children_or_links=links;
    inode.owner=501;inode.group=20;inode.bsd_flags=0x8000;inode.write_generation=17;
    inode.create_time=123456700;inode.modification_time=223456700;inode.change_time=323456700;inode.access_time=423456700;
    if(!directory) { inode.uncompressed_size=size;AppleExtendedField stream{8,0,Bytes(40)};
        PutU64LE(stream.data,0,size);PutU64LE(stream.data,8,4096);inode.extended_fields.push_back(stream); }
    return Encode(inode,EncodeAppleInodeRecord);
}
Record Drec(const std::string& name) {
    AppleDirectoryRecord d;d.parent_id=2;d.file_id=30;d.name_utf8=name;d.flags=8;d.date_added=987654300;
    Record out;std::string error;Check(EncodeAppleDirectoryRecord(d,out,error),"drec encode");return out;
}
struct Fixture : SnapshotFixture {
    std::vector<Record> fs, refs;
    Fixture() {
        fs={Inode(2,0,1,true),Drec("report.txt"),Inode(30,8,1),
            Encode(AppleFileExtentRecord{30,0,4096,220,0,4096},EncodeAppleFileExtentRecord),
            Encode(AppleDataStreamIdRecord{30,1},EncodeAppleDataStreamIdRecord),
            Encode(AppleXattrRecord{30,"com.apple.FinderInfo",kAppleXattrDataEmbedded,Bytes(32,std::byte{0x42})},EncodeAppleXattrRecord)};
        refs={Encode(ApplePhysicalExtentRecord{220,1,1,30,1},EncodeApplePhysicalExtentRecord)};
        Trees();
        auto live=fs;
        for(auto& r:live) if((ReadU64LE(r.key,0).value()>>60)==8) PutU64LE(r.value,8,221);
        PutRecords(7,live,20,root_oid,2,14);
        PutRecords(8,{Encode(ApplePhysicalExtentRecord{221,1,1,30,1},EncodeApplePhysicalExtentRecord)},20,8,kObjectPhysical|2,15);
        Bytes old(bs),current(bs);PutBytes(old,0,"snapshot",8);PutBytes(current,0,"LIVEVIEW",8);Put(220,old,false);Put(221,current,false);
    }
    void PutRecords(std::uint64_t block,std::vector<Record> records,std::uint64_t xid,std::uint64_t oid,
        std::uint32_t type,std::uint32_t subtype) {
        std::string error;
        if(subtype==14) Check(SortAppleBtreeRecords(records,AppleBtreeKeyOrder::FileSystemCaseSensitive,error),"sort fixture: "+error);
        std::vector<Bytes> k,v;for(auto& r:records){k.push_back(r.key);v.push_back(r.value);}
        Put(block,BuildRawLeafNode(k,v,xid,bs,0,oid,type,subtype));
    }
    void Trees() { PutRecords(183,fs,10,root_oid,2,14);PutRecords(184,refs,10,184,kObjectPhysical|2,15); }
    ApfsSnapshotIdentity Identity() const {std::vector<ApfsSnapshotInfo> out;std::string error;
        Check(Enumerate(out,error)&&out.size()==1,"fixture enumerate: "+error);return out[0].identity;}
    void External() {
        Bytes descriptor(48);PutU64LE(descriptor,0,40);PutU64LE(descriptor,8,9);PutU64LE(descriptor,16,4096);
        fs.push_back(Encode(AppleXattrRecord{30,"com.apple.ResourceFork",kAppleXattrDataStream,descriptor},EncodeAppleXattrRecord));
        fs.push_back(Encode(AppleDataStreamIdRecord{40,1},EncodeAppleDataStreamIdRecord));
        fs.push_back(Encode(AppleFileExtentRecord{40,0,4096,222,0,4096},EncodeAppleFileExtentRecord));
        refs.push_back(Encode(ApplePhysicalExtentRecord{222,1,1,40,1},EncodeApplePhysicalExtentRecord));
        Bytes bytes(bs);PutBytes(bytes,0,"fork-past",9);Put(222,bytes,false);Trees();
    }
    void Hardlinks() {
        fs[0]=Inode(2,0,2,true);fs[2]=Inode(30,8,2);fs.push_back(Drec("alias.txt"));
        fs.push_back(Encode(AppleSiblingLinkRecord{30,70,2,"report.txt"},EncodeAppleSiblingLinkRecord));
        fs.push_back(Encode(AppleSiblingLinkRecord{30,71,2,"alias.txt"},EncodeAppleSiblingLinkRecord));
        fs.push_back(Encode(AppleSiblingMapRecord{70,30},EncodeAppleSiblingMapRecord));
        fs.push_back(Encode(AppleSiblingMapRecord{71,30},EncodeAppleSiblingMapRecord));Trees();
    }
    void Multilevel(std::uint64_t mapping_xid=10,std::uint64_t header_xid=10) {
        AppleBtreeOptions opts;opts.block_size=4096;opts.xid=header_xid;opts.root_object_id=root_oid;opts.root_physical_block=183;
        // Force a real multilevel tree with 28 reachable empty regular files.
        fs[0]=Inode(2,0,29,true);
        for(unsigned n=0;n<28;++n) {
            auto inode=Inode(100+n,0,1);PutU64LE(inode.value,inode.value.size()-32,0);fs.push_back(inode);
            auto d=Drec("child-"+std::to_string(n));PutU64LE(d.value,0,100+n);fs.push_back(d);
        }
        opts.first_child_object_id=0x7000;opts.first_child_physical_block=230;
        opts.subtype=14;opts.key_order=AppleBtreeKeyOrder::FileSystemCaseSensitive;
        AppleSerializedBtree tree;std::string error;Check(SerializeAppleBtree(fs,opts,tree,error),"serialize multilevel: "+error);
        Check(tree.height>0,"real multilevel");std::vector<OmapRecordSpec> mappings;
        for(auto& object:tree.objects) {Put(object.location.physical_block,object.bytes);
            if(object.location.physical_block!=183) mappings.push_back({object.location.object_id,object.location.physical_block,0,mapping_xid});}
        SetMappings(mappings);
    }
};
class TracedSource : public RandomAccessSource {
public:
    const Bytes& bytes;mutable std::vector<std::pair<std::uint64_t,std::size_t>> reads;
    explicit TracedSource(const Bytes& b):bytes(b){}
    std::uint64_t SizeBytes() const override{return bytes.size();}
    bool Read(std::uint64_t offset,std::size_t size,Bytes& out)const override {
        out.clear();if(offset>bytes.size()||size>bytes.size()-offset)return false;
        reads.emplace_back(offset,size);out.assign(bytes.begin()+offset,bytes.begin()+offset+size);return true;
    }
    bool Touched(std::uint64_t offset,std::uint64_t length)const {
        for(auto [at,size]:reads) if(at<offset+length&&offset<at+size)return true;return false;
    }
};
bool Load(const RandomAccessSource& source,const ApfsSnapshotIdentity& id,Projection& out,std::string& error) {
    return NativeApfsReader::TryLoadSnapshotProjection(source,id,out,error);
}
std::string ReadData(const RandomAccessSource& source,const MetadataStore::FileExtent& extent,std::size_t size) {
    Bytes out;Check(source.Read(extent.physical_address,size,out),"read projected bytes");
    return std::string(reinterpret_cast<const char*>(out.data()),out.size());
}
void Positive() {
    for(bool offset:{false,true}) {
        Fixture f;f.External();f.Hardlinks();const auto before=f.image;
        if(offset){f.image.insert(f.image.begin(),8192,std::byte{0xEE});f.scope.store_offset_bytes=8192;}
        const auto id=f.Identity();TracedSource source(f.image);Projection result;std::string error;
        Check(Load(source,id,result,error),"projection: "+error);const auto& v=result->View();
        Check(result->Snapshot().identity==id&&!result->Snapshot().snapshot_uuid_hex,"exact immutable identity, absent UUID");
        Check(v.volume_object_id==101&&result->Snapshot().metadata.volume.superblock.object_id==180,"virtual volume vs physical APSB");
        Check(v.volume_superblock_block==180+(offset?2:0)&&v.root_tree_block==183+(offset?2:0),"source relative metadata blocks");
        Check(v.checkpoint_xid==20&&v.inodes.size()==2&&v.directory_links.size()==2,"historical namespace");
        const auto inode=std::find_if(v.inodes.begin(),v.inodes.end(),[](const auto& i){return i.object_id==30;});
        Check(inode!=v.inodes.end()&&inode->xid==10&&inode->owner==501&&inode->group==20&&inode->mode==0100644&&
            inode->write_generation==17&&inode->bsd_flags==0x8000&&inode->link_count==2,"stable Mac ownership and generation");
        Check(inode->create_time_utc==116444736001234567ull&&inode->modification_time_utc==116444736002234567ull&&
            inode->change_time_utc==116444736003234567ull&&inode->access_time_utc==116444736004234567ull,"four Mac timestamps");
        Check(v.extended_attributes_by_inode.at(30).at("com.apple.FinderInfo").data==Bytes(32,std::byte{0x42}),"FinderInfo stable");
        Check(!source.Touched(f.scope.store_offset_bytes+220*4096,3*4096),"projection reads metadata only");
        Check(ReadData(source,v.read_extents_by_inode.at(30).at(0),8)=="snapshot","historical file bytes");
        Check(ReadData(source,v.attribute_stream_extents.at(40)->at(0),9)=="fork-past","historical external fork bytes");
        Check(!source.Touched(f.scope.store_offset_bytes+221*4096,4096),"no live payload selection");
        Check(v.btree_records.empty(),"no mutable legacy catalog records");
        const auto saved=result;Check(Load(source,result->Snapshot().identity,result,error),"alias safe immutable reload");
        Check(result->Snapshot().identity==saved->Snapshot().identity,"stable repeated identity");
        Check(std::equal(before.begin(),before.end(),f.image.begin()+f.scope.store_offset_bytes),"no image writes");
        // Independent authoritative live-tree control over the same fixture.
        TracedSource control(f.image);OffsetRandomAccessSource store(&control,f.scope.store_offset_bytes,f.scope.store_size_bytes);
        std::vector<Record> live;BtreeReadPolicy policy;policy.enforce_object_identity=true;
        policy.root_object_id=Fixture::root_oid;policy.subtype=14;policy.require_complete_traversal=true;
        Check(ReadBtreeLeafRecords(store,4096,7,false,5,20,policy,live,error),"live tree control: "+error);
        const auto extent=std::find_if(live.begin(),live.end(),[](const auto& r){return ReadU64LE(r.key,0).value()==((8ull<<60)|30);});
        Check(extent!=live.end(),"live extent present");AppleFileExtentRecord decoded;
        Check(DecodeAppleFileExtentRecord(*extent,4096,decoded,error),"live extent decode");
        Check(ReadData(store,{0,decoded.physical_block*4096,4096},8)=="LIVEVIEW","live bytes differ from selected snapshot");
        Pass(offset?"offset external attribute and hardlink projection":"historical bytes Mac metadata and hardlink projection");
    }
    { Fixture f;f.Multilevel();auto id=f.Identity();TracedSource source(f.image);Projection out;std::string error;
      Check(Load(source,id,out,error),"multilevel projection: "+error);Check(out->View().inodes.size()==30,"all historical virtual children");
      Check(ReadData(source,out->View().read_extents_by_inode.at(30).at(0),8)=="snapshot","multilevel historical payload");Pass("multilevel historical virtual children"); }
    { Fixture f;f.Edit(180,[](auto& b){PutU32LE(b,0x74,kObjectPhysical|2);PutU64LE(b,0x88,183);});
      f.PutRecords(183,f.fs,10,183,kObjectPhysical|2,14);auto id=f.Identity();TracedSource source(f.image);Projection out;std::string error;
      Check(Load(source,id,out,error)&&out->View().root_tree_oid==183,"physical snapshot FS root: "+error);Pass("physical FS root with physical APSB"); }
    { SnapshotFixture f(8192);std::vector<ApfsSnapshotInfo> snapshots;std::string error;Check(f.Enumerate(snapshots,error),"8K enumerate");
      TracedSource source(f.image);Projection out;Check(Load(source,snapshots[0].identity,out,error)&&out->View().block_size==8192&&
          out->View().inodes.size()==1,"8K projection: "+error);Pass("8K exact root projection"); }
    { Fixture f;auto id=f.Identity();TracedSource source(f.image);ApfsSnapshotRecords out;std::string error;
      Check(ApfsSnapshotStore::LoadExactRecords(source,id,out,error)&&out.trees.filesystem.size()==f.fs.size(),"exact store capture");
      Check(ApfsSnapshotStore::LoadExactRecords(source,out.snapshot.identity,out,error),"exact store alias revalidation");
      f.Edit(184,[](auto& b){PutU64LE(b,0x10,11);});
      Check(!ApfsSnapshotStore::LoadExactRecords(source,id,out,error)&&out.trees.filesystem.empty()&&out.trees.extentref.empty()&&
          out.snapshot.identity.snapshot_xid==0&&out.checkpoint.volumes.empty(),"late store failure clears every output");Pass("exact store captured records alias and late refusal"); }
    { Fixture f;std::string error;AppleInodeRecord inode;
      Check(ApfsExtendedRecordCodec::DecodeInode(Inode(30,8192,1),inode,error),"sparse fixture inode");
      inode.internal_flags|=0x200;AppleExtendedField sparse{13,0,Bytes(8)};PutU64LE(sparse.data,0,4096);inode.extended_fields.push_back(sparse);
      f.fs[2]=Encode(inode,EncodeAppleInodeRecord);f.fs.push_back(Encode(AppleFileExtentRecord{30,4096,4096,0,0,4096},EncodeAppleFileExtentRecord));f.Trees();
      f.image.insert(f.image.begin(),8192,std::byte{0});f.scope.store_offset_bytes=8192;auto id=f.Identity();TracedSource source(f.image);Projection out;
      Check(Load(source,id,out,error),"sparse projection: "+error);const auto& extents=out->View().read_extents_by_inode.at(30);
      Check(extents.size()==2&&extents[0].physical_address==8192+220*4096&&extents[1].physical_address==0&&extents[1].logical_offset==4096,
          "source offset applied once while explicit hole stays zero");Pass("explicit sparse hole and nonzero store routing"); }
    { Fixture f;std::string error;const auto policy=ApfsNamePolicy::FromIncompatibleFeatures(9);
      AppleDirectoryRecord d;d.parent_id=2;d.file_id=30;d.name_utf8="Café.txt";d.flags=8;
      Check(EncodeAppleDirectoryRecord(d,policy,f.fs[1],error),"hashed Unicode fixture");
      Check(SortAppleBtreeRecords(f.fs,AppleBtreeKeyOrder::FileSystemHashedDirectory,error),"hashed sort");
      std::vector<Bytes> k,v;for(const auto& r:f.fs){k.push_back(r.key);v.push_back(r.value);}
      f.Put(183,BuildRawLeafNode(k,v,10,4096,0,f.root_oid,2,14));f.Edit(180,[](auto& b){PutU64LE(b,0x38,9);});
      const auto id=f.Identity();TracedSource source(f.image);Projection out;
      Check(Load(source,id,out,error)&&out->View().name_policy.UsesHashedDirectoryKeys()&&
          out->View().directory_links[0].entry_name_utf8=="Café.txt","snapshot APSB name policy: "+error);
      k[1][11]^=std::byte{0x40};f.Put(183,BuildRawLeafNode(k,v,10,4096,0,f.root_oid,2,14));
      Check(!Load(source,id,out,error)&&!out,"malformed hashed name clears projection");Pass("historical Unicode name policy and malformed hash refusal"); }
}
void Reject(const std::string& label,const std::function<void(Fixture&)>& change,const std::string& reason={}) {
    Fixture f;auto id=f.Identity();TracedSource source(f.image);Projection out;std::string error;
    Check(Load(source,id,out,error),"seed valid output: "+error);change(f);
    Check(!Load(source,id,out,error),label+" accepted");Check(!out,label+" leaked stale output");
    Check(!error.empty()&&(reason.empty()||error.find(reason)!=std::string::npos),label+" wrong error: "+error);Pass(label);
}
void Negative() {
    const std::vector<std::function<void(ApfsSnapshotIdentity&)>> changes={
        [](auto& x){x.scope.container_uuid_hex=std::string(32,'c');},[](auto& x){x.scope.volume_uuid_hex=std::string(32,'c');},
        [](auto& x){++x.scope.volume_oid;},[](auto& x){--x.scope.checkpoint_xid;},[](auto& x){x.name_utf8="Backup";},
        [](auto& x){++x.snapshot_xid;},[](auto& x){++x.root_oid;},[](auto& x){++x.root_physical_block;},
        [](auto& x){++x.superblock_physical_block;},[](auto& x){++x.omap_physical_block;},
        [](auto& x){++x.omap_tree_physical_block;},[](auto& x){++x.extentref_physical_block;},
        [](auto& x){++x.scope.store_offset_bytes;},[](auto& x){--x.scope.store_size_bytes;},
        [](auto& x){x.snapshot_xid=0;},[](auto& x){x.scope.volume_oid=0;}};
    for(std::size_t n=0;n<changes.size();++n){Fixture f;auto id=f.Identity();TracedSource source(f.image);Projection out;std::string error;
        Check(Load(source,id,out,error),"seed exact");changes[n](id);Check(!Load(source,id,out,error)&&!out&&!error.empty(),"wrong identity atomic");Pass("wrong identity "+std::to_string(n));}
    Reject("changed UUID bytes",[](auto& f){f.Edit(180,[](auto& b){b[0xF0]=std::byte{0xCC};});});
    Reject("changed authoritative checkpoint",[](auto& f){f.Edit(12,[](auto& b){PutU64LE(b,0x10,21);});});
    Reject("changed snapshot name bytes",[](auto& f){f.snapshots={f.Metadata(10,"renamed"),f.Name(10,"renamed")};f.Inventory();});
    Reject("changed snapshot root bytes",[](auto& f){f.Edit(180,[](auto& b){PutU64LE(b,0x88,0x9999);});});
    Reject("changed volume OID bytes",[](auto& f){f.Edit(4,[](auto& b){PutU64LE(b,8,102);});});
    Reject("late malformed inode",[](auto& f){auto bad=f.fs[2];bad.value.resize(10);f.fs.push_back(bad);
        std::vector<Bytes> k,v;for(auto& r:f.fs){k.push_back(r.key);v.push_back(r.value);}f.Put(183,BuildRawLeafNode(k,v,10,4096,0,f.root_oid,2,14));});
    Reject("missing namespace target",[](auto& f){PutU64LE(f.fs[1].value,0,999);f.Trees();});
    Reject("missing file extent no invented zeros",[](auto& f){f.fs.erase(f.fs.begin()+3);f.refs.clear();f.Trees();},"Coverage");
    for (const auto size : {UINT64_MAX, UINT64_MAX - 4094, UINT64_MAX - 4095})
        Reject("huge missing extent " + std::to_string(size), [size](auto& f) {
            f.fs[2] = Inode(30, size, 1);
            PutU64LE(f.fs[2].value, f.fs[2].value.size() - 32, 0);
            f.fs.erase(f.fs.begin() + 3); f.refs.clear(); f.Trees();
        }, "Coverage");
    Reject("hidden extent on empty file",[](auto& f){f.fs[2]=Inode(30,0,1);PutU64LE(f.fs[2].value,f.fs[2].value.size()-32,0);f.Trees();},"HiddenFileExtent");
    Reject("zero private stream identity",[](auto& f){PutU64LE(f.fs[2].value,8,0);f.Trees();});
    Reject("sparse byte count mismatch",[](auto& f){AppleInodeRecord inode;std::string error;
        Check(ApfsExtendedRecordCodec::DecodeInode(f.fs[2],inode,error),"sparse negative inode");inode.internal_flags|=0x200;
        AppleExtendedField sparse{13,0,Bytes(8)};PutU64LE(sparse.data,0,4096);inode.extended_fields.push_back(sparse);
        f.fs[2]=Encode(inode,EncodeAppleInodeRecord);f.Trees();},"SparseByteCount");
    Reject("unknown filesystem record no invented fallback",[](auto& f){Record record{Bytes(8),Bytes(8)};
        PutU64LE(record.key,0,(7ull<<60)|30);f.fs.push_back(record);f.Trees();},"Unsupported");
    Reject("unsupported compressed read plan",[](auto& f){PutU32LE(f.fs[2].value,0x44,0x20);f.Trees();},"Compressed");
    Reject("encrypted file extent",[](auto& f){PutU64LE(f.fs[3].value,16,3);f.Trees();},"Encrypted");
    Reject("extent outside geometry",[](auto& f){PutU64LE(f.fs[3].value,8,512);f.Trees();});
    Reject("extent owner mismatch",[](auto& f){PutU64LE(f.refs[0].value,8,99);f.Trees();});
    Reject("payload overlaps metadata",[](auto& f){PutU64LE(f.fs[3].value,8,183);PutU64LE(f.refs[0].key,0,(2ull<<60)|183);f.Trees();},"MetadataOverlap");
    Reject("external attribute owner mismatch",[](auto& f){f.External();for(auto& r:f.fs)
        if(ReadU64LE(r.key,0).value()==((6ull<<60)|40))PutU32LE(r.value,0,2);f.Trees();},"AttributeStream");
    Reject("external attribute late coverage gap",[](auto& f){f.External();for(auto& r:f.fs)
        if(ReadU64LE(r.key,0).value()==((8ull<<60)|40))PutU64LE(r.key,8,4096);f.Trees();},"AttributeStream");
    Reject("external attribute crypto descriptor",[](auto& f){f.External();for(auto& r:f.fs)
        if((ReadU64LE(r.key,0).value()>>60)==4&&(ReadU16LE(r.value,0).value()&kAppleXattrDataStream))PutU64LE(r.value,4+24,7);f.Trees();},"AttributeStream");
    Reject("external attribute metadata overlap",[](auto& f){f.External();for(auto& r:f.fs)
        if(ReadU64LE(r.key,0).value()==((8ull<<60)|40))PutU64LE(r.value,8,184);
        PutU64LE(f.refs.back().key,0,(2ull<<60)|184);f.Trees();},"MetadataOverlap");
    Reject("unsupported encryption",[](auto& f){f.Edit(180,[](auto& b){PutU64LE(b,0x108,0);});});
    Reject("unsupported fext",[](auto& f){f.Edit(180,[](auto& b){PutU64LE(b,0x408,200);});});
    Reject("unsupported Fusion",[](auto& f){f.Edit(12,[](auto& b){PutU64LE(b,0x38,0x100);});});
    Reject("root mapping older than header",[](auto& f){f.Put(6,BuildBtreeNode({{f.root_oid,183,0,9},{f.root_oid,7,0,20},{f.snap_oid,9,0,20}},20,4096,0,6,kObjectPhysical|2,11));},"FutureXid");
    { Fixture f;auto id=f.Identity();f.Multilevel(9,10);TracedSource source(f.image);Projection out;std::string error;
      Check(!Load(source,id,out,error)&&!out&&error.find("FutureXid")!=std::string::npos,"child mapping bound: "+error);Pass("child mapping older than header"); }
    { Fixture f;f.image.insert(f.image.begin(),1,std::byte{0});f.scope.store_offset_bytes=1;auto id=f.Identity();
      TracedSource source(f.image);Projection out;std::string error;Check(!Load(source,id,out,error)&&!out&&error.find("Unaligned")!=std::string::npos,"unaligned: "+error);Pass("unaligned image store refused"); }
    { Fixture f;f.image.insert(f.image.end(),4096,std::byte{0});f.scope.store_size_bytes+=4096;auto id=f.Identity();
      TracedSource source(f.image);Projection out;std::string error;Check(!Load(source,id,out,error)&&!out&&error.find("SourceWindow")!=std::string::npos,"overwide: "+error);Pass("overwide image store refused"); }
}
void Budgets() {
    Fixture control;auto identity=control.Identity();TracedSource traced(control.image);Projection projected;std::string e;
    Check(Load(traced,identity,projected,e),"budget control");const auto needed=static_cast<unsigned long long>(traced.reads.size());
    for(auto allowance:{0ull,5ull,needed-1}) {Fixture f;auto id=f.Identity();TracedSource source(f.image);
        auto budget=std::make_shared<ApfsReadBudget>(allowance,1ull<<30,1000000,1ull<<30);BudgetedRandomAccessSource bounded(source,budget);
        Projection out;std::string error;Check(!Load(bounded,id,out,error)&&!out&&budget->Failed(),"bounded source refusal");
        const auto reads=source.reads.size();Check(!Load(bounded,id,out,error)&&source.reads.size()==reads,"sticky no retries");Pass("shared read allowance "+std::to_string(allowance));}
    {Fixture f;auto id=f.Identity();TracedSource source(f.image);auto budget=std::make_shared<ApfsReadBudget>(65536,1ull<<30,1000000,50000);
     BudgetedRandomAccessSource bounded(source,budget);Projection out;std::string error;Check(!Load(bounded,id,out,error)&&!out&&budget->Failed(),"materialization failure atomic");Pass("shared materialization allowance");}
    { auto budget=std::make_shared<ApfsReadBudget>(needed*2-1,1ull<<30,1000000,1ull<<30);BudgetedRandomAccessSource bounded(traced,budget);
      Projection out;std::string error;Check(Load(bounded,identity,out,error),"caller budget success: "+error);
      Check(!Load(bounded,out->Snapshot().identity,out,error)&&!out&&budget->Failed(),"budget preserved across operations and alias failure");
      Pass("shared budget cumulative across successful and failed calls"); }
}
}
int main(){try{Positive();Negative();Budgets();std::cout<<"RESULT PASS cases="<<cases<<" checks="<<checks<<"\n";return 0;}
catch(const std::exception& e){std::cerr<<"FAIL cases="<<cases<<" checks="<<checks<<": "<<e.what()<<"\n";return 1;}}
