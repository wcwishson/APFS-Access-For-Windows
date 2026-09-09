// Software source-byte fixtures, never macOS compatibility evidence.
#define main quota_test_main
#include "AppleVolumeTransactionTests.cpp"
#undef main
#include "ApfsExtendedRecordCodec.h"
#include "ApfsCompression.h"
#include <fstream>
#include <map>
#include <set>

namespace {
constexpr std::uint64_t kShared = 128;
std::uint64_t Id(const BtreeRecord& r) { return ReadU64LE(r.key, 0).value() & ((1ull<<60)-1); }
std::uint64_t Type(const BtreeRecord& r) { return ReadU64LE(r.key, 0).value() >> 60; }
std::vector<BtreeRecord> ReadTree(const Fixture& f, bool refs=false, std::optional<std::uint64_t> xid={}) {
    VectorRandomAccessSource source(f.image); std::string error;
    auto view=LoadAppleCheckpointView(source,0,source.SizeBytes(),error,xid);
    Check(!!view,"reload tree checkpoint: "+error);
    const auto& v=view->volumes.front(); const auto& root=refs?*v.extentref_tree:v.root_tree;
    BtreeReadPolicy policy; policy.enforce_object_identity=true; policy.root_object_id=root.object_id;
    policy.storage_type=root.type; policy.subtype=root.subtype;
    std::vector<BtreeRecord> records;
    Check(ReadBtreeLeafRecords(source,kBlockSize,root.physical_block,refs,refs?0:v.superblock.omap_oid,
        view->container.superblock.xid,policy,records,error),"strict tree: "+error);
    return records;
}
BuilderStore CloneSpec(unsigned owners=2) {
    auto spec=Spec(); spec.block_count=512; auto& v=spec.volumes.front();
    v.next_object_id=1000; v.additional_file_system_allocated_blocks=4;
    auto add=[&](auto value, auto encode){BtreeRecord r; std::string e; Check(encode(value,r,e),e);v.filesystem_records.push_back(r);};
    AppleInodeRecord root; root.object_id=root.private_id=root.parent_id=2;root.mode=0040755;root.children_or_links=owners;
    add(root,EncodeAppleInodeRecord);
    for(unsigned n=0;n<owners;++n){
        auto id=17+n; AppleInodeRecord inode; inode.object_id=inode.private_id=id;inode.parent_id=2;
        inode.mode=0100640;inode.owner=501;inode.group=20;inode.children_or_links=1;inode.uncompressed_size=4*kBlockSize;
        AppleExtendedField stream;stream.type=8;stream.flags=1;stream.data.resize(40);
        PutU64LE(stream.data,0,4*kBlockSize);PutU64LE(stream.data,8,4*kBlockSize);inode.extended_fields.push_back(stream);
        add(inode,EncodeAppleInodeRecord);
        AppleDirectoryRecord d;d.parent_id=2;d.file_id=id;d.flags=8;d.name_utf8="clone"+std::to_string(n);
        BtreeRecord rec; std::string error;
        Check(EncodeAppleDirectoryRecord(d,ApfsNamePolicy::FromIncompatibleFeatures(kIncompatCaseInsensitive),rec,error),error);
        v.filesystem_records.push_back(rec);
        add(AppleDataStreamIdRecord{id,1},EncodeAppleDataStreamIdRecord);
        add(AppleFileExtentRecord{id,0,4*kBlockSize,kShared,0,kBlockSize},EncodeAppleFileExtentRecord);
        AppleXattrRecord attr;attr.object_id=id;attr.name_utf8="user.keep";attr.flags=kAppleXattrDataEmbedded;
        attr.data=HexToBytes("cafebabe012345");
        Check(EncodeAppleXattrRecord(attr,rec,error),error);v.filesystem_records.push_back(rec);
    }
    // Literal Apple j_phys_ext_key_t/value source bytes: PEXT_KIND_NEW=1,
    // four blocks, owning private ID 17, signed little-endian refcnt.
    BtreeRecord physical;physical.key=HexToBytes("8000000000000020");
    physical.value=HexToBytes("0400000000000010110000000000000002000000");PutU32LE(physical.value,16,owners);
    v.extentref_records.push_back(physical);
    for(unsigned n=0;n<4;++n){std::vector<std::byte> bytes(kBlockSize);for(unsigned i=0;i<kBlockSize;++i)bytes[i]=std::byte((i*13+n*47)%251);
        spec.authoritative_seeded_main_blocks.push_back({kShared+n,std::move(bytes)});}
    return spec;
}
std::vector<std::byte> Payload(const Fixture& f,std::uint64_t id,std::optional<std::uint64_t> xid={}) {
    auto records=ReadTree(f,false,xid);std::vector<std::byte> result;
    for(const auto& r:records)if(Type(r)==8&&Id(r)==id){AppleFileExtentRecord e;std::string error;
        Check(DecodeAppleFileExtentRecord(r,kBlockSize,e,error),error);result.resize((std::max<std::size_t>)(result.size(),e.logical_address+e.length_bytes));
        if(e.physical_block)std::copy_n(f.image.begin()+e.physical_block*kBlockSize,e.length_bytes,result.begin()+e.logical_address);}
    return result;
}
bool Deferred(const AppleVolumeTransactionPlan& plan,std::uint64_t b){return std::any_of(plan.allocation.deferred_frees.begin(),plan.allocation.deferred_frees.end(),[b](auto r){return b>=r.physical_block&&b-r.physical_block<r.block_count;});}
AppleVolumeTransactionPlan PlanClone(Fixture& f,const AppleVolumeTransactionRequest& r){
    AppleVolumeTransactionPlan p;VectorRandomAccessSource src(f.image);std::string error;
    const bool ok=PlanAppleVolumeTransaction(src,f.checkpoint,r,p,error); Check(ok,"clone plan: "+error);return p;
}
AppleVolumeTransactionRequest Remove(Fixture& f,std::set<std::uint64_t> ids){
    AppleVolumeTransactionRequest r;r.volume_object_id=101;r.file_count_delta=-static_cast<std::int64_t>(ids.size());
    for(auto rec:ReadTree(f)){
        if(Type(rec)==8&&ids.contains(Id(rec))){AppleFileExtentRecord e;std::string error;Check(DecodeAppleFileExtentRecord(rec,kBlockSize,e,error),error);r.released_data_blocks.push_back({e.physical_block,e.length_bytes/kBlockSize});continue;}
        if(ids.contains(Id(rec)))continue;
        if(Type(rec)==3&&Id(rec)==2){AppleInodeRecord root;std::string error;Check(ApfsExtendedRecordCodec::DecodeInode(rec,root,error),error);root.children_or_links-=static_cast<std::int32_t>(ids.size());Check(EncodeAppleInodeRecord(root,rec,error),error);}
        if(Type(rec)==9&&ids.contains(ReadU64LE(rec.value,0).value()))continue;
        r.filesystem_records.push_back(rec);
    }return r;
}
void CheckGraph(Fixture& f){auto records=ReadTree(f),refs=ReadTree(f,true);std::vector<ApplePhysicalExtentRecord> extents;std::string error;
    Check(ValidateApplePayloadExtentGraph(records,refs,kBlockSize,f.checkpoint.container.superblock.block_count,extents,error),"published graph: "+error);}
void SharedCowCases(){
    Fixture f(CloneSpec(3));auto old=Payload(f,17);const auto xid=f.checkpoint.container.superblock.xid;
    AppleVolumeTransactionRequest r;r.volume_object_id=101;r.required_checkpoint_xids={xid};
    for(auto rec:ReadTree(f)){
        if(Type(rec)==8&&Id(rec)==18){AppleFileExtentRecord e;std::string error;Check(DecodeAppleFileExtentRecord(rec,kBlockSize,e,error),error);
            e.length_bytes=kBlockSize;Check(EncodeAppleFileExtentRecord(e,rec,error),error);r.filesystem_records.push_back(rec);
            e.logical_address=2*kBlockSize;e.physical_block=kShared+2;e.length_bytes=2*kBlockSize;Check(EncodeAppleFileExtentRecord(e,rec,error),error);}
        r.filesystem_records.push_back(rec);
    }
    r.released_data_blocks={{kShared+1,1}};AppleVolumeDataWrite w;w.file_private_id=18;w.logical_address=kBlockSize;w.bytes.assign(kBlockSize,std::byte{0x91});r.data_writes={w};
    auto plan=PlanClone(f,r);Check(plan.payload_blocks.size()==1,"one-block first-write COW");
    for(auto b:plan.payload_blocks)Check(b<kShared||b>=kShared+4,"fresh allocation never aliases shared source");
    for(unsigned n=0;n<4;++n)Check(!Deferred(plan,kShared+n),"live clone reference never deferred");
    Publish(f,plan);CheckGraph(f);Check(Payload(f,17)==old&&Payload(f,19)==old,"two independent clone inodes retain original bytes");
    auto expected=old;std::fill_n(expected.begin()+kBlockSize,kBlockSize,std::byte{0x91});Check(Payload(f,18)==expected,"partial overwrite preserves prefix/suffix");
    Check(Payload(f,18,xid)==old,"retained checkpoint still maps original source bytes");
    // Descendant clone graph has three distinct streams. Removing its original
    // owner and a descendant simultaneously must decrement overlapping ranges.
    auto removal=Remove(f,{17,19});removal.required_checkpoint_xids={xid};auto unlink=PlanClone(f,removal);
    Check(Deferred(unlink,kShared+1),"only overwritten block now has zero live references");
    for(auto n:{0,2,3})Check(!Deferred(unlink,kShared+n),"remaining clone pins its ranges");
    Publish(f,unlink);CheckGraph(f);Check(Payload(f,18)==expected,"surviving descendant payload");
    auto final=Remove(f,{18});final.required_checkpoint_xids={xid};auto last=PlanClone(f,final);Publish(f,last);CheckGraph(f);
    Check(Payload(f,17,xid)==old,"last unlink retains old generation payload");
    for(unsigned n=0;n<4;++n){const auto& sm=f.checkpoint.spaceman;bool allocated=false;for(const auto& c:sm.chunks)if(kShared+n>=c.start_block&&kShared+n-c.start_block<c.block_count){auto bit=kShared+n-c.start_block;allocated=(std::to_integer<unsigned>(c.allocation_bitmap[bit/8])&(1u<<(bit%8)))!=0;}
        Check(allocated,"retained generation block remains allocated after last unlink");}
    std::ofstream out("clone-retained-final.apfs",std::ios::binary);out.write(reinterpret_cast<const char*>(f.image.data()),f.image.size());
}
void UnlinkAndTruncateCases(){
    for(unsigned count:{1,2,3}){Fixture f(CloneSpec(3));auto old=Payload(f,19);std::set<std::uint64_t> ids;for(unsigned i=0;i<count;++i)ids.insert(17+i);
        auto r=Remove(f,ids);auto p=PlanClone(f,r);for(unsigned n=0;n<4;++n)Check(Deferred(p,kShared+n)==(count==3),"unlink one/many exact last-owner retirement");Publish(f,p);CheckGraph(f);if(count<3)Check(Payload(f,19)==old,"unlink preserves survivor");}
    Fixture f(CloneSpec());auto old=Payload(f,18);AppleVolumeTransactionRequest r;r.volume_object_id=101;
    for(auto rec:ReadTree(f)){
        if(Type(rec)==8&&Id(rec)==17){AppleFileExtentRecord e;std::string error;Check(DecodeAppleFileExtentRecord(rec,kBlockSize,e,error),error);e.length_bytes=kBlockSize;Check(EncodeAppleFileExtentRecord(e,rec,error),error);}
        if(Type(rec)==3&&Id(rec)==17){AppleInodeRecord i;std::string error;Check(ApfsExtendedRecordCodec::DecodeInode(rec,i,error),error);PutU64LE(i.extended_fields[0].data,0,kBlockSize);PutU64LE(i.extended_fields[0].data,8,kBlockSize);Check(EncodeAppleInodeRecord(i,rec,error),error);}
        r.filesystem_records.push_back(rec);
    }r.released_data_blocks={{kShared+1,3}};auto p=PlanClone(f,r);for(unsigned n=0;n<4;++n)Check(!Deferred(p,kShared+n),"truncate shared range stays allocated");Publish(f,p);CheckGraph(f);Check(Payload(f,18)==old&&Payload(f,17).size()==kBlockSize,"truncate one inode only");
}
AppleVolumeTransactionRequest CloneRequest(Fixture& f, std::uint64_t source_id) {
    AppleVolumeTransactionRequest r;r.volume_object_id=101;r.file_count_delta=1;r.filesystem_records=ReadTree(f);
    const auto target=f.checkpoint.volumes.front().superblock.next_object_id;
    AppleInodeRecord inode;std::string error;bool found=false;
    for(auto& rec:r.filesystem_records){
        if(Type(rec)==3&&Id(rec)==source_id){Check(ApfsExtendedRecordCodec::DecodeInode(rec,inode,error),error);found=true;}
        if(Type(rec)==3&&Id(rec)==2){AppleInodeRecord root;Check(ApfsExtendedRecordCodec::DecodeInode(rec,root,error),error);++root.children_or_links;Check(EncodeAppleInodeRecord(root,rec,error),error);}
    }
    Check(found,"clone source inode exists");inode.object_id=inode.private_id=target;inode.children_or_links=1;
    BtreeRecord rec;Check(EncodeAppleInodeRecord(inode,rec,error),error);r.filesystem_records.push_back(rec);
    AppleDirectoryRecord d;d.parent_id=2;d.file_id=target;d.flags=8;d.name_utf8="created"+std::to_string(target);
    Check(EncodeAppleDirectoryRecord(d,ApfsNamePolicy::FromIncompatibleFeatures(kIncompatCaseInsensitive),rec,error),error);r.filesystem_records.push_back(rec);
    r.clones.push_back({source_id,target});return r;
}
// Valid type-3 bytes from the independent review: decode to 16 KiB of 'z'.
std::vector<std::byte> CloneCompressionBytes() {
    auto bytes=HexToBytes("66706d63030000000040000000000000");
    auto zlib=HexToBytes("789cedc13101000000c2a0de4b6f0c1fa000000000000000000000000000000080ce06b43881c3");
    bytes.insert(bytes.end(),zlib.begin(),zlib.end());return bytes;
}
void SeedCloneExternalAttribute(BuilderStore& spec, const std::string& name) {
    auto& v=spec.volumes[0];auto bytes=CloneCompressionBytes();BtreeRecord rec;std::string error;
    AppleXattrRecord a{17,name,kAppleXattrDataStream,std::vector<std::byte>(kAppleXattrDataStreamBytes)};
    PutU64LE(a.data,0,777);PutU64LE(a.data,8,bytes.size());PutU64LE(a.data,16,kBlockSize);
    Check(EncodeAppleXattrRecord(a,rec,error),error);v.filesystem_records.push_back(rec);
    Check(EncodeAppleDataStreamIdRecord({777,1},rec,error),error);v.filesystem_records.push_back(rec);
    Check(EncodeAppleFileExtentRecord({777,0,kBlockSize,160,0,kBlockSize},rec,error),error);v.filesystem_records.push_back(rec);
    Check(EncodeApplePhysicalExtentRecord({160,1,kApplePhysicalExtentKindNew,777,1},rec,error),error);v.extentref_records.push_back(rec);
    ++v.additional_file_system_allocated_blocks;bytes.resize(kBlockSize);
    spec.authoritative_seeded_main_blocks.push_back({160,std::move(bytes)});
}
void RequestedCloneCompressionRefusals() {
    std::vector<std::byte> decoded;
    Check(static_cast<bool>(ApfsCompression::DecodeRange(CloneCompressionBytes(), {}, 0, 16384, {}, decoded)) &&
        decoded == std::vector<std::byte>(16384, std::byte{0x7a}),
        "requested compression fixture decodes all matching-EOF bytes through the actual codec");
    unsigned failures=0;
    for(bool source:{false,true})for(bool external:{false,true})for(bool first:{false,true}) {
        auto spec=CloneSpec(1);
        if(external)SeedCloneExternalAttribute(spec,"user.compressed-bytes");
        Fixture f(spec);auto request=CloneRequest(f,17);const auto id=source?17:request.clones[0].target_inode_id;
        // Seed a real successful plan to verify refusal clears previously populated output.
        auto plan=PlanClone(f,request);Check(!Empty(plan),"refusal test starts with populated plan");
        AppleXattrRecord a{id,"com.apple.decmpfs",kAppleXattrDataEmbedded,CloneCompressionBytes()};std::string error;
        if(external) {
            for(const auto& rec:request.filesystem_records)if(Type(rec)==4&&Id(rec)==17) {
                AppleXattrRecord old;Check(ApfsExtendedRecordCodec::DecodeXattr(rec,old,error),error);
                if(old.name_utf8=="user.compressed-bytes"){a.flags=old.flags;a.data=old.data;}
            }
            // Keep a complete, already allocated external stream with valid compressed contents.
            // Ownership normalization may also refuse this new binding; the clone gate must refuse first.
        }
        BtreeRecord record;Check(EncodeAppleXattrRecord(a,record,error),error);
        request.filesystem_records.insert(first?request.filesystem_records.begin():request.filesystem_records.end(),record);
        Check(request.data_writes.empty(),"compression request supplies zero payload writes");
        const auto image=f.image;VectorRandomAccessSource input(f.image);
        bool accepted=PlanAppleVolumeTransaction(input,f.checkpoint,request,plan,error);
        const bool ok=!accepted&&Empty(plan)&&error=="AppleVolumeCloneStreamUnsupported";
        failures+=!ok;
        std::cout<<"requested_compression source="<<source<<" external="<<external<<" first="<<first
                 <<" accepted="<<accepted<<" empty="<<Empty(plan)<<" error="<<error<<"\n";
        Check(f.image==image,"refused/requested planning never changes source image");
    }
    Check(failures==0,"all eight requested compression cases refuse at clone gate with empty plan");
}
BuilderStore FragmentedCloneSpec() {
    auto spec=CloneSpec(2);auto& v=spec.volumes[0];
    std::erase_if(v.filesystem_records,[](const auto& r){return Type(r)==8;});v.extentref_records.clear();
    for(unsigned n=0;n<4;++n) {
        auto physical=kShared+2*n;spec.authoritative_seeded_main_blocks[n].first=physical;
        BtreeRecord rec;std::string error;
        for(auto id:{17ull,18ull}) {Check(EncodeAppleFileExtentRecord({id,n*kBlockSize,kBlockSize,physical,0,kBlockSize},rec,error),error);v.filesystem_records.push_back(rec);}
        Check(EncodeApplePhysicalExtentRecord({physical,1,kApplePhysicalExtentKindNew,17,2},rec,error),error);v.extentref_records.push_back(rec);
    }
    return spec;
}
void FragmentedCloneLookup() {
    for(unsigned fault=0;fault<8;++fault)for(bool reverse:{false,true}) {
        Fixture f(FragmentedCloneSpec());auto original=Payload(f,17);auto request=CloneRequest(f,17);
        const auto target=request.clones[0].target_inode_id;
        auto it=std::find_if(request.filesystem_records.begin(),request.filesystem_records.end(),[](const auto& r){return Type(r)==8&&Id(r)==17&&ReadU64LE(r.key,8)==2*kBlockSize;});
        Check(it!=request.filesystem_records.end(),"fragmented middle record exists");auto record=*it;
        if(fault==1)request.filesystem_records.erase(it); // Missing middle mapping.
        if(fault==2)PutU64LE(it->value,8,kShared+3); // Same key, different physical bytes.
        if(fault==3)request.filesystem_records.push_back(record); // Identical duplicate.
        if(fault==4){PutU64LE(record.value,8,kShared+3);request.filesystem_records.push_back(record);} // Conflict plus exact record.
        if(fault==5)PutU64LE(it->key,8,5*kBlockSize); // Same value, wrong logical key.
        if(fault==6)PutU64LE(it->value,16,1); // Crypto identity alone changes.
        if(fault==7){PutU64LE(it->value,8,kShared+3);request.filesystem_records.push_back(record);} // Exact duplicate after conflict.
        if(reverse)std::reverse(request.filesystem_records.begin(),request.filesystem_records.end());
        VectorRandomAccessSource input(f.image);AppleVolumeTransactionPlan plan;std::string error;
        bool accepted=PlanAppleVolumeTransaction(input,f.checkpoint,request,plan,error);
        Check(accepted==(fault==0),"fragmented lookup acceptance fault "+std::to_string(fault)+": "+error);
        std::cout<<"lookup fault="<<fault<<" reverse="<<reverse<<" accepted="<<accepted<<" empty="<<Empty(plan)<<"\n";
        if(fault){Check(Empty(plan),"fragmented duplicate/conflict refusal is atomic");continue;}
        Check(plan.payload_blocks.empty(),"fragmented clone allocates no payload");Publish(f,plan);CheckGraph(f);
        Check(Payload(f,17)==original&&Payload(f,18)==original&&Payload(f,target)==original,"fragmented published source/sibling/target bytes match");
        for(const auto& r:ReadTree(f,true)){ApplePhysicalExtentRecord e;Check(DecodeApplePhysicalExtentRecord(r,e,error),error);Check(e.reference_count==3&&e.owning_object_id==17,"fragmented exact physical references and owner");}
    }
}
void CloneMetadataPreservation() {
    for(bool external:{false,true}) {
        auto spec=CloneSpec(1);auto& records=spec.volumes[0].filesystem_records;std::string error;BtreeRecord rec;
        if(external)SeedCloneExternalAttribute(spec,"com.apple.ResourceFork");
        else {Check(EncodeAppleXattrRecord({17,"com.apple.ResourceFork",kAppleXattrDataEmbedded,HexToBytes("001122334455")},rec,error),error);records.push_back(rec);}
        Check(EncodeAppleXattrRecord({17,"com.apple.FinderInfo",kAppleXattrDataEmbedded,std::vector<std::byte>(32,std::byte{0x35})},rec,error),error);records.push_back(rec);
        Fixture f(spec);auto before=ReadTree(f);auto original=Payload(f,17);auto request=CloneRequest(f,17);
        // Caller-supplied target metadata remains supported, including a separate embedded fork.
        const auto target=request.clones[0].target_inode_id;
        for(const auto* name:{"user.target","com.apple.ResourceFork","com.apple.FinderInfo"}) {
            Check(EncodeAppleXattrRecord({target,name,kAppleXattrDataEmbedded,std::vector<std::byte>(32,std::byte{0x36})},rec,error),error);request.filesystem_records.push_back(rec);
        }
        const auto requested=request.filesystem_records;auto plan=PlanClone(f,request);Check(plan.payload_blocks.empty(),"metadata clone has no payload allocation");Publish(f,plan);CheckGraph(f);
        auto after=ReadTree(f);
        for(const auto& r:requested)if(Type(r)==4)Check(std::any_of(after.begin(),after.end(),[&](const auto& next){return r.key==next.key&&r.value==next.value;}),"source/target xattrs and fork descriptors preserved exactly");
        for(const auto& r:after)if(Type(r)==3&&(Id(r)==17||Id(r)==target)) {
            AppleInodeRecord inode;Check(ApfsExtendedRecordCodec::DecodeInode(r,inode,error),error);
            Check(inode.owner==501&&inode.group==20&&inode.mode==0100640,"original Mac owner/group/mode preserved on source/target");
        }
        Check(Payload(f,17)==original&&Payload(f,target)==original,"metadata clone retains ordinary data");
        if(external)Check(Payload(f,777)==std::vector<std::byte>(f.image.begin()+160*kBlockSize,f.image.begin()+161*kBlockSize),"external fork keeps its physical bytes");
    }
}

void NestedCloneCreation(){
    Fixture f(CloneSpec(1));auto original=Payload(f,17);const auto xid=f.checkpoint.container.superblock.xid;
    auto r=CloneRequest(f,17);auto child=r.clones.front().target_inode_id;r.required_checkpoint_xids={xid};
    auto p=PlanClone(f,r);Check(p.payload_blocks.empty(),"whole clone allocates no payload blocks");Publish(f,p);CheckGraph(f);
    Check(Payload(f,child)==original,"created clone shares original source bytes");
    r=CloneRequest(f,child);auto grandchild=r.clones.front().target_inode_id;r.required_checkpoint_xids={xid};p=PlanClone(f,r);Check(p.payload_blocks.empty(),"nested clone allocates no payload");Publish(f,p);CheckGraph(f);
    Check(Payload(f,grandchild)==original,"nested clone reads original payload");
    auto remove=Remove(f,{17,child});remove.required_checkpoint_xids={xid};p=PlanClone(f,remove);
    for(unsigned n=0;n<4;++n)Check(!Deferred(p,kShared+n),"nested descendant prevents ancestor retirement");Publish(f,p);CheckGraph(f);
    Check(Payload(f,grandchild)==original&&Payload(f,17,xid)==original,"nested clone survives ancestor unlink and checkpoint retention");
    for(const auto& rec:ReadTree(f,true)){ApplePhysicalExtentRecord e;std::string error;Check(DecodeApplePhysicalExtentRecord(rec,e,error),error);Check(e.reference_count==1&&e.owning_object_id==grandchild,"surviving private owner recorded exactly");}
    Fixture bad(CloneSpec(1));for(unsigned fault=0;fault<4;++fault){auto request=CloneRequest(bad,17);
        if(fault==0)request.clones[0].source_inode_id=999;
        if(fault==1)request.clones.push_back(request.clones.front());
        if(fault==2){AppleVolumeDataWrite w;w.file_private_id=17;w.bytes.resize(kBlockSize);request.data_writes.push_back(w);}
        if(fault==3)for(auto& rec:request.filesystem_records)if(Type(rec)==3&&Id(rec)==request.clones.front().target_inode_id)PutU64LE(rec.value,8,17);
        VectorRandomAccessSource src(bad.image);AppleVolumeTransactionPlan plan;std::string error;Check(!PlanAppleVolumeTransaction(src,bad.checkpoint,request,plan,error)&&Empty(plan),"invalid native clone input fails atomically");}
}
void PublicationBoundaries(){
    for(unsigned operation=0;operation<3;++operation)for(const auto* stage:{"before-apple-device-write","before-apple-prepublication-flush","before-apple-checkpoint-switch","before-apple-final-flush"}){
        Fixture f(CloneSpec());const auto original=Payload(f,18);const auto old_xid=f.checkpoint.container.superblock.xid;
        auto request=operation==0?CloneRequest(f,17):Remove(f,operation==1?std::set<std::uint64_t>{17}:std::set<std::uint64_t>{17,18});
        request.required_checkpoint_xids={old_xid};auto plan=PlanClone(f,request);MemoryTarget target(f.image);std::string error;
        Check(!ExecuteAppleCheckpointPublication(target,plan.commit.publication,error,[stage](std::string_view at){return at!=stage;}),"interrupted clone/reference publication reports failure");
        if(std::string_view(stage)=="before-apple-device-write")Check(target.writes==0,"preimage gate does no writes");
        f.image=std::move(target.image);f.Reload();CheckGraph(f);
        const bool published=std::string_view(stage)=="before-apple-final-flush";
        Check((f.checkpoint.container.superblock.xid!=old_xid)==published,"strict reload selects one complete checkpoint at flush boundary");
        Check(Payload(f,18,old_xid)==original,"every clone accounting boundary retains original generation bytes");
        if(operation<2||!published)Check(Payload(f,18)==original,"unaffected live clone survives publication interruption");
    }
    Fixture f(CloneSpec());auto request=Remove(f,{17});auto plan=PlanClone(f,request);MemoryTarget target(f.image);
    const auto root=f.checkpoint.volumes.front().root_tree.physical_block*kBlockSize;target.image[root+200]^=std::byte{1};std::string error;
    Check(!ExecuteAppleCheckpointPublication(target,plan.commit.publication,error)&&target.writes==0,"changed reference preimage refuses before first write");
    for(unsigned fault=0;fault<3;++fault){Fixture invalid(CloneSpec());
        if(fault==0){SetApsbCounter(invalid,0,0xD8,1);invalid.Reload();}
        if(fault==1){invalid.checkpoint.volumes.front().file_extent_tree=invalid.checkpoint.volumes.front().root_tree;}
        if(fault==2){invalid.checkpoint.spaceman.devices[1].block_count=1;}
        auto r=Remove(invalid,{17});VectorRandomAccessSource src(invalid.image);AppleVolumeTransactionPlan p;error.clear();
        Check(!PlanAppleVolumeTransaction(src,invalid.checkpoint,r,p,error)&&Empty(p),"snapshot/fext/Fusion remains closed");std::cout<<"unsupported "<<fault<<": "<<error<<"\n";
    }
}
void ReplaceCloneOwnerSameTransaction(){
    Fixture f(CloneSpec());auto original=Payload(f,18);auto request=CloneRequest(f,18);auto child=request.clones.front().target_inode_id;
    request.file_count_delta=0;
    for(auto& record:request.filesystem_records)if(Type(record)==3&&Id(record)==2){AppleInodeRecord root;std::string error;Check(ApfsExtendedRecordCodec::DecodeInode(record,root,error),error);--root.children_or_links;Check(EncodeAppleInodeRecord(root,record,error),error);}
    std::erase_if(request.filesystem_records,[&](const auto& record){
        if(Type(record)==8&&Id(record)==17){request.released_data_blocks.push_back({kShared,4});return true;}
        return Id(record)==17||(Type(record)==9&&ReadU64LE(record.value,0).value()==17);
    });
    auto plan=PlanClone(f,request);for(unsigned n=0;n<4;++n)Check(!Deferred(plan,kShared+n),"zero-net reference delta retains physical storage");Publish(f,plan);
    auto remove=Remove(f,{18});plan=PlanClone(f,remove);Publish(f,plan);CheckGraph(f);Check(Payload(f,child)==original,"new clone survives original owner replacement and source unlink");
}
void RetentionPressure(){
    Fixture f(CloneSpec());auto original=Payload(f,17);const auto xid=f.checkpoint.container.superblock.xid;
    auto removal=Remove(f,{17,18});removal.required_checkpoint_xids={xid};auto p=PlanClone(f,removal);Publish(f,p);
    bool blocked=false;unsigned successes=0;
    for(unsigned iteration=0;iteration<32;++iteration){AppleVolumeTransactionRequest r;r.volume_object_id=101;r.filesystem_records=ReadTree(f);r.required_checkpoint_xids={xid};
        VectorRandomAccessSource source(f.image);AppleVolumeTransactionPlan plan;std::string error;
        if(!PlanAppleVolumeTransaction(source,f.checkpoint,r,plan,error)){
            Check(error=="AppleSpacemanBitmapRetentionExhausted"||error=="AppleSpacemanInternalPoolRetentionExhausted"||error=="AppleCheckpointDataRetentionExhausted"||error=="AppleCheckpointDescriptorRetentionExhausted","pin pressure fails with retention capacity reason: "+error);
            Check(Empty(plan),"retention backpressure exposes no partial publication");blocked=true;break;}
        Publish(f,plan);++successes;Check(Payload(f,17,xid)==original,"old clone bytes survive repeated checkpoint turnover");
    }
    Check(blocked&&successes>0,"retained generation blocks ring reuse without losing its payload");
}
void CloneQuotaAccounting(){
    Fixture f(CloneSpec(1));auto request=CloneRequest(f,17);
    const auto prototype=request.clones.front().target_inode_id;
    AppleInodeRecord inode;std::string error;
    for(const auto& record:request.filesystem_records)if(Type(record)==3&&Id(record)==prototype)Check(ApfsExtendedRecordCodec::DecodeInode(record,inode,error),error);
    for(unsigned n=1;n<24;++n){inode.object_id=inode.private_id=prototype+n;BtreeRecord rec;Check(EncodeAppleInodeRecord(inode,rec,error),error);request.filesystem_records.push_back(rec);
        AppleDirectoryRecord d;d.parent_id=2;d.file_id=inode.object_id;d.flags=8;d.name_utf8="quota-clone"+std::to_string(n);Check(EncodeAppleDirectoryRecord(d,ApfsNamePolicy::FromIncompatibleFeatures(kIncompatCaseInsensitive),rec,error),error);request.filesystem_records.push_back(rec);request.clones.push_back({17,inode.object_id});}
    request.file_count_delta=24;
    for(auto& rec:request.filesystem_records)if(Type(rec)==3&&Id(rec)==2){AppleInodeRecord root;Check(ApfsExtendedRecordCodec::DecodeInode(rec,root,error),error);root.children_or_links=25;Check(EncodeAppleInodeRecord(root,rec,error),error);}
    auto allowed=PlanClone(f,request);Check(allowed.payload_blocks.empty(),"many clones share payload without reallocation");
    const auto before=f.checkpoint.volumes.front().superblock.space.allocated_block_count;
    SetApsbCounter(f,0,0x50,before);f.Reload(); // apfs_fs_quota_block_count
    VectorRandomAccessSource source(f.image);AppleVolumeTransactionPlan plan;
    const bool ok=PlanAppleVolumeTransaction(source,f.checkpoint,request,plan,error);
    Check(!ok&&error=="AppleVolumeQuotaExceeded"&&Empty(plan),"clone COW metadata still obeys quota: "+error);
}
void Refusals(){
    for(unsigned fault=0;fault<6;++fault){auto spec=CloneSpec();auto& v=spec.volumes[0];
        if(fault==0)PutU32LE(v.extentref_records[0].value,16,1);
        if(fault==1)PutU64LE(v.extentref_records[0].value,0,(2ull<<60)|4);
        if(fault==2)PutU32LE(v.extentref_records[0].value,16,0xffffffff);
        if(fault==3){for(auto& rec:v.filesystem_records)if(Type(rec)==6&&Id(rec)==17)PutU32LE(rec.value,0,2);}
        if(fault==4){for(auto& rec:v.filesystem_records)if(Type(rec)==3&&Id(rec)==18)PutU64LE(rec.value,8,17);}
        if(fault==5)PutU64LE(v.extentref_records[0].value,8,99);
        Fixture f(spec);auto r=Remove(f,{17});AppleVolumeTransactionPlan p;VectorRandomAccessSource source(f.image);std::string error;
        Check(!PlanAppleVolumeTransaction(source,f.checkpoint,r,p,error),"unsupported reference form refuses");Check(Empty(p),"failed plan exposes no publishable result");
        std::cout<<"refusal "<<fault<<": "<<error<<"\n";
    }
}
}
 #ifndef APPLE_CLONE_TEST_HELPERS_ONLY
int main(){try{RequestedCloneCompressionRefusals();FragmentedCloneLookup();CloneMetadataPreservation();SharedCowCases();UnlinkAndTruncateCases();NestedCloneCreation();PublicationBoundaries();RetentionPressure();ReplaceCloneOwnerSameTransaction();CloneQuotaAccounting();Refusals();std::cout<<"PASS clone COW "<<checks<<" checks\n";return 0;}catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<"\n";return 1;}}

#endif
