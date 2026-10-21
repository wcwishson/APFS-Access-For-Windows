#define wmain SnapshotGeneralizedUnusedMain
#include "SnapshotGeneralizedPlanningTests.cpp"
#undef wmain
#include "ApfsReadOnlyMetadataAdmission.h"
#include "ApfsExtendedRecordCodec.h"
#include <fstream>

namespace {
AppleSnapshotRetentionView PhysicalInventory(const Bytes& image, std::size_t expected) {
    const auto cp=Load(image);const auto& v=cp.volumes.at(0);
    Check(v.superblock.snap_meta_tree_type==(kObjectPhysical|kObjectTypeBtree) &&
        v.snapshot_metadata_tree && v.snapshot_metadata_tree->object_id==v.snapshot_metadata_tree->physical_block &&
        v.superblock.snap_meta_tree_oid==v.snapshot_metadata_tree->physical_block,"physical APSB root identity");
    VectorRandomAccessSource source(image);std::string error;AppleSnapshotRetentionView retained;
    Call(LoadAppleSnapshotRetention(source,cp,retained,error),"strict physical retained owners",error);
    Check(retained.identities.size()==expected,"exact physical snapshot census");
    AppleSnapshotCatalogRecords catalog;
    Call(LoadAppleReadOnlySnapshotCatalog(source,cp,v.superblock.object_id,catalog,error),"canonical physical catalog",error);
    Check(catalog.inventory.size()==expected && catalog.snapshots.size()==expected,"complete canonical historical views");
    for(const auto block:MetadataBlocks(image)) {
        const auto type=ReadU32LE(image,block*4096+0x18).value();
        Check(ReadU64LE(image,block*4096+8)==block &&
            type==(kObjectPhysical|(block==v.snapshot_metadata_tree->physical_block?kObjectTypeBtree:kObjectTypeBtreeNode)),
            "every physical snapshot node uses its paddr identity and exact node type");
    }
    return retained;
}
void PhysicalOmapInvariant(const Bytes& before,const Bytes& after) {
    const auto read=[](const Bytes& image) {
        const auto cp=Load(image);VectorRandomAccessSource source(image);std::string error;
        std::vector<BtreeRecord> records;std::vector<std::uint64_t> visited;
        Call(ReadAppleSnapshotTree(source,4096,cp.volumes[0].object_map.tree,cp.volumes[0].object_map,
            cp.container.superblock.xid,cp.container.superblock.xid,records,visited,error),"complete physical OMAP",error);
        return records;
    };
    const auto old=read(before),next=read(after);
    Check(old.size()==next.size() && std::equal(old.begin(),old.end(),next.begin(),
        [](const auto& a,const auto& b){return a.key==b.key && a.value==b.value;}),
        "physical metadata never fabricates or removes virtual OMAP mappings");
    Check(Load(before).volumes[0].superblock.next_object_id==Load(after).volumes[0].superblock.next_object_id,
        "physical metadata never consumes virtual inode IDs");
}
void PublicPhysicalInventory(const Bytes& image) {
    const auto cp=Load(image);const auto& v=cp.volumes[0];VectorRandomAccessSource source(image);std::string error;
    ApfsSnapshotScope scope{0,source.SizeBytes(),cp.container.superblock.uuid_hex,v.superblock.uuid_hex,1026,cp.container.superblock.xid};
    std::vector<ApfsSnapshotInfo> inventory;
    Call(ApfsSnapshotStore::Enumerate(source,scope,inventory,error),"public genuine snapshot enumeration",error);
    Check(inventory.size()==12,"public exact twelve-snapshot census");
    for(const auto& snapshot:inventory){
        ApfsSnapshotRecords records;
        Call(ApfsSnapshotStore::LoadExactResolvedRecords(source,snapshot.identity,records,error),"public exact physical resolved records",error);
        Check(records.snapshot.identity==snapshot.identity && !records.trees.filesystem.empty(),"public snapshot identity and original filesystem");
        bool header_owner=false;
        for(const auto& raw:records.trees.extentref){ApplePhysicalExtentRecord e;
            Call(DecodeApplePhysicalExtentRecord(raw,e,error),"resolved physical snapshot owner",error);
            if(e.physical_block==98){Check(e.owning_object_id==23 && e.reference_count==1,"public retained external stream uses header owner 23");header_owner=true;}}
        Check(header_owner,"public exact history retains the external-xattr block");
    }
    auto wrong=inventory.front().identity;wrong.name_utf8="spoofed";ApfsSnapshotRecords denied;
    Check(!ApfsSnapshotStore::LoadExactResolvedRecords(source,wrong,denied,error) && error=="SnapshotExactIdentityMismatchOrMissing" &&
        denied.trees.filesystem.empty(),"public physical identity spoof clears all output");
    Pass("public physical enumeration and twelve exact resolved snapshot owner graphs");
}
Bytes GenuineSource() {
    const std::filesystem::path path=L"D:\\ApfsAccessScratch\\WindowsClosure\\encrypted-fixtures-20261008-173132\\dfvfs-plain-apfs.raw";
    Check(std::filesystem::file_size(path)==4153344,"genuine original length");
    Bytes image(4153344);std::ifstream input(path,std::ios::binary);
    input.read(reinterpret_cast<char*>(image.data()),static_cast<std::streamsize>(image.size()));
    Check(input.good(),"complete genuine original read");
    const auto cp=Load(image);
    Check(cp.container.superblock.uuid_hex=="d08a9fa0d5a5458b813eebf9bf5d5338" && cp.container.superblock.xid==4 &&
        cp.volumes.size()==1 && cp.volumes[0].superblock.object_id==1026 &&
        cp.volumes[0].superblock.snap_meta_tree_oid==88,"exact genuine initial authority");
    PhysicalInventory(image,0);return image;
}
void PhysicalRefusals(const Bytes& image) {
    const auto cp=Load(image);const auto inventory=PhysicalInventory(image,12);std::string error;
    for(unsigned variant=0;variant<4;++variant) {
        AppleSnapshotDeleteRequest request;request.expected=inventory.identities[3];request.modification_time_ns=50;
        if(variant==0)request.expected.name_utf8="wrong-name";
        if(variant==1)++request.expected.superblock_physical_block;
        if(variant==2)request.expected.scope.volume_oid=1027;
        if(variant==3)request.required_checkpoint_xids={cp.container.superblock.next_xid+1};
        VectorRandomAccessSource source(image);AppleSnapshotDeletePlan denied;
        Check(!PlanAppleSnapshotDelete(source,cp,request,denied,error) && !error.empty() &&
            denied.commit.publication.before_superblock_writes.empty() && denied.allocation.allocated_main_blocks.empty(),
            "wrong identity or missing required checkpoint refuses before publication: "+error);
        std::cout<<"REFUSAL "<<variant<<" "<<error<<std::endl;
    }
    const auto nodes=MetadataBlocks(image);
    Check(nodes.size()>1,"malformed controls use a real physical child");
    const auto child=*std::find_if(nodes.begin(),nodes.end(),[&](auto b){return b!=cp.volumes[0].snapshot_metadata_tree->physical_block;});
    for(unsigned variant=0;variant<4;++variant) {
        auto changed=image;const auto base=child*4096;
        if(variant==0)changed[base+64]^=std::byte{1};
        if(variant==1)PutU64LE(changed,base+8,child+1);
        if(variant==2)PutU32LE(changed,base+0x18,kObjectTypeBtreeNode);
        if(variant==3)PutU32LE(changed,base+0x1c,kObjectTypeFsTree);
        if(variant){Bytes block(changed.begin()+base,changed.begin()+base+4096);FletcherForBlock(block,4096);
            std::copy(block.begin(),block.end(),changed.begin()+base);}
        const auto before=changed;VectorRandomAccessSource source(changed);AppleSnapshotCreatePlan denied;
        Check(!PlanAppleSnapshotCreate(source,cp,{1026,"corrupt-child",1},denied,error) && !error.empty() &&
            denied.commit.publication.before_superblock_writes.empty() && denied.allocation.allocated_main_blocks.empty() && changed==before,
            "checksum/OID/storage/subtype corruption refuses without any mutation: "+error);
    }
    Pass("genuine physical child corruption, exact identity and required-checkpoint vetoes");
}
void FirstCreateCuts(const std::filesystem::path& root,const Bytes& original,const AppleCheckpointPublicationPlan& plan) {
    std::string error;unsigned index=0;
    for(const auto stage:{"before-apple-device-write","before-apple-prepublication-flush","before-apple-checkpoint-switch","before-apple-final-flush"}) {
        const auto path=root/(L"create-cut-"+std::to_wstring(index++)+L".img");
        {FileTarget file(path,&original);
            Check(!ExecuteAppleCheckpointPublication(file,plan,error,[&](std::string_view at){return at!=stage;}),
                "actual physical create cut refuses acknowledgement");}
        FileTarget reopened(path,nullptr);const auto image=reopened.All();const auto xid=Load(image).container.superblock.xid;
        Check(xid==4 || xid==5,"actual cut selects an exact old or new checkpoint");PhysicalInventory(image,xid==4?0:1);
    }
    {FileTarget file(root/L"create-partial.img",&original);file.fail_after_writes=plan.before_superblock_writes.size()/2;
        Check(!ExecuteAppleCheckpointPublication(file,plan,error) && file.writes>0,"partial actual physical COW write refuses");}
    {FileTarget file(root/L"create-partial.img",nullptr);const auto image=file.All();
        Check(Load(image).container.superblock.xid==4,"partial write preserves original canonical selection");PhysicalInventory(image,0);}
    Pass("genuine regular-image publication cuts and partial physical COW");
}
Bytes MutateRetained(FileTarget& file,const Bytes& image,bool pinned) {
    const auto cp=Load(image);VectorRandomAccessSource source(image);std::string error;AppleSnapshotCatalogRecords catalog;
    Call(LoadAppleReadOnlySnapshotCatalog(source,cp,1026,catalog,error),"genuine mutation canonical source",error);
    AppleVolumeTransactionRequest request;request.volume_object_id=1026;request.filesystem_records=catalog.live.filesystem;
    if(pinned)request.required_checkpoint_xids={4};
    bool found=false;std::uint64_t stream=0;
    for(auto& raw:request.filesystem_records)if((ReadU64LE(raw.key,0).value_or(0)>>60)==3 &&
        (ReadU64LE(raw.key,0).value()&((1ull<<60)-1))==17) {
        AppleInodeRecord inode;Call(ApfsExtendedRecordCodec::DecodeInode(raw,inode,error),"genuine target inode",error);
        Check((inode.mode&0170000)==0100000 && inode.private_id==17,"genuine target regular stream");stream=inode.private_id;
        inode.uncompressed_size=4096;
        for(auto& field:inode.extended_fields)if(field.type==8){Check(field.data.size()==40,"genuine dstream shape");
            PutU64LE(field.data,0,4096);PutU64LE(field.data,8,4096);found=true;}
        Call(EncodeAppleInodeRecord(inode,raw,error),"canonical genuine mutation inode",error);
    }
    Check(found,"genuine inode has a complete size-bearing data stream");
    std::erase_if(request.filesystem_records,[&](const auto& raw){
        if((ReadU64LE(raw.key,0).value_or(0)>>60)!=8)return false;
        AppleFileExtentRecord extent;Call(DecodeAppleFileExtentRecord(raw,4096,extent,error),"genuine release extent",error);
        if(extent.object_id!=stream)return false;
        request.released_data_blocks.push_back({extent.physical_block,(extent.length_bytes+4095)/4096});return true;
    });
    request.data_writes.push_back({stream,0,0,Bytes(4096,std::byte{0x6d})});AppleVolumeTransactionPlan plan;
    Call(PlanAppleSnapshotLiveTransaction(file,cp,request,plan,error),"genuine retained live mutation plan",error);
    Check(file.All()==image,"live mutation planning leaves original file exact");
    const auto retained=PhysicalInventory(image,12);
    Call(ExecuteAppleCheckpointPublication(file,plan.commit.publication,error),"genuine retained live mutation publication",error);
    const auto after=file.All();PhysicalInventory(after,12);RetainedBytes(image,after,retained);
    VectorRandomAccessSource next(after);AppleSnapshotCatalogRecords changed;
    Call(LoadAppleReadOnlySnapshotCatalog(next,Load(after),1026,changed,error),"genuine mutation canonical readback",error);
    unsigned extents=0;
    for(const auto& raw:changed.live.filesystem)if((ReadU64LE(raw.key,0).value_or(0)>>60)==8) {
        AppleFileExtentRecord e;Call(DecodeAppleFileExtentRecord(raw,4096,e,error),"mutated live extent",error);
        if(e.object_id==stream){Bytes bytes;Check(next.Read(e.physical_block*4096,4096,bytes) && bytes==Bytes(4096,std::byte{0x6d}),
            "mutated live raw payload has exact pattern");++extents;}
    }
    Check(extents==1,"exact one new native live data extent");
    Pass("genuine live COW preserves all twelve snapshot payloads and external header ownership");return after;
}
void GenuineHistory(const std::filesystem::path& root,bool long_names,bool pinned) {
    const auto original=GenuineSource();Bytes image=original;std::string error;
    const auto path=root/L"genuine.img";
    {FileTarget seed(path,&image);}
    bool branch=false;AppleCheckpointPublicationPlan first_create;
    for(unsigned i=0;i<12;++i) {
        FileTarget file(path,nullptr);const auto cp=Load(image);const auto retained=PhysicalInventory(image,i);
        AppleSnapshotCreateRequest request{1026,(long_names?std::string(225,'x')+"-":"")+"physical-"+std::to_string(i),i+1};
        if(pinned)request.required_checkpoint_xids={4};
        AppleSnapshotCreatePlan plan;
        Call(PlanAppleSnapshotCreate(file,cp,request,plan,error),"genuine physical create plan",error);
        if(!i)first_create=plan.commit.publication;
        Check(file.All()==image,"create planning preserves every source byte");
        Call(ExecuteAppleCheckpointPublication(file,plan.commit.publication,error),"genuine physical create publication",error);
        const auto next=file.All();PhysicalInventory(next,i+1);RetainedBytes(image,next,retained);
        PhysicalOmapInvariant(image,next);image=next;branch|=MetadataBlocks(image).size()>1;
        std::cout<<"CREATE "<<i+1<<" xid="<<Load(image).container.superblock.xid<<std::endl;
    }
    Check(branch==long_names,"genuine twelve-snapshot physical tree has the expected branch or leaf shape");
    {FileTarget saved(root/L"twelve.img",&image);}
    Pass("twelve genuine physical snapshots, canonical history, paddr roots and unchanged OMAP");
    PublicPhysicalInventory(image);
    if(long_names)PhysicalRefusals(image);
    FirstCreateCuts(root,original,first_create);
    {FileTarget file(path,nullptr);image=MutateRetained(file,image,pinned);}
    {FileTarget saved(root/L"mutated.img",&image);}
    if(pinned){VectorRandomAccessSource source(image);std::vector<AppleRecoveryCheckpointView> pins;
        Call(LoadAppleSnapshotRecoveryCheckpoints(source,Load(image),{4},pins,error),"genuine original checkpoint pin after twelve snapshots and mutation",error);
        Check(pins.size()==1 && pins[0].checkpoint.container.superblock.xid==4,"exact genuine original checkpoint remains canonical and owned");
        Pass("genuine original XID 4 remains a complete recovery owner after thirteen publications");}
    for(unsigned count=12;count;--count) {
        FileTarget file(path,nullptr);const auto cp=Load(image);const auto inventory=PhysicalInventory(image,count);
        AppleSnapshotDeleteRequest request;request.expected=inventory.identities[count%3==0?count-1:count%3==1?0:count/2];
        request.modification_time_ns=100+count;
        if(pinned)request.required_checkpoint_xids={4};
        AppleSnapshotDeletePlan plan;
        if(count==1) {
            request.required_checkpoint_xids={pinned?4ull:16ull};AppleSnapshotDeletePlan denied;
            Check(!PlanAppleSnapshotDelete(file,cp,request,denied,error) && !error.empty() &&
                denied.commit.publication.before_superblock_writes.empty() && file.All()==image,
                "retained pre-mutation checkpoint prevents final original-payload retirement: "+error);
            if(pinned)Check(error=="AppleSnapshotDeleteRecoveryOwner","genuine available original pin vetoes actual payload release: "+error);
            std::cout<<"FINAL PIN REFUSAL "<<error<<std::endl;request.required_checkpoint_xids.clear();
        }
        Call(PlanAppleSnapshotDelete(file,cp,request,plan,error),"genuine physical delete plan",error);
        Check(file.All()==image,"delete planning preserves every source byte");
        Call(ExecuteAppleCheckpointPublication(file,plan.commit.publication,error),"genuine physical delete publication",error);
        const auto next=file.All();PhysicalInventory(next,count-1);PhysicalOmapInvariant(image,next);image=next;
        Check(plan.released_payload_blocks==(count==1?1:0),"only last snapshot releases the overwritten original payload block");
        std::cout<<"DELETE remaining="<<count-1<<std::endl;
    }
    Check(!Load(image).volumes[0].object_map.snapshot_tree_oid,"last deletion clears OMAP snapshot index");
    Pass("genuine oldest/middle/newest deletion through branch, leaf and empty");
    {FileTarget file(path,nullptr);AppleSnapshotCreatePlan plan;
        Call(PlanAppleSnapshotCreate(file,Load(image),{1026,"genuine-recreated",200},plan,error),"physical create after final deletion",error);
        Call(ExecuteAppleCheckpointPublication(file,plan.commit.publication,error),"physical recreation publication",error);
        PhysicalInventory(file.All(),1);}
    Pass("physical snapshot recreation after native mutation and final deletion");
}
void GenuinePinBudget(const std::filesystem::path& root) {
    const auto original=GenuineSource();const auto path=root/L"pinned.img";
    {FileTarget seed(path,&original);}
    std::string error;
    for(unsigned i=0;i<2;++i){FileTarget file(path,nullptr);const auto before=file.All();const auto cp=Load(before);
        AppleSnapshotCreateRequest request{1026,"pinned-"+std::to_string(i),i+1};request.required_checkpoint_xids={4};
        AppleSnapshotCreatePlan plan;Call(PlanAppleSnapshotCreate(file,cp,request,plan,error),"genuine pinned create",error);
        Call(ExecuteAppleCheckpointPublication(file,plan.commit.publication,error),"genuine pinned publication",error);
        const auto after=file.All();PhysicalInventory(after,i+1);std::vector<AppleRecoveryCheckpointView> pins;
        Call(LoadAppleSnapshotRecoveryCheckpoints(file,Load(after),{4},pins,error),"complete genuine original pin",error);
        const auto original_pin=std::find_if(pins.begin(),pins.end(),[](const auto& pin){
            return pin.checkpoint.container.superblock.xid==4;});
        Check(pins.size()==i+1 && original_pin!=pins.end(),"complete continuity chain includes exact original XID pin");
        for(const auto block:original_pin->metadata_blocks)
            Check(std::equal(original.begin()+block*4096,original.begin()+(block+1)*4096,after.begin()+block*4096),
                "every pinned original metadata block is immutable");
        for(const auto& range:original_pin->payload_extents)
            Check(std::equal(original.begin()+range.physical_block*4096,
                original.begin()+(range.physical_block+range.block_count)*4096,after.begin()+range.physical_block*4096),
                "every pinned original payload interval is immutable");
    }
    FileTarget file(path,nullptr);const auto before=file.All();AppleSnapshotCreateRequest request{1026,"pin-quota",3};
    request.required_checkpoint_xids={4};AppleSnapshotCreatePlan denied;
    Check(!PlanAppleSnapshotCreate(file,Load(before),request,denied,error) && error=="AppleSpacemanInternalPoolRetentionExhausted" &&
        denied.allocation.allocated_main_blocks.empty() && denied.commit.publication.before_superblock_writes.empty() && file.All()==before,
        "genuine finite IP retention quota refuses before plan exposure and target mutation: "+error);
    Pass("two genuine snapshots retain exact original checkpoint and finite IP quota refuses the third");
}
}
#ifndef PHYSICAL_SNAPSHOT_NO_MAIN
int wmain(int argc,wchar_t** argv) {
    try {
        Check(argc==2 || (argc==3 && (std::wstring_view(argv[2])==L"--leaf" || std::wstring_view(argv[2])==L"--pinned-leaf")),
            "fresh private D artifact root and optional leaf control");
        FreshRoot root(argv[1]);
        if(argc==3 && std::wstring_view(argv[2])==L"--pinned-leaf")GenuinePinBudget(root.path);
        else GenuineHistory(root.path,argc==2,false);
        std::cout<<"PASS "<<groups<<" groups "<<checks<<" checks"<<std::endl;return 0;
    }catch(const std::exception& e){std::cerr<<"FAIL after "<<checks<<" checks: "<<e.what()<<std::endl;return 1;}
}
#endif
