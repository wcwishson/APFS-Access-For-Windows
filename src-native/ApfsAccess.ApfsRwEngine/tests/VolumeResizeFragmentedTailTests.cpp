#define APFS_RELOCATION_KEEPER_FIXTURE_ONLY
#include "VolumeResizeRelocationKeeperTests.cpp"
#undef APFS_RELOCATION_KEEPER_FIXTURE_ONLY
#include "NativeApfsReader.h"
#include "ApfsExtendedRecordCodec.h"

namespace {
using CatRecord=apfsaccess::catalog::BtreeRecord;
constexpr std::uint64_t Boundary=3*mc::ChunkBlocks-25;
Bytes Pattern(){Bytes out(8*4096);for(std::size_t i=0;i<out.size();++i)out[i]=std::byte((i*13+(i/4096)*47)%251);return out;}
std::uint64_t Kind(const CatRecord& r){return ReadU64LE(r.key,0).value()>>60;}
std::uint64_t Owner(const CatRecord& r){return ReadU64LE(r.key,0).value()&0x0fffffffffffffffULL;}
template<class S> void Leaf(S& source,const AppleObjectLocation& location,std::vector<CatRecord> records,AppleBtreeKeyOrder order){
    std::string error;Check(SortAppleBtreeRecords(records,order,error),error);AppleBtreeOptions o;
    o.block_size=4096;o.root_object_id=location.object_id;o.root_physical_block=location.physical_block;o.xid=location.xid;
    o.subtype=location.subtype;o.storage_type=location.type&kObjectStorageTypeMask;o.key_order=order;o.max_nodes=1;
    o.tree_flags=o.storage_type==kObjectPhysical?kAppleBtreePhysical:0;
    AppleSerializedBtree tree;Check(SerializeAppleBtree(records,o,tree,error)&&tree.objects.size()==1,"fixture canonical leaf: "+error);
    Check(source.WriteBlock(location.physical_block,tree.objects.front().bytes),"fixture bounded leaf write");
}
mc::SparseStore SharedSource(){
    auto source=Source();auto format=Request(root,VolumeImageOperation::Format,Fixture());format.expected_bytes=format.target_bytes=source.SizeBytes();
    auto formatted=vi::BuildFormatPublication(source,format,mc::Load(source));vi::FinishFormatSource(source,format,formatted);
    source=mc::Publish(std::move(source),formatted);auto cp=mc::Load(source);const auto oid=cp.volumes.front().superblock.object_id;
    AppleVolumeTransactionRequest r;r.volume_object_id=oid;std::string error;
    Check(ReadAppleVolumeFileSystemRecords(source,cp.container,cp.volumes.front(),r.filesystem_records,error),error);
    CatRecord encoded;AppleInodeRecord inode;inode.object_id=inode.private_id=1030;inode.parent_id=2;inode.mode=0100644;inode.children_or_links=1;inode.uncompressed_size=32768;
    AppleExtendedField stream{8,0,Bytes(40)};PutU64LE(stream.data,0,32768);PutU64LE(stream.data,8,32768);inode.extended_fields.push_back(stream);
    Check(EncodeAppleInodeRecord(inode,encoded,error),error);r.filesystem_records.push_back(encoded);
    AppleDirectoryRecord entry{2,1030,0,8,"source-tail.bin"};Check(EncodeAppleDirectoryRecord(entry,ApfsNamePolicy::FromIncompatibleFeatures(cp.volumes.front().superblock.incompatible_features),encoded,error),error);r.filesystem_records.push_back(encoded);
    Check(EncodeAppleDataStreamIdRecord({1030,1},encoded,error),error);r.filesystem_records.push_back(encoded);
    for(auto& record:r.filesystem_records)if(Kind(record)==3&&Owner(record)==2){AppleInodeRecord parent;Check(ApfsExtendedRecordCodec::DecodeInode(record,parent,error),error);++parent.children_or_links;Check(EncodeAppleInodeRecord(parent,record,error),error);}
    r.file_count_delta=1;r.data_writes.push_back({1030,0,0,Pattern()});AppleVolumeTransactionPlan written;
    Check(PlanAppleVolumeTransaction(source,cp,r,written,error),"native initial eight-block file: "+error);
    Check(ExecuteAppleCheckpointPublication(source,written.commit.publication,error),error);cp=mc::Load(source);
    const auto& volume=cp.volumes.front();std::vector<CatRecord> records;
    Check(ReadAppleVolumeFileSystemRecords(source,cp.container,volume,records,error),error);
    std::map<std::uint64_t,std::uint64_t> old;
    for(const auto& record:records)if(Kind(record)==8&&Owner(record)==1030){AppleFileExtentRecord extent;Check(DecodeAppleFileExtentRecord(record,4096,extent,error),error);
        for(std::uint64_t i=0;i<extent.length_bytes/4096;++i)Check(old.emplace(extent.logical_address/4096+i,extent.physical_block+i).second,"complete original logical census");}
    Check(old.size()==8,"eight actual original payload blocks");
    // Authored canonical source, before keeper authority: two distinct private
    // streams share three physical runs, including a run crossing the new EOF.
    for(auto& record:records)if(Kind(record)==3&&Owner(record)==2){AppleInodeRecord parent;Check(ApfsExtendedRecordCodec::DecodeInode(record,parent,error),error);++parent.children_or_links;Check(EncodeAppleInodeRecord(parent,record,error),error);}
    inode.object_id=inode.private_id=1031;Check(EncodeAppleInodeRecord(inode,encoded,error),error);records.push_back(encoded);
    entry.file_id=1031;entry.name_utf8="clone-tail.bin";Check(EncodeAppleDirectoryRecord(entry,ApfsNamePolicy::FromIncompatibleFeatures(volume.superblock.incompatible_features),encoded,error),error);records.push_back(encoded);
    Check(EncodeAppleDataStreamIdRecord({1031,1},encoded,error),error);records.push_back(encoded);
    std::erase_if(records,[](const auto& record){return Kind(record)==8&&Owner(record)==1030;});
    const std::array<std::uint64_t,8> destination{Boundary-1,Boundary,Boundary+1,3*mc::ChunkBlocks+500,3*mc::ChunkBlocks+501,Boundary-64,Boundary-63,Boundary-62};
    std::vector<CatRecord> references;
    for(const auto [logical,count]:{std::pair{0ull,3ull},std::pair{3ull,2ull},std::pair{5ull,3ull}}){
        for(auto id:{1030ull,1031ull}){Check(EncodeAppleFileExtentRecord({id,logical*4096,count*4096,destination[logical],0,4096},encoded,error),error);records.push_back(encoded);}
        Check(EncodeApplePhysicalExtentRecord({destination[logical],count,kApplePhysicalExtentKindNew,1030,2},encoded,error),error);references.push_back(encoded);
    }
    Leaf(source,volume.root_tree,std::move(records),AppleBtreeKeyOrder::FileSystemHashedDirectory);
    Check(volume.extentref_tree.has_value(),"physical reference root required");Leaf(source,*volume.extentref_tree,std::move(references),AppleBtreeKeyOrder::PhysicalExtent);
    std::map<std::size_t,Bytes> bitmaps,cibs;std::map<std::size_t,std::uint64_t> bitmap_addresses;
    Check(cp.spaceman.internal_pool.active_bitmaps.size()==1,"bounded authored fixture has one current pool bitmap");
    auto pool_bitmap=cp.spaceman.internal_pool.active_bitmaps.front().bytes;bool pool_changed=false;
    for(auto block:destination){const auto index=static_cast<std::size_t>(block/cp.spaceman.blocks_per_chunk);const auto& chunk=cp.spaceman.chunks.at(index);
        if(chunk.bitmap_block||bitmap_addresses.contains(index))continue;
        Check(chunk.free_count==chunk.block_count,"null bitmap chunk is completely free before fixture authoring");
        std::uint64_t slot=0;while(slot<cp.spaceman.internal_pool.block_count&&vi::Bit(pool_bitmap,slot))++slot;
        Check(slot<cp.spaceman.internal_pool.block_count,"fixture has a real free internal-pool bitmap slot");vi::SetBit(pool_bitmap,slot,true);pool_changed=true;
        bitmap_addresses[index]=cp.spaceman.internal_pool.base_block+slot;auto& bitmap=bitmaps[index];bitmap.assign(4096,std::byte{});
        for(std::uint64_t bit=chunk.block_count;bit<cp.spaceman.blocks_per_chunk;++bit)vi::SetBit(bitmap,bit,true);
        auto [where,_]=cibs.try_emplace(chunk.cib_index,cp.spaceman.devices[0].cibs.at(chunk.cib_index).bytes);vi::Put(where->second,0x28+chunk.index_in_cib*32+24,bitmap_addresses.at(index));
    }
    for(std::size_t i=0;i<8;++i){const auto from=old.at(i),to=destination[i];Bytes bytes;
        Check(source.Read(from*4096,4096,bytes)&&source.WriteBlock(to,bytes),"copy exact old payload into authored fragments");
        for(const auto [block,set]:{std::pair{from,false},std::pair{to,true}}){const auto index=static_cast<std::size_t>(block/cp.spaceman.blocks_per_chunk);const auto& chunk=cp.spaceman.chunks.at(index);
            auto [where,_]=bitmaps.try_emplace(index,chunk.allocation_bitmap);Check((chunk.bitmap_block||bitmap_addresses.contains(index))&&vi::Bit(where->second,block-chunk.start_block)!=set,"author only exact old/free bitmap bits");vi::SetBit(where->second,block-chunk.start_block,set);}
    }
    for(const auto& [index,bitmap]:bitmaps){const auto& chunk=cp.spaceman.chunks.at(index);std::uint64_t free=0;for(std::uint64_t bit=0;bit<chunk.block_count;++bit)if(!vi::Bit(bitmap,bit))++free;
        auto [where,_]=cibs.try_emplace(chunk.cib_index,cp.spaceman.devices[0].cibs.at(chunk.cib_index).bytes);vi::Put(where->second,0x28+chunk.index_in_cib*32+20,free,4);Check(source.WriteBlock(chunk.bitmap_block?chunk.bitmap_block:bitmap_addresses.at(index),bitmap),"exact fixture bitmap");}
    if(pool_changed)Check(source.WriteBlock(cp.spaceman.internal_pool.active_bitmaps.front().physical_block,pool_bitmap),"exact fixture internal-pool ownership for materialized bitmap");
    for(auto& [index,bytes]:cibs){vi::Checksum(bytes);Check(source.WriteBlock(cp.spaceman.devices[0].cibs.at(index).object.physical_block,bytes),"exact fixture CIB counts");}
    Bytes apsb;Check(source.Read(volume.superblock_object.physical_block*4096,4096,apsb),"fixture volume counts");
    vi::Put(apsb,0xb8,ReadU64LE(apsb,0xb8).value()+1);vi::Put(apsb,0xb0,(std::max)(ReadU64LE(apsb,0xb0).value(),1032ull));vi::Checksum(apsb);
    Check(source.WriteBlock(volume.superblock_object.physical_block,apsb)&&source.Flush(),"fixture clone counters");
    mc::Verify(source,mc::Load(source));std::vector<std::uint64_t> metadata;std::vector<ApplePhysicalExtentRecord> payload;
    Check(LoadAppleSnapshotCheckpointOwners(source,mc::Load(source),metadata,payload,error),"complete authored clone graph: "+error);return source;
}
template<class S> void Payloads(S& source,bool cow=false,const std::filesystem::path& oracle={}){
    const auto cp=mc::Load(source);mc::Verify(source,cp);const auto& volume=cp.volumes.front();std::string error;std::vector<CatRecord> records,references;
    Check(ReadAppleVolumeFileSystemRecords(source,cp.container,volume,records,error),error);
    Check(ReadBtreeLeafRecords(source,4096,volume.extentref_tree->physical_block,true,0,volume.superblock.xid,references,error),error);
    std::vector<ApplePhysicalExtentRecord> graph;Check(ValidateApplePayloadExtentGraph(records,references,4096,cp.container.superblock.block_count,graph,error),"complete relocated clone references: "+error);
    std::ofstream exported;if(!oracle.empty()){exported.open(oracle);exported<<"# inode logical physical bytes cow\n";}
    for(auto id:{1030ull,1031ull}){Bytes actual(32768);std::uint64_t total=0;unsigned pieces=0;
        for(const auto& record:records)if(Kind(record)==8&&Owner(record)==id){AppleFileExtentRecord extent;Check(DecodeAppleFileExtentRecord(record,4096,extent,error),error);Bytes bytes;
            Check(extent.logical_address<32768&&extent.length_bytes<=32768-extent.logical_address&&source.Read(extent.physical_block*4096,static_cast<std::size_t>(extent.length_bytes),bytes),"actual relocated extent bounds/read");
            std::copy(bytes.begin(),bytes.end(),actual.begin()+extent.logical_address);total+=extent.length_bytes;++pieces;
            if(exported)exported<<id<<' '<<extent.logical_address<<' '<<extent.physical_block*4096<<' '<<extent.length_bytes<<' '<<cow<<'\n';}
        auto expected=Pattern();if(cow&&id==1030)std::fill_n(expected.begin(),4096,std::byte{0x35});
        Check(total==32768&&pieces>=4&&actual==expected,"every logical byte of both fragmented clone streams is exact");}
    if(!cow)for(const auto& extent:graph)Check(extent.reference_count==2,"every shared block retains two canonical references");
    if(exported)Check(exported.good(),"bounded raw-range oracle exported");
}
void OrdinaryCow(Target& source){const auto cp=mc::Load(source);AppleVolumeTransactionRequest r;r.volume_object_id=cp.volumes.front().superblock.object_id;r.required_checkpoint_xids={cp.container.superblock.xid};std::string error;
    Check(ReadAppleVolumeFileSystemRecords(source,cp.container,cp.volumes.front(),r.filesystem_records,error),error);unsigned removed=0;
    std::erase_if(r.filesystem_records,[&](const auto& record){if(Kind(record)!=8||Owner(record)!=1030||ReadU64LE(record.key,8)!=0)return false;AppleFileExtentRecord e;
        Check(DecodeAppleFileExtentRecord(record,4096,e,error)&&e.length_bytes==4096,"split crossing extent has exact one-block retained prefix");r.released_data_blocks.push_back({e.physical_block,1});++removed;return true;});
    Check(removed==1,"one affected source mapping");r.data_writes.push_back({1030,0,0,Bytes(4096,std::byte{0x35})});AppleVolumeTransactionPlan plan;
    Check(PlanAppleVolumeTransaction(source,cp,r,plan,error),"ordinary shared-block COW after resize: "+error);Check(ExecuteAppleCheckpointPublication(source,plan.commit.publication,error),error);Payloads(source,true);
}
VolumeImageRequest RequestForSource(const mc::SparseStore& source,const std::filesystem::path& dir){VolumeImageRequest r;const auto cp=mc::Load(source);
    r.image=dir/"image.apfs";r.journal_directory=dir/"keeper";r.operation=VolumeImageOperation::Shrink;r.expected_bytes=source.SizeBytes();r.target_bytes=Boundary*4096;
    r.container_uuid=cp.container.superblock.uuid_hex;r.volume_uuid=cp.volumes.front().superblock.uuid_hex;r.volume_oid=cp.volumes.front().superblock.object_id;r.checkpoint_xid=cp.container.superblock.xid;r.sibling_wals={{r.volume_oid,r.journal_directory/"original.wal"}};return r;}
void CompressedJournal(const std::filesystem::path& path){std::filesystem::create_directories(path);const auto h=CreateFileW(FixtureIoPath(path).c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,nullptr);
    Check(h!=INVALID_HANDLE_VALUE,"owned private keeper directory");USHORT format=COMPRESSION_FORMAT_DEFAULT;DWORD returned=0;const auto ok=DeviceIoControl(h,FSCTL_SET_COMPRESSION,&format,sizeof(format),nullptr,0,&returned,nullptr);CloseHandle(h);Check(ok!=FALSE,"compress new private journals only");}
void Cases(){auto source=SharedSource();auto r=RequestForSource(source,root/"memory");const auto inventory=vi::InspectResizeRelocationSource(source,r);
    Check(std::count_if(inventory.blocks.begin(),inventory.blocks.end(),[](const auto& b){return b.Has(vi::ResizeTailRole::Payload);})==4&&!inventory.unknown_blocks,"four unique tail payload blocks despite two clone references");
    const auto plan=vi::BuildResizeRelocationPublication(source,r);auto post=mc::Publish(source,plan);post.block_count=Boundary;Payloads(post);
    auto bad=source;const auto cp=mc::Load(bad);std::vector<CatRecord> records;std::string error;Check(ReadBtreeLeafRecords(bad,4096,cp.volumes.front().extentref_tree->physical_block,true,0,cp.volumes.front().superblock.xid,records,error),error);
    vi::Put(records.front().value,16,1,4);Leaf(bad,*cp.volumes.front().extentref_tree,records,AppleBtreeKeyOrder::PhysicalExtent);const auto before=bad.blocks;bool refused=false;
    try{(void)vi::BuildResizeRelocationPublication(bad,r);}catch(const std::exception&){refused=true;}Check(refused&&bad.blocks==before,"wrong shared refcount refuses without a partial publication");
    for(unsigned mode=0;mode<3;++mode){Check(std::filesystem::space(root).available>154ull*1024*1024,"shared reserve before next bounded sparse carrier");
        const auto dir=root/("case-"+std::to_string(mode));std::filesystem::create_directories(dir);auto request=RequestForSource(source,dir);CompressedJournal(request.journal_directory);mc::SparseFile(request.image,source);
        const auto original=Digests(request.image);auto prepared=PrepareVolumeResize(request);Check(prepared.outcome==VolumeImageOutcome::Prepared,"fragmented shared-tail keeper prepares: "+prepared.error);
        Check(Digests(request.image)==original,"preparation preserves every source byte");
        if(mode==0){Check(CancelVolumeResize(request,prepared.token).outcome==VolumeImageOutcome::Cancelled&&Digests(request.image)==original,"cancel preserves original clone graph and bytes");prepared=PrepareVolumeResize(request);Check(prepared.outcome==VolumeImageOutcome::Prepared,prepared.error);}
        if(mode==2){Change(request,Boundary-62,[](auto& bytes){bytes[23]^=std::byte{1};});const auto damaged=Digests(request.image);
            Check(ApplyVolumeResize(request,prepared.token).outcome==VolumeImageOutcome::Refused&&Digests(request.image)==damaged,"stale retained fragment refuses every target write");continue;}
        bool hit=false;const auto applied=ApplyVolumeResize(request,prepared.token,[&](auto stage){if(mode==1&&stage=="before-image-anchor"){hit=true;return false;}return true;});
        Check(applied.outcome==(mode?VolumeImageOutcome::RecoveryRequired:VolumeImageOutcome::Committed),"actual fragmented clone relocation result: "+applied.error);
        if(mode){Check(hit,"accepted post-checkpoint/pre-anchor cut reached");Check(RecoverVolumeResize(request).outcome==VolumeImageOutcome::Committed,"fresh keeper forward recovery");}
        {Target target(request.image);Payloads(target,false,dir/"ranges-before-cow.txt");auto history=AcquireVolumeKeeperHistory(prepared.source_identity,target,request.journal_directory,{});OrdinaryCow(target);Payloads(target,true,dir/"ranges-after-cow.txt");}
        Check(RecoverVolumeResize(request).outcome==VolumeImageOutcome::Committed&&InspectVolumeKeeperImage(request.image,0,request.journal_directory).admitted,"completed history admits later ordinary COW/reopen");
    }
    Pass("zero-zone crossing fragmented shared payload relocation refcounts cancel stale source cut recovery and ordinary COW");
}
void Reader(const std::filesystem::path& image){const auto observed=ObserveVolumeManagement({image,0});Check(observed.complete&&!observed.volumes.empty(),"fresh native observation");std::string error;
    auto device=BlockDevice::OpenStableReadOnlyImage(image.wstring(),error);Check(!!device,"fresh read-only file authority");NativeApfsVolumeProjection view;std::wstring detail;
    Check(NativeApfsReader::TryLoadVolumeProjection(*device,observed.volumes.front().oid,view,detail),"fresh native projection");
    for(auto id:{1030ull,1031ull}){Bytes actual(32768);std::uint64_t total=0;Check(view.read_extents_by_inode.contains(id),"native clone inode projection");
        for(const auto& extent:view.read_extents_by_inode.at(id)){Bytes bytes;Check(extent.logical_offset<32768&&extent.bytes<=32768-extent.logical_offset&&device->Read(extent.physical_address,static_cast<std::size_t>(extent.bytes),bytes),"native projected extent read");
            std::copy(bytes.begin(),bytes.end(),actual.begin()+extent.logical_offset);total+=extent.bytes;}
        auto expected=Pattern();if(id==1030)std::fill_n(expected.begin(),4096,std::byte{0x35});Check(total==32768&&actual==expected,"fresh native complete file oracle");}
    Check(!device->HasWriteHandle()&&device->RevalidateStableReadOnlyImage(),"fresh reader retains read-only exact authority");
}
}
int wmain(int argc,wchar_t** argv){try{Check(argc==2||argc==3,"private root or reader image");if(argc==3){Check(std::wstring_view(argv[1])==L"--reader","known reader mode");Reader(argv[2]);}
    else{root=argv[1];Check(root.is_absolute()&&!std::filesystem::exists(root),"fresh private root");std::filesystem::create_directories(root);Cases();}
    std::cout<<"PASS groups="<<groups<<" checks="<<checks<<'\n';return 0;
}catch(const std::exception& e){std::cerr<<"FAIL checks="<<checks<<' '<<e.what()<<'\n';return 1;}}
