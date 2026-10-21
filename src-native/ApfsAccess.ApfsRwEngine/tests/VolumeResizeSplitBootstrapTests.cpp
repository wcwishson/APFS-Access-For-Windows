#define APFS_RELOCATION_KEEPER_FIXTURE_ONLY
#include "VolumeResizeRelocationKeeperTests.cpp"
#undef APFS_RELOCATION_KEEPER_FIXTURE_ONLY
#include "ApfsExtendedRecordCodec.h"
#include "NativeApfsReader.h"

namespace {
using Record=apfsaccess::catalog::BtreeRecord;
constexpr std::uint64_t TargetBlocks=3*mc::ChunkBlocks-25;
struct Gap {std::uint64_t first,count;};
template<class S> void Leaf(S& source,const AppleObjectLocation& location,std::vector<Record> records,AppleBtreeKeyOrder order){
    std::string error;Check(SortAppleBtreeRecords(records,order,error),error);AppleBtreeOptions o;
    o.block_size=4096;o.root_object_id=location.object_id;o.root_physical_block=location.physical_block;o.xid=location.xid;
    o.subtype=location.subtype;o.storage_type=location.type&kObjectStorageTypeMask;o.key_order=order;o.max_nodes=1;
    o.tree_flags=o.storage_type==kObjectPhysical?kAppleBtreePhysical:0;AppleSerializedBtree tree;
    Check(SerializeAppleBtree(records,o,tree,error)&&tree.objects.size()==1,"canonical fragmented-bootstrap fixture leaf: "+error);
    Check(source.WriteBlock(location.physical_block,tree.objects.front().bytes),"bounded bootstrap source metadata write");
}
mc::SparseStore Fragmented(bool enough){
    auto source=Source();auto format=Request(root,VolumeImageOperation::Format,Fixture());format.expected_bytes=format.target_bytes=source.SizeBytes();
    auto plan=vi::BuildFormatPublication(source,format,mc::Load(source));vi::FinishFormatSource(source,format,plan);source=mc::Publish(std::move(source),plan);
    const auto cp=mc::Load(source);const auto& v=cp.volumes.front();std::string error;
    const std::array<Gap,5> gaps{{{4096,enough?256ull:255ull},{5000,64},{5200,32},{5300,16},{5400,128}}};
    const auto free=[&](std::uint64_t block){const auto& chunk=cp.spaceman.chunks.at(static_cast<std::size_t>(block/cp.spaceman.blocks_per_chunk));return !chunk.bitmap_block||!vi::Bit(chunk.allocation_bitmap,block-chunk.start_block);};
    for(const auto& gap:gaps)for(auto b=gap.first;b<gap.first+gap.count;++b)Check(free(b),"authored staging gap contains no original owner");
    std::vector<Gap> payload;
    const auto append=[&](std::uint64_t b){if(!payload.empty()&&payload.back().first+payload.back().count==b)++payload.back().count;else payload.push_back({b,1});};
    for(std::uint64_t block=1;block<TargetBlocks;++block){
        if(!free(block)||std::any_of(gaps.begin(),gaps.end(),[&](const auto& g){return block>=g.first&&block-g.first<g.count;}))continue;
        append(block);source.blocks.erase(block);
    }
    const auto tail=TargetBlocks+10;Check(free(tail),"actual allocated tail source initially free");append(tail);source.blocks.erase(tail);
    std::uint64_t allocated=0;std::vector<Record> fs,refs;Record encoded;
    Check(ReadAppleVolumeFileSystemRecords(source,cp.container,v,fs,error),error);
    for(const auto& extent:payload){
        Check(EncodeAppleFileExtentRecord({1030,allocated*4096,extent.count*4096,extent.first,0,4096},encoded,error),error);fs.push_back(encoded);
        Check(EncodeApplePhysicalExtentRecord({extent.first,extent.count,kApplePhysicalExtentKindNew,1030,1},encoded,error),error);refs.push_back(encoded);allocated+=extent.count;
    }
    AppleInodeRecord inode;inode.object_id=inode.private_id=1030;inode.parent_id=2;inode.mode=0100644;inode.children_or_links=1;inode.uncompressed_size=allocated*4096;
    AppleExtendedField stream{8,0,Bytes(40)};vi::Put(stream.data,0,allocated*4096);vi::Put(stream.data,8,allocated*4096);inode.extended_fields.push_back(stream);
    Check(EncodeAppleInodeRecord(inode,encoded,error),error);fs.push_back(encoded);
    Check(EncodeAppleDataStreamIdRecord({1030,1},encoded,error),error);fs.push_back(encoded);
    Check(EncodeAppleDirectoryRecord({2,1030,0,8,"fragmented-bootstrap.bin"},ApfsNamePolicy::FromIncompatibleFeatures(v.superblock.incompatible_features),encoded,error),error);fs.push_back(encoded);
    for(auto& record:fs)if((ReadU64LE(record.key,0).value()>>60)==3&&(ReadU64LE(record.key,0).value()&0x0fffffffffffffffULL)==2){AppleInodeRecord parent;
        Check(ApfsExtendedRecordCodec::DecodeInode(record,parent,error),error);++parent.children_or_links;Check(EncodeAppleInodeRecord(parent,record,error),error);}
    Leaf(source,v.root_tree,std::move(fs),AppleBtreeKeyOrder::FileSystemHashedDirectory);Check(v.extentref_tree.has_value(),"complete physical reference tree");Leaf(source,*v.extentref_tree,std::move(refs),AppleBtreeKeyOrder::PhysicalExtent);
    std::map<std::size_t,Bytes> bitmaps,cibs;std::map<std::size_t,std::uint64_t> addresses;
    Check(cp.spaceman.internal_pool.active_bitmaps.size()==1,"one original internal-pool bitmap");auto ip_bitmap=cp.spaceman.internal_pool.active_bitmaps.front().bytes;
    for(const auto& extent:payload)for(std::uint64_t b=extent.first;b<extent.first+extent.count;++b){const auto index=static_cast<std::size_t>(b/cp.spaceman.blocks_per_chunk);const auto& chunk=cp.spaceman.chunks.at(index);
        auto found=bitmaps.find(index);if(found==bitmaps.end()){
            auto bitmap=chunk.allocation_bitmap;auto address=chunk.bitmap_block;
            if(!address){bitmap.assign(4096,std::byte{});for(auto bit=chunk.block_count;bit<cp.spaceman.blocks_per_chunk;++bit)vi::SetBit(bitmap,bit,true);
                std::uint64_t slot=0;while(slot<cp.spaceman.internal_pool.block_count&&vi::Bit(ip_bitmap,slot))++slot;Check(slot<cp.spaceman.internal_pool.block_count,"real unused pool slot for authored chunk bitmap");
                vi::SetBit(ip_bitmap,slot,true);address=cp.spaceman.internal_pool.base_block+slot;}
            addresses[index]=address;found=bitmaps.emplace(index,std::move(bitmap)).first;
        }
        Check(!vi::Bit(found->second,b-chunk.start_block),"dense zero owner claims only original free bitmap bits");vi::SetBit(found->second,b-chunk.start_block,true);
    }
    for(const auto& [index,bitmap]:bitmaps){const auto& chunk=cp.spaceman.chunks.at(index);std::uint64_t available=0;for(std::uint64_t b=0;b<chunk.block_count;++b)if(!vi::Bit(bitmap,b))++available;
        auto [cib,_]=cibs.try_emplace(chunk.cib_index,cp.spaceman.devices[0].cibs.at(chunk.cib_index).bytes);vi::Put(cib->second,0x28+chunk.index_in_cib*32+20,available,4);vi::Put(cib->second,0x28+chunk.index_in_cib*32+24,addresses.at(index));
        Check(source.WriteBlock(addresses.at(index),bitmap),"complete authored chunk bitmap");}
    for(auto& [index,cib]:cibs){vi::Checksum(cib);Check(source.WriteBlock(cp.spaceman.devices[0].cibs.at(index).object.physical_block,cib),"complete authored CIB");}
    Check(source.WriteBlock(cp.spaceman.internal_pool.active_bitmaps.front().physical_block,ip_bitmap),"exact authored pool usage");
    auto sm=cp.spaceman.bytes;vi::Put(sm,0x48,cp.spaceman.devices[0].free_count-allocated);vi::Checksum(sm);Check(source.WriteBlock(cp.spaceman.object.physical_block,sm),"exact authored main free count");
    Bytes apsb;Check(source.Read(v.superblock_object.physical_block*4096,4096,apsb),"original volume accounting");for(auto at:{0x58u,0xe0u})vi::Put(apsb,at,ReadU64LE(apsb,at).value()+allocated);
    vi::Put(apsb,0xb8,ReadU64LE(apsb,0xb8).value()+1);vi::Put(apsb,0xb0,(std::max)(ReadU64LE(apsb,0xb0).value(),1031ull));vi::Checksum(apsb);Check(source.WriteBlock(v.superblock_object.physical_block,apsb),"exact authored file allocation charge");
    mc::Verify(source,mc::Load(source));return source;
}
VolumeImageRequest Resize(const mc::SparseStore& source,const std::filesystem::path& dir){const auto cp=mc::Load(source);VolumeImageRequest r;
    r.image=dir/"image.apfs";r.journal_directory=dir/"keeper";r.expected_bytes=source.SizeBytes();r.target_bytes=TargetBlocks*4096;r.operation=VolumeImageOperation::Shrink;
    r.container_uuid=cp.container.superblock.uuid_hex;r.volume_oid=cp.volumes.front().superblock.object_id;r.volume_uuid=cp.volumes.front().superblock.uuid_hex;r.checkpoint_xid=cp.container.superblock.xid;r.sibling_wals={{r.volume_oid,r.journal_directory/"original.wal"}};return r;}
template<class S> void Verify(S& source,const std::filesystem::path& ranges={}){const auto cp=mc::Load(source);mc::Verify(source,cp);std::string error;std::vector<Record> fs;
    Check(ReadAppleVolumeFileSystemRecords(source,cp.container,cp.volumes.front(),fs,error),error);std::ofstream out;if(!ranges.empty())out.open(ranges);std::uint64_t end=0;unsigned extents=0;
    for(const auto& record:fs)if((ReadU64LE(record.key,0).value()>>60)==8&&(ReadU64LE(record.key,0).value()&0x0fffffffffffffffULL)==1030){AppleFileExtentRecord e;Check(DecodeAppleFileExtentRecord(record,4096,e,error),error);
        Check(e.logical_address==end&&e.physical_block<cp.container.superblock.block_count&&e.length_bytes/4096<=cp.container.superblock.block_count-e.physical_block,"complete dense logical graph stays in new geometry");end+=e.length_bytes;++extents;
        if(out)out<<e.logical_address<<' '<<e.physical_block*4096<<' '<<e.length_bytes<<'\n';}
    Check(end>(256ull<<20)&&extents>5,"large real dense owner and fragmented free staging");if(out)Check(out.good(),"independent dense-zero range oracle");}
void OrdinaryCow(Target& source){const auto cp=mc::Load(source);AppleVolumeTransactionRequest request;std::string error;
    request.volume_object_id=cp.volumes.front().superblock.object_id;request.required_checkpoint_xids={cp.container.superblock.xid};
    Check(ReadAppleVolumeFileSystemRecords(source,cp.container,cp.volumes.front(),request.filesystem_records,error),error);unsigned found=0;
    for(auto& record:request.filesystem_records)if((ReadU64LE(record.key,0).value()>>60)==8&&
        (ReadU64LE(record.key,0).value()&0x0fffffffffffffffULL)==1030&&ReadU64LE(record.key,8)==0){AppleFileExtentRecord extent;
        Check(DecodeAppleFileExtentRecord(record,4096,extent,error)&&extent.length_bytes>4096,"dense retained prefix can split for ordinary COW");
        request.released_data_blocks.push_back({extent.physical_block,1});extent.logical_address+=4096;extent.physical_block++;extent.length_bytes-=4096;
        Check(EncodeAppleFileExtentRecord(extent,record,error),error);++found;}
    Check(found==1,"exactly one affected retained dense prefix");request.data_writes.push_back({1030,0,0,Bytes(4096,std::byte{0x35})});AppleVolumeTransactionPlan plan;
    Check(PlanAppleVolumeTransaction(source,cp,request,plan,error),"ordinary dense COW after split bootstrap: "+error);
    Check(ExecuteAppleCheckpointPublication(source,plan.commit.publication,error),"ordinary dense publication: "+error);Verify(source);
}
void CompressNewJournal(const std::filesystem::path& path){std::filesystem::create_directories(path);
    const auto h=CreateFileW(FixtureIoPath(path).c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,nullptr);
    Check(h!=INVALID_HANDLE_VALUE,"private new keeper directory");USHORT format=COMPRESSION_FORMAT_DEFAULT;DWORD returned=0;
    const auto ok=DeviceIoControl(h,FSCTL_SET_COMPRESSION,&format,sizeof(format),nullptr,0,&returned,nullptr);CloseHandle(h);Check(ok!=FALSE,"compress only newly created owned journal directory");}
void Cases(){
    auto source=Fragmented(true);const auto request=Resize(source,root/"memory");
    const auto plan=vi::BuildResizeRelocationPublication(source,request);const auto after=mc::Load(mc::Publish(source,plan));
    Check(after.container.superblock.xp_data_base_block!=after.container.superblock.xp_desc_base_block+32,"genuine split checkpoint-ring placement");
    std::vector<std::uint64_t> metadata;std::vector<ApplePhysicalExtentRecord> owners;std::string error;
    Check(LoadAppleSnapshotCheckpointOwners(source,mc::Load(source),metadata,owners,error),"complete original dense owner census: "+error);
    const auto excludes=[&](const auto& write){const auto end=write.physical_block+write.bytes.size()/4096;
        return std::none_of(owners.begin(),owners.end(),[&](const auto& e){return write.physical_block<e.physical_block+e.block_count&&e.physical_block<end;});};
    Check(excludes(plan.publication.superblock_write)&&std::all_of(plan.publication.before_superblock_writes.begin(),plan.publication.before_superblock_writes.end(),excludes),"all split staging writes exclude every old payload owner");
    auto bad=Fragmented(false);auto no=Resize(bad,root/"negative-memory");const auto bytes=bad.blocks;bool refused=false;
    try{(void)vi::BuildResizeRelocationPublication(bad,no);}catch(const std::exception&){refused=true;}Check(refused&&bad.blocks==bytes,"missing intrinsic 256-block data ring refuses without source mutation");
    for(unsigned mode=0;mode<2;++mode){Check(std::filesystem::space(root).available>154ull*1024*1024,"shared reserve before bounded sparse split fixture");const auto dir=root/("case-"+std::to_string(mode));std::filesystem::create_directories(dir);
        auto r=Resize(source,dir);CompressNewJournal(r.journal_directory);mc::SparseFile(r.image,source);const auto original=Digests(r.image);const auto prepared=PrepareVolumeResize(r);Check(prepared.outcome==VolumeImageOutcome::Prepared,"split bootstrap prepare: "+prepared.error);
        Check(Digests(r.image)==original,"split prepare preserves all original bytes");bool hit=false;
        const auto result=ApplyVolumeResize(r,prepared.token,[&](auto stage){if(mode&&stage=="before-image-anchor"){hit=true;return false;}return true;});
        Check(result.outcome==(mode?VolumeImageOutcome::RecoveryRequired:VolumeImageOutcome::Committed),"split bootstrap publication: "+result.error);
        if(mode)Check(hit&&RecoverVolumeResize(r).outcome==VolumeImageOutcome::Committed,"fresh split-bootstrap forward recovery");
        {Target target(r.image);Verify(target);auto history=AcquireVolumeKeeperHistory(prepared.source_identity,target,r.journal_directory,{});
            OrdinaryCow(target);Verify(target,dir/"dense-ranges.txt");}
        Check(RecoverVolumeResize(r).outcome==VolumeImageOutcome::Committed&&InspectVolumeKeeperImage(r.image,0,r.journal_directory).admitted,
            "completed split evidence admits later ordinary COW/reopen");
    }
    Pass("independently contiguous bootstrap regions preserve canonical dense owner and allocated tail");
}
void Reader(const std::filesystem::path& image){const auto observed=ObserveVolumeManagement({image,0});Check(observed.complete&&!observed.volumes.empty(),"fresh native geometry observation");std::string error;
    auto device=BlockDevice::OpenStableReadOnlyImage(image.wstring(),error);Check(!!device,"fresh read-only held split image");NativeApfsVolumeProjection view;std::wstring detail;
    Check(NativeApfsReader::TryLoadVolumeProjection(*device,observed.volumes.front().oid,view,detail),"fresh native split projection");
    Check(view.read_extents_by_inode.contains(1030),"fresh native dense inode");std::uint64_t end=0;
    for(const auto& extent:view.read_extents_by_inode.at(1030)){Check(extent.logical_offset==end,"fresh native dense graph has no gap");
        for(std::uint64_t at=0;at<extent.bytes;at+=65536){Bytes bytes;const auto n=static_cast<std::size_t>((std::min)(65536ull,extent.bytes-at));
            Check(device->Read(extent.physical_address+at,n,bytes)&&bytes.size()==n,"fresh native bounded full-file read");
            for(std::size_t i=0;i<n;++i)if(bytes[i]!=(extent.logical_offset+at+i<4096?std::byte{0x35}:std::byte{}))throw std::runtime_error("fresh native dense payload mismatch");}
        end+=extent.bytes;}
    Check(end>(256ull<<20)&&!device->HasWriteHandle()&&device->RevalidateStableReadOnlyImage(),"fresh native complete large dense payload and exact read-only identity");
}
}
int wmain(int argc,wchar_t** argv){try{Check(argc==2||argc==3,"private split-bootstrap root or reader");if(argc==3){Check(std::wstring_view(argv[1])==L"--reader","known reader mode");Reader(argv[2]);}
    else{root=argv[1];Check(root.is_absolute()&&!std::filesystem::exists(root),"fresh private evidence");std::filesystem::create_directories(root);Cases();}
    std::cout<<"PASS groups="<<groups<<" checks="<<checks<<'\n';return 0;}catch(const std::exception& e){std::cerr<<"FAIL checks="<<checks<<' '<<e.what()<<'\n';return 1;}}
