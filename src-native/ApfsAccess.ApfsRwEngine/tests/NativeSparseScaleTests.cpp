#define APFS_RELOCATION_KEEPER_FIXTURE_ONLY
#include "VolumeResizeRelocationKeeperTests.cpp"
#undef APFS_RELOCATION_KEEPER_FIXTURE_ONLY
#include "NativeSparseV2.h"
#include "MetadataStore.h"
#include "NativeApfsReader.h"
#include "ApfsExtendedRecordCodec.h"

namespace {
using Store=MetadataStore;
using Journal=TransactionManager;
using Record=apfsaccess::catalog::BtreeRecord;
constexpr std::uint64_t PayloadFirst=8192,PayloadBlocks=10240,PayloadBytes=PayloadBlocks*4096;
constexpr std::uint64_t FileBytes=PayloadBytes-37;
struct IoCensus {
    bool active=false;
    std::uint64_t reads=0,bytes=0,payload_bytes=0,probe_bytes=0,unrelated_bytes=0,writes=0,write_bytes=0;
    std::set<std::uint64_t> allowed,seen;
    std::vector<ApplePhysicalExtentRecord> payload;
} io;
std::vector<NativeSparseAllocatedRange> zeros;
std::uint64_t Kind(const Record& r){return ReadU64LE(r.key,0).value()>>60;}
std::uint64_t Id(const Record& r){return ReadU64LE(r.key,0).value()&0x0fffffffffffffffULL;}
Bytes PatternAt(std::uint64_t offset,std::size_t size){Bytes bytes(size);
    for(std::size_t i=0;i<size;++i)bytes[i]=std::byte(((offset+i)*13+((offset+i)/4096)*47)%251);return bytes;}
template<class S> void WriteLeaf(S& source,const AppleObjectLocation& location,std::vector<Record> records,AppleBtreeKeyOrder order){
    std::string error;Check(SortAppleBtreeRecords(records,order,error),error);AppleBtreeOptions o;
    o.block_size=4096;o.root_object_id=location.object_id;o.root_physical_block=location.physical_block;o.xid=location.xid;
    o.subtype=location.subtype;o.storage_type=location.type&kObjectStorageTypeMask;o.key_order=order;o.max_nodes=1;
    o.tree_flags=o.storage_type==kObjectPhysical?kAppleBtreePhysical:0;AppleSerializedBtree tree;
    Check(SerializeAppleBtree(records,o,tree,error)&&tree.objects.size()==1,"canonical scale fixture leaf: "+error);
    Check(source.WriteBlock(location.physical_block,tree.objects.front().bytes),"bounded scale fixture metadata write");
}
mc::SparseStore ScaleSource(){
    auto source=Source();auto request=Request(root,VolumeImageOperation::Format,Fixture());request.expected_bytes=request.target_bytes=source.SizeBytes();
    auto plan=vi::BuildFormatPublication(source,request,mc::Load(source));vi::FinishFormatSource(source,request,plan);source=mc::Publish(std::move(source),plan);
    const auto cp=mc::Load(source);const auto& v=cp.volumes.front();std::string error;std::vector<Record> fs;
    Check(ReadAppleVolumeFileSystemRecords(source,cp.container,v,fs,error),error);Record encoded;
    for(auto id:{1030ull,1031ull}){
        AppleInodeRecord inode;inode.object_id=inode.private_id=id;inode.parent_id=2;inode.mode=0100644;inode.children_or_links=1;inode.uncompressed_size=FileBytes;
        AppleExtendedField stream{8,0,Bytes(40)};vi::Put(stream.data,0,FileBytes);vi::Put(stream.data,8,PayloadBytes);inode.extended_fields.push_back(stream);
        Check(EncodeAppleInodeRecord(inode,encoded,error),error);fs.push_back(encoded);
        AppleDirectoryRecord entry{2,id,0,8,id==1030?"scale-source.bin":"scale-clone.bin"};
        Check(EncodeAppleDirectoryRecord(entry,ApfsNamePolicy::FromIncompatibleFeatures(v.superblock.incompatible_features),encoded,error),error);fs.push_back(encoded);
        Check(EncodeAppleDataStreamIdRecord({id,1},encoded,error),error);fs.push_back(encoded);
        Check(EncodeAppleFileExtentRecord({id,0,PayloadBytes,PayloadFirst,0,4096},encoded,error),error);fs.push_back(encoded);
    }
    for(auto& record:fs)if(Kind(record)==3&&Id(record)==2){AppleInodeRecord parent;Check(ApfsExtendedRecordCodec::DecodeInode(record,parent,error),error);parent.children_or_links+=2;Check(EncodeAppleInodeRecord(parent,record,error),error);}
    WriteLeaf(source,v.root_tree,fs,AppleBtreeKeyOrder::FileSystemHashedDirectory);
    Check(v.extentref_tree.has_value(),"scale fixture physical references");
    Check(EncodeApplePhysicalExtentRecord({PayloadFirst,PayloadBlocks,kApplePhysicalExtentKindNew,1030,2},encoded,error),error);
    WriteLeaf(source,*v.extentref_tree,{encoded},AppleBtreeKeyOrder::PhysicalExtent);
    const auto& chunk=cp.spaceman.chunks.front();Check(PayloadFirst+PayloadBlocks<=chunk.block_count&&chunk.bitmap_block,"bounded scale payload fits canonical first chunk");
    auto bitmap=chunk.allocation_bitmap;
    for(std::uint64_t i=0;i<PayloadBlocks;++i){Check(!vi::Bit(bitmap,PayloadFirst+i),"scale payload claims only free blocks");vi::SetBit(bitmap,PayloadFirst+i,true);
        Check(source.WriteBlock(PayloadFirst+i,PatternAt(i*4096,4096)),"bounded patterned payload authoring");}
    Check(source.WriteBlock(chunk.bitmap_block,bitmap),"exact scale allocation bitmap");
    auto cib=cp.spaceman.devices[0].cibs.at(chunk.cib_index).bytes;vi::Put(cib,0x28+chunk.index_in_cib*32+20,chunk.free_count-PayloadBlocks,4);vi::Checksum(cib);
    Check(source.WriteBlock(cp.spaceman.devices[0].cibs.at(chunk.cib_index).object.physical_block,cib),"exact scale CIB");
    auto sm=cp.spaceman.bytes;vi::Put(sm,0x48,cp.spaceman.devices[0].free_count-PayloadBlocks);vi::Checksum(sm);Check(source.WriteBlock(cp.spaceman.object.physical_block,sm),"exact scale spaceman count");
    Bytes apsb;Check(source.Read(v.superblock_object.physical_block*4096,4096,apsb),"scale volume accounting");
    for(auto at:{0x58u,0xe0u})vi::Put(apsb,at,ReadU64LE(apsb,at).value()+PayloadBlocks);
    vi::Put(apsb,0xb8,ReadU64LE(apsb,0xb8).value()+2);vi::Put(apsb,0xb0,(std::max)(ReadU64LE(apsb,0xb0).value(),1032ull));vi::Checksum(apsb);
    Check(source.WriteBlock(v.superblock_object.physical_block,apsb),"scale file accounting");mc::Verify(source,mc::Load(source));return source;
}
class DeviceSource final:public RandomAccessSource {
public:explicit DeviceSource(const BlockDevice& device):device_(device){}
    std::uint64_t SizeBytes()const override{return device_.GetGeometry().total_bytes;}
    bool Read(std::uint64_t at,std::size_t n,Bytes& bytes)const override{
        const auto first=at/4096*4096,last=(at+n+4095)/4096*4096;Bytes whole;
        if(at>SizeBytes()||n>SizeBytes()-at||!device_.ReadForVerification(first,static_cast<std::size_t>(last-first),whole))return false;
        bytes.assign(whole.begin()+at-first,whole.begin()+at-first+n);return true;}
private:const BlockDevice& device_;
};
struct Owner {
    Store::VolumeContext context;std::shared_ptr<BlockDevice> device;std::unique_ptr<Store> store;std::unique_ptr<Journal> journal;
    Owner(){context.device_path=std::filesystem::absolute(root/"scale.apfs").wstring();context.allow_legacy_scaffold_for_fixtures=false;
        std::string error;device=BlockDevice::OpenExclusiveManagementImage(context.device_path,0,error);Check(!!device,"held scale image: "+error);
        DeviceSource source(*device);const auto cp=mc::Load(source);context.volume_object_id=cp.volumes.front().superblock.object_id;
        store=std::make_unique<Store>(context,device);Check(store->PrepareNativeWritePath(),"canonical scale store");journal=std::make_unique<Journal>(L"Strict");
        const auto hex=cp.container.superblock.uuid_hex;const auto identity=L"apfs-vol:"+std::wstring(hex.begin(),hex.end())+L":"+std::to_wstring(context.volume_object_id);
        const auto wal=std::filesystem::absolute(root/"original.wal");Check(journal->OpenStartupJournal(wal.wstring(),identity,error),"open exact scale original: "+error);
        if(!std::filesystem::exists(wal))Check(journal->MaterializeAbsentStartupJournal(error),error);Check(journal->EnrollCanonicalJournalIdentity(identity),"canonical scale original identity");}
    NativeSparseState State(){DeviceSource source(*device);const auto cp=mc::Load(source);NativeSparseState state;std::string error;
        Check(ReadNativeSparseStateV2(source,cp,context.volume_object_id,1030,state,error),"complete scaled state: "+error);return state;}
    NativeSparseOpenEntry Entry(){const auto inode=store->LookupCommittedInodeByPath(L"\\scale-source.bin");Check(!!inode,"actual scale open entry");return {1030,inode->xid,2,0,"scale-source.bin"};}
};
NativeSparseRequest Set(bool sparse){return {NativeSparseAction::SetSparse,sparse,0,0,123456789};}
NativeSparseRequest Zero(std::uint64_t at,std::uint64_t n){return {NativeSparseAction::ZeroRange,false,at,n,123456790};}
void StartIo(Owner& owner,const NativeSparseRequest& request){
    DeviceSource source(*owner.device);const auto cp=mc::Load(source);NativeSparseState state;AppleVolumeTransactionPlan plan;std::vector<NativeSparseSourceBlock> reads;std::string error;
    Check(PlanNativeSparseTransactionV2(source,cp,owner.context.volume_object_id,1030,request,state,plan,reads,error),"independent expected canonical read set: "+error);
    io={};io.payload=state.payload;for(const auto& read:reads)io.allowed.insert(read.physical_block);io.active=true;
}
void StopIo(const char* phase){io.active=false;
    std::cout<<"READ_BUDGET "<<phase<<" reads="<<io.reads<<" bytes="<<io.bytes<<" payload="<<io.payload_bytes<<" gpt_probe="<<io.probe_bytes<<" unrelated="<<io.unrelated_bytes<<" boundary_blocks="<<io.seen.size()<<" writes="<<io.writes<<'\n';
    if(io.unrelated_bytes){std::cout<<"READ_BLOCKS allowed=";for(const auto block:io.allowed)std::cout<<block<<',';
        std::cout<<" observed=";for(const auto block:io.seen)std::cout<<block<<',';std::cout<<'\n';}
    Check(io.reads>0&&io.unrelated_bytes==0&&io.probe_bytes<=4096&&io.seen.size()<=2&&io.bytes<(16ull<<20),"bounded actual OS reads exclude unrelated old payload apart from one fixed GPT probe");}
Store::SparseAcceptance Accept(Owner& o,const NativeSparseRequest& request,bool v2=true,bool required=true){std::string error;Store::SparseReceipt receipt;auto outcome=Store::SparseAcceptance::Refused;
    const bool borrowed=o.store->WithNativeSparseSession(o.Entry(),[&](const auto& session,std::string& detail){outcome=v2?o.store->AcceptNativeSparseV2(*o.journal,session,request,receipt,detail):o.store->AcceptNativeSparse(*o.journal,session,request,receipt,detail);return outcome==Store::SparseAcceptance::Accepted;},error);
    Check(borrowed==(outcome==Store::SparseAcceptance::Accepted),"opaque session outcome matches typed acceptance");
    if(v2&&required)Check(outcome==Store::SparseAcceptance::Accepted,"actual NSP2 accepted: "+error);return outcome;}
Bytes Persistence(){std::ifstream in(root/"original.wal",std::ios::binary|std::ios::ate);const auto n=in.tellg();Check(n>=0&&n<8*1024*1024,"bounded exact original persistence");Bytes bytes(static_cast<std::size_t>(n));in.seekg(0);in.read(reinterpret_cast<char*>(bytes.data()),bytes.size());Check(in.good()||bytes.empty(),"original persistence read");return bytes;}
void VerifyPayload(Owner& o){
    for(auto path:{L"\\scale-source.bin",L"\\scale-clone.bin"})for(std::uint64_t at=0;at<FileBytes;at+=65536){Bytes actual;const auto n=static_cast<std::size_t>((std::min)(65536ull,FileBytes-at));
        Check(o.store->ReadCommittedFileRange(path,at,n,actual),"actual complete scale payload read");auto expected=PatternAt(at,n);
        if(path==std::wstring_view(L"\\scale-source.bin"))for(const auto& zero:zeros){const auto lo=(std::max)(at,zero.offset),hi=(std::min)(at+n,zero.offset+zero.length);if(lo<hi)std::fill(expected.begin()+lo-at,expected.begin()+hi-at,std::byte{});}
        Check(actual==expected,"complete target and clone patterned payload bytes");}
}
void Export(Owner& o){const auto state=o.State();DeviceSource source(*o.device);const auto cp=mc::Load(source);std::vector<Record> fs;std::string error;
    Check(ReadAppleVolumeFileSystemRecords(source,cp.container,cp.volumes.front(),fs,error),error);std::ofstream ranges(root/"ranges.txt"),changes(root/"zeros.txt");
    for(const auto& record:fs)if(Kind(record)==8&&(Id(record)==1030||Id(record)==1031)){AppleFileExtentRecord e;Check(DecodeAppleFileExtentRecord(record,4096,e,error),error);if(e.physical_block)ranges<<Id(record)<<' '<<e.logical_address<<' '<<e.physical_block*4096<<' '<<e.length_bytes<<'\n';}
    for(const auto& zero:zeros)changes<<zero.offset<<' '<<zero.length<<'\n';Check(ranges.good()&&changes.good(),"bounded independent raw oracle inputs");
}
void Operation(const NativeSparseRequest& request,const std::string& cut={},bool torn=false){
    std::vector<ApplePhysicalExtentRecord> original_payload;
    {Owner o;StartIo(o,request);original_payload=io.payload;Accept(o,request);std::string error;
        if(cut!="accepted-only"){
            if(!cut.empty())o.store->SetCommitStageHook([&](auto stage){return stage!=cut;});
            const auto outcome=o.store->PublishOrRecoverNativeSparse(*o.journal,error);
            Check(outcome==(cut.empty()?Store::SparsePublication::Published:Store::SparsePublication::RecoveryRequired),"scaled publication/cut: "+error);}
        StopIo(cut.empty()?"publish":cut.c_str());
        if(torn){std::vector<Journal::AcceptedTransaction> debt;Check(o.journal->LoadAcceptedTransactionsSinceCleanup(debt,&error)&&debt.size()==1,"exact retained NSP2 original");
            NativeSparseV2Proof proof;Check(DecodeNativeSparseV2(debt.front().mutations.front().inline_payload,proof),"strict NSP2 body");
            DeviceSource source(*o.device);const auto cp=mc::Load(source);NativeSparseState before;AppleVolumeTransactionPlan plan;std::vector<NativeSparseSourceBlock> reads;
            Check(PlanNativeSparseTransactionV2(source,cp,proof.volume_oid,proof.inode,request,before,plan,reads,error),error);
            auto bytes=plan.commit.publication.before_superblock_writes.front().bytes;bytes.resize(4096);bytes[29]^=std::byte{0x51};
            Check(o.device->Write(plan.commit.publication.before_superblock_writes.front().physical_block*4096,bytes)&&o.device->Flush(),"genuine torn planned COW destination");}
    }
    if(!cut.empty()){Owner fresh;std::vector<Journal::AcceptedTransaction> debt;std::string error;Check(fresh.journal->LoadAcceptedTransactionsSinceCleanup(debt,&error)&&debt.size()==1,"fresh original debt");
        NativeSparseV2Proof proof;Check(DecodeNativeSparseV2(debt.front().mutations.front().inline_payload,proof),"fresh NSP2 decode");
        io={};io.payload=original_payload;for(const auto& b:proof.source_blocks)io.allowed.insert(b.physical_block);io.active=true;
        const auto result=fresh.store->PublishOrRecoverNativeSparse(*fresh.journal,error);StopIo("fresh-recover");
        Check(result==Store::SparsePublication::Published||result==Store::SparsePublication::AlreadyPublished,"fresh exact scaled recovery: "+error);
        Check(fresh.journal->Watermarks().accepted_sequence==fresh.journal->Watermarks().cleanup_sequence,"scaled original cleaned only after complete verification");}
    if(request.action==NativeSparseAction::ZeroRange)zeros.push_back({request.offset,request.length});
}
void Init(){Check(!std::filesystem::exists(root),"fresh scale root");Check(std::filesystem::space(root.parent_path()).available>198ull*1024*1024,"150 MiB reserve plus bounded scale carrier/build allowance");
    std::filesystem::create_directories(root);auto source=ScaleSource();Check(source.SizeBytes()>(256ull<<20)&&PayloadBytes>(32ull<<20),"genuine scale dimensions");mc::SparseFile(root/"scale.apfs",source);
    {Owner o;const auto before=o.journal->Watermarks();Check(Accept(o,Set(true),false)==Store::SparseAcceptance::Refused&&o.journal->Watermarks().accepted_sequence==before.accepted_sequence,"NSP1 source-size refusal preserved before acceptance");
        const auto original=Persistence();o.journal->SetJournalMaxBytesForTest(1);StartIo(o,Set(true));
        Check(Accept(o,Set(true),true,false)==Store::SparseAcceptance::Refused,"exact finite original capacity refuses before Begin");StopIo("capacity-refusal");
        Check(!io.writes&&o.journal->CurrentState()==Journal::State::Idle&&o.journal->Watermarks().accepted_sequence==before.accepted_sequence&&Persistence()==original,"capacity refusal preserves original and target calls");}
    Operation(Set(true));
    {Owner o;const auto request=Zero(4096+101,12000);StartIo(o,request);Accept(o,request);StopIo("accepted-before-publication");}
    std::cout<<"PASS accepted NSP2 scale original; fresh process must recover\n";
}
void Resume(){const auto first=Zero(4096+101,12000);
    {Owner fresh;std::vector<Journal::AcceptedTransaction> debt;std::string error;Check(fresh.journal->LoadAcceptedTransactionsSinceCleanup(debt,&error)&&debt.size()==1,"fresh-process accepted original");
        NativeSparseV2Proof proof;Check(DecodeNativeSparseV2(debt.front().mutations.front().inline_payload,proof)&&proof.source_blocks.size()==2&&proof.body_version==3,"body3 original binds exactly two contributing blocks");
        Check(EncodeNativeSparseV2(proof)==debt.front().mutations.front().inline_payload,"body3 whole original roundtrip is byte-exact");
        auto future=proof;future.body_version=4;Check(EncodeNativeSparseV2(future).empty(),"unknown producer policy cannot be encoded");
        auto future_bytes=debt.front().mutations.front().inline_payload;future_bytes[8]=std::byte{4};NativeSparseV2Proof future_proof;
        Check(!DecodeNativeSparseV2(future_bytes,future_proof),"unknown producer policy cannot be decoded");
        NativeSparseProof legacy;Check(!DecodeNativeSparse(debt.front().mutations.front().inline_payload,legacy),"NSP2 cannot reinterpret as NSP1");
        for(unsigned mode=0;mode<6;++mode){auto row=debt.front().mutations.front();
            if(mode==0)row.inline_payload[0]=std::byte{0x4f};if(mode==1)row.inline_payload[8]=std::byte{1};
            if(mode==2)++row.object_id;if(mode==3)++row.parent_object_id;if(mode==4)row.flags=1;if(mode==5)++row.logical_offset;
            Check(!WriteAheadLog::NativeSparseIsConsistent(row),"versioned original/outer authority mismatch refuses");}
        auto duplicate=proof;duplicate.source_blocks.push_back(duplicate.source_blocks.front());Check(EncodeNativeSparseV2(duplicate).empty(),"duplicate contributing census refuses");
        Check(EncodeNativeSparse(proof).empty(),"large NSP2 cannot be emitted as legacy NSP1");
        Bytes original_boundary;const auto boundary=proof.source_blocks.front().physical_block;
        Check(fresh.device->ReadForVerification(boundary*4096,4096,original_boundary),"exact contributing block before fault");
        auto damaged=original_boundary;damaged[23]^=std::byte{0x61};
        Check(fresh.device->Write(boundary*4096,damaged)&&fresh.device->Flush(),"genuine original contributing-source corruption");
        for(const auto& [name,bytes]:{std::pair{"boundary-original.bin",original_boundary},std::pair{"boundary-corrupt.bin",damaged}}){std::ofstream file(root/name,std::ios::binary);file.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());Check(file.good(),"preserve exact source-corruption evidence");}
        const auto original=Persistence();
        {Store refused(fresh.context,fresh.device);Check(refused.PrepareNativeWritePath(),"fresh corrupted-boundary owner still selects original checkpoint");
            io={};io.payload=fresh.State().payload;for(const auto& block:proof.source_blocks)io.allowed.insert(block.physical_block);io.active=true;
            const auto outcome=refused.PublishOrRecoverNativeSparse(*fresh.journal,error);StopIo("corrupt-boundary-refusal");
            Check(outcome==Store::SparsePublication::RecoveryRequired&&!io.writes&&Persistence()==original&&fresh.journal->Watermarks().cleanup_sequence<debt.front().accepted_sequence,"changed contributing source cannot earn target writes or original completion");}
        Bytes retained;Check(fresh.device->ReadForVerification(boundary*4096,4096,retained)&&retained==damaged,"refusal preserves corrupted source exactly");
        Check(fresh.device->Write(boundary*4096,original_boundary)&&fresh.device->Flush(),"restore exact privately authored test boundary for positive control");
        io={};io.payload=fresh.State().payload;for(const auto& block:proof.source_blocks)io.allowed.insert(block.physical_block);io.active=true;
        const auto result=fresh.store->PublishOrRecoverNativeSparse(*fresh.journal,error);StopIo("fresh-process-recover");
        Check(result==Store::SparsePublication::Published,"fresh process publishes exact accepted NSP2: "+error);}
    zeros.push_back({first.offset,first.length});{Owner o;VerifyPayload(o);}
    Operation(Set(false));Operation(Zero(60*4096+101,5*4096));Operation(Set(true));Operation(Zero(FileBytes-100,1000));
    Operation(Zero(100*4096+101,12000),"accepted-only",true);
    Operation(Zero(110*4096+101,12000),"before-apple-checkpoint-switch");
    Operation(Zero(120*4096+101,12000),"before-apple-final-flush");
    {Owner o;VerifyPayload(o);Export(o);std::vector<NativeSparseAllocatedRange> ranges;std::string error;
        Check(o.store->WithNativeSparseSession(o.Entry(),[&](const auto& session,std::string& detail){return o.store->QueryNativeAllocatedRangesV2(session,0,PayloadBytes,32,ranges,detail);},error),"scaled actual allocated range query: "+error);
        Check(ranges==std::vector<NativeSparseAllocatedRange>{{0,101*4096},{102*4096,9*4096},{112*4096,9*4096},{122*4096,FileBytes-122*4096}},"query exactly reflects full-block holes and unaligned logical EOF");
        const auto state=o.State();Check(state.size==FileBytes,"unaligned EOF preserved");std::uint64_t covered=0;unsigned holes=0;
        for(const auto& extent:state.extents){Check(extent.logical_address==covered,"body3 emits complete explicit logical coverage");covered+=extent.length_bytes;if(!extent.physical_block)++holes;}
        Check(covered==PayloadBytes&&holes==3,"three explicit hole extents cover the aligned EOF");
        for(const auto& extent:state.extents)if(extent.logical_address<=FileBytes-1&&FileBytes-1<extent.logical_address+extent.length_bytes){Bytes block;
            Check(o.device->ReadForVerification((extent.physical_block+(FileBytes-1-extent.logical_address)/4096)*4096,4096,block)&&
                std::all_of(block.begin()+FileBytes%4096,block.end(),[](auto b){return b==std::byte{};}),"new COW final-block physical padding is zero");}}
    Pass("NSP2 above 256 MiB image and 32 MiB payload; bounded reads, clone, dense/unsparse, torn and fresh recovery");
}
}
BOOL WINAPI NativeSparseMeasuredReadFile(HANDLE h,LPVOID buffer,DWORD n,LPDWORD got,LPOVERLAPPED overlap){
    if(io.active){++io.reads;io.bytes+=n;if(overlap){const auto start=(std::uint64_t(overlap->OffsetHigh)<<32)|overlap->Offset;
        for(const auto& extent:io.payload){const auto lo=(std::max)(start,extent.physical_block*4096),hi=(std::min)(start+n,(extent.physical_block+extent.block_count)*4096);
            for(auto at=lo;at<hi;){const auto block=at/4096,end=(std::min)(hi,(block+1)*4096);io.payload_bytes+=end-at;
                // Catalog reload probes a 4 KiB-sector GPT header even for a
                // partitionless image. It can coincide with an allocated file.
                if(block==1&&start==4096&&n==4096&&!io.allowed.contains(block)){io.probe_bytes+=end-at;at=end;continue;}
                io.seen.insert(block);if(!io.allowed.contains(block)){
                if(!io.unrelated_bytes){std::array<void*,12> frames{};const auto count=CaptureStackBackTrace(0,static_cast<DWORD>(frames.size()),frames.data(),nullptr);
                    const auto base=reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));std::cout<<"UNRELATED_READ block="<<block<<" stack=";
                    for(unsigned i=0;i<count;++i)std::cout<<std::hex<<(reinterpret_cast<std::uintptr_t>(frames[i])-base)<<',';std::cout<<std::dec<<'\n';}
                io.unrelated_bytes+=end-at;}at=end;}}}}
    return ::ReadFile(h,buffer,n,got,overlap);
}
BOOL WINAPI NativeSparseMeasuredWriteFile(HANDLE h,LPCVOID buffer,DWORD n,LPDWORD wrote,LPOVERLAPPED overlap){if(io.active){++io.writes;io.write_bytes+=n;}return ::WriteFile(h,buffer,n,wrote,overlap);}
int wmain(int argc,wchar_t** argv){try{Check(argc==3,"private scale root and init/recover mode");root=argv[1];Check(root.is_absolute()&&root.wstring().substr(0,3)==L"D:\\","private D scale evidence");
    if(std::wstring_view(argv[2])==L"--init")Init();else{Check(std::wstring_view(argv[2])==L"--recover","known mode");Resume();}
    std::cout<<"PASS groups="<<groups<<" checks="<<checks<<'\n';return 0;
}catch(const std::exception& e){io.active=false;std::cerr<<"FAIL checks="<<checks<<' '<<e.what()<<'\n';return 1;}}
