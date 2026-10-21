#include "FusionImageRuntime.h"
#include "FusionContinuationCompression.h"
#include "FusionObjectIds.h"
#include "ApfsTransactionWriter.h"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#ifdef CreateFile
#undef CreateFile
#endif

using namespace apfsaccess;
namespace {
unsigned checks=0;std::string error;
struct WitnessLease {
    HANDLE handle=INVALID_HANDLE_VALUE;
    ~WitnessLease(){if(handle!=INVALID_HANDLE_VALUE)CloseHandle(handle);}
};
void Check(bool ok,const char* label){if(!ok)throw std::runtime_error(std::string(label)+": "+error);
    ++checks;std::cout<<"PASS "<<label<<std::endl;}
void ObjectIds(){
    using namespace rw::fusion_ids;
    std::vector<catalog::BtreeRecord> records,mappings;std::uint64_t next=0;
    Check(Next(996,1000,records,{},mappings,next,error)&&next==1001,"child IDs advance beyond fixed root");
    Check(Next(4096,1000,records,{},mappings,next,error)&&next==4096,"monotonic original next ID is preserved");
    rw::AppleOmapRecord mapping;mapping.object_id=6000;mapping.xid=129;mapping.size_bytes=4096;mapping.physical_block=77;
    catalog::BtreeRecord encoded;
    Check(rw::EncodeAppleOmapRecord(mapping,encoded,error),"canonical object-map identity encoded");mappings.push_back(encoded);
    Check(Next(996,1000,records,{},mappings,next,error)&&next==6001,"mapped non-root identity is excluded");
    rw::AppleInodeRecord inode;inode.object_id=7000;inode.private_id=7000;inode.parent_id=2;inode.mode=0100644;inode.children_or_links=1;
    Check(rw::EncodeAppleInodeRecord(inode,encoded,error),"canonical filesystem inode encoded");records.push_back(encoded);
    Check(Next(996,1000,records,{},mappings,next,error)&&next==7001,"old filesystem identity is excluded after removal");
    Check(Next(996,1000,{},records,mappings,next,error)&&next==7001,"new filesystem identity is excluded");
    Check(!Next(0,1000,{}, {}, {},next,error)&&!next,"missing source counter refuses");
    Check(!Next(996,Limit,{}, {}, {},next,error)&&!next,"root ID exhaustion refuses");
    mappings.front().key.pop_back();
    Check(!Next(996,1000,{}, {},mappings,next,error)&&!next,"malformed object-map key refuses");
    records.front().key.resize(7);
    Check(!Next(996,1000,records,{}, {},next,error)&&!next,"truncated filesystem key refuses");
    Check(Range(1001,4095,error),"complete bounded child range fits");
    Check(!Range(Limit-1,2,error),"next-ID overflow refuses before publication");
    Check(!Range(0,1,error)&&!Range(UINT64_MAX,0,error),"invalid child range refuses");
}
void Compression(){
    using namespace rw::fusion_continuation;
    Bytes original(529000),stored,decoded;
    for(std::size_t i=0;i<original.size();++i)original[i]=std::byte((i*31+7)%251);
    Check(Pack(original,stored)&&stored.size()<original.size()/8,"patterned archive compresses before encryption");
    Check(Unpack(stored,decoded)&&decoded==original,"compressed original bytes round trip exactly");
    auto broken=stored;broken.pop_back();
    Check(!Unpack(broken,decoded)&&decoded.empty(),"truncated compressed archive refuses");
    broken=stored;broken.push_back(std::byte{});
    Check(!Unpack(broken,decoded),"compressed archive trailing bytes refuse");
    broken=stored;Put64(broken,8,PlainLimit+1);
    Check(!Unpack(broken,decoded)&&decoded.empty(),"declared decompression allocation stays bounded");
    broken=stored;Put64(broken,8,original.size()+1);
    Check(!Unpack(broken,decoded)&&decoded.empty(),"decompressed original length must match exactly");
    broken=stored;std::fill(broken.begin()+HeaderSize,broken.end(),std::byte{});
    Check(!Unpack(broken,decoded)&&decoded.empty(),"invalid compressed body refuses");
    Check(Unpack(original,decoded)&&decoded==original,"legacy uncompressed archive remains byte exact");
    std::uint64_t random=0xb29f8c37193ac821ULL;
    for(auto& b:original){random^=random<<13;random^=random>>7;random^=random<<17;b=std::byte(random&255);}
    Check(Pack(original,stored)&&stored==original&&Unpack(stored,decoded)&&decoded==original,
        "incompressible original retains legacy encoding without expansion");
    Check(!Pack({},stored)&&!Unpack({},decoded),"empty archive refuses");
    original.assign(PlainLimit+1,std::byte{});
    Check(!Pack(original,stored)&&!Unpack(original,decoded),"oversized original refuses before codec");
}
void Legacy(const std::filesystem::path& root){
    using Wal=rw::WriteAheadLog;const auto path=root/L"legacy.wal";
    Wal wal({path,"fusion-continuation-legacy"});std::vector<Wal::Record> rows;
    for(std::uint64_t sequence=1;sequence<=2;++sequence){Wal::Record index;index.volume_identity="fusion-continuation-legacy";
        index.sequence=sequence;index.operation=Wal::OperationKind::CompactionIndex;index.state=Wal::RecordState::Cleaned;rows.push_back(index);}
    auto mutation=Wal::Record{};mutation.volume_identity="fusion-continuation-legacy";mutation.sequence=3;
    mutation.transaction_id=1;mutation.operation=Wal::OperationKind::SetFileSize;mutation.path_utf8="legacy";rows.push_back(mutation);
    Check(wal.AppendBatch(rows),"legacy original records appended");
    for(std::uint64_t floor=3;floor<=4;++floor){
        Check(wal.Compact(floor),"public legacy compaction succeeds without capability");
        rows.erase(std::remove_if(rows.begin(),rows.end(),[&](const auto& row){return row.sequence<floor&&
            row.operation!=Wal::OperationKind::CompactionIndex;}),rows.end());
        Wal::Record index;index.volume_identity="fusion-continuation-legacy";index.sequence=floor;
        index.operation=Wal::OperationKind::CompactionIndex;index.state=Wal::RecordState::Cleaned;rows.push_back(index);
        std::vector<std::uint8_t> expected;for(const auto& row:rows){auto b=Wal::EncodeForTest(row);expected.insert(expected.end(),b.begin(),b.end());}
        std::ifstream f(path,std::ios::binary);std::vector<std::uint8_t> actual((std::istreambuf_iterator<char>(f)),{});
        Check(actual==expected,"legacy compaction preserves exact record bytes and every prior index");
    }
}
std::unique_ptr<rw::FusionImageRuntime> Open(const std::filesystem::path& root,bool latest,std::wstring_view control={}){
    catalog::FusionBindRequest request;request.checkpoint_xid=20;
    request.container_uuid_hex=std::string(32,'a');request.fusion_uuid_hex=std::string(31,'b')+"a";
    request.convention=catalog::FusionRoleConvention::LinuxApfsLastByteLowBit;
    request.budget=rw::FusionImageRuntime::CreateStartupReadBudget();
    request.cancellation=std::make_shared<std::atomic<bool>>(control==L"reject-cancel");
    for(unsigned i=0;i<2;++i){catalog::FusionImageMember member;member.path=(root/(i?L"tier.apfs":L"main.apfs")).wstring();
        member.role=i?catalog::FusionMemberRole::Tier2:catalog::FusionMemberRole::Main;member.store_offset=8192;
        member.stable_store_id=i?"apfs-store:test-tier2":"apfs-store:test-main";
        if(!catalog::ApfsFusionStore::InspectImage(member.path,member.exact_identity,error))return {};
        member.store_size=member.exact_identity.size_bytes-8192;request.members.push_back(member);}
    if(latest){std::ifstream f(root/L"main.apfs",std::ios::binary);std::vector<std::byte> nx(4096);f.seekg(8192);
        f.read(reinterpret_cast<char*>(nx.data()),4096);const auto parsed=catalog::ParseNxSuperblock(nx);
        if(!f||!parsed){error="PrivateFixtureSelectorUnavailable";return {};}request.checkpoint_xid=parsed->xid;}
    if(control==L"reject-swap")std::swap(request.members[0].role,request.members[1].role);
    if(control==L"reject-window"){request.members[0].store_offset+=4096;request.members[0].store_size-=4096;}
    rw::FusionVolumeSelection selected{request.container_uuid_hex,std::string(32,'c'),
        {"apfs-store:test-main","apfs-store:test-tier2"},101,request.checkpoint_xid};
    return rw::FusionImageRuntime::Open(request,selected,(root/L"private.wal").wstring(),error);
}
}
int wmain(int argc,wchar_t** argv)try{
    if(argc!=3)return 2;std::filesystem::path root(argv[1]);const std::wstring mode(argv[2]);
    if(!root.is_absolute()||!root.wstring().starts_with(L"D:\\ApfsAccessScratch\\WindowsClosure\\fusion-service-20261017\\"))return 2;
    if(mode==L"compression"){Compression();std::cout<<"PASS "<<checks<<" continuation checks\n";return 0;}
    if(mode==L"object-ids"){ObjectIds();std::cout<<"PASS "<<checks<<" continuation checks\n";return 0;}
    if(mode==L"legacy"){Legacy(root);std::cout<<"PASS "<<checks<<" continuation checks\n";return 0;}
    WitnessLease witness;
    if(mode==L"retained-read-lease"||mode==L"retained-active-read-lease"||mode==L"reject-pending-read-lease"){
        std::uint64_t sequence=2;
        if(mode!=L"retained-read-lease")for(const auto& file:std::filesystem::directory_iterator(root)){
            const auto name=file.path().filename().wstring();
            if(name.starts_with(L"private.wal.fusion-")&&name.ends_with(L".witness")){
                const auto number=name.substr(19,name.size()-19-8);
                sequence=(std::max)(sequence,static_cast<std::uint64_t>(std::stoull(number)));
            }
        }
        const auto path=root/(L"private.wal.fusion-"+std::to_wstring(sequence)+L".witness");
        witness.handle=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
        Check(witness.handle!=INVALID_HANDLE_VALUE,"external read lease pins exact historical witness");
    }
    auto runtime=Open(root,mode==L"reopen-latest"||mode==L"retained-read-lease"||mode==L"retained-active-read-lease"||mode.starts_with(L"reject"),mode);
    if(mode.starts_with(L"reject")){Check(!runtime&&!error.empty(),"unproved continuation refuses fresh owner");
        std::cout<<"REFUSAL "<<error<<'\n';}
    else{
        Check(bool(runtime),"exact original two-member owner opens");Check(runtime->Recover(error),"fresh original recovery");
        if(mode==L"run"){
            Check(runtime->UnlinkRetainingFile(30,error),"original private ownership before rollover");
            for(unsigned i=0;i<12;++i)Check(runtime->Overwrite(30,i*262144ull,std::vector<std::byte>(262144,std::byte{0x66}),error),
                "accepted large held-file write across original rollover");
            std::vector<std::byte> actual;Check(runtime->ReadFile(30,11*262144ull,4096,actual,error)&&
                actual==std::vector<std::byte>(4096,std::byte{0x66}),"large private file exact last range");
            for(unsigned i=0;i<30;++i){std::uint64_t inode=0;const auto name="continued-"+std::to_string(i)+".txt";
                Check(runtime->CreateRegularFile(2,name,inode,error),"continued namespace creates original inode");
                Check(runtime->Overwrite(inode,0,std::vector<std::byte>(97,std::byte(i)),error),"continued namespace writes payload");}
            Check(runtime->HasRetainedFile(30),"private owner survives multiple certified predecessors");
        }else if(mode==L"segment-window"){
            const auto certificates=[&]{std::size_t count=0;
                for(const auto& f:std::filesystem::directory_iterator(root))
                    if(f.path().filename().wstring().starts_with(L"private.wal.fusion-continue-")&&f.path().extension()==L".cert")++count;
                return count;};
            const auto before=certificates();
            for(unsigned i=0;i<6&&certificates()==before;++i)
                Check(runtime->Overwrite(30,0,std::vector<std::byte>(262144,std::byte{0x55}),error),"bounded payload reaches certified rollover");
            const auto rolled=certificates();Check(rolled>before,"payload byte threshold still certifies original predecessor");
            for(unsigned i=0;i<4;++i){
                Check(runtime->Overwrite(30,0,std::vector<std::byte>(1,std::byte{0x55}),error),"small original mutation remains accepted");
                Check(certificates()==rolled,"small segment avoids unnecessary native compaction");
            }
        }else if(mode==L"extend"){
            rw::MetadataStore::DirectoryLink entry;Check(runtime->LookupEntry(2,L"continued-0.txt",entry,error),"continued original inode resolves");
            for(unsigned i=0;i<20;++i)Check(runtime->Overwrite(entry.child_object_id,0,
                std::vector<std::byte>(97,i%2?std::byte{}:std::byte{0x99}),error),"fresh owner continues through another certified predecessor");
        }else if(mode==L"pending"||mode==L"pending-no-witness"){
            bool hit=false;const auto before=runtime->Watermarks();
            Check(!runtime->Overwrite(30,0,std::vector<std::byte>(4096,std::byte{0x44}),error,
                [&](std::string_view stage){if(stage==(mode==L"pending"?"after-fusion-witness":"after-fusion-accept")){hit=true;return false;}return true;})&&hit,
                "original accepted debt cut survives certified predecessor");
            const auto after=runtime->Watermarks();
            Check(after.accepted_sequence>before.accepted_sequence&&after.apfs_durable_sequence==before.apfs_durable_sequence&&
                after.cleanup_sequence==before.cleanup_sequence,"pending original cannot claim durable or cleaned");
            std::cout<<"PASS "<<checks<<" continuation checks\n";return 0;
        }else if(mode.starts_with(L"cut-")){
            const std::string cut(mode.begin()+4,mode.end());bool hit=false;
            for(unsigned i=0;i<20&&!hit;++i){const auto before=runtime->Watermarks();
                const bool ok=runtime->Overwrite(30,0,std::vector<std::byte>(262144,std::byte{0x55}),error,
                    [&](std::string_view stage){
                        if((cut=="cancel-certified"&&stage=="fusion-continuation-certified")||
                            (cut=="cancel-replaced"&&stage=="compact-after-replace")){
                            hit=true;runtime->Cancel();return true;
                        }
                        if(stage==cut){hit=true;return false;}return true;});
                if(hit){Check(!ok,"continuation interruption reaches production boundary");
                    const auto after=runtime->Watermarks();Check(before.accepted_sequence==after.accepted_sequence&&
                        after.accepted_sequence==after.apfs_durable_sequence&&after.accepted_sequence==after.cleanup_sequence,
                        "continuation interruption cannot accept new image mutation");}
                else Check(ok,"original publication before selected cut");}
            Check(hit,"requested continuation cut observed");
        }else if(mode==L"reopen"||mode==L"reopen-latest"||mode==L"retained-read-lease"||mode==L"retained-active-read-lease"){
            Check(!runtime->HasRetainedFile(30),"fresh owner retires original private lifetime");
            for(unsigned i=0;i<30;++i){rw::MetadataStore::DirectoryLink entry;const auto name=L"continued-"+std::to_wstring(i)+L".txt";
                Check(runtime->LookupEntry(2,name,entry,error),"fresh owner resolves continued namespace");std::vector<std::byte> actual;
                Check(runtime->ReadFile(entry.child_object_id,0,97,actual,error)&&actual==std::vector<std::byte>(97,std::byte(i)),
                    "fresh owner reads exact continued payload");}
        }else if(mode==L"recover-cut"||mode==L"recover-pending"){
            std::vector<std::byte> actual;Check(runtime->ReadFile(30,0,4096,actual,error)&&
                actual==std::vector<std::byte>(4096,mode==L"recover-pending"?std::byte{0x44}:std::byte{0x55}),"fresh cut recovery preserves last original payload");
            Check(runtime->Overwrite(30,0,std::vector<std::byte>(4096,std::byte{0x55}),error),"fresh cut recovery permits next accepted mutation");
        }
        const auto w=runtime->Watermarks();Check(w.accepted_sequence==w.apfs_durable_sequence&&w.accepted_sequence==w.cleanup_sequence,
            "all original fences clean");
    }
    std::cout<<"PASS "<<checks<<" continuation checks\n";return 0;
}catch(const std::exception& ex){std::cerr<<"FAIL "<<ex.what()<<'\n';return 1;}
