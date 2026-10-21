#include "FusionImageRuntime.h"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace {
using namespace apfsaccess;
unsigned checks=0;
std::string error;
void Check(bool ok,const char* label) {
    if(!ok)throw std::runtime_error(std::string(label)+": "+error);
    ++checks;std::cout<<"PASS "<<label<<'\n';
}
std::unique_ptr<rw::FusionImageRuntime> Open(const std::filesystem::path& root,bool latest) {
    catalog::FusionBindRequest request;request.checkpoint_xid=20;
    request.container_uuid_hex=std::string(32,'a');request.fusion_uuid_hex=std::string(31,'b')+"a";
    request.convention=catalog::FusionRoleConvention::LinuxApfsLastByteLowBit;
    request.budget=rw::FusionImageRuntime::CreateStartupReadBudget();
    request.cancellation=std::make_shared<std::atomic<bool>>(false);
    if(latest){
        std::ifstream file(root/L"main.apfs",std::ios::binary);std::vector<std::byte> nx(4096);file.seekg(8192);
        file.read(reinterpret_cast<char*>(nx.data()),4096);const auto parsed=catalog::ParseNxSuperblock(nx);
        if(!file||!parsed)return {};request.checkpoint_xid=parsed->xid;
    }
    for(unsigned i=0;i<2;++i){
        catalog::FusionImageMember member;member.path=(root/(i?L"tier.apfs":L"main.apfs")).wstring();
        member.role=i?catalog::FusionMemberRole::Tier2:catalog::FusionMemberRole::Main;
        member.stable_store_id=i?"apfs-store:test-tier2":"apfs-store:test-main";member.store_offset=8192;
        if(!catalog::ApfsFusionStore::InspectImage(member.path,member.exact_identity,error))return {};
        member.store_size=member.exact_identity.size_bytes-8192;request.members.push_back(member);
    }
    rw::FusionVolumeSelection selected{request.container_uuid_hex,std::string(32,'c'),
        {"apfs-store:test-main","apfs-store:test-tier2"},101,request.checkpoint_xid};
    return rw::FusionImageRuntime::Open(request,selected,(root/L"private.wal").wstring(),error);
}
void Read(rw::FusionImageRuntime& runtime,std::uint64_t inode,const std::vector<std::byte>& expected) {
    std::vector<std::byte> actual;Check(runtime.ReadFile(inode,0,expected.size(),actual,error)&&actual==expected,
        "exact retained or current stream readback");
}
}
int wmain(int argc,wchar_t** argv) try {
    if(argc!=3)return 2;
    const std::filesystem::path root(argv[1]);const std::wstring mode(argv[2]);
    if(!root.is_absolute()||!root.wstring().starts_with(L"D:\\ApfsAccessScratch\\WindowsClosure\\fusion-service-20261017\\"))return 2;
    auto runtime=Open(root,mode==L"reopen-unlink"||mode==L"reopen-latest"||mode==L"reject-latest"||mode==L"reopen-capacity");
    if(mode==L"reject-latest"){
        Check(!runtime&&!error.empty(),"latest selector refuses incomplete private ownership");
        std::cout<<"REFUSAL "<<error<<"\nPASS "<<checks<<" private lifecycle checks\n";return 0;
    }
    Check(bool(runtime),"original selector opens exact two members");
    if(mode==L"capacity"||mode==L"capacity-two"){
        Check(runtime->Recover(error),"initial recovery");
        Check(runtime->UnlinkRetainingFile(30,error),"capacity control owns original private inode");
        std::uint64_t second=0;
        if(mode==L"capacity-two"){
            Check(runtime->CreateRegularFile(2,"second-private.txt",second,error),"create second independent private candidate");
            Check(runtime->Overwrite(second,0,std::vector<std::byte>(97,std::byte{0x77}),error),"write second independent private payload");
            Check(runtime->UnlinkRetainingFile(second,error),"retain second original inode before quota pressure");
        }
        std::size_t length=256*1024,publications=0,refusals=0;
        while(length){
            const auto before=runtime->Watermarks();
            if(runtime->Overwrite(30,0,std::vector<std::byte>(length,std::byte{0x66}),error)){
                if(++publications>48)throw std::runtime_error("Capacity control publication bound");
            }else{
                Check(error=="FusionRuntimeOriginalCapacity"||error=="FusionRuntimePrivateRetirementCapacity",
                    "capacity refusal has exact preaccept reason");
                const auto after=runtime->Watermarks();
                Check(before.accepted_sequence==after.accepted_sequence&&before.apfs_durable_sequence==after.apfs_durable_sequence&&
                    before.cleanup_sequence==after.cleanup_sequence,"capacity refusal preserves all original fences");
                if(++refusals>20)throw std::runtime_error("Capacity control refusal bound");
                length/=2;
            }
        }
        Check(publications>=7&&refusals>0,"original journal capacity exhausted by real accepted writes");
        Check(runtime->CheckAvailable(error),"capacity rejection retains readable owner");
        Read(*runtime,30,std::vector<std::byte>(4096,std::byte{0x66}));
        Check(runtime->ReleaseRetainedFile(30,error),"reserved original capacity retires final private inode");
        Check(!runtime->HasRetainedFile(30),"capacity retirement drains original private ownership");
        if(second){
            Check(runtime->HasRetainedFile(second),"first retirement preserves second original owner");
            Read(*runtime,second,std::vector<std::byte>(97,std::byte{0x77}));
            Check(runtime->ReleaseRetainedFile(second,error),"second reserved original retirement remains available");
            Check(!runtime->HasRetainedFile(second),"both private owners retired before restart");
        }
        const auto water=runtime->Watermarks();
        Check(water.accepted_sequence==water.apfs_durable_sequence&&water.accepted_sequence==water.cleanup_sequence,
            "capacity retirement leaves no accepted debt");
        std::cout<<"CAPACITY acceptedWrites="<<publications<<" refusedAttempts="<<refusals<<'\n';
    }else if(mode==L"reopen-capacity"){
        const auto before=runtime->Watermarks();
        Check(runtime->Recover(error),"fresh owner proves capacity retirement history");
        rw::MetadataStore::DirectoryLink entry;rw::FusionNodeInfo node;
        Check(!runtime->LookupEntry(2,L"file.txt",entry,error)&&!runtime->GetMetadata(30,node,error),
            "fresh capacity owner has neither public nor private retired inode");
        const auto water=runtime->Watermarks();
        Check(water.accepted_sequence==water.apfs_durable_sequence&&water.accepted_sequence==water.cleanup_sequence,
            "fresh capacity owner retains clean original fences");
        Check(water.accepted_sequence==before.accepted_sequence,"fresh capacity owner needs no additional retirement transaction");
    }else if(mode==L"unlink"){
        Check(runtime->Recover(error),"initial recovery");
        const auto before=runtime->Watermarks();
        Check(!runtime->ReleaseRetainedFile(30,error),"ordinary file cannot be reaped as private ownership");
        Check(runtime->Watermarks().accepted_sequence==before.accepted_sequence,"unproved release refuses before acceptance");
        Check(runtime->UnlinkRetainingFile(30,error),"original unlink retains exact live inode");
        rw::MetadataStore::DirectoryLink entry;Check(!runtime->LookupEntry(2,L"file.txt",entry,error),"retained unlink removes public name");
        std::vector<std::byte> old(8192,std::byte{0xA1});std::fill(old.begin()+4096,old.end(),std::byte{0xB1});Read(*runtime,30,old);
        Check(runtime->Overwrite(30,100,std::vector<std::byte>(97,std::byte{0x77}),error),"unlinked held inode remains writable");
        std::fill(old.begin()+100,old.begin()+197,std::byte{0x77});Read(*runtime,30,old);
    }else if(mode==L"reopen"||mode==L"reopen-unlink"||mode==L"reopen-latest"){
        rw::FusionNodeInfo node;Check(!runtime->GetMetadata(30,node,error),"fresh owner fences unreaped private inode");
        Check(runtime->Recover(error),"fresh original replay and private retirement");
        Check(!runtime->HasRetainedFile(30),"retained ownership drained");
        Check(!runtime->GetMetadata(30,node,error),"retired inode absent");
        rw::MetadataStore::DirectoryLink entry;
        if(mode==L"reopen-unlink")Check(!runtime->LookupEntry(2,L"file.txt",entry,error),"fresh retirement preserves original unlink");
        else{Check(runtime->LookupEntry(2,L"file.txt",entry,error)&&entry.child_object_id!=30,
            "replacement survives fresh retirement");Read(*runtime,entry.child_object_id,std::vector<std::byte>(7000,std::byte{0x55}));}
    }else{
        Check(runtime->Recover(error),"initial recovery");
        std::uint64_t source=0;Check(runtime->CreateRegularFile(2,"replacement.txt",source,error),"create original replacement source");
        Check(runtime->Overwrite(source,0,std::vector<std::byte>(7000,std::byte{0x55}),error),"write replacement payload");
        const auto cut=mode==L"cut-witness"?"after-fusion-witness":mode==L"cut-main"?"after-fusion-main":"";
        const auto ok=runtime->RenameRetainingDestination(source,2,"file.txt",30,error,
            [&](std::string_view stage){return stage!=cut;});
        if(*cut){
            Check(!ok,"original retained replacement interrupted");
            const auto w=runtime->Watermarks();Check(w.accepted_sequence>w.cleanup_sequence,"accepted debt retained");
        }else{
            Check(ok,"replace retains exact destination inode");
            Check(runtime->HasRetainedFile(30),"retained ownership belongs to original boundary");
            rw::MetadataStore::DirectoryLink entry;
            Check(runtime->LookupEntry(2,L"file.txt",entry,error)&&entry.child_object_id==source,"public name resolves new source");
            Check(!runtime->LookupEntry(2,L"private-dir",entry,error),"private directory hidden from public namespace");
            std::vector<std::byte> old(8192,std::byte{0xA1});std::fill(old.begin()+4096,old.end(),std::byte{0xB1});
            Read(*runtime,30,old);Read(*runtime,source,std::vector<std::byte>(7000,std::byte{0x55}));
            Check(runtime->Overwrite(30,100,std::vector<std::byte>(97,std::byte{0x77}),error),"held victim remains writable");
            std::fill(old.begin()+100,old.begin()+197,std::byte{0x77});Read(*runtime,30,old);
            Check(runtime->Resize(30,4097,error),"held victim resize preserves ownership");old.resize(4097);Read(*runtime,30,old);
            Check(runtime->Rename(source,2,"renamed.txt",error),"canonical primary name follows subsequent rename");
            Check(runtime->Rename(source,2,"file.txt",error),"canonical primary name supports repeated rename");
            if(mode==L"release"){
                Check(runtime->ReleaseRetainedFile(30,error),"final owner releases retained inode");
                rw::FusionNodeInfo node;Check(!runtime->GetMetadata(30,node,error),"released inode absent");
                Read(*runtime,source,std::vector<std::byte>(7000,std::byte{0x55}));
            }
        }
    }
    std::cout<<"PASS "<<checks<<" private lifecycle checks\n";return 0;
}catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}
