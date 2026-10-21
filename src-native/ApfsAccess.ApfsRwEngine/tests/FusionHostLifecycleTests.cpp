#include <algorithm>
#include <array>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <windows.h>
#include <winternl.h>
#ifndef PNTSTATUS
typedef NTSTATUS* PNTSTATUS;
#endif
#include <winfsp/winfsp.h>
#include "FusionMountState.h"
#include "ApfsFormat.h"

namespace {
unsigned checks=0;
void Check(bool ok,const std::string& reason) {
    if(!ok)throw std::runtime_error(reason);
    ++checks;std::cout<<"PASS "<<reason<<'\n';
}
std::unique_ptr<apfsaccess::rw::FusionImageRuntime> Open(
    const std::filesystem::path& root,const std::shared_ptr<std::atomic<bool>>& cancelled) {
    using namespace apfsaccess::catalog;
    FusionBindRequest request;
    request.container_uuid_hex=std::string(32,'a');request.fusion_uuid_hex=std::string(31,'b')+"a";
    std::vector<std::byte> bytes(4096);
    std::ifstream input(root/L"main.apfs",std::ios::binary);input.seekg(8192);
    input.read(reinterpret_cast<char*>(bytes.data()),4096);input.close();
    auto nx=ParseNxSuperblock(bytes);Check(bool(nx),"canonical fixture anchor");
    request.checkpoint_xid=nx->xid;request.convention=FusionRoleConvention::LinuxApfsLastByteLowBit;
    request.budget=std::make_shared<ApfsReadBudget>(100000,256ull<<20,1000000,256ull<<20);
    request.cancellation=cancelled;
    std::string error;
    for(unsigned i=0;i<2;++i) {
        FusionImageMember m;m.path=(root/(i?L"tier.apfs":L"main.apfs")).wstring();
        m.role=i?FusionMemberRole::Tier2:FusionMemberRole::Main;
        m.stable_store_id=i?"apfs-store:test-tier2":"apfs-store:test-main";m.store_offset=8192;
        Check(ApfsFusionStore::InspectImage(m.path,m.exact_identity,error),"held fixture identity "+error);
        m.store_size=m.exact_identity.size_bytes-8192;request.members.push_back(m);
    }
    apfsaccess::rw::FusionVolumeSelection selected;
    selected.container_uuid_hex=request.container_uuid_hex;
    selected.volume_uuid_hex=std::string(32,'c');selected.volume_oid=101;selected.checkpoint_xid=nx->xid;
    selected.member_store_ids={"apfs-store:test-main","apfs-store:test-tier2"};
    auto runtime=apfsaccess::rw::FusionImageRuntime::Open(request,selected,(root/L"lifecycle.wal").wstring(),error);
    Check(bool(runtime),"production original journal and exact owner "+error);return runtime;
}
void Handles() {
    fusion_mount::State s;std::lock_guard lock(s.serial);
    s.open_counts[30]=2;FSP_FSCTL_FILE_INFO info{};info.FileSize=9;
    auto first=new fusion_mount::Handle;first->node.inode_id=30;PVOID out=first;
    fusion_mount::DiscardUnpublishedHandle(s,&out,&info);
    Check(!out&&!info.FileSize&&s.open_counts.at(30)==1,"failed return clears output and only its open count");
    auto second=new fusion_mount::Handle;second->node.inode_id=30;out=second;
    fusion_mount::DiscardUnpublishedHandle(s,&out,&info);
    Check(!out&&!s.open_counts.contains(30),"last unpublished handle removes registration");
    s.open_counts[31]=1;out=nullptr;
    fusion_mount::DiscardUnpublishedHandle(s,&out,&info);
    Check(s.open_counts.at(31)==1,"failure before handle publication preserves sibling count");
    auto cleaned=new fusion_mount::Handle;cleaned->node.inode_id=31;cleaned->cleaned=true;out=cleaned;
    fusion_mount::DiscardUnpublishedHandle(s,&out,&info);
    Check(!out&&s.open_counts.at(31)==1,"already-cleaned handle does not decrement twice");
}
void Publications(const std::filesystem::path& root) {
    fusion_mount::State s;s.writer=Open(root,s.cancelled);std::string error;
    std::vector<std::byte> first(1024,std::byte{0x41}),second(1024,std::byte{0x52});
    std::uint64_t final_sequence=0;
    {
        std::lock_guard serial(s.serial);fusion_mount::State::Operation operation(s);
        const auto initial=s.threads.at(operation.thread);
        s.PublicationCompleted();Check(s.threads.at(operation.thread)==initial,"no accepted boundary cannot renew");
        Check(s.writer->Overwrite(30,32,first,error),"first original publication "+error);
        const auto old_deadline=GetTickCount64()+10000;s.threads.at(operation.thread)=old_deadline;
        s.PublicationCompleted();
        Check(s.threads.at(operation.thread)>old_deadline&&s.completed_boundary==s.writer->Watermarks().cleanup_sequence,
            "new fully durable original boundary renews");
        const auto renewed=s.threads.at(operation.thread);s.PublicationCompleted();
        Check(s.threads.at(operation.thread)==renewed,"same original boundary cannot renew twice");
    }
    {
        std::lock_guard serial(s.serial);fusion_mount::State::Operation operation(s);
        const auto deadline=s.threads.at(operation.thread);
        const auto cut=[](std::string_view stage){return stage!="after-fusion-witness";};
        Check(!s.writer->Overwrite(30,2048,second,error,cut),"bounded interruption after durable witness");
        const auto debt=s.writer->Watermarks();
        Check(debt.accepted_sequence>debt.apfs_durable_sequence&&debt.accepted_sequence>debt.cleanup_sequence,
            "interruption leaves real original accepted debt");
        s.PublicationCompleted();Check(s.threads.at(operation.thread)==deadline,"pending original debt cannot renew");
        Check(s.writer->Recover(error),"same-owner exact witness replay "+error);
        const auto water=s.writer->Watermarks();final_sequence=water.accepted_sequence;
        Check(final_sequence==water.apfs_durable_sequence&&final_sequence==water.cleanup_sequence,"replay cleans only proven original boundary");
        const auto expired=GetTickCount64()-1;s.threads.at(operation.thread)=expired;
        s.PublicationCompleted();Check(s.threads.at(operation.thread)==expired,"expired deadline cannot revive after durable progress");
        s.Watch([](){return true;});
        for(unsigned i=0;i<100&&!s.cancelled->load();++i)Sleep(10);
        Check(s.cancelled->load()&&s.failed.load()&&s.deadline_expired.load(),"watchdog makes deadline cancellation terminal");
        s.PublicationCompleted();Check(s.threads.at(operation.thread)==expired,"canceled failed owner cannot revive");
    }
    s.Close();auto fresh=Open(root,std::make_shared<std::atomic<bool>>(false));
    Check(fresh->Recover(error)&&fresh->Watermarks().cleanup_sequence==final_sequence,"fresh owner observes exact cleaned original sequence");
    std::vector<std::byte> expected(8192,std::byte{0xA1}),actual;
    std::fill(expected.begin()+4096,expected.end(),std::byte{0xB1});
    std::copy(first.begin(),first.end(),expected.begin()+32);std::copy(second.begin(),second.end(),expected.begin()+2048);
    Check(fresh->ReadFile(30,0,8192,actual,error)&&actual==expected,"fresh canonical owner complete two-member readback "+error);
}
}
int wmain(int argc,wchar_t** argv) try {
    if(argc!=2)return 2;
    const std::filesystem::path root(argv[1]);
    if(!root.is_absolute()||root.wstring().find(L"D:\\ApfsAccessScratch\\WindowsClosure\\fusion-service-20261017\\")!=0)return 2;
    Handles();Publications(root);std::cout<<"PASS "<<checks<<" lifecycle checks, 2 original publications\n";return 0;
} catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}
