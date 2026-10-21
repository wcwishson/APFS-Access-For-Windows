#include "FusionImageRuntime.h"
#include "ApfsFormat.h"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace {
using namespace apfsaccess;
unsigned checks=0;
void Check(bool ok,const std::string& reason) {
    if(!ok)throw std::runtime_error(reason);++checks;std::cout<<"PASS "<<reason<<'\n';
}
std::unique_ptr<rw::FusionImageRuntime> Open(const std::filesystem::path& root,std::uint64_t xid,
    const std::string& mode,const std::filesystem::path& journal,std::string& error) {
    catalog::FusionBindRequest request;request.checkpoint_xid=xid;
    request.container_uuid_hex=std::string(32,'a');request.fusion_uuid_hex=std::string(31,'b')+"a";
    request.convention=catalog::FusionRoleConvention::LinuxApfsLastByteLowBit;
    request.budget=mode=="history-probe-tight"?
        std::make_shared<catalog::ApfsReadBudget>(100000,256ull<<20,1000000,256ull<<20):
        rw::FusionImageRuntime::CreateStartupReadBudget();
    request.cancellation=std::make_shared<std::atomic<bool>>(false);
    for(unsigned i=0;i<2;++i) {
        catalog::FusionImageMember m;m.path=(root/(i?L"tier.apfs":L"main.apfs")).wstring();
        m.role=i?catalog::FusionMemberRole::Tier2:catalog::FusionMemberRole::Main;
        m.stable_store_id=i?"apfs-store:test-tier2":"apfs-store:test-main";m.store_offset=8192;
        if(!catalog::ApfsFusionStore::InspectImage(m.path,m.exact_identity,error))return {};
        m.store_size=m.exact_identity.size_bytes-8192;request.members.push_back(m);
    }
    if(mode=="wrong-identity")request.members[1].exact_identity.file_id[0]^=std::byte{1};
    if(mode=="wrong-window")request.members[1].store_size-=4096;
    rw::FusionVolumeSelection selected;selected.container_uuid_hex=request.container_uuid_hex;
    selected.volume_uuid_hex=std::string(32,'c');selected.volume_oid=101;selected.checkpoint_xid=xid;
    selected.member_store_ids={"apfs-store:test-main","apfs-store:test-tier2"};
    return rw::FusionImageRuntime::Open(request,selected,journal.wstring(),error);
}
void Readback(rw::FusionImageRuntime& r,bool third,std::string& error) {
    std::vector<std::byte> expected(8192,std::byte{0xA1}),actual;
    std::fill(expected.begin()+4096,expected.end(),std::byte{0xB1});
    std::fill(expected.begin()+32,expected.begin()+1056,std::byte{0x41});
    std::fill(expected.begin()+2048,expected.begin()+3072,std::byte{0x52});
    if(third)std::fill(expected.begin()+4096,expected.begin()+5120,std::byte{0x63});
    Check(r.ReadFile(30,0,8192,actual,error)&&actual==expected,"complete two-member canonical readback: "+error);
}
}
int wmain(int argc,wchar_t** argv) try {
    if(argc!=3&&argc!=4)return 2;
    const std::filesystem::path root(argv[1]);const std::string mode=rw::TransactionManager::WideToUtf8(argv[2]);
    if(!root.is_absolute()||(!root.wstring().starts_with(L"D:\\ApfsAccessScratch\\WindowsClosure\\fusion-service-20261017\\")&&
        !root.wstring().starts_with(L"D:\\ApfsAccessScratch\\FA1\\")))return 2;
    const auto journal=argc==4?std::filesystem::path(argv[3]):root/L"chain.wal";
    if(!journal.is_absolute()||!journal.wstring().starts_with(L"D:\\ApfsAccessScratch\\"))return 2;
    std::string error;auto r=Open(root,mode=="unrelated-selector"?19:20,mode,journal,error);
    if(mode=="history-probe-tight") {
        Check(!r&&error.find("ApfsReadBudgetRecordLimit")!=error.npos,"caller budget stays cumulative and sticky: "+error);
        std::cout<<"PASS "<<checks<<" explicit budget checks\n";return 0;
    }
    if(mode=="history-probe") {
        Check(bool(r),"full retained original namespace chain: "+error);
        const auto w=r->Watermarks();Check(w.accepted_sequence&&w.accepted_sequence==w.apfs_durable_sequence&&
            w.accepted_sequence==w.cleanup_sequence,"long-chain observer sees fully cleaned original history");
        std::vector<std::byte> expected(8192,std::byte{0xA1}),actual;
        std::fill(expected.begin()+4096,expected.end(),std::byte{0xB1});
        Check(r->ReadFile(30,0,8192,actual,error)&&actual==expected,"long-chain original two-member file remains complete");
        rw::FusionRuntimeVolumeInfo info;Check(r->GetVolumeInfo(info,error)&&info.checkpoint_xid>40,"long-chain canonical final selector");
        std::cout<<"PASS "<<checks<<" long-chain checks, xid "<<info.checkpoint_xid<<", accepted/durable/cleaned "<<w.accepted_sequence<<'\n';return 0;
    }
    if(mode=="reject"||mode=="wrong-identity"||mode=="wrong-window"||mode=="unrelated-selector") {
        Check(!r,"fresh original chain refuses: "+error);
    } else {
        Check(bool(r),"fresh held two-member owner from original selector: "+error);
        if(mode=="seed") {
            Check(r->Overwrite(30,32,std::vector<std::byte>(1024,std::byte{0x41}),error),"first original publication: "+error);
            Check(r->Overwrite(30,2048,std::vector<std::byte>(1024,std::byte{0x52}),error),"second original publication: "+error);
        } else if(mode=="pending") {
            Check(!r->Overwrite(30,4096,std::vector<std::byte>(1024,std::byte{0x63}),error,
                [](std::string_view stage){return stage!="after-fusion-witness";}),"third original witness interruption");
            const auto w=r->Watermarks();Check(w.accepted_sequence>w.cleanup_sequence&&w.apfs_durable_sequence==w.cleanup_sequence,
                "real pending original debt remains behind cleaned chain");
            std::cout<<"PASS "<<checks<<" chain checks\n";return 0;
        }
        const auto before=r->Watermarks();
        Check(r->Recover(error),"fresh original recovery: "+error);
        const auto w=r->Watermarks();Check(w.accepted_sequence==w.apfs_durable_sequence&&w.accepted_sequence==w.cleanup_sequence,
            "all original fences complete");
        if(mode=="probe"||mode=="seed")Check(before.cleanup_sequence==w.cleanup_sequence,"cleaned proof never advances original fences");
        Readback(*r,mode=="recover"||mode=="probe-three",error);
        rw::FusionRuntimeVolumeInfo info;Check(r->GetVolumeInfo(info,error)&&info.checkpoint_xid==
            ((mode=="recover"||mode=="probe-three")?23u:22u),"exact original chain target metadata");
    }
    std::cout<<"PASS "<<checks<<" chain checks\n";return 0;
} catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}
