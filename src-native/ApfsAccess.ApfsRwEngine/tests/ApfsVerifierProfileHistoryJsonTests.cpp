#include "ApfsVerificationJson.h"
#include "ApfsFusionStore.h"
#include <filesystem>
#include <fstream>
#include <iostream>

using namespace apfsaccess::catalog;
namespace
{
unsigned cases=0,checks=0;
void Check(bool value,const char* message){++checks;if(!value)throw std::runtime_error(message);}
struct Fixture
{
    RetainedProfileHistoryReport report;
    VerificationScope scope;
    std::vector<VerificationStoreBinding> stores;
    std::vector<std::string> labels;
    explicit Fixture(bool fusion=true)
    {
        scope.source_identity="held-retained-profile";scope.exact={fusion?8192ULL:0ULL,32ULL*4096,std::string(32,'a'),std::string(32,'b'),101,7};
        report.profile=fusion?CurrentVerificationProfile::FusionCleanCache:CurrentVerificationProfile::EncryptedOneKeyGenerationZero;
        stores.push_back({fusion?"main":scope.source_identity,scope.exact.store_offset_bytes,scope.exact.store_size_bytes});labels.push_back("D:\\held\\image.apfs");
        if(fusion){stores.push_back({"tier2",4096,8ULL*4096});labels.push_back("D:\\held\\tier2.apfs");}
        report.endpoint_scope=scope;report.from_xid=5;report.stores=stores;report.outcome=VerificationOutcome::Complete;
        report.selected=VerifiedCheckpointIdentity{scope.exact,1,2,7,1001,3};report.allocation_unit_bytes=4096;
        report.historical_namespace_verified=true;report.chain_xids={5,6,7};
        for(const auto xid:report.chain_xids)report.checkpoints.push_back({xid,{{2,2},{5,1}},{{10,2}}});
        if(fusion)report.checkpoints[0].payload_ranges.push_back({kFusionTier2ByteAddress/4096+1,1});
        report.source_reads=3;report.source_read_bytes=12288;
        report.read_budget=std::make_shared<ApfsReadBudget>(scope.max_reads,scope.max_read_bytes,scope.max_records,scope.max_record_bytes);
        Check(report.read_budget->Read(12288),"test allowance");
    }
    void Failed(bool refused=false)
    {
        report.outcome=refused?VerificationOutcome::Refused:VerificationOutcome::Incomplete;
        report.chain_xids.clear();report.checkpoints.clear();report.selected.reset();report.allocation_unit_bytes=0;report.historical_namespace_verified.reset();report.stores.clear();
        report.findings.push_back({refused?VerificationCode::UnsupportedFeature:VerificationCode::ChecksumMismatch,
            refused?VerificationSeverity::Warning:VerificationSeverity::Error,VerificationCheck::RequestedHistoryOwnership,101,{},20,5,{},"typed retained refusal"});
    }
    bool Encode(std::string& json,payload::Reason& reason,std::size_t cap=MaxImageVerificationJsonBytes,const std::function<bool()>& alive=[]{return true;})
    {return SerializeRetainedProfileVerificationReport(report,stores.size()==2?CurrentVerificationProfile::FusionCleanCache:CurrentVerificationProfile::EncryptedOneKeyGenerationZero,
        scope,5,stores,labels,alive,cap,json,reason);}
};
template<class Edit> void Reject(const char* name,Edit edit,payload::Reason expected=payload::Reason::InvalidProjection)
{Fixture f;edit(f);std::string json="clear-me";payload::Reason reason;Check(!f.Encode(json,reason)&&json.empty()&&reason==expected,name);++cases;}
void Save(const std::filesystem::path& folder,const char* name,Fixture& fixture)
{
    std::string json;payload::Reason reason;Check(fixture.Encode(json,reason),"retained positive encode");
    Check(json.starts_with("{\"format\":\"apfs-access-retained-profile-verification\",\"version\":1,"),"separate version contract");
    Check(json.find("\"retainedOwnershipComplete\":false")!=std::string::npos&&json.find("\"applePurgeableBytes\":null")!=std::string::npos,"no policy promotion");
    std::ofstream out(folder/(std::string(name)+".json"),std::ios::binary);out<<json;out.close();Check(static_cast<bool>(out),"encoded artifact");++cases;
}
}
int main(int argc,char** argv)try
{
    Check(argc==2,"bounded evidence directory required");std::filesystem::create_directories(argv[1]);
    {Fixture f;Save(argv[1],"fusion-history",f);}
    {Fixture f(false);Save(argv[1],"encrypted-history",f);}
    {Fixture f;f.Failed();Save(argv[1],"incomplete",f);}
    {Fixture f(false);f.Failed(true);Save(argv[1],"refused",f);}
    Reject("wrong source",[](auto& f){f.report.endpoint_scope.source_identity+="foreign";},payload::Reason::InvalidBinding);
    Reject("wrong explicit from",[](auto& f){f.report.from_xid=4;},payload::Reason::InvalidBinding);
    Reject("wrong member binding",[](auto& f){f.report.stores[1].offset_bytes=0;},payload::Reason::InvalidBinding);
    Reject("missing namespace",[](auto& f){f.report.historical_namespace_verified.reset();});
    Reject("false namespace",[](auto& f){f.report.historical_namespace_verified=false;});
    Reject("missing endpoint",[](auto& f){f.report.selected.reset();});
    Reject("wrong endpoint",[](auto& f){++f.report.selected->exact.checkpoint_xid;});
    Reject("missing chain endpoint",[](auto& f){f.report.chain_xids.pop_back();f.report.checkpoints.pop_back();});
    Reject("duplicate generation",[](auto& f){f.report.chain_xids[1]=5;});
    Reject("graph wrong generation",[](auto& f){f.report.checkpoints[1].checkpoint_xid=5;});
    Reject("missing graph",[](auto& f){f.report.checkpoints.erase(f.report.checkpoints.begin());});
    Reject("range overflow",[](auto& f){f.report.checkpoints[0].payload_ranges={{UINT64_MAX,2}};});
    Reject("range exceeds member",[](auto& f){f.report.checkpoints[0].payload_ranges={{31,2}};});
    Reject("encoded Fusion gap",[](auto& f){f.report.checkpoints[0].payload_ranges={{100,1}};});
    Reject("cross-generation payload metadata collision",[](auto& f){f.report.checkpoints[1].payload_ranges={{5,1}};});
    Reject("adjacent noncanonical ranges",[](auto& f){f.report.checkpoints[0].metadata_ranges={{2,1},{3,1}};});
    Reject("unsorted ranges",[](auto& f){f.report.checkpoints[0].metadata_ranges={{5,1},{2,1}};});
    Reject("invented purgeable zero",[](auto& f){f.report.apple_purgeable_bytes=0;});
    Reject("invented reclaimable",[](auto& f){f.report.reclaimable_bytes=4096;});
    Reject("invented charge",[](auto& f){f.report.snapshot_allocation_charge_bytes=4096;});
    Reject("whole scope promotion",[](auto& f){f.scope.require_whole_volume=f.report.endpoint_scope.require_whole_volume=true;});
    Reject("failed graph retained",[](auto& f){f.Failed();f.report.checkpoints.push_back({5,{{2,1}},{}});});
    Reject("failed namespace retained",[](auto& f){f.Failed();f.report.historical_namespace_verified=true;});
    Reject("failed selected retained",[](auto& f){f.Failed();f.report.selected=VerifiedCheckpointIdentity{f.scope.exact,1,2,7,1001,3};});
    Reject("failure severity mismatch",[](auto& f){f.Failed();f.report.findings[0].severity=VerificationSeverity::Warning;});
    {Fixture f;std::string json;payload::Reason reason;Check(!f.Encode(json,reason,16)&&json.empty()&&reason==payload::Reason::OutputLimit,"bounded clear output");
        Check(!f.Encode(json,reason)&&reason==payload::Reason::SharedBudget,"sticky limit");++cases;}
    {Fixture f;std::string json;payload::Reason reason;Check(!f.Encode(json,reason,MaxImageVerificationJsonBytes,[]{return false;})&&json.empty()&&reason==payload::Reason::Deadline,"deadline");++cases;}
    {Fixture f;Check(f.report.read_budget->Refuse("test" )==false,"exhaust");std::string json;payload::Reason reason;
        Check(!f.Encode(json,reason)&&json.empty()&&reason==payload::Reason::SharedBudget,"budget failure no graph document");++cases;}
    std::cout<<"PASS "<<cases<<" cases / "<<checks<<" checks\n";return 0;
}
catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}
