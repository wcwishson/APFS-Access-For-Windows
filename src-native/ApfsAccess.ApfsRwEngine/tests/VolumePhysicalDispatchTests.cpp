#define APFS_PHYSICAL_KEEPER_FIXTURE_ONLY
#include "VolumePhysicalKeeperTests.cpp"
#define APFS_VOLUME_IMAGE_FAULT_INJECTION
#include "../tools/VolumeResizeCli.h"
#include <sstream>

namespace {
namespace cli=apfsaccess::rw::volume_image_cli;
std::wstring W(std::string_view text){return {text.begin(),text.end()};}
std::string BindingHex(const PhysicalFixture& fixture){
    constexpr char digits[]="0123456789abcdef";std::string text;
    for(const auto byte:volume_physical::Encode(fixture.file->binding,fixture.source->InstanceId())){
        const auto value=std::to_integer<unsigned>(byte);text+=digits[value>>4];text+=digits[value&15];}
    return text;
}
std::vector<std::wstring> Arguments(const PhysicalFixture& f,std::wstring mode,std::string_view token={}){
    const auto& r=f.request;std::vector<std::wstring> args={L"private-surrogate",L"--operation",r.operation==VolumeImageOperation::Erase?L"erase":L"format",
        L"--mode",mode,L"--source-kind",L"physical",L"--physical-binding-hex",W(BindingHex(f)),L"--image",f.source->InstanceId(),
        L"--journal-directory",r.journal_directory.wstring(),L"--container",W(r.container_uuid),L"--volume",W(r.volume_uuid),
        L"--oid",std::to_wstring(r.volume_oid),L"--xid",std::to_wstring(r.checkpoint_xid),L"--expected-bytes",std::to_wstring(r.expected_bytes),
        L"--target-bytes",std::to_wstring(r.target_bytes),L"--new-container",W(r.new_container_uuid),L"--new-volume",W(r.new_volume_uuid),
        L"--new-wal",r.new_volume_wal.wstring(),L"--name",W(r.name_utf8),L"--case-sensitive",L"false",
        L"--history-spool-root",r.history_context.spool_root.wstring(),L"--history-recovery-root",r.history_context.recovery_root.wstring()};
    for(const auto& [oid,path]:r.sibling_wals)args.insert(args.end(),{L"--wal",std::to_wstring(oid)+L"="+path.wstring()});
    if(mode==L"dry-run" || mode==L"apply")args.insert(args.end(),{L"--physical-device",L"\\\\.\\PhysicalDrive2"});
    if(!token.empty())args.insert(args.end(),{L"--confirm",W(token)});return args;
}
void Replace(std::vector<std::wstring>& args,std::wstring_view key,std::wstring value){
    const auto it=std::find(args.begin(),args.end(),key);Check(it!=args.end() && it+1!=args.end(),"existing option");*(it+1)=std::move(value);
}
struct Reply {int code;std::string text;};
Reply Invoke(PhysicalFixture& fixture,std::vector<std::wstring> args,unsigned& calls){
    std::vector<wchar_t*> argv;for(auto& value:args)argv.push_back(value.data());
    std::ostringstream output;auto* old=std::cout.rdbuf(output.rdbuf());
    struct Restore{std::streambuf* old;~Restore(){std::cout.rdbuf(old);}} restore{old};
    const auto code=cli::Run(static_cast<int>(argv.size()),argv.data(),true,
        [&](const RawSnapshotBinding& binding,std::wstring_view instance,std::wstring_view selected,std::string& error){
            ++calls;
            if(binding!=fixture.file->binding || instance!=fixture.source->InstanceId() ||
                (!selected.empty() && selected!=L"\\\\.\\PhysicalDrive2")){
                error="SurrogateSelectedAuthorityMismatch";return std::shared_ptr<VolumePhysicalSource>{};}
            return fixture.source;
        });
    return {code,output.str()};
}
void SaveReply(const PhysicalFixture& fixture,std::string_view name,const Reply& reply){
    std::ofstream file(fixture.request.journal_directory/(std::string(name)+".json"),std::ios::binary);
    file<<reply.text;Check(file.good(),"actual native wire receipt");
}
std::string Token(const Reply& reply){
    constexpr std::string_view prefix="\"confirmationToken\":\"";const auto at=reply.text.find(prefix);
    Check(at!=std::string::npos,"native confirmation field");const auto token=reply.text.substr(at+prefix.size(),64);
    Check(token.size()==64 && token.find_first_not_of("0123456789abcdef")==std::string::npos &&
        reply.text.at(at+prefix.size()+64)=='"',"exact native token");return token;
}
void ProductionPaths(PhysicalFixture& fixture){
    auto& r=fixture.request;r.history_context={r.journal_directory/"spool",r.journal_directory/"recovery"};
    std::filesystem::create_directories(r.history_context.spool_root);std::filesystem::create_directories(r.history_context.recovery_root);
    const auto wal=[&](std::string_view container,std::uint64_t oid){const auto identity=DeriveVolumePhysicalRecoveryIdentity(fixture.file->binding,container,oid);
        return r.history_context.spool_root/("apfs_recovery_v1_"+identity.substr(17))/"write-ahead.wal";};
    for(auto& [oid,path]:r.sibling_wals){path=wal(r.container_uuid,oid);std::filesystem::create_directories(path.parent_path());
        Check(!std::filesystem::exists(path),"fresh current-source WAL fixture");Save(path,{});}
    r.new_volume_wal=wal(r.new_container_uuid,1024);std::filesystem::create_directories(r.new_volume_wal.parent_path());
    std::ofstream oracle(r.journal_directory/"binding-oracle.json",std::ios::binary);
    oracle<<"{\"bindingHex\":\""<<BindingHex(fixture)<<"\",\"sourceIdentity\":\""<<fixture.source->Identity()
        <<"\",\"containerUuid\":\""<<r.container_uuid<<"\",\"volumeUuid\":\""<<r.volume_uuid<<"\",\"oid\":\""<<r.volume_oid
        <<"\",\"xid\":\""<<r.checkpoint_xid<<"\",\"expectedBytes\":\""<<r.expected_bytes
        <<"\",\"walIdentity\":\""<<DeriveVolumePhysicalRecoveryIdentity(fixture.file->binding,r.container_uuid,r.volume_oid)<<"\"}";
    Check(oracle.good(),"actual native binding codec oracle");
}
void Dispatch(VolumeImageOperation operation){
    PhysicalFixture f(operation==VolumeImageOperation::Erase?"dispatch-erase":"dispatch-format",operation);
    for(unsigned i=0;i<16;++i){f.file->binding.media.disk_guid[i]=std::byte(i+1);f.file->binding.media.partition_guid[i]=std::byte(0xa0+i);}
    f.source=VolumePhysicalKeeperTestPeer::Bind(f.file);ProductionPaths(f);unsigned calls=0;
    const auto before=f.Digests();
    auto malformed=Arguments(f,L"dry-run");Replace(malformed,L"--physical-device",L"");
    const auto bad=Invoke(f,std::move(malformed),calls);Check(bad.code==2 && calls==0 && !f.file->writes && !f.file->zeros,"empty selection rejects before factory and target");
    const auto plan=Invoke(f,Arguments(f,L"dry-run"),calls);SaveReply(f,"prepare",plan);
    Check(plan.code==0 && calls==1 && before==f.Digests() && !f.file->writes && !f.file->zeros,"actual physical CLI prepare preserves target: "+plan.text);
    const auto token=Token(plan);
    auto wrong=Arguments(f,L"apply",token);Replace(wrong,L"--physical-device",L"\\\\.\\PhysicalDrive0");
    const auto denied=Invoke(f,std::move(wrong),calls);SaveReply(f,"wrong-selection",denied);
    Check(denied.code==1 && before==f.Digests() && !f.file->writes && !f.file->zeros,"wrong selected alias preserves prepared evidence and target");
    auto cut=Arguments(f,L"apply",token);cut.insert(cut.end(),{L"--interrupt-at",L"after-image-accept"});
    const auto interrupted=Invoke(f,std::move(cut),calls);SaveReply(f,"accepted-cut",interrupted);
    Check(interrupted.code==3 && before==f.Digests() && !f.file->writes && !f.file->zeros,"actual original acceptance cut precedes target publication");
    const auto recovered=Invoke(f,Arguments(f,L"recover"),calls);SaveReply(f,"recovered",recovered);
    Check(recovered.code==0 && f.file->writes && !f.file->escaped && f.file->Current(),"physical CLI forward recovery and unrelated ranges: "+recovered.text);
    const auto cp=mc::Load(*f.source);mc::Verify(*f.source,cp);
    Check(cp.container.superblock.uuid_hex==f.request.new_container_uuid && cp.volumes.size()==1,"physical CLI exact canonical destination");
    if(operation==VolumeImageOperation::Erase)Check(f.file->zeros>0,"erase uses sparse zero-range sink");
    auto history=AcquireVolumeKeeperPhysicalHistory(f.source,*f.source,f.request.journal_directory,{}, {},{}, {},f.request.history_context,true);
    mc::NativeWrite(*f.source);const auto later=mc::Load(*f.source);mc::Verify(*f.source,later);history.reset();
    const auto count=f.file->writes;const auto repeated=Invoke(f,Arguments(f,L"recover"),calls);SaveReply(f,"later-reopen",repeated);
    Check(repeated.code==0 && f.file->writes==count && !f.file->escaped && f.file->Current(),"completed physical history authorizes ordinary write and unchanged reopen");
}
}
int wmain(int argc,wchar_t** argv){try{
    Check(argc==2,"private actual software evidence root required");root=argv[1];std::filesystem::create_directories(root);
    Dispatch(VolumeImageOperation::Format);Dispatch(VolumeImageOperation::Erase);
    Pass("production physical CLI parser dispatch partitioned original WALs acceptance recovery native write and history reopen");
    std::cout<<"PASS groups="<<groups<<" checks="<<checks<<" hardware=0 simulatedAuthority=1\n";return 0;
}catch(const std::exception& e){std::cerr<<"FAIL checks="<<checks<<" "<<e.what()<<'\n';return 1;}}
