#define APFSACCESS_FSHOST_UNIT_TEST 1
#ifndef APFSACCESS_SYSTEM_DATA_TEST_MAIN
#define APFSACCESS_SYSTEM_DATA_TEST_MAIN "../src/main.cpp"
#endif
#include APFSACCESS_SYSTEM_DATA_TEST_MAIN

namespace {
unsigned checks=0;
void Check(bool ok,const char* message){++checks;if(!ok)throw std::runtime_error(message);}
Arguments Selection(const std::wstring& image,const std::wstring& lifetime)
{
    std::vector<std::wstring> strings={L"test",L"--device",image,L"--volume-oid",L"101",L"--container-id",std::wstring(32,L'a'),
        L"--system-data-image",L"--system-data-group",std::wstring(32,L'd'),L"--system-data-data-oid",L"102",L"--system-data-checkpoint-xid",L"20",
        L"--readonly",L"--write-backend",L"Disabled",L"--mount",lifetime+L"-mount",L"--parent-pid",std::to_wstring(GetCurrentProcessId()),
        L"--lifetime-file",lifetime,L"--startup-gate-file",lifetime+L"-gate",L"--startup-gate-token",std::wstring(64,L'b'),L"--status-file",lifetime+L"-status"};
    std::vector<wchar_t*> pointers;for(auto& text:strings)pointers.push_back(text.data());Arguments args;
    Check(ParseArgs(static_cast<int>(pointers.size()),pointers.data(),args),"explicit production SystemData ParseArgs");return args;
}
void Positive(const Arguments& args,HANDLE parent)
{
    MountContext c;c.args=args;Check(PrepareSystemDataMount(c,parent),"production PrepareSystemDataMount from canonical image");
    Check(c.system_data&&c.system_data->admitted.load()&&!c.metadata_store&&!c.tx_manager&&!c.payload_spool&&!c.native_write_enabled&&!c.overlay_write_enabled,
        "no writable owner, original journal or caller record authority");
    const auto status=SystemDataStatusJson(c);
    Check(status.find("ImageTableReadOnly")!=status.npos&&status.find("Unverified")!=status.npos,"capability distinguishes software route and genuine corpus");
    FSP_FILE_SYSTEM fs{};fs.UserContext=&c;FSP_FSCTL_FILE_INFO info{};void* h=nullptr;wchar_t payload[]=L"\\Users\\payload";
    Check(NT_SUCCESS(SystemDataOpen(&fs,payload,FILE_NON_DIRECTORY_FILE,FILE_READ_DATA,&h,&info))&&h,"production interface open routes Data file");
    const std::string expected="independently expected data-volume bytes\n";
    std::vector<char> bytes(4096);ULONG done=999;
    Check(NT_SUCCESS(SystemDataRead(&fs,h,bytes.data(),0,static_cast<ULONG>(bytes.size()),&done))&&
        std::string(bytes.data(),done)==expected,"actual production callback bytes independently expected");
    Check(info.FileSize==expected.size()&&info.IndexNumber&&info.FileAttributes&FILE_ATTRIBUTE_READONLY,"backing metadata and scoped kernel index");
    done=999;Check(SystemDataRead(&fs,h,bytes.data(),INT64_MAX,1,&done)==STATUS_INVALID_DEVICE_REQUEST&&done==0,"overflow read publishes zero bytes");
    done=999;Check(SystemDataServeInterface().Write(&fs,h,nullptr,0,1,FALSE,FALSE,&done,&info)==STATUS_MEDIA_WRITE_PROTECTED&&done==0,"production mutation callback refuses");
    SystemDataServeInterface().Close(&fs,h);h=nullptr;
    Check(SystemDataOpen(&fs,payload,0,FILE_WRITE_DATA,&h,&info)==STATUS_MEDIA_WRITE_PROTECTED&&!h,"write open refuses before handle publication");
    std::string path,error;std::vector<apfsaccess::rw::FirmlinkDirectoryEntry> entries;
    Check(c.system_data->session->TryWindowsPath(L"\\Users",path,error)&&path=="/Users"&&
        c.system_data->session->TryEnumerate(path,entries,error)&&entries.size()==1&&entries.front().windows_name==L"payload"&&
        entries.front().target.identity.volume.object_id==102,"product enumeration comes from paired Data root");
    Check(!c.system_data->session->TryWindowsPath(L"\\Users\\SystemOnly",path,error)&&path.empty(),"no hidden System namespace fallback");
    Check(!c.system_data->session->TryWindowsPath(L"\\Users\\payload:bogus",path,error)&&path.empty(),"no unsupported Windows stream coercion");
    c.system_data->Close();Check(!c.system_data->session&&!c.system_data->admitted.load(),"owner close releases image producer");
}
}
int wmain(int argc,wchar_t** argv)
{
    try {
        Check(argc==3,"pinned fixture directory and owned lifetime file required");
        const std::filesystem::path fixtures=argv[1];const auto args=Selection((fixtures/L"system-data.apfs").wstring(),argv[2]);
        HANDLE parent=OpenProcess(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,GetCurrentProcessId());
        Check(parent!=nullptr,"own parent observation handle");ScopeExit release{[&](){CloseHandle(parent);}};
        Positive(args,parent);Positive(args,parent);
        const auto refuse=[&](Arguments changed){MountContext c;c.args=std::move(changed);
            Check(!PrepareSystemDataMount(c,parent),"changed canonical selection refuses production admission");
            Check(!c.metadata_store&&!c.tx_manager&&!c.payload_spool&&!c.native_write_enabled&&!c.overlay_write_enabled,"refusal never creates mutation authority");};
        auto changed=args;changed.system_data.group=std::wstring(32,L'e');refuse(changed);
        changed=args;changed.system_data.checkpoint_xid=19;refuse(changed);
        changed=args;changed.container_id=std::wstring(32,L'e');refuse(changed);
        changed=args;std::swap(changed.volume_object_id,changed.system_data.data_oid);refuse(changed);
        for(const auto* name:{L"bad-table.apfs",L"wrong-role.apfs",L"missing-target.apfs",L"table-data-only.apfs"}){
            changed=args;changed.device=(fixtures/name).wstring();refuse(changed);
        }
        changed=args;changed.readonly=false;changed.readwrite=true;Check(!ValidateSystemDataArguments(changed),"RW flag refuses selection");
        changed=args;changed.write_backend=L"Native";Check(!ValidateSystemDataArguments(changed),"native backend flag refuses");
        changed=args;changed.encrypted.enabled=true;Check(!ValidateSystemDataArguments(changed),"encrypted mode cannot mix");
        changed=args;changed.fusion.enabled=true;Check(!ValidateSystemDataArguments(changed),"Fusion mode cannot mix");
        changed=args;changed.allow_raw_physical_write=true;Check(!ValidateSystemDataArguments(changed),"raw write flag refuses");
        changed=args;changed.device=L"\\\\.\\PhysicalDrive0";Check(!ValidateSystemDataArguments(changed),"raw device path refuses without opening");
        changed=args;changed.snapshot_xid=20;Check(!ValidateSystemDataArguments(changed),"snapshot selector cannot mix");
        std::cout<<"PASS "<<checks<<" checks: production SystemData selection/callbacks, actual canonical image/refusals and fresh owner\n";return 0;
    }catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<" after "<<checks<<" checks\n";return 1;}
}
