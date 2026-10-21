#pragma once

namespace encrypted_root_observation_cases
{
constexpr UINT32 Access=FILE_READ_ATTRIBUTES|READ_CONTROL|SYNCHRONIZE;
struct Request
{
    alignas(FSP_FSCTL_TRANSACT_REQ) std::array<std::byte,FSP_FSCTL_TRANSACT_REQ_SIZEMAX> bytes{};
    FSP_FSCTL_TRANSACT_REQ& Get(){return *reinterpret_cast<FSP_FSCTL_TRANSACT_REQ*>(bytes.data());}
    Request()
    {
        auto& r=Get();r.Kind=FspFsctlTransactCreateKind;
        r.Req.Create.CreateOptions=(FILE_OPEN<<24)|FILE_DIRECTORY_FILE;
        r.Req.Create.DesiredAccess=Access;r.Req.Create.GrantedAccess=Access;
        Name(L"\\");
    }
    void Name(std::wstring_view name)
    {
        auto& r=Get();r.FileName.Offset=0;r.FileName.Size=static_cast<UINT16>((name.size()+1)*sizeof(WCHAR));
        r.Size=static_cast<UINT16>(offsetof(FSP_FSCTL_TRANSACT_REQ,Buffer)+r.FileName.Size);
        std::memset(r.Buffer,0,r.FileName.Size);std::memcpy(r.Buffer,name.data(),name.size()*sizeof(WCHAR));
    }
};
template<class Work> void UnderBothLocks(FSP_FILE_SYSTEM& fs,enc::State& state,Work work,bool expect_fast=true)
{
    std::atomic<bool> done=false;std::exception_ptr failure;
    std::unique_lock callbacks(state.callbacks);AcquireSRWLockExclusive(&fs.OpGuardLock);
    std::jthread worker([&](){try{work();}catch(...){failure=std::current_exception();}done=true;});
    const auto deadline=GetTickCount64()+500;
    while(!done.load() && GetTickCount64()<deadline)Sleep(1);
    const bool fast=done.load();ReleaseSRWLockExclusive(&fs.OpGuardLock);callbacks.unlock();worker.join();
    if(failure)std::rethrow_exception(failure);
    CHECK(fast==expect_fast);
}
struct Sdk
{
    HMODULE module=nullptr;
    FSP_FILE_SYSTEM_OPERATION *create=nullptr,*volume=nullptr;
    FSP_FILE_SYSTEM_OPERATION_GUARD *enter=nullptr,*leave=nullptr;
    ~Sdk(){if(module)FreeLibrary(module);}
    Sdk()
    {
        constexpr wchar_t path[]=L"C:\\Program Files (x86)\\WinFsp\\bin\\winfsp-x64.dll";
        module=LoadLibraryW(path);CHECK(module);
        wchar_t actual[32768]{};CHECK(GetModuleFileNameW(module,actual,32768) && _wcsicmp(actual,path)==0);
        create=reinterpret_cast<FSP_FILE_SYSTEM_OPERATION*>(GetProcAddress(module,"FspFileSystemOpCreate"));
        volume=reinterpret_cast<FSP_FILE_SYSTEM_OPERATION*>(GetProcAddress(module,"FspFileSystemOpQueryVolumeInformation"));
        enter=reinterpret_cast<FSP_FILE_SYSTEM_OPERATION_GUARD*>(GetProcAddress(module,"FspFileSystemOpEnter"));
        leave=reinterpret_cast<FSP_FILE_SYSTEM_OPERATION_GUARD*>(GetProcAddress(module,"FspFileSystemOpLeave"));
        CHECK(create && volume && enter && leave);
    }
};
NTSTATUS Dispatch(FSP_FILE_SYSTEM& fs,Request& request,FSP_FILE_SYSTEM_OPERATION* operation,PVOID* handle=nullptr)
{
    alignas(FSP_FSCTL_TRANSACT_RSP) std::array<std::byte,FSP_FSCTL_TRANSACT_RSP_SIZEMAX> bytes{};
    auto& response=*reinterpret_cast<FSP_FSCTL_TRANSACT_RSP*>(bytes.data());auto& r=request.Get();
    response.Size=sizeof response;response.Kind=r.Kind;
    const auto status=fs.EnterOperation(&fs,&r,&response);CHECK(status==STATUS_SUCCESS);
    CHECK(g_root_observation_guard_bypass.fs==&fs && g_root_observation_guard_bypass.request==&r);
    NTSTATUS result=STATUS_UNSUCCESSFUL,leave_status=STATUS_UNSUCCESSFUL;
    {ScopeExit leave{[&](){leave_status=fs.LeaveOperation(&fs,&r,&response);}};
     result=operation(&fs,&r,&response);
     if(handle)*handle=reinterpret_cast<PVOID>(static_cast<UINT_PTR>(response.Rsp.Create.Opened.UserContext));}
    CHECK(leave_status==STATUS_SUCCESS && !g_root_observation_guard_bypass.fs && !g_root_observation_guard_bypass.request);
    return result;
}
void Run()
{
    ++groups;
    auto source=EncFixture();const auto original=source->image;
    MountContext c;BindMemory(c,source);auto& state=*c.encrypted;
    ScopeExit release_security{[&](){LocalFree(c.sd);c.sd=nullptr;}};
    Sdk sdk;FSP_FILE_SYSTEM fs{};fs.Version=sizeof fs;fs.UserContext=&c;
    fs.OpGuardStrategy=FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FINE;InitializeSRWLock(&fs.OpGuardLock);
    fs.EnterOperation=sdk.enter;fs.LeaveOperation=sdk.leave;InstallOperationDiagnostics(&fs);
    HANDLE primary=nullptr,token=nullptr;
    CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_DUPLICATE,&primary));
    ScopeExit close_primary{[&](){CloseHandle(primary);}};
    CHECK(DuplicateTokenEx(primary,TOKEN_QUERY|TOKEN_IMPERSONATE|TOKEN_DUPLICATE,nullptr,SecurityImpersonation,TokenImpersonation,&token));
    ScopeExit close_token{[&](){CloseHandle(token);}};
    const auto reads=source->reads;
    for(const auto* iface:{&EncryptedServeInterface(),&EncryptedWritableServeInterface()})
    {
        fs.Interface=iface;
        UnderBothLocks(fs,state,[&](){
            Request request;auto& r=request.Get();r.Req.Create.GrantedAccess=0;r.Req.Create.UserMode=1;
            r.Req.Create.ShareAccess=FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE;
            r.Req.Create.AccessToken=(static_cast<UINT64>(GetCurrentProcessId())<<32)|static_cast<UINT32>(reinterpret_cast<UINT_PTR>(token));
            PVOID opened=nullptr;CHECK(Dispatch(fs,request,sdk.create,&opened)==STATUS_SUCCESS);CHECK(opened);
            ScopeExit close{[&](){iface->Close(&fs,opened);}};
            CHECK(static_cast<enc::Handle*>(opened)->cached_root_observation);
            CHECK(!static_cast<enc::Handle*>(opened)->open_entry);
            FSP_FSCTL_FILE_INFO info{};CHECK(iface->GetFileInfo(&fs,opened,&info)==STATUS_SUCCESS);
            CHECK(info.IndexNumber==state.names.root_inode_id && (info.FileAttributes&FILE_ATTRIBUTE_DIRECTORY));
            CHECK(iface->Flush(&fs,opened,&info)==STATUS_SUCCESS);
            SIZE_T size=0;CHECK(iface->GetSecurity(&fs,opened,nullptr,&size)==STATUS_BUFFER_OVERFLOW && size==c.sd_size);
            std::array<std::byte,128> data{};ULONG done=99;
            CHECK(iface->Read(&fs,opened,data.data(),0,1,&done)==STATUS_ACCESS_DENIED && done==0);
            CHECK(iface->ReadDirectory(&fs,opened,nullptr,nullptr,data.data(),static_cast<ULONG>(data.size()),&done)==STATUS_ACCESS_DENIED);
            CHECK(iface->GetStreamInfo(&fs,opened,data.data(),static_cast<ULONG>(data.size()),&done)==STATUS_ACCESS_DENIED);
            if(iface==&EncryptedWritableServeInterface()) {
                CHECK(iface->SetBasicInfo(&fs,opened,FILE_ATTRIBUTE_NORMAL,0,0,0,0,&info)==STATUS_ACCESS_DENIED);
                CHECK(iface->SetFileSize(&fs,opened,1,FALSE,&info)==STATUS_ACCESS_DENIED);
                CHECK(iface->Write(&fs,opened,data.data(),0,1,FALSE,FALSE,&done,&info)==STATUS_ACCESS_DENIED && done==0);
                CHECK(iface->SetDelete(&fs,opened,nullptr,TRUE)==STATUS_ACCESS_DENIED);
            }
            iface->Cleanup(&fs,opened,nullptr,0);iface->Cleanup(&fs,opened,nullptr,0);
            Request volume;volume.Get().Kind=FspFsctlTransactQueryVolumeInformationKind;
            // This memory fixture has a read session, not a fabricated Runtime.
            // The RW volume callback must refuse that missing owner immediately.
            CHECK(Dispatch(fs,volume,sdk.volume)==(iface==&EncryptedServeInterface()?STATUS_SUCCESS:STATUS_INVALID_PARAMETER));
        });
        CHECK(state.open_entries.empty() && state.pending_deletes.load()==0 && !state.failed.load());
    }
    Request eligible;CHECK(IsCachedRootObservationRequest(c,fs,eligible.Get()));
    // A real SDK-delegated nonroot FILE_OPEN still waits behind the writer SRW lock.
    UnderBothLocks(fs,state,[&](){
        Request nonroot;nonroot.Name(L"\\child");
        alignas(FSP_FSCTL_TRANSACT_RSP) std::array<std::byte,FSP_FSCTL_TRANSACT_RSP_SIZEMAX> response{};
        auto* rsp=reinterpret_cast<FSP_FSCTL_TRANSACT_RSP*>(response.data());auto& r=nonroot.Get();
        CHECK(fs.EnterOperation(&fs,&r,rsp)==STATUS_SUCCESS);CHECK(!g_root_observation_guard_bypass.fs);
        CHECK(fs.LeaveOperation(&fs,&r,rsp)==STATUS_SUCCESS);
    },false);
    // Nested original delegation must not consume or overwrite the outer bypass.
    {
        Request outer,nested;
        alignas(FSP_FSCTL_TRANSACT_RSP) std::array<std::byte,FSP_FSCTL_TRANSACT_RSP_SIZEMAX> response{};
        auto* rsp=reinterpret_cast<FSP_FSCTL_TRANSACT_RSP*>(response.data());
        CHECK(fs.EnterOperation(&fs,&outer.Get(),rsp)==STATUS_SUCCESS);
        CHECK(fs.EnterOperation(&fs,&nested.Get(),rsp)==STATUS_SUCCESS);
        CHECK(g_root_observation_guard_bypass.request==&outer.Get());
        CHECK(fs.LeaveOperation(&fs,&nested.Get(),rsp)==STATUS_SUCCESS);
        CHECK(g_root_observation_guard_bypass.request==&outer.Get());
        CHECK(fs.LeaveOperation(&fs,&outer.Get(),rsp)==STATUS_SUCCESS && !g_root_observation_guard_bypass.fs);
    }
    // Bypassing the operation lock must still run the real SDK AccessCheck.
    {
        PSECURITY_DESCRIPTOR denied=nullptr;
        CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:BAD:P(D;;0x120080;;;WD)(A;;FA;;;WD)",
            SDDL_REVISION_1,&denied,nullptr));
        auto* saved=c.sd;const auto saved_size=c.sd_size;c.sd=denied;c.sd_size=GetSecurityDescriptorLength(denied);
        ScopeExit restore{[&](){c.sd=saved;c.sd_size=saved_size;LocalFree(denied);}};
        UnderBothLocks(fs,state,[&](){
            Request denied_request;auto& r=denied_request.Get();r.Req.Create.UserMode=1;r.Req.Create.GrantedAccess=0;
            r.Req.Create.ShareAccess=FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE;
            r.Req.Create.AccessToken=(static_cast<UINT64>(GetCurrentProcessId())<<32)|static_cast<UINT32>(reinterpret_cast<UINT_PTR>(token));
            PVOID opened=nullptr;CHECK(Dispatch(fs,denied_request,sdk.create,&opened)==STATUS_ACCESS_DENIED && !opened);
        });
    }
    const auto rejected=[&](auto change){Request r;change(r);CHECK(!IsCachedRootObservationRequest(c,fs,r.Get()));};
    rejected([](Request& r){r.Name(L"\\.");});rejected([](Request& r){r.Name(L"\\child");});
    rejected([](Request& r){r.Get().Req.Create.DesiredAccess|=FILE_LIST_DIRECTORY;});
    rejected([](Request& r){r.Get().Req.Create.GrantedAccess|=FILE_WRITE_ATTRIBUTES;});
    rejected([](Request& r){r.Get().Req.Create.CreateOptions|=FILE_DELETE_ON_CLOSE;});
    rejected([](Request& r){r.Get().Req.Create.CreateOptions=(FILE_OPEN_IF<<24);});
    rejected([](Request& r){r.Get().Req.Create.Ea.Size=1;});
    rejected([](Request& r){r.Get().Req.Create.SecurityDescriptor.Size=1;});
    rejected([](Request& r){r.Get().Req.Create.AllocationSize=1;});
    rejected([](Request& r){r.Get().Req.Create.NamedStream=1;});
    rejected([](Request& r){--r.Get().Size;});
    c.args.fusion.enabled=true;CHECK(!IsCachedRootObservationRequest(c,fs,eligible.Get()));c.args.fusion.enabled=false;
    c.args.snapshot_xid=1;CHECK(!IsCachedRootObservationRequest(c,fs,eligible.Get()));c.args.snapshot_xid=0;
    fs.OpGuardStrategy=FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_COARSE;
    CHECK(!IsCachedRootObservationRequest(c,fs,eligible.Get()));fs.OpGuardStrategy=FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FINE;
    const auto attributes=state.root_attributes.exchange(0);CHECK(!IsCachedRootObservationRequest(c,fs,eligible.Get()));state.root_attributes=attributes;
    CHECK(source->reads==reads && source->image==original);
    const auto before=CaptureCallbackStatusSnapshot(c);state.Fail(enc::State::Failure::CachedRootMutationRequested);
    const auto after=CaptureCallbackStatusSnapshot(c);
    CHECK(after.encrypted_failure_tick_ms==state.FailureTickMs() && !CallbackStatusSnapshotsEqual(before,after));
    UnderBothLocks(fs,state,[&](){
        PVOID opened=nullptr;FSP_FSCTL_FILE_INFO info{};
        auto& r=eligible.Get();alignas(FSP_FSCTL_TRANSACT_RSP) std::array<std::byte,FSP_FSCTL_TRANSACT_RSP_SIZEMAX> response{};
        auto* rsp=reinterpret_cast<FSP_FSCTL_TRANSACT_RSP*>(response.data());
        CHECK(fs.EnterOperation(&fs,&r,rsp)==STATUS_SUCCESS);
        CHECK(EncryptedWritableServeInterface().Open(&fs,const_cast<PWSTR>(L"\\"),r.Req.Create.CreateOptions,Access,&opened,&info)==STATUS_CANCELLED && !opened);
        CHECK(fs.LeaveOperation(&fs,&r,rsp)==STATUS_SUCCESS);
    });
    CHECK(source->reads==reads && source->image==original && state.open_entries.empty());
}
}
