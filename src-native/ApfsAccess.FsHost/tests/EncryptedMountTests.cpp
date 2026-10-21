// Includes the actual host parser, owned admission, interface and callbacks.
// External WinFsp functions are replaced only at the dispatcher boundary.
#define APFSACCESS_FSHOST_UNIT_TEST 1
#include "../src/main.cpp"
#define main encrypted_engine_neighbor_main
#include "ApfsEncryptedReadSessionTests.cpp"
#undef main

namespace encrypted_mount
{
struct DeadlineStateTestAccess
{
    // Unit-only synthetic authority for the common State deadline path. Native
    // callback cases below separately require actual privately minted events.
    static bool Complete(State::Operation& operation,const apfsaccess::catalog::EncryptedImageRuntime& owner,
        std::uint64_t invocation,std::uint64_t ordinal,unsigned slot,ULONGLONG now)
    {return operation.CompleteAt(owner,invocation,ordinal,static_cast<OperationDeadline::Boundary>(slot),now);}
};
}

namespace {
const auto& ei=EncryptedServeInterface();
BOOLEAN AddEncDir(FSP_FSCTL_DIR_INFO* d,PVOID buffer,ULONG size,PULONG done)
{
    if(!d) return TRUE;
    if(d->Size>size-*done) return FALSE;
    std::memcpy(static_cast<std::byte*>(buffer)+*done,d,d->Size); *done+=d->Size; return TRUE;
}
BOOLEAN AddEncStream(FSP_FSCTL_STREAM_INFO* d,PVOID buffer,ULONG size,PULONG done)
{
    if(!d) return TRUE;
    if(d->Size>size-*done) return FALSE;
    std::memcpy(static_cast<std::byte*>(buffer)+*done,d,d->Size); *done+=d->Size; return TRUE;
}
auto EncFixture(std::uint64_t features=1)
{
    auto source=std::make_shared<Source>(); auto records=NamespaceRecords(features);
    RenameNamespaceEntry(records,"Report.txt","Straße",features);
    RenameNamespaceEntry(records,"Alias.txt","é.txt",features);
    std::string error; BtreeRecord record;
    CHECK(apfsaccess::rw::EncodeAppleXattrRecord({100,"com.apple.ResourceFork",apfsaccess::rw::kAppleXattrDataEmbedded,NamespacePayload()},record,error));
    records.push_back(std::move(record));
    InstallNamespace(source,std::move(records),features); return source;
}
void SaveEncFixture(const std::filesystem::path& path, bool long_label=false)
{
    auto source=EncFixture();
    if(long_label) source->MutateAt(4,[](auto& block) {
        const std::string label=std::string(18,'A')+"\xF0\x9F\x98\x80"+"tail";
        std::fill_n(block.begin()+0x2c0,256,std::byte{});
        std::memcpy(block.data()+0x2c0,label.data(),label.size());
    });
    auto bytes=source->image;
    std::copy(source->root.begin(),source->root.end(),bytes.begin()+80*4096);
    std::copy(source->data.begin(),source->data.end(),bytes.begin()+100*4096);
    std::ofstream out(path,std::ios::binary); out.write(reinterpret_cast<const char*>(bytes.data()),bytes.size()); CHECK(bool(out));
}
void BindMemory(MountContext& c,const std::shared_ptr<Source>& source)
{
    c.args.encrypted.enabled=true; c.args.readonly=true; c.args.incompatible_features=1;
    c.encrypted=std::make_unique<enc::State>(); auto& s=*c.encrypted;
    E error; UnlockError unlock; PasswordUnlockBudget attempts;
    s.session=ApfsEncryptedReadSession::Unlock(source,source->identity,source->revision,Request(),Hex(k::Password),attempts,error,unlock,s.cancelled);
    CHECK(s.session); CHECK(s.session->GetNamespaceInfo(s.names)==E::None);
    CHECK(EncCacheRootAttributes(s));
    c.sd=BuildWritableVolumeSecurityDescriptor(&c.sd_size); CHECK(c.sd);
    c.api.AddDir=AddEncDir; c.api.AddStream=AddEncStream; c.label=L"Data (read-only)";
}
void CallbackCases(MountContext& c)
{
    ++groups;
    FSP_FILE_SYSTEM fs{};fs.UserContext=&c; FSP_FSCTL_FILE_INFO info{};
    std::vector<PVOID> handles;
    ScopeExit cleanup{[&](){for(auto h:handles)ei.Close(&fs,h);}};
    auto open=[&](std::wstring name) {
        PVOID h=nullptr; const auto st=ei.Open(&fs,name.data(),FILE_OPEN<<24,GENERIC_READ,&h,&info);
        CHECK(st==STATUS_SUCCESS); CHECK(h); handles.push_back(h); return h;
    };
    auto root=open(L"\\"); auto file=open(L"\\STRASSE"); auto alias=open(L"\\é.txt"); auto other=open(L"\\Folder\\.\\Other.txt");
    auto dot=open(L"\\Folder\\..\\Straße");
    const auto* fh=static_cast<enc::Handle*>(file); const auto* ah=static_cast<enc::Handle*>(alias);
    CHECK(fh->node.inode_id==ah->node.inode_id && fh->sibling!=ah->sibling);
    CHECK(fh->node.uid==501 && fh->node.gid==20 && fh->node.mode==0100640 && fh->node.children_or_links==3);
    CHECK(fh->entry_parent==2 && static_cast<enc::Handle*>(other)->entry_parent==10);
    CHECK(ei.GetFileInfo(&fs,file,&info)==STATUS_SUCCESS && info.IndexNumber==100 && info.HardLinks==3 && info.FileSize==700);
    CHECK(info.FileAttributes&FILE_ATTRIBUTE_READONLY);
    CHECK(info.LastAccessTime==116444736000000004ULL);
    std::array<std::byte,1024> bytes{};ULONG done=0;
    for(auto h:{file,alias,other,dot}) {
        CHECK(ei.Read(&fs,h,bytes.data(),509,900,&done)==STATUS_SUCCESS && done==191);
        for(std::size_t n=0;n<done;++n) CHECK(bytes[n]==std::byte(((n+509)*7+3)%256));
    }
    CHECK(ei.Read(&fs,file,bytes.data(),700,1,&done)==STATUS_END_OF_FILE && !done);
    CHECK(ei.Read(&fs,file,bytes.data(),UINT64_MAX,1,&done)==STATUS_END_OF_FILE && !done);
    CHECK(ei.Read(&fs,file,bytes.data(),700,0,&done)==STATUS_SUCCESS && !done);
    auto resource=open(L"\\Straße:APFS.ResourceFork:$DATA");
    CHECK(ei.Read(&fs,resource,bytes.data(),0,1024,&done)==STATUS_SUCCESS && done==173);
    CHECK(std::equal(bytes.begin(),bytes.begin()+done,NamespacePayload().begin()));
    // WinFsp removes the stream type before dispatching a real Windows open.
    for (const auto suffix : {L":APFS.ResourceFork", L":apfs.resourcefork:$data",
             L":APFS.Xattr.636F6D2E6170706C652E5265736F75726365466F726B"}) {
        auto normalized = open(std::wstring(L"\\Straße") + suffix);
        CHECK(ei.Read(&fs,normalized,bytes.data(),0,1024,&done)==STATUS_SUCCESS && done==173);
        CHECK(std::equal(bytes.begin(),bytes.begin()+done,NamespacePayload().begin()));
    }
    for (const auto suffix : {L":APFS.ResourceFork:$INDEX_ALLOCATION", L":APFS.ResourceFork:$DATA:$DATA",
             L":APFS.Xattr.00", L":APFS.Xattr.FF", L":APFS.Xattr.1", L":APFS.Xattr.", L":APFS.Xattr.ZZ"}) {
        auto malformed = std::wstring(L"\\Straße") + suffix;
        PVOID rejected = nullptr;
        CHECK(ei.Open(&fs,malformed.data(),FILE_OPEN<<24,GENERIC_READ,&rejected,&info)==STATUS_OBJECT_NAME_INVALID);
        CHECK(!rejected);
    }
    auto protocol=open(L"\\Straße:APFS.XattrProtocol:$DATA");
    CHECK(ei.Read(&fs,protocol,bytes.data(),0,1024,&done)==STATUS_SUCCESS && done==13);
    CHECK(std::memcmp(bytes.data(),"APFS-XATTR/1\n",13)==0);
    auto normalized_protocol=open(L"\\Straße:apfs.xattrprotocol");
    CHECK(ei.Read(&fs,normalized_protocol,bytes.data(),0,1024,&done)==STATUS_SUCCESS && done==13);
    CHECK(std::memcmp(bytes.data(),"APFS-XATTR/1\n",13)==0);
    auto empty=open(L"\\:APFS.Xattr.757365722E656D707479:$DATA");
    CHECK(ei.Read(&fs,empty,bytes.data(),0,10,&done)==STATUS_END_OF_FILE && !done);
    auto normalized_empty=open(L"\\:APFS.Xattr.757365722E656D707479");
    CHECK(ei.Read(&fs,normalized_empty,bytes.data(),0,10,&done)==STATUS_END_OF_FILE && !done);
    for(const auto path : {L"\\.:APFS.XattrProtocol", L"\\Folder\\..:APFS.XattrProtocol:$DATA"}) {
        auto root_protocol=open(path);
        CHECK(info.IndexNumber==2);
        CHECK(ei.Read(&fs,root_protocol,bytes.data(),0,1024,&done)==STATUS_SUCCESS && done==13);
        CHECK(std::memcmp(bytes.data(),"APFS-XATTR/1\n",13)==0);
    }
    auto root_empty=open(L"\\.:APFS.Xattr.757365722E656D707479:$DATA");
    CHECK(ei.Read(&fs,root_empty,bytes.data(),0,10,&done)==STATUS_END_OF_FILE && !done);
    auto x=open(L"\\Straße"+EncStreamName("user.note"));
    { allocation_observer::Watch watch(NamespacePayload());
      CHECK(ei.Read(&fs,x,bytes.data(),0,1024,&done)==STATUS_SUCCESS && done==173);
      auto result=watch.Stop(); CHECK(!result.intact && !result.live && result.zero>0); }
    std::array<std::byte,4096> dir{};
    CHECK(ei.ReadDirectory(&fs,root,nullptr,nullptr,dir.data(),static_cast<ULONG>(sizeof(FSP_FSCTL_DIR_INFO)+2),&done)==STATUS_SUCCESS);
    CHECK(done>0); auto* first=reinterpret_cast<FSP_FSCTL_DIR_INFO*>(dir.data());
    CHECK(first->FileNameBuf[0]==L'.' && first->Size==done);
    auto marker=std::wstring(L".");
    CHECK(ei.ReadDirectory(&fs,root,nullptr,marker.data(),dir.data(),static_cast<ULONG>(dir.size()),&done)==STATUS_SUCCESS && done>0);
    unsigned rows=0; for(ULONG at=0;at<done;) {auto* d=reinterpret_cast<FSP_FSCTL_DIR_INFO*>(dir.data()+at);CHECK(d->Size);++rows;at+=d->Size;}
    CHECK(rows==4); CHECK(static_cast<enc::Handle*>(root)->cursor==5);
    auto root2=open(L"\\"); CHECK(!static_cast<enc::Handle*>(root2)->enumerated);
    CHECK(ei.ReadDirectory(&fs,root2,nullptr,nullptr,dir.data(),static_cast<ULONG>(dir.size()),&done)==STATUS_SUCCESS);
    CHECK(ei.GetStreamInfo(&fs,file,dir.data(),static_cast<ULONG>(dir.size()),&done)==STATUS_SUCCESS && done>0);
    unsigned streams=0;for(ULONG at=0;at<done;){auto* si=reinterpret_cast<FSP_FSCTL_STREAM_INFO*>(dir.data()+at);CHECK(si->Size);++streams;at+=si->Size;} CHECK(streams==4);
    SIZE_T size=0;UINT32 attrs=0;auto name=std::wstring(L"\\Straße");
    CHECK(ei.GetSecurityByName(&fs,name.data(),&attrs,nullptr,&size)==STATUS_BUFFER_OVERFLOW && size>0);
    std::vector<std::byte> sd(size);CHECK(ei.GetSecurity(&fs,file,sd.data(),&size)==STATUS_SUCCESS);
    FSP_FSCTL_VOLUME_INFO vi{};CHECK(ei.GetVolumeInfo(&fs,&vi)==STATUS_SUCCESS && vi.FreeSize==0 && vi.TotalSize==0);
    CHECK(vi.VolumeLabelLength && std::wstring_view(vi.VolumeLabel,vi.VolumeLabelLength/2).ends_with(L"(read-only)"));
    FSP_FSCTL_VOLUME_PARAMS vp{}; FILETIME now{};ConfigureVolumeParamsForExplorer(c,now,vp);
    CHECK(vp.ReadOnlyVolume && vp.NamedStreams && !vp.PersistentAcls && !vp.CaseSensitiveSearch && !vp.ReparsePoints);
    const auto deny=[&](NTSTATUS st){CHECK(st==STATUS_MEDIA_WRITE_PROTECTED);};
    PVOID invalid=nullptr; deny(ei.Create(&fs,name.data(),0,0,0,nullptr,0,&invalid,&info));CHECK(!invalid);
    for(auto access:std::array<UINT32,8>{GENERIC_WRITE,DELETE,WRITE_DAC,WRITE_OWNER,FILE_WRITE_DATA,FILE_WRITE_ATTRIBUTES,FILE_WRITE_EA,FILE_APPEND_DATA})
        deny(ei.Open(&fs,name.data(),0,access,&invalid,&info));
    deny(ei.Open(&fs,name.data(),FILE_DELETE_ON_CLOSE,GENERIC_READ,&invalid,&info));
    deny(ei.Write(&fs,file,bytes.data(),0,1,FALSE,FALSE,&done,&info));CHECK(!done);
    deny(ei.Overwrite(&fs,file,0,FALSE,0,&info));deny(ei.SetBasicInfo(&fs,file,0,0,0,0,0,&info));
    deny(ei.CreateEx(&fs,name.data(),0,0,0,nullptr,0,nullptr,0,FALSE,&invalid,&info));
    deny(ei.OverwriteEx(&fs,file,0,FALSE,0,nullptr,0,&info));deny(ei.SetEa(&fs,file,nullptr,0,&info));
    deny(ei.SetFileSize(&fs,file,0,FALSE,&info));deny(ei.SetFileSize(&fs,file,4096,TRUE,&info));
    deny(ei.CanDelete(&fs,file,name.data()));deny(ei.SetDelete(&fs,file,name.data(),TRUE));deny(ei.SetDelete(&fs,file,name.data(),FALSE));
    deny(ei.Rename(&fs,file,name.data(),name.data(),FALSE));deny(ei.SetSecurity(&fs,file,DACL_SECURITY_INFORMATION,c.sd));
    deny(ei.SetReparsePoint(&fs,file,name.data(),bytes.data(),1));deny(ei.DeleteReparsePoint(&fs,file,name.data(),bytes.data(),1));
    deny(ei.SetVolumeLabel(&fs,name.data(),&vi));deny(ei.Control(&fs,file,0,nullptr,0,nullptr,0,&done));
    CHECK(ei.Flush(&fs,file,&info)==STATUS_SUCCESS);
    CHECK(ei.Flush(&fs,nullptr,nullptr)==STATUS_SUCCESS);
    ei.Cleanup(&fs,file,name.data(),FspCleanupDelete);
    CHECK(ei.Read(&fs,file,bytes.data(),0,1,&done)==STATUS_SUCCESS);
    CHECK(!c.metadata_store && !c.tx_manager && !c.payload_spool && c.session_root.empty() && c.cache_root.empty());
}
void ProductionRuntimeReads(MountContext& c)
{
    ++groups;
    CHECK(c.encrypted && c.encrypted->source);
    const auto original_budget = c.encrypted->source->ReadBudget();
    original_budget->LimitRemainingTo(0, 0, 0, 0);
    CHECK(!original_budget->Failed());
    CallbackCases(c);
    FSP_FILE_SYSTEM fs{}; fs.UserContext = &c;
    FSP_FSCTL_FILE_INFO info{}; PVOID handle = nullptr;
    std::wstring name = L"\\STRASSE";
    CHECK(ei.Open(&fs, name.data(), 0, GENERIC_READ, &handle, &info) == STATUS_SUCCESS);
    ScopeExit close{[&]() { ei.Close(&fs, handle); }};
    std::array<std::byte, 700> bytes{};
    for (unsigned round = 0; round < 256; ++round)
    {
        ULONG done = 0;
        CHECK(ei.Read(&fs, handle, bytes.data(), 0, static_cast<ULONG>(bytes.size()), &done) == STATUS_SUCCESS);
        CHECK(done == bytes.size());
        for (std::size_t i = 0; i < bytes.size(); ++i)
            CHECK(bytes[i] == std::byte((i * 7 + 3) % 256));
    }
    CHECK(c.encrypted->source->ReadBudget() == original_budget && !original_budget->Failed());
    CHECK(!c.encrypted->failed && !c.encrypted->cancelled->load());
}
void FaultCases()
{
    ++groups;
    for(unsigned fault=0;fault<4;++fault) {
        MountContext c;auto source=EncFixture();BindMemory(c,source);FSP_FILE_SYSTEM fs{};fs.UserContext=&c;
        FSP_FSCTL_FILE_INFO info{};PVOID handle=nullptr;auto name=std::wstring(L"\\Straße");
        CHECK(ei.Open(&fs,name.data(),0,GENERIC_READ,&handle,&info)==STATUS_SUCCESS);
        if(fault==0) ++source->revision;
        if(fault==1) c.encrypted->Cancel();
        if(fault==2) {source->fault_offset=100*4096;source->fault=2;}
        if(fault==3) source->identity+="changed";
        std::array<std::byte,10> bytes{};ULONG done=9;
        CHECK(!NT_SUCCESS(ei.Read(&fs,handle,bytes.data(),0,10,&done)) && done==0);
        CHECK(c.encrypted->cancelled->load());
        CHECK(!NT_SUCCESS(ei.GetFileInfo(&fs,handle,&info)));
        ei.Close(&fs,handle);LocalFree(c.sd);c.sd=nullptr;
    }
    // Exact sensitive volume still refuses case folding in the actual adapter.
    MountContext c;BindMemory(c,EncFixture(0));c.args.incompatible_features=0;
    FSP_FILE_SYSTEM fs{};fs.UserContext=&c;PVOID h=nullptr;FSP_FSCTL_FILE_INFO info{};auto name=std::wstring(L"\\STRASSE");
    CHECK(ei.Open(&fs,name.data(),0,GENERIC_READ,&h,&info)==STATUS_OBJECT_NAME_NOT_FOUND && !h);
    LocalFree(c.sd);c.sd=nullptr;
}
void CancelHeldRead()
{
    ++groups;MountContext c;auto source=EncFixture();BindMemory(c,source);
    FSP_FILE_SYSTEM fs{};fs.UserContext=&c;PVOID h=nullptr;FSP_FSCTL_FILE_INFO info{};auto name=std::wstring(L"\\Straße");
    CHECK(ei.Open(&fs,name.data(),0,GENERIC_READ,&h,&info)==STATUS_SUCCESS);
    std::atomic<bool> entered=false,release=false;
    source->before=[&](std::uint64_t offset) {
        if(offset==100*4096) {entered=true;while(!release)Sleep(1);}
    };
    std::array<std::byte,10> bytes{};ULONG done=99;NTSTATUS result=STATUS_UNSUCCESSFUL;
    std::jthread reader([&](){result=ei.Read(&fs,h,bytes.data(),0,10,&done);});
    const auto deadline=GetTickCount64()+5000;while(!entered && GetTickCount64()<deadline)Sleep(1);
    const bool held=entered && c.active_callback_count==1;
    c.encrypted->Cancel();release=true;reader.join();
    CHECK(held && result==STATUS_CANCELLED && done==0 && c.active_callback_count==0);
    CHECK(std::all_of(bytes.begin(),bytes.end(),[](auto b){return b==std::byte{};}));
    ei.Close(&fs,h);LocalFree(c.sd);c.sd=nullptr;c.encrypted->Close();
    CHECK(c.encrypted->threads.empty() && !c.encrypted->session);
}
std::atomic<bool> enc_stopped=false,enc_release_stop=false,enc_removed=false,enc_deleted=false;
VOID StopEnc(FSP_FILE_SYSTEM*) {enc_stopped=true;while(!enc_release_stop)Sleep(1);}
VOID RemoveEnc(FSP_FILE_SYSTEM*) {enc_removed=true;}
VOID DeleteEnc(FSP_FILE_SYSTEM*) {enc_deleted=true;}
bool EncWriter(const std::wstring& image) {
    auto h=CreateFileW(image.c_str(),GENERIC_WRITE,7,nullptr,OPEN_EXISTING,0,nullptr);
    if(h==INVALID_HANDLE_VALUE)return false;CloseHandle(h);return true;
}
void Lifecycle(std::unique_ptr<MountContext>& owner)
{
    ++groups; auto& c=*owner;FSP_FILE_SYSTEM fs{};fs.UserContext=&c;c.fs=&fs;
    c.api.Stop=StopEnc;c.api.RemoveMount=RemoveEnc;c.api.Delete=DeleteEnc;
    c.winfsp_lifecycle_phase=WinFspLifecyclePhase::Dispatching;c.mount_ready=true;
    CHECK(WriteHostStatusFile(c));
    int result=-1;std::jthread drain([&](){result=RunFsHostShutdownDrain(owner);});
    const auto deadline=GetTickCount64()+5000;while(!enc_stopped && GetTickCount64()<deadline)Sleep(1);
    const bool reached=enc_stopped; const bool held=!EncWriter(c.args.device);
    enc_release_stop=true;drain.join();
    CHECK(reached && held && result==0 && enc_removed && enc_deleted && owner && !owner->fs);
    CHECK(EncWriter(c.args.device));CHECK(!c.encrypted->session && !c.encrypted->source);
    std::ifstream status(c.args.status_file);std::string json((std::istreambuf_iterator<char>(status)),{});
    CHECK(json.find("\"mountReady\":false")!=json.npos && json.find("\"immutableEncryptedImage\":true")!=json.npos);
}
}
#include "EncryptedReviewTests.h"
void EncryptedArgumentCases()
{
    ++groups;
    enc::Options options;
    CHECK(ParseEncryptedOption(L"--encrypted-container-bag-oid",L"0",options));
    CHECK(ParseEncryptedOption(L"--encrypted-volume-bag-oid",L"0",options));
    CHECK(options.container_bag_oid_supplied && options.volume_bag_oid_supplied);
    CHECK(!options.container_bag_oid && !options.volume_bag_oid);
    for(const auto key : {L"--encrypted-store-size",L"--encrypted-checkpoint-xid",
            L"--encrypted-container-bag-xid",L"--encrypted-volume-bag-xid"})
        CHECK(!ParseEncryptedOption(key,L"0",options));
    for(const auto value : {L"00",L"-1",L"+0",L" 0",L"0 ",L"18446744073709551616"})
        CHECK(!ParseEncryptedOption(L"--encrypted-container-bag-oid",value,options));
    Arguments args;
    args.encrypted=options;args.encrypted.enabled=true;
    args.device=L"D:\\private\\fixture.img";args.readonly=true;args.readwrite=false;
    args.write_backend=L"Disabled";args.container_id=std::wstring(32,L'1');args.volume_object_id=1026;
    args.mount=L"D:\\private\\mount";args.parent_pid=123;
    args.lifetime_file=L"D:\\private\\lifetime";args.startup_gate_file=L"D:\\private\\gate";
    args.startup_gate_token=L"gate";args.status_file=L"D:\\private\\status";
    auto& selected=args.encrypted;
    selected.source_id=L"image-test-v1";selected.volume_uuid=std::wstring(32,L'2');
    selected.user_uuid=std::wstring(32,L'3');selected.store_size=4096;selected.checkpoint=7;
    selected.container_bag_xid=2;selected.volume_bag_xid=2;selected.bag_length=L"includes-header";
    CHECK(ValidateEncryptedArguments(args));
    selected.container_bag_oid_supplied=false;CHECK(!ValidateEncryptedArguments(args));
    selected.container_bag_oid_supplied=true;selected.volume_bag_oid_supplied=false;
    CHECK(!ValidateEncryptedArguments(args));
    selected.volume_bag_oid_supplied=true;
    args.readonly=false;args.readwrite=true;CHECK(!ValidateEncryptedArguments(args));
    selected.write_root=L"D:\\private\\recovery";CHECK(ValidateEncryptedArguments(args));
    args.allow_raw_physical_write=true;CHECK(!ValidateEncryptedArguments(args));
    args.allow_raw_physical_write=false;args.device=L"\\\\.\\PhysicalDrive2";
    CHECK(!ValidateEncryptedArguments(args));
    args.device=L"D:\\private\\fixture.img";args.readonly=true;
    CHECK(!ValidateEncryptedArguments(args));
    args.readwrite=false;selected.write_root.clear();CHECK(ValidateEncryptedArguments(args));
}
void PendingDeleteReviewCases()
{
    ++groups;
    auto source=EncFixture();const auto original=source->image;
    MountContext c;BindMemory(c,source);FSP_FILE_SYSTEM fs{};fs.UserContext=&c;
    auto& state=*c.encrypted;const auto& writable=EncryptedWritableServeInterface();
    auto removed=std::make_shared<enc::OpenEntry>();removed->handles=2;removed->unlinked=true;
    state.open_entries.emplace(100,removed);
    auto first=new enc::Handle;first->node.inode_id=100;first->open_entry=removed;
    auto second=new enc::Handle;second->node.inode_id=100;second->open_entry=removed;
    writable.Cleanup(&fs,first,nullptr,FspCleanupDelete);
    writable.Cleanup(&fs,second,nullptr,FspCleanupDelete);
    CHECK(!removed->delete_pending && state.pending_deletes.load()==0);
    writable.Close(&fs,first);writable.Close(&fs,second);
    CHECK(state.open_entries.empty() && state.pending_deletes.load()==0 && !state.failed.load());
    auto pending=std::make_shared<enc::OpenEntry>();pending->handles=1;
    state.SetDeletePending(*pending,true);state.open_entries.emplace(100,pending);
    auto handle=new enc::Handle;handle->node.inode_id=100;handle->open_entry=pending;
    state.Cancel();writable.Close(&fs,handle);
    CHECK(state.open_entries.empty() && state.pending_deletes.load()==1);
    state.Close();CHECK(state.failed.load() && state.pending_deletes.load()==1);
    CHECK(std::string_view(state.FailureReasonName())=="PendingDeleteAtClose");
    CHECK(source->image==original);
    LocalFree(c.sd);c.sd=nullptr;
}
void StreamDeleteReviewCases()
{
    ++groups;
    auto source=EncFixture();const auto original=source->image;
    MountContext c;BindMemory(c,source);FSP_FILE_SYSTEM fs{};fs.UserContext=&c;
    auto& state=*c.encrypted;const auto& writable=EncryptedWritableServeInterface();
    std::vector<PVOID> handles;
    const auto open=[&](std::wstring name,NTSTATUS expected=STATUS_SUCCESS) {
        PVOID h=nullptr;FSP_FSCTL_FILE_INFO info{};
        CHECK(writable.Open(&fs,name.data(),0,GENERIC_READ,&h,&info)==expected);
        CHECK((h!=nullptr)==NT_SUCCESS(expected));
        if(h)handles.push_back(h);
        return static_cast<enc::Handle*>(h);
    };
    auto* handle=open(L"\\Stra\u00dfe:APFS.ResourceFork");
    auto* alias=open(L"\\Stra\u00dfe:APFS.Xattr.636F6D2E6170706C652E5265736F75726365466F726B");
    const auto entry=handle->open_entry;const auto stream=handle->open_stream;
    CHECK(alias->open_stream==stream && stream->active_handles==2 && stream->contexts==2);
    CHECK(writable.SetDelete(&fs,handle,nullptr,TRUE)==STATUS_SHARING_VIOLATION);
    CHECK(state.pending_deletes.load()==0);
    // Cleanup ends active sharing even when WinFsp retains the context until Close.
    writable.Cleanup(&fs,alias,nullptr,0);writable.Cleanup(&fs,alias,nullptr,0);
    CHECK(stream->active_handles==1 && stream->contexts==2);
    open(L"\\Stra\u00dfe");open(L"\\Stra\u00dfe:APFS.Xattr.757365722E6E6F7465");
    open(L"\\Stra\u00dfe:APFS.XattrProtocol");
    CHECK(entry->handles==5 && EncWritableDeleteAdmission(state,*handle)==STATUS_SUCCESS);
    CHECK(writable.SetDelete(&fs,handle,nullptr,TRUE)==STATUS_SUCCESS && state.pending_deletes.load()==1);
    open(L"\\Stra\u00dfe:APFS.ResourceFork",STATUS_DELETE_PENDING);
    open(L"\\Stra\u00dfe:APFS.Xattr.636F6D2E6170706C652E5265736F75726365466F726B",STATUS_DELETE_PENDING);
    open(L"\\Stra\u00dfe");open(L"\\Stra\u00dfe:APFS.Xattr.757365722E6E6F7465");
    CHECK(entry->handles==7 && EncWritableDeleteAdmission(state,*handle)==STATUS_SUCCESS);
    CHECK(writable.SetDelete(&fs,handle,nullptr,FALSE)==STATUS_SUCCESS && state.pending_deletes.load()==0);
    auto* reopened=open(L"\\Stra\u00dfe:APFS.ResourceFork");
    CHECK(reopened->open_stream==stream && stream->active_handles==2 && stream->contexts==3);
    CHECK(writable.CanDelete(&fs,handle,nullptr)==STATUS_SHARING_VIOLATION);
    writable.Cleanup(&fs,reopened,nullptr,0);
    CHECK(stream->active_handles==1 && writable.CanDelete(&fs,handle,nullptr)==STATUS_SUCCESS);
    CHECK(!state.failed.load() && !state.cancelled->load() && source->image==original);
    // A native refusal from void Cleanup retains debt, despite unrelated open contexts.
    writable.Cleanup(&fs,handle,nullptr,FspCleanupDelete);
    CHECK(handle->stream_delete_pending && !handle->stream_active && stream->active_handles==0);
    CHECK(state.pending_deletes.load()==1 && state.failed.load() && state.cancelled->load());
    CHECK(std::string_view(state.FailureReasonName())=="CleanupRemoveFailure");
    for(auto h:handles)writable.Close(&fs,h);
    CHECK(state.open_entries.empty() && stream->contexts==0 && stream->active_handles==0);
    CHECK(state.pending_deletes.load()==1);
    state.Close();CHECK(state.failed.load() && source->image==original);
    LocalFree(c.sd);c.sd=nullptr;
}
#include "EncryptedRootObservationCases.h"
void CachedShellProbeCases()
{
    ++groups;
    auto source=EncFixture();const auto original=source->image;
    MountContext c;BindMemory(c,source);FSP_FILE_SYSTEM fs{};fs.UserContext=&c;
    auto& state=*c.encrypted;const auto& writable=EncryptedWritableServeInterface();
    const auto reads=source->reads;
    enc::Handle handle;handle.node.inode_id=100;
    std::array<NTSTATUS,5> status{};UINT32 attrs=0;SIZE_T required=0;
    FSP_FSCTL_VOLUME_INFO volume{};std::vector<std::byte> security(c.sd_size);
    std::atomic<bool> done{false};bool bytes_match=false;
    std::unique_lock gate(state.callbacks);
    std::jthread probes([&](){
        status[0]=writable.GetSecurity(&fs,&handle,nullptr,&required);
        SIZE_T size=security.size();status[1]=writable.GetSecurity(&fs,&handle,security.data(),&size);
        bytes_match=size==c.sd_size && std::memcmp(security.data(),c.sd,size)==0;
        std::wstring root=L"\\";status[2]=writable.GetSecurityByName(&fs,root.data(),&attrs,nullptr,nullptr);
        root=L"\\.";status[3]=ei.GetSecurityByName(&fs,root.data(),nullptr,nullptr,nullptr);
        status[4]=ei.GetVolumeInfo(&fs,&volume);done=true;
    });
    const auto deadline=GetTickCount64()+1000;
    while(!done.load() && GetTickCount64()<deadline)Sleep(1);
    const bool completed_while_held=done.load();gate.unlock();probes.join();
    CHECK(completed_while_held);
    CHECK(status[0]==STATUS_BUFFER_OVERFLOW && required==c.sd_size);
    for(std::size_t i=1;i<status.size();++i)CHECK(status[i]==STATUS_SUCCESS);
    CHECK(bytes_match && attrs==(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_READONLY));
    CHECK(volume.FreeSize==0 && volume.TotalSize==0 && volume.VolumeLabelLength==c.label.size()*sizeof(WCHAR));
    CHECK(source->reads==reads && source->image==original && !state.failed.load());
    state.root_attributes=FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_HIDDEN;
    std::wstring root=L"\\";
    CHECK(writable.GetSecurityByName(&fs,root.data(),&attrs,nullptr,nullptr)==STATUS_SUCCESS);
    CHECK(attrs==(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_HIDDEN) && source->reads==reads);
    state.Cancel();SIZE_T size=security.size();
    CHECK(writable.GetSecurity(&fs,&handle,security.data(),&size)==STATUS_CANCELLED);
    CHECK(writable.GetSecurityByName(&fs,root.data(),&attrs,nullptr,nullptr)==STATUS_CANCELLED);
    CHECK(ei.GetVolumeInfo(&fs,&volume)==STATUS_CANCELLED);
    CHECK(source->reads==reads && source->image==original);
    LocalFree(c.sd);c.sd=nullptr;
}
void FailureReasonCases()
{
    ++groups;
    for(unsigned timeout=0;timeout<3;++timeout) {
        const bool callback_timeout=timeout!=0;
        MountContext context;context.encrypted=std::make_unique<enc::State>();
        auto& state=*context.encrypted;const auto start=GetTickCount64();
        std::optional<ScopedCallbackActivity> activity;
        if(callback_timeout)activity.emplace(&context,"EncryptedDeadlineProbe");
        enc::State::Operation operation(state);
        {
            std::lock_guard lock(state.operations);state.threads.at(operation.thread)=start;
            if(timeout==2)state.absolute_deadlines.at(operation.thread)=start;
        }
        state.Watch([](){return true;},[&context](){return context.active_callback_count.load()!=0;});
        const auto deadline=start+1000;
        while(!state.cancelled->load() && GetTickCount64()<deadline)Sleep(1);
        CHECK(state.failed.load() && state.cancelled->load());
        const auto expected_reason=timeout==2 ? "CallbackAbsoluteCeilingExceeded" :
            callback_timeout ? "CallbackDeadlineExceeded" : "IoDeadlineExceeded";
        CHECK(std::string_view(state.FailureReasonName())==expected_reason);
        const auto failure_tick=state.FailureTickMs();
        CHECK(failure_tick>=start && failure_tick<=GetTickCount64());
        state.Fail(enc::State::Failure::CloseRemoveFailure);
        CHECK(std::string_view(state.FailureReasonName())==expected_reason && state.FailureTickMs()==failure_tick);
        state.monitor.request_stop();state.monitor.join();
        const auto directory=std::filesystem::temp_directory_path()/
            (L"encrypted-timeout-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(start));
        std::filesystem::create_directory(directory);
        ScopeExit remove{[&](){std::filesystem::remove_all(directory);}};
        context.args.status_file=(directory/L"status.json").wstring();
        std::atomic<bool> receipt_done{false};
        std::unique_lock callback(state.callbacks);
        std::jthread publish([&](){WriteCallbackWatchdogFile(context);receipt_done=true;});
        const auto receipt_deadline=GetTickCount64()+1000;
        while(!receipt_done.load() && GetTickCount64()<receipt_deadline)Sleep(1);
        const bool published_while_held=receipt_done.load();callback.unlock();publish.join();
        CHECK(published_while_held);
        std::ifstream input(directory/L"status.json.callback.json",std::ios::binary);
        const std::string receipt((std::istreambuf_iterator<char>(input)),{});
        CHECK(receipt.find(std::string("\"encryptedFailureReason\":\"")+expected_reason+"\"")!=receipt.npos);
        CHECK(receipt.find("\"encryptedFailureTickMs\":"+std::to_string(failure_tick))!=receipt.npos);
        CHECK(receipt.find("CloseRemoveFailure")==receipt.npos);
        CHECK(receipt.find("\"encryptedNoProgressMs\":30000")!=receipt.npos);
        CHECK(receipt.find("\"encryptedCallbackAbsoluteMs\":240000")!=receipt.npos);
    }
    {
        auto source=EncFixture();const auto original=source->image;
        MountContext c;BindMemory(c,source);FSP_FILE_SYSTEM fs{};fs.UserContext=&c;
        const auto status=EncCall(&fs,"EncryptedFailureReasonTest",[](MountContext&,enc::State&)->NTSTATUS {
            throw std::runtime_error("test text must not be diagnostic authority");
        });
        CHECK(status==STATUS_IO_DEVICE_ERROR && c.encrypted->failed.load());
        CHECK(std::string_view(c.encrypted->FailureReasonName())=="EncCallException" && c.encrypted->FailureTickMs()!=0);
        CHECK(source->image==original);LocalFree(c.sd);c.sd=nullptr;
    }
    for(bool active : {true,false}) {
        auto source=EncFixture();const auto original=source->image;
        MountContext c;BindMemory(c,source);FSP_FILE_SYSTEM fs{};fs.UserContext=&c;
        const auto& writable=EncryptedWritableServeInterface();PVOID h=nullptr;FSP_FSCTL_FILE_INFO info{};
        std::wstring name=L"\\Stra\u00dfe:APFS.ResourceFork";
        CHECK(writable.Open(&fs,name.data(),0,GENERIC_READ,&h,&info)==STATUS_SUCCESS && h);
        auto& handle=*static_cast<enc::Handle*>(h);
        if(active)handle.open_stream->active_handles=0;
        else handle.open_stream->contexts=0;
        writable.Close(&fs,h);
        CHECK(c.encrypted->failed.load() && c.encrypted->cancelled->load());
        CHECK(std::string_view(c.encrypted->FailureReasonName())==(active ? "StreamActiveCounterUnderflow" : "StreamContextCounterUnderflow"));
        CHECK(source->image==original);LocalFree(c.sd);c.sd=nullptr;
    }
}
void CompletedDeadlineCases(const std::filesystem::path& directory)
{
    ++groups;
    using apfsaccess::catalog::EncryptedImageRuntime;
    CHECK(directory.is_absolute() && (directory.native()[0]==L'D' || directory.native()[0]==L'd'));
    CHECK(!std::filesystem::exists(directory));std::filesystem::create_directories(directory);
    const auto image=directory/L"fixture.apfs";SaveEncFixture(image);
    std::ifstream before(image,std::ios::binary);
    const std::string original((std::istreambuf_iterator<char>(before)),{});before.close();
    for(unsigned profile=0;profile<4;++profile) {
        enc::State state;EncryptedImageRuntime::Options options;
        options.image={image,0,original.size(),101};
        options.recovery_directory=directory/(L"r"+std::to_wstring(profile));std::string error;
        state.writer=EncryptedImageRuntime::Open(options,error);
        if(!state.writer)throw std::runtime_error("DeadlineStateOwner:"+error);
        {
            enc::State::Operation operation(state,profile!=2);
            ULONGLONG start=0;
            {std::lock_guard lock(state.operations);start=state.threads.at(operation.thread)-30000;}
            const auto complete=[&](ULONGLONG now,std::uint64_t invocation,std::uint64_t ordinal,unsigned slot) {
                return enc::DeadlineStateTestAccess::Complete(operation,*state.writer,invocation,ordinal,slot,now);
            };
            EncRuntimePhases phases;
            CHECK(phases("before-encrypted-private-prepare") && phases("continuation-after-ready-receipt") &&
                phases("arbitrary-user-stage"));
            CHECK(state.completed_barriers.load()==0);
            {std::lock_guard lock(state.operations);CHECK(state.threads.at(operation.thread)==start+30000);}
            if(profile==0) {
                CHECK(complete(start+20000,1,1,0));CHECK(complete(start+40000,1,2,1));
                CHECK(!state.cancelled->load() && state.completed_barriers.load()==2);
                CHECK(!complete(start+71000,1,3,2));
                CHECK(state.failed.load() && state.cancelled->load());
                CHECK(std::string_view(state.FailureReasonName())=="CallbackDeadlineExceeded");
                const auto count=state.completed_barriers.load();
                CHECK(!complete(start+41000,1,3,2) && state.completed_barriers.load()==count);
            }else if(profile==1) {
                for(unsigned slot=0;slot<11;++slot)CHECK(complete(start+20000+slot*20000,1,slot+1,slot));
                CHECK(complete(start+239999,1,12,11));
                {std::lock_guard lock(state.operations);CHECK(state.threads.at(operation.thread)==start+240000);}
                CHECK(!complete(start+240000,1,13,12));
                CHECK(state.failed.load() && state.cancelled->load());
                CHECK(std::string_view(state.FailureReasonName())=="CallbackAbsoluteCeilingExceeded");
                CHECK(!complete(start+239999,1,13,12));
            }else if(profile==2) {
                CHECK(!complete(start+1000,1,1,0));
                CHECK(!state.failed.load() && !state.cancelled->load() && state.completed_barriers.load()==0);
                state.Cancel();CHECK(!complete(start+2000,1,1,0));
                CHECK(state.completed_barriers.load()==0);
            }else {
                bool foreign=true;
                std::jthread other([&](){foreign=complete(start+1000,1,1,0);});other.join();
                CHECK(!foreign && state.completed_barriers.load()==0 && !state.cancelled->load());
                CHECK(complete(start+2000,1,1,0));
                state.Cancel();CHECK(!complete(start+3000,1,2,1));
                CHECK(state.completed_barriers.load()==1);
            }
        }
        CHECK(state.threads.empty() && state.absolute_deadlines.empty());state.Close();
    }
    std::ifstream after(image,std::ios::binary);
    CHECK(std::string((std::istreambuf_iterator<char>(after)),{})==original);
}
void StreamDeleteNativeReview(const std::filesystem::path& image,const std::filesystem::path& recovery)
{
    ++groups;
    using apfsaccess::catalog::EncryptedImageRuntime;
    MountContext c;c.encrypted=std::make_unique<enc::State>();auto& state=*c.encrypted;
    EncryptedImageRuntime::Options options;options.image={image,20480,4153344,1026};
    options.recovery_directory=recovery;std::string error;
    state.writer=EncryptedImageRuntime::Open(options,error);
    if(!state.writer)throw std::runtime_error(error);
    state.Watch([](){return true;},[&c](){return c.active_callback_count.load()!=0;});
    auto credential=apfsaccess::transport::ReceiveCredential(GetStdHandle(STD_INPUT_HANDLE),
        std::chrono::milliseconds(5000),*state.cancelled);
    CHECK(credential);PasswordUnlockBudget budget;
    const auto unlocked=state.writer->Unlock(credential.bytes,budget,error);credential.bytes.Clear();
    if(!unlocked)throw std::runtime_error(error);
    CHECK(EncWritableRefresh(state)==STATUS_SUCCESS);
    c.sd=BuildWritableVolumeSecurityDescriptor(&c.sd_size);CHECK(c.sd);
    ScopeExit security{[&](){LocalFree(c.sd);c.sd=nullptr;}};
    FSP_FILE_SYSTEM fs{};fs.UserContext=&c;
    const auto& writable=EncryptedWritableServeInterface();FSP_FSCTL_FILE_INFO info{};
    std::vector<PVOID> handles;
    ScopeExit close{[&](){for(auto h:handles)writable.Close(&fs,h);}};
    const auto create=[&](std::wstring name) {
        PVOID h=nullptr;
        CHECK(writable.Create(&fs,name.data(),0,GENERIC_WRITE,FILE_ATTRIBUTE_NORMAL,nullptr,0,&h,&info)==STATUS_SUCCESS);
        CHECK(h);handles.push_back(h);return static_cast<enc::Handle*>(h);
    };
    const auto open=[&](std::wstring name,NTSTATUS expected=STATUS_SUCCESS) {
        PVOID h=nullptr;
        CHECK(writable.Open(&fs,name.data(),0,GENERIC_READ,&h,&info)==expected);
        CHECK((h!=nullptr)==NT_SUCCESS(expected));
        if(h)handles.push_back(h);return static_cast<enc::Handle*>(h);
    };
    const auto write=[&](enc::Handle* h,std::string_view data) {
        ULONG done=0;
        CHECK(writable.Write(&fs,h,const_cast<char*>(data.data()),0,static_cast<ULONG>(data.size()),FALSE,FALSE,&done,&info)==STATUS_SUCCESS);
        CHECK(done==data.size());
    };
    const auto read=[&](enc::Handle* h,std::string_view expected) {
        std::array<char,64> bytes{};ULONG done=0;
        CHECK(writable.Read(&fs,h,bytes.data(),0,static_cast<ULONG>(bytes.size()),&done)==STATUS_SUCCESS);
        CHECK(std::string_view(bytes.data(),done)==expected);
    };
    auto* base=create(L"\\stream-callback-review");write(base,"base-preserved");
    auto* stream=create(L"\\stream-callback-review:APFS.ResourceFork");write(stream,"old-stream");
    auto* other=create(L"\\stream-callback-review:APFS.FinderInfo");
    auto* alias=open(L"\\stream-callback-review:APFS.Xattr.636F6D2E6170706C652E5265736F75726365466F726B");
    const auto old_stream=stream->open_stream;
    CHECK(alias->open_stream==old_stream && old_stream->active_handles==2);
    CHECK(writable.SetDelete(&fs,stream,nullptr,TRUE)==STATUS_SHARING_VIOLATION);
    CHECK(state.pending_deletes.load()==0 && !state.failed.load());
    writable.Cleanup(&fs,alias,nullptr,0);writable.Cleanup(&fs,alias,nullptr,0);
    CHECK(old_stream->active_handles==1 && old_stream->contexts==2);
    CHECK(writable.SetDelete(&fs,stream,nullptr,TRUE)==STATUS_SUCCESS);
    open(L"\\stream-callback-review:APFS.ResourceFork",STATUS_DELETE_PENDING);
    open(L"\\stream-callback-review:APFS.Xattr.636F6D2E6170706C652E5265736F75726365466F726B",STATUS_DELETE_PENDING);
    auto* later_base=open(L"\\stream-callback-review");
    open(L"\\stream-callback-review:APFS.FinderInfo");
    open(L"\\stream-callback-review:APFS.XattrProtocol");
    CHECK(stream->open_entry->handles==7 && writable.CanDelete(&fs,stream,nullptr)==STATUS_SUCCESS);
    writable.Cleanup(&fs,stream,nullptr,FspCleanupDelete);
    CHECK(state.pending_deletes.load()==0 && old_stream->removed && old_stream->active_handles==0);
    CHECK(!state.failed.load() && !state.cancelled->load());
    writable.Cleanup(&fs,stream,nullptr,FspCleanupDelete);
    open(L"\\stream-callback-review:APFS.ResourceFork",STATUS_OBJECT_NAME_NOT_FOUND);
    CHECK(writable.GetFileInfo(&fs,alias,&info)==STATUS_FILE_DELETED);
    std::array<char,64> bytes{};ULONG done=99;
    CHECK(writable.Read(&fs,alias,bytes.data(),0,64,&done)==STATUS_FILE_DELETED && !done);
    read(base,"base-preserved");read(later_base,"base-preserved");
    CHECK(writable.GetFileInfo(&fs,other,&info)==STATUS_SUCCESS && info.FileSize==32);
    auto* replacement=create(L"\\stream-callback-review:APFS.ResourceFork");write(replacement,"new-stream");
    CHECK(replacement->open_stream!=old_stream && !replacement->open_stream->removed);
    CHECK(writable.GetFileInfo(&fs,alias,&info)==STATUS_FILE_DELETED);
    const auto current= replacement->open_stream;
    writable.Close(&fs,alias);handles.erase(std::find(handles.begin(),handles.end(),alias));
    writable.Close(&fs,stream);handles.erase(std::find(handles.begin(),handles.end(),stream));
    CHECK(current->contexts==1 && current->active_handles==1);
    read(replacement,"new-stream");
    // Exercise native Cleanup deletion without a preceding SetDelete as well.
    writable.Cleanup(&fs,replacement,nullptr,FspCleanupDelete);
    writable.Cleanup(&fs,replacement,nullptr,FspCleanupDelete);
    CHECK(state.pending_deletes.load()==0 && current->removed && !state.failed.load());
    read(base,"base-preserved");
    const auto status=state.writer->CachedStatus();
    CHECK(status.accepted>0 && status.accepted==status.durable && status.durable==status.cleaned);
    CHECK(!status.recovery_required && state.writer->CachedPersistenceStateValid());
    CHECK(state.publication_barriers.load()==status.image.commits && state.publication_barriers.load()>0);
    CHECK(state.completed_barriers.load()>state.publication_barriers.load());
    for(auto h:handles)writable.Close(&fs,h);handles.clear();
    CHECK(state.open_entries.empty() && old_stream->contexts==0 && current->contexts==0);
    state.Close();CHECK(!state.failed.load() && state.pending_deletes.load()==0);
    std::cout<<"native stream deletion accepted="<<status.accepted<<" durable="<<status.durable<<" cleaned="<<status.cleaned<<"\n";
    std::cout<<"actual typed barriers="<<state.completed_barriers.load()<<" publications="<<state.publication_barriers.load()<<
        " quietMs="<<enc::OperationDeadline::interval_ms<<" absoluteMs="<<enc::OperationDeadline::absolute_interval_ms<<"\n";
}
int wmain(int argc,wchar_t** argv)
{
    try {
        if(argc==3 && std::wstring_view(argv[1])==L"--completed-deadlines") {
            CompletedDeadlineCases(argv[2]);std::cout<<"PASS "<<groups<<" groups / "<<checks<<" assertions\n";return 0;
        }
        if(argc==2 && std::wstring_view(argv[1])==L"--cached-root-guard") {
            encrypted_root_observation_cases::Run();std::cout<<"PASS "<<groups<<" groups / "<<checks<<" assertions\n";return 0;
        }
        if(argc==2 && std::wstring_view(argv[1])==L"--failure-reasons") {
            FailureReasonCases();std::cout<<"PASS "<<groups<<" groups / "<<checks<<" assertions\n";return 0;
        }
        if(argc==2 && std::wstring_view(argv[1])==L"--cached-shell-probes") {
            CachedShellProbeCases();std::cout<<"PASS "<<groups<<" groups / "<<checks<<" assertions\n";return 0;
        }
        if(argc==4 && std::wstring_view(argv[1])==L"--stream-delete-native-review") {
            StreamDeleteNativeReview(argv[2],argv[3]);std::cout<<"PASS "<<groups<<" groups / "<<checks<<" assertions\n";return 0;
        }
        if(argc==2 && std::wstring_view(argv[1])==L"--stream-delete-review") {
            StreamDeleteReviewCases();std::cout<<"PASS "<<groups<<" groups / "<<checks<<" assertions\n";return 0;
        }
        if(argc==2 && std::wstring_view(argv[1])==L"--pending-delete-review") {
            PendingDeleteReviewCases();std::cout<<"PASS "<<groups<<" groups / "<<checks<<" assertions\n";return 0;
        }
        if(argc==2 && std::wstring_view(argv[1])==L"--arguments-only") {
            EncryptedArgumentCases();std::cout<<"PASS "<<groups<<" groups / "<<checks<<" assertions\n";return 0;
        }
        if(argc==2 && std::wstring_view(argv[1])==L"--review-budget") {
            ReviewBudgetRecovery();std::cout<<"PASS "<<groups<<" groups / "<<checks<<" assertions\n";return 0;
        }
        if(argc==2 && std::wstring_view(argv[1])==L"--review-boundaries") {
            ReviewBoundaries();std::cout<<"PASS "<<groups<<" groups / "<<checks<<" assertions\n";return 0;
        }
        if(argc==3 && std::wstring_view(argv[1])==L"--fixture-label") {SaveEncFixture(argv[2],true);return 0;}
        if(argc==2 && std::wstring_view(argv[1])==L"--namespace-refusals") {
            NamespaceRefusals();std::cout<<"PASS "<<groups<<" groups / "<<checks<<" assertions\n";return 0;
        }
        if(argc==3 && std::wstring_view(argv[1])==L"--fixture") {SaveEncFixture(argv[2]);return 0;}
        if(argc==3 && std::wstring_view(argv[1])==L"--source") {
            auto lease=std::make_shared<apfsaccess::transport::WindowsImageLease>(argv[2]);
            apfsaccess::transport::OwnedEncryptedImageSource source(lease,0,lease->SizeBytes());
            std::cout<<source.SourceIdentity()<<"\n";return 0;
        }
        if(argc>2 && std::wstring_view(argv[1])==L"--admission") {
            auto owner=std::make_unique<MountContext>();auto& c=*owner;
            if(!ParseArgs(argc-1,argv+1,c.args)) return 2;
            auto parent=OpenOwningParentProcess(c.args.parent_pid);if(!parent)return 15;
            ScopeExit close_parent{[&](){CloseHandle(parent);}};
            if(!WaitForStartupAuthorization(c.args,parent,std::chrono::milliseconds(1000)))return 14;
            const char* failure=nullptr;
            if(!PrepareEncryptedMount(c,parent,&failure)) {CHECK(!c.encrypted && !c.metadata_store);CHECK(EncWriter(c.args.device));std::cerr<<"Refused: "<<(failure?failure:"unknown")<<"\n";return 24;}
            CHECK(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,c.encrypted->label.data(),static_cast<int>(c.encrypted->label.size()),nullptr,0,nullptr,nullptr)>0);
            if(c.encrypted->label.starts_with(std::wstring(18,L'A')))
                CHECK(c.encrypted->label==std::wstring(18,L'A')+L" (read-only)");
            c.sd=BuildWritableVolumeSecurityDescriptor(&c.sd_size);c.label=c.encrypted->label;
            c.api.AddDir=AddEncDir;c.api.AddStream=AddEncStream;
            CHECK(!EncWriter(c.args.device));ProductionRuntimeReads(c);Lifecycle(owner);LocalFree(c.sd);c.sd=nullptr;
        } else {
            EncryptedArgumentCases();PendingDeleteReviewCases();StreamDeleteReviewCases();CachedShellProbeCases();FailureReasonCases();MountContext c;BindMemory(c,EncFixture());CallbackCases(c);LocalFree(c.sd);c.sd=nullptr;FaultCases();CancelHeldRead();
        }
        std::cout<<"PASS "<<groups<<" groups / "<<checks<<" assertions; no mount launched\n";return 0;
    } catch(const std::exception& e) {std::cerr<<"FAIL "<<e.what()<<" after "<<checks<<" assertions\n";return 1;}
}
