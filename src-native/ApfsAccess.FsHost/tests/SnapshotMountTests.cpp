// Real parser, startup helpers and callbacks; WinFsp teardown is stubbed only
// at the external API boundary. This executable never mounts anything.
#define APFSACCESS_FSHOST_UNIT_TEST 1
#include "../src/main.cpp"
#define main snapshot_projection_fixture_test_main
#include "SnapshotProjectionTests.cpp"
#undef main

namespace {
Fixture MountFixture() {
    Fixture f; f.External(); f.Hardlinks();
    AppleInodeRecord inode; std::string error;
    Check(ApfsExtendedRecordCodec::DecodeInode(Inode(30,8192,2),inode,error),"sparse inode");
    inode.internal_flags |= 0x200;
    AppleExtendedField hole{13,0,Bytes(8)}; PutU64LE(hole.data,0,4096);
    inode.extended_fields.push_back(hole); f.fs[2]=Encode(inode,EncodeAppleInodeRecord);
    f.fs.push_back(Encode(AppleFileExtentRecord{30,4096,4096,0,0,4096},EncodeAppleFileExtentRecord));
    f.Trees(); return f;
}
void Save(const std::filesystem::path& path, const Bytes& bytes) {
    std::ofstream out(path,std::ios::binary|std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()),bytes.size()); Check(bool(out),"save fixture");
}
std::vector<std::wstring> Command(const std::filesystem::path& image) {
    return {L"host",L"--snapshot-xid",L"10",L"--device",image.wstring(),L"--container-id",std::wstring(32,L'a'),
        L"--volume-oid",L"101",L"--readonly",L"--mount",L"D:\\unused-snapshot-mount",
        L"--parent-pid",std::to_wstring(GetCurrentProcessId()),L"--lifetime-file",L"D:\\unused.life",
        L"--startup-gate-file",L"D:\\unused.gate",L"--startup-gate-token",L"test-gate"};
}
bool Parse(std::vector<std::wstring> words,Arguments& args) {
    std::vector<wchar_t*> pointers; for(auto& word:words) pointers.push_back(word.data());
    return ParseArgs(static_cast<int>(pointers.size()),pointers.data(),args);
}
void Parser(const std::filesystem::path& path) {
    Arguments args; Check(Parse(Command(path),args)&&args.snapshot_xid==10,"exact parser");
    for(auto xid:{L"0",L"01",L"+10",L"-10",L" 10",L"10x",L"18446744073709551616",L""}) {
        auto words=Command(path);words[2]=xid;Arguments out;Check(!Parse(words,out),"noncanonical XID rejected");
    }
    for(auto image:{L"relative.apfs",L"D:relative.apfs",L"\\\\.\\PhysicalDrive1",L"\\\\?\\D:\\image.apfs",L"\\\\server\\image",L"D:\\file:stream"}) {
        auto words=Command(path);words[4]=image;Arguments out;Check(!Parse(words,out),"nonlocal image rejected");
    }
    for(auto extra:std::vector<std::vector<std::wstring>>{{L"--readwrite"},{L"--write-backend",L"Native"},
        {L"--write-backend",L"Overlay"},{L"--container-manifest",L"D:\\manifest"},
        {L"--recovery-identity",L"apfs-recovery-v1-"+std::wstring(64,L'a')},{L"--allow-raw-physical-write"},
        {L"--snapshot-xid",L"11"},{L"--unknown"},{L"--device",path.wstring()}}) {
        auto words=Command(path);words.insert(words.end(),extra.begin(),extra.end());Arguments out;
        Check(!Parse(words,out),"mixed or duplicate selector rejected");
    }
    for(auto key:{L"--device",L"--container-id",L"--volume-oid",L"--mount",L"--parent-pid",L"--lifetime-file",L"--startup-gate-file",L"--startup-gate-token"}) {
        auto words=Command(path);auto it=std::find(words.begin(),words.end(),key);words.erase(it,it+2);
        Arguments out;Check(!Parse(words,out),"required field missing");
    }
    {auto words=Command(path);words[6]=std::wstring(32,L'A');Arguments out;Check(!Parse(words,out),"uppercase UUID rejected");}
    {auto words=Command(path);words[8]=L"0";Arguments out;Check(!Parse(words,out),"volume zero rejected");}
    for(auto value:{L"+101",L"0101",L"101x",L"-1"}) {
        auto words=Command(path);words[8]=value;Arguments out;Check(!Parse(words,out),"noncanonical volume rejected");
    }
    for(auto value:{L"+0",L"00",L"0junk",L"-1"}) {
        auto words=Command(path);words.insert(words.end(),{L"--device-offset",value});Arguments out;
        Check(!Parse(words,out),"noncanonical offset rejected");
    }
    Pass("snapshot parser selectors and forbidden combinations");
}
void AncestorPins(const std::filesystem::path& path) {
    const auto suffix=std::to_string(GetCurrentProcessId());
    const auto directory=path.parent_path()/("pinned-parent-"+suffix);
    std::filesystem::create_directory(directory);
    std::vector<UniqueWinHandle> pins;std::string error;
    Check(PinSnapshotImageAncestors((directory/"fixture.apfs").wstring(),pins,error),"pin ordinary ancestors");
    const auto renamed=path.parent_path()/("renamed-parent-"+suffix);
    Check(!std::filesystem::exists(renamed)&&pins.size()>1,"fresh ancestor rename destination and retained handles");
    Check(!MoveFileExW(directory.c_str(),renamed.c_str(),0),"ancestor cannot move during selection");
    pins.clear();Check(MoveFileExW(directory.c_str(),renamed.c_str(),0)!=0,"ancestor pin released after selection");
    std::filesystem::remove(renamed);Pass("stable ancestor lease closes path replacement gap");
}
bool WriterAvailable(const std::filesystem::path& path) {
    auto h=CreateFileW(path.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        nullptr,OPEN_EXISTING,0,nullptr);
    if(h==INVALID_HANDLE_VALUE)return false; CloseHandle(h);return true;
}
void StartupRefusals(const std::filesystem::path& path) {
    for(unsigned n=0;n<7;++n) {
        MountContext c; Check(Parse(Command(path),c.args),"refusal parse");
        if(n==0)c.args.snapshot_xid=11;
        if(n==1)c.args.volume_object_id=102;
        if(n==2)c.args.container_id=std::wstring(32,L'c');
        if(n==3)c.args.volume=L"wrong-name";
        if(n==4)c.args.device_offset_bytes=4096;
        if(n==5)c.args.device+=L".missing";
        if(n==6)c.args.device=(path.parent_path()/"bad.apfs").wstring();
        std::string error;Check(!PrepareExplicitSnapshotMount(c,error)&&!error.empty(),"startup fails exact identity/image");
        Check(!c.metadata_store&&!c.tx_manager&&!c.payload_spool&&!c.recovery_active&&!c.write_degraded,"failure leaves no writer/recovery");
        Check(WriterAvailable(path),"failed preparation releases lease");
    }
    Pass("startup rejects wrong scope exact XID and invalid images");
}
void OrdinaryReadNeighbor(const std::filesystem::path& path) {
    MountContext c;Check(Parse(Command(path),c.args),"ordinary neighbor parse base");
    c.args.snapshot_xid=0;c.args.volume=L"Data";c.args.allow_legacy_scaffold_for_fixtures=false;
    Check(ResolveMountVolumeObjectId(c.args),"ordinary exact volume resolution");
    c.owned_metadata_store=std::make_unique<MetadataStore>(BuildMetadataStoreVolumeContext(c.args));
    c.metadata_store=c.owned_metadata_store.get();
    Check(c.metadata_store->LoadContainerState()&&c.metadata_store->LoadVolumeState(),"ordinary live bootstrap");
    Check(InitializeMountNamespace(c),"ordinary namespace neighbor");
    FSP_FILE_SYSTEM fs{};fs.UserContext=&c;FSP_FSCTL_FILE_INFO info{};PVOID h=nullptr;
    auto name=std::wstring(L"\\report.txt");
    const auto opened=CB_Open(&fs,name.data(),FILE_NON_DIRECTORY_FILE|(FILE_OPEN<<24),GENERIC_READ,&h,&info);
    Check(NT_SUCCESS(opened),"ordinary callback open: "+WideToUtf8(FormatNtStatus(opened)));
    Bytes out(8);ULONG done=0;const auto result=CB_Read(&fs,h,out.data(),0,8,&done);CB_Close(&fs,h);
    Check(NT_SUCCESS(result)&&done==8&&std::string(reinterpret_cast<const char*>(out.data()),8)=="LIVEVIEW","same image live callback differs from snapshot");
    Pass("ordinary read startup and historic versus live callback control");
}
std::atomic<bool> stopped{false},removed{false},deleted{false},release_stop{false};
std::atomic<bool> read_paused{false},release_read{false};
void PauseSnapshotRead(MountContext*) {
    read_paused=true;while(!release_read)std::this_thread::sleep_for(std::chrono::milliseconds(1));
}
void StopSnapshot(FSP_FILE_SYSTEM* fs) {
    auto* c=Ctx(fs); if(!c->metadata_store->Device().RevalidateStableReadOnlyImage())std::abort();
    stopped=true;while(!release_stop)std::this_thread::sleep_for(std::chrono::milliseconds(1));
}
void RemoveSnapshot(FSP_FILE_SYSTEM*) { removed=true; }
void DeleteSnapshot(FSP_FILE_SYSTEM*) { deleted=true; }
std::vector<std::wstring> listed_names;
BOOLEAN CaptureSnapshotDirectory(FSP_FSCTL_DIR_INFO* entry,PVOID,ULONG,PULONG done) {
    if(entry) {listed_names.emplace_back(entry->FileNameBuf,(entry->Size-sizeof(*entry))/sizeof(WCHAR));*done+=entry->Size;}
    return TRUE;
}
void Callbacks(const std::filesystem::path& path) {
    auto owner=std::make_unique<MountContext>();auto& c=*owner;
    Check(Parse(Command(path),c.args),"startup parse");std::string error;
    Check(InitializeSessionPaths(&c),"normal session paths");
    Check(PrepareExplicitSnapshotMount(c,error),"actual snapshot startup: "+error);
    Check(InitializeMountNamespace(c),"normal namespace bootstrap");
    c.sd=BuildWritableVolumeSecurityDescriptor(&c.sd_size);Check(c.sd!=nullptr,"normal security bootstrap");
    c.label=L"backup (snapshot 10)";FSP_FILE_SYSTEM fs{};fs.UserContext=&c;
    c.api.AddDir=CaptureSnapshotDirectory;
    FSP_FSCTL_FILE_INFO root_info{};PVOID root_handle=nullptr;auto root_name=std::wstring(L"\\");
    Check(NT_SUCCESS(CB_Open(&fs,root_name.data(),FILE_DIRECTORY_FILE|(FILE_OPEN<<24),GENERIC_READ,&root_handle,&root_info)),"root directory callback open");
    std::array<std::byte,4096> directory_buffer{};ULONG directory_done=0;
    Check(NT_SUCCESS(CB_ReadDirectory(&fs,root_handle,nullptr,nullptr,directory_buffer.data(),directory_buffer.size(),&directory_done)),"root directory callback enumeration");
    CB_Close(&fs,root_handle);
    Check(std::find(listed_names.begin(),listed_names.end(),L"report.txt")!=listed_names.end()&&
        std::find(listed_names.begin(),listed_names.end(),L"alias.txt")!=listed_names.end(),"historical directory callback names");
    Check(!WriterAvailable(path),"installed snapshot excludes writer");
    Check(!DeleteFileW(path.c_str())&&!MoveFileExW(path.c_str(),(path.wstring()+L".moved").c_str(),0),"lease excludes delete/replace");
    FSP_FSCTL_FILE_INFO info{};std::vector<PVOID> handles;
    auto open=[&](std::wstring name) {
        PVOID h=nullptr;const auto status=CB_Open(&fs,name.data(),FILE_NON_DIRECTORY_FILE|(FILE_OPEN<<24),GENERIC_READ,&h,&info);
        Check(NT_SUCCESS(status),"callback Open: "+WideToUtf8(name)+" "+WideToUtf8(FormatNtStatus(status)));
        handles.push_back(h);return h;
    };
    auto read=[&](PVOID h,UINT64 offset,ULONG count) {
        Bytes out(count,std::byte{0xCC});ULONG done=99;
        Check(NT_SUCCESS(CB_Read(&fs,h,out.data(),offset,count,&done)),"callback Read");out.resize(done);return out;
    };
    auto regular=open(L"\\report.txt");auto alias=open(L"\\alias.txt");
    const auto bytes=read(regular,0,8);Check(std::string(reinterpret_cast<const char*>(bytes.data()),bytes.size())=="snapshot","historic regular callback bytes");
    Check(read(alias,0,8)==bytes,"hardlink callback bytes");
    auto* ro=static_cast<OpenContext*>(regular);auto* ao=static_cast<OpenContext*>(alias);
    Check(ro->file==INVALID_HANDLE_VALUE&&ao->file==INVALID_HANDLE_VALUE&&ro->metadata_read_fallback&&ao->metadata_read_fallback,
        "snapshot hardlinks use native plans without hydration handles");
    Check(ro->node->object_id==ao->node->object_id&&
        c.metadata_store->LookupCommittedInodeByObjectId(ro->node->object_id)->link_count==2,"hardlink identity");
    Check(read(regular,4092,4100)==Bytes(4100),"explicit data/hole crossing callback");
    auto finder=open(L"\\report.txt:APFS.FinderInfo:$DATA");
    Check(read(finder,0,64)==Bytes(32,std::byte{0x42}),"exact Finder stream callback");
    auto fork=open(L"\\report.txt:APFS.ResourceFork:$DATA");
    auto forkbytes=read(fork,0,9);Check(std::string(reinterpret_cast<const char*>(forkbytes.data()),forkbytes.size())=="fork-past","historical resource callback");
    auto protocol=open(L"\\report.txt:APFS.XattrProtocol:$DATA");Check(!read(protocol,0,64).empty(),"native xattr protocol read");
    std::array<std::byte,2048> streams{};ULONG done=0;
    Check(NT_SUCCESS(CB_GetStreamInfo(&fs,regular,streams.data(),streams.size(),&done))&&done>sizeof(FSP_FSCTL_STREAM_INFO),"native streams enumerated");
    SIZE_T security_size=0;UINT32 attrs=0;auto name=std::wstring(L"\\report.txt");
    Check(CB_GetSecurityByName(&fs,name.data(),&attrs,nullptr,&security_size)==STATUS_BUFFER_OVERFLOW&&security_size>0,"security by name");
    Bytes security(security_size);Check(NT_SUCCESS(CB_GetSecurity(&fs,regular,security.data(),&security_size)),"security callback");
    FSP_FSCTL_VOLUME_INFO volume{};Check(NT_SUCCESS(CB_GetVolumeInfo(&fs,&volume))&&volume.TotalSize==512*4096&&volume.FreeSize==0,"known geometry unknown free capacity");
    Check(!CaptureReportedVolumeInfo(c).free_size_bytes,"unknown free capacity remains optional");
    FSP_FSCTL_VOLUME_PARAMS parameters{};FILETIME now{};GetSystemTimeAsFileTime(&now);
    ConfigureVolumeParamsForExplorer(c,now,parameters);
    Check(parameters.ReadOnlyVolume&&parameters.NamedStreams&&parameters.PersistentAcls,"WinFsp advertises immutable native metadata");
    auto current_args=c.args;current_args.snapshot_xid=0;
    Check(BuildStableVolumeSerial(c.args)!=BuildStableVolumeSerial(current_args),"snapshot serial differs from current view");
    auto denied=[](NTSTATUS status){Check(!NT_SUCCESS(status),"mutation callback refuses");};
    Bytes payload(8);denied(CB_Write(&fs,regular,payload.data(),0,8,FALSE,FALSE,&done,&info));
    denied(CB_Overwrite(&fs,regular,0,FALSE,4096,&info));
    denied(CB_SetBasicInfo(&fs,regular,FILE_ATTRIBUTE_NORMAL,1,2,3,4,&info));
    denied(CB_SetFileSize(&fs,regular,1,FALSE,&info));
    denied(CB_SetFileSize(&fs,regular,16384,TRUE,&info));
    denied(CB_CanDelete(&fs,regular,name.data()));denied(CB_SetDelete(&fs,regular,name.data(),TRUE));
    auto target=std::wstring(L"\\new");denied(CB_Rename(&fs,regular,name.data(),target.data(),FALSE));
    denied(CB_SetSecurity(&fs,regular,DACL_SECURITY_INFORMATION,c.sd));
    denied(CB_SetReparsePoint(&fs,regular,name.data(),payload.data(),payload.size()));
    denied(CB_DeleteReparsePoint(&fs,regular,name.data(),payload.data(),payload.size()));
    PVOID invalid=nullptr;denied(CB_Create(&fs,target.data(),FILE_NON_DIRECTORY_FILE,GENERIC_WRITE,0,nullptr,0,&invalid,&info));
    denied(CB_Open(&fs,name.data(),FILE_NON_DIRECTORY_FILE|(FILE_OPEN<<24),GENERIC_WRITE,&invalid,&info));
    denied(CB_Write(&fs,fork,payload.data(),0,8,FALSE,FALSE,&done,&info));
    Check(NT_SUCCESS(CB_Flush(&fs,regular,&info)),"readonly flush is harmless");
    Check(c.deferred_access_times.empty()&&c.metadata_store->PendingMutationCount()==0,"no atime or mutation state");
    Check(std::filesystem::is_empty(c.cache_root),"snapshot callback path creates no hydration files");
    Check(!c.tx_manager&&!c.payload_spool&&c.tx_journal_file.empty()&&c.recovery_marker_file.empty()&&
        !c.metadata_store->Device().HasWriteHandle()&&!c.metadata_store->IsRecoveryRequired()&&!c.recovery_active&&!c.write_degraded,"no writer journal spool or false degradation");
    c.args.status_file=(path.parent_path()/"status.json").wstring();c.mount_ready=true;
    Check(WriteHostStatusFile(c),"snapshot status");
    std::ifstream status(c.args.status_file);std::string json((std::istreambuf_iterator<char>(status)),{});
    status.close();
    Check(json.find("\"snapshotXid\":\"10\"")!=std::string::npos&&json.find("ImmutableSnapshotReadOnly")!=std::string::npos&&
        json.find("\"snapshotName\":\"backup\"")!=std::string::npos&&
        json.find("\"commitModel\":\"None\"")!=std::string::npos&&json.find("\"commitBlobMagic\":null")!=std::string::npos&&
        json.find("\"nativeWriteValidationState\":\"NotApplicable\"")!=std::string::npos,"status exact identity readonly without scaffold claims");
    c.fs=&fs;c.api.Stop=StopSnapshot;c.api.RemoveMount=RemoveSnapshot;c.api.Delete=DeleteSnapshot;
    c.winfsp_lifecycle_phase=WinFspLifecyclePhase::Dispatching;
    g_hydration_read_before_io_hook=PauseSnapshotRead;
    Bytes pending_bytes(8);ULONG pending_done=0;NTSTATUS pending_status=STATUS_UNSUCCESSFUL;
    std::thread reader([&]{pending_status=CB_Read(&fs,regular,pending_bytes.data(),0,8,&pending_done);});
    while(!read_paused)std::this_thread::sleep_for(std::chrono::milliseconds(1));
    int shutdown=-1;std::thread drain([&]{shutdown=RunFsHostShutdownDrain(owner);});
    while(!stopped)std::this_thread::sleep_for(std::chrono::milliseconds(1));
    const bool excluded_during_stop=!WriterAvailable(path);
    release_read=true;reader.join();g_hydration_read_before_io_hook=nullptr;
    for(auto h:handles)CB_Close(&fs,h);
    release_stop=true;drain.join();
    Check(NT_SUCCESS(pending_status)&&pending_done==8&&pending_bytes==bytes,"pending real read finishes with historical bytes during owned teardown");
    Check(excluded_during_stop&&shutdown==0&&removed&&deleted&&owner,"owned teardown preserves lease until dispatcher finished");
    Check(!WriterAvailable(path),"lease retained by owner after callback teardown");
    std::ifstream terminal(c.args.status_file);std::string terminal_json((std::istreambuf_iterator<char>(terminal)),{});terminal.close();
    Check(terminal_json.find("\"mountReady\":false")!=std::string::npos,"graceful shutdown terminal status");
    CleanupHydrationSession(owner.get());LocalFree(owner->sd);owner->sd=nullptr;owner.reset();
    Check(WriterAvailable(path),"lease released only after owner destroyed");
    Pass("real startup namespace callbacks status shutdown and stable lease lifetime");
}
}
int main(int argc,char** argv) {
    try {
        auto fixture=MountFixture();
        if(argc==3&&std::string(argv[1])=="--make-fixture") {
            Save(std::filesystem::absolute(argv[2]),fixture.image);
            std::cout<<"container="<<fixture.scope.container_uuid_hex<<" volume=101 xid=10 name=backup\n"
                <<"report.txt=8192 bytes: snapshot then zeros; alias.txt same inode; live report.txt=LIVEVIEW\n"
                <<"ResourceFork=fork-past; FinderInfo=32 bytes 0x42\n";return 0;
        }
        const auto path=std::filesystem::absolute("snapshot-mount.apfs");Save(path,fixture.image);Save(path.parent_path()/"bad.apfs",Bytes(4096));
        Parser(path);AncestorPins(path);StartupRefusals(path);Callbacks(path);OrdinaryReadNeighbor(path);
        std::ifstream source(path,std::ios::binary);std::vector<char> current((std::istreambuf_iterator<char>(source)),{});
        Check(current.size()==fixture.image.size()&&std::memcmp(current.data(),fixture.image.data(),current.size())==0,"source byte-for-byte unchanged");
        std::cout<<"PASS "<<cases<<" cases "<<checks<<" checks; no mount performed\n";return 0;
    }catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<"\n";return 1;}
}
