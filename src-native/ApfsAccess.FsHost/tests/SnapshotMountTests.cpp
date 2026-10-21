// Real parser, startup helpers and callbacks; WinFsp teardown is stubbed only
// at the external API boundary. This executable never mounts anything.
#define APFSACCESS_FSHOST_UNIT_TEST 1
#include "../src/main.cpp"
#define main snapshot_projection_fixture_test_main
#include "SnapshotProjectionTests.cpp"
#undef main
#include "SnapshotRetirementFixture.h"
#include "RawSnapshotStartupEvidenceTests.h"

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
Fixture BackupMountFixture() {
    auto f=MountFixture();
    for(const auto block:{4ull,180ull})
        f.Edit(block,[](auto& bytes){PutU16LE(bytes,0x3C4,0x0180);});
    VectorRandomAccessSource source(f.image);
    ApfsSnapshotRecords records;std::string error;
    Check(ApfsSnapshotStore::LoadExactRecords(source,f.Identity(),records,error),"backup historical scope: "+error);
    Check(records.snapshot.metadata.volume.superblock.role_raw==0x0180,
        "historical APSB retains actual backup role");
    const auto current=LoadAppleCheckpointView(source,0,f.image.size(),error);
    Check(current&&current->volumes.size()==1&&current->volumes[0].superblock.role_raw==0x0180,
        "current APSB also has backup role");
    return f;
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
std::vector<std::wstring> NameCommand(const std::filesystem::path& image);
void Callbacks(const std::filesystem::path& path,bool by_name=false) {
    auto owner=std::make_unique<MountContext>();auto& c=*owner;
    Check(Parse(by_name?NameCommand(path):Command(path),c.args),"startup parse");std::string error;
    Check(InitializeSessionPaths(&c),"normal session paths");
    Check(PrepareExplicitSnapshotMount(c,error),"actual snapshot startup: "+error);
    Check(c.args.snapshot_xid==10&&c.metadata_store->IsImmutableSnapshotView(),
        "selected name or XID must install the immutable historical view");
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

// ---- Task 7 public tranche: name selection, enrollment, control channel ----
// --snapshot-name participates in the same strict selector discipline as
// --snapshot-xid: exactly one of the two, canonical values only, and no
// mixing with container-manifest or write selectors.
std::vector<std::wstring> NameCommand(const std::filesystem::path& image) {
    auto words=Command(image);
    words[1]=L"--snapshot-name";words[2]=L"backup";
    return words;
}
void SnapshotNameArgMatrix(const std::filesystem::path& path) {
    {
        Arguments args;Check(Parse(NameCommand(path),args),"name selector parses");
        Check(args.snapshot_xid==0&&args.snapshot_name==L"backup","name held, XID unresolved at parse");
    }
    {
        auto words=NameCommand(path);words.insert(words.end(),{L"--snapshot-xid",L"10"});
        Arguments out;Check(!Parse(words,out),"XID plus name rejected");
    }
    for (const std::wstring& name : {std::wstring(), std::wstring(L"a\r"), std::wstring(L"a\n"), std::wstring(256, L'x')}) {
        auto words = NameCommand(path);
        words[2] = name;
        Arguments out;
        Check(!Parse(words, out), "bad name refused");
    }
    {
        auto words=NameCommand(path);
        words.insert(words.end(),{L"--readwrite"});
        Arguments out;Check(!Parse(words,out),"name with readwrite rejected");
    }
    {
        auto words=NameCommand(path);
        words.insert(words.end(),{L"--container-manifest",L"D:\\manifest"});
        Arguments out;Check(!Parse(words,out),"name with manifest rejected");
    }
    {
        // 255 wide characters remain admissible at parse; inventory match decides.
        auto words=NameCommand(path);words[2]=std::wstring(255,L'y');
        Arguments args;Check(Parse(words,args)&&args.snapshot_name.size()==255,"255-char name parses");
    }
    Pass("snapshot-name selector matrix");
}
void SnapshotNameResolutionUnit() {
    using apfsaccess::catalog::ApfsSnapshotInfo;
    auto info=[](std::uint64_t xid,const std::string& name){ApfsSnapshotInfo i{};i.identity.snapshot_xid=xid;i.identity.name_utf8=name;return i;};
    std::uint64_t xid=0;std::string error;
    Check(ResolveSnapshotXidByName({info(10,"backup"),info(11,"other")},"backup",xid,error)&&xid==10,"exact match resolves");
    Check(!ResolveSnapshotXidByName({info(10,"dup"),info(11,"dup")},"dup",xid,error)&&error=="SnapshotNameAmbiguous","duplicate names refuse");
    Check(!ResolveSnapshotXidByName({info(10,"backup")},"missing",xid,error)&&error=="SnapshotNameNotFound","missing name refuses");
    Check(!ResolveSnapshotXidByName({},"backup",xid,error)&&error=="SnapshotNameNotFound","empty inventory refuses");
    Check(!ResolveSnapshotXidByName({info(10,"backup")},"",xid,error)&&error=="SnapshotNameNotFound","empty name refuses");
    Pass("snapshot name resolution unit");
}
void SnapshotNamePrepare(const std::filesystem::path& path) {
    MountContext c;Check(Parse(NameCommand(path),c.args),"name prepare parse");
    std::string error;Check(PrepareExplicitSnapshotMount(c,error),"name-selected startup: "+error);
    Check(c.args.snapshot_xid==10&&c.args.snapshot_name==L"backup","name resolved to XID 10 with name retained");
    Check(c.metadata_store&&c.metadata_store->IsImmutableSnapshotView(),"resolved view is immutable");
    Pass("snapshot name prepares the identical historical view");
}
// Canonical journal enrollment: first enrollment wins, remap refuses,
// empty refuses, and the lease query stays independent of enrollment.
void SnapshotEnrollUnit() {
    apfsaccess::rw::TransactionManager fresh(L"Strict"), again(L"Strict");
    const std::wstring canonical=L"apfs-vol:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:101";
    Check(fresh.EnrollCanonicalJournalIdentity(canonical),"fresh enrollment accepted");
    Check(fresh.EnrolledCanonicalJournalIdentity()==canonical,"enrolled identity readable");
    Check(fresh.EnrollCanonicalJournalIdentity(canonical),"same-value enrollment idempotent");
    Check(!fresh.EnrollCanonicalJournalIdentity(L"apfs-vol:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:101"),"remap refused");
    Check(!again.EnrollCanonicalJournalIdentity(L""),"empty enrollment refused");
    Check(!fresh.OwnsEnrolledCanonicalJournal(L"D:\\journal.wal",L"apfs-vol:cccccccccccccccccccccccccccccccc:101"),"wrong identity owns nothing");
    Check(!fresh.OwnsEnrolledCanonicalJournal(L"D:\\other.wal",canonical),"unleased journal owns nothing");
    Pass("canonical journal enrollment state machine");
}
// Immutable-write diagnostic: every mutation entry point refuses with the
// snapshot-scoped message while the Win32 status stays write-protected.
void SnapshotImmutableDiagnostic(const std::filesystem::path& path) {
    MountContext c;Check(Parse(Command(path),c.args),"diagnostic parse");
    auto capture=[&](const wchar_t* operation) {
        std::wstringstream buffer;auto* previous=std::wcerr.rdbuf(buffer.rdbuf());
        const auto status=HandleMutationWriteDisabled(&c,operation);
        std::wcerr.rdbuf(previous);
        Check(status==STATUS_MEDIA_WRITE_PROTECTED,"write-protected status");
        return buffer.str();
    };
    const auto text=capture(L"Write");
    Check(text.find(L"immutable snapshot")!=std::wstring::npos&&text.find(L"snapshot_xid=10")!=std::wstring::npos,
        "snapshot diagnostic names the immutable target");
    MountContext plain;plain.args.snapshot_xid=0;
    std::wstringstream buffer;auto* previous=std::wcerr.rdbuf(buffer.rdbuf());
    Check(HandleMutationWriteDisabled(&plain,L"Write")==STATUS_MEDIA_WRITE_PROTECTED,"ordinary refusal unchanged");
    std::wcerr.rdbuf(previous);
    Check(buffer.str().find(L"immutable snapshot")==std::wstring::npos,"ordinary diagnostic stays generic");
    Pass("immutable snapshot write diagnostic");
}
// ---- Control-channel snapshot operations over a real coordinator ----
const std::string kControlToken(64,'e');
const std::string kControlRequestId(32,'f');
std::string ControlContents(const std::string& action,std::uint64_t oid,const std::vector<std::string>& extra={}) {
    std::string body="APFS-CONTROL/1\n"+kControlRequestId+"\n"+kControlToken+"\n"+action+"\n"+std::to_string(oid)+"\n";
    for(const auto& line:extra)body+=line+"\n";
    return body;
}
bool ParseControl(const std::string& contents,ContainerControlRequest& request,std::string& error) {
    return ParseContainerControlRequestContents(contents,kControlToken,request,error);
}
void SnapshotControlParseMatrix() {
    ContainerControlRequest request;std::string error;
    Check(ParseControl(ControlContents("snapshot-create",101,{"backup"}),request,error)&&
        request.action==ContainerControlAction::SnapshotCreate&&request.volume_object_id==101&&
        request.snapshot_name=="backup","create parses");
    {
        std::vector<std::string> fields={"11","backup","249","17","230","8293","8","250","10"};
        Check(ParseControl(ControlContents("snapshot-delete",101,fields),request,error)&&
            request.action==ContainerControlAction::SnapshotDelete&&request.has_snapshot_identity&&
            request.snapshot_identity.snapshot_xid==11&&request.snapshot_identity.name_utf8=="backup"&&
            request.snapshot_identity.superblock_physical_block==249&&request.snapshot_identity.omap_physical_block==17&&
            request.snapshot_identity.omap_tree_physical_block==230&&request.snapshot_identity.root_oid==8293&&
            request.snapshot_identity.root_physical_block==8&&request.snapshot_identity.extentref_physical_block==250&&
            request.snapshot_identity.scope.checkpoint_xid==10,"delete parses full identity");
    }
    Check(ParseControl(ControlContents("snapshot-recover",101),request,error)&&
        request.action==ContainerControlAction::SnapshotRecover,"recover parses");
    Check(!ParseControl(ControlContents("snapshot-frobnicate",101),request,error),"unknown action refused");
    {
        auto bad=ControlContents("snapshot-create",101,{"backup"});
        bad.replace(bad.find(kControlToken),64,std::string(64,'g'));
        Check(!ParseControl(bad,request,error),"wrong token refused");
    }
    Check(!ParseControl(ControlContents("snapshot-create",0,{"backup"}),request,error),"zero OID refused");
    Check(!ParseControl(ControlContents("snapshot-create",101,{}),request,error),"missing name refused");
    Check(!ParseControl(ControlContents("snapshot-create",101,{""}),request,error),"empty name refused");
    Check(!ParseControl(ControlContents("snapshot-create",101,{std::string(256,'x')}),request,error),"overlong name refused");
    Check(!ParseControl(ControlContents("snapshot-create",101,{"a\nb"}),request,error),"multiline name refused");
    Check(!ParseControl(ControlContents("snapshot-create",101,{"ok","trailing"}),request,error),"trailing data refused");
    Check(!ParseControl(ControlContents("snapshot-recover",101,{"extra"}),request,error),"recover extras refused");
    Check(!ParseControl(ControlContents("snapshot-delete",101,{"11","backup"}),request,error),"short identity refused");
    {
        auto fields=std::vector<std::string>{"01","backup","249","17","230","8293","8","250","10"};
        Check(!ParseControl(ControlContents("snapshot-delete",101,fields),request,error),"noncanonical decimal refused");
    }
    {
        auto fields=std::vector<std::string>{"0","backup","249","17","230","8293","8","250","10"};
        Check(!ParseControl(ControlContents("snapshot-delete",101,fields),request,error),"zero XID refused");
    }
    {
        // 512-byte envelope bound: a maximal name still fits, a larger body refuses.
        auto big=ControlContents("snapshot-create",101,{std::string(200,'y')});
        Check(ParseControl(big,request,error),"200-byte name parses");
        Check(!ParseControl(big+std::string(400,'z'),request,error),"oversize envelope refused");
    }
    {
        // Volume OID is canonical: a lax spelling must not silently address
        // another volume than the sender named.
        std::string raw="APFS-CONTROL/1\n"+kControlRequestId+"\n"+kControlToken+"\nsnapshot-create\n01\nbackup\n";
        Check(!ParseControl(raw,request,error),"noncanonical volume OID refused");
        raw="APFS-CONTROL/1\n"+kControlRequestId+"\n"+kControlToken+"\nsnapshot-recover\n101\n";
        Check(ParseControl(raw,request,error)&&request.action==ContainerControlAction::SnapshotRecover,"canonical recover parses");
    }
    Check(!ParseControl(ControlContents("snapshot-create",101,{"a\rb"}),request,error),"carriage-return name refused");
    {
        auto fields=std::vector<std::string>{"11","a\rb","249","17","230","8293","8","250","10"};
        Check(!ParseControl(ControlContents("snapshot-delete",101,fields),request,error),"carriage-return delete name refused");
    }
    Pass("snapshot control request matrix");
}
// Live dispatch through ProcessContainerControlRequest over a real
// coordinator, canonical session and enrolled session journal. The fixture
// is authoritative with history and uses the original production recovery
// storage and startup reconciliation, without invoking a WinFsp mount.
// Complete historical ownership and allocator accounting before dispatch.
void ReserveDispatchFixtureSnapshotBlocks(apfsaccess::testfixture::SnapshotFixture& fixture) {
    apfsaccess::testfixture::CompleteDispatchSnapshotRetirementFixture(fixture);
}
struct DispatchStorageEnvironment {
    std::wstring name;
    std::optional<std::wstring> previous;
    DispatchStorageEnvironment(const wchar_t* key, const std::filesystem::path& root) : name(key) {
        if (const auto* value = _wgetenv(key)) previous = value;
        Check(_wputenv_s(key, root.c_str()) == 0, "private dispatch storage environment");
    }
    ~DispatchStorageEnvironment() { (void)_wputenv_s(name.c_str(), previous ? previous->c_str() : L""); }
};
struct DispatchHarness {
    std::filesystem::path dir, image, journal, control, status;
    std::unique_ptr<DispatchStorageEnvironment> recovery_root, spool_root;
    std::unique_ptr<apfsaccess::catalog::ContainerMountCoordinator> owner;
    std::vector<std::unique_ptr<MountContext>> contexts;
    Arguments process_args;
    std::string container_uuid;
    std::wstring journal_identity = L"apfs-recovery-v1-" + std::wstring(43, L'A');
    bool ready = false;
    explicit DispatchHarness(const std::string& tag) {
        const auto suffix = std::to_string(GetCurrentProcessId()) + "-" + tag + "-" + std::to_string(GetTickCount64());
        const auto root = std::filesystem::temp_directory_path() / "apfsaccess-snapshot-dispatch";
        std::filesystem::create_directories(root);
        dir = root / ("snapshot-dispatch-" + suffix);
        Check(std::filesystem::create_directory(dir), "fresh private dispatch directory");
        recovery_root = std::make_unique<DispatchStorageEnvironment>(L"APFSACCESS_RECOVERY_ROOT", dir / "recovery");
        spool_root = std::make_unique<DispatchStorageEnvironment>(L"APFSACCESS_SPOOL_ROOT", dir / "spool");
        image = dir / "volume.apfs.img";
        control = dir / "owner.control";
        status = dir / "owner.status.json";
        apfsaccess::testfixture::SnapshotFixture fixture;
        ReserveDispatchFixtureSnapshotBlocks(fixture);
        Save(image, fixture.image);
    }
    ~DispatchHarness() { Teardown(true); }
    void Teardown(bool remove) {
        contexts.clear();
        if (owner) (void)owner->DrainAndStop(std::chrono::seconds(10));
        owner.reset();
        ready = false;
        if (remove) { std::error_code ec; std::filesystem::remove_all(dir, ec); }
    }
    // Restart the owner over the same image and journal without regenerating
    // them: the interrupted commit latched container recovery, which is
    // terminal for the failed owner process. Only a restarted owner may
    // replay the accepted debt it left behind.
    bool Restart(std::string& error) { Teardown(false); return Open(error); }
    MountContext& session() { return *contexts.front(); }
    bool Open(std::string& error) {
        error.clear();
        std::string open_error;
        owner = apfsaccess::catalog::ContainerMountCoordinator::Open(
            image.string(), 0, open_error,
            apfsaccess::catalog::CatalogLoadPolicy::StrictApple, true, true);
        if (!owner) { error = "DispatchOwnerOpen: " + open_error; return false; }
        container_uuid = owner->ContainerUuidHex();
        auto session_context = std::make_unique<MountContext>();
        session_context->args.device = image.wstring();
        session_context->args.container_id = Utf8ToWide(container_uuid);
        session_context->args.recovery_identity = journal_identity;
        session_context->args.volume_object_id = 101;
        session_context->args.volume = L"Data";
        session_context->args.container_manifest = L"test-manifest";
        session_context->args.readwrite = true;
        session_context->args.write_backend = L"Native";
        session_context->args.allow_legacy_scaffold_for_fixtures = false;
        session_context->args.enable_image_snapshots = true;
        session_context->args.write_crash_replay_mode = L"FailClosed";
        session_context->native_write_enabled.store(true, std::memory_order_release);
        session_context->recovery_marker_file = BuildRecoveryMarkerPath(session_context->args);
        (void)LoadRecoveryMarkerAtStartup(*session_context);
        const auto storage = BuildPayloadSpoolSessionRoot(session_context->args,
            apfsaccess::rw::PayloadSpool::ResolveDefaultRoot());
        journal = storage / "write-ahead.wal";
        session_context->tx_manager = std::make_unique<apfsaccess::rw::TransactionManager>(L"Strict");
        session_context->tx_journal_file = journal;
        auto& tx = *session_context->tx_manager;
        tx.SetJournalPath(journal.wstring());
        tx.SetVolumeIdentity(journal_identity);
        // Enrollment preserves the original configured recovery identity.
        const auto canonical = Utf8ToWide("apfs-vol:" + container_uuid + ":101");
        if (!tx.EnrollCanonicalJournalIdentity(canonical)) { error = "DispatchEnroll"; return false; }
        if (!tx.AcquireJournalOwnership(error)) return false;
        const auto marks = tx.Watermarks();
        if (!ArmRecoveryMarkerForPendingWriteAheadLog(*session_context, !tx.RecoveryStateValid() ||
                tx.HasUnappliedAcceptedWork() || marks.cleanup_sequence < marks.apfs_durable_sequence))
        { error = "DispatchMarkerArm"; return false; }
        session_context->payload_spool_volume_identity = WideToUtf8(journal_identity);
        session_context->payload_spool = std::make_unique<apfsaccess::rw::PayloadSpool>(
            apfsaccess::rw::PayloadSpool::Options{storage, session_context->payload_spool_volume_identity,
                kPayloadSpoolMaxBytes, kPayloadSpoolForegroundFlushBytes, kPayloadSpoolForegroundFlushAppends});
        std::wstring mount_error;
        if (!MountManifestSession(*owner, session_context->args, *session_context, mount_error))
        { error = "DispatchMount: " + WideToUtf8(mount_error); return false; }
        contexts.push_back(std::move(session_context));
        if (!InitializeManifestCheckpointCensus(*owner, contexts, open_error))
        { error = "DispatchCensus: " + open_error; return false; }
        auto& c = session();
        if (!c.metadata_store->IsNativeWriteReady()) { error = "DispatchMetadataNotReady"; return false; }
        c.runtime_last_commit_xid = ResolveCleanRecoveryCheckpointXid(*c.metadata_store);
        bool pending = !tx.RecoveryStateValid() || tx.HasUnappliedAcceptedWork() ||
            marks.cleanup_sequence < marks.apfs_durable_sequence;
        if (pending && c.native_write_enabled && ReplayAcceptedWriteAheadLogAfterMetadataBootstrap(c)) pending = false;
        ReconcilePayloadSpoolRecoveryAfterMetadataBootstrap(c, c.payload_spool->RecoveryRequired());
        ReconcileWriteAheadLogRecoveryAfterMetadataBootstrap(c, pending);
        process_args.container_control_file = control.wstring();
        process_args.container_control_token = Utf8ToWide(kControlToken);
        process_args.status_file = status.wstring();
        ready = true;
        return true;
    }
    // Dispatches one control request body, returns the response code line.
    std::string Dispatch(const std::string& body, bool& consumed) {
        consumed = false;
        {
            std::ofstream out(control, std::ios::binary | std::ios::trunc);
            out.write(body.data(), static_cast<std::streamsize>(body.size()));
        }
        const auto response = control.wstring() + L".response";
        std::error_code ec;
        std::filesystem::remove(response, ec);
        if (!ProcessContainerControlRequest(process_args, *owner, contexts)) return {};
        consumed = !std::filesystem::exists(control, ec);
        std::ifstream in(response, std::ios::binary);
        std::ostringstream text;
        text << in.rdbuf();
        const auto lines = text.str();
        // Response envelope: APFS-CONTROL/1, request id, ok|error, code.
        std::vector<std::string> fields;
        std::istringstream input(lines);
        std::string line;
        while (std::getline(input, line))
        {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            fields.push_back(line);
        }
        while (!fields.empty() && fields.back().empty()) fields.pop_back();
        if (fields.size() != 4 || fields[0] != "APFS-CONTROL/1" || fields[1] != kControlRequestId ||
            (fields[2] != "ok" && fields[2] != "error"))
        {
            return {};
        }
        return fields[2] + ":" + fields[3];
    }
};

Bytes DispatchHeldImageBytes(DispatchHarness& harness) {
    const auto& device = harness.owner->Device();
    const auto size = device.GetGeometry().total_bytes;
    constexpr std::size_t window = 128 * 1024;
    Check(size >= window && size <= 256 * 1024 * 1024, "bounded full dispatch image");
    apfsaccess::rw::BlockDevice::StableImageIdentity before, after;
    Check(device.QueryHeldImageIdentity(before), "dispatch held source identity");
    Bytes image(static_cast<std::size_t>(size)), bytes;
    // Windows larger reads bypass the device's small-read cache.
    for (std::uint64_t at = 0; at < size; at += window) {
        const auto start = (std::min)(at, size - window);
        Check(device.Read(start, window, bytes) && bytes.size() == window, "fresh dispatch held image window");
        std::copy(bytes.begin(), bytes.end(), image.begin() + static_cast<std::size_t>(start));
    }
    Check(device.QueryHeldImageIdentity(after) && before == after, "stable dispatch image during reads");
    return image;
}
std::vector<char> DispatchWalBytes(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    Check(in.good(), "read original dispatch WAL");
    return std::vector<char>((std::istreambuf_iterator<char>(in)), {});
}
struct DispatchEvidence {
    Bytes image;
    std::vector<std::vector<char>> journals;
    std::vector<apfsaccess::rw::TransactionManager::DurabilityWatermarks> watermarks;
};
DispatchEvidence CaptureDispatchEvidence(DispatchHarness& harness) {
    DispatchEvidence proof;
    proof.image = DispatchHeldImageBytes(harness);
    for (const auto& c : harness.contexts) {
        proof.journals.push_back(DispatchWalBytes(c->tx_journal_file));
        proof.watermarks.push_back(c->tx_manager->Watermarks());
    }
    return proof;
}
void CheckDispatchUnchanged(DispatchHarness& harness, const DispatchEvidence& proof, const std::string& reason) {
    Check(DispatchHeldImageBytes(harness) == proof.image && harness.contexts.size() == proof.journals.size(),
        reason + " preserves entire held image and peer set");
    for (std::size_t i = 0; i < harness.contexts.size(); ++i) {
        const auto& c = *harness.contexts[i];
        const auto marks = c.tx_manager->Watermarks(), before = proof.watermarks[i];
        Check(DispatchWalBytes(c.tx_journal_file) == proof.journals[i] &&
            marks.accepted_sequence == before.accepted_sequence && marks.apfs_durable_sequence == before.apfs_durable_sequence &&
            marks.cleanup_sequence == before.cleanup_sequence, reason + " preserves original WAL and every watermark");
    }
}

std::vector<apfsaccess::catalog::ApfsSnapshotInfo> DispatchEnumerate(
    apfsaccess::catalog::ContainerMountCoordinator& owner) {
    // Read-only inventory straight off the owner lease (no session needed).
    class LeaseSource final : public apfsaccess::catalog::RandomAccessSource {
    public:
        explicit LeaseSource(const apfsaccess::rw::BlockDevice& device) : device_(device) {}
        std::uint64_t SizeBytes() const override { return device_.GetGeometry().total_bytes; }
        bool Read(std::uint64_t offset, std::size_t count, std::vector<std::byte>& out) const override
        { return device_.Read(offset, count, out); }
    private:
        const apfsaccess::rw::BlockDevice& device_;
    };
    LeaseSource source(owner.Device());
    apfsaccess::catalog::ApfsContainerCatalog catalog;
    std::wstring wide_error;
    std::string error;
    Check(apfsaccess::catalog::ApfsContainerCatalog::TryLoadDevice(
        owner.Device(), catalog, wide_error), "dispatch inventory catalog");
    const auto& container = catalog.Containers().front();
    Check(container.volumes.size() == 1 && container.volumes.front().object_id == 101,
        "dispatch fixture carries volume 101");
    apfsaccess::catalog::ApfsSnapshotScope scope{0, source.SizeBytes(),
        container.container_uuid_hex, container.volumes.front().volume_uuid_hex,
        container.volumes.front().object_id, container.checkpoint_xid};
    std::vector<apfsaccess::catalog::ApfsSnapshotInfo> inventory;
    Check(apfsaccess::catalog::ApfsSnapshotStore::Enumerate(source, scope, inventory, error),
        "dispatch inventory: " + error);
    return inventory;
}

std::string DispatchInventoryNames(apfsaccess::catalog::ContainerMountCoordinator& owner) {
    std::string names;
    for (const auto& entry : DispatchEnumerate(owner)) names += "[" + entry.identity.name_utf8 + "]";
    return names;
}

std::vector<std::string> DispatchDeleteArgs(const apfsaccess::catalog::ApfsSnapshotIdentity& id) {
    return {std::to_string(id.snapshot_xid), id.name_utf8,
        std::to_string(id.superblock_physical_block), std::to_string(id.omap_physical_block),
        std::to_string(id.omap_tree_physical_block), std::to_string(id.root_oid),
        std::to_string(id.root_physical_block), std::to_string(id.extentref_physical_block),
        std::to_string(id.scope.checkpoint_xid)};
}

void SnapshotControlDispatch() {
    DispatchHarness harness("dispatch");
    std::string error;
    Check(harness.Open(error), "dispatch harness opens: " + error);
    bool consumed = false;
    const auto initial = CaptureDispatchEvidence(harness);
    // Unknown volume refuses before touching any session.
    Check(harness.Dispatch(ControlContents("snapshot-create", 999, {"ghost"}), consumed) == "error:VolumeNotPredeclared" && consumed,
        "unknown volume refused and consumed");
    CheckDispatchUnchanged(harness, initial, "unknown volume refusal");
    // Read-only sessions refuse mutations with evidence.
    harness.session().native_write_enabled.store(false, std::memory_order_release);
    Check(harness.Dispatch(ControlContents("snapshot-create", 101, {"ro-attempt"}), consumed) == "error:SnapshotSessionNotWritable" && consumed,
        "read-only session refused");
    CheckDispatchUnchanged(harness, initial, "read-only refusal");
    harness.session().native_write_enabled.store(true, std::memory_order_release);
    // Positive create through the full owner path.
    const auto created = harness.Dispatch(ControlContents("snapshot-create", 101, {"dispatched"}), consumed);
    Check(created == "ok:SnapshotCreated" && consumed, "dispatched create publishes: " + created);
    Check(DispatchInventoryNames(*harness.owner).find("[dispatched]") != std::string::npos,
        "created snapshot inventoried");
    // Duplicate name refuses before image or WAL acceptance.
    const auto duplicate_before = CaptureDispatchEvidence(harness);
    const auto duplicate = harness.Dispatch(ControlContents("snapshot-create", 101, {"dispatched"}), consumed);
    Check(duplicate.rfind("error:", 0) == 0 && consumed, "duplicate name refused and consumed");
    CheckDispatchUnchanged(harness, duplicate_before, "duplicate name refusal");
    // Status file refreshed by dispatch.
    {
        std::ifstream status(harness.status, std::ios::binary);
        std::ostringstream text;
        text << status.rdbuf();
        Check(text.str().find(harness.container_uuid) != std::string::npos, "dispatch refreshes container status");
    }
    // Recover with no debt is a clean no-op.
    Check(harness.Dispatch(ControlContents("snapshot-recover", 101), consumed) == "ok:SnapshotRecoverNoOp" && consumed,
        "clean recover is a no-op");
    CheckDispatchUnchanged(harness, duplicate_before, "clean recovery no-op");
    Pass("snapshot control dispatch lifecycle");
}

void SnapshotControlDispatchRecovery() {
    DispatchHarness harness("dispatch-recover");
    std::string error;
    Check(harness.Open(error), "recovery harness opens: " + error);
    bool consumed = false;
    Check(harness.Dispatch(ControlContents("snapshot-create", 101, {"doomed"}), consumed) == "ok:SnapshotCreated",
        "baseline snapshot published");
    // Interrupt the next publication after acceptance via the session hook.
    auto* store = harness.owner->FindSessionStore(101);
    Check(store != nullptr, "session store present");
    store->SetCommitStageHook([](std::string_view stage) { return stage != "before-apple-final-flush"; });
    const auto interrupted = harness.Dispatch(ControlContents("snapshot-create", 101, {"interrupted"}), consumed);
    Check(interrupted.rfind("error:", 0) == 0 && consumed, "interrupted publication retains recovery");
    store->SetCommitStageHook({});
    Check(harness.owner->IsRecoveryRequired() && store->IsRecoveryRequired() && !store->IsCommitPathReady(),
        "interrupted owner retains latched metadata recovery and blocked commit path");
    using Tx = apfsaccess::rw::TransactionManager;
    std::vector<Tx::AcceptedTransaction> debt;
    Check(harness.session().tx_manager->LoadAcceptedTransactionsSinceCleanup(debt, &error) &&
        debt.size() == 1 && debt.front().mutations.size() == 1, "exact accepted snapshot debt retained");
    apfsaccess::rw::NativeSnapshotIntent intent;
    Check(apfsaccess::rw::DecodeNativeSnapshotIntent(debt.front().mutations.front().inline_payload, intent) &&
        intent.create && intent.name == "interrupted" && intent.scope.volume_oid == 101 &&
        debt.front().mutations.front().volume_identity == WideToUtf8(harness.journal_identity),
        "original recovery-form receipt identifies interrupted snapshot");
    const auto retained = CaptureDispatchEvidence(harness);
    const auto original_journal = harness.journal, original_marker = harness.session().recovery_marker_file;
    // Further mutation refuses while recovery is latched.
    Check(harness.Dispatch(ControlContents("snapshot-create", 101, {"blocked"}), consumed).rfind("error:", 0) == 0,
        "mutation blocked during recovery");
    CheckDispatchUnchanged(harness, retained, "failed-owner mutation refusal");
    // The interruption latched container recovery, which is terminal for the
    // failed owner: in-process replay refuses fail-closed. Only a restarted
    // owner over the same image and journal may replay the accepted debt.
    const auto retained_recovery = harness.Dispatch(ControlContents("snapshot-recover", 101), consumed);
    // The host's original-peer gate wraps the engine owner-not-ready refusal:
    // BootstrapFailed metadata is never a clean original recovery peer.
    Check(retained_recovery == "error:SnapshotRecoveryOriginalPeerRequired" && consumed,
        "latched recovery refuses in-process replay: " + retained_recovery);
    CheckDispatchUnchanged(harness, retained, "failed-owner recovery refusal");
    Check(harness.Restart(error), "restart after interruption: " + error);
    auto& restarted = harness.session();
    Check(!harness.owner->IsRecoveryRequired() && restarted.metadata_store->IsNativeWriteReady() &&
        !restarted.native_write_enabled && restarted.recovery_active && restarted.write_degraded &&
        restarted.tx_journal_file == original_journal && restarted.recovery_marker_file == original_marker &&
        restarted.tx_manager->ConfiguredVolumeIdentity() == harness.journal_identity,
        "safe restart keeps original production storage and blocks writes pending explicit recovery");
    CheckDispatchUnchanged(harness, retained, "startup before authenticated recovery");
    std::vector<Tx::AcceptedTransaction> reopened_debt;
    std::vector<std::uint64_t> pins;
    Check(restarted.tx_manager->LoadAcceptedTransactionsSinceCleanup(reopened_debt, &error) &&
        reopened_debt.size() == 1 && reopened_debt.front().mutations.size() == 1 &&
        reopened_debt.front().accepted_sequence == debt.front().accepted_sequence &&
        reopened_debt.front().preimage_checkpoint_xid == debt.front().preimage_checkpoint_xid &&
        reopened_debt.front().mutations.front().inline_payload == debt.front().mutations.front().inline_payload &&
        restarted.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(pins, &error) &&
        pins == std::vector<std::uint64_t>{intent.scope.checkpoint_xid}, "restart retains exact receipt and preimage pin");
    const auto census = harness.owner->CheckpointCensusSnapshot();
    Check(census.size() == 1 && census.front().volume_object_id == 101 && census.front().unapplied_accepted_work &&
        census.front().required_checkpoint_xids == pins && restarted.container_session_contexts.size() == 1 &&
        restarted.container_session_contexts.front() == &restarted, "complete original peer and WAL-derived census");
    const auto recovered = harness.Dispatch(ControlContents("snapshot-recover", 101), consumed);
    Check(recovered == "ok:SnapshotRecovered" && consumed, "recovery replays the accepted operation: " + recovered);
    const auto marks = restarted.tx_manager->Watermarks();
    Check(marks.accepted_sequence == debt.front().accepted_sequence && marks.apfs_durable_sequence == marks.accepted_sequence &&
        marks.cleanup_sequence == marks.accepted_sequence && restarted.tx_manager->ValidatedCleanJournalGeneration() &&
        restarted.tx_manager->CanClearRecoveryState() && restarted.native_write_enabled && !restarted.recovery_active &&
        !restarted.write_degraded && !restarted.pending_native_writes, "native recovery completes original acceptance and restores writer");
    Check(restarted.tx_manager->LoadAcceptedTransactionsSinceCleanup(reopened_debt, &error) && reopened_debt.empty() &&
        restarted.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(pins, &error) && pins.empty(),
        "native completion clears original accepted suffix and preimage pins");
    const auto clean_census = harness.owner->CheckpointCensusSnapshot();
    Check(clean_census.size() == 1 && !clean_census.front().unapplied_accepted_work &&
        clean_census.front().required_checkpoint_xids.empty(), "native completion clears original census debt");
    Check(harness.owner->CheckpointXid() == intent.scope.checkpoint_xid + 1 &&
        apfsaccess::rw::VerifyPublishedSnapshot(*restarted.metadata_store, intent, error), "actual native snapshot publication: " + error);
    RecoveryMarkerState marker;
    Check(TryLoadRecoveryMarkerState(original_marker, marker) && !marker.dirty && marker.last_commit_xid == harness.owner->CheckpointXid(),
        "original production recovery marker durably clean");
    Check(DispatchInventoryNames(*harness.owner).find("[interrupted]") != std::string::npos,
        "recovered snapshot inventoried");
    const auto completed = CaptureDispatchEvidence(harness);
    Check(harness.Dispatch(ControlContents("snapshot-recover", 101), consumed) == "ok:SnapshotRecoverNoOp" && consumed,
        "second recovery is a clean no-op");
    CheckDispatchUnchanged(harness, completed, "second recovery without replay");
    Pass("snapshot control interruption and recovery");
}

void SnapshotControlRecoverDebtPending() {
    // A journal holding accepted NON-snapshot debt must not report a clean
    // no-op: the foreign work still requires its original recovery owner.
    DispatchHarness harness("dispatch-debt");
    std::string error;
    Check(harness.Open(error), "debt harness opens: " + error);
    auto* journal = harness.session().tx_manager.get();
    Check(journal != nullptr, "session journal present");
    Check(journal->Begin(), "debt transaction begins");
    apfsaccess::rw::TransactionManager::MutationIntent intent;
    intent.kind = apfsaccess::rw::TransactionManager::MutationKind::Write;
    intent.path = L"\\report.txt";
    intent.object_id = 30;
    intent.generation = 21;
    Check(journal->RecordMutation(intent), "file debt records");
    Check(journal->Accept(harness.owner->CheckpointXid()), "file debt accepted");
    std::vector<std::uint64_t> pins;
    Check(journal->LoadRequiredCheckpointXidsSinceCleanup(pins, &error) &&
        harness.owner->UpdateRequiredCheckpointXids(101, pins, error, true), "foreign accepted receipt updates real census");
    const auto retained = CaptureDispatchEvidence(harness);
    bool consumed = false;
    // Typed recovery admission rejects a Write receipt as non-snapshot.
    // SnapshotRecoverDebtPending belonged to the previous replay dispatcher.
    Check(harness.Dispatch(ControlContents("snapshot-recover", 101), consumed) ==
        "error:SnapshotRuntimeReplayIdentity" && consumed,
        "recover with foreign debt refuses instead of no-op");
    CheckDispatchUnchanged(harness, retained, "foreign accepted debt refusal");
    Check(journal->HasUnappliedAcceptedWork(), "foreign accepted work remains owed to original recovery owner");
    Pass("snapshot recover refuses clean no-op while foreign debt remains");
}

void SaveDispatchWalBytes(const std::filesystem::path& path, const std::vector<char>& bytes) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    Check(bool(out), "save terminal WAL fixture evidence");
}

void SnapshotTerminalReceiptEvidence() {
    using Wal = apfsaccess::rw::WriteAheadLog;
    DispatchHarness harness("terminal-receipt");
    std::string error;
    Check(harness.Open(error), "terminal receipt harness opens: " + error);
    bool consumed = false;
    const auto created = harness.Dispatch(ControlContents("snapshot-create", 101, {"terminal"}), consumed);
    Check(created == "ok:SnapshotCreated" && consumed, "terminal receipt publication: " + created);
    const auto before = CaptureDispatchEvidence(harness);
    auto& c = harness.session();
    const auto history = Wal::ReadAll(harness.journal, WideToUtf8(harness.journal_identity));
    Check(history.status == Wal::ReadStatus::Ok && !history.recovered_torn_tail && history.records.size() > 1,
        "real publication supplies complete terminal history");
    RetainedSnapshotRecoveryProof proof;
    {
        SnapshotControlLocks locks(c, true);
        Check(locks.acquired, "production terminal consumer owns original peer gates");
        const auto admitted = SnapshotRecoveryCleanTerminalReceipt(c, proof, error);
        Check(admitted, "production terminal budgets admit actual published receipt: " + error);
    }
    const auto inspect = [&](apfsaccess::rw::WalReadLimits limits, std::uint64_t allocation = 256ull * 1024 * 1024) {
        SnapshotControlLocks locks(c, true);
        Check(locks.acquired, "terminal inspection holds every original peer gate");
        proof = {};
        error.clear();
        return SnapshotRecoveryCleanTerminalReceipt(c, proof, error, limits, allocation);
    };
    const apfsaccess::rw::WalReadLimits exact{before.journals.front().size(), history.records.size()};
    const auto exact_admitted = inspect(exact);
    Check(exact_admitted, "terminal consumer accepts exact byte and record boundaries: " + error);
    apfsaccess::rw::BlockDevice::StableImageIdentity held;
    Check(c.metadata_store->Device().QueryHeldImageIdentity(held) && proof.source == held &&
        proof.intent && proof.intent->create && proof.intent->name == "terminal" && proof.completion_retry &&
        proof.accepted_sequence == before.watermarks.front().accepted_sequence &&
        DispatchInventoryNames(*harness.owner).find("[terminal]") != std::string::npos,
        "terminal consumer proves the actual published snapshot and original source");
    CheckDispatchUnchanged(harness, before, "successful terminal evidence inspection");
    bool observed_bounded_capacity = false;
    g_snapshot_terminal_wal_decoded_test_hook = [&](const Wal::ReadResult& decoded) {
        observed_bounded_capacity = decoded.status == Wal::ReadStatus::Ok &&
            decoded.records.size() == exact.records && decoded.records.capacity() == exact.records;
    };
    const auto tight_admitted = inspect(exact, 64ull * 1024);
    Check(tight_admitted && observed_bounded_capacity && proof.intent && proof.intent->name == "terminal",
        "actual terminal receipt fits a tight allocation budget without record-vector growth: " + error);
    CheckDispatchUnchanged(harness, before, "tight terminal allocation success");
    for (const auto limits : std::vector<apfsaccess::rw::WalReadLimits>{
            {exact.bytes - 1, exact.records}, {exact.bytes, exact.records - 1},
            {UINT64_MAX, exact.records}, {exact.bytes, SIZE_MAX}}) {
        bool observed_limit = false;
        g_snapshot_terminal_wal_decoded_test_hook = [&](const Wal::ReadResult& decoded) {
            observed_limit = decoded.status == Wal::ReadStatus::ResourceLimit && decoded.records.empty();
        };
        Check(!inspect(limits) && error == "SnapshotRecoveryTerminalWalInvalid" &&
            !proof.intent && !proof.accepted_sequence && !proof.completion_retry && observed_limit,
            "terminal consumer refuses exceeded or unlimited read budgets: " + error);
        CheckDispatchUnchanged(harness, before, "terminal read budget refusal");
    }
    bool observed_allocation_limit = false;
    g_snapshot_terminal_wal_decoded_test_hook = [&](const Wal::ReadResult& decoded) {
        observed_allocation_limit = decoded.status == Wal::ReadStatus::ResourceLimit && decoded.records.empty();
    };
    Check(!inspect(exact, 1) && error == "SnapshotRecoveryTerminalWalInvalid" && !proof.intent && observed_allocation_limit,
        "terminal consumer refuses allocation before accepting any receipt");
    CheckDispatchUnchanged(harness, before, "terminal allocation refusal");

    // A same-content replacement must not inherit the original writer's evidence.
    const auto replacement = harness.dir / "replacement.wal";
    SaveDispatchWalBytes(replacement, before.journals.front());
    g_snapshot_terminal_wal_opened_test_hook = [&](MountContext& context, HANDLE) {
        Check(!ReplaceFileW(harness.journal.c_str(), replacement.c_str(), nullptr, 0, nullptr, nullptr),
            "original held WAL excludes file replacement");
        context.tx_journal_file = replacement;
    };
    Check(!inspect(exact) && error == "SnapshotRecoveryTerminalWalInvalid" && !proof.intent,
        "terminal consumer refuses source path rebound after the original handle was pinned");
    c.tx_journal_file = harness.journal;
    CheckDispatchUnchanged(harness, before, "terminal source replacement refusal");
    Check(DispatchWalBytes(replacement) == before.journals.front(), "replacement evidence remains unchanged");
    const auto retry_admitted = inspect(exact);
    Check(retry_admitted, "original terminal evidence remains usable after replacement refusal: " + error);
    CheckDispatchUnchanged(harness, before, "terminal receipt retry after refusal");
    Pass("production terminal receipt success and bounded evidence refusals");
}

void SnapshotTerminalReceiptTornEvidence() {
    using Wal = apfsaccess::rw::WriteAheadLog;
    for (const bool truncate : {false, true}) {
        DispatchHarness harness(truncate ? "terminal-truncated" : "terminal-torn");
        std::string error;
        Check(harness.Open(error), "torn terminal harness opens: " + error);
        bool consumed = false;
        const auto created = harness.Dispatch(ControlContents("snapshot-create", 101, {"terminal-tail"}), consumed);
        Check(created == "ok:SnapshotCreated" && consumed, "tail fixture publication: " + created);
        const auto original = CaptureDispatchEvidence(harness);
        auto altered = original.journals.front();
        Check(altered.size() > 1, "complete original terminal WAL bytes");
        if (truncate) altered.pop_back();
        else altered.insert(altered.end(), {'A', 'A'});
        std::optional<DispatchEvidence> retained;
        g_snapshot_terminal_wal_opened_test_hook = [&](MountContext& context, HANDLE) {
            // Release the test owner's writer only after production inspection pins
            // the original file, then inject damage into that same held file.
            context.tx_manager->SetJournalPath(L"", false);
            const auto moved = harness.dir / "retired.wal";
            Check(!MoveFileExW(harness.journal.c_str(), moved.c_str(), 0),
                "evidence reader's own pin excludes source replacement after writer release");
            SaveDispatchWalBytes(harness.journal, altered);
            const auto legacy = Wal::ReadAll(harness.journal, WideToUtf8(harness.journal_identity));
            Check(legacy.status == Wal::ReadStatus::Ok && legacy.recovered_torn_tail && !legacy.records.empty(),
                "injected evidence has a valid prefix and incomplete tail under the unchanged legacy reader");
            retained = CaptureDispatchEvidence(harness);
        };
        RetainedSnapshotRecoveryProof proof;
        bool observed_torn_refusal = false;
        g_snapshot_terminal_wal_decoded_test_hook = [&](const Wal::ReadResult& decoded) {
            // Strict framing refuses before prefix recovery; the legacy positive above remains independent.
            observed_torn_refusal = decoded.status == Wal::ReadStatus::Corrupt &&
                !decoded.recovered_torn_tail && decoded.records.empty();
        };
        auto& c = harness.session();
        SnapshotControlLocks locks(c, true);
        Check(locks.acquired, "torn terminal consumer holds all original peer gates");
        const auto admitted = SnapshotRecoveryCleanTerminalReceipt(c, proof, error);
        Check(!admitted && error == "SnapshotRecoveryTerminalWalInvalid" &&
            !proof.intent && !proof.accepted_sequence && !proof.completion_retry && retained && observed_torn_refusal,
            "terminal consumer refuses torn or truncated evidence instead of accepting its prefix: " + error);
        Check(retained->image == original.image && retained->journals.front() == altered,
            "only the test injection changed original WAL evidence");
        CheckDispatchUnchanged(harness, *retained, truncate ? "truncated terminal refusal" : "torn terminal refusal");
    }
    Pass("production terminal reader preserves torn and truncated WAL evidence");
}

void SnapshotControlDispatchDelete() {
    DispatchHarness harness("dispatch-delete");
    std::string error;
    Check(harness.Open(error), "delete harness opens: " + error);
    bool consumed = false;
    const auto create_response = harness.Dispatch(ControlContents("snapshot-create", 101, {"victim"}), consumed);
    Check(create_response == "ok:SnapshotCreated", "victim published: " + create_response);
    auto inventory = DispatchEnumerate(*harness.owner);
    // The fixture ships a pre-existing "backup" snapshot; the dispatched
    // "victim" joins it. Select by exact name, never by position.
    const auto victim = std::find_if(inventory.begin(), inventory.end(),
        [](const auto& entry) { return entry.identity.name_utf8 == "victim"; });
    Check(victim != inventory.end(), "victim inventoried");
    // Tamper exactly one block field of the real identity: exact match refuses.
    auto tampered = DispatchDeleteArgs(victim->identity);
    tampered[6] = std::to_string(victim->identity.root_physical_block + 1);
    const auto before_refusal = CaptureDispatchEvidence(harness);
    Check(harness.Dispatch(ControlContents("snapshot-delete", 101, tampered), consumed).rfind("error:", 0) == 0,
        "tampered delete identity refused");
    CheckDispatchUnchanged(harness, before_refusal, "tampered delete identity refusal");
    auto stale = DispatchDeleteArgs(victim->identity);
    stale[8] = std::to_string(victim->identity.scope.checkpoint_xid - 1);
    Check(harness.Dispatch(ControlContents("snapshot-delete", 101, stale), consumed) ==
        "error:SnapshotRuntimeDeleteStaleIdentity" && consumed, "stale delete checkpoint refused exactly");
    CheckDispatchUnchanged(harness, before_refusal, "stale delete checkpoint refusal");
    Check(DispatchInventoryNames(*harness.owner).find("[victim]") != std::string::npos,
        "refusal retains the snapshot");
    // Exact identity deletes.
    Check(harness.Dispatch(ControlContents("snapshot-delete", 101, DispatchDeleteArgs(victim->identity)), consumed) ==
        "ok:SnapshotDeleted", "exact delete publishes");
    Check(DispatchInventoryNames(*harness.owner).find("[victim]") == std::string::npos,
        "deleted snapshot gone");
    Check(DispatchInventoryNames(*harness.owner).find("[backup]") != std::string::npos,
        "sibling snapshot retained");
    Pass("snapshot control delete refusal");
}
}
#include "RawSnapshotHostTests.h"
int main(int argc,char** argv) {
    try {
        if(argc==3&&std::string_view(argv[1])=="--make-backup-fixture"){
            auto fixture=BackupMountFixture();Save(std::filesystem::absolute(argv[2]),fixture.image);
            std::cout<<"container="<<fixture.scope.container_uuid_hex<<" volume=101 xid=10 name=backup role=backup\n"
                <<"report.txt=snapshot; live report.txt=LIVEVIEW; ResourceFork=fork-past\n";return 0;
        }
        if(argc==2&&(std::string_view(argv[1])=="--test-backup-snapshot-xid"||
            std::string_view(argv[1])=="--test-backup-snapshot-name")){
            auto fixture=BackupMountFixture();
            const auto path=std::filesystem::absolute("backup-snapshot-mount.apfs");
            Save(path,fixture.image);Save(path.parent_path()/"bad.apfs",Bytes(4096));
            Parser(path);AncestorPins(path);StartupRefusals(path);SnapshotNameArgMatrix(path);
            Callbacks(path,std::string_view(argv[1])=="--test-backup-snapshot-name");
            std::ifstream input(path,std::ios::binary);std::vector<char> bytes((std::istreambuf_iterator<char>(input)),{});
            Check(bytes.size()==fixture.image.size()&&std::memcmp(bytes.data(),fixture.image.data(),bytes.size())==0,
                "backup source remains byte-for-byte unchanged");
            std::cout<<"PASS "<<cases<<" cases "<<checks<<" checks; no mount performed\n";return 0;
        }
        if(argc==2&&std::string_view(argv[1])=="--test-raw-host-idle-retry"){
            RunRawHostIdleRetryTests();
            std::cout<<"PASS "<<cases<<" cases "<<checks<<" checks; no mount performed\n";return 0;
        }
        if(argc==2&&std::string_view(argv[1])=="--test-raw-host-contract"){
            RunRawSnapshotHostTests();
            std::cout<<"PASS "<<cases<<" cases "<<checks<<" checks; no mount performed\n";return 0;
        }
        if(argc==2&&std::string_view(argv[1])=="--test-raw-startup-evidence"){
            Check(apfsaccess::fshost::tests::RunRawSnapshotStartupEvidenceTests(),"raw startup evidence tests");
            Pass("raw startup original evidence and parent materialization");
            std::cout<<"PASS "<<cases<<" cases "<<checks<<" checks; no mount performed\n";return 0;
        }
        if(argc==2&&std::string_view(argv[1])=="--test-terminal-receipt"){
            SnapshotTerminalReceiptEvidence();SnapshotTerminalReceiptTornEvidence();
            std::cout<<"PASS "<<cases<<" cases "<<checks<<" checks; no mount performed\n";return 0;
        }
        if(argc==2&&std::string_view(argv[1])=="--test-control-delete"){
            SnapshotControlDispatchDelete();
            std::cout<<"PASS "<<cases<<" cases "<<checks<<" checks; no mount performed\n";return 0;
        }
        auto fixture=MountFixture();
        if(argc==3&&std::string(argv[1])=="--make-fixture") {
            Save(std::filesystem::absolute(argv[2]),fixture.image);
            std::cout<<"container="<<fixture.scope.container_uuid_hex<<" volume=101 xid=10 name=backup\n"
                <<"report.txt=8192 bytes: snapshot then zeros; alias.txt same inode; live report.txt=LIVEVIEW\n"
                <<"ResourceFork=fork-past; FinderInfo=32 bytes 0x42\n";return 0;
        }
        const auto path=std::filesystem::absolute("snapshot-mount.apfs");Save(path,fixture.image);Save(path.parent_path()/"bad.apfs",Bytes(4096));
        Parser(path);AncestorPins(path);StartupRefusals(path);Callbacks(path);OrdinaryReadNeighbor(path);
        SnapshotNameArgMatrix(path);SnapshotNameResolutionUnit();SnapshotNamePrepare(path);
        SnapshotEnrollUnit();SnapshotImmutableDiagnostic(path);
        SnapshotControlParseMatrix();SnapshotControlDispatch();SnapshotControlDispatchRecovery();SnapshotControlRecoverDebtPending();SnapshotControlDispatchDelete();
        SnapshotTerminalReceiptEvidence();SnapshotTerminalReceiptTornEvidence();
        RunRawSnapshotHostTests();
        Check(apfsaccess::fshost::tests::RunRawSnapshotStartupEvidenceTests(),"raw startup evidence tests");
        Pass("raw startup original evidence and parent materialization");
        SnapshotNameArgMatrix(path);SnapshotNameResolutionUnit();SnapshotNamePrepare(path);
        SnapshotEnrollUnit();SnapshotImmutableDiagnostic(path);
        SnapshotControlParseMatrix();SnapshotControlDispatch();SnapshotControlDispatchRecovery();SnapshotControlRecoverDebtPending();SnapshotControlDispatchDelete();
        std::ifstream source(path,std::ios::binary);std::vector<char> current((std::istreambuf_iterator<char>(source)),{});
        Check(current.size()==fixture.image.size()&&std::memcmp(current.data(),fixture.image.data(),current.size())==0,"source byte-for-byte unchanged");
        std::cout<<"PASS "<<cases<<" cases "<<checks<<" checks; no mount performed\n";return 0;
    }catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<"\n";return 1;}
}
