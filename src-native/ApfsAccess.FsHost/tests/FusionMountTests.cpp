#define APFSACCESS_FSHOST_UNIT_TEST 1
#include "../src/main.cpp"
#define wmain fusion_fixture_export_main
#include "FusionReadToolFixtures.cpp"
#undef wmain
namespace {
#define REQUIRE(x) Check(bool(x),std::string(__FUNCTION__)+":"+std::to_string(__LINE__)+" " #x)
const auto& fi=FusionServeInterface();
std::filesystem::path testroot;
BOOLEAN PackDir(FSP_FSCTL_DIR_INFO* d,PVOID b,ULONG size,PULONG done) {
    if(!d)return TRUE;if(*done>size || d->Size>size-*done)return FALSE;
    std::memcpy(static_cast<std::byte*>(b)+*done,d,d->Size);*done+=d->Size;return TRUE;
}
BOOLEAN PackStream(FSP_FSCTL_STREAM_INFO* d,PVOID b,ULONG size,PULONG done) {
    if(!d)return TRUE;if(*done>size || d->Size>size-*done)return FALSE;
    std::memcpy(static_cast<std::byte*>(b)+*done,d,d->Size);*done+=d->Size;return TRUE;
}
bool Writer(const std::wstring& p) {
    auto h=CreateFileW(p.c_str(),GENERIC_WRITE,7,nullptr,OPEN_EXISTING,0,nullptr);
    if(h==INVALID_HANDLE_VALUE)return false;CloseHandle(h);return true;
}
std::vector<std::wstring> Args(const std::wstring& kind=L"good",bool reverse=false) {
    CatalogFixture f;std::string error;
    std::vector<std::wstring> a={L"test",L"--fusion-images",L"--readonly",L"--container-id",std::wstring(32,L'a'),L"--volume-oid",L"101",
        L"--mount",(testroot/L"unused-mount").wstring(),L"--parent-pid",std::to_wstring(GetCurrentProcessId()),
        L"--lifetime-file",(testroot/L"lifetime").wstring(),L"--startup-gate-file",(testroot/L"gate").wstring(),
        L"--startup-gate-token",L"private-fusion-test",L"--status-file",(testroot/L"status.json").wstring(),
        L"--fusion-uuid",Utf8ToWide(f.request.fusion_uuid_hex),L"--fusion-volume-uuid",std::wstring(32,L'c'),
        L"--fusion-checkpoint-xid",L"20",L"--fusion-role-convention",L"linux-apfs-last-byte-low-bit"};
    for(unsigned slot=0;slot<2;++slot) {
        auto n=reverse?1-slot:slot;auto suffix=slot?L"-b":L"-a";auto p=(testroot/kind/(n?L"tier2.img":L"main.img")).wstring();
        FusionImageIdentity id;REQUIRE(ApfsFusionStore::InspectImage(p,id,error));
        const auto add=[&](const wchar_t* key,std::wstring value){a.push_back(std::wstring(L"--fusion-")+key+suffix);a.push_back(std::move(value));};
        add(L"member",p);add(L"identity",Utf8ToWide(apfsaccess::fusion_arguments::Identity(id)));add(L"role",n?L"tier2":L"main");
        add(L"store-id",n?L"store:tier2":L"store:main");add(L"store-offset",L"0");add(L"store-size",std::to_wstring(f.request.members[n].store_size));
    }return a;
}
void Change(std::vector<std::wstring>& a,std::wstring key,std::wstring value) {
    auto i=std::find(a.begin(),a.end(),key);REQUIRE(i!=a.end() && i+1!=a.end());*(i+1)=value;
}
bool Parse(std::vector<std::wstring> a,Arguments& out) {
    std::vector<wchar_t*> raw;for(auto& v:a)raw.push_back(v.data());return ParseArgs(static_cast<int>(raw.size()),raw.data(),out);
}
void SaveAliases(bool sibling_fields=true,const std::wstring& kind=L"aliases") {
    CatalogFixture f(false,true,true);std::string error;
    for(auto& r:f.fs) {
        auto key=ReadU64LE(r.key,0).value();
        if(key==((3ull<<60)|2))r=FileInode(2,0,2,true);
        if(key==((3ull<<60)|30)) {
            r=FileInode(30,20480,2,false,true);AppleInodeRecord inode;
            REQUIRE(ApfsExtendedRecordCodec::DecodeInode(r,inode,error));
            inode.owner=501;inode.group=20;inode.create_time=100;inode.modification_time=200;inode.change_time=300;inode.access_time=400;
            r=Enc(inode,EncodeAppleInodeRecord);
        }
    }
    if(sibling_fields)for(auto& record:f.fs) {
        AppleDirectoryRecord original;
        if(!ApfsExtendedRecordCodec::DecodeDirectory(record,ApfsNamePolicy::FromIncompatibleFeatures(1),original,error) ||
            original.file_id!=30)continue;
        original.extended_fields.push_back({1,0,Bytes(8)});
        Put(original.extended_fields.back().data,0,100);
        record=Enc(original,[&](const auto& value,auto& out,auto& err){return EncodeAppleDirectoryRecord(value,ApfsNamePolicy::FromIncompatibleFeatures(1),out,err);});
    }
    AppleDirectoryRecord d;d.parent_id=2;d.file_id=30;d.name_utf8="Alias.txt";d.flags=8;
    if(sibling_fields){d.extended_fields.push_back({1,0,Bytes(8)});Put(d.extended_fields.back().data,0,101);}
    f.fs.push_back(Enc(d,[&](const auto& value,auto& out,auto& err){return EncodeAppleDirectoryRecord(value,ApfsNamePolicy::FromIncompatibleFeatures(1),out,err);}));
    f.fs.push_back(Enc(AppleSiblingLinkRecord{30,100,2,"Café.txt"},EncodeAppleSiblingLinkRecord));
    f.fs.push_back(Enc(AppleSiblingLinkRecord{30,101,2,"Alias.txt"},EncodeAppleSiblingLinkRecord));
    f.fs.push_back(Enc(AppleSiblingMapRecord{100,30},EncodeAppleSiblingMapRecord));
    f.fs.push_back(Enc(AppleSiblingMapRecord{101,30},EncodeAppleSiblingMapRecord));
    f.fs.push_back(Enc(AppleXattrRecord{2,"user.empty",kAppleXattrDataEmbedded,{}},EncodeAppleXattrRecord));
    f.Trees();
    f.Edit(1,4,[](auto& b){std::string label=std::string(18,'A')+"😀tail";
        std::fill_n(b.begin()+0x2c0,256,std::byte{});std::memcpy(b.data()+0x2c0,label.data(),label.size());});
    std::filesystem::create_directories(testroot/kind);
    for(unsigned n=0;n<2;++n) {std::ofstream out(testroot/kind/(n?L"tier2.img":L"main.img"),std::ios::binary);
        out.write(reinterpret_cast<const char*>(f.sources[n]->bytes.data()),f.sources[n]->bytes.size());REQUIRE(bool(out));}
}
void Setup() {
    std::filesystem::create_directories(testroot);
    for(auto kind:{L"good",L"multilevel",L"encrypted",L"dirty-cache",L"nonempty-middle",L"unknown-feature",L"bad-range"}) {
        auto p=(testroot/kind).wstring();wchar_t program[]=L"fixture";wchar_t* argv[]={program,p.data(),const_cast<wchar_t*>(kind)};
        REQUIRE(fusion_fixture_export_main(3,argv)==0);
    }
    SaveAliases();SaveAliases(false,L"aliases-missing-sibling-fields");
    std::ofstream(testroot/L"lifetime")<<"held";std::ofstream(testroot/L"gate")<<"private-fusion-test";
}
void Admit(MountContext& c,const std::wstring& kind=L"good",bool reverse=false) {
    REQUIRE(Parse(Args(kind,reverse),c.args));std::ofstream(testroot/L"gate")<<"private-fusion-test";
    REQUIRE(WaitForStartupAuthorization(c.args,GetCurrentProcess(),std::chrono::milliseconds(50)));
    if(!PrepareFusionMount(c,GetCurrentProcess()))throw std::runtime_error("admission: "+(c.fusion?c.fusion->error:"no state"));
    REQUIRE(c.fusion->admitted && c.fusion->session && !c.metadata_store && !c.tx_manager && !c.payload_spool);
    c.sd=BuildWritableVolumeSecurityDescriptor(&c.sd_size);REQUIRE(c.sd);c.api.AddDir=PackDir;c.api.AddStream=PackStream;c.label=c.fusion->label;
}
struct Callbacks {
    MountContext& c;FSP_FILE_SYSTEM fs{};std::vector<PVOID> handles;
    explicit Callbacks(MountContext& c):c(c){fs.UserContext=&c;}
    ~Callbacks(){for(auto h:handles)fi.Close(&fs,h);if(c.sd){LocalFree(c.sd);c.sd=nullptr;}}
    PVOID Open(std::wstring name,FSP_FSCTL_FILE_INFO* result=nullptr) {
        PVOID h=nullptr;FSP_FSCTL_FILE_INFO info{};REQUIRE(fi.Open(&fs,name.data(),0,GENERIC_READ,&h,&info)==STATUS_SUCCESS && h);
        handles.push_back(h);if(result)*result=info;return h;
    }
};
void ArgumentCases() {
    ++cases;Arguments good;auto args=Args();REQUIRE(Parse(args,good));
    auto writable=args;*std::find(writable.begin(),writable.end(),L"--readonly")=L"--readwrite";
    writable.insert(writable.end(),{L"--fusion-write-root",(testroot/L"journal").wstring()});
    Arguments write_args;REQUIRE(Parse(writable,write_args)&&!write_args.fusion.write_root.empty()&&!write_args.readonly);
    for(const auto& extra:std::vector<std::vector<std::wstring>>{{L"--readonly"},{L"--fusion-write-root",L"D:\\duplicate"},{L"--write-backend",L"Native"},{L"--encrypted-image"}}){
        auto v=writable;v.insert(v.end(),extra.begin(),extra.end());Arguments a;REQUIRE(!Parse(v,a));
    }
    for(const auto& extra:std::vector<std::vector<std::wstring>>{{L"--readwrite"},{L"--encrypted-image"},{L"--snapshot-xid",L"20"},
        {L"--allow-raw-physical-write"},{L"--device",L"\\\\.\\PhysicalDrive0"},{L"--write-backend",L"Native"},
        {L"--fusion-images"},{L"--nonsense"},{L"--fusion-wrong",L"x"}}) {
        auto v=args;v.insert(v.end(),extra.begin(),extra.end());Arguments a;REQUIRE(!Parse(v,a));
    }
    for(const auto& [key,value]:std::vector<std::pair<std::wstring,std::wstring>>{
        {L"--fusion-role-b",L"main"},{L"--fusion-identity-b",good.fusion.selectors.at(L"identity-a")},
        {L"--fusion-checkpoint-xid",L"020"},{L"--fusion-checkpoint-xid",L"0"},{L"--fusion-store-offset-a",L"-1"},
        {L"--fusion-store-size-b",L"18446744073709551616"},{L"--fusion-uuid",std::wstring(32,L'B')},
        {L"--fusion-role-convention",L"guess"},{L"--volume-oid",L"0101"},{L"--fusion-identity-a",L"malformed"},{L"--fusion-store-id-b",L"store:main"}}) {
        auto v=args;Change(v,key,value);Arguments a;REQUIRE(!Parse(v,a));
    }
    for(std::size_t n=0;n<args.size();++n)if(args[n].starts_with(L"--fusion-") && args[n]!=L"--fusion-images") {
        auto v=args;v.erase(v.begin()+n,v.begin()+n+2);Arguments a;REQUIRE(!Parse(v,a));
    }
}
void Refusals() {
    ++cases;
    for(auto kind:{L"encrypted",L"dirty-cache",L"nonempty-middle",L"unknown-feature",L"bad-range",L"aliases-missing-sibling-fields"}) {
        MountContext c;REQUIRE(Parse(Args(kind),c.args));REQUIRE(!PrepareFusionMount(c,GetCurrentProcess()));
        REQUIRE(c.fusion && !c.fusion->session && c.fusion->failed && !c.mount_ready);
        REQUIRE(Writer((testroot/kind/L"main.img").wstring()) && Writer((testroot/kind/L"tier2.img").wstring()));
    }
    auto args=Args();
    for(const auto& [key,value]:std::vector<std::pair<std::wstring,std::wstring>>{
        {L"--fusion-member-b",(testroot/L"missing.img").wstring()},{L"--fusion-member-a",L"\\\\.\\PhysicalDrive0"},
        {L"--fusion-member-a",L"D:\\bad.img:stream"},{L"--fusion-store-size-b",L"4096"},{L"--fusion-checkpoint-xid",L"19"},
        {L"--fusion-volume-uuid",std::wstring(32,L'd')},{L"--volume-oid",L"103"},{L"--container-id",std::wstring(32,L'e')},{L"--fusion-store-offset-a",L"4096"}}) {
        auto v=args;Change(v,key,value);MountContext c;REQUIRE(Parse(v,c.args));REQUIRE(!PrepareFusionMount(c,GetCurrentProcess()));
        REQUIRE(Writer((testroot/L"good/main.img").wstring()) && Writer((testroot/L"good/tier2.img").wstring()));
        if(key==L"--fusion-member-b")REQUIRE(c.fusion->missing_members==2 && FusionStatusJson(c).find("MissingMemberReadOnly")!=std::string::npos);
    }
    MountContext reverse;Admit(reverse,L"good",true);REQUIRE(reverse.fusion->members[0].role==FusionMemberRole::Main);
    reverse.fusion->Close();LocalFree(reverse.sd);reverse.sd=nullptr;
    Change(args,L"--fusion-role-a",L"tier2");Change(args,L"--fusion-role-b",L"main");MountContext wrong;
    REQUIRE(Parse(args,wrong.args));REQUIRE(!PrepareFusionMount(wrong,GetCurrentProcess()));
    for(unsigned n=0;n<2;++n) {
        auto v=Args();auto p=(testroot/(n?L"good/tier2.img":L"good/main.img")).wstring();
        auto writer=CreateFileW(p.c_str(),GENERIC_WRITE,7,nullptr,OPEN_EXISTING,0,nullptr);REQUIRE(writer!=INVALID_HANDLE_VALUE);
        MountContext c;REQUIRE(Parse(v,c.args));REQUIRE(!PrepareFusionMount(c,GetCurrentProcess()));CloseHandle(writer);
        REQUIRE(Writer((testroot/L"good/main.img").wstring()) && Writer((testroot/L"good/tier2.img").wstring()));
    }
    for(auto key:{L"--fusion-identity-a",L"--fusion-identity-b"}) {
        auto v=Args();auto it=std::find(v.begin(),v.end(),key);auto id=apfsaccess::fusion_arguments::ParseIdentity(*(it+1));++id.write_time;
        *(it+1)=Utf8ToWide(apfsaccess::fusion_arguments::Identity(id));MountContext c;REQUIRE(Parse(v,c.args));REQUIRE(!PrepareFusionMount(c,GetCurrentProcess()));
        REQUIRE(Writer((testroot/L"good/main.img").wstring()) && Writer((testroot/L"good/tier2.img").wstring()));
    }
}
void ReadCallbacks() {
    ++cases;MountContext c;Admit(c);Callbacks cb(c);FSP_FSCTL_FILE_INFO info{};
    auto root=cb.Open(L"\\");auto file=cb.Open(L"\\Caf\u00e9.txt",&info);auto dots=cb.Open(L"\\.\\..\\Caf\u00e9.txt");
    REQUIRE(info.IndexNumber==30 && info.FileSize==20480 && info.AllocationSize==16384 && info.HardLinks==0 && (info.FileAttributes&FILE_ATTRIBUTE_READONLY));
    REQUIRE(static_cast<fusion_mount::Handle*>(file)->node.children_or_links==1);
    for(const auto& m:c.fusion->members) {
        REQUIRE(!Writer(m.path));REQUIRE(!MoveFileExW(m.path.c_str(),(m.path+L".moved").c_str(),0) && GetLastError()==ERROR_SHARING_VIOLATION);
        REQUIRE(!DeleteFileW(m.path.c_str()) && GetLastError()==ERROR_SHARING_VIOLATION);
    }
    std::vector<std::byte> bytes(32768);ULONG done=0;
    REQUIRE(fi.Read(&cb.fs,file,bytes.data(),4090,9000,&done)==STATUS_SUCCESS && done==9000);
    for(unsigned n=0;n<done;++n)REQUIRE(bytes[n]==std::byte((4090+n)/4096==0?0xa1:(4090+n)/4096==1?0xb1:(4090+n)/4096==2?0xa2:0xb2));
    REQUIRE(fi.Read(&cb.fs,dots,bytes.data(),16380,9000,&done)==STATUS_SUCCESS && done==4100 && bytes[3]==std::byte{0xb2});
    REQUIRE(std::all_of(bytes.begin()+4,bytes.begin()+done,[](auto b){return b==std::byte{};}));
    REQUIRE(fi.Read(&cb.fs,file,bytes.data(),20480,1,&done)==STATUS_END_OF_FILE && !done);
    REQUIRE(fi.Read(&cb.fs,file,bytes.data(),UINT64_MAX,0,&done)==STATUS_SUCCESS && !done);
    REQUIRE(fi.Read(&cb.fs,root,bytes.data(),0,1,&done)==STATUS_FILE_IS_A_DIRECTORY && !done);
    auto fork=cb.Open(L"\\Caf\u00e9.txt:APFS.ResourceFork:$DATA",&info);REQUIRE(info.FileSize==8192 && info.IndexNumber==30);
    REQUIRE(fi.Read(&cb.fs,fork,bytes.data(),4090,100,&done)==STATUS_SUCCESS && done==100);
    REQUIRE(std::all_of(bytes.begin(),bytes.begin()+6,[](auto b){return b==std::byte{'X'};}));
    REQUIRE(std::all_of(bytes.begin()+6,bytes.begin()+100,[](auto b){return b==std::byte{'Y'};}));
    auto finder=cb.Open(L"\\Caf\u00e9.txt:APFS.FinderInfo:$DATA");REQUIRE(fi.Read(&cb.fs,finder,bytes.data(),5,40,&done)==STATUS_SUCCESS && done==27);
    REQUIRE(std::all_of(bytes.begin(),bytes.begin()+done,[](auto b){return b==std::byte{0x42};}));
    auto standard=cb.Open(L"\\Caf\u00e9.txt"+EncStreamName("com.apple.ResourceFork"));
    REQUIRE(fi.Read(&cb.fs,standard,bytes.data(),8180,100,&done)==STATUS_SUCCESS && done==12);
    auto protocol=cb.Open(L"\\Caf\u00e9.txt:APFS.XattrProtocol:$DATA");
    REQUIRE(fi.Read(&cb.fs,protocol,bytes.data(),5,100,&done)==STATUS_SUCCESS && done==8 && std::memcmp(bytes.data(),"XATTR/1\n",8)==0);
    FSP_FSCTL_VOLUME_PARAMS vp{};FILETIME now{};ConfigureVolumeParamsForExplorer(c,now,vp);
    REQUIRE(vp.ReadOnlyVolume && vp.NamedStreams && !vp.ReparsePoints && !vp.PersistentAcls && !vp.SupportsPosixUnlinkRename);
    FSP_FSCTL_VOLUME_INFO vi{};REQUIRE(fi.GetVolumeInfo(&cb.fs,&vi)==STATUS_SUCCESS && vi.FreeSize==0 && vi.TotalSize==0);
    SIZE_T size=0;REQUIRE(fi.GetSecurity(&cb.fs,file,nullptr,&size)==STATUS_BUFFER_OVERFLOW && size==c.sd_size);
    REQUIRE(fi.Flush(&cb.fs,file,&info)==STATUS_SUCCESS && fi.Flush(&cb.fs,nullptr,nullptr)==STATUS_SUCCESS);
    for(auto name:{L"\\missing",L"\\Caf\u00e9.txt\\child",L"\\Caf\u00e9.txt:bad:$DATA",L"\\Caf\u00e9.txt:APFS.Xattr.00:$DATA"}) {
        PVOID h=nullptr;auto text=std::wstring(name);REQUIRE(!NT_SUCCESS(fi.Open(&cb.fs,text.data(),0,GENERIC_READ,&h,&info)) && !h);
    }
    const auto budget=c.fusion->budget;budget->LimitRemainingTo(0,0,0,0);
    for(unsigned n=0;n<27000;++n) {
        REQUIRE(fi.Read(&cb.fs,file,bytes.data(),0,16384,&done)==STATUS_SUCCESS && done==16384);
        REQUIRE(bytes[0]==std::byte{0xa1} && bytes[4096]==std::byte{0xb1} && bytes[8192]==std::byte{0xa2} && bytes[12288]==std::byte{0xb2});
    }
    for(unsigned n=0;n<21000;++n) {ApfsContainerCatalog cat;std::string error;std::lock_guard lock(c.fusion->serial);REQUIRE(c.fusion->session->GetCatalog(cat,error));}
    REQUIRE(c.fusion->budget==budget && !budget->Failed() && !c.fusion->cancelled->load());
    std::cout<<"Repeated runtime: 27000 x 16 KiB = 442368000 bytes, 108000 member reads; 21000 catalog copies; original credits held at zero\n";
}
void AliasMetadata() {
    ++cases;MountContext c;Admit(c,L"aliases");Callbacks cb(c);FSP_FSCTL_FILE_INFO info;
    REQUIRE(c.args.incompatible_features==1 && c.fusion->label==std::wstring(18,L'A')+L" (read-only)");
    auto a=cb.Open(L"\\CAFÉ.TXT",&info);auto b=cb.Open(L"\\alias.txt");
    auto* ah=static_cast<fusion_mount::Handle*>(a);auto* bh=static_cast<fusion_mount::Handle*>(b);
    REQUIRE(ah->node.inode_id==bh->node.inode_id && ah->sibling==100 && bh->sibling==101 && ah->entry_parent==2 && bh->entry_parent==2);
    REQUIRE(ah->node.uid==501 && ah->node.gid==20 && ah->node.mode==0100644);
    REQUIRE(info.CreationTime==116444736000000001ULL && info.LastWriteTime==116444736000000002ULL &&
        info.ChangeTime==116444736000000003ULL && info.LastAccessTime==116444736000000004ULL && info.HardLinks==0);
    REQUIRE(ah->node.children_or_links==2 && bh->node.children_or_links==2);
    auto empty=cb.Open(L"\\:APFS.Xattr.757365722E656D707479:$DATA");ULONG done=9;std::array<std::byte,8> bytes;
    REQUIRE(fi.Read(&cb.fs,empty,bytes.data(),0,1,&done)==STATUS_END_OF_FILE && !done);
    std::wstring invalid=L"\\";invalid.push_back(0xd800);PVOID out=nullptr;
    REQUIRE(!NT_SUCCESS(fi.Open(&cb.fs,invalid.data(),0,GENERIC_READ,&out,&info)) && !out);
    REQUIRE(fi.GetFileInfo(&cb.fs,a,&info)==STATUS_SUCCESS);
}
void HeldLeaseDrain() {
    ++cases;MountContext c;Admit(c);Callbacks cb(c);
    std::atomic<bool> entered=false,release=false,closed=false;
    // Hold the actual callback wrapper after a production read with both leases.
    NTSTATUS result=STATUS_UNSUCCESSFUL;
    std::jthread reader([&](){result=FusionCall(&cb.fs,"FusionHeldLease",[&](MountContext&,fusion_mount::State& s){
        std::string error;std::vector<std::byte> data;
        if(!s.session->ReadFile(30,0,8192,data,error))return FusionStatus(s,false);
        entered=true;while(!release)Sleep(1);return STATUS_SUCCESS;
    });});
    auto deadline=GetTickCount64()+5000;while(!entered && GetTickCount64()<deadline)Sleep(1);
    std::jthread closer([&](){c.fusion->Close();closed=true;});Sleep(20);
    bool held=entered && !closed && !Writer(c.fusion->members[0].path) && !Writer(c.fusion->members[1].path);
    release=true;reader.join();closer.join();
    REQUIRE(held && result==STATUS_CANCELLED && c.active_callback_count==0 && c.fusion->threads.empty());
    REQUIRE(Writer(c.fusion->members[0].path) && Writer(c.fusion->members[1].path));
}
void Mutations() {
    ++cases;MountContext c;Admit(c);Callbacks cb(c);auto file=cb.Open(L"\\Caf\u00e9.txt");FSP_FSCTL_FILE_INFO info{};ULONG done=7;PVOID h=nullptr;auto name=std::wstring(L"\\Caf\u00e9.txt");
    for(UINT32 access:std::array<UINT32,9>{FILE_WRITE_DATA,FILE_APPEND_DATA,FILE_WRITE_EA,FILE_WRITE_ATTRIBUTES,DELETE,WRITE_DAC,WRITE_OWNER,GENERIC_WRITE,GENERIC_ALL})
        REQUIRE(fi.Open(&cb.fs,name.data(),0,access,&h,&info)==STATUS_MEDIA_WRITE_PROTECTED && !h);
    REQUIRE(fi.Open(&cb.fs,name.data(),FILE_DELETE_ON_CLOSE,GENERIC_READ,&h,&info)==STATUS_MEDIA_WRITE_PROTECTED);
    REQUIRE(fi.Create(&cb.fs,name.data(),0,0,0,nullptr,0,&h,&info)==STATUS_MEDIA_WRITE_PROTECTED);
    REQUIRE(!fi.CreateEx||fi.CreateEx(&cb.fs,name.data(),0,0,0,nullptr,0,nullptr,0,FALSE,&h,&info)==STATUS_MEDIA_WRITE_PROTECTED);
    REQUIRE(fi.Overwrite(&cb.fs,file,0,FALSE,0,&info)==STATUS_MEDIA_WRITE_PROTECTED);
    REQUIRE(!fi.OverwriteEx||fi.OverwriteEx(&cb.fs,file,0,FALSE,0,nullptr,0,&info)==STATUS_MEDIA_WRITE_PROTECTED);
    REQUIRE(fi.Write(&cb.fs,file,nullptr,0,0,FALSE,FALSE,&done,&info)==STATUS_MEDIA_WRITE_PROTECTED && !done);
    REQUIRE(fi.SetBasicInfo(&cb.fs,file,0,0,0,0,0,&info)==STATUS_MEDIA_WRITE_PROTECTED);
    REQUIRE(fi.SetFileSize(&cb.fs,file,0,FALSE,&info)==STATUS_MEDIA_WRITE_PROTECTED);
    REQUIRE(fi.CanDelete(&cb.fs,file,name.data())==STATUS_MEDIA_WRITE_PROTECTED);
    REQUIRE(fi.SetDelete(&cb.fs,file,name.data(),TRUE)==STATUS_MEDIA_WRITE_PROTECTED);
    REQUIRE(fi.Rename(&cb.fs,file,name.data(),name.data(),FALSE)==STATUS_MEDIA_WRITE_PROTECTED);
    REQUIRE(fi.SetSecurity(&cb.fs,file,0,nullptr)==STATUS_MEDIA_WRITE_PROTECTED);
    REQUIRE(fi.SetEa(&cb.fs,file,nullptr,0,&info)==STATUS_MEDIA_WRITE_PROTECTED);
    REQUIRE(fi.SetVolumeLabel(&cb.fs,name.data(),nullptr)==STATUS_MEDIA_WRITE_PROTECTED);
    REQUIRE(fi.SetReparsePoint(&cb.fs,file,name.data(),nullptr,0)==STATUS_MEDIA_WRITE_PROTECTED);
    REQUIRE(fi.DeleteReparsePoint(&cb.fs,file,name.data(),nullptr,0)==STATUS_MEDIA_WRITE_PROTECTED);
    REQUIRE(fi.Control(&cb.fs,file,FSCTL_SET_SPARSE,nullptr,0,nullptr,0,&done)==STATUS_MEDIA_WRITE_PROTECTED && !done);
    fi.Cleanup(&cb.fs,file,name.data(),0);REQUIRE(fi.GetFileInfo(&cb.fs,file,&info)==STATUS_SUCCESS);
    REQUIRE(!c.fusion->failed && !c.fusion->cancelled->load());
    auto forged=cb.Open(name);
    fi.Cleanup(&cb.fs,forged,name.data(),FspCleanupDelete);
    REQUIRE(c.fusion->failed && c.fusion->cancelled->load());
    REQUIRE(!NT_SUCCESS(fi.GetFileInfo(&cb.fs,forged,&info)));
}
void Packing() {
    ++cases;MountContext c;Admit(c,L"multilevel");Callbacks cb(c);auto root=cb.Open(L"\\");auto file=cb.Open(L"\\Caf\u00e9.txt");
    std::array<std::byte,4096> bytes{};ULONG done=999;constexpr ULONG cap=4096;
    c.api.AddDir=nullptr;REQUIRE(fi.ReadDirectory(&cb.fs,root,nullptr,nullptr,bytes.data(),cap,&done)==STATUS_INVALID_DEVICE_STATE && !done);c.api.AddDir=PackDir;
    REQUIRE(fi.ReadDirectory(&cb.fs,root,nullptr,nullptr,bytes.data(),1,&done)==STATUS_SUCCESS && !done);
    std::wstring marker;std::set<std::wstring> seen;
    for(unsigned n=0;n<40;++n) {
        REQUIRE(fi.ReadDirectory(&cb.fs,root,nullptr,marker.empty()?nullptr:marker.data(),bytes.data(),160,&done)==STATUS_SUCCESS);
        if(!done)break;
        for(ULONG at=0;at<done;) {auto* d=reinterpret_cast<FSP_FSCTL_DIR_INFO*>(bytes.data()+at);REQUIRE(d->Size>=sizeof(*d) && at+d->Size<=done);
            marker.assign(d->FileNameBuf,(d->Size-sizeof(*d))/sizeof(WCHAR));REQUIRE(seen.insert(marker).second);REQUIRE(d->FileInfo.IndexNumber);at+=d->Size;}
    }
    REQUIRE(seen.size()==33 && seen.contains(L"Caf\u00e9.txt") && seen.contains(L".") && seen.contains(L".."));
    auto missing=std::wstring(L"not-a-marker");REQUIRE(fi.ReadDirectory(&cb.fs,root,nullptr,missing.data(),bytes.data(),cap,&done)==STATUS_OBJECT_NAME_NOT_FOUND && !done);
    c.api.AddStream=nullptr;REQUIRE(fi.GetStreamInfo(&cb.fs,file,bytes.data(),cap,&done)==STATUS_INVALID_DEVICE_STATE && !done);c.api.AddStream=PackStream;
    REQUIRE(fi.GetStreamInfo(&cb.fs,file,bytes.data(),80,&done)==STATUS_BUFFER_OVERFLOW && !done);
    REQUIRE(fi.GetStreamInfo(&cb.fs,file,bytes.data(),cap,&done)==STATUS_SUCCESS);
    unsigned streams=0;for(ULONG at=0;at<done;) {auto* st=reinterpret_cast<FSP_FSCTL_STREAM_INFO*>(bytes.data()+at);REQUIRE(st->Size>=sizeof(*st) && st->Size+at<=done);++streams;at+=st->Size;}
    REQUIRE(streams==3 && !c.fusion->failed);
}
void BindMemory(MountContext& c,CatalogFixture& f) {
    c.args.fusion.enabled=true;c.args.readonly=true;c.fusion=std::make_unique<fusion_mount::State>();auto& s=*c.fusion;f.request.cancellation=s.cancelled;
    std::vector<ApfsFusionStore::TestMember> sources;for(auto p:f.sources)sources.push_back({p,[p]{return p->present;}});
    std::string error;auto store=ApfsFusionStore::BindTestSources(f.request,sources,error);REQUIRE(store);FusionReadStatus status;
    s.session=ApfsFusionReadSession::Open(std::move(store),f.Selection(),status,error);REQUIRE(s.session);
    REQUIRE(s.session->GetNamespaceInfo(s.names,error));s.admitted=true;
}
void RevocationAndDrain() {
    ++cases;
    for(unsigned fault=0;fault<5;++fault) {
        MountContext c;CatalogFixture f(false,false,true);BindMemory(c,f);Callbacks cb(c);auto file=cb.Open(L"\\Caf\u00e9.txt");
        if(fault<2)f.sources[fault]->present=false;else if(fault==2)f.sources[1]->short_read=true;
        else if(fault==3)c.fusion->Cancel();else (void)f.request.budget->Refuse("sticky-initial-budget");
        std::array<std::byte,8192> bytes{};ULONG done=5;auto status=fi.Read(&cb.fs,file,bytes.data(),fault==2?4096:20480,10,&done);
        REQUIRE(!NT_SUCCESS(status) && !done && c.fusion->cancelled->load());if(fault<2)REQUIRE(c.fusion->missing_members==(1u<<fault));
        f.sources[0]->present=f.sources[1]->present=true;FSP_FSCTL_FILE_INFO info;REQUIRE(!NT_SUCCESS(fi.GetFileInfo(&cb.fs,file,&info)));
    }
    MountContext c;CatalogFixture f;BindMemory(c,f);Callbacks cb(c);auto file=cb.Open(L"\\Caf\u00e9.txt");
    std::atomic<bool> entered=false,release=false,closed=false;f.sources[0]->after_read=[&](){entered=true;while(!release)Sleep(1);};
    std::array<std::byte,16> bytes{};ULONG done=99;NTSTATUS result=STATUS_UNSUCCESSFUL;
    std::jthread read([&](){result=fi.Read(&cb.fs,file,bytes.data(),0,16,&done);});auto deadline=GetTickCount64()+5000;
    while(!entered && GetTickCount64()<deadline)Sleep(1);bool held=entered && c.active_callback_count==1;
    std::jthread close([&](){c.fusion->Close();closed=true;});Sleep(20);bool waited=!closed;release=true;read.join();close.join();
    REQUIRE(held && waited && !NT_SUCCESS(result) && !done && closed && !c.fusion->session && c.active_callback_count==0 && c.fusion->threads.empty());
}
std::atomic<bool> stopped=false,release_stop=false,removed=false,deleted=false;
VOID Stop(FSP_FILE_SYSTEM*){stopped=true;while(!release_stop)Sleep(1);}
VOID Remove(FSP_FILE_SYSTEM*){removed=true;}
VOID Delete(FSP_FILE_SYSTEM*){deleted=true;}
void Review640() {
    ++cases;
    for(unsigned missing=0;missing<2;++missing) {
        CatalogFixture f;std::string error;unsigned mask=99;
        std::vector<ApfsFusionStore::TestMember> sources;
        for(auto p:f.sources)sources.push_back({p,[p]{return p->present;}});
        f.sources[0]->after_read=[&](){f.sources[missing]->present=false;};
        auto store=ApfsFusionStore::BindTestSources(f.request,sources,error,&mask);
        REQUIRE(!store && mask==(1u<<missing) && error=="FusionMemberDisappearedOrChanged");
    }
    for(unsigned missing=0;missing<2;++missing) {
        CatalogFixture f;std::string error;unsigned mask=99;
        std::vector<ApfsFusionStore::TestMember> sources;
        for(auto p:f.sources)sources.push_back({p,[p]{return p->present;}});
        auto store=ApfsFusionStore::BindTestSources(f.request,sources,error);REQUIRE(store);
        f.sources[0]->after_read=[&](){f.sources[missing]->present=false;};
        FusionReadStatus status;auto session=ApfsFusionReadSession::Open(std::move(store),f.Selection(),status,error,&mask);
        REQUIRE(!session && mask==(1u<<missing) && status==FusionReadStatus::Unavailable);
    }
    MountContext c;Admit(c);Callbacks cb(c);
    // Parent634 accepts WinFsp-normalized stream prefixes; exact xattr bytes remain authoritative.
    auto fork=cb.Open(L"\\Café.txt:APFS.RESOURCEFORK");
    auto protocol=cb.Open(L"\\Café.txt:APFS.XATTRPROTOCOL");
    std::array<std::byte,32> bytes{};ULONG done=0;
    REQUIRE(fi.Read(&cb.fs,protocol,bytes.data(),0,32,&done)==STATUS_SUCCESS && done==13);
    REQUIRE(std::memcmp(bytes.data(),"APFS-XATTR/1\n",13)==0);
    REQUIRE(fi.Read(&cb.fs,fork,bytes.data(),4090,32,&done)==STATUS_SUCCESS && done==32);
}
void Lifecycle() {
    ++cases;auto owner=std::make_unique<MountContext>();Admit(*owner);auto& c=*owner;FSP_FILE_SYSTEM fs{};fs.UserContext=&c;c.fs=&fs;
    c.api.Stop=Stop;c.api.RemoveMount=Remove;c.api.Delete=Delete;c.winfsp_lifecycle_phase=WinFspLifecyclePhase::Dispatching;c.mount_ready=true;
    REQUIRE(WriteHostStatusFile(c));REQUIRE(FusionStatusJson(c).find("\"fusionHealth\":\"ReadOnly\"")!=std::string::npos);
    int result=-1;std::jthread drain([&](){result=RunFsHostShutdownDrain(owner);});const auto deadline=GetTickCount64()+5000;
    while(!stopped && GetTickCount64()<deadline)Sleep(1);bool held=stopped && !Writer(c.fusion->members[0].path) && !Writer(c.fusion->members[1].path);
    release_stop=true;drain.join();REQUIRE(held && result==0 && removed && deleted && owner && !c.fs && !c.fusion->session);
    REQUIRE(Writer(c.fusion->members[0].path) && Writer(c.fusion->members[1].path));
    REQUIRE(WriteTerminalMountNotReadyStatusFile(c));
    std::ifstream status(c.args.status_file);std::string json((std::istreambuf_iterator<char>(status)),{});
    REQUIRE(json.find("\"mountReady\":false")!=json.npos && json.find("\"immutableFusionImageSet\":true")!=json.npos);
    REQUIRE(json.find("StoppedReadOnly")!=json.npos && json.find("HeldReadOnly")==json.npos);
    REQUIRE(json.find("ReleasedOrNotAdmitted")!=json.npos);
    REQUIRE(json.find("store:main")!=json.npos && json.find("store:tier2")!=json.npos);if(c.sd){LocalFree(c.sd);c.sd=nullptr;}
    MountContext cancelled;REQUIRE(Parse(Args(),cancelled.args));cancelled.args.lifetime_file=(testroot/L"absent-lifetime").wstring();
    REQUIRE(!PrepareFusionMount(cancelled,GetCurrentProcess()) && !cancelled.fusion->session);
    cancelled.args.status_file=(testroot/L"refused-first-status.json").wstring();
    REQUIRE(WriteTerminalMountNotReadyStatusFile(cancelled));
    std::ifstream first(cancelled.args.status_file);std::string initial((std::istreambuf_iterator<char>(first)),{});
    REQUIRE(initial.find("ErrorReadOnly")!=initial.npos && initial.find("HeldReadOnly")==initial.npos);
    REQUIRE(initial.find("\"mountReady\":false")!=initial.npos && initial.find("store:tier2")!=initial.npos);
    REQUIRE(Writer((testroot/L"good/main.img").wstring()) && Writer((testroot/L"good/tier2.img").wstring()));
}
void RootStream651() {
    ++cases;
    CatalogFixture f(false,true,true);
    for(auto& r:f.fs)if(ReadU64LE(r.key,0).value()==((3ull<<60)|2))r=FileInode(2,0,2,true);
    f.fs.push_back(FileInode(60,0,0,true));
    AppleDirectoryRecord d;d.parent_id=2;d.file_id=60;d.name_utf8="Folder";d.flags=4;
    f.fs.push_back(Enc(d,[&](const auto& v,auto& out,auto& err){return EncodeAppleDirectoryRecord(v,ApfsNamePolicy::FromIncompatibleFeatures(1),out,err);}));
    f.fs.push_back(Enc(AppleXattrRecord{2,"user.empty",kAppleXattrDataEmbedded,{}},EncodeAppleXattrRecord));
    f.fs.push_back(Enc(AppleXattrRecord{60,"user.child",kAppleXattrDataEmbedded,{std::byte{0x63}}},EncodeAppleXattrRecord));
    f.Trees();std::filesystem::create_directories(testroot/L"root651");
    for(unsigned n=0;n<2;++n){std::ofstream out(testroot/L"root651"/(n?L"tier2.img":L"main.img"),std::ios::binary);
        out.write(reinterpret_cast<const char*>(f.sources[n]->bytes.data()),f.sources[n]->bytes.size());REQUIRE(bool(out));}
    std::ofstream(testroot/L"lifetime")<<"held";
    MountContext c;Admit(c,L"root651");Callbacks cb(c);
    unsigned failures=0;
    auto check=[&](bool ok,const std::wstring& name,const char* stage){++checks;if(!ok)++failures;
        std::cout<<(ok?"PASS ":"FAIL ")<<WideToUtf8(name)<<" "<<stage<<"\n";};
    auto opened=[&](std::wstring name,UINT64 inode,bool stream,const std::string& expected){
        PVOID h=nullptr;FSP_FSCTL_FILE_INFO info{};
        const auto status=fi.Open(&cb.fs,name.data(),0,GENERIC_READ,&h,&info);
        check(status==STATUS_SUCCESS && h,name,"Open");
        if(!h){check(info.IndexNumber==0 && info.FileSize==0,name,"failure output cleared");return;}
        cb.handles.push_back(h);check(info.IndexNumber==inode,name,"inode");
        if(stream){check(info.FileSize==expected.size() && !(info.FileAttributes&FILE_ATTRIBUTE_DIRECTORY),name,"stream metadata");
            std::array<char,32> bytes{};ULONG done=99;
            auto st=fi.Read(&cb.fs,h,bytes.data(),0,bytes.size(),&done);
            check(expected.empty()?(st==STATUS_END_OF_FILE && done==0):(st==STATUS_SUCCESS && done==expected.size() && std::string(bytes.data(),done)==expected),name,"exact read");
            st=fi.Read(&cb.fs,h,bytes.data(),expected.size(),1,&done);check(st==STATUS_END_OF_FILE && done==0,name,"EOF");
        }else check((info.FileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=0,name,"directory metadata");
    };
    for(auto base:{L"\\.",L"\\..",L"\\Folder\\..",L"\\Folder\\.\\..",L"\\.\\.."}) {
        for(auto suffix:{L"",L":$DATA"}) {
            opened(std::wstring(base)+L":APFS.XattrProtocol"+suffix,2,true,"APFS-XATTR/1\n");
            opened(std::wstring(base)+L":APFS.Xattr.757365722E656D707479"+suffix,2,true,"");
        }
        opened(std::wstring(base)+L"::$DATA",2,false,"");
    }
    opened(L"\\:APFS.XattrProtocol:$DATA",2,true,"APFS-XATTR/1\n");
    opened(L"\\:APFS.Xattr.757365722E656D707479:$DATA",2,true,"");
    opened(L"\\Folder\\.:APFS.Xattr.757365722E6368696C64",60,true,"c");
    opened(L"\\Folder\\.:APFS.XattrProtocol",60,true,"APFS-XATTR/1\n");
    opened(L"\\Folder\\.",60,false,"");opened(L"\\Folder\\..",2,false,"");
    opened(L"\\Caf\u00e9.txt:APFS.FinderInfo",30,true,std::string(32,'B'));
    for(auto name:{L"\\.:APFS.XattrProtocol\\child",L"\\Folder\\..:APFS.XattrProtocol\\child",L"\\Folder\\.:bad",L"\\Folder\\..:APFS.Xattr.757365722E6368696C64",L"\\Caf\u00e9.txt\\..:APFS.XattrProtocol"}){
        PVOID h=nullptr;FSP_FSCTL_FILE_INFO info{};auto text=std::wstring(name);
        auto st=fi.Open(&cb.fs,text.data(),0,GENERIC_READ,&h,&info);
        check(!NT_SUCCESS(st)&&!h&&info.IndexNumber==0,name,"invalid/missing/non-directory refused");
    }
    REQUIRE(!c.fusion->failed && !c.fusion->cancelled->load());
    std::cout<<"ROOT651 failures="<<failures<<"\n";REQUIRE(failures==0);
}

}
int wmain(int argc,wchar_t** argv) {
    try {if(argc!=3)return 2;testroot=argv[2];testroot.make_preferred();const std::wstring mode=argv[1];
        const auto run=[](const char* name,auto test){std::cerr<<"RUN "<<name<<std::endl;test();};
        if(mode==L"--root651")RootStream651();else if(mode==L"--setup")Setup();else if(mode==L"--callbacks"){
            run("arguments",ArgumentCases);run("refusals",Refusals);run("read",ReadCallbacks);run("aliases",AliasMetadata);
            run("held-lease-drain",HeldLeaseDrain);run("mutations",Mutations);run("packing",Packing);
            run("revocation-drain",RevocationAndDrain);run("lifecycle",Lifecycle);
        }else if(mode==L"--review-640"){Review640();ArgumentCases();Refusals();AliasMetadata();HeldLeaseDrain();Mutations();Packing();RevocationAndDrain();Lifecycle();}else return 2;
        std::cout<<"PASS "<<cases<<" groups / "<<checks<<" assertions\n";return 0;
    }catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<" after "<<checks<<" assertions\n";return 1;}
}
