std::unique_ptr<FusionImageRuntime> OpenRuntime(const fs::path& directory,std::string& error,bool wrong_window=false,std::uint64_t selected_xid=0)
{
    Fixture fixture(4096,2);auto request=fixture.request;
    auto main=Load(directory/"main.apfs");auto nx=ParseNxSuperblock(Bytes(main.begin()+8192,main.begin()+12288));
    Check(selected_xid||nx.has_value(),"runtime anchor parse");request.checkpoint_xid=selected_xid?selected_xid:nx->xid;
    for(auto& m:request.members) {
        m.path=(directory/(m.role==FusionMemberRole::Main?"main.apfs":"tier.apfs")).wstring();
        m.store_size=(m.role==FusionMemberRole::Main?512ull:128ull)*4096;
        if(wrong_window&&m.role==FusionMemberRole::Tier2)m.store_offset=4096;
        if(!ApfsFusionStore::InspectImage(m.path,m.exact_identity,error))return {};
    }
    FusionVolumeSelection selected{request.container_uuid_hex,std::string(32,'c'),{"apfs-store:test-main","apfs-store:test-tier2"},101,request.checkpoint_xid};
    return FusionImageRuntime::Open(request,selected,(directory/"original.wal").wstring(),error);
}
int RuntimeChild(const fs::path& directory,const std::string& mode,const std::string& cut)
{
    std::string error;auto runtime=OpenRuntime(directory,error,mode=="window",mode.ends_with("-torn")?20:0);
    if(!runtime){std::cerr<<"OPEN "<<error<<'\n';return mode.starts_with("refuse")||mode=="window"?0:2;}
    if(mode=="window")return 8;
    const auto hook=[&](std::string_view stage){if(stage==cut)ExitProcess(73);return true;};
    if(mode.starts_with("refuse")) {
        if(runtime->Recover(error)){std::cerr<<"unexpected recovery\n";return 3;}
        const auto water=runtime->Watermarks();Check(water.cleanup_sequence<water.accepted_sequence,"refusal consumed debt");return 0;
    }
    const bool resize=mode.starts_with("resize-")||mode.starts_with("recover-resize-");
    const bool create=mode.starts_with("create-")||mode.starts_with("recover-create-");
    const auto length=(resize||create)?static_cast<std::size_t>(std::stoull(mode.substr(mode.rfind('-')+1))):8192u;
    std::uint64_t created=0;
    bool ok=mode=="write"?runtime->Overwrite(30,3000,Bytes(5000,std::byte{0x6D}),error,hook):
        mode.starts_with("create-")?runtime->CreateRegularFile(2,"created.bin",created,error,hook):
        mode.starts_with("resize-")?runtime->Resize(30,length,error,hook):runtime->Recover(error,hook);
    if(!ok){std::cerr<<"EXEC "<<error<<'\n';return 4;}
    Bytes expected(8192,std::byte{0xA1});std::fill(expected.begin()+4096,expected.end(),std::byte{0xB1});
    if(create)expected=Bytes(length,std::byte{0x71});else if(resize)expected.resize(length);else std::fill(expected.begin()+3000,expected.begin()+8000,std::byte{0x6D});Bytes actual;
    Check(runtime->ReadFile(create?40:30,0,length+1,actual,error)&&actual==expected,"runtime complete reader: "+error);
    if(create){Check(runtime->ReadFile(30,0,8192,actual,error)&&actual.size()==8192&&actual.front()==std::byte{0xA1}&&actual.back()==std::byte{0xB1},"create retained original");}
    const auto water=runtime->Watermarks();Check(water.accepted_sequence&&water.accepted_sequence==water.apfs_durable_sequence&&water.accepted_sequence==water.cleanup_sequence,"runtime watermarks");
    return 0;
}
DWORD RuntimeProcess(const fs::path& directory,const std::string& mode,const std::string& cut="")
{
    wchar_t executable[32768]{};Check(GetModuleFileNameW(nullptr,executable,32768)!=0,"test executable");
    const std::wstring wm(mode.begin(),mode.end()),wc(cut.begin(),cut.end());
    auto command=L"\""+std::wstring(executable)+L"\" --runtime-child \""+directory.wstring()+L"\" "+wm+L" "+wc;
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES),nullptr,TRUE};
    auto log=directory/(mode+"-"+cut+".log");auto output=CreateFileW(log.c_str(),GENERIC_WRITE,FILE_SHARE_READ,&security,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    Check(output!=INVALID_HANDLE_VALUE,"child evidence log");
    STARTUPINFOW startup{};startup.cb=sizeof(startup);startup.dwFlags=STARTF_USESTDHANDLES;
    startup.hStdOutput=startup.hStdError=output;startup.hStdInput=GetStdHandle(STD_INPUT_HANDLE);PROCESS_INFORMATION process{};
    Check(CreateProcessW(executable,command.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW,nullptr,nullptr,&startup,&process)!=FALSE,"fresh child");
    const auto wait=WaitForSingleObject(process.hProcess,120000);DWORD code=999;
    if(wait!=WAIT_OBJECT_0)TerminateProcess(process.hProcess,99);
    Check(GetExitCodeProcess(process.hProcess,&code)!=FALSE,"child exit");CloseHandle(process.hThread);CloseHandle(process.hProcess);CloseHandle(output);
    if(code!=0&&code!=73){auto bytes=Load(log);std::cerr<<std::string(reinterpret_cast<const char*>(bytes.data()),bytes.size());}
    Check(wait==WAIT_OBJECT_0,"child timeout");return code;
}
void RunFusionRuntimeTests(const fs::path& root)
{
    Run("original WAL runtime actual two-image overwrite and owner reopen",[&]{
        Files f(root,2);VolumePlanFixture(f);const auto beforeMain=Load(f.main),beforeTier=Load(f.tier);
        Check(RuntimeProcess(f.directory,"write")==0,"runtime positive child");Check(RuntimeProcess(f.directory,"recover")==0,"clean reopen child");
        auto main=Load(f.main),tier=Load(f.tier);
        Check(std::equal(main.begin(),main.begin()+8192,beforeMain.begin())&&std::equal(tier.begin(),tier.begin()+8192,beforeTier.begin()),"window prefixes");
        f.Refresh(21);std::string error;auto store=ApfsFusionStore::BindImages(f.request,error);
        Check(store!=nullptr,"independent current store");
        auto old=LoadContainerCheckpointView(*store,0,store->SizeBytes(),error,20);
        Check(old&&LoadAppleReadOnlyVolumeView(*store,*old,error).has_value(),"old checkpoint independent parse");
    });
    for(const std::string cut:{"after-fusion-accept","after-fusion-witness","before-fusion-device-write",
        "before-fusion-mirror","after-fusion-mirror","before-fusion-checkpoint","after-fusion-checkpoint",
        "before-fusion-main","after-fusion-main","before-fusion-durable","after-fusion-durable","after-fusion-cleanup"})
    Run(("fresh process cut "+cut).c_str(),[&]{
        Files f(root,2);VolumePlanFixture(f);
        Check(RuntimeProcess(f.directory,"write",cut)==73,"crash cut reached: "+cut);
        Check(RuntimeProcess(f.directory,"recover")==0,"fresh recovery: "+cut);
        Check(RuntimeProcess(f.directory,"recover")==0,"idempotent fresh reopen: "+cut);
    });
    Run("member identity mismatch preserves original WAL and both images",[&]{
        Files f(root,2);VolumePlanFixture(f);Check(RuntimeProcess(f.directory,"write","after-fusion-mirror")==73,"member mismatch cut");
        auto bytes=Load(f.tier);fs::rename(f.tier,f.directory/"original-tier.apfs");Save(f.tier,bytes);
        auto main=Load(f.main),wal=Load(f.directory/"original.wal");
        Check(RuntimeProcess(f.directory,"refuse")==0,"member replacement refusal");
        Check(Load(f.main)==main&&Load(f.tier)==bytes&&Load(f.directory/"original.wal")==wal,"mismatch mutated member or WAL");
    });
    Run("missing member preserves surviving member and WAL",[&]{
        Files f(root,2);VolumePlanFixture(f);Check(RuntimeProcess(f.directory,"write","before-fusion-mirror")==73,"member loss cut");
        fs::rename(f.tier,f.directory/"held-out-tier.apfs");auto main=Load(f.main),wal=Load(f.directory/"original.wal");
        Check(RuntimeProcess(f.directory,"refuse")==0,"member loss refusal");
        Check(Load(f.main)==main&&Load(f.directory/"original.wal")==wal,"loss changed surviving bytes");
    });
    Run("partial witness preserved with untouched image pair",[&]{
        Files f(root,2);VolumePlanFixture(f);Check(RuntimeProcess(f.directory,"write","after-fusion-witness")==73,"witness cut");
        fs::path witness;for(const auto& file:fs::directory_iterator(f.directory))if(file.path().extension()==".witness")witness=file.path();
        Check(!witness.empty(),"separate complete witness");auto bytes=Load(witness);bytes.resize(bytes.size()-11);Save(witness,bytes);
        auto main=Load(f.main),tier=Load(f.tier),wal=Load(f.directory/"original.wal");
        Check(RuntimeProcess(f.directory,"refuse")==0,"partial witness refusal");
        Check(Load(f.main)==main&&Load(f.tier)==tier&&Load(witness)==bytes&&Load(f.directory/"original.wal")==wal,"partial debt changed");
    });
    Run("checksum-valid changed witness cannot replace original accepted commitment",[&]{
        Files f(root,2);VolumePlanFixture(f);Check(RuntimeProcess(f.directory,"write","after-fusion-witness")==73,"commitment cut");
        fs::path witness;for(const auto& file:fs::directory_iterator(f.directory))if(file.path().extension()==".witness")witness=file.path();
        auto bytes=Load(witness);bytes[bytes.size()-33]^=std::byte{0x20};
        Check(BCryptHash(BCRYPT_SHA256_ALG_HANDLE,nullptr,0,reinterpret_cast<PUCHAR>(bytes.data()),static_cast<ULONG>(bytes.size()-32),
            reinterpret_cast<PUCHAR>(bytes.data()+bytes.size()-32),32)>=0,"adversarial witness checksum");Save(witness,bytes);
        auto main=Load(f.main),tier=Load(f.tier),wal=Load(f.directory/"original.wal");
        Check(RuntimeProcess(f.directory,"refuse")==0,"changed committed witness refusal");
        Check(Load(f.main)==main&&Load(f.tier)==tier&&Load(f.directory/"original.wal")==wal&&Load(witness)==bytes,"changed witness retired debt");
    });
    Run("cancellation after staged data isolates anchors and permits fresh exact replay",[&]{
        Files f(root,2);VolumePlanFixture(f);std::string error;auto runtime=OpenRuntime(f.directory,error);Check(runtime!=nullptr,error);
        Check(!runtime->Overwrite(30,3000,Bytes(5000,std::byte{0x6D}),error,[&](auto stage){
            if(stage=="before-fusion-mirror")runtime->Cancel();return true;}),"publication ignored cancellation");
        auto water=runtime->Watermarks();Check(water.accepted_sequence&&water.apfs_durable_sequence==0&&water.cleanup_sequence==0,"cancel advanced watermarks");
        runtime.reset();auto main=Load(f.main),tier=Load(f.tier);
        Check(ReadU64LE(main,8192+16)==20&&ReadU64LE(tier,8192+16)==20,"cancel switched anchors");
        Check(RuntimeProcess(f.directory,"recover")==0,"cancelled owner fresh replay");
    });
    Run("unknown member block debt preserved before any replay writes",[&]{
        Files f(root,2);VolumePlanFixture(f);Check(RuntimeProcess(f.directory,"write","after-fusion-witness")==73,"unknown cut");
        auto main=Load(f.main);main[8192+192*4096+2]^=std::byte{0x40};Save(f.main,main);
        auto tier=Load(f.tier),wal=Load(f.directory/"original.wal");
        Check(RuntimeProcess(f.directory,"refuse")==0,"unknown ownership refusal");
        Check(Load(f.main)==main&&Load(f.tier)==tier&&Load(f.directory/"original.wal")==wal,"unknown debt changed");
    });
    Run("bounds preflight and cancellation precede original acceptance",[&]{
        Files f(root,2);VolumePlanFixture(f);auto main=Load(f.main),tier=Load(f.tier);std::string error;
        auto runtime=OpenRuntime(f.directory,error);Check(runtime!=nullptr,error);
        Check(!runtime->Overwrite(30,(1ull<<56)-4096,Bytes(3),error),"out of bounds admitted");
        Check(runtime->Watermarks().accepted_sequence==0,"out of bounds accepted");runtime->Cancel();
        Check(!runtime->Overwrite(30,0,Bytes(1),error)&&runtime->Watermarks().accepted_sequence==0,"cancel accepted");runtime.reset();
        Check(Load(f.main)==main&&Load(f.tier)==tier,"preflight changed images");
    });
    for(const auto length:{0u,4096u,12288u})Run(("original SetFileSize fresh mirror cut and exact resize "+std::to_string(length)).c_str(),[&]{
        Files f(root,2);VolumePlanFixture(f);const auto text=std::to_string(length);
        Check(RuntimeProcess(f.directory,"resize-"+text,"after-fusion-mirror")==73,"resize cut reached");
        Check(RuntimeProcess(f.directory,"recover-resize-"+text)==0,"resize recovery");
        Check(RuntimeProcess(f.directory,"recover-resize-"+text)==0,"resize clean reader");
    });
    for(const auto length:{0u})for(const std::string cut:{"after-fusion-accept","after-fusion-mirror","after-fusion-main"})
    Run(("original create "+std::to_string(length)+" fresh process "+cut).c_str(),[&]{
        Files f(root,2);VolumePlanFixture(f);const auto text=std::to_string(length);
        Check(RuntimeProcess(f.directory,"create-"+text,cut)==73,"create cut reached");
        Check(RuntimeProcess(f.directory,"recover-create-"+text)==0,"create recovery");
        Check(RuntimeProcess(f.directory,"recover-create-"+text)==0,"create clean reader");
    });
    Run("create collision and missing parent refuse before original acceptance",[&]{
        Files f(root,2);VolumePlanFixture(f);std::string error;auto runtime=OpenRuntime(f.directory,error);Check(runtime!=nullptr,error);std::uint64_t inode=0;
        Check(!runtime->CreateRegularFile(2,"file.txt",inode,error)&&inode==0&&runtime->Watermarks().accepted_sequence==0,"name collision accepted");
        Check(!runtime->CreateRegularFile(999,"new.bin",inode,error)&&runtime->Watermarks().accepted_sequence==0,"missing parent accepted");
        Check(!runtime->CreateRegularFile(30,"new.bin",inode,error)&&runtime->Watermarks().accepted_sequence==0,"file as parent accepted");
    });
    Run("same owner complete create then resize uses refreshed held pair",[&]{
        Files f(root,2);VolumePlanFixture(f);std::string error;auto runtime=OpenRuntime(f.directory,error);Check(runtime!=nullptr,error);std::uint64_t inode=0;
        Check(runtime->CreateRegularFile(2,"sequence.bin",inode,error)&&inode==40,"same owner create: "+error);
        Check(runtime->Resize(inode,6000,error),"same owner resize: "+error);Bytes actual,expected(6000);
        Check(runtime->ReadFile(inode,0,7000,actual,error)&&actual==expected,"same owner content");
        auto water=runtime->Watermarks();Check(water.accepted_sequence==water.cleanup_sequence&&water.cleanup_sequence==water.apfs_durable_sequence,"second boundary watermarks");
        runtime.reset();f.Refresh(22);auto reader=f.Open();Check(reader->ReadFile(40,0,7000,actual,error)&&actual==expected,"fresh independent owner after second transaction");
    });
    Run("same files with wrong member window cannot replay accepted bytes",[&]{
        Files f(root,2);VolumePlanFixture(f);Check(RuntimeProcess(f.directory,"write","after-fusion-witness")==73,"window cut");
        auto main=Load(f.main),tier=Load(f.tier),wal=Load(f.directory/"original.wal");
        Check(RuntimeProcess(f.directory,"window")==0,"wrong window accepted");
        Check(Load(f.main)==main&&Load(f.tier)==tier&&Load(f.directory/"original.wal")==wal,"wrong window changed evidence");
    });
    Run("same owner retries require complete durable witness on disk",[&]{
        Files f(root,2);VolumePlanFixture(f);std::string error;auto runtime=OpenRuntime(f.directory,error);Check(runtime!=nullptr,error);
        Check(!runtime->Overwrite(30,3000,Bytes(5000,std::byte{0x6D}),error,[](auto stage){return stage!="after-fusion-witness";}),"witness interruption");
        fs::path witness;for(const auto& file:fs::directory_iterator(f.directory))if(file.path().extension()==".witness")witness=file.path();
        auto bytes=Load(witness);bytes.resize(31);Save(witness,bytes);
        Check(!runtime->Recover(error)&&runtime->Watermarks().apfs_durable_sequence==0&&runtime->Watermarks().cleanup_sequence==0,"cached plan bypassed partial witness");
        runtime.reset();auto main=Load(f.main),tier=Load(f.tier);
        Check(ReadU64LE(main,8192+16)==20&&ReadU64LE(tier,8192+16)==20,"cached plan switched anchors");
    });
}
