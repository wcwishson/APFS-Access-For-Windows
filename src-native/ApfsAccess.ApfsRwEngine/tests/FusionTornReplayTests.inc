// Decode the durable evidence independently for fault injection only. Execution
// remains the public production runtime in a fresh child, without a test friend.
struct TornWitness {
    std::map<std::uint64_t,Bytes> writes,guards,before;
    std::vector<std::uint64_t> staged;
    std::uint64_t mirror=0,checkpoint=0;
};
TornWitness ReadTornWitness(const fs::path& directory) {
    fs::path path;for(const auto& f:fs::directory_iterator(directory))if(f.path().extension()==".witness")path=f.path();
    Check(!path.empty(),"torn complete witness exists");auto file=Load(path);
    Check(ReadU64LE(file,32).value_or(0)==file.size()-72,"torn witness body length");
    Bytes body(file.begin()+40,file.end()-32);std::size_t at=0;
    auto number=[&](){auto n=ReadU64LE(body,at);Check(n.has_value(),"torn evidence number");at+=8;return *n;};
    auto blob=[&](){auto n=number();Check(n<=body.size()-at,"torn evidence blob");Bytes b(body.begin()+at,body.begin()+at+n);at+=n;return b;};
    number();for(unsigned i=0;i<4;++i)blob();for(unsigned i=0;i<5;++i)number();blob();
    Check(number()==4096,"torn block size");for(unsigned i=0;i<3;++i)number();
    TornWitness w;
    auto write=[&](){number();auto block=number();number();auto data=blob();Check(data.size()==4096&&w.writes.emplace(block,data).second,"torn destination");return block;};
    auto n=number();Check(n<=1024,"torn bounded writes");for(std::uint64_t i=0;i<n;++i)w.staged.push_back(write());
    w.checkpoint=write();w.mirror=write();w.writes.emplace(0,w.writes.at(w.checkpoint));
    n=number();Check(n<=1024,"torn bounded guards");for(std::uint64_t i=0;i<n;++i){auto block=number();w.guards.emplace(block,blob());}
    n=number();Check(n<=1027,"torn bounded preimages");for(std::uint64_t i=0;i<n;++i){auto block=number();w.before.emplace(block,blob());}
    Check(at==body.size(),"torn complete body parsed");return w;
}
void PersistTornBlock(const Files& f,std::uint64_t block,const Bytes& bytes) {
    const auto tier=kFusionTier2ByteAddress/4096;const auto path=block>=tier?f.tier:f.main;
    auto h=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_WRITE_THROUGH,nullptr);
    Check(h!=INVALID_HANDLE_VALUE,"fault injector private image open");LARGE_INTEGER offset{};offset.QuadPart=8192+(block>=tier?block-tier:block)*4096;
    DWORD n=0;const bool ok=SetFilePointerEx(h,offset,nullptr,FILE_BEGIN)&&WriteFile(h,bytes.data(),static_cast<DWORD>(bytes.size()),&n,nullptr)&&n==bytes.size()&&FlushFileBuffers(h);
    CloseHandle(h);Check(ok,"fault injector durable 32-byte prefix outcome");
}
void RunFusionTornTests(const fs::path& root) {
    for(const std::string kind:{"data","metadata","mirror","checkpoint","anchor"})Run(("fresh original-WAL 32-byte torn "+kind).c_str(),[&]{
        Files f(root,2);VolumePlanFixture(f);Check(RuntimeProcess(f.directory,"write","after-fusion-witness")==73,"torn witness cut");
        auto w=ReadTornWitness(f.directory);std::uint64_t target=kind=="mirror"?w.mirror:kind=="checkpoint"?w.checkpoint:0;
        if(kind=="data"||kind=="metadata"){
            bool found=false;for(auto b:w.staged){const auto& data=w.writes.at(b);auto mixed=w.before.at(b);std::copy_n(data.begin(),32,mixed.begin());
                if((VerifyObjectChecksum(data,4096)==(kind=="metadata"))&&mixed!=data&&mixed!=w.before.at(b)){target=b;found=true;break;}}
            Check(found,"eligible staged torn block");
        } else {
            for(auto b:w.staged)PersistTornBlock(f,b,w.writes.at(b));
            if(kind!="mirror")PersistTornBlock(f,w.mirror,w.writes.at(w.mirror));
            if(kind=="anchor")PersistTornBlock(f,w.checkpoint,w.writes.at(w.checkpoint));
        }
        auto mixed=w.before.at(target);std::copy_n(w.writes.at(target).begin(),32,mixed.begin());
        Check(mixed!=w.before.at(target)&&mixed!=w.writes.at(target),"fault is actually partial");PersistTornBlock(f,target,mixed);
        Check(RuntimeProcess(f.directory,"recover-torn")==0,"fresh torn owner recovery");
        Check(RuntimeProcess(f.directory,"recover")==0,"torn clean idempotent owner");
        f.Refresh(21);std::string error;auto readonly=ApfsFusionStore::BindImages(f.request,error);Check(readonly!=nullptr,error);
        auto old=LoadContainerCheckpointView(*readonly,0,readonly->SizeBytes(),error,20);
        Check(old&&LoadAppleReadOnlyVolumeView(*readonly,*old,error).has_value(),"torn independent old checkpoint");
        FusionReadStatus status;auto reader=ApfsFusionReadSession::Open(std::move(readonly),f.Selection(),status,error);Bytes data;
        Check(reader&&reader->ReadFile(30,3000,5000,data,error)&&data==Bytes(5000,std::byte{0x6D}),"torn independent complete new reader");
    });
    for(const std::string kind:{"guard","unrelated-xid","unknown-destination","member-main","member-tier"})Run(("torn debt refusal "+kind).c_str(),[&]{
        Files f(root,2);VolumePlanFixture(f);Check(RuntimeProcess(f.directory,"write","after-fusion-witness")==73,"negative witness cut");
        auto w=ReadTornWitness(f.directory);auto mixed=w.before.at(w.mirror);std::copy_n(w.writes.at(w.mirror).begin(),32,mixed.begin());PersistTornBlock(f,w.mirror,mixed);
        if(kind=="guard"){
            bool found=false;for(const auto& [block,bytes]:w.guards)if(!w.writes.contains(block)){auto changed=bytes;changed[80]^=std::byte{0x40};PersistTornBlock(f,block,changed);found=true;break;}
            Check(found,"non-destination guard found");
        } else if(kind=="unrelated-xid"){
            auto changed=w.before.at(0);Put(changed,16,999);Seal(changed);PersistTornBlock(f,0,changed);
        } else if(kind.starts_with("member-")) {
            const auto path=kind=="member-main"?f.main:f.tier;auto original=Load(path);
            fs::rename(path,path.wstring()+L".original");Save(path,original);
        } else {
            auto block=w.staged.front();auto changed=w.before.at(block);unsigned v=0;
            while(std::byte(v)==changed[99]||std::byte(v)==w.writes.at(block)[99])++v;changed[99]=std::byte(v);PersistTornBlock(f,block,changed);
        }
        auto main=Load(f.main),tier=Load(f.tier),wal=Load(f.directory/"original.wal");
        Check(RuntimeProcess(f.directory,"refuse-torn")==0,"unrelated mutation admitted");
        Check(Load(f.main)==main&&Load(f.tier)==tier&&Load(f.directory/"original.wal")==wal,"negative replay changed member or original debt");
    });
}
