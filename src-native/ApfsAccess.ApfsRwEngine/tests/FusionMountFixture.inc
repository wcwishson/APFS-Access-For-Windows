int SelectFusionMountFixture(const fs::path& directory) {
    Fixture fixture(4096,2);auto request=fixture.request;std::string error;
    Bytes bytes(4096);std::ifstream input(directory/"main.apfs",std::ios::binary);input.seekg(8192);input.read(reinterpret_cast<char*>(bytes.data()),4096);
    auto nx=ParseNxSuperblock(bytes);Check(nx.has_value(),"mount NX");
    std::cout<<"{\"container\":\""<<request.container_uuid_hex<<"\",\"fusion\":\""<<request.fusion_uuid_hex<<"\",\"xid\":"<<nx->xid<<",\"members\":[";
    bool comma=false;for(auto& m:request.members){
        m.path=(directory/(m.role==FusionMemberRole::Main?"main.apfs":"tier.apfs")).wstring();
        Check(ApfsFusionStore::InspectImage(m.path,m.exact_identity,error),error);
        if(comma)std::cout<<',';comma=true;
        std::cout<<"{\"role\":\""<<(m.role==FusionMemberRole::Main?"main":"tier2")<<"\",\"store\":\""<<m.stable_store_id<<"\",\"size\":"<<(m.exact_identity.size_bytes-8192)<<",\"identity\":\"";
        std::cout<<apfsaccess::fusion_arguments::Identity(m.exact_identity)<<"\"}";
    }std::cout<<"]}\n";return 0;
}
int ExportFusionMountFixture(const fs::path& root, bool wide_guards=false) {
    Check(root.is_absolute()&&root.root_name()==L"D:"&&fs::create_directory(root),"private new mount fixture root");
    Files f(root,2);VolumePlanFixture(f);
    constexpr std::uint64_t main_blocks=32768,tier_chunks=32,tier_blocks=tier_chunks*32768,pool=3*(1+tier_chunks+2);
    auto nx=f.Block(0,0);Put(nx,0x28,main_blocks+tier_blocks);Seal(nx);f.Place(0,0,nx);f.Place(0,129,nx);nx[0x50F]|=std::byte{1};Seal(nx);f.Place(1,0,nx);
    Bytes main(f.bs),tier(f.bs),ip(f.bs);
    for(std::uint64_t b:{0,15,17,18,20,22,24,25,26,27,30,31})Bit(main,b);
    for(unsigned b=128;b<208;++b)Bit(main,b);for(unsigned b=256;b<256+pool;++b)Bit(main,b);
    for(unsigned b:{0,4,5,6,20,22,23})Bit(tier,b);for(unsigned b=0;b<4;++b)Bit(ip,b);
    f.Place(0,192,ip);f.Place(0,258,main);f.Place(0,259,tier);
    f.Edit(0,256,[&](auto& cib){Put(cib,0x38,32768,4);Put(cib,0x3C,32768-Population(main),4);});
    auto cib=Object(f.bs,257,kObjectPhysical|kObjectTypeSpacemanCib);Put(cib,0x24,tier_chunks,4);
    for(unsigned i=0;i<tier_chunks;++i){auto at=0x28+i*0x20;Put(cib,at,20);Put(cib,at+8,i*32768ull);Put(cib,at+16,32768,4);Put(cib,at+20,32768-(i?0:Population(tier)),4);Put(cib,at+24,i?0:259);}Seal(cib);f.Place(0,257,cib);
    f.Edit(0,160,[&](auto& sm){
        Put(sm,0x30,main_blocks);Put(sm,0x60,tier_blocks);Put(sm,0x68,tier_chunks);Put(sm,0x48,main_blocks-Population(main));Put(sm,0x78,tier_blocks-Population(tier));Put(sm,0x98,pool);
    });
    if(wide_guards) {
        constexpr unsigned base=1024,count=1100;
        f.sources[0]->bytes.resize(static_cast<std::size_t>(f.prefix+(base+2)*f.bs));
        auto descriptor=f.Block(0,128);Put(descriptor,8,base);Seal(descriptor);f.Place(0,base,descriptor);
        auto current=f.Block(0,0);Put(current,0x68,count,4);Put(current,0x70,base);Seal(current);
        f.Place(0,0,current);f.Place(0,base+1,current);current[0x50F]|=std::byte{1};Seal(current);f.Place(1,0,current);
        for(unsigned block=base;block<base+count;++block)Bit(main,block);
        f.Place(0,258,main);
        f.Edit(0,256,[&](auto& c){Put(c,0x3C,main_blocks-Population(main),4);});
        f.Edit(0,160,[&](auto& sm){Put(sm,0x48,main_blocks-Population(main));});
    }
    for(auto& m:f.request.members)m.store_size=(m.role==FusionMemberRole::Main?main_blocks:tier_blocks)*f.bs;
    Save(f.main,f.sources[0]->bytes);Save(f.tier,f.sources[1]->bytes);ExtendSparse(f.main,f.prefix+main_blocks*f.bs);ExtendSparse(f.tier,f.prefix+tier_blocks*f.bs);f.Refresh(20);
    auto owner=f.Open();std::string error;const bool admitted=owner->CheckAllocatorAdmission(error);Check(admitted,"mount allocation: "+error);owner->Close();
    return SelectFusionMountFixture(f.directory);
}
std::unique_ptr<FusionImageRuntime> OpenMountRuntime(const fs::path&,std::string&,bool);
int FusionWitnessBoundsChild(const fs::path& directory,bool cut,bool profile=false) {
    std::string error;auto runtime=OpenMountRuntime(directory,error,false);Check(runtime!=nullptr,error);
    if(profile) {
        const auto start=GetTickCount64();
        const auto hook=[&](std::string_view stage){std::cout<<(GetTickCount64()-start)<<" ms "<<stage<<std::endl;return true;};
        std::uint64_t inode=0;Check(runtime->MakeDirectory(2,"profile-dir",inode,error,hook),error);
        std::cout<<(GetTickCount64()-start)<<" ms PASS canonical directory create\n";return 0;
    }
    if(cut) {
        const auto hook=[](std::string_view stage){if(stage=="after-fusion-witness")ExitProcess(73);return true;};
        Check(runtime->Overwrite(30,3000,Bytes(5000,std::byte{0x6D}),error,hook),error);
        throw std::runtime_error("witness cut was not reached");
    }
    Check(runtime->Recover(error),"wide canonical guard fresh replay: "+error);
    Bytes expected(8192,std::byte{0xA1}),actual;
    std::fill(expected.begin()+4096,expected.end(),std::byte{0xB1});
    std::fill(expected.begin()+3000,expected.begin()+8000,std::byte{0x6D});
    Check(runtime->ReadFile(30,0,8193,actual,error)&&actual==expected,"wide witness complete payload");
    const auto water=runtime->Watermarks();
    Check(water.accepted_sequence&&water.accepted_sequence==water.apfs_durable_sequence&&water.accepted_sequence==water.cleanup_sequence,"wide witness original markers");
    std::cout<<"PASS wide canonical guard original replay and complete payload\n";return 0;
}
std::unique_ptr<FusionImageRuntime> OpenMountRuntime(const fs::path& directory,std::string& error,bool mounted_journal=false) {
    Fixture fixture(4096,2);auto request=fixture.request;Bytes bytes(4096);
    request.budget=std::make_shared<ApfsReadBudget>(100000,256ull*1024*1024,1000000,256ull*1024*1024);
    std::ifstream input(directory/"main.apfs",std::ios::binary);input.seekg(8192);input.read(reinterpret_cast<char*>(bytes.data()),4096);
    input.close();auto nx=ParseNxSuperblock(bytes);Check(nx.has_value(),"sequence NX");request.checkpoint_xid=nx->xid;
    for(auto& m:request.members){m.path=(directory/(m.role==FusionMemberRole::Main?"main.apfs":"tier.apfs")).wstring();
        Check(ApfsFusionStore::InspectImage(m.path,m.exact_identity,error),error);m.store_size=m.exact_identity.size_bytes-8192;}
    FusionVolumeSelection selection{request.container_uuid_hex,std::string(32,'c'),{"apfs-store:test-main","apfs-store:test-tier2"},101,nx->xid};
    return FusionImageRuntime::Open(request,selection,((mounted_journal?directory/"recovery":directory)/"original.wal").wstring(),error);
}
int FusionMountSequence(const fs::path& root) {
    ExportFusionMountFixture(root);std::string error;auto runtime=OpenMountRuntime(root/"case-1",error);Check(runtime!=nullptr,error);std::uint64_t inode=0;
    auto verify=[&](bool ok,const char* operation){Check(ok,std::string(operation)+": "+error);std::cout<<"PASS "<<operation<<'\n';};
    verify(runtime->CreateRegularFile(2,"copy.bin",inode,error),"create");
    verify(runtime->Resize(inode,8192,error),"resize");
    verify(runtime->Overwrite(inode,0,Bytes(8192,std::byte{0x71}),error),"write");
    verify(runtime->SetTimes(inode,{133000000000000000,133000000000000000,133000000000000000,0},error),"times");
    verify(runtime->Rename(inode,2,"renamed.bin",error),"rename");
    verify(runtime->Unlink(inode,error),"unlink");
    for(unsigned i=0;i<24;++i)verify(runtime->Overwrite(30,0,Bytes(64,std::byte(i)),error),"sustained overwrite");
    return 0;
}
int FusionMountCut(const fs::path& directory,std::string_view stage) {
    std::string error;auto runtime=OpenMountRuntime(directory,error,true);Check(runtime!=nullptr,error);
    const auto hook=[&](std::string_view reached){if(reached==stage)ExitProcess(73);return true;};
    const bool ok=runtime->Overwrite(30,3000,Bytes(5000,std::byte{0x6D}),error,hook);
    Check(ok,error);throw std::runtime_error("requested cut was not reached");
}
int InspectFusionMountFixture(const fs::path& directory) {
    Fixture fixture(4096,2);auto request=fixture.request;std::string error;Bytes anchor(4096);
    request.budget=std::make_shared<ApfsReadBudget>(100000,256ull*1024*1024,1000000,256ull*1024*1024);
    std::ifstream input(directory/"main.apfs",std::ios::binary);input.seekg(8192);
    input.read(reinterpret_cast<char*>(anchor.data()),anchor.size());Check(bool(input),"inspection anchor read");input.close();
    auto nx=ParseNxSuperblock(anchor);Check(nx.has_value(),"inspection NX");request.checkpoint_xid=nx->xid;
    for(auto& member:request.members){
        member.path=(directory/(member.role==FusionMemberRole::Main?"main.apfs":"tier.apfs")).wstring();
        Check(ApfsFusionStore::InspectImage(member.path,member.exact_identity,error),error);
        member.store_size=member.exact_identity.size_bytes-8192;
    }
    auto store=ApfsFusionStore::BindImages(request,error);Check(store!=nullptr,error);
    AppleSpacemanView view;Check(LoadFusionSpacemanAllocationView(*store,view,error),error);
    std::uint64_t owned=0;
    for(std::uint64_t bit=0;bit<view.internal_pool.block_count;++bit){
        const auto& bitmap=view.internal_pool.active_bitmaps.at(static_cast<std::size_t>(bit/(4096*8)));
        const auto local=bit%(4096*8);
        if((std::to_integer<unsigned>(bitmap.bytes.at(static_cast<std::size_t>(local/8)))>>(local%8))&1u)++owned;
    }
    FusionReadStatus status;FusionVolumeSelection selection{request.container_uuid_hex,std::string(32,'c'),{"apfs-store:test-main","apfs-store:test-tier2"},101,nx->xid};
    auto reader=ApfsFusionReadSession::Open(std::move(store),selection,status,error);Check(reader!=nullptr,error);
    Bytes content;Check(reader->ReadFile(30,0,8193,content,error)&&content.size()==8192,error);
    std::array<unsigned char,32> digest{};
    Check(BCryptHash(BCRYPT_SHA256_ALG_HANDLE,nullptr,0,reinterpret_cast<PUCHAR>(content.data()),static_cast<ULONG>(content.size()),digest.data(),digest.size())>=0,"inspection hash");
    std::string hex;for(auto value:digest){hex.push_back("0123456789abcdef"[value>>4]);hex.push_back("0123456789abcdef"[value&15]);}
    std::cout<<"{\"xid\":"<<nx->xid<<",\"fileSha256\":\""<<hex<<"\",\"poolBlocks\":"<<view.internal_pool.block_count
        <<",\"poolOwned\":"<<owned<<",\"bitmapSlots\":"<<view.internal_pool.bitmap_block_count<<",\"activeRotations\":[";
    bool comma=false;for(const auto& bitmap:view.internal_pool.active_bitmaps){if(comma)std::cout<<',';comma=true;std::cout<<bitmap.rotation_index;}
    std::cout<<"],\"devices\":[";comma=false;
    for(const auto& device:view.devices){if(comma)std::cout<<',';comma=true;std::cout<<"{\"blocks\":"<<device.block_count<<",\"free\":"<<device.free_count<<",\"cibs\":"<<device.cibs.size()<<",\"cabs\":"<<device.cabs.size()<<'}';}
    std::cout<<"],\"queues\":[";comma=false;
    for(const auto& queue:view.free_queues){if(comma)std::cout<<',';comma=true;std::cout<<"{\"blocks\":"<<queue.block_count<<",\"entries\":"<<queue.entries.size()<<",\"oldestXid\":"<<queue.oldest_xid<<'}';}
    std::cout<<"]}\n";return 0;
}
