void ExtendSparse(const fs::path& path, std::uint64_t bytes)
{
    HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    Check(handle != INVALID_HANDLE_VALUE, "open private sparse fixture");
    DWORD returned = 0;
    const bool sparse = DeviceIoControl(handle, FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &returned, nullptr) != FALSE;
    LARGE_INTEGER end; end.QuadPart = static_cast<LONGLONG>(bytes);
    const bool extended = sparse && SetFilePointerEx(handle, end, nullptr, FILE_BEGIN) && SetEndOfFile(handle);
    const auto failure = GetLastError(); CloseHandle(handle);
    Check(extended, "extend sparse regular fixture: " + std::to_string(failure));
}
struct CabLayout
{
    static constexpr std::uint64_t main_blocks = 262144, per_chunk = 32768;
    static constexpr unsigned per_cib = 126, per_cab = 507, tier_cibs = 508;
    static constexpr std::uint64_t tier_chunks = per_cab * per_cib + 1;
    static constexpr std::uint64_t tier_blocks = tier_chunks * per_chunk;
    static constexpr std::uint64_t pool_blocks = 3 * (8 + tier_chunks + 1 + tier_cibs + 2);
    static constexpr std::uint64_t cab0 = 765, cab1 = 766, main_bitmap = 767, tier_bitmap = 775;
};
void CabFixture(Files& f)
{
    using C = CabLayout;
    AllocationFixture(f);
    f.sources[0]->bytes.resize(static_cast<std::size_t>(f.prefix + 1024 * f.bs));
    f.EditNx([](auto& nx){Put(nx,0x28,C::main_blocks+C::tier_blocks);});
    std::array<Bytes,8> bitmaps;
    for (auto& b:bitmaps) b.resize(f.bs);
    const auto mark = [&](std::uint64_t b) { Bit(bitmaps[b / C::per_chunk], b % C::per_chunk); };
    for (std::uint64_t b : {0,1,2,3,4,8,9,10,11,15,16,17,18,20,21,22,24,25,26,27,30}) mark(b);
    for (std::uint64_t b=64;b<160;++b) mark(b);
    for (std::uint64_t b=256;b<256+C::pool_blocks;++b) mark(b);
    Bytes tier(f.bs); for (std::uint64_t b : {0,4,5,6,20,21,22,23}) Bit(tier,b);
    f.Place(0,C::tier_bitmap,tier);
    std::uint64_t main_free=0;
    auto cib=Object(f.bs,256,kObjectPhysical|kObjectTypeSpacemanCib);
    Put(cib,0x24,8,4);
    for(unsigned n=0;n<8;++n) {
        const auto at=0x28+n*0x20; const auto free=C::per_chunk-Population(bitmaps[n]);
        main_free+=free; Put(cib,at,20); Put(cib,at+8,n*C::per_chunk);
        Put(cib,at+16,C::per_chunk,4); Put(cib,at+20,free,4); Put(cib,at+24,C::main_bitmap+n);
        f.Place(0,C::main_bitmap+n,bitmaps[n]);
    }
    Seal(cib); f.Place(0,256,cib);
    for (unsigned n=0;n<C::tier_cibs;++n) {
        auto tc=Object(f.bs,257+n,kObjectPhysical|kObjectTypeSpacemanCib);
        Put(tc,0x20,n,4); const auto chunks=n==C::tier_cibs-1?1:C::per_cib; Put(tc,0x24,chunks,4);
        for(unsigned j=0;j<chunks;++j) {
            const auto at=0x28+j*0x20; const std::uint64_t chunk=n*C::per_cib+j;
            Put(tc,at,20); Put(tc,at+8,chunk*C::per_chunk); Put(tc,at+16,C::per_chunk,4);
            Put(tc,at+20,C::per_chunk-(chunk==0?Population(tier):0),4);
            Put(tc,at+24,chunk==0?C::tier_bitmap:0);
        }
        Seal(tc); f.Place(0,257+n,tc);
    }
    for(unsigned n=0;n<2;++n) {
        auto cab=Object(f.bs,C::cab0+n,kObjectPhysical|kObjectTypeSpacemanCab);
        Put(cab,0x20,n,4); const auto count=n?1:C::per_cab; Put(cab,0x24,count,4);
        for(unsigned j=0;j<count;++j) Put(cab,0x28+j*8,257+n*C::per_cab+j);
        Seal(cab); f.Place(0,C::cab0+n,cab);
    }
    for(unsigned n=0;n<6;++n) {
        Bytes ip(f.bs);
        if(n==0) for(std::uint64_t b=256;b<=C::tier_bitmap;++b) Bit(ip,b-256);
        f.Place(0,64+n,ip);
    }
    f.Edit(0,8,[&](auto& sm){
        Put(sm,0x30,C::main_blocks); Put(sm,0x38,8); Put(sm,0x48,main_free);
        Put(sm,0x60,C::tier_blocks); Put(sm,0x68,C::tier_chunks);
        Put(sm,0x70,C::tier_cibs,4); Put(sm,0x74,2,4); Put(sm,0x78,C::tier_blocks-Population(tier));
        Put(sm,0x98,C::pool_blocks); Put(sm,0xA0,6,4); Put(sm,0xA4,96,4); Put(sm,0xA8,64); Put(sm,0xB0,256);
        Put(sm,0x140,6,2); Put(sm,0x142,95,2); Put(sm,0x144,0x180,4);
        Put(sm,0x148,0x1B0,4); Put(sm,0x14C,0x1C0,4);
        std::fill(sm.begin()+0x158,sm.end(),std::byte{0});
        Put(sm,0x158,256); Put(sm,0x160,C::cab0); Put(sm,0x168,C::cab1);
        for(unsigned n=0;n<6;++n) { Put(sm,0x180+n*8,20); Put(sm,0x1B0+n*2,n,2); }
        for(unsigned n=0;n<96;++n) Put(sm,0x1C0+n*2,n<6||n==95?0xFFFF:n+1,2);
    });
    for(auto& m:f.request.members) m.store_size=(m.role==FusionMemberRole::Main?C::main_blocks:C::tier_blocks)*f.bs;
}
void PersistCab(Files& f)
{
    Save(f.main,f.sources[0]->bytes); Save(f.tier,f.sources[1]->bytes);
    ExtendSparse(f.main,f.prefix+CabLayout::main_blocks*f.bs);
    ExtendSparse(f.tier,f.prefix+CabLayout::tier_blocks*f.bs);
    f.Refresh(20);
}
void RunCabTests(const fs::path& root)
{
    Run("actual sparse two-image tier CAB chain, 508 CIBs, complete ownership", [&] {
        Files f(root,2); CabFixture(f); PersistCab(f); auto owner=f.Open(); std::string error;
        Check(owner->CheckAllocatorAdmission(error),"CAB held admission: "+error);
        AppleSpacemanView view;
        Check(LoadFusionSpacemanAllocationView(Access::Store(*owner),view,error),"CAB ownership: "+error);
        Check(view.devices[1].cabs.size()==2 && view.devices[1].cibs.size()==508 &&
            view.chunks.size()==8+CabLayout::tier_chunks,"CAB hierarchy coverage");
        Check(view.chunks.back().device_index==1 &&
            view.chunks.back().start_block==CabLayout::tier_blocks-CabLayout::per_chunk &&
            view.chunks.back().bitmap_block==0 && view.chunks.back().free_count==CabLayout::per_chunk,
            "canonical all-free last chunk");
        owner->Close(); f.Refresh(20); auto reader=ApfsFusionStore::BindImages(f.request,error);
        Check(reader && LoadFusionSpacemanAllocationView(*reader,view,error),"CAB independent reopen: "+error);
    });
    const std::vector<std::pair<const char*,std::function<void(Files&)>>> failures={
        {"CAB child aliases main CIB",[](auto& f){f.Edit(0,CabLayout::cab0,[](auto& b){Put(b,0x28,256);});}},
        {"CAB index mismatch",[](auto& f){f.Edit(0,CabLayout::cab1,[](auto& b){Put(b,0x20,0,4);});}},
        {"CAB duplicate child",[](auto& f){f.Edit(0,CabLayout::cab1,[](auto& b){Put(b,0x28,257);});}},
        {"CAB child outside main window",[](auto& f){f.Edit(0,CabLayout::cab1,[](auto& b){Put(b,0x28,CabLayout::main_blocks);});}},
        {"CAB parent older than child",[](auto& f){f.Edit(0,CabLayout::cab1,[](auto& b){Put(b,16,19);});}}
    };
    for(const auto& [name,mutate]:failures) Run(name,[&]{
        Files f(root); CabFixture(f); mutate(f); PersistCab(f); auto owner=f.Open(); std::string error;
        Check(!owner->CheckAllocatorAdmission(error) && !error.empty(),std::string("CAB accepted: ")+name);
        Check(Access::Writer(*owner).counters().main_blocks_written==0 &&
            Access::Writer(*owner).counters().tier2_blocks_written==0,"CAB parser wrote");
    });
}

