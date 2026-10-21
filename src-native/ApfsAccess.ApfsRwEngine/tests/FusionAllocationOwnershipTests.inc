// Native layouts and production B-tree serialization on new private images.
void Bit(Bytes& bytes, std::uint64_t bit, bool set = true)
{
    const auto mask = std::byte(1u << (bit % 8));
    if (set) bytes.at(static_cast<std::size_t>(bit / 8)) |= mask;
    else bytes.at(static_cast<std::size_t>(bit / 8)) &= ~mask;
}
std::uint32_t Population(const Bytes& bytes)
{
    std::uint32_t count = 0;
    for (auto b : bytes) for (unsigned bit = 0; bit < 8; ++bit)
        count += (std::to_integer<unsigned>(b) >> bit) & 1;
    return count;
}
Bytes Queue(Files& f, std::uint64_t oid, std::uint64_t block,
    const std::vector<AppleSpacemanFreeQueueEntry>& entries)
{
    AppleBtreeOptions options;
    options.block_size = f.bs; options.xid = 20; options.root_object_id = oid;
    options.root_physical_block = block; options.storage_type = kObjectEphemeral;
    options.subtype = kObjectTypeSpacemanFreeQueue;
    options.tree_flags = kAppleBtreeEphemeral | kAppleBtreeAllowGhosts |
        kAppleBtreeUint64Keys | kAppleBtreeSequentialInsert;
    options.fixed_key_size = options.minimum_longest_key = 16;
    options.fixed_value_size = options.minimum_longest_value = 8;
    options.key_order = AppleBtreeKeyOrder::SpacemanFreeQueue;
    std::vector<apfsaccess::catalog::BtreeRecord> records;
    for (const auto& entry : entries)
    {
        apfsaccess::catalog::BtreeRecord r; r.key.resize(16);
        Put(r.key, 0, entry.xid); Put(r.key, 8, entry.physical_block);
        if (entry.block_count != 1) { r.value.resize(8); Put(r.value, 0, entry.block_count); }
        records.push_back(std::move(r));
    }
    AppleSerializedBtree tree; std::string error;
    Check(SerializeAppleBtree(records, options, tree, error) && tree.objects.size() == 1, "canonical queue serialize: " + error);
    return tree.objects.front().bytes;
}
void Persist(Files& f)
{
    Save(f.main, f.sources[0]->bytes); Save(f.tier, f.sources[1]->bytes); f.Refresh(20);
}
void AllocationFixture(Files& f)
{
    f.EditNx([](auto& nx) { Put(nx, 0x84, 0, 4); Put(nx, 0x94, 4, 4); });
    f.Edit(0, 1, [&](auto& map) {
        Put(map, 0x24, 4, 4);
        for (unsigned q = 0; q < 2; ++q) {
            const auto at = 0x78 + q * 0x28;
            Put(map, at, kObjectEphemeral | kObjectTypeBtree, 4);
            Put(map, at + 4, kObjectTypeSpacemanFreeQueue, 4); Put(map, at + 8, f.bs, 4);
            Put(map, at + 24, 80 + q); Put(map, at + 32, 10 + q);
        }
    });
    f.Place(0, 10, Queue(f, 80, 10, {{19, f.TierBlock() + 22, 2}}));
    f.Place(0, 11, Queue(f, 81, 11, {{19, 22, 1}}));
    Bytes main(f.bs), tier(f.bs), ip(f.bs);
    for (std::uint64_t b : {0,1,2,3,4,8,9,10,11,15,16,17,18,20,21,22,24,25,26,27,30}) Bit(main, b);
    for (std::uint64_t b = 32; b < 48; ++b) Bit(main, b);
    for (std::uint64_t b = 52; b < 64; ++b) Bit(main, b);
    for (std::uint64_t b : {0,4,5,6,20,21,22,23}) Bit(tier, b);
    for (std::uint64_t b = 0; b < 4; ++b) Bit(ip, b);
    f.Place(0, 32, ip); f.Place(0, 54, main); f.Place(0, 55, tier);
    for (unsigned device = 0; device < 2; ++device) {
        auto cib = Object(f.bs, 52 + device, kObjectPhysical | kObjectTypeSpacemanCib);
        Put(cib, 0x24, 1, 4); Put(cib, 0x28, 20); Put(cib, 0x30, 0);
        Put(cib, 0x38, device ? 32 : 64, 4);
        Put(cib, 0x3C, (device ? 32 : 64) - Population(device ? tier : main), 4);
        Put(cib, 0x40, 54 + device); Seal(cib); f.Place(0, 52 + device, cib);
    }
    f.Edit(0, 8, [&](auto& sm) {
        Put(sm, 0x48, 64 - Population(main)); Put(sm, 0x78, 32 - Population(tier));
        Put(sm, 0x50, 0x158, 4); Put(sm, 0x80, 0x160, 4);
        Put(sm, 0x94, 16, 4); Put(sm, 0x98, 12); Put(sm, 0xA0, 1, 4); Put(sm, 0xA4, 16, 4);
        Put(sm, 0xA8, 32); Put(sm, 0xB0, 52);
        Put(sm, 0xF0, 1); Put(sm, 0xF8, 81); Put(sm, 0x100, 19); Put(sm, 0x108, 64, 2);
        Put(sm, 0x118, 2); Put(sm, 0x120, 80); Put(sm, 0x128, 19); Put(sm, 0x130, 64, 2);
        Put(sm, 0x140, 1, 2); Put(sm, 0x142, 15, 2);
        Put(sm, 0x144, 0x168, 4); Put(sm, 0x148, 0x170, 4); Put(sm, 0x14C, 0x172, 4);
        Put(sm, 0x158, 52); Put(sm, 0x160, 53); Put(sm, 0x168, 20); Put(sm, 0x170, 0, 2);
        for (unsigned n = 0; n < 16; ++n) Put(sm, 0x172 + n * 2, n == 0 || n == 15 ? 0xFFFF : n + 1, 2);
    });
    Persist(f);
}
void RunAllocationTests(const fs::path& root)
{
    Run("canonical two-image allocator admission, local chunks and encoded queue", [&] {
        Files f(root, 2); AllocationFixture(f);
        auto before_main = Load(f.main), before_tier = Load(f.tier); auto owner = f.Open(); std::string error;
        Check(owner->CheckAllocatorAdmission(error), "held admission: " + error);
        AppleSpacemanView view;
        Check(LoadFusionSpacemanAllocationView(Access::Store(*owner), view, error), "canonical allocation: " + error);
        Check(view.chunks.size() == 2 && view.chunks[1].device_index == 1 && view.chunks[1].start_block == 0 &&
            view.devices[1].cibs[0].chunk_indices == std::vector<std::size_t>{1}, "device-local chunk indexing");
        Check(view.free_queues[2].entries[0].physical_block == f.TierBlock() + 22, "encoded tier queue lost");
        Check(!LoadAppleSpacemanOwnershipView(Access::Store(*owner), Access::Store(*owner).Checkpoint(), view, error) &&
            error == "AppleSpacemanTier2Unsupported" && view.chunks.empty(), "single-device allocator accepted Fusion");
        owner->Close(); f.Refresh(20);
        auto reader = ApfsFusionStore::BindImages(f.request, error);
        Check(reader && LoadFusionSpacemanAllocationView(*reader, view, error), "independent read-only reopen: " + error);
        reader.reset(); Check(Load(f.main) == before_main && Load(f.tier) == before_tier, "parser mutated images");
    });
    const std::vector<std::pair<const char*, std::function<void(Files&)>>> failures = {
        {"tier chunk carries encoded address", [](auto& f) { f.Edit(0,53,[&](auto& b){Put(b,0x30,f.TierBlock());}); }},
        {"tier chunk overruns member", [](auto& f) { f.Edit(0,53,[](auto& b){Put(b,0x38,33,4);}); }},
        {"tier bitmap aliases main bitmap", [](auto& f) { f.Edit(0,53,[](auto& b){Put(b,0x40,54);}); }},
        {"tier CIB aliases main CIB", [](auto& f) { f.Edit(0,8,[](auto& b){Put(b,0x160,52);}); }},
        {"tier bitmap points into encoded gap", [](auto& f) { f.Edit(0,53,[](auto& b){Put(b,0x40,96);}); }},
        {"tier bitmap outside internal pool", [](auto& f) { f.Edit(0,53,[&](auto& b){Put(b,0x40,f.TierBlock()+10);}); }},
        {"future tier CIB", [](auto& f) { f.Edit(0,53,[](auto& b){Put(b,16,21);}); }},
        {"tier chunk newer than CIB", [](auto& f) { f.Edit(0,53,[](auto& b){Put(b,16,19);}); }},
        {"overlapping address arrays", [](auto& f) { f.Edit(0,8,[](auto& b){Put(b,0x80,0x158,4);}); }},
        {"array overlaps fixed header", [](auto& f) { f.Edit(0,8,[](auto& b){Put(b,0x80,0x150,4);}); }},
        {"array beyond spaceman", [](auto& f) { f.Edit(0,8,[](auto& b){Put(b,0x80,4096,4);}); }},
        {"queue2 missing tier tag", [](auto& f) { f.Place(0,10,Queue(f,80,10,{{19,22,2}})); }},
        {"queue2 crosses member end", [](auto& f) { f.Place(0,10,Queue(f,80,10,{{19,f.TierBlock()+31,2}})); }},
        {"queue2 unknown high bits", [](auto& f) { f.Place(0,10,Queue(f,80,10,{{19,UINT64_MAX-1,2}})); }},
        {"queue2 targets free bitmap bits", [](auto& f) { f.Place(0,10,Queue(f,80,10,{{19,f.TierBlock()+24,2}})); }},
        {"queue2 overlap across XIDs", [](auto& f) { f.Place(0,10,Queue(f,80,10,{{18,f.TierBlock()+22,1},{19,f.TierBlock()+22,1}})); f.Edit(0,8,[](auto& b){Put(b,0x128,18);}); }},
        {"queue1 targets allocator metadata", [](auto& f) { f.Place(0,11,Queue(f,81,11,{{19,54,1}})); }},
        {"queue1 targets checkpoint", [](auto& f) { f.Place(0,11,Queue(f,81,11,{{19,2,1}})); }},
        {"queue2 targets tier anchor", [](auto& f) { f.Place(0,10,Queue(f,80,10,{{19,f.TierBlock(),1}})); f.Edit(0,8,[](auto& b){Put(b,0x118,1);}); }},
        {"internal pool marks tier CIB free", [](auto& f) { auto b=f.Block(0,32); Bit(b,1,false); f.Place(0,32,b); }},
        {"tier bitmap padding allocated", [](auto& f) { auto b=f.Block(0,55); Bit(b,32); f.Place(0,55,b); }},
        {"wrong tier free count", [](auto& f) { f.Edit(0,8,[](auto& b){Put(b,0x78,23);}); }},
        {"tier CIB unknown object flags", [](auto& f) { f.Edit(0,53,[](auto& b){Put(b,24,kObjectPhysical|kObjectTypeSpacemanCib|0x08000000u,4);}); }},
        {"internal bitmap nonzero padding", [](auto& f) { auto b=f.Block(0,32); Bit(b,12); f.Place(0,32,b); }},
        {"queue2 nonzero reserved fields", [](auto& f) { f.Edit(0,8,[](auto& b){Put(b,0x138,1);}); }},
        {"unsupported reservation profile", [](auto& f) { f.Edit(0,8,[](auto& b){Put(b,0xB8,1);}); }},
        {"CIB newer than every chunk", [](auto& f) { f.Edit(0,53,[](auto& b){Put(b,0x28,19);}); }},
        {"wrong internal pool size", [](auto& f) { f.Edit(0,8,[](auto& b){Put(b,0x98,11);}); }},
        {"unallocated tier anchor", [](auto& f) { auto b=f.Block(0,55); Bit(b,0,false); f.Place(0,55,b); f.Edit(0,53,[](auto& c){Put(c,0x3C,25,4);}); f.Edit(0,8,[](auto& s){Put(s,0x78,25);}); }}
    };
    for (const auto& [name, mutate] : failures) Run(name, [&] {
        Files f(root); AllocationFixture(f); mutate(f); Persist(f);
        const auto before_main = Load(f.main), before_tier = Load(f.tier);
        auto owner = f.Open(); std::string error; AppleSpacemanView view;
        Check(!owner->CheckAllocatorAdmission(error) && !error.empty(), std::string("bad admission: ") + name);
        Check(!LoadFusionSpacemanAllocationView(Access::Store(*owner),view,error) && view.chunks.empty() &&
            view.devices[1].cibs.empty(), "partial ownership escaped");
        Check(Access::Writer(*owner).counters().main_blocks_written == 0 &&
            Access::Writer(*owner).counters().tier2_blocks_written == 0, "parser wrote");
        owner->Close(); Check(Load(f.main)==before_main && Load(f.tier)==before_tier, "negative changed members");
    });
    Run("queue2 ghost record", [&] {
        Files f(root); AllocationFixture(f);
        f.Place(0,10,Queue(f,80,10,{{19,f.TierBlock()+22,1}}));
        f.Edit(0,8,[](auto& b){Put(b,0x118,1);}); Persist(f);
        auto owner=f.Open(); std::string error; Check(owner->CheckAllocatorAdmission(error), error);
    });
    Run("owned parser cancellation and sticky budget exhaustion", [&] {
        Files f(root); AllocationFixture(f); auto owner=f.Open(); std::string error;
        Check(owner->CheckAllocatorAdmission(error),error); owner->Cancel();
        Check(!owner->CheckAllocatorAdmission(error),"cancelled ownership accepted");
        owner->Close(); f.Refresh(20); owner=f.Open();
        f.request.budget->LimitRemainingTo(100,1<<20,1,1);
        Check(!owner->CheckAllocatorAdmission(error) && f.request.budget->Failed(),"budget exceeded");
        Check(!owner->CheckAllocatorAdmission(error),"sticky failure bypassed");
    });
    Run("owned parser member loss and confined store windows", [&] {
        Files f(root,2); AllocationFixture(f); auto owner=f.Open(); std::string error;
        Check(owner->CheckAllocatorAdmission(error),error);
        Check(Access::Device(*owner,1).Write(f.prefix+32*f.bs,Bytes(f.bs)),"private tier resize");
        Check(!owner->CheckAllocatorAdmission(error),"changed member ownership accepted");
        owner->Close(); f.Refresh(20);
        f.request.members[1].store_size=31*f.bs;
        Check(!ApfsFusionImageWriteSession::Open(f.request,f.Selection(),error),"short member window accepted");
    });
}

