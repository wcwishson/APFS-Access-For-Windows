void VolumePlanFixture(Files& f)
{
    AllocationFixture(f);
    f.sources[0]->bytes.resize(static_cast<std::size_t>(f.prefix + 512 * f.bs));
    f.sources[1]->bytes.resize(static_cast<std::size_t>(f.prefix + 128 * f.bs));
    auto nx = f.Block(0,0);
    Put(nx,0x28,640); Put(nx,0x58,10000); Put(nx,0x68,16,4); Put(nx,0x6C,32,4);
    Put(nx,0x70,128); Put(nx,0x78,160); Put(nx,0x80,2,4); Put(nx,0x84,4,4);
    Seal(nx); f.Place(0,0,nx); f.Place(0,129,nx);
    nx[0x50F] |= std::byte{1}; Seal(nx); f.Place(1,0,nx);
    auto map = f.Block(0,1); Put(map,8,128);
    for (unsigned i=0;i<4;++i) Put(map,0x48+i*0x28,160+i);
    Seal(map); f.Place(0,128,map);
    for(unsigned i=0;i<4;++i) f.Place(0,160+i,f.Block(0,8+i));
    f.Edit(0,15,[](auto& b){Put(b,0x20,1,4);});
    f.Edit(1,4,[](auto& b){Put(b,0x58,7);Put(b,0xE0,7);Put(b,0x78,kObjectPhysical|kObjectTypeBtree,4);Put(b,0x90,31);Put(b,0xB0,40);Put(b,0xB8,1);Put(b,0xC0,1);});
    std::vector<apfsaccess::catalog::BtreeRecord> extents;
    for(auto block: {20ull,f.TierBlock()+20}) {
        ApplePhysicalExtentRecord e{block,1,kApplePhysicalExtentKindNew,30,1};
        extents.push_back(Enc(e,EncodeApplePhysicalExtentRecord));
    }
    AppleBtreeOptions opts;opts.block_size=f.bs;opts.xid=20;opts.root_object_id=31;opts.root_physical_block=31;
    opts.storage_type=kObjectPhysical;opts.tree_flags=kAppleBtreePhysical;
    opts.subtype=kObjectTypeBlockRefTree;opts.key_order=AppleBtreeKeyOrder::PhysicalExtent;
    AppleSerializedBtree tree;std::string error;
    Check(SerializeAppleBtree(extents,opts,tree,error),error); f.Place(0,31,tree.objects.front().bytes);
    OffsetRandomAccessSource main_source(f.sources[0].get(),f.prefix,512*f.bs);
    std::vector<apfsaccess::catalog::BtreeRecord> filesystem;
    Check(ReadBtreeLeafRecords(main_source,f.bs,30,false,0,20,filesystem,error),error);
    filesystem.push_back(Enc(AppleDataStreamIdRecord{30,1},EncodeAppleDataStreamIdRecord));
    opts.root_object_id=1000;opts.root_physical_block=30;opts.storage_type=0;opts.tree_flags=0;
    opts.subtype=kObjectTypeFsTree;opts.key_order=AppleBtreeKeyOrder::FileSystemCaseSensitive;
    Check(SerializeAppleBtree(filesystem,opts,tree,error),error);f.Place(0,30,tree.objects.front().bytes);
    Bytes main(f.bs),tier(f.bs),ip(f.bs);
    for(std::uint64_t b:{0,15,17,18,20,22,24,25,26,27,30,31})Bit(main,b);
    for(std::uint64_t b=128;b<208;++b)Bit(main,b);
    for(std::uint64_t b=256;b<268;++b)Bit(main,b);
    for(std::uint64_t b:{0,4,5,6,20,22,23})Bit(tier,b);
    for(unsigned b=0;b<4;++b)Bit(ip,b);
    f.Place(0,192,ip); f.Place(0,258,main);f.Place(0,259,tier);
    for(unsigned d=0;d<2;++d){
        auto cib=Object(f.bs,256+d,kObjectPhysical|kObjectTypeSpacemanCib);
        Put(cib,0x24,1,4);Put(cib,0x28,20);Put(cib,0x38,d?128:512,4);
        Put(cib,0x3C,(d?128:512)-Population(d?tier:main),4);Put(cib,0x40,258+d);Seal(cib);f.Place(0,256+d,cib);
    }
    f.Edit(0,160,[&](auto& sm){
        Put(sm,0x30,512);Put(sm,0x60,128);Put(sm,0x48,512-Population(main));Put(sm,0x78,128-Population(tier));
        Put(sm,0xA8,192);Put(sm,0xB0,256);Put(sm,0x158,256);Put(sm,0x160,257);
    });
    for(auto& member:f.request.members)member.store_size=(member.role==FusionMemberRole::Main?512ull:128ull)*f.bs;
    Persist(f);
}

void AddSiblingVolume(Files& f)
{
    for(auto [member,block]:std::vector<std::pair<unsigned,std::uint64_t>>{{0,0},{0,129},{1,0}})
        f.Edit(member,block,[](auto& b){Put(b,0xC0,102);});
    f.Place(0,18,tf::BuildBtreeNode({{101,f.TierBlock()+4,0,20},{102,44,0,20}},20,f.bs,0,18,
        kObjectPhysical|kObjectTypeBtree,kObjectTypeOmap));
    tf::BuilderVolume v;v.oid=102;v.uuid_hex=std::string(32,'d');v.name="Unchanged sibling";v.incompat=0;
    v.vol_omap_oid_override=45;v.root_oid_override=2000;v.extentref_tree_oid=48;
    v.extentref_tree_type=kObjectPhysical|kObjectTypeBtree;v.file_system_allocated_blocks=6;
    v.reserve_block_count=30;v.next_object_id=60;v.total_blocks_allocated=6;
    f.Place(0,44,tf::BuildApsb(v,20,f.bs));
    f.Edit(0,44,[](auto& b){Put(b,0xB8,1);Put(b,0xC0,1);});
    f.Place(0,45,tf::BuildOmap(46,20,f.bs,45,kObjectPhysical|kObjectTypeOmap,kObjectPhysical|kObjectTypeBtree));
    f.Place(0,46,tf::BuildBtreeNode({{2000,47,0,20}},20,f.bs,0,46,kObjectPhysical|kObjectTypeBtree,kObjectTypeOmap));
    AppleInodeRecord root;root.object_id=root.private_id=root.parent_id=2;root.mode=0040755;root.children_or_links=1;
    AppleInodeRecord file;file.object_id=file.private_id=50;file.parent_id=2;file.mode=0100644;file.children_or_links=1;file.uncompressed_size=4096;
    AppleExtendedField stream{8,0,Bytes(40)};Put(stream.data,0,4096);Put(stream.data,8,4096);file.extended_fields.push_back(stream);
    AppleDirectoryRecord dir;dir.parent_id=2;dir.file_id=50;dir.flags=8;dir.name_utf8="sibling.bin";
    apfsaccess::catalog::BtreeRecord raw;std::string error;
    Check(EncodeAppleDirectoryRecord(dir,ApfsNamePolicy::FromIncompatibleFeatures(0),raw,error),error);
    std::vector<apfsaccess::catalog::BtreeRecord> records={Enc(root,EncodeAppleInodeRecord),Enc(file,EncodeAppleInodeRecord),raw,
        Enc(AppleDataStreamIdRecord{50,1},EncodeAppleDataStreamIdRecord),
        Enc(AppleFileExtentRecord{50,0,4096,f.TierBlock()+40,0,4096},EncodeAppleFileExtentRecord)};
    AppleBtreeOptions options;options.block_size=f.bs;options.xid=20;options.root_object_id=2000;options.root_physical_block=47;
    options.subtype=kObjectTypeFsTree;options.key_order=AppleBtreeKeyOrder::FileSystemCaseSensitive;
    AppleSerializedBtree tree;Check(SerializeAppleBtree(records,options,tree,error),error);f.Place(0,47,tree.objects.front().bytes);
    options.root_object_id=options.root_physical_block=48;options.storage_type=kObjectPhysical;options.tree_flags=kAppleBtreePhysical;
    options.subtype=kObjectTypeBlockRefTree;options.key_order=AppleBtreeKeyOrder::PhysicalExtent;
    records={Enc(ApplePhysicalExtentRecord{f.TierBlock()+40,1,kApplePhysicalExtentKindNew,50,1},EncodeApplePhysicalExtentRecord)};
    Check(SerializeAppleBtree(records,options,tree,error),error);f.Place(0,48,tree.objects.front().bytes);
    f.Place(1,40,Bytes(f.bs,std::byte{0x53}));
    auto main=f.Block(0,258),tier=f.Block(0,259);for(unsigned b=44;b<=48;++b)Bit(main,b);Bit(tier,40);
    f.Place(0,258,main);f.Place(0,259,tier);
    f.Edit(0,256,[&](auto& b){Put(b,0x3C,512-Population(main),4);});
    f.Edit(0,257,[&](auto& b){Put(b,0x3C,128-Population(tier),4);});
    f.Edit(0,160,[&](auto& b){Put(b,0x48,512-Population(main));Put(b,0x78,128-Population(tier));});
    Persist(f);
}

void CabVolumeFixture(Files& f)
{
    CabFixture(f);
    f.EditNx([](auto& b){Put(b,0x58,10000);Put(b,0x78,200);Put(b,0x6C,32,4);Put(b,0x84,4,4);});
    f.Edit(0,1,[](auto& m){for(unsigned i=0;i<4;++i)Put(m,0x48+i*0x28,200+i);});
    for(unsigned i=0;i<4;++i)f.Place(0,200+i,f.Block(0,8+i));
    f.Edit(0,15,[](auto& b){Put(b,0x20,1,4);});
    f.Edit(1,4,[](auto& b){Put(b,0x58,7);Put(b,0xE0,7);Put(b,0x78,kObjectPhysical|kObjectTypeBtree,4);Put(b,0x90,31);Put(b,0xB0,40);Put(b,0xB8,1);Put(b,0xC0,1);});
    std::string error;OffsetRandomAccessSource main_source(f.sources[0].get(),f.prefix,1024*f.bs);
    std::vector<apfsaccess::catalog::BtreeRecord> records;
    Check(ReadBtreeLeafRecords(main_source,f.bs,30,false,0,20,records,error),error);
    records.push_back(Enc(AppleDataStreamIdRecord{30,1},EncodeAppleDataStreamIdRecord));
    AppleBtreeOptions options;options.block_size=f.bs;options.xid=20;options.root_object_id=1000;options.root_physical_block=30;
    options.subtype=kObjectTypeFsTree;options.key_order=AppleBtreeKeyOrder::FileSystemCaseSensitive;
    AppleSerializedBtree tree;Check(SerializeAppleBtree(records,options,tree,error),error);f.Place(0,30,tree.objects.front().bytes);
    records={Enc(ApplePhysicalExtentRecord{20,1,kApplePhysicalExtentKindNew,30,1},EncodeApplePhysicalExtentRecord),
        Enc(ApplePhysicalExtentRecord{f.TierBlock()+20,1,kApplePhysicalExtentKindNew,30,1},EncodeApplePhysicalExtentRecord)};
    options.root_object_id=options.root_physical_block=31;options.storage_type=kObjectPhysical;options.tree_flags=kAppleBtreePhysical;
    options.subtype=kObjectTypeBlockRefTree;options.key_order=AppleBtreeKeyOrder::PhysicalExtent;
    Check(SerializeAppleBtree(records,options,tree,error),error);f.Place(0,31,tree.objects.front().bytes);
    auto bitmap=f.Block(0,CabLayout::main_bitmap);const auto old_population=Population(bitmap);
    Bit(bitmap,31);for(unsigned b=200;b<232;++b)Bit(bitmap,b);const auto delta=Population(bitmap)-old_population;
    f.Place(0,CabLayout::main_bitmap,bitmap);
    f.Edit(0,256,[&](auto& b){Put(b,0x3C,32768-Population(bitmap),4);});
    f.Edit(0,200,[&](auto& b){Put(b,0x48,ReadU64LE(b,0x48).value()-delta);});
    PersistCab(f);f.Budget(100000,512ull<<20,8000000,512ull<<20);
}

std::vector<apfsaccess::catalog::BtreeRecord> CurrentRecords(ApfsFusionImageWriteSession& owner)
{
    auto& store=Access::Store(owner);std::string error;
    auto cp=LoadAppleReadOnlyVolumeView(store,store.Checkpoint(),error);
    Check(cp.has_value(),"volume read: "+error);
    std::vector<apfsaccess::catalog::BtreeRecord> records;
    const auto& v=cp->volumes.front();
    Check(ReadBtreeLeafRecords(store,4096,v.root_tree.physical_block,false,v.superblock.omap_oid,
        cp->container.superblock.xid,records,error),"FS read: "+error);return records;
}
AppleVolumeTransactionRequest ReplaceFile(ApfsFusionImageWriteSession& owner,std::size_t bytes,std::byte fill)
{
    AppleVolumeTransactionRequest r;r.volume_object_id=101;
    auto records=CurrentRecords(owner);std::string error;
    for(auto record:records){
        const auto key=ReadU64LE(record.key,0).value(); const auto kind=key>>60;const auto oid=key&((1ull<<60)-1);
        if(kind==8&&oid==30){AppleFileExtentRecord e;Check(DecodeAppleFileExtentRecord(record,4096,e,error),error);
            if(e.physical_block)r.released_data_blocks.push_back({e.physical_block,e.length_bytes/4096});continue;}
        if(kind==3&&oid==30){AppleInodeRecord inode;Check(ApfsExtendedRecordCodec::DecodeInode(record,inode,error),error);
            inode.uncompressed_size=bytes;
            for(auto& field:inode.extended_fields)if(field.type==8){Put(field.data,0,bytes);Put(field.data,8,((bytes+4095)/4096)*4096);}
            record=Enc(inode,EncodeAppleInodeRecord);}
        r.filesystem_records.push_back(std::move(record));
    }
    if(bytes)r.data_writes.push_back({30,0,0,Bytes(bytes,fill)});
    return r;
}
AppleVolumeTransactionRequest CreateFile(ApfsFusionImageWriteSession& owner)
{
    AppleVolumeTransactionRequest r;r.volume_object_id=101;r.filesystem_records=CurrentRecords(owner);r.file_count_delta=1;
    AppleInodeRecord inode;inode.object_id=inode.private_id=40;inode.parent_id=2;inode.children_or_links=1;inode.mode=0100644;inode.uncompressed_size=4096;
    AppleExtendedField stream{8,0,Bytes(40)};Put(stream.data,0,4096);Put(stream.data,8,4096);inode.extended_fields.push_back(stream);
    r.filesystem_records.push_back(Enc(inode,EncodeAppleInodeRecord));
    AppleDirectoryRecord dir;dir.parent_id=2;dir.file_id=40;dir.flags=8;dir.name_utf8="created.bin";
    apfsaccess::catalog::BtreeRecord raw;std::string error;
    Check(EncodeAppleDirectoryRecord(dir,ApfsNamePolicy::FromIncompatibleFeatures(0),raw,error),error);
    r.filesystem_records.push_back(raw);r.data_writes.push_back({40,0,0,Bytes(4096,std::byte{0x71})});
    for(auto& record:r.filesystem_records)if(ReadU64LE(record.key,0)==((3ull<<60)|2)){
        AppleInodeRecord root;Check(ApfsExtendedRecordCodec::DecodeInode(record,root,error),error);++root.children_or_links;record=Enc(root,EncodeAppleInodeRecord);
    }
    return r;
}
FusionVolumeTransactionPlan PlanVolume(ApfsFusionImageWriteSession& owner,const AppleVolumeTransactionRequest& request)
{
    FusionVolumeTransactionPlan plan;std::string error;
    const bool ok=owner.PlanVolumeTransaction(request,plan,error);Check(ok,"Fusion ordinary plan: "+error);
    Check(plan.transaction.allocation.updated_spaceman.devices[1].free_count<128,"tier counter unchanged");
    Check(!plan.transaction.commit.publication.before_superblock_writes.empty(),"empty publication");return plan;
}
void RunVolumePlanTests(const fs::path& root)
{
    Run("bound allocator COW for tier CAB and proven all-free chunk",[&]{
        Files f(root);CabFixture(f);f.EditNx([](auto& nx){Put(nx,0x58,10000);});PersistCab(f);
        auto owner=f.Open();AppleSpacemanAllocationRequest r;r.expected_checkpoint_xid=20;r.transaction_xid=21;
        r.first_ephemeral_object_id=10000;r.main_block_count=1;r.search_from_end=true;
        r.released_blocks={{20,1},{f.TierBlock()+20,1}};
        FusionSpacemanAllocationPlan p;std::string error;
        const bool ok=PlanFusionSpacemanAllocation(Access::Store(*owner),r,1,p,error);
        Check(ok,"CAB allocation: "+error);
        Check(p.main.allocated_main_blocks==std::vector<std::uint64_t>{CabLayout::main_blocks-1}&&
            p.allocated_tier2_blocks==std::vector<std::uint64_t>{f.TierBlock()+CabLayout::tier_blocks-1},"device-end allocations");
        Check(p.main.updated_spaceman.devices[1].cabs[1].object.xid==21&&
            p.main.updated_spaceman.devices[1].cabs[0].object.xid==20,"CAB COW scope");
        Check(p.main.updated_spaceman.chunks.back().bitmap_block!=0&&
            p.main.updated_spaceman.chunks.back().free_count==32767,"proven all-free bitmap materialization");
        Check(p.main.updated_spaceman.free_queues[2].entries.size()==2,"queue2 retained and appended");
        Check(Access::Writer(*owner).counters().main_blocks_written==0,"allocator performed IO mutation");
    });
    for(const auto size:{8192u,4096u,12288u,0u})Run(("ordinary Fusion write/resize "+std::to_string(size)).c_str(),[&]{
        Files f(root,2);VolumePlanFixture(f);const auto oldmain=Load(f.main),oldtier=Load(f.tier);
        auto owner=f.Open();std::string error;
        auto request=ReplaceFile(*owner,size,std::byte{0x67});auto plan=PlanVolume(*owner,request);
        Bytes main_bytes(oldmain.size()),tier_bytes(oldtier.size());
        Check(Access::Device(*owner,0).ReadForVerification(0,oldmain.size(),main_bytes)&&
            Access::Device(*owner,1).ReadForVerification(0,oldtier.size(),tier_bytes)&&
            main_bytes==oldmain&&tier_bytes==oldtier,"planner mutated images");
        Check(plan.allocated_tier2_blocks.size()==(size+4095)/4096,"tier payload allocation count");
        Check(Execute(*owner,plan.transaction.commit.publication,error),"ordinary publish: "+error);
        VerifyWrites(*owner,plan.transaction.commit.publication);owner->Close();f.Refresh(21);owner=f.Open();
        Check(owner->CheckAllocatorAdmission(error),"reparsed new canonical ownership: "+error);
        Bytes bytes;Check(owner->ReadFile(30,0,size+1,bytes,error)&&bytes==Bytes(size,std::byte{0x67}),"reader write/resize: "+error);
    });
    Run("ordinary Fusion create with unchanged original file",[&]{
        Files f(root);VolumePlanFixture(f);auto owner=f.Open();auto plan=PlanVolume(*owner,CreateFile(*owner));std::string error;
        Check(Execute(*owner,plan.transaction.commit.publication,error),error);VerifyWrites(*owner,plan.transaction.commit.publication);
        owner->Close();f.Refresh(21);owner=f.Open();Bytes bytes;
        Check(owner->ReadFile(40,0,4096,bytes,error)&&bytes==Bytes(4096,std::byte{0x71}),"created file reader: "+error);
        Check(owner->ReadFile(30,0,8192,bytes,error)&&bytes.size()==8192&&bytes.front()==std::byte{0xA1}&&bytes.back()==std::byte{0xB1},"retained original");
        Check(owner->CheckAllocatorAdmission(error),"created ownership: "+error);
    });
    for(const auto stage:{"before-apple-device-write","before-apple-fusion-anchor-mirror","before-apple-checkpoint-switch","before-apple-final-flush"})
    Run((std::string("ordinary Fusion interruption ")+stage).c_str(),[&]{
        Files f(root);VolumePlanFixture(f);auto owner=f.Open();auto plan=PlanVolume(*owner,ReplaceFile(*owner,8192,std::byte{0x33}));std::string error;bool hit=false;
        const bool done=Execute(*owner,plan.transaction.commit.publication,error,[&](auto name){if(name==stage){hit=true;return false;}return true;});
        Check(hit&&!done,"interruption stage not reached");
        auto& store=Access::Store(*owner);auto old=LoadContainerCheckpointView(store,0,store.SizeBytes(),error,20);
        Check(old.has_value(),"old checkpoint after interruption");
        auto latest=LoadContainerCheckpointView(store,0,store.SizeBytes(),error);Check(latest.has_value(),"complete interrupted checkpoint");
        const auto xid=latest->superblock.xid;Check(xid==20||xid==21,"torn generation selected");
        owner->Close();f.Refresh(xid);owner=f.Open();Bytes bytes;
        Check(owner->ReadFile(30,0,8192,bytes,error),"recovery reader: "+error);
        Check(bytes==(xid==21?Bytes(8192,std::byte{0x33}):[&]{Bytes b(8192,std::byte{0xA1});std::fill(b.begin()+4096,b.end(),std::byte{0xB1});return b;}()),"recovery mixed data");
    });
    Run("bound planner cancellation, wrong volume and member loss",[&]{
        Files f(root);VolumePlanFixture(f);auto owner=f.Open();auto request=ReplaceFile(*owner,4096,std::byte{1});FusionVolumeTransactionPlan plan;std::string error;
        request.volume_object_id=102;Check(!owner->PlanVolumeTransaction(request,plan,error),"wrong volume admitted");request.volume_object_id=101;
        Check(Access::Device(*owner,1).Write(f.prefix+128*f.bs,Bytes(f.bs)),"private member growth");
        Check(!owner->PlanVolumeTransaction(request,plan,error)&&plan.transaction.commit.publication.before_superblock_writes.empty(),"lost member plan");
        owner->Cancel();Check(!owner->PlanVolumeTransaction(request,plan,error),"cancelled plan");
    });
    const std::vector<std::pair<const char*,std::function<void(Files&)>>> invalid={
        {"live payload marked free",[](auto& f){auto b=f.Block(0,259);Bit(b,20,false);f.Place(0,259,b);
            f.Edit(0,257,[](auto& c){Put(c,0x3C,122,4);});f.Edit(0,160,[](auto& sm){Put(sm,0x78,122);});}},
        {"live metadata marked free",[](auto& f){auto b=f.Block(0,258);Bit(b,31,false);f.Place(0,258,b);
            f.Edit(0,256,[&](auto& c){Put(c,0x3C,512-Population(b),4);});f.Edit(0,160,[&](auto& sm){Put(sm,0x48,512-Population(b));});}},
        {"live payload already queued",[](auto& f){f.Place(0,162,Queue(f,80,162,{{19,f.TierBlock()+20,1},{19,f.TierBlock()+22,2}}));
            f.Edit(0,160,[](auto& s){Put(s,0x118,3);});}},
        {"tier bitmap crossed member ownership",[](auto& f){f.Edit(0,257,[&](auto& c){Put(c,0x30,f.TierBlock());});}}
    };
    for(const auto& [name,mutate]:invalid)Run(name,[&]{
        Files f(root);VolumePlanFixture(f);mutate(f);Persist(f);
        const auto before_main=Load(f.main),before_tier=Load(f.tier);auto owner=f.Open();
        AppleVolumeTransactionRequest request;request.volume_object_id=101;request.filesystem_records=CurrentRecords(*owner);
        FusionVolumeTransactionPlan plan;std::string error;
        Check(!owner->PlanVolumeTransaction(request,plan,error)&&plan.transaction.commit.publication.before_superblock_writes.empty(),"invalid owner plan: "+error);
        owner->Close();Check(Load(f.main)==before_main&&Load(f.tier)==before_tier,"negative ownership changed members");
    });
    Run("allocator rejects encoded gap and allocated reserved releases",[&]{
        Files f(root);VolumePlanFixture(f);auto owner=f.Open();
        AppleSpacemanAllocationRequest request;request.expected_checkpoint_xid=20;request.transaction_xid=21;request.first_ephemeral_object_id=10000;
        for(auto b:{512ull,f.TierBlock()+128,17ull,24ull,f.TierBlock(),f.TierBlock()+22}){
            request.released_blocks={{b,1}};FusionSpacemanAllocationPlan p;std::string error;
            Check(!PlanFusionSpacemanAllocation(Access::Store(*owner),request,1,p,error)&&p.allocated_tier2_blocks.empty(),"unsafe release admitted");
        }
    });
    Run("ordinary Fusion publication preserves sibling payload and reserve",[&]{
        Files f(root,2);VolumePlanFixture(f);AddSiblingVolume(f);auto owner=f.Open();std::string error;
        auto plan=PlanVolume(*owner,ReplaceFile(*owner,8192,std::byte{0x62}));
        Check(Execute(*owner,plan.transaction.commit.publication,error),"sibling publish: "+error);
        VerifyWrites(*owner,plan.transaction.commit.publication);owner->Close();f.Refresh(21);
        auto selection=f.Selection();selection.volume_oid=102;selection.volume_uuid_hex=std::string(32,'d');
        auto sibling=ApfsFusionImageWriteSession::Open(f.request,selection,error);Check(static_cast<bool>(sibling),"sibling reopen: "+error);
        Bytes bytes;Check(sibling->ReadFile(50,0,4096,bytes,error)&&bytes==Bytes(4096,std::byte{0x53}),"sibling data lost");
        Check(sibling->CheckAllocatorAdmission(error),"sibling ownership lost: "+error);
    });
    Run("sibling metadata guard refuses stale publication before writes",[&]{
        Files f(root);VolumePlanFixture(f);AddSiblingVolume(f);auto owner=f.Open();auto plan=PlanVolume(*owner,CreateFile(*owner));std::string error;
        auto bytes=f.Block(0,44);Put(bytes,0x48,31);Seal(bytes);
        Check(Access::Device(*owner,0).Write(f.prefix+44*f.bs,bytes),"private stale sibling control");
        Check(!Execute(*owner,plan.transaction.commit.publication,error)&&error=="AppleCheckpointGuardChanged","stale sibling publication: "+error);
        Check(Access::Writer(*owner).counters().main_blocks_written==0&&Access::Writer(*owner).counters().tier2_blocks_written==0,"stale plan dispatched writes");
    });
    Run("actual sparse CAB ordinary COW publication and reader reopen",[&]{
        Files f(root,2);CabVolumeFixture(f);auto owner=f.Open();std::string error;FusionVolumeTransactionPlan plan;
        const bool planned=owner->PlanVolumeTransaction(ReplaceFile(*owner,8192,std::byte{0x75}),plan,error);
        Check(planned,"CAB ordinary plan: "+error);
        Check(plan.transaction.allocation.updated_spaceman.devices[1].cabs[0].object.xid==21,"tier CAB was not COWed");
        Check(Execute(*owner,plan.transaction.commit.publication,error),"CAB ordered publish: "+error);
        VerifyWrites(*owner,plan.transaction.commit.publication);owner->Close();f.Refresh(21);owner=f.Open();
        Check(owner->CheckAllocatorAdmission(error),"CAB canonical postimage: "+error);Bytes bytes;
        Check(owner->ReadFile(30,0,8192,bytes,error)&&bytes==Bytes(8192,std::byte{0x75}),"CAB independent reader: "+error);
    });
    Run("staged namespace proof rejects a hidden new file extent",[&]{
        Files f(root);VolumePlanFixture(f);auto owner=f.Open();auto request=CreateFile(*owner);
        for(auto& record:request.filesystem_records)if(ReadU64LE(record.key,0)==((3ull<<60)|40)){
            AppleInodeRecord inode;std::string error;Check(ApfsExtendedRecordCodec::DecodeInode(record,inode,error),error);
            inode.extended_fields.clear();record=Enc(inode,EncodeAppleInodeRecord);
        }
        FusionVolumeTransactionPlan plan;std::string error;
        Check(!owner->PlanVolumeTransaction(request,plan,error)&&error=="SnapshotHiddenFileExtent", "invalid staged namespace admitted: "+error);
        Check(plan.transaction.commit.publication.before_superblock_writes.empty(),"invalid draft escaped");
    });
    Run("second canonical generation protects old checkpoints and queue2",[&]{
        Files f(root);VolumePlanFixture(f);auto owner=f.Open();auto first=PlanVolume(*owner,CreateFile(*owner));std::string error;
        Check(Execute(*owner,first.transaction.commit.publication,error),error);owner->Close();f.Refresh(21);owner=f.Open();
        auto request=ReplaceFile(*owner,4096,std::byte{0x42});request.required_checkpoint_xids={20};
        auto second=PlanVolume(*owner,request);Check(Execute(*owner,second.transaction.commit.publication,error),"second publish: "+error);
        VerifyWrites(*owner,second.transaction.commit.publication);
        auto old=LoadContainerCheckpointView(Access::Store(*owner),0,Access::Store(*owner).SizeBytes(),error,20);
        Check(old.has_value(),"accepted old pin lost");owner->Close();f.Refresh(22);owner=f.Open();Bytes bytes;
        Check(owner->ReadFile(40,0,4096,bytes,error)&&bytes==Bytes(4096,std::byte{0x71}),"first generation file lost");
        Check(owner->ReadFile(30,0,4096,bytes,error)&&bytes==Bytes(4096,std::byte{0x42}),"second generation data wrong");
        Check(owner->CheckAllocatorAdmission(error),"second generation parser: "+error);
    });
}
