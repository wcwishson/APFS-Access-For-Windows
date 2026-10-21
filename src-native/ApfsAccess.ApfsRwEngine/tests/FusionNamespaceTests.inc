int FusionNamespaceSequence(const fs::path& root) {
    ExportFusionMountFixture(root);const auto directory=root/"case-1";std::string error;
    auto runtime=OpenMountRuntime(directory,error);Check(runtime!=nullptr,error);
    auto verify=[&](bool ok,const char* op){Check(ok,std::string(op)+": "+error);std::cout<<"PASS "<<op<<'\n';};
    auto clean=[&](){const auto w=runtime->Watermarks();Check(w.accepted_sequence==w.cleanup_sequence&&w.cleanup_sequence==w.apfs_durable_sequence,"namespace complete original boundary");return w.accepted_sequence;};
    std::uint64_t parent=0,child=0,file=0,victim=0;
    verify(runtime->MakeDirectory(2,"\xE7\x9B\xAE\xE5\xBD\x95",parent,error),"Unicode directory");clean();
    verify(runtime->MakeDirectory(parent,"nested",child,error),"nested directory");
    verify(runtime->CreateRegularFile(child,"caf\xC3\xA9.bin",file,error),"Unicode file");
    verify(runtime->Resize(file,4096,error),"nested resize");
    verify(runtime->Overwrite(file,0,Bytes(4096,std::byte{0x75}),error),"nested payload");
    auto before=clean();
    Check(!runtime->Unlink(parent,error)&&error=="FusionRuntimeDirectoryNotEmpty"&&clean()==before,"nonempty directory original acceptance");
    Check(!runtime->Rename(parent,child,"cycle",error)&&error=="FusionRuntimeDirectoryCycle"&&clean()==before,"ancestor cycle original acceptance");
    std::uint64_t bad=0;
    Check(!runtime->CreateRegularFile(child,"\xC0\xAF",bad,error)&&clean()==before,"invalid UTF8 original acceptance");
    Check(!runtime->CreateRegularFile(child,"caf\xC3\xA9.bin",bad,error)&&clean()==before,"Unicode collision original acceptance");
    verify(runtime->Rename(child,2,"moved",error),"directory move");
    verify(runtime->Unlink(parent,error),"empty directory removal");
    verify(runtime->CreateRegularFile(2,"target.bin",victim,error),"replacement destination");
    verify(runtime->Resize(victim,8192,error),"replacement old allocation");
    before=clean();
    Check(!runtime->RenameReplacing(file,2,"target.bin",victim+1,error)&&clean()==before,"wrong replacement inode original acceptance");
    verify(runtime->RenameReplacing(file,2,"target.bin",victim,error),"atomic replacement");clean();
    FusionNodeInfo info;Bytes bytes;
    Check(!runtime->GetMetadata(victim,info,error)&&runtime->LastStatus()==FusionReadStatus::NotFound,"replaced inode retained");
    verify(runtime->Rename(file,2,"TARGET.bin",error),"case spelling rename");
    verify(runtime->Unlink(child,error),"moved empty directory removal");
    runtime.reset();runtime=OpenMountRuntime(directory,error);Check(runtime!=nullptr,error);verify(runtime->Recover(error),"fresh owner recovery");
    MetadataStore::DirectoryLink link;verify(runtime->LookupEntry(2,L"TARGET.bin",link,error)&&link.child_object_id==file,"fresh name lookup");
    verify(runtime->ReadFile(file,0,4097,bytes,error)&&bytes==Bytes(4096,std::byte{0x75}),"fresh payload readback");
    clean();std::cout<<"PASS namespace "<<checks<<" checks\n";return 0;
}
void RunFusionNamePolicies(const fs::path& root) {
    for(const auto feature:{1ull,8ull})Run(("canonical name policy "+std::to_string(feature)).c_str(),[&]{
        Files f(root,2);VolumePlanFixture(f);std::string error;
        OffsetRandomAccessSource source(f.sources[0].get(),f.prefix,512*f.bs);std::vector<apfsaccess::catalog::BtreeRecord> records;
        Check(ReadBtreeLeafRecords(source,f.bs,30,false,0,20,records,error),error);
        const auto policy=ApfsNamePolicy::FromIncompatibleFeatures(feature);
        for(auto& record:records)if(ReadU64LE(record.key,0).value_or(0)>>60==9){AppleDirectoryRecord link;
            Check(ApfsExtendedRecordCodec::DecodeDirectory(record,ApfsNamePolicy::FromIncompatibleFeatures(0),link,error),error);
            Check(EncodeAppleDirectoryRecord(link,policy,record,error),error);}
        AppleBtreeOptions options;options.block_size=f.bs;options.xid=20;options.root_object_id=1000;options.root_physical_block=30;
        options.subtype=kObjectTypeFsTree;options.key_order=AppleBtreeKeyOrder::FileSystemHashedDirectory;
        AppleSerializedBtree tree;Check(SerializeAppleBtree(records,options,tree,error),error);Check(tree.objects.size()==1,"policy fixture leaf");
        f.Place(0,30,tree.objects.front().bytes);f.Edit(1,4,[&](auto& b){Put(b,0x38,feature);});Persist(f);
        auto runtime=OpenRuntime(f.directory,error);Check(runtime!=nullptr,error);std::uint64_t inode=0,other=0;
        const bool created=runtime->CreateRegularFile(2,"Caf\xC3\xA9.bin",inode,error);Check(created,"canonical name create: "+error);
        const auto sequence=runtime->Watermarks().accepted_sequence;
        Check(!runtime->CreateRegularFile(2,"Cafe\xCC\x81.bin",other,error)&&error=="FusionRuntimeNameCollision"&&runtime->Watermarks().accepted_sequence==sequence,"normalization alias accepted");
        if(feature==1)Check(!runtime->CreateRegularFile(2,"CAF\xC3\x89.bin",other,error)&&error=="FusionRuntimeNameCollision"&&runtime->Watermarks().accepted_sequence==sequence,"case alias accepted");
        const bool renamed=runtime->Rename(inode,2,"CAFE\xCC\x81.bin",error);Check(renamed,"canonical case-spelling rename: "+error);
        runtime.reset();f.Refresh(22);auto store=ApfsFusionStore::BindImages(f.request,error);FusionReadStatus status;
        auto reader=ApfsFusionReadSession::Open(std::move(store),f.Selection(),status,error);Check(reader!=nullptr,error);
        MetadataStore::DirectoryLink found;Check(reader->LookupEntry(2,L"CAFE\u0301.bin",found,error)&&found.child_object_id==inode,"canonical independent name lookup");
        if(feature==1)Check(reader->LookupEntry(2,L"caf\u00e9.bin",found,error)&&found.child_object_id==inode,"case folded independent lookup");
    });
}
