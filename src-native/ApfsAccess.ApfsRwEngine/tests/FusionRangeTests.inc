fs::path FusionRangeFixtureDirectory(const fs::path& root) {
    fs::path result;
    for (const auto& entry : fs::directory_iterator(root))
        if (entry.is_directory() && fs::is_regular_file(entry.path()/"main.apfs") && fs::is_regular_file(entry.path()/"tier.apfs")) {
            Check(result.empty(), "unique range fixture pair"); result = entry.path();
        }
    Check(!result.empty(), "range fixture pair present"); return result;
}
int FusionRangeChild(const fs::path& directory, const std::string& mode, const std::string& cut) {
    std::string error; auto runtime = OpenMountRuntime(directory, error); Check(runtime != nullptr, error);
    const auto hook = [&](std::string_view stage) { if (stage == cut) ExitProcess(73); return true; };
    constexpr std::uint64_t at = 6ull * 1024 * 1024 * 1024 + 3;
    const auto ok = mode == "range-write" ? runtime->Overwrite(30, at, Bytes(5000, std::byte{0x67}), error, hook) : runtime->Recover(error, hook);
    Check(ok, "range child: " + error);
    Bytes actual;
    Check(runtime->ReadFile(30, at - 3, 5004, actual, error) && actual == [] { Bytes b(5003); std::fill(b.begin()+3,b.end(),std::byte{0x67}); return b; }(), "range complete postimage: " + error);
    Check(runtime->ReadFile(30, 8192, 8192, actual, error) && actual == Bytes(8192), "canonical sparse gap: " + error);
    const auto water = runtime->Watermarks(); Check(water.accepted_sequence && water.accepted_sequence == water.cleanup_sequence && water.cleanup_sequence == water.apfs_durable_sequence, "range child original debt");
    return 0;
}
void RunFusionRangeTests(const fs::path& root) {
    Run("range COW, sparse growth, shrink tail, retained mappings and fresh owner", [&] {
        const auto fixture = root / "ranges"; ExportFusionMountFixture(fixture); const auto directory = FusionRangeFixtureDirectory(fixture);
        std::string error; auto runtime = OpenMountRuntime(directory, error); Check(runtime != nullptr, error);
        auto verify = [&](bool ok, const char* op) { Check(ok, std::string(op) + ": " + error); };
        std::uint64_t inode = 0; verify(runtime->CreateRegularFile(2, "larger.bin", inode, error), "create range file");
        Bytes expected(600123); for (std::size_t i = 0; i < expected.size(); ++i) expected[i] = std::byte((i * 17 + 31) % 251);
        for (std::size_t at = 0; at < expected.size();) {
            auto count = (std::min)(std::size_t{65536}, expected.size() - at);
            verify(runtime->Overwrite(inode, at, std::span(expected).subspan(at, count), error), "extending bounded write"); at += count;
        }
        Bytes actual; verify(runtime->ReadFile(inode, 0, expected.size()+1, actual, error) && actual == expected, "larger full readback");
        const Bytes patch(113, std::byte{0xDC}); verify(runtime->Overwrite(inode, 4091, patch, error), "unaligned retained subranges");
        std::copy(patch.begin(), patch.end(), expected.begin()+4091);
        verify(runtime->Resize(inode, 300123, error), "partial shrink"); expected.resize(300123);
        verify(runtime->Resize(inode, 800001, error), "sparse grow"); expected.resize(800001);
        verify(runtime->ReadFile(inode, 0, expected.size()+1, actual, error) && actual == expected, "shrink grow padding zeros");
        verify(runtime->Overwrite(inode, 1200003, patch, error), "write across sparse gap"); expected.resize(1200003 + patch.size());
        std::copy(patch.begin(), patch.end(), expected.begin()+1200003);
        verify(runtime->ReadFile(inode, 0, expected.size()+1, actual, error) && actual == expected, "sparse gap complete bytes");
        const auto water = runtime->Watermarks();
        Check(!runtime->Overwrite(inode, (1ull<<56)-4096, Bytes(1), error) && runtime->Watermarks().accepted_sequence == water.accepted_sequence, "canonical extent-address overflow preaccept");
        runtime.reset(); runtime = OpenMountRuntime(directory, error); Check(runtime != nullptr, error);
        verify(runtime->Recover(error), "range fresh recovery");
        verify(runtime->ReadFile(inode, 0, expected.size()+1, actual, error) && actual == expected, "range fresh full readback");
    });
    for (const std::string stage : {"after-fusion-accept", "after-fusion-mirror", "after-fusion-main"}) Run(("sparse range fresh process " + stage).c_str(), [&] {
        const auto fixture = root / stage; ExportFusionMountFixture(fixture); const auto directory = FusionRangeFixtureDirectory(fixture);
        Check(RuntimeProcess(directory, "range-write", stage) == 73, "range fresh cut reached");
        Check(RuntimeProcess(directory, "range-recover") == 0, "range fresh original replay");
        Check(RuntimeProcess(directory, "range-recover") == 0, "range idempotent replay");
    });
    Run("actual two-member device reclamation reuses retired extents", [&] {
        const auto fixture=root/"device-reuse";ExportFusionMountFixture(fixture);const auto directory=FusionRangeFixtureDirectory(fixture);
        std::string error;std::set<std::uint64_t> payload_blocks,metadata_blocks;bool payload_reused=false,metadata_reused=false;
        for(unsigned iteration=0;iteration<32;++iteration) {
            auto runtime=OpenMountRuntime(directory,error);Check(runtime!=nullptr,error);
            const auto written=runtime->Overwrite(30,0,Bytes(4096,std::byte(iteration+1)),error);Check(written,"reclaim write: "+error);
            const auto water=runtime->Watermarks();Check(water.accepted_sequence==water.apfs_durable_sequence&&water.accepted_sequence==water.cleanup_sequence,"reclaim original debt");runtime.reset();
            Fixture transport(4096,2);auto request=transport.request;Bytes anchor(4096);
            {std::ifstream input(directory/"main.apfs",std::ios::binary);input.seekg(8192);input.read(reinterpret_cast<char*>(anchor.data()),anchor.size());Check(bool(input),"reuse anchor read");}
            const auto nx=ParseNxSuperblock(anchor);Check(nx.has_value(),"reuse canonical anchor");request.checkpoint_xid=nx->xid;
            request.budget=std::make_shared<ApfsReadBudget>(100000,256ull<<20,1000000,256ull<<20);
            for(auto& member:request.members){member.path=(directory/(member.role==FusionMemberRole::Main?"main.apfs":"tier.apfs")).wstring();
                Check(ApfsFusionStore::InspectImage(member.path,member.exact_identity,error),error);member.store_size=member.exact_identity.size_bytes-8192;}
            auto store=ApfsFusionStore::BindImages(request,error);Check(store!=nullptr,error);
            auto cp=LoadAppleReadOnlyVolumeView(*store,store->Checkpoint(),error);Check(cp.has_value(),error);
            const auto volume=std::find_if(cp->volumes.begin(),cp->volumes.end(),[](const auto& v){return v.superblock.object_id==101;});Check(volume!=cp->volumes.end(),"reuse exact volume");
            std::vector<apfsaccess::catalog::BtreeRecord> records;Check(ReadBtreeLeafRecords(*store,4096,volume->root_tree.physical_block,false,volume->superblock.omap_oid,nx->xid,records,error),error);
            const auto extent=std::find_if(records.begin(),records.end(),[](const auto& r){return ReadU64LE(r.key,0)==((8ull<<60)|30)&&ReadU64LE(r.key,8)==0;});
            Check(extent!=records.end(),"reclaim extent present");const auto physical=ReadU64LE(extent->value,8);Check(physical&&*physical>=kFusionTier2ByteAddress/4096,"encoded Tier2 retained");
            payload_reused|=!payload_blocks.insert(*physical).second;metadata_reused|=!metadata_blocks.insert(volume->root_tree.physical_block).second;
            FusionReclamationCensus census;Check(CollectFusionReclamationCensus(*store,census,error),"independent retained owner census: "+error);
            auto old=LoadContainerCheckpointView(*store,0,store->SizeBytes(),error,nx->xid-1);Check(old&&LoadAppleReadOnlyVolumeView(*store,*old,error),"previous checkpoint remains readable");
            FusionReadStatus status;FusionVolumeSelection selection{request.container_uuid_hex,std::string(32,'c'),{"apfs-store:test-main","apfs-store:test-tier2"},101,nx->xid};
            auto reader=ApfsFusionReadSession::Open(std::move(store),selection,status,error);Check(reader!=nullptr,error);Bytes bytes;
            Check(reader->ReadFile(30,0,8193,bytes,error)&&bytes.size()==8192&&
                std::all_of(bytes.begin(),bytes.begin()+4096,[&](auto b){return b==std::byte(iteration+1);})&&
                std::all_of(bytes.begin()+4096,bytes.end(),[](auto b){return b==std::byte{0xB1};}),"reused block complete independent readback: "+error);
        }
        Check(payload_reused&&metadata_reused,"actual queue1 and queue2 addresses must both be reused");
    });
    Run("multinode namespace retained through replace and owner reopen", [&] {
        const auto fixture = root / "namespace"; ExportFusionMountFixture(fixture); const auto directory = FusionRangeFixtureDirectory(fixture);
        std::string error; auto runtime = OpenMountRuntime(directory,error); Check(runtime != nullptr,error);
        std::uint64_t parent = 0; Check(runtime->MakeDirectory(2,"many",parent,error),error);
        std::vector<std::uint64_t> ids; std::vector<std::string> names;
        for(unsigned i=0;i<64;++i) {
            std::uint64_t id = 0; auto name = std::to_string(i) + std::string(150,'n') + ".bin";
            const auto ok = runtime->CreateRegularFile(parent,name,id,error); Check(ok,"multinode create " + std::to_string(i) + ": " + error);
            ids.push_back(id); names.push_back(name);
        }
        const auto renamed = runtime->RenameReplacing(ids[0],parent,names.back(),ids.back(),error); Check(renamed,"multinode replace: " + error);
        runtime.reset(); runtime=OpenMountRuntime(directory,error); Check(runtime!=nullptr,error); Check(runtime->Recover(error),error);
        std::vector<MetadataStore::DirectoryLink> entries; Check(runtime->Enumerate(parent,entries,error) && entries.size()==63,"multinode complete fresh enumeration: " + error);
        for(unsigned i=1;i<63;++i) {MetadataStore::DirectoryLink link; Check(runtime->LookupEntry(parent,std::wstring(names[i].begin(),names[i].end()),link,error)&&link.child_object_id==ids[i],"retained multinode entry");}
    });
}
