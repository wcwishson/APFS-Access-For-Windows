#define APFS_PHYSICAL_KEEPER_FIXTURE_ONLY
#include "VolumePhysicalKeeperTests.cpp"
#include "../src/VolumePhysicalGeometryInternal.h"
#define APFS_VOLUME_IMAGE_FAULT_INJECTION
#include "../tools/VolumeResizeCli.h"
#include <sstream>

namespace apfsaccess::rw {
struct VolumePhysicalGeometryTestPeer {
    static std::shared_ptr<VolumePhysicalGeometrySource> Bind(const std::shared_ptr<PhysicalFile>& file,const RawSnapshotBinding& original) {
        auto impl=std::make_unique<VolumePhysicalGeometrySource::Impl>();auto* state=impl.get();
        impl->original=original;impl->instance=SimulatedInstance;impl->current=[file]{return file->Current();};
        impl->read=[file](auto at,auto n,auto& out){return file->Read(at,n,out);};
        impl->write=[file,state](auto at,auto bytes){
            const bool window=state->plan && at>=SimulatedBase && at-SimulatedBase<=state->plan->snapshot.target_bytes &&
                bytes.size()<=state->plan->snapshot.target_bytes-(at-SimulatedBase);
            const bool gpt=state->plan && std::any_of(state->plan->writes.begin(),state->plan->writes.end(),[&](const auto& w){
                return w.offset==at && bytes.size()==w.after.size() && std::equal(bytes.begin(),bytes.end(),w.after.begin());});
            if(!window && !gpt){++file->escaped;return false;}
            LARGE_INTEGER offset{};offset.QuadPart=at;DWORD n{};++file->writes;
            return SetFilePointerEx(file->handle,offset,nullptr,FILE_BEGIN) && WriteFile(file->handle,bytes.data(),static_cast<DWORD>(bytes.size()),&n,nullptr) && n==bytes.size();
        };
        impl->zero=[file,state](auto at,auto n){
            if(!state->plan || at<SimulatedBase || at-SimulatedBase>state->plan->snapshot.target_bytes || n>state->plan->snapshot.target_bytes-(at-SimulatedBase))return false;
            FILE_ZERO_DATA_INFORMATION range{};range.FileOffset.QuadPart=at;range.BeyondFinalZero.QuadPart=at+n;DWORD got{};++file->zeros;
            return DeviceIoControl(file->handle,FSCTL_SET_ZERO_DATA,&range,sizeof(range),nullptr,0,&got,nullptr)!=FALSE;
        };
        impl->flush=[file]{return FlushFileBuffers(file->handle)!=FALSE;};impl->refresh=[file]{return file->Current();};
        impl->retire=[file]{return file->Current();};
        impl->rebind=[file](const RawSnapshotBinding& binding,std::string&){file->binding=binding;return VolumePhysicalKeeperTestPeer::Bind(file);};
        return std::shared_ptr<VolumePhysicalGeometrySource>(new VolumePhysicalGeometrySource(std::move(impl)));
    }
    static void CorruptRebind(const std::shared_ptr<VolumePhysicalGeometrySource>& source,const std::shared_ptr<PhysicalFile>& file){
        source->impl_->rebind=[file](const RawSnapshotBinding& binding,std::string&){
            file->binding=binding;Bytes anchor;
            Check(file->Read(SimulatedBase,4096,anchor),"handoff control reads completed anchor");anchor.front()^=std::byte{1};
            Check(file->Write(0,anchor) && FlushFileBuffers(file->handle),"handoff control alters only APFS after geometry retirement");
            return VolumePhysicalKeeperTestPeer::Bind(file);
        };
    }
};
}
namespace {
namespace vg=apfsaccess::rw::volume_geometry;
void RawWrite(const std::shared_ptr<PhysicalFile>& file,std::uint64_t at,const Bytes& bytes) {
    LARGE_INTEGER offset{};offset.QuadPart=at;DWORD n{};
    Check(SetFilePointerEx(file->handle,offset,nullptr,FILE_BEGIN) && WriteFile(file->handle,bytes.data(),static_cast<DWORD>(bytes.size()),&n,nullptr) && n==bytes.size() &&
        FlushFileBuffers(file->handle),"actual private fixture bytes");
}
void StoreGuid(Bytes& bytes,std::size_t at,const std::array<std::byte,16>& guid){
    constexpr unsigned order[]={3,2,1,0,5,4,7,6,8,9,10,11,12,13,14,15};for(unsigned i=0;i<16;++i)bytes[at+order[i]]=guid[i];
}
struct GeometryFixture {
    PhysicalFixture fixture;RawSnapshotBinding original;VolumeImageRequest request;std::shared_ptr<VolumePhysicalGeometrySource> source;
    explicit GeometryFixture(const std::string& name,bool grow,std::uint32_t sector=4096,bool ephemeral_nx=false,
        std::uint64_t partition_bytes=0):fixture(name,VolumeImageOperation::Format){
        auto file=fixture.file;file->binding.media.logical_sector_bytes=sector;
        if(partition_bytes)file->binding.media.partition_length_bytes=partition_bytes;
        original=file->binding;request=fixture.request;request.operation=grow?VolumeImageOperation::Grow:VolumeImageOperation::Shrink;
        request.target_bytes=(grow?5*mc::ChunkBlocks-13:3*mc::ChunkBlocks-25)*4096;
        request.new_container_uuid.clear();request.new_volume_uuid.clear();request.new_volume_wal.clear();request.name_utf8.clear();request.case_sensitive=false;
        file->sentinels.clear();RawWrite(file,SimulatedBase+request.expected_bytes,Bytes(4096));
        const auto last=SimulatedDiskBytes/sector-1;const auto array_sectors=16384/sector;
        Bytes array(16384);std::array<std::byte,16> type{};
        const unsigned apfs[]={0x7c,0x34,0x57,0xef,0,0,0x11,0xaa,0xaa,0x11,0,0x30,0x65,0x43,0xec,0xac};
        for(unsigned i=0;i<16;++i)type[i]=std::byte(apfs[i]);StoreGuid(array,0,type);StoreGuid(array,16,original.media.partition_guid);
        vi::Put(array,32,SimulatedBase/sector);vi::Put(array,40,(SimulatedBase+original.media.partition_length_bytes)/sector-1);
        type.fill(std::byte{0x63});StoreGuid(array,128,type);type.fill(std::byte{0x64});StoreGuid(array,144,type);
        const auto neighbor=SimulatedBase+(std::max)(original.media.partition_length_bytes,request.target_bytes)+(16u<<20);
        vi::Put(array,160,neighbor/sector);vi::Put(array,168,neighbor/sector+7);vi::Put(array,176,0x1234);vi::Put(array,184,'N',2);
        Bytes mbr(sector);mbr[450]=std::byte{0xee};vi::Put(mbr,454,1,4);vi::Put(mbr,458,(std::min<std::uint64_t>)(last,UINT32_MAX),4);mbr[510]=std::byte{0x55};mbr[511]=std::byte{0xaa};
        const auto header=[&](bool backup){Bytes bytes(sector);vi::Put(bytes,0,0x5452415020494645ull);vi::Put(bytes,8,0x10000,4);vi::Put(bytes,12,92,4);
            vi::Put(bytes,24,backup?last:1);vi::Put(bytes,32,backup?1:last);vi::Put(bytes,40,34);vi::Put(bytes,48,last-33);StoreGuid(bytes,56,original.media.disk_guid);
            vi::Put(bytes,72,backup?last-array_sectors:2);vi::Put(bytes,80,128,4);vi::Put(bytes,84,128,4);vi::Put(bytes,88,vg::Crc32(array),4);vi::Put(bytes,16,vg::Crc32(std::span(bytes).first(92)),4);return bytes;};
        RawWrite(file,0,mbr);RawWrite(file,sector,header(false));RawWrite(file,2*sector,array);RawWrite(file,(last-array_sectors)*sector,array);RawWrite(file,last*sector,header(true));
        for(const auto at:{SimulatedBase-sector,neighbor,neighbor+7*sector,SimulatedDiskBytes-(1u<<20)}){
            const Bytes bytes(sector,std::byte{0x6d});RawWrite(file,at,bytes);file->sentinels.emplace(at,bytes);}
        if(ephemeral_nx)for(std::uint64_t block=0;block<1024;++block){Bytes bytes;Check(file->Read(SimulatedBase+block*4096,4096,bytes),"authored ephemeral NX fixture read");
            if(ParseNxSuperblock(bytes)){vi::Put(bytes,0x18,apfsaccess::catalog::kObjectEphemeral|apfsaccess::catalog::kNxSuperblockObjectType,4);vi::Checksum(bytes);RawWrite(file,SimulatedBase+block*4096,bytes);}}
        if(ephemeral_nx){
            const auto cp=mc::Load(*fixture.source);
            const auto fixed_map=[&](const AppleOmapView& map,std::uint64_t obsolete=0){
                std::string error;std::vector<apfsaccess::catalog::BtreeRecord> records;
                Check(ReadBtreeLeafRecords(*fixture.source,4096,map.tree.physical_block,true,0,cp.container.superblock.xid,records,error),error);
                if(obsolete){const auto count=records.size();std::erase_if(records,[&](const auto& record){return ReadU64LE(record.key,0)==obsolete;});
                    Check(records.size()+1==count,"remove exact old virtual snapshot mapping");}
                AppleBtreeOptions options;options.block_size=4096;options.xid=map.tree.xid;options.root_object_id=options.root_physical_block=map.tree.physical_block;
                options.storage_type=apfsaccess::catalog::kObjectPhysical;options.subtype=apfsaccess::catalog::kObjectTypeOmap;options.key_order=AppleBtreeKeyOrder::ObjectMap;
                options.tree_flags=kAppleBtreePhysical;options.fixed_key_size=options.fixed_value_size=16;
                AppleSerializedBtree tree;Check(SerializeAppleBtree(records,options,tree,error) && tree.objects.size()==1,"canonical fixed OMAP fixture: "+error);
                RawWrite(file,SimulatedBase+map.tree.physical_block*4096,tree.objects.front().bytes);
                Bytes object;Check(fixture.source->Read(map.object.physical_block*4096,4096,object),"OMAP object fixture read");
                vi::Put(object,8,map.object.physical_block);vi::Put(object,24,apfsaccess::catalog::kObjectPhysical|apfsaccess::catalog::kObjectTypeOmap,4);
                vi::Put(object,40,apfsaccess::catalog::kObjectPhysical|apfsaccess::catalog::kObjectTypeBtree,4);vi::Put(object,48,map.tree.physical_block);vi::Checksum(object);
                RawWrite(file,SimulatedBase+map.object.physical_block*4096,object);
            };
            fixed_map(cp.container_object_map);
            for(const auto& volume:cp.volumes){
                Check(volume.snapshot_metadata_tree.has_value(),"authored snapshot metadata tree exists");
                const auto snapshot_block=volume.snapshot_metadata_tree->physical_block;
                std::vector<apfsaccess::catalog::BtreeRecord> records;std::string error;
                Check(ReadBtreeLeafRecords(*fixture.source,4096,snapshot_block,false,volume.superblock.omap_oid,cp.container.superblock.xid,records,error) && records.empty(),"authored empty snapshot metadata tree: "+error);
                AppleBtreeOptions options;options.block_size=4096;options.xid=volume.snapshot_metadata_tree->xid;
                options.root_object_id=options.root_physical_block=snapshot_block;options.storage_type=apfsaccess::catalog::kObjectPhysical;
                options.subtype=0x10;options.tree_flags=kAppleBtreePhysical;
                AppleSerializedBtree snapshots;
                Check(SerializeAppleBtree(records,options,snapshots,error) && snapshots.objects.size()==1,"canonical empty physical snapshot tree: "+error);
                RawWrite(file,SimulatedBase+snapshot_block*4096,snapshots.objects.front().bytes);
                Bytes superblock;Check(fixture.source->Read(volume.superblock_object.physical_block*4096,4096,superblock),"snapshot APSB fixture read");
                vi::Put(superblock,0x7c,apfsaccess::catalog::kObjectPhysical|apfsaccess::catalog::kObjectTypeBtree,4);
                vi::Put(superblock,0x98,snapshot_block);vi::Checksum(superblock);
                RawWrite(file,SimulatedBase+volume.superblock_object.physical_block*4096,superblock);
                fixed_map(volume.object_map,volume.superblock.snap_meta_tree_oid);
            }
            mc::Verify(*fixture.source,mc::Load(*fixture.source));
        }
        std::filesystem::create_directories(request.journal_directory);
        const auto h=CreateFileW(FixtureIoPath(request.journal_directory).c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,nullptr);
        USHORT compression=COMPRESSION_FORMAT_DEFAULT;DWORD got{};
        Check(h!=INVALID_HANDLE_VALUE && DeviceIoControl(h,FSCTL_SET_COMPRESSION,&compression,sizeof(compression),nullptr,0,&got,nullptr),"compress journal directory without compressing sparse carrier");CloseHandle(h);
        source=VolumePhysicalGeometryTestPeer::Bind(file,original);Check(source->Revalidate(),"exact fictional held identity");
    }
    void Fresh(){source=VolumePhysicalGeometryTestPeer::Bind(fixture.file,original);}
};
void GeometryPositive(){
    for(bool grow:{true,false}){GeometryFixture f(grow?"grow":"shrink",grow);const auto before=fe::Scan(*f.fixture.source).digests;
        const auto p=PrepareVolumePhysicalResize(f.source,f.request);Check(p.outcome==VolumeImageOutcome::Prepared,"physical resize prepare: "+p.error);
        Check(fe::Scan(*f.fixture.source).digests==before && !f.fixture.file->writes,"prepare preserves entire original");
        Check(ReadU64LE(Read(p.journal),0)==vg::Magic,"explicit VIF7 receipt");
        std::shared_ptr<VolumePhysicalSource> fixed;const auto done=ApplyVolumePhysicalResize(f.source,f.request,p.token,{},&fixed);
        Check(done.outcome==VolumeImageOutcome::Committed && fixed && !f.source->Revalidate(),"actual resize and capability replacement: "+done.error);
        const auto plan=DecodeVolumeKeeperGeometryPlan(Read(p.journal));std::string error;
        Check(fixed->Binding()==plan.after && fixed->SizeBytes()==f.request.target_bytes && fixed->VerifyCompletedGeometry(vg::Encode(plan),error),"full primary backup and neighbor census after rebind: "+error);
        mc::Verify(*fixed,mc::Load(*fixed));
        {auto history=AcquireVolumeKeeperPhysicalHistory(fixed,*fixed,f.request.journal_directory,{});mc::NativeWrite(*fixed);}
        f.Fresh();Check(RecoverVolumePhysicalResize(f.source,f.request).outcome==VolumeImageOutcome::Committed,"completed geometry permits ordinary mutation and reopen");
        Check(f.fixture.file->Current() && !f.fixture.file->escaped,"unrelated neighbor bytes unchanged and no write escaped grant");
    }Pass("physical grow/shrink exact GPT and canonical native write history");
}
void GeometryCuts(){
    const std::vector<std::string> stages={"after-image-accept","after-image-anchor","after-gpt-backup-array","after-gpt-backup-header","after-gpt-primary-array","after-gpt-primary-header"};
    for(std::size_t i=0;i<stages.size();++i){GeometryFixture f("cut-"+std::to_string(i),i%2==0);const auto p=PrepareVolumePhysicalResize(f.source,f.request);
        Check(p.outcome==VolumeImageOutcome::Prepared,p.error);bool hit=false;
        const auto cut=ApplyVolumePhysicalResize(f.source,f.request,p.token,[&](auto stage){if(stage==stages[i]){hit=true;return false;}return true;});
        Check(hit && cut.outcome==VolumeImageOutcome::RecoveryRequired,"accepted cut: "+cut.error);
        if(i==2){const auto plan=DecodeVolumeKeeperGeometryPlan(Read(p.journal));auto bytes=plan.writes.front().after;std::fill(bytes.begin()+311,bytes.end(),std::byte{0xa7});RawWrite(f.fixture.file,plan.writes.front().offset,bytes);}
        f.Fresh();std::shared_ptr<VolumePhysicalSource> fixed;const auto recovered=RecoverVolumePhysicalResize(f.source,f.request,{},&fixed);
        Check(recovered.outcome==VolumeImageOutcome::Committed && fixed,"fresh held-source forward recovery: "+recovered.error);
        mc::Verify(*fixed,mc::Load(*fixed));Check(f.fixture.file->Current() && !f.fixture.file->escaped,"cut recovery preserves neighbors");
    }Pass("fresh capability replay across APFS/GPT cuts and torn planned GPT sector");
}
void GeometryControls(){
    for(unsigned i=0;i<6;++i){GeometryFixture f("control-"+std::to_string(i),true);const auto p=PrepareVolumePhysicalResize(f.source,f.request);Check(p.outcome==VolumeImageOutcome::Prepared,p.error);
        if(i==0){const auto before=fe::Scan(*f.fixture.source).digests;Check(CancelVolumePhysicalResize(f.source,f.request,p.token).outcome==VolumeImageOutcome::Cancelled &&
            fe::Scan(*f.fixture.source).digests==before && !f.fixture.file->writes,"cancel preserves source and GPT");continue;}
        if(i==1){auto bytes=Bytes(4096,std::byte{0x13});RawWrite(f.fixture.file,SimulatedBase+40000*4096ull,bytes);}
        if(i==2)Save(f.request.sibling_wals.at(f.request.volume_oid),{std::byte{1}});
        if(i==3)RawWrite(f.fixture.file,SimulatedBase+f.request.expected_bytes,Bytes(4096,std::byte{0x15}));
        if(i==4){auto bytes=Read(p.journal);bytes.resize(bytes.size()-1);Save(p.journal,bytes);}
        if(i==5){Bytes header;Check(f.source->Read(4096,4096,header),"read original GPT");header[100]^=std::byte{1};RawWrite(f.fixture.file,4096,header);}
        const auto before=f.fixture.file->writes;const auto denied=ApplyVolumePhysicalResize(f.source,f.request,p.token);
        Check(denied.outcome==VolumeImageOutcome::Refused && f.fixture.file->writes==before,"stale source/WAL/nonzero growth/partial frame/GPT refuses before target writes: "+denied.error);
    }Pass("cancel and exact original authority refusal controls");
}
void GeometryDispatch(bool window=false){
    GeometryFixture f("dispatch",true,4096,false,window?6*mc::ChunkBlocks*4096:0);auto& r=f.request;
    r.history_context={r.journal_directory/"spool",r.journal_directory/"recovery"};
    std::filesystem::create_directories(r.history_context.spool_root);std::filesystem::create_directories(r.history_context.recovery_root);
    const auto cp=mc::Load(*f.fixture.source);r.sibling_wals.clear();
    for(const auto& volume:cp.volumes){const auto id=DeriveVolumePhysicalRecoveryIdentity(f.original,r.container_uuid,volume.superblock.object_id);
        const auto path=r.history_context.spool_root/("apfs_recovery_v1_"+id.substr(17))/"write-ahead.wal";
        std::filesystem::create_directories(path.parent_path());r.sibling_wals.emplace(volume.superblock.object_id,path);}
    std::string hex;constexpr char digits[]="0123456789abcdef";
    for(const auto byte:volume_physical::Encode(f.original,SimulatedInstance)){const auto n=std::to_integer<unsigned>(byte);hex+=digits[n>>4];hex+=digits[n&15];}
    const auto wide=[](const std::string& s){return std::wstring(s.begin(),s.end());};
    std::string token;unsigned factories=0;
    const auto command=[&](const std::wstring& mode,const std::string& label,bool cut=false){
        std::vector<std::wstring> args={L"private-geometry-surrogate",L"--operation",L"grow",L"--mode",mode,L"--source-kind",L"physical",L"--physical-binding-hex",wide(hex),
            L"--image",std::wstring(SimulatedInstance),L"--journal-directory",r.journal_directory.wstring(),L"--container",wide(r.container_uuid),L"--volume",wide(r.volume_uuid),
            L"--oid",std::to_wstring(r.volume_oid),L"--xid",std::to_wstring(r.checkpoint_xid),L"--expected-bytes",std::to_wstring(r.expected_bytes),L"--target-bytes",std::to_wstring(r.target_bytes),
            L"--history-spool-root",r.history_context.spool_root.wstring(),L"--history-recovery-root",r.history_context.recovery_root.wstring()};
        for(const auto& [oid,path]:r.sibling_wals)args.insert(args.end(),{L"--wal",std::to_wstring(oid)+L"="+path.wstring()});
        if(mode==L"dry-run" || mode==L"apply")args.insert(args.end(),{L"--physical-device",L"\\\\.\\PhysicalDrive42"});
        if(mode==L"apply")args.insert(args.end(),{L"--confirm",wide(token)});
        if(cut)args.insert(args.end(),{L"--interrupt-at",window?L"after-image-anchor":L"after-gpt-backup-header"});
        std::vector<wchar_t*> argv;for(auto& arg:args)argv.push_back(arg.data());std::ostringstream output;const auto previous=std::cout.rdbuf(output.rdbuf());
        const auto exit=volume_image_cli::Run(static_cast<int>(argv.size()),argv.data(),false,{},[&](const auto& binding,auto instance,auto selected,std::string& error){
            ++factories;if(binding!=f.original || instance!=SimulatedInstance || (mode==L"dry-run" || mode==L"apply"?selected!=L"\\\\.\\PhysicalDrive42":!selected.empty())){
                error="PrivateFixtureSelectedAuthorityMismatch";return std::shared_ptr<VolumePhysicalGeometrySource>{};}return f.source;});
        std::cout.rdbuf(previous);std::ofstream json(r.journal_directory/(label+".json"),std::ios::binary);json<<output.str();json.close();
        Check(exit==(cut?3:0),"actual production physical resize CLI "+label+": "+output.str());
    };
    // The prepared token is read from the authenticated native frame below.
    command(L"dry-run","prepare");
    std::filesystem::path journal;for(const auto& entry:std::filesystem::directory_iterator(r.journal_directory))if(entry.path().extension()==L".vif1")journal=entry.path();
    token=DecodeVolumeKeeperHistoryBinding(Read(journal),journal,r.journal_directory,VolumePhysicalIdentity(f.original,SimulatedInstance)).token;
    command(L"apply","accepted-cut",true);f.Fresh();command(L"recover","recovered");
    std::shared_ptr<VolumePhysicalSource> fixed;Check(RecoverVolumePhysicalResize(f.source,r,{},&fixed).outcome==VolumeImageOutcome::Committed && fixed,"dispatch rebind");
    {auto history=AcquireVolumeKeeperPhysicalHistory(fixed,*fixed,r.journal_directory,{});mc::NativeWrite(*fixed);}
    f.Fresh();command(L"recover","later-reopen");Check(factories==4 && !f.fixture.file->escaped,"explicit factory used with exact selected source");
    std::ofstream oracle(r.journal_directory/"binding-hex.txt",std::ios::binary);oracle<<hex;
    Pass("production physical resize CLI with original WAL/spool namespaces and forward recovery");
}
void GeometryBoundaryControls(bool window=false){
    const auto partition=window?6*mc::ChunkBlocks*4096:0;
    {GeometryFixture f("sector512",true,512,window,partition);const auto p=PrepareVolumePhysicalResize(f.source,f.request);
        Check(p.outcome==VolumeImageOutcome::Prepared,"512-byte logical GPT prepare: "+p.error);
        const auto cut=ApplyVolumePhysicalResize(f.source,f.request,p.token,[&](auto stage){return stage!=(window?"after-image-anchor":"after-gpt-backup-header");});
        Check(cut.outcome==VolumeImageOutcome::RecoveryRequired,"512-byte logical accepted cut");f.Fresh();std::shared_ptr<VolumePhysicalSource> fixed;
        const auto done=RecoverVolumePhysicalResize(f.source,f.request,{},&fixed);Check(done.outcome==VolumeImageOutcome::Committed && fixed,"512-byte logical replay: "+done.error);
        const auto plan=DecodeVolumeKeeperGeometryPlan(Read(p.journal));std::string error;
        Check(fixed->VerifyCompletedGeometry(vg::Encode(plan),error),"512-byte GPT full copies and unaffected census: "+error);
        auto history=AcquireVolumeKeeperPhysicalHistory(fixed,*fixed,f.request.journal_directory,{});mc::NativeWrite(*fixed);
        Check(f.fixture.file->Current() && !f.fixture.file->escaped,"512-byte logical sector preserves unrelated neighbors");}
    {GeometryFixture f("foreign-gpt",false,4096,window,partition);const auto p=PrepareVolumePhysicalResize(f.source,f.request);Check(p.outcome==VolumeImageOutcome::Prepared,p.error);
        Check(ApplyVolumePhysicalResize(f.source,f.request,p.token,[](auto stage){return stage!="after-image-anchor";}).outcome==VolumeImageOutcome::RecoveryRequired,"accepted GPT foreign-header control");
        Bytes header;Check(f.source->Read(4096,4096,header),"read primary header before foreign mutation");
        vi::Put(header,48,ReadU64LE(header,48).value()-1);vi::Put(header,16,0,4);vi::Put(header,16,vg::Crc32(std::span(header).first(92)),4);RawWrite(f.fixture.file,4096,header);
        const auto writes=f.fixture.file->writes;f.Fresh();const auto denied=RecoverVolumePhysicalResize(f.source,f.request);
        Check(denied.outcome==VolumeImageOutcome::RecoveryRequired && denied.error==(window?"VolumeGptOriginalOrNeighborChanged":"VolumeGptForeignValidHeader") && f.fixture.file->writes==writes,"foreign valid GPT refuses without replay writes: "+denied.error);}
    {GeometryFixture f("foreign-nx",true,4096,window,partition);const auto p=PrepareVolumePhysicalResize(f.source,f.request);Check(p.outcome==VolumeImageOutcome::Prepared,p.error);
        const auto cp=mc::Load(*f.fixture.source);const auto plan=vi::BuildResizePublication(*f.fixture.source,f.request,cp);
        Check(ApplyVolumePhysicalResize(f.source,f.request,p.token,[](auto stage){return stage!="after-image-accept";}).outcome==VolumeImageOutcome::RecoveryRequired,"accepted NX foreign-checkpoint control");
        auto bytes=cp.container.superblock_bytes;vi::Put(bytes,16,cp.container.superblock.xid+100);vi::Put(bytes,0x60,cp.container.superblock.xid+101);vi::Checksum(bytes);
        Check(ParseNxSuperblock(bytes).has_value(),"checksum-valid foreign NX checkpoint");RawWrite(f.fixture.file,SimulatedBase+plan.publication.before_superblock_writes.front().physical_block*4096,bytes);
        const auto writes=f.fixture.file->writes;f.Fresh();const auto denied=RecoverVolumePhysicalResize(f.source,f.request);
        Check(denied.outcome==VolumeImageOutcome::RecoveryRequired && denied.error=="VolumeImageRecoveryForeignCheckpoint" && f.fixture.file->writes==writes,"foreign valid NX refuses without replay writes: "+denied.error);}
    Pass("512-byte GPT replay and authenticated foreign GPT/NX refusal boundaries");
}
void GeometryLibraryProfile(){
    GeometryFixture f("ephemeral-nx",true,4096,true);const auto p=PrepareVolumePhysicalResize(f.source,f.request);
    Check(p.outcome==VolumeImageOutcome::Prepared,"ephemeral NX source resize preparation: "+p.error);std::shared_ptr<VolumePhysicalSource> fixed;
    const auto result=ApplyVolumePhysicalResize(f.source,f.request,p.token,{},&fixed);
    Check(result.outcome==VolumeImageOutcome::Committed && fixed,"ephemeral NX source actual resize: "+result.error);
    {auto history=AcquireVolumeKeeperPhysicalHistory(fixed,*fixed,f.request.journal_directory,{});mc::NativeWrite(*fixed);}
    f.Fresh();Check(RecoverVolumePhysicalResize(f.source,f.request).outcome==VolumeImageOutcome::Committed,"ephemeral NX source ordinary mutation and history reopen");
    Check(f.fixture.file->Current() && !f.fixture.file->escaped,"ephemeral NX source preserves neighbors");
    Pass("authored ephemeral NX profile actual resize and ordinary payload publication");
}
void GeometrySequential(bool window=false){
    GeometryFixture f("sequential",true,4096,true,window?6*mc::ChunkBlocks*4096:0);const auto original_size=f.request.expected_bytes;
    const auto first=PrepareVolumePhysicalResize(f.source,f.request);Check(first.outcome==VolumeImageOutcome::Prepared,first.error);
    std::shared_ptr<VolumePhysicalSource> fixed;
    const auto grown=ApplyVolumePhysicalResize(f.source,f.request,first.token,{},&fixed);
    Check(grown.outcome==VolumeImageOutcome::Committed && fixed,"first sequential grow: "+grown.error);
    const auto first_plan=DecodeVolumeKeeperGeometryPlan(Read(first.journal));
    {auto history=AcquireVolumeKeeperPhysicalHistory(fixed,*fixed,f.request.journal_directory,{});mc::NativeWrite(*fixed);}
    const auto current=mc::Load(*fixed);
    Check(current.container.superblock.xid>f.request.checkpoint_xid+1,"later canonical generation selected");
    // Free space has no zero-content contract after completion. The next
    // shrink must preserve these out-of-window bytes as its original evidence.
    const auto tail_block=original_size/4096+1;
    const auto chunk=std::find_if(current.spaceman.chunks.begin(),current.spaceman.chunks.end(),[&](const auto& c){
        return c.device_index==0 && tail_block>=c.start_block && tail_block-c.start_block<c.block_count;});
    Check(chunk!=current.spaceman.chunks.end() && (!chunk->bitmap_block ||
        !(std::to_integer<unsigned>(chunk->allocation_bitmap.at((tail_block-chunk->start_block)/8))&(1u<<((tail_block-chunk->start_block)%8)))),"observed unallocated tail block");
    RawWrite(f.fixture.file,SimulatedBase+original_size+4096,Bytes(4096,std::byte{0x56}));
    f.Fresh();const auto reopened=RecoverVolumePhysicalResize(f.source,f.request);
    Check(reopened.outcome==VolumeImageOutcome::Committed,"first completed generation after ordinary mutation: "+reopened.error);
    f.original=fixed->Binding();f.request.operation=VolumeImageOperation::Shrink;
    f.request.expected_bytes=f.request.target_bytes;f.request.target_bytes=original_size;
    f.request.checkpoint_xid=mc::Load(*fixed).container.superblock.xid;
    fixed.reset();f.Fresh();
    const auto second=PrepareVolumePhysicalResize(f.source,f.request);
    Check(second.outcome==VolumeImageOutcome::Prepared,"second sequential shrink: "+second.error);
    const auto second_plan=DecodeVolumeKeeperGeometryPlan(Read(second.journal));
    Check(vg::Follows(first_plan,second_plan),"second original contains exact first GPT postimage");
    const auto interrupted=ApplyVolumePhysicalResize(f.source,f.request,second.token,[&](auto stage){return stage!=(window?"after-image-anchor":"after-gpt-primary-array");});
    Check(interrupted.outcome==VolumeImageOutcome::RecoveryRequired,"second generation accepted GPT cut: "+interrupted.error);
    f.Fresh();const auto done=RecoverVolumePhysicalResize(f.source,f.request,{},&fixed);
    Check(done.outcome==VolumeImageOutcome::Committed && fixed && fixed->SizeBytes()==original_size,"second generation forward replay: "+done.error);
    {auto history=AcquireVolumeKeeperPhysicalHistory(fixed,*fixed,f.request.journal_directory,{});mc::Verify(*fixed,mc::Load(*fixed));}
    f.Fresh();Check(RecoverVolumePhysicalResize(f.source,f.request).outcome==VolumeImageOutcome::Committed,"two completed generations reopen after ordinary mutation");
    Check(f.fixture.file->Current() && !f.fixture.file->escaped,"sequential geometry preserves all neighbors");
    Pass("sequential grow, ordinary write, accepted shrink cut and complete-history reopen");
}
void GeometryRebindControl(){
    GeometryFixture f("rebind-control",true);const auto p=PrepareVolumePhysicalResize(f.source,f.request);
    Check(p.outcome==VolumeImageOutcome::Prepared,p.error);
    VolumePhysicalGeometryTestPeer::CorruptRebind(f.source,f.fixture.file);
    std::shared_ptr<VolumePhysicalSource> fixed;const auto result=ApplyVolumePhysicalResize(f.source,f.request,p.token,{},&fixed);
    Check(result.outcome==VolumeImageOutcome::RecoveryRequired && !fixed && !f.source->Revalidate(),
        "rebind corruption must withhold replacement authority and report recovery-required: "+result.error);
    const auto frame=DecodeVolumeKeeperHistoryBinding(Read(p.journal),p.journal,f.request.journal_directory,VolumePhysicalIdentity(f.original,SimulatedInstance));
    Check(frame.state==VolumeKeeperJournalState::Completed && f.fixture.file->Current() && !f.fixture.file->escaped,
        "completed original receipt and unrelated ranges survive failed rebind admission");
    Pass("new held source revalidates completed canonical history before replacement capability exposure");
}
}
#ifndef APFS_PHYSICAL_RESIZE_FIXTURE_ONLY
int wmain(int argc,wchar_t** argv){try{Check(argc==2 || argc==3,"private sparse fixture root required");root=argv[1];std::filesystem::create_directories(root);
    if(argc==3){const auto mode=std::wstring_view(argv[2]);Check(mode==L"--dispatch-only" || mode==L"--boundary-controls" || mode==L"--library-profile" || mode==L"--history-profile" || mode==L"--rebind-control","focused mode");
        if(mode==L"--dispatch-only")GeometryDispatch();else if(mode==L"--boundary-controls")GeometryBoundaryControls();else if(mode==L"--library-profile")GeometryLibraryProfile();else if(mode==L"--history-profile")GeometrySequential();else GeometryRebindControl();}
    else{GeometryPositive();GeometryCuts();GeometryControls();}
    std::cout<<"PASS groups="<<groups<<" checks="<<checks<<" hardware=0\n";return 0;
}catch(const std::exception& e){std::cerr<<"FAIL checks="<<checks<<" "<<e.what()<<'\n';return 1;}}
#endif
