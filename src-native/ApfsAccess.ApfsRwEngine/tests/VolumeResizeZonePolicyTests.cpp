#define APFS_RELOCATION_KEEPER_FIXTURE_ONLY
#include "VolumeResizeRelocationKeeperTests.cpp"

namespace {
Bytes ZonePolicy() {
    Bytes bytes(0x880);
    vi::Put(bytes,0,0x4000);vi::Put(bytes,8,0x8000);vi::Put(bytes,128,1,2);vi::Put(bytes,130,2,2);
    vi::Put(bytes,16,0x1000);vi::Put(bytes,24,0x2000);vi::Put(bytes,32,0x2000);vi::Put(bytes,40,0x3000);
    vi::Put(bytes,136,0x9000);vi::Put(bytes,144,0xc000);vi::Put(bytes,264,2,2);
    return bytes;
}
VolumeImageRequest ZonedImage(const std::string& name,VolumeImageOperation operation,const Bytes& policy) {
    auto source=Source();const auto cp=mc::Load(source);auto sm=cp.spaceman.bytes;
    Check(policy.size()==0x880,"exact version-one policy array");
    std::copy(policy.begin(),policy.end(),sm.begin()+0x158);vi::Checksum(sm);
    source.blocks[cp.spaceman.object.physical_block]=std::move(sm);
    const auto dir=root/name;std::filesystem::create_directories(dir);
    auto request=Request(dir,operation,Fixture());request.expected_bytes=source.SizeBytes();
    request.target_bytes=(operation==VolumeImageOperation::Grow?5*mc::ChunkBlocks-13:3*mc::ChunkBlocks-25)*4096;
    mc::SparseFile(request.image,source);return request;
}
void ExactPolicy(Target& target,const Bytes& policy) {
    const auto cp=mc::Load(target);mc::Verify(target,cp);
    Check(std::equal(policy.begin(),policy.end(),cp.spaceman.bytes.begin()+0x158),"all current and previous zone bytes remain exact");
}
void PositiveZones() {
    const auto policy=ZonePolicy();
    for(const auto operation:{VolumeImageOperation::Grow,VolumeImageOperation::Shrink}) {
        auto request=ZonedImage(operation==VolumeImageOperation::Grow?"grow":"shrink",operation,policy);
        const auto before=Digests(request.image);const auto prepared=PrepareVolumeResize(request);
        if(operation==VolumeImageOperation::Shrink){
            Check(prepared.outcome==VolumeImageOutcome::Refused && prepared.token.empty() &&
                prepared.error=="VolumeResizeAllocationZoneShrinkUnitsUnproven" && Digests(request.image)==before,
                "populated-zone shrink requires proved address units");continue;
        }
        Check(prepared.outcome==VolumeImageOutcome::Prepared,"nonempty policy keeper prepare: "+prepared.error);
        Check(Digests(request.image)==before,"nonempty policy prepare preserves the entire original");
        Check(ApplyVolumeResize(request,prepared.token).outcome==VolumeImageOutcome::Committed,"actual nonempty policy resize");
        {Target target(request.image);ExactPolicy(target,policy);
            auto history=AcquireVolumeKeeperHistory(prepared.source_identity,target,request.journal_directory,{});
            mc::NativeWrite(target);ExactPolicy(target,policy);}
        Check(RecoverVolumeResize(request).outcome==VolumeImageOutcome::Committed,"nonempty policy history after ordinary write");
    }
    Pass("restricted nonempty policy grow preserves bytes and history; shrink refuses unproved units");
}
void ZoneControls() {
    for(unsigned variant=0;variant<8;++variant){
        auto policy=ZonePolicy();
        if(variant==0)vi::Put(policy,132,1,4);
        if(variant==1)vi::Put(policy,130,8,2);
        if(variant==2)vi::Put(policy,130,3,2);
        if(variant==3)vi::Put(policy,264,1,2);
        if(variant==4){vi::Put(policy,136,0x6000);vi::Put(policy,144,0xa000);}
        if(variant==5)policy[8*136]=std::byte{1};
        if(variant==6)vi::Put(policy,128,0,2);
        if(variant==7){vi::Put(policy,136,0x10000);vi::Put(policy,144,0x18000);}
        auto request=ZonedImage("bad-"+std::to_string(variant),VolumeImageOperation::Shrink,policy);
        const auto before=Digests(request.image);const auto denied=PrepareVolumeResize(request);
        Check(denied.outcome==VolumeImageOutcome::Refused && denied.token.empty() && Digests(request.image)==before,
            "reserved/index/history/ID/overlap/tier2/orphan/tail policy refuses without source mutation: "+denied.error);
    }
    Pass("malformed or truncated nonempty zone policies refuse before acceptance");
}
void RelocatedZones() {
    const auto policy=ZonePolicy();auto request=RelocationImage("relocated-zones",true);
    {Target target(request.image);const auto cp=mc::Load(target);auto sm=cp.spaceman.bytes;
        std::copy(policy.begin(),policy.end(),sm.begin()+0x158);vi::Checksum(sm);
        Check(target.WriteBlock(cp.spaceman.object.physical_block,sm) && target.Flush(),"seed authored nonempty policy before keeper admission");}
    const auto before=Digests(request.image);const auto prepared=PrepareVolumeResize(request);
    Check(prepared.outcome==VolumeImageOutcome::Refused && prepared.token.empty() &&
        prepared.error=="VolumeResizeAllocationZoneShrinkUnitsUnproven" && Digests(request.image)==before,
        "bootstrap relocation also refuses populated zones before acceptance: "+prepared.error);
    Pass("populated-zone relocation shrink refuses before acceptance without source change");
}
void ZoneBoundaries() {
    auto source=Source();const auto original=mc::Load(source).spaceman;
    const auto make=[&](const Bytes& policy){auto sm=original;std::copy(policy.begin(),policy.end(),sm.bytes.begin()+0x158);return sm;};
    const auto accepts=[&](const AppleSpacemanView& sm,std::uint64_t target,const std::string& label){
        const auto before=sm.bytes;vi::ValidateResizeAllocationZones(sm,target);Check(sm.bytes==before,label);};
    const auto refuses=[&](const AppleSpacemanView& sm,std::uint64_t target,const std::string& expected,const std::string& label){
        const auto before=sm.bytes;std::string error;try{vi::ValidateResizeAllocationZones(sm,target);}catch(const std::exception& e){error=e.what();}
        Check(error==expected && sm.bytes==before,label+": "+error);};
    constexpr std::uint64_t Old=0x20000, Grow=0x28000, Shrink=0x18000;
    auto sm=make(ZonePolicy());sm.devices[0].block_count=Old;
    accepts(sm,Grow,"restricted separated current/history profile grows without interpreting units");
    accepts(sm,Old,"same geometry preserves populated policy");
    refuses(sm,Shrink,"VolumeResizeAllocationZoneShrinkUnitsUnproven","nonempty shrink refuses even when numeric bounds fit");
    auto changed=sm;vi::Put(changed.bytes,0x158+144,Old);
    refuses(changed,Grow,"VolumeResizeAllocationZoneBoundsUnproven","end equal original block count refuses under inclusive interpretation");
    changed=sm;changed.devices[0].block_count=Grow;vi::Put(changed.bytes,0x158+144,Shrink);
    refuses(changed,Shrink,"VolumeResizeAllocationZoneBoundsUnproven","end equal target block count refuses");
    vi::Put(changed.bytes,0x158+144,Shrink+4096);
    refuses(changed,Shrink,"VolumeResizeAllocationZoneBoundsUnproven","end beyond target refuses");
    changed=sm;vi::Put(changed.bytes,0x158+136,0x8000);
    refuses(changed,Grow,"VolumeResizeAllocationZoneOverlap","touching current boundaries refuse under inclusive interpretation");
    changed=sm;vi::Put(changed.bytes,0x158+136,0x7000);
    refuses(changed,Grow,"VolumeResizeAllocationZoneOverlap","interior current overlap refuses");
    changed=sm;vi::Put(changed.bytes,0x158+144,0);
    refuses(changed,Grow,"VolumeResizeAllocationZoneBoundsUnproven","nonempty start with invalid zero end refuses");
    changed=sm;vi::Put(changed.bytes,0x158+264,0,2);
    refuses(changed,Grow,"VolumeResizeAllocationZoneIdentityProfileUnsupported","nonempty zero ID is outside this profile, not declared universally invalid");
    changed=sm;std::fill(changed.bytes.begin()+0x158+32,changed.bytes.begin()+0x158+128,std::byte{});
    vi::Put(changed.bytes,0x158+130,1,2);
    accepts(changed,Grow,"one history with empty next-write slot one is admitted");
    accepts(sm,Grow,"two histories with empty next-write slot two remain admitted");
    changed=sm;vi::Put(changed.bytes,0x158+130,0,2);
    accepts(changed,Grow,"zero-based history position zero with populated history is admitted");
    auto policy=ZonePolicy();std::fill(policy.begin()+16,policy.begin()+128,std::byte{});vi::Put(policy,130,0,2);
    changed=make(policy);changed.devices[0].block_count=Old;
    accepts(changed,Grow,"zero previous index with empty history is admitted");
    vi::Put(changed.bytes,0x158+130,6,2);vi::Put(changed.bytes,0x158+112,0x1000);vi::Put(changed.bytes,0x158+120,0x2000);
    accepts(changed,Grow,"zero-based sixth index selects the seventh history pair");
    vi::Put(changed.bytes,0x158+130,7,2);
    refuses(changed,Grow,"VolumeResizeAllocationZoneHeaderProfileUnsupported","index seven is outside the native v1 ring");
    vi::Put(changed.bytes,0x158+130,8,2);
    refuses(changed,Grow,"VolumeResizeAllocationZoneHeaderProfileUnsupported","out-of-profile previous index refuses");
    changed=make(Bytes(0x880));changed.devices[0].block_count=Old;
    accepts(changed,Shrink,"all-zero zones with zero IDs and indices remain valid for shrink");
    vi::Put(changed.bytes,0x158+16,0x1000);vi::Put(changed.bytes,0x158+24,0x2000);vi::Put(changed.bytes,0x158+130,0,2);
    refuses(changed,Shrink,"VolumeResizeAllocationZoneShrinkUnitsUnproven","history-only populated policy also vetoes shrink");
    Pass("focused preserved-policy endpoint overlap zero-ID/index and unproved-unit boundaries");
}
}
#ifndef APFS_ZONE_POLICY_FIXTURE_ONLY
int wmain(int argc,wchar_t** argv) {
    try {Check(argc==2,"private D root or --boundaries-only required");
        if(std::wstring_view(argv[1])==L"--boundaries-only"){ZoneBoundaries();std::cout<<"PASS groups="<<groups<<" checks="<<checks<<'\n';return 0;}
        root=argv[1];std::filesystem::create_directories(root);
        PositiveZones();ZoneControls();RelocatedZones();std::cout<<"PASS groups="<<groups<<" checks="<<checks<<'\n';return 0;
    }catch(const std::exception& e){std::cerr<<"FAIL checks="<<checks<<" "<<e.what()<<'\n';return 1;}
}
#endif
