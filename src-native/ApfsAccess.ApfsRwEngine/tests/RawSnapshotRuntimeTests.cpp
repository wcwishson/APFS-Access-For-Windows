#define SNAPSHOT_RUNTIME_TEST_HELPERS_ONLY
#include "SnapshotRuntimeTests.cpp"
#include <type_traits>

namespace apfsaccess::rw {
struct BlockDeviceRawSnapshotTestPeer {
    static void Seed(BlockDevice& d,const RawSnapshotDescriptors& descriptors){
        std::lock_guard<std::mutex> handle(d.handle_mutex_);
        std::lock_guard<std::mutex> source(d.write_source_mutex_);
        DWORD flags=0;
        if(!GetHandleInformation(d.read_handle_.load(),&flags)||!GetHandleInformation(d.write_handle_.load(),&flags))
            throw std::runtime_error("Raw runtime fixture requires real held handles");
        d.regular_file_.store(false);d.raw_writer_accepted_.store(true);d.writable_.store(true);
        d.raw_write_limit_bytes_.store(descriptors.media.limit_bytes);
        d.raw_write_source_size_bytes_=descriptors.media.disk_size_bytes-d.BaseOffsetBytes();
        d.raw_writer_identity_="gpt:loopback|base:"+std::to_string(d.BaseOffsetBytes())+"|limit:"+std::to_string(descriptors.media.limit_bytes);
        d.raw_presence_probe_result_.store(true);d.raw_snapshot_lease_retired_=false;d.write_source_handles_retired_=false;
        d.raw_snapshot_descriptors_attempted_=true;d.raw_snapshot_descriptors_complete_=true;
        d.raw_snapshot_descriptors_=descriptors;d.raw_snapshot_descriptors_error_.clear();
        FILE_ID_INFO identity{};
        if(!GetFileInformationByHandleEx(d.read_handle_.load(),FileIdInfo,&identity,sizeof(identity)))
            throw std::runtime_error("Raw runtime fixture requires a held file identity");
        // File-backed transport evidence replaces PnP enumeration only in this fixture.
        d.raw_presence_probe_hook_for_tests_=[&d,identity,size=descriptors.media.disk_size_bytes](DWORD& error){
            std::lock_guard<std::mutex> handle(d.handle_mutex_);
            std::lock_guard<std::mutex> source(d.write_source_mutex_);
            error=ERROR_DEVICE_NOT_CONNECTED;
            if(d.write_source_handles_retired_||d.raw_snapshot_lease_retired_)return false;
            for(const auto held:{d.read_handle_.load(),d.write_handle_.load()}){
                FILE_STANDARD_INFO info{};FILE_ID_INFO current{};
                if(GetFileType(held)!=FILE_TYPE_DISK||
                    !GetFileInformationByHandleEx(held,FileStandardInfo,&info,sizeof(info))||
                    !GetFileInformationByHandleEx(held,FileIdInfo,&current,sizeof(current))||
                    info.Directory||info.DeletePending||info.EndOfFile.QuadPart!=size||
                    current.VolumeSerialNumber!=identity.VolumeSerialNumber||
                    std::memcmp(current.FileId.Identifier,identity.FileId.Identifier,sizeof(identity.FileId.Identifier)))return false;
            }
            error=ERROR_SUCCESS;return true;
        };
        d.raw_presence_probe_error_.store(ERROR_SUCCESS);d.raw_presence_probe_tick_ms_.store(0);
    }
    static void ChangeSerial(BlockDevice& d){std::lock_guard<std::mutex> lock(d.write_source_mutex_);d.raw_snapshot_descriptors_.device.serial="DIFFERENT00000490";}
    static void Retire(BlockDevice& d){std::lock_guard<std::mutex> lock(d.handle_mutex_);d.InvalidateWriteSourceHandlesLocked();}
};
}

namespace apfsaccess::catalog {
// Faults only the coordinator latch, never grants a source or WAL capability.
struct RawSnapshotRuntimeRecoveryTestPeer {
    static bool CompletionHeld(const ContainerMountCoordinator& owner,std::uint64_t oid,const std::vector<std::uint64_t>& expected){
        std::lock_guard<std::mutex> state(owner.mutex_);
        const auto* pins=owner.FindVolumeCheckpointPinsNoLock(oid);
        return owner.recovery_required_&&owner.recovery_volume_object_id_==oid&&owner.raw_snapshot_recovery_&&
            pins&&pins->unapplied_accepted_work&&pins->required_checkpoint_xids==expected;
    }
    static void UnrelatedLatch(ContainerMountCoordinator& owner,const std::string& reason,std::uint64_t oid){
        std::lock_guard<std::timed_mutex> serialized(owner.commit_mutex_);
        std::lock_guard<std::mutex> state(owner.mutex_);
        owner.recovery_required_=true;owner.recovery_volume_object_id_=oid;owner.recovery_reason_=reason;
    }
};
}

namespace {
using Authority=apfsaccess::rw::RawSnapshotRuntimeAuthority;
using Peer=apfsaccess::rw::RawSnapshotRuntimePeerOwner;
using DevicePeer=apfsaccess::rw::BlockDeviceRawSnapshotTestPeer;
constexpr std::uint64_t raw_base=4096;
constexpr std::uint64_t raw_tail=8192;
constexpr std::uint64_t raw_limit=2048ull*kBlockSize;

RawHardwareQualification Qualification(){
    RawHardwareQualification q;q.kind=RawHardwareIdentityKind::QualifiedSerialTuple;q.bus_type=BusTypeUsb;
    q.vendor="Samsung";q.product="Flash Drive FIT";q.qualified_serial="AA00000000000489";return q;
}
RawSnapshotDescriptors Descriptors(){
    RawSnapshotDescriptors d;d.device={BusTypeUsb,"Samsung","Flash Drive FIT","1100","AA00000000000489"};
    auto& m=d.media;m.disk_guid.fill(std::byte{0x0a});m.partition_guid.fill(std::byte{0x0b});
    m.base_offset_bytes=m.partition_offset_bytes=raw_base;m.partition_length_bytes=m.limit_bytes=raw_limit;
    m.disk_size_bytes=raw_base+raw_limit+raw_tail;m.logical_sector_bytes=512;m.physical_sector_bytes=4096;return d;
}
void FreshRaw(const std::filesystem::path& p){auto f=Fresh(p);std::vector<std::byte> b(raw_base,std::byte{0x5a});
    b.insert(b.end(),f.image.begin(),f.image.end());b.resize(b.size()+raw_tail,std::byte{0x6b});Save(p,b);}
void ConfigureRaw(Tx& j,const std::filesystem::path& p,std::uint64_t oid){
    const auto rid=L"raw-original-rid-"+std::to_wstring(oid);
    j.SetJournalPath(std::filesystem::absolute(p).wstring());j.SetVolumeIdentity(rid);
    Check(j.EnrollCanonicalJournalIdentity(L"apfs-vol:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:"+std::to_wstring(oid)),"raw canonical enrollment");
    if(j.ObservedJournalAppendLeaseGeneration()==0)Check(j.Begin()&&j.Abort(),"materialize original clean WAL lease");
}
std::unique_ptr<Owner> OpenRaw(const std::filesystem::path& p,Tx& selected,Tx& sibling,bool runtime=true){
    std::string e;auto owner=Owner::Open(std::filesystem::absolute(p).string(),raw_base,e,CatalogLoadPolicy::StrictApple,true,true);
    Check(!!owner,"loopback owner: "+e);std::vector<VolumeCheckpointPins> census;
    for(auto oid:{101ull,102ull}){ContainerVolumeSession s;s.volume_object_id=oid;s.container_uuid_hex=owner->ContainerUuidHex();
        s.requested_write=true;s.use_canonical_transaction=true;s.recovery_identity="raw-original-rid-"+std::to_string(oid);
        s.metadata_context.allow_legacy_scaffold_for_fixtures=false;
        s.metadata_context.allow_native_snapshot_runtime=runtime;s.metadata_context.allow_raw_device_canonical_commit=true;
        Check(owner->MountVolume(s,e),"raw session: "+e);VolumeCheckpointPins pins;pins.volume_object_id=oid;
        auto& j=oid==101?selected:sibling;Check(j.LoadRequiredCheckpointXidsSinceCleanup(pins.required_checkpoint_xids,&e),"original raw census: "+e);
        pins.unapplied_accepted_work=j.HasUnappliedAcceptedWork();census.push_back(std::move(pins));}
    Check(owner->InitializeRequiredCheckpointCensus(census,e),"raw complete census: "+e);
    DevicePeer::Seed(const_cast<BlockDevice&>(owner->Device()),Descriptors());return owner;
}
std::vector<Peer> Peers(Owner& o,Tx& selected,Tx& sibling,const std::string& stem){
    return {{101,o.FindSessionStore(101),&selected,std::filesystem::absolute(stem+"-101.wal").wstring()},
        {102,o.FindSessionStore(102),&sibling,std::filesystem::absolute(stem+"-102.wal").wstring()}};
}
std::shared_ptr<const Authority> Capture(Owner& o,const std::vector<Peer>& peers){
    std::shared_ptr<const Authority> a;std::string e;Check(CaptureRawSnapshotRuntimeAuthority(o,peers,Qualification(),a,e),"capture raw authority: "+e);return a;
}
NativeSnapshotIntent Decoded(const SnapshotRuntimePlan& p){NativeSnapshotIntent intent;
    Check(DecodeNativeSnapshotIntent(p.request.inline_payload,intent),"decode raw runtime plan");return intent;}
ContainerCommitResult ApplyFixture(Owner& owner,Tx& journal,SnapshotRuntimePlan& plan){
    return ApplySnapshot(owner,journal,plan,[](std::string&){return true;});
}
void PreserveEnvelope(const std::vector<std::byte>& before,const std::vector<std::byte>& after){
    Check(before.size()==after.size()&&std::equal(before.begin(),before.begin()+raw_base,after.begin())&&
        std::equal(before.end()-raw_tail,before.end(),after.end()-raw_tail),"raw publication preserves physical prefix and tail");
}
void SameCensus(const std::vector<VolumeCheckpointPins>& before,Owner& owner){
    const auto after=owner.CheckpointCensusSnapshot();Check(before.size()==after.size(),"unchanged census size");
    for(std::size_t i=0;i<before.size();++i)Check(before[i].volume_object_id==after[i].volume_object_id&&
        before[i].required_checkpoint_xids==after[i].required_checkpoint_xids&&
        before[i].unapplied_accepted_work==after[i].unapplied_accepted_work,"unchanged original peer pins/debt");
}
struct RawEvidence {
    std::string stem;
    std::vector<std::byte> image,selected_wal,sibling_wal;
    Tx::DurabilityWatermarks selected_marks,sibling_marks;
    std::vector<VolumeCheckpointPins> census;
    RawEvidence(const std::string& name,Owner& owner,Tx& selected,Tx& sibling):stem(name),
        image(Bytes(name+".apfs")),selected_wal(Bytes(name+"-101.wal")),sibling_wal(Bytes(name+"-102.wal")),
        selected_marks(selected.Watermarks()),sibling_marks(sibling.Watermarks()),census(owner.CheckpointCensusSnapshot()){}
    void Unchanged(Owner& owner,Tx& selected,Tx& sibling)const{
        Check(Bytes(stem+".apfs")==image&&Bytes(stem+"-101.wal")==selected_wal&&Bytes(stem+"-102.wal")==sibling_wal,
            "refusal preserves complete source and both original WAL files");
        SameWatermarks(selected_marks,selected);SameWatermarks(sibling_marks,sibling);SameCensus(census,owner);
    }
};
std::vector<std::byte> HostBytes(const std::string& value){
    std::vector<std::byte> bytes;for(const auto c:value)bytes.push_back(std::byte(static_cast<unsigned char>(c)));return bytes;
}
void DurableHostMarker(const std::string& path,const std::vector<std::byte>& bytes){
    HANDLE file=CreateFileW(std::filesystem::absolute(path).c_str(),GENERIC_WRITE,FILE_SHARE_READ,nullptr,
        CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);Check(file!=INVALID_HANDLE_VALUE,"real host marker writer handle");
    DWORD written=0;const bool wrote=WriteFile(file,bytes.data(),static_cast<DWORD>(bytes.size()),&written,nullptr)!=FALSE;
    const bool flushed=FlushFileBuffers(file)!=FALSE;const bool closed=CloseHandle(file)!=FALSE;
    Check(wrote&&written==bytes.size()&&flushed&&closed&&Bytes(path)==bytes,"actual flushed host marker bytes");
}
struct HostCompletionFiles {
    std::string marker,spool;std::uint64_t xid;std::vector<std::uint64_t> pins;std::vector<std::byte> dirty,clean;
    unsigned calls=0;
    HostCompletionFiles(const std::string& stem,const NativeSnapshotIntent& intent):marker(stem+".host-marker"),spool(stem+".host-spool"),
        xid(intent.scope.checkpoint_xid+1),pins(intent.pins),dirty(HostBytes("dirty:"+std::to_string(xid))){
        Save(spool,HostBytes("selected original host spool"));DurableHostMarker(marker,dirty);
    }
    void Before(const Owner& owner,const Store& store,const Tx& journal){
        ++calls;const auto marks=journal.Watermarks();
        Check(store.CheckpointXid()==xid&&marks.accepted_sequence&&marks.apfs_durable_sequence==marks.accepted_sequence&&
            marks.cleanup_sequence<marks.accepted_sequence,"host hook sees exact publication/durability before WAL cleanup");
        Check(apfsaccess::catalog::RawSnapshotRuntimeRecoveryTestPeer::CompletionHeld(owner,101,pins),
            "host hook observes exact typed selected latch and unreleased pins without coordinator reentry");
        Check(Bytes(marker)==dirty||(!clean.empty()&&Bytes(marker)==clean),"original host marker remains owned through retries");
    }
    bool Finish(const Owner& owner,const Store& store,const Tx& journal){
        Before(owner,store,journal);std::error_code error;std::filesystem::remove(spool,error);
        Check(!error&&!std::filesystem::exists(spool),"actual selected host spool completion is idempotent");
        clean=HostBytes("clean:"+std::to_string(xid)+":"+std::to_string(journal.Watermarks().accepted_sequence));
        DurableHostMarker(marker,clean);return true;
    }
};
void OrdinaryWritesRefused(const std::string& stem,Owner& owner,Tx& selected,Tx& sibling){
    const RawEvidence before(stem,owner,selected,sibling);Store::MutationRequest request;
    request.operation=Store::MutationOperation::Write;request.path=L"\\ordinary.bin";request.object_id=17;
    request.length=1;request.inline_payload={std::byte{0x42}};
    for(const auto oid:{101ull,102ull}){
        Check(!owner.Commit(oid,{request}).committed,"ordinary selected/sibling write remains latched");
        Check(!owner.Commit(oid,{request},{},{},{},true,owner.CheckpointXid()).committed,"ordinary replay flag cannot cross typed completion latch");
    }
    before.Unchanged(owner,selected,sibling);
}
void PureInspection(const std::string&,Owner&,Tx&,Tx&,const std::shared_ptr<const Authority>&);
void NormalCompletion(){
    for(const bool deletion:{false,true})for(const bool first_throw:{false,true}){
        const auto stem=std::string("raw-normal-completion-")+(deletion?"delete-":"create-")+(first_throw?"throw":"false");
        FreshRaw(stem+".apfs");Tx selected(L"Strict"),sibling(L"Strict");
        ConfigureRaw(selected,stem+"-101.wal",101);ConfigureRaw(sibling,stem+"-102.wal",102);
        auto owner=OpenRaw(stem+".apfs",selected,sibling);auto a=Capture(*owner,Peers(*owner,selected,sibling,stem));
        if(deletion){SnapshotRuntimePlan seed;std::string e;Check(PrepareSnapshotCreate(*owner,101,"normal-completion",1,0,a,seed,e),"normal deletion seed");Success(ApplyFixture(*owner,selected,seed));}
        SnapshotRuntimePlan plan;std::string e;
        Check(deletion?PrepareSnapshotDelete(*owner,List(*owner).at(0).identity,2,a,plan,e):
            PrepareSnapshotCreate(*owner,101,"normal-completion",1,0,a,plan,e),"normal completion plan");
        const auto intent=Decoded(plan);auto* store=owner->FindSessionStore(101);HostCompletionFiles host(stem,intent);
        const RawEvidence before(stem,*owner,selected,sibling);const auto epoch=store->StateEpoch();
        const auto missing=ApplySnapshot(*owner,selected,plan);
        Check(!missing.committed&&missing.error=="SnapshotRuntimeRawCompletionHookRequired"&&!plan.consumed,"raw no-hook Apply refuses before acceptance and leaves the plan reusable");
        Check(!ApplySnapshot(*owner,selected,plan,RawSnapshotRuntimeCompletionHook{}).committed&&!plan.consumed,"empty raw completion hook refuses before acceptance");
        before.Unchanged(*owner,selected,sibling);Check(store->StateEpoch()==epoch&&Bytes(host.marker)==host.dirty,"no-hook refusal does not prepare or change host marker");
        const auto result=ApplySnapshot(*owner,selected,plan,[&](std::string& error)->bool{
            host.Before(*owner,*store,selected);if(first_throw)throw std::runtime_error("normal host marker interrupted");
            error="normal host marker pending";return false;
        });
        Check(result.committed&&result.commit_recovery_required&&owner->IsRecoveryRequired()&&
            owner->RecoveryReason()=="RawSnapshotHostCompletionPending"&&host.calls==1,"normal verified publication remains typed debt after hook false/throw");
        Check(List(*owner).size()==(deletion?0u:1u)&&selected.Watermarks().cleanup_sequence==before.selected_marks.cleanup_sequence,
            "failed normal host completion publishes once and never releases WAL cleanup");
        const RawEvidence publication(stem,*owner,selected,sibling);const auto published_epoch=store->StateEpoch();
        const RawSnapshotRuntimeReplayParameters replay{a,selected.Watermarks().accepted_sequence};
        Check(AdmitRetainedRawSnapshotRecovery(*owner,selected,101,replay,e),"normal completion exposes pure retained admission: "+e);
        std::shared_ptr<const RawSnapshotRuntimeRecoveryToken> token,same;
        Check(RecoverRetainedRawSnapshot(*owner,selected,101,replay,token,e)&&token&&
            RecoverRetainedRawSnapshot(*owner,selected,101,replay,same,e)&&same==token,"normal retry obtains the original completion token");
        Check(store->StateEpoch()==published_epoch,"normal retained retry cannot reload or republish");publication.Unchanged(*owner,selected,sibling);
        OrdinaryWritesRefused(stem,*owner,selected,sibling);
        Check(!CompleteRetainedRawSnapshotRecovery(*owner,token,[&](std::string&)->bool{
            host.Before(*owner,*store,selected);Check(std::filesystem::remove(host.spool),"actual partial host spool completion");
            throw std::runtime_error("marker still dirty after spool completion");
        },e),"partial actual host completion stays retryable");
        publication.Unchanged(*owner,selected,sibling);Check(Bytes(host.marker)==host.dirty&&owner->IsRecoveryRequired(),"partial spool completion retains dirty marker and latch");
        OrdinaryWritesRefused(stem,*owner,selected,sibling);
        Check(CompleteRetainedRawSnapshotRecovery(*owner,token,[&](std::string&){return host.Finish(*owner,*store,selected);},e),"normal retry completes exact host files and engine proof: "+e);
        Check(!owner->IsRecoveryRequired()&&Bytes(host.marker)==host.clean&&Bytes(stem+".apfs")==publication.image,
            "host clean marker precedes final latch release without republishing");
        const auto marks=selected.Watermarks();Check(marks.accepted_sequence==marks.apfs_durable_sequence&&marks.accepted_sequence==marks.cleanup_sequence,"normal hook success closes exact selected sequence");
        Check(Bytes(stem+"-102.wal")==before.sibling_wal,"normal completion preserves original sibling WAL bytes");SameWatermarks(before.sibling_marks,sibling);
        PureInspection(stem,*owner,selected,sibling,a);
    }
}
void FaultEvidence(Owner& owner,const ContainerCommitResult& result,const NativeSnapshotIntent& intent,bool published){
    auto* store=owner.FindSessionStore(101);SnapshotRuntimeDeviceSource source(owner.Device(),store->AuthoritativeAppleCheckpointView()->container.superblock);
    std::string e;const auto disk=LoadAppleCheckpointView(source,0,source.SizeBytes(),e);Check(!!disk,"read actual fault checkpoint: "+e);
    const auto reason=store->RecoveryReason();
    std::cout<<"raw fault "<<(published?"after":"before")<<" publication: result.stage="<<result.commit_stage
        <<" result.status="<<result.commit_status_code
        <<" result.recovery="<<result.commit_recovery_required<<" owner.poison="<<owner.IsRecoveryRequired()
        <<" owner.reason="<<owner.RecoveryReason()<<" store.poison="<<store->IsRecoveryRequired()
        <<" store.reason="<<std::string(reason.begin(),reason.end())<<" store.pending="<<store->PendingMutationCount()
        <<" store.xid="<<store->CheckpointXid().value_or(0)<<" owner.xid="<<owner.CheckpointXid()
        <<" disk.xid="<<disk->container.superblock.xid<<"\n";
    Check(result.commit_recovery_required&&!result.committed,"fault result retains accepted snapshot debt");
    Check(owner.IsRecoveryRequired()&&store->IsRecoveryRequired()==published,"accepted fault retains owner debt and phase-specific store poison");
    Check(store->CheckpointXid()==intent.scope.checkpoint_xid&&owner.CheckpointXid()==intent.scope.checkpoint_xid&&
        disk->container.superblock.xid==intent.scope.checkpoint_xid+(published?1:0),"exact retained P and actual P/P+1 fault boundary");
    Check(store->PendingMutationCount()==1,"accepted fault retains exactly the selected snapshot request before and after publication");
    Check(!store->HasUncommittedAllocatorState()&&!store->PendingAllocationCount()&&!store->PendingDeallocationCount()&&
        !store->PendingObjectMapUpdateCount()&&!store->PendingBtreeRecordCount()&&!store->PendingPayloadByteEstimate(),
        "snapshot fault has no unrelated allocator/tree/payload working state");
    if(published)Check(owner.RecoveryVolumeObjectId()==101&&
        owner.RecoveryReason()=="SessionCommitRecoveryRequired: AppleCommitInterruptedAfterPublish"&&
        reason==L"AppleCommitInterruptedAfterPublish","exact selected after-publication latch provenance");
    else Check(owner.RecoveryVolumeObjectId()==101&&owner.RecoveryReason()=="AcceptedWorkPublicationFailed"&&
        reason.empty()&&store->LastCommitFailureReason()==L"AppleCommitInterruptedBeforePublish"&&
        result.commit_stage=="apple-publish-stage-blocked","accepted prepublication interruption retains exact original debt provenance");
}
void PureInspection(const std::string& stem,Owner& owner,Tx& selected,Tx& sibling,const std::shared_ptr<const Authority>& authority){
    const RawEvidence before(stem,owner,selected,sibling);
    const auto selected_epoch=owner.FindSessionStore(101)->StateEpoch(),sibling_epoch=owner.FindSessionStore(102)->StateEpoch();
    const auto expected=List(owner);ApfsSnapshotScope scope,scope_only;std::vector<ApfsSnapshotInfo> inventory;std::string e;
    Check(InspectRawSnapshotRuntimeAuthority(authority,owner,101,scope,&inventory,e),"pure clean raw inventory inspection: "+e);
    Check(scope.store_offset_bytes==0&&scope.store_size_bytes==raw_limit&&scope.volume_oid==101&&
        scope.checkpoint_xid==owner.CheckpointXid()&&inventory.size()==expected.size(),"inspection returns exact bounded selected scope/inventory");
    for(std::size_t i=0;i<inventory.size();++i)Check(inventory[i].identity==expected[i].identity,"inspection matches actual snapshot identity");
    Check(InspectRawSnapshotRuntimeAuthority(authority,owner,101,scope_only,nullptr,e)&&scope_only==scope,
        "pure scope-only inspection uses the same original authority proof");
    Check(!InspectRawSnapshotRuntimeAuthority(authority,owner,999,scope,&inventory,e)&&scope==ApfsSnapshotScope{}&&inventory.empty(),
        "unknown selected peer refuses with empty inspection outputs");
    DevicePeer::ChangeSerial(const_cast<BlockDevice&>(owner.Device()));
    Check(!InspectRawSnapshotRuntimeAuthority(authority,owner,101,scope,&inventory,e)&&scope==ApfsSnapshotScope{}&&inventory.empty(),
        "changed original hardware refuses pure inspection");
    DevicePeer::Seed(const_cast<BlockDevice&>(owner.Device()),Descriptors());
    Check(owner.FindSessionStore(101)->StateEpoch()==selected_epoch&&owner.FindSessionStore(102)->StateEpoch()==sibling_epoch,
        "pure inspection leaves both original store epochs unchanged");
    before.Unchanged(owner,selected,sibling);
}

void LifecycleParity(){
    FreshRaw("raw-parity.apfs");FreshRaw("image-parity.apfs");
    Tx selected(L"Strict"),sibling(L"Strict"),image_journal(L"Strict");
    ConfigureRaw(selected,"raw-parity-101.wal",101);ConfigureRaw(sibling,"raw-parity-102.wal",102);
    Configure(image_journal,"image-parity.wal");auto image_owner=Open("image-parity.apfs",image_journal,true,raw_base);
    auto owner=OpenRaw("raw-parity.apfs",selected,sibling);auto a=Capture(*owner,Peers(*owner,selected,sibling,"raw-parity"));
    auto lease=owner->Device().CaptureHeldRawSnapshotLease();Check(lease.has_value(),"original lease captured");
    PureInspection("raw-parity",*owner,selected,sibling,a);
    for(const bool deletion:{false,true}){
        SnapshotRuntimePlan raw,image;std::string e;
        const auto time=1700000000000000000ull+(deletion?1:0);
        Check(deletion?PrepareSnapshotDelete(*owner,List(*owner).at(0).identity,time,a,raw,e):
            PrepareSnapshotCreate(*owner,101,"same-inputs",time,0,a,raw,e),"raw prepare: "+e);
        Check(deletion?PrepareSnapshotDelete(*image_owner,List(*image_owner).at(0).identity,time,image,e):
            PrepareSnapshotCreate(*image_owner,101,"same-inputs",time,0,image,e),"image prepare: "+e);
        auto intent=Decoded(raw);
        Check(intent.raw_receipt&&intent.raw_receipt->peers.size()==2&&
            intent.raw_receipt->selected_journal_identity=="raw-original-rid-101","SNP2 includes original configured RIDs and complete peers");
        intent.raw_receipt.reset();Check(EncodeNativeSnapshotIntent(intent)==image.request.inline_payload,"SNP1 arguments and hashes byte-identical for same inputs");
        auto* store=owner->FindSessionStore(101);const auto& cp=*store->AuthoritativeAppleCheckpointView();
        SnapshotRuntimeDeviceSource caller_source(store->Device(),cp.container.superblock);AppleVolumeTransactionPlan publication;
        const auto raw_intent=Decoded(raw);
        Check(!PlanSnapshotRuntimeCheckpoint(caller_source,cp,raw_intent,raw_intent.pins,publication,e),"arbitrary caller source cannot grant SNP2 planning");
        Check(!PlanSnapshotRuntimeCheckpoint(*store,cp,raw_intent,raw_intent.pins,publication,e),"unarmed direct store planner refuses SNP2");
        const auto marks=selected.Watermarks();Check(store->StageMutation(raw.request)!=Store::MutationStatus::Applied,"unarmed directly staged SNP2 refuses");
        Check(!owner->Commit(101,{raw.request}).committed,"direct commit cannot grant raw payload by enrollment alone");
        SameWatermarks(marks,selected);const auto before=Bytes("raw-parity.apfs");
        Success(ApplyFixture(*owner,selected,raw));Success(ApplySnapshot(*image_owner,image_journal,image));
        Check(owner->Device().IsHeldRawSnapshotLeaseCurrent(*lease),"own WAL and APFS writes preserve original raw lease");
        Check(Bytes("raw-parity.apfs")==Bytes("image-parity.apfs"),"raw and image actual Create/Delete publications are byte-identical");
        PreserveEnvelope(before,Bytes("raw-parity.apfs"));
        const auto wal=WriteAheadLog::ReadAll("raw-parity-101.wal","raw-original-rid-101");bool found=false;
        for(const auto& record:wal.records)if(record.operation==(deletion?WriteAheadLog::OperationKind::DeleteSnapshot:WriteAheadLog::OperationKind::CreateSnapshot)){
            NativeSnapshotIntent accepted;Check(WriteAheadLog::SnapshotIntentIsConsistent(record)&&DecodeNativeSnapshotIntent(record.inline_payload,accepted)&&accepted.raw_receipt.has_value(),"actual WAL receipt carries authenticated SNP2");found=true;}
        Check(found,"actual snapshot WAL mutation exists");
        PureInspection("raw-parity",*owner,selected,sibling,a);
    }
    Check(List(*owner).empty(),"actual raw Delete removes snapshot");
}

void AdmissionRefusals(){
    static_assert(!std::is_default_constructible_v<Authority>);
    FreshRaw("raw-refusal.apfs");Tx selected(L"Strict"),sibling(L"Strict");
    ConfigureRaw(selected,"raw-refusal-101.wal",101);ConfigureRaw(sibling,"raw-refusal-102.wal",102);
    auto owner=OpenRaw("raw-refusal.apfs",selected,sibling);auto peers=Peers(*owner,selected,sibling,"raw-refusal");
    const auto before=Bytes("raw-refusal.apfs"),wal=Bytes("raw-refusal-101.wal");const auto marks=selected.Watermarks();
    std::shared_ptr<const Authority> a;std::string e;auto q=Qualification();q.qualified_serial="WRONG00000490";
    Check(!CaptureRawSnapshotRuntimeAuthority(*owner,peers,q,a,e),"wrong hardware qualification refuses");
    auto incomplete=peers;incomplete.pop_back();Check(!CaptureRawSnapshotRuntimeAuthority(*owner,incomplete,Qualification(),a,e),"incomplete cohort refuses");
    auto duplicate=peers;duplicate[1]=duplicate[0];Check(!CaptureRawSnapshotRuntimeAuthority(*owner,duplicate,Qualification(),a,e),"duplicate cohort refuses");
    auto wrong_path=peers;wrong_path[1].journal_path+=L".substitute";
    Check(!CaptureRawSnapshotRuntimeAuthority(*owner,wrong_path,Qualification(),a,e),"substitute journal path refuses");
    sibling.SetVolumeIdentity(L"wrong-configured-rid-102");
    Check(!CaptureRawSnapshotRuntimeAuthority(*owner,peers,Qualification(),a,e),"changed configured RID loses original canonical ownership");
    sibling.SetVolumeIdentity(L"raw-original-rid-102");
    Check(sibling.EnrollCanonicalJournalIdentity(L"apfs-vol:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:102"),"restore fixture's original sibling enrollment");
    if(!sibling.ObservedJournalAppendLeaseGeneration())Check(sibling.Begin()&&sibling.Abort(),"restore original sibling append observation");
    auto descriptors=Descriptors();descriptors.media.limit_bytes+=4096;descriptors.media.partition_length_bytes+=4096;
    DevicePeer::Seed(const_cast<BlockDevice&>(owner->Device()),descriptors);
    Check(!CaptureRawSnapshotRuntimeAuthority(*owner,peers,Qualification(),a,e),"raw limit greater than NX refuses");
    DevicePeer::Seed(const_cast<BlockDevice&>(owner->Device()),Descriptors());a=Capture(*owner,peers);
    SnapshotRuntimePlan raw;Check(PrepareSnapshotCreate(*owner,101,"refusal",1,0,a,raw,e),"prepare authenticated raw refusal plan");
    auto forged=Decoded(raw);forged.raw_receipt->peers[1].journal_identity="wrong-original-rid-102";
    SnapshotRuntimePlan bad;bad.owner=raw.owner;bad.raw_authority=a;bad.request=raw.request;
    bad.request.inline_payload=EncodeNativeSnapshotIntent(forged);bad.request.length=bad.request.inline_payload.size();
    Check(!ApplyFixture(*owner,selected,bad).committed,"changed serialized peer RID refuses before acceptance");
    DevicePeer::ChangeSerial(const_cast<BlockDevice&>(owner->Device()));Check(!ApplyFixture(*owner,selected,raw).committed,"changed held hardware refuses before acceptance");
    SameWatermarks(marks,selected);Check(Bytes("raw-refusal.apfs")==before&&Bytes("raw-refusal-101.wal")==wal,"admission refusals preserve original disk and WAL bytes");
    DevicePeer::Seed(const_cast<BlockDevice&>(owner->Device()),Descriptors());SnapshotRuntimePlan retired;
    Check(PrepareSnapshotCreate(*owner,101,"retired",1,0,a,retired,e),"prepare before retirement");
    DevicePeer::Retire(const_cast<BlockDevice&>(owner->Device()));Check(!ApplyFixture(*owner,selected,retired).committed,"retired original lease refuses");
    Check(!owner->Device().ProbeUnderlyingDevice(true)&&!owner->Device().ProbeUnderlyingDevice(true),
        "retired synthetic transport fails forced presence probes without resurrection");
    SameWatermarks(marks,selected);Check(Bytes("raw-refusal.apfs")==before,"retirement refusal preserves whole image");
}

void RestartReplay(){
    for(const unsigned phase:{0u,1u,2u}){
        const bool published=phase!=0;
        const auto stem=std::string("raw-replay-")+(phase==2?"host-pending":published?"published":"preimage");FreshRaw(stem+".apfs");
        TransactionManager::AcceptedTransaction accepted;
        {
            Tx selected(L"Strict"),sibling(L"Strict");ConfigureRaw(selected,stem+"-101.wal",101);ConfigureRaw(sibling,stem+"-102.wal",102);
            auto owner=OpenRaw(stem+".apfs",selected,sibling);auto a=Capture(*owner,Peers(*owner,selected,sibling,stem));
            SnapshotRuntimePlan p;std::string e;Check(PrepareSnapshotCreate(*owner,101,"recover",1,0,a,p,e),"prepare raw recovery");
            const auto intent=Decoded(p);
            if(phase!=2)owner->FindSessionStore(101)->SetCommitStageHook([&](std::string_view stage){return stage!=(published?"after-apple-publish":"before-apple-publish");});
            const auto result=phase==2?ApplySnapshot(*owner,selected,p,[](std::string&){return false;}):ApplyFixture(*owner,selected,p);
            if(phase!=2)FaultEvidence(*owner,result,intent,published);
            else Check(result.committed&&result.commit_recovery_required&&owner->IsRecoveryRequired()&&
                owner->CheckpointXid()==intent.scope.checkpoint_xid+1&&selected.Watermarks().accepted_sequence==selected.Watermarks().apfs_durable_sequence,
                "actual normal host-pending publication persists an already-durable restart receipt");
            std::vector<Tx::AcceptedTransaction> debt;Check(selected.LoadAcceptedTransactionsSinceCleanup(debt)&&debt.size()==1,"original isolated raw debt");accepted=debt[0];
            owner->FindSessionStore(101)->SetCommitStageHook({});
            const RawEvidence evidence(stem,*owner,selected,sibling);RawSnapshotRuntimeReplayParameters replay{a,accepted.accepted_sequence};
            const auto retry=ReplaySnapshot(*owner,selected,101,replay,e);
            std::cout<<"ordinary retained replay refusal: "<<e<<" owner.poison="<<owner->IsRecoveryRequired()<<"\n";
            Check(retry.has_value()&&!*retry&&owner->IsRecoveryRequired(),"generic retained replay cannot clear accepted debt in either original phase");
            Check(!owner->Commit(102,{}, {},{},{},true,intent.scope.checkpoint_xid).committed,"normal sibling replay flag cannot cross retained debt");
            evidence.Unchanged(*owner,selected,sibling);
        }
        Tx selected(L"Strict"),sibling(L"Strict");ConfigureRaw(selected,stem+"-101.wal",101);ConfigureRaw(sibling,stem+"-102.wal",102);
        auto owner=OpenRaw(stem+".apfs",selected,sibling);auto peers=Peers(*owner,selected,sibling,stem);
        std::shared_ptr<const Authority> a;std::string e;auto wrong=accepted;++wrong.accepted_sequence;
        const RawEvidence evidence(stem,*owner,selected,sibling);const auto& before=evidence.image;
        Check(!CaptureRawSnapshotRuntimeRestartAuthority(*owner,peers,Qualification(),wrong,a,e),"caller accepted transaction cannot self-attest");
        evidence.Unchanged(*owner,selected,sibling);
        for(const auto mode:{"payload","preimage-digest","publication-digest","marker-preimage","marker-transaction"}){
            auto altered=accepted;
            if(std::string_view(mode)=="marker-preimage")++altered.preimage_checkpoint_xid;
            else if(std::string_view(mode)=="marker-transaction")++altered.transaction_id;
            else {
                NativeSnapshotIntent forged;Check(DecodeNativeSnapshotIntent(altered.mutations[0].inline_payload,forged),"decode same-sequence forgery");
                if(std::string_view(mode)=="payload"){forged.name+="-altered";forged.expected_identity.name_utf8=forged.name;}
                else if(std::string_view(mode)=="preimage-digest")forged.preimage_hash[0]^=1;
                else forged.publication_hash[0]^=1;
                altered.mutations[0].inline_payload=EncodeNativeSnapshotIntent(forged);
                altered.mutations[0].payload_length=altered.mutations[0].inline_payload.size();
                altered.mutations[0].logical_length=0;
                HashPayload(altered.mutations[0].inline_payload,altered.mutations[0].payload_sha256);
                Check(WriteAheadLog::SnapshotIntentIsConsistent(altered.mutations[0]),"well-formed altered SNP2 with recomputed WAL digest");
            }
            Check(!CaptureRawSnapshotRuntimeRestartAuthority(*owner,peers,Qualification(),altered,a,e),
                std::string("actual original WAL refuses same-sequence ")+mode+": "+e);
            evidence.Unchanged(*owner,selected,sibling);
        }
        Check(CaptureRawSnapshotRuntimeRestartAuthority(*owner,peers,Qualification(),accepted,a,e),"restart authority matches actual held WAL: "+e);
        RawSnapshotRuntimeReplayParameters replay{a,accepted.accepted_sequence};const auto epoch=owner->FindSessionStore(101)->StateEpoch();
        const auto generic=ReplaySnapshot(*owner,selected,101,replay,e),untyped=ReplaySnapshot(*owner,selected,101,e);
        Check(generic.has_value()&&!*generic&&untyped.has_value()&&!*untyped,"fresh raw no-hook Replay cannot publish or clean debt");
        std::shared_ptr<const RawSnapshotRuntimeRecoveryToken> token,same;auto wrong_parameters=replay;++wrong_parameters.accepted_sequence;
        Check(!AdmitRawSnapshotRestartRecovery(*owner,selected,101,wrong_parameters,e)&&
            !RecoverRawSnapshotRestart(*owner,selected,101,wrong_parameters,token,e)&&!token,"fresh wrong sequence cannot mint typed recovery");
        Check(!AdmitRawSnapshotRestartRecovery(*owner,sibling,101,replay,e)&&
            !AdmitRawSnapshotRestartRecovery(*owner,selected,102,replay,e),"fresh original journal/OID substitution refuses");
        DevicePeer::ChangeSerial(const_cast<BlockDevice&>(owner->Device()));
        Check(!AdmitRawSnapshotRestartRecovery(*owner,selected,101,replay,e)&&
            !RecoverRawSnapshotRestart(*owner,selected,101,replay,token,e)&&!token,"fresh changed binding refuses without latch changes");
        DevicePeer::Seed(const_cast<BlockDevice&>(owner->Device()),Descriptors());
        NativeSnapshotIntent intent;Check(DecodeNativeSnapshotIntent(accepted.mutations[0].inline_payload,intent),"decode exact fresh host receipt");
        std::vector<std::byte> slot;const auto slot_offset=intent.checkpoint_slot*kBlockSize;
        Check(owner->Device().Read(slot_offset,kBlockSize,slot),"read fresh accepted descriptor destination");auto changed=slot;changed[0]^=std::byte{1};
        Check(const_cast<BlockDevice&>(owner->Device()).Write(slot_offset,changed),"actual fresh descriptor tamper");
        const RawEvidence changed_source(stem,*owner,selected,sibling);
        Check(!AdmitRawSnapshotRestartRecovery(*owner,selected,101,replay,e)&&
            !RecoverRawSnapshotRestart(*owner,selected,101,replay,token,e)&&!token&&!owner->IsRecoveryRequired(),
            "fresh source refusal cannot register a latch or publish");changed_source.Unchanged(*owner,selected,sibling);
        Check(const_cast<BlockDevice&>(owner->Device()).Write(slot_offset,slot),"restore exact fresh descriptor destination");
        Check(AdmitRawSnapshotRestartRecovery(*owner,selected,101,replay,e)&&
            AdmitRawSnapshotRestartRecovery(*owner,selected,101,replay,e),"pure exact fresh P/P+1 admission: "+e);
        Check(!owner->IsRecoveryRequired()&&!owner->RecoveryVolumeObjectId()&&owner->FindSessionStore(101)->StateEpoch()==epoch,
            "fresh refused/valid probes leave owner/store epochs and latch unchanged");evidence.Unchanged(*owner,selected,sibling);
        HostCompletionFiles host(stem,intent);auto* store=owner->FindSessionStore(101);
        Check(RecoverRawSnapshotRestart(*owner,selected,101,replay,token,e)&&token,"actual typed raw restart: "+e);
        Check(owner->IsRecoveryRequired()&&List(*owner).size()==1,"fresh recovery publishes once while retaining selected completion latch");
        const RawEvidence publication(stem,*owner,selected,sibling);const auto published_epoch=store->StateEpoch();
        Check(AdmitRawSnapshotRestartRecovery(*owner,selected,101,replay,e)&&RecoverRawSnapshotRestart(*owner,selected,101,replay,same,e)&&same==token,
            "fresh API retry returns the exact original completion token");
        Check(store->StateEpoch()==published_epoch,"fresh retry does not reload/reapply publication");publication.Unchanged(*owner,selected,sibling);
        OrdinaryWritesRefused(stem,*owner,selected,sibling);
        Check(!CompleteRetainedRawSnapshotRecovery(*owner,token,[&](std::string& error){host.Before(*owner,*store,selected);error="fresh marker pending";return false;},e),
            "fresh host false retains cleanup/pins");
        const RawEvidence durable(stem,*owner,selected,sibling);
        Check(!CompleteRetainedRawSnapshotRecovery(*owner,token,[&](std::string&)->bool{host.Before(*owner,*store,selected);throw std::runtime_error("fresh marker interrupted");},e),
            "fresh host throw retains exact original completion debt");durable.Unchanged(*owner,selected,sibling);
        OrdinaryWritesRefused(stem,*owner,selected,sibling);
        Check(Bytes(host.marker)==host.dirty&&CompleteRetainedRawSnapshotRecovery(*owner,token,[&](std::string&){return host.Finish(*owner,*store,selected);},e),
            "fresh host marker/spool completion precedes selected cleanup: "+e);
        Check(!owner->IsRecoveryRequired()&&Bytes(stem+".apfs")==publication.image&&Bytes(host.marker)==host.clean&&!std::filesystem::exists(host.spool),
            "fresh closure leaves exact publication and actual clean host marker");
        const auto after=selected.Watermarks();Check(after.accepted_sequence==after.apfs_durable_sequence&&after.accepted_sequence==after.cleanup_sequence,"raw recovery discharges only selected debt");
        Check(Bytes(stem+"-102.wal")==evidence.sibling_wal,"restart leaves exact original sibling WAL bytes");SameWatermarks(evidence.sibling_marks,sibling);
        PreserveEnvelope(before,Bytes(stem+".apfs"));
    }
}

void RetainedRecovery(){
    using Completion=RawSnapshotRuntimeRecoveryToken;
    static_assert(!std::is_default_constructible_v<Completion>);
    for(const bool published:{false,true})for(const bool deletion:{false,true}){
        const auto stem=std::string("raw-retained-")+(published?"after-":"before-")+(deletion?"delete":"create");
        FreshRaw(stem+".apfs");Tx selected(L"Strict"),sibling(L"Strict");
        ConfigureRaw(selected,stem+"-101.wal",101);ConfigureRaw(sibling,stem+"-102.wal",102);
        auto owner=OpenRaw(stem+".apfs",selected,sibling);auto a=Capture(*owner,Peers(*owner,selected,sibling,stem));
        if(deletion){SnapshotRuntimePlan seed;std::string e;Check(PrepareSnapshotCreate(*owner,101,"retained",1,0,a,seed,e),"prepare retained delete seed");Success(ApplyFixture(*owner,selected,seed));}
        SnapshotRuntimePlan plan;std::string e;
        Check(deletion?PrepareSnapshotDelete(*owner,List(*owner)[0].identity,2,a,plan,e):
            PrepareSnapshotCreate(*owner,101,"retained",1,0,a,plan,e),"prepare actual retained operation: "+e);
        const auto intent=Decoded(plan);const auto envelope=Bytes(stem+".apfs");
        const auto sibling_location=owner->FindSessionStore(102)->AuthoritativeAppleCheckpointView()->volumes[1].superblock_object;
        std::vector<std::byte> sibling_apfs;
        Check(owner->Device().Read(sibling_location.physical_block*kBlockSize,sibling_location.size_bytes,sibling_apfs),
            "read actual original sibling APSB bytes");
        std::vector<std::byte> sibling_payload;Check(owner->Device().Read(528ull*kBlockSize,4*kBlockSize,sibling_payload),"read original sibling payload bytes");
        const auto lease=owner->Device().CaptureHeldRawSnapshotLease();Check(lease.has_value(),"retained original source lease");
        owner->FindSessionStore(101)->SetCommitStageHook([&](std::string_view stage){return stage!=(published?"after-apple-publish":"before-apple-publish");});
        const auto result=ApplyFixture(*owner,selected,plan);FaultEvidence(*owner,result,intent,published);
        owner->FindSessionStore(101)->SetCommitStageHook({});
        RawSnapshotRuntimeReplayParameters replay{a,selected.Watermarks().accepted_sequence};
        std::shared_ptr<const Completion> completion;
        const RawEvidence original(stem,*owner,selected,sibling);
        const auto latch_before=owner->IsRecoveryRequired();const auto reason_before=owner->RecoveryReason();
        const auto epoch_before=owner->FindSessionStore(101)->StateEpoch();
        ApfsSnapshotScope inspected_scope;std::vector<ApfsSnapshotInfo> inspected_inventory;
        Check(!InspectRawSnapshotRuntimeAuthority(a,*owner,101,inspected_scope,&inspected_inventory,e)&&
            inspected_scope==ApfsSnapshotScope{}&&inspected_inventory.empty(),"retained debt cannot enter the pure clean inspection route");
        Check(AdmitRetainedRawSnapshotRecovery(*owner,selected,101,replay,e)&&
            AdmitRetainedRawSnapshotRecovery(*owner,selected,101,replay,e),"pure repeated original retained admission: "+e);
        Check(owner->IsRecoveryRequired()==latch_before&&owner->RecoveryReason()==reason_before&&
            owner->FindSessionStore(101)->StateEpoch()==epoch_before,"admission cannot reload/grant/change the original latch or store epoch");
        original.Unchanged(*owner,selected,sibling);
        auto wrong=replay;++wrong.accepted_sequence;
        Check(!RecoverRetainedRawSnapshot(*owner,selected,101,wrong,completion,e)&&!completion,"retained sequence cannot self-authorize");
        original.Unchanged(*owner,selected,sibling);
        DevicePeer::ChangeSerial(const_cast<BlockDevice&>(owner->Device()));
        Check(!RecoverRetainedRawSnapshot(*owner,selected,101,replay,completion,e),"retained changed hardware refuses: "+e);
        original.Unchanged(*owner,selected,sibling);DevicePeer::Seed(const_cast<BlockDevice&>(owner->Device()),Descriptors());
        auto& context=const_cast<Store::VolumeContext&>(owner->FindSessionStore(102)->Context());const auto uuid=context.volume_uuid_hex;
        context.volume_uuid_hex=std::string(32,'d');
        Check(!RecoverRetainedRawSnapshot(*owner,selected,101,replay,completion,e),"retained changed cohort UUID refuses: "+e);
        original.Unchanged(*owner,selected,sibling);context.volume_uuid_hex=uuid;
        std::vector<std::byte> slot;const auto slot_offset=intent.checkpoint_slot*kBlockSize;
        Check(owner->Device().Read(slot_offset,kBlockSize,slot),"read exact original descriptor destination");auto corrupted=slot;corrupted[0]^=std::byte{1};
        Check(const_cast<BlockDevice&>(owner->Device()).Write(slot_offset,corrupted),"actual source descriptor tamper");
        const RawEvidence tampered(stem,*owner,selected,sibling);
        Check(!RecoverRetainedRawSnapshot(*owner,selected,101,replay,completion,e),"changed actual source refuses without publication: "+e);
        tampered.Unchanged(*owner,selected,sibling);
        Check(const_cast<BlockDevice&>(owner->Device()).Write(slot_offset,slot),"restore actual fixture descriptor");
        Check(RecoverRetainedRawSnapshot(*owner,selected,101,replay,completion,e)&&completion,"typed retained P/P+1 recovery: "+e);
        Check(owner->IsRecoveryRequired()&&owner->RecoveryVolumeObjectId()==101&&owner->CheckpointXid()==intent.scope.checkpoint_xid+1,
            "publication token retains exact selected completion latch");
        Check(owner->Device().IsHeldRawSnapshotLeaseCurrent(*lease),"recovery retains the original opaque raw lease");
        Check(List(*owner).size()==(deletion?0u:1u),"retained Create/Delete publishes exactly the requested inventory");
        const RawEvidence publication(stem,*owner,selected,sibling);std::shared_ptr<const Completion> same;
        Check(RecoverRetainedRawSnapshot(*owner,selected,101,replay,same,e)&&same==completion,"publication retry returns the same completion token");
        Check(!owner->Commit(102,{}, {},{},{},true,intent.scope.checkpoint_xid+1).committed,"normal sibling replay flag stays refused through completion");
        Check(!owner->RefreshSessionForRecovery(101,e)&&
            !owner->InspectCurrentSession(101,[](const Store&,std::string&){return true;},e,true),"ordinary refresh/inspection keep the selected latch");
        publication.Unchanged(*owner,selected,sibling);
        unsigned host_calls=0;const auto cleanup_before=selected.Watermarks().cleanup_sequence;
        Check(!CompleteRetainedRawSnapshotRecovery(*owner,completion,[&](std::string&)->bool{++host_calls;throw std::runtime_error("host marker fault");},e),
            "host completion exception remains conservative");
        Check(owner->IsRecoveryRequired()&&selected.Watermarks().cleanup_sequence==cleanup_before,"failed host completion cannot release accepted pins");
        Check(!CompleteRetainedRawSnapshotRecovery(*owner,completion,[&](std::string& error){++host_calls;error="host spool fault";return false;},e),
            "host completion refusal retains retryable selected debt");
        Check(owner->IsRecoveryRequired()&&Bytes(stem+".apfs")==publication.image,"failed completion does not republish or clear the latch");
        Check(CompleteRetainedRawSnapshotRecovery(*owner,completion,[&](std::string&){++host_calls;return true;},e),"complete original selected host/WAL proof: "+e);
        Check(host_calls==3&&!owner->IsRecoveryRequired()&&!owner->RecoveryVolumeObjectId(),"only successful typed completion clears selected latch");
        const auto marks=selected.Watermarks();Check(marks.accepted_sequence==replay.accepted_sequence&&marks.accepted_sequence==marks.apfs_durable_sequence&&
            marks.accepted_sequence==marks.cleanup_sequence,"exact original accepted sequence is terminal");
        Check(Bytes(stem+".apfs")==publication.image&&Bytes(stem+"-102.wal")==original.sibling_wal,"completion preserves publication and original sibling WAL bytes");
        SameWatermarks(original.sibling_marks,sibling);
        const auto& current=*owner->FindSessionStore(101)->AuthoritativeAppleCheckpointView();
        const auto& current_sibling=current.volumes[1].superblock_object;
        std::vector<std::byte> sibling_after;
        Check(owner->Device().Read(current_sibling.physical_block*kBlockSize,current_sibling.size_bytes,sibling_after)&&
            sibling_after==sibling_apfs,"retained recovery preserves actual sibling APSB bytes");
        std::vector<std::byte> payload_after;Check(owner->Device().Read(528ull*kBlockSize,4*kBlockSize,payload_after)&&payload_after==sibling_payload,
            "retained recovery preserves actual sibling payload bytes");
        const auto census=owner->CheckpointCensusSnapshot();Check(census.size()==2&&census[1].volume_object_id==original.census[1].volume_object_id&&
            census[1].required_checkpoint_xids==original.census[1].required_checkpoint_xids&&
            census[1].unapplied_accepted_work==original.census[1].unapplied_accepted_work,"retained recovery preserves sibling pins/debt");
        PreserveEnvelope(envelope,publication.image);
        const RawEvidence completed(stem,*owner,selected,sibling);
        Check(!CompleteRetainedRawSnapshotRecovery(*owner,completion,[](std::string&){return true;},e),"consumed completion token refuses");
        completed.Unchanged(*owner,selected,sibling);
    }
}

void OrdinaryJournalAppend(Tx& journal,std::size_t payload_bytes,std::uint64_t preimage,bool clean){
    Tx::MutationIntent mutation;mutation.kind=Tx::MutationKind::Write;mutation.path=L"\\budget.bin";
    mutation.object_id=17;mutation.generation=preimage+1;mutation.length=mutation.payload_length=payload_bytes;
    mutation.inline_payload.assign(payload_bytes,std::byte{0x41});HashPayload(mutation.inline_payload,mutation.payload_checksum);
    Check(journal.Begin()&&journal.RecordMutation(mutation)&&journal.Accept(preimage),"actual ordinary accepted append chain");
    if(clean){const auto sequence=journal.Watermarks().accepted_sequence;
        Check(journal.MarkApfsDurableThrough(sequence)&&journal.MarkCleanedThrough(sequence),"actual ordinary cleaned append chain");}
}

void FreshRestartRefusals(){
    for(const bool published:{false,true})for(const auto mode:{"mixed","sibling-history","selected-epoch","sibling-epoch","ledger","transport"}){
        const auto stem=std::string("raw-fresh-refuse-")+(published?"after-":"before-")+mode;FreshRaw(stem+".apfs");
        Tx::AcceptedTransaction accepted;
        {
            Tx selected(L"Strict"),sibling(L"Strict");ConfigureRaw(selected,stem+"-101.wal",101);ConfigureRaw(sibling,stem+"-102.wal",102);
            auto owner=OpenRaw(stem+".apfs",selected,sibling);auto a=Capture(*owner,Peers(*owner,selected,sibling,stem));
            SnapshotRuntimePlan plan;std::string e;Check(PrepareSnapshotCreate(*owner,101,"fresh-refuse",1,0,a,plan,e),"prepare actual fresh refusal debt");
            owner->FindSessionStore(101)->SetCommitStageHook([&](std::string_view stage){return stage!=(published?"after-apple-publish":"before-apple-publish");});
            Check(ApplyFixture(*owner,selected,plan).commit_recovery_required,"actual fresh P/P+1 fault receipt");
            std::vector<Tx::AcceptedTransaction> debt;Check(selected.LoadAcceptedTransactionsSinceCleanup(debt)&&debt.size()==1,"load original fresh accepted receipt");accepted=debt[0];
        }
        Tx selected(L"Strict"),sibling(L"Strict");ConfigureRaw(selected,stem+"-101.wal",101);ConfigureRaw(sibling,stem+"-102.wal",102);
        auto owner=OpenRaw(stem+".apfs",selected,sibling);const auto peers=Peers(*owner,selected,sibling,stem);
        std::shared_ptr<const Authority> a;std::string e;Check(CaptureRawSnapshotRuntimeRestartAuthority(*owner,peers,Qualification(),accepted,a,e),"capture exact original fresh refusal authority");
        const RawSnapshotRuntimeReplayParameters replay{a,accepted.accepted_sequence};
        if(std::string_view(mode)=="mixed")OrdinaryJournalAppend(selected,32,owner->CheckpointXid(),false);
        else if(std::string_view(mode)=="sibling-history")OrdinaryJournalAppend(sibling,32,owner->CheckpointXid(),true);
        else if(std::string_view(mode)=="selected-epoch"||std::string_view(mode)=="sibling-epoch"){
            auto* store=owner->FindSessionStore(std::string_view(mode)=="selected-epoch"?101:102);const auto old_epoch=store->StateEpoch();
            Check(store->PrepareNativeWritePath()&&store->StateEpoch()!=old_epoch,"actual clean peer reload changes captured epoch");
        }else apfsaccess::catalog::RawSnapshotRuntimeRecoveryTestPeer::UnrelatedLatch(*owner,
            std::string_view(mode)=="ledger"?"AllocationOverlapDetected":"SessionCommitRecoveryRequired: AppleCommitPublishFailed",101);
        const RawEvidence before(stem,*owner,selected,sibling);const auto poison=owner->IsRecoveryRequired();
        const auto reason=owner->RecoveryReason();const auto oid=owner->RecoveryVolumeObjectId();
        const auto selected_epoch=owner->FindSessionStore(101)->StateEpoch(),sibling_epoch=owner->FindSessionStore(102)->StateEpoch();
        std::shared_ptr<const RawSnapshotRuntimeRecoveryToken> completion;
        Check(!AdmitRawSnapshotRestartRecovery(*owner,selected,101,replay,e)&&
            !RecoverRawSnapshotRestart(*owner,selected,101,replay,completion,e)&&!completion,std::string("fresh changed original proof refuses ")+mode+": "+e);
        Check(owner->IsRecoveryRequired()==poison&&owner->RecoveryReason()==reason&&owner->RecoveryVolumeObjectId()==oid&&
            owner->FindSessionStore(101)->StateEpoch()==selected_epoch&&owner->FindSessionStore(102)->StateEpoch()==sibling_epoch,
            "fresh refusal preserves original latch and both epochs without repair/reload");before.Unchanged(*owner,selected,sibling);
    }
}

void RetainedRefusals(){
    for(const bool published:{false,true})for(const auto mode:{"selected-rid","sibling-rid","wal-suffix","sibling-wal-growth","selected-reservation","retired","ledger","transport","unknown"}){
        const auto stem=std::string("raw-retained-refuse-")+(published?"after-":"before-")+mode;
        FreshRaw(stem+".apfs");Tx selected(L"Strict"),sibling(L"Strict");
        ConfigureRaw(selected,stem+"-101.wal",101);ConfigureRaw(sibling,stem+"-102.wal",102);
        auto owner=OpenRaw(stem+".apfs",selected,sibling);auto a=Capture(*owner,Peers(*owner,selected,sibling,stem));
        SnapshotRuntimePlan plan;std::string e;Check(PrepareSnapshotCreate(*owner,101,"refuse",1,0,a,plan,e),"prepare retained refusal fixture");
        owner->FindSessionStore(101)->SetCommitStageHook([&](std::string_view stage){return stage!=(published?"after-apple-publish":"before-apple-publish");});
        Check(ApplyFixture(*owner,selected,plan).commit_recovery_required,"actual isolated snapshot debt exists before tamper");
        owner->FindSessionStore(101)->SetCommitStageHook({});
        const RawSnapshotRuntimeReplayParameters replay{a,selected.Watermarks().accepted_sequence};
        if(std::string_view(mode)=="selected-rid")selected.SetVolumeIdentity(L"substituted-selected-rid");
        else if(std::string_view(mode)=="sibling-rid")sibling.SetVolumeIdentity(L"substituted-sibling-rid");
        else if(std::string_view(mode)=="wal-suffix")OrdinaryJournalAppend(selected,32,owner->CheckpointXid(),false);
        else if(std::string_view(mode)=="sibling-wal-growth")OrdinaryJournalAppend(sibling,32,owner->CheckpointXid(),true);
        else if(std::string_view(mode)=="selected-reservation"){
            const auto epoch=owner->FindSessionStore(101)->StateEpoch();
            Check(owner->FindSessionStore(101)->AllocateExtent(kBlockSize).has_value(),"actual unaccepted selected allocator reservation");
            Check(owner->FindSessionStore(101)->StateEpoch()==epoch&&owner->FindSessionStore(101)->HasUncommittedAllocatorState(),
                "allocator reservation is observable even without an epoch change");
        }
        else if(std::string_view(mode)=="retired")DevicePeer::Retire(const_cast<BlockDevice&>(owner->Device()));
        else {
            const auto reason=std::string_view(mode)=="ledger"?"AllocationOverlapDetected":
                std::string_view(mode)=="transport"?"SessionCommitRecoveryRequired: AppleCommitPublishFailed":"UnknownOwnerPoison";
            apfsaccess::catalog::RawSnapshotRuntimeRecoveryTestPeer::UnrelatedLatch(*owner,reason,std::string_view(mode)=="unknown"?102:101);
        }
        const RawEvidence evidence(stem,*owner,selected,sibling);const auto poison=owner->IsRecoveryRequired();const auto reason=owner->RecoveryReason();
        const auto recovery_oid=owner->RecoveryVolumeObjectId();std::shared_ptr<const RawSnapshotRuntimeRecoveryToken> completion;
        const auto epoch=owner->FindSessionStore(101)->StateEpoch();
        Check(!AdmitRetainedRawSnapshotRecovery(*owner,selected,101,replay,e),std::string("pure admission refuses ")+mode+": "+e);
        Check(!RecoverRetainedRawSnapshot(*owner,selected,101,replay,completion,e)&&!completion,
            std::string("typed retained refusal for ")+mode+": "+e);
        Check(owner->IsRecoveryRequired()==poison&&owner->RecoveryReason()==reason&&owner->RecoveryVolumeObjectId()==recovery_oid,
            "unrelated or unauthenticated failure leaves original latch untouched");
        Check(owner->FindSessionStore(101)->StateEpoch()==epoch,"refused retained recovery cannot discard or reload selected state");
        Check(!owner->Commit(102,{}, {},{},{},true,owner->CheckpointXid()).committed,"generic sibling replay cannot authorize tampered recovery");
        evidence.Unchanged(*owner,selected,sibling);
    }
}

struct EvidenceReplayStats {
    std::uint64_t bytes=0,allocation=0;
    std::size_t records=0;
};

EvidenceReplayStats EvidenceReplay(const std::string& path,const char* phase){
    HANDLE held=CreateFileW(std::filesystem::absolute(path).c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,
        nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    Check(held!=INVALID_HANDLE_VALUE,"hold original WAL for finite replay proof");
    const auto decoded=WriteAheadLog::ReadAllEvidenceFromHeldHandle(held,"raw-original-rid-101",
        {64ull*1024*1024,1000000},256ull*1024*1024);
    Check(CloseHandle(held)&&decoded.status==WriteAheadLog::ReadStatus::Ok&&!decoded.recovered_torn_tail,
        "actual original history fits unchanged replay budget");
    EvidenceReplayStats stats;stats.bytes=std::filesystem::file_size(path);stats.records=decoded.records.size();
    std::uint64_t encoded=0;
    for(const auto& record:decoded.records)encoded+=WriteAheadLog::EncodeForTest(record).size();
    Check(encoded==stats.bytes,"decoded records reproduce exact serialized original WAL bytes");
    stats.allocation=stats.bytes*4+stats.records*(sizeof(WriteAheadLog::Record)+4ull);
    Check(stats.allocation<=256ull*1024*1024,"exact frame reservation remains within fixed allocation budget");
    std::cout<<"evidence-budget "<<phase<<" bytes="<<stats.bytes<<" frames="<<stats.records
        <<" allocation="<<stats.allocation<<" limit="<<(256ull*1024*1024)<<"\n";
    return stats;
}

void EvidenceCapacity(){
    const std::string stem="raw-evidence-capacity";FreshRaw(stem+".apfs");Tx selected(std::wstring(4096,L'S')),sibling(L"Strict");
    ConfigureRaw(selected,stem+"-101.wal",101);ConfigureRaw(sibling,stem+"-102.wal",102);
    auto owner=OpenRaw(stem+".apfs",selected,sibling);auto a=Capture(*owner,Peers(*owner,selected,sibling,stem));
    SnapshotRuntimePlan control;std::string control_error;
    Check(PrepareSnapshotCreate(*owner,101,"long-label-control",1,0,a,control,control_error),"prepare long admitted safety-label control");
    Success(ApplyFixture(*owner,selected,control));
    const auto generation=selected.ObservedJournalWriterLeaseGeneration();const auto lease=owner->Device().CaptureHeldRawSnapshotLease();
    // The held reader pre-counts actual frames and reserves one record vector.
    // Measure a real append, then approach that reader boundary without inventing records.
    const auto start=EvidenceReplay(stem+"-101.wal","initial");
    OrdinaryJournalAppend(selected,16384,owner->CheckpointXid(),true);
    const auto sample=EvidenceReplay(stem+"-101.wal","ordinary-sample");
    const auto overhead=sample.bytes-start.bytes-16384;
    const auto ordinary_frames=sample.records-start.records;
    Check(overhead>0&&overhead<16384,"finite ordinary chain codec overhead");
    Check(ordinary_frames==4,"ordinary sample has actual prepared/accepted/durable/cleaned frames");
    const auto grow_to=[&](std::uint64_t bound){
        for(unsigned i=0;i<128;++i){const auto size=std::filesystem::file_size(stem+"-101.wal");
            if(size>=bound||bound-size<=overhead)break;
            const auto payload=static_cast<std::size_t>((std::min)(1024ull*1024,static_cast<std::uint64_t>(bound-size-overhead)));
            OrdinaryJournalAppend(selected,payload,owner->CheckpointXid(),true);
        }
    };
    grow_to((64ull*1024*1024)-512ull*1024);
    const auto near_before=EvidenceReplay(stem+"-101.wal","near-before");
    SnapshotRuntimePlan near_control;
    Check(PrepareSnapshotCreate(*owner,101,"long-label-near-control",2,0,a,near_control,control_error),"prepare near-budget long safety-label control");
    unsigned host_calls=0;
    const auto pending=ApplySnapshot(*owner,selected,near_control,[&](std::string& error){
        ++host_calls;error="near-budget host completion pending";return false;
    });
    Check(pending.committed&&pending.commit_recovery_required&&owner->IsRecoveryRequired()&&host_calls==1,
        "actual near-budget host hook retains original completion debt");
    const auto near_pending=EvidenceReplay(stem+"-101.wal","near-pending");
    Check(near_pending.bytes>near_before.bytes&&near_pending.records>near_before.records,
        "actual accepted snapshot bytes remain replay-readable before host completion");
    const RawSnapshotRuntimeReplayParameters replay{a,selected.Watermarks().accepted_sequence};
    std::shared_ptr<const RawSnapshotRuntimeRecoveryToken> completion;
    Check(RecoverRetainedRawSnapshot(*owner,selected,101,replay,completion,control_error)&&completion,
        "typed original near-budget recovery validates serialized receipt: "+control_error);
    Check(CompleteRetainedRawSnapshotRecovery(*owner,completion,[&](std::string&){++host_calls;return true;},control_error),
        "actual near-budget host completion closes only verified original debt: "+control_error);
    const auto near_complete=EvidenceReplay(stem+"-101.wal","near-complete");
    const auto complete_marks=selected.Watermarks();
    Check(host_calls==2&&!owner->IsRecoveryRequired()&&
        complete_marks.accepted_sequence==complete_marks.apfs_durable_sequence&&
        complete_marks.apfs_durable_sequence==complete_marks.cleanup_sequence,
        "near-budget typed replay/completion converges actual selected acceptance");
    std::cout<<"evidence-budget actual-completion bytes="<<near_complete.bytes-near_before.bytes
        <<" frames="<<near_complete.records-near_before.records<<" hooks="<<host_calls<<"\n";
    const auto final_frames=near_complete.records+ordinary_frames;
    const auto record_bytes=final_frames*(sizeof(WriteAheadLog::Record)+4ull);
    Check(record_bytes<256ull*1024*1024,"finite measured frame reservation");
    const auto target=(std::min)(64ull*1024*1024,(256ull*1024*1024-record_bytes)/4)-256;
    Check(target>near_complete.bytes+overhead&&target-near_complete.bytes-overhead<=WriteAheadLog::MaxInlinePayloadBytes,
        "one bounded actual ordinary append reaches the measured reader boundary");
    grow_to(target);
    const auto boundary=EvidenceReplay(stem+"-101.wal","refusal-boundary");
    Check(boundary.bytes==target&&boundary.records==final_frames,"valid cleaned original WAL reaches actual finite reader threshold");
    Check(boundary.allocation+4ull*4096>256ull*1024*1024,
        "the real acceptance label alone would cross the remaining allocation budget");
    Check(selected.ObservedJournalWriterLeaseGeneration()==generation&&selected.ObservedJournalAppendLeaseGeneration()==generation&&
        lease&&owner->Device().IsHeldRawSnapshotLeaseCurrent(*lease),"clean growth retains authority's original writer and raw lease");
    SnapshotRuntimePlan plan;std::string e;Check(PrepareSnapshotCreate(*owner,101,"capacity-refusal",1,0,a,plan,e),"retained authority prepares at valid existing budget: "+e);
    Tx::MutationIntent intent;intent.kind=Tx::MutationKind::CreateSnapshot;intent.path=L"\\";intent.object_id=101;intent.generation=owner->CheckpointXid()+1;
    intent.inline_payload=plan.request.inline_payload;intent.length=intent.payload_length=intent.inline_payload.size();HashPayload(intent.inline_payload,intent.payload_checksum);
    Check(!selected.SnapshotEvidenceCapacityAvailable(intent,e)&&e=="SnapshotRuntimeEvidenceCapacityExceeded","prospective snapshot/completion crosses finite evidence budget");
    const RawEvidence evidence(stem,*owner,selected,sibling);const auto prior_calls=host_calls;
    const auto result=ApplySnapshot(*owner,selected,plan,[&](std::string&){++host_calls;return true;});
    Check(!result.committed&&!result.commit_recovery_required&&result.clean_prepublication_refusal&&
        result.error=="SnapshotRuntimeEvidenceCapacityExceeded","actual raw acceptance refuses before Begin and source publication");
    evidence.Unchanged(*owner,selected,sibling);Check(!owner->IsRecoveryRequired()&&host_calls==prior_calls,
        "budget refusal does not manufacture owner poison/debt or invoke completion");
    const auto refused=EvidenceReplay(stem+"-101.wal","after-refusal");
    Check(refused.bytes==boundary.bytes&&refused.records==boundary.records&&refused.allocation==boundary.allocation,
        "refused publication preserves the same replay-readable original budget");
}
}

int main(int argc,char** argv){try{
    Check(argc==2,"pass a private D: evidence directory");const auto root=std::filesystem::absolute(argv[1]);
    Check(root.root_name()=="D:","raw runtime artifacts must be on D:");std::filesystem::create_directories(root);
    std::filesystem::path run;
    for(unsigned i=0;i<1024;++i){auto p=root/("raw-runtime-run-"+std::to_string(i));if(std::filesystem::create_directory(p)){run=p;break;}}
    Check(!run.empty(),"fresh private raw runtime evidence directory");std::filesystem::current_path(run);
    LifecycleParity();AdmissionRefusals();NormalCompletion();RestartReplay();FreshRestartRefusals();RetainedRecovery();RetainedRefusals();EvidenceCapacity();
    std::cout<<"RawSnapshotRuntimeTests: "<<checks<<" checks, 0 failures\n";return 0;
}catch(const std::exception& e){std::cerr<<"FAIL after "<<checks<<" checks: "<<e.what()<<"\n";return 1;}}
