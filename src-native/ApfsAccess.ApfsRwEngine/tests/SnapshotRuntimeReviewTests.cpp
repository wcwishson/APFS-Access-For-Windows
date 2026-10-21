#define SNAPSHOT_RUNTIME_TEST_HELPERS_ONLY
#include "SnapshotRuntimeTests.cpp"

#include <thread>
#include <atomic>

void DrainReader(bool acquire_after) {
    Fresh("drain.apfs"); Tx tx(L"Strict"); Configure(tx,"drain.wal");
    auto owner=Open("drain.apfs",tx); Create(*owner,tx,"held");
    const auto id=List(*owner)[0].identity;std::string error;
    auto reader=owner->AcquireSnapshotReader(id,error);Check(!!reader,"reader before drain");
    std::vector<std::byte> bytes;Check(reader->Read(17,0,kBlockSize,bytes),"read before drain");
    const auto result=owner->DrainAndStop(std::chrono::seconds(2));
    Check(result.clean&&!owner->RawLeaseHeld()&&owner->MountedVolumeCount()==0,"drain closes owner");
    if(acquire_after) {
        Check(!owner->AcquireSnapshotReader(id,error),"reader acquisition after drain refuses");
    } else {
        bytes.assign(1,std::byte{1});
        Check(!reader->Read(17,0,kBlockSize,bytes)&&bytes.empty(),"drain closes reader before history ownership ends");
        Check(owner->SnapshotRuntimeCheckpointPins().empty(),"drain releases closed reader pins");
    }
    Check(owner->DrainAndStop(std::chrono::seconds(2)).clean,"repeated drain remains safe");
}

void PreimagePayload(bool published) {
    Fresh("preimage.apfs");Tx tx(L"Strict");Configure(tx,"preimage.wal");
    auto owner=Open("preimage.apfs",tx);SnapshotRuntimePlan plan;std::string error;
    Check(PrepareSnapshotCreate(*owner,101,"bound",1,0,plan,error),"payload preimage prepares");
    NativeSnapshotIntent intent;Check(DecodeNativeSnapshotIntent(plan.request.inline_payload,intent),"payload intent");
    if(published)Success(ApplySnapshot(*owner,tx,plan));
    auto& device=const_cast<BlockDevice&>(owner->Device());
    std::vector<std::byte> changed(kBlockSize,std::byte{0x79});
    Check(device.Write(512*kBlockSize,changed)&&device.Flush(),"bounded same-XID payload drift");
    const auto disk=Bytes("preimage.apfs"),wal=Bytes("preimage.wal");
    if(published)Check(!VerifyPublishedSnapshot(*owner->FindSessionStore(101),intent,error),"publication proof rejects changed historical payload");
    else Check(!ApplySnapshot(*owner,tx,plan).committed,"preacceptance rejects changed live payload");
    Check(Bytes("preimage.apfs")==disk&&Bytes("preimage.wal")==wal,"payload refusal preserves image and WAL");
}

void ActiveReadDrain() {
    SetEnvironmentVariableW(L"APFSACCESS_EXPERIMENTAL_BLOCK_READ_CACHE",L"1");
    Fresh("active.apfs");Tx tx(L"Strict");Configure(tx,"active.wal");
    auto owner=Open("active.apfs",tx);Create(*owner,tx,"active");
    SetEnvironmentVariableW(L"APFSACCESS_EXPERIMENTAL_BLOCK_READ_CACHE",nullptr);
    const auto id=List(*owner)[0].identity;std::string error;
    auto reader=owner->AcquireSnapshotReader(id,error);Check(!!reader,"active reader acquired");
    auto& device=const_cast<BlockDevice&>(owner->Device());
    std::vector<std::byte> spare;Check(device.Read(2047*kBlockSize,kBlockSize,spare)&&device.Write(2047*kBlockSize,spare),"invalidate synthetic image read cache");
    HANDLE entered=CreateEventW(nullptr,TRUE,FALSE,nullptr),release=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    Check(entered&&release,"read rendezvous events");
    device.SetReadCacheMissHookForTests([&]{SetEvent(entered);WaitForSingleObject(release,5000);});
    bool read_ok=false;std::vector<std::byte> bytes;
    std::thread active([&]{read_ok=reader->Read(17,0,kBlockSize,bytes);});
    const bool reached=WaitForSingleObject(entered,5000)==WAIT_OBJECT_0;
    const auto start=std::chrono::steady_clock::now();
    const auto result=owner->DrainAndStop(std::chrono::milliseconds(100));
    const auto elapsed=std::chrono::steady_clock::now()-start;
    const bool held=owner->RawLeaseHeld()&&owner->MountedVolumeCount()==2;
    const bool refused=!owner->AcquireSnapshotReader(id,error);
    SetEvent(release);active.join();device.SetReadCacheMissHookForTests({});
    CloseHandle(entered);CloseHandle(release);
    Check(reached,"read paused inside real BlockDevice read");
    Check(!result.clean&&result.error=="ContainerSnapshotReaderDrainTimeout"&&elapsed<std::chrono::seconds(2),"drain times out within deadline during active read");
    Check(held&&refused,"timed-out drain retains owner and refuses new readers");
    Check(read_ok&&bytes.size()==kBlockSize,"already active read completes");
    Check(owner->DrainAndStop(std::chrono::seconds(2)).clean,"drain retries after read releases");
    Check(!reader->Read(17,0,kBlockSize,bytes)&&bytes.empty(),"retry closes old reader");
}
void PinCensusDrift() {
    Fresh("pins.apfs");Tx tx(L"Strict");Configure(tx,"pins.wal");auto owner=Open("pins.apfs",tx);
    Create(*owner,tx,"older");const auto old=owner->CheckpointXid();Create(*owner,tx,"newer");
    SnapshotRuntimePlan plan;std::string error;Check(PrepareSnapshotCreate(*owner,101,"stale-pins",1,0,plan,error),"pin plan prepares");
    Check(owner->UpdateRequiredCheckpointXids(102,{old},error),"sibling adds retained checkpoint");
    const auto disk=Bytes("pins.apfs"),wal=Bytes("pins.wal");
    auto result=ApplySnapshot(*owner,tx,plan);
    Check(!result.committed&&result.clean_prepublication_refusal,"new sibling pin invalidates preacceptance plan");
    Check(Bytes("pins.apfs")==disk&&Bytes("pins.wal")==wal,"pin drift leaves image and WAL exact");
    const auto pins=owner->SnapshotRuntimeCheckpointPins();Check(std::find(pins.begin(),pins.end(),old)!=pins.end(),"sibling pin conserved on refusal");
}
void WireBounds() {
    Fresh("wire.apfs");Tx tx(L"Strict");Configure(tx,"wire.wal");auto owner=Open("wire.apfs",tx);
    SnapshotRuntimePlan plan;std::string error;Check(PrepareSnapshotCreate(*owner,101,"wire",1,0,plan,error),"bounded wire base");
    NativeSnapshotIntent decoded;const auto& wire=plan.request.inline_payload;
    for(std::size_t n=0;n<wire.size();++n)Check(!DecodeNativeSnapshotIntent(std::span(wire).first(n),decoded),"truncated typed intent refuses");
    auto trailing=wire;trailing.push_back(std::byte{0});Check(!DecodeNativeSnapshotIntent(trailing,decoded),"trailing typed intent refuses");
    for(std::size_t at=0;at<wire.size();++at){auto changed=wire;changed[at]^=std::byte{0xff};(void)DecodeNativeSnapshotIntent(changed,decoded);}
    Check(true,"every single-byte mutation decoded within bounded process");
}

void PublicationOverlay() {
    Fresh("overlay.apfs");Tx tx(L"Strict");Configure(tx,"overlay.wal");auto owner=Open("overlay.apfs",tx);
    SnapshotRuntimePlan plan;std::string error;Check(PrepareSnapshotCreate(*owner,101,"overlay",1,0,plan,error),"overlay prepares");
    NativeSnapshotIntent intent;Check(DecodeNativeSnapshotIntent(plan.request.inline_payload,intent),"overlay intent");
    const auto source_slot=owner->FindSessionStore(101)->AuthoritativeAppleCheckpointView()->container.superblock_physical_block;
    Success(ApplySnapshot(*owner,tx,plan));const auto disk=Bytes("overlay.apfs"),wal=Bytes("overlay.wal");
    Check(VerifyPublishedSnapshot(*owner->FindSessionStore(101),intent,error),"exact deterministic publication verifies");
    for(unsigned mode=0;mode<5;++mode){auto bad=intent;
        if(mode==0)bad.checkpoint_slot=512;
        if(mode==1)bad.checkpoint_slot=source_slot;
        if(mode==2)bad.checkpoint_slot_preimage.pop_back();
        if(mode==3)++bad.expected_identity.root_physical_block;
        if(mode==4)bad.publication_hash[0]^=1;
        Check(!VerifyPublishedSnapshot(*owner->FindSessionStore(101),bad,error),"out-of-scope overlay or forged exact publication refuses");
    }
    Check(Bytes("overlay.apfs")==disk&&Bytes("overlay.wal")==wal,"overlay verification never alters evidence");
}
void CloneRecovery(bool published) {
    Fresh("clone-restart.apfs");std::vector<std::byte> original;
    {
        Tx tx(L"Strict");Configure(tx,"clone-restart.wal");auto owner=Open("clone-restart.apfs",tx);
        original=LiveBytes(*owner,L"\\clone0");Create(*owner,tx,"old");
        Store::MutationRequest write;write.operation=Store::MutationOperation::Write;write.path=L"\\clone0";write.length=4*kBlockSize;
        Live(*owner,tx,write,std::vector<std::byte>(4*kBlockSize,std::byte{0x67}));
        Store::MutationRequest clone;Check(owner->FindSessionStore(101)->PrepareNativeClone(L"\\clone0",L"\\recovered",clone),"snapshot-bearing clone prepares");
        owner->FindSessionStore(101)->SetCommitStageHook([=](std::string_view stage){return stage!=(published?"before-apple-final-flush":"before-apple-publish");});
        const auto result=owner->Commit(101,{clone},[&](const auto& requests,const auto& ids,std::uint64_t xid,auto& pins,std::string& error){
            Tx::MutationIntent intent;intent.kind=Tx::MutationKind::CloneFile;intent.path=requests[0].path;intent.secondary_path=requests[0].secondary_path;
            intent.object_id=ids[0].object_id;intent.generation=ids[0].generation;intent.inline_payload=requests[0].inline_payload;intent.length=intent.payload_length=intent.inline_payload.size();HashPayload(intent.inline_payload,intent.payload_checksum);
            return tx.Begin()&&tx.RecordMutation(intent)&&tx.Accept(xid)&&tx.LoadRequiredCheckpointXidsSinceCleanup(pins,&error);
        });Check(!result.committed||result.commit_recovery_required,"clone interruption is not acknowledged");
    }
    for(unsigned restart=0;restart<2;++restart){
        Tx tx(L"Strict");Configure(tx,"clone-restart.wal");auto owner=Open("clone-restart.apfs",tx);std::string error;
        std::vector<Tx::AcceptedTransaction> accepted;Check(tx.LoadAcceptedTransactionsSinceCleanup(accepted,&error),"fresh clone WAL census");
        if(!restart){
            Check(accepted.size()==1,"one retained accepted clone");const auto& receipt=accepted[0];auto* store=owner->FindSessionStore(101);
            if(!published){Store::MutationRequest request;Check(Store::NativeCloneFromWal(receipt.mutations[0],request),"clone WAL decodes on restart");
                Success(owner->Commit(101,{request},{},{},{},true,receipt.preimage_checkpoint_xid));}
            Check(store->ReplayNativeClone(receipt.mutations[0],receipt.preimage_checkpoint_xid)==Store::CloneReplay::AlreadyPublished,"fresh snapshot-bearing clone proves publication");
            Check(tx.MarkApfsDurableThrough(receipt.accepted_sequence)&&tx.MarkCleanedThrough(receipt.accepted_sequence),"clone cleans only after exact proof");
            std::vector<std::uint64_t> pins;Check(tx.LoadRequiredCheckpointXidsSinceCleanup(pins,&error)&&owner->UpdateRequiredCheckpointXids(101,pins,error),"clone recovery retires WAL pins");
        }else Check(accepted.empty(),"second clone restart has no receipt or republication");
        Check(LiveBytes(*owner,L"\\recovered")==std::vector<std::byte>(4*kBlockSize,std::byte{0x67}),"recovered clone has post-snapshot source bytes");
        Observe(*owner,0,original,{std::byte{1},std::byte{2},std::byte{3}});
    }
}
int main(){try {
    const char* mode=std::getenv("APFS_REVIEW_CASE");
    if(mode&&std::string(mode)=="preimage")PreimagePayload(false);
    else if(mode&&std::string(mode)=="published-payload")PreimagePayload(true);
    else if(mode&&std::string(mode)=="drain-acquire")DrainReader(true);
    else if(mode&&std::string(mode)=="drain-read")DrainReader(false);
    else if(mode&&std::string(mode)=="active-read")ActiveReadDrain();
    else {
        const auto root=std::filesystem::current_path();unsigned ordinal=0;
        const auto run=[&](auto test){auto path=root/std::to_string(++ordinal);std::filesystem::create_directory(path);std::filesystem::current_path(path);test();std::filesystem::current_path(root);};
        run([]{DrainReader(false);});run([]{DrainReader(true);});run([]{PreimagePayload(false);});run([]{PreimagePayload(true);});run(ActiveReadDrain);run(PinCensusDrift);run(WireBounds);run(PublicationOverlay);run([]{CloneRecovery(false);});run([]{CloneRecovery(true);});
    }
    std::cout<<"SnapshotRuntimeReviewTests: "<<checks<<" checks, 0 failures\n";return 0;
}catch(const std::exception&e){std::cerr<<"FAIL after "<<checks<<" checks: "<<e.what()<<"\n";return 1;}}
