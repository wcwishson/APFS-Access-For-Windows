#define SNAPSHOT_RUNTIME_TEST_HELPERS_ONLY
#define Configure InheritedSnapshotConfigure
#include "SnapshotRuntimeTests.cpp"
#undef Configure
#include "VolumeMetadata.h"
#include "ApfsRepair.h"
#include "MutationCompactor.h"

namespace {
constexpr const char* kIntegrationUuid = "64906490649064906490649064906490";
void Configure(Tx& journal, const std::filesystem::path& path) {
    journal.SetJournalPath(std::filesystem::absolute(path).wstring());
    journal.SetVolumeIdentity(L"apfs-vol:64906490649064906490649064906490:101");
}
void FreshRepair(const std::filesystem::path& path) {
    auto spec = RuntimeSpec();spec.uuid_hex=kIntegrationUuid;
    std::string error;
    for (auto& volume : spec.volumes)
        Check(SortAppleBtreeRecords(volume.filesystem_records, AppleBtreeKeyOrder::FileSystemHashedDirectory, error),
            "sort complete ordinary repair census: " + error);
    Fresh(path, spec);
}
void DamageCount(const std::filesystem::path& path) {
    auto image = Bytes(path);
    VectorRandomAccessSource source(image);
    std::string error;
    const auto checkpoint = LoadAppleCheckpointView(source, 0, image.size(), error);
    Check(!!checkpoint, "load count damage preimage: " + error);
    const auto block = checkpoint->volumes[0].superblock_object.physical_block;
    std::vector<std::byte> apsb(image.begin() + block * kBlockSize, image.begin() + (block + 1) * kBlockSize);
    PutU64LE(apsb, 0xb8, 99);
    Check(FinalizeAppleObjectChecksum(apsb, error), "checksum typed count damage");
    std::copy(apsb.begin(), apsb.end(), image.begin() + block * kBlockSize);
    Save(path, image);
}


void QuotaApply(Owner& owner, Tx& journal, std::uint64_t quota=64, std::uint64_t reserve=20) {
    VolumeQuotaReservePlan plan; std::string error;
    const bool prepared=PrepareVolumeQuotaReserve(owner,101,quota,reserve,plan,error);
    Check(prepared,"combined quota preparation: "+error);
    Success(ApplyVolumeQuotaReserve(owner,journal,plan));
}
void RepairQuotaSnapshotTransition() {
    FreshRepair("transition.apfs"); DamageCount("transition.apfs");
    Tx journal(L"Strict");Configure(journal,"transition.wal");auto owner=Open("transition.apfs",journal);
    const auto original=LiveBytes(*owner,L"\\clone0");std::string error;ApfsCountRepairPlan repair;
    Check(PrepareApfsCountRepair(*owner,101,repair,error),"repair before quota: "+error);
    QuotaApply(*owner,journal);
    ApfsCountRepairPlan currentRepair;Check(PrepareApfsCountRepair(*owner,101,currentRepair,error),"refresh repair after quota: "+error);
    Success(ApplyApfsCountRepair(*owner,journal,currentRepair,currentRepair.ConfirmationToken()));
    VolumeQuotaReservePlan historical;
    Check(!PrepareVolumeQuotaReserve(*owner,101,96,8,historical,error)&&error=="VolumeQuotaReserveExactChargedAllocationUnproven","repair historical charges remain conservatively refused: "+error);
    Check(LiveBytes(*owner,L"\\clone0")==original,"repair/quota keep payload");
    Create(*owner,journal,"after-quota");Observe(*owner,0,original,{std::byte{1},std::byte{2},std::byte{3}});
    auto id=List(*owner).at(0).identity;auto reader=owner->AcquireSnapshotReader(id,error);Check(!!reader,"reader pin after quota");
    auto image=Bytes("transition.apfs"),wal=Bytes("transition.wal");VolumeQuotaReservePlan rejected;
    Check(!PrepareVolumeQuotaReserve(*owner,101,96,8,rejected,error),"quota refuses snapshot-bearing source with runtime enabled");
    Check(Bytes("transition.apfs")==image&&Bytes("transition.wal")==wal,"snapshot quota refusal conserves image and WAL");
    std::vector<std::byte> read;Check(reader->Read(17,0,original.size(),read)&&read==original,"quota refusal preserves historical reader");
    Check(owner->DrainAndStop(std::chrono::seconds(2)).clean,"combined owner drain");
}
void PlansCrossSourceChanges() {
    FreshRepair("stale.apfs");DamageCount("stale.apfs");
    Tx journal(L"Strict");Configure(journal,"stale.wal");auto owner=Open("stale.apfs",journal);std::string error;
    ApfsCountRepairPlan repair;Check(PrepareApfsCountRepair(*owner,101,repair,error),"prepare repair before quota change: "+error);
    QuotaApply(*owner,journal);auto image=Bytes("stale.apfs"),wal=Bytes("stale.wal");
    const auto stale=ApplyApfsCountRepair(*owner,journal,repair,repair.ConfirmationToken());
    Check(!stale.committed&&!stale.commit_recovery_required,"quota checkpoint invalidates prepared repair before acceptance");
    Check(Bytes("stale.apfs")==image&&Bytes("stale.wal")==wal,"stale repair keeps quota publication and WAL");
    VolumeQuotaReservePlan quota;Check(PrepareVolumeQuotaReserve(*owner,101,96,8,quota,error),"prepare quota before repair: "+error);
    ApfsCountRepairPlan fresh;Check(PrepareApfsCountRepair(*owner,101,fresh,error),"reprepare bound repair: "+error);
    Success(ApplyApfsCountRepair(*owner,journal,fresh,fresh.ConfirmationToken()));image=Bytes("stale.apfs");wal=Bytes("stale.wal");
    const auto refused=ApplyVolumeQuotaReserve(*owner,journal,quota);
    Check(!refused.committed&&!refused.commit_recovery_required,"repair checkpoint invalidates quota plan before acceptance");
    Check(Bytes("stale.apfs")==image&&Bytes("stale.wal")==wal,"stale quota preserves repaired publication and WAL");
    VolumeQuotaReservePlan historical;Check(!PrepareVolumeQuotaReserve(*owner,101,96,8,historical,error),"new quota also refuses retained historical repair charge");Create(*owner,journal,"bound");
}
void AcceptedQuotaExcludesNeighbors() {
    for(bool published:{false,true}) {
        const std::string stem=published?"published":"unpublished";auto path=stem+".apfs",walpath=stem+".wal";
        FreshRepair(path);DamageCount(path);
        {Tx journal(L"Strict");Configure(journal,walpath);auto owner=Open(path,journal);std::string error;VolumeQuotaReservePlan quota;
            Check(PrepareVolumeQuotaReserve(*owner,101,64,20,quota,error),"prepare accepted quota: "+error);
            if(published)quota.fault_hook_for_tests=[](std::string_view stage){return stage=="before-cleanup";};
            else owner->FindSessionStore(101)->SetCommitStageHook([](std::string_view stage){return stage!="before-apple-publish";});
            auto result=ApplyVolumeQuotaReserve(*owner,journal,quota);std::vector<Tx::AcceptedTransaction> debt;Check(result.commit_recovery_required&&journal.LoadAcceptedTransactionsSinceCleanup(debt)&&debt.size()==1,"retain actual quota WAL: "+result.error);}
        Tx journal(L"Strict");Configure(journal,walpath);auto owner=Open(path,journal);std::string error;
        auto image=Bytes(path),wal=Bytes(walpath);ApfsCountRepairPlan repair;SnapshotRuntimePlan snapshot;
        if(!published) {
            Check(!PrepareApfsCountRepair(*owner,101,repair,error)&&error=="InspectionAcceptedOwnerConflict","quota debt excludes bounded repair: "+error);
            Check(!PrepareSnapshotCreate(*owner,101,"blocked",1,0,snapshot,error)&&error=="SnapshotRuntimeAcceptedOwnerConflict","quota debt excludes snapshots: "+error);
        } else {
            Check(PrepareApfsCountRepair(*owner,101,repair,error),"durable retained owner permits repair preview: "+error);
            Check(!ApplyApfsCountRepair(*owner,journal,repair,repair.ConfirmationToken()).committed,"retained selected WAL blocks repair acceptance");
            Check(PrepareSnapshotCreate(*owner,101,"blocked",1,0,snapshot,error),"durable retained owner permits snapshot preview: "+error);
            Check(!ApplySnapshot(*owner,journal,snapshot).committed,"retained selected WAL blocks snapshot acceptance");
        }
        Check(!ReplayApfsCountRepair(*owner,journal,101,error).has_value()&&!ReplaySnapshot(*owner,journal,101,error).has_value(),"neighbor replay declines QRS1 without fallback publication");
        Check(Bytes(path)==image&&Bytes(walpath)==wal,"neighbor refusal preserves quota evidence");
        Check(ReplayVolumeQuotaReserve(*owner,journal,101,error).value_or(false),"quota replay with merged owner: "+error);
        Check(!ReplayVolumeQuotaReserve(*owner,journal,101,error).has_value(),"quota replay cleans once");
        ApfsCountRepairPlan recoveredRepair;Check(PrepareApfsCountRepair(*owner,101,recoveredRepair,error),"repair after quota recovery: "+error);
        Success(ApplyApfsCountRepair(*owner,journal,recoveredRepair,recoveredRepair.ConfirmationToken()));Create(*owner,journal,"after-recovery");
    }
}
void AcceptedNeighborsExcludeQuota() {
    for(bool snapshot:{false,true}) {
        const std::string stem=snapshot?"snapshot":"repair";auto path=stem+".apfs",walpath=stem+".wal";FreshRepair(path);DamageCount(path);
        {Tx journal(L"Strict");Configure(journal,walpath);auto owner=Open(path,journal);std::string error;
            owner->FindSessionStore(101)->SetCommitStageHook([](std::string_view stage){return stage!="before-apple-publish";});
            if(snapshot){SnapshotRuntimePlan plan;Check(PrepareSnapshotCreate(*owner,101,"pending",1,0,plan,error),"prepare snapshot debt");Check(ApplySnapshot(*owner,journal,plan).commit_recovery_required,"snapshot retained");}
            else {ApfsCountRepairPlan plan;Check(PrepareApfsCountRepair(*owner,101,plan,error),"prepare repair debt: "+error);Check(ApplyApfsCountRepair(*owner,journal,plan,plan.ConfirmationToken()).commit_recovery_required,"repair retained");}}
        Tx journal(L"Strict");Configure(journal,walpath);auto owner=Open(path,journal);std::string error;auto image=Bytes(path),wal=Bytes(walpath);VolumeQuotaReservePlan quota;
        Check(!PrepareVolumeQuotaReserve(*owner,101,64,20,quota,error),"accepted neighbor excludes quota");
        Check(!ReplayVolumeQuotaReserve(*owner,journal,101,error).has_value(),"quota replay declines neighbor intent");
        Check(Bytes(path)==image&&Bytes(walpath)==wal,"quota refusal preserves neighbor source and WAL");
        Check((snapshot?ReplaySnapshot(*owner,journal,101,error):ReplayApfsCountRepair(*owner,journal,101,error)).value_or(false),"neighbor recovery after quota refusal: "+error);
        if(!snapshot){VolumeQuotaReservePlan historical;Check(!PrepareVolumeQuotaReserve(*owner,101,64,20,historical,error),"repaired historical charge stays outside quota profile");}
    }
}
void SharedWireBoundaries() {
    FreshRepair("wire.apfs");Tx journal(L"Strict");Configure(journal,"wire.wal");auto owner=Open("wire.apfs",journal);std::string error;VolumeQuotaReservePlan quota;
    Check(PrepareVolumeQuotaReserve(*owner,101,64,20,quota,error),"wire quota: "+error);
    WriteAheadLog::Record record;record.operation=WriteAheadLog::OperationKind::SetVolumeQuotaReserve;record.path_utf8="\\";record.volume_identity="apfs-vol:64906490649064906490649064906490:101";
    record.object_id=101;record.parent_object_id=owner->CheckpointXid()+1;record.transaction_id=1;record.sequence=1;record.inline_payload=quota.request.inline_payload;record.payload_length=record.inline_payload.size();HashPayload(record.inline_payload,record.payload_sha256);
    Check(!WriteAheadLog::EncodeForTest(record,2).empty(),"QRS1 canonical inline WAL");
    Check(WriteAheadLog::EncodeForTest(record,1).empty(),"QRS1 cannot downgrade WAL envelope");
    for(auto opcode:{17,18,19,24,25}){auto bad=record;bad.operation=static_cast<WriteAheadLog::OperationKind>(opcode);Check(WriteAheadLog::EncodeForTest(bad).empty(),"QRS1 rejects relabel as rename/snapshot/repair/reserved");}
    using Kind=MutationCompactor::MutationKind;
    for(auto kind:{Kind::CreateSnapshot,Kind::DeleteSnapshot,Kind::SetVolumeQuotaReserve,Kind::RepairVolumeFileCount}){
        auto summary=MutationCompactor::Summarize({{Kind::Write,L"\\file",L"",4},{kind,L"\\",L"",0},{Kind::Write,L"\\file",L"",8}});
        Check(summary.compacted_mutation_count==3&&summary.payload_paths.size()==1,"all management barriers retain ordered writes");}
    SnapshotRuntimePlan snapshot;Check(PrepareSnapshotCreate(*owner,101,"typed",1,0,snapshot,error),"snapshot wire prepare");
    for(const auto& request:{quota.request,snapshot.request}) {
        auto* store=owner->FindSessionStore(101);Check(store->StageMutation(request)==Store::MutationStatus::Applied,"isolated management stage");
        Check(store->StageMutation(request.operation==Store::MutationOperation::SetVolumeQuotaReserve?snapshot.request:quota.request)!=Store::MutationStatus::Applied,"quota/snapshot cannot share metadata transaction");
        auto& prepared=journal;
        Tx::MutationIntent intent;intent.kind=static_cast<Tx::MutationKind>(request.operation);intent.path=request.path;intent.object_id=request.object_id;intent.generation=request.generation;
        intent.inline_payload=request.inline_payload;intent.length=intent.payload_length=intent.inline_payload.size();HashPayload(intent.inline_payload,intent.payload_checksum);
        Check(prepared.Begin(),"canonical prepared metadata begin");
        Check(prepared.RecordMutation(intent),"canonical prepared metadata record");
        Check(!prepared.FlushPreparedRecords(),"prepared typed management records cannot flush before acceptance");
        Check(prepared.Abort(),"prepared isolated metadata abort");
        owner.reset();owner=Open("wire.apfs",journal);
    }
}
void RepairRawReservationBoundary() {
    FreshRepair("reservation.apfs");DamageCount("reservation.apfs");Tx journal(L"Strict");Configure(journal,"reservation.wal");auto owner=Open("reservation.apfs",journal);std::string error;
    auto* store=owner->FindSessionStore(101);auto allocation=store->AllocateExtent(1);Check(allocation.has_value()&&store->HasUncommittedAllocatorState(),"raw reservation has working allocator state");
    auto image=Bytes("reservation.apfs"),wal=Bytes("reservation.wal");ApfsCountRepairPlan repair;
    Check(!PrepareApfsCountRepair(*owner,101,repair,error),"repair inspection refuses raw allocation reservation");
    Check(!owner->RefreshSessionForRecovery(101,error),"shared recovery refresh refuses raw allocation reservation");
    Check(store->HasUncommittedAllocatorState()&&Bytes("reservation.apfs")==image&&Bytes("reservation.wal")==wal,"shared inspection/refresh retain reservation and bytes");
}
void LateManagementReservations() {
    for(bool snapshot:{false,true})for(auto oid:{101ull,102ull}) {
        const auto stem=std::string(snapshot?"snapshot-":"repair-")+std::to_string(oid);const auto path=stem+".apfs",walpath=stem+".wal";
        FreshRepair(path);DamageCount(path);Tx journal(L"Strict");Configure(journal,walpath);auto owner=Open(path,journal);std::string error;
        ApfsCountRepairPlan repair;SnapshotRuntimePlan snap;
        Check(snapshot?PrepareSnapshotCreate(*owner,101,"pending",1,0,snap,error):PrepareApfsCountRepair(*owner,101,repair,error),"prepare before selected/sibling raw reservation: "+error);
        auto* reserved=owner->FindSessionStore(oid);Check(reserved->AllocateExtent(1).has_value()&&reserved->HasUncommittedAllocatorState(),"late raw selected/sibling reservation");
        const auto image=Bytes(path),wal=Bytes(walpath);
        const auto result=snapshot?ApplySnapshot(*owner,journal,snap):ApplyApfsCountRepair(*owner,journal,repair,repair.ConfirmationToken());
        Check(!result.committed&&!result.commit_recovery_required&&result.error=="NativeManagementActiveSessionReservation","management refuses before reload can discard raw reservation: "+result.error);
        Check(reserved->HasUncommittedAllocatorState()&&!journal.Watermarks().accepted_sequence,"refusal retains raw reservation before WAL acceptance");
        Check(Bytes(path)==image&&Bytes(walpath)==wal,"late selected/sibling reservation refusal is byte preserving");
    }
}
void RawRecoveryRefresh() {
    FreshRepair("refresh.apfs");Tx journal(L"Strict");Configure(journal,"refresh.wal");auto owner=Open("refresh.apfs",journal);std::string error;
    auto* store=owner->FindSessionStore(101);Check(store->AllocateExtent(1).has_value()&&store->HasUncommittedAllocatorState(),"raw refresh reservation");
    const auto image=Bytes("refresh.apfs"),wal=Bytes("refresh.wal");
    Check(!owner->RefreshSessionForRecovery(101,error)&&error=="RecoveryRefreshUnexpectedPendingState","shared recovery reload refuses raw reservation: "+error);
    Check(store->HasUncommittedAllocatorState()&&Bytes("refresh.apfs")==image&&Bytes("refresh.wal")==wal,"recovery refresh conserves allocator and bytes");
}
void MissingCanonicalJournal() {
    FreshRepair("missing-wal.apfs");Tx actual(L"Strict");Configure(actual,"actual.wal");auto owner=Open("missing-wal.apfs",actual);std::string error;
    VolumeQuotaReservePlan quota;Check(PrepareVolumeQuotaReserve(*owner,101,64,20,quota,error),"plan for missing-journal refusal: "+error);
    Tx noPath(L"Strict");noPath.SetVolumeIdentity(L"apfs-vol:64906490649064906490649064906490:101");
    const auto image=Bytes("missing-wal.apfs"),wal=Bytes("actual.wal");const auto result=ApplyVolumeQuotaReserve(*owner,noPath,quota);
    Check(!result.committed&&!result.commit_recovery_required,"missing canonical path refuses before creating false accepted recovery debt: "+result.error);
    Check(Bytes("missing-wal.apfs")==image&&Bytes("actual.wal")==wal&&!noPath.Watermarks().accepted_sequence,"missing journal refusal preserves source, real WAL, and acceptance");
    Check(noPath.CurrentState()==Tx::State::Idle,"missing journal cannot begin a substitute transaction");
}
}
int main(int argc,char**argv) {
    try {std::string group=argc>1?argv[1]:"all";const auto root=std::filesystem::current_path();unsigned ordinal=0;
        const auto run=[&](const char*name,auto test){if(group!="all"&&group!=name)return;auto path=root/("quota-"+std::to_string(++ordinal));std::filesystem::create_directory(path);std::filesystem::current_path(path);test();std::filesystem::current_path(root);std::cout<<"PASS "<<name<<"\n";};
        run("transition",RepairQuotaSnapshotTransition);run("stale",PlansCrossSourceChanges);run("quota-debt",AcceptedQuotaExcludesNeighbors);run("neighbor-debt",AcceptedNeighborsExcludeQuota);run("wire",SharedWireBoundaries);run("reservation",RepairRawReservationBoundary);run("late-reservation",LateManagementReservations);run("refresh",RawRecoveryRefresh);run("missing-journal",MissingCanonicalJournal);
        std::cout<<"QuotaRepairSnapshotIntegrationTests: "<<checks<<" checks, 0 failures\n";return 0;
    }catch(const std::exception&error){std::cerr<<"FAIL after "<<checks<<" checks: "<<error.what()<<'\n';return 1;}
}
