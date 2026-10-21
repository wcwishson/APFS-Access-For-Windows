#include <windows.h>
#undef CreateFile
#undef CreateDirectory
#include "VolumeQuotaReserveTestHelpers.h"
#include "ApfsVerifier.h"
#include "VolumeManagementTestFixture.h"
#include <set>

namespace {
Fixture QuotaFixture() { auto spec=RenameSpec();std::string error;for(auto& v:spec.volumes)for(auto& r:v.filesystem_records)if(Type(r)==3){AppleInodeRecord i;Check(ApfsExtendedRecordCodec::DecodeInode(r,i,error),error);for(auto& x:i.extended_fields)x.flags=0;Check(EncodeAppleInodeRecord(i,r,error),error);}for(auto& v:spec.volumes)Check(SortAppleBtreeRecords(v.filesystem_records,AppleBtreeKeyOrder::FileSystemHashedDirectory,error),"sort fixture");Fixture f(spec); auto at=f.checkpoint.container_object_map.object.physical_block*kBlockSize; std::vector<std::byte> b(f.image.begin()+at,f.image.begin()+at+kBlockSize); PutU32LE(b,0x20,1);FletcherForBlock(b,b.size());std::copy(b.begin(),b.end(),f.image.begin()+at);f.Reload();return f; }
void CreateOriginalEmptyWal(const std::filesystem::path& path) {
    const auto h=CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,nullptr,
        CREATE_NEW,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    Check(h!=INVALID_HANDLE_VALUE,"original empty WAL created exclusively");CloseHandle(h);
}
apfsaccess::rw::VolumeManagementRequest QuotaOriginalWals(const std::filesystem::path& image) {
    auto bytes=ReadImage(image);VectorRandomAccessSource source(bytes);std::string error;
    const auto cp=LoadAppleCheckpointView(source,0,source.SizeBytes(),error);Check(!!cp,error);
    apfsaccess::rw::VolumeManagementRequest request;request.image=image;
    request.container_uuid=cp->container.superblock.uuid_hex;
    for(auto oid:{101ull,102ull})request.sibling_wals[oid]=std::filesystem::absolute(std::to_string(oid)+".wal");
    return request;
}
void RetainProductionQuotaReceipt(const std::filesystem::path& path,bool published,
    const std::filesystem::path& wal=std::filesystem::absolute("101.wal"),std::uint64_t configured_oid=101) {
    const auto before=ReadImage(path);auto owner=OpenOwner(path);std::string error;
    VolumeQuotaReservePlan plan;Check(PrepareVolumeQuotaReserve(*owner,101,64,20,plan,error),"original quota receipt plan: "+error);
    NativeVolumeQuotaReserve decoded;Check(DecodeNativeVolumeQuotaReserve(plan.request.inline_payload,decoded),"native quota intent decodes");
    const auto identity=DerivePartitionlessVolumeRecoveryIdentity(owner->ContainerUuidHex(),configured_oid);
    Tx journal(L"Strict");journal.SetJournalPath(wal.wstring());
    journal.SetVolumeIdentity(std::wstring(identity.begin(),identity.end()));
    const auto canonical="apfs-vol:"+owner->ContainerUuidHex()+":101";
    Check(journal.EnrollCanonicalJournalIdentity(std::wstring(canonical.begin(),canonical.end()))&&journal.AcquireJournalOwnership(error),
        "original production journal owner and canonical enrollment: "+error);
    Tx::MutationIntent intent;intent.kind=Tx::MutationKind::SetVolumeQuotaReserve;intent.path=L"\\";
    intent.object_id=101;intent.generation=decoded.checkpoint+1;intent.inline_payload=plan.request.inline_payload;
    intent.length=intent.payload_length=intent.inline_payload.size();
    BCRYPT_ALG_HANDLE algorithm{};Check(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,nullptr,0)>=0,"native quota receipt hash provider");
    const auto hashed=BCryptHash(algorithm,nullptr,0,reinterpret_cast<PUCHAR>(intent.inline_payload.data()),
        static_cast<ULONG>(intent.inline_payload.size()),intent.payload_checksum.data(),static_cast<ULONG>(intent.payload_checksum.size()));
    BCryptCloseAlgorithmProvider(algorithm,0);Check(hashed>=0,"native quota receipt hash");
    Check(journal.Begin()&&journal.RecordMutation(intent)&&journal.Accept(decoded.checkpoint),"real production operation20 acceptance");
    const auto accepted=journal.Watermarks().accepted_sequence;
    std::vector<std::uint64_t> pins;
    Check(accepted&&journal.LoadRequiredCheckpointXidsSinceCleanup(pins,&error)&&
        owner->UpdateRequiredCheckpointXids(101,pins,error,true),"original accepted operation20 pins: "+error);
    if(published) {
        const auto result=owner->Commit(101,{plan.request},{},{},{},true,decoded.checkpoint,{},
            [&](const Store& live,std::uint64_t,std::string& why){return VerifyPublishedVolumeRename(live,decoded,why);});
        CheckSuccess(result);
        Check(journal.MarkApfsDurableThrough(accepted),"real published quota durable watermark");
        Check(owner->CheckpointXid()==decoded.checkpoint+1&&ReadImage(path)!=before,"real native quota publication advances checkpoint");
    } else Check(ReadImage(path)==before,"unpublished accepted production quota leaves image unchanged");
    std::vector<Tx::AcceptedTransaction> debt;
    Check(journal.LoadAcceptedTransactionsSinceCleanup(debt,&error)&&debt.size()==1&&debt.front().mutations.size()==1&&
        debt.front().mutations.front().operation==WriteAheadLog::OperationKind::SetVolumeQuotaReserve&&
        debt.front().mutations.front().volume_identity==identity&&journal.Watermarks().cleanup_sequence<accepted,
        "original production target operation20 debt remains recoverable");
}
void ProductionQuotaCommandFixture(const std::filesystem::path& path,const std::string& group) {
    auto request=QuotaOriginalWals(path);
    if(group=="production-unknown") {
        apfsaccess::volume_management_test::ProvisionOriginalWal(request,101,true);
        request.sibling_wals[101]=std::filesystem::absolute("102.wal");
        apfsaccess::volume_management_test::ProvisionOriginalWal(request,101,true);
    } else {
        apfsaccess::volume_management_test::ProvisionOriginalWals(request,group!="canonical");
        if(group=="production-mixed") {
            auto other=std::filesystem::absolute("mixed-source.apfs");SaveImage(other,QuotaFixture().image);
            auto canonical=QuotaOriginalWals(other);canonical.sibling_wals[102]=std::filesystem::absolute("canonical-peer.wal");
            apfsaccess::volume_management_test::ProvisionOriginalWal(canonical,102,false);
            auto mixed=ReadImage("102.wal"),suffix=ReadImage("canonical-peer.wal");
            mixed.insert(mixed.end(),suffix.begin(),suffix.end());SaveImage("102.wal",mixed);
            const auto records=WriteAheadLog::ReadAll("102.wal","");
            Check(records.status==WriteAheadLog::ReadStatus::Ok&&!records.recovered_torn_tail,"mixed identities retain actual CRC-valid native records");
            std::set<std::string> identities;for(const auto& record:records.records)identities.insert(record.volume_identity);
            Check(identities.size()==2,"mixed original peer contains both native identity histories");
        } else if(group=="production-accepted"||group=="production-accepted-unpublished")
            RetainProductionQuotaReceipt(path,group=="production-accepted");
    }
    if(group!="production-unknown"&&group!="production-mixed")for(auto oid:{101ull,102ull}) {
        const auto identity=group=="canonical"?"apfs-vol:"+request.container_uuid+":"+std::to_string(oid):
            DerivePartitionlessVolumeRecoveryIdentity(request.container_uuid,oid);
        const auto wal=std::filesystem::absolute(std::to_string(oid)+".wal");
        const auto records=WriteAheadLog::ReadAll(wal,identity);
        Check(records.status==WriteAheadLog::ReadStatus::Ok&&!records.recovered_torn_tail&&!records.records.empty(),"actual original production WAL records");
        for(const auto& record:records.records)Check(record.volume_identity==identity,"every native record retains exact derived original identity");
        std::vector<Tx::AcceptedTransaction> debt;Tx::DurabilityWatermarks marks{};std::string error;
        Check(Tx::InspectAcceptedTransactionsReadOnly(wal,identity,debt,marks,error)&&marks.cleanup_sequence,
            "real original production WAL validates: "+error);
        if(oid==102||group=="production"||group=="canonical")Check(debt.empty()&&marks.accepted_sequence==marks.apfs_durable_sequence&&
            marks.cleanup_sequence==marks.accepted_sequence,"actual original clean transaction on each production peer");
    }
}
void ProductionQuotaAuthorityRefusals() {
    const auto same_marks=[](const Tx::DurabilityWatermarks& a,const Tx::DurabilityWatermarks& b) {
        return a.accepted_sequence==b.accepted_sequence&&a.apfs_durable_sequence==b.apfs_durable_sequence&&
            a.cleanup_sequence==b.cleanup_sequence;
    };
    for(const std::string mode:{"unenrolled","wrong-enrollment","wrong-derived-oid"}) {
        const auto stem="production-authority-"+mode;
        const auto image=std::filesystem::absolute(stem+".apfs"),wal=std::filesystem::absolute(stem+".wal");
        SaveImage(image,QuotaFixture().image);auto original=QuotaOriginalWals(image);
        const auto configured_oid=mode=="wrong-derived-oid"?102ull:101ull;
        original.sibling_wals[configured_oid]=wal;
        apfsaccess::volume_management_test::ProvisionOriginalWal(original,configured_oid,true);
        const auto identity=DerivePartitionlessVolumeRecoveryIdentity(original.container_uuid,configured_oid);
        Tx journal(L"Strict");journal.SetVolumeIdentity(std::wstring(identity.begin(),identity.end()));
        journal.SetJournalPath(wal.wstring());std::string error;
        Check(journal.RecoveryStateValid()&&journal.AcquireJournalOwnership(error),"real original production refusal journal owner: "+error);
        if(mode!="unenrolled") {
            const auto canonical="apfs-vol:"+original.container_uuid+":"+(mode=="wrong-enrollment"?"102":"101");
            Check(journal.EnrollCanonicalJournalIdentity(std::wstring(canonical.begin(),canonical.end())),"enroll exact negative witness");
        } else Check(journal.EnrolledCanonicalJournalIdentity().empty(),"production journal starts without enrollment");
        auto owner=OpenOwner(image);VolumeQuotaReservePlan plan;
        Check(PrepareVolumeQuotaReserve(*owner,101,64,20,plan,error),"production authority refusal has a valid native plan: "+error);
        const auto before=ReadImage(image),beforewal=ReadImage(wal);const auto marks=journal.Watermarks();
        Check(marks.accepted_sequence&&marks.accepted_sequence==marks.cleanup_sequence&&
            marks.accepted_sequence==marks.apfs_durable_sequence,"refusal starts from real clean production history");
        const auto result=ApplyVolumeQuotaReserve(*owner,journal,plan);
        Check(!result.committed&&!result.commit_recovery_required&&result.error=="VolumeQuotaReservePlanOrJournalBindingMismatch",
            "exact production authority Apply refusal "+mode+": "+result.error);
        Check(ReadImage(image)==before&&ReadImage(wal)==beforewal&&same_marks(journal.Watermarks(),marks),
            "production authority Apply refusal preserves whole image/WAL/all watermarks "+mode);
        std::cout<<"PASS production authority Apply "<<mode<<" error="<<result.error<<"\n";
    }
    for(const auto& [mode,published]:std::vector<std::pair<std::string,bool>>{
        {"unenrolled",false},{"unenrolled",true},{"wrong-enrollment",false},{"wrong-derived-oid",false}}) {
        const auto stem=std::string("production-authority-replay-")+mode+(published?"-published":"-unpublished");
        const auto image=std::filesystem::absolute(stem+".apfs"),wal=std::filesystem::absolute(stem+".wal");
        SaveImage(image,QuotaFixture().image);auto original=QuotaOriginalWals(image);
        const auto configured_oid=mode=="wrong-derived-oid"?102ull:101ull;original.sibling_wals[configured_oid]=wal;
        apfsaccess::volume_management_test::ProvisionOriginalWal(original,configured_oid,true);
        RetainProductionQuotaReceipt(image,published,wal,configured_oid);
        const auto identity=DerivePartitionlessVolumeRecoveryIdentity(original.container_uuid,configured_oid);
        Tx journal(L"Strict");journal.SetVolumeIdentity(std::wstring(identity.begin(),identity.end()));
        journal.SetJournalPath(wal.wstring());std::string error;
        Check(journal.RecoveryStateValid()&&journal.AcquireJournalOwnership(error),"fresh original production replay owner: "+error);
        if(mode!="unenrolled") {
            const auto canonical="apfs-vol:"+original.container_uuid+":"+(mode=="wrong-enrollment"?"102":"101");
            Check(journal.EnrollCanonicalJournalIdentity(std::wstring(canonical.begin(),canonical.end())),"enroll exact Replay negative witness");
        } else Check(journal.EnrolledCanonicalJournalIdentity().empty(),"fresh production Replay owner has no canonical enrollment");
        std::vector<Tx::AcceptedTransaction> debt;
        Check(journal.LoadAcceptedTransactionsSinceCleanup(debt,&error)&&debt.size()==1&&debt.front().mutations.size()==1&&
            debt.front().mutations.front().operation==WriteAheadLog::OperationKind::SetVolumeQuotaReserve&&
            debt.front().mutations.front().object_id==101&&debt.front().mutations.front().volume_identity==identity,
            "fresh owner retains actual production operation20 debt: "+error);
        auto owner=OpenOwner(image,&journal);
        const auto before=ReadImage(image),beforewal=ReadImage(wal);const auto marks=journal.Watermarks();
        const auto result=ReplayVolumeQuotaReserve(*owner,journal,101,error);
        Check(result==std::optional<bool>{false}&&error=="VolumeQuotaReserveReplayJournalIdentityMismatch",
            "exact production Replay authority refusal "+mode+": "+error);
        Check(ReadImage(image)==before&&ReadImage(wal)==beforewal&&same_marks(journal.Watermarks(),marks),
            "production Replay authority refusal preserves whole image/WAL/all watermarks "+mode);
        std::vector<Tx::AcceptedTransaction> retained;
        Check(journal.LoadAcceptedTransactionsSinceCleanup(retained,&error)&&retained.size()==1&&
            retained.front().accepted_sequence==debt.front().accepted_sequence&&
            retained.front().preimage_checkpoint_xid==debt.front().preimage_checkpoint_xid&&retained.front().mutations.size()==1&&
            retained.front().mutations.front().inline_payload==debt.front().mutations.front().inline_payload&&
            retained.front().mutations.front().volume_identity==identity,
            "production Replay authority refusal preserves exact original receipt and preimage "+mode);
        std::cout<<"PASS production authority Replay "<<mode<<" "<<(published?"published":"unpublished")<<"\n";
    }
}
void VerifyQuotaCommandFixture(const std::filesystem::path& dir,const std::string& group) {
    const auto image=dir/"fixture.apfs";const auto bytes=ReadImage(image);
    VectorRandomAccessSource source(bytes);std::string error;
    const auto cp=LoadAppleCheckpointView(source,0,source.SizeBytes(),error);Check(!!cp,error);
    const bool clear=group.ends_with("-clear");
    Check(cp->volumes[0].superblock.space.quota_block_count==(clear?0:64)&&
        cp->volumes[0].superblock.space.reserve_block_count==(clear?0:20),"fresh native quota/reserve pair");
    for(auto oid:{101ull,102ull}) {
        const auto identity=group.starts_with("verify-canonical")&&oid==101?
            "apfs-vol:"+cp->container.superblock.uuid_hex+":"+std::to_string(oid):
            DerivePartitionlessVolumeRecoveryIdentity(cp->container.superblock.uuid_hex,oid);
        const auto wal=dir/(std::to_string(oid)+".wal");
        const auto records=WriteAheadLog::ReadAll(wal,"");
        Check(records.status==WriteAheadLog::ReadStatus::Ok&&!records.recovered_torn_tail,"fresh strict original WAL readback");
        if(oid==101) {
            Check(!records.records.empty(),"target original WAL contains actual native history");
            for(const auto& record:records.records)Check(record.volume_identity==identity,"exact target original WAL identity retained");
            Check(std::any_of(records.records.begin(),records.records.end(),[](const auto& record){
                return record.operation==WriteAheadLog::OperationKind::SetVolumeQuotaReserve;
            }),"actual operation20 present after command");
        } else for(const auto& record:records.records)Check(record.volume_identity==identity||
            (group=="verify-canonical-history"&&record.volume_identity=="apfs-vol:"+cp->container.superblock.uuid_hex+":102"),
            "legal peer identity retained");
        std::vector<Tx::AcceptedTransaction> debt;Tx::DurabilityWatermarks marks{};
        const auto selected=records.records.empty()?identity:records.records.front().volume_identity;
        Check(Tx::InspectAcceptedTransactionsReadOnly(wal,selected,debt,marks,error)&&debt.empty()&&
            marks.accepted_sequence==marks.apfs_durable_sequence&&marks.accepted_sequence==marks.cleanup_sequence,
            "native publication leaves exact clean original watermarks: "+error);
        if(oid==101)Check(marks.cleanup_sequence>0,"native target cleanup progressed");
    }
    auto owner=OpenOwner(image);const auto initial=QuotaFixture();
    for(auto oid:{101ull,102ull}) {
        std::vector<std::byte> payload;
        Check(owner->FindSessionStore(oid)->ReadCommittedFileRange(L"\\clone0",0,4*kBlockSize,payload)&&
            payload.size()==4*kBlockSize&&std::equal(payload.begin(),payload.end(),initial.image.begin()+(oid==101?128:144)*kBlockSize),
            "fresh native readback preserves both volume payloads");
    }
}
void HoldQuotaWal(const std::filesystem::path& dir,const std::string& group) {
    const auto oid=group.ends_with("101")?101ull:102ull;
    auto request=QuotaOriginalWals(dir/"fixture.apfs");
    const auto identity=group.starts_with("hold-production-")?DerivePartitionlessVolumeRecoveryIdentity(request.container_uuid,oid):
        "apfs-vol:"+request.container_uuid+":"+std::to_string(oid);
    WriteAheadLog owner({dir/(std::to_string(oid)+".wal"),identity});
    Check(owner.AcquireWriterLeaseOnly(),"actual legal identity WAL guard lease");
    {std::ofstream ready(dir/"wal-hold.ready");ready<<identity<<'\n';Check(!!ready,"WAL guard ready");}
    const auto deadline=GetTickCount64()+30000;
    while(!std::filesystem::exists(dir/"wal-hold.stop")&&GetTickCount64()<deadline)Sleep(10);
    Check(std::filesystem::exists(dir/"wal-hold.stop"),"bounded WAL guard release");
}
void ObserveLimits(const std::filesystem::path& path, const Fixture& f, std::uint64_t quota, std::uint64_t reserve) {
    auto bytes=ReadImage(path); VectorRandomAccessSource source(bytes); std::string error;
    auto cp=LoadAppleCheckpointView(source,0,source.SizeBytes(),error); Check(!!cp,"fresh native checkpoint: "+error);
    const auto& v=cp->volumes[0]; const auto& before=f.checkpoint.volumes[0];
    Check(v.superblock.space.quota_block_count==quota && v.superblock.space.reserve_block_count==reserve,"raw APSB pair atomic");
    Check(v.superblock.uuid_hex==before.superblock.uuid_hex && v.superblock.name_utf8==before.superblock.name_utf8 &&
        v.superblock.role_raw==before.superblock.role_raw,"label/role/UUID preserved");
    auto a=std::vector<std::byte>(f.image.begin()+before.superblock_object.physical_block*kBlockSize,
        f.image.begin()+(before.superblock_object.physical_block+1)*kBlockSize);
    auto b=std::vector<std::byte>(bytes.begin()+v.superblock_object.physical_block*kBlockSize,
        bytes.begin()+(v.superblock_object.physical_block+1)*kBlockSize);
    for(auto offset:{0u,0x10u,0x48u,0x50u,0x58u,0x80u,0xe0u,0xe8u}) { std::fill_n(a.begin()+offset,8,std::byte{});std::fill_n(b.begin()+offset,8,std::byte{}); }
    Check(a==b,"all unrelated APSB bytes including group/crypto identity unchanged");
    const auto& old=f.checkpoint.volumes[1];const auto& peer=cp->volumes[1];
    Check(std::equal(bytes.begin()+peer.superblock_object.physical_block*kBlockSize,
        bytes.begin()+(peer.superblock_object.physical_block+1)*kBlockSize,
        f.image.begin()+old.superblock_object.physical_block*kBlockSize),"sibling superblock byte-for-byte preserved");
    auto owner=OpenOwner(path);
    for(auto oid:{101ull,102ull}) {
        std::vector<std::byte> payload;auto* store=owner->FindSessionStore(oid);
        Check(store->ReadCommittedFileRange(L"\\clone0",0,4*kBlockSize,payload),"fresh owner reads existing file");
        Check(payload.size()==4*kBlockSize && std::equal(payload.begin(),payload.end(),f.image.begin()+(oid==101?128:144)*kBlockSize),"payload unchanged");
    }
}
void SuccessAndQuota() {
    auto f=QuotaFixture();auto path=std::filesystem::absolute("success.apfs");SaveImage(path,f.image);
    const auto charged=f.checkpoint.volumes[0].superblock.space.allocated_block_count;
    std::cout<<"source charged="<<charged<<" blocks\n";
    const std::pair<std::uint64_t,std::uint64_t> changes[]={{64,20},{256,32},{charged,0},{0,0},{0,24},{96,8}};
    unsigned n=0;
    for(auto [quota,reserve]:changes) {
        {
            Tx journal(L"Strict");Configure(journal,"success.wal");auto owner=OpenOwner(path);std::string error;
            VolumeQuotaReservePlan plan;
            const bool prepared=PrepareVolumeQuotaReserve(*owner,101,quota,reserve,plan,error); Check(prepared,"prepare lower/raise/clear pair: "+error);
            const auto before=ReadImage(path);auto watermark=journal.Watermarks().accepted_sequence;
            Check(before==ReadImage(path),"dry run unchanged");
            bool accepted_old=false;
            journal.SetJournalFaultInjectionHook([&](std::string_view stage){if(stage=="durable-flush"&&!accepted_old){Check(ReadImage(path)==before,"WAL acceptance before native bytes");accepted_old=true;}return false;});
            auto result=ApplyVolumeQuotaReserve(*owner,journal,plan);CheckSuccess(result);
            Check(accepted_old&&journal.Watermarks().accepted_sequence>watermark,"one durable WAL acceptance");
            auto published=ReadImage(path);Check(!ApplyVolumeQuotaReserve(*owner,journal,plan).committed&&ReadImage(path)==published,"single-use plan");
            Check(journal.Watermarks().cleanup_sequence==journal.Watermarks().accepted_sequence,"canonical cleanup");
            if(quota==charged) {
                auto* store=owner->FindSessionStore(101);
                store->SetFilePayloadProvider([](const std::wstring&,std::uint64_t size){return std::vector<std::byte>(size,std::byte{0x71});});
                Store::MutationRequest write;write.operation=Store::MutationOperation::Write;write.path=L"\\clone0";write.offset=4*kBlockSize;write.length=8*kBlockSize;
                auto refused=owner->Commit(101,{write});
                Check(!refused.committed&&refused.clean_prepublication_refusal&&refused.commit_status_code==static_cast<int>(Store::CommitStatus::CapacityBlocked),"live allocation beyond quota refused cleanly: "+refused.error);
                Check(ReadImage(path)==published,"quota allocation refusal preserves native bytes");
                std::vector<std::byte> payload;Check(store->ReadCommittedFileRange(L"\\clone0",0,4*kBlockSize,payload)&&payload.size()==4*kBlockSize,"continued readability after refusal");
            }
        }
        ObserveLimits(path,f,quota,reserve);std::cout<<"PASS lower/raise/clear "<<n++<<"\n";
    }
}
void QuotaRefusals() {
    auto f=QuotaFixture();auto path=std::filesystem::absolute("refused.apfs");SaveImage(path,f.image);
    auto owner=OpenOwner(path);Tx journal(L"Strict");Configure(journal,"refused.wal");std::string error;
    for(auto pair:std::vector<std::pair<std::uint64_t,std::uint64_t>>{{1,0},{128,129},{0,513},{0,500},{128,12}}) {
        VolumeQuotaReservePlan p;Check(!PrepareVolumeQuotaReserve(*owner,101,pair.first,pair.second,p,error),"invalid quota/reserve refuses: "+error);
        Check(ReadImage(path)==f.image&&journal.Watermarks().accepted_sequence==0,"refused plan has no native or accepted changes");
    }
    VolumeQuotaReservePlan p;Check(PrepareVolumeQuotaReserve(*owner,101,64,20,p,error),"valid before staleness");
    VolumeRenamePlan rename;Check(PrepareVolumeRename(*owner,101,"Later",rename,error),"integrated rename prepare");CheckSuccess(ApplyVolumeRename(*owner,journal,rename));
    auto latest=ReadImage(path);auto seq=journal.Watermarks().accepted_sequence;
    Check(!ApplyVolumeQuotaReserve(*owner,journal,p).committed&&ReadImage(path)==latest&&journal.Watermarks().accepted_sequence==seq,"stale quota plan refuses after durable rename");
    VolumeQuotaReservePlan busy;Check(PrepareVolumeQuotaReserve(*owner,101,64,20,busy,error),"plan before sibling reservation");
    Store::MutationRequest create;create.operation=Store::MutationOperation::CreateFile;create.path=L"\\pending";
    Check(owner->FindSessionStore(102)->StageMutation(create)==Store::MutationStatus::Applied,"active sibling staged reservation");
    Check(!ApplyVolumeQuotaReserve(*owner,journal,busy).committed&&ReadImage(path)==latest,"conflicting sibling staging refuses");
    owner.reset();
    owner=OpenOwner(path);VolumeQuotaReservePlan wrong;Check(PrepareVolumeQuotaReserve(*owner,101,64,20,wrong,error),"owner plan");
    auto secondpath=std::filesystem::absolute("other.apfs");SaveImage(secondpath,ReadImage(path));auto other=OpenOwner(secondpath);
    Check(!ApplyVolumeQuotaReserve(*other,journal,wrong).committed&&!ApplyVolumeQuotaReserve(*owner,journal,wrong).committed,"wrong owner attempt consumes plan");
    VolumeQuotaReservePlan expires;Check(PrepareVolumeQuotaReserve(*owner,101,64,20,expires,error),"expiry plan");expires.expires=std::chrono::steady_clock::now();
    Check(!ApplyVolumeQuotaReserve(*owner,journal,expires).committed,"expired plan refuses");
    Check(ReadImage(path)==latest,"all identity/expiry refusals preserve native bytes");
}
void CodecAndCensus() {
    auto f=QuotaFixture();auto path=std::filesystem::absolute("codec.apfs");SaveImage(path,f.image);
    auto owner=OpenOwner(path);std::string error;VolumeQuotaReservePlan p;
    Check(PrepareVolumeQuotaReserve(*owner,101,64,20,p,error),"codec prepare: "+error);
    NativeVolumeQuotaReserve intent;Check(DecodeNativeVolumeQuotaReserve(p.request.inline_payload,intent),"QRS1 roundtrip");
    NativeVolumeRename rename;Check(!DecodeNativeVolumeRename(p.request.inline_payload,rename),"WAL17 cannot decode operation20");
    auto verify=[&](NativeVolumeQuotaReserve bad){auto req=p.request;req.inline_payload=EncodeNativeVolumeQuotaReserve(bad);req.length=req.inline_payload.size();return ValidateVolumeMetadataMutation(*owner->FindSessionStore(101),req,error);};
    for(unsigned n=0;n<7;++n) {
        auto bad=intent;
        if(n==0)bad.container_uuid[0]=bad.container_uuid[0]=='a'?'b':'a';
        if(n==1)bad.volume_uuid[0]=bad.volume_uuid[0]=='a'?'b':'a';
        if(n==2)++bad.volume;
        if(n==3)++bad.checkpoint;
        if(n==4)bad.image_identity[0]=bad.image_identity[0]=='a'?'b':'a';
        if(n==5)bad.new_label="Changed";
        if(n==6)bad.quota_blocks=1;
        Check(!verify(bad),"wrong store/container/volume/OID/XID/label/quota proof refuses");
    }
    auto bytes=p.request.inline_payload;
    for(std::size_t size:{0u,8u,127u,512u}) {NativeVolumeQuotaReserve d;Check(!DecodeNativeVolumeQuotaReserve(std::span(bytes).first(size),d),"truncated intent refuses");}
    bytes.push_back(std::byte{});NativeVolumeQuotaReserve d;Check(!DecodeNativeVolumeQuotaReserve(bytes,d),"trailing data refuses");
    auto req=p.request;req.operation=Store::MutationOperation::RenameVolume;Check(!ValidateVolumeMetadataMutation(*owner->FindSessionStore(101),req,error),"wrong enum refuses");
    auto record=WriteAheadLog::Record{};record.operation=WriteAheadLog::OperationKind::SetVolumeQuotaReserve;record.inline_payload=p.request.inline_payload;
    record.object_id=intent.volume;record.parent_object_id=intent.checkpoint+1;record.path_utf8="\\";record.payload_length=record.inline_payload.size();
    BCRYPT_ALG_HANDLE alg=nullptr;Check(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0)>=0,"hash provider");
    Check(BCryptHash(alg,nullptr,0,reinterpret_cast<PUCHAR>(record.inline_payload.data()),static_cast<ULONG>(record.inline_payload.size()),record.payload_sha256.data(),32)>=0,"hash intent");BCryptCloseAlgorithmProvider(alg,0);
    Check(WriteAheadLog::VolumeQuotaReserveIsConsistent(record),"WAL20 consistency");
    for(unsigned n=0;n<8;++n){auto bad=record;if(n==0)bad.flags=1;if(n==1)bad.logical_length=1;if(n==2)bad.payload_offset=1;if(n==3)bad.payload_spool_id=1;if(n==4)bad.secondary_path_utf8="x";if(n==5)bad.object_id++;if(n==6)bad.parent_object_id++;if(n==7)bad.payload_sha256[0]^=1;Check(!WriteAheadLog::VolumeQuotaReserveIsConsistent(bad),"malformed WAL refuses");}
    owner.reset();
    for(unsigned n=0;n<3;++n) {
        auto bad=QuotaFixture(); const auto& v=bad.checkpoint.volumes[n==0?1:0];auto at=v.superblock_object.physical_block*kBlockSize;
        std::vector<std::byte> apsb(bad.image.begin()+at,bad.image.begin()+at+kBlockSize);
        PutU64LE(apsb,n==2?0x58:0xd8,n==2?1:1);Check(FinalizeAppleObjectChecksum(apsb,error),"bad accounting fixture checksum");std::copy(apsb.begin(),apsb.end(),bad.image.begin()+at);
        auto badpath=std::filesystem::absolute("census-"+std::to_string(n)+".apfs");SaveImage(badpath,bad.image);
        auto badowner=OpenOwner(badpath);VolumeQuotaReservePlan reject;
        Check(!PrepareVolumeQuotaReserve(*badowner,101,64,20,reject,error),"snapshot or understated charged allocation refused: "+error);
        Check(ReadImage(badpath)==bad.image,"census refusal unchanged bytes");
    }
}


void QuotaEnforcementTransitions() {
    auto f=QuotaFixture();auto path=std::filesystem::absolute("enforcement.apfs");SaveImage(path,f.image);
    std::string error;std::uint64_t final_size=0;
    {
        auto owner=OpenOwner(path);Tx journal(L"Strict");Configure(journal,"enforcement.wal");
        const auto change=[&](std::uint64_t quota,std::uint64_t reserve){VolumeQuotaReservePlan p;
            bool ok=PrepareVolumeQuotaReserve(*owner,101,quota,reserve,p,error);Check(ok,error);CheckSuccess(ApplyVolumeQuotaReserve(*owner,journal,p));};
        const auto grow=[&](std::uint64_t oid,std::uint64_t offset,std::uint64_t blocks){auto* store=owner->FindSessionStore(oid);
            std::vector<std::byte> prior;auto inode=store->LookupCommittedInodeByPath(L"\\clone0");Check(inode.has_value()&&store->ReadCommittedFileRange(L"\\clone0",0,inode->logical_size,prior),"capture prior payload for whole-file provider");
            store->SetFilePayloadProvider([prior](const std::wstring&,std::uint64_t size){std::vector<std::byte> bytes(size,std::byte{0x71});std::copy_n(prior.begin(),(std::min)(prior.size(),bytes.size()),bytes.begin());return bytes;});
            Store::MutationRequest write;write.operation=Store::MutationOperation::Write;write.path=L"\\clone0";write.offset=offset;write.length=blocks*kBlockSize;
            return owner->Commit(oid,{write});};
        change(10,0);const auto capped=ReadImage(path);auto denied=grow(101,4*kBlockSize,8);
        Check(!denied.committed&&denied.clean_prepublication_refusal&&ReadImage(path)==capped,"charged allocation cap denies actual growth");
        change(64,0);CheckSuccess(grow(101,4*kBlockSize,8));
        Check(owner->FindSessionStore(101)->AuthoritativeAppleCheckpointView()->volumes[0].superblock.space.allocated_block_count>10,"raising quota allows growth beyond former cap");
        change(0,0);CheckSuccess(grow(101,12*kBlockSize,60));final_size=72*kBlockSize;
        Check(owner->FindSessionStore(101)->AuthoritativeAppleCheckpointView()->volumes[0].superblock.space.allocated_block_count>64,"zero quota permits growth beyond former maximum");
        const auto available=owner->LookupSharedSpace(owner->ContainerUuidHex(),102);Check(available.has_value(),"sibling shared-space observation");
        change(0,350);const auto protected_space=owner->LookupSharedSpace(owner->ContainerUuidHex(),102);
        Check(protected_space&&protected_space->available_bytes<available->available_bytes,"new reserve immediately protects space against sibling allocation");
        const auto protected_image=ReadImage(path);auto peer=grow(102,4*kBlockSize,128);
        Check(!peer.committed&&peer.clean_prepublication_refusal&&ReadImage(path)==protected_image,"sibling cannot spend selected volume reserve");
        change(0,0);auto released=owner->LookupSharedSpace(owner->ContainerUuidHex(),102);
        Check(released&&released->available_bytes>protected_space->available_bytes,"clearing reserve releases sibling availability");
    }
    auto owner=OpenOwner(path);std::vector<std::byte> data;
    Check(owner->FindSessionStore(101)->ReadCommittedFileRange(L"\\clone0",0,final_size,data)&&data.size()==final_size,"fresh owner reads growth after raise and clear");
    Check(std::equal(data.begin(),data.begin()+4*kBlockSize,f.image.begin()+128*kBlockSize)&&
        std::all_of(data.begin()+4*kBlockSize,data.end(),[](auto b){return b==std::byte{0x71};}),"original bytes and newly allocated bytes survive reopen");
    Check(owner->FindSessionStore(102)->ReadCommittedFileRange(L"\\clone0",0,4*kBlockSize,data)&&
        std::equal(data.begin(),data.end(),f.image.begin()+144*kBlockSize),"sibling remains readable after reserve refusal");
    std::cout<<"PASS actual allocation enforcement across raise, clear and sibling reserves\n";
}
void QuotaBindingAndRetainedReplay() {
    auto f=QuotaFixture();auto path=std::filesystem::absolute("binding.apfs");SaveImage(path,f.image);std::string error;
    {
        auto owner=OpenOwner(path);Tx journal(L"Strict");Configure(journal,"binding.wal");
        VolumeQuotaReservePlan p,duplicate;
        Check(PrepareVolumeQuotaReserve(*owner,101,64,20,p,error)&&PrepareVolumeQuotaReserve(*owner,101,64,20,duplicate,error),"deterministic prepares");
        Check(p.request.inline_payload==duplicate.request.inline_payload,"same source/pair produces identical intent");
        Check(!owner->Commit(101,{p.request}).committed&&ReadImage(path)==f.image,"no coordinator publication without accepted WAL boundary");
        NativeVolumeQuotaReserve changed;Check(DecodeNativeVolumeQuotaReserve(p.request.inline_payload,changed),"decode sealed plan");
        changed.quota_blocks=96;p.request.inline_payload=EncodeNativeVolumeQuotaReserve(changed);p.request.length=p.request.inline_payload.size();
        Check(!ApplyVolumeQuotaReserve(*owner,journal,p).committed&&journal.Watermarks().accepted_sequence==0,"editing prepared limits invalidates single-use plan");
        journal.SetVolumeIdentity(L"apfs-vol:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:101");
        Check(!ApplyVolumeQuotaReserve(*owner,journal,duplicate).committed&&ReadImage(path)==f.image,"wrong canonical WAL identity refuses");
    }
    // Same-XID sibling edits must invalidate the frozen complete space census,
    // both during coordinator reload and immediately before WAL acceptance.
    for(bool late:{false,true}) {
        auto local=std::filesystem::absolute(late?"late-source.apfs":"same-xid.apfs");SaveImage(local,f.image);
        auto owner=OpenOwner(local);Tx journal(L"Strict");Configure(journal,late?"late-source.wal":"same-xid.wal");VolumeQuotaReservePlan p;
        Check(PrepareVolumeQuotaReserve(*owner,101,64,20,p,error),"source-change plan");
        auto external=f.image;const auto block=f.checkpoint.volumes[1].superblock_object.physical_block;
        std::vector<std::byte> raw(external.begin()+block*kBlockSize,external.begin()+(block+1)*kBlockSize);
        PutU64LE(raw,0x48,17);Check(FinalizeAppleObjectChecksum(raw,error),error);std::copy(raw.begin(),raw.end(),external.begin()+block*kBlockSize);
        if(late)p.fault_hook_for_tests=[&](std::string_view stage){if(stage=="before-acceptance")SaveImage(local,external);return false;};
        else SaveImage(local,external);
        const auto result=ApplyVolumeQuotaReserve(*owner,journal,p);
        Check(!result.committed&&journal.Watermarks().accepted_sequence==0&&ReadImage(local)==external,"final source proof refuses changed sibling with no engine writes");
    }
    for(std::uint64_t subsequent:{0ull,101ull,102ull}) {
        auto stem="history-"+std::to_string(subsequent);auto image=std::filesystem::absolute(stem+".apfs");auto wal=std::filesystem::absolute(stem+".wal");SaveImage(image,f.image);
        std::vector<std::byte> accepted;
        {
            auto owner=OpenOwner(image);Tx journal(L"Strict");Configure(journal,wal);VolumeQuotaReservePlan p;
            Check(PrepareVolumeQuotaReserve(*owner,101,64,20,p,error),"retained proof plan");
            journal.SetJournalFaultInjectionHook([&](std::string_view stage){if(stage=="durable-flush"&&accepted.empty())accepted=ReadImage(wal);return false;});
            CheckSuccess(ApplyVolumeQuotaReserve(*owner,journal,p));Check(!accepted.empty(),"save actual accepted WAL prefix");
            Check(owner->UpdateRequiredCheckpointXids(subsequent==101?102:101,{f.checkpoint.container.superblock.xid,owner->CheckpointXid()},error,false),"retain proof chain");
            journal.SetJournalPath(L"");
            if(subsequent){Tx next(L"Strict");Configure(next,stem+"-later.wal");
                for(unsigned n=0;n<2;++n){Check(owner->RefreshSessionForRecovery(subsequent,error),error);VolumeRenamePlan rename;
                    Check(PrepareVolumeRename(*owner,subsequent,"Later"+std::to_string(n),rename,error),error);CheckSuccess(ApplyVolumeRename(*owner,next,rename));}
            }
        }
        SaveImage(wal,accepted);const auto before=ReadImage(image);
        if(subsequent==0){
            auto copied=std::filesystem::absolute("copied.apfs");SaveImage(copied,before);SaveImage("copied.wal",accepted);
            Tx journal(L"Strict");Configure(journal,"copied.wal");auto owner=OpenOwner(copied,&journal);
            Check(ReplayVolumeQuotaReserve(*owner,journal,101,error)==std::optional<bool>{false}&&ReadImage(copied)==before,"copied source image with same APFS UUIDs refuses actual WAL");
        }
        for(unsigned reopened=0;reopened<2;++reopened){
            Tx journal(L"Strict");Configure(journal,wal);auto owner=OpenOwner(image,&journal);
            if(reopened==0&&subsequent==0){
                Check(owner->UpdateRequiredCheckpointXids(102,{f.checkpoint.container.superblock.xid},error,true),"active conflicting sibling WAL census");
                Check(ReplayVolumeQuotaReserve(*owner,journal,101,error)==std::optional<bool>{false}&&ReadImage(image)==before&&journal.Watermarks().cleanup_sequence==0,"sibling replay debt refuses metadata replay");
                Check(owner->UpdateRequiredCheckpointXids(102,{},error,false),"release test sibling debt");
            }
            auto result=ReplayVolumeQuotaReserve(*owner,journal,101,error);
            Check(reopened? !result.has_value():result.value_or(false),"retained first-publication proof: "+error);
            Check(ReadImage(image)==before,"retained replay preserves later selected and sibling bytes");
        }
    }
    std::cout<<"PASS bindings, same-XID census and retained multi-checkpoint replay\n";
}

void ReviewSourceBinding() {
    auto f=QuotaFixture();std::string error;
    for(bool late:{false,true}) {
        auto stem=late?"review-tree-late":"review-tree-preview";
        auto path=std::filesystem::absolute(std::string(stem)+".apfs");SaveImage(path,f.image);
        auto owner=OpenOwner(path);Tx journal(L"Strict");Configure(journal,std::string(stem)+".wal");VolumeQuotaReservePlan p;
        Check(PrepareVolumeQuotaReserve(*owner,101,64,20,p,error),"review tree prepare: "+error);
        auto changed=f.image;const auto block=f.checkpoint.volumes[0].root_tree.physical_block;
        std::vector<std::byte> raw(changed.begin()+block*kBlockSize,changed.begin()+(block+1)*kBlockSize);
        auto records=ReadTree(f);bool edited=false;
        for(const auto& record:records) if(Type(record)==3&&Id(record)==17) {
            AppleInodeRecord inode;Check(ApfsExtendedRecordCodec::DecodeInode(record,inode,error),error);
            inode.mode=0100600;apfsaccess::catalog::BtreeRecord replacement;Check(EncodeAppleInodeRecord(inode,replacement,error),error);
            auto at=std::search(raw.begin(),raw.end(),record.value.begin(),record.value.end());
            Check(at!=raw.end()&&record.value.size()==replacement.value.size(),"locate exact inode value");
            std::copy(replacement.value.begin(),replacement.value.end(),at);edited=true;
        }
        Check(edited&&FinalizeAppleObjectChecksum(raw,error),"valid same-XID inode edit");
        std::copy(raw.begin(),raw.end(),changed.begin()+block*kBlockSize);
        VerificationScope scope;scope.source_identity="review";scope.exact={0,changed.size(),f.checkpoint.container.superblock.uuid_hex,
            f.checkpoint.volumes[0].superblock.uuid_hex,101,f.checkpoint.container.superblock.xid};
        Check(ApfsVerifier::Verify(VectorRandomAccessSource(changed),scope).outcome==VerificationOutcome::Complete,"changed graph independently remains valid");
        if(late)p.fault_hook_for_tests=[&](std::string_view stage){if(stage=="before-acceptance")SaveImage(path,changed);return false;};
        else SaveImage(path,changed);
        auto result=ApplyVolumeQuotaReserve(*owner,journal,p);
        std::cout<<"review source late="<<late<<" accepted="<<journal.Watermarks().accepted_sequence<<" error="<<result.error<<"\n";
        Check(!result.committed&&journal.Watermarks().accepted_sequence==0&&ReadImage(path)==changed,"same-XID valid tree change refuses before acceptance and preserves external bytes");
    }
}
void ReviewAccounting() {
    auto f=QuotaFixture();std::string error;
    for(unsigned peer:{0u,1u}) {
        auto changed=f.image;auto block=f.checkpoint.volumes[peer].superblock_object.physical_block;
        std::vector<std::byte> raw(changed.begin()+block*kBlockSize,changed.begin()+(block+1)*kBlockSize);
        PutU64LE(raw,0x58,40);PutU64LE(raw,0x48,40);Check(FinalizeAppleObjectChecksum(raw,error),error);
        std::copy(raw.begin(),raw.end(),changed.begin()+block*kBlockSize);
        auto path=std::filesystem::absolute("review-inflated-"+std::to_string(peer)+".apfs");SaveImage(path,changed);
        auto owner=OpenOwner(path);VolumeQuotaReservePlan plan;
        const bool prepared=PrepareVolumeQuotaReserve(*owner,101,64,20,plan,error);
        std::cout<<"review inflated peer="<<peer<<" prepared="<<prepared<<" error="<<error<<"\n";
        Check(!prepared&&ReadImage(path)==changed,"unproven inflated charged allocation cannot discharge reserve promises");
    }
}
void ReviewReplayReservations() {
    auto f=QuotaFixture();std::string error;
    for(auto selected:{101ull,102ull}) {
        auto stem="review-reservation-"+std::to_string(selected);auto path=std::filesystem::absolute(stem+".apfs");SaveImage(path,f.image);
        Tx journal(L"Strict");Configure(journal,stem+".wal");auto owner=OpenOwner(path);VolumeQuotaReservePlan p;
        Check(PrepareVolumeQuotaReserve(*owner,101,64,20,p,error),error);
        p.fault_hook_for_tests=[](std::string_view stage){return stage=="before-cleanup";};
        Check(ApplyVolumeQuotaReserve(*owner,journal,p).commit_recovery_required,"retain published accepted owner");
        Check(owner->RefreshSessionForRecovery(selected,error),error);
        auto* store=owner->FindSessionStore(selected);Check(store->AllocateExtent(kBlockSize).has_value(),"stage allocation without mutation");
        const auto pending=store->DebugWorkingFreeExtentTotalBytes();Check(store->PendingMutationCount()==0,"allocation-only state");
        const auto before=ReadImage(path),wal=ReadImage(stem+".wal");const auto census=owner->CheckpointCensusSnapshot();
        const auto replay=ReplayVolumeQuotaReserve(*owner,journal,101,error);
        std::cout<<"review reservation oid="<<selected<<" replay="<<replay.value_or(false)<<" pending="<<store->PendingAllocationCount()<<" error="<<error<<"\n";
        Check(replay==std::optional<bool>{false}&&store->DebugWorkingFreeExtentTotalBytes()==pending&&ReadImage(path)==before&&ReadImage(stem+".wal")==wal,
            "published replay refuses active allocation before refresh or owner cleanup");
    }
}

void ReviewPublishedAccounting() {
    auto f=QuotaFixture();std::string error;auto path=std::filesystem::absolute("review-published.apfs");SaveImage(path,f.image);
    auto wal=std::filesystem::absolute("review-published.wal");
    {
        Tx journal(L"Strict");Configure(journal,wal);auto owner=OpenOwner(path);VolumeQuotaReservePlan p;
        Check(PrepareVolumeQuotaReserve(*owner,101,64,20,p,error),error);
        p.fault_hook_for_tests=[](std::string_view stage){return stage=="before-cleanup";};
        Check(ApplyVolumeQuotaReserve(*owner,journal,p).commit_recovery_required,"published debt");
    }
    auto changed=ReadImage(path);VectorRandomAccessSource source(changed);
    auto cp=LoadAppleCheckpointView(source,0,source.SizeBytes(),error);Check(!!cp,error);
    auto block=cp->volumes[0].superblock_object.physical_block;
    std::vector<std::byte> raw(changed.begin()+block*kBlockSize,changed.begin()+(block+1)*kBlockSize);
    PutU64LE(raw,0x58,cp->volumes[0].superblock.space.allocated_block_count+1);
    Check(FinalizeAppleObjectChecksum(raw,error),error);std::copy(raw.begin(),raw.end(),changed.begin()+block*kBlockSize);SaveImage(path,changed);
    Tx journal(L"Strict");Configure(journal,wal);auto owner=OpenOwner(path,&journal);const auto beforewal=ReadImage(wal);
    const auto result=ReplayVolumeQuotaReserve(*owner,journal,101,error);
    std::cout<<"review publication replay="<<result.value_or(false)<<" cleanup="<<journal.Watermarks().cleanup_sequence<<" error="<<error<<"\n";
    Check(result==std::optional<bool>{false}&&ReadImage(path)==changed&&ReadImage(wal)==beforewal,"retained publication must prove resulting charge before durable owner cleanup");
}
void ReviewLateReservation() {
    auto f=QuotaFixture();std::string error;auto path=std::filesystem::absolute("review-late-reservation.apfs");SaveImage(path,f.image);
    auto owner=OpenOwner(path);Tx journal(L"Strict");Configure(journal,"review-late-reservation.wal");VolumeQuotaReservePlan p;
    Check(PrepareVolumeQuotaReserve(*owner,101,64,20,p,error),error);
    std::uint64_t held=0;
    p.fault_hook_for_tests=[&](std::string_view stage){if(stage=="before-acceptance") {
        auto* peer=owner->FindSessionStore(102);Check(peer->AllocateExtent(kBlockSize).has_value(),"late sibling allocation");held=peer->DebugWorkingFreeExtentTotalBytes();
    }return false;};
    const auto result=ApplyVolumeQuotaReserve(*owner,journal,p);
    std::cout<<"review late reservation accepted="<<journal.Watermarks().accepted_sequence<<" error="<<result.error<<"\n";
    Check(!result.committed&&journal.Watermarks().accepted_sequence==0&&ReadImage(path)==f.image&&owner->FindSessionStore(102)->DebugWorkingFreeExtentTotalBytes()==held,
        "last acceptance check preserves newly held sibling reservation");
}
void ReviewLateCheckpoint() {
    auto f=QuotaFixture();std::string error;auto path=std::filesystem::absolute("review-late-nx.apfs");SaveImage(path,f.image);
    auto owner=OpenOwner(path);Tx journal(L"Strict");Configure(journal,"review-late-nx.wal");VolumeQuotaReservePlan p;
    Check(PrepareVolumeQuotaReserve(*owner,101,64,20,p,error),error);
    auto changed=f.image;auto block=f.checkpoint.container.superblock_physical_block;
    std::vector<std::byte> raw(changed.begin()+block*kBlockSize,changed.begin()+(block+1)*kBlockSize);
    PutU64LE(raw,0x58,f.checkpoint.container.superblock.next_oid+1);Check(FinalizeAppleObjectChecksum(raw,error),error);
    std::copy(raw.begin(),raw.end(),changed.begin()+block*kBlockSize);
    p.fault_hook_for_tests=[&](std::string_view stage){if(stage=="before-acceptance")SaveImage(path,changed);return false;};
    const auto result=ApplyVolumeQuotaReserve(*owner,journal,p);
    std::cout<<"review late NX accepted="<<journal.Watermarks().accepted_sequence<<" error="<<result.error<<"\n";
    Check(!result.committed&&journal.Watermarks().accepted_sequence==0&&ReadImage(path)==changed,"cached NX cannot authenticate a changed source before acceptance");
}
void FaultsAndReplay() {
    for(const std::string mode:{"before-accept","acceptance","before-publish","switch","final-flush","durable-watermark","cleanup","after-cleanup"}) {
        auto f=QuotaFixture();auto stem="fault-"+mode;auto path=std::filesystem::absolute(stem+".apfs");SaveImage(path,f.image);
        bool accepted=false;
        {
            Tx journal(L"Strict");Configure(journal,stem+".wal");auto owner=OpenOwner(path);std::string error;VolumeQuotaReservePlan p;
            Check(PrepareVolumeQuotaReserve(*owner,101,64,20,p,error),"fault plan "+mode+": "+error);
            p.fault_hook_for_tests=[&](std::string_view stage){return
                (mode=="before-accept"&&stage=="before-acceptance") ||
                (mode=="durable-watermark"&&stage=="before-durable-watermark") ||
                (mode=="cleanup"&&stage=="before-cleanup") ||
                (mode=="after-cleanup"&&stage=="after-cleanup");};
            unsigned flushes=0;
            journal.SetJournalFaultInjectionHook([&](std::string_view stage){
                if(stage!="durable-flush")return false;++flushes;
                return mode=="acceptance"&&flushes==1;
            });
            owner->FindSessionStore(101)->SetCommitStageHook([&](std::string_view stage){
                if(mode=="final-flush"&&stage=="before-apple-final-flush")SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_FLUSH",L"1");
                return !((mode=="before-publish"&&stage=="before-apple-publish")||(mode=="switch"&&stage=="before-apple-checkpoint-switch"));
            });
            auto result=ApplyVolumeQuotaReserve(*owner,journal,p);SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_FLUSH",nullptr);
            accepted=journal.Watermarks().accepted_sequence>0; std::cout<<"fault "<<mode<<" result="<<result.error<<" accepted="<<journal.Watermarks().accepted_sequence<<" cleanup="<<journal.Watermarks().cleanup_sequence<<"\n";
            Check(!result.committed||result.commit_recovery_required,"fault never acknowledged "+mode);
            if(mode=="before-accept")Check(ReadImage(path)==f.image&&!accepted,"before acceptance untouched");
        }
        std::vector<std::byte> once;
        for(unsigned reopen=0;reopen<2;++reopen) {
            Tx journal(L"Strict");Configure(journal,stem+".wal");auto owner=OpenOwner(path,&journal);std::string error;
            auto result=ReplayVolumeQuotaReserve(*owner,journal,101,error);std::cout<<"replay "<<mode<<" owner="<<reopen<<" result="<<(result.has_value()?(*result?"true":"false"):"empty")<<" error="<<error<<"\n";
            Check(!result.has_value()||*result,"fresh owner actual WAL replay "+mode+": "+error);
            Check(!journal.HasUnappliedAcceptedWork(),"replay cleans existing debt");
            if(reopen==0)once=ReadImage(path);else Check(ReadImage(path)==once&&!result.has_value(),"second fresh owner no duplicate publication");
        }
        ObserveLimits(path,f,mode=="before-accept"?128:64,mode=="before-accept"?12:20);
        std::cout<<"PASS fault/reopen "<<mode<<"\n";
    }
}
}
int main(int argc,char** argv) {
    try {
        if(argc<2||argc>3)throw std::runtime_error("VolumeQuotaReserveTests <D: evidence> [group]");
        std::string group=argc==3?argv[2]:"all";
        if(group=="verify-production"||group=="verify-production-clear"||group=="verify-canonical"||group=="verify-canonical-history") {
            VerifyQuotaCommandFixture(std::filesystem::absolute(argv[1]),group);
            std::cout<<"PASS quota command native readback "<<checks<<" checks\n";return 0;
        }
        if(group=="hold-canonical-101"||group=="hold-canonical-102"||group=="hold-production-101"||group=="hold-production-102") {
            HoldQuotaWal(std::filesystem::absolute(argv[1]),group);return 0;
        }
        auto run=std::filesystem::path(argv[1])/("run-"+std::to_string(GetCurrentProcessId())+"-"+std::to_string(GetTickCount64()));
        std::filesystem::create_directories(run);std::filesystem::current_path(run);std::cout<<"Evidence "<<run.string()<<"\n";
        if(group=="fixture"||group=="accepted"||group=="accepted-unpublished"||group=="production"||group=="production-accepted"||
            group=="production-accepted-unpublished"||group=="production-unknown"||group=="production-mixed"||group=="canonical") {
            auto f=QuotaFixture();auto path=std::filesystem::absolute("fixture.apfs");SaveImage(path,f.image);
            if(group.starts_with("production")||group=="canonical")ProductionQuotaCommandFixture(path,group);
            else for(auto oid:{101ull,102ull})CreateOriginalEmptyWal(std::filesystem::absolute(std::to_string(oid)+".wal"));
            if(group=="accepted"||group=="accepted-unpublished") {
                Tx journal(L"Strict");Configure(journal,"101.wal");auto owner=OpenOwner(path);VolumeQuotaReservePlan plan;std::string error;
                const bool prepared=PrepareVolumeQuotaReserve(*owner,101,64,20,plan,error);Check(prepared,error);
                if(group=="accepted")plan.fault_hook_for_tests=[](std::string_view stage){return stage=="before-cleanup";};
                else owner->FindSessionStore(101)->SetCommitStageHook([](std::string_view stage){return stage!="before-apple-publish";});
                const auto result=ApplyVolumeQuotaReserve(*owner,journal,plan);Check(result.commit_recovery_required,"accepted fixture holds real WAL debt");
            }
            if(group=="fixture") {
                auto owner=OpenOwner(path);VolumeQuotaReservePlan plan;std::string error;
                const bool prepared=PrepareVolumeQuotaReserve(*owner,101,64,20,plan,error);Check(prepared,error);
                SaveImage("request.bin",plan.request.inline_payload);
            }
            auto bytes=ReadImage(path);VectorRandomAccessSource src(bytes);std::string error;auto cp=LoadAppleCheckpointView(src,0,src.SizeBytes(),error);Check(!!cp,error);
            std::ofstream manifest("fixture.json");manifest<<"{\"container\":\""<<cp->container.superblock.uuid_hex<<"\",\"volume\":\""<<cp->volumes[0].superblock.uuid_hex<<"\",\"xid\":"<<cp->container.superblock.xid<<"}";
        }
        if(group=="all"||group=="review-source")ReviewSourceBinding();
        if(group=="all"||group=="review-accounting")ReviewAccounting();
        if(group=="all"||group=="review-replay")ReviewReplayReservations();
        if(group=="all"||group=="review-published")ReviewPublishedAccounting();
        if(group=="review-published") {
            CreateOriginalEmptyWal(std::filesystem::absolute("peer.wal"));
            const auto bytes=ReadImage("review-published.apfs");VectorRandomAccessSource source(bytes);std::string error;
            const auto cp=LoadAppleCheckpointView(source,0,source.SizeBytes(),error);Check(!!cp,error);
            std::ofstream manifest("fixture.json");manifest<<"{\"container\":\""<<cp->container.superblock.uuid_hex<<
                "\",\"volume\":\""<<cp->volumes[0].superblock.uuid_hex<<"\",\"xid\":"<<cp->container.superblock.xid<<"}";
        }
        if(group=="all"||group=="review-late-reservation")ReviewLateReservation();
        if(group=="all"||group=="review-late-nx")ReviewLateCheckpoint();
        if(group=="all"||group=="success")SuccessAndQuota();
        if(group=="all"||group=="refusal")QuotaRefusals();
        if(group=="all"||group=="codec")CodecAndCensus();
        if(group=="all"||group=="faults")FaultsAndReplay();
        if(group=="all"||group=="bindings")QuotaBindingAndRetainedReplay();
        if(group=="all"||group=="production-authority")ProductionQuotaAuthorityRefusals();
        if(group=="all"||group=="enforcement")QuotaEnforcementTransitions();
        std::cout<<"PASS quota/reserve "<<checks<<" checks\n";return 0;
    }catch(const std::exception& x){std::cerr<<"FAIL after "<<checks<<" checks: "<<x.what()<<"\n";return 1;}
}

