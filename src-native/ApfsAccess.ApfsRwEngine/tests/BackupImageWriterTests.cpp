#include <Windows.h>
#undef CreateFile
#undef CreateDirectory
#define APPLE_CLONE_TEST_HELPERS_ONLY
#include "AppleCloneCowTests.cpp"
#include "BackupImageWriterProfile.h"
#include "MetadataStore.h"
#include "NativeApfsReader.h"
#include "TransactionManager.h"
#include "PayloadSpool.h"
#include "InodeMetadataPatch.h"
#include <filesystem>

namespace {
using BackupStore=MetadataStore;
using BackupTx=TransactionManager;
std::vector<std::byte> BackupDisk(const std::filesystem::path& path) {
    std::ifstream in(path,std::ios::binary);std::vector<char> raw((std::istreambuf_iterator<char>(in)),{});
    std::vector<std::byte> bytes(raw.size());std::memcpy(bytes.data(),raw.data(),raw.size());return bytes;
}
void BackupSave(const std::filesystem::path& path,const std::vector<std::byte>& bytes){
    std::ofstream out(path,std::ios::binary|std::ios::trunc);out.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());Check(bool(out),"save private backup fixture");
}
BuilderStore BackupSpec(){
    auto spec=CloneSpec(2);auto& v=spec.volumes.front();std::string error;
    for(auto& raw:v.filesystem_records)if(Type(raw)==3){AppleInodeRecord inode;Check(ApfsExtendedRecordCodec::DecodeInode(raw,inode,error),error);
        for(auto& field:inode.extended_fields)field.flags=0;Check(EncodeAppleInodeRecord(inode,raw,error),error);}
    AppleSecurityRecord security;security.acl_flags=0x100;security.entries.push_back({{},1,3});std::vector<std::byte> acl;
    Check(ApfsExtendedRecordCodec::EncodeSecurity(security,acl,error),error);
    for(const auto& attribute:{AppleXattrRecord{17,"com.apple.system.Security",kAppleXattrDataEmbedded,acl},
        AppleXattrRecord{17,"com.apple.ResourceFork",kAppleXattrDataEmbedded,HexToBytes("0102030405")},
        AppleXattrRecord{17,"com.apple.FinderInfo",kAppleXattrDataEmbedded,std::vector<std::byte>(32,std::byte{0x42})}}){
        apfsaccess::catalog::BtreeRecord raw;Check(EncodeAppleXattrRecord(attribute,raw,error),error);v.filesystem_records.push_back(std::move(raw));}
    AppleXattrRecord fork{18,"com.apple.ResourceFork",kAppleXattrDataStream,std::vector<std::byte>(48)};
    PutU64LE(fork.data,0,90);PutU64LE(fork.data,8,7);PutU64LE(fork.data,16,kBlockSize);
    apfsaccess::catalog::BtreeRecord raw;Check(EncodeAppleXattrRecord(fork,raw,error),error);v.filesystem_records.push_back(raw);
    Check(EncodeAppleDataStreamIdRecord({90,1},raw,error),error);v.filesystem_records.push_back(raw);
    Check(EncodeAppleFileExtentRecord({90,0,kBlockSize,132,0,kBlockSize},raw,error),error);v.filesystem_records.push_back(raw);
    Check(EncodeApplePhysicalExtentRecord({132,1,kApplePhysicalExtentKindNew,18,1},raw,error),error);v.extentref_records.push_back(raw);
    ++v.additional_file_system_allocated_blocks;
    std::vector<std::byte> fork_bytes(kBlockSize,std::byte{0});auto prefix=HexToBytes("10203040506070");
    std::copy(prefix.begin(),prefix.end(),fork_bytes.begin());spec.authoritative_seeded_main_blocks.push_back({132,std::move(fork_bytes)});
    return spec;
}
BuilderStore BackupCompressedSpec(bool invalid=false){
    auto spec=BackupSpec();auto& v=spec.volumes.front();std::string error;
    for(auto& raw:v.filesystem_records)if(Id(raw)==2&&Type(raw)==3){AppleInodeRecord root;
        Check(ApfsExtendedRecordCodec::DecodeInode(raw,root,error),error);++root.children_or_links;
        Check(EncodeAppleInodeRecord(root,raw,error),error);}
    AppleInodeRecord inode;inode.object_id=inode.private_id=19;inode.parent_id=2;inode.mode=0100644;inode.children_or_links=1;
    inode.bsd_flags=kAppleBsdCompressedFlag;inode.internal_flags=kAppleInodeHasUncompressedSize;inode.uncompressed_size=16384;
    inode.extended_fields.push_back({8,0,std::vector<std::byte>(40)});
    apfsaccess::catalog::BtreeRecord raw;Check(EncodeAppleInodeRecord(inode,raw,error),error);v.filesystem_records.push_back(raw);
    AppleDirectoryRecord d;d.parent_id=2;d.file_id=19;d.flags=8;d.name_utf8="compressed-history";
    Check(EncodeAppleDirectoryRecord(d,ApfsNamePolicy::FromIncompatibleFeatures(kIncompatCaseInsensitive),raw,error),error);v.filesystem_records.push_back(raw);
    auto compressed=CloneCompressionBytes();if(invalid)PutU32LE(compressed,4,99);
    Check(EncodeAppleXattrRecord({19,"com.apple.decmpfs",kAppleXattrDataEmbedded,compressed},raw,error),error);v.filesystem_records.push_back(raw);
    return spec;
}
Fixture BackupFixture(BuilderStore spec=BackupSpec(),bool historical_compressed=false){
    Fixture f(spec);VectorRandomAccessSource source(f.image);AppleSnapshotCreatePlan created;std::string error;
    const bool snapshot_planned=PlanAppleSnapshotCreate(source,f.checkpoint,{101,"backup-base",123456789},created,error);
    Check(snapshot_planned,"create genuine serialized snapshot graph: "+error);
    MemoryTarget target(f.image);Check(ExecuteAppleCheckpointPublication(target,created.commit.publication,error),"fixture snapshot publication: "+error);
    f.image=std::move(target.image);f.Reload();
    if(historical_compressed){
        VectorRandomAccessSource live(f.image);auto remove=Remove(f,{19});AppleVolumeTransactionPlan removed;
        Check(PlanAppleSnapshotLiveTransaction(live,f.checkpoint,remove,removed,error),"construct plain live tree with compressed historical stream: "+error);
        Publish(f,removed);
    }
    VectorRandomAccessSource next(f.image);AppleSnapshotCatalogRecords catalog;
    Check(LoadAppleSnapshotCatalog(next,f.checkpoint,101,catalog,error),"fixture canonical history: "+error);
    std::set<std::uint64_t> apsbs{f.checkpoint.volumes.front().superblock_object.physical_block};
    for(const auto& snapshot:catalog.inventory)apsbs.insert(snapshot.volume.superblock_object.physical_block);
    for(const auto block:apsbs){
        auto start=f.image.begin()+static_cast<std::ptrdiff_t>(block*kBlockSize);std::vector<std::byte> bytes(start,start+kBlockSize);
        PutU16LE(bytes,0x3c4,0x180);Check(FinalizeAppleObjectChecksum(bytes,error),error);std::copy(bytes.begin(),bytes.end(),start);
    }
    f.Reload();return f;
}
BackupStore::VolumeContext BackupContext(const std::filesystem::path& path,bool admitted=true){
    BackupStore::VolumeContext c;c.device_path=std::filesystem::absolute(path).wstring();c.volume_object_id=101;
    c.allow_legacy_scaffold_for_fixtures=false;c.allow_native_snapshot_runtime=admitted;return c;
}
void BackupHistorical(const std::filesystem::path& path,const std::vector<std::byte>& expected){
    Fixture f(BackupSpec());f.image=BackupDisk(path);f.Reload();VectorRandomAccessSource source(f.image);std::string error;
    Check(f.checkpoint.volumes.front().superblock.role_raw==0x180,"current backup role remains canonical");
    AppleSnapshotCatalogRecords catalog;Check(LoadAppleSnapshotCatalog(source,f.checkpoint,101,catalog,error),"load published backup catalog: "+error);
    Check(catalog.inventory.size()==1&&catalog.inventory.front().name_utf8=="backup-base","backup inventory exact");
    Check(catalog.inventory.front().volume.superblock.role_raw==0x180,"historical role retained");
    const auto& original=catalog.snapshots.front().filesystem;
    const auto inode=std::find_if(original.begin(),original.end(),[](const auto& r){return Id(r)==17&&Type(r)==3;});Check(inode!=original.end(),"historic source inode retained");
    ApfsSnapshotScope scope{0,f.image.size(),f.checkpoint.container.superblock.uuid_hex,
        f.checkpoint.volumes.front().superblock.uuid_hex,101,f.checkpoint.container.superblock.xid};
    std::vector<ApfsSnapshotInfo> inventory;
    Check(ApfsSnapshotStore::Enumerate(source,scope,inventory,error)&&inventory.size()==1,"current canonical snapshot identity after ring advancement");
    std::shared_ptr<const NativeApfsSnapshotProjection> historical;
    Check(NativeApfsReader::TryLoadSnapshotProjection(source,inventory.front().identity,historical,error),"canonical immutable backup history: "+error);
    std::vector<std::byte> content;
    for(const auto& extent:historical->View().read_extents_by_inode.at(17)){
        const auto count=static_cast<std::size_t>((std::min)(extent.bytes,static_cast<std::uint64_t>(expected.size()-content.size())));
        std::vector<std::byte> part;Check(source.Read(extent.physical_address,count,part),"read exact historical extent");content.insert(content.end(),part.begin(),part.end());}
    Check(content==expected,"historical shared bytes unchanged independently of old container checkpoint");
    const auto count=std::count_if(original.begin(),original.end(),[](const auto& r){return Id(r)==17&&Type(r)==4;});
    Check(count==4,"all historical user/security/finder/resource xattr records retained");
    AppleSnapshotRetentionView retention;Check(LoadAppleSnapshotRetention(source,f.checkpoint,retention,error),"complete after-operation retention graph: "+error);
    std::vector<std::byte> fork(7);std::size_t read=0;
    {BackupStore current(BackupContext(path));Check(current.PrepareNativeWritePath(),"fresh external-fork owner");
     Check(current.ReadCommittedExtendedAttributeRange(18,"com.apple.ResourceFork",0,fork,read)&&read==7&&fork==HexToBytes("10203040506070"),"unchanged peer external fork exact");}
    const auto stream=historical->View().attribute_stream_extents.find(90);
    Check(stream!=historical->View().attribute_stream_extents.end()&&stream->second&&!stream->second->empty(),"historical external fork owns canonical extent");
    std::vector<std::byte> raw_fork;
    Check(source.Read(stream->second->front().physical_address,7,raw_fork)&&raw_fork==fork,"historical external resource fork unchanged");
    if(std::any_of(original.begin(),original.end(),[](const auto& r){return Id(r)==19&&Type(r)==3;})){
        auto context=BackupContext(path);context.allow_native_snapshot_runtime=false;BackupStore snapshot(context);
        Check(snapshot.PrepareNativeSnapshotReadPath(inventory.front().identity,error),"fresh canonical compressed history owner: "+error);
        std::vector<std::byte> decoded;
        Check(snapshot.ReadCommittedFileRange(L"\\compressed-history",0,16384,decoded)&&decoded==std::vector<std::byte>(16384,std::byte{0x7a}),
            "compressed history decodes independently expected bytes after current publication");
    }
}
void BackupAdmissionAndOperations(){
    auto f=BackupFixture();auto before=Payload(f,17);BackupSave("operations.bin",f.image);const auto c=BackupContext("operations.bin");
    {BackupStore ordinary(BackupContext("operations.bin",false));Check(!ordinary.PrepareNativeWritePath(),"ordinary writer still refuses backup role");}
    {VectorRandomAccessSource source(f.image);std::string error;Check(ValidateBackupImageWriterProfile(source,f.checkpoint,101,error),"explicit complete backup profile: "+error);
     Check(!CheckAppleVolumeWriteFeatures(f.checkpoint.container.superblock,f.checkpoint.volumes.front().superblock,error),"common role gate unchanged");
     auto request=Remove(f,{18});AppleVolumeTransactionPlan plan;Check(!PlanAppleVolumeTransaction(source,f.checkpoint,request,plan,error),"ordinary planner unchanged");}
    {
        BackupStore store(c);Check(store.PrepareNativeWritePath(),"explicit backup writer opens supported graph");
        auto expected=before;expected[4101]=std::byte{0x7A};BackupStore::MutationRequest write;write.operation=BackupStore::MutationOperation::Write;
        write.path=L"\\clone0";write.offset=4101;write.length=1;
        Check(store.StageMutation(write)==BackupStore::MutationStatus::Applied,"backup one-byte COW stages");
        store.SetFilePayloadRangeProvider([&](const auto& name,auto,auto at,std::span<std::byte> out){Check(name==L"\\clone0","exact COW provider target");std::copy_n(expected.begin()+at,out.size(),out.begin());return true;});
        auto status=store.CommitCanonicalTransaction();if(status!=BackupStore::CommitStatus::Committed)std::wcerr<<store.LastCommitFailureReason()<<L" "<<store.LastCommitFailureDetail()<<L'\n';
        Check(status==BackupStore::CommitStatus::Committed,"backup COW publication");
        std::vector<std::byte> bytes;Check(store.ReadCommittedFileRange(L"\\clone0",0,expected.size(),bytes)&&bytes==expected,"COW exact changed byte");
        Check(store.ReadCommittedFileRange(L"\\clone1",0,before.size(),bytes)&&bytes==before,"peer clone unchanged");
    }
    BackupHistorical("operations.bin",before);
    for(unsigned op=0;op<4;++op){
        BackupStore store(c);Check(store.PrepareNativeWritePath(),"fresh ordinary-operation owner");BackupStore::MutationRequest r;
        auto expected=before;expected[4101]=std::byte{0x7A};
        store.SetFilePayloadRangeProvider([&](const auto& name,auto identity,auto at,std::span<std::byte> out){
            Check(name==L"\\renamed"&&identity.object_id==17,"metadata rewrite acquires only the known renamed inode");
            Check(at<=expected.size()&&out.size()<=expected.size()-at,"metadata rewrite stays in independently expected bytes");
            std::copy_n(expected.begin()+at,out.size(),out.begin());return true;});
        r.operation=op==0?BackupStore::MutationOperation::Rename:op==1?BackupStore::MutationOperation::SetFileSize:op==2?BackupStore::MutationOperation::CreateFile:BackupStore::MutationOperation::Delete;
        r.path=op==0?L"\\clone0":op==1?L"\\renamed":L"\\temporary";r.secondary_path=op==0?L"\\renamed":L"";r.length=op==1?4096:0;
        Check(store.StageMutation(r)==BackupStore::MutationStatus::Applied,"backup ordinary operation stages");
        const auto status=store.CommitCanonicalTransaction();if(status!=BackupStore::CommitStatus::Committed)std::wcerr<<store.LastCommitFailureReason()<<L" "<<store.LastCommitFailureDetail()<<L'\n';
        Check(status==BackupStore::CommitStatus::Committed,"backup ordinary operation preserves graph");
    }
    BackupHistorical("operations.bin",before);
    std::cout<<"PASS backup COW rename truncate create unlink and historical metadata\n";
}
void BackupCloneHintAdmission(){
    auto f=BackupFixture();auto records=ReadTree(f);
    std::string error;
    const auto validate=[&](const auto& input,bool backup){
        auto budget=std::make_shared<ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
        return backup?NativeApfsReader::ValidateBackupWriterFileSystemRecords(input,f.checkpoint.container.superblock,
            f.checkpoint.volumes.front().superblock,budget,error):NativeApfsReader::ValidateOrdinaryFileSystemRecords(
            input,f.checkpoint.container.superblock,f.checkpoint.volumes.front().superblock,budget,error);
    };
    const auto flag=[&](auto& input,std::uint64_t oid,std::uint64_t bits){
        auto it=std::find_if(input.begin(),input.end(),[&](const auto& r){return Id(r)==oid&&Type(r)==3;});
        Check(it!=input.end(),"flag test canonical inode");AppleInodeRecord inode;
        Check(ApfsExtendedRecordCodec::DecodeInode(*it,inode,error),error);inode.internal_flags|=bits;
        Check(EncodeAppleInodeRecord(inode,*it,error),error);
    };
    flag(records,17,0x400);
    Check(validate(records,true),"backup known clone hint preserves strict graph validation");
    Check(!validate(records,false)&&error=="VerifierInodeFlagsUnsupported","ordinary source-free profile unchanged");
    auto invalid=records;flag(invalid,2,0x400);
    Check(!validate(invalid,true)&&error=="VerifierInodeFlagsUnsupported","clone hint on directory refused");
    invalid=records;flag(invalid,17,0x20000000);
    Check(!validate(invalid,true),"unknown flags still refuse backup writer");
    std::cout<<"PASS backup clone hint bounded admission\n";
}
void BackupAcceptedCloneCuts(bool compressed=false){
    const std::vector<std::string> cuts=compressed?std::vector<std::string>{"before-apple-checkpoint-switch","after-apple-publish"}:
        std::vector<std::string>{"before-apple-device-write","before-apple-prepublication-flush","before-apple-checkpoint-switch","before-apple-final-flush","after-apple-publish",""};
    for(const auto& cut:cuts){
        const auto tag=(compressed?"compressed-":"")+(cut.empty()?std::string("commit"):cut);const auto image=std::filesystem::absolute(tag+".bin"),wal=std::filesystem::absolute(tag+".wal");
        auto f=compressed?BackupFixture(BackupCompressedSpec(),true):BackupFixture();const auto original=Payload(f,17);BackupSave(image,f.image);const auto c=BackupContext(image);
        BackupStore::CloneReceipt receipt;std::uint64_t seq=0;
        {BackupStore store(c);Check(store.PrepareNativeWritePath(),"accepted backup clone owner");BackupTx tx(L"Strict");tx.SetJournalPath(wal.wstring());tx.SetVolumeIdentity(L"backup-image-writer-v1");
         BackupStore::MutationRequest prepared;
         const auto prepared_ok=store.PrepareNativeClone(L"\\clone0",L"\\accepted",prepared);
         const auto capacity=prepared_ok?store.PreflightNativeCapacityMutation(prepared):BackupStore::MutationStatus::NotReady;
         if(!prepared_ok||capacity!=BackupStore::MutationStatus::Applied)std::wcerr<<L"clone prepare="<<prepared_ok<<L" capacity="<<static_cast<unsigned>(capacity)<<L" "<<store.LastMutationFailureReason()<<L" "<<store.LastCommitFailureReason()<<L" "<<store.LastCommitFailureDetail()<<L'\n';
         Check(prepared_ok&&capacity==BackupStore::MutationStatus::Applied,"backup native clone preflight");
         const auto acceptance=store.AcceptNativeClone(tx,L"\\clone0",L"\\accepted",receipt);
         if(acceptance!=BackupStore::CloneAcceptance::Accepted)std::wcerr<<L"acceptance="<<static_cast<unsigned>(acceptance)<<L" "<<store.LastMutationFailureReason()<<L" "<<store.RecoveryReason()<<L'\n';
         Check(acceptance==BackupStore::CloneAcceptance::Accepted,"native backup clone accepted into original TM");seq=receipt.sequence;
         if(!cut.empty())store.SetCommitStageHook([&](std::string_view stage){return stage!=cut;});
         const auto status=store.CommitCanonicalTransaction({receipt.checkpoint});Check(cut.empty()?status==BackupStore::CommitStatus::Committed:status==BackupStore::CommitStatus::PersistFailed,"actual backup publication cut");
         Check(tx.Watermarks().apfs_durable_sequence==0&&tx.Watermarks().cleanup_sequence==0,"unfinalized original accepted boundary retained");}
        {
            BackupTx tx(L"Strict");tx.SetJournalPath(wal.wstring());tx.SetVolumeIdentity(L"backup-image-writer-v1");std::vector<BackupTx::AcceptedTransaction> accepted;std::string error;
            Check(tx.LoadUnappliedAcceptedTransactions(accepted,&error)&&accepted.size()==1,"fresh original owner authenticates acceptance: "+error);
            Check(accepted.front().accepted_sequence==seq&&accepted.front().preimage_checkpoint_xid==receipt.checkpoint,"same accepted sequence/preimage");
            Check(tx.FlushAcceptedEvidenceDurability(seq),"unconditional fresh original acceptance durability barrier");
            BackupStore recovered(c);Check(recovered.PrepareNativeWritePath(),"fresh backup recovery owner");
            const auto replay=recovered.ReplayNativeClone(accepted.front().mutations.front(),receipt.checkpoint);
            Check(replay==BackupStore::CloneReplay::Staged||replay==BackupStore::CloneReplay::AlreadyPublished,"typed exact backup clone recovery");
            if(replay==BackupStore::CloneReplay::Staged)Check(recovered.CommitPendingMutations({receipt.checkpoint})==BackupStore::CommitStatus::Committed,"backup accepted recovery publishes");
            std::vector<std::byte> bytes;Check(recovered.ReadCommittedFileRange(L"\\accepted",0,original.size(),bytes)&&bytes==original,"accepted clone bytes after recovery");
            Check(recovered.LookupCommittedExtendedAttribute(receipt.target,"com.apple.ResourceFork")->data==HexToBytes("0102030405"),"accepted clone fork preserved");
            Check(const_cast<BlockDevice&>(recovered.Device()).Flush(),"fresh owner flushes exact verified APFS publication before watermark");
            Check(tx.MarkApfsDurableThrough(seq)&&tx.MarkCleanedThrough(seq),"only verified backup publication cleans original boundary");
        }
        BackupHistorical(image,original);std::cout<<"PASS backup accepted clone cut "<<tag<<'\n';
    }
}
void BackupAmbiguousCloneAcceptance(){
    auto f=BackupFixture();const auto original=Payload(f,17);const auto path=std::filesystem::absolute("ambiguous.bin");
    const auto wal=std::filesystem::absolute("ambiguous.wal");BackupSave(path,f.image);const auto c=BackupContext(path);
    {
        BackupStore store(c);Check(store.PrepareNativeWritePath(),"ambiguous backup owner");BackupTx tx(L"Strict");
        tx.SetJournalPath(wal.wstring());tx.SetVolumeIdentity(L"backup-ambiguous");
        tx.SetJournalFaultInjectionHook([](std::string_view stage){return stage=="durable-flush";});BackupStore::CloneReceipt receipt;
        Check(store.AcceptNativeClone(tx,L"\\clone0",L"\\ambiguous",receipt)==BackupStore::CloneAcceptance::RecoveryRequired,
            "actual complete original acceptance with failed durable flush requires recovery");
        Check(store.IsRecoveryRequired()&&!store.LookupWorkingInodeByPath(L"\\ambiguous")&&store.PendingMutationCount()==0,
            "ambiguous acceptance exposes no namespace mutation");
        Check(BackupDisk(path)==f.image,"ambiguous WAL acceptance leaves image byte exact");
    }
    {
        BackupTx tx(L"Strict");tx.SetJournalPath(wal.wstring());tx.SetVolumeIdentity(L"backup-ambiguous");
        std::vector<BackupTx::AcceptedTransaction> accepted;std::string error;
        Check(tx.LoadUnappliedAcceptedTransactions(accepted,&error)&&accepted.size()==1,"fresh original authenticates readable ambiguous acceptance");
        Check(tx.FlushAcceptedEvidenceDurability(accepted[0].accepted_sequence),"fresh unconditional acceptance barrier succeeds");
        BackupStore store(c);Check(store.PrepareNativeWritePath(),"fresh ambiguous image owner");
        Check(store.ReplayNativeClone(accepted[0].mutations[0],accepted[0].preimage_checkpoint_xid)==BackupStore::CloneReplay::Staged,
            "ambiguous clone stages exact retained preimage");
        Check(store.CommitPendingMutations({accepted[0].preimage_checkpoint_xid})==BackupStore::CommitStatus::Committed,"ambiguous clone publication");
        std::vector<std::byte> bytes;Check(store.ReadCommittedFileRange(L"\\ambiguous",0,original.size(),bytes)&&bytes==original,"ambiguous exact native bytes");
        Check(const_cast<BlockDevice&>(store.Device()).Flush()&&tx.MarkApfsDurableThrough(accepted[0].accepted_sequence)&&
            tx.MarkCleanedThrough(accepted[0].accepted_sequence),"ambiguous boundary cleaned only after actual APFS flush");
    }
    BackupHistorical(path,original);std::cout<<"PASS backup ambiguous original WAL flush and fresh recovery\n";
}
void BackupProfileRefusals(){
    for(unsigned scenario=0;scenario<7;++scenario){
        auto f=BackupFixture();const auto expected=f.checkpoint;auto request=Remove(f,{18});
        auto begin=f.image.begin()+static_cast<std::ptrdiff_t>(f.checkpoint.volumes.front().superblock_object.physical_block*kBlockSize);
        std::vector<std::byte> apsb(begin,begin+kBlockSize);std::string error;
        if(scenario==0)PutU16LE(apsb,0x3c4,0x40);
        if(scenario==1)PutU64LE(apsb,0x108,kFsFlagUnencrypted|0x400);
        if(scenario==2)PutU64LE(apsb,0x28,1ull<<63);
        if(scenario==3)PutU64LE(apsb,0x3e8,999);
        if(scenario==4)apsb[0xf0]^=std::byte{1};
        Check(FinalizeAppleObjectChecksum(apsb,error),error);std::copy(apsb.begin(),apsb.end(),begin);
        if(scenario==5)f.image.resize(f.image.size()+kBlockSize);
        const auto path=std::filesystem::absolute("refusal-"+std::to_string(scenario)+".bin");BackupSave(path,f.image);
        VectorRandomAccessSource source(f.image);request.volume_object_id=scenario==6?102:101;
        AppleVolumeTransactionPlan out;out.payload_blocks.push_back(999);
        Check(!PlanAppleBackupImageTransaction(source,expected,request,out,error),"altered canonical role/flags/features/extended metadata/UUID/geometry/volume refused");
        Check(out.payload_blocks.empty()&&out.commit.publication.before_superblock_writes.empty(),"refusal clears previously populated plan");
        Check(BackupDisk(path)==f.image,"backup profile refusal writes no image bytes");
    }
    auto f=BackupFixture();VectorRandomAccessSource source(f.image);auto request=Remove(f,{18});request.required_checkpoint_xids={999};
    AppleVolumeTransactionPlan out;std::string error;
    Check(!PlanAppleBackupImageTransaction(source,f.checkpoint,request,out,error),"missing required accepted preimage pin refuses planning");
    std::cout<<"PASS backup canonical profile and missing-pin refusals\n";
}
class BackupCutTarget final:public AppleCheckpointWriteTarget {
public:
    BackupCutTarget(const std::filesystem::path& path,std::uint64_t cut_block,bool torn_switch,bool fail_flush):
        cut_(cut_block),switch_(torn_switch),fail_flush_(fail_flush){
        handle_=CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
        Check(handle_!=INVALID_HANDLE_VALUE,"exclusive private publication target");
    }
    ~BackupCutTarget(){if(handle_!=INVALID_HANDLE_VALUE)CloseHandle(handle_);}
    bool ReadBlock(std::uint64_t block,std::uint32_t size,std::vector<std::byte>& bytes) override {
        bytes.resize(size);LARGE_INTEGER at;at.QuadPart=block*kBlockSize;DWORD done=0;
        return size==kBlockSize&&SetFilePointerEx(handle_,at,nullptr,FILE_BEGIN)&&ReadFile(handle_,bytes.data(),size,&done,nullptr)&&done==size;
    }
    bool WriteBlock(std::uint64_t block,std::span<const std::byte> bytes) override {
        const bool cut=block==cut_&&!fail_flush_;const auto count=cut?(switch_?32u:static_cast<unsigned>(bytes.size()/2)):static_cast<unsigned>(bytes.size());
        LARGE_INTEGER at;at.QuadPart=block*kBlockSize;DWORD done=0;
        const bool ok=SetFilePointerEx(handle_,at,nullptr,FILE_BEGIN)&&WriteFile(handle_,bytes.data(),count,&done,nullptr)&&done==count;
        ++writes;if(cut){torn=true;Check(FlushFileBuffers(handle_)!=FALSE,"retain actual partial write before simulated interruption");}
        return ok&&!cut;
    }
    bool Flush() override {++flushes;const bool actual=FlushFileBuffers(handle_)!=FALSE;return actual&&!(fail_flush_&&flushes==2);}
    bool torn=false;unsigned writes=0,flushes=0;
private:HANDLE handle_=INVALID_HANDLE_VALUE;std::uint64_t cut_;bool switch_,fail_flush_;
};
void BackupDataPublicationCuts(){
    for(unsigned scenario=0;scenario<3;++scenario){
        auto f=BackupFixture();const auto original=Payload(f,17);auto expected=original;std::fill(expected.begin(),expected.end(),std::byte{0x73});
        AppleVolumeTransactionRequest request;request.volume_object_id=101;request.required_checkpoint_xids={f.checkpoint.container.superblock.xid};
        request.filesystem_records=ReadTree(f);std::erase_if(request.filesystem_records,[](const auto& r){return Id(r)==17&&Type(r)==8;});
        request.released_data_blocks={{kShared,4}};request.data_writes.push_back({17,0,0,expected});
        VectorRandomAccessSource source(f.image);AppleVolumeTransactionPlan plan;std::string error;
        Check(PlanAppleBackupImageTransaction(source,f.checkpoint,request,plan,error),"backup data COW pure plan: "+error);
        Check(plan.payload_blocks.size()==4,"backup data plan contains four fresh COW blocks");
        const auto path=std::filesystem::absolute("data-cut-"+std::to_string(scenario)+".bin");BackupSave(path,f.image);
        {
            BackupCutTarget target(path,scenario==0?plan.payload_blocks.front():plan.commit.publication.superblock_write.physical_block,scenario==1,scenario==2);
            Check(!ExecuteAppleCheckpointPublication(target,plan.commit.publication,error),"actual partial-data/torn-NXSB/final-flush failure");
            Check(scenario==2?target.flushes==2:target.torn,"requested actual write/flush cut reached");
        }
        {
            BackupStore reopened(BackupContext(path));Check(reopened.PrepareNativeWritePath(),"fresh owner after actual file cut");
            std::vector<std::byte> bytes;
            Check(reopened.ReadCommittedFileRange(L"\\clone0",0,original.size(),bytes)&&bytes==(scenario==2?expected:original),"canonical old/new selection after interrupted file publication");
            Check(reopened.ReadCommittedFileRange(L"\\clone1",0,original.size(),bytes)&&bytes==original,"data cut preserves unchanged clone peer");
        }
        BackupHistorical(path,original);std::cout<<"PASS backup actual data publication cut "<<scenario<<'\n';
    }
}
void BackupCompressedHistoryWriter(){
    auto f=BackupFixture(BackupCompressedSpec(),true);const auto path=std::filesystem::absolute("compressed-history-write.bin");
    BackupSave(path,f.image);const auto original=Payload(f,17);auto expected=original;expected[4101]=std::byte{0x51};
    {BackupStore store(BackupContext(path));Check(store.PrepareNativeWritePath(),"writer admits canonical compressed historical fork");
     BackupStore::MutationRequest request;request.path=L"\\clone0";request.offset=4101;request.length=1;
     Check(store.StageMutation(request)==BackupStore::MutationStatus::Applied,"ordinary current write with compressed history stages");
     store.SetFilePayloadRangeProvider([&](const auto& name,auto identity,auto at,std::span<std::byte> bytes){
        Check(name==L"\\clone0"&&identity.object_id==17,"compressed history writer acquires only changed current file");
        std::copy_n(expected.begin()+at,bytes.size(),bytes.begin());return true;});
     const auto status=store.CommitCanonicalTransaction();if(status!=BackupStore::CommitStatus::Committed)std::wcerr<<store.LastCommitFailureDetail()<<L'\n';
     Check(status==BackupStore::CommitStatus::Committed,"current COW preserves immutable compressed history");}
    {BackupStore store(BackupContext(path));Check(store.PrepareNativeWritePath(),"fresh current owner after compressed-history COW");std::vector<std::byte> bytes;
     Check(store.ReadCommittedFileRange(L"\\clone0",0,expected.size(),bytes)&&bytes==expected,"current changed bytes exact");
     Check(store.ReadCommittedFileRange(L"\\clone1",0,original.size(),bytes)&&bytes==original,"compressed history COW preserves live clone peer");}
    BackupHistorical(path,original);BackupAcceptedCloneCuts(true);
    auto invalid=BackupFixture(BackupCompressedSpec(true),true);VectorRandomAccessSource source(invalid.image);std::string error;
    auto request=Remove(invalid,{18});AppleVolumeTransactionPlan plan;
    Check(!PlanAppleBackupImageTransaction(source,invalid.checkpoint,request,plan,error)&&plan.commit.publication.before_superblock_writes.empty(),
        "unknown historical codec refuses current publication before writes");
    std::cout<<"PASS compressed history current COW and accepted clone recovery\n";
}
void BackupRetainedClonePin(){
    auto f=BackupFixture(BackupCompressedSpec(),true);const auto original=Payload(f,17);
    const auto path=std::filesystem::absolute("retained-pin.bin"),wal=std::filesystem::absolute("retained-pin.wal");BackupSave(path,f.image);
    const auto c=BackupContext(path);BackupStore::CloneReceipt receipt;std::uint64_t first=0;
    {
        BackupTx tx(L"Strict");tx.SetJournalPath(wal.wstring());tx.SetVolumeIdentity(L"backup-sequential");
        BackupStore store(c);Check(store.PrepareNativeWritePath(),"retained clone source owner");
        Check(store.AcceptNativeClone(tx,L"\\clone0",L"\\accepted",receipt)==BackupStore::CloneAcceptance::Accepted,"first original accepted clone");
        first=receipt.sequence;Check(store.CommitPendingMutations({receipt.checkpoint})==BackupStore::CommitStatus::Committed,"first accepted clone actual publication");
        Check(tx.Watermarks().cleanup_sequence==0,"original accepted preimage remains uncleaned");
    }
    {
        BackupStore store(c);Check(store.PrepareNativeWritePath(),"later source unlink owner");BackupStore::MutationRequest remove;
        remove.operation=BackupStore::MutationOperation::Delete;remove.path=L"\\clone0";
        Check(store.StageMutation(remove)==BackupStore::MutationStatus::Applied&&store.CommitPendingMutations({receipt.checkpoint})==BackupStore::CommitStatus::Committed,
            "source unlink retains exact original accepted checkpoint");
    }
    {
        BackupTx tx(L"Strict");tx.SetJournalPath(wal.wstring());tx.SetVolumeIdentity(L"backup-sequential");
        std::vector<BackupTx::AcceptedTransaction> batches;std::string error;
        Check(tx.LoadUnappliedAcceptedTransactions(batches,&error)&&batches.size()==1&&batches[0].accepted_sequence==first,"reopened original still owns first boundary");
        Check(tx.FlushAcceptedEvidenceDurability(first),"first reopened original durability barrier");
        BackupStore store(c);Check(store.PrepareNativeWritePath(),"retained first-publication recovery owner");
        Check(store.ValidateRequiredRecoveryCheckpoints({receipt.checkpoint},error),"old uncleaned native preimage is still canonical and owned");
        Check(!store.ValidateRequiredRecoveryCheckpoints({999},error),"wrong native preimage pin refuses");
        Check(!store.LookupCommittedInodeByPath(L"\\clone0")&&store.ReplayNativeClone(batches[0].mutations[0],receipt.checkpoint)==BackupStore::CloneReplay::AlreadyPublished,
            "recovery proves original first publication after later source unlink");
        std::vector<std::byte> bytes;Check(store.ReadCommittedFileRange(L"\\accepted",0,original.size(),bytes)&&bytes==original,"pinned accepted clone bytes exact");
        Check(const_cast<BlockDevice&>(store.Device()).Flush()&&tx.MarkApfsDurableThrough(first)&&tx.MarkCleanedThrough(first),"first original boundary cleans only after durable readback");
        BackupStore::CloneReceipt second;
        Check(store.AcceptNativeClone(tx,L"\\accepted",L"\\second",second)==BackupStore::CloneAcceptance::Accepted&&second.sequence>first&&second.checkpoint>receipt.checkpoint,
            "same original TM and WAL accepts second publication at new exact preimage");
        receipt=second;
        store.SetCommitStageHook([](std::string_view stage){return stage!="before-apple-checkpoint-switch";});
        Check(store.CommitPendingMutations({receipt.checkpoint})==BackupStore::CommitStatus::PersistFailed,"second publication interrupted with original acceptance retained");
    }
    {
        BackupTx tx(L"Strict");tx.SetJournalPath(wal.wstring());tx.SetVolumeIdentity(L"backup-sequential");
        std::vector<BackupTx::AcceptedTransaction> batches;Check(tx.LoadUnappliedAcceptedTransactions(batches)&&batches.size()==1&&
            batches[0].accepted_sequence==receipt.sequence,"fresh original selects only second uncleaned boundary");
        Check(tx.FlushAcceptedEvidenceDurability(receipt.sequence),"second unconditional original durability barrier");
        BackupStore store(c);Check(store.PrepareNativeWritePath()&&store.ReplayNativeClone(batches[0].mutations[0],receipt.checkpoint)==BackupStore::CloneReplay::Staged,
            "second exact accepted clone fresh-owner replay");
        Check(store.CommitPendingMutations({receipt.checkpoint})==BackupStore::CommitStatus::Committed,"second recovery actual APFS publication");
        std::vector<std::byte> bytes;for(const auto* name:{L"\\clone1",L"\\accepted",L"\\second"})
            Check(store.ReadCommittedFileRange(name,0,original.size(),bytes)&&bytes==original,"all surviving clone peer bytes unchanged");
        Check(const_cast<BlockDevice&>(store.Device()).Flush()&&tx.MarkApfsDurableThrough(receipt.sequence)&&tx.MarkCleanedThrough(receipt.sequence),
            "second accepted boundary durable/clean after exact bytes");
    }
    BackupHistorical(path,original);std::cout<<"PASS backup retained pin and two sequential accepted recoveries on one original WAL\n";
}
void SeedBackupHostRecovery(const std::filesystem::path& path,const std::filesystem::path& root,const std::string& volume,const std::string& cut){
    Check(path.is_absolute()&&root.is_absolute()&&path.root_name()==L"D:"&&root.root_name()==L"D:","private D-only actual host recovery inputs");
    Check(cut=="before-switch"||cut=="after-publish"||cut=="watermark-flush"||cut=="cleanup-flush","finite actual host recovery cut");
    const auto at=cut=="before-switch"?5010ull:cut=="after-publish"?5011ull:cut=="watermark-flush"?5012ull:5013ull;
    std::string error;auto device=BlockDevice::OpenExclusiveManagementImage(path.wstring(),0,error);Check(bool(device),error);
    BackupStore store(BackupContext(path),device);Check(store.PrepareNativeWritePath(),"actual host recovery seed owns complete backup graph");
    const auto preimage=*store.CheckpointXid();const auto inode=store.LookupCommittedInodeByPath(L"\\clone0");Check(bool(inode),"seed target exists");
    std::vector<std::byte> expected;Check(store.ReadCommittedFileRange(L"\\clone0",0,inode->logical_size,expected)&&at<expected.size()&&expected[at]!=std::byte{0x7e},"independently bounded seed replacement");expected[at]=std::byte{0x7e};
    Check(volume.size()==60&&volume.starts_with("apfs-recovery-v1-")&&std::all_of(volume.begin(),volume.end(),[](unsigned char c){return c>=32&&c<127;}),"canonical ASCII host recovery identity");
    BackupTx tx(L"Strict");tx.SetJournalPath((root/"write-ahead.wal").wstring());tx.SetVolumeIdentity(std::wstring(volume.begin(),volume.end()));
    PayloadSpool spool(PayloadSpool::Options{root,volume});Check(tx.Begin(),"actual same host WAL begin");
    BackupStore::MutationRequest request;request.path=L"\\clone0";request.offset=at;request.length=1;BackupStore::PayloadIdentity identity;
    Check(store.StageMutation(request,&identity)==BackupStore::MutationStatus::Applied,"actual host seed stages exact Write");
    BackupTx::MutationIntent intent;intent.kind=BackupTx::MutationKind::Write;intent.path=request.path;intent.offset=at;intent.object_id=identity.object_id;
    intent.generation=identity.generation;intent.wal_sequence=tx.NextMutationSequence();PayloadSpool::AppendResult reference;
    const std::vector<std::byte> payload{std::byte{0x7e}};
    Check(spool.Append({volume,identity.object_id,identity.generation,at,intent.wal_sequence,payload},&reference),"actual host original immutable spool append");
    intent.length=intent.payload_length=reference.payload_length;intent.payload_spool_offset=reference.spool_offset;intent.payload_checksum=reference.payload_sha256;
    Check(tx.RecordMutation(intent)&&spool.FlushDirtyState()&&tx.Accept(preimage),"actual same host original WAL acceptance durable");
    store.SetFilePayloadRangeProvider([&](const auto& name,auto id,auto offset,std::span<std::byte> out){
        Check(name==request.path&&id.object_id==identity.object_id&&id.generation==identity.generation&&offset<=expected.size()&&out.size()<=expected.size()-offset,"actual host original full postimage provider");
        std::copy_n(expected.begin()+offset,out.size(),out.begin());return true;});
    const auto stage=cut=="before-switch"?"before-apple-checkpoint-switch":"after-apple-publish";
    store.SetCommitStageHook([&](std::string_view current){return current!=stage;});
    Check(store.CommitPendingMutations({preimage})==BackupStore::CommitStatus::PersistFailed,"actual native publication seed cut");
    const auto accepted=tx.Watermarks().accepted_sequence;
    if(cut=="watermark-flush"||cut=="cleanup-flush"){
        Check(device->Flush(),"actual host seed APFS flush");
        if(cut=="cleanup-flush")Check(tx.MarkApfsDurableThrough(accepted),"APFS watermark truly durable before cleanup ambiguity");
        tx.SetJournalFaultInjectionHook([](std::string_view name){return name=="durable-flush";});
        Check(cut=="cleanup-flush"?!tx.MarkCleanedThrough(accepted):!tx.MarkApfsDurableThrough(accepted),
            "complete original watermark frame then real durable-flush failure");
    }
    std::cout<<"HOST_RECOVERY_SEED cut="<<cut<<" accepted="<<accepted<<" preimage="<<preimage<<" offset="<<at<<'\n';
}
void BackupCleanupMarkerRecovery(){
    auto fixture=BackupFixture(BackupCompressedSpec(),true);const auto original=Payload(fixture,17);
    const auto image=std::filesystem::absolute("cleanup-only.apfs"),root=std::filesystem::absolute("cleanup-original");
    const auto wal=root/"write-ahead.wal";const std::string volume="apfs-recovery-v1-"+std::string(43,'a');
    BackupSave(image,fixture.image);SeedBackupHostRecovery(image,root,volume,"cleanup-flush");
    const auto published=BackupDisk(image),original_wal=BackupDisk(wal);
    Check(!original_wal.empty(),"complete original cleanup evidence exists");
    const auto files=[&](){std::map<std::filesystem::path,std::vector<std::byte>> result;
        for(const auto& entry:std::filesystem::directory_iterator(root))if(entry.is_regular_file()){
            auto bytes=BackupDisk(entry.path());Check(bytes.size()==entry.file_size(),"read exact original journal/spool evidence");
            result.emplace(entry.path().filename(),std::move(bytes));}return result;};
    const auto evidence=files();Check(evidence.size()>=3,"cleanup ambiguity retains original WAL and payload/index evidence");
    std::uint64_t accepted=0;
    {
        BackupTx tx(L"Strict");tx.SetVolumeIdentity(std::wstring(volume.begin(),volume.end()));tx.SetJournalPath(wal.wstring());
        const auto marks=tx.Watermarks();accepted=marks.accepted_sequence;
        Check(tx.RecoveryStateValid()&&accepted&&marks.apfs_durable_sequence==accepted&&marks.cleanup_sequence==accepted,
            "fresh original reads complete Cleaned marker despite failed durable flush");
        std::vector<BackupTx::AcceptedTransaction> pending;Check(tx.LoadAcceptedTransactionsSinceCleanup(pending)&&pending.empty(),
            "readable cleaned boundary has no remaining accepted replay work");
        Check(!tx.FlushAcceptedEvidenceDurability(accepted),"old accepted-only barrier cannot prove retired boundary");
        unsigned flushes=0;tx.SetJournalFaultInjectionHook([&](std::string_view name){if(name=="durable-flush"){++flushes;return true;}return false;});
        Check(!tx.FlushRetainedOriginalEvidenceDurability()&&flushes==1,"actual retained original flush failure is observed once");
        Check(!tx.RecoveryStateValid()&&tx.CurrentState()==BackupTx::State::Failed&&!tx.Begin(),"failed original barrier poisons owner");
        tx.SetJournalFaultInjectionHook({});Check(!tx.FlushRetainedOriginalEvidenceDurability(),"poisoned owner cannot retry by removing fault");
        Check(BackupDisk(image)==published&&BackupDisk(wal)==original_wal&&files()==evidence,
            "failed startup barrier performs zero image/WAL/spool writes or reclamation");
    }
    {
        BackupTx tx(L"Strict");tx.SetVolumeIdentity(std::wstring(volume.begin(),volume.end()));tx.SetJournalPath(wal.wstring());
        const auto lease=tx.ObservedJournalWriterLeaseGeneration();unsigned flushes=0;
        tx.SetJournalFaultInjectionHook([&](std::string_view name){if(name=="durable-flush")++flushes;return false;});
        Check(lease&&tx.FlushRetainedOriginalEvidenceDurability()&&flushes==1,"fresh exact original always flushes readable cleaned marker");
        Check(tx.FlushRetainedOriginalEvidenceDurability()&&flushes==2,"barrier never trusts process-local already-durable fast path");
        Check(tx.ObservedJournalWriterLeaseGeneration()==lease&&tx.ObservedJournalAppendLeaseGeneration()==lease&&
            tx.Watermarks().accepted_sequence==accepted&&tx.Watermarks().cleanup_sequence==accepted,
            "original lease and watermarks unchanged by flush barrier");
        Check(BackupDisk(image)==published&&BackupDisk(wal)==original_wal&&files()==evidence,"successful original barrier only flushes retained bytes");
        PayloadSpool spool(PayloadSpool::Options{root,volume});
        Check(spool.SnapshotCounters().dirty_range_count==1,"original immutable payload remains until durable cleanup admission");
        std::string error;auto device=BlockDevice::OpenExclusiveManagementImage(image.wstring(),0,error);Check(bool(device),error);
        BackupStore store(BackupContext(image),device);Check(store.PrepareNativeWritePath()&&store.FlushBackupImageRecoveryEvidence(),
            "fresh complete canonical backup profile and actual image flush");
        Check(spool.CleanupThroughSequence(accepted)&&spool.SnapshotCounters().dirty_range_count==0,
            "spool reclamation follows flushed original Cleaned evidence and image admission");
        std::vector<std::byte> observed;
        Check(device->ReadForVerification(0,published.size(),observed)&&observed==published&&BackupDisk(wal)==original_wal,
            "clean-only recovery has no image or original WAL append writes");
        auto expected=original;expected[5013]=std::byte{0x7e};std::vector<std::byte> bytes;
        Check(store.ReadCommittedFileRange(L"\\clone0",0,expected.size(),bytes)&&bytes==expected,"complete accepted postimage exact after clean-only recovery");
        Check(store.ReadCommittedFileRange(L"\\clone1",0,original.size(),bytes)&&bytes==original,"clean-only recovery preserves clone peer");
    }
    BackupHistorical(image,original);std::cout<<"PASS actual original Cleaned flush failure, poisoned retry, fresh durability and no-replay cleanup\n";
}
void BackupTypedNamespacePrefix(unsigned begin=0,unsigned end=4){
    for(unsigned operation=begin;operation<end;++operation){
        auto f=BackupFixture(BackupCompressedSpec(),true);const auto original=Payload(f,17);
        const auto stem="typed-prefix-"+std::to_string(operation);
        const auto path=std::filesystem::absolute(stem+".apfs"),wal=std::filesystem::absolute(stem+".wal"),spoolRoot=std::filesystem::absolute(stem+"-spool");
        BackupSave(path,f.image);std::uint64_t sequence=0;std::string error;
        {
            auto device=BlockDevice::OpenExclusiveManagementImage(path.wstring(),0,error);Check(bool(device),error);
            BackupStore store(BackupContext(path),device);Check(store.PrepareNativeWritePath(),"typed backup accepted owner");
            const auto preimage=*store.CheckpointXid();BackupTx tx(L"Strict");tx.SetJournalPath(wal.wstring());tx.SetVolumeIdentity(L"backup-typed-prefix");
            PayloadSpool spool(PayloadSpool::Options{spoolRoot,"backup-typed-prefix"});Check(tx.Begin(),"original typed begin");
            BackupStore::MutationRequest request;
            request.operation=operation==0?BackupStore::MutationOperation::Rename:operation==1?BackupStore::MutationOperation::SetFileSize:
                operation==2?BackupStore::MutationOperation::CreateFile:operation==3?BackupStore::MutationOperation::Delete:BackupStore::MutationOperation::SetAllocationSize;
            request.path=operation==2?L"\\new-file":L"\\clone0";request.secondary_path=operation==0?L"\\renamed":L"";
            request.length=(operation==1||operation==4)?4096:0;BackupStore::PayloadIdentity identity;std::optional<UnlinkOutcome> unlink;
            Check(store.StageMutation(request,&identity,&unlink)==BackupStore::MutationStatus::Applied,"stage actual typed namespace operation");
            BackupTx::MutationIntent intent;intent.kind=operation==0?BackupTx::MutationKind::Rename:operation==1?BackupTx::MutationKind::SetFileSize:
                operation==2?BackupTx::MutationKind::CreateFile:operation==3?BackupTx::MutationKind::Delete:BackupTx::MutationKind::SetAllocationSize;
            intent.path=request.path;intent.secondary_path=request.secondary_path;intent.length=request.length;
            intent.object_id=identity.object_id;intent.generation=identity.generation;intent.unlink_outcome=unlink;
            Check(tx.RecordMutation(intent)&&tx.Accept(preimage),"exact typed original accepted before image publication");sequence=tx.Watermarks().accepted_sequence;
            store.SetFilePayloadRangeProvider([&](const auto&,auto id,auto at,std::span<std::byte> out){
                Check(id.object_id==17&&at<=original.size()&&out.size()<=original.size()-at,"typed rewrite independently expected original payload");
                std::copy_n(original.begin()+at,out.size(),out.begin());return true;});
            store.SetCommitStageHook([](std::string_view stage){return stage!="after-apple-publish";});
            Check(store.CommitPendingMutations({preimage})==BackupStore::CommitStatus::PersistFailed,"typed actual published boundary loses watermark");
        }
        {
            BackupTx tx(L"Strict");tx.SetJournalPath(wal.wstring());tx.SetVolumeIdentity(L"backup-typed-prefix");
            std::vector<BackupTx::AcceptedTransaction> batches;Check(tx.LoadAcceptedTransactionsSinceCleanup(batches)&&batches.size()==1,"reopen exact typed acceptance");
            Check(tx.FlushAcceptedEvidenceDurability(sequence),"typed original unconditional WAL barrier");
            PayloadSpool spool(PayloadSpool::Options{spoolRoot,"backup-typed-prefix"});
            auto device=BlockDevice::OpenExclusiveManagementImage(path.wstring(),0,error);Check(bool(device),error);
            BackupStore store(BackupContext(path),device);Check(store.PrepareNativeWritePath(),"fresh typed backup owner");
            std::vector<std::byte> before,after;Check(device->ReadForVerification(0,f.image.size(),before),"typed before-proof bytes");
            std::vector<std::uint64_t> proven;const auto ok=store.ProveBackupRetainedAcceptedPrefix(tx,spool,wal,"backup-typed-prefix",proven,error);
            std::cout<<"TYPED_PREFIX operation="<<operation<<" proof="<<ok<<" error="<<error<<'\n';
            Check(ok&&proven==std::vector<std::uint64_t>{sequence},"exact typed original publication proves after restart");
            Check(device->ReadForVerification(0,f.image.size(),after)&&before==after,"typed proof has no image writes");
            Check(store.FlushBackupImageRecoveryEvidence()&&tx.MarkApfsDurableThrough(sequence)&&tx.MarkCleanedThrough(sequence),"typed actual flush then original markers");
            std::vector<std::byte> bytes;
            if(operation==0)Check(!store.LookupCommittedInodeByPath(L"\\clone0")&&store.ReadCommittedFileRange(L"\\renamed",0,original.size(),bytes)&&bytes==original,"exact renamed source bytes");
            if(operation==1)Check(store.ReadCommittedFileRange(L"\\clone0",0,4096,bytes)&&bytes==std::vector<std::byte>(original.begin(),original.begin()+4096),"exact truncated source bytes");
            if(operation==2)Check(store.LookupCommittedInodeByPath(L"\\new-file")->logical_size==0,"exact created empty file");
            if(operation==3)Check(!store.LookupCommittedInodeByPath(L"\\clone0"),"exact source unlink");
            if(operation==4)Check(store.LookupCommittedInodeByPath(L"\\clone0")->logical_size==4096&&store.ReadCommittedFileRange(L"\\clone0",0,4096,bytes)&&bytes==std::vector<std::byte>(original.begin(),original.begin()+4096),"exact allocation shrink and bounded EOF");
            Check(store.ReadCommittedFileRange(L"\\clone1",0,original.size(),bytes)&&bytes==original,"typed unchanged clone peer");
        }
        BackupHistorical(path,original);
    }
}
void BackupWriteRecoveryDependency(unsigned scenario=0,bool prefix=false){
    auto f=BackupFixture(BackupCompressedSpec(),true);auto expected=Payload(f,17);expected[4101]=std::byte{0x6d};
    const auto stem=std::string(prefix?"prefix-recovery-":"write-recovery-")+std::to_string(scenario);
    const auto path=std::filesystem::absolute(stem+".bin"),wal=std::filesystem::absolute(stem+".wal");
    const auto spool_path=std::filesystem::absolute(stem+"-spool");BackupSave(path,f.image);
    const auto context=BackupContext(path);std::uint64_t sequence=0,preimage=0;std::string error;
    {
        auto device=BlockDevice::OpenExclusiveManagementImage(path.wstring(),0,error);Check(bool(device),"exclusive backup source: "+error);
        BackupStore store(context,device);Check(store.PrepareNativeWritePath(),"accepted plain write backup owner");preimage=*store.CheckpointXid();
        BackupTx tx(L"Strict");tx.SetJournalPath(wal.wstring());tx.SetVolumeIdentity(L"backup-write-recovery");
        PayloadSpool spool(PayloadSpool::Options{spool_path,"backup-write-recovery"});
        Check(tx.Begin(),"begin original accepted backup Write");BackupStore::MutationRequest write;write.path=L"\\clone0";write.offset=4101;write.length=1;
        BackupStore::PayloadIdentity identity;Check(store.StageMutation(write,&identity)==BackupStore::MutationStatus::Applied,"stage exact current COW Write");
        BackupTx::MutationIntent intent;intent.kind=BackupTx::MutationKind::Write;intent.path=write.path;intent.offset=write.offset;
        intent.object_id=identity.object_id;intent.generation=identity.generation;intent.wal_sequence=tx.NextMutationSequence();
        PayloadSpool::AppendResult reference;const std::vector<std::byte> replacement{std::byte{0x6d}};
        Check(spool.Append({"backup-write-recovery",identity.object_id,identity.generation,write.offset,intent.wal_sequence,replacement},&reference),"persist original exact Write spool reference");
        intent.length=intent.payload_length=reference.payload_length;intent.payload_spool_offset=reference.spool_offset;intent.payload_checksum=reference.payload_sha256;
        Check(tx.RecordMutation(intent),"record exact original Write reference");
        if(scenario==5||scenario==14||prefix){auto extra=intent;extra.kind=BackupTx::MutationKind::SetBasicInfo;extra.offset=extra.length=extra.payload_length=extra.payload_spool_offset=extra.wal_sequence=0;
            extra.payload_checksum={};extra.timestamp_utc=132537600000000000ull;
            BackupStore::MutationRequest basic;basic.operation=BackupStore::MutationOperation::SetBasicInfo;basic.path=write.path;basic.timestamp_utc=extra.timestamp_utc;
            Check(store.StageMutation(basic)==BackupStore::MutationStatus::Applied,"stage actual typed content-time metadata accompanying Write");
            Check(tx.RecordMutation(extra),"record second original typed operation");}
        Check(spool.FlushDirtyState()&&tx.Accept(scenario==7?preimage-1:preimage),"original spool and accepted WAL are durable before APFS writes");sequence=tx.Watermarks().accepted_sequence;
        store.SetFilePayloadRangeProvider([&](const auto& name,auto id,auto at,std::span<std::byte> bytes){
            Check(name==write.path&&id.object_id==identity.object_id&&id.generation==identity.generation,"actual original accepted Write publication identity");
            std::copy_n(expected.begin()+at,bytes.size(),bytes.begin());return true;});
        const std::string cut=scenario==9?"before-apple-device-write":scenario==10?"before-apple-checkpoint-switch":
            scenario==12?"before-apple-final-flush":"after-apple-publish";
        store.SetCommitStageHook([&](std::string_view stage){return stage!=cut;});
        if(scenario==11)Check(SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_WRITE",L"first-half")!=FALSE,"arm actual block-device half-write fault");
        struct ResetWriteFault{~ResetWriteFault(){SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_WRITE",nullptr);}} reset;
        Check(store.CommitPendingMutations({preimage})==BackupStore::CommitStatus::PersistFailed,"actual durable Write publication loses original APFS watermark");
        if(scenario==11)SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_WRITE",nullptr);
        Check(tx.Watermarks().apfs_durable_sequence==0&&tx.Watermarks().cleanup_sequence==0,"lost Write watermark leaves original acceptance uncleaned");
        if(scenario==1){
            Check(device->Flush(),"actual APFS flush before ambiguous watermark");
            tx.SetJournalFaultInjectionHook([](std::string_view stage){return stage=="durable-flush";});
            Check(!tx.MarkApfsDurableThrough(sequence),"complete original Checkpointed marker then actual WAL durable-flush failure");
        }
    }
    {
        BackupTx tx(L"Strict");tx.SetJournalPath(wal.wstring());tx.SetVolumeIdentity(L"backup-write-recovery");
        std::vector<BackupTx::AcceptedTransaction> accepted;Check(tx.LoadAcceptedTransactionsSinceCleanup(accepted)&&accepted.size()==1&&accepted[0].accepted_sequence==sequence,
            "fresh original owner authenticates exact lost-watermark Write");
        if(scenario==1)Check(tx.Watermarks().apfs_durable_sequence==sequence,"fresh original reads complete marker despite previous failed flush");
        Check(tx.FlushAcceptedEvidenceDurability(sequence),"fresh original accepted Write barrier");
        PayloadSpool spool(PayloadSpool::Options{scenario==2?std::filesystem::absolute(stem+"-wrong-spool"):spool_path,"backup-write-recovery"});
        auto device=scenario==6?std::make_shared<BlockDevice>(path.wstring()):BlockDevice::OpenExclusiveManagementImage(path.wstring(),0,error);Check(bool(device),"fresh backup recovery source: "+error);
        BackupStore store(context,device);Check(store.PrepareNativeWritePath(),"fresh backup owner selects valid checkpoint after accepted Write cut");
        if(scenario>=9&&store.CheckpointXid()==preimage){
            const auto& r=accepted[0].mutations[0];std::vector<std::byte> payload;
            Check(spool.ReadPersistedRange({"backup-write-recovery",r.object_id,r.parent_object_id,r.logical_offset,
                r.payload_length,r.payload_offset,r.payload_spool_id,r.payload_sha256},payload)&&payload==std::vector<std::byte>{std::byte{0x6d}},
                "fresh original spool authenticates exact accepted replacement before replay writes");
            BackupStore::MutationRequest replay;replay.path=L"\\clone0";replay.object_id=r.object_id;replay.generation=r.parent_object_id;
            replay.offset=r.logical_offset;replay.length=r.logical_length;
            Check(store.StageMutation(replay)==BackupStore::MutationStatus::Applied,"exact accepted preimage Write stages on fresh owner");
            if(prefix){const auto& basic=accepted[0].mutations.at(1);BackupStore::MutationRequest metadata;
                metadata.operation=BackupStore::MutationOperation::SetBasicInfo;metadata.path=replay.path;
                metadata.object_id=basic.object_id;metadata.generation=basic.parent_object_id;metadata.timestamp_utc=basic.logical_offset;
                Check(store.StageMutation(metadata)==BackupStore::MutationStatus::Applied,"fresh owner replays exact original accompanying metadata");}
            store.SetFilePayloadRangeProvider([&](const auto& name,auto id,auto at,std::span<std::byte> bytes){
                Check(name==replay.path&&id.object_id==r.object_id&&id.generation==r.parent_object_id,"replayed original Write provider exact identity");
                std::copy_n(expected.begin()+at,bytes.size(),bytes.begin());return true;});
            Check(store.CommitPendingMutations({accepted[0].preimage_checkpoint_xid})==BackupStore::CommitStatus::Committed,"fresh accepted Write replay publishes");
        }
        Check(store.CheckpointXid()==preimage+1,"fresh/replayed backup owner selects actual accepted Write successor");
        Check(device->CaptureExclusiveWriteSourceObservation().has_value()!=(scenario==6),"retained proof distinguishes actual exclusive owner");
        std::vector<std::byte> bytes;Check(store.ReadCommittedFileRange(L"\\clone0",0,expected.size(),bytes)&&bytes==expected,"published lost-watermark Write exact bytes");
        if(scenario==3||scenario==8){
            std::uint64_t block=0;
            if(scenario==8){VectorRandomAccessSource historical(f.image);AppleSnapshotCatalogRecords catalog;
                Check(LoadAppleSnapshotCatalog(historical,f.checkpoint,101,catalog,error),error);block=catalog.inventory.front().volume.superblock_object.physical_block;}
            else{std::vector<std::byte> image;Check(device->ReadForVerification(0,f.image.size(),image),"capture current exact extents for corruption test");
                Fixture changed(BackupSpec());changed.image=std::move(image);changed.Reload();
                for(const auto& raw:ReadTree(changed))if(Id(raw)==17&&Type(raw)==8){AppleFileExtentRecord extent;Check(DecodeAppleFileExtentRecord(raw,kBlockSize,extent,error),error);
                    if(4101>=extent.logical_address&&4101-extent.logical_address<extent.length_bytes)block=extent.physical_block+(4101-extent.logical_address)/kBlockSize;}}
            Check(block!=0,"exact corruption destination selected from canonical owner");std::vector<std::byte> corrupt;
            Check(device->ReadForVerification(block*kBlockSize,kBlockSize,corrupt),"read exact corruption source");corrupt[scenario==3?5:64]^=std::byte{1};
            Check(device->Write(block*kBlockSize,corrupt)&&device->Flush(),"retain actual payload or historical metadata corruption before proof");
        }
        std::vector<std::byte> before,after;Check(device->ReadForVerification(0,f.image.size(),before),"capture actual endpoint before proof");
        std::vector<std::uint64_t> proven;
        Check(!store.ProveRetainedAcceptedPrefix(tx,spool,wal,"backup-write-recovery",proven,error)&&error=="RetainedAcceptedProfileUnsupported",
            "ordinary retained-prefix entry remains closed for snapshot-runtime backup owners");
        const bool proof=(scenario==14||prefix)?store.ProveBackupRetainedAcceptedPrefix(tx,spool,wal,scenario==4?"wrong-volume":"backup-write-recovery",proven,error):
            store.ProveBackupRetainedAcceptedWrite(tx,spool,wal,scenario==4?"wrong-volume":"backup-write-recovery",proven,error);
        Check(device->ReadForVerification(0,f.image.size(),after)&&before==after,"retained proof attempts no image writes");
        std::cout<<"WRITE_RECOVERY case="<<scenario<<" proof="<<proof<<" reason="<<error<<" originalAccepted="<<sequence<<" preimage="<<preimage<<'\n';
        if(scenario>=2&&scenario<=8&&(!prefix||scenario!=5)){Check(!proof&&proven.empty()&&!error.empty()&&tx.Watermarks().cleanup_sequence==0&&tx.Watermarks().apfs_durable_sequence==0,
            "wrong spool/published bytes/volume/multiple operations/source lease/preimage/history refuse with no receipt or cleanup");return;}
        Check(proof&&proven==std::vector<std::uint64_t>{sequence},"separate backup proof reconstructs exact original accepted Write publication");
        Check(store.FlushBackupImageRecoveryEvidence()&&tx.MarkApfsDurableThrough(sequence)&&tx.MarkCleanedThrough(sequence),"actual held backup APFS flush precedes Write durable and cleanup markers");
    }
    {BackupTx tx(L"Strict");tx.SetJournalPath(wal.wstring());tx.SetVolumeIdentity(L"backup-write-recovery");std::vector<BackupTx::AcceptedTransaction> pending;
     Check(tx.LoadUnappliedAcceptedTransactions(pending)&&pending.empty(),"fresh original owner confirms accepted Write fully cleaned");}
    BackupHistorical(path,Payload(f,17));std::cout<<"PASS actual accepted backup Write lost-watermark recovery and historical bytes\n";
}
}
#ifndef APFSACCESS_BACKUP_FIXTURES_ONLY
int main(int argc,char**argv){try{Check(std::filesystem::temp_directory_path().root_name()==L"D:","D-only private writer fixtures");const std::string only=argc>1?argv[1]:"";
    if(only=="seed-host-recovery"){Check(argc==6,"explicit private host recovery arguments");SeedBackupHostRecovery(argv[2],argv[3],argv[4],argv[5]);}
    if(only=="inspect-wal"){
        Check(argc==5,"explicit held original WAL inspection inputs");const auto minimum=std::stoull(argv[4]);
        const auto handle=CreateFileW(std::filesystem::path(argv[2]).c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
        Check(handle!=INVALID_HANDLE_VALUE,"open exact original WAL read-only");
        const auto history=WriteAheadLog::ReadAllEvidenceFromHeldHandle(handle,argv[3],{16ull<<20,65536},64ull<<20);CloseHandle(handle);
        Check(history.status==WriteAheadLog::ReadStatus::Ok,"original WAL authenticates without repair");
        for(const auto& record:history.records)if(record.sequence>minimum){
            std::cout<<"WAL sequence="<<record.sequence<<" state="<<static_cast<unsigned>(record.state)<<" operation="<<static_cast<unsigned>(record.operation)
                <<" offset="<<record.logical_offset<<" length="<<record.logical_length<<" payload="<<record.payload_length;
            if(record.operation==WriteAheadLog::OperationKind::SetInodeMetadata){InodeMetadataPatch patch;
                Check(DecodeInodeMetadataPatch(record.inline_payload,patch),"canonical metadata patch");std::cout<<" metadataMask="<<patch.mask;}
            std::cout<<'\n';
            if(record.state==WriteAheadLog::RecordState::Prepared)Check(record.operation==WriteAheadLog::OperationKind::SetInodeMetadata||
                record.operation==WriteAheadLog::OperationKind::SetBasicInfo,"rejected oversized request never accepted Write/Resize/allocation intent");
        }
    }
    if(only=="public-fixture"){auto f=BackupFixture(BackupCompressedSpec(),true);BackupSave("backup-public.apfs",f.image);
        BackupSave("expected-source.bin",Payload(f,17));BackupSave("expected-peer.bin",Payload(f,18));
        std::ofstream metadata("fixture.json");metadata<<"{\"containerUuid\":\""<<f.checkpoint.container.superblock.uuid_hex
            <<"\",\"volumeUuid\":\""<<f.checkpoint.volumes.front().superblock.uuid_hex
            <<"\",\"volumeOid\":101,\"checkpointXid\":"<<f.checkpoint.container.superblock.xid<<"}";
        Check(bool(metadata),"persist private public fixture identity");}
    if(only=="verify-public"){
        const auto before=BackupDisk("backup-seed.apfs"),after=BackupDisk("backup-public.apfs");
        Fixture old(BackupSpec()),now(BackupSpec());old.image=before;old.Reload();now.image=after;now.Reload();
        VectorRandomAccessSource a(before),b(after);AppleSnapshotCatalogRecords original,current;std::string error;
        std::vector<AppleSnapshotMetadataClaim> owners;
        Check(LoadAppleSnapshotCatalog(a,old.checkpoint,101,original,owners,error)&&LoadAppleSnapshotCatalog(b,now.checkpoint,101,current,error),error);
        Check(original.inventory.size()==1&&current.inventory.size()==1&&original.inventory[0].xid==current.inventory[0].xid&&
            original.inventory[0].name_utf8==current.inventory[0].name_utf8,"actual public snapshot inventory unchanged");
        const auto same=[](const auto& first,const auto& second){if(first.size()!=second.size())return false;
            for(std::size_t i=0;i<first.size();++i)if(first[i].key!=second[i].key||first[i].value!=second[i].value)return false;return true;};
        Check(same(original.snapshots[0].filesystem,current.snapshots[0].filesystem)&&same(original.snapshots[0].extentref,current.snapshots[0].extentref),
            "actual public raw historical FS and extent-reference records unchanged");
        AppleSnapshotRetentionView retained;Check(LoadAppleSnapshotRetention(a,old.checkpoint,retained,error),error);
        const auto unchanged=[&](std::uint64_t block){Check(block<before.size()/kBlockSize&&block<after.size()/kBlockSize,"retained actual block bound");
            return std::equal(before.begin()+block*kBlockSize,before.begin()+(block+1)*kBlockSize,after.begin()+block*kBlockSize);};
        std::set<std::uint64_t> historical_metadata;
        for(const auto& owner:owners)if(std::any_of(original.inventory.begin(),original.inventory.end(),[&](const auto& snapshot){return owner.view_xid==snapshot.xid;})){
            Check(owner.block_count&&owner.physical_block<before.size()/kBlockSize&&owner.block_count<=before.size()/kBlockSize-owner.physical_block,"canonical historical metadata claim bound");
            for(std::uint64_t i=0;i<owner.block_count;++i)historical_metadata.insert(owner.physical_block+i);}
        Check(!historical_metadata.empty(),"canonical selected historical metadata owners present");
        for(auto block:historical_metadata)Check(unchanged(block),"actual public raw selected historical metadata block unchanged: "+std::to_string(block));
        std::size_t retired_live=0;
        for(auto block:retained.metadata_blocks)if(!historical_metadata.contains(block)&&!unchanged(block))++retired_live;
        std::cout<<"PUBLIC_HISTORY selectedImmutableBlocks="<<historical_metadata.size()<<" retiredLiveDependencyBlocksChanged="<<retired_live<<'\n';
        for(const auto& extent:retained.payload_extents)for(std::uint64_t i=0;i<extent.block_count;++i)
            Check(unchanged(extent.physical_block+i),"actual public historical payload block unchanged");
        BackupHistorical("backup-public.apfs",BackupDisk("expected-source.bin"));
        if(std::filesystem::exists("expected-current.bin")){
            const auto expected=BackupDisk("expected-current.bin");std::string why;
            auto device=BlockDevice::OpenExclusiveManagementImage(std::filesystem::absolute("backup-public.apfs").wstring(),0,why);Check(bool(device),why);
            BackupStore store(BackupContext("backup-public.apfs"),device);Check(store.PrepareNativeWritePath(),"fresh canonical current verification owner");
            const auto inode=store.LookupCommittedInodeByPath(L"\\clone0");std::vector<std::byte> bytes;
            Check(inode&&inode->logical_size==expected.size()&&store.ReadCommittedFileRange(L"\\clone0",0,expected.size(),bytes)&&bytes==expected,"recovered current payload and refused EOF remain exact");
        }
        Check(now.checkpoint.container.superblock.xid>old.checkpoint.container.superblock.xid,"actual public native checkpoint advanced");
    }
    if(only.empty()||only=="clone"){BackupCloneHintAdmission();BackupAdmissionAndOperations();BackupAcceptedCloneCuts();BackupAmbiguousCloneAcceptance();}
    if(only.empty()||only=="refusals")BackupProfileRefusals();if(only.empty()||only=="data")BackupDataPublicationCuts();
    if(only=="history")BackupCompressedHistoryWriter();
    if(only=="pin")BackupRetainedClonePin();
    if(only=="write-recovery-dependency")BackupWriteRecoveryDependency();
    if(only=="write-watermark-ambiguity")BackupWriteRecoveryDependency(1);
    if(only=="write-proof-refusals")for(unsigned i=2;i<9;++i)BackupWriteRecoveryDependency(i);
    if(only=="write-cuts")for(unsigned i=9;i<13;++i)BackupWriteRecoveryDependency(i);
    if(only=="write-prefix-mixed")BackupWriteRecoveryDependency(14);
    if(only=="typed-prefix")BackupTypedNamespacePrefix();
    if(only=="typed-prefix-allocation")BackupTypedNamespacePrefix(4,5);
    if(only=="cleanup-marker-recovery")BackupCleanupMarkerRecovery();
    if(only=="write-prefix-cuts"){BackupWriteRecoveryDependency(1,true);for(unsigned i=9;i<13;++i)BackupWriteRecoveryDependency(i,true);}
    if(only=="write-prefix-refusals")for(unsigned i=2;i<9;++i)if(i!=5)BackupWriteRecoveryDependency(i,true);
    std::cout<<"RESULT PASS checks="<<checks<<'\n';return 0;}catch(const std::exception& e){std::cerr<<"FAIL checks="<<checks<<": "<<e.what()<<'\n';return 1;}}
#endif
