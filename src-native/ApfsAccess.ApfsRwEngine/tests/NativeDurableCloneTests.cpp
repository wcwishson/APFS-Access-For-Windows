#include <windows.h>
#undef CreateFile
#undef CreateDirectory
#define APPLE_CLONE_TEST_HELPERS_ONLY
#include "AppleCloneCowTests.cpp"
#include "MetadataStore.h"
#include "TransactionManager.h"
#include "NativeClone.h"
#include "InodeMetadataPatch.h"
#include <windows.h>
#include <bcrypt.h>
#undef CreateFile
#undef CreateDirectory
#include <filesystem>
namespace {
using Store=MetadataStore;using Tx=TransactionManager;using Wal=WriteAheadLog;
void Save(const std::filesystem::path& p,const std::vector<std::byte>& b){std::ofstream f(p,std::ios::binary);f.write(reinterpret_cast<const char*>(b.data()),b.size());Check(!!f,"save fixture");}
std::vector<std::byte> Disk(const std::filesystem::path& p){std::ifstream f(p,std::ios::binary);std::vector<char> c((std::istreambuf_iterator<char>(f)),{});std::vector<std::byte>b(c.size());std::memcpy(b.data(),c.data(),c.size());return b;}
Store::VolumeContext Context(const std::filesystem::path& p){Store::VolumeContext c;c.device_path=p.wstring();c.volume_object_id=101;c.allow_legacy_scaffold_for_fixtures=false;return c;}
Store::MutationRequest Request(Fixture& f){NativeCloneProof p;p.checkpoint=f.checkpoint.container.superblock.xid;p.volume=101;p.source=17;p.generation=p.checkpoint;p.target=f.checkpoint.volumes.front().superblock.next_object_id;p.container_uuid=f.checkpoint.container.superblock.uuid_hex;p.volume_uuid=f.checkpoint.volumes.front().superblock.uuid_hex;
for(const auto& r:ReadTree(f))if(Id(r)==17)p.records.push_back(r);std::string e;Check(SortAppleBtreeRecords(p.records,AppleBtreeKeyOrder::FileSystemCaseSensitive,e),e);
Store::MutationRequest r;r.operation=static_cast<Store::MutationOperation>(16);r.path=L"\\new";r.secondary_path=L"\\clone0";r.object_id=p.target;r.generation=p.checkpoint+1;r.inline_payload=EncodeNativeClone(p);r.length=r.inline_payload.size();return r;}
void AdmissionRedGreen(){Fixture f(CloneSpec(1));Save("admission.apfs",f.image);Store s(Context(std::filesystem::absolute("admission.apfs")));Check(s.PrepareNativeWritePath(),"source opens");auto r=Request(f);

auto status=s.StageMutation(r);if(status!=Store::MutationStatus::Applied)std::wcerr<<L"admission diagnostic "<<s.LastMutationFailureReason()<<L"\n";Check(status==Store::MutationStatus::Applied,"typed native clone creation stages (baseline RED)");}
#ifndef BASELINE_RED
void AcceptanceReplay(){
 auto spec=CloneSpec(2);std::string encode_error;
 AppleSecurityRecord security;security.acl_flags=0x100;security.entries.push_back({{},1,3});
 std::vector<std::byte> acl;Check(ApfsExtendedRecordCodec::EncodeSecurity(security,acl,encode_error),"encode native ACL fixture");
 for(auto attr:{AppleXattrRecord{17,"com.apple.system.Security",kAppleXattrDataEmbedded,acl},AppleXattrRecord{17,"com.apple.ResourceFork",kAppleXattrDataEmbedded,HexToBytes("1234567890abcdef")}}){apfsaccess::catalog::BtreeRecord record;Check(EncodeAppleXattrRecord(attr,record,encode_error),encode_error);spec.volumes[0].filesystem_records.push_back(record);}
 for(auto& record:spec.volumes[0].filesystem_records)if(Id(record)==17&&Type(record)==3){AppleInodeRecord inode;Check(ApfsExtendedRecordCodec::DecodeInode(record,inode,encode_error),encode_error);inode.create_time=1234567890123;inode.modification_time=2345678901234;inode.change_time=3456789012345;inode.access_time=4567890123456;Check(EncodeAppleInodeRecord(inode,record,encode_error),encode_error);}
 Fixture f(spec);Save("accept.apfs",f.image);auto c=Context(std::filesystem::absolute("accept.apfs"));auto original=Payload(f,17);std::uint64_t xid=0,seq=0,target=0;
 {Store s(c);Check(s.PrepareNativeWritePath(),"accept source opens");xid=*s.CheckpointXid();
  Store::MutationRequest r;Check(s.PrepareNativeClone(L"\\clone0",L"\\new",r),"prepare source proof");target=r.object_id;
  Check(!s.LookupWorkingInodeByPath(L"\\new")&&s.PendingMutationCount()==0,"prepare leaves namespace and pending state untouched");
  auto before=Disk("accept.apfs");auto capacity=s.PreflightNativeCapacityMutation(r,{xid});if(capacity!=Store::MutationStatus::Applied)std::wcerr<<L"capacity diagnostic "<<s.LastMutationFailureReason()<<L" "<<s.LastCommitFailureReason()<<L" "<<s.LastCommitFailureDetail()<<L"\n";Check(capacity==Store::MutationStatus::Applied,"real clone planner capacity preview");
  Store::MutationRequest retry;Check(s.PrepareNativeClone(L"\\clone0",L"\\new",retry)&&r.inline_payload==retry.inline_payload&&r.object_id==retry.object_id,"preview returns inode reservation and exact proof");
  Check(Disk("accept.apfs")==before&&!s.LookupWorkingInodeByPath(L"\\new"),"preview writes nothing and exposes no target");
  Tx tx(L"Strict");tx.SetJournalPath(std::filesystem::absolute("accept.wal").wstring());tx.SetVolumeIdentity(L"native-clone-486");
  bool flush_saw_hidden=false;tx.SetJournalFaultInjectionHook([&](std::string_view stage){if(stage=="durable-flush"){Check(!s.LookupWorkingInodeByPath(L"\\new"),"target hidden until WAL flush returns");flush_saw_hidden=true;}return false;});
  Store::CloneReceipt receipt;auto accepted=s.AcceptNativeClone(tx,L"\\clone0",L"\\new",receipt);
  if(accepted!=Store::CloneAcceptance::Accepted)std::wcerr<<L"accept diagnostic "<<s.LastMutationFailureReason()<<L" commit "<<s.LastCommitFailureReason()<<L" "<<s.LastCommitFailureDetail()<<L"\n";
  Check(accepted==Store::CloneAcceptance::Accepted&&flush_saw_hidden,"durable acceptance API succeeds");seq=receipt.sequence;
  Check(receipt.checkpoint==xid&&receipt.target==target&&tx.AcceptedSequenceForTransaction(receipt.transaction_id)==seq,"receipt retains sequence identity");
  Check(s.LookupWorkingInodeByPath(L"\\new")&&!s.LookupCommittedInodeByPath(L"\\new"),"accepted target staged but not published");
  Check(s.LookupWorkingExtendedAttribute(target,"user.keep")->data==HexToBytes("cafebabe012345"),"working xattrs preserve source");
  Store::MutationRequest remove;remove.operation=Store::MutationOperation::Delete;remove.path=L"\\clone0";
  Check(s.StageMutation(remove)!=Store::MutationStatus::Applied&&s.PendingMutationCount()==1,"source cannot mutate in isolated accepted transaction");
 }
  std::filesystem::copy_file("accept.wal","accept-original.wal",
      std::filesystem::copy_options::overwrite_existing);
 for(unsigned attempt=0;attempt<2;++attempt){Tx tx(L"Strict");tx.SetJournalPath(std::filesystem::absolute("accept.wal").wstring());tx.SetVolumeIdentity(L"native-clone-486");std::vector<Tx::AcceptedTransaction> a;std::string error;
  Check(tx.LoadUnappliedAcceptedTransactions(a,&error)&&a.size()==1,"restart reads accepted clone: "+error);Check(a[0].preimage_checkpoint_xid==xid&&a[0].accepted_sequence==seq,"exact accepted preimage and sequence survive");
  auto record=a[0].mutations[0];Store::MutationRequest r;Check(Store::NativeCloneFromWal(record,r),"typed clone WAL decode");
  auto bad=record;bad.inline_payload[0]^=std::byte{1};Check(!Store::NativeCloneFromWal(bad,r),"unknown payload version rejected");bad=record;bad.object_id++;Check(!Store::NativeCloneFromWal(bad,r),"target incarnation mismatch rejected");
  Check(Store::NativeCloneFromWal(record,r),"restore valid record");
  Store s(c);Check(s.PrepareNativeWritePath()&&s.CheckpointXid()==xid,"reopen exact unmodified source checkpoint");
  auto corrupt=r;corrupt.secondary_path=L"\\missing";Check(s.StageMutation(corrupt)!=Store::MutationStatus::Applied&&s.PendingMutationCount()==0&&!s.LookupWorkingInodeByPath(L"\\new"),"missing source refuses atomically");
  corrupt=r;NativeCloneProof wrong_volume;Check(DecodeNativeClone(corrupt.inline_payload,wrong_volume),"decode volume-bound proof");wrong_volume.volume_uuid=std::string(32,'1');corrupt.inline_payload=EncodeNativeClone(wrong_volume);corrupt.length=corrupt.inline_payload.size();Check(s.StageMutation(corrupt)!=Store::MutationStatus::Applied&&s.PendingMutationCount()==0,"same object IDs cannot substitute a different native volume UUID");
  corrupt=r;corrupt.inline_payload.back()^=std::byte{1};Check(s.StageMutation(corrupt)!=Store::MutationStatus::Applied&&s.PendingMutationCount()==0,"modified exact preimage refuses atomically");
  Check(s.ReplayNativeClone(record,xid)==Store::CloneReplay::Staged,"accepted clone replay stages exact source");
  unsigned payload_calls=0;s.SetFilePayloadRangeProvider([&](const auto&,auto,auto,std::span<std::byte>){++payload_calls;return false;});
  if(!attempt)s.SetCommitStageHook([](std::string_view stage){return stage!="before-apple-checkpoint-switch";});
  auto status=s.CommitCanonicalTransaction({xid});if(status!=Store::CommitStatus::Committed)std::wcerr<<L"publish diagnostic "<<s.LastCommitFailureReason()<<L" "<<s.LastCommitFailureDetail()<<L"\n";
  if(!attempt){Check(status==Store::CommitStatus::PersistFailed,"interrupted publication retains accepted replay");Check(tx.Watermarks().apfs_durable_sequence==0&&tx.Watermarks().cleanup_sequence==0,"failed publication never advances watermarks");continue;}
  Check(status==Store::CommitStatus::Committed&&payload_calls==0,"native clone publishes with zero payload acquisition");
  Store fresh(c);Check(fresh.PrepareNativeWritePath(),"fresh clone publication opens");std::vector<std::byte> bytes;Check(fresh.ReadCommittedFileRange(L"\\new",0,original.size(),bytes)&&bytes==original,"new native clone reads exact bytes");
  auto inode=fresh.LookupCommittedInodeByPath(L"\\new");Check(inode&&inode->owner==501&&inode->group==20&&inode->mode==0100640,"clone preserves Mac uid gid mode");
  Check(fresh.LookupCommittedExtendedAttribute(target,"user.keep")->data==HexToBytes("cafebabe012345"),"published native xattr preserved");
  Check(fresh.LookupCommittedExtendedAttribute(target,"com.apple.system.Security")->data==acl,"native ACL copied byte exactly");
  Check(fresh.LookupCommittedExtendedAttribute(target,"com.apple.ResourceFork")->data==HexToBytes("1234567890abcdef"),"embedded resource fork copied byte exactly");
  f.image=Disk("accept.apfs");f.Reload();CheckGraph(f);auto records=ReadTree(f);bool shared=false;for(const auto& e:records)if(Id(e)==target&&Type(e)==8)shared=ReadU64LE(e.value,8).value()==kShared;Check(shared,"target shares source physical extent rather than copied payload");
  Check(Payload(f,17,xid)==original,"accepted old generation is pinned");
  Check(fresh.ReplayNativeClone(record,xid)==Store::CloneReplay::AlreadyPublished&&fresh.PendingMutationCount()==0,"restart after publication proves exact accepted result without recreating target");
  Store::MutationRequest remove;remove.operation=Store::MutationOperation::Delete;remove.path=L"\\clone0";
  Check(fresh.StageMutation(remove)==Store::MutationStatus::Applied&&fresh.CommitCanonicalTransaction({xid})==Store::CommitStatus::Committed,"source unlinked after accepted publication with original preimage pinned");
  Store after_unlink(c);Check(after_unlink.PrepareNativeWritePath()&&!after_unlink.LookupCommittedInodeByPath(L"\\clone0"),"unlinked source absent on restart");
  Check(after_unlink.ReplayNativeClone(record,xid)==Store::CloneReplay::AlreadyPublished,"replay authenticates first publication after source unlink, never later source state");
  Check(tx.MarkApfsDurableThrough(seq)&&tx.MarkCleanedThrough(seq),"only verified publication advances durable and cleanup");
 }
 Tx done(L"Strict");done.SetJournalPath(std::filesystem::absolute("accept.wal").wstring());done.SetVolumeIdentity(L"native-clone-486");std::vector<Tx::AcceptedTransaction>a;Check(done.LoadUnappliedAcceptedTransactions(a)&&a.empty(),"clean replay after publication is empty");
 Store cow(c);Check(cow.PrepareNativeWritePath(),"COW writer opens accepted clone");auto expected=original;std::fill_n(expected.begin()+kBlockSize+17,29,std::byte{0x7a});Store::MutationRequest w;w.path=L"\\new";w.offset=kBlockSize+17;w.length=29;Check(cow.StageMutation(w)==Store::MutationStatus::Applied,"accepted clone first write stages");std::uint64_t acquired=0;
 cow.SetFilePayloadRangeProvider([&](const auto& path,auto id,auto at,std::span<std::byte>b){Check(path==L"\\new"&&id.object_id==target,"first COW identity");acquired+=b.size();std::copy_n(expected.begin()+at,b.size(),b.begin());return true;});
 Check(cow.CommitCanonicalTransaction({xid})==Store::CommitStatus::Committed&&acquired==kBlockSize,"accepted clone first write allocates/acquires one block");
 Store fresh(c);Check(fresh.PrepareNativeWritePath(),"COW reopen");std::vector<std::byte> bytes;Check(fresh.ReadCommittedFileRange(L"\\new",0,expected.size(),bytes)&&bytes==expected,"first COW output exact");Check(fresh.ReadCommittedFileRange(L"\\clone1",0,original.size(),bytes)&&bytes==original,"first COW preserves other shared owner payload");
}
void Refusal(){Fixture f(CloneSpec(1));Save("refusal.apfs",f.image);auto c=Context(std::filesystem::absolute("refusal.apfs"));
 {Store s(c);Check(s.PrepareNativeWritePath(),"refusal source opens");Store::MutationRequest r;
 Check(!s.PrepareNativeClone(L"\\clone0",L"\\clone0",r),"existing target explicitly refused");Check(!s.PrepareNativeClone(L"\\missing",L"\\new",r),"missing source refused before inode allocation");
 Check(s.PrepareNativeClone(L"\\clone0",L"\\new",r)&&r.object_id==f.checkpoint.volumes.front().superblock.next_object_id,"refusal reuses unconsumed inode allocation");
 Tx tx(L"Strict");tx.SetJournalPath(std::filesystem::absolute("refusal.wal").wstring());tx.SetVolumeIdentity(L"refusal");tx.SetJournalFaultInjectionHook([](std::string_view stage){return stage=="durable-flush";});Store::CloneReceipt receipt;
 auto status=s.AcceptNativeClone(tx,L"\\clone0",L"\\new",receipt);Check(status==Store::CloneAcceptance::RecoveryRequired&&!s.LookupWorkingInodeByPath(L"\\new")&&s.PendingMutationCount()==0&&s.IsRecoveryRequired(),"ambiguous WAL flush exposes no target and requires recovery");
 Check(Disk("refusal.apfs")==f.image,"failed acceptance never writes image");
 }
 Tx replay(L"Strict");replay.SetJournalPath(std::filesystem::absolute("refusal.wal").wstring());replay.SetVolumeIdentity(L"refusal");std::vector<Tx::AcceptedTransaction> accepted;Check(replay.LoadUnappliedAcceptedTransactions(accepted)&&accepted.size()==1,"restart recovers complete acceptance whose flush result was ambiguous");
 Store recovered(c);Check(recovered.PrepareNativeWritePath()&&recovered.ReplayNativeClone(accepted[0].mutations[0],accepted[0].preimage_checkpoint_xid)==Store::CloneReplay::Staged,"ambiguous acceptance replays exact preimage");Check(recovered.CommitPendingMutations({accepted[0].preimage_checkpoint_xid})==Store::CommitStatus::Committed,"ambiguous acceptance publishes on recovery");
}

void HashRecord(Wal::Record& r){BCRYPT_ALG_HANDLE a=nullptr;Check(BCryptOpenAlgorithmProvider(&a,BCRYPT_SHA256_ALGORITHM,nullptr,0)>=0,"hash provider");auto result=BCryptHash(a,nullptr,0,reinterpret_cast<PUCHAR>(r.inline_payload.data()),static_cast<ULONG>(r.inline_payload.size()),r.payload_sha256.data(),32);BCryptCloseAlgorithmProvider(a,0);Check(result>=0,"hash WAL payload");}
Wal::Record Record(const Store::MutationRequest& request){Wal::Record r;r.volume_identity="codec";r.transaction_id=1;r.sequence=1;r.operation=Wal::OperationKind::CloneFile;r.object_id=request.object_id;r.parent_object_id=request.generation;r.payload_length=request.length;r.inline_payload=request.inline_payload;for(auto c:request.path)r.path_utf8.push_back(static_cast<char>(c));for(auto c:request.secondary_path)r.secondary_path_utf8.push_back(static_cast<char>(c));HashRecord(r);return r;}
void CodecCases(){Fixture f(CloneSpec(1));auto record=Record(Request(f));Check(Wal::NativeCloneIsConsistent(record),"new typed WAL payload valid");
 Check(Wal::EncodeForTest(record,1).empty()&&Wal::EncodeForTest(record,3).empty()&&Wal::EncodeForTest(record,99).empty(),"clone refuses prior/unknown envelope versions");
 auto bad=record;bad.inline_payload[0]=std::byte{0};HashRecord(bad);Check(!Wal::NativeCloneIsConsistent(bad),"unknown clone payload version refused even with matching checksum");
 for(unsigned kind=0;kind<3;++kind){Wal::Record r;r.volume_identity="legacy";r.transaction_id=1;r.sequence=1;r.path_utf8="\\file";r.object_id=17;r.parent_object_id=8;
  if(kind==0)r.operation=Wal::OperationKind::CreateFile;
  if(kind==1){r.operation=Wal::OperationKind::Write;r.inline_payload={std::byte{42}};r.payload_length=r.logical_length=1;HashRecord(r);}
  if(kind==2){r.parent_object_id=7;r.operation=Wal::OperationKind::Delete;r.unlink_outcome=UnlinkOutcome{17,7,8,2,1,0,"\\file"};}
  auto bytes=Wal::EncodeForTest(r,static_cast<std::uint16_t>(kind+1));Check(!bytes.empty(),"legacy WAL envelope encodes");auto path=std::filesystem::path("legacy-")+=std::to_string(kind)+".wal";{std::ofstream out(path,std::ios::binary);out.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());}
  auto read=Wal::ReadAll(path,"legacy");Check(read.status==Wal::ReadStatus::Ok&&read.records.size()==1,"prior WAL version still decodes");
 }
 bad=record;bad.operation=static_cast<Wal::OperationKind>(999);bad.inline_payload.clear();bad.payload_length=0;auto bytes=Wal::EncodeForTest(bad);
 if(!bytes.empty()){std::ofstream out("unknown.wal",std::ios::binary);out.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());out.close();Check(Wal::ReadAll("unknown.wal","codec").status!=Wal::ReadStatus::Ok,"unknown opcode rejected on read");}else Check(true,"unknown opcode rejected on encode");
}
void ChangedSourceCases(){for(unsigned scenario=0;scenario<3;++scenario){auto stem="changed-"+std::to_string(scenario);Fixture f(CloneSpec(1));auto path=std::filesystem::absolute(stem+".apfs");Save(path,f.image);auto c=Context(path);Store original(c);Check(original.PrepareNativeWritePath(),"changed source opens");Store::MutationRequest clone;Check(original.PrepareNativeClone(L"\\clone0",L"\\new",clone),"source proof captured before change");auto record=Record(clone);auto xid=*original.CheckpointXid();
  Store change(c);Check(change.PrepareNativeWritePath(),"independent source changer opens");Store::MutationRequest mutation;mutation.path=L"\\clone0";
  if(scenario==0){mutation.operation=Store::MutationOperation::SetInodeMetadata;InodeMetadataPatch patch;patch.mask=InodeMetadataPatch::Owner;patch.owner=502;Check(EncodeInodeMetadataPatch(patch,mutation.inline_payload),"encode source UID change");mutation.length=mutation.inline_payload.size();}
  else mutation.operation=Store::MutationOperation::Delete;
  Check(change.StageMutation(mutation)==Store::MutationStatus::Applied&&change.CommitCanonicalTransaction({xid})==Store::CommitStatus::Committed,"source change commits with accepted old preimage retained");
  if(scenario==2){mutation={};mutation.operation=Store::MutationOperation::CreateFile;mutation.path=L"\\clone0";Check(change.StageMutation(mutation)==Store::MutationStatus::Applied&&change.CommitCanonicalTransaction({xid})==Store::CommitStatus::Committed,"replacement source uses new inode");}
  Store fresh(c);Check(fresh.PrepareNativeWritePath(),"changed source replay opens");Check(fresh.ReplayNativeClone(record,xid)==Store::CloneReplay::Refused&&fresh.PendingMutationCount()==0&&!fresh.LookupWorkingInodeByPath(L"\\new"),"missing/replaced/modified source cannot silently substitute later checkpoint");
  Check(fresh.StageMutation(clone)!=Store::MutationStatus::Applied&&fresh.PendingMutationCount()==0,"raw staging also binds exact accepted checkpoint");
 }}
void UnsupportedMetadata(){for(unsigned scenario=0;scenario<6;++scenario){auto spec=CloneSpec(scenario==5?2:1);auto& v=spec.volumes[0];std::string error;
  if(scenario<2){AppleXattrRecord a;a.object_id=17;a.name_utf8=scenario==0?"user.external":"com.apple.ResourceFork";a.flags=kAppleXattrDataStream;a.data.resize(48);PutU64LE(a.data,0,3000);PutU64LE(a.data,8,kBlockSize);PutU64LE(a.data,16,kBlockSize);apfsaccess::catalog::BtreeRecord r;Check(EncodeAppleXattrRecord(a,r,error),error);v.filesystem_records.push_back(r);Check(EncodeAppleDataStreamIdRecord({3000,1},r,error),error);v.filesystem_records.push_back(r);Check(EncodeAppleFileExtentRecord({3000,0,kBlockSize,132,0,kBlockSize},r,error),error);v.filesystem_records.push_back(r);Check(EncodeApplePhysicalExtentRecord({132,1,kApplePhysicalExtentKindNew,3000,1},r,error),error);v.extentref_records.push_back(r);v.additional_file_system_allocated_blocks++;v.next_object_id=4000;spec.authoritative_seeded_main_blocks.push_back({132,std::vector<std::byte>(kBlockSize,std::byte{9})});}
  if(scenario==2){AppleXattrRecord a{17,"com.apple.decmpfs",kAppleXattrDataEmbedded,{}};a.data=CloneCompressionBytes();apfsaccess::catalog::BtreeRecord r;Check(EncodeAppleXattrRecord(a,r,error),error);v.filesystem_records.push_back(r);}
  if(scenario==3){for(auto& r:v.filesystem_records)if(Id(r)==17&&Type(r)==3){AppleInodeRecord inode;Check(ApfsExtendedRecordCodec::DecodeInode(r,inode,error),error);inode.extended_fields.push_back({42,0,{std::byte{1}}});Check(EncodeAppleInodeRecord(inode,r,error),error);}}
  if(scenario==4){for(auto& r:v.filesystem_records)if(Id(r)==17&&Type(r)==3){AppleInodeRecord inode;Check(ApfsExtendedRecordCodec::DecodeInode(r,inode,error),error);inode.uncompressed_size--;for(auto& field:inode.extended_fields)if(field.type==8)PutU64LE(field.data,0,inode.uncompressed_size);Check(EncodeAppleInodeRecord(inode,r,error),error);}}
  if(scenario==5){std::erase_if(v.filesystem_records,[](const auto& r){return Id(r)==17&&(Type(r)==6||Type(r)==8);});for(auto& r:v.filesystem_records){if(Id(r)==17&&Type(r)==3){AppleInodeRecord inode;Check(ApfsExtendedRecordCodec::DecodeInode(r,inode,error),error);inode.private_id=18;Check(EncodeAppleInodeRecord(inode,r,error),error);}if(Id(r)==18&&Type(r)==6)Check(EncodeAppleDataStreamIdRecord({18,2},r,error),error);}Check(EncodeApplePhysicalExtentRecord({128,4,kApplePhysicalExtentKindNew,18,1},v.extentref_records.front(),error),error);}
  Fixture f(spec);auto path=std::filesystem::absolute("unsupported-"+std::to_string(scenario)+".apfs");Save(path,f.image);Store store(Context(path));const auto ready=store.PrepareNativeWritePath();Store::MutationRequest out;Check(!ready||!store.PrepareNativeClone(L"\\clone0",L"\\new",out),"external/compressed/unknown/unaligned/private-alias metadata refuses before acceptance");Check(store.PendingMutationCount()==0&&!store.LookupWorkingInodeByPath(L"\\new")&&Disk(path)==f.image,"unsupported class refusal is atomic");
 }}

void PreservedMetadataReplay()
{
    for (unsigned scenario = 0; scenario != 3; ++scenario) {
        const auto stem = "preserved-metadata-" + std::to_string(scenario);
        auto spec = CloneSpec(1);
        std::string error;
        for (auto& record : spec.volumes[0].filesystem_records) {
            if (Id(record) != 17 || Type(record) != 3) continue;
            AppleInodeRecord inode;
            Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), error);
            inode.uncompressed_size = 0;
            Check(EncodeAppleInodeRecord(inode, record, error), error);
        }
        Fixture fixture(spec);
        const auto path = std::filesystem::absolute(stem + ".apfs");
        Save(path, fixture.image);
        const auto context = Context(path);
        const auto destination = scenario == 0 ? L"\\new" :
            scenario == 1 ? L"\\Folder\\new" : L"\\folder\\new";
        Store::CloneReceipt receipt;
        {
            Store store(context);
            Check(store.PrepareNativeWritePath(), "metadata source opens");
            if (scenario) {
                Store::MutationRequest directory;
                directory.operation = Store::MutationOperation::CreateDirectory;
                directory.path = L"\\Folder";
                Check(store.StageMutation(directory) == Store::MutationStatus::Applied,
                    "original parent spelling stages");
                Check(store.CommitCanonicalTransaction() == Store::CommitStatus::Committed,
                    "original parent spelling publishes");
            }
            Tx journal(L"Strict");
            journal.SetJournalPath(std::filesystem::absolute(stem + ".wal").wstring());
            journal.SetVolumeIdentity(L"clone-metadata-replay");
            Check(store.AcceptNativeClone(journal, L"\\clone0", destination, receipt) ==
                Store::CloneAcceptance::Accepted, "metadata clone accepted");
            Check(store.CommitCanonicalTransaction({receipt.checkpoint}) ==
                Store::CommitStatus::Committed, "metadata clone published");
        }
        fixture.image = Disk(path);
        fixture.Reload();
        unsigned owners = 0;
        for (const auto& record : ReadTree(fixture)) {
            if (Type(record) != 3 || (Id(record) != 17 && Id(record) != receipt.target)) continue;
            AppleInodeRecord inode;
            Check(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), error);
            Check(inode.uncompressed_size == 0, "clone preserves native uncompressed size on both owners");
            ++owners;
        }
        Check(owners == 2, "both clone owners inspected");
        Tx journal(L"Strict");
        journal.SetJournalPath(std::filesystem::absolute(stem + ".wal").wstring());
        journal.SetVolumeIdentity(L"clone-metadata-replay");
        std::vector<Tx::AcceptedTransaction> accepted;
        Check(journal.LoadUnappliedAcceptedTransactions(accepted) && accepted.size() == 1,
            "accepted metadata clone survives restart");
        Store reopened(context);
        Check(reopened.PrepareNativeWritePath(), "published clone reopens");
        Check(reopened.ReplayNativeClone(accepted[0].mutations[0],
            accepted[0].preimage_checkpoint_xid) == Store::CloneReplay::AlreadyPublished &&
            reopened.PendingMutationCount() == 0, "metadata clone replay recognizes publication");
    }
}

#include "NativeDurableCloneQuotaTests.h"
#include "NativeInodePaddingTests.h"
#endif
}
int main(){try{
    // Isolate fixed filenames from the shared CTest working directory and from
    // reruns: each invocation runs in a fresh private directory.
    const auto root=std::filesystem::current_path();std::filesystem::path run_dir;
    for(unsigned n=0;n<1024;++n){auto path=root/("native-durable-clone-run-"+std::to_string(n));
        if(std::filesystem::create_directory(path)){run_dir=std::move(path);break;}}
    Check(!run_dir.empty(),"fresh private durable-clone evidence directory");
    std::filesystem::current_path(run_dir);
    try{AdmissionRedGreen();
#ifndef BASELINE_RED
    AcceptanceReplay();Refusal();CodecCases();ChangedSourceCases();UnsupportedMetadata();QuotaCases();PreservedMetadataReplay();NativeInodePaddingCases();
#endif
    }catch(...){std::filesystem::current_path(root);throw;}
    std::filesystem::current_path(root);
    std::cout<<"PASS native durable clone "<<checks<<" checks\n";return 0;}catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<"\n";return 1;}}
