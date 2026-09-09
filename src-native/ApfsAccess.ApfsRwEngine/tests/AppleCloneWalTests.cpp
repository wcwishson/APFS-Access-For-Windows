#define APPLE_CLONE_TEST_HELPERS_ONLY
#include "AppleCloneCowTests.cpp"
#include "MetadataStore.h"
#include "TransactionManager.h"
#include "WriteAheadLog.h"
#include "../tools/Sha256.h"
#include <filesystem>
namespace {
void AcceptedCloneReplay(bool unlink){
    using Store=MetadataStore;using Tx=TransactionManager;using Wal=WriteAheadLog;
    const auto stem=unlink?"clone-unlink-wal":"clone-write-wal";
    std::filesystem::path run_dir;
    for(unsigned n=0;n<1024;++n){auto path=std::filesystem::current_path()/(std::string(stem)+"-run-"+std::to_string(n));
        if(std::filesystem::create_directory(path)){run_dir=std::move(path);break;}}
    Check(!run_dir.empty(),"fresh private WAL evidence directory");
    const auto image_path=run_dir/"source.apfs";
    const auto wal_path=run_dir/"accepted.wal";
    Fixture fixture(CloneSpec());const auto original=Payload(fixture,18);auto expected=original;
    const std::uint64_t offset=kBlockSize+83;std::vector<std::byte> accepted_bytes(29,std::byte{0x67});
    std::copy(accepted_bytes.begin(),accepted_bytes.end(),expected.begin()+offset);
    {std::ofstream file(image_path,std::ios::binary);file.write(reinterpret_cast<const char*>(fixture.image.data()),fixture.image.size());Check(!!file,"WAL source fixture saved on D");}
    const std::wstring volume_id=unlink?L"clone-unlink-445":L"clone-write-445";
    Store::VolumeContext context;context.device_path=image_path.wstring();context.volume_object_id=101;context.allow_legacy_scaffold_for_fixtures=false;
    std::uint64_t source_xid=0,sequence=0;
    {Store source(context);Check(source.PrepareNativeWritePath(),"foreground shared source opens");source_xid=*source.CheckpointXid();
        Tx tx(L"Strict");tx.SetJournalPath(wal_path.wstring());tx.SetVolumeIdentity(volume_id);Check(tx.Begin(),"begin actual journal transaction");
        const auto record=[&](Store::MutationRequest request,Tx::MutationKind kind){Store::PayloadIdentity identity;std::optional<UnlinkOutcome> outcome;
            Check(source.StageMutation(request,&identity,&outcome)==Store::MutationStatus::Applied,"foreground clone mutation stages");
            Tx::MutationIntent intent;intent.kind=kind;intent.path=request.path;intent.offset=request.offset;intent.length=request.length;
            intent.object_id=identity.object_id;intent.generation=identity.generation;intent.unlink_outcome=outcome;intent.wal_sequence=tx.NextMutationSequence();
            if(kind==Tx::MutationKind::Write){intent.inline_payload=accepted_bytes;intent.payload_length=accepted_bytes.size();std::string error,hex;
                auto hash=apfsaccess::observer::Sha256Stream::Create(error);Check(hash&&hash->Update(accepted_bytes.data(),accepted_bytes.size())&&hash->FinalHex(hex),"accepted payload SHA-256");
                for(std::size_t i=0;i<intent.payload_checksum.size();++i)intent.payload_checksum[i]=static_cast<std::uint8_t>(std::stoul(hex.substr(i*2,2),nullptr,16));}
            Check(tx.RecordMutation(intent),"actual WAL records identity and unlink witness");};
        Store::MutationRequest write;write.path=L"\\clone1";write.offset=offset;write.length=accepted_bytes.size();record(write,Tx::MutationKind::Write);
        if(unlink){Store::MutationRequest remove;remove.operation=Store::MutationOperation::Delete;remove.path=L"\\clone0";record(remove,Tx::MutationKind::Delete);}
        Check(tx.Accept(source_xid),"accept WAL against exact cloned preimage");sequence=tx.Watermarks().accepted_sequence;
        Check(sequence&&tx.Watermarks().apfs_durable_sequence==0&&tx.Watermarks().cleanup_sequence==0,"accepted work precedes publication and cleanup");}
    std::filesystem::copy_file(wal_path,wal_path.string()+".accepted-original");
    for(unsigned attempt=0;attempt<2;++attempt){Tx replay(L"Strict");replay.SetJournalPath(wal_path.wstring());replay.SetVolumeIdentity(volume_id);
        std::vector<Tx::AcceptedTransaction> transactions;std::string error;
        Check(replay.LoadUnappliedAcceptedTransactions(transactions,&error)&&transactions.size()==1,"restart decodes one accepted transaction");
        const auto& accepted=transactions.front();Check(accepted.preimage_checkpoint_xid==source_xid&&accepted.accepted_sequence==sequence,"restart retains exact checkpoint pin");
        Store recovered(context);Check(recovered.PrepareNativeWritePath()&&recovered.CheckpointXid()==source_xid,"restart selects unchanged prepublication checkpoint");
        for(const auto& record:accepted.mutations){Store::MutationRequest request;request.path.assign(record.path_utf8.begin(),record.path_utf8.end());
            request.object_id=record.object_id;request.generation=record.parent_object_id;request.offset=record.logical_offset;request.length=record.logical_length;request.expected_unlink_outcome=record.unlink_outcome;
            request.operation=record.operation==Wal::OperationKind::Write?Store::MutationOperation::Write:Store::MutationOperation::Delete;
            if(record.operation==Wal::OperationKind::Write){Check(Wal::InlinePayloadIsConsistent(record)&&record.inline_payload==accepted_bytes,"actual WAL inline checksum binds accepted bytes");auto corrupt=record;corrupt.inline_payload[0]^=std::byte{1};Check(!Wal::InlinePayloadIsConsistent(corrupt),"changed accepted bytes fail checksum");}
            Store::PayloadIdentity identity;std::optional<UnlinkOutcome> outcome;Check(recovered.StageMutation(request,&identity,&outcome)==Store::MutationStatus::Applied&&identity.object_id==request.object_id&&identity.generation==request.generation&&outcome==record.unlink_outcome,"replay restores exact inode generation and unlink witness");}
        recovered.SetFilePayloadRangeProvider([&](const auto& path,auto identity,auto begin,std::span<std::byte> bytes){
            Check(path==L"\\clone1"&&identity.object_id==18&&identity.generation==source_xid+1&&begin<=expected.size()&&bytes.size()<=expected.size()-begin,"replayed payload remains inode-bound");std::copy_n(expected.begin()+begin,bytes.size(),bytes.begin());return true;});
        if(attempt==0)recovered.SetCommitStageHook([](std::string_view stage){return stage!="before-apple-checkpoint-switch";});
        const auto result=recovered.CommitCanonicalTransaction({accepted.preimage_checkpoint_xid});
        if(attempt==0){Check(result==Store::CommitStatus::PersistFailed,"interrupt actual accepted replay before checkpoint switch");Check(replay.Watermarks().apfs_durable_sequence==0&&replay.Watermarks().cleanup_sequence==0,"interruption cannot certify or clean accepted WAL");continue;}
        Check(result==Store::CommitStatus::Committed,"fresh retry publishes accepted clone COW");
        {Store fresh(context);Check(fresh.PrepareNativeWritePath(),"independent accepted replay reopen");std::vector<std::byte> bytes;
            Check(fresh.ReadCommittedFileRange(L"\\clone1",0,expected.size(),bytes)&&bytes==expected,"accepted writer bytes survive retry/reopen");
            if(unlink)Check(!fresh.LookupCommittedInodeByPath(L"\\clone0"),"accepted original clone unlink persists");
            else Check(fresh.ReadCommittedFileRange(L"\\clone0",0,original.size(),bytes)&&bytes==original,"other clone unchanged after accepted replay");}
        Check(replay.MarkApfsDurableThrough(sequence)&&replay.MarkCleanedThrough(sequence),"watermarks advance only after verified canonical bytes");}
    Tx finished(L"Strict");finished.SetJournalPath(wal_path.wstring());finished.SetVolumeIdentity(volume_id);std::vector<Tx::AcceptedTransaction> remaining;
    Check(finished.LoadUnappliedAcceptedTransactions(remaining)&&remaining.empty()&&finished.Watermarks().cleanup_sequence==sequence,"next journal restart has no accepted work to replay");
}
}
int main(){try{AcceptedCloneReplay(false);AcceptedCloneReplay(true);std::cout<<"PASS clone accepted WAL "<<checks<<" checks\n";return 0;}catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<"\n";return 1;}}
