#define NATIVE_HARD_LINK_TEST_HELPERS_ONLY
#include "NativeHardLinkAcceptanceTests.cpp"
#include "PayloadSpool.h"
#include "NativeApfsReader.h"

namespace {
void PayloadExclusion()
{
    std::vector<ApplePhysicalExtentRecord> payload{{128,8193,kApplePhysicalExtentKindNew,17,1}};
    NativeHardLinkDigest digest{};
    Check(NativeHardLinkExtentHash(payload,digest),"metadata extent commitment has no 32 MiB payload ceiling");
    AppleCheckpointPublicationPlan publication;publication.block_size=4096;
    publication.superblock_write.physical_block=1;publication.superblock_write.bytes.resize(4096);
    AppleCheckpointPlannedWrite write;write.physical_block=9000;write.bytes.resize(4096);
    publication.before_superblock_writes.push_back(write);
    Check(NativeHardLinkWritesExcludePayload(publication,payload,10240),"complete metadata writes exclude a large live payload");
    publication.before_superblock_writes[0].physical_block=128;
    Check(!NativeHardLinkWritesExcludePayload(publication,payload,10240),"payload start overlap refuses");
    publication.before_superblock_writes[0].physical_block=8320;
    Check(!NativeHardLinkWritesExcludePayload(publication,payload,10240),"payload final block overlap refuses");
    publication.before_superblock_writes[0].physical_block=127;publication.before_superblock_writes[0].bytes.resize(8192);
    Check(!NativeHardLinkWritesExcludePayload(publication,payload,10240),"spanning range overlap refuses");
    publication.before_superblock_writes[0].physical_block=8321;publication.before_superblock_writes[0].bytes.resize(4096);
    Check(NativeHardLinkWritesExcludePayload(publication,payload,10240),"exact adjacent metadata range is disjoint");
    publication.superblock_write.physical_block=129;
    Check(!NativeHardLinkWritesExcludePayload(publication,payload,10240),"checkpoint destination cannot overlap payload");
    std::cout<<"PASS no-payload-write extent exclusion\n";
}
void LaterAliasPlanner()
{
    Fixture fixture(HardLinkSpec(1));
    auto records=ReadTree(fixture); std::string error; NativeHardLinkPlan plan;
    const auto policy=ApfsNamePolicy::FromIncompatibleFeatures(kIncompatCaseInsensitive);
    auto floor=fixture.checkpoint.volumes.front().superblock.next_object_id;
    for(unsigned aliases=1;aliases<=4;++aliases) {
        const auto before=records;
        Check(PrepareNativeHardLinkPlan(records,policy,{17,2,floor,123456789,"alias"+std::to_string(aliases)},plan,error),
            "complete sibling census adds later alias:"+error);
        Check(plan.source_links==aliases&&plan.primary_parent==2&&plan.primary_name=="clone0"&&
            plan.next_object_id==floor+(aliases==1?2:1),"primary and exact one/two sibling reservation");
        if(aliases>1) for(const auto& row:before) if(Type(row)==5||Type(row)==12) {
            Check(std::any_of(plan.after.begin(),plan.after.end(),[&](const auto& next){return next.key==row.key&&next.value==row.value;}),
                "later alias preserves every prior sibling/map byte");
        }
        records=plan.after;floor=plan.next_object_id;
    }
    for(unsigned fault=0;fault<10;++fault) {
        auto wrong=records;
        const auto find=[&](unsigned type){return std::find_if(wrong.begin(),wrong.end(),[&](const auto& row){return Type(row)==type&&
            (type==12||Id(row)==17);});};
        auto inode=find(3);
        if(fault==0||fault==6||fault==7||fault==9) {
            AppleInodeRecord value;Check(ApfsExtendedRecordCodec::DecodeInode(*inode,value,error),error);
            if(fault==0)++value.children_or_links;
            if(fault==6)value.parent_id=99;
            if(fault==7)for(auto& field:value.extended_fields)if(field.type==4)field.data={std::byte{'x'},std::byte{0}};
            if(fault==9)value.children_or_links=INT32_MAX;
            Check(EncodeAppleInodeRecord(value,*inode,error),error);
        } else if(fault==1)wrong.erase(find(5));
        else if(fault==2)wrong.erase(find(12));
        else if(fault==3) {
            auto it=find(12);AppleSiblingMapRecord value;
            Check(ApfsExtendedRecordCodec::DecodeSiblingMap(*it,value,error),error);++value.file_id;
            Check(EncodeAppleSiblingMapRecord(value,*it,error),error);
        } else if(fault==4) {
            auto it=find(5);AppleSiblingLinkRecord value;
            Check(ApfsExtendedRecordCodec::DecodeSiblingLink(*it,value,error),error);value.name_utf8="foreign";
            Check(EncodeAppleSiblingLinkRecord(value,*it,error),error);
        } else if(fault==5) {
            auto it=std::find_if(wrong.begin(),wrong.end(),[](const auto& row){return Type(row)==9;});
            AppleDirectoryRecord value;Check(ApfsExtendedRecordCodec::DecodeDirectory(*it,policy,value,error),error);
            value.extended_fields.clear();Check(EncodeAppleDirectoryRecord(value,policy,*it,error),error);
        } else {
            apfsaccess::catalog::BtreeRecord extra;Check(EncodeAppleSiblingMapRecord({floor-1,18},extra,error),error);wrong.push_back(extra);
        }
        Check(!PrepareNativeHardLinkPlan(wrong,policy,{17,2,floor,123456789,"refused"},plan,error)&&
            plan.before.empty()&&plan.after.empty(),"wrong sibling/map/count/primary ownership refuses atomically");
    }
    std::cout<<"PASS later-alias complete sibling planner\n";
}

void StrictSiblingProjection()
{
    auto spec=HardLinkSpec(1);std::string error;
    for(auto& record:spec.volumes.front().filesystem_records)if(Type(record)==3){
        AppleInodeRecord inode;Check(ApfsExtendedRecordCodec::DecodeInode(record,inode,error),error);
        for(auto& field:inode.extended_fields)field.flags=0;
        Check(EncodeAppleInodeRecord(inode,record,error),error);
    }
    Fixture fixture(spec);auto records=ReadTree(fixture);NativeHardLinkPlan plan;
    const auto policy=ApfsNamePolicy::FromIncompatibleFeatures(kIncompatCaseInsensitive);
    Check(PrepareNativeHardLinkPlan(records,policy,{17,2,fixture.checkpoint.volumes.front().superblock.next_object_id,123456789,"alias"},plan,error),error);
    for(unsigned fault=0;fault<9;++fault){
        auto changed=plan.after;
        auto row=std::find_if(changed.begin(),changed.end(),[](const auto& r){return Type(r)==9;});
        AppleDirectoryRecord directory;Check(ApfsExtendedRecordCodec::DecodeDirectory(*row,policy,directory,error),error);
        if(fault==1)directory.extended_fields.front().type=2;
        if(fault==2)directory.extended_fields.front().flags=1;
        if(fault==3)directory.extended_fields.front().data.resize(7);
        if(fault==4)directory.extended_fields.front().data.assign(8,std::byte{0});
        if(fault==5)directory.extended_fields.front().data.front()^=std::byte{0x40};
        if(fault==6)directory.extended_fields.clear();
        if(fault==7)directory.extended_fields.push_back({2,0,std::vector<std::byte>(8)});
        if(fault==8)directory.flags=4;
        Check(EncodeAppleDirectoryRecord(directory,policy,*row,error),"encode explicit directory metadata control:"+error);
        NativeApfsVolumeProjection projection;const auto budget=std::make_shared<ApfsReadBudget>(65536,256ULL<<20,262144,256ULL<<20);
        const auto okay=NativeApfsReader::TryProjectOrdinaryFileSystemRecords(changed,fixture.checkpoint.container.superblock,
            fixture.checkpoint.volumes.front().superblock,budget,projection,error);
        Check(okay==(fault==0),"strict complete sibling field/census control:"+error);
    }
    std::cout<<"PASS strict canonical sibling projection controls\n";
}

void CheckAliases(Store& store,const std::vector<std::wstring>& aliases,std::uint32_t count,
    const std::vector<std::byte>& expected,const std::vector<std::byte>& peer)
{
    for(const auto& path:aliases) {
        const auto inode=store.LookupCommittedInodeByPath(path);
        Check(inode&&inode->object_id==17&&inode->link_count==count,"every alias names the exact shared inode/count");
        std::vector<std::byte> bytes;
        Check(store.ReadCommittedFileRange(path,0,expected.size(),bytes)&&bytes==expected,"all alias bytes are exact");
    }
    std::vector<std::byte> bytes;
    Check(store.ReadCommittedFileRange(L"\\clone1",0,peer.size(),bytes)&&bytes==peer,"independent clone peer remains byte-exact");
}

void LaterAliasRecovery(const std::string& cut)
{
    auto fixture=HardLinkFixture(100);const auto original=Payload(fixture,17);
    const auto stem="later-"+(cut.empty()?std::string("clean"):cut);
    const auto image=std::filesystem::path(stem+".apfs"),wal=std::filesystem::path(stem+".wal");
    SaveImage(image,fixture.image);const auto context=HardLinkContext(image);
    std::uint64_t sequence=0;
    {
        std::string error;auto lease=BlockDevice::OpenExclusiveManagementImage(context.device_path,0,error);
        Check(!!lease,"later alias exclusive owner:"+error);Store store(context,lease);
        Check(store.PrepareNativeWritePath(),"later alias source opens");Journal journal(L"Strict");OpenJournal(journal,wal,fixture);
        Store::HardLinkReceipt receipt;
        Check(store.AcceptNativeHardLink(journal,L"\\clone0",L"\\alias1",123456789,receipt,error)==Store::HardLinkAcceptance::Accepted&&
            store.PublishOrRecoverNativeHardLink(journal,error)==Store::HardLinkPublication::Published,"first alias original publication:"+error);
        CheckAliases(store,{L"\\clone0",L"\\alias1"},2,original,original);
        Check(store.AcceptNativeHardLink(journal,L"\\alias1",L"\\alias2",123456790,receipt,error)==Store::HardLinkAcceptance::Accepted,
            "third alias accepted from a nonprimary sibling:"+error);sequence=receipt.sequence;
        if(!cut.empty())store.SetCommitStageHook([&](auto stage){return stage!=cut;});
        const auto result=store.PublishOrRecoverNativeHardLink(journal,error);
        Check(result==(cut.empty()?Store::HardLinkPublication::Published:Store::HardLinkPublication::RecoveryRequired),
            "third alias exact publication cut:"+error);
        if(!cut.empty())Check(journal.Watermarks().cleanup_sequence<sequence,"interrupted third alias retains original debt");
    }
    {
        std::string error;auto lease=BlockDevice::OpenExclusiveManagementImage(context.device_path,0,error);
        Check(!!lease,"fresh later alias lease:"+error);Store store(context,lease);
        Check(store.PrepareNativeWritePath(),"fresh later alias source opens");Journal journal(L"Strict");OpenJournal(journal,wal,fixture);
        if(!cut.empty())Check(store.PublishOrRecoverNativeHardLink(journal,error)==
            (cut=="before-apple-final-flush"?Store::HardLinkPublication::AlreadyPublished:Store::HardLinkPublication::Published),
            "fresh exact third alias recovery:"+error);
        CheckAliases(store,{L"\\clone0",L"\\alias1",L"\\alias2"},3,original,original);
        Store::HardLinkReceipt receipt;
        Check(store.AcceptNativeHardLink(journal,L"\\alias2",L"\\alias3",123456791,receipt,error)==Store::HardLinkAcceptance::Accepted&&
            store.PublishOrRecoverNativeHardLink(journal,error)==Store::HardLinkPublication::Published,"fourth alias original publication:"+error);
        CheckAliases(store,{L"\\clone0",L"\\alias1",L"\\alias2",L"\\alias3"},4,original,original);
        Check(journal.Watermarks().accepted_sequence==receipt.sequence&&journal.Watermarks().cleanup_sequence==receipt.sequence,
            "later aliases preserve monotonic settled original boundaries");
    }
    std::cout<<"PASS later alias recovery "<<cut<<'\n'<<std::flush;
}

void BindBytes(Store& store,Store::PayloadIdentity identity,const std::vector<std::byte>& bytes)
{
    store.SetFilePayloadRangeProvider([identity,&bytes](const auto&,auto requested,std::uint64_t offset,std::span<std::byte> out){
        if(requested.object_id!=identity.object_id||requested.generation!=identity.generation||
            offset>bytes.size()||out.size()>bytes.size()-offset)return false;
        std::copy_n(bytes.begin()+static_cast<std::ptrdiff_t>(offset),out.size(),out.begin());return true;
    });
}

void Settle(Journal& journal,const BlockDevice& device,std::uint64_t sequence)
{
    Check(const_cast<BlockDevice&>(device).Flush(),"flush actual canonical image before original fences");
    Check(journal.MarkApfsDurableThrough(sequence)&&journal.MarkCleanedThrough(sequence)&&
        journal.FlushRetainedOriginalEvidenceDurability(),"flush original durable and cleaned fences");
}

void AliasLifecycle()
{
    auto spec=CloneSpec(2);std::string fixture_error;
    std::erase_if(spec.volumes.front().filesystem_records,[](const auto& row){return Type(row)==4&&Id(row)==17;});
    for(auto& row:spec.volumes.front().filesystem_records)if(Type(row)==3){
        AppleInodeRecord inode;Check(ApfsExtendedRecordCodec::DecodeInode(row,inode,fixture_error),fixture_error);
        for(auto& field:inode.extended_fields)field.flags=0;
        Check(EncodeAppleInodeRecord(inode,row,fixture_error),fixture_error);
    }
    Fixture fixture(spec);const auto peer=Payload(fixture,17);auto expected=peer;
    const auto image=std::filesystem::path("lifecycle.apfs"),wal=std::filesystem::path("lifecycle.wal");
    SaveImage(image,fixture.image);const auto context=HardLinkContext(image);
    PayloadSpool::Options options;options.root=std::filesystem::absolute("lifecycle-spool");
    options.volume_identity="apfs-vol:"+fixture.checkpoint.container.superblock.uuid_hex+":101";
    {
        std::string error;auto lease=BlockDevice::OpenExclusiveManagementImage(context.device_path,0,error);
        Check(!!lease,"lifecycle exclusive owner:"+error);Store store(context,lease);
        Check(store.PrepareNativeWritePath(),"lifecycle canonical source");Journal journal(L"Strict");OpenJournal(journal,wal,fixture);
        for(unsigned n=1;n<=3;++n){Store::HardLinkReceipt receipt;
            Check(store.AcceptNativeHardLink(journal,n==1?L"\\clone0":L"\\alias1",L"\\alias"+std::to_wstring(n),123456789+n,receipt,error)==
                Store::HardLinkAcceptance::Accepted&&store.PublishOrRecoverNativeHardLink(journal,error)==Store::HardLinkPublication::Published,
                "lifecycle original alias:"+error);
        }
        CheckAliases(store,{L"\\clone0",L"\\alias1",L"\\alias2",L"\\alias3"},4,expected,peer);
    }
    const std::vector<std::byte> patch(29,std::byte{0xa6});const std::uint64_t offset=4096+17;
    std::copy(patch.begin(),patch.end(),expected.begin()+offset);
    for(unsigned step=0;step<3;++step){
        const auto cut=step==0?"before-apple-checkpoint-switch":"before-apple-final-flush";
        {
            std::string error;auto lease=BlockDevice::OpenExclusiveManagementImage(context.device_path,0,error);
            Check(!!lease,"lifecycle mutation owner:"+error);Store store(context,lease);Check(store.PrepareNativeWritePath(),"lifecycle mutation opens");
            Journal journal(L"Strict");OpenJournal(journal,wal,fixture);PayloadSpool spool(options);
            const auto before=ImageBytes(*lease);const auto checkpoint=store.AuthoritativeAppleCheckpointView()->container.superblock.xid;
            Store::MutationRequest request;
            request.path=step==2?L"\\clone0":L"\\alias2";
            request.operation=step==0?Store::MutationOperation::Write:step==1?Store::MutationOperation::Rename:Store::MutationOperation::Delete;
            if(step==0){request.offset=offset;request.length=patch.size();}
            if(step==1)request.secondary_path=L"\\renamed";
            Store::PayloadIdentity identity;std::optional<UnlinkOutcome> outcome;
            Check(store.StageMutation(request,&identity,&outcome)==Store::MutationStatus::Applied,"stage exact alias lifecycle mutation");
            Journal::MutationIntent intent;intent.kind=step==0?Journal::MutationKind::Write:step==1?Journal::MutationKind::Rename:Journal::MutationKind::Delete;
            intent.path=request.path;intent.secondary_path=request.secondary_path;intent.object_id=identity.object_id;intent.generation=identity.generation;
            intent.offset=request.offset;intent.length=request.length;intent.unlink_outcome=outcome;
            if(step==0){
                PayloadSpool::AppendResult appended;intent.wal_sequence=journal.NextMutationSequence();
                Check(spool.Append({options.volume_identity,identity.object_id,identity.generation,offset,intent.wal_sequence,patch},&appended)&&
                    spool.FlushPayloadBytes()&&spool.FlushDirtyState(),"real alias write spool is durable before original acceptance");
                intent.payload_spool_offset=appended.spool_offset;intent.payload_length=appended.payload_length;
                intent.payload_checksum=appended.payload_sha256;intent.inline_payload=patch;BindBytes(store,identity,expected);
            }
            Check(journal.Begin()&&journal.RecordMutation(intent)&&journal.Accept(checkpoint),"actual typed alias mutation acceptance");
            const auto sequence=journal.Watermarks().accepted_sequence;
            Check(ImageBytes(*lease)==before&&journal.FlushAcceptedEvidenceDurability(sequence),"original acceptance is durable before APFS mutation");
            store.SetCommitStageHook([&](auto stage){return stage!=cut;});
            const auto result=store.CommitCanonicalTransaction({checkpoint});
            Check(result!=Store::CommitStatus::Committed&&journal.Watermarks().cleanup_sequence<sequence,"actual alias publication cut retains original debt");
        }
        {
            std::string error;auto lease=BlockDevice::OpenExclusiveManagementImage(context.device_path,0,error);
            Check(!!lease,"fresh alias recovery owner:"+error);Store store(context,lease);Check(store.PrepareNativeWritePath(),"fresh alias recovery source");
            Journal journal(L"Strict");OpenJournal(journal,wal,fixture);PayloadSpool spool(options);
            std::vector<Journal::AcceptedTransaction> batches;
            Check(journal.LoadAcceptedTransactionsSinceCleanup(batches,&error)&&batches.size()==1&&batches.front().mutations.size()==1,
                "fresh recovery consumes one actual original transaction:"+error);
            const auto& batch=batches.front();const auto& row=batch.mutations.front();
            Check(journal.FlushAcceptedEvidenceDurability(batch.accepted_sequence),"fresh original evidence barrier");
            if(step==0){
                std::vector<std::byte> persisted;
                Check(spool.ReadPersistedRange({options.volume_identity,row.object_id,row.parent_object_id,row.logical_offset,row.payload_length,
                    row.payload_offset,row.payload_spool_id,row.payload_sha256},persisted)&&persisted==patch,"fresh replay exact physical spool reference");
                Store::MutationRequest replay;replay.operation=Store::MutationOperation::Write;replay.path=L"\\alias2";
                replay.object_id=row.object_id;replay.generation=row.parent_object_id;replay.offset=row.logical_offset;replay.length=row.logical_length;
                Store::PayloadIdentity identity;
                Check(store.StageMutation(replay,&identity)==Store::MutationStatus::Applied,"restage accepted alias write incarnation");
                BindBytes(store,identity,expected);
                Check(store.CommitCanonicalTransaction({batch.preimage_checkpoint_xid})==Store::CommitStatus::Committed,"fresh original-backed alias COW replay");
            }else{
                std::vector<std::uint64_t> applied;
                const auto proved=store.ProveRetainedAcceptedPrefix(journal,spool,std::filesystem::absolute(wal),options.volume_identity,applied,error);
                if(!proved){
                    const auto actual=ImageBytes(*lease);VectorRandomAccessSource source(actual);
                    std::vector<AppleRecoveryCheckpointView> history;std::string diagnostic;
                    if(LoadAppleRecoveryCheckpoints(source,*store.AuthoritativeAppleCheckpointView(),{batch.preimage_checkpoint_xid},history,diagnostic))
                        for(const auto& old:history){std::vector<apfsaccess::catalog::BtreeRecord> records;NativeApfsVolumeProjection projection;
                            const auto budget=std::make_shared<ApfsReadBudget>(65536,256ULL<<20,262144,256ULL<<20);
                            const auto okay=ReadAppleVolumeFileSystemRecords(source,old.checkpoint.container,old.checkpoint.volumes.front(),records,diagnostic)&&
                                NativeApfsReader::TryProjectOrdinaryFileSystemRecords(records,old.checkpoint.container.superblock,
                                    old.checkpoint.volumes.front().superblock,budget,projection,diagnostic);
                            std::cerr<<"retained projection diagnostic xid="<<old.checkpoint.container.superblock.xid<<" ok="<<okay<<" error="<<diagnostic<<'\n';
                        }
                    else std::cerr<<"retained load diagnostic "<<diagnostic<<'\n';
                }
                Check(proved&&applied==std::vector<std::uint64_t>{batch.accepted_sequence},"full retained original publication proof:"+error);
            }
            Settle(journal,*lease,batch.accepted_sequence);
            const auto aliases=step==0?std::vector<std::wstring>{L"\\clone0",L"\\alias1",L"\\alias2",L"\\alias3"}:
                step==1?std::vector<std::wstring>{L"\\clone0",L"\\alias1",L"\\renamed",L"\\alias3"}:
                std::vector<std::wstring>{L"\\alias1",L"\\renamed",L"\\alias3"};
            CheckAliases(store,aliases,step==2?3:4,expected,peer);
            if(step>=1)Check(!store.LookupCommittedInodeByPath(step==1?L"\\alias2":L"\\clone0"),"renamed/unlinked entry is absent after fresh proof");
            if(step==2){Store::HardLinkReceipt receipt;
                Check(store.AcceptNativeHardLink(journal,L"\\renamed",L"\\alias4",123456799,receipt,error)==Store::HardLinkAcceptance::Accepted&&
                    store.PublishOrRecoverNativeHardLink(journal,error)==Store::HardLinkPublication::Published,"add later alias after primary unlink promotion:"+error);
                CheckAliases(store,{L"\\alias1",L"\\renamed",L"\\alias3",L"\\alias4"},4,expected,peer);
            }
        }
    }
    for(const auto removed:{L"\\alias3",L"\\renamed",L"\\alias1"}){
        const bool cut=std::wstring_view(removed)==L"\\alias1";
        {
            std::string error;auto lease=BlockDevice::OpenExclusiveManagementImage(context.device_path,0,error);Check(!!lease,error);
            Store store(context,lease);Check(store.PrepareNativeWritePath(),"remaining alias unlink opens");Journal journal(L"Strict");OpenJournal(journal,wal,fixture);
            const auto checkpoint=store.AuthoritativeAppleCheckpointView()->container.superblock.xid;
            Store::MutationRequest request;request.operation=Store::MutationOperation::Delete;request.path=removed;
            Store::PayloadIdentity identity;std::optional<UnlinkOutcome> outcome;
            Check(store.StageMutation(request,&identity,&outcome)==Store::MutationStatus::Applied&&outcome.has_value(),"exact remaining alias unlink outcome");
            Journal::MutationIntent intent;intent.kind=Journal::MutationKind::Delete;intent.path=removed;intent.object_id=identity.object_id;
            intent.generation=identity.generation;intent.unlink_outcome=outcome;
            Check(journal.Begin()&&journal.RecordMutation(intent)&&journal.Accept(checkpoint)&&
                journal.FlushAcceptedEvidenceDurability(journal.Watermarks().accepted_sequence),"durable original remaining unlink");
            if(cut)store.SetCommitStageHook([](auto stage){return stage!="before-apple-final-flush";});
            const auto committed=store.CommitCanonicalTransaction({checkpoint});
            Check((committed==Store::CommitStatus::Committed)!=cut,"remaining alias exact publication cut");
            if(!cut)Settle(journal,*lease,journal.Watermarks().accepted_sequence);
        }
        if(cut){
            std::string error;auto lease=BlockDevice::OpenExclusiveManagementImage(context.device_path,0,error);Check(!!lease,error);
            Store store(context,lease);Check(store.PrepareNativeWritePath(),"fresh 2-to-1 alias recovery source");Journal journal(L"Strict");OpenJournal(journal,wal,fixture);
            PayloadSpool spool(options);std::vector<std::uint64_t> applied;const auto sequence=journal.Watermarks().accepted_sequence;
            Check(journal.FlushAcceptedEvidenceDurability(sequence),"2-to-1 retained original barrier");
            const auto proved=store.ProveRetainedAcceptedPrefix(journal,spool,std::filesystem::absolute(wal),options.volume_identity,applied,error);
            Check(proved&&applied==std::vector<std::uint64_t>{sequence},"2-to-1 full original recovery proof:"+error);Settle(journal,*lease,sequence);
            CheckAliases(store,{L"\\alias4"},1,expected,peer);Store::HardLinkReceipt receipt;
            const auto accepted=store.AcceptNativeHardLink(journal,L"\\alias4",L"\\reborn",123456899,receipt,error);
            Check(accepted==Store::HardLinkAcceptance::Accepted,"relink acceptance after returning to one name:"+error);
            const auto published=store.PublishOrRecoverNativeHardLink(journal,error);
            Check(published==Store::HardLinkPublication::Published,"relink publication after returning to one name:"+error);
            CheckAliases(store,{L"\\alias4",L"\\reborn"},2,expected,peer);
        }
    }
    std::cout<<"PASS original-backed alias COW rename unlink fresh recovery\n"<<std::flush;
}

void LegacyOriginalRecovery()
{
    Fixture fixture(HardLinkSpec(1));SaveImage("legacy.apfs",fixture.image);const auto context=HardLinkContext("legacy.apfs");
    {
        std::string error;auto lease=BlockDevice::OpenExclusiveManagementImage(context.device_path,0,error);Check(!!lease,error);
        Store store(context,lease);Check(store.PrepareNativeWritePath(),"legacy source opens");Journal journal(L"Strict");OpenJournal(journal,"legacy-new.wal",fixture);
        Store::HardLinkReceipt receipt;
        Check(store.AcceptNativeHardLink(journal,L"\\clone0",L"\\legacy",123456789,receipt,error)==Store::HardLinkAcceptance::Accepted,error);
        auto read=WriteAheadLog::ReadAll("legacy-new.wal",TransactionManager::WideToUtf8(journal.ConfiguredVolumeIdentity()));
        Check(read.status==WriteAheadLog::ReadStatus::Ok&&read.records.size()==2,"real original rows for NHL2 compatibility");
        auto& row=read.records.front();NativeHardLinkProof proof;Check(DecodeNativeHardLink(row.inline_payload,proof),"actual new proof decodes");
        proof.version=2;
        Check(NativeHardLinkLegacyPayloadHash(*lease,std::vector<ApplePhysicalExtentRecord>{{kShared,4,kApplePhysicalExtentKindNew,17,1}},proof.payload_sha),
            "bounded streaming legacy payload digest");
        std::vector<std::byte> historical;for(auto number:{kShared,std::uint64_t{4}})for(unsigned n=0;n<8;++n)historical.push_back(std::byte((number>>(8*n))&255));
        const auto bytes=Payload(fixture,17);historical.insert(historical.end(),bytes.begin(),bytes.end());NativeHardLinkDigest expected;
        Check(NativeHardLinkHash(historical,expected)&&expected==proof.payload_sha,"legacy exact historical digest bytes preserved");
        row.inline_payload=EncodeNativeHardLink(proof);Check(!row.inline_payload.empty()&&NativeHardLinkHash(row.inline_payload,row.payload_sha256),"legacy exact original mapping");
        std::ofstream output("legacy.wal",std::ios::binary);for(const auto& record:read.records){const auto encoded=WriteAheadLog::EncodeForTest(record);
            Check(!encoded.empty(),"legacy original framing");output.write(reinterpret_cast<const char*>(encoded.data()),encoded.size());}
        Check(!!output,"preserve independent legacy original");
    }
    {
        std::string error;auto lease=BlockDevice::OpenExclusiveManagementImage(context.device_path,0,error);Check(!!lease,error);
        Store store(context,lease);Check(store.PrepareNativeWritePath(),"legacy fresh source opens");Journal journal(L"Strict");OpenJournal(journal,"legacy.wal",fixture);
        Check(store.PublishOrRecoverNativeHardLink(journal,error)==Store::HardLinkPublication::Published,"actual accepted NHL2 original still replays:"+error);
        const auto inode=store.LookupCommittedInodeByPath(L"\\legacy");Check(inode&&inode->link_count==2&&inode->object_id==17,"legacy alias exact inode");
    }
    std::cout<<"PASS legacy NHL2 original recovery\n"<<std::flush;
}

void LargePayloadMetadataOnly()
{
    constexpr std::uint64_t blocks=8193,bytes=blocks*4096;
    auto spec=HardLinkSpec(1);spec.block_count=10240;auto& volume=spec.volumes.front();
    volume.additional_file_system_allocated_blocks=blocks;std::string error;
    for(auto& record:volume.filesystem_records){
        if(Type(record)==3&&Id(record)==17){AppleInodeRecord inode;Check(ApfsExtendedRecordCodec::DecodeInode(record,inode,error),error);
            inode.uncompressed_size=bytes;for(auto& field:inode.extended_fields)if(field.type==8){PutU64LE(field.data,0,bytes);PutU64LE(field.data,8,bytes);}
            Check(EncodeAppleInodeRecord(inode,record,error),error);
        }
        if(Type(record)==8)Check(EncodeAppleFileExtentRecord({17,0,bytes,kShared,0,4096},record,error),error);
    }
    Check(EncodeApplePhysicalExtentRecord({kShared,blocks,kApplePhysicalExtentKindNew,17,1},volume.extentref_records.front(),error),error);
    spec.authoritative_seeded_main_blocks.clear();
    for(std::uint64_t n=0;n<blocks;++n){std::vector<std::byte> block(4096,std::byte{0x5d});block.front()=std::byte(n%251);
        spec.authoritative_seeded_main_blocks.push_back({kShared+n,std::move(block)});}
    Fixture fixture(spec);SaveImage("large.apfs",fixture.image);fixture.image.clear();fixture.image.shrink_to_fit();
    const auto context=HardLinkContext("large.apfs");
    {
        auto lease=BlockDevice::OpenExclusiveManagementImage(context.device_path,0,error);Check(!!lease,error);
        Store store(context,lease);Check(store.PrepareNativeWritePath(),"large owned-payload source opens");Journal journal(L"Strict");OpenJournal(journal,"large.wal",fixture);
        std::ofstream metric("large-io.json");metric<<"{\"before\":"<<lease->PerformanceJson();Store::HardLinkReceipt receipt;
        Check(store.AcceptNativeHardLink(journal,L"\\clone0",L"\\large-alias",123456789,receipt,error)==Store::HardLinkAcceptance::Accepted,
            "actual metadata link exceeds historical 32 MiB payload cap:"+error);
        metric<<",\"after_accept\":"<<lease->PerformanceJson();
        Check(store.PublishOrRecoverNativeHardLink(journal,error)==Store::HardLinkPublication::Published,"large metadata-only publication:"+error);
        metric<<",\"after_publish\":"<<lease->PerformanceJson()<<"}";Check(!!metric,"preserve actual phase I/O counters");
    }
    {
        auto lease=BlockDevice::OpenExclusiveManagementImage(context.device_path,0,error);Check(!!lease,error);Store store(context,lease);
        Check(store.PrepareNativeWritePath(),"fresh large metadata source opens");Journal journal(L"Strict");OpenJournal(journal,"large.wal",fixture);
        Check(!journal.HasUnappliedAcceptedWork(),"large original is durably settled on reopen");
        for(const auto path:{L"\\clone0",L"\\large-alias"}){
            const auto inode=store.LookupCommittedInodeByPath(path);Check(inode&&inode->object_id==17&&inode->link_count==2&&inode->logical_size==bytes,"large alias identity/size");
            for(auto block:{std::uint64_t{0},std::uint64_t{4096},blocks-1}){std::vector<std::byte> actual;
                Check(store.ReadCommittedFileRange(path,block*4096,4096,actual)&&actual.size()==4096&&actual.front()==std::byte(block%251)&&
                    std::all_of(actual.begin()+1,actual.end(),[](auto value){return value==std::byte{0x5d};}),"large payload canaries survive metadata publication");}
        }
    }
    std::cout<<"PASS actual >32 MiB metadata-only hard link and reopen\n"<<std::flush;
}

NativeHardLinkOpenEntry OpenEntry(Store& store,const std::wstring& path)
{
    const auto inode=store.LookupCommittedInodeByPath(path);Check(inode.has_value(),"real open-entry inode");
    NativeHardLinkOpenEntry entry;entry.object_id=inode->object_id;entry.generation=inode->xid;
    entry.parent_object_id=inode->parent_object_id;entry.name_utf8=inode->name_utf8;
    if(path!=L"\\"){
        const auto link=store.LookupCommittedDirectoryLinkByPath(path);Check(link.has_value(),"real exact open-entry link");
        entry.parent_object_id=link->parent_object_id;entry.sibling_id=link->sibling_id;entry.name_utf8=link->entry_name_utf8;
    }
    return entry;
}

void OpenSessionControls()
{
    for(unsigned exception=0;exception<2;++exception){
        Fixture fixture(HardLinkSpec(1));const auto stem="session-"+std::to_string(exception);
        const auto image=std::filesystem::path(stem+".apfs"),wal=std::filesystem::path(stem+".wal");
        SaveImage(image,fixture.image);const auto context=HardLinkContext(image);
        {
            std::string error;auto lease=BlockDevice::OpenExclusiveManagementImage(context.device_path,0,error);Check(!!lease,error);
            Store store(context,lease);Check(store.PrepareNativeWritePath(),"session source opens");Journal journal(L"Strict");OpenJournal(journal,wal,fixture);
            const auto source=OpenEntry(store,L"\\clone0"),directory=OpenEntry(store,L"\\");
            const auto original=FileBytes(wal),before=ImageBytes(*lease);unsigned callbacks=0;
            for(unsigned fault=0;fault<11;++fault){
                auto wrong_source=source,wrong_directory=directory;std::wstring leaf=L"alias";
                if(fault==0)++wrong_source.object_id;
                if(fault==1)++wrong_source.generation;
                if(fault==2)++wrong_source.parent_object_id;
                if(fault==3)++wrong_source.sibling_id;
                if(fault==4)wrong_source.name_utf8="foreign";
                if(fault==5)++wrong_directory.generation;
                if(fault==6)wrong_directory=source;
                if(fault==7)leaf=L"..";
                if(fault==8)leaf=L"child\\alias";
                if(fault==9)leaf=L"alias:stream";
                if(fault==10)leaf.assign(256,L'x');
                const auto result=store.WithNativeHardLinkSession(wrong_source,wrong_directory,leaf,123456789,
                    [&](const auto&,auto&){++callbacks;return Store::HardLinkAcceptance::Accepted;},error);
                Check(result==Store::HardLinkAcceptance::Refused&&!callbacks&&FileBytes(wal)==original&&ImageBytes(*lease)==before,
                    "wrong open tuple/leaf refuses before callback or original mutation");
            }
            const auto unused=store.WithNativeHardLinkSession(source,directory,L"alias",123456789,
                [](const auto&,auto&){return Store::HardLinkAcceptance::Accepted;},error);
            Check(unused==Store::HardLinkAcceptance::Refused&&FileBytes(wal)==original,"callback cannot claim an unconsumed acceptance");
            const auto rejected=store.WithNativeHardLinkSession(source,directory,L"clone0",123456789,
                [&](const auto& session,auto& failure){
                    Store::HardLinkReceipt refused;
                    Check(store.AcceptNativeHardLink(journal,session,refused,failure)==Store::HardLinkAcceptance::Refused&&
                        !refused.sequence,"same-name plan refuses after session consumption");
                    return Store::HardLinkAcceptance::Accepted;
                },error);
            Check(rejected==Store::HardLinkAcceptance::Refused&&FileBytes(wal)==original&&ImageBytes(*lease)==before,
                "consumed but refused plan cannot become reported acceptance");
            Store other(context,lease);Store::HardLinkReceipt receipt;
            const auto result=store.WithNativeHardLinkSession(source,directory,L"alias",123456789,
                [&](const auto& session,auto& failure){
                    Store::HardLinkReceipt wrong;
                    Check(other.AcceptNativeHardLink(journal,session,wrong,failure)==Store::HardLinkAcceptance::Refused&&
                        !wrong.sequence&&FileBytes(wal)==original,"foreign owner cannot consume a session");
                    const auto accepted=store.AcceptNativeHardLink(journal,session,receipt,failure);
                    Check(accepted==Store::HardLinkAcceptance::Accepted&&receipt.sequence,"real session original acceptance");
                    Check(store.AcceptNativeHardLink(journal,session,wrong,failure)==Store::HardLinkAcceptance::Refused&&!wrong.sequence,
                        "session is one-use");
                    Check(ImageBytes(*lease)==before,"session acceptance publishes no image bytes");
                    if(exception)throw std::runtime_error("injected callback after original acceptance");
                    const auto published=store.PublishOrRecoverNativeHardLink(journal,failure);
                    Check(published==Store::HardLinkPublication::Published,"same-session complete publication:"+failure);
                    return Store::HardLinkAcceptance::Accepted;
                },error);
            Check(result==(exception?Store::HardLinkAcceptance::RecoveryRequired:Store::HardLinkAcceptance::Accepted),"session callback outcome");
            Check(exception?journal.HasUnappliedAcceptedWork()&&ImageBytes(*lease)==before:!journal.HasUnappliedAcceptedWork(),
                "callback failure preserves actual original debt and image preimage");
        }
        {
            std::string error;auto lease=BlockDevice::OpenExclusiveManagementImage(context.device_path,0,error);Check(!!lease,error);
            Store store(context,lease);Check(store.PrepareNativeWritePath(),"fresh session source");Journal journal(L"Strict");OpenJournal(journal,wal,fixture);
            if(exception)Check(store.PublishOrRecoverNativeHardLink(journal,error)==Store::HardLinkPublication::Published,"accepted session callback recovery:"+error);
            const auto alias=store.LookupCommittedInodeByPath(L"\\alias");Check(alias&&alias->object_id==17&&alias->link_count==2&&
                !journal.HasUnappliedAcceptedWork(),"fresh session original settled once");
        }
    }
    std::cout<<"PASS exact open-entry session controls and callback cut recovery\n"<<std::flush;
}

void PublicationNamespaceControls()
{
    for(unsigned fault=0;fault<3;++fault){
        Fixture fixture(HardLinkSpec(1));const auto stem="namespace-"+std::to_string(fault);
        const auto image=std::filesystem::path(stem+".apfs"),wal=std::filesystem::path(stem+".wal");
        SaveImage(image,fixture.image);const auto context=HardLinkContext(image);
        {
            std::string error;auto lease=BlockDevice::OpenExclusiveManagementImage(context.device_path,0,error);Check(!!lease,error);
            Store store(context,lease);Check(store.PrepareNativeWritePath(),"namespace source opens");
            Journal journal(L"Strict");OpenJournal(journal,wal,fixture);Store::HardLinkReceipt receipt;
            Check(store.AcceptNativeHardLink(journal,L"\\clone0",L"\\alias",123456789,receipt,error)==
                Store::HardLinkAcceptance::Accepted,"namespace original acceptance:"+error);
            unsigned calls=0;bool threw=false;Store::HardLinkPublication result=Store::HardLinkPublication::Refused;
            try{
                result=store.PublishOrRecoverNativeHardLink(journal,[&](const auto& committed,auto& failure){
                    ++calls;const auto inode=committed.LookupCommittedInodeByPath(L"\\alias");
                    const auto marks=journal.Watermarks();
                    Check(inode&&inode->object_id==17&&inode->link_count==2&&
                        marks.accepted_sequence==receipt.sequence&&marks.apfs_durable_sequence<receipt.sequence&&
                        marks.cleanup_sequence<receipt.sequence,"namespace sees full committed image before durable/cleaned fences");
                    if(fault==1)throw std::runtime_error("namespace consumer fault");
                    if(fault==0){failure="injected namespace refusal";return false;}
                    return true;
                },error);
            }catch(const std::runtime_error&){threw=true;}
            Check(calls==1,"namespace callback invoked exactly once");
            Check(fault==1?threw:!threw&&result==(fault==0?Store::HardLinkPublication::RecoveryRequired:
                Store::HardLinkPublication::Published),"namespace publication outcome");
            const auto marks=journal.Watermarks();
            Check(fault<2?journal.HasUnappliedAcceptedWork()&&marks.cleanup_sequence<receipt.sequence:
                !journal.HasUnappliedAcceptedWork()&&marks.cleanup_sequence==receipt.sequence,
                "namespace failure retains actual accepted original debt");
        }
        {
            std::string error;auto lease=BlockDevice::OpenExclusiveManagementImage(context.device_path,0,error);Check(!!lease,error);
            Store store(context,lease);Check(store.PrepareNativeWritePath(),"fresh namespace source");
            Journal journal(L"Strict");OpenJournal(journal,wal,fixture);
            if(fault<2){
                const auto result=store.PublishOrRecoverNativeHardLink(journal,error);
                Check(result==Store::HardLinkPublication::AlreadyPublished,"fresh namespace cut verifies full publication:"+error);
            }
            Check(!journal.HasUnappliedAcceptedWork()&&journal.RecoveryStateValid(),"namespace fresh original settles once");
            const auto inode=store.LookupCommittedInodeByPath(L"\\alias");
            Check(inode&&inode->object_id==17&&inode->link_count==2,"namespace exact alias survives fresh recovery");
        }
    }
    std::cout<<"PASS post-publication namespace refusal/throw and fresh recovery\n"<<std::flush;
}
}

int main(int argc,char** argv)
{
    try {
        Check(argc>=2,"fresh absolute private root required");
        const auto root=std::filesystem::path(argv[1]);
        Check(root.is_absolute()&&root.wstring().starts_with(L"D:\\")&&!std::filesystem::exists(root),"fresh D-only alias root");
        Check(std::filesystem::create_directories(root),"create alias evidence root");std::filesystem::current_path(root);
        const auto mode=argc>2?std::string(argv[2]):"all";
        ProofCodec();PayloadExclusion();LaterAliasPlanner();StrictSiblingProjection();
        if(mode=="all")for(const auto& cut:{std::string{},std::string("before-apple-checkpoint-switch"),std::string("before-apple-final-flush")})
            LaterAliasRecovery(cut);
        if(mode=="all"||mode=="--lifecycle")AliasLifecycle();
        if(mode=="all"||mode=="--legacy")LegacyOriginalRecovery();
        if(mode=="all"||mode=="--large")LargePayloadMetadataOnly();
        if(mode=="all"||mode=="--session")OpenSessionControls();
        if(mode=="all"||mode=="--session")PublicationNamespaceControls();
        if(mode=="all"){
            for(unsigned files:{1u,100u})for(const auto& cut:{std::string{},std::string("before-apple-checkpoint-switch"),std::string("before-apple-final-flush")})
                AcceptanceRecovery(files,cut);
            RefusalCases();
        }
        std::cout<<"PASS native later-alias "<<checks<<" checks\n";return 0;
    }catch(const std::exception& error){std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}
}
