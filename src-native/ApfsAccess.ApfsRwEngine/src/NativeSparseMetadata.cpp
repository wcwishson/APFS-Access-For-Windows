#include "MetadataStore.h"
#include "NativeSparse.h"
#include "NativeSparseV2.h"
#include "TransactionManager.h"
#include <algorithm>
#include <map>
#include <set>

namespace apfsaccess::rw
{
namespace
{
template<class F> struct Finally { F call; ~Finally(){call();} };
template<class F> Finally(F)->Finally<F>;
template<class Manager,class Log> bool Registered()
{
    if constexpr(requires {Manager::MutationKind::NativeSparse;Log::OperationKind::NativeSparse;})
        return static_cast<std::uint32_t>(Manager::MutationKind::NativeSparse)==NativeSparseOperationKind &&
            static_cast<std::uint32_t>(Log::OperationKind::NativeSparse)==NativeSparseOperationKind;
    else return false;
}
bool Fail(std::string& error,const char* text){if(error.empty())error=text;return false;}
class Source final:public catalog::RandomAccessSource
{
public:
    explicit Source(const BlockDevice& device):device_(device){}
    std::uint64_t SizeBytes()const override{return device_.GetGeometry().total_bytes;}
    bool Read(std::uint64_t at,std::size_t n,std::vector<std::byte>& bytes)const override
    {
        bytes.clear();const auto size=SizeBytes();
        if(failed_ || at>size || n>size-at || n>(1u<<20))return false;
        if(!n)return true;
        const auto begin=at/4096*4096,end=(at+n+4095)/4096*4096;
        if(end>size || reads_==65536 || end-begin>(256ull<<20)-read_bytes_){failed_=true;return false;}
        ++reads_;read_bytes_+=end-begin;std::vector<std::byte> whole;
        if(!device_.ReadForVerification(begin,static_cast<std::size_t>(end-begin),whole) || whole.size()!=end-begin){failed_=true;return false;}
        bytes.assign(whole.begin()+at-begin,whole.begin()+at-begin+n);return true;
    }
private:const BlockDevice& device_;mutable std::uint64_t read_bytes_=0,reads_=0;mutable bool failed_=false;
};
class Overlay final:public catalog::RandomAccessSource
{
public:
    explicit Overlay(const catalog::RandomAccessSource& source):source_(source){}
    std::map<std::uint64_t,std::vector<std::byte>> blocks;
    std::uint64_t SizeBytes()const override{return source_.SizeBytes();}
    bool Read(std::uint64_t at,std::size_t n,std::vector<std::byte>& bytes)const override
    {
        if(at>SizeBytes() || n>SizeBytes()-at || !source_.Read(at,n,bytes) || bytes.size()!=n)return false;
        for(const auto& [block,data]:blocks){const auto start=block*4096;
            const auto lo=(std::max)(at,start),hi=(std::min)(at+n,start+4096);
            if(lo<hi)std::copy_n(data.begin()+lo-start,hi-lo,bytes.begin()+lo-at);}
        return true;
    }
private:const catalog::RandomAccessSource& source_;
};
std::wstring Canonical(const catalog::AppleCheckpointView& cp,std::uint64_t volume)
{return L"apfs-vol:"+std::wstring(cp.container.superblock.uuid_hex.begin(),cp.container.superblock.uuid_hex.end())+L":"+std::to_wstring(volume);}
bool Wide(std::string_view text,std::wstring& out)
{
    out.clear();if(text.empty() || text.size()>4096 || text.find('\0')!=text.npos)return false;
    const auto n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),nullptr,0);
    if(n<=0)return false;out.resize(n);
    return MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),out.data(),n)==n;
}
bool Utf8(const std::wstring& text,std::string& out)
{
    out.clear();const auto n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),nullptr,0,nullptr,nullptr);
    if(n<=0 || n>4096)return false;out.resize(n);
    return WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),out.data(),n,nullptr,nullptr)==n;
}
bool ImageMatches(const BlockDevice& device,const NativeSparseProof& p)
{
    BlockDevice::StableImageIdentity image;
    return device.IsRegularFile() && !device.BaseOffsetBytes() && device.QueryHeldImageIdentity(image) &&
        image.volume_serial==p.image_volume_serial && image.file_id==p.image_file_id && image.size_bytes==p.image_size &&
        image.creation_time==p.image_creation_time;
}
bool Postimages(const AppleCheckpointPublicationPlan& plan,std::uint64_t blocks,
    std::map<std::uint64_t,std::vector<std::byte>>& out)
{
    out.clear();
    const auto add=[&](const auto& write){
        if(write.bytes.empty() || write.bytes.size()%4096 || write.physical_block>=blocks || write.bytes.size()/4096>blocks-write.physical_block)return false;
        for(std::size_t n=0;n<write.bytes.size()/4096;++n){
            if(!out.emplace(write.physical_block+n,std::vector<std::byte>(write.bytes.begin()+n*4096,write.bytes.begin()+(n+1)*4096)).second ||
                out.size()>NativeSparseMaxPreimages)return false;}
        return true;
    };
    return plan.block_size==4096 && !plan.fusion_tier2_anchor_write &&
        std::all_of(plan.before_superblock_writes.begin(),plan.before_superblock_writes.end(),add) && add(plan.superblock_write);
}
bool Capture(const catalog::RandomAccessSource& source,const AppleCheckpointPublicationPlan& plan,NativeSparseProof& p,std::string& error)
{
    std::map<std::uint64_t,std::vector<std::byte>> writes;
    if(!Postimages(plan,p.block_count,writes))return Fail(error,"SparseDestinationCensusInvalid");
    std::set<std::uint64_t> blocks{0};for(const auto& [block,_]:writes)blocks.insert(block);
    for(const auto& guard:plan.guard_blocks){
        if(guard.bytes.empty() || guard.bytes.size()%4096 || guard.physical_block>=p.block_count || guard.bytes.size()/4096>p.block_count-guard.physical_block)
            return Fail(error,"SparseGuardCensusInvalid");
        for(std::size_t n=0;n<guard.bytes.size()/4096;++n)blocks.insert(guard.physical_block+n);
        if(blocks.size()>NativeSparseMaxPreimages)return Fail(error,"SparsePreimageQuota");}
    if(blocks.size()>NativeSparseMaxPreimages)return Fail(error,"SparsePreimageQuota");
    p.preimages.clear();
    for(const auto block:blocks){std::vector<std::byte> bytes;NativeSparsePreimage pre;pre.physical_block=block;
        if(!source.Read(block*4096,4096,bytes) || bytes.size()!=4096)return Fail(error,"SparsePreimageUnreadable");
        std::copy(bytes.begin(),bytes.end(),pre.bytes.begin());p.preimages.push_back(std::move(pre));}
    return true;
}
// 0: exact preacceptance; 1: old canonical checkpoint selected, planned COW
// destinations may be torn; 2: exact fully published bytes. Other guards never relax.
bool Evidence(const BlockDevice& device,const NativeSparseV2Proof& p,const AppleCheckpointPublicationPlan& plan,unsigned mode,std::string& error)
{
    std::map<std::uint64_t,std::vector<std::byte>> writes;
    if(mode>2 || !Postimages(plan,p.block_count,writes))return Fail(error,"SparseEvidenceCensusInvalid");
    for(const auto& source:p.source_blocks){std::vector<std::byte> bytes;
        if(writes.contains(source.physical_block) || !device.ReadForVerification(source.physical_block*4096,4096,bytes) ||
            bytes.size()!=4096 || !std::equal(bytes.begin(),bytes.end(),source.bytes.begin()))return Fail(error,"SparseContributingSourceChanged");}
    for(const auto& pre:p.preimages){std::vector<std::byte> bytes;
        if(!device.ReadForVerification(pre.physical_block*4096,4096,bytes) || bytes.size()!=4096)return Fail(error,"SparseEvidenceUnreadable");
        const auto next=writes.find(pre.physical_block);
        const bool old=std::equal(bytes.begin(),bytes.end(),pre.bytes.begin());
        if(next==writes.end() || mode==0){if(!old)return Fail(error,"SparseOriginalGuardChanged");}
        else if(mode==2){if(bytes!=next->second)return Fail(error,"SparsePublishedBytesChanged");}
        else if(!old && bytes!=next->second && catalog::ParseNxSuperblock(bytes))return Fail(error,"SparseForeignValidCheckpoint");
        if(next!=writes.end())writes.erase(next);
    }
    return writes.empty() || Fail(error,"SparseDestinationEvidenceMissing");
}
std::uint64_t Resolve(const std::vector<catalog::BtreeRecord>& records,const ApfsNamePolicy& policy,const std::wstring& path)
{
    if(path.empty() || path.front()!=L'\\')return 0;
    std::uint64_t parent=2;std::size_t at=1;
    for(unsigned depth=0;at<path.size() && depth<128;++depth){
        auto end=path.find(L'\\',at);if(end==path.npos)end=path.size();
        const auto key=ApfsNameCodec::CanonicalWindowsComponentKey(std::wstring_view(path).substr(at,end-at),policy);
        if(!key.ok())return 0;std::uint64_t found=0;
        for(const auto& record:records){const auto header=catalog::ReadU64LE(record.key,0).value_or(0);
            if((header>>60)!=9 || (header&0x0fffffffffffffffULL)!=parent)continue;
            AppleDirectoryRecord entry;std::string error;
            if(!ApfsExtendedRecordCodec::DecodeDirectory(record,policy,entry,error))return 0;
            const auto name=ApfsNameCodec::Decode(std::as_bytes(std::span(entry.name_utf8)),policy);
            if(!name.ok())return 0;const auto candidate=ApfsNameCodec::CanonicalWindowsComponentKey(name.value->windows_display,policy);
            if(!candidate.ok())return 0;if(*candidate.value==*key.value){if(found)return 0;found=entry.file_id;}}
        if(!found)return 0;parent=found;at=end+1;
    }
    return at>=path.size()?parent:0;
}
bool PayloadCommitment(const BlockDevice& device,std::span<const ApplePhysicalExtentRecord> payload,bool scaled,NativeSparseDigest& hash)
{return scaled?NativeHardLinkExtentHash(payload,hash):NativeHardLinkLegacyPayloadHash(device,payload,hash);}
bool ReadState(const catalog::RandomAccessSource& source,const catalog::AppleCheckpointView& cp,
    std::uint64_t volume,std::uint64_t inode,NativeSparseState& state,bool scaled,std::string& error)
{return scaled?ReadNativeSparseStateV2(source,cp,volume,inode,state,error):ReadNativeSparseState(source,cp,volume,inode,state,error);}
bool Build(const BlockDevice& device,const catalog::RandomAccessSource& source,const catalog::AppleCheckpointView& cp,
    NativeSparseV2Proof& p,AppleVolumeTransactionPlan& plan,std::vector<ApplePhysicalExtentRecord>& payload,bool recovery,bool scaled,std::string& error)
{
    NativeSparseV2Proof observed=p;NativeSparseState before;
    if(scaled){const auto planner=p.body_version==2?PlanNativeSparseTransactionV2Legacy:PlanNativeSparseTransactionV2;
        if(!planner(source,cp,p.volume_oid,p.inode,p.request,before,plan,observed.source_blocks,error))return false;}
    else if(!PlanNativeSparseTransaction(source,cp,p.volume_oid,p.inode,p.request,before,plan,error))return false;
    std::wstring path;if(!Wide(p.path_utf8,path) || Resolve(before.filesystem,
        ApfsNamePolicy::FromIncompatibleFeatures(cp.volumes.front().superblock.incompatible_features),path)!=p.inode)
        return Fail(error,"SparseOriginalOpenIdentityMismatch");
    observed.checkpoint=cp.container.superblock.xid;observed.generation=cp.volumes.front().superblock.xid;
    observed.container_uuid=cp.container.superblock.uuid_hex;observed.volume_uuid=cp.volumes.front().superblock.uuid_hex;
    observed.block_count=cp.container.superblock.block_count;
    if(!NativeHardLinkWritesExcludePayload(plan.commit.publication,before.payload,observed.block_count) ||
        !NativeHardLinkRecordsHash(before.filesystem,observed.before_sha) || !NativeHardLinkRecordsHash(before.references,observed.before_refs_sha) ||
        !PayloadCommitment(device,before.payload,scaled,observed.payload_sha) ||
        !NativeHardLinkPublicationHash(plan.commit.publication,observed.publication_sha))return Fail(error,"SparseBeforeProofUnavailable");
    Overlay post(source);if(!Postimages(plan.commit.publication,observed.block_count,post.blocks))return Fail(error,"SparsePostimageQuota");
    const auto after=catalog::LoadAppleCheckpointView(post,0,post.SizeBytes(),error);NativeSparseState state;
    if(!after || after->container.superblock.xid!=plan.commit.publication.transaction_xid ||
        !ReadState(post,*after,p.volume_oid,p.inode,state,scaled,error) ||
        !NativeHardLinkRecordsHash(state.filesystem,observed.after_sha) || !NativeHardLinkRecordsHash(state.references,observed.after_refs_sha) ||
        !Capture(source,plan.commit.publication,observed,error))return Fail(error,"SparseAfterProofUnavailable");
    if(recovery && observed!=p)return Fail(error,"SparseWholeOriginalBodyMismatch");
    payload=std::move(before.payload);p=std::move(observed);return true;
}
}
bool MetadataStore::WithNativeSparseSession(const NativeSparseOpenEntry& entry,const SparseSessionConsumer& consumer,std::string& error)
{
    error.clear();
    if(!consumer || immutable_snapshot_view_ || context_.shared_container_session || context_.allow_native_snapshot_runtime ||
        !CanUseAppleTransactionWriter() || recovery_required_ || !pending_mutations_.empty() || !device_ || !device_->IsRegularFile() ||
        device_->BaseOffsetBytes() || !authoritative_apple_checkpoint_view_ || committed_directory_links_.size()>16384)
        return Fail(error,"SparseSessionOwnerUnsupported");
    const auto inode=committed_inodes_.find(entry.object_id);const auto epoch=StateEpoch();
    const auto observation=device_->CaptureExclusiveWriteSourceObservation();
    if(!observation || inode==committed_inodes_.end() || !entry.generation || inode->second.xid!=entry.generation ||
        inode->second.node_type!=NodeType::RegularFile)return Fail(error,"SparseSessionOpenEntryStale");
    std::wstring path;unsigned matched=0;
    for(const auto& link:committed_directory_links_){
        if(link.child_object_id!=entry.object_id || link.parent_object_id!=entry.parent_object_id ||
            link.sibling_id!=entry.sibling_id || link.entry_name_utf8!=entry.name_utf8)continue;
        const auto parent=committed_inodes_.find(link.parent_object_id);
        if(++matched!=1 || parent==committed_inodes_.end() || !parent->second.is_directory)return Fail(error,"SparseSessionAliasInvalid");
        path=parent->second.full_path==L"\\"?L"\\"+link.entry_name:parent->second.full_path+L"\\"+link.entry_name;
    }
    const auto selected=path.empty()?nullptr:LookupCommittedInodeByPathView(path);
    if(matched!=1 || !selected || selected->object_id!=entry.object_id || selected->xid!=entry.generation || StateEpoch()!=epoch ||
        !device_->IsExclusiveWriteSourceObservationCurrent(*observation))return Fail(error,"SparseSessionOpenBindingMismatch");
    NativeSparseSession session(this,epoch,*observation,entry.object_id,entry.generation,std::move(path));
    Finally invalidate{[&]{session.active_=false;}};
    try{
        const bool done=consumer(session,error);
        if(session.ambiguous_ || (session.accepted_ && !done)){
            MarkRecoveryRequired(L"NativeSparseSessionOutcomeAmbiguous");return Fail(error,"SparseSessionOutcomeAmbiguous");}
        return done && session.consumed_ && session.succeeded_;
    }catch(...){
        if(session.accepted_ || session.ambiguous_)MarkRecoveryRequired(L"NativeSparseSessionCallbackFailed");
        return Fail(error,"SparseSessionCallbackFailed");
    }
}
bool MetadataStore::QueryNativeAllocatedRanges(const NativeSparseSession& session,std::uint64_t offset,std::uint64_t length,
    std::size_t maximum,std::vector<NativeSparseAllocatedRange>& out,std::string& error)const
{return QueryNativeAllocatedRangesImpl(session,offset,length,maximum,out,error,false);}
bool MetadataStore::QueryNativeAllocatedRangesV2(const NativeSparseSession& session,std::uint64_t offset,std::uint64_t length,
    std::size_t maximum,std::vector<NativeSparseAllocatedRange>& out,std::string& error)const
{return QueryNativeAllocatedRangesImpl(session,offset,length,maximum,out,error,true);}
bool MetadataStore::QueryNativeAllocatedRangesImpl(const NativeSparseSession& session,std::uint64_t offset,std::uint64_t length,
    std::size_t maximum,std::vector<NativeSparseAllocatedRange>& out,std::string& error,bool scaled)const
{
    out.clear();error.clear();
    if(session.owner_!=this || !session.active_ || session.consumed_ || StateEpoch()!=session.epoch_ ||
        !device_ || !device_->IsExclusiveWriteSourceObservationCurrent(session.observation_))return Fail(error,"SparseSessionStaleForeignOrConsumed");
    session.consumed_=true;Source raw(*device_);
    const auto budget=std::make_shared<catalog::ApfsReadBudget>(65536,256ull<<20,131072,128ull<<20);
    catalog::BudgetedRandomAccessSource source(raw,budget);
    const auto cp=catalog::LoadAppleCheckpointView(source,0,source.SizeBytes(),error);NativeSparseState state;
    if(!cp || cp->container.superblock_bytes!=authoritative_apple_checkpoint_view_->container.superblock_bytes ||
        !ReadState(source,*cp,context_.volume_object_id,session.inode_,state,scaled,error) ||
        !QueryNativeSparseRanges(state,offset,length,maximum,out,error) || StateEpoch()!=session.epoch_ ||
        !device_->IsExclusiveWriteSourceObservationCurrent(session.observation_)){
        out.clear();return Fail(error,"SparseQuerySourceChanged");}
    session.succeeded_=true;return true;
}
MetadataStore::SparseAcceptance MetadataStore::AcceptNativeSparse(TransactionManager& journal,const NativeSparseSession& session,
    const NativeSparseRequest& request,SparseReceipt& receipt,std::string& error)
{return AcceptNativeSparseImpl(journal,session,request,receipt,error,false);}
MetadataStore::SparseAcceptance MetadataStore::AcceptNativeSparseV2(TransactionManager& journal,const NativeSparseSession& session,
    const NativeSparseRequest& request,SparseReceipt& receipt,std::string& error)
{return AcceptNativeSparseImpl(journal,session,request,receipt,error,true);}
MetadataStore::SparseAcceptance MetadataStore::AcceptNativeSparseImpl(TransactionManager& journal,const NativeSparseSession& session,
    const NativeSparseRequest& request,SparseReceipt& receipt,std::string& error,bool scaled)
{
    receipt={};error.clear();const auto refuse=[&](const char* text){Fail(error,text);return SparseAcceptance::Refused;};
    if(session.owner_!=this || !session.active_ || session.consumed_ || StateEpoch()!=session.epoch_ ||
        !device_ || !device_->IsExclusiveWriteSourceObservationCurrent(session.observation_))return refuse("SparseSessionStaleForeignOrConsumed");
    session.consumed_=true;
    if(!Registered<TransactionManager,WriteAheadLog>())return refuse("SparseOriginalKindNotRegistered");
    if(!NativeSparseRequestIsValid(request) || journal.ProtectedSourceBinding())return refuse("SparseRequestOrOriginalProfileUnsupported");
    const auto marks=journal.Watermarks();std::vector<TransactionManager::AcceptedTransaction> debt;
    if(journal.CurrentState()!=TransactionManager::State::Idle || !journal.RecoveryStateValid() || !journal.ObservedJournalWriterLeaseGeneration() ||
        marks.accepted_sequence!=marks.cleanup_sequence || !journal.LoadAcceptedTransactionsSinceCleanup(debt,&error) || !debt.empty())
        return refuse("SparseOriginalNotClean");
    Source raw(*device_);const auto budget=std::make_shared<catalog::ApfsReadBudget>(65536,256ull<<20,131072,128ull<<20);
    catalog::BudgetedRandomAccessSource source(raw,budget);const auto cp=catalog::LoadAppleCheckpointView(source,0,source.SizeBytes(),error);
    BlockDevice::StableImageIdentity image;
    if(!cp || !device_->QueryHeldImageIdentity(image) || cp->container.superblock_bytes!=authoritative_apple_checkpoint_view_->container.superblock_bytes ||
        cp->container.superblock.xid!=checkpoint_xid_ || journal.EnrolledCanonicalJournalIdentity()!=Canonical(*cp,context_.volume_object_id))
        return refuse("SparseCanonicalOwnerMismatch");
    NativeSparseV2Proof proof;proof.volume_oid=context_.volume_object_id;proof.inode=session.inode_;proof.request=request;
    proof.store_offset=device_->BaseOffsetBytes();proof.image_volume_serial=image.volume_serial;proof.image_file_id=image.file_id;
    proof.image_size=image.size_bytes;proof.image_creation_time=image.creation_time;
    if(!Utf8(session.path_,proof.path_utf8))return refuse("SparsePathEncodingInvalid");
    AppleVolumeTransactionPlan plan;std::vector<ApplePhysicalExtentRecord> payload;
    if(!Build(*device_,source,*cp,proof,plan,payload,false,scaled,error))return refuse("SparsePlanRefused");
    auto body=scaled?EncodeNativeSparseV2(proof):EncodeNativeSparse(proof);if(body.empty())return refuse("SparseProofInvalid");
    if(scaled){
        // Exercise the exact historical reconstruction allowance before Begin.
        // Each later verification owns an independent finite read allowance.
        for(bool published:{false,true}){
            Source replay_raw(*device_);Overlay replay_old(replay_raw),replay_post(replay_raw);
            for(const auto& pre:proof.preimages)replay_old.blocks.emplace(pre.physical_block,std::vector<std::byte>(pre.bytes.begin(),pre.bytes.end()));
            if(published && !Postimages(plan.commit.publication,proof.block_count,replay_post.blocks))return refuse("SparseReplayCapacityUnproven");
            const auto replay_budget=std::make_shared<catalog::ApfsReadBudget>(65536,256ull<<20,131072,128ull<<20);
            catalog::BudgetedRandomAccessSource replay_source(published?static_cast<const catalog::RandomAccessSource&>(replay_post):static_cast<const catalog::RandomAccessSource&>(replay_raw),replay_budget),historical(replay_old,replay_budget);
            const auto current=catalog::LoadAppleCheckpointView(replay_source,0,replay_source.SizeBytes(),error);
            const auto prior=catalog::LoadAppleCheckpointView(historical,0,historical.SizeBytes(),error);
            auto exact=proof;AppleVolumeTransactionPlan rebuilt;std::vector<ApplePhysicalExtentRecord> owners;
            const auto& expected=published?plan.commit.publication.superblock_write.bytes:cp->container.superblock_bytes;
            if(!current || !prior || current->container.superblock_bytes!=expected ||
                !Build(*device_,historical,*prior,exact,rebuilt,owners,true,true,error))return refuse("SparseReplayCapacityUnproven");
        }
    }
    TransactionManager::MutationIntent intent;intent.kind=static_cast<TransactionManager::MutationKind>(NativeSparseOperationKind);
    intent.path=session.path_;intent.object_id=proof.inode;intent.generation=proof.checkpoint;
    intent.length=intent.payload_length=body.size();intent.inline_payload=std::move(body);
    NativeSparseDigest payload_check;
    if(!NativeHardLinkHash(intent.inline_payload,intent.payload_checksum) || !AllowCommitStage("before-native-sparse-accept") ||
        !PayloadCommitment(*device_,payload,scaled,payload_check) || payload_check!=proof.payload_sha ||
        !Evidence(*device_,proof,plan.commit.publication,0,error) || StateEpoch()!=session.epoch_ ||
        !device_->IsExclusiveWriteSourceObservationCurrent(session.observation_))return refuse("SparsePreacceptanceChanged");
    if(scaled && !journal.NativeSparseEvidenceCapacityAvailable(intent,error))return refuse("SparseEvidenceCapacityExceeded");
    bool complete=false;Finally poison{[&]{if(!complete){session.ambiguous_=true;MarkRecoveryRequired(L"NativeSparseAcceptanceRequiresRecovery");}}};
    const auto uncertain=[&](const char* text){Fail(error,text);return SparseAcceptance::RecoveryRequired;};
    if(!journal.Begin())return uncertain("SparseBeginFailed");const auto tx=journal.CurrentTransactionId();
    if(!AllowCommitStage("after-native-sparse-begin"))return uncertain("SparseAcceptanceAmbiguous");
    if(!journal.RetainAcceptedSequenceProof(tx) || !journal.CanAddInlinePayload(intent.inline_payload.size()) ||
        !journal.RecordMutation(intent))return uncertain("SparseAcceptanceAmbiguous");
    if(!AllowCommitStage("after-native-sparse-record") || !journal.Accept(proof.checkpoint))return uncertain("SparseAcceptanceAmbiguous");
    receipt={tx,journal.Watermarks().accepted_sequence,proof.checkpoint,proof.inode};
    session.accepted_=session.succeeded_=true;complete=true;return SparseAcceptance::Accepted;
}
MetadataStore::SparsePublication MetadataStore::PublishOrRecoverNativeSparse(TransactionManager& journal,std::string& error)
{return PublishOrRecoverNativeSparse(journal,{},error);}
MetadataStore::SparsePublication MetadataStore::PublishOrRecoverNativeSparse(TransactionManager& journal,const SparsePostpublicationHook& hook,std::string& error)
{
    error.clear();const auto refuse=[&](const char* text){Fail(error,text);return SparsePublication::Refused;};
    if(!Registered<TransactionManager,WriteAheadLog>())return refuse("SparseOriginalKindNotRegistered");
    if(immutable_snapshot_view_ || context_.shared_container_session || context_.allow_native_snapshot_runtime ||
        !CanUseAppleTransactionWriter() || recovery_required_ || !pending_mutations_.empty() || !device_ || !device_->IsRegularFile() ||
        device_->BaseOffsetBytes() || !authoritative_apple_checkpoint_view_ || journal.ProtectedSourceBinding())return refuse("SparseRecoveryOwnerUnsupported");
    const auto observation=device_->CaptureExclusiveWriteSourceObservation();
    std::vector<TransactionManager::AcceptedTransaction> batches;
    if(!observation || journal.CurrentState()!=TransactionManager::State::Idle || !journal.RecoveryStateValid() ||
        !journal.ObservedJournalWriterLeaseGeneration() || !journal.LoadAcceptedTransactionsSinceCleanup(batches,&error) ||
        batches.size()!=1 || batches.front().mutations.size()!=1)return refuse("SparseOriginalBoundaryUnproven");
    const auto& accepted=batches.front();const auto& record=accepted.mutations.front();NativeSparseV2Proof proof;std::wstring identity,path;
    const bool scaled=DecodeNativeSparseV2(record.inline_payload,proof);
    if((scaled?!NativeSparseV2WalIsConsistent(record):(!NativeSparseWalIsConsistent(record) || !DecodeNativeSparse(record.inline_payload,proof))) ||
        !Wide(record.volume_identity,identity) || identity!=journal.ConfiguredVolumeIdentity() || accepted.transaction_id!=record.transaction_id ||
        !accepted.accepted_sequence || record.sequence>=accepted.accepted_sequence || accepted.preimage_checkpoint_xid!=proof.checkpoint ||
        journal.Watermarks().accepted_sequence!=accepted.accepted_sequence || proof.volume_oid!=context_.volume_object_id || !ImageMatches(*device_,proof) ||
        !Wide(proof.path_utf8,path) || path!=NormalizePath(path))return refuse("SparseOriginalBindingMismatch");
    bool complete=false;Finally poison{[&]{if(!complete)MarkRecoveryRequired(L"NativeSparsePublicationRequiresRecovery");}};
    const auto failed=[&](const char* text){Fail(error,text);return SparsePublication::RecoveryRequired;};
    // An authenticated/readable original is not a durability barrier, including
    // on a fresh owner after interruption. Flush before target graph reads.
    if(!journal.FlushAcceptedEvidenceDurability(accepted.accepted_sequence))return failed("SparseOriginalBarrierFailed");
    Source raw(*device_);const auto budget=std::make_shared<catalog::ApfsReadBudget>(65536,256ull<<20,131072,128ull<<20);
    catalog::BudgetedRandomAccessSource source(raw,budget);const auto current=catalog::LoadAppleCheckpointView(source,0,source.SizeBytes(),error);
    if(!current || current->container.superblock_bytes!=authoritative_apple_checkpoint_view_->container.superblock_bytes ||
        journal.EnrolledCanonicalJournalIdentity()!=Canonical(*current,proof.volume_oid))return failed("SparseRecoveryEndpointMismatch");
    Overlay restored(raw);for(const auto& pre:proof.preimages)restored.blocks.emplace(pre.physical_block,std::vector<std::byte>(pre.bytes.begin(),pre.bytes.end()));
    catalog::BudgetedRandomAccessSource historical(restored,budget);const auto before=catalog::LoadAppleCheckpointView(historical,0,historical.SizeBytes(),error);
    if(!before || before->container.superblock.xid!=proof.checkpoint)return failed("SparseOriginalPreimageUnavailable");
    AppleVolumeTransactionPlan transaction;std::vector<ApplePhysicalExtentRecord> payload;
    if(!Build(*device_,historical,*before,proof,transaction,payload,true,scaled,error))return failed("SparseWholeOriginalPlanMismatch");
    const auto& publication=transaction.commit.publication;const auto xid=publication.transaction_xid;
    if(current->container.superblock.xid!=proof.checkpoint && current->container.superblock.xid!=xid)return failed("SparseForeignCanonicalCheckpoint");
    const bool published=current->container.superblock.xid==xid;
    if(!Evidence(*device_,proof,publication,published?2:1,error))return failed("SparsePhysicalEvidenceChanged");
    const auto verify=[&]{
        Source phase_raw(*device_);const auto phase_budget=std::make_shared<catalog::ApfsReadBudget>(65536,256ull<<20,131072,128ull<<20);
        catalog::BudgetedRandomAccessSource phase(phase_raw,phase_budget);
        const auto& input=scaled?static_cast<const catalog::RandomAccessSource&>(phase):static_cast<const catalog::RandomAccessSource&>(source);
        const auto cp=catalog::LoadAppleCheckpointView(input,0,input.SizeBytes(),error);NativeSparseState state;NativeSparseDigest a,b,old_payload;
        return cp && cp->container.superblock.xid==xid && cp->container.superblock.uuid_hex==proof.container_uuid &&
            cp->container.superblock_physical_block==publication.superblock_write.physical_block && cp->container.superblock_bytes==publication.superblock_write.bytes &&
            cp->volumes.size()==1 && cp->volumes.front().superblock.uuid_hex==proof.volume_uuid &&
            Evidence(*device_,proof,publication,2,error) && ReadState(input,*cp,proof.volume_oid,proof.inode,state,scaled,error) &&
            NativeHardLinkRecordsHash(state.filesystem,a) && a==proof.after_sha && NativeHardLinkRecordsHash(state.references,b) && b==proof.after_refs_sha &&
            PayloadCommitment(*device_,payload,scaled,old_payload) && old_payload==proof.payload_sha;
    };
    NativeSparseDigest payload_check;
    if(!AllowCommitStage("before-native-sparse-publication") ||
        !PayloadCommitment(*device_,payload,scaled,payload_check) || payload_check!=proof.payload_sha ||
        !Evidence(*device_,proof,publication,published?2:1,error) ||
        !device_->IsExclusiveWriteSourceObservationCurrent(*observation))return failed("SparsePublicationInterrupted");
    if(published){if(!device_->Flush() || !verify())return failed("SparsePublishedFlushFailed");}
    else{
        auto execution=publication;std::map<std::uint64_t,std::vector<std::byte>> writes;
        if(!Postimages(publication,proof.block_count,writes))return failed("SparseDestinationCensusInvalid");
        for(auto& guard:execution.guard_blocks)
            for(std::size_t n=0;n<guard.bytes.size()/4096;++n)if(writes.contains(guard.physical_block+n)){
                std::vector<std::byte> bytes;
                if(!device_->ReadForVerification((guard.physical_block+n)*4096,4096,bytes) || bytes.size()!=4096)
                    return failed("SparseReplayGuardUnreadable");
                std::copy(bytes.begin(),bytes.end(),guard.bytes.begin()+n*4096);
            }
        if(!ExecuteAppleCheckpointPublication(*device_,execution,error,[&](auto stage){return AllowCommitStage(stage);}) || !verify())return failed("SparsePublicationFailed");
    }
    if(!PrepareNativeWritePath())return failed("SparseCommittedReloadFailed");const auto epoch=StateEpoch();
    const auto inode=LookupCommittedInodeByPath(path);
    if(!inode || inode->object_id!=proof.inode || (hook && (!hook(*this,error) || StateEpoch()!=epoch)))return failed("SparseHostPublicationFailed");
    if(!AllowCommitStage("before-native-sparse-durable") || !verify() || !journal.MarkApfsDurableThrough(accepted.accepted_sequence) ||
        !AllowCommitStage("before-native-sparse-cleaned") || !verify() || !journal.MarkCleanedThrough(accepted.accepted_sequence) ||
        !journal.FlushRetainedOriginalEvidenceDurability())return failed("SparseWatermarkFailed");
    journal.ReleaseAcceptedSequenceProof(accepted.transaction_id);complete=true;
    return published?SparsePublication::AlreadyPublished:SparsePublication::Published;
}
}
