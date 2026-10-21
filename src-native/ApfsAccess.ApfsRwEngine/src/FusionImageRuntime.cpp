#include "FusionImageRuntime.h"
#include "FusionPublicationInternal.h"
#include "FusionReclamationProof.h"
#include "ApfsExtendedRecordCodec.h"
#include "ApfsFusionSpaceman.h"
#include <algorithm>
#include <filesystem>
#include <set>
#include <charconv>
#include <Windows.h>
#include "FusionPrivateFile.h"
#include "FusionJournalContinuation.h"
#include "FusionObjectIds.h"
#include "FusionVerificationRanges.h"

namespace apfsaccess::rw {
namespace {
constexpr std::uint64_t MaxFile=(1ull<<56)-4096;
constexpr std::size_t MaxPayload=256*1024;
constexpr std::string_view LegacyCommitment="\\$fusion-inline-v1:";
constexpr std::string_view RangeV2Commitment="\\$fusion-range-v2:";
constexpr std::string_view Commitment="\\$fusion-reclaim-v3:";
constexpr std::string_view PrivateCommitment="\\$fusion-private-v4:";
constexpr std::string_view NamesCommitment="\\$fusion-names-v5:";
constexpr std::string_view UnlinkCommitment="\\$fusion-unlink-v6:";
constexpr std::string_view CanonicalNamesCommitment="\\$fusion-names-v7:";
constexpr std::string_view CanonicalPrivateCommitment="\\$fusion-private-v7:";
constexpr std::string_view CanonicalUnlinkCommitment="\\$fusion-unlink-v7:";
constexpr std::string_view CompactedNamesCommitment="\\$fusion-names-v8:";
constexpr std::string_view CompactedPrivateCommitment="\\$fusion-private-v8:";
constexpr std::string_view CompactedUnlinkCommitment="\\$fusion-unlink-v8:";
bool Fail(std::string& e,const char* why){e=why;return false;}
bool IntentName(std::string_view name,std::wstring& wide,std::string& error) {
    wide.clear();if(name.empty())return true;
    if(name.size()>255)return Fail(error,"FusionRuntimeNameTooLong");
    const auto n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,name.data(),static_cast<int>(name.size()),nullptr,0);
    if(!n)return Fail(error,"FusionRuntimeInvalidUtf8");wide.resize(n);
    return MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,name.data(),static_cast<int>(name.size()),wide.data(),n)==n;
}
bool CanonicalName(std::string_view name,const ApfsNamePolicy& policy,std::wstring& display,std::string& error) {
    const auto decoded=ApfsNameCodec::Decode(std::as_bytes(std::span(name)),policy);
    if(!decoded.ok())return Fail(error,"FusionRuntimeInvalidName");
    display=decoded.value->windows_display;return true;
}
bool Stage(const AppleCheckpointStageHook& hook,std::string_view name,std::string& e) {
    return !hook||hook(name)||Fail(e,"FusionRuntimeInterrupted");
}
#include "FusionRuntimeRanges.inc"
}
FusionImageRuntime::FusionImageRuntime()=default;
FusionImageRuntime::~FusionImageRuntime()=default;
FusionImageRuntime::PlanVersion FusionImageRuntime::NamespaceVersion(PlanVersion version) {
    if(version==PlanVersion::NamesV7||version==PlanVersion::NamesV8)return PlanVersion::NamesV5;
    if(version==PlanVersion::PrivateV7||version==PlanVersion::PrivateV8)return PlanVersion::PrivateV4;
    if(version==PlanVersion::UnlinkV7||version==PlanVersion::UnlinkV8)return PlanVersion::UnlinkV6;
    return version;
}
std::string_view FusionImageRuntime::PlanCommitment(PlanVersion version) {
    switch(version) {
    case PlanVersion::InlineV1:return LegacyCommitment;
    case PlanVersion::RangeV2:return RangeV2Commitment;
    case PlanVersion::ReclaimV3:return Commitment;
    case PlanVersion::PrivateV4:return PrivateCommitment;
    case PlanVersion::NamesV5:return NamesCommitment;
    case PlanVersion::UnlinkV6:return UnlinkCommitment;
    case PlanVersion::NamesV7:return CanonicalNamesCommitment;
    case PlanVersion::PrivateV7:return CanonicalPrivateCommitment;
    case PlanVersion::UnlinkV7:return CanonicalUnlinkCommitment;
    case PlanVersion::NamesV8:return CompactedNamesCommitment;
    case PlanVersion::PrivateV8:return CompactedPrivateCommitment;
    case PlanVersion::UnlinkV8:return CompactedUnlinkCommitment;
    default:return {};
    }
}
FusionImageRuntime::PlanVersion FusionImageRuntime::OriginalPlanVersion(std::string_view path) {
    if(path.starts_with(CompactedNamesCommitment))return PlanVersion::NamesV8;
    if(path.starts_with(CompactedPrivateCommitment))return PlanVersion::PrivateV8;
    if(path.starts_with(CompactedUnlinkCommitment))return PlanVersion::UnlinkV8;
    if(path.starts_with(CanonicalNamesCommitment))return PlanVersion::NamesV7;
    if(path.starts_with(CanonicalPrivateCommitment))return PlanVersion::PrivateV7;
    if(path.starts_with(CanonicalUnlinkCommitment))return PlanVersion::UnlinkV7;
    if(path.starts_with(LegacyCommitment))return PlanVersion::InlineV1;
    if(path.starts_with(RangeV2Commitment))return PlanVersion::RangeV2;
    if(path.starts_with(Commitment))return PlanVersion::ReclaimV3;
    if(path.starts_with(PrivateCommitment))return PlanVersion::PrivateV4;
    if(path.starts_with(NamesCommitment))return PlanVersion::NamesV5;
    if(path.starts_with(UnlinkCommitment))return PlanVersion::UnlinkV6;
    return PlanVersion::Invalid;
}
std::shared_ptr<catalog::ApfsReadBudget> FusionImageRuntime::CreateStartupReadBudget() {
    return std::make_shared<catalog::ApfsReadBudget>(200000,512ull<<20,2000000,512ull<<20);
}
std::unique_ptr<FusionImageRuntime> FusionImageRuntime::Open(const catalog::FusionBindRequest& request,
    const FusionVolumeSelection& selected,const std::wstring& path,std::string& e) try {
    e.clear();auto r=std::unique_ptr<FusionImageRuntime>(new FusionImageRuntime);
    std::array<std::byte,32> source{};std::wstring jid;
    if(!ApfsFusionImageWriteSession::Identify(request,selected,4096,source,jid,e))return {};
    r->journal_path_=path;r->witness_=std::unique_ptr<FusionPublicationJournal>(new FusionPublicationJournal(path));
    if(!r->witness_->Pin(e)||!FusionJournalContinuation::OpenOriginal(*r,request,selected,source,jid,e))return {};
    if(request.checkpoint_xid!=selected.checkpoint_xid)return (Fail(e,"FusionRuntimeSelectorMismatch"),nullptr);
    TransactionManager::RetainedAcceptedHistory history;
    if(!r->transactions_.LoadRetainedAcceptedHistory(history,e,{4ull<<20,4096}))return {};
    std::unique_ptr<FusionContinuationAdmission> continuation;
    if(!FusionJournalContinuation::Admit(*r,history,source,jid,continuation,e,request.cancellation.get()))return {};
    if(continuation){
        const auto last=history.pending.empty()?history.cleaned.back().preimage_checkpoint_xid+1:
            history.pending.back().preimage_checkpoint_xid+1;
        if(request.checkpoint_xid<continuation->origin_xid||request.checkpoint_xid>last)
            return (Fail(e,"FusionContinuationSelectorOutsideOriginalChain"),nullptr);
        auto binding=request;auto selection=selected;
        binding.checkpoint_xid=selection.checkpoint_xid=continuation->base_xid;
        if(!r->BindRetainedChain(binding,selection,source,jid,history,e,continuation.get()))return {};
        return r;
    }
    const auto& pending=history.pending;
    if(!history.cleaned.empty()){
        const auto latest=history.cleaned.back().preimage_checkpoint_xid;
        if(latest==UINT64_MAX||request.checkpoint_xid<history.cleaned.front().preimage_checkpoint_xid||
            request.checkpoint_xid>latest+1+((!pending.empty()&&latest<UINT64_MAX-1)?1u:0u))
            return (Fail(e,"FusionRuntimeSelectorOutsideOriginalChain"),nullptr);
        auto binding=request;auto selection=selected;
        binding.checkpoint_xid=selection.checkpoint_xid=history.cleaned.front().preimage_checkpoint_xid;
        if(!r->BindRetainedChain(binding,selection,source,jid,history,e))return {};
        return r;
    }
    auto binding=request;auto selection=selected;std::map<std::uint64_t,std::vector<std::byte>> overlay;
    if(!pending.empty()) {
        if(pending.size()!=1)return (Fail(e,"FusionRuntimeSinglePendingBoundaryRequired"),nullptr);
        if(!r->witness_->Load(pending.front().accepted_sequence,r->recovery_,e)) {
            if(e!="FusionWitnessMissing")return {};e.clear();
        } else {
            auto& p=*r->recovery_;
            if(p.source!=source||p.jid!=TransactionManager::WideToUtf8(jid)||p.volume!=selected.volume_oid||
                (request.checkpoint_xid!=p.plan.expected_checkpoint_xid&&request.checkpoint_xid!=p.plan.transaction_xid)||
                !r->Match(p,pending.front(),e))return (Fail(e,"FusionRuntimeRecoveryBindingMismatch"),nullptr);
            for(const auto& [block,bytes]:p.before) {
                if(block>UINT64_MAX/4096)return (Fail(e,"FusionRuntimeRecoveryAddressOverflow"),nullptr);
                overlay.emplace(block*4096,bytes);
            }
            binding.checkpoint_xid=selection.checkpoint_xid=p.plan.expected_checkpoint_xid;
        }
    }
    if(r->owner_){if(!r->owner_->RefreshHeld(binding.checkpoint_xid,e,overlay.empty()?nullptr:&overlay))return {};}
    else r->owner_=ApfsFusionImageWriteSession::OpenInternal(binding,selection,e,nullptr,overlay.empty()?nullptr:&overlay);
    if(!r->owner_||r->owner_->SourceBinding()!=source||r->owner_->JournalIdentity()!=jid)return {};
    if(r->owner_->store_->Checkpoint().superblock.block_size!=4096)return (Fail(e,"FusionRuntime4096ProfileRequired"),nullptr);
    if(!r->AdoptPrivateOwnership(history,binding.checkpoint_xid,e)||!r->ValidatePrivateOwnership(e))return {};
    r->startup_recovery_=!pending.empty()||!r->retained_files_.empty();
    if(pending.empty()&&!r->RefreshVolumeInfo(e))return {};
    return r;
} catch(const std::bad_alloc&){e="FusionRuntimeAllocationLimit";return {};}
  catch(const std::length_error&){e="FusionRuntimeAllocationLimit";return {};}

bool FusionImageRuntime::Prepare(WriteAheadLog::OperationKind operation,std::uint64_t inode,std::uint64_t offset,std::uint64_t length,std::span<const std::byte> payload,std::string_view name,
    std::unique_ptr<FusionPreparedPublication>& result,std::string& e,PlanVersion version) {
    result.reset();if(!owner_->Available(e))return false;
    if(version==PlanVersion::Invalid)return Fail(e,"FusionRuntimeUnknownPlannerVersion");
    if(operation==WriteAheadLog::OperationKind::Rename||operation==WriteAheadLog::OperationKind::Delete||operation==WriteAheadLog::OperationKind::SetBasicInfo) {
        if(!payload.empty()||(length&&operation!=WriteAheadLog::OperationKind::Rename))return Fail(e,"FusionRuntimeMetadataPayload");
        AppleVolumeTransactionRequest request;
        return PrepareMetadata(operation,inode,offset,length,name,request,e,version)&&SealPlan(operation,inode,offset,length,payload,name,request,result,e,version);
    }
    const bool resize=operation==WriteAheadLog::OperationKind::SetFileSize;
    const bool directory=operation==WriteAheadLog::OperationKind::CreateDirectory;
    const bool create=operation==WriteAheadLog::OperationKind::CreateFile||directory;
    if((operation!=WriteAheadLog::OperationKind::Write&&!resize&&!create)||length>MaxFile||payload.size()>MaxPayload||(!create&&offset>MaxFile)||
        (resize?(!payload.empty()||offset!=0):((!create&&payload.empty())||length!=payload.size())))return Fail(e,"FusionRuntimeInlineLimit");
    if(create?(!payload.empty()||length!=0||name.empty()||name.size()>255):!name.empty())return Fail(e,"FusionRuntimeCreateNameOrPayload");
    FusionNodeInfo node;
    if(!owner_->reader_->GetMetadata(create?offset:inode,node,e))return false;
    if(create?!node.IsDirectory():((node.mode&0170000)!=0100000||node.size>MaxFile||(!resize&&payload.size()>MaxFile-offset)))
        return Fail(e,"FusionRuntimeExistingFileRangeRequired");
    auto& store=*owner_->store_;const auto& container=store.Checkpoint();
    auto cp=catalog::LoadAppleReadOnlyVolumeView(store,container,e);if(!cp)return false;
    auto volume=std::find_if(cp->volumes.begin(),cp->volumes.end(),[&](const auto& v){return v.superblock.object_id==owner_->volume_oid_;});
    if(volume==cp->volumes.end())return Fail(e,"FusionRuntimeSelectedVolumeMissing");
    if(create) {
        std::wstring display;MetadataStore::DirectoryLink existing;
        if(!CanonicalName(name,ApfsNamePolicy::FromIncompatibleFeatures(volume->superblock.incompatible_features),display,e))return false;
        if(owner_->reader_->LookupEntry(offset,display,existing,e))return Fail(e,"FusionRuntimeNameCollision");
        if(owner_->reader_->LastStatus()!=FusionReadStatus::NotFound)return false;e.clear();
    }
    std::vector<catalog::BtreeRecord> records;
    if(!catalog::ReadBtreeLeafRecords(store,4096,volume->root_tree.physical_block,false,volume->superblock.omap_oid,
        container.superblock.xid,records,e))return false;
    if(create) {
        auto next=volume->superblock.next_object_id;
        if(version!=NamespaceVersion(version)) {
            std::vector<catalog::BtreeRecord> mappings;
            if(!catalog::ReadBtreeLeafRecords(store,4096,volume->object_map.tree.physical_block,true,0,
                container.superblock.xid,mappings,e)||!fusion_ids::Next(next,volume->root_tree.object_id,
                    records,{},mappings,next,e))return false;
        }
        if(next<16||next>=fusion_ids::Limit||(inode&&inode!=next))return Fail(e,"FusionRuntimeCreateInodeIdentity");inode=next;
    }
    AppleInodeRecord native,parent;bool found=false;
    for(const auto& record:records)if(catalog::ReadU64LE(record.key,0)==((3ull<<60)|(create?offset:inode))) {
        if(found||!ApfsExtendedRecordCodec::DecodeInode(record,native,e))return Fail(e,"FusionRuntimeInodeInvalid");found=true;
    }
    if(!found)return Fail(e,"FusionRuntimeInodeMissing");
    if((native.internal_flags&1)&&(!retained_files_.contains(inode)||native.parent_id!=3||
        !fusion_private::PrimaryNameIs(native,fusion_private::Name(inode,retained_files_.at(inode)))))
        return Fail(e,"FusionRuntimePrivateOwnershipUnproved");
    if(create) {
        parent=native;if(parent.children_or_links<0||parent.children_or_links==INT32_MAX)return Fail(e,"FusionRuntimeParentCountOverflow");++parent.children_or_links;
        native={};native.object_id=native.private_id=inode;native.parent_id=offset;native.mode=directory?0040755:0100644;native.children_or_links=directory?0:1;
        if(NamespaceVersion(version)==PlanVersion::NamesV5)fusion_private::PrimaryName(native,name);
        if(!directory)native.extended_fields.push_back({8,0,std::vector<std::byte>(40)});
    } else if(native.private_id!=inode||native.uncompressed_size!=node.size)return Fail(e,"FusionRuntimeOrdinaryPrivateStreamRequired");
    AppleVolumeTransactionRequest request;request.volume_object_id=owner_->volume_oid_;
    request.required_checkpoint_xids={container.superblock.xid};
    if(!directory&&!(version==PlanVersion::InlineV1?
        PlanFusionLegacyFile(*owner_->reader_,node,native,create,resize,offset,length,payload,records,request,e):
        PlanFusionFileRanges(*owner_->reader_,node,native,create,resize,offset,length,payload,records,request,e)))return false;
    for(auto& record:records) {
        const auto key=catalog::ReadU64LE(record.key,0);if(!key)return Fail(e,"FusionRuntimeRecordKey");
        if(create&&(*key&((1ull<<60)-1))==inode)return Fail(e,"FusionRuntimeCreateOidCollision");
        if(!create&&(*key>>60)==8&&(*key&((1ull<<60)-1))==native.private_id) {
            // Exact retained fragments and releases were derived above.
        } else {
            if(*key==((3ull<<60)|inode)&&!EncodeAppleInodeRecord(native,record,e))return false;
            if(create&&*key==((3ull<<60)|offset)&&!EncodeAppleInodeRecord(parent,record,e))return false;
            request.filesystem_records.push_back(std::move(record));
        }
    }
    if(create) {
        catalog::BtreeRecord record;if(!EncodeAppleInodeRecord(native,record,e))return false;request.filesystem_records.push_back(record);
        AppleDirectoryRecord link;link.parent_id=offset;link.file_id=inode;link.flags=directory?4:8;link.name_utf8=name;
        if(!EncodeAppleDirectoryRecord(link,ApfsNamePolicy::FromIncompatibleFeatures(volume->superblock.incompatible_features),record,e))return false;
        request.filesystem_records.push_back(record);
        if(directory)request.directory_count_delta=1;else request.file_count_delta=1;
    }
    return SealPlan(operation,inode,offset,length,payload,name,request,result,e,version);
}
bool FusionImageRuntime::SealPlan(WriteAheadLog::OperationKind operation,std::uint64_t inode,std::uint64_t offset,std::uint64_t length,
    std::span<const std::byte> payload,std::string_view name,const AppleVolumeTransactionRequest& request,
    std::unique_ptr<FusionPreparedPublication>& result,std::string& e,PlanVersion version) {
    auto& store=*owner_->store_;
    FusionVolumeTransactionPlan planned;
    const bool compacted=version==PlanVersion::NamesV8||version==PlanVersion::PrivateV8||version==PlanVersion::UnlinkV8;
    const bool admitted=compacted?PlanFusionCompactedVolumeTransaction(store,request,planned,e):
        version!=NamespaceVersion(version)?PlanFusionCanonicalVolumeTransaction(store,request,planned,e):
        (version==PlanVersion::ReclaimV3||version==PlanVersion::PrivateV4||version==PlanVersion::NamesV5||version==PlanVersion::UnlinkV6)?PlanFusionReclaimingVolumeTransaction(store,request,planned,e):
        PlanFusionVolumeTransaction(store,request,planned,e);
    if(!admitted) {
        const auto budget=store.ReadBudget();
        if(budget&&budget->Failed()) {
            const auto used=budget->Consumed();
            e+=":budget="+std::string(budget->Failure())+":reads="+std::to_string(used.reads)+
                ":readBytes="+std::to_string(used.read_bytes)+":records="+std::to_string(used.records)+
                ":recordBytes="+std::to_string(used.record_bytes);
        }
        std::string unavailable;
        if(!owner_->Available(unavailable))e+=":source="+unavailable;
        return false;
    }
    auto p=std::unique_ptr<FusionPreparedPublication>(new FusionPreparedPublication);
    p->source=owner_->source_binding_;p->jid=TransactionManager::WideToUtf8(owner_->journal_identity_);
    p->volume=owner_->volume_oid_;p->inode=inode;p->offset=offset;p->length=length;p->operation=static_cast<std::uint64_t>(operation);p->payload.assign(payload.begin(),payload.end());p->name=name;
    if(!FusionPublicationHash(payload,p->payload_hash))return Fail(e,"FusionRuntimePayloadHash");
    p->plan=std::move(planned.transaction.commit.publication);
    if(p->plan.before_superblock_writes.size()>FusionPreparedPublication::WriteLimit||
        p->plan.guard_blocks.size()>FusionPreparedPublication::GuardLimit||!p->plan.fusion_tier2_anchor_write)
        return Fail(e,"FusionRuntimePublicationLimit");
    auto before=[&](std::uint64_t block,const auto& bytes) {
        catalog::FusionRoute route;std::vector<std::byte> old;
        if(bytes.size()!=4096||p->before.contains(block)||!store.MapPhysical(block,0,4096,route,e)||
            !store.Read(block*4096,4096,old))return Fail(e,"FusionRuntimeWriteBoundsOrCollision");
        p->before.emplace(block,std::move(old));return true;
    };
    for(const auto& w:p->plan.before_superblock_writes)if(!before(w.physical_block,w.bytes))return false;
    if(!before(p->plan.superblock_write.physical_block,p->plan.superblock_write.bytes)||
        !before(p->plan.fusion_tier2_anchor_write->physical_block,p->plan.fusion_tier2_anchor_write->bytes)||
        !before(0,p->plan.superblock_write.bytes))return false;
    for(const auto& g:p->plan.guard_blocks) {catalog::FusionRoute route;if(g.bytes.size()!=4096||!store.MapPhysical(g.physical_block,0,4096,route,e))return false;}
    std::vector<std::byte> bounded;if(!p->Encode(bounded,e)||!owner_->Available(e))return false;
    result=std::move(p);return true;
}
bool FusionImageRuntime::Original(std::uint64_t sequence,TransactionManager::AcceptedTransaction& out,std::string& e) {
    if(!transactions_.RecoveryStateValid()||!transactions_.JournalMatchesVolumeIdentity(owner_->journal_identity_)||
        !transactions_.ObservedJournalWriterLeaseGeneration())return Fail(e,"FusionRuntimeOriginalGateLost");
    std::vector<TransactionManager::AcceptedTransaction> list;
    if(!transactions_.LoadAcceptedTransactionsSinceCleanup(list,&e,{4ull<<20,4096}))return false;
    if(list.size()!=1||list.front().accepted_sequence!=sequence)return Fail(e,"FusionRuntimeExactOriginalBoundaryRequired");
    out=std::move(list.front());return true;
}
bool FusionImageRuntime::Match(const FusionPreparedPublication& p,const TransactionManager::AcceptedTransaction& original,std::string& e,
    std::string* verified_digest) {
    if(verified_digest)verified_digest->clear();
    if(!original.transaction_id||!original.accepted_sequence||original.mutations.size()!=1||
        original.preimage_checkpoint_xid!=p.plan.expected_checkpoint_xid||p.plan.transaction_xid!=p.plan.expected_checkpoint_xid+1)
        return Fail(e,"FusionRuntimeOriginalBoundaryMismatch");
    const auto& m=original.mutations.front();std::string digest;if(!p.Digest(digest,e))return false;
    if(p.accepted_sequence&&(p.accepted_sequence!=original.accepted_sequence||p.transaction_id!=original.transaction_id||p.mutation_sequence!=m.sequence))return Fail(e,"FusionRuntimeEnrolledBoundaryMismatch");
    const bool resize=p.operation==static_cast<std::uint64_t>(WriteAheadLog::OperationKind::SetFileSize);
    const bool create=p.operation==static_cast<std::uint64_t>(WriteAheadLog::OperationKind::CreateFile)||p.operation==static_cast<std::uint64_t>(WriteAheadLog::OperationKind::CreateDirectory);
    const bool metadata=p.operation==static_cast<std::uint64_t>(WriteAheadLog::OperationKind::Rename)||p.operation==static_cast<std::uint64_t>(WriteAheadLog::OperationKind::Delete)||p.operation==static_cast<std::uint64_t>(WriteAheadLog::OperationKind::SetBasicInfo);
    if((!resize&&!create&&!metadata&&p.operation!=static_cast<std::uint64_t>(WriteAheadLog::OperationKind::Write))||
        static_cast<std::uint64_t>(m.operation)!=p.operation||m.state!=WriteAheadLog::RecordState::Prepared||
        m.transaction_id!=original.transaction_id||!m.sequence||m.sequence>=original.accepted_sequence||m.volume_identity!=p.jid||
        m.object_id!=p.inode||m.parent_object_id!=p.plan.expected_checkpoint_xid||m.logical_offset!=p.offset||
        m.logical_length!=p.length||m.payload_length!=p.payload.size()||m.inline_payload!=p.payload||m.payload_offset||
        m.payload_spool_id!=(p.payload.empty()?0:m.sequence)||m.flags||m.unlink_outcome||m.secondary_path_utf8!=p.name||(!create&&!metadata&&!p.name.empty())||
        (OriginalPlanVersion(m.path_utf8)==PlanVersion::Invalid||m.path_utf8!=std::string(PlanCommitment(OriginalPlanVersion(m.path_utf8)))+digest)||(!p.payload.empty()&&!WriteAheadLog::InlinePayloadIsConsistent(m))||
        (p.payload.empty()&&std::any_of(m.payload_sha256.begin(),m.payload_sha256.end(),[](auto b){return b!=0;}))||
        (resize&&(!p.payload.empty()||p.offset)))return Fail(e,"FusionRuntimeOriginalCommitmentMismatch");
    if(verified_digest)*verified_digest=std::move(digest);
    return true;
}
bool FusionImageRuntime::Overwrite(std::uint64_t inode,std::uint64_t offset,std::span<const std::byte> bytes,
    std::string& e,const AppleCheckpointStageHook& hook) {
    return Mutate(WriteAheadLog::OperationKind::Write,inode,offset,bytes.size(),bytes,{},e,hook);
}
bool FusionImageRuntime::Resize(std::uint64_t inode,std::uint64_t length,std::string& e,const AppleCheckpointStageHook& hook) {
    return Mutate(WriteAheadLog::OperationKind::SetFileSize,inode,0,length,{},{},e,hook);
}
bool FusionImageRuntime::CreateRegularFile(std::uint64_t parent,std::string_view name,
    std::uint64_t& created,std::string& e,const AppleCheckpointStageHook& hook) {
    created=0;return Mutate(WriteAheadLog::OperationKind::CreateFile,0,parent,0,{},name,e,hook,&created);
}
bool FusionImageRuntime::MakeDirectory(std::uint64_t parent,std::string_view name,
    std::uint64_t& created,std::string& e,const AppleCheckpointStageHook& hook) {
    created=0;return Mutate(WriteAheadLog::OperationKind::CreateDirectory,0,parent,0,{},name,e,hook,&created);
}
bool FusionImageRuntime::Mutate(WriteAheadLog::OperationKind operation,std::uint64_t inode,std::uint64_t offset,std::uint64_t length,
    std::span<const std::byte> bytes,std::string_view name,std::string& e,const AppleCheckpointStageHook& hook,std::uint64_t* created,PlanVersion version) {
    std::lock_guard lock(gate_);
    if(startup_recovery_)return Fail(e,"FusionRuntimeStartupRecoveryRequired");
    const auto result=MutateLocked(operation,inode,offset,length,bytes,name,e,hook,created,version);
    if(!result&&owner_&&owner_->request_.budget&&owner_->request_.budget->Failed()) {
        const auto used=owner_->request_.budget->Consumed();
        const auto refused=owner_->request_.budget->ReservationFailure();
        e+=":walk-reads="+std::to_string(used.reads)+":walk-read-bytes="+std::to_string(used.read_bytes)+
            ":walk-records="+std::to_string(used.records)+":walk-record-bytes="+std::to_string(used.record_bytes)+
            ":refused-records="+std::to_string(refused.count)+":refused-bytes="+std::to_string(refused.bytes);
    }
    return result;
}
bool FusionImageRuntime::MutateLocked(WriteAheadLog::OperationKind operation,std::uint64_t inode,std::uint64_t offset,std::uint64_t length,
    std::span<const std::byte> bytes,std::string_view name,std::string& e,const AppleCheckpointStageHook& hook,std::uint64_t* created,PlanVersion version) try {
    e.clear();auto water=transactions_.Watermarks();
    if(water.accepted_sequence!=water.cleanup_sequence||recovery_)return Fail(e,"FusionRuntimePendingRecovery");
    if(!owner_->Available(e)||!owner_->request_.budget||owner_->request_.budget->Failed())return false;
    // A new, bounded walk starts only after admission/previous cleanup succeeded.
    // All planning, acceptance, replay and post-publication checks share it;
    // failed walks remain sticky and can never renew their allowance on retry.
    auto prior_budget=owner_->request_.budget;
    owner_->request_.budget=std::make_shared<catalog::ApfsReadBudget>(100000,256ull*1024*1024,1000000,256ull*1024*1024);
    if(!owner_->RefreshHeld(owner_->status_.checkpoint_xid,e)) {
        owner_->request_.budget=std::move(prior_budget);owner_->cancellation_->store(true);return false;
    }
    if(!FusionJournalContinuation::Continue(*this,e,hook))return false;
    std::unique_ptr<FusionPreparedPublication> preflight;if(!Prepare(operation,inode,offset,length,bytes,name,preflight,e,version))return false;
    if(!Stage(hook,"after-fusion-preflight",e))return false;
    inode=preflight->inode;
    std::string digest;if(!preflight->Digest(digest,e))return false;
    const bool resize=operation==WriteAheadLog::OperationKind::SetFileSize;
    TransactionManager::MutationIntent intent;intent.kind=resize?TransactionManager::MutationKind::SetFileSize:
        operation==WriteAheadLog::OperationKind::CreateFile?TransactionManager::MutationKind::CreateFile:
        operation==WriteAheadLog::OperationKind::CreateDirectory?TransactionManager::MutationKind::CreateDirectory:
        operation==WriteAheadLog::OperationKind::Rename?TransactionManager::MutationKind::Rename:
        operation==WriteAheadLog::OperationKind::Delete?TransactionManager::MutationKind::Delete:
        operation==WriteAheadLog::OperationKind::SetBasicInfo?TransactionManager::MutationKind::SetBasicInfo:TransactionManager::MutationKind::Write;
    const auto path=std::string(PlanCommitment(version))+digest;intent.path.assign(path.begin(),path.end());intent.object_id=inode;
    intent.generation=preflight->plan.expected_checkpoint_xid;intent.offset=offset;intent.length=length;intent.payload_length=bytes.size();
    intent.inline_payload.assign(bytes.begin(),bytes.end());
    if(!IntentName(name,intent.secondary_path,e))return false;
    if(!bytes.empty())for(std::size_t i=0;i<32;++i)intent.payload_checksum[i]=std::to_integer<std::uint8_t>(preflight->payload_hash[i]);
    WriteAheadLog::Record record;
    record.volume_identity=preflight->jid;record.transaction_id=1;record.sequence=transactions_.NextMutationSequence();
    record.object_id=inode;record.parent_object_id=intent.generation;record.logical_offset=offset;record.logical_length=length;
    record.operation=operation;record.path_utf8=path;record.inline_payload=intent.inline_payload;
    record.payload_length=bytes.size();record.payload_sha256=intent.payload_checksum;record.payload_spool_id=bytes.empty()?0:record.sequence;record.secondary_path_utf8=name;
    std::vector<WriteAheadLog::Record> capacity{record};
    for(unsigned i=0;i<7;++i){WriteAheadLog::Record marker;marker.volume_identity=preflight->jid;marker.transaction_id=1;
        marker.sequence=record.sequence+i+1;marker.path_utf8="strict";marker.object_id=intent.generation;marker.logical_length=1;marker.flags=8;
        marker.operation=WriteAheadLog::OperationKind::TransactionMarker;marker.state=WriteAheadLog::RecordState::Accepted;capacity.push_back(std::move(marker));}
    std::error_code capacity_error;
    const auto present=std::filesystem::exists(journal_path_,capacity_error);
    std::uint64_t capacity_bytes=present?std::filesystem::file_size(journal_path_,capacity_error):0;
    if(capacity_error||capacity_bytes>2ull<<20)return Fail(e,"FusionRuntimeOriginalCapacity");
    for(const auto& entry:capacity){const auto encoded=WriteAheadLog::EncodeForTest(entry);
        if(encoded.empty()||encoded.size()>(2ull<<20)-capacity_bytes)return Fail(e,"FusionRuntimeOriginalCapacity");capacity_bytes+=encoded.size();}
    auto retained_after=retained_files_.size();
    if((NamespaceVersion(version)==PlanVersion::PrivateV4&&operation==WriteAheadLog::OperationKind::Rename)||
        NamespaceVersion(version)==PlanVersion::UnlinkV6)++retained_after;
    else if(NamespaceVersion(version)==PlanVersion::PrivateV4&&operation==WriteAheadLog::OperationKind::Delete){
        if(!retained_after)return Fail(e,"FusionRuntimePrivateOwnershipUnproved");--retained_after;
    }
    if(retained_after){
        // Reserve a complete future original transaction for each held private
        // inode. These records measure encoded capacity only; they are never
        // persisted or used as acceptance, ownership or replay authority.
        auto retirement=record;retirement.operation=WriteAheadLog::OperationKind::Delete;
        retirement.logical_offset=retirement.logical_length=retirement.payload_length=retirement.payload_spool_id=0;
        retirement.inline_payload.clear();retirement.payload_sha256={};retirement.secondary_path_utf8.clear();
        retirement.path_utf8=std::string(CanonicalPrivateCommitment)+digest;
        auto encoded=WriteAheadLog::EncodeForTest(retirement);
        if(encoded.empty())return Fail(e,"FusionRuntimePrivateRetirementCapacity");
        auto retirement_bytes=encoded.size();
        for(std::size_t i=1;i<capacity.size();++i){
            encoded=WriteAheadLog::EncodeForTest(capacity[i]);
            if(encoded.empty()||encoded.size()>(2ull<<20)-retirement_bytes)return Fail(e,"FusionRuntimePrivateRetirementCapacity");
            retirement_bytes+=encoded.size();
        }
        if(retained_after>((2ull<<20)-capacity_bytes)/retirement_bytes)
            return Fail(e,"FusionRuntimePrivateRetirementCapacity");
    }
    // The held TM owns the original file; this bounded profile stays below
    // its configured 64 MiB quota, including seven complete terminal records.
    if(!transactions_.ObservedJournalWriterLeaseGeneration()||transactions_.CurrentState()!=TransactionManager::State::Idle||
        transactions_.NextMutationSequence()>UINT64_MAX-9)return Fail(e,"FusionRuntimeOriginalCapacity");
    if(!witness_->Preflight(transactions_.NextMutationSequence()+1,*preflight,e))return false;
    if(!Stage(hook,"before-fusion-accept",e)||!owner_->Available(e))return false;
    std::error_code ec;const auto exists=std::filesystem::exists(journal_path_,ec);
    if(ec||(!exists&&!transactions_.MaterializeAbsentStartupJournal(e)))return false;
    if(!transactions_.Begin()||(!bytes.empty()&&!transactions_.CanAddInlinePayload(bytes.size()))||!transactions_.RecordMutation(intent)||!transactions_.Accept(intent.generation))return Fail(e,"FusionRuntimeOriginalAcceptanceFailed");
    if(!Stage(hook,"after-fusion-accept",e))return false;
    const auto sequence=transactions_.Watermarks().accepted_sequence;
    TransactionManager::AcceptedTransaction original;
    if(!Original(sequence,original,e)||!Match(*preflight,original,e))return false;
    // Derive again from the held original accepted record, never from the
    // caller's preview or a caller-authored physical write set.
    const auto& m=original.mutations.front();std::unique_ptr<FusionPreparedPublication> accepted;
    if(!Prepare(m.operation,m.object_id,m.logical_offset,m.logical_length,m.inline_payload,m.secondary_path_utf8,accepted,e,OriginalPlanVersion(m.path_utf8))||!Match(*accepted,original,e))return false;
    if(!Stage(hook,"after-fusion-accepted-derive",e))return false;
    accepted->accepted_sequence=sequence;accepted->transaction_id=original.transaction_id;accepted->mutation_sequence=m.sequence;
    if(!transactions_.FlushAcceptedEvidenceDurability(sequence))return Fail(e,"FusionRuntimeOriginalFlush");
    if(!witness_->Store(sequence,*accepted,e))return false;
    recovery_=std::move(accepted);
    if(!Stage(hook,"after-fusion-witness",e))return false;
    if(!RecoverLocked(e,hook))return false;if(created)*created=inode;return true;
} catch(const std::bad_alloc&){return Fail(e,"FusionRuntimeAllocationLimit");}
  catch(const std::length_error&){return Fail(e,"FusionRuntimeAllocationLimit");}

bool FusionImageRuntime::RecoverLocked(std::string& e,const AppleCheckpointStageHook& hook) {
    const auto sequence=transactions_.Watermarks().accepted_sequence;
    if(sequence==transactions_.Watermarks().cleanup_sequence){recovery_.reset();return owner_->Available(e);}
    TransactionManager::AcceptedTransaction original;if(!Original(sequence,original,e))return false;
    // Every retry reopens the durable stream. An in-memory draft left by a
    // failed append can never stand in for a complete flushed witness.
    if(!witness_->Load(sequence,recovery_,e)) {
        if(e!="FusionWitnessMissing"||original.mutations.size()!=1)return false;e.clear();
        const auto& m=original.mutations.front();
        if(!Prepare(m.operation,m.object_id,m.logical_offset,m.logical_length,m.inline_payload,m.secondary_path_utf8,recovery_,e,OriginalPlanVersion(m.path_utf8))||!Match(*recovery_,original,e))return false;
        recovery_->accepted_sequence=sequence;recovery_->transaction_id=original.transaction_id;recovery_->mutation_sequence=m.sequence;
        if(!transactions_.FlushAcceptedEvidenceDurability(sequence)){recovery_.reset();return Fail(e,"FusionRuntimeOriginalFlush");}
        if(!witness_->Store(sequence,*recovery_,e)) {recovery_.reset();return false;}
        if(!witness_->Load(sequence,recovery_,e))return false;
    }
    if(!Match(*recovery_,original,e))return false;
    if(recovery_->source!=owner_->source_binding_||recovery_->jid!=TransactionManager::WideToUtf8(owner_->journal_identity_))return Fail(e,"FusionRuntimeRecoveryBindingMismatch");
    std::map<std::uint64_t,std::vector<std::byte>> overlay;
    for(const auto& [block,bytes]:recovery_->before) {
        if(block>UINT64_MAX/4096)return Fail(e,"FusionRuntimeRecoveryAddressOverflow");
        overlay.emplace(block*4096,bytes);
    }
    if(!owner_->RefreshHeld(recovery_->plan.expected_checkpoint_xid,e,&overlay))return false;
    std::unique_ptr<FusionPreparedPublication> derived;
    if(!Prepare(static_cast<WriteAheadLog::OperationKind>(recovery_->operation),recovery_->inode,recovery_->offset,recovery_->length,recovery_->payload,recovery_->name,derived,e,OriginalPlanVersion(original.mutations.front().path_utf8))||!Match(*derived,original,e))return false;
    if(!Stage(hook,"after-fusion-recovery-derive",e))return false;
    if(!Publish(*recovery_,sequence,e,hook,OriginalPlanVersion(original.mutations.front().path_utf8)))return false;
    recovery_.reset();return true;
}
bool FusionImageRuntime::Recover(std::string& e,const AppleCheckpointStageHook& hook) try {
    std::lock_guard lock(gate_);e.clear();if(!RecoverLocked(e,hook))return false;
    if(startup_recovery_){
        if(!ValidatePrivateOwnership(e))return false;
        while(!retained_files_.empty()){
            const auto inode=retained_files_.begin()->first;
            if(!MutateLocked(WriteAheadLog::OperationKind::Delete,inode,0,0,{},{},e,hook,nullptr,PlanVersion::PrivateV8))return false;
        }
        startup_recovery_=false;
    }
    return true;
} catch(const std::bad_alloc&){return Fail(e,"FusionRuntimeAllocationLimit");}
  catch(const std::length_error&){return Fail(e,"FusionRuntimeAllocationLimit");}

bool FusionImageRuntime::Publish(const FusionPreparedPublication& p,std::uint64_t sequence,std::string& e,const AppleCheckpointStageHook& hook,PlanVersion version) {
    if(!p.accepted_sequence||p.accepted_sequence!=sequence||!p.transaction_id||!p.mutation_sequence)return Fail(e,"FusionRuntimeWitnessEnrollmentRequired");
    auto& store=*owner_->store_;const auto& plan=p.plan;
    std::map<std::uint64_t,std::vector<std::byte>> writes;
    for(const auto& w:plan.before_superblock_writes)if(!writes.emplace(w.physical_block,w.bytes).second)return Fail(e,"FusionRuntimeWriteCollision");
    if(!plan.fusion_tier2_anchor_write||!writes.emplace(plan.superblock_write.physical_block,plan.superblock_write.bytes).second||
        !writes.emplace(plan.fusion_tier2_anchor_write->physical_block,plan.fusion_tier2_anchor_write->bytes).second||
        !writes.emplace(0,plan.superblock_write.bytes).second||writes.size()!=p.before.size())return Fail(e,"FusionRuntimeAnchorCollision");
    auto read_range=[&](std::uint64_t block,std::size_t count,std::vector<std::byte>& bytes) {
        catalog::FusionRoute route;if(!owner_->Available(e)||!store.MapPhysical(block,0,count*4096,route,e))return false;
        const auto role=route.role==catalog::FusionMemberRole::Main?0u:1u;
        return owner_->devices_[role]->ReadForVerification(route.image_offset,count*4096,bytes)&&bytes.size()==count*4096&&owner_->Available(e);
    };
    auto read=[&](std::uint64_t block,std::vector<std::byte>& bytes){return read_range(block,1,bytes);};
    std::set<std::uint64_t> complete,partial;
    if(!fusion_verify::Ranges(writes,read_range,[&](std::uint64_t block,std::span<const std::byte> bytes,std::span<const std::byte> actual){
        auto before=p.before.find(block);
        if(before==p.before.end()||before->second.size()!=4096)return Fail(e,"FusionRuntimePreflightRead");
        if(std::equal(actual.begin(),actual.end(),bytes.begin()))complete.insert(block);
        else if(!std::equal(actual.begin(),actual.end(),before->second.begin())) {
            // The original commitment and canonical rederivation have already
            // proved this exact destination. Admit only old/new byte mixtures;
            // unrelated bytes or another checksum-valid object remain debt.
            for(std::size_t i=0;i<actual.size();++i)
                if(actual[i]!=before->second[i]&&actual[i]!=bytes[i])return Fail(e,"FusionRuntimeUnknownPartialWriteDebt");
            if(catalog::VerifyObjectChecksum(bytes,4096)&&catalog::VerifyObjectChecksum(actual,4096))return Fail(e,"FusionRuntimeUnrelatedDestinationObject");
            partial.insert(block);
        }
        return true;
    }))return Fail(e,e.empty()?"FusionRuntimePreflightRead":e.c_str());
    std::map<std::uint64_t,const std::vector<std::byte>*> guards;
    for(const auto& g:plan.guard_blocks)
        if(g.bytes.size()!=4096||!guards.emplace(g.physical_block,&g.bytes).second)return Fail(e,"FusionRuntimeGuardCollision");
    for(auto first=guards.begin();first!=guards.end();) {
        auto end=std::next(first);std::size_t count=1;
        while(end!=guards.end()&&count<16&&first->first<=UINT64_MAX-count&&end->first==first->first+count){++end;++count;}
        catalog::FusionRoute route;std::vector<std::byte> actual;
        if(!owner_->Available(e)||!store.MapPhysical(first->first,0,count*4096,route,e))return false;
        const auto role=route.role==catalog::FusionMemberRole::Main?0u:1u;
        if(!owner_->devices_[role]->ReadForVerification(route.image_offset,count*4096,actual)||actual.size()!=count*4096)
            return Fail(e,"FusionRuntimeGuardRead");
        if(!owner_->Available(e))return false;
        std::size_t index=0;
        for(auto g=first;g!=end;++g,++index) {
            const auto block=g->first;const auto& expected=*g->second;
            const auto begin=actual.begin()+index*4096;
            const auto matches=[&](const auto& bytes){return bytes.size()==4096&&std::equal(begin,begin+4096,bytes.begin());};
            if(!matches(expected)&&(!complete.contains(block)||!matches(writes.at(block)))&&
                (!partial.contains(block)||p.before.at(block)!=expected))return Fail(e,"FusionRuntimeGuardChanged");
        }
        first=end;
    }
    // All non-destination guards have passed before the first redo write. A
    // partial destination restarts the entire proven publication in order,
    // including both member barriers and both main publication blocks.
    if(!partial.empty())complete.clear();
    bool staged=true;for(const auto& w:plan.before_superblock_writes)staged=staged&&complete.contains(w.physical_block);
    const auto mirror=plan.fusion_tier2_anchor_write->physical_block,checkpoint=plan.superblock_write.physical_block;
    if((complete.contains(mirror)&&!staged)||(complete.contains(checkpoint)&&(!staged||!complete.contains(mirror)))||
        (complete.contains(0)&&(!staged||!complete.contains(mirror)||!complete.contains(checkpoint))))return Fail(e,"FusionRuntimePublicationOrderDebt");
    if(!transactions_.FlushAcceptedEvidenceDurability(sequence))return Fail(e,"FusionRuntimeOriginalFlush");
    auto write=[&](std::uint64_t block) {
        if(!owner_->Available(e))return false;
        if(complete.contains(block))return true;
        if(!owner_->writer_->WriteBlocks(block,writes.at(block),e))return false;
        std::vector<std::byte> actual;
        if(!read(block,actual)||actual!=writes.at(block))return Fail(e,"FusionRuntimeWriteReadback");
        complete.insert(block);return true;
    };
    auto flush=[&]() {return owner_->Available(e)&&owner_->writer_->FlushOrdered(e)&&owner_->Available(e);};
    if(!Stage(hook,"before-fusion-device-write",e))return false;
    for(const auto& w:plan.before_superblock_writes)if(!write(w.physical_block))return false;
    if(!flush())return false;
    for(const auto& w:plan.before_superblock_writes){std::vector<std::byte> actual;if(!read(w.physical_block,actual)||actual!=w.bytes)return Fail(e,"FusionRuntimeStagingReadback");}
    if(!Stage(hook,"before-fusion-mirror",e)||!write(mirror)||!flush()||!Stage(hook,"after-fusion-mirror",e))return false;
    if(!Stage(hook,"before-fusion-checkpoint",e)||!write(checkpoint)||!flush()||!Stage(hook,"after-fusion-checkpoint",e))return false;
    if(!Stage(hook,"before-fusion-main",e)||!write(0)||!flush()||!Stage(hook,"after-fusion-main",e))return false;
    if(!fusion_verify::Ranges(writes,read_range,[&](std::uint64_t,std::span<const std::byte> bytes,std::span<const std::byte> actual){
        return std::equal(actual.begin(),actual.end(),bytes.begin());
    }))return Fail(e,"FusionRuntimeFinalReadback");
    // Rebind canonical readers to the same leases, then prove both complete
    // checkpoint generations and actual post-publication allocation truth.
    if(!owner_->RefreshHeld(plan.transaction_xid,e))return false;
    auto& current=*owner_->store_;
    auto old=catalog::LoadContainerCheckpointView(current,0,current.SizeBytes(),e,plan.expected_checkpoint_xid);
    if(!old||!catalog::LoadAppleReadOnlyVolumeView(current,*old,e)) {
        const auto reason=current.ReadBudget()->Failed()?current.ReadBudget()->Failure():e;
        e="FusionRuntimeOldCheckpointProof:"+std::string(reason);return false;
    }
    catalog::AppleSpacemanView allocation;
    if(!catalog::LoadFusionSpacemanAllocationView(current,allocation,e))return false;
    std::vector<std::byte> payload;
    if(p.operation==static_cast<std::uint64_t>(WriteAheadLog::OperationKind::SetFileSize)) {
        FusionNodeInfo node;if(!owner_->reader_->GetMetadata(p.inode,node,e)||node.size!=p.length)return Fail(e,"FusionRuntimeResizeReadback");
    } else if(p.operation==static_cast<std::uint64_t>(WriteAheadLog::OperationKind::Delete)) {
        if(NamespaceVersion(version)==PlanVersion::UnlinkV6){
            std::map<std::uint64_t,std::string> files;
            if(!owner_->reader_->PrivateFiles(files,e)||!files.contains(p.inode)||
                files.at(p.inode)!=fusion_private::Name(p.inode,p.plan.transaction_xid))return Fail(e,"FusionRuntimeRetainedUnlinkReadback");
        }else{FusionNodeInfo node;if(owner_->reader_->GetMetadata(p.inode,node,e)||owner_->reader_->LastStatus()!=FusionReadStatus::NotFound)return Fail(e,"FusionRuntimeUnlinkReadback");}e.clear();
    } else if(p.operation==static_cast<std::uint64_t>(WriteAheadLog::OperationKind::Rename)) {
        MetadataStore::DirectoryLink entry;std::wstring name;FusionNamespaceInfo names;
        if(!owner_->reader_->GetNamespaceInfo(names,e)||!CanonicalName(p.name,names.name_policy,name,e))return false;
        if(!owner_->reader_->LookupEntry(p.offset,name,entry,e)||entry.child_object_id!=p.inode)return Fail(e,"FusionRuntimeRenameReadback");
        if(p.length){FusionNodeInfo removed;
            if(NamespaceVersion(version)==PlanVersion::PrivateV4){
                std::map<std::uint64_t,std::string> files;
                if(!owner_->reader_->PrivateFiles(files,e)||!files.contains(p.length)||
                    files.at(p.length)!=fusion_private::Name(p.length,p.plan.transaction_xid))return Fail(e,"FusionRuntimeRetainedReplaceReadback");
            } else if(owner_->reader_->GetMetadata(p.length,removed,e)||owner_->reader_->LastStatus()!=FusionReadStatus::NotFound)return Fail(e,"FusionRuntimeReplaceReadback");e.clear();}
    } else if(p.operation==static_cast<std::uint64_t>(WriteAheadLog::OperationKind::CreateDirectory)) {
        FusionNodeInfo node;if(!owner_->reader_->GetMetadata(p.inode,node,e)||!node.IsDirectory()||node.children_or_links)return Fail(e,"FusionRuntimeDirectoryReadback");
    } else if(p.operation!=static_cast<std::uint64_t>(WriteAheadLog::OperationKind::SetBasicInfo)&&
        (!owner_->reader_->ReadFile(p.inode,p.operation==static_cast<std::uint64_t>(WriteAheadLog::OperationKind::CreateFile)?0:p.offset,p.payload.size(),payload,e)||payload!=p.payload))return Fail(e,"FusionRuntimePayloadReadback");
    if(!RefreshVolumeInfo(e))return false;
    if(!owner_->Available(e))return false;
    TransactionManager::AcceptedTransaction final_original;
    if(!Original(sequence,final_original,e)||!Match(p,final_original,e))return false;
    if(!Stage(hook,"before-fusion-durable",e)||!transactions_.MarkApfsDurableThrough(sequence))return Fail(e,"FusionRuntimeDurableMarker");
    if(!Stage(hook,"after-fusion-durable",e)||!owner_->Available(e)||!transactions_.MarkCleanedThrough(sequence))return Fail(e,"FusionRuntimeCleanupMarker");
    TrackPrivateBoundary(final_original);
    if(!ValidatePrivateOwnership(e))return false;
    return Stage(hook,"after-fusion-cleanup",e);
}
bool FusionImageRuntime::ReadFile(std::uint64_t inode,std::uint64_t offset,std::size_t length,std::vector<std::byte>& out,std::string& e) {
    std::lock_guard lock(gate_);out.clear();
    if(!ReadReady(e))return false;
    return owner_->ReadFile(inode,offset,length,out,e);
}
TransactionManager::DurabilityWatermarks FusionImageRuntime::Watermarks() const {std::lock_guard lock(gate_);return transactions_.Watermarks();}
void FusionImageRuntime::Cancel() noexcept {owner_->Cancel();}
#include "FusionRuntimeRetainedChain.inc"
#include "FusionRuntimePrivateFiles.inc"
#include "FusionRuntimeMetadata.inc"
}
