#include "MetadataStore.h"
#include "NativeHardLink.h"
#include "TransactionManager.h"
#include "AppleVolumeTransaction.h"
#include <algorithm>
#include <map>
#include <set>

namespace apfsaccess::rw
{
namespace
{
template<class F> struct OnExit { F call; ~OnExit() {call();} };
template<class F> OnExit(F) -> OnExit<F>;
template<class Manager, class Log>
bool RegisteredKind()
{
    if constexpr(requires {Manager::MutationKind::HardLink; Log::OperationKind::HardLink;})
        return static_cast<std::uint32_t>(Manager::MutationKind::HardLink)==NativeHardLinkOperationKind &&
            static_cast<std::uint32_t>(Log::OperationKind::HardLink)==NativeHardLinkOperationKind;
    else return false;
}
class Source final : public catalog::RandomAccessSource
{
public:
    explicit Source(const BlockDevice& device) : device_(device) {}
    std::uint64_t SizeBytes() const override {return device_.GetGeometry().total_bytes;}
    bool Read(std::uint64_t offset,std::size_t size,std::vector<std::byte>& out) const override
    {
        out.clear();return offset<=SizeBytes() && size<=SizeBytes()-offset &&
            (size==0 || (device_.Read(offset,size,out) && out.size()==size));
    }
private:
    const BlockDevice& device_;
};
class PreimageSource final : public catalog::RandomAccessSource
{
public:
    PreimageSource(const catalog::RandomAccessSource& source, const NativeHardLinkProof& proof)
        : source_(source), proof_(proof) {}
    std::uint64_t SizeBytes() const override { return source_.SizeBytes(); }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override
    {
        if (offset > SizeBytes() || size > SizeBytes() - offset ||
            !source_.Read(offset, size, out) || out.size() != size) return false;
        for (const auto& preimage : proof_.preimages) {
            const auto start = preimage.physical_block * 4096;
            const auto lo = (std::max)(offset, start), hi = (std::min)(offset + size, start + 4096);
            if (lo < hi) std::copy_n(preimage.bytes.begin() + static_cast<std::ptrdiff_t>(lo - start),
                static_cast<std::size_t>(hi - lo), out.begin() + static_cast<std::ptrdiff_t>(lo - offset));
        }
        return true;
    }
private:
    const catalog::RandomAccessSource& source_;
    const NativeHardLinkProof& proof_;
};
bool CapturePreimages(const catalog::RandomAccessSource& source, const AppleCheckpointPublicationPlan& plan,
    NativeHardLinkProof& proof, std::string& error)
{
    const auto fail = [&] { error = "HardLinkPreimageCensusInvalid"; return false; };
    if (plan.block_size != 4096 || plan.fusion_tier2_anchor_write) return fail();
    std::set<std::uint64_t> blocks;
    const auto add = [&](const auto& block) {
        if (block.bytes.empty() || block.bytes.size() % 4096) return false;
        const auto count = block.bytes.size() / 4096;
        if (block.physical_block >= proof.block_count || count > proof.block_count - block.physical_block) return false;
        for (std::size_t n = 0; n < count; ++n) {
            blocks.insert(block.physical_block + n);
            if (blocks.size() > MaxNativeHardLinkPreimageBlocks) return false;
        }
        return true;
    };
    // Future descriptor destinations must be restored too, otherwise the
    // canonical loader still selects the newly published checkpoint.
    for (const auto& guard : plan.guard_blocks) if (!add(guard)) return fail();
    for (const auto& write : plan.before_superblock_writes) if (!add(write)) return fail();
    if (!add(plan.superblock_write) || !blocks.contains(0)) return fail();
    proof.preimages.clear(); proof.preimages.reserve(blocks.size());
    for (const auto block : blocks) {
        std::vector<std::byte> bytes;
        if (!source.Read(block * 4096, 4096, bytes) || bytes.size() != 4096) return fail();
        NativeHardLinkPreimage preimage; preimage.physical_block = block;
        std::copy(bytes.begin(), bytes.end(), preimage.bytes.begin()); proof.preimages.push_back(std::move(preimage));
    }
    return true;
}
bool VerifyPhysicalEvidence(const BlockDevice& device, const NativeHardLinkProof& proof,
    const AppleCheckpointPublicationPlan& plan, bool published, std::string& error)
{
    std::map<std::uint64_t, std::array<std::byte, 4096>> postimages;
    const auto add = [&](const auto& write) {
        if (write.bytes.empty() || write.bytes.size() % 4096 || write.physical_block >= proof.block_count ||
            write.bytes.size() / 4096 > proof.block_count - write.physical_block) return false;
        for (std::size_t n = 0; n < write.bytes.size() / 4096; ++n) {
            std::array<std::byte, 4096> bytes;
            std::copy_n(write.bytes.begin() + static_cast<std::ptrdiff_t>(n * 4096), 4096, bytes.begin());
            if (!postimages.emplace(write.physical_block + n, std::move(bytes)).second ||
                postimages.size() > MaxNativeHardLinkPreimageBlocks) return false;
        }
        return true;
    };
    for (const auto& write : plan.before_superblock_writes) if (!add(write)) { error = "HardLinkPostimageCensusInvalid"; return false; }
    if (!add(plan.superblock_write)) { error = "HardLinkPostimageCensusInvalid"; return false; }
    for (const auto& preimage : proof.preimages) {
        std::vector<std::byte> actual;
        if (!device.ReadForVerification(preimage.physical_block * 4096, 4096, actual) || actual.size() != 4096) {
            error = "HardLinkPhysicalEvidenceUnreadable"; return false;
        }
        const auto post = postimages.find(preimage.physical_block);
        const bool old = std::equal(actual.begin(), actual.end(), preimage.bytes.begin());
        const bool next = post != postimages.end() && std::equal(actual.begin(), actual.end(), post->second.begin());
        if (post == postimages.end() ? !old : published ? !next : !old && !next) {
            error = "HardLinkPhysicalEvidenceChanged"; return false;
        }
        if (post != postimages.end()) postimages.erase(post);
    }
    if (!postimages.empty()) { error = "HardLinkPostimageCoverageMissing"; return false; }
    return true;
}
std::wstring CanonicalIdentity(const catalog::AppleCheckpointView& checkpoint,std::uint64_t oid)
{
    const auto& uuid=checkpoint.container.superblock.uuid_hex;
    return L"apfs-vol:"+std::wstring(uuid.begin(),uuid.end())+L":"+std::to_wstring(oid);
}
bool Text(std::string_view text,std::wstring& out)
{
    out.clear();if(text.empty()||text.size()>4096||text.find('\0')!=std::string_view::npos)return false;
    const auto count=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),nullptr,0);
    if(count<=0)return false;out.resize(count);
    return MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),out.data(),count)==count;
}
std::uint64_t Resolve(const std::vector<catalog::BtreeRecord>& records,const ApfsNamePolicy& policy,
    const std::wstring& path)
{
    if(path.empty()||path.front()!=L'\\')return 0;
    std::uint64_t parent=2;std::size_t at=1;
    for(unsigned depth=0;at<path.size() && depth<128;++depth)
    {
        auto end=path.find(L'\\',at);if(end==std::wstring::npos)end=path.size();
        const auto key=ApfsNameCodec::CanonicalWindowsComponentKey(std::wstring_view(path).substr(at,end-at),policy);
        if(!key.ok())return 0;
        std::uint64_t found=0;
        for(const auto& record:records)
        {
            const auto header=catalog::ReadU64LE(record.key,0).value_or(0);
            if((header>>60)!=9 || (header&0x0fffffffffffffffULL)!=parent)continue;
            AppleDirectoryRecord d;std::string error;
            if(!ApfsExtendedRecordCodec::DecodeDirectory(record,policy,d,error))return 0;
            const auto name=ApfsNameCodec::Decode(std::as_bytes(std::span(d.name_utf8)),policy);
            if(!name.ok())return 0;
            const auto candidate=ApfsNameCodec::CanonicalWindowsComponentKey(name.value->windows_display,policy);
            if(!candidate.ok())return 0;
            if(*candidate.value==*key.value){if(found)return 0;found=d.file_id;}
        }
        if(!found)return 0;parent=found;at=end+1;
    }
    return at>=path.size()?parent:0;
}
bool ImageMatches(const BlockDevice& device,const NativeHardLinkProof& p)
{
    BlockDevice::StableImageIdentity image;
    return device.IsRegularFile() && device.QueryHeldImageIdentity(image) &&
        device.BaseOffsetBytes()==p.store_offset && image.volume_serial==p.image_volume_serial &&
        image.file_id==p.image_file_id && image.size_bytes==p.image_size && image.creation_time==p.image_creation_time;
}
bool ReadRecords(const catalog::RandomAccessSource& source,const catalog::AppleCheckpointView& checkpoint,
    std::uint64_t oid,std::vector<catalog::BtreeRecord>& filesystem,std::vector<catalog::BtreeRecord>& refs,
    std::vector<ApplePhysicalExtentRecord>& payload,std::string& error)
{
    filesystem.clear();refs.clear();payload.clear();
    if(checkpoint.volumes.size()!=1 || checkpoint.volumes.front().superblock.object_id!=oid ||
        checkpoint.container.superblock.block_size!=4096)
    {error="HardLinkSoleVolumeGeometryRequired";return false;}
    const auto& v=checkpoint.volumes.front();
    if(!v.extentref_tree || v.file_extent_tree || v.object_map.snapshot_tree_oid ||
        v.superblock.snap_meta_ext_oid)
    {error="HardLinkTreeProfileUnsupported";return false;}
    if(v.superblock.snap_meta_tree_oid)
    {
        AppleSnapshotRetentionView retention;
        if(!LoadAppleSnapshotRetention(source,checkpoint,retention,error))return false;
        if(!retention.identities.empty()){error="HardLinkSnapshotHistoryUnsupported";return false;}
    }
    if(!catalog::ReadAppleVolumeFileSystemRecords(source,checkpoint.container,v,filesystem,error))return false;
    catalog::BtreeReadPolicy policy;policy.enforce_object_identity=true;policy.root_object_id=v.extentref_tree->object_id;
    policy.storage_type=v.extentref_tree->type;policy.subtype=v.extentref_tree->subtype;
    const bool physical=(v.extentref_tree->type&catalog::kObjectStorageTypeMask)==catalog::kObjectPhysical;
    if(!catalog::ReadBtreeLeafRecords(source,4096,v.extentref_tree->physical_block,physical,
        physical?0:v.superblock.omap_oid,checkpoint.container.superblock.xid,policy,refs,error))return false;
    return ValidateApplePayloadExtentGraph(filesystem,refs,4096,checkpoint.container.superblock.block_count,payload,error) &&
        ValidateAppleCheckpointPayloadOwnership(source,checkpoint,payload,error);
}
bool PayloadHash(const BlockDevice& device,const std::vector<ApplePhysicalExtentRecord>& payload,
    std::uint64_t version,NativeHardLinkDigest& out)
{
    return version==3?NativeHardLinkExtentHash(payload,out):
        version==2&&NativeHardLinkLegacyPayloadHash(device,payload,out);
}
bool Build(const BlockDevice& device,const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,const std::wstring& from,const std::wstring& target,
    NativeHardLinkProof& p,AppleVolumeTransactionPlan& transaction,bool recovering,std::string& error)
{
    const auto fail=[&](const char* reason){if(error.empty())error=reason;return false;};
    if(checkpoint.volumes.size()!=1)return fail("HardLinkSoleVolumeRequired");
    const auto& volume=checkpoint.volumes.front();
    const auto policy=ApfsNamePolicy::FromIncompatibleFeatures(volume.superblock.incompatible_features);
    std::vector<catalog::BtreeRecord> filesystem,refs;std::vector<ApplePhysicalExtentRecord> payload;
    if(!ReadRecords(source,checkpoint,p.volume_oid,filesystem,refs,payload,error))return fail("HardLinkSourceRecordsUnproven");
    const auto slash=target.find_last_of(L'\\');
    if(slash==std::wstring::npos || slash+1==target.size())return fail("HardLinkTargetPathInvalid");
    const auto parent=Resolve(filesystem,policy,slash?target.substr(0,slash):L"\\");
    const auto name=ApfsNameCodec::EncodeWindowsName(std::wstring_view(target).substr(slash+1));
    if(!parent||!name.ok()||Resolve(filesystem,policy,from)!=p.source_inode||Resolve(filesystem,policy,target))
        return fail("HardLinkNamespacePreimageMismatch");
    NativeHardLinkProof observed=p;
    observed.container_uuid=checkpoint.container.superblock.uuid_hex;observed.volume_uuid=volume.superblock.uuid_hex;
    observed.checkpoint=checkpoint.container.superblock.xid;observed.source_generation=volume.superblock.xid;
    observed.destination_parent=parent;observed.destination_name=*name.value;
    observed.incompatible_features=volume.superblock.incompatible_features;observed.block_size=4096;
    observed.block_count=checkpoint.container.superblock.block_count;
    if(!recovering)observed.first_sibling=volume.superblock.next_object_id;
    if(observed.first_sibling<volume.superblock.next_object_id)return fail("HardLinkSiblingCounterInvalid");
    observed.next_object_id=observed.first_sibling+1;
    NativeHardLinkPlan plan;
    if(!PrepareNativeHardLinkPlan(filesystem,policy,{p.source_inode,parent,observed.first_sibling,p.timestamp_ns,*name.value},plan,error) ||
        !NativeHardLinkRecordsHash(plan.before,observed.before_sha)||!NativeHardLinkRecordsHash(plan.after,observed.after_sha)||
        !NativeHardLinkRecordsHash(refs,observed.references_sha)||!PayloadHash(device,payload,p.version,observed.payload_sha))
        return fail("HardLinkPreparedProofUnavailable");
    if(p.version==2&&(plan.source_links!=1||plan.next_object_id!=observed.first_sibling+2))
        return fail("HardLinkLegacySourceProfileUnsupported");
    observed.original_parent=plan.primary_parent;observed.original_name=plan.primary_name;
    AppleVolumeTransactionRequest request;request.volume_object_id=p.volume_oid;request.required_checkpoint_xids={observed.checkpoint};
    request.filesystem_records=plan.after;request.preserve_source_metadata=true;
    if(!PlanAppleVolumeTransaction(source,checkpoint,request,transaction,error) || !transaction.payload_blocks.empty() ||
        !NativeHardLinkWritesExcludePayload(transaction.commit.publication,payload,observed.block_count) ||
        !NativeHardLinkPublicationHash(transaction.commit.publication,observed.publication_sha))
        return fail("HardLinkPublicationProofUnavailable");
    // Filesystem child nodes consume volume IDs in addition to the two siblings.
    // Bind the serialized APSB counter rather than guessing its final value.
    bool found_apsb=false;
    for(const auto& write:transaction.commit.publication.before_superblock_writes)
    {
        const auto apsb=catalog::ParseApsb(write.bytes);
        if(!apsb || apsb->object_id!=p.volume_oid)continue;
        if(found_apsb || apsb->uuid_hex!=observed.volume_uuid ||
            apsb->xid!=checkpoint.container.superblock.next_xid ||
            apsb->next_object_id<plan.next_object_id ||
            apsb->next_object_id>=0x0fffffffffffffffULL)
        {error="HardLinkPlannedObjectCounterInvalid";return false;}
        found_apsb=true;observed.next_object_id=apsb->next_object_id;
    }
    if(!found_apsb){error="HardLinkPlannedVolumeMissing";return false;}
    NativeHardLinkDigest normalized;
    auto normalized_records=transaction.filesystem_records;
    const auto order=policy.UsesHashedDirectoryKeys()?AppleBtreeKeyOrder::FileSystemHashedDirectory:
        AppleBtreeKeyOrder::FileSystemCaseSensitive;
    if(!SortAppleBtreeRecords(normalized_records,order,error)||
        !NativeHardLinkRecordsHash(normalized_records,normalized)||normalized!=observed.after_sha)
        return fail("HardLinkNormalizedRecordsChanged");
    if (!CapturePreimages(source,transaction.commit.publication,observed,error)) return false;
    if(recovering && observed!=p){error="HardLinkOriginalPreimageMismatch";return false;}
    p=std::move(observed);return true;
}
}

MetadataStore::HardLinkAcceptance MetadataStore::WithNativeHardLinkSession(
    const NativeHardLinkOpenEntry& source, const NativeHardLinkOpenEntry& destination,
    const std::wstring& leaf, std::uint64_t timestamp_ns,
    const HardLinkSessionConsumer& consumer, std::string& error)
{
    error.clear();
    const auto refuse=[&](const char* reason){error=reason;return HardLinkAcceptance::Refused;};
    if(!consumer||!timestamp_ns||leaf.empty()||leaf.size()>255||leaf==L"."||leaf==L".."||
        leaf.find_first_of(L"\\/:")!=std::wstring::npos||leaf.find(L'\0')!=std::wstring::npos||
        immutable_snapshot_view_||context_.shared_container_session||context_.allow_native_snapshot_runtime||
        !CanUseAppleTransactionWriter()||recovery_required_||!pending_mutations_.empty()||
        !device_||!device_->IsRegularFile()||!authoritative_apple_checkpoint_view_||
        committed_directory_links_.size()>16384)return refuse("HardLinkSessionOwnerOrLeafInvalid");
    const auto observation=device_->CaptureExclusiveWriteSourceObservation();
    if(!observation)return refuse("HardLinkSessionExclusiveOwnerRequired");
    const auto epoch=StateEpoch();
    const auto resolve=[&](const NativeHardLinkOpenEntry& entry,bool directory,std::wstring& path){
        const auto inode=committed_inodes_.find(entry.object_id);
        if(inode==committed_inodes_.end()||!entry.generation||inode->second.xid!=entry.generation||
            (directory?inode->second.node_type!=NodeType::Directory:inode->second.node_type!=NodeType::RegularFile))return false;
        if(entry.object_id==RootDirectoryObjectId()){
            if(!directory||entry.parent_object_id!=inode->second.parent_object_id||entry.sibling_id||
                entry.name_utf8!=inode->second.name_utf8)return false;
            path=L"\\";return true;
        }
        bool matched=false;
        for(const auto& link:committed_directory_links_){
            if(link.child_object_id!=entry.object_id||link.parent_object_id!=entry.parent_object_id||
                link.sibling_id!=entry.sibling_id||link.entry_name_utf8!=entry.name_utf8)continue;
            const auto parent=committed_inodes_.find(link.parent_object_id);
            if(matched||parent==committed_inodes_.end()||!parent->second.is_directory)return false;
            path=parent->second.full_path==L"\\"?L"\\"+link.entry_name:parent->second.full_path+L"\\"+link.entry_name;
            const auto selected=LookupCommittedInodeByPath(path);
            if(!selected||selected->object_id!=entry.object_id||selected->xid!=entry.generation)return false;
            matched=true;
        }
        return matched;
    };
    std::wstring from,parent;
    if(!resolve(source,false,from)||!resolve(destination,true,parent)||StateEpoch()!=epoch||
        !device_->IsExclusiveWriteSourceObservationCurrent(*observation))return refuse("HardLinkOpenEntryStaleOrForeign");
    NativeHardLinkSession session(this,epoch,*observation,from,parent==L"\\"?L"\\"+leaf:parent+L"\\"+leaf);
    session.timestamp_ns_=timestamp_ns;
    OnExit invalidate{[&](){session.active_=false;}};
    try{
        const auto result=consumer(session,error);
        if(result==HardLinkAcceptance::Accepted&&!session.accepted_)return refuse("HardLinkSessionNotAccepted");
        if(session.ambiguous_||(session.accepted_&&result==HardLinkAcceptance::Refused)){
            MarkRecoveryRequired(L"NativeHardLinkSessionOutcomeAmbiguous");error="HardLinkSessionOutcomeAmbiguous";
            return HardLinkAcceptance::RecoveryRequired;
        }
        return result;
    }catch(...){
        if(session.consumed_){MarkRecoveryRequired(L"NativeHardLinkSessionCallbackFailed");error="HardLinkSessionCallbackAfterConsumption";
            return HardLinkAcceptance::RecoveryRequired;}
        return refuse("HardLinkSessionCallbackFailed");
    }
}

MetadataStore::HardLinkAcceptance MetadataStore::AcceptNativeHardLink(TransactionManager& journal,
    const NativeHardLinkSession& session,HardLinkReceipt& receipt,std::string& error)
{
    receipt={};error.clear();
    if(session.owner_!=this||!session.active_||session.consumed_||StateEpoch()!=session.epoch_||
        !device_||!device_->IsExclusiveWriteSourceObservationCurrent(session.observation_)){
        error="HardLinkSessionStaleForeignOrConsumed";return HardLinkAcceptance::Refused;
    }
    session.consumed_=true;
    const auto result=AcceptNativeHardLink(journal,session.source_,session.target_,session.timestamp_ns_,receipt,error);
    session.accepted_=result==HardLinkAcceptance::Accepted;
    session.ambiguous_=result==HardLinkAcceptance::RecoveryRequired;
    return result;
}

MetadataStore::HardLinkAcceptance MetadataStore::AcceptNativeHardLink(TransactionManager& journal,
    const std::wstring& source_path,const std::wstring& target_path,std::uint64_t timestamp_ns,
    HardLinkReceipt& receipt,std::string& error)
{
    receipt={};error.clear();
    const auto refuse=[&](const char* reason){if(error.empty())error=reason;return HardLinkAcceptance::Refused;};
    if(!RegisteredKind<TransactionManager,WriteAheadLog>())return refuse("HardLinkOriginalKindNotRegistered");
    if(immutable_snapshot_view_||context_.shared_container_session||context_.allow_native_snapshot_runtime||
        !CanUseAppleTransactionWriter()||recovery_required_||!pending_mutations_.empty()||!device_->IsRegularFile()||
        !authoritative_apple_checkpoint_view_||source_path!=NormalizePath(source_path)||target_path!=NormalizePath(target_path)||
        source_path==target_path||!timestamp_ns)return refuse("HardLinkOwnerNotAdmitted");
    const auto observation=device_->CaptureExclusiveWriteSourceObservation();
    if(!observation)return refuse("HardLinkExclusiveImageRequired");
    std::vector<TransactionManager::AcceptedTransaction> pending;
    const auto marks=journal.Watermarks();
    if(journal.CurrentState()!=TransactionManager::State::Idle||!journal.RecoveryStateValid()||
        !journal.ObservedJournalWriterLeaseGeneration()||marks.accepted_sequence!=marks.cleanup_sequence||
        !journal.LoadAcceptedTransactionsSinceCleanup(pending,&error)||!pending.empty())return refuse("HardLinkOriginalNotClean");
    const auto epoch=StateEpoch();Source raw(*device_);
    const auto budget=std::make_shared<catalog::ApfsReadBudget>(65536,256ULL<<20,131072,128ULL<<20);
    catalog::BudgetedRandomAccessSource input(raw,budget);
    const auto checkpoint=catalog::LoadAppleCheckpointView(input,0,input.SizeBytes(),error);
    if(!checkpoint||checkpoint->container.superblock_bytes!=authoritative_apple_checkpoint_view_->container.superblock_bytes||
        checkpoint->container.superblock.xid!=checkpoint_xid_||
        journal.EnrolledCanonicalJournalIdentity()!=CanonicalIdentity(*checkpoint,context_.volume_object_id))
        return refuse("HardLinkCanonicalOwnerMismatch");
    const auto inode=LookupCommittedInodeByPathView(source_path);
    BlockDevice::StableImageIdentity image;
    if(!inode||inode->node_type!=NodeType::RegularFile||!device_->QueryHeldImageIdentity(image))return refuse("HardLinkSourceMissing");
    NativeHardLinkProof proof;proof.volume_oid=context_.volume_object_id;proof.source_inode=inode->object_id;
    proof.timestamp_ns=timestamp_ns;proof.store_offset=device_->BaseOffsetBytes();proof.image_volume_serial=image.volume_serial;
    proof.image_file_id=image.file_id;proof.image_size=image.size_bytes;proof.image_creation_time=image.creation_time;
    AppleVolumeTransactionPlan plan;
    if(!Build(*device_,input,*checkpoint,source_path,target_path,proof,plan,false,error))return refuse("HardLinkPlanRefused");
    auto payload=EncodeNativeHardLink(proof);if(payload.empty())return refuse("HardLinkProofInvalid");
    TransactionManager::MutationIntent intent;intent.kind=static_cast<TransactionManager::MutationKind>(NativeHardLinkOperationKind);
    intent.path=target_path;intent.secondary_path=source_path;intent.object_id=proof.source_inode;intent.generation=proof.checkpoint;
    intent.length=intent.payload_length=payload.size();intent.inline_payload=std::move(payload);
    if(!NativeHardLinkHash(intent.inline_payload,intent.payload_checksum)||
        !VerifyPhysicalEvidence(*device_,proof,plan.commit.publication,false,error)||
        !device_->IsExclusiveWriteSourceObservationCurrent(*observation)||StateEpoch()!=epoch)
        return refuse("HardLinkPreacceptanceChanged");
    if(journal.ProtectedSourceBinding() && !journal.ProtectedMutationCapacityAvailable(intent,error))
        return refuse("HardLinkProtectedCapacityRefused");
    const auto uncertain=[&](const char* reason){error=reason;MarkRecoveryRequired(L"NativeHardLinkAcceptanceRequiresRecovery");return HardLinkAcceptance::RecoveryRequired;};
    bool complete=false;
    OnExit poison{[&](){if(!complete)MarkRecoveryRequired(L"NativeHardLinkAcceptanceRequiresRecovery");}};
    if(!journal.Begin())return uncertain("HardLinkBeginFailed");
    const auto tx=journal.CurrentTransactionId();
    if(!AllowCommitStage("after-native-hardlink-begin"))return uncertain("HardLinkAcceptanceAmbiguous");
    if(!journal.RetainAcceptedSequenceProof(tx)||!journal.CanAddInlinePayload(intent.inline_payload.size())||
        !journal.RecordMutation(intent)||!AllowCommitStage("after-native-hardlink-record")||!journal.Accept(proof.checkpoint))
        return uncertain("HardLinkAcceptanceAmbiguous");
    receipt={tx,journal.Watermarks().accepted_sequence,proof.checkpoint,proof.source_inode};
    complete=true;
    return HardLinkAcceptance::Accepted;
}

MetadataStore::HardLinkPublication MetadataStore::PublishOrRecoverNativeHardLink(TransactionManager& journal,std::string& error)
{
    return PublishOrRecoverNativeHardLink(journal,{},error);
}

MetadataStore::HardLinkPublication MetadataStore::PublishOrRecoverNativeHardLink(TransactionManager& journal,
    const HardLinkPostpublicationHook& publish_namespace,std::string& error)
{
    error.clear();
    const auto refuse=[&](const char* reason){if(error.empty())error=reason;return HardLinkPublication::Refused;};
    if(!RegisteredKind<TransactionManager,WriteAheadLog>())return refuse("HardLinkOriginalKindNotRegistered");
    if(immutable_snapshot_view_||context_.shared_container_session||context_.allow_native_snapshot_runtime||
        !CanUseAppleTransactionWriter()||recovery_required_||!pending_mutations_.empty()||!device_->IsRegularFile()||
        !authoritative_apple_checkpoint_view_||!device_->CaptureExclusiveWriteSourceObservation())return refuse("HardLinkRecoveryOwnerNotAdmitted");
    std::vector<TransactionManager::AcceptedTransaction> batches;
    if(journal.CurrentState()!=TransactionManager::State::Idle||!journal.RecoveryStateValid()||
        !journal.ObservedJournalWriterLeaseGeneration()||!journal.LoadAcceptedTransactionsSinceCleanup(batches,&error)||
        batches.size()!=1||batches.front().mutations.size()!=1)return refuse("HardLinkOriginalBoundaryUnproven");
    const auto& accepted=batches.front();const auto& record=accepted.mutations.front();NativeHardLinkProof proof;
    std::wstring original_identity;
    if(!NativeHardLinkWalIsConsistent(record)||!DecodeNativeHardLink(record.inline_payload,proof)||
        accepted.preimage_checkpoint_xid!=proof.checkpoint||proof.volume_oid!=context_.volume_object_id||
        !Text(record.volume_identity,original_identity)||original_identity!=journal.ConfiguredVolumeIdentity()||
        accepted.transaction_id!=record.transaction_id||!accepted.accepted_sequence||
        record.sequence>=accepted.accepted_sequence||!ImageMatches(*device_,proof))return refuse("HardLinkOriginalBindingMismatch");
    std::wstring from,target;
    if(!Text(record.secondary_path_utf8,from)||!Text(record.path_utf8,target)||from!=NormalizePath(from)||target!=NormalizePath(target))
        return refuse("HardLinkOriginalPathInvalid");
    Source raw(*device_);const auto budget=std::make_shared<catalog::ApfsReadBudget>(65536,256ULL<<20,131072,128ULL<<20);
    catalog::BudgetedRandomAccessSource input(raw,budget);
    const auto current=catalog::LoadAppleCheckpointView(input,0,input.SizeBytes(),error);
    if(!current||current->container.superblock_bytes!=authoritative_apple_checkpoint_view_->container.superblock_bytes||
        current->container.superblock.uuid_hex!=proof.container_uuid||
        journal.EnrolledCanonicalJournalIdentity()!=CanonicalIdentity(*current,proof.volume_oid))
        return refuse("HardLinkRecoveryEndpointMismatch");
    PreimageSource overlay(raw,proof);
    catalog::BudgetedRandomAccessSource historical(overlay,budget);
    const auto before=catalog::LoadAppleCheckpointView(historical,0,historical.SizeBytes(),error);
    if(!before || before->container.superblock.xid!=proof.checkpoint ||
        before->container.superblock.uuid_hex!=proof.container_uuid)
        return refuse("HardLinkOriginalPreimageUnavailable");
    AppleVolumeTransactionPlan transaction;
    if(!Build(*device_,historical,*before,from,target,proof,transaction,true,error))return refuse("HardLinkRecoveryPlanMismatch");
    const auto& publication=transaction.commit.publication;
    std::uint32_t expected_links=0;
    for(const auto& row:transaction.filesystem_records)
        if(catalog::ReadU64LE(row.key,0).value_or(0)==((3ULL<<60)|proof.source_inode)) {
            AppleInodeRecord inode;
            if(expected_links||!ApfsExtendedRecordCodec::DecodeInode(row,inode,error)||inode.children_or_links<2)
                return refuse("HardLinkPlannedLinkCountInvalid");
            expected_links=static_cast<std::uint32_t>(inode.children_or_links);
        }
    if(!expected_links)return refuse("HardLinkPlannedLinkCountMissing");
    const auto xid=publication.transaction_xid;
    if(current->container.superblock.xid!=proof.checkpoint && current->container.superblock.xid!=xid)
        return refuse("HardLinkRecoveryEndpointMismatch");
    const bool published=current->container.superblock.xid==xid;
    if(!VerifyPhysicalEvidence(*device_,proof,publication,published,error))return refuse("HardLinkPhysicalEvidenceChanged");
    const auto verify=[&](){
        const auto checkpoint=catalog::LoadAppleCheckpointView(input,0,input.SizeBytes(),error);
        if(!checkpoint||checkpoint->container.superblock.xid!=xid||checkpoint->volumes.size()!=1||
            checkpoint->container.superblock.uuid_hex!=proof.container_uuid||checkpoint->volumes.front().superblock.uuid_hex!=proof.volume_uuid||
            checkpoint->volumes.front().superblock.next_object_id!=proof.next_object_id||
            checkpoint->container.superblock_physical_block!=publication.superblock_write.physical_block||
            checkpoint->container.superblock_bytes!=publication.superblock_write.bytes||
            !VerifyPhysicalEvidence(*device_,proof,publication,true,error))return false;
        std::vector<catalog::BtreeRecord> fs,refs;std::vector<ApplePhysicalExtentRecord> payload;NativeHardLinkDigest a,b,c;
        return ReadRecords(input,*checkpoint,proof.volume_oid,fs,refs,payload,error)&&
            NativeHardLinkRecordsHash(fs,a)&&a==proof.after_sha&&NativeHardLinkRecordsHash(refs,b)&&b==proof.references_sha&&
            PayloadHash(*device_,payload,proof.version,c)&&c==proof.payload_sha&&
            NativeHardLinkWritesExcludePayload(publication,payload,proof.block_count);
    };
    if(published&&!verify())return refuse("HardLinkPublishedStateMismatch");
    const auto failed=[&](const char* reason){if(error.empty())error=reason;MarkRecoveryRequired(L"NativeHardLinkPublicationRequiresRecovery");return HardLinkPublication::RecoveryRequired;};
    bool complete=false;
    OnExit poison{[&](){if(!complete)MarkRecoveryRequired(L"NativeHardLinkPublicationRequiresRecovery");}};
    if(!journal.FlushAcceptedEvidenceDurability(accepted.accepted_sequence))return failed("HardLinkOriginalBarrierFailed");
    if(published)
    {
        if(!device_->Flush()||!verify())return failed("HardLinkPublishedFlushFailed");
    }
    else
    {
        if(!ExecuteAppleCheckpointPublication(*device_,transaction.commit.publication,error,
            [&](std::string_view stage){return AllowCommitStage(stage);})||!verify())return failed("HardLinkPublicationFailed");
    }
    if(!PrepareNativeWritePath())return failed("HardLinkCommittedReloadFailed");
    const auto original=LookupCommittedInodeByPath(from),linked=LookupCommittedInodeByPath(target);
    if(!original||!linked||original->object_id!=proof.source_inode||linked->object_id!=proof.source_inode||
        original->link_count!=expected_links||linked->link_count!=expected_links)return failed("HardLinkCommittedNamespaceMismatch");
    const auto epoch=StateEpoch();
    if(publish_namespace&&(!publish_namespace(*this,error)||StateEpoch()!=epoch))
        return failed("HardLinkHostNamespacePublicationFailed");
    if(!journal.MarkApfsDurableThrough(accepted.accepted_sequence)||!journal.MarkCleanedThrough(accepted.accepted_sequence)||
        !journal.FlushRetainedOriginalEvidenceDurability())
        return failed("HardLinkWatermarkFailed");
    journal.ReleaseAcceptedSequenceProof(accepted.transaction_id);
    complete=true;
    return published?HardLinkPublication::AlreadyPublished:HardLinkPublication::Published;
}
}
