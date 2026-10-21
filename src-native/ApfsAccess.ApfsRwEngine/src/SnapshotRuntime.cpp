#include "SnapshotRuntime.h"
#include "SnapshotRuntimeSource.h"
#include "SnapshotPreimageHash.h"
#include <bcrypt.h>
#include <set>
#include <tuple>

namespace apfsaccess::rw {
bool snapshot_detail::HashPreimageBlocks(const catalog::RandomAccessSource& source,
    std::uint32_t block_size, std::uint64_t block_count,
    const std::set<std::uint64_t>& blocks, std::array<std::uint8_t,32>& hash) {
    hash={};
    constexpr std::size_t scratch_limit=65536;
    if(!block_size||block_size>scratch_limit||!block_count||blocks.size()>65536||
        block_count>UINT64_MAX/block_size||source.SizeBytes()!=block_count*block_size||
        (!blocks.empty()&&*blocks.rbegin()>=block_count))return false;
    const auto budget=source.ReadBudget();
    if(budget&&(budget->Failed()||!budget->Materialize(1,blocks.size()*40+scratch_limit)))return false;
    struct Algorithm {
        BCRYPT_ALG_HANDLE handle=nullptr;
        ~Algorithm(){if(handle)BCryptCloseAlgorithmProvider(handle,0);}
    } algorithm;
    if(BCryptOpenAlgorithmProvider(&algorithm.handle,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0)return false;
    const auto digest=[&](std::span<const std::byte> bytes,std::array<std::uint8_t,32>& out){
        return bytes.size()<=ULONG_MAX&&BCryptHash(algorithm.handle,nullptr,0,
            reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())),
            static_cast<ULONG>(bytes.size()),out.data(),static_cast<ULONG>(out.size()))>=0;
    };
    std::vector<std::byte> canonical,actual;
    canonical.reserve(blocks.size()*40);actual.reserve(scratch_limit);
    for(auto begin=blocks.begin();begin!=blocks.end();) {
        auto end=std::next(begin);
        std::size_t count=1;
        while(end!=blocks.end()&&*end==*begin+count&&count<scratch_limit/block_size){++end;++count;}
        const auto size=count*block_size;
        if(!source.Read(*begin*block_size,size,actual)||actual.size()!=size)return false;
        std::size_t index=0;
        for(auto block=begin;block!=end;++block,++index){
            std::array<std::uint8_t,32> observed{};
            if(!digest(std::span<const std::byte>(actual).subspan(index*block_size,block_size),observed))return false;
            snapshot_wire::Put(canonical,*block);
            for(auto byte:observed)canonical.push_back(std::byte(byte));
        }
        begin=end;
    }
    std::array<std::uint8_t,32> observed{};
    if((budget&&budget->Failed())||source.SizeBytes()!=block_count*block_size||!digest(canonical,observed))return false;
    hash=observed;return true;
}

struct RawSnapshotRuntimeJournalProof {
    std::uint64_t oid = 0;
    TransactionManager::DurabilityWatermarks marks;
    std::shared_ptr<const std::vector<WriteAheadLog::Record>> records;
    std::uint64_t store_epoch = 0;
};
struct RawSnapshotRuntimeAuthority::State {
    struct Peer {
        RawSnapshotRuntimePeerOwner original;
        NativeRawSnapshotPeer identity;
        std::string canonical;
        std::uint64_t writer_generation = 0;
    };
    const catalog::ContainerMountCoordinator* owner = nullptr;
    std::weak_ptr<const std::uint8_t> owner_lifetime;
    const BlockDevice* device = nullptr;
    BlockDevice::RawSnapshotLease lease;
    RawHardwareQualification qualification;
    RawSnapshotBinding binding;
    std::string container_uuid;
    std::vector<Peer> peers;
    std::optional<TransactionManager::AcceptedTransaction> restart_receipt;
    std::vector<RawSnapshotRuntimeJournalProof> restart_journals;
    std::vector<catalog::VolumeCheckpointPins> restart_census;
};

struct RawSnapshotRuntimeRecoveryToken::State {
    std::shared_ptr<const RawSnapshotRuntimeAuthority> authority;
    NativeSnapshotIntent intent;
    MetadataStore::MutationRequest request;
    TransactionManager::AcceptedTransaction accepted;
    std::vector<RawSnapshotRuntimeJournalProof> journals;
    bool acceptance_started = false;
    bool durability_written = false;
    bool cleanup_written = false;
    std::uint64_t selected_epoch = 0;
    bool publication_verified = false;
};
bool RawSnapshotRuntimeRecoveryToken::AcceptanceStarted() const noexcept { return state_->acceptance_started; }
void RawSnapshotRuntimeRecoveryToken::CaptureSelectedState(const MetadataStore& store) const noexcept {
    state_->selected_epoch=store.StateEpoch();
}
bool RawSnapshotRuntimeRecoveryToken::CaptureVerifiedPublication(const MetadataStore& store) const noexcept {
    if(!state_->acceptance_started||!state_->accepted.accepted_sequence||
        state_->accepted.mutations.size()!=1||state_->journals.empty()||
        state_->accepted.mutations[0].inline_payload!=state_->request.inline_payload||
        store.CheckpointXid()!=state_->intent.scope.checkpoint_xid+1||store.IsRecoveryRequired())return false;
    CaptureSelectedState(store);state_->publication_verified=true;return true;
}

// This definition is private to the runtime TU. Neither an arbitrary source
// nor serialized receipt fields can mint a source capability or store grant.
struct RawSnapshotRuntimeAccess {
    using Authority = RawSnapshotRuntimeAuthority;
    using Owner = catalog::ContainerMountCoordinator;
    using State = Authority::State;
    using Recovery = RawSnapshotRuntimeRecoveryToken;
    struct SourceCapability {
        const catalog::RandomAccessSource* source;
        const MetadataStore* store;
        std::shared_ptr<const Authority> authority;
        std::shared_ptr<const Recovery> recovery;
    private:
        friend struct RawSnapshotRuntimeAccess;
        SourceCapability(const catalog::RandomAccessSource& s, const MetadataStore& m,
            std::shared_ptr<const Authority> a,std::shared_ptr<const Recovery> r={}) :
            source(&s), store(&m), authority(std::move(a)),recovery(std::move(r)) {}
    };
    static bool Fail(std::string& e, const char* why) { e=why;return false; }
    static const State::Peer* Peer(const Authority& a, std::uint64_t oid) {
        const auto& peers=a.state_->peers;
        const auto it=std::find_if(peers.begin(),peers.end(),[&](const auto& p){return p.identity.volume_oid==oid;});
        return it==peers.end()?nullptr:&*it;
    }
    static bool StoreClean(const MetadataStore& s) {
        return !s.PendingMutationCount()&&!s.HasUncommittedAllocatorState()&&!s.PendingAllocationCount()&&
            !s.PendingDeallocationCount()&&!s.PendingObjectMapUpdateCount()&&!s.PendingBtreeRecordCount()&&!s.PendingPayloadByteEstimate();
    }
    static bool JournalClean(const TransactionManager& j) {
        const auto m=j.Watermarks();
        return j.CurrentState()==TransactionManager::State::Idle&&!j.PendingMutationCount()&&j.RecoveryStateValid()&&
            !j.HasUnappliedAcceptedWork()&&m.accepted_sequence==m.apfs_durable_sequence&&m.accepted_sequence==m.cleanup_sequence;
    }
    static bool Owned(const State::Peer& p, std::string& e) {
        const auto& j=*p.original.journal;
        const std::wstring canonical(p.canonical.begin(),p.canonical.end());
        if(TransactionManager::WideToUtf8(j.ConfiguredVolumeIdentity())!=p.identity.journal_identity||
            !(j.OwnsJournalForMaintenance(p.original.journal_path,canonical)||
              j.OwnsEnrolledCanonicalJournal(p.original.journal_path,canonical))||
            !p.writer_generation||j.ObservedJournalWriterLeaseGeneration()!=p.writer_generation||
            j.ObservedJournalAppendLeaseGeneration()!=p.writer_generation)
            return Fail(e,"SnapshotRuntimeRawOriginalJournalChanged");
        return true;
    }
    static NativeRawSnapshotReceipt Receipt(const Authority& a, std::uint64_t oid) {
        NativeRawSnapshotReceipt r;r.binding=a.state_->binding;
        for(const auto& p:a.state_->peers){r.peers.push_back(p.identity);if(p.identity.volume_oid==oid)r.selected_journal_identity=p.identity.journal_identity;}
        return r;
    }
    static bool Cohort(const Authority& a,const catalog::AppleCheckpointView& cp,std::string& e) {
        std::uint64_t bytes=0;
        if(cp.container.superblock.uuid_hex!=a.state_->container_uuid||
            !SnapshotRuntimeStoreSize(cp.container.superblock,bytes)||bytes!=a.state_->binding.media.limit_bytes||
            cp.volumes.size()!=a.state_->peers.size())return Fail(e,"SnapshotRuntimeRawCohortChanged");
        std::set<std::uint64_t> seen;
        for(const auto& v:cp.volumes){const auto* p=Peer(a,v.superblock.object_id);
            if(!p||!seen.insert(v.superblock.object_id).second||v.superblock.uuid_hex!=p->identity.volume_uuid_hex||
                !CheckAppleVolumeWriteFeatures(cp.container.superblock,v.superblock,e))return Fail(e,"SnapshotRuntimeRawCohortChanged");}
        return true;
    }
    static bool Verify(const std::shared_ptr<const Authority>& a,const MetadataStore& selected,
        const NativeSnapshotIntent& p,std::string& e,bool selected_debt=false) {
        if(!a||!p.raw_receipt||a->state_->owner_lifetime.expired()||a->state_->device!=&selected.Device()||
            p.scope.container_uuid_hex!=a->state_->container_uuid||*p.raw_receipt!=Receipt(*a,p.scope.volume_oid))
            return Fail(e,"SnapshotRuntimeRawReceiptNotAdmitted");
        const auto* peer=Peer(*a,p.scope.volume_oid);
        if(!peer||peer->original.store!=&selected||selected.raw_snapshot_runtime_authority_.lock()!=a)
            return Fail(e,"SnapshotRuntimeRawStoreNotEnrolled");
        const auto& d=selected.Device();RawSnapshotBinding current;
        if(d.IsRegularFile()||!d.IsRawWriterAccepted()||d.RawWriteLimitBytes()!=p.scope.store_size_bytes||
            !d.IsHeldRawSnapshotLeaseCurrent(a->state_->lease)||
            !d.QueryHeldRawSnapshotBinding(a->state_->lease,a->state_->qualification,current,e)||current!=a->state_->binding)
            return Fail(e,"SnapshotRuntimeRawSourceChanged");
        const auto* cp=selected.AuthoritativeAppleCheckpointView();
        if(!cp||!Cohort(*a,*cp,e))return false;
        for(const auto& original:a->state_->peers){const auto& s=*original.original.store;
            if(&s.Device()!=a->state_->device||s.raw_snapshot_runtime_authority_.lock()!=a||
                !s.Context().allow_native_snapshot_runtime||!s.Context().allow_raw_device_canonical_commit||
                s.Context().volume_object_id!=original.identity.volume_oid||
                s.Context().container_uuid_hex!=a->state_->container_uuid||
                s.Context().volume_uuid_hex!=original.identity.volume_uuid_hex||s.IsImmutableSnapshotView()||
                ((!selected_debt||&s!=&selected)&&(!s.IsNativeWriteReady()||s.IsRecoveryRequired()))||
                !Owned(original,e))return Fail(e,"SnapshotRuntimeRawPeerChanged");
            if(&s!=&selected&&(!StoreClean(s)||!JournalClean(*original.original.journal)))return Fail(e,"SnapshotRuntimeRawSiblingBusy");
        }
        return d.IsHeldRawSnapshotLeaseCurrent(a->state_->lease)||Fail(e,"SnapshotRuntimeRawSourceChanged");
    }
    static bool Preflight(const std::shared_ptr<const Authority>& a,Owner& o,std::uint64_t oid,std::string& e) {
        if(!a||a->state_->owner!=&o||a->state_->owner_lifetime.expired()||o.IsRecoveryRequired()||
            !o.CheckpointCensusRequired()||&o.Device()!=a->state_->device||o.ContainerUuidHex()!=a->state_->container_uuid||
            o.MountedVolumeCount()!=a->state_->peers.size())return Fail(e,"SnapshotRuntimeRawOwnerNotReady");
        auto census=o.CheckpointCensusSnapshot();
        if(census.size()!=a->state_->peers.size())return Fail(e,"SnapshotRuntimeRawCensusIncomplete");
        std::set<std::uint64_t> seen;
        for(const auto& entry:census){const auto* peer=Peer(*a,entry.volume_object_id);
            std::string canonical, recovery_identity;
            if(!peer||!seen.insert(entry.volume_object_id).second||
                o.FindSessionStore(entry.volume_object_id)!=peer->original.store||
                !o.SessionCanonicalJournalIdentity(entry.volume_object_id,canonical)||canonical!=peer->canonical||
                !o.SessionRecoveryIdentity(entry.volume_object_id,recovery_identity)||recovery_identity!=peer->identity.journal_identity||
                !Owned(*peer,e))return Fail(e,"SnapshotRuntimeRawCensusChanged");
            std::vector<std::uint64_t> expected;
            const auto& journal=*peer->original.journal;
            if(!JournalClean(journal)){
                if(entry.volume_object_id!=oid)return Fail(e,"SnapshotRuntimeRawSiblingBusy");
                TransactionManager::AcceptedTransaction tx;
                if(!LoadRawTransaction(*peer,journal.Watermarks().accepted_sequence,tx,e))return false;
                NativeSnapshotIntent accepted;
                if(!DecodeNativeSnapshotIntent(tx.mutations[0].inline_payload,accepted)||!accepted.raw_receipt||
                    *accepted.raw_receipt!=Receipt(*a,oid))return Fail(e,"SnapshotRuntimeRawCensusChanged");
                expected=accepted.pins;
            }
            if(entry.required_checkpoint_xids!=expected||entry.unapplied_accepted_work!=journal.HasUnappliedAcceptedWork())
                return Fail(e,"SnapshotRuntimeRawCensusChanged");
        }
        return Peer(*a,oid)!=nullptr||Fail(e,"SnapshotRuntimeRawSelectedPeerMissing");
    }
    static bool SameRecord(const WriteAheadLog::Record& a,const WriteAheadLog::Record& b) {
        const auto fields=[](const auto& r){return std::tie(r.volume_identity,r.transaction_id,r.sequence,r.operation,r.state,
            r.object_id,r.parent_object_id,r.payload_spool_id,r.payload_offset,r.payload_length,r.logical_offset,r.logical_length,
            r.flags,r.payload_sha256,r.inline_payload,r.path_utf8,r.secondary_path_utf8,r.unlink_outcome);};
        return fields(a)==fields(b);
    }
    static bool SameTransaction(const TransactionManager::AcceptedTransaction& a,const TransactionManager::AcceptedTransaction& b) {
        return a.transaction_id==b.transaction_id&&a.accepted_sequence==b.accepted_sequence&&
            a.preimage_checkpoint_xid==b.preimage_checkpoint_xid&&a.mutations.size()==b.mutations.size()&&
            std::equal(a.mutations.begin(),a.mutations.end(),b.mutations.begin(),SameRecord);
    }
    static bool RestartReceiptChanged(const Authority& a,const TransactionManager::AcceptedTransaction& tx) {
        return a.state_->restart_receipt&&!SameTransaction(*a.state_->restart_receipt,tx);
    }
    static bool ReadHeldHistory(const State::Peer& peer,WriteAheadLog::ReadResult& history,std::string& e) {
        using Wal=WriteAheadLog;
        if(!Owned(peer,e))return false;
        HANDLE held=CreateFileW(peer.original.journal_path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,
            nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        if(held==INVALID_HANDLE_VALUE)return Fail(e,"SnapshotRuntimeRawOriginalWalMissing");
        history=Wal::ReadAllEvidenceFromHeldHandle(held,peer.identity.journal_identity,
            {64ull*1024*1024,1000000},256ull*1024*1024);
        const bool closed=CloseHandle(held)!=FALSE;
        if(!closed||history.status!=Wal::ReadStatus::Ok||history.recovered_torn_tail||!Owned(peer,e))
            return Fail(e,"SnapshotRuntimeRawOriginalWalInvalid");
        return true;
    }
    static bool ReadablePeers(const Authority& authority,std::string& e) {
        for(const auto& peer:authority.state_->peers){
            WriteAheadLog::ReadResult history;if(!ReadHeldHistory(peer,history,e))return false;
        }
        return true;
    }
    static bool HeldReceipt(const State::Peer& peer,const TransactionManager::AcceptedTransaction& tx,std::string& e,
        bool allow_completed=false) {
        using Wal=WriteAheadLog;
        if(!tx.transaction_id||!tx.accepted_sequence||tx.mutations.size()!=1||
            !Wal::SnapshotIntentIsConsistent(tx.mutations[0]))return Fail(e,"SnapshotRuntimeRawRestartReceiptInvalid");
        Wal::ReadResult history;if(!ReadHeldHistory(peer,history,e))return false;
        const Wal::Record* marker=nullptr;const Wal::Record* mutation=nullptr;
        const auto marks=peer.original.journal->Watermarks();
        if(marks.accepted_sequence!=tx.accepted_sequence||marks.cleanup_sequence>tx.accepted_sequence||
            (!allow_completed&&marks.cleanup_sequence==tx.accepted_sequence)||
            marks.apfs_durable_sequence>tx.accepted_sequence||!peer.original.journal->RecoveryStateValid()||
            peer.original.journal->CurrentState()!=TransactionManager::State::Idle||peer.original.journal->PendingMutationCount())
            return Fail(e,"SnapshotRuntimeRawRestartDebtMismatch");
        for(const auto& r:history.records){
            if(r.operation==Wal::OperationKind::TransactionMarker&&r.state==Wal::RecordState::Accepted&&
                r.sequence>marks.cleanup_sequence&&r.sequence!=tx.accepted_sequence)
                return Fail(e,"SnapshotRuntimeRawRestartMixedDebt");
            if(r.sequence>tx.accepted_sequence&&r.operation!=Wal::OperationKind::DurabilityWatermark&&
                r.operation!=Wal::OperationKind::CompactionIndex)return Fail(e,"SnapshotRuntimeRawRestartAcceptedSuffix");
        }
        for(const auto& r:history.records)if(r.transaction_id==tx.transaction_id){
            if(r.operation==Wal::OperationKind::TransactionMarker){
                if(marker||r.sequence!=tx.accepted_sequence||r.state!=Wal::RecordState::Accepted||r.flags!=0x8||
                    r.logical_length!=1||r.object_id!=tx.preimage_checkpoint_xid)return Fail(e,"SnapshotRuntimeRawAcceptedMarkerMismatch");
                marker=&r;
            }else if(r.operation!=Wal::OperationKind::DurabilityWatermark&&r.operation!=Wal::OperationKind::CompactionIndex){
                if(mutation||r.state!=Wal::RecordState::Prepared||r.sequence>=tx.accepted_sequence||
                    !SameRecord(r,tx.mutations[0]))return Fail(e,"SnapshotRuntimeRawAcceptedMutationMismatch");mutation=&r;
            }
        }
        NativeSnapshotIntent intent;
        return (marker&&mutation&&DecodeNativeSnapshotIntent(mutation->inline_payload,intent)&&intent.raw_receipt&&
            intent.scope.checkpoint_xid==tx.preimage_checkpoint_xid)||Fail(e,"SnapshotRuntimeRawAcceptedReceiptMissing");
    }
    static bool LoadRawTransaction(const State::Peer& peer,std::uint64_t sequence,TransactionManager::AcceptedTransaction& tx,std::string& e) {
        tx={};WriteAheadLog::ReadResult history;if(!sequence||!ReadHeldHistory(peer,history,e))return false;
        const WriteAheadLog::Record* marker=nullptr;
        for(const auto& r:history.records)if(r.sequence==sequence&&r.operation==WriteAheadLog::OperationKind::TransactionMarker&&
            r.state==WriteAheadLog::RecordState::Accepted){if(marker)return Fail(e,"SnapshotRuntimeRawAcceptedMarkerMismatch");marker=&r;}
        if(!marker)return Fail(e,"SnapshotRuntimeRawAcceptedReceiptMissing");
        tx.transaction_id=marker->transaction_id;tx.accepted_sequence=sequence;tx.preimage_checkpoint_xid=marker->object_id;
        for(const auto& r:history.records)if(r.transaction_id==tx.transaction_id&&r.operation!=WriteAheadLog::OperationKind::TransactionMarker&&
            r.operation!=WriteAheadLog::OperationKind::DurabilityWatermark&&r.operation!=WriteAheadLog::OperationKind::CompactionIndex)tx.mutations.push_back(r);
        return HeldReceipt(peer,tx,e);
    }
    static bool Capture(Owner& o,std::span<const RawSnapshotRuntimePeerOwner> peers,const RawHardwareQualification& qualification,
        const TransactionManager::AcceptedTransaction* restart,std::shared_ptr<const Authority>& out,std::string& e) {
        out.reset();e.clear();
        if(o.IsRecoveryRequired()||!o.CheckpointCensusRequired()||peers.empty()||peers.size()>100||
            o.MountedVolumeCount()!=peers.size())return Fail(e,"SnapshotRuntimeRawOwnerNotReady");
        auto state=std::make_shared<State>();state->owner=&o;state->owner_lifetime=o.LifetimeToken();state->device=&o.Device();
        state->container_uuid=o.ContainerUuidHex();state->qualification=qualification;
        const auto lease=o.Device().CaptureHeldRawSnapshotLease();
        if(!lease||!o.Device().QueryHeldRawSnapshotBinding(*lease,qualification,state->binding,e))return false;
        state->lease=*lease;
        std::set<const MetadataStore*> stores;std::set<const TransactionManager*> journals;std::set<std::wstring> paths;
        for(const auto& original:peers){State::Peer peer;peer.original=original;
            if(!original.volume_oid||!original.store||!original.journal||original.journal_path.empty()||
                !std::filesystem::path(original.journal_path).is_absolute()||
                o.FindSessionStore(original.volume_oid)!=original.store||&original.store->Device()!=state->device||
                !stores.insert(original.store).second||!journals.insert(original.journal).second||!paths.insert(original.journal_path).second||
                !original.store->raw_snapshot_runtime_authority_.expired()||
                !o.SessionCanonicalJournalIdentity(original.volume_oid,peer.canonical))return Fail(e,"SnapshotRuntimeRawPeerNotOwned");
            std::string original_identity;
            if(!o.SessionRecoveryIdentity(original.volume_oid,original_identity)||
                original_identity!=TransactionManager::WideToUtf8(original.journal->ConfiguredVolumeIdentity()))
                return Fail(e,"SnapshotRuntimeRawOriginalJournalChanged");
            peer.identity={original.volume_oid,original.store->Context().volume_uuid_hex,std::move(original_identity)};
            peer.writer_generation=original.journal->ObservedJournalWriterLeaseGeneration();
            if(!Owned(peer,e)||!StoreClean(*original.store))return Fail(e,"SnapshotRuntimeRawPeerNotClean");
            state->peers.push_back(std::move(peer));
        }
        std::sort(state->peers.begin(),state->peers.end(),[](const auto& a,const auto& b){return a.identity.volume_oid<b.identity.volume_oid;});
        auto authority=std::shared_ptr<const Authority>(new Authority(state));
        const auto* cp=state->peers.front().original.store->AuthoritativeAppleCheckpointView();
        if(!cp||!Cohort(*authority,*cp,e)||state->binding.media.limit_bytes!=o.Device().RawWriteLimitBytes())return Fail(e,"SnapshotRuntimeRawSourceWindowInvalid");
        NativeSnapshotIntent accepted;std::uint64_t selected=state->peers.front().identity.volume_oid;
        if(restart){
            if(restart->mutations.size()!=1||!DecodeNativeSnapshotIntent(restart->mutations[0].inline_payload,accepted)||!accepted.raw_receipt)
                return Fail(e,"SnapshotRuntimeRawRestartReceiptInvalid");
            selected=accepted.scope.volume_oid;const auto* peer=Peer(*authority,selected);
            if(!peer||*accepted.raw_receipt!=Receipt(*authority,selected)||!HeldReceipt(*peer,*restart,e))return Fail(e,"SnapshotRuntimeRawRestartReceiptMismatch");
            state->restart_receipt=*restart;
        }
        if(!Preflight(authority,o,selected,e))return false;
        for(const auto& peer:state->peers){const auto& s=*peer.original.store;
            if(!s.Context().allow_native_snapshot_runtime||!s.Context().allow_raw_device_canonical_commit||
                s.Context().volume_object_id!=peer.identity.volume_oid||s.Context().container_uuid_hex!=state->container_uuid||
                s.IsImmutableSnapshotView()||!s.IsNativeWriteReady()||s.IsRecoveryRequired()||
                ((!restart||peer.identity.volume_oid!=selected)&&!JournalClean(*peer.original.journal)))return Fail(e,"SnapshotRuntimeRawPeerNotEnrolled");
            if(!ValidateNativeRawSnapshotReceiptShape(Receipt(*authority,peer.identity.volume_oid),peer.identity.volume_oid,
                peer.identity.volume_uuid_hex,state->binding.media.limit_bytes))return Fail(e,"SnapshotRuntimeRawCohortInvalid");
            WriteAheadLog::ReadResult history;
            if(!ReadHeldHistory(peer,history,e))return false;
            if(restart)state->restart_journals.push_back({peer.identity.volume_oid,peer.original.journal->Watermarks(),
                std::make_shared<const std::vector<WriteAheadLog::Record>>(std::move(history.records)),s.StateEpoch()});
        }
        if(restart)state->restart_census=o.CheckpointCensusSnapshot();
        if(!o.Device().IsHeldRawSnapshotLeaseCurrent(state->lease))return Fail(e,"SnapshotRuntimeRawSourceChanged");
        for(const auto& peer:state->peers)peer.original.store->raw_snapshot_runtime_authority_=authority;
        out=std::move(authority);return true;
    }
    static std::shared_ptr<const Authority> Enrolled(const MetadataStore& store) {return store.raw_snapshot_runtime_authority_.lock();}
    static bool Granted(const MetadataStore& store,const NativeSnapshotIntent& p,std::string& e) {
        return (!store.raw_snapshot_runtime_payload_.empty()&&store.raw_snapshot_runtime_payload_==EncodeNativeSnapshotIntent(p))||
            Fail(e,"SnapshotRuntimeRawPayloadNotGranted");
    }
    static bool Arm(const MetadataStore& store,const std::shared_ptr<const Authority>& a,const NativeSnapshotIntent& p,std::string& e) {
        if(!store.raw_snapshot_runtime_payload_.empty()||!Verify(a,store,p,e))return Fail(e,"SnapshotRuntimeRawPayloadNotGranted");
        store.raw_snapshot_runtime_payload_=EncodeNativeSnapshotIntent(p);return !store.raw_snapshot_runtime_payload_.empty();
    }
    static void Disarm(const MetadataStore& store) {store.raw_snapshot_runtime_payload_.clear();}
    static SourceCapability Bind(const catalog::RandomAccessSource& source,const MetadataStore& store,
        std::shared_ptr<const Authority> a) {return {source,store,std::move(a)};}
    static SourceCapability BindRetained(const catalog::RandomAccessSource& source,const MetadataStore& store,
        const std::shared_ptr<const Recovery>& token) {return {source,store,token->state_->authority,token};}
    static bool RetainedSource(const std::shared_ptr<const Recovery>& token,const MetadataStore& store,
        const NativeSnapshotIntent& p,std::string& e) {
        return (token&&EncodeNativeSnapshotIntent(p)==token->state_->request.inline_payload&&
            Verify(token->state_->authority,store,p,e,true))||Fail(e,"SnapshotRuntimeRawRecoveryReceiptMismatch");
    }
    static std::shared_ptr<const Recovery> Candidate(const std::shared_ptr<const Authority>& a,
        const NativeSnapshotIntent& intent,const MetadataStore::MutationRequest& request) {
        auto state=std::make_shared<Recovery::State>();state->authority=a;state->intent=intent;state->request=request;
        return std::shared_ptr<const Recovery>(new Recovery(std::move(state)));
    }
    static bool Accepted(const std::shared_ptr<const Recovery>& token,std::uint64_t sequence,std::string& e) {
        if(!token)return true;
        auto& state=*token->state_;const auto* peer=Peer(*state.authority,state.intent.scope.volume_oid);
        if(!peer||!LoadRawTransaction(*peer,sequence,state.accepted,e)||
            state.accepted.mutations[0].inline_payload!=state.request.inline_payload)
            return Fail(e,"SnapshotRuntimeRawAcceptedMutationMismatch");
        for(const auto& original:state.authority->state_->peers){
            WriteAheadLog::ReadResult history;if(!ReadHeldHistory(original,history,e))return false;
            state.journals.push_back({original.identity.volume_oid,original.original.journal->Watermarks(),
                std::make_shared<const std::vector<WriteAheadLog::Record>>(std::move(history.records)),original.original.store->StateEpoch()});
        }
        return true;
    }
    static void StartingAcceptance(const std::shared_ptr<const Recovery>& token) {
        if(token)token->state_->acceptance_started=true;
    }
    static bool PublicationVerified(const std::shared_ptr<const Recovery>& token) {
        return token&&token->state_->publication_verified;
    }
    static catalog::ContainerCommitResult Commit(Owner& o,std::uint64_t oid,
        const std::vector<MetadataStore::MutationRequest>& requests,
        const catalog::ContainerPrepublicationHook& accept,
        const catalog::ContainerMutationPreparationHook& prepare,
        const catalog::ContainerPostpublicationVerifierHook& verify,
        const std::shared_ptr<const Recovery>& candidate) {
        if(candidate)return o.CommitRawSnapshot(oid,requests,accept,prepare,verify,candidate);
        return o.Commit(oid,requests,accept,{},{},false,{},prepare,verify);
    }
    static bool HasRetained(Owner& o) {
        std::lock_guard<std::timed_mutex> lock(o.commit_mutex_);return o.raw_snapshot_recovery_!=nullptr;
    }
    static bool CleanPeersNoLock(const std::shared_ptr<const Authority>& authority,Owner& owner,
        std::uint64_t oid,std::string& error) {
        if(!authority||authority->state_->owner!=&owner||authority->state_->owner_lifetime.expired()||!Peer(*authority,oid))
            return Fail(error,"SnapshotRuntimeRawInspectionOwnerNotReady");
        {
            std::lock_guard<std::mutex> state(owner.mutex_);
            if(owner.draining_||owner.recovery_required_||owner.raw_snapshot_recovery_||
                !owner.require_checkpoint_census_||!owner.checkpoint_census_initialized_||
                owner.device_.get()!=authority->state_->device||owner.container_uuid_hex_!=authority->state_->container_uuid)
                return Fail(error,"SnapshotRuntimeRawInspectionOwnerNotReady");
        }
        const auto observations=owner.ObserveRawSnapshotPeersNoLock();std::set<std::uint64_t> seen;
        if(observations.size()!=authority->state_->peers.size()||owner.volume_checkpoint_pins_.size()!=observations.size())
            return Fail(error,"SnapshotRuntimeRawCensusIncomplete");
        for(const auto& observation:observations){const auto* original=Peer(*authority,observation.oid);
            if(!original||!seen.insert(observation.oid).second||observation.store!=original->original.store||
                !observation.canonical_writer||observation.canonical_identity!=original->canonical||
                observation.recovery_identity!=original->identity.journal_identity||!Owned(*original,error))
                return Fail(error,"SnapshotRuntimeRawCensusChanged");
            if(!StoreClean(*original->original.store)||!JournalClean(*original->original.journal)||
                !observation.census.required_checkpoint_xids.empty()||observation.census.unapplied_accepted_work)
                return Fail(error,"SnapshotRuntimeRawInspectionPeerBusy");
        }
        return true;
    }
    static bool LockedPeers(Owner& o,const Recovery& token,bool selected_debt,std::string& e,bool retained_census=true) {
        const auto& state=*token.state_;const auto& a=state.authority;const auto oid=state.intent.scope.volume_oid;
        const auto* selected=Peer(*a,oid);
        if(!selected||a->state_->owner!=&o||&o.Device()!=a->state_->device||
            o.container_uuid_hex_!=a->state_->container_uuid||o.volume_checkpoint_pins_.size()!=a->state_->peers.size())
            return Fail(e,"SnapshotRuntimeRawRecoveryOwnerChanged");
        const auto observations=o.ObserveRawSnapshotPeersNoLock();std::set<std::uint64_t> seen;
        if(observations.size()!=a->state_->peers.size())return Fail(e,"SnapshotRuntimeRawRecoveryCohortChanged");
        for(const auto& observation:observations){const auto* peer=Peer(*a,observation.oid);
            if(!peer||!seen.insert(observation.oid).second||observation.store!=peer->original.store||
                !observation.canonical_writer||observation.canonical_identity!=peer->canonical||
                observation.recovery_identity!=peer->identity.journal_identity||!Owned(*peer,e))
                return Fail(e,"SnapshotRuntimeRawRecoveryCohortChanged");
            WriteAheadLog::ReadResult history;if(!ReadHeldHistory(*peer,history,e))return false;
            const auto proof=std::find_if(state.journals.begin(),state.journals.end(),
                [&](const auto& original){return original.oid==observation.oid;});
            if(proof==state.journals.end()||!proof->records||(observation.oid!=oid&&peer->original.store->StateEpoch()!=proof->store_epoch)||
                history.records.size()<proof->records->size()||
                !std::equal(proof->records->begin(),proof->records->end(),history.records.begin(),SameRecord))
                return Fail(e,"SnapshotRuntimeRawRecoveryWalChanged");
            auto expected_marks=proof->marks;auto expected_size=proof->records->size();
            if(observation.oid==oid){
                std::uint64_t last_sequence=0;
                for(const auto& record:*proof->records)if(record.operation!=WriteAheadLog::OperationKind::CompactionIndex)
                    last_sequence=(std::max)(last_sequence,record.sequence);
                const auto completion_record=[&](WriteAheadLog::RecordState record_state){
                    WriteAheadLog::Record expected;expected.volume_identity=peer->identity.journal_identity;
                    expected.sequence=++last_sequence;expected.operation=WriteAheadLog::OperationKind::DurabilityWatermark;
                    expected.state=record_state;expected.logical_offset=state.accepted.accepted_sequence;
                    return expected_size<history.records.size()&&SameRecord(history.records[expected_size++],expected);
                };
                if(state.durability_written&&proof->marks.apfs_durable_sequence<state.accepted.accepted_sequence){
                    if(!completion_record(WriteAheadLog::RecordState::Checkpointed))return Fail(e,"SnapshotRuntimeRawRecoveryWalChanged");
                    expected_marks.apfs_durable_sequence=state.accepted.accepted_sequence;
                }
                if(state.cleanup_written&&proof->marks.cleanup_sequence<state.accepted.accepted_sequence){
                    if(!completion_record(WriteAheadLog::RecordState::Cleaned))return Fail(e,"SnapshotRuntimeRawRecoveryWalChanged");
                    expected_marks.cleanup_sequence=state.accepted.accepted_sequence;
                }
            }
            const auto observed_marks=peer->original.journal->Watermarks();
            if(history.records.size()!=expected_size||observed_marks.accepted_sequence!=expected_marks.accepted_sequence||
                observed_marks.apfs_durable_sequence!=expected_marks.apfs_durable_sequence||
                observed_marks.cleanup_sequence!=expected_marks.cleanup_sequence)
                return Fail(e,"SnapshotRuntimeRawRecoveryWalChanged");
            const bool debt=observation.oid==oid&&peer->original.journal->Watermarks().cleanup_sequence<state.accepted.accepted_sequence;
            const auto expected=debt?state.intent.pins:std::vector<std::uint64_t>{};
            const bool expected_owner=debt&&(retained_census||peer->original.journal->HasUnappliedAcceptedWork());
            if(observation.census.required_checkpoint_xids!=expected||observation.census.unapplied_accepted_work!=expected_owner)
                return Fail(e,"SnapshotRuntimeRawRecoveryCensusChanged");
        }
        return Verify(a,*selected->original.store,state.intent,e,selected_debt)&&
            (selected_debt||StoreClean(*selected->original.store)||Fail(e,"SnapshotRuntimeRawRecoverySelectedBusy"))&&
            HeldReceipt(*selected,state.accepted,e,true);
    }
    static bool LatchMatchesNoLock(Owner& o,const std::shared_ptr<const Recovery>& token,std::string& e) {
        std::lock_guard<std::mutex> state_lock(o.mutex_);
        if(!token||o.raw_snapshot_recovery_!=token||o.draining_||
            (o.recovery_required_&&(o.recovery_volume_object_id_!=token->state_->intent.scope.volume_oid||
                o.recovery_reason_!=o.raw_snapshot_recovery_reason_))||
            (!o.recovery_required_&&!o.raw_snapshot_recovery_reason_.empty()))
            return Fail(e,"SnapshotRuntimeRawRecoveryLatchNotAuthorized");
        return true;
    }
    static bool Recover(Owner&,TransactionManager&,std::uint64_t,const RawSnapshotRuntimeReplayParameters&,
        std::shared_ptr<const Recovery>&,std::string&);
    static bool RecoverNoLock(Owner&,TransactionManager&,std::uint64_t,const RawSnapshotRuntimeReplayParameters&,
        std::shared_ptr<const Recovery>&,std::string&);
    static bool ProveRecoveryNoLock(Owner&,const std::shared_ptr<const Recovery>&,
        std::optional<catalog::AppleCheckpointView>&,std::string&);
    static bool RestartNoLock(Owner&,TransactionManager&,std::uint64_t,const RawSnapshotRuntimeReplayParameters&,
        std::shared_ptr<const Recovery>&,std::string&);
    static bool Restart(Owner&,TransactionManager&,std::uint64_t,const RawSnapshotRuntimeReplayParameters&,
        std::shared_ptr<const Recovery>*,std::string&);
    static bool AdmitNoLock(Owner&,TransactionManager&,std::uint64_t,const RawSnapshotRuntimeReplayParameters&,
        std::optional<catalog::AppleCheckpointView>&,std::string&);
    static bool Admit(Owner& owner,TransactionManager& journal,std::uint64_t oid,
        const RawSnapshotRuntimeReplayParameters& parameters,std::string& error) {
        error.clear();std::lock_guard<std::timed_mutex> serialized(owner.commit_mutex_);
        std::optional<catalog::AppleCheckpointView> observed;
        return AdmitNoLock(owner,journal,oid,parameters,observed,error);
    }
    static bool Complete(Owner&,const std::shared_ptr<const Recovery>&,
        const RawSnapshotRuntimeCompletionHook&,std::string&);
    static bool Inspect(const std::shared_ptr<const Authority>&,Owner&,std::uint64_t,
        catalog::ApfsSnapshotScope&,std::vector<catalog::ApfsSnapshotInfo>*,std::string&,bool refresh_published_peer=false);
};

bool CaptureRawSnapshotRuntimeAuthority(catalog::ContainerMountCoordinator& o,std::span<const RawSnapshotRuntimePeerOwner> peers,
    const RawHardwareQualification& qualification,std::shared_ptr<const RawSnapshotRuntimeAuthority>& out,std::string& e) {
    return RawSnapshotRuntimeAccess::Capture(o,peers,qualification,nullptr,out,e);
}
bool CaptureRawSnapshotRuntimeRestartAuthority(catalog::ContainerMountCoordinator& o,std::span<const RawSnapshotRuntimePeerOwner> peers,
    const RawHardwareQualification& qualification,const TransactionManager::AcceptedTransaction& tx,
    std::shared_ptr<const RawSnapshotRuntimeAuthority>& out,std::string& e) {
    return RawSnapshotRuntimeAccess::Capture(o,peers,qualification,&tx,out,e);
}
bool VerifyRawSnapshotRuntimeAuthority(const std::shared_ptr<const RawSnapshotRuntimeAuthority>& a,
    catalog::ContainerMountCoordinator& o,const NativeSnapshotIntent& p,std::string& e) {
    if(!RawSnapshotRuntimeAccess::Preflight(a,o,p.scope.volume_oid,e))return false;
    const auto* peer=RawSnapshotRuntimeAccess::Peer(*a,p.scope.volume_oid);
    return RawSnapshotRuntimeAccess::Verify(a,*peer->original.store,p,e);
}

namespace {
using Store=MetadataStore;using Owner=catalog::ContainerMountCoordinator;
bool Fail(std::string& e,const char* s){e=s;return false;}
const catalog::AppleVolumeCheckpointView* Volume(const catalog::AppleCheckpointView& cp,std::uint64_t oid){
    auto it=std::find_if(cp.volumes.begin(),cp.volumes.end(),[&](const auto&v){return v.superblock.object_id==oid;});return it==cp.volumes.end()?nullptr:&*it;
}
bool Hash(std::span<const std::byte>b,std::array<std::uint8_t,32>&h){
    if(b.size()>ULONG_MAX)return false;BCRYPT_ALG_HANDLE a=nullptr;
    if(BCryptOpenAlgorithmProvider(&a,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0)return false;
    auto s=BCryptHash(a,nullptr,0,reinterpret_cast<PUCHAR>(const_cast<std::byte*>(b.data())),static_cast<ULONG>(b.size()),h.data(),32);
    BCryptCloseAlgorithmProvider(a,0);return s>=0;
}
bool Inventory(const catalog::RandomAccessSource&s,const NativeSnapshotIntent&p,std::vector<catalog::ApfsSnapshotIdentity>&out,std::string&e){
    std::vector<catalog::ApfsSnapshotInfo> inventory;if(!catalog::ApfsSnapshotStore::Enumerate(s,p.scope,inventory,e))return false;
    out.clear();for(const auto&i:inventory)out.push_back(i.identity);return out.size()<=64||Fail(e,"SnapshotRuntimeInventoryBound");
}
bool SourceAdmission(const catalog::RandomAccessSource& s,const NativeSnapshotIntent& p,
    const RawSnapshotRuntimeAccess::SourceCapability* raw,std::string& e){
    if(!p.raw_receipt)return !raw||Fail(e,"SnapshotRuntimeRawReceiptRequired");
    return (raw&&raw->source==&s&&(raw->recovery?RawSnapshotRuntimeAccess::RetainedSource(raw->recovery,*raw->store,p,e):
        RawSnapshotRuntimeAccess::Verify(raw->authority,*raw->store,p,e)))||
        Fail(e,"SnapshotRuntimeRawReceiptNotAdmitted");
}
bool Preimage(const catalog::RandomAccessSource&s,const catalog::AppleCheckpointView&cp,const NativeSnapshotIntent&p,std::array<std::uint8_t,32>&hash,std::string&e,
    const RawSnapshotRuntimeAccess::SourceCapability* raw=nullptr){
    if(!SourceAdmission(s,p,raw,e))return false;
    const auto*v=Volume(cp,p.scope.volume_oid);
    std::uint64_t store_size=0;
    if(!SnapshotRuntimeStoreSize(cp.container.superblock,store_size)||p.scope.store_offset_bytes||p.scope.store_size_bytes!=store_size||
        !v||cp.container.superblock.xid!=p.scope.checkpoint_xid||cp.container.superblock.uuid_hex!=p.scope.container_uuid_hex||
        v->superblock.uuid_hex!=p.scope.volume_uuid_hex||s.SizeBytes()!=p.scope.store_size_bytes||!CheckAppleVolumeWriteFeatures(cp.container.superblock,v->superblock,e))return Fail(e,"SnapshotRuntimePreimageIdentity");
    std::vector<catalog::ApfsSnapshotIdentity> inventory;if(!Inventory(s,p,inventory,e)||inventory!=p.inventory)return Fail(e,"SnapshotRuntimeInventoryChanged");
    AppleSnapshotRetentionView retained;if(!LoadAppleSnapshotRetention(s,cp,retained,e))return false;
    // Bind actual per-view metadata and payload bytes, including sibling owners.
    std::vector<std::uint64_t> metadata;
    std::vector<ApplePhysicalExtentRecord> payload;
    if(!LoadAppleSnapshotCheckpointOwners(s,cp,metadata,payload,e))return false;
    std::set<std::uint64_t> blocks(metadata.begin(),metadata.end());
    for(const auto&r:payload){if(r.block_count>65536||blocks.size()+r.block_count>65536)return Fail(e,"SnapshotRuntimePreimageBound");for(std::uint64_t i=0;i<r.block_count;++i)blocks.insert(r.physical_block+i);}
    if(blocks.size()>65536)return Fail(e,"SnapshotRuntimePreimageBound");
    return (snapshot_detail::HashPreimageBlocks(s,cp.container.superblock.block_size,
        cp.container.superblock.block_count,blocks,hash)||Fail(e,"SnapshotRuntimePreimageRead"))&&SourceAdmission(s,p,raw,e);
}
bool RawPlan(const catalog::RandomAccessSource&s,const catalog::AppleCheckpointView&cp,const NativeSnapshotIntent&p,AppleVolumeTransactionPlan&out,std::string&e,catalog::ApfsSnapshotIdentity*identity=nullptr){
    out={};catalog::ApfsSnapshotIdentity planned_identity;if(p.create){AppleSnapshotCreateRequest r;r.volume_object_id=p.scope.volume_oid;r.name_utf8=p.name;r.creation_time_ns=p.time_ns;r.snapshot_inum=p.inum;r.required_checkpoint_xids=p.pins;
        AppleSnapshotCreatePlan plan;if(!PlanAppleSnapshotCreate(s,cp,r,plan,e))return false;planned_identity=plan.identity;out.allocation=std::move(plan.allocation);out.commit=std::move(plan.commit);}
    else{const auto it=std::find_if(p.inventory.begin(),p.inventory.end(),[&](const auto&id){return id.snapshot_xid==p.snapshot_xid&&id.name_utf8==p.name;});if(it==p.inventory.end())return Fail(e,"SnapshotRuntimeDeleteIdentityMissing");
        AppleSnapshotDeleteRequest r;r.expected=*it;r.modification_time_ns=p.time_ns;r.required_checkpoint_xids=p.pins;AppleSnapshotDeletePlan plan;
        if(!PlanAppleSnapshotDelete(s,cp,r,plan,e))return false;planned_identity=plan.removed;out.allocation=std::move(plan.allocation);out.commit=std::move(plan.commit);}
    if(identity)*identity=planned_identity;else if(planned_identity!=p.expected_identity){out={};return Fail(e,"SnapshotRuntimePlannedIdentityMismatch");}
    return true;
}
bool PublicationHash(const AppleCheckpointPublicationPlan&p,std::array<std::uint8_t,32>&hash){
    std::vector<std::byte> bytes;const auto add=[&](const auto&w){snapshot_wire::Put(bytes,w.physical_block);snapshot_wire::Put(bytes,w.bytes.size());bytes.insert(bytes.end(),w.bytes.begin(),w.bytes.end());};
    snapshot_wire::Put(bytes,p.expected_checkpoint_xid);snapshot_wire::Put(bytes,p.transaction_xid);
    for(const auto&w:p.before_superblock_writes)add(w);add(p.superblock_write);return Hash(bytes,hash);
}
std::vector<std::uint64_t> Pins(Owner&o,std::uint64_t xid){auto p=o.SnapshotRuntimeCheckpointPins();p.push_back(xid);std::sort(p.begin(),p.end());p.erase(std::unique(p.begin(),p.end()),p.end());return p;}
bool Prepare(Owner&o,NativeSnapshotIntent p,SnapshotRuntimePlan&out,std::string&e,
    const std::shared_ptr<const RawSnapshotRuntimeAuthority>& authority={}){
    out.owner=nullptr;out.request={};out.raw_authority.reset();out.consumed=false;auto*store=o.FindSessionStore(p.scope.volume_oid);
    if(!store||o.IsRecoveryRequired()||!o.CheckpointCensusRequired()||!store->Context().allow_native_snapshot_runtime||store->PendingMutationCount()||!store->IsNativeWriteReady())return Fail(e,"SnapshotRuntimeOwnerNotReady");
    for(const auto&entry:o.CheckpointCensusSnapshot())if(entry.unapplied_accepted_work)return Fail(e,"SnapshotRuntimeAcceptedOwnerConflict");
    const auto*cp=store->AuthoritativeAppleCheckpointView();const auto*v=cp?Volume(*cp,p.scope.volume_oid):nullptr;if(!v)return Fail(e,"SnapshotRuntimeVolumeMissing");
    SnapshotRuntimeDeviceSource source(store->Device(),cp->container.superblock);
    if(!source.IsValid())return Fail(e,"SnapshotRuntimeSourceWindowInvalid");
    p.scope={0,source.SizeBytes(),cp->container.superblock.uuid_hex,v->superblock.uuid_hex,p.scope.volume_oid,cp->container.superblock.xid};
    std::optional<RawSnapshotRuntimeAccess::SourceCapability> raw;
    if(authority){
        if(!RawSnapshotRuntimeAccess::Preflight(authority,o,p.scope.volume_oid,e))return false;
        const auto* peer=RawSnapshotRuntimeAccess::Peer(*authority,p.scope.volume_oid);
        if(!RawSnapshotRuntimeAccess::JournalClean(*peer->original.journal))return Fail(e,"SnapshotRuntimeRawJournalDebt");
        p.raw_receipt=RawSnapshotRuntimeAccess::Receipt(*authority,p.scope.volume_oid);
        if(!RawSnapshotRuntimeAccess::Verify(authority,*store,p,e))return false;
        raw=RawSnapshotRuntimeAccess::Bind(source,*store,authority);
    }else if(!store->Device().IsRegularFile())return Fail(e,"SnapshotRuntimeRawReceiptRequired");
    p.pins=Pins(o,p.scope.checkpoint_xid);
    if(!Inventory(source,p,p.inventory,e))return false;if(p.create)p.snapshot_xid=cp->container.superblock.next_xid;
    if(!Preimage(source,*cp,p,p.preimage_hash,e,raw?&*raw:nullptr))return false;
    AppleVolumeTransactionPlan plan;if(!RawPlan(source,*cp,p,plan,e,&p.expected_identity)||!PublicationHash(plan.commit.publication,p.publication_hash))return false;
    p.checkpoint_slot=plan.commit.publication.superblock_write.physical_block;
    if(!source.Read(p.checkpoint_slot*plan.commit.publication.block_size,plan.commit.publication.block_size,p.checkpoint_slot_preimage))return Fail(e,"SnapshotRuntimeCheckpointSlotRead");
    NativeSnapshotIntent checked;if(!DecodeNativeSnapshotIntent(EncodeNativeSnapshotIntent(p),checked))return Fail(e,"SnapshotRuntimeArgumentsInvalid");
    auto&r=out.request;r.operation=p.create?Store::MutationOperation::CreateSnapshot:Store::MutationOperation::DeleteSnapshot;r.path=L"\\";r.object_id=p.scope.volume_oid;r.generation=p.scope.checkpoint_xid+1;
    if(!SourceAdmission(source,p,raw?&*raw:nullptr,e))return false;
    r.inline_payload=EncodeNativeSnapshotIntent(p);r.length=r.inline_payload.size();out.raw_authority=authority;out.owner=&o;return true;
}
bool Finalize(Owner&o,TransactionManager&j,std::uint64_t oid,std::uint64_t seq,std::string&e){
    if(!seq||!j.MarkApfsDurableThrough(seq)||!j.MarkCleanedThrough(seq))return Fail(e,"SnapshotRuntimeCleanupFailed");
    std::vector<std::uint64_t>pins;return j.LoadRequiredCheckpointXidsSinceCleanup(pins,&e)&&o.UpdateRequiredCheckpointXids(oid,pins,e,j.HasUnappliedAcceptedWork());
}
// Journal identity for snapshot maintenance: the configured identity matches
// directly, or the session owner enrolled the canonical form while keeping
// its recovery-form configured identity (legacy evidence recognition,
// storage keys and spool identity keep working untouched). Records accepted
// through an enrolled session carry the effective configured identity.
bool SnapshotJournalIdentityMatches(const TransactionManager&j,const std::string&canonical,const std::string&record_identity){
    const std::wstring wide(canonical.begin(),canonical.end());
    if(j.ConfiguredVolumeIdentity()==wide)return record_identity.empty()||record_identity==canonical;
    if(j.EnrolledCanonicalJournalIdentity()!=wide||wide.empty())return false;
    return record_identity.empty()||record_identity==TransactionManager::WideToUtf8(j.ConfiguredVolumeIdentity());
}
bool SnapshotJournalOwnershipHolds(const TransactionManager&j,const std::wstring&journal_path,const std::string&canonical){
    const std::wstring wide(canonical.begin(),canonical.end());
    return j.OwnsJournalForMaintenance(journal_path,wide)||j.OwnsEnrolledCanonicalJournal(journal_path,wide);
}
}
bool RawSnapshotRuntimeAccess::Inspect(const std::shared_ptr<const Authority>& authority,Owner& owner,
    std::uint64_t oid,catalog::ApfsSnapshotScope& scope,std::vector<catalog::ApfsSnapshotInfo>* inventory,std::string& error,
    bool refresh_published_peer) {
    scope={};if(inventory)inventory->clear();error.clear();
    std::lock_guard<std::timed_mutex> serialized(owner.commit_mutex_);
    try {
        if(!CleanPeersNoLock(authority,owner,oid,error))return false;
        const auto* peer=Peer(*authority,oid);
        const auto* mounted=peer->original.store->AuthoritativeAppleCheckpointView();
        if(!mounted)return Fail(error,"SnapshotRuntimeRawInspectionCheckpointMissing");
        SnapshotRuntimeDeviceSource source(*authority->state_->device,mounted->container.superblock);
        if(!source.IsValid()||source.SizeBytes()!=authority->state_->binding.media.limit_bytes)
            return Fail(error,"SnapshotRuntimeRawSourceChanged");
        if(!ReadablePeers(*authority,error))return false;
        const auto disk=catalog::LoadAppleCheckpointView(source,0,source.SizeBytes(),error);
        const auto* selected=disk?Volume(*disk,oid):nullptr;
        auto* cached=Volume(*mounted,oid);
        if(!disk)return false;
        if(!selected||!cached)return Fail(error,"SnapshotRuntimeRawInspectionVolumeMissing");
        if(!Cohort(*authority,*disk,error))return false;
        const auto same_location=[](const catalog::AppleObjectLocation& a,const catalog::AppleObjectLocation& b){
            return a.object_id==b.object_id&&a.xid==b.xid&&a.physical_block==b.physical_block&&
                a.type==b.type&&a.subtype==b.subtype&&a.size_bytes==b.size_bytes;
        };
        const auto same_optional=[&](const auto& a,const auto& b){
            return a.has_value()==b.has_value()&&(!a||same_location(*a,*b));
        };
        const auto same_volume=[&](const auto& a,const auto& b){
            return a.superblock.xid==b.superblock.xid&&a.superblock.uuid_hex==b.superblock.uuid_hex&&
                same_location(a.superblock_object,b.superblock_object)&&
                same_location(a.object_map.object,b.object_map.object)&&same_location(a.object_map.tree,b.object_map.tree)&&
                same_location(a.root_tree,b.root_tree)&&same_optional(a.extentref_tree,b.extentref_tree)&&
                same_optional(a.snapshot_metadata_tree,b.snapshot_metadata_tree)&&same_optional(a.file_extent_tree,b.file_extent_tree);
        };
        const auto current_selected=[&](){
            return mounted->container.superblock_bytes==disk->container.superblock_bytes&&cached&&same_volume(*cached,*selected)&&
                owner.checkpoint_xid_.load(std::memory_order_relaxed)==disk->container.superblock.xid;
        };
        if(!refresh_published_peer&&!current_selected())return Fail(error,"SnapshotRuntimeRawInspectionMountedCheckpointStale");
        NativeSnapshotIntent intent;
        intent.scope={0,source.SizeBytes(),disk->container.superblock.uuid_hex,
            selected->superblock.uuid_hex,oid,disk->container.superblock.xid};
        intent.raw_receipt=Receipt(*authority,oid);
        if(!Verify(authority,*peer->original.store,intent,error))return false;
        if(!current_selected()){
            // Only an exact checkpoint already held by the original cohort can
            // authorize replacing a clean sibling's obsolete mounted view.
            bool published=false;
            if(refresh_published_peer&&mounted->container.superblock.xid<disk->container.superblock.xid&&
                owner.checkpoint_xid_.load(std::memory_order_relaxed)==disk->container.superblock.xid){
                for(const auto& original:authority->state_->peers){
                    const auto* view=original.original.store->AuthoritativeAppleCheckpointView();
                    if(!view||view->container.superblock_bytes!=disk->container.superblock_bytes||
                        view->volumes.size()!=disk->volumes.size()||
                        !same_location(view->container_object_map.object,disk->container_object_map.object)||
                        !same_location(view->container_object_map.tree,disk->container_object_map.tree)||
                        !same_location(view->spaceman.object,disk->spaceman.object)||view->spaceman.bytes!=disk->spaceman.bytes)continue;
                    published=std::all_of(disk->volumes.begin(),disk->volumes.end(),[&](const auto& volume){
                        const auto* held=Volume(*view,volume.superblock.object_id);return held&&same_volume(*held,volume);
                    });
                    if(published)break;
                }
            }
            if(!published)return Fail(error,"SnapshotRuntimeRawInspectionMountedCheckpointStale");
            if(!CleanPeersNoLock(authority,owner,oid,error)||!ReadablePeers(*authority,error)||
                !Verify(authority,*peer->original.store,intent,error)||
                !owner.ReloadRawSnapshotRecoveryNoLock(oid,error))return false;
            mounted=peer->original.store->AuthoritativeAppleCheckpointView();
            cached=mounted?Volume(*mounted,oid):nullptr;
            if(!mounted||!current_selected())return Fail(error,"SnapshotRuntimeRawInspectionMountedCheckpointStale");
        }
        std::vector<catalog::ApfsSnapshotInfo> observed;
        if(inventory&&!catalog::ApfsSnapshotStore::Enumerate(source,intent.scope,observed,error))return false;
        if(inventory&&observed.size()>64)return Fail(error,"SnapshotRuntimeInventoryBound");
        if(!source.IsValid()||!CleanPeersNoLock(authority,owner,oid,error)||!ReadablePeers(*authority,error)||
            !Verify(authority,*peer->original.store,intent,error))return false;
        scope=intent.scope;if(inventory)*inventory=std::move(observed);return true;
    }catch(...){scope={};if(inventory)inventory->clear();return Fail(error,"SnapshotRuntimeRawInspectionException");}
}
bool InspectRawSnapshotRuntimeAuthority(const std::shared_ptr<const RawSnapshotRuntimeAuthority>& authority,
    Owner& owner,std::uint64_t oid,catalog::ApfsSnapshotScope& scope,
    std::vector<catalog::ApfsSnapshotInfo>* inventory,std::string& error) {
    return RawSnapshotRuntimeAccess::Inspect(authority,owner,oid,scope,inventory,error);
}
bool RefreshAndInspectRawSnapshotRuntimeAuthority(const std::shared_ptr<const RawSnapshotRuntimeAuthority>& authority,
    Owner& owner,std::uint64_t oid,catalog::ApfsSnapshotScope& scope,
    std::vector<catalog::ApfsSnapshotInfo>* inventory,std::string& error) {
    return RawSnapshotRuntimeAccess::Inspect(authority,owner,oid,scope,inventory,error,true);
}
bool PrepareSnapshotCreate(Owner&o,std::uint64_t oid,std::string_view name,std::uint64_t time,std::uint64_t inum,SnapshotRuntimePlan&out,std::string&e){
    NativeSnapshotIntent p;p.scope.volume_oid=oid;p.name=name;p.time_ns=time;p.inum=inum;return Prepare(o,p,out,e);
}
bool PrepareSnapshotCreate(Owner&o,std::uint64_t oid,std::string_view name,std::uint64_t time,std::uint64_t inum,
    const std::shared_ptr<const RawSnapshotRuntimeAuthority>& authority,SnapshotRuntimePlan&out,std::string&e){
    NativeSnapshotIntent p;p.scope.volume_oid=oid;p.name=name;p.time_ns=time;p.inum=inum;
    if(!authority)return Fail(e,"SnapshotRuntimeRawAuthorityRequired");return Prepare(o,p,out,e,authority);
}
bool VerifySnapshotMaintenanceOwner(Owner&o,std::uint64_t oid,TransactionManager&j,const std::wstring& journal_path,std::string&e){
    auto*store=o.FindSessionStore(oid);
    if(!store||o.IsRecoveryRequired()||!o.CheckpointCensusRequired())return Fail(e,"SnapshotMaintenanceOwnerNotReady");
    std::string canonical;if(!o.SessionCanonicalJournalIdentity(oid,canonical)||canonical.empty())return Fail(e,"SnapshotMaintenanceNoSession");
    if(!SnapshotJournalOwnershipHolds(j,journal_path,canonical))return Fail(e,"SnapshotMaintenanceJournalNotOwned");
    if(j.CurrentState()!=TransactionManager::State::Idle||j.PendingMutationCount()||!j.RecoveryStateValid())return Fail(e,"SnapshotMaintenanceJournalBusy");
    std::vector<TransactionManager::AcceptedTransaction>debt;std::string detail;
    if(!j.LoadAcceptedTransactionsSinceCleanup(debt,&detail)||!debt.empty()||j.HasUnappliedAcceptedWork())return Fail(e,"SnapshotMaintenanceAcceptedDebt");
    return true;
}
bool VerifySnapshotRecoveryOwner(Owner&o,std::uint64_t oid,TransactionManager&j,const std::wstring& journal_path,std::string&e){
    auto*store=o.FindSessionStore(oid);
    if(!store||o.IsRecoveryRequired()||!o.CheckpointCensusRequired())return Fail(e,"SnapshotMaintenanceOwnerNotReady");
    std::string canonical;if(!o.SessionCanonicalJournalIdentity(oid,canonical)||canonical.empty())return Fail(e,"SnapshotMaintenanceNoSession");
    if(!SnapshotJournalOwnershipHolds(j,journal_path,canonical))return Fail(e,"SnapshotMaintenanceJournalNotOwned");
    return true;
}
bool VerifySnapshotJournalCurrency(Owner&o,std::uint64_t oid,TransactionManager&j,std::string&e){
    return VerifySnapshotJournalCurrency(o,oid,j,true,e);
}
bool VerifySnapshotJournalCurrency(Owner&o,std::uint64_t oid,TransactionManager&j,bool strict_substitution_check,std::string&e){
    auto*store=o.FindSessionStore(oid);
    if(!store||o.IsRecoveryRequired())return Fail(e,"SnapshotMaintenanceOwnerNotReady");
    const auto xid=store->CheckpointXid();if(!xid.has_value())return Fail(e,"SnapshotMaintenanceCheckpointUnknown");
    std::vector<std::uint64_t>pins;std::string detail;
    if(!j.LoadRequiredCheckpointXidsSinceCleanup(pins,&detail))return Fail(e,"SnapshotMaintenancePinsUnreadable");
    for(const auto pin:pins)if(pin>xid.value())return Fail(e,"SnapshotMaintenanceJournalAhead");
    const auto marks=j.Watermarks();
    if(strict_substitution_check&&pins.empty()&&marks.accepted_sequence==0&&marks.apfs_durable_sequence==0){
        // Caller-supplied journal directories are never trusted by assertion:
        // a journal with no durable history authenticates itself only against
        // an image with no snapshot history. Anything else is a substituted
        // clean journal (or a fresh file pointed at a used image: the real
        // journal lives elsewhere and must be found, not replaced).
        // Session-owned journals skip this branch (strict_substitution_check
        // false): the session host established the file, startup recovery
        // already reconciled markers, and ownership is proven by lease.
        const auto*cp=store->AuthoritativeAppleCheckpointView();if(!cp)return Fail(e,"SnapshotMaintenanceCheckpointUnknown");
        const auto*v=Volume(*cp,oid);if(!v)return Fail(e,"SnapshotMaintenanceVolumeMissing");
        SnapshotRuntimeDeviceSource source(store->Device(),cp->container.superblock);
        if(!source.IsValid())return Fail(e,"SnapshotRuntimeSourceWindowInvalid");
        catalog::ApfsSnapshotScope scope{0,source.SizeBytes(),cp->container.superblock.uuid_hex,v->superblock.uuid_hex,oid,xid.value()};
        std::vector<catalog::ApfsSnapshotInfo>inventory;
        if(!catalog::ApfsSnapshotStore::Enumerate(source,scope,inventory,e))return false;
        if(!inventory.empty())return Fail(e,"SnapshotMaintenanceJournalNoChain");
    }
    return true;
}
bool PrepareSnapshotDelete(Owner&o,const catalog::ApfsSnapshotIdentity&id,std::uint64_t time,SnapshotRuntimePlan&out,std::string&e){
    NativeSnapshotIntent p;p.create=false;p.scope=id.scope;p.name=id.name_utf8;p.snapshot_xid=id.snapshot_xid;p.time_ns=time;
    if(!Prepare(o,p,out,e))return false;NativeSnapshotIntent checked;
    if(!DecodeNativeSnapshotIntent(out.request.inline_payload,checked)||std::find(checked.inventory.begin(),checked.inventory.end(),id)==checked.inventory.end()) {out.owner=nullptr;return Fail(e,"SnapshotRuntimeDeleteStaleIdentity");}return true;
}
bool PrepareSnapshotDelete(Owner&o,const catalog::ApfsSnapshotIdentity&id,std::uint64_t time,
    const std::shared_ptr<const RawSnapshotRuntimeAuthority>& authority,SnapshotRuntimePlan&out,std::string&e){
    NativeSnapshotIntent p;p.create=false;p.scope=id.scope;p.name=id.name_utf8;p.snapshot_xid=id.snapshot_xid;p.time_ns=time;
    if(!authority)return Fail(e,"SnapshotRuntimeRawAuthorityRequired");
    if(!Prepare(o,p,out,e,authority))return false;NativeSnapshotIntent checked;
    if(!DecodeNativeSnapshotIntent(out.request.inline_payload,checked)||std::find(checked.inventory.begin(),checked.inventory.end(),id)==checked.inventory.end()){
        out.owner=nullptr;out.raw_authority.reset();return Fail(e,"SnapshotRuntimeDeleteStaleIdentity");}return true;
}
bool ValidateSnapshotMutation(const Store&store,const Store::MutationRequest&r,std::string&e){
    NativeSnapshotIntent p;const auto*cp=store.AuthoritativeAppleCheckpointView();
    if(!store.Context().allow_native_snapshot_runtime||store.IsImmutableSnapshotView()||!store.IsNativeWriteReady()||store.IsRecoveryRequired()||!cp||
        (r.operation!=Store::MutationOperation::CreateSnapshot&&r.operation!=Store::MutationOperation::DeleteSnapshot)||!DecodeNativeSnapshotIntent(r.inline_payload,p)||
        p.create!=(r.operation==Store::MutationOperation::CreateSnapshot)||r.path!=L"\\"||!r.secondary_path.empty()||r.offset||r.timestamp_utc||r.replace_if_exists||r.expected_unlink_outcome||
        r.object_id!=p.scope.volume_oid||r.generation!=p.scope.checkpoint_xid+1||r.length!=r.inline_payload.size()||store.Context().volume_object_id!=p.scope.volume_oid)return Fail(e,"SnapshotRuntimeMutationInvalid");
    SnapshotRuntimeDeviceSource source(store.Device(),cp->container.superblock);
    std::optional<RawSnapshotRuntimeAccess::SourceCapability> raw;
    if(p.raw_receipt){
        if(store.Device().IsRegularFile())return Fail(e,"SnapshotRuntimeRawReceiptNotAdmitted");
        auto authority=RawSnapshotRuntimeAccess::Enrolled(store);
        if(!RawSnapshotRuntimeAccess::Granted(store,p,e)||!RawSnapshotRuntimeAccess::Verify(authority,store,p,e))return false;
        raw=RawSnapshotRuntimeAccess::Bind(source,store,std::move(authority));
    }else if(!store.Device().IsRegularFile())return Fail(e,"SnapshotRuntimeRawReceiptRequired");
    std::array<std::uint8_t,32>hash{};return Preimage(source,*cp,p,hash,e,raw?&*raw:nullptr)&&(hash==p.preimage_hash||Fail(e,"SnapshotRuntimePreimageHashChanged"));
}
static bool PlanSnapshotRuntimeCheckpointBound(const catalog::RandomAccessSource&s,const catalog::AppleCheckpointView&cp,const NativeSnapshotIntent&p,const std::vector<std::uint64_t>&pins,AppleVolumeTransactionPlan&out,std::string&e,
    const RawSnapshotRuntimeAccess::SourceCapability* raw){
    out={};auto normalized=pins;normalized.push_back(cp.container.superblock.xid);std::sort(normalized.begin(),normalized.end());normalized.erase(std::unique(normalized.begin(),normalized.end()),normalized.end());
    if(normalized!=p.pins)return Fail(e,"SnapshotRuntimePinCensusChanged");std::array<std::uint8_t,32>hash{};
    if(!Preimage(s,cp,p,hash,e,raw)||hash!=p.preimage_hash)return Fail(e,"SnapshotRuntimePreimageHashChanged");
    std::vector<std::byte>slot;
    if(p.checkpoint_slot>=cp.container.superblock.block_count||p.checkpoint_slot_preimage.size()!=cp.container.superblock.block_size||
        !s.Read(p.checkpoint_slot*cp.container.superblock.block_size,cp.container.superblock.block_size,slot)||slot!=p.checkpoint_slot_preimage)return Fail(e,"SnapshotRuntimeCheckpointSlotChanged");
    AppleVolumeTransactionPlan plan;if(!RawPlan(s,cp,p,plan,e)||!PublicationHash(plan.commit.publication,hash))return false;
    if(plan.commit.publication.superblock_write.physical_block!=p.checkpoint_slot)return Fail(e,"SnapshotRuntimeCheckpointSlotMismatch");
    if(hash!=p.publication_hash)return Fail(e,"SnapshotRuntimePublicationPlanChanged");
    if(!SourceAdmission(s,p,raw,e))return false;out=std::move(plan);return true;
}
bool PlanSnapshotRuntimeCheckpoint(const catalog::RandomAccessSource&s,const catalog::AppleCheckpointView&cp,const NativeSnapshotIntent&p,
    const std::vector<std::uint64_t>&pins,AppleVolumeTransactionPlan&out,std::string&e){
    return PlanSnapshotRuntimeCheckpointBound(s,cp,p,pins,out,e,nullptr);
}
bool PlanSnapshotRuntimeCheckpoint(const Store&store,const catalog::AppleCheckpointView&cp,const NativeSnapshotIntent&p,
    const std::vector<std::uint64_t>&pins,AppleVolumeTransactionPlan&out,std::string&e){
    out={};SnapshotRuntimeDeviceSource source(store.Device(),cp.container.superblock);
    if(!source.IsValid())return Fail(e,"SnapshotRuntimeSourceWindowInvalid");
    if(!p.raw_receipt){if(!store.Device().IsRegularFile())return Fail(e,"SnapshotRuntimeRawReceiptRequired");
        return PlanSnapshotRuntimeCheckpointBound(source,cp,p,pins,out,e,nullptr);}
    auto authority=RawSnapshotRuntimeAccess::Enrolled(store);
    const auto* current=store.AuthoritativeAppleCheckpointView();
    if(!current||current->container.superblock_bytes!=cp.container.superblock_bytes)return Fail(e,"SnapshotRuntimeRawPlannerCheckpointChanged");
    if(!RawSnapshotRuntimeAccess::Granted(store,p,e)||!RawSnapshotRuntimeAccess::Verify(authority,store,p,e))return false;
    const auto raw=RawSnapshotRuntimeAccess::Bind(source,store,std::move(authority));
    return PlanSnapshotRuntimeCheckpointBound(source,cp,p,pins,out,e,&raw);
}
static bool VerifyPublishedSnapshotBound(const Store&store,const NativeSnapshotIntent&p,std::string&e,
    const catalog::AppleCheckpointView* observed=nullptr,
    const std::shared_ptr<const RawSnapshotRuntimeRecoveryToken>& retained={}){
    std::shared_ptr<const RawSnapshotRuntimeAuthority> authority;
    if(p.raw_receipt){authority=RawSnapshotRuntimeAccess::Enrolled(store);
        if(retained?!RawSnapshotRuntimeAccess::RetainedSource(retained,store,p,e):
            !RawSnapshotRuntimeAccess::Verify(authority,store,p,e))return false;
    }else if(!store.Device().IsRegularFile())return Fail(e,"SnapshotRuntimeRawReceiptRequired");
    const auto*current=observed?observed:store.AuthoritativeAppleCheckpointView();
    if(!current||current->container.superblock.xid!=p.scope.checkpoint_xid+1||current->container.superblock.uuid_hex!=p.scope.container_uuid_hex||
        (!retained&&store.PendingMutationCount()))return Fail(e,"SnapshotRuntimePublicationBoundaryMismatch");
    SnapshotRuntimeDeviceSource source(store.Device(),current->container.superblock);
    if(!source.IsValid()||p.scope.store_offset_bytes||p.scope.store_size_bytes!=source.SizeBytes())return Fail(e,"SnapshotRuntimeSourceWindowInvalid");
    std::vector<AppleRecoveryCheckpointView>history;if(!LoadAppleSnapshotRecoveryCheckpoints(source,*current,{p.scope.checkpoint_xid},history,e)||history.size()!=1)return false;
    const auto&before=history[0].checkpoint;
    const auto&nx=before.container.superblock;
    // Only the descriptor destination is overwritten at publication. Restore
    // that exact bounded preimage for deterministic planner replay; it cannot
    // cover a live data/metadata block or the accepted source checkpoint.
    if(p.checkpoint_slot>=nx.block_count||p.checkpoint_slot<nx.xp_desc_base_block||p.checkpoint_slot-nx.xp_desc_base_block>=nx.xp_desc_block_count||
        p.checkpoint_slot==before.container.superblock_physical_block||p.checkpoint_slot_preimage.size()!=nx.block_size)return Fail(e,"SnapshotRuntimeReplaySlotInvalid");
    class BeforeSource final:public catalog::RandomAccessSource {
        const catalog::RandomAccessSource&s;const NativeSnapshotIntent&p;std::uint64_t offset;
    public:BeforeSource(const catalog::RandomAccessSource&s,const NativeSnapshotIntent&p,std::uint32_t bs):s(s),p(p),offset(p.checkpoint_slot*bs){}
        std::uint64_t SizeBytes()const override{return s.SizeBytes();}
        bool Read(std::uint64_t o,std::size_t n,std::vector<std::byte>&b)const override{if(!s.Read(o,n,b))return false;const auto start=(std::max)(o,offset),end=(std::min)(o+n,offset+p.checkpoint_slot_preimage.size());if(start<end)std::copy(p.checkpoint_slot_preimage.begin()+start-offset,p.checkpoint_slot_preimage.begin()+end-offset,b.begin()+start-o);return true;}
    } before_source(source,p,nx.block_size);
    std::optional<RawSnapshotRuntimeAccess::SourceCapability> raw;
    if(retained)raw=RawSnapshotRuntimeAccess::BindRetained(before_source,store,retained);
    else if(authority)raw=RawSnapshotRuntimeAccess::Bind(before_source,store,authority);
    AppleVolumeTransactionPlan expected;if(!PlanSnapshotRuntimeCheckpointBound(before_source,before,p,p.pins,expected,e,raw?&*raw:nullptr))return false;
    const auto verify=[&](const auto&w){std::vector<std::byte>b;return source.Read(w.physical_block*expected.commit.publication.block_size,w.bytes.size(),b)&&b==w.bytes;};
    for(const auto&w:expected.commit.publication.before_superblock_writes)if(!verify(w))return Fail(e,"SnapshotRuntimePublishedBytesMismatch");
    if(!verify(expected.commit.publication.superblock_write))return Fail(e,"SnapshotRuntimePublishedCheckpointMismatch");
    AppleSnapshotRetentionView after;if(!LoadAppleSnapshotRetention(source,*current,after,e))return false;
    // Replanned typed composer independently proves inventory, historical XIDs,
    // live filesystem equality, sibling APSBs, allocation and exact reference layers.
    return retained?RawSnapshotRuntimeAccess::RetainedSource(retained,store,p,e):
        !authority||RawSnapshotRuntimeAccess::Verify(authority,store,p,e);
}
bool VerifyPublishedSnapshot(const Store& store,const NativeSnapshotIntent& intent,std::string& error){
    return VerifyPublishedSnapshotBound(store,intent,error);
}

bool RawSnapshotRuntimeAccess::AdmitNoLock(Owner& o,TransactionManager& journal,std::uint64_t oid,
    const RawSnapshotRuntimeReplayParameters& parameters,std::optional<catalog::AppleCheckpointView>& disk,std::string& e) {
    disk.reset();
    const auto token=o.raw_snapshot_recovery_;
    if(!LatchMatchesNoLock(o,token,e))return false;
    auto& state=*token->state_;const auto& p=state.intent;
    const auto* peer=Peer(*state.authority,oid);
    if(parameters.authority!=state.authority||!peer||peer->original.journal!=&journal||
        oid!=p.scope.volume_oid||!parameters.accepted_sequence||parameters.accepted_sequence!=state.accepted.accepted_sequence||
        state.accepted.mutations.size()!=1||state.accepted.mutations[0].inline_payload!=state.request.inline_payload||
        state.accepted.preimage_checkpoint_xid!=p.scope.checkpoint_xid)
        return Fail(e,"SnapshotRuntimeRawRecoveryReceiptMismatch");
    if(!LockedPeers(o,*token,!state.publication_verified,e)||!ProveRecoveryNoLock(o,token,disk,e))return false;
    return LatchMatchesNoLock(o,token,e)&&LockedPeers(o,*token,!state.publication_verified,e);
}

bool RawSnapshotRuntimeAccess::ProveRecoveryNoLock(Owner& o,const std::shared_ptr<const Recovery>& token,
    std::optional<catalog::AppleCheckpointView>& disk,std::string& e) {
    disk.reset();const auto& state=*token->state_;const auto& p=state.intent;
    const auto* peer=Peer(*state.authority,p.scope.volume_oid);
    if(!peer)return Fail(e,"SnapshotRuntimeRawRecoveryReceiptMismatch");
    try {
        const auto& selected=*peer->original.store;
        if(selected.StateEpoch()!=state.selected_epoch||selected.HasUncommittedAllocatorState()||
            selected.PendingAllocationCount()||selected.PendingDeallocationCount()||
            selected.PendingObjectMapUpdateCount()||selected.PendingBtreeRecordCount()||selected.PendingPayloadByteEstimate())
            return Fail(e,"SnapshotRuntimeRawRecoverySelectedStateChanged");
        if(peer->original.store->IsRecoveryRequired()&&
            peer->original.store->RecoveryReason()!=L"AppleCommitInterruptedAfterPublish")
            return Fail(e,"SnapshotRuntimeRawRecoveryStorePoisonNotAuthorized");
        const auto* original=peer->original.store->AuthoritativeAppleCheckpointView();
        if(!original)return Fail(e,"SnapshotRuntimeRawRecoveryCheckpointMissing");
        SnapshotRuntimeDeviceSource source(*state.authority->state_->device,original->container.superblock);
        if(!source.IsValid())return Fail(e,"SnapshotRuntimeRawSourceChanged");
        disk=catalog::LoadAppleCheckpointView(source,0,source.SizeBytes(),e);
        const auto preimage=p.scope.checkpoint_xid;
        const auto owner_xid=o.checkpoint_xid_.load(std::memory_order_relaxed);
        if(!disk||!Cohort(*state.authority,*disk,e)||
            (disk->container.superblock.xid!=preimage&&disk->container.superblock.xid!=preimage+1)||
            (owner_xid!=preimage&&owner_xid!=preimage+1))return Fail(e,"SnapshotRuntimeRawRecoveryCheckpointAdvanced");
        if((state.publication_verified||selected.IsRecoveryRequired())&&disk->container.superblock.xid!=preimage+1)
            return Fail(e,"SnapshotRuntimeRawRecoveryPublishedCheckpointLost");
        const auto pending=peer->original.store->DebugSnapshotPendingMutations();
        if(!pending.empty()&&(pending.size()!=1||pending[0]!=state.request))
            return Fail(e,"SnapshotRuntimeRawRecoveryPendingChanged");
        if(disk->container.superblock.xid==preimage){
            const auto capability=BindRetained(source,*peer->original.store,token);AppleVolumeTransactionPlan plan;
            if(!PlanSnapshotRuntimeCheckpointBound(source,*disk,p,p.pins,plan,e,&capability))return false;
        }else if(!VerifyPublishedSnapshotBound(*peer->original.store,p,e,&*disk,token))return false;
        return true;
    }catch(...){return Fail(e,"SnapshotRuntimeRawRetainedAdmissionException");}
}

bool RawSnapshotRuntimeAccess::Recover(Owner& o,TransactionManager& journal,std::uint64_t oid,
    const RawSnapshotRuntimeReplayParameters& parameters,std::shared_ptr<const Recovery>& completion,std::string& e) {
    completion.reset();e.clear();std::lock_guard<std::timed_mutex> serialized(o.commit_mutex_);
    return RecoverNoLock(o,journal,oid,parameters,completion,e);
}
bool RawSnapshotRuntimeAccess::RecoverNoLock(Owner& o,TransactionManager& journal,std::uint64_t oid,
    const RawSnapshotRuntimeReplayParameters& parameters,std::shared_ptr<const Recovery>& completion,std::string& e) {
    std::optional<catalog::AppleCheckpointView> disk;
    if(!AdmitNoLock(o,journal,oid,parameters,disk,e))return false;
    const auto token=o.raw_snapshot_recovery_;auto& state=*token->state_;const auto& p=state.intent;
    const auto* peer=Peer(*state.authority,oid);const auto preimage=p.scope.checkpoint_xid;
    if(state.publication_verified){completion=token;return true;}
    struct SelectedStateGuard {
        Recovery::State& state;const MetadataStore& store;
        ~SelectedStateGuard(){state.selected_epoch=store.StateEpoch();}
    } selected_state{state,*peer->original.store};
    try {
        // The latch is established before reloading any accepted working view.
        // It remains set on every failure, including completion exceptions.
        {
            std::lock_guard<std::mutex> lock(o.mutex_);
            o.recovery_required_=true;o.recovery_volume_object_id_=oid;
            o.recovery_reason_="RawSnapshotRetainedRecoveryPending";
            o.raw_snapshot_recovery_reason_=o.recovery_reason_;
        }
        o.InvalidateSharedSpaceNoLock();
        if(!o.ReloadRawSnapshotRecoveryNoLock(oid,e)||!LockedPeers(o,*token,false,e))return false;
        auto& live=*peer->original.store;
        if(live.CheckpointXid()!=disk->container.superblock.xid)return Fail(e,"SnapshotRuntimeRawRecoveryReloadChanged");
        if(live.CheckpointXid()==preimage){
            struct Grant {const MetadataStore& store;~Grant(){RawSnapshotRuntimeAccess::Disarm(store);}} grant{live};
            const auto result=o.CommitNoLock(oid,{state.request},{},{},{},true,preimage,
                [&](const MetadataStore& selected,auto& requests,std::string& why){
                    if(!LockedPeers(o,*token,false,why)||requests.size()!=1||
                        requests[0].inline_payload!=state.request.inline_payload||!Arm(selected,state.authority,p,why))return false;
                    return ValidateSnapshotMutation(selected,requests[0],why);
                },[&](const MetadataStore& selected,std::uint64_t,std::string& why){
                    return LockedPeers(o,*token,false,why)&&VerifyPublishedSnapshot(selected,p,why);
                },true,false,{},token);
            if(!result.committed||result.commit_status_code!=static_cast<int>(MetadataStore::CommitStatus::Committed)){
                e=result.error;return false;
            }
        }else if(!VerifyPublishedSnapshot(live,p,e))return false;
        if(!LatchMatchesNoLock(o,token,e)||!LockedPeers(o,*token,false,e)||!VerifyPublishedSnapshot(live,p,e))return false;
        o.AccountRawSnapshotRecoveryNoLock(preimage+1);
        state.publication_verified=true;completion=token;return true;
    }catch(...){return Fail(e,"SnapshotRuntimeRawRetainedRecoveryException");}
}

bool RawSnapshotRuntimeAccess::RestartNoLock(Owner& o,TransactionManager& journal,std::uint64_t oid,
    const RawSnapshotRuntimeReplayParameters& parameters,std::shared_ptr<const Recovery>& candidate,std::string& e) {
    candidate.reset();const auto& a=parameters.authority;
    if(!a||!a->state_->restart_receipt||a->state_->owner!=&o||a->state_->owner_lifetime.expired()||
        !parameters.accepted_sequence||parameters.accepted_sequence!=a->state_->restart_receipt->accepted_sequence)
        return Fail(e,"SnapshotRuntimeRawRestartAuthorityRequired");
    {
        std::lock_guard<std::mutex> lock(o.mutex_);
        if(o.draining_||o.recovery_required_||o.raw_snapshot_recovery_||o.device_.get()!=a->state_->device||
            !o.require_checkpoint_census_||!o.checkpoint_census_initialized_)
            return Fail(e,"SnapshotRuntimeRawRestartOwnerNotReady");
    }
    try {
        const auto* peer=Peer(*a,oid);TransactionManager::AcceptedTransaction accepted;
        if(!peer||peer->original.journal!=&journal||
            !LoadRawTransaction(*peer,parameters.accepted_sequence,accepted,e)||RestartReceiptChanged(*a,accepted))
            return Fail(e,"SnapshotRuntimeRawRestartReceiptMismatch");
        NativeSnapshotIntent intent;
        if(accepted.mutations.size()!=1||!DecodeNativeSnapshotIntent(accepted.mutations[0].inline_payload,intent)||
            !intent.raw_receipt||intent.scope.volume_oid!=oid||accepted.preimage_checkpoint_xid!=intent.scope.checkpoint_xid)
            return Fail(e,"SnapshotRuntimeRawRestartReceiptMismatch");
        MetadataStore::MutationRequest request;
        request.operation=intent.create?MetadataStore::MutationOperation::CreateSnapshot:MetadataStore::MutationOperation::DeleteSnapshot;
        request.path=L"\\";request.object_id=oid;request.generation=intent.scope.checkpoint_xid+1;
        request.inline_payload=accepted.mutations[0].inline_payload;request.length=request.inline_payload.size();
        auto token=Candidate(a,intent,request);auto& state=*token->state_;
        state.accepted=std::move(accepted);state.journals=a->state_->restart_journals;state.acceptance_started=true;
        token->CaptureSelectedState(*peer->original.store);
        const auto observations=o.ObserveRawSnapshotPeersNoLock();
        if(observations.size()!=a->state_->restart_census.size()||state.journals.size()!=a->state_->peers.size())
            return Fail(e,"SnapshotRuntimeRawRestartCensusChanged");
        for(const auto& observation:observations){
            const auto original=std::find_if(a->state_->restart_census.begin(),a->state_->restart_census.end(),
                [&](const auto& pins){return pins.volume_object_id==observation.oid;});
            const auto proof=std::find_if(state.journals.begin(),state.journals.end(),
                [&](const auto& recorded){return recorded.oid==observation.oid;});
            if(original==a->state_->restart_census.end()||proof==state.journals.end()||
                observation.store->StateEpoch()!=proof->store_epoch||!StoreClean(*observation.store)||
                observation.census.required_checkpoint_xids!=original->required_checkpoint_xids||
                observation.census.unapplied_accepted_work!=original->unapplied_accepted_work)
                return Fail(e,"SnapshotRuntimeRawRestartOriginalStateChanged");
        }
        std::optional<catalog::AppleCheckpointView> disk;
        if(!LockedPeers(o,*token,false,e,false)||!ProveRecoveryNoLock(o,token,disk,e))return false;
        const auto* mounted=peer->original.store->AuthoritativeAppleCheckpointView();
        if(!mounted||mounted->container.superblock_bytes!=disk->container.superblock_bytes||
            o.checkpoint_xid_.load(std::memory_order_relaxed)!=disk->container.superblock.xid)
            return Fail(e,"SnapshotRuntimeRawRestartSourceChanged");
        // Repeat the complete held history and source binding before any latch,
        // grant, reload, publication, durability or census change is authorized.
        if(!LockedPeers(o,*token,false,e,false))return false;
        {
            std::lock_guard<std::mutex> lock(o.mutex_);
            if(o.draining_||o.recovery_required_||o.raw_snapshot_recovery_)
                return Fail(e,"SnapshotRuntimeRawRestartOwnerNotReady");
        }
        candidate=std::move(token);return true;
    }catch(...){return Fail(e,"SnapshotRuntimeRawRestartAdmissionException");}
}

bool RawSnapshotRuntimeAccess::Restart(Owner& o,TransactionManager& journal,std::uint64_t oid,
    const RawSnapshotRuntimeReplayParameters& parameters,std::shared_ptr<const Recovery>* completion,std::string& e) {
    if(completion)completion->reset();e.clear();std::lock_guard<std::timed_mutex> serialized(o.commit_mutex_);
    if(!parameters.authority||!parameters.authority->state_->restart_receipt||
        parameters.accepted_sequence!=parameters.authority->state_->restart_receipt->accepted_sequence)
        return Fail(e,"SnapshotRuntimeRawRestartAuthorityRequired");
    if(o.raw_snapshot_recovery_){
        std::optional<catalog::AppleCheckpointView> disk;
        if(!AdmitNoLock(o,journal,oid,parameters,disk,e))return false;
        return !completion||RecoverNoLock(o,journal,oid,parameters,*completion,e);
    }
    std::shared_ptr<const Recovery> candidate;
    if(!RestartNoLock(o,journal,oid,parameters,candidate,e))return false;
    if(!completion)return true;
    std::string reason="RawSnapshotRestartRecoveryPending",expected=reason;
    auto* pins=o.FindVolumeCheckpointPinsNoLock(oid);
    if(!pins)return Fail(e,"SnapshotRuntimeRawRestartCensusChanged");
    {
        std::lock_guard<std::mutex> lock(o.mutex_);
        if(o.draining_||o.recovery_required_||o.raw_snapshot_recovery_)
            return Fail(e,"SnapshotRuntimeRawRestartOwnerNotReady");
        o.recovery_required_=true;o.recovery_volume_object_id_=oid;
        o.recovery_reason_.swap(reason);o.raw_snapshot_recovery_reason_.swap(expected);
        o.raw_snapshot_recovery_=candidate;
    }
    pins->unapplied_accepted_work=true;o.InvalidateSharedSpaceNoLock();
    return RecoverNoLock(o,journal,oid,parameters,*completion,e);
}

bool RawSnapshotRuntimeAccess::Complete(Owner& o,const std::shared_ptr<const Recovery>& token,
    const RawSnapshotRuntimeCompletionHook& host_completion,std::string& e) {
    e.clear();std::lock_guard<std::timed_mutex> serialized(o.commit_mutex_);
    if(!LatchMatchesNoLock(o,token,e)||!token->state_->publication_verified||!host_completion)
        return Fail(e,"SnapshotRuntimeRawCompletionNotAuthorized");
    auto& state=*token->state_;const auto& p=state.intent;
    const auto* peer=Peer(*state.authority,p.scope.volume_oid);auto& journal=*peer->original.journal;
    try {
        if(peer->original.store->StateEpoch()!=state.selected_epoch)return Fail(e,"SnapshotRuntimeRawRecoverySelectedStateChanged");
        if(!LockedPeers(o,*token,false,e)||!VerifyPublishedSnapshot(*peer->original.store,p,e))return false;
        if(!journal.MarkApfsDurableThrough(state.accepted.accepted_sequence))return Fail(e,"SnapshotRuntimeRawCompletionDurabilityFailed");
        state.durability_written=true;
        if(!LockedPeers(o,*token,false,e)||!VerifyPublishedSnapshot(*peer->original.store,p,e))return false;
        if(!host_completion(e)||!e.empty()){
            if(e.empty())e="SnapshotRuntimeRawHostCompletionRefused";return false;
        }
        // Recheck the original device/cohort/receipt after the host's selected
        // spool/marker work and before authorizing its WAL cleanup.
        if(peer->original.store->StateEpoch()!=state.selected_epoch)return Fail(e,"SnapshotRuntimeRawRecoverySelectedStateChanged");
        if(!LatchMatchesNoLock(o,token,e)||!LockedPeers(o,*token,false,e)||
            !VerifyPublishedSnapshot(*peer->original.store,p,e))return false;
        if(!journal.MarkCleanedThrough(state.accepted.accepted_sequence))return Fail(e,"SnapshotRuntimeRawCompletionCleanupFailed");
        state.cleanup_written=true;
        if(!JournalClean(journal)||!HeldReceipt(*peer,state.accepted,e,true))return false;
        auto* pins=o.FindVolumeCheckpointPinsNoLock(p.scope.volume_oid);
        if(!pins)return Fail(e,"SnapshotRuntimeRawRecoveryCensusChanged");
        pins->required_checkpoint_xids.clear();pins->unapplied_accepted_work=false;
        if(!LatchMatchesNoLock(o,token,e)||!LockedPeers(o,*token,false,e)||
            !VerifyPublishedSnapshot(*peer->original.store,p,e))return false;
        {
            std::lock_guard<std::mutex> lock(o.mutex_);
            if(o.draining_||o.raw_snapshot_recovery_!=token||!o.recovery_required_||
                o.recovery_volume_object_id_!=p.scope.volume_oid||o.recovery_reason_!=o.raw_snapshot_recovery_reason_||
                !state.authority->state_->device->IsHeldRawSnapshotLeaseCurrent(state.authority->state_->lease))
                return Fail(e,"SnapshotRuntimeRawCompletionLatchChanged");
            o.recovery_required_=false;o.recovery_volume_object_id_.reset();o.recovery_reason_.clear();
            o.raw_snapshot_recovery_reason_.clear();o.raw_snapshot_recovery_.reset();
        }
        o.PublishSharedSpaceNoLock(peer->original.store->AuthoritativeAppleCheckpointView(),true);
        return true;
    }catch(...){return Fail(e,"SnapshotRuntimeRawCompletionException");}
}

bool RecoverRetainedRawSnapshot(Owner& o,TransactionManager& journal,std::uint64_t oid,
    const RawSnapshotRuntimeReplayParameters& parameters,
    std::shared_ptr<const RawSnapshotRuntimeRecoveryToken>& completion,std::string& e) {
    return RawSnapshotRuntimeAccess::Recover(o,journal,oid,parameters,completion,e);
}
bool AdmitRetainedRawSnapshotRecovery(Owner& o,TransactionManager& journal,std::uint64_t oid,
    const RawSnapshotRuntimeReplayParameters& parameters,std::string& e) {
    return RawSnapshotRuntimeAccess::Admit(o,journal,oid,parameters,e);
}
bool AdmitRawSnapshotRestartRecovery(Owner& o,TransactionManager& journal,std::uint64_t oid,
    const RawSnapshotRuntimeReplayParameters& parameters,std::string& e) {
    return RawSnapshotRuntimeAccess::Restart(o,journal,oid,parameters,nullptr,e);
}
bool RecoverRawSnapshotRestart(Owner& o,TransactionManager& journal,std::uint64_t oid,
    const RawSnapshotRuntimeReplayParameters& parameters,std::shared_ptr<const RawSnapshotRuntimeRecoveryToken>& completion,std::string& e) {
    return RawSnapshotRuntimeAccess::Restart(o,journal,oid,parameters,&completion,e);
}
bool CompleteRetainedRawSnapshotRecovery(Owner& o,const std::shared_ptr<const RawSnapshotRuntimeRecoveryToken>& token,
    const RawSnapshotRuntimeCompletionHook& hook,std::string& e) {
    return RawSnapshotRuntimeAccess::Complete(o,token,hook,e);
}

static catalog::ContainerCommitResult ApplySnapshotBound(Owner&o,TransactionManager&j,SnapshotRuntimePlan&plan,
    const RawSnapshotRuntimeCompletionHook* host_completion){
    catalog::ContainerCommitResult result;NativeSnapshotIntent p;
    if(plan.consumed||plan.owner!=&o||!DecodeNativeSnapshotIntent(plan.request.inline_payload,p)){result.error="SnapshotRuntimePlanInvalid";return result;}
    if(p.raw_receipt&&o.Device().IsRegularFile()){result.error="SnapshotRuntimeRawReceiptNotAdmitted";return result;}
    if(p.raw_receipt&&(!host_completion||!*host_completion)){result.error="SnapshotRuntimeRawCompletionHookRequired";return result;}
    plan.consumed=true;
    if(p.raw_receipt){
        if(!VerifyRawSnapshotRuntimeAuthority(plan.raw_authority,o,p,result.error))return result;
        const auto* peer=RawSnapshotRuntimeAccess::Peer(*plan.raw_authority,p.scope.volume_oid);
        if(peer->original.journal!=&j||!RawSnapshotRuntimeAccess::JournalClean(j)){result.error="SnapshotRuntimeRawOriginalJournalRequired";return result;}
    }else if(plan.raw_authority||!o.Device().IsRegularFile()){result.error="SnapshotRuntimeRawReceiptRequired";return result;}
    const auto identity="apfs-vol:"+p.scope.container_uuid_hex+":"+std::to_string(p.scope.volume_oid);
    if(!SnapshotJournalIdentityMatches(j,identity,"")){result.error="SnapshotRuntimeJournalIdentityMismatch";return result;}
    std::vector<TransactionManager::AcceptedTransaction>debt;
    if(j.CurrentState()!=TransactionManager::State::Idle||j.PendingMutationCount()||!j.RecoveryStateValid()||
        (!p.raw_receipt&&(!j.LoadAcceptedTransactionsSinceCleanup(debt)||!debt.empty()))){result.error="SnapshotRuntimeJournalDebt";return result;}
    struct Grant {const Store* store=nullptr;~Grant(){if(store)RawSnapshotRuntimeAccess::Disarm(*store);}} grant;
    bool acceptance=false;std::uint64_t seq=0;
    const auto candidate=p.raw_receipt?RawSnapshotRuntimeAccess::Candidate(plan.raw_authority,p,plan.request):nullptr;
    try{result=RawSnapshotRuntimeAccess::Commit(o,p.scope.volume_oid,{plan.request},[&](const auto&requests,const auto&ids,std::uint64_t xid,auto&pins,std::string&e){
        if(requests.size()!=1||ids.size()!=1||xid!=p.scope.checkpoint_xid||requests[0].inline_payload!=plan.request.inline_payload||ids[0].object_id!=p.scope.volume_oid||ids[0].generation!=xid+1)return Fail(e,"SnapshotRuntimeAcceptanceIdentity");
        if(p.raw_receipt&&(!grant.store||!RawSnapshotRuntimeAccess::Granted(*grant.store,p,e)||
            !RawSnapshotRuntimeAccess::Verify(plan.raw_authority,*grant.store,p,e)||!RawSnapshotRuntimeAccess::JournalClean(j)))return false;
        TransactionManager::MutationIntent intent;intent.kind=p.create?TransactionManager::MutationKind::CreateSnapshot:TransactionManager::MutationKind::DeleteSnapshot;
        intent.path=L"\\";intent.object_id=p.scope.volume_oid;intent.generation=xid+1;intent.inline_payload=requests[0].inline_payload;intent.length=intent.payload_length=intent.inline_payload.size();
        if(!Hash(intent.inline_payload,intent.payload_checksum))return Fail(e,"SnapshotRuntimeAcceptanceHash");
        if(p.raw_receipt&&!RawSnapshotRuntimeAccess::ReadablePeers(*plan.raw_authority,e))return false;
        if(p.raw_receipt&&!j.SnapshotEvidenceCapacityAvailable(intent,e))return false;
        acceptance=true;
        RawSnapshotRuntimeAccess::StartingAcceptance(candidate);
        if(!j.Begin()||!j.RecordMutation(intent)||!j.Accept(xid))return Fail(e,"SnapshotRuntimeAcceptanceFailed");seq=j.Watermarks().accepted_sequence;
        return seq&&RawSnapshotRuntimeAccess::Accepted(candidate,seq,e)&&j.LoadRequiredCheckpointXidsSinceCleanup(pins,&e);
    },[&](const Store&s,auto&r,std::string&e){
        if(r.size()!=1||r[0].inline_payload!=plan.request.inline_payload)return Fail(e,"SnapshotRuntimeAcceptanceIdentity");
        if(p.raw_receipt){if(!RawSnapshotRuntimeAccess::Arm(s,plan.raw_authority,p,e))return false;grant.store=&s;}
        return ValidateSnapshotMutation(s,r[0],e);},
        [&](const Store&s,std::uint64_t,std::string&e){
            return (!candidate||RawSnapshotRuntimeAccess::LockedPeers(o,*candidate,false,e))&&VerifyPublishedSnapshot(s,p,e);
        },candidate);
        if(candidate&&result.committed&&result.commit_status_code==static_cast<int>(Store::CommitStatus::Committed)&&
            RawSnapshotRuntimeAccess::PublicationVerified(candidate)){
            if(grant.store){RawSnapshotRuntimeAccess::Disarm(*grant.store);grant.store=nullptr;}
            if(RawSnapshotRuntimeAccess::Complete(o,candidate,*host_completion,result.error)){
                result.commit_recovery_required=false;result.commit_recovery_reason.clear();return result;
            }
            result.commit_recovery_required=true;result.commit_recovery_reason=L"RawSnapshotHostCompletionPending";return result;
        }
        if(result.committed&&!result.commit_recovery_required&&result.commit_status_code==static_cast<int>(Store::CommitStatus::Committed)&&
            !p.raw_receipt&&Finalize(o,j,p.scope.volume_oid,seq,result.error))return result;
    }catch(...){result.error="SnapshotRuntimeException";}
    if(acceptance){result.commit_recovery_required=true;result.commit_status_code=static_cast<int>(Store::CommitStatus::InvariantFailed);result.commit_recovery_reason=L"SnapshotRuntimeRequiresRecovery";
        auto pins=p.pins;for(const auto&entry:o.CheckpointCensusSnapshot())if(entry.volume_object_id==p.scope.volume_oid)pins.insert(pins.end(),entry.required_checkpoint_xids.begin(),entry.required_checkpoint_xids.end());std::string e;(void)o.UpdateRequiredCheckpointXids(p.scope.volume_oid,pins,e,true);}
    return result;
}
catalog::ContainerCommitResult ApplySnapshot(Owner&o,TransactionManager&j,SnapshotRuntimePlan&plan){
    return ApplySnapshotBound(o,j,plan,nullptr);
}
catalog::ContainerCommitResult ApplySnapshot(Owner&o,TransactionManager&j,SnapshotRuntimePlan&plan,
    const RawSnapshotRuntimeCompletionHook& completion){
    return ApplySnapshotBound(o,j,plan,&completion);
}
static std::optional<bool> ReplaySnapshotBound(Owner&o,TransactionManager&j,std::uint64_t oid,
    const RawSnapshotRuntimeReplayParameters* raw,std::string&e){
    if(raw&&o.IsRecoveryRequired())return Fail(e,"SnapshotRuntimeRawPoisonedOwnerRecoveryInterfaceRequired");
    if(raw&&RawSnapshotRuntimeAccess::HasRetained(o))return Fail(e,"SnapshotRuntimeRawRetainedRecoveryRequired");
    if(raw)return Fail(e,"SnapshotRuntimeRawCompletionInterfaceRequired");
    if(!o.Device().IsRegularFile())return Fail(e,"SnapshotRuntimeRawCompletionInterfaceRequired");
    std::vector<TransactionManager::AcceptedTransaction>txs;
    if(!j.LoadAcceptedTransactionsSinceCleanup(txs,&e))return false;
    bool found=false;
    for(const auto&tx:txs)for(const auto&r:tx.mutations)found|=r.operation==WriteAheadLog::OperationKind::CreateSnapshot||r.operation==WriteAheadLog::OperationKind::DeleteSnapshot;
    if(!found)return std::nullopt;if(!o.CheckpointCensusRequired()||txs.size()!=1||txs[0].mutations.size()!=1)return Fail(e,"SnapshotRuntimeReplayMixedReceipt");
    const auto&tx=txs[0];const auto&r=tx.mutations[0];NativeSnapshotIntent p;
    if(!WriteAheadLog::SnapshotIntentIsConsistent(r)||!DecodeNativeSnapshotIntent(r.inline_payload,p)||p.scope.volume_oid!=oid||tx.preimage_checkpoint_xid!=p.scope.checkpoint_xid)return Fail(e,"SnapshotRuntimeReplayIdentity");
    const auto identity="apfs-vol:"+p.scope.container_uuid_hex+":"+std::to_string(oid);
    if(!SnapshotJournalIdentityMatches(j,identity,r.volume_identity))return Fail(e,"SnapshotRuntimeReplayJournalIdentityMismatch");
    if(p.raw_receipt){
        return Fail(e,o.Device().IsRegularFile()?"SnapshotRuntimeRawReceiptNotAdmitted":"SnapshotRuntimeRawCompletionInterfaceRequired");
    }else if(!o.Device().IsRegularFile())return Fail(e,"SnapshotRuntimeRawReceiptRequired");
    std::vector<std::uint64_t>pins;if(!j.LoadRequiredCheckpointXidsSinceCleanup(pins,&e)||!o.UpdateRequiredCheckpointXids(oid,pins,e,true)||!o.RefreshSessionForRecovery(oid,e))return false;
    auto*s=o.FindSessionStore(oid);if(!s)return Fail(e,"SnapshotRuntimeReplaySession");
    if(s->CheckpointXid()==p.scope.checkpoint_xid){Store::MutationRequest request;request.operation=p.create?Store::MutationOperation::CreateSnapshot:Store::MutationOperation::DeleteSnapshot;
        request.path=L"\\";request.object_id=oid;request.generation=p.scope.checkpoint_xid+1;request.inline_payload=r.inline_payload;request.length=r.inline_payload.size();
        catalog::ContainerMutationPreparationHook prepare;
        const auto result=o.Commit(oid,{request},{},{},{},true,p.scope.checkpoint_xid,prepare,
            [&](const Store&live,std::uint64_t,std::string&why){return VerifyPublishedSnapshot(live,p,why);},p.raw_receipt.has_value());
        if(!result.committed||result.commit_recovery_required||result.commit_status_code!=static_cast<int>(Store::CommitStatus::Committed)){e=result.error;return false;}}
    else if(!VerifyPublishedSnapshot(*s,p,e))return false;
    return Finalize(o,j,oid,tx.accepted_sequence,e);
}
std::optional<bool> ReplaySnapshot(Owner&o,TransactionManager&j,std::uint64_t oid,std::string&e){
    return ReplaySnapshotBound(o,j,oid,nullptr,e);
}
std::optional<bool> ReplaySnapshot(Owner&o,TransactionManager&j,std::uint64_t oid,const RawSnapshotRuntimeReplayParameters& raw,std::string&e){
    return ReplaySnapshotBound(o,j,oid,&raw,e);
}
bool LoadSnapshotRuntimeLiveReferences(const catalog::RandomAccessSource&s,const catalog::AppleCheckpointView&cp,std::uint64_t oid,std::vector<catalog::BtreeRecord>&out,std::string&e){
    out.clear();AppleSnapshotRetentionView retained;
    std::uint64_t store_size=0;
    if(!SnapshotRuntimeStoreSize(cp.container.superblock,store_size)||s.SizeBytes()!=store_size)return Fail(e,"SnapshotRuntimeSourceWindowInvalid");
    const auto current=catalog::LoadAppleCheckpointView(s,0,s.SizeBytes(),e);if(!current)return false;
    if(current->container.superblock.xid==cp.container.superblock.xid){if(!LoadAppleSnapshotRetention(s,cp,retained,e))return false;}
    else {
        std::vector<AppleRecoveryCheckpointView>history;
        if(!LoadAppleSnapshotRecoveryCheckpoints(s,*current,{cp.container.superblock.xid},history,e)||history.empty()||
            history.front().checkpoint.container.superblock_bytes!=cp.container.superblock_bytes)return Fail(e,"SnapshotRuntimeLiveHistoryMismatch");
        const auto*v=Volume(cp,oid);if(!v)return Fail(e,"SnapshotRuntimeLiveVolumeMissing");
        catalog::ApfsSnapshotScope scope{0,s.SizeBytes(),cp.container.superblock.uuid_hex,v->superblock.uuid_hex,oid,cp.container.superblock.xid};
        std::vector<catalog::ApfsSnapshotInfo>inventory;if(!catalog::ApfsSnapshotStore::Enumerate(s,scope,inventory,e))return false;
        for(const auto&i:inventory)retained.identities.push_back(i.identity);
    }
    std::vector<ApplePhysicalExtentRecord>previous,historical;for(const auto&id:retained.identities)if(id.scope.volume_oid==oid){catalog::ApfsSnapshotRecords records;
        if(!catalog::ApfsSnapshotStore::LoadExactResolvedRecords(s,id,records,e)||!ValidateApplePayloadExtentGraph(records.trees.filesystem,records.trees.extentref,cp.container.superblock.block_size,cp.container.superblock.block_count,previous,e))return false;historical.insert(historical.end(),previous.begin(),previous.end());}
    const auto*v=Volume(cp,oid);if(!v||!v->extentref_tree)return Fail(e,"SnapshotRuntimeLiveReferenceMissing");
    auto read=[&](const auto&root,auto&records){catalog::BtreeReadPolicy policy;policy.enforce_object_identity=true;policy.root_object_id=root.object_id;policy.storage_type=root.type;policy.subtype=root.subtype;
        bool physical=(root.type&catalog::kObjectStorageTypeMask)==catalog::kObjectPhysical;
        return catalog::ReadBtreeLeafRecords(s,cp.container.superblock.block_size,root.physical_block,physical,physical?0:v->superblock.omap_oid,cp.container.superblock.xid,policy,records,e);};
    std::vector<catalog::BtreeRecord>fs,refs;std::vector<ApplePhysicalExtentRecord>resolved;if(!read(v->root_tree,fs)||!read(*v->extentref_tree,refs)||
        !ResolveAppleSnapshotExtentLayer(previous,historical,fs,refs,cp.container.superblock.block_size,cp.container.superblock.block_count,resolved,e))return false;
    for(const auto&r:resolved){catalog::BtreeRecord record;if(!EncodeApplePhysicalExtentRecord(r,record,e))return false;out.push_back(std::move(record));}return true;
}
}
