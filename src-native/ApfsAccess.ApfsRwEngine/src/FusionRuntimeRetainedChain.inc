bool FusionImageRuntime::BindRetainedChain(const catalog::FusionBindRequest& request,
    const FusionVolumeSelection& selected,const std::array<std::byte,32>& source,
    const std::wstring& jid,const TransactionManager::RetainedAcceptedHistory& history,std::string& e,
    const FusionContinuationAdmission* continuation)
{
    if((history.coverage!=TransactionManager::RetainedHistoryCoverage::RetainedComplete&&!continuation)||history.pending.size()>1)
        return Fail(e,"FusionRuntimeRetainedChainUnavailable");
    auto first=std::find_if(history.cleaned.begin(),history.cleaned.end(),[&](const auto& row) {
        return row.preimage_checkpoint_xid==request.checkpoint_xid;
    });
    if(first==history.cleaned.end())return Fail(e,"FusionRuntimeSelectorOutsideOriginalChain");
    if(history.cleaned.end()-first>64)return Fail(e,"FusionRuntimeRetainedChainLimit");
    std::vector<std::unique_ptr<FusionPreparedPublication>> chain;
    std::map<std::uint64_t,std::vector<std::byte>> overlay;
    std::size_t proof_bytes=0;
    std::uint64_t target=request.checkpoint_xid;
    const auto load=[&](const TransactionManager::AcceptedTransaction& row,std::unique_ptr<FusionPreparedPublication>& p) {
        // This selector is derived from the held original's Cleaned fence.
        // Pending replay still takes the writable lease and durability barrier.
        const bool cleaned=row.accepted_sequence<=history.watermarks.cleanup_sequence;
        if(!(cleaned?witness_->LoadRetained(row.accepted_sequence,p,e):witness_->Load(row.accepted_sequence,p,e)))return false;
        if(p->accepted_sequence!=row.accepted_sequence||p->source!=source||
            p->jid!=TransactionManager::WideToUtf8(jid)||p->volume!=selected.volume_oid||
            !Match(*p,row,e))return Fail(e,"FusionRuntimeRetainedWitnessMismatch");
        const auto bytes=(p->before.size()+p->plan.before_superblock_writes.size()+p->plan.guard_blocks.size()+3)*4096ull+p->payload.size();
        if(bytes>(64ull<<20)-proof_bytes)return Fail(e,"FusionRuntimeRetainedChainLimit");
        proof_bytes+=static_cast<std::size_t>(bytes);return true;
    };
    for(auto row=first;row!=history.cleaned.end();++row) {
        if(row->preimage_checkpoint_xid!=target||target==UINT64_MAX)return Fail(e,"FusionRuntimeOriginalChainGap");
        std::unique_ptr<FusionPreparedPublication> p;if(!load(*row,p))return false;
        target=p->plan.transaction_xid;chain.push_back(std::move(p));
    }
    if(!history.pending.empty()) {
        if(history.pending.front().preimage_checkpoint_xid!=target)return Fail(e,"FusionRuntimePendingChainGap");
        if(!load(history.pending.front(),recovery_)) {
            if(e!="FusionWitnessMissing")return false;e.clear();
        }
    }
    const auto rewind=[&](const FusionPreparedPublication& p) {
        for(const auto& [block,bytes]:p.before) {
            if(block>UINT64_MAX/4096||bytes.size()!=4096)return Fail(e,"FusionRuntimeRetainedAddressBounds");
            overlay[block*4096]=bytes;
        }
        return true;
    };
    if(recovery_&&!rewind(*recovery_))return false;
    for(auto p=chain.rbegin();p!=chain.rend();++p)if(!rewind(**p))return false;
    if(owner_){if(!owner_->RefreshHeld(request.checkpoint_xid,e,&overlay))return false;}
    else owner_=ApfsFusionImageWriteSession::OpenInternal(request,selected,e,nullptr,&overlay);
    if(!owner_||owner_->SourceBinding()!=source||owner_->JournalIdentity()!=jid)return false;
    if(owner_->store_->Checkpoint().superblock.block_size!=4096)return Fail(e,"FusionRuntime4096ProfileRequired");
    if(!AdoptPrivateOwnership(history,request.checkpoint_xid,e,continuation)||!ValidatePrivateOwnership(e))return false;

    std::map<std::uint64_t,std::vector<std::byte>> final_blocks;
    std::size_t index=0;
    for(auto row=first;row!=history.cleaned.end();++row,++index) {
        const auto& p=*chain[index];
        std::unique_ptr<FusionPreparedPublication> derived;
        const auto& mutation=row->mutations.front();
        if(!Prepare(mutation.operation,mutation.object_id,mutation.logical_offset,mutation.logical_length,
            mutation.inline_payload,mutation.secondary_path_utf8,derived,e,OriginalPlanVersion(mutation.path_utf8))||
            !Match(*derived,*row,e)) {
            const auto detail=owner_->store_->ReadBudget()->Failed()?owner_->store_->ReadBudget()->Failure():e;
            e="FusionRuntimeRetainedDerive:"+std::to_string(row->accepted_sequence)+":"+
                std::to_string(row->preimage_checkpoint_xid)+":"+std::string(detail);
            if(owner_->store_->ReadBudget()->Failed()) {
                const auto used=owner_->store_->ReadBudget()->Consumed();
                e+=":reads="+std::to_string(used.reads)+":readBytes="+std::to_string(used.read_bytes)+
                    ":records="+std::to_string(used.records)+":recordBytes="+std::to_string(used.record_bytes);
            }
            return false;
        }
        // Guards not written by this link must match its independently derived
        // old view. Later links may replace them only through their own plans.
        for(const auto& guard:p.plan.guard_blocks) {
            std::vector<std::byte> actual;
            if(guard.physical_block>UINT64_MAX/4096||guard.bytes.size()!=4096||
                !owner_->store_->Read(guard.physical_block*4096,4096,actual)||actual!=guard.bytes)
                return Fail(e,"FusionRuntimeRetainedGuardChanged");
            final_blocks[guard.physical_block]=guard.bytes;
        }
        std::map<std::uint64_t,std::vector<std::byte>> writes;
        for(const auto& w:p.plan.before_superblock_writes)
            if(!writes.emplace(w.physical_block,w.bytes).second)return Fail(e,"FusionRuntimeRetainedWriteCollision");
        if(!p.plan.fusion_tier2_anchor_write||
            !writes.emplace(p.plan.superblock_write.physical_block,p.plan.superblock_write.bytes).second||
            !writes.emplace(p.plan.fusion_tier2_anchor_write->physical_block,p.plan.fusion_tier2_anchor_write->bytes).second||
            !writes.emplace(0,p.plan.superblock_write.bytes).second||writes.size()!=p.before.size())
            return Fail(e,"FusionRuntimeRetainedAnchorCollision");
        for(const auto& [block,bytes]:writes) {
            std::vector<std::byte> actual;const auto before=p.before.find(block);
            if(block>UINT64_MAX/4096||bytes.size()!=4096||before==p.before.end()||
                !owner_->store_->Read(block*4096,4096,actual)||actual!=before->second)
                return Fail(e,"FusionRuntimeRetainedPreimageChanged");
            overlay[block*4096]=bytes;final_blocks[block]=bytes;
        }
        // Prepare's ComposeFusionVolume already reparses the complete old,
        // new and retained graphs and their allocation through this exact plan.
        // Match pins that proof to the original commitment; do not repeat those
        // walks and charge the same logical materialization a second time.
        if(!owner_->RefreshHeld(p.plan.transaction_xid,e,&overlay))return false;
        TrackPrivateBoundary(*row);
        if(!ValidatePrivateOwnership(e))return false;
    }
    // Verify the final physical state through the same device handles. Only
    // the one original pending plan may differ; its normal redo proves it.
    for(const auto& [block,bytes]:final_blocks) {
        if(recovery_&&recovery_->before.contains(block))continue;
        catalog::FusionRoute route;std::vector<std::byte> actual;
        if(!owner_->Available(e)||!owner_->store_->MapPhysical(block,0,4096,route,e))return false;
        const auto role=route.role==catalog::FusionMemberRole::Main?0u:1u;
        if(!owner_->devices_[role]->ReadForVerification(route.image_offset,4096,actual)||actual!=bytes)
            return Fail(e,"FusionRuntimeRetainedPhysicalMismatch");
    }
    std::map<std::uint64_t,std::vector<std::byte>> pending_before;
    if(recovery_)for(const auto& [block,bytes]:recovery_->before)pending_before.emplace(block*4096,bytes);
    if(!owner_->RefreshHeld(target,e,pending_before.empty()?nullptr:&pending_before)||
        transactions_.ObservedJournalWriterLeaseGeneration()!=history.writer_lease_generation||!owner_->Available(e))return false;
    startup_recovery_=!history.pending.empty()||!retained_files_.empty();
    return !history.pending.empty()||RefreshVolumeInfo(e);
}
