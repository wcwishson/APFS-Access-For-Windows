void FusionImageRuntime::TrackPrivateBoundary(const TransactionManager::AcceptedTransaction& original)
{
    if(original.mutations.size()!=1)return;
    const auto& m=original.mutations.front();
    const auto version=NamespaceVersion(OriginalPlanVersion(m.path_utf8));
    if(version==PlanVersion::UnlinkV6&&m.operation==WriteAheadLog::OperationKind::Delete){
        retained_files_[m.object_id]=original.preimage_checkpoint_xid+1;return;
    }
    if(version!=PlanVersion::PrivateV4)return;
    if(m.operation==WriteAheadLog::OperationKind::Rename&&m.logical_length)
        retained_files_[m.logical_length]=original.preimage_checkpoint_xid+1;
    else if(m.operation==WriteAheadLog::OperationKind::Delete)retained_files_.erase(m.object_id);
}

bool FusionImageRuntime::AdoptPrivateOwnership(const TransactionManager::RetainedAcceptedHistory& history,
    std::uint64_t xid,std::string& error,const FusionContinuationAdmission* continuation)
{
    retained_files_.clear();
    if(continuation){
        if(xid<continuation->base_xid)return Fail(error,"FusionContinuationPrivateBaselineXid");
        retained_files_=continuation->private_files;
    }
    for(const auto& row:history.cleaned){
        if(row.preimage_checkpoint_xid>=xid||row.mutations.size()!=1)continue;
        const auto version=NamespaceVersion(OriginalPlanVersion(row.mutations.front().path_utf8));
        if(version!=PlanVersion::PrivateV4&&version!=PlanVersion::UnlinkV6)continue;
        if(history.coverage!=TransactionManager::RetainedHistoryCoverage::RetainedComplete&&!continuation)
            return Fail(error,"FusionRuntimePrivateHistoryUnavailable");
        std::unique_ptr<FusionPreparedPublication> proof;
        const bool cleaned=row.accepted_sequence<=history.watermarks.cleanup_sequence;
        if(!(cleaned?witness_->LoadRetained(row.accepted_sequence,proof,error):witness_->Load(row.accepted_sequence,proof,error))||!Match(*proof,row,error)||
            proof->source!=owner_->source_binding_||proof->jid!=TransactionManager::WideToUtf8(owner_->journal_identity_))
            return Fail(error,"FusionRuntimePrivateOriginalMismatch");
        TrackPrivateBoundary(row);
    }
    return true;
}

bool FusionImageRuntime::ValidatePrivateOwnership(std::string& error)
{
    std::map<std::uint64_t,std::string> actual;
    if(!owner_->reader_->PrivateFiles(actual,error)||actual.size()!=retained_files_.size())
        return Fail(error,"FusionRuntimePrivateOwnershipUnproved");
    for(const auto& [id,xid]:retained_files_)
        if(!actual.contains(id)||actual.at(id)!=fusion_private::Name(id,xid))
            return Fail(error,"FusionRuntimePrivateOwnershipUnproved");
    return true;
}

bool FusionImageRuntime::RenameRetainingDestination(std::uint64_t inode,std::uint64_t parent,std::string_view name,
    std::uint64_t destination,std::string& error,const AppleCheckpointStageHook& hook)
{
    if(!destination)return Fail(error,"FusionRuntimeReplacementRequired");
    return Mutate(WriteAheadLog::OperationKind::Rename,inode,parent,destination,{},name,error,hook,nullptr,PlanVersion::PrivateV8);
}

bool FusionImageRuntime::HasRetainedFile(std::uint64_t inode) const
{
    std::lock_guard lock(gate_);return retained_files_.contains(inode);
}

bool FusionImageRuntime::ReleaseRetainedFile(std::uint64_t inode,std::string& error,const AppleCheckpointStageHook& hook)
{
    return Mutate(WriteAheadLog::OperationKind::Delete,inode,0,0,{},{},error,hook,nullptr,PlanVersion::PrivateV8);
}

bool FusionImageRuntime::UnlinkRetainingFile(std::uint64_t inode,std::string& error,const AppleCheckpointStageHook& hook)
{
    return Mutate(WriteAheadLog::OperationKind::Delete,inode,0,0,{},{},error,hook,nullptr,PlanVersion::UnlinkV8);
}

