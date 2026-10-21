// Included inside the runtime namespace. All callers hold the original gate.
bool FusionImageRuntime::PrepareMetadata(WriteAheadLog::OperationKind op,std::uint64_t inode,std::uint64_t parent,std::uint64_t replacement,
    std::string_view name,AppleVolumeTransactionRequest& request,std::string& error,PlanVersion version) {
    const bool rename=op==WriteAheadLog::OperationKind::Rename,remove=op==WriteAheadLog::OperationKind::Delete;
    version=NamespaceVersion(version);
    const bool retaining_unlink=version==PlanVersion::UnlinkV6&&remove;
    const bool retain=(version==PlanVersion::PrivateV4&&rename&&replacement)||retaining_unlink;
    if(version==PlanVersion::UnlinkV6&&!retaining_unlink)return Fail(error,"FusionRuntimePrivateIntentUnsupported");
    if(version==PlanVersion::PrivateV4&&!retain&&!remove)return Fail(error,"FusionRuntimePrivateIntentUnsupported");
    if(rename?(name.empty()||name.size()>255||replacement==inode):
        (parent!=0||replacement||(remove&&!name.empty())))return Fail(error,"FusionRuntimeMetadataIntent");
    auto& store=*owner_->store_;const auto& cp=store.Checkpoint();
    auto volumes=catalog::LoadAppleReadOnlyVolumeView(store,cp,error);if(!volumes)return false;
    const auto volume=std::find_if(volumes->volumes.begin(),volumes->volumes.end(),[&](const auto& v){return v.superblock.object_id==owner_->volume_oid_;});
    if(volume==volumes->volumes.end())return Fail(error,"FusionRuntimeVolumeMissing");
    std::vector<catalog::BtreeRecord> records;
    if(!catalog::ReadBtreeLeafRecords(store,4096,volume->root_tree.physical_block,false,volume->superblock.omap_oid,cp.superblock.xid,records,error))return false;
    std::map<std::uint64_t,AppleInodeRecord> inodes;
    for(const auto& raw:records)if(catalog::ReadU64LE(raw.key,0).value_or(0)>>60==3){
        AppleInodeRecord node;if(!ApfsExtendedRecordCodec::DecodeInode(raw,node,error)||!inodes.emplace(node.object_id,node).second)return false;
    }
    auto found=inodes.find(inode);
    if(found==inodes.end())return Fail(error,"FusionRuntimeInodeMissing");
    auto& node=found->second;
    const bool directory=(node.mode&0170000)==0040000;
    const bool private_file=(node.internal_flags&1)!=0;
    if(retaining_unlink&&(private_file||directory))return Fail(error,"FusionRuntimeRetainedRegularFileRequired");
    if(private_file&&(!retained_files_.contains(inode)||node.parent_id!=3||
        !fusion_private::PrimaryNameIs(node,fusion_private::Name(inode,retained_files_.at(inode)))||
        (rename)||(remove&&version!=PlanVersion::PrivateV4)))return Fail(error,"FusionRuntimePrivateOwnershipUnproved");
    if(version==PlanVersion::PrivateV4&&remove&&!private_file)return Fail(error,"FusionRuntimeRetainedFileRequired");
    if(inode<=2||(!directory&&(node.mode&0170000)!=0100000)||node.private_id!=inode||
        (!directory&&node.children_or_links!=1)||node.uncompressed_size>MaxFile)
        return Fail(error,"FusionRuntimeSingleRegularLinkRequired");
    if(!rename&&!remove) {
        std::array<std::uint64_t,4> times{};std::size_t start=0;
        for(auto& time:times){auto end=name.find(':',start);if(end==name.npos)return Fail(error,"FusionRuntimeTimesEncoding");
            auto [at,ec]=std::from_chars(name.data()+start,name.data()+end,time);
            if(ec!=std::errc{}||at!=name.data()+end||end==start)return Fail(error,"FusionRuntimeTimesEncoding");start=end+1;}
        if(start!=name.size())return Fail(error,"FusionRuntimeTimesEncoding");
        std::uint64_t* fields[]={&node.create_time,&node.access_time,&node.modification_time,&node.change_time};
        for(unsigned i=0;i<4;++i)if(times[i]&&times[i]!=UINT64_MAX){
            constexpr std::uint64_t epoch=116444736000000000ull;
            if(times[i]<epoch||times[i]-epoch>UINT64_MAX/100)return Fail(error,"FusionRuntimeTimestampRange");
            *fields[i]=(times[i]-epoch)*100;
        }
    }
    std::map<std::uint64_t,std::uint64_t> links,children,parents;
    const auto policy=ApfsNamePolicy::FromIncompatibleFeatures(volume->superblock.incompatible_features);
    for(const auto& raw:records)if(catalog::ReadU64LE(raw.key,0).value_or(0)>>60==9){
        AppleDirectoryRecord d;if(!ApfsExtendedRecordCodec::DecodeDirectory(raw,policy,d,error))return false;
        ++links[d.file_id];++children[d.parent_id];parents[d.file_id]=d.parent_id;
    }
    const auto old_parent=node.parent_id;
    auto owned=[&](std::uint64_t id) {
        auto it=inodes.find(id);return id>2&&it!=inodes.end()&&it->second.private_id==id&&
            links[id]==1&&parents[id]==it->second.parent_id;
    };
    auto valid_parent=[&](std::uint64_t id) {
        auto it=inodes.find(id);return it!=inodes.end()&&(it->second.mode&0170000)==0040000&&
            it->second.children_or_links>=0&&static_cast<std::uint64_t>(it->second.children_or_links)==children[id];
    };
    if(!owned(inode)||!valid_parent(old_parent)||(directory&&!valid_parent(inode)))return Fail(error,"FusionRuntimeLinkOwnership");
    if(remove&&directory&&children[inode])return Fail(error,"FusionRuntimeDirectoryNotEmpty");
    if(rename){
        if(!valid_parent(parent))return Fail(error,"FusionRuntimeParentMissing");
        if(directory){
            std::set<std::uint64_t> visited;
            for(auto at=parent;at!=2;at=inodes.at(at).parent_id){
                if(at==inode||!visited.insert(at).second)return Fail(error,"FusionRuntimeDirectoryCycle");
                if(!owned(at)||!valid_parent(at))return Fail(error,"FusionRuntimeParentOwnership");
            }
        }
        MetadataStore::DirectoryLink existing;std::wstring wide;
        if(!CanonicalName(name,policy,wide,error))return false;
        const bool exists=owner_->reader_->LookupEntry(parent,wide,existing,error);
        if(!exists&&owner_->reader_->LastStatus()!=FusionReadStatus::NotFound)return false;error.clear();
        if(replacement){
            if(!exists||existing.child_object_id!=replacement||!owned(replacement))return Fail(error,"FusionRuntimeReplacementChanged");
            const auto& victim=inodes.at(replacement);
            if(directory||(victim.mode&0170000)!=0100000||victim.parent_id!=parent||victim.children_or_links!=1||victim.uncompressed_size>MaxFile||
                (victim.internal_flags&1))
                return Fail(error,"FusionRuntimeReplacementProfile");
        } else if(exists&&existing.child_object_id!=inode)return Fail(error,"FusionRuntimeNameCollision");
        if(old_parent!=parent){if(inodes[old_parent].children_or_links<=0||inodes[parent].children_or_links==INT32_MAX)return Fail(error,"FusionRuntimeParentCount");
            --inodes[old_parent].children_or_links;++inodes[parent].children_or_links;node.parent_id=parent;}
        if(replacement){if(inodes[parent].children_or_links<=0)return Fail(error,"FusionRuntimeParentCount");--inodes[parent].children_or_links;}
        if(version==PlanVersion::NamesV5)fusion_private::PrimaryName(node,name);
    }
    if(remove){if(inodes[old_parent].children_or_links<=0)return Fail(error,"FusionRuntimeParentCount");--inodes[old_parent].children_or_links;}
    request={};request.volume_object_id=owner_->volume_oid_;request.required_checkpoint_xids={cp.superblock.xid};
    request.file_count_delta=(remove&&!directory&&!private_file)||replacement?-1:0;request.directory_count_delta=remove&&directory?-1:0;
    std::vector<catalog::BtreeRecord> additions;
    if(retain){
        if(!inodes.contains(3)){
            auto root=inodes.find(2);
            if(root==inodes.end()||root->second.parent_id!=2||root->second.private_id!=2||
                (root->second.mode&0170000)!=0040000||links[2]||children[1])return Fail(error,"FusionRuntimePrivateRootAdmission");
            root->second.parent_id=1;fusion_private::PrimaryName(root->second,"root");
            AppleInodeRecord priv;priv.object_id=priv.private_id=3;priv.parent_id=1;priv.mode=0040700;
            fusion_private::PrimaryName(priv,"private-dir");inodes.emplace(3,std::move(priv));
            catalog::BtreeRecord raw;
            for(const auto id:{2ull,3ull}){
                AppleDirectoryRecord anchor;anchor.parent_id=1;anchor.file_id=id;anchor.flags=4;
                anchor.name_utf8=id==2?"root":"private-dir";
                if(!EncodeAppleDirectoryRecord(anchor,policy,raw,error))return false;additions.push_back(raw);
            }
            request.directory_count_delta=1;
        }
        auto& priv=inodes.at(3);if(priv.children_or_links==INT32_MAX)return Fail(error,"FusionRuntimePrivateDirectoryCapacity");
        ++priv.children_or_links;
        const auto retained_inode=retaining_unlink?inode:replacement;
        auto& victim=inodes.at(retained_inode);victim.parent_id=3;victim.internal_flags|=1;
        const auto orphan_name=fusion_private::Name(retained_inode,cp.superblock.next_xid);
        fusion_private::PrimaryName(victim,orphan_name);
        if(rename)fusion_private::PrimaryName(node,name);
        AppleDirectoryRecord link;link.parent_id=3;link.file_id=retained_inode;link.flags=8;link.name_utf8=orphan_name;
        catalog::BtreeRecord raw;if(!EncodeAppleDirectoryRecord(link,policy,raw,error))return false;additions.push_back(raw);
    }
    for(auto raw:records){
        const auto key=catalog::ReadU64LE(raw.key,0);if(!key)return Fail(error,"FusionRuntimeRecordKey");
        const auto kind=*key>>60,id=*key&((1ull<<60)-1);
        if(kind==9){AppleDirectoryRecord d;if(!ApfsExtendedRecordCodec::DecodeDirectory(raw,policy,d,error))return false;
            if(replacement&&d.file_id==replacement)continue;
            if(d.file_id==inode){if(remove)continue;if(rename){d.parent_id=parent;d.name_utf8=name;if(!EncodeAppleDirectoryRecord(d,policy,raw,error))return false;}}}
        if((remove&&!retaining_unlink&&id==inode)||(replacement&&!retain&&id==replacement)){
            if(kind==8){AppleFileExtentRecord extent;if(!DecodeAppleFileExtentRecord(raw,4096,extent,error)||extent.crypto_id||extent.length_bytes%4096)return Fail(error,"FusionRuntimeDeleteExtent");
                if(extent.physical_block)request.released_data_blocks.push_back({extent.physical_block,extent.length_bytes/4096});}
            else if(kind!=3&&kind!=6)return Fail(error,"FusionRuntimeDeleteExtraOwnership");
            continue;
        }
        if(kind==3&&!EncodeAppleInodeRecord(inodes.at(id),raw,error))return false;
        request.filesystem_records.push_back(std::move(raw));
    }
    if(retain&&request.directory_count_delta==1){
        catalog::BtreeRecord raw;if(!EncodeAppleInodeRecord(inodes.at(3),raw,error))return false;additions.push_back(std::move(raw));
    }
    for(auto& raw:additions)request.filesystem_records.push_back(std::move(raw));
    return true;
}
bool FusionImageRuntime::Rename(std::uint64_t inode,std::uint64_t parent,std::string_view name,std::string& error) {
    return Mutate(WriteAheadLog::OperationKind::Rename,inode,parent,0,{},name,error,{});
}
bool FusionImageRuntime::RenameReplacing(std::uint64_t inode,std::uint64_t parent,std::string_view name,
    std::uint64_t destination,std::string& error,const AppleCheckpointStageHook& hook) {
    if(!destination)return Fail(error,"FusionRuntimeReplacementRequired");
    return Mutate(WriteAheadLog::OperationKind::Rename,inode,parent,destination,{},name,error,hook);
}
bool FusionImageRuntime::Unlink(std::uint64_t inode,std::string& error) {
    return Mutate(WriteAheadLog::OperationKind::Delete,inode,0,0,{},{},error,{});
}
bool FusionImageRuntime::SetTimes(std::uint64_t inode,const std::array<std::uint64_t,4>& times,std::string& error) {
    std::string text;for(auto t:times){text+=std::to_string(t);text+=':';}
    return Mutate(WriteAheadLog::OperationKind::SetBasicInfo,inode,0,0,{},text,error,{});
}
bool FusionImageRuntime::RefreshVolumeInfo(std::string& error) {
    FusionRuntimeVolumeInfo info;auto& store=*owner_->store_;catalog::AppleSpacemanView allocation;
    if(!owner_->reader_->GetNamespaceInfo(info.names,error)||!catalog::LoadFusionSpacemanAllocationView(store,allocation,error))return false;
    auto cp=catalog::LoadAppleReadOnlyVolumeView(store,store.Checkpoint(),error);if(!cp)return false;
    auto volume=std::find_if(cp->volumes.begin(),cp->volumes.end(),[&](const auto& v){return v.superblock.object_id==owner_->volume_oid_;});
    if(volume==cp->volumes.end())return Fail(error,"FusionRuntimeVolumeMissing");
    info.label=volume->superblock.name_utf8;info.checkpoint_xid=cp->container.superblock.xid;
    const auto total=cp->container.superblock.block_count;
    const auto free=allocation.devices[0].free_count+allocation.devices[1].free_count;
    if(total>UINT64_MAX/4096||free>total)return Fail(error,"FusionRuntimeSpaceGeometry");
    info.total_bytes=total*4096;info.free_bytes=free*4096;volume_info_=std::move(info);return true;
}
bool FusionImageRuntime::ReadReady(std::string& error) {
    if(startup_recovery_)return Fail(error,"FusionRuntimeStartupRecoveryRequired");
    if(transactions_.Watermarks().accepted_sequence!=transactions_.Watermarks().cleanup_sequence)return Fail(error,"FusionRuntimePendingRecovery");
    return owner_->Available(error);
}
bool FusionImageRuntime::GetVolumeInfo(FusionRuntimeVolumeInfo& out,std::string& error) {std::lock_guard lock(gate_);if(!ReadReady(error))return false;out=volume_info_;return true;}
bool FusionImageRuntime::GetNamespaceInfo(FusionNamespaceInfo& out,std::string& error) {std::lock_guard lock(gate_);if(!ReadReady(error))return false;out=volume_info_.names;return true;}
bool FusionImageRuntime::GetMetadata(std::uint64_t id,FusionNodeInfo& out,std::string& e) {std::lock_guard lock(gate_);return ReadReady(e)&&owner_->reader_->GetMetadata(id,out,e);}
bool FusionImageRuntime::LookupEntry(std::uint64_t id,std::wstring_view name,MetadataStore::DirectoryLink& out,std::string& e) {std::lock_guard lock(gate_);return ReadReady(e)&&owner_->reader_->LookupEntry(id,name,out,e);}
bool FusionImageRuntime::Enumerate(std::uint64_t id,std::vector<MetadataStore::DirectoryLink>& out,std::string& e) {std::lock_guard lock(gate_);return ReadReady(e)&&owner_->reader_->Enumerate(id,out,e);}
bool FusionImageRuntime::ListXattrs(std::uint64_t id,std::vector<FusionXattrInfo>& out,std::string& e) {std::lock_guard lock(gate_);return ReadReady(e)&&owner_->reader_->ListXattrs(id,out,e);}
bool FusionImageRuntime::ReadXattr(std::uint64_t id,const std::string& name,std::uint64_t offset,std::size_t count,std::vector<std::byte>& out,std::string& e) {std::lock_guard lock(gate_);return ReadReady(e)&&owner_->reader_->ReadXattr(id,name,offset,count,out,e);}
bool FusionImageRuntime::CheckAvailable(std::string& e) {std::lock_guard lock(gate_);return ReadReady(e);}
FusionReadStatus FusionImageRuntime::LastStatus() const {std::lock_guard lock(gate_);return owner_->reader_->LastStatus();}
unsigned FusionImageRuntime::UnavailableMembers() const {std::lock_guard lock(gate_);return owner_->Status().unavailable_members;}
