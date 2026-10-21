#pragma once
#include "InodeMetadataPatch.h"
#include "EncryptedRuntimeProgress.h"

NTSTATUS EncWritableRefresh(enc::State& s)
{
    if(!s.writer || s.cancelled->load()) return STATUS_CANCELLED;
    if(s.session) s.session->Close();
    s.session.reset(); s.read_xid=0;
    EncError error{}; s.session=s.writer->OpenReadView(error);
    if(!s.session) {s.Fail(enc::State::Failure::ReadViewOpenFailure);return STATUS_IO_DEVICE_ERROR;}
    s.read_xid=s.writer->CachedStatus().image.checkpoint_xid;
    const auto status=EncStatus(s,s.session->GetNamespaceInfo(s.names));
    if(!NT_SUCCESS(status))return status;
    if(!EncCacheRootAttributes(s)){s.Fail(enc::State::Failure::RootMetadataFailure);return STATUS_IO_DEVICE_ERROR;}
    return STATUS_SUCCESS;
}

NTSTATUS EncWritableInfo(enc::State& s,enc::Handle& h,FSP_FSCTL_FILE_INFO* info)
{
    if(h.StreamRemoved())return STATUS_FILE_DELETED;
    if(!s.session) {const auto status=EncWritableRefresh(s);if(!NT_SUCCESS(status)) return status;}
    std::shared_ptr<apfsaccess::catalog::ApfsEncryptedReadSession> retained;
    ScopeExit close_retained{[&](){if(retained)retained->Close();}};
    auto* reader=s.session.get();
    if(h.open_entry && h.open_entry->unlinked) {
        if(!h.open_entry->read_inode)return STATUS_FILE_DELETED;
        EncError error{};retained=s.writer->OpenReadView(*h.open_entry->read_inode,error);
        if(!retained)return EncStatus(s,error);
        reader=retained.get();
    }
    const auto status=EncStatus(s,reader->GetMetadata(h.node.inode_id,h.node));
    if(!NT_SUCCESS(status))return status;
    if(h.stream && !h.protocol) {
        enc::Bytes bytes;
        const auto stream_status=EncStatus(s,reader->ReadXattr(h.node.inode_id,h.xattr,bytes));
        if(!NT_SUCCESS(stream_status))return stream_status;
        h.stream_size=bytes.size();
    }
    if(info) EncInfo(h,info);
    return status;
}

class EncRuntimePhases
{
    LatencyTrace* trace=latency_parent_trace;
    std::optional<LatencySpan> phase;
    void Mark(const char* name) noexcept {phase.reset();phase.emplace(trace,name);}
public:
    EncRuntimePhases() noexcept {Mark("encrypted.runtime-before-prepare");}
    bool operator()(std::string_view stage) noexcept
    {
        if(!trace)return true;
        if(stage=="before-encrypted-private-prepare")Mark("encrypted.private-prepare");
        else if(stage=="after-encrypted-private-prepare")Mark("encrypted.witness-preflight");
        else if(stage=="after-encrypted-witness-preflight")Mark("encrypted.original-preflight");
        else if(stage=="after-encrypted-original-preflight")Mark("encrypted.original-accept");
        else if(stage=="after-encrypted-original-accept")Mark("encrypted.witness-publish");
        else if(stage=="before-encrypted-cleanup")Mark("encrypted.original-cleanup");
        else if(stage=="continuation-after-original-spool-barrier")Mark("encrypted.continuation-seal");
        else if(stage=="continuation-after-intent-flush")Mark("encrypted.continuation-candidates");
        else if(stage.starts_with("continuation-after-candidate-"))Mark("encrypted.continuation-candidate-flushed");
        else if(stage.starts_with("continuation-after-old-rename-"))Mark("encrypted.continuation-old-renamed");
        else if(stage.starts_with("continuation-after-new-rename-"))Mark("encrypted.continuation-new-renamed");
        else if(stage=="continuation-after-recovery-barrier")Mark("encrypted.continuation-receipts");
        else if(stage=="continuation-after-completion-receipt")Mark("encrypted.continuation-retire");
        else if(stage=="continuation-after-retirement-receipt")Mark("encrypted.continuation-ready-receipt");
        else if(stage.starts_with("continuation-after-retirement-"))Mark("encrypted.continuation-retire");
        else if(stage.starts_with("continuation-after-control-rename-"))Mark("encrypted.continuation-control-renamed");
        else if(stage=="continuation-after-certificate-promotion")Mark("encrypted.continuation-validate");
        else if(stage=="continuation-after-ready-receipt" || stage=="continuation-after-admission")Mark("encrypted.runtime-before-prepare");
        return true;
    }
};

NTSTATUS EncWritableApply(enc::State& s,const apfsaccess::catalog::EncryptedMutationRequest& request,
    std::uint64_t* result=nullptr)
{
    if(result) *result=0;
    if(!s.writer || s.cancelled->load()) return STATUS_CANCELLED;
    if(s.session) s.session->Close();
    s.session.reset();s.read_xid=0;
    std::string error;std::uint64_t inode=0;
    EncRuntimePhases phases;
    enc::RuntimeProgressObserver progress(s);
    const auto applied=s.writer->Apply(request,inode,error,std::ref(phases),std::ref(progress));
    const auto status=s.writer->CachedStatus();
    if(status.recovery_required || status.closed) {s.Fail(enc::State::Failure::RuntimeApplyDebt);return STATUS_IO_DEVICE_ERROR;}
    const auto refreshed=EncWritableRefresh(s);
    if(!NT_SUCCESS(refreshed)) return refreshed;
    if(!applied) {
        if(error.find("Locked")!=error.npos || error.find("ResourceLimit")!=error.npos)
            return STATUS_INSUFFICIENT_RESOURCES;
        if(error.find("Capacity")!=error.npos || error.find("Exhaust")!=error.npos)
            return STATUS_DISK_FULL;
        return STATUS_NOT_SUPPORTED;
    }
    if(result) *result=inode;
    return STATUS_SUCCESS;
}

NTSTATUS EncWritableParent(enc::State& s,std::wstring_view path,std::uint64_t& parent,std::string& name)
{
    parent=0;enc::Wipe(name);
    const auto last=path.find_last_of(L'\\');
    if(last==path.npos || last+1>=path.size() || path.find(L':')!=path.npos) return STATUS_OBJECT_NAME_INVALID;
    auto encoded=apfsaccess::rw::ApfsNameCodec::EncodeWindowsName(path.substr(last+1));
    if(!encoded.ok()) return STATUS_OBJECT_NAME_INVALID;
    enc::Handle directory;
    const auto status=EncResolve(s,last ? path.substr(0,last) : std::wstring_view(L"\\"),directory);
    if(!NT_SUCCESS(status)) return status;
    if(!directory.node.IsDirectory()) return STATUS_NOT_A_DIRECTORY;
    parent=directory.node.inode_id;name=std::move(*encoded.value);
    return STATUS_SUCCESS;
}

NTSTATUS EncWritableResolveStream(enc::State& s,std::wstring_view path,enc::Handle& h,bool& exists)
{
    exists=false;
    const auto slash=path.find_last_of(L'\\');
    const auto colon=path.find(L':',slash==path.npos ? 0 : slash+1);
    if(colon==path.npos)return STATUS_OBJECT_NAME_INVALID;
    const auto base=path.substr(0,colon);
    auto status=EncResolve(s,base.empty() ? std::wstring_view(L"\\") : base,h);
    if(!NT_SUCCESS(status))return status;
    if(!EncDecodeStream(path.substr(colon),h.xattr))return STATUS_OBJECT_NAME_INVALID;
    h.stream=true;h.protocol=h.xattr.empty();h.writable=!h.protocol;
    const auto pending=s.open_entries.find(h.node.inode_id);
    if(pending!=s.open_entries.end() && pending->second->delete_pending_streams.contains(h.xattr))return STATUS_DELETE_PENDING;
    if(h.protocol){h.stream_size=13;exists=true;return STATUS_SUCCESS;}
    enc::Bytes bytes;
    const auto found=s.session->ReadXattr(h.node.inode_id,h.xattr,bytes);
    if(found==EncError::XattrNotFound)return STATUS_SUCCESS;
    if(found!=EncError::None)return EncStatus(s,found);
    exists=true;h.stream_size=bytes.size();return STATUS_SUCCESS;
}

NTSTATUS EncWritableSetStream(enc::State& s,enc::Handle& h,std::span<const std::byte> bytes,bool remove=false)
{
    if(!EncMutableNodeType(h.node))return STATUS_MEDIA_WRITE_PROTECTED;
    if(!h.stream || h.protocol)return STATUS_MEDIA_WRITE_PROTECTED;
    if(h.StreamRemoved() || (h.open_entry && h.open_entry->unlinked))return STATUS_FILE_DELETED;
    if(bytes.size()>apfsaccess::catalog::EncryptedImageRuntime::MaxEmbeddedXattrBytes)return STATUS_EA_TOO_LARGE;
    apfsaccess::catalog::EncryptedMutationRequest request;
    request.kind=remove ? apfsaccess::catalog::EncryptedMutationKind::RemoveExtendedAttribute
        : apfsaccess::catalog::EncryptedMutationKind::SetExtendedAttribute;
    request.inode=h.node.inode_id;request.name=h.xattr;request.data=bytes;
    const auto status=EncWritableApply(s,request);
    if(NT_SUCCESS(status)){
        h.stream_size=bytes.size();h.stream_removed=remove;
        if(remove && h.open_stream) {
            h.open_stream->removed=true;
            auto found=h.open_entry->streams.find(h.xattr);
            if(found!=h.open_entry->streams.end() && found->second==h.open_stream){
                auto key=h.open_entry->streams.extract(found);enc::Wipe(key.key());
            }
        }
    }
    return status;
}

NTSTATUS EncWritableRegister(enc::State& s,enc::Handle& h)
{
    const auto found=s.open_entries.find(h.node.inode_id);
    if(found!=s.open_entries.end()) {
        if(found->second->delete_pending || found->second->unlinked) return STATUS_DELETE_PENDING;
        if(h.stream && found->second->delete_pending_streams.contains(h.xattr))return STATUS_DELETE_PENDING;
        h.open_entry=found->second;
    } else {
        if(s.open_entries.size()>=65536) return STATUS_INSUFFICIENT_RESOURCES;
        h.open_entry=std::make_shared<enc::OpenEntry>();
        h.open_entry->parent=h.entry_parent;h.open_entry->name=h.entry_name;
        s.open_entries.emplace(h.node.inode_id,h.open_entry);
    }
    if(h.stream && !h.protocol) {
        auto found=h.open_entry->streams.find(h.xattr);
        if(found==h.open_entry->streams.end())found=h.open_entry->streams.emplace(h.xattr,std::make_shared<enc::OpenStream>()).first;
        if(found->second->removed)return STATUS_FILE_DELETED;
        h.open_stream=found->second;
        ++h.open_stream->contexts;++h.open_stream->active_handles;h.stream_active=true;
    }
    ++h.open_entry->handles;
    return STATUS_SUCCESS;
}

bool EncWritableReleaseStream(enc::Handle& h) noexcept
{
    if(!h.stream_active)return true;
    if(!h.open_stream || !h.open_stream->active_handles)return false;
    --h.open_stream->active_handles;h.stream_active=false;
    return true;
}

void EncWritableUnregister(enc::State& s,enc::Handle& h) noexcept
{
    if(!h.open_entry)return;
    auto& entry=*h.open_entry;
    if(!EncWritableReleaseStream(h))s.Fail(enc::State::Failure::StreamActiveCounterUnderflow);
    if(h.open_stream) {
        if(!h.open_stream->contexts)s.Fail(enc::State::Failure::StreamContextCounterUnderflow);
        else --h.open_stream->contexts;
        const auto found=entry.streams.find(h.xattr);
        if(!h.open_stream->contexts && found!=entry.streams.end() && found->second==h.open_stream &&
            !entry.delete_pending_streams.contains(h.xattr)){
            auto key=entry.streams.extract(found);enc::Wipe(key.key());
        }
        h.open_stream.reset();
    }
    if(!entry.handles)s.Fail(enc::State::Failure::OpenContextCounterUnderflow);
    else if(!--entry.handles)s.open_entries.erase(h.node.inode_id);
    h.open_entry.reset();
}

NTSTATUS EncWritableStreamDeletePending(enc::State& s,enc::Handle& h,bool pending)
{
    if(!h.open_entry || !h.stream || h.protocol)return STATUS_CANNOT_DELETE;
    if(h.stream_delete_pending==pending)return STATUS_SUCCESS;
    if(pending) {
        if(!h.open_entry->delete_pending_streams.insert(h.xattr).second)return STATUS_DELETE_PENDING;
        h.stream_delete_pending=true;s.pending_deletes.fetch_add(1);
    } else {
        auto key=h.open_entry->delete_pending_streams.extract(h.xattr);
        if(key.empty())return STATUS_INVALID_DEVICE_STATE;
        enc::Wipe(key.value());
        h.stream_delete_pending=false;s.pending_deletes.fetch_sub(1);
    }
    return STATUS_SUCCESS;
}

NTSTATUS EncWritableDeleteAdmission(enc::State& s,enc::Handle& h)
{
    if(!EncMutableNodeType(h.node))return STATUS_CANNOT_DELETE;
    if(!h.open_entry)return STATUS_CANNOT_DELETE;
    if(h.stream) {
        if(h.protocol)return STATUS_CANNOT_DELETE;
        if(h.StreamRemoved())return STATUS_FILE_DELETED;
        if(!h.open_stream || h.open_stream->active_handles<(h.stream_active ? 1u : 0u))return STATUS_INVALID_DEVICE_STATE;
        return h.open_stream->active_handles>(h.stream_active ? 1u : 0u) ? STATUS_SHARING_VIOLATION : STATUS_SUCCESS;
    }
    if(h.node.inode_id==s.names.root_inode_id) return STATUS_CANNOT_DELETE;
    if(h.node.IsDirectory() && h.open_entry->handles>1) return STATUS_SHARING_VIOLATION;
    const auto status=EncWritableInfo(s,h,nullptr);if(!NT_SUCCESS(status)) return status;
    if(h.node.bsd_flags&2) return STATUS_CANNOT_DELETE;
    if(h.node.IsDirectory()) {
        enc::Entries entries;
        const auto listed=EncStatus(s,s.session->ListDirectory(h.node.inode_id,entries));
        if(!NT_SUCCESS(listed)) return listed;
        if(!entries.empty()) return STATUS_DIRECTORY_NOT_EMPTY;
    }
    return STATUS_SUCCESS;
}

void EncWritableCompleteStreamDeletes(enc::State& s,enc::OpenEntry& entry) noexcept
{
    while(!entry.delete_pending_streams.empty()) {
        auto name=entry.delete_pending_streams.extract(entry.delete_pending_streams.begin());
        const auto stream=entry.streams.find(name.value());
        if(stream!=entry.streams.end())stream->second->removed=true;
        enc::Wipe(name.value());s.pending_deletes.fetch_sub(1);
    }
}

NTSTATUS EncWritableUnlink(enc::State& s,enc::Handle& h)
{
    if(!EncMutableNodeType(h.node))return STATUS_MEDIA_WRITE_PROTECTED;
    if(!h.open_entry)return STATUS_SUCCESS;
    if(h.open_entry->unlinked){s.SetDeletePending(*h.open_entry,false);return STATUS_SUCCESS;}
    if(!h.node.IsDirectory() && !h.open_entry->read_inode) {
        std::string error;
        h.open_entry->read_inode=s.writer->RetainReadInode(h.node.inode_id,error);
        if(!h.open_entry->read_inode)return STATUS_NOT_SUPPORTED;
    }
    apfsaccess::catalog::EncryptedMutationRequest request;
    request.kind=apfsaccess::catalog::EncryptedMutationKind::Unlink;request.inode=h.node.inode_id;
    request.parent=h.open_entry->parent;request.name=h.open_entry->name;
    const auto status=EncWritableApply(s,request);
    if(NT_SUCCESS(status)) {
        s.SetDeletePending(*h.open_entry,false);h.open_entry->unlinked=true;
        EncWritableCompleteStreamDeletes(s,*h.open_entry);
    }
    return status;
}

NTSTATUS EncWritableOpen(FSP_FILE_SYSTEM* fs,PWSTR name,UINT32 options,UINT32 access,PVOID* out,FSP_FSCTL_FILE_INFO* info)
{
    if(out)*out=nullptr;if(info)*info={};
    if(!name || !out || !info) return STATUS_INVALID_PARAMETER;
    if(EncIsCachedRootOpen(fs,name,options,access))return EncCachedRootOpen(fs,out,info);
    return EncCall(fs,"EncryptedWritableOpen",[&](MountContext&,enc::State& s) {
        auto h=std::make_unique<enc::Handle>();
        auto status=EncResolve(s,name,*h);if(!NT_SUCCESS(status)) return status;
        constexpr UINT32 writes=FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES|
            DELETE|WRITE_DAC|WRITE_OWNER|GENERIC_WRITE|GENERIC_ALL;
        if(!EncMutableNodeType(h->node) && ((access&writes) || (options&FILE_DELETE_ON_CLOSE)))return STATUS_MEDIA_WRITE_PROTECTED;
        if(h->stream && h->protocol && ((access&writes) || (options&FILE_DELETE_ON_CLOSE))) return STATUS_MEDIA_WRITE_PROTECTED;
        if((options&FILE_DIRECTORY_FILE) && (!h->node.IsDirectory() || h->stream)) return STATUS_NOT_A_DIRECTORY;
        if((options&FILE_NON_DIRECTORY_FILE) && h->node.IsDirectory() && !h->stream) return STATUS_FILE_IS_A_DIRECTORY;
        status=EncWritableRegister(s,*h);if(!NT_SUCCESS(status)) return status;
        if(options&FILE_DELETE_ON_CLOSE) {
            status=EncWritableDeleteAdmission(s,*h);
            if(!NT_SUCCESS(status)) {
                EncWritableUnregister(s,*h);
                return status;
            }
            if(h->stream){
                status=EncWritableStreamDeletePending(s,*h,true);
                if(!NT_SUCCESS(status)){EncWritableUnregister(s,*h);return status;}
            }
            else s.SetDeletePending(*h->open_entry,true);
        }
        EncInfo(*h,info);*out=h.release();return STATUS_SUCCESS;
    });
}

NTSTATUS EncWritableCreate(FSP_FILE_SYSTEM* fs,PWSTR name,UINT32 options,UINT32,UINT32 attributes,
    PSECURITY_DESCRIPTOR,UINT64,PVOID* out,FSP_FSCTL_FILE_INFO* info)
{
    if(out)*out=nullptr;if(info)*info={};
    if(!name || !out || !info) return STATUS_INVALID_PARAMETER;
    if(attributes&~(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_NORMAL|FILE_ATTRIBUTE_ARCHIVE)) return STATUS_NOT_SUPPORTED;
    return EncCall(fs,"EncryptedWritableCreate",[&](MountContext&,enc::State& s) {
        if(std::wstring_view(name).find(L':')!=std::wstring_view::npos) {
            if(options&FILE_DIRECTORY_FILE)return STATUS_NOT_A_DIRECTORY;
            auto h=std::make_unique<enc::Handle>();bool exists=false;
            auto status=EncWritableResolveStream(s,name,*h,exists);if(!NT_SUCCESS(status))return status;
            if(h->protocol)return STATUS_MEDIA_WRITE_PROTECTED;
            if(exists)return STATUS_OBJECT_NAME_COLLISION;
            if(options&FILE_DELETE_ON_CLOSE) {
                const auto found=s.open_entries.find(h->node.inode_id);
                if(found!=s.open_entries.end()) {
                    const auto stream=found->second->streams.find(h->xattr);
                    if(stream!=found->second->streams.end() && stream->second->active_handles)return STATUS_SHARING_VIOLATION;
                }
            }
            enc::Bytes empty;
            if(h->xattr=="com.apple.FinderInfo")empty.resize(32);
            status=EncWritableSetStream(s,*h,empty);if(!NT_SUCCESS(status))return status;
            status=EncWritableRegister(s,*h);if(!NT_SUCCESS(status))return status;
            if(options&FILE_DELETE_ON_CLOSE){
                status=EncWritableDeleteAdmission(s,*h);
                if(NT_SUCCESS(status))status=EncWritableStreamDeletePending(s,*h,true);
                if(!NT_SUCCESS(status)){EncWritableUnregister(s,*h);return status;}
            }
            EncInfo(*h,info);*out=h.release();return STATUS_SUCCESS;
        }
        std::uint64_t parent=0;std::string leaf;
        ScopeExit wipe{[&](){enc::Wipe(leaf);}};
        auto status=EncWritableParent(s,name,parent,leaf);if(!NT_SUCCESS(status)) return status;
        apfsaccess::catalog::EncryptedDirectoryEntry existing;
        ScopeExit wipe_entry{[&](){enc::Wipe(existing.name_utf8);enc::Wipe(existing.windows_name);}};
        const auto lookup=s.session->Lookup(parent,leaf,existing);
        if(lookup==EncError::None) return STATUS_OBJECT_NAME_COLLISION;
        if(lookup!=EncError::FileNotFound) return EncStatus(s,lookup);
        const bool directory=(options&FILE_DIRECTORY_FILE)!=0;
        apfsaccess::catalog::EncryptedMutationRequest request;
        request.kind=directory ? apfsaccess::catalog::EncryptedMutationKind::MakeDirectory : apfsaccess::catalog::EncryptedMutationKind::Create;
        request.parent=parent;request.name=leaf;request.permissions=directory ? 0777 : 0666;
        std::uint64_t inode=0;status=EncWritableApply(s,request,&inode);if(!NT_SUCCESS(status)) return status;
        auto h=std::make_unique<enc::Handle>();h->node.inode_id=inode;h->entry_parent=parent;h->entry_name=leaf;h->writable=true;
        status=EncWritableInfo(s,*h,info);if(!NT_SUCCESS(status)) return status;
        status=EncWritableRegister(s,*h);if(!NT_SUCCESS(status)) return status;
        if(options&FILE_DELETE_ON_CLOSE) s.SetDeletePending(*h->open_entry,true);
        *out=h.release();return STATUS_SUCCESS;
    });
}

bool PrepareEncryptedWritableMount(MountContext& c,HANDLE parent,const char** failure=nullptr)
{
    using namespace apfsaccess::catalog;
    const auto stage=[&](const char* value){if(failure)*failure=value;};
    stage("Arguments");
    if(!ValidateEncryptedArguments(c.args) || c.args.encrypted.write_root.empty() || c.encrypted ||
        c.metadata_store || c.tx_manager || c.payload_spool || c.native_write_enabled || c.overlay_write_enabled) return false;
    auto owned=std::make_unique<enc::State>();auto& s=*owned;
    try {
        const auto& o=c.args.encrypted;
        EncryptedImageRuntime::Options options;
        options.image={c.args.device,c.args.device_offset_bytes,o.store_size,c.args.volume_object_id,
            o.bag_length==L"includes-header" ? KeybagLength::IncludesHeader : KeybagLength::EntriesOnly};
        options.recovery_directory=o.write_root;
        stage("ExclusiveRuntime");std::string error;
        s.writer=EncryptedImageRuntime::Open(options,error);if(!s.writer)return false;
        s.Watch([&c,parent](){return !g_exit.load() && OwningParentIsAlive(parent) && LifetimeFileExists(c.args);},
            [&c](){return c.active_callback_count.load(std::memory_order_acquire)!=0;});
        enc::State::Operation operation(s);
        stage("ExactSourceSelection");
        if(s.writer->SourceIdentity()!=WideToUtf8(o.source_id) || s.writer->ContainerUuid()!=WideToUtf8(c.args.container_id) ||
            s.writer->VolumeUuid()!=WideToUtf8(o.volume_uuid) || s.writer->VolumeObjectId()!=c.args.volume_object_id ||
            s.writer->CachedStatus().image.checkpoint_xid!=o.checkpoint)return false;
        stage("Credential");
        auto input=GetStdHandle(STD_INPUT_HANDLE);SetStdHandle(STD_INPUT_HANDLE,nullptr);
        auto credential=apfsaccess::transport::ReceiveCredential(input,std::chrono::milliseconds(5000),*s.cancelled);
        if(!credential){stage(apfsaccess::transport::CredentialErrorName(credential.error));return false;}
        stage("Unlock");PasswordUnlockBudget budget;
        const auto unlocked=s.writer->Unlock(credential.bytes,budget,error);credential.bytes.Clear();
        if(!unlocked)return false;
        stage("ExactKeybagSelection");
        const auto selected=s.writer->UnlockedSelection();
        const auto uuid=[](const KeybagUuid& value){return BytesToHexLower(value.data(),value.size());};
        if(!selected || selected->checkpoint_xid!=o.checkpoint || selected->volume_oid!=c.args.volume_object_id ||
            uuid(selected->container_uuid)!=WideToUtf8(c.args.container_id) || uuid(selected->volume_uuid)!=WideToUtf8(o.volume_uuid) ||
            uuid(selected->user_uuid)!=WideToUtf8(o.user_uuid) || selected->container_bag.oid!=o.container_bag_oid ||
            selected->container_bag.xid!=o.container_bag_xid || selected->volume_bag.oid!=o.volume_bag_oid ||
            selected->volume_bag.xid!=o.volume_bag_xid || selected->length!=options.image.keybag_length)return false;
        stage("Namespace");
        if(!NT_SUCCESS(EncWritableRefresh(s)) || !s.Writable())return false;
        s.label=c.args.volume.empty() ? L"APFS encrypted volume" : BuildExplorerVolumeLabel(c.args.volume);
        c.encrypted=std::move(owned);stage(nullptr);return true;
    } catch(...){return false;}
}

const FSP_FILE_SYSTEM_INTERFACE& EncryptedWritableServeInterface()
{
    static const auto iface=[] {
        auto i=EncryptedServeInterface();
        i.GetVolumeInfo=[](FSP_FILE_SYSTEM* fs,FSP_FSCTL_VOLUME_INFO* info)->NTSTATUS {
            if(info)*info={};auto* c=Ctx(fs);
            if(!info || !c || !c->encrypted || !c->encrypted->writer) return STATUS_INVALID_PARAMETER;
            ScopedCallbackActivity activity(c,"EncryptedWritableGetVolumeInfo");
            const auto status=c->encrypted->writer->CachedStatus();
            info->TotalSize=status.image.container_bytes;
            info->FreeSize=status.image.free_space_valid && !status.image.recovery_required && !status.closed
                ? status.image.free_bytes : 0;
            const auto length=(std::min)(c->label.size(),std::size_t{31});
            info->VolumeLabelLength=static_cast<UINT16>(length*sizeof(WCHAR));
            std::memcpy(info->VolumeLabel,c->label.data(),info->VolumeLabelLength);return STATUS_SUCCESS;
        };
        i.Open=EncWritableOpen;i.Create=EncWritableCreate;i.CreateEx=nullptr;i.OverwriteEx=nullptr;
        i.GetFileInfo=[](FSP_FILE_SYSTEM* fs,PVOID handle,FSP_FSCTL_FILE_INFO* info)->NTSTATUS {
            if(info)*info={};if(!handle || !info) return STATUS_INVALID_PARAMETER;
            if(static_cast<enc::Handle*>(handle)->cached_root_observation)return EncGetInfo(fs,handle,info);
            return EncCall(fs,"EncryptedWritableGetInfo",[&](MountContext&,enc::State& s) {
                return EncWritableInfo(s,*static_cast<enc::Handle*>(handle),info);
            });
        };
        i.Write=[](FSP_FILE_SYSTEM* fs,PVOID handle,PVOID buffer,UINT64 offset,ULONG length,BOOLEAN append,
            BOOLEAN constrained,PULONG done,FSP_FSCTL_FILE_INFO* info)->NTSTATUS {
            if(done)*done=0;if(info)*info={};if(!handle || !done || !info || (!buffer && length)) return STATUS_INVALID_PARAMETER;
            if(static_cast<enc::Handle*>(handle)->cached_root_observation)return STATUS_ACCESS_DENIED;
            return EncCall(fs,"EncryptedWritableWrite",[&](MountContext&,enc::State& s) {
                auto& h=*static_cast<enc::Handle*>(handle);
                if(!EncMutableNodeType(h.node))return STATUS_MEDIA_WRITE_PROTECTED;
                if(h.open_entry && h.open_entry->unlinked)return STATUS_FILE_DELETED;
                if(h.stream) {
                    if(h.protocol)return STATUS_MEDIA_WRITE_PROTECTED;
                    if(h.StreamRemoved())return STATUS_FILE_DELETED;
                    enc::Bytes bytes;
                    auto status=EncStatus(s,s.session->ReadXattr(h.node.inode_id,h.xattr,bytes));
                    if(!NT_SUCCESS(status))return status;
                    if(append)offset=bytes.size();
                    const auto count=constrained ? offset>=bytes.size() ? 0 :
                        (std::min<std::size_t>)(length,bytes.size()-static_cast<std::size_t>(offset)) : static_cast<std::size_t>(length);
                    if(!count)return EncWritableInfo(s,h,info);
                    constexpr auto limit=apfsaccess::catalog::EncryptedImageRuntime::MaxEmbeddedXattrBytes;
                    if(offset>limit || count>limit-offset)return STATUS_EA_TOO_LARGE;
                    const auto end=static_cast<std::size_t>(offset)+count;
                    if(end>bytes.size())bytes.resize(end);
                    std::memcpy(bytes.data()+static_cast<std::size_t>(offset),buffer,count);
                    status=EncWritableSetStream(s,h,bytes);if(!NT_SUCCESS(status))return status;
                    *done=static_cast<ULONG>(count);return EncWritableInfo(s,h,info);
                }
                if(h.node.IsDirectory()) return STATUS_FILE_IS_A_DIRECTORY;
                auto status=EncWritableInfo(s,h,nullptr);if(!NT_SUCCESS(status)) return status;
                if(append) offset=h.node.size;
                auto count=static_cast<std::size_t>(length);
                if(constrained) count=offset>=h.node.size ? 0 : static_cast<std::size_t>((std::min<std::uint64_t>)(count,h.node.size-offset));
                if(s.session)s.session->Close();s.session.reset();s.read_xid=0;
                std::size_t completed=0;std::string error;
                EncRuntimePhases phases;
                enc::RuntimeProgressObserver progress(s);
                const auto applied=s.writer->Write(h.node.inode_id,offset,
                    std::span(static_cast<const std::byte*>(buffer),count),completed,error,std::ref(phases),std::ref(progress));
                *done=static_cast<ULONG>(completed);
                if(s.writer->CachedStatus().recovery_required) {s.Fail(enc::State::Failure::RuntimeWriteDebt);return STATUS_IO_DEVICE_ERROR;}
                status=EncWritableRefresh(s);if(!NT_SUCCESS(status)) return status;
                status=EncWritableInfo(s,h,info);if(!NT_SUCCESS(status)) return status;
                return applied || completed ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
            });
        };
        i.SetFileSize=[](FSP_FILE_SYSTEM* fs,PVOID handle,UINT64 size,BOOLEAN allocation,FSP_FSCTL_FILE_INFO* info)->NTSTATUS {
            if(info)*info={};if(!handle || !info) return STATUS_INVALID_PARAMETER;
            if(static_cast<enc::Handle*>(handle)->cached_root_observation)return STATUS_ACCESS_DENIED;
            return EncCall(fs,"EncryptedWritableResize",[&](MountContext&,enc::State& s) {
                auto& h=*static_cast<enc::Handle*>(handle);
                if(!EncMutableNodeType(h.node))return STATUS_MEDIA_WRITE_PROTECTED;
                if(h.open_entry && h.open_entry->unlinked)return STATUS_FILE_DELETED;
                if(h.stream) {
                    if(h.protocol)return STATUS_MEDIA_WRITE_PROTECTED;
                    if(h.StreamRemoved())return STATUS_FILE_DELETED;
                    enc::Bytes bytes;
                    auto status=EncStatus(s,s.session->ReadXattr(h.node.inode_id,h.xattr,bytes));
                    if(!NT_SUCCESS(status))return status;
                    if((!allocation || size<bytes.size()) && size!=bytes.size()) {
                        if(size>apfsaccess::catalog::EncryptedImageRuntime::MaxEmbeddedXattrBytes)return STATUS_EA_TOO_LARGE;
                        bytes.resize(static_cast<std::size_t>(size));
                        status=EncWritableSetStream(s,h,bytes);if(!NT_SUCCESS(status))return status;
                    }
                    return EncWritableInfo(s,h,info);
                }
                if(h.node.IsDirectory()) return STATUS_FILE_IS_A_DIRECTORY;
                auto status=EncWritableInfo(s,h,nullptr);if(!NT_SUCCESS(status)) return status;
                if((!allocation || size<h.node.size) && size!=h.node.size) {
                    apfsaccess::catalog::EncryptedMutationRequest request;
                    request.kind=apfsaccess::catalog::EncryptedMutationKind::Resize;request.inode=h.node.inode_id;request.size=size;
                    status=EncWritableApply(s,request);if(!NT_SUCCESS(status)) return status;
                }
                return EncWritableInfo(s,h,info);
            });
        };
        i.Overwrite=[](FSP_FILE_SYSTEM* fs,PVOID handle,UINT32,BOOLEAN,UINT64,FSP_FSCTL_FILE_INFO* info)->NTSTATUS {
            if(info)*info={};if(!handle || !info) return STATUS_INVALID_PARAMETER;
            if(static_cast<enc::Handle*>(handle)->cached_root_observation)return STATUS_ACCESS_DENIED;
            return EncCall(fs,"EncryptedWritableOverwrite",[&](MountContext&,enc::State& s) {
                auto& h=*static_cast<enc::Handle*>(handle);
                if(!EncMutableNodeType(h.node))return STATUS_MEDIA_WRITE_PROTECTED;
                if(h.open_entry && h.open_entry->unlinked)return STATUS_FILE_DELETED;
                if(h.stream) {
                    enc::Bytes empty;if(h.xattr=="com.apple.FinderInfo")empty.resize(32);
                    const auto status=EncWritableSetStream(s,h,empty);return NT_SUCCESS(status)?EncWritableInfo(s,h,info):status;
                }
                if(h.node.IsDirectory()) return STATUS_FILE_IS_A_DIRECTORY;
                apfsaccess::catalog::EncryptedMutationRequest request;
                request.kind=apfsaccess::catalog::EncryptedMutationKind::Resize;request.inode=h.node.inode_id;
                const auto status=EncWritableApply(s,request);return NT_SUCCESS(status) ? EncWritableInfo(s,h,info) : status;
            });
        };
        i.SetBasicInfo=[](FSP_FILE_SYSTEM* fs,PVOID handle,UINT32 attributes,UINT64 created,UINT64 accessed,
            UINT64 modified,UINT64 changed,FSP_FSCTL_FILE_INFO* info)->NTSTATUS {
            if(info)*info={};if(!handle || !info)return STATUS_INVALID_PARAMETER;
            if(static_cast<enc::Handle*>(handle)->cached_root_observation)return STATUS_ACCESS_DENIED;
            if(attributes!=INVALID_FILE_ATTRIBUTES &&
                (attributes&~(FILE_ATTRIBUTE_NORMAL|FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_DIRECTORY|
                    FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN)))return STATUS_NOT_SUPPORTED;
            return EncCall(fs,"EncryptedWritableSetBasicInfo",[&](MountContext&,enc::State& s) {
                auto& h=*static_cast<enc::Handle*>(handle);if(h.protocol)return STATUS_MEDIA_WRITE_PROTECTED;
                if(!EncMutableNodeType(h.node))return STATUS_MEDIA_WRITE_PROTECTED;
                if(h.open_entry && h.open_entry->unlinked)return STATUS_FILE_DELETED;
                auto status=EncWritableInfo(s,h,nullptr);if(!NT_SUCCESS(status))return status;
                apfsaccess::rw::InodeMetadataPatch patch;
                const auto time=[&](UINT64 value,std::uint64_t current,apfsaccess::rw::InodeMetadataPatch::Field field,std::uint64_t& destination) {
                    if(value && value!=UINT64_MAX && value!=current/100+apfsaccess::rw::InodeMetadataPatch::UnixEpochTicks){
                        patch.mask|=field;destination=value;
                    }
                };
                time(created,h.node.create_time,apfsaccess::rw::InodeMetadataPatch::CreateTime,patch.create_time_utc);
                time(accessed,h.node.access_time,apfsaccess::rw::InodeMetadataPatch::AccessTime,patch.access_time_utc);
                time(modified,h.node.modification_time,apfsaccess::rw::InodeMetadataPatch::ModificationTime,patch.modification_time_utc);
                time(changed,h.node.change_time,apfsaccess::rw::InodeMetadataPatch::ChangeTime,patch.change_time_utc);
                if(attributes!=INVALID_FILE_ATTRIBUTES) {
                    const auto bsd=(h.node.bsd_flags&~0x8002u) |
                        (attributes&FILE_ATTRIBUTE_READONLY ? 2u : 0u) |
                        (attributes&FILE_ATTRIBUTE_HIDDEN ? 0x8000u : 0u);
                    if(bsd!=h.node.bsd_flags){patch.mask|=apfsaccess::rw::InodeMetadataPatch::BsdFlags;patch.bsd_flags=bsd;}
                }
                if(patch.mask) {
                    enc::Bytes bytes;if(!apfsaccess::rw::EncodeInodeMetadataPatch(patch,bytes))return STATUS_INVALID_PARAMETER;
                    apfsaccess::catalog::EncryptedMutationRequest request;
                    request.kind=apfsaccess::catalog::EncryptedMutationKind::SetInodeMetadata;
                    request.inode=h.node.inode_id;request.data=bytes;
                    status=EncWritableApply(s,request);if(!NT_SUCCESS(status))return status;
                }
                return EncWritableInfo(s,h,info);
            });
        };
        i.Rename=[](FSP_FILE_SYSTEM* fs,PVOID handle,PWSTR,PWSTR destination,BOOLEAN replace)->NTSTATUS {
            if(!handle || !destination)return STATUS_INVALID_PARAMETER;
            if(static_cast<enc::Handle*>(handle)->cached_root_observation)return STATUS_ACCESS_DENIED;
            return EncCall(fs,"EncryptedWritableRename",[&](MountContext&,enc::State& s) {
                auto& h=*static_cast<enc::Handle*>(handle);
                if(!EncMutableNodeType(h.node))return STATUS_MEDIA_WRITE_PROTECTED;
                if(h.stream || !h.open_entry || h.node.inode_id==s.names.root_inode_id)return STATUS_NOT_SUPPORTED;
                if(h.open_entry->delete_pending || h.open_entry->unlinked)return STATUS_DELETE_PENDING;
                std::uint64_t parent=0;std::string leaf;
                ScopeExit wipe{[&](){enc::Wipe(leaf);}};
                auto status=EncWritableParent(s,destination,parent,leaf);if(!NT_SUCCESS(status))return status;
                apfsaccess::catalog::EncryptedDirectoryEntry existing;
                ScopeExit wipe_entry{[&](){enc::Wipe(existing.name_utf8);enc::Wipe(existing.windows_name);}};
                const auto lookup=s.session->Lookup(parent,leaf,existing);
                std::shared_ptr<enc::OpenEntry> target;
                if(lookup==EncError::None && existing.inode_id!=h.node.inode_id) {
                    if(!replace)return STATUS_OBJECT_NAME_COLLISION;
                    if(h.node.IsDirectory())return STATUS_NOT_SUPPORTED;
                    apfsaccess::catalog::EncryptedNodeInfo target_info;
                    status=EncStatus(s,s.session->GetMetadata(existing.inode_id,target_info));
                    if(!NT_SUCCESS(status))return status;
                    if(!EncMutableNodeType(target_info))return STATUS_NOT_SUPPORTED;
                    if(target_info.bsd_flags&2)return STATUS_CANNOT_DELETE;
                    const auto found=s.open_entries.find(existing.inode_id);
                    if(found!=s.open_entries.end()) {
                        target=found->second;
                        if(target->delete_pending || target->unlinked)return STATUS_DELETE_PENDING;
                        if(!target->read_inode) {
                            std::string error;target->read_inode=s.writer->RetainReadInode(existing.inode_id,error);
                            if(!target->read_inode)return STATUS_NOT_SUPPORTED;
                        }
                    }
                }
                if(lookup!=EncError::None && lookup!=EncError::FileNotFound)return EncStatus(s,lookup);
                if(parent==h.open_entry->parent && leaf==h.open_entry->name)return STATUS_SUCCESS;
                apfsaccess::catalog::EncryptedMutationRequest request;
                request.kind=replace && lookup==EncError::None && existing.inode_id!=h.node.inode_id
                    ? apfsaccess::catalog::EncryptedMutationKind::ReplaceRename
                    : apfsaccess::catalog::EncryptedMutationKind::Rename;
                request.inode=h.node.inode_id;
                request.parent=h.open_entry->parent;request.name=h.open_entry->name;
                request.destination_parent=parent;request.destination_name=leaf;
                status=EncWritableApply(s,request);if(!NT_SUCCESS(status))return status;
                if(target) {
                    s.SetDeletePending(*target,false);target->unlinked=true;
                    EncWritableCompleteStreamDeletes(s,*target);
                }
                h.open_entry->parent=parent;enc::Wipe(h.open_entry->name);h.open_entry->name=leaf;
                h.entry_parent=parent;enc::Wipe(h.entry_name);h.entry_name=leaf;
                return EncWritableInfo(s,h,nullptr);
            });
        };
        i.CanDelete=[](FSP_FILE_SYSTEM* fs,PVOID handle,PWSTR)->NTSTATUS {
            if(!handle)return STATUS_INVALID_PARAMETER;
            if(static_cast<enc::Handle*>(handle)->cached_root_observation)return STATUS_ACCESS_DENIED;
            return EncCall(fs,"EncryptedWritableCanDelete",[&](MountContext&,enc::State& s) {
                return EncWritableDeleteAdmission(s,*static_cast<enc::Handle*>(handle));
            });
        };
        i.SetDelete=[](FSP_FILE_SYSTEM* fs,PVOID handle,PWSTR,BOOLEAN remove)->NTSTATUS {
            if(!handle)return STATUS_INVALID_PARAMETER;
            if(static_cast<enc::Handle*>(handle)->cached_root_observation)return STATUS_ACCESS_DENIED;
            return EncCall(fs,"EncryptedWritableSetDelete",[&](MountContext&,enc::State& s) {
                auto& h=*static_cast<enc::Handle*>(handle);
                if(!EncMutableNodeType(h.node))return STATUS_MEDIA_WRITE_PROTECTED;
                if(!h.open_entry || h.open_entry->unlinked)return STATUS_DELETE_PENDING;
                if(remove){const auto status=EncWritableDeleteAdmission(s,h);if(!NT_SUCCESS(status))return status;}
                if(h.stream) {
                    return EncWritableStreamDeletePending(s,h,remove!=FALSE);
                } else s.SetDeletePending(*h.open_entry,remove!=FALSE);
                return STATUS_SUCCESS;
            });
        };
        i.Cleanup=[](FSP_FILE_SYSTEM* fs,PVOID handle,PWSTR,ULONG flags) {
            if(!handle)return;
            if(static_cast<enc::Handle*>(handle)->cached_root_observation) {
                auto* c=Ctx(fs);ScopedCallbackActivity activity(c,"EncryptedCachedRootCleanup");
                if((flags&FspCleanupDelete) && c && c->encrypted)c->encrypted->Fail(enc::State::Failure::CachedRootMutationRequested);
                return;
            }
            (void)EncCall(fs,"EncryptedWritableCleanup",[&](MountContext&,enc::State& s) {
                auto& h=*static_cast<enc::Handle*>(handle);
                ScopeExit release_stream{[&](){if(!EncWritableReleaseStream(h))s.Fail(enc::State::Failure::StreamActiveCounterUnderflow);}};
                if(flags&FspCleanupDelete) {
                    if(!EncMutableNodeType(h.node))return STATUS_MEDIA_WRITE_PROTECTED;
                    if(!h.open_entry)return STATUS_INVALID_DEVICE_STATE;
                    if(h.stream) {
                        if(h.StreamRemoved())return STATUS_SUCCESS;
                        auto status=EncWritableStreamDeletePending(s,h,true);
                        if(!NT_SUCCESS(status))return status;
                        status=EncWritableDeleteAdmission(s,h);
                        if(NT_SUCCESS(status))status=EncWritableSetStream(s,h,{},true);
                        if(NT_SUCCESS(status))return EncWritableStreamDeletePending(s,h,false);
                        s.Fail(enc::State::Failure::CleanupRemoveFailure);
                        return status;
                    }
                    if(h.open_entry->unlinked)return STATUS_SUCCESS;
                    s.SetDeletePending(*h.open_entry,true);
                    if(h.open_entry->handles==1 || !h.node.IsDirectory()) return EncWritableUnlink(s,h);
                }
                return STATUS_SUCCESS;
            });
        };
        i.Close=[](FSP_FILE_SYSTEM* fs,PVOID handle) {
            auto* c=Ctx(fs);ScopedCallbackActivity activity(c,"EncryptedWritableClose");
            std::unique_ptr<enc::Handle> h(static_cast<enc::Handle*>(handle));
            if(!c || !c->encrypted || !h || !h->open_entry)return;
            auto& s=*c->encrypted;std::lock_guard lock(s.callbacks);
            auto& entry=*h->open_entry;
            if(!EncWritableReleaseStream(*h))s.Fail(enc::State::Failure::StreamActiveCounterUnderflow);
            if(h->stream_delete_pending && !h->StreamRemoved() && !s.cancelled->load()) {
                try {
                    enc::State::Operation io(s,true);
                    auto status=EncWritableDeleteAdmission(s,*h);
                    if(NT_SUCCESS(status))status=EncWritableSetStream(s,*h,{},true);
                    if(!NT_SUCCESS(status))s.Fail(enc::State::Failure::CloseRemoveFailure);
                    else (void)EncWritableStreamDeletePending(s,*h,false);
                } catch(...){s.Fail(enc::State::Failure::CloseOperationException);}
            }
            if(entry.handles==1 && entry.delete_pending && !entry.unlinked && !s.cancelled->load()) {
                try {
                    enc::State::Operation io(s,true);
                    if(!NT_SUCCESS(EncWritableUnlink(s,*h)))s.Fail(enc::State::Failure::CloseUnlinkFailure);
                } catch(...) {s.Fail(enc::State::Failure::CloseOperationException);}
            }
            EncWritableUnregister(s,*h);
        };
        i.Flush=[](FSP_FILE_SYSTEM* fs,PVOID handle,FSP_FSCTL_FILE_INFO* info)->NTSTATUS {
            if(handle && static_cast<enc::Handle*>(handle)->cached_root_observation) {
                ScopedCallbackActivity activity(Ctx(fs),"EncryptedCachedRootFlush");
                FSP_FSCTL_FILE_INFO ignored{};return EncCachedRootInfo(fs,info ? info : &ignored);
            }
            return EncCall(fs,"EncryptedWritableFlush",[&](MountContext&,enc::State& s) {
                const auto status=s.writer->CachedStatus();
                if(status.recovery_required || status.accepted!=status.durable || status.durable!=status.cleaned) return STATUS_IO_DEVICE_ERROR;
                return handle && info ? EncWritableInfo(s,*static_cast<enc::Handle*>(handle),info) : STATUS_SUCCESS;
            });
        };
        return i;
    }();
    return iface;
}
