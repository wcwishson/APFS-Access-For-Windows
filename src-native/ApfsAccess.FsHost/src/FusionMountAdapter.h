#pragma once
// Actual immutable callbacks inside the existing FsHost dispatcher/lifecycle.
NTSTATUS FusionStatus(fusion_mount::State& s,bool ok) {
    if(ok)return STATUS_SUCCESS;
    if(s.cancelled->load())return STATUS_CANCELLED;
    s.missing_members=s.UnavailableMembers();
    using E=apfsaccess::rw::FusionReadStatus;
    switch(s.LastStatus()) {
    case E::NotFound:return STATUS_OBJECT_NAME_NOT_FOUND;
    case E::NotRegularFile:return STATUS_INVALID_DEVICE_REQUEST;
    case E::RangeLimit:case E::ResourceLimit: {
        std::string error;
        if(s.CheckAvailable(error))return STATUS_INSUFFICIENT_RESOURCES;
        s.missing_members=s.UnavailableMembers();s.failed=true;s.Cancel();return STATUS_IO_DEVICE_ERROR;
    }
    default:s.failed=true;s.Cancel();return STATUS_IO_DEVICE_ERROR;
    }
}
template<class F> NTSTATUS FusionCall(FSP_FILE_SYSTEM* fs,const char* operation,F&& call,
    PVOID* created_handle=nullptr,FSP_FSCTL_FILE_INFO* created_info=nullptr) {
    auto* c=Ctx(fs);
    if(!c || !c->fusion)return STATUS_INVALID_DEVICE_STATE;
    auto& s=*c->fusion;
    try {
        // Only the main loop uses this operation, before session locks are held.
        if(std::strcmp(operation,"FusionHealth")==0&&
            c->active_callback_count.load(std::memory_order_acquire)==0&&s.status_dirty.exchange(false))
            if(!WriteHostStatusFile(*c)||c->callback_status_publish_pending.load(std::memory_order_acquire))
                s.status_dirty=true;
        ScopedCallbackActivity activity(c,operation);
        std::lock_guard lock(s.serial);
        bool returned=false;
        ScopeExit discard{[&](){if(!returned)fusion_mount::DiscardUnpublishedHandle(s,created_handle,created_info);}};
        if(s.cancelled->load())return STATUS_CANCELLED;
        fusion_mount::State::Operation io(s);
        if(!s.session&&!s.writer)return STATUS_INVALID_DEVICE_STATE;
        std::string error;
        auto status=FusionStatus(s,s.CheckAvailable(error));
        if(!NT_SUCCESS(status))return status;
        status=call(*c,s);
        if(!NT_SUCCESS(status) && s.writer) {
            s.Failure(operation,status);
            std::cerr << "[FsHost] " << operation << " status=" << std::hex << status << std::dec
                << " reason=" << s.error << std::endl;
        }
        // Include cached/EOF/zero reads and bounded directory/stream publication.
        if(NT_SUCCESS(status) && !s.CheckAvailable(error)) status=FusionStatus(s,false);
        if(s.cancelled->load() && NT_SUCCESS(status))return STATUS_CANCELLED;
        returned=NT_SUCCESS(status);
        return status;
    } catch(...) {s.failed=true;s.Cancel();return STATUS_IO_DEVICE_ERROR;}
}
void FusionInfo(const fusion_mount::Handle& h, FSP_FSCTL_FILE_INFO* info)
{
    *info={};
    info->FileAttributes=(h.writable?0:FILE_ATTRIBUTE_READONLY) |
        (h.node.IsDirectory() && !h.stream ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_ARCHIVE);
    info->FileSize=h.stream ? h.stream_size : h.node.size;
    info->AllocationSize=h.stream ? (h.stream_size>UINT64_MAX-4095 ? h.stream_size : (h.stream_size+4095)/4096*4096) : h.node.allocated_size;
    info->IndexNumber=h.node.inode_id;
    // WinFsp reserves this field and synthesizes its own Windows link count.
    info->HardLinks=0;
    // The shared strict projector already converts APFS nanoseconds to FILETIME.
    const auto time=[](std::uint64_t ticks) { return ticks; };
    info->CreationTime=time(h.node.create_time); info->LastAccessTime=time(h.node.access_time);
    info->LastWriteTime=time(h.node.modification_time); info->ChangeTime=time(h.node.change_time);
}
NTSTATUS FusionResolve(fusion_mount::State& s, std::wstring_view path, fusion_mount::Handle& h)
{
    if(path.empty() || path.size()>32768 || path.front()!=L'\\' || path.find(L'/')!=path.npos)
        return STATUS_OBJECT_NAME_INVALID;
    std::string error;
    auto id=s.names.root_inode_id;
    h.writable=s.Writable();auto status=FusionStatus(s,s.GetMetadata(id,h.node,error));
    if(!NT_SUCCESS(status)) return status;
    for(std::size_t at=1; at<path.size();) {
        auto end=path.find(L'\\',at); if(end==path.npos) end=path.size();
        auto part=path.substr(at,end-at);
        if(part.empty()) return STATUS_OBJECT_NAME_INVALID;
        if(!h.node.IsDirectory()) return STATUS_NOT_A_DIRECTORY;
        if(part==L"..") id=h.node.parent_id;
        else if(part!=L".") {
            // Stream syntax exists only on the last component; projected APFS
            // colons are escaped by ApfsNameCodec, so cannot collide here.
            const auto colon=part.find(L':');
            if(colon!=part.npos) {
                if(end!=path.size()) return STATUS_OBJECT_NAME_INVALID;
                auto stream=std::wstring(part.substr(colon));
                ScopeExit wipe_stream{[&](){encrypted_mount::Wipe(stream);}};
                if(stream!=L"::$DATA") {
                    if(!EncDecodeStream(stream,h.xattr)) return STATUS_OBJECT_NAME_INVALID;
                    h.stream=true; h.protocol=h.xattr.empty();
                }
                part=part.substr(0,colon);
            }
            // Stream-bearing dot components still identify their directory.
            if(part==L"." || (part.empty() && at==1 && colon==0)) { /* current/root stream */ }
            else if(part==L"..") id=h.node.parent_id;
            else {
                apfsaccess::rw::MetadataStore::DirectoryLink entry;
                status=FusionStatus(s,s.LookupEntry(id,part,entry,error));
                if(!NT_SUCCESS(status)) return status;
                id=entry.child_object_id;h.entry_parent=entry.parent_object_id;h.sibling=entry.sibling_id;
            }
        }
        status=FusionStatus(s,s.GetMetadata(id,h.node,error));
        if(!NT_SUCCESS(status)) return status;
        at=end+1;
    }
    if(h.stream) {
        if(h.protocol) h.stream_size=13; // APFS-XATTR/1\n
        else {
            std::vector<apfsaccess::rw::FusionXattrInfo> attrs;
            status=FusionStatus(s,s.ListXattrs(id,attrs,error));
            if(!NT_SUCCESS(status)) return status;
            const auto it=std::find_if(attrs.begin(),attrs.end(),[&](const auto& x){return x.name_utf8==h.xattr;});
            if(it==attrs.end())return STATUS_OBJECT_NAME_NOT_FOUND;
            h.stream_size=it->size;
        }
    }
    return STATUS_SUCCESS;
}
NTSTATUS FusionOpen(FSP_FILE_SYSTEM* fs,PWSTR name,UINT32 options,UINT32 access,PVOID* out,FSP_FSCTL_FILE_INFO* info)
{
    if(out) *out=nullptr; if(info) *info={};
    if(!name || !out || !info) return STATUS_INVALID_PARAMETER;
    constexpr UINT32 writes=FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES|
        DELETE|WRITE_DAC|WRITE_OWNER|GENERIC_WRITE|GENERIC_ALL;
    return FusionCall(fs,"FusionOpen",[&](MountContext&,fusion_mount::State& s) {
        if(((access&writes)||(options&FILE_DELETE_ON_CLOSE))&&!s.Writable())return STATUS_MEDIA_WRITE_PROTECTED;
        auto h=std::make_unique<fusion_mount::Handle>();
        auto status=FusionResolve(s,name,*h); if(!NT_SUCCESS(status)) return status;
        const bool directory=h->node.IsDirectory() && !h->stream;
        if(((access&writes)||(options&FILE_DELETE_ON_CLOSE))&&h->stream)return STATUS_NOT_SUPPORTED;
        if((options&FILE_DELETE_ON_CLOSE)&&directory&&h->node.children_or_links)return STATUS_DIRECTORY_NOT_EMPTY;
        if((options&FILE_DELETE_ON_CLOSE)&&h->node.inode_id<=2)return STATUS_CANNOT_DELETE;
        if((options&FILE_DIRECTORY_FILE) && !directory) return STATUS_NOT_A_DIRECTORY;
        if((options&FILE_NON_DIRECTORY_FILE) && directory) return STATUS_FILE_IS_A_DIRECTORY;
        ++s.open_counts[h->node.inode_id];FusionInfo(*h,info); *out=h.release(); return STATUS_SUCCESS;
    },out,info);
}
NTSTATUS FusionGetInfo(FSP_FILE_SYSTEM* fs,PVOID context,FSP_FSCTL_FILE_INFO* info)
{
    if(info) *info={}; if(!context || !info) return STATUS_INVALID_PARAMETER;
    return FusionCall(fs,"FusionGetFileInfo",[&](MountContext&,fusion_mount::State& s) {
        auto& h=*static_cast<fusion_mount::Handle*>(context);std::string error;
        if(!h.deleted&&!s.GetMetadata(h.node.inode_id,h.node,error))return FusionStatus(s,false);
        FusionInfo(h,info); return STATUS_SUCCESS;
    });
}
NTSTATUS FusionRead(FSP_FILE_SYSTEM* fs,PVOID context,PVOID buffer,UINT64 offset,ULONG length,PULONG done)
{
    if(done) *done=0;
    if(!context || !done || (!buffer && length)) return STATUS_INVALID_PARAMETER;
    auto* h=static_cast<fusion_mount::Handle*>(context);
    const auto result=FusionCall(fs,"FusionRead",[&](MountContext&,fusion_mount::State& s) {
        std::string error;
        if(s.writer&&!s.GetMetadata(h->node.inode_id,h->node,error))return FusionStatus(s,false);
        if(h->node.IsDirectory() && !h->stream) return STATUS_FILE_IS_A_DIRECTORY;
        const auto size=h->stream ? h->stream_size : h->node.size;
        if(!length) return STATUS_SUCCESS;
        if(offset>=size) return STATUS_END_OF_FILE;
        const auto count=static_cast<std::size_t>((std::min<std::uint64_t>)(
            (std::min<std::uint64_t>)(length,1024*1024),size-offset));
        std::vector<std::byte> bytes;
        NTSTATUS status=STATUS_SUCCESS;
        if(h->protocol) {
            constexpr std::string_view protocol="APFS-XATTR/1\n";
            bytes.assign(reinterpret_cast<const std::byte*>(protocol.data()+offset),reinterpret_cast<const std::byte*>(protocol.data()+offset+count));
        } else if(h->stream) status=FusionStatus(s,s.ReadXattr(h->node.inode_id,h->xattr,offset,count,bytes,error));
        else status=FusionStatus(s,s.ReadFile(h->node.inode_id,offset,count,bytes,error));
        if(!NT_SUCCESS(status)) return status;
        if(s.cancelled->load()) return STATUS_CANCELLED;
        if(bytes.size()!=count) {s.failed=true;s.Cancel();return STATUS_IO_DEVICE_ERROR;}
        std::memcpy(buffer,bytes.data(),count);
        *done=static_cast<ULONG>(count); return STATUS_SUCCESS;
    });
    if(!NT_SUCCESS(result)) {if(buffer && *done)SecureZeroMemory(buffer,*done);*done=0;}
    return result;
}
NTSTATUS FusionSecurity(FSP_FILE_SYSTEM* fs,PVOID context,PSECURITY_DESCRIPTOR sd,SIZE_T* size)
{
    if(!context || !size) return STATUS_INVALID_PARAMETER;
    return FusionCall(fs,"FusionGetSecurity",[&](MountContext& c,fusion_mount::State&) {
        const auto supplied=*size; *size=c.sd_size;
        if(supplied<c.sd_size) return STATUS_BUFFER_OVERFLOW;
        if(sd && c.sd_size) std::memcpy(sd,c.sd,c.sd_size);
        return STATUS_SUCCESS;
    });
}
NTSTATUS FusionSecurityByName(FSP_FILE_SYSTEM* fs,PWSTR name,PUINT32 attrs,PSECURITY_DESCRIPTOR sd,SIZE_T* size)
{
    if(!name) return STATUS_INVALID_PARAMETER;
    return FusionCall(fs,"FusionGetSecurityByName",[&](MountContext& c,fusion_mount::State& s) {
        fusion_mount::Handle h; const auto status=FusionResolve(s,name,h); if(!NT_SUCCESS(status)) return status;
        FSP_FSCTL_FILE_INFO info; FusionInfo(h,&info); if(attrs) *attrs=info.FileAttributes;
        if(size) { const auto supplied=*size; *size=c.sd_size;
            if(supplied<c.sd_size) return STATUS_BUFFER_OVERFLOW;
            if(sd && c.sd_size) std::memcpy(sd,c.sd,c.sd_size); }
        return STATUS_SUCCESS;
    });
}
NTSTATUS FusionDirectory(FSP_FILE_SYSTEM* fs,PVOID context,PWSTR,PWSTR marker,PVOID buffer,ULONG length,PULONG done)
{
    if(done) *done=0; if(!context || !done || !buffer) return STATUS_INVALID_PARAMETER;
    const auto result=FusionCall(fs,"FusionReadDirectory",[&](MountContext& c,fusion_mount::State& s) {
        std::string error;
        if(!c.api.AddDir) return STATUS_INVALID_DEVICE_STATE;
        auto& h=*static_cast<fusion_mount::Handle*>(context); std::lock_guard lock(h.mutex);
        if(s.writer&&!s.GetMetadata(h.node.inode_id,h.node,error))return FusionStatus(s,false);
        if(!h.node.IsDirectory() || h.stream) return STATUS_NOT_A_DIRECTORY;
        if(!h.enumerated || !marker || (s.writer&&h.enumeration_xid!=s.checkpoint.load())) {
            h.entries.clear(); h.enumerated=false; h.cursor=0;
            const auto status=FusionStatus(s,s.Enumerate(h.node.inode_id,h.entries,error));
            if(!NT_SUCCESS(status)) return status;
            // Markers are exact returned Windows names. Keep the APFS ordering.
            h.enumerated=true;h.enumeration_xid=s.checkpoint.load();
        }
        std::size_t index=0;
        if(marker) {
            if(std::wstring_view(marker)==L".") index=1;
            else if(std::wstring_view(marker)==L"..") index=2;
            else {
                const auto it=std::find_if(h.entries.begin(),h.entries.end(),[&](const auto& e){return e.entry_name==marker;});
                if(it==h.entries.end()) return STATUS_OBJECT_NAME_NOT_FOUND;
                index=static_cast<std::size_t>(it-h.entries.begin())+3;
            }
        }
        for(;index<h.entries.size()+2;++index) {
            const std::wstring_view name=index==0?std::wstring_view(L"."):index==1?std::wstring_view(L".."):
                std::wstring_view(h.entries[index-2].entry_name);
            const auto id=index==0?h.node.inode_id:index==1?h.node.parent_id:h.entries[index-2].child_object_id;
            fusion_mount::Handle entry;entry.writable=s.Writable();const auto status=FusionStatus(s,s.GetMetadata(id,entry.node,error));
            if(!NT_SUCCESS(status)) return status;
            std::vector<std::byte> storage; storage.resize(sizeof(FSP_FSCTL_DIR_INFO)+name.size()*sizeof(WCHAR));
            auto* di=reinterpret_cast<FSP_FSCTL_DIR_INFO*>(storage.data());
            if(storage.size()>UINT16_MAX)return STATUS_OBJECT_NAME_INVALID;
            di->Size=static_cast<UINT16>(storage.size()); FusionInfo(entry,&di->FileInfo);
            std::memcpy(di->FileNameBuf,name.data(),name.size()*sizeof(WCHAR));
            if(!c.api.AddDir || !c.api.AddDir(di,buffer,length,done)) { h.cursor=index; return STATUS_SUCCESS; }
        }
        h.cursor=index; c.api.AddDir(nullptr,buffer,length,done); return STATUS_SUCCESS;
    });
    if(!NT_SUCCESS(result)) { SecureZeroMemory(buffer,*done); *done=0; }
    return result;
}
NTSTATUS FusionStreams(FSP_FILE_SYSTEM* fs,PVOID context,PVOID buffer,ULONG length,PULONG done)
{
    if(done) *done=0; if(!context || !buffer || !done) return STATUS_INVALID_PARAMETER;
    const auto result=FusionCall(fs,"FusionGetStreamInfo",[&](MountContext& c,fusion_mount::State& s) {
        if(!c.api.AddStream) return STATUS_INVALID_DEVICE_STATE;
        auto& h=*static_cast<fusion_mount::Handle*>(context);
        std::string error;
        std::vector<apfsaccess::rw::FusionXattrInfo> attrs; const auto status=FusionStatus(s,s.ListXattrs(h.node.inode_id,attrs,error));
        if(!NT_SUCCESS(status)) return status;
        const auto add=[&](std::wstring name,std::uint64_t size) {
            ScopeExit wipe{[&](){encrypted_mount::Wipe(name);}};
            auto bare=std::wstring_view(name).substr(1,name.size()-7);
            std::vector<std::byte> storage; storage.resize(sizeof(FSP_FSCTL_STREAM_INFO)+bare.size()*sizeof(WCHAR));
            if(storage.size()>UINT16_MAX) return false;
            auto* si=reinterpret_cast<FSP_FSCTL_STREAM_INFO*>(storage.data()); si->Size=static_cast<UINT16>(storage.size());
            si->StreamSize=size; si->StreamAllocationSize=size>UINT64_MAX-4095 ? size : (size+4095)/4096*4096;
            std::memcpy(si->StreamNameBuf,bare.data(),bare.size()*sizeof(WCHAR));
            return c.api.AddStream && c.api.AddStream(si,buffer,length,done);
        };
        if(!h.node.IsDirectory() && !add(L"::$DATA",h.node.size)) return STATUS_BUFFER_OVERFLOW;
        for(const auto& x:attrs) if(!add(EncStreamName(x.name_utf8),x.size)) return STATUS_BUFFER_OVERFLOW;
        if(!c.api.AddStream || !c.api.AddStream(nullptr,buffer,length,done)) return STATUS_BUFFER_OVERFLOW;
        return STATUS_SUCCESS;
    });
    if(!NT_SUCCESS(result)) { SecureZeroMemory(buffer,*done); *done=0; }
    return result;
}

#include "FusionWritableCallbacks.h"
const FSP_FILE_SYSTEM_INTERFACE& FusionServeInterface()
{
    static const auto iface=[] {
        FSP_FILE_SYSTEM_INTERFACE i{};
        i.GetVolumeInfo=[](FSP_FILE_SYSTEM* fs,FSP_FSCTL_VOLUME_INFO* v)->NTSTATUS {
            if(!v) return STATUS_INVALID_PARAMETER;
            return FusionCall(fs,"FusionGetVolumeInfo",[&](MountContext& c,fusion_mount::State& s) {
                *v={};v->TotalSize=s.total_bytes.load();v->FreeSize=s.free_bytes.load();
                auto label=c.label.substr(0,31); ScopeExit wipe{[&](){encrypted_mount::Wipe(label);}};
                v->VolumeLabelLength=static_cast<UINT16>(label.size()*sizeof(WCHAR));
                std::memcpy(v->VolumeLabel,label.data(),v->VolumeLabelLength); return STATUS_SUCCESS;
            });
        };
        i.SetVolumeLabel=[](FSP_FILE_SYSTEM*,PWSTR,FSP_FSCTL_VOLUME_INFO*)->NTSTATUS {return STATUS_MEDIA_WRITE_PROTECTED;};
        i.Open=FusionOpen; i.Read=FusionRead; i.GetFileInfo=FusionGetInfo;
        i.Flush=[](FSP_FILE_SYSTEM* fs,PVOID h,FSP_FSCTL_FILE_INFO* info)->NTSTATUS {
            if(h) return FusionGetInfo(fs,h,info);
            return FusionCall(fs,"FusionFlushVolume",[](MountContext&,fusion_mount::State&){return STATUS_SUCCESS;});
        };
        i.GetSecurity=FusionSecurity; i.GetSecurityByName=FusionSecurityByName;
        i.ReadDirectory=FusionDirectory; i.GetStreamInfo=FusionStreams;
        i.Cleanup=FusionCleanup;
        i.Close=[](FSP_FILE_SYSTEM* fs,PVOID context) { ScopedCallbackActivity activity(Ctx(fs),"FusionClose");
            auto* h=static_cast<fusion_mount::Handle*>(context);auto* c=Ctx(fs);
            if(h&&c&&c->fusion&&!h->cleaned){std::lock_guard lock(c->fusion->serial);auto it=c->fusion->open_counts.find(h->node.inode_id);if(it!=c->fusion->open_counts.end()&&!--it->second)c->fusion->open_counts.erase(it);}delete h; };
        i.Create=[](FSP_FILE_SYSTEM*,PWSTR,UINT32,UINT32,UINT32,PSECURITY_DESCRIPTOR,UINT64,PVOID* h,FSP_FSCTL_FILE_INFO*)->NTSTATUS { if(h)*h=nullptr; return STATUS_MEDIA_WRITE_PROTECTED; };
        i.Overwrite=[](FSP_FILE_SYSTEM*,PVOID,UINT32,BOOLEAN,UINT64,FSP_FSCTL_FILE_INFO*)->NTSTATUS { return STATUS_MEDIA_WRITE_PROTECTED; };
        i.CreateEx=[](FSP_FILE_SYSTEM*,PWSTR,UINT32,UINT32,UINT32,PSECURITY_DESCRIPTOR,UINT64,PVOID,ULONG,BOOLEAN,PVOID* h,FSP_FSCTL_FILE_INFO*)->NTSTATUS {if(h)*h=nullptr;return STATUS_MEDIA_WRITE_PROTECTED;};
        i.OverwriteEx=[](FSP_FILE_SYSTEM*,PVOID,UINT32,BOOLEAN,UINT64,PFILE_FULL_EA_INFORMATION,ULONG,FSP_FSCTL_FILE_INFO*)->NTSTATUS {return STATUS_MEDIA_WRITE_PROTECTED;};
        i.SetEa=[](FSP_FILE_SYSTEM*,PVOID,PFILE_FULL_EA_INFORMATION,ULONG,FSP_FSCTL_FILE_INFO*)->NTSTATUS {return STATUS_MEDIA_WRITE_PROTECTED;};
        i.Write=[](FSP_FILE_SYSTEM*,PVOID,PVOID,UINT64,ULONG,BOOLEAN,BOOLEAN,PULONG n,FSP_FSCTL_FILE_INFO*)->NTSTATUS { if(n)*n=0; return STATUS_MEDIA_WRITE_PROTECTED; };
        i.SetBasicInfo=[](FSP_FILE_SYSTEM*,PVOID,UINT32,UINT64,UINT64,UINT64,UINT64,FSP_FSCTL_FILE_INFO*)->NTSTATUS { return STATUS_MEDIA_WRITE_PROTECTED; };
        i.SetFileSize=[](FSP_FILE_SYSTEM*,PVOID,UINT64,BOOLEAN,FSP_FSCTL_FILE_INFO*)->NTSTATUS { return STATUS_MEDIA_WRITE_PROTECTED; };
        i.CanDelete=[](FSP_FILE_SYSTEM*,PVOID,PWSTR)->NTSTATUS { return STATUS_MEDIA_WRITE_PROTECTED; };
        i.SetDelete=[](FSP_FILE_SYSTEM*,PVOID,PWSTR,BOOLEAN)->NTSTATUS { return STATUS_MEDIA_WRITE_PROTECTED; };
        i.Rename=[](FSP_FILE_SYSTEM*,PVOID,PWSTR,PWSTR,BOOLEAN)->NTSTATUS { return STATUS_MEDIA_WRITE_PROTECTED; };
        i.SetSecurity=[](FSP_FILE_SYSTEM*,PVOID,SECURITY_INFORMATION,PSECURITY_DESCRIPTOR)->NTSTATUS { return STATUS_MEDIA_WRITE_PROTECTED; };
        i.SetReparsePoint=[](FSP_FILE_SYSTEM*,PVOID,PWSTR,PVOID,SIZE_T)->NTSTATUS { return STATUS_MEDIA_WRITE_PROTECTED; };
        i.DeleteReparsePoint=i.SetReparsePoint;
        i.Control=[](FSP_FILE_SYSTEM*,PVOID,UINT32,PVOID,ULONG,PVOID,ULONG,PULONG done)->NTSTATUS { if(done)*done=0; return STATUS_MEDIA_WRITE_PROTECTED; };
        i.Create=FusionCreate;i.Overwrite=FusionOverwrite;i.Write=FusionWrite;i.SetFileSize=FusionSetSize;
        i.CreateEx=nullptr;i.OverwriteEx=nullptr;
        i.SetBasicInfo=FusionSetBasic;i.CanDelete=FusionCanDelete;i.SetDelete=FusionSetDelete;i.Rename=FusionRename;
        return i;
    }();
    return iface;
}

bool PrepareFusionMount(MountContext& c,HANDLE parent) {
    using namespace apfsaccess;
    if(!ValidateFusionArguments(c.args) || c.fusion || c.encrypted || c.metadata_store || c.tx_manager || c.payload_spool ||
        c.native_write_enabled || c.overlay_write_enabled)return false;
    c.fusion=std::make_unique<fusion_mount::State>();auto& s=*c.fusion;
    bool success=false;
    ScopeExit failure{[&](){if(!success){s.failed=true;s.Close();}}};
    try {
        if(!OwningParentIsAlive(parent) || !LifetimeFileExists(c.args) || g_exit.load())return false;
        s.Watch([&c,parent](){return !g_exit.load() && OwningParentIsAlive(parent) && LifetimeFileExists(c.args);});
        std::lock_guard lock(s.serial);fusion_mount::State::Operation io(s);
        catalog::FusionBindRequest request;rw::FusionVolumeSelection selection;
        if(!BuildFusionRequest(c.args,request,selection))return false;
        for(const auto& m:request.members)s.members[m.role==catalog::FusionMemberRole::Main?0:1]=m;
        s.budget=c.args.fusion.write_root.empty()?
            std::make_shared<catalog::ApfsReadBudget>(100000,256*1024*1024,1000000,256*1024*1024):
            rw::FusionImageRuntime::CreateStartupReadBudget();
        request.budget=s.budget;request.cancellation=s.cancelled;
        if(!c.args.fusion.write_root.empty()) {
            // The runtime pins ordinary local ancestors and both exact members.
            auto root=std::filesystem::path(c.args.fusion.write_root);
            if(!root.is_absolute()||!std::filesystem::is_directory(root))return false;
            s.write_mode=true;
            s.writer=rw::FusionImageRuntime::Open(request,selection,(root/L"original.wal").wstring(),s.error);
            if(!s.writer||!s.writer->Recover(s.error)||!s.Cache(s.error))return false;
            rw::FusionRuntimeVolumeInfo info;if(!s.writer->GetVolumeInfo(info,s.error))return false;
            c.args.volume=Utf8ToWide(info.label);c.args.incompatible_features=s.names.incompatible_features;
            s.label=c.args.volume.substr(0,31);
            if(s.cancelled->load()||!s.writer->CheckAvailable(s.error))return false;
            s.admitted=true;success=true;return true;
        }
        unsigned unavailable=0;
        auto store=catalog::ApfsFusionStore::BindImages(request,s.error,&unavailable);
        s.missing_members=unavailable;
        if(!store)return false;
        rw::FusionReadStatus status;
        s.session=rw::ApfsFusionReadSession::Open(std::move(store),selection,status,s.error,&unavailable);
        s.missing_members=unavailable;
        if(!s.session || !s.session->EnableRuntimeReads(s.error) || !s.session->GetNamespaceInfo(s.names,s.error))return false;
        catalog::ApfsContainerCatalog catalog;
        if(!s.session->GetCatalog(catalog,s.error))return false;
        const auto* view=catalog.TryGetReadOnlyVolumeView();if(!view)return false;
        const auto found=std::find_if(view->volumes.begin(),view->volumes.end(),[&](const auto& v){return v.superblock.object_id==selection.volume_oid;});
        if(found==view->volumes.end())return false;
        auto label=Utf8ToWide(found->superblock.name_utf8);
        if(!c.args.volume.empty() && c.args.volume!=label)return false;
        c.args.volume=label;c.args.incompatible_features=s.names.incompatible_features;
        auto units=(std::min)(label.size(),std::size_t{19});
        if(units && units<label.size() && label[units-1]>=0xd800 && label[units-1]<=0xdbff &&
            label[units]>=0xdc00 && label[units]<=0xdfff)--units;
        s.label=label.substr(0,units)+L" (read-only)";
        if(s.cancelled->load() || !s.session->CheckAvailable(s.error))return false;
        s.admitted=true;success=true;return true;
    } catch(...) {return false;}
}
