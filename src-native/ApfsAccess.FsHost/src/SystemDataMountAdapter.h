#pragma once
template<class F> NTSTATUS SystemDataCall(FSP_FILE_SYSTEM* fs,const char* operation,F&& call)
{
    auto* c=Ctx(fs);ScopedCallbackActivity activity(c,operation);
    if(!c||!c->system_data)return STATUS_INVALID_DEVICE_STATE;
    auto& s=*c->system_data;
    try {
        std::lock_guard lock(s.serial);
        if(s.cancelled.load())return STATUS_CANCELLED;
        if(!s.session)return STATUS_INVALID_DEVICE_STATE;
        std::string error;
        if(!s.session->CheckAvailable(error)){s.failed=true;s.Cancel();return STATUS_IO_DEVICE_ERROR;}
        auto status=call(*c,s);
        if(!s.session->CheckAvailable(error)){s.failed=true;s.Cancel();return STATUS_IO_DEVICE_ERROR;}
        return s.cancelled.load()?STATUS_CANCELLED:status;
    }catch(...){s.failed=true;s.Cancel();return STATUS_IO_DEVICE_ERROR;}
}
NTSTATUS SystemDataError(const std::string& error)
{
    if(error=="FirmlinkLookupMissing")return STATUS_OBJECT_NAME_NOT_FOUND;
    if(error=="FirmlinkLookupNotDirectory")return STATUS_NOT_A_DIRECTORY;
    if(error=="FirmlinkLookupNameInvalid"||error=="FirmlinkLookupPathInvalid")return STATUS_OBJECT_NAME_INVALID;
    if(error=="FirmlinkFileReadUnsupported")return STATUS_INVALID_DEVICE_REQUEST;
    return STATUS_IO_DEVICE_ERROR;
}
void SystemDataInfo(const system_data_mount::Handle& h,FSP_FSCTL_FILE_INFO* out)
{
    *out={};out->FileAttributes=FILE_ATTRIBUTE_READONLY|(h.node.is_directory?FILE_ATTRIBUTE_DIRECTORY:FILE_ATTRIBUTE_ARCHIVE);
    if(h.node.bsd_flags&0x8000)out->FileAttributes|=FILE_ATTRIBUTE_HIDDEN;
    out->FileSize=h.node.logical_size;out->AllocationSize=h.node.allocation_size.value_or(0);
    out->IndexNumber=h.index;out->HardLinks=h.node.is_directory?1:h.node.link_count;
    out->CreationTime=h.node.create_time_utc;out->LastAccessTime=h.node.access_time_utc;
    out->LastWriteTime=h.node.modification_time_utc;out->ChangeTime=h.node.change_time_utc;
}
NTSTATUS SystemDataResolve(system_data_mount::State& s,std::wstring_view name,system_data_mount::Handle& h)
{
    std::string error;
    if(!s.session->TryWindowsPath(name,h.path,error)||!s.session->TryGetMetadata(h.path,h.node,h.index,error))return SystemDataError(error);
    if(h.node.node_type!=apfsaccess::rw::MetadataStore::NodeType::Directory&&
        h.node.node_type!=apfsaccess::rw::MetadataStore::NodeType::RegularFile)return STATUS_INVALID_DEVICE_REQUEST;
    return STATUS_SUCCESS;
}
NTSTATUS SystemDataOpen(FSP_FILE_SYSTEM* fs,PWSTR name,UINT32 options,UINT32 access,PVOID* out,FSP_FSCTL_FILE_INFO* info)
{
    if(out)*out=nullptr;if(info)*info={};if(!name||!out||!info)return STATUS_INVALID_PARAMETER;
    constexpr UINT32 writes=FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES|DELETE|WRITE_DAC|WRITE_OWNER|GENERIC_WRITE|GENERIC_ALL;
    if((access&writes)||(options&FILE_DELETE_ON_CLOSE))return STATUS_MEDIA_WRITE_PROTECTED;
    const auto status=SystemDataCall(fs,"SystemDataOpen",[&](MountContext&,system_data_mount::State& s){
        auto h=std::make_unique<system_data_mount::Handle>();auto status=SystemDataResolve(s,name,*h);
        if(!NT_SUCCESS(status))return status;
        if((options&FILE_DIRECTORY_FILE)&&!h->node.is_directory)return STATUS_NOT_A_DIRECTORY;
        if((options&FILE_NON_DIRECTORY_FILE)&&h->node.is_directory)return STATUS_FILE_IS_A_DIRECTORY;
        SystemDataInfo(*h,info);*out=h.release();return STATUS_SUCCESS;
    });
    if(!NT_SUCCESS(status)){delete static_cast<system_data_mount::Handle*>(*out);*out=nullptr;*info={};}return status;
}
NTSTATUS SystemDataGetInfo(FSP_FILE_SYSTEM* fs,PVOID context,FSP_FSCTL_FILE_INFO* info)
{
    if(info)*info={};if(!context||!info)return STATUS_INVALID_PARAMETER;
    const auto status=SystemDataCall(fs,"SystemDataGetFileInfo",[&](MountContext&,system_data_mount::State&){
        SystemDataInfo(*static_cast<system_data_mount::Handle*>(context),info);return STATUS_SUCCESS;});
    if(!NT_SUCCESS(status))*info={};return status;
}
NTSTATUS SystemDataRead(FSP_FILE_SYSTEM* fs,PVOID context,PVOID buffer,UINT64 offset,ULONG length,PULONG done)
{
    if(done)*done=0;if(!context||!done||(!buffer&&length))return STATUS_INVALID_PARAMETER;
    const auto status=SystemDataCall(fs,"SystemDataRead",[&](MountContext&,system_data_mount::State& s){
        const auto& h=*static_cast<system_data_mount::Handle*>(context);
        if(h.node.is_directory)return STATUS_FILE_IS_A_DIRECTORY;
        std::vector<std::byte> bytes;std::string error;
        const auto count=(std::min)(length,ULONG{1024*1024});
        if(!s.session->TryReadFile(h.path,offset,count,bytes,error))return SystemDataError(error);
        if(length&&offset>=h.node.logical_size)return STATUS_END_OF_FILE;
        if(!bytes.empty())std::memcpy(buffer,bytes.data(),bytes.size());*done=static_cast<ULONG>(bytes.size());return STATUS_SUCCESS;
    });
    if(!NT_SUCCESS(status)){if(buffer&&*done)SecureZeroMemory(buffer,*done);*done=0;}return status;
}
NTSTATUS SystemDataDirectory(FSP_FILE_SYSTEM* fs,PVOID context,PWSTR,PWSTR marker,PVOID buffer,ULONG length,PULONG done)
{
    if(done)*done=0;if(!context||!done||!buffer)return STATUS_INVALID_PARAMETER;
    const auto status=SystemDataCall(fs,"SystemDataReadDirectory",[&](MountContext& c,system_data_mount::State& s){
        const auto& h=*static_cast<system_data_mount::Handle*>(context);
        if(!h.node.is_directory)return STATUS_NOT_A_DIRECTORY;
        if(!c.api.AddDir)return STATUS_INVALID_DEVICE_STATE;
        std::vector<apfsaccess::rw::FirmlinkDirectoryEntry> entries;std::string error;
        if(!s.session->TryEnumerate(h.path,entries,error))return SystemDataError(error);
        std::size_t start=0;
        if(marker){
            if(std::wstring_view(marker)==L".")start=1;
            else if(std::wstring_view(marker)==L"..")start=2;
            else {const auto it=std::find_if(entries.begin(),entries.end(),[&](const auto& e){return e.windows_name==marker;});
                if(it==entries.end())return STATUS_OBJECT_NAME_NOT_FOUND;start=static_cast<std::size_t>(it-entries.begin())+3;}
        }
        for(auto index=start;index<entries.size()+2;++index){
            const std::wstring_view name=index==0?L".":index==1?L"..":std::wstring_view(entries[index-2].windows_name);
            const std::string path=index==0?h.path:index==1?(h.path=="/"?"/..":h.path+"/.."):entries[index-2].unix_path;
            system_data_mount::Handle entry;
            if(!s.session->TryGetMetadata(path,entry.node,entry.index,error))return SystemDataError(error);
            std::vector<std::byte> storage(sizeof(FSP_FSCTL_DIR_INFO)+name.size()*sizeof(WCHAR));
            if(storage.size()>UINT16_MAX)return STATUS_OBJECT_NAME_INVALID;
            auto* di=reinterpret_cast<FSP_FSCTL_DIR_INFO*>(storage.data());di->Size=static_cast<UINT16>(storage.size());
            SystemDataInfo(entry,&di->FileInfo);std::memcpy(di->FileNameBuf,name.data(),name.size()*sizeof(WCHAR));
            if(!c.api.AddDir(di,buffer,length,done))return STATUS_SUCCESS;
        }
        c.api.AddDir(nullptr,buffer,length,done);return STATUS_SUCCESS;
    });
    if(!NT_SUCCESS(status)){SecureZeroMemory(buffer,*done);*done=0;}return status;
}
NTSTATUS SystemDataSecurityByName(FSP_FILE_SYSTEM* fs,PWSTR name,PUINT32 attrs,PSECURITY_DESCRIPTOR sd,SIZE_T* size)
{
    if(!name)return STATUS_INVALID_PARAMETER;
    return SystemDataCall(fs,"SystemDataGetSecurityByName",[&](MountContext& c,system_data_mount::State& s){
        system_data_mount::Handle h;const auto status=SystemDataResolve(s,name,h);if(!NT_SUCCESS(status))return status;
        FSP_FSCTL_FILE_INFO info;SystemDataInfo(h,&info);if(attrs)*attrs=info.FileAttributes;
        if(size){const auto supplied=*size;*size=c.sd_size;if(supplied<c.sd_size)return STATUS_BUFFER_OVERFLOW;
            if(sd&&c.sd_size)std::memcpy(sd,c.sd,c.sd_size);}return STATUS_SUCCESS;});
}
const FSP_FILE_SYSTEM_INTERFACE& SystemDataServeInterface()
{
    static const auto iface=[] {
        FSP_FILE_SYSTEM_INTERFACE i{};
        i.Open=SystemDataOpen;i.Read=SystemDataRead;i.GetFileInfo=SystemDataGetInfo;i.ReadDirectory=SystemDataDirectory;
        i.GetSecurityByName=SystemDataSecurityByName;
        i.GetSecurity=[](FSP_FILE_SYSTEM* fs,PVOID context,PSECURITY_DESCRIPTOR sd,SIZE_T* size)->NTSTATUS {
            if(!context||!size)return STATUS_INVALID_PARAMETER;
            return SystemDataCall(fs,"SystemDataGetSecurity",[&](MountContext& c,system_data_mount::State&){
                const auto supplied=*size;*size=c.sd_size;if(supplied<c.sd_size)return STATUS_BUFFER_OVERFLOW;
                if(sd&&c.sd_size)std::memcpy(sd,c.sd,c.sd_size);return STATUS_SUCCESS;});};
        i.GetVolumeInfo=[](FSP_FILE_SYSTEM* fs,FSP_FSCTL_VOLUME_INFO* v)->NTSTATUS {
            if(!v)return STATUS_INVALID_PARAMETER;
            return SystemDataCall(fs,"SystemDataGetVolumeInfo",[&](MountContext& c,system_data_mount::State&){
                *v={};v->VolumeLabelLength=static_cast<UINT16>(c.label.size()*sizeof(WCHAR));
                std::memcpy(v->VolumeLabel,c.label.data(),v->VolumeLabelLength);return STATUS_SUCCESS;});};
        i.Flush=[](FSP_FILE_SYSTEM* fs,PVOID h,FSP_FSCTL_FILE_INFO* info)->NTSTATUS {
            if(h)return SystemDataGetInfo(fs,h,info);
            return SystemDataCall(fs,"SystemDataFlush",[](MountContext&,system_data_mount::State&){return STATUS_SUCCESS;});};
        i.Cleanup=[](FSP_FILE_SYSTEM*,PVOID,PWSTR,ULONG){};
        i.Close=[](FSP_FILE_SYSTEM* fs,PVOID h){ScopedCallbackActivity activity(Ctx(fs),"SystemDataClose");delete static_cast<system_data_mount::Handle*>(h);};
        i.SetVolumeLabel=[](FSP_FILE_SYSTEM*,PWSTR,FSP_FSCTL_VOLUME_INFO*)->NTSTATUS{return STATUS_MEDIA_WRITE_PROTECTED;};
        i.Create=[](FSP_FILE_SYSTEM*,PWSTR,UINT32,UINT32,UINT32,PSECURITY_DESCRIPTOR,UINT64,PVOID* h,FSP_FSCTL_FILE_INFO*)->NTSTATUS{if(h)*h=nullptr;return STATUS_MEDIA_WRITE_PROTECTED;};
        i.Overwrite=[](FSP_FILE_SYSTEM*,PVOID,UINT32,BOOLEAN,UINT64,FSP_FSCTL_FILE_INFO*)->NTSTATUS{return STATUS_MEDIA_WRITE_PROTECTED;};
        i.CreateEx=[](FSP_FILE_SYSTEM*,PWSTR,UINT32,UINT32,UINT32,PSECURITY_DESCRIPTOR,UINT64,PVOID,ULONG,BOOLEAN,PVOID* h,FSP_FSCTL_FILE_INFO*)->NTSTATUS{if(h)*h=nullptr;return STATUS_MEDIA_WRITE_PROTECTED;};
        i.OverwriteEx=[](FSP_FILE_SYSTEM*,PVOID,UINT32,BOOLEAN,UINT64,PFILE_FULL_EA_INFORMATION,ULONG,FSP_FSCTL_FILE_INFO*)->NTSTATUS{return STATUS_MEDIA_WRITE_PROTECTED;};
        i.SetEa=[](FSP_FILE_SYSTEM*,PVOID,PFILE_FULL_EA_INFORMATION,ULONG,FSP_FSCTL_FILE_INFO*)->NTSTATUS{return STATUS_MEDIA_WRITE_PROTECTED;};
        i.Write=[](FSP_FILE_SYSTEM*,PVOID,PVOID,UINT64,ULONG,BOOLEAN,BOOLEAN,PULONG n,FSP_FSCTL_FILE_INFO*)->NTSTATUS{if(n)*n=0;return STATUS_MEDIA_WRITE_PROTECTED;};
        i.SetBasicInfo=[](FSP_FILE_SYSTEM*,PVOID,UINT32,UINT64,UINT64,UINT64,UINT64,FSP_FSCTL_FILE_INFO*)->NTSTATUS{return STATUS_MEDIA_WRITE_PROTECTED;};
        i.SetFileSize=[](FSP_FILE_SYSTEM*,PVOID,UINT64,BOOLEAN,FSP_FSCTL_FILE_INFO*)->NTSTATUS{return STATUS_MEDIA_WRITE_PROTECTED;};
        i.CanDelete=[](FSP_FILE_SYSTEM*,PVOID,PWSTR)->NTSTATUS{return STATUS_MEDIA_WRITE_PROTECTED;};
        i.SetDelete=[](FSP_FILE_SYSTEM*,PVOID,PWSTR,BOOLEAN)->NTSTATUS{return STATUS_MEDIA_WRITE_PROTECTED;};
        i.Rename=[](FSP_FILE_SYSTEM*,PVOID,PWSTR,PWSTR,BOOLEAN)->NTSTATUS{return STATUS_MEDIA_WRITE_PROTECTED;};
        i.SetSecurity=[](FSP_FILE_SYSTEM*,PVOID,SECURITY_INFORMATION,PSECURITY_DESCRIPTOR)->NTSTATUS{return STATUS_MEDIA_WRITE_PROTECTED;};
        i.SetReparsePoint=[](FSP_FILE_SYSTEM*,PVOID,PWSTR,PVOID,SIZE_T)->NTSTATUS{return STATUS_MEDIA_WRITE_PROTECTED;};
        i.DeleteReparsePoint=i.SetReparsePoint;
        i.Control=[](FSP_FILE_SYSTEM*,PVOID,UINT32,PVOID,ULONG,PVOID,ULONG,PULONG done)->NTSTATUS{if(done)*done=0;return STATUS_MEDIA_WRITE_PROTECTED;};
        return i;
    }();return iface;
}
bool PrepareSystemDataMount(MountContext& c,HANDLE parent)
{
    if(!ValidateSystemDataArguments(c.args)||c.system_data||c.encrypted||c.fusion||c.metadata_store||c.tx_manager||c.payload_spool||
        c.native_write_enabled||c.overlay_write_enabled)return false;
    c.system_data=std::make_unique<system_data_mount::State>();auto& s=*c.system_data;
    try {
        if(!OwningParentIsAlive(parent)||!LifetimeFileExists(c.args)||g_exit.load())return false;
        const auto& o=c.args.system_data;
        const apfsaccess::rw::FirmlinkImageOptions expected{WideToUtf8(c.args.container_id),WideToUtf8(o.group),
            c.args.volume_object_id,o.data_oid,o.checkpoint_xid};
        if(!apfsaccess::rw::ApfsFirmlinkProducer::TryOpenImage(c.args.device,expected,s.session,s.error)){s.failed=true;return false;}
        apfsaccess::rw::FirmlinkLookupResult root;
        if(!s.session->TryLookup("/",apfsaccess::rw::FirmlinkAccess::Read,root,s.error))return false;
        // A single mounted Windows name policy cannot represent mixed policies.
        // Refuse rather than silently changing either canonical volume policy.
        for(const auto& pair:s.session->Records())if(pair.source.volume.incompatible_features!=root.identity.volume.incompatible_features||
            pair.target.volume.incompatible_features!=root.identity.volume.incompatible_features){s.error="SystemDataMixedNamePolicies";s.failed=true;return false;}
        c.args.incompatible_features=root.identity.volume.incompatible_features;
        if(!c.args.volume.empty()&&c.args.volume!=Utf8ToWide(root.identity.volume.name_utf8)){s.error="SystemDataLabelMismatch";s.failed=true;return false;}
        c.args.volume=Utf8ToWide(root.identity.volume.name_utf8);
        if(!OwningParentIsAlive(parent)||!LifetimeFileExists(c.args)||g_exit.load())return false;
        s.pair_count=s.session->Records().size();s.admitted=true;return true;
    }catch(...){s.failed=true;return false;}
}
