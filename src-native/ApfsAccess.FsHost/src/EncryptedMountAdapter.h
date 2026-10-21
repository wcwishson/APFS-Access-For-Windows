#pragma once
// Included after the normal callbacks. The same binary, supervisor, diagnostics,
// and owned WinFsp teardown serve this explicit immutable mode.
namespace enc = encrypted_mount;
using EncError = apfsaccess::catalog::EncryptedReadError;

// Same APFS.Xattr protocol as the ordinary host, with view-based decoding so
// decrypted names do not leave unwiped lower-case/hex/string temporaries.
bool EncDecodeStream(std::wstring_view text,std::string& name)
{
    const auto equal=[](std::wstring_view a,std::wstring_view b) {
        return a.size()==b.size() && CompareStringOrdinal(a.data(),static_cast<int>(a.size()),b.data(),static_cast<int>(b.size()),TRUE)==CSTR_EQUAL;
    };
    // Windows names include a stream type; WinFsp callback names omit it.
    if(text.size()>=6 && equal(text.substr(text.size()-6),L":$DATA")) text.remove_suffix(6);
    if(equal(text,L":APFS.XattrProtocol")) return true;
    if(equal(text,L":APFS.ResourceFork")) {name="com.apple.ResourceFork";return true;}
    if(equal(text,L":APFS.FinderInfo")) {name="com.apple.FinderInfo";return true;}
    if(text.size()<14 || !equal(text.substr(0,12),L":APFS.Xattr.")) return false;
    auto hex=text.substr(12); if(hex.empty() || hex.size()%2 || hex.size()>1642) return false;
    const auto digit=[](wchar_t c)->int {if(c>=L'0'&&c<=L'9')return c-L'0';if(c>=L'a'&&c<=L'f')return c-L'a'+10;if(c>=L'A'&&c<=L'F')return c-L'A'+10;return -1;};
    name.reserve(hex.size()/2);
    for(std::size_t i=0;i<hex.size();i+=2) {const auto a=digit(hex[i]),b=digit(hex[i+1]);if(a<0||b<0||(!a&&!b))return false;name.push_back(static_cast<char>(a*16+b));}
    return MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,name.data(),static_cast<int>(name.size()),nullptr,0)>0;
}
std::wstring EncStreamName(std::string_view name)
{
    constexpr wchar_t hex[]=L"0123456789ABCDEF";
    std::wstring result; result.reserve(18+name.size()*2); result=L":APFS.Xattr.";
    for(unsigned char c:name) {result+=hex[c>>4];result+=hex[c&15];}
    result+=L":$DATA"; return result;
}

NTSTATUS EncStatus(enc::State& s, EncError error)
{
    if(error==EncError::ResourceLimit && s.session) {
        // 596 gives each runtime call its own allowance. Probe with a fresh,
        // bounded metadata call; never retry the failed request or refill the
        // original source budget. Sticky source/budget/cancel failures survive
        // this probe and retain the existing terminal policy below.
        apfsaccess::catalog::EncryptedNamespaceInfo health;
        const auto check=s.session->GetNamespaceInfo(health);
        if(check==EncError::None) {
            if(!s.source || s.source->VerifyUnchanged()) return STATUS_INSUFFICIENT_RESOURCES;
            error=EncError::ReadFailure;
        } else error=check;
    }
    switch(error) {
    case EncError::None: return STATUS_SUCCESS;
    case EncError::FileNotFound: case EncError::XattrNotFound: return STATUS_OBJECT_NAME_NOT_FOUND;
    case EncError::NotDirectory: return STATUS_NOT_A_DIRECTORY;
    case EncError::InvalidArgument: return STATUS_OBJECT_NAME_INVALID;
    case EncError::Closed: case EncError::Cancelled: s.Cancel(); return STATUS_CANCELLED;
    default: s.Fail(enc::State::Failure::ReadSessionFailure);return STATUS_IO_DEVICE_ERROR;
    }
}
template<class F> NTSTATUS EncCall(FSP_FILE_SYSTEM* fs, const char* operation, F&& call)
{
    auto* c=Ctx(fs);
    ScopedCallbackActivity activity(c,operation);
    if(!c || !c->encrypted) return STATUS_INVALID_DEVICE_STATE;
    auto& s=*c->encrypted;
    if(s.cancelled->load()) return STATUS_CANCELLED;
    try {
        enc::State::Operation io(s,true);
        std::lock_guard lock(s.callbacks);
        if(s.writer && (!s.session || s.read_xid!=s.writer->CachedStatus().image.checkpoint_xid)) {
            if(s.session) s.session->Close();
            s.session.reset();
            EncError view_error{};
            s.session=s.writer->OpenReadView(view_error);
            if(!s.session) {s.Fail(enc::State::Failure::ReadViewOpenFailure);return STATUS_IO_DEVICE_ERROR;}
            s.read_xid=s.writer->CachedStatus().image.checkpoint_xid;
        }
        if(!s.session) return STATUS_INVALID_DEVICE_STATE;
        if(s.source && !s.source->VerifyUnchanged()) {s.Fail(enc::State::Failure::ReadSourceChanged);return STATUS_IO_DEVICE_ERROR;}
        apfsaccess::catalog::EncryptedNamespaceInfo info;
        const auto check=EncStatus(s,s.session->GetNamespaceInfo(info));
        if(!NT_SUCCESS(check)) return check;
        return call(*c,s);
    } catch(...) {s.Fail(enc::State::Failure::EncCallException);return STATUS_IO_DEVICE_ERROR;}
}
bool EncMutableNodeType(const apfsaccess::catalog::EncryptedNodeInfo& node) noexcept
{
    const auto kind = node.mode & 0170000;
    return kind == 0100000 || kind == 0040000;
}
void EncInfo(const enc::Handle& h, FSP_FSCTL_FILE_INFO* info)
{
    *info={};
    info->FileAttributes=(!h.writable || !EncMutableNodeType(h.node) || (h.node.bsd_flags&2) ? FILE_ATTRIBUTE_READONLY : 0) |
        (h.node.IsDirectory() && !h.stream ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_ARCHIVE);
    if(h.node.bsd_flags&0x8000) info->FileAttributes|=FILE_ATTRIBUTE_HIDDEN;
    info->FileSize=h.stream ? h.stream_size : h.node.size;
    info->AllocationSize=h.stream ? (h.stream_size+4095)/4096*4096 : h.node.allocated_size;
    info->IndexNumber=h.node.inode_id;
    info->HardLinks=h.node.IsDirectory() ? 1 : h.node.children_or_links;
    const auto time=[](std::uint64_t ns) { return ns/100+116444736000000000ULL; };
    info->CreationTime=time(h.node.create_time); info->LastAccessTime=time(h.node.access_time);
    info->LastWriteTime=time(h.node.modification_time); info->ChangeTime=time(h.node.change_time);
}
NTSTATUS EncCachedRootInfo(FSP_FILE_SYSTEM* fs,FSP_FSCTL_FILE_INFO* info)
{
    if(!info)return STATUS_INVALID_PARAMETER;
    *info={};auto* c=Ctx(fs);
    if(!c || !c->encrypted)return STATUS_INVALID_DEVICE_STATE;
    auto& s=*c->encrypted;
    if(s.cancelled->load())return STATUS_CANCELLED;
    std::lock_guard lock(s.root_cache_mutex);
    if(!s.root_attributes.load())return STATUS_INVALID_DEVICE_STATE;
    *info=s.root_info;return STATUS_SUCCESS;
}
bool EncIsCachedRootOpen(FSP_FILE_SYSTEM* fs,std::wstring_view name,UINT32 options,UINT32 access)
{
    constexpr UINT32 allowed_access=FILE_READ_ATTRIBUTES|READ_CONTROL|SYNCHRONIZE;
    constexpr UINT32 allowed_options=FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_ALERT|
        FILE_SYNCHRONOUS_IO_NONALERT|FILE_OPEN_FOR_BACKUP_INTENT|FILE_OPEN_REPARSE_POINT;
    const auto& bypass=g_root_observation_guard_bypass;
    return name==L"\\" && bypass.fs==fs && bypass.request &&
        bypass.request->Kind==FspFsctlTransactCreateKind &&
        ((options&0xffffff)&~allowed_options)==0 && (access&~allowed_access)==0;
}
NTSTATUS EncCachedRootOpen(FSP_FILE_SYSTEM* fs,PVOID* out,FSP_FSCTL_FILE_INFO* info)
{
    auto* c=Ctx(fs);ScopedCallbackActivity activity(c,"EncryptedCachedRootOpen");
    try {
        const auto status=EncCachedRootInfo(fs,info);if(!NT_SUCCESS(status))return status;
        auto h=std::make_unique<enc::Handle>();h->cached_root_observation=true;
        *out=h.release();return STATUS_SUCCESS;
    }catch(...){if(c && c->encrypted)c->encrypted->Fail(enc::State::Failure::EncCallException);return STATUS_IO_DEVICE_ERROR;}
}
NTSTATUS EncResolve(enc::State& s, std::wstring_view path, enc::Handle& h)
{
    if(path.empty() || path.size()>32768 || path.front()!=L'\\' || path.find(L'/')!=path.npos)
        return STATUS_OBJECT_NAME_INVALID;
    auto id=s.names.root_inode_id;
    h.writable=static_cast<bool>(s.writer);
    auto status=EncStatus(s,s.session->GetMetadata(id,h.node));
    if(!NT_SUCCESS(status)) return status;
    for(std::size_t at=1; at<path.size();) {
        auto end=path.find(L'\\',at); if(end==path.npos) end=path.size();
        auto part=path.substr(at,end-at);
        if(part.empty()) return STATUS_OBJECT_NAME_INVALID;
        if(!h.node.IsDirectory()) return STATUS_NOT_A_DIRECTORY;
        if(part==L"..") id=h.node.parent_id;
        else if(part!=L".") {
            apfsaccess::catalog::EncryptedDirectoryEntry entry;
            ScopeExit wipe{[&](){ enc::Wipe(entry.name_utf8); enc::Wipe(entry.windows_name); }};
            // Stream syntax exists only on the last component; projected APFS
            // colons are escaped by ApfsNameCodec, so cannot collide here.
            const auto colon=part.find(L':');
            if(colon!=part.npos) {
                if(end!=path.size()) return STATUS_OBJECT_NAME_INVALID;
                auto stream=std::wstring(part.substr(colon));
                ScopeExit wipe_stream{[&](){enc::Wipe(stream);}};
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
                status=EncStatus(s,s.session->LookupWindows(id,part,entry));
                if(!NT_SUCCESS(status)) return status;
                id=entry.inode_id; h.entry_parent=entry.parent_id; h.sibling=entry.sibling_id;
                enc::Wipe(h.entry_name);h.entry_name=entry.name_utf8;
            }
        }
        if(s.writer) {
            const auto found=s.open_entries.find(id);
            if(found!=s.open_entries.end() && (found->second->delete_pending || found->second->unlinked))
                return STATUS_DELETE_PENDING;
        }
        status=EncStatus(s,s.session->GetMetadata(id,h.node));
        if(!NT_SUCCESS(status)) return status;
        at=end+1;
    }
    const auto pending_streams=s.open_entries.find(id);
    if(h.stream && pending_streams!=s.open_entries.end() && pending_streams->second->delete_pending_streams.contains(h.xattr))
        return STATUS_DELETE_PENDING;
    if(h.stream) {
        h.writable=static_cast<bool>(s.writer) && !h.protocol;
        if(h.protocol) h.stream_size=13; // APFS-XATTR/1\n
        else {
            enc::Bytes bytes;
            status=EncStatus(s,s.session->ReadXattr(id,h.xattr,bytes));
            if(!NT_SUCCESS(status)) return status;
            h.stream_size=bytes.size();
        }
    }
    return STATUS_SUCCESS;
}
NTSTATUS EncOpen(FSP_FILE_SYSTEM* fs,PWSTR name,UINT32 options,UINT32 access,PVOID* out,FSP_FSCTL_FILE_INFO* info)
{
    if(out) *out=nullptr; if(info) *info={};
    if(!name || !out || !info) return STATUS_INVALID_PARAMETER;
    constexpr UINT32 writes=FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES|
        DELETE|WRITE_DAC|WRITE_OWNER|GENERIC_WRITE|GENERIC_ALL;
    if((access&writes) || (options&FILE_DELETE_ON_CLOSE)) return STATUS_MEDIA_WRITE_PROTECTED;
    if(EncIsCachedRootOpen(fs,name,options,access))return EncCachedRootOpen(fs,out,info);
    return EncCall(fs,"EncryptedOpen",[&](MountContext&,enc::State& s) {
        auto h=std::make_unique<enc::Handle>();
        auto status=EncResolve(s,name,*h); if(!NT_SUCCESS(status)) return status;
        const bool directory=h->node.IsDirectory() && !h->stream;
        if((options&FILE_DIRECTORY_FILE) && !directory) return STATUS_NOT_A_DIRECTORY;
        if((options&FILE_NON_DIRECTORY_FILE) && directory) return STATUS_FILE_IS_A_DIRECTORY;
        EncInfo(*h,info); *out=h.release(); return STATUS_SUCCESS;
    });
}
NTSTATUS EncGetInfo(FSP_FILE_SYSTEM* fs,PVOID context,FSP_FSCTL_FILE_INFO* info)
{
    if(info) *info={}; if(!context || !info) return STATUS_INVALID_PARAMETER;
    if(static_cast<enc::Handle*>(context)->cached_root_observation) {
        ScopedCallbackActivity activity(Ctx(fs),"EncryptedCachedRootGetInfo");
        return EncCachedRootInfo(fs,info);
    }
    return EncCall(fs,"EncryptedGetFileInfo",[&](MountContext&,enc::State&) {
        EncInfo(*static_cast<enc::Handle*>(context),info); return STATUS_SUCCESS;
    });
}
NTSTATUS EncRead(FSP_FILE_SYSTEM* fs,PVOID context,PVOID buffer,UINT64 offset,ULONG length,PULONG done)
{
    if(done) *done=0;
    if(!context || !done || (!buffer && length)) return STATUS_INVALID_PARAMETER;
    auto* h=static_cast<enc::Handle*>(context);
    if(h->cached_root_observation)return STATUS_ACCESS_DENIED;
    return EncCall(fs,"EncryptedRead",[&](MountContext&,enc::State& s) {
        if(h->StreamRemoved())return STATUS_FILE_DELETED;
        std::shared_ptr<apfsaccess::catalog::ApfsEncryptedReadSession> retained;
        ScopeExit close_retained{[&](){if(retained)retained->Close();}};
        auto* reader=s.session.get();
        if(s.writer && h->open_entry && h->open_entry->unlinked) {
            if(!h->open_entry->read_inode)return STATUS_FILE_DELETED;
            EncError error{};retained=s.writer->OpenReadView(*h->open_entry->read_inode,error);
            if(!retained)return EncStatus(s,error);
            reader=retained.get();
        }
        if(s.writer) {
            const auto status=EncStatus(s,reader->GetMetadata(h->node.inode_id,h->node));
            if(!NT_SUCCESS(status))return status;
        }
        enc::Bytes bytes;
        if(h->stream && !h->protocol) {
            const auto status=EncStatus(s,reader->ReadXattr(h->node.inode_id,h->xattr,bytes));
            if(!NT_SUCCESS(status))return status;
            h->stream_size=bytes.size();
        }
        if(h->node.IsDirectory() && !h->stream) return STATUS_FILE_IS_A_DIRECTORY;
        const auto size=h->stream ? h->stream_size : h->node.size;
        if(!length) return STATUS_SUCCESS;
        if(offset>=size) return STATUS_END_OF_FILE;
        const auto count=static_cast<std::size_t>((std::min<std::uint64_t>)(
            (std::min<std::uint64_t>)(length,apfsaccess::crypto::SecureBytes::kMaxBytes),size-offset));
        NTSTATUS status=STATUS_SUCCESS;
        if(h->protocol) {
            constexpr std::string_view protocol="APFS-XATTR/1\n";
            bytes.assign(reinterpret_cast<const std::byte*>(protocol.data()),reinterpret_cast<const std::byte*>(protocol.data()+protocol.size()));
        } else if(!h->stream && (h->node.mode&0170000)==0120000) {
            status=EncStatus(s,reader->ReadXattr(h->node.inode_id,"com.apple.fs.symlink",bytes));
            if(NT_SUCCESS(status) && (bytes.size()!=size+1 || bytes.empty() || bytes.back()!=std::byte{} ||
                std::find(bytes.begin(),bytes.end()-1,std::byte{})!=bytes.end()-1))
                return EncStatus(s,EncError::MetadataIntegrityFailure);
        } else if(!h->stream) {
            if((h->node.mode&0170000)!=0100000)return STATUS_NOT_SUPPORTED;
            status=EncStatus(s,reader->ReadFile(h->node.inode_id,offset,count,bytes));
        }
        if(!NT_SUCCESS(status)) return status;
        if(s.cancelled->load()) return STATUS_CANCELLED;
        const bool whole_value=h->stream || (h->node.mode&0170000)==0120000;
        std::memcpy(buffer,bytes.data()+(whole_value ? offset : 0),count);
        *done=static_cast<ULONG>(count); return STATUS_SUCCESS;
    });
}
bool EncCacheRootAttributes(enc::State& s)
{
    enc::Handle root;
    if(!s.session || s.session->GetMetadata(s.names.root_inode_id,root.node)!=EncError::None || !root.node.IsDirectory())return false;
    root.writable=s.writer!=nullptr;
    FSP_FSCTL_FILE_INFO info{};EncInfo(root,&info);
    std::lock_guard lock(s.root_cache_mutex);s.root_info=info;
    s.root_attributes.store(info.FileAttributes,std::memory_order_release);
    return true;
}

NTSTATUS EncCopySecurity(const MountContext& c,PSECURITY_DESCRIPTOR sd,SIZE_T* size)
{
    if(!size)return STATUS_SUCCESS;
    const auto supplied=*size;*size=c.sd_size;
    if(supplied<c.sd_size)return STATUS_BUFFER_OVERFLOW;
    if(sd && c.sd_size)std::memcpy(sd,c.sd,c.sd_size);
    return STATUS_SUCCESS;
}

NTSTATUS EncSecurity(FSP_FILE_SYSTEM* fs,PVOID context,PSECURITY_DESCRIPTOR sd,SIZE_T* size)
{
    if(!context || !size) return STATUS_INVALID_PARAMETER;
    auto* c=Ctx(fs);ScopedCallbackActivity activity(c,"EncryptedGetSecurity");
    if(!c || !c->encrypted)return STATUS_INVALID_DEVICE_STATE;
    if(c->encrypted->cancelled->load())return STATUS_CANCELLED;
    return EncCopySecurity(*c,sd,size);
}
NTSTATUS EncSecurityByName(FSP_FILE_SYSTEM* fs,PWSTR name,PUINT32 attrs,PSECURITY_DESCRIPTOR sd,SIZE_T* size)
{
    if(!name) return STATUS_INVALID_PARAMETER;
    if(std::wstring_view(name)==L"\\" || std::wstring_view(name)==L"\\.") {
        auto* c=Ctx(fs);ScopedCallbackActivity activity(c,"EncryptedGetRootSecurityByName");
        if(!c || !c->encrypted)return STATUS_INVALID_DEVICE_STATE;
        if(c->encrypted->cancelled->load())return STATUS_CANCELLED;
        const auto cached=c->encrypted->root_attributes.load();
        if(!cached)return STATUS_INVALID_DEVICE_STATE;
        if(attrs)*attrs=cached;
        return EncCopySecurity(*c,sd,size);
    }
    return EncCall(fs,"EncryptedGetSecurityByName",[&](MountContext& c,enc::State& s) {
        enc::Handle h; const auto status=EncResolve(s,name,h); if(!NT_SUCCESS(status)) return status;
        FSP_FSCTL_FILE_INFO info; EncInfo(h,&info); if(attrs) *attrs=info.FileAttributes;
        return EncCopySecurity(c,sd,size);
    });
}
NTSTATUS EncDirectory(FSP_FILE_SYSTEM* fs,PVOID context,PWSTR,PWSTR marker,PVOID buffer,ULONG length,PULONG done)
{
    if(done) *done=0; if(!context || !done || !buffer) return STATUS_INVALID_PARAMETER;
    if(static_cast<enc::Handle*>(context)->cached_root_observation)return STATUS_ACCESS_DENIED;
    const auto result=EncCall(fs,"EncryptedReadDirectory",[&](MountContext& c,enc::State& s) {
        if(!c.api.AddDir) return STATUS_INVALID_DEVICE_STATE;
        auto& h=*static_cast<enc::Handle*>(context); std::lock_guard lock(h.mutex);
        if(!h.node.IsDirectory() || h.stream) return STATUS_NOT_A_DIRECTORY;
        if(s.writer) {
            const auto status=EncStatus(s,s.session->GetMetadata(h.node.inode_id,h.node));
            if(!NT_SUCCESS(status))return status;
        }
        if(!h.enumerated || !marker || (s.writer && h.enumeration_xid!=s.read_xid)) {
            h.entries.Clear(); h.enumerated=false; h.cursor=0;
            const auto status=EncStatus(s,s.session->ListDirectory(h.node.inode_id,h.entries));
            if(!NT_SUCCESS(status)) return status;
            if(s.writer) {
                for(auto it=h.entries.begin();it!=h.entries.end();) {
                    const auto found=s.open_entries.find(it->inode_id);
                    if(found!=s.open_entries.end() && (found->second->delete_pending || found->second->unlinked) &&
                        found->second->parent==it->parent_id && found->second->name==it->name_utf8) {
                        enc::Wipe(it->name_utf8);enc::Wipe(it->windows_name);it=h.entries.erase(it);
                    } else ++it;
                }
                h.enumeration_xid=s.read_xid;
            }
            // Markers are exact returned Windows names. Keep the APFS ordering.
            h.enumerated=true;
        }
        std::size_t index=0;
        if(marker) {
            if(std::wstring_view(marker)==L".") index=1;
            else if(std::wstring_view(marker)==L"..") index=2;
            else {
                const auto it=std::find_if(h.entries.begin(),h.entries.end(),[&](const auto& e){return e.windows_name==marker;});
                if(it==h.entries.end()) return STATUS_OBJECT_NAME_NOT_FOUND;
                index=static_cast<std::size_t>(it-h.entries.begin())+3;
            }
        }
        for(;index<h.entries.size()+2;++index) {
            const std::wstring_view name=index==0?std::wstring_view(L"."):index==1?std::wstring_view(L".."):
                std::wstring_view(h.entries[index-2].windows_name);
            const auto id=index==0?h.node.inode_id:index==1?h.node.parent_id:h.entries[index-2].inode_id;
            enc::Handle entry; const auto status=EncStatus(s,s.session->GetMetadata(id,entry.node));
            if(!NT_SUCCESS(status)) return status;
            entry.writable=s.Writable();
            enc::Bytes storage; storage.resize(sizeof(FSP_FSCTL_DIR_INFO)+name.size()*sizeof(WCHAR));
            auto* di=reinterpret_cast<FSP_FSCTL_DIR_INFO*>(storage.data());
            di->Size=static_cast<UINT16>(storage.size()); EncInfo(entry,&di->FileInfo);
            std::memcpy(di->FileNameBuf,name.data(),name.size()*sizeof(WCHAR));
            if(!c.api.AddDir || !c.api.AddDir(di,buffer,length,done)) { h.cursor=index; return STATUS_SUCCESS; }
        }
        h.cursor=index; c.api.AddDir(nullptr,buffer,length,done); return STATUS_SUCCESS;
    });
    if(!NT_SUCCESS(result)) { SecureZeroMemory(buffer,*done); *done=0; }
    return result;
}
NTSTATUS EncStreams(FSP_FILE_SYSTEM* fs,PVOID context,PVOID buffer,ULONG length,PULONG done)
{
    if(done) *done=0; if(!context || !buffer || !done) return STATUS_INVALID_PARAMETER;
    if(static_cast<enc::Handle*>(context)->cached_root_observation)return STATUS_ACCESS_DENIED;
    const auto result=EncCall(fs,"EncryptedGetStreamInfo",[&](MountContext& c,enc::State& s) {
        if(!c.api.AddStream) return STATUS_INVALID_DEVICE_STATE;
        auto& h=*static_cast<enc::Handle*>(context);
        std::shared_ptr<apfsaccess::catalog::ApfsEncryptedReadSession> retained;
        ScopeExit close_retained{[&](){if(retained)retained->Close();}};
        auto* reader=s.session.get();
        if(s.writer && h.open_entry && h.open_entry->unlinked) {
            if(!h.open_entry->read_inode)return STATUS_FILE_DELETED;
            EncError error{};retained=s.writer->OpenReadView(*h.open_entry->read_inode,error);
            if(!retained)return EncStatus(s,error);
            reader=retained.get();
        }
        if(s.writer) {
            const auto status=EncStatus(s,reader->GetMetadata(h.node.inode_id,h.node));
            if(!NT_SUCCESS(status))return status;
        }
        enc::Xattrs attrs; const auto status=EncStatus(s,reader->ListXattrs(h.node.inode_id,attrs));
        if(!NT_SUCCESS(status)) return status;
        const auto add=[&](std::wstring name,std::uint64_t size) {
            ScopeExit wipe{[&](){enc::Wipe(name);}};
            auto bare=std::wstring_view(name).substr(1,name.size()-7);
            enc::Bytes storage; storage.resize(sizeof(FSP_FSCTL_STREAM_INFO)+bare.size()*sizeof(WCHAR));
            if(storage.size()>UINT16_MAX) return false;
            auto* si=reinterpret_cast<FSP_FSCTL_STREAM_INFO*>(storage.data()); si->Size=static_cast<UINT16>(storage.size());
            si->StreamSize=size; si->StreamAllocationSize=(size+4095)/4096*4096;
            std::memcpy(si->StreamNameBuf,bare.data(),bare.size()*sizeof(WCHAR));
            return c.api.AddStream && c.api.AddStream(si,buffer,length,done);
        };
        if(!h.node.IsDirectory() && !add(L"::$DATA",h.node.size)) return STATUS_BUFFER_OVERFLOW;
        for(const auto& x:attrs) if(!add(EncStreamName(x.name_utf8),x.data.size())) return STATUS_BUFFER_OVERFLOW;
        if(!c.api.AddStream || !c.api.AddStream(nullptr,buffer,length,done)) return STATUS_BUFFER_OVERFLOW;
        return STATUS_SUCCESS;
    });
    if(!NT_SUCCESS(result)) { SecureZeroMemory(buffer,*done); *done=0; }
    return result;
}

bool PrepareEncryptedMount(MountContext& c,HANDLE parent,const char** failure=nullptr)
{
    using namespace apfsaccess::catalog;
    const auto stage=[&](const char* name) {if(failure)*failure=name;};
    stage("Arguments");
    if(!ValidateEncryptedArguments(c.args) || c.encrypted || c.metadata_store || c.tx_manager || c.payload_spool ||
        c.native_write_enabled || c.overlay_write_enabled) return false;
    auto owned=std::make_unique<enc::State>(); auto& s=*owned;
    try {
        s.Watch([&c,parent]() { return !g_exit.load() && OwningParentIsAlive(parent) && LifetimeFileExists(c.args); },
            [&c](){return c.active_callback_count.load(std::memory_order_acquire)!=0;});
        enc::State::Operation io(s);
        stage("ImageLease");
        auto lease=std::make_shared<apfsaccess::transport::WindowsImageLease>(c.args.device);
        const auto& o=c.args.encrypted;
        s.source=std::make_shared<apfsaccess::transport::OwnedEncryptedImageSource>(lease,c.args.device_offset_bytes,o.store_size);
        stage("SourceBinding");
        if(s.source->SourceIdentity()!=WideToUtf8(o.source_id)) return false;
        stage("StoreCheckpointBinding");
        // Use the existing object-only reader. The allocator/writer catalog
        // validates ordinary filesystem tree headers and therefore cannot be
        // the encrypted namespace's admission parser. No legacy retry occurs.
        std::string error;
        auto checkpoint=LoadContainerCheckpointView(*s.source,0,s.source->SizeBytes(),error,o.checkpoint);
        if(!checkpoint) return false;
        const auto& nx=checkpoint->superblock;
        if(nx.uuid_hex!=WideToUtf8(c.args.container_id) || nx.xid!=o.checkpoint ||
            !nx.block_size || nx.block_count>UINT64_MAX/nx.block_size || nx.block_count*nx.block_size!=o.store_size ||
            (nx.incompatible_features&~kNxSupportedIncompatibleFeaturesMask) || nx.fusion_middle_tree_oid ||
            nx.fusion_writeback_oid || nx.fusion_writeback_start || nx.fusion_writeback_blocks ||
            std::any_of(nx.fusion_uuid.begin(),nx.fusion_uuid.end(),[](auto b){return b!=std::byte{};})) return false;
        stage("VolumeBinding");
        auto volumes=LoadAppleReadOnlyVolumeView(*s.source,*checkpoint,error);
        if(!volumes) return false;
        ScopeExit wipe_volume_names{[&](){for(auto& v:volumes->volumes) enc::Wipe(v.superblock.name_utf8);}};
        const ApsbVolume* volume=nullptr;
        for(const auto& item:volumes->volumes) if(item.superblock.object_id==c.args.volume_object_id) {
            if(volume) return false; volume=&item.superblock;
        }
        if(!volume || volume->uuid_hex!=WideToUtf8(o.volume_uuid) ||
            (!c.args.volume.empty() && WideToUtf8(c.args.volume)!=volume->name_utf8)) return false;
        const auto uuid=[](const std::wstring& value) {
            KeybagUuid result{};
            const auto digit=[](wchar_t ch) { return ch<=L'9' ? ch-L'0' : ch-L'a'+10; };
            for(unsigned i=0;i<16;++i) result[i]=std::byte((digit(value[2*i])<<4)|digit(value[2*i+1]));
            return result;
        };
        PasswordUnlockRequest request; request.container_uuid=uuid(c.args.container_id);
        request.volume_uuid=uuid(o.volume_uuid); request.user_uuid=uuid(o.user_uuid);
        request.volume_oid=c.args.volume_object_id; request.checkpoint_xid=o.checkpoint;
        request.container_bag={o.container_bag_oid,o.container_bag_xid}; request.volume_bag={o.volume_bag_oid,o.volume_bag_xid};
        request.length=o.bag_length==L"includes-header" ? KeybagLength::IncludesHeader : KeybagLength::EntriesOnly;
        // No credential read happens before the immutable source and exact
        // container/volume/checkpoint selectors have passed admission.
        stage("Credential");
        auto input=GetStdHandle(STD_INPUT_HANDLE); SetStdHandle(STD_INPUT_HANDLE,nullptr);
        auto credential=apfsaccess::transport::ReceiveCredential(input,std::chrono::milliseconds(5000),*s.cancelled);
        if(!credential) {stage(apfsaccess::transport::CredentialErrorName(credential.error));return false;}
        stage("Unlock");
        PasswordUnlockBudget attempts; EncError read_error; UnlockError unlock_error;
        s.session=ApfsEncryptedReadSession::Unlock(s.source,WideToUtf8(o.source_id),s.source->Revision(),request,
            credential.bytes.Bytes(),attempts,read_error,unlock_error,s.cancelled);
        credential.bytes.Clear();
        if(!s.session) return false;
        stage("Namespace");
        if(s.session->GetNamespaceInfo(s.names)!=EncError::None || !EncCacheRootAttributes(s) || s.cancelled->load()) return false;
        c.args.incompatible_features=volume->incompatible_features;
        const auto policy=apfsaccess::rw::ApfsNamePolicy::FromIncompatibleFeatures(c.args.incompatible_features);
        stage("NamePolicy");
        if(policy.case_mode!=s.names.name_policy.case_mode || policy.normalization_mode!=s.names.name_policy.normalization_mode) return false;
        auto volume_name=Utf8ToWide(volume->name_utf8);ScopeExit wipe_name{[&](){enc::Wipe(volume_name);}};
        auto label_units=(std::min)(volume_name.size(),std::size_t{19});
        if(label_units && label_units<volume_name.size() &&
            volume_name[label_units-1]>=0xd800 && volume_name[label_units-1]<=0xdbff &&
            volume_name[label_units]>=0xdc00 && volume_name[label_units]<=0xdfff) --label_units;
        s.label.reserve(31);s.label.assign(volume_name.data(),label_units);
        s.label+=L" (read-only)";
        c.encrypted=std::move(owned);stage(nullptr);return true;
    } catch(...) { return false; }
}

const FSP_FILE_SYSTEM_INTERFACE& EncryptedServeInterface()
{
    static const auto iface=[] {
        FSP_FILE_SYSTEM_INTERFACE i{};
        i.GetVolumeInfo=[](FSP_FILE_SYSTEM* fs,FSP_FSCTL_VOLUME_INFO* v)->NTSTATUS {
            if(!v) return STATUS_INVALID_PARAMETER;
            auto* c=Ctx(fs);ScopedCallbackActivity activity(c,"EncryptedGetVolumeInfo");
            if(!c || !c->encrypted)return STATUS_INVALID_DEVICE_STATE;
            if(c->encrypted->cancelled->load())return STATUS_CANCELLED;
            *v={}; // Allocator capacity is not exposed by this profile. Zero available on RO.
            const auto length=(std::min)(c->label.size(),std::size_t{31});
            v->VolumeLabelLength=static_cast<UINT16>(length*sizeof(WCHAR));
            std::memcpy(v->VolumeLabel,c->label.data(),v->VolumeLabelLength);return STATUS_SUCCESS;
        };
        i.SetVolumeLabel=CB_SetVolumeLabel;
        i.Open=EncOpen; i.Read=EncRead; i.GetFileInfo=EncGetInfo;
        i.Flush=[](FSP_FILE_SYSTEM* fs,PVOID h,FSP_FSCTL_FILE_INFO* info)->NTSTATUS {
            if(h) return EncGetInfo(fs,h,info);
            return EncCall(fs,"EncryptedFlushVolume",[](MountContext&,enc::State&){return STATUS_SUCCESS;});
        };
        i.GetSecurity=EncSecurity; i.GetSecurityByName=EncSecurityByName;
        i.ReadDirectory=EncDirectory; i.GetStreamInfo=EncStreams;
        i.Cleanup=[](FSP_FILE_SYSTEM*,PVOID,PWSTR,ULONG) {};
        i.Close=[](FSP_FILE_SYSTEM* fs,PVOID h) { ScopedCallbackActivity activity(Ctx(fs),"EncryptedClose"); delete static_cast<enc::Handle*>(h); };
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
        return i;
    }();
    return iface;
}
