#pragma once
#include "FusionMutationResult.h"
// CopyFile passes the source compression attribute as a creation hint. The
// destination's canonical extents are ordinary data; compression is not claimed.
constexpr UINT32 FusionCopyAttributes = FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_COMPRESSED;
constexpr UINT64 FusionMaximumFileSize = (1ull << 56) - 4096;
NTSTATUS FusionParent(fusion_mount::State& s,std::wstring_view path,std::uint64_t& parent,std::string& leaf) {
    auto at=path.rfind(L'\\');if(at==path.npos||at+1==path.size())return STATUS_OBJECT_NAME_INVALID;
    const auto encoded=apfsaccess::rw::ApfsNameCodec::EncodeWindowsName(path.substr(at+1));
    if(!encoded.ok())return STATUS_OBJECT_NAME_INVALID;leaf=*encoded.value;
    fusion_mount::Handle directory;auto status=FusionResolve(s,at?path.substr(0,at):std::wstring_view(L"\\"),directory);
    if(!NT_SUCCESS(status))return status;if(!directory.node.IsDirectory()||directory.stream)return STATUS_NOT_A_DIRECTORY;
    parent=directory.node.inode_id;return STATUS_SUCCESS;
}
NTSTATUS FusionCreate(FSP_FILE_SYSTEM* fs,PWSTR name,UINT32 options,UINT32,UINT32 attributes,PSECURITY_DESCRIPTOR,UINT64 allocation,PVOID* out,FSP_FSCTL_FILE_INFO* info) {
    if(out)*out=nullptr;if(info)*info={};if(!name||!out||!info)return STATUS_INVALID_PARAMETER;
    return FusionCall(fs,"FusionCreate",[&](MountContext&,fusion_mount::State& s){
        if(!s.Writable())return STATUS_MEDIA_WRITE_PROTECTED;
        const bool directory=(options&FILE_DIRECTORY_FILE)!=0;
        if(allocation>FusionMaximumFileSize||(directory&&allocation)||(attributes&~(FusionCopyAttributes|FILE_ATTRIBUTE_DIRECTORY))) {
            s.error="FusionCreateArguments:"+std::to_string(allocation)+":"+std::to_string(attributes);return STATUS_NOT_SUPPORTED;}
        std::uint64_t parent=0,id=0;std::string leaf;auto status=FusionParent(s,name,parent,leaf);if(!NT_SUCCESS(status))return status;
        status=FusionMutationResult(s,directory?s.writer->MakeDirectory(parent,leaf,id,s.error):s.writer->CreateRegularFile(parent,leaf,id,s.error));if(!NT_SUCCESS(status))return status;
        auto h=std::make_unique<fusion_mount::Handle>();h->writable=true;h->entry_parent=parent;
        if(!s.GetMetadata(id,h->node,s.error))return FusionStatus(s,false);
        ++s.open_counts[id];FusionInfo(*h,info);*out=h.release();return STATUS_SUCCESS;
    },out,info);
}
NTSTATUS FusionSetSize(FSP_FILE_SYSTEM* fs,PVOID context,UINT64 size,BOOLEAN allocation,FSP_FSCTL_FILE_INFO* info) {
    if(!context||!info)return STATUS_INVALID_PARAMETER;
    return FusionCall(fs,"FusionSetFileSize",[&](MountContext&,fusion_mount::State& s){
        if(!s.Writable())return STATUS_MEDIA_WRITE_PROTECTED;auto& h=*static_cast<fusion_mount::Handle*>(context);
        if(h.stream||h.node.IsDirectory()||size>FusionMaximumFileSize)return STATUS_NOT_SUPPORTED;
        if(!s.GetMetadata(h.node.inode_id,h.node,s.error))return FusionStatus(s,false);
        if((!allocation||size<h.node.size)&&size!=h.node.size){auto status=FusionMutationResult(s,s.writer->Resize(h.node.inode_id,size,s.error));if(!NT_SUCCESS(status))return status;}
        if(!s.GetMetadata(h.node.inode_id,h.node,s.error))return FusionStatus(s,false);FusionInfo(h,info);return STATUS_SUCCESS;
    });
}
NTSTATUS FusionOverwrite(FSP_FILE_SYSTEM* fs,PVOID h,UINT32 attrs,BOOLEAN,UINT64,FSP_FSCTL_FILE_INFO* info) {
    if(attrs&~FusionCopyAttributes)return STATUS_NOT_SUPPORTED;
    return FusionSetSize(fs,h,0,FALSE,info);
}
NTSTATUS FusionWrite(FSP_FILE_SYSTEM* fs,PVOID context,PVOID buffer,UINT64 offset,ULONG length,BOOLEAN append,BOOLEAN constrained,PULONG done,FSP_FSCTL_FILE_INFO* info) {
    if(done)*done=0;if(!context||!done||!info||(!buffer&&length))return STATUS_INVALID_PARAMETER;
    return FusionCall(fs,"FusionWrite",[&](MountContext&,fusion_mount::State& s){
        if(!s.Writable())return STATUS_MEDIA_WRITE_PROTECTED;auto& h=*static_cast<fusion_mount::Handle*>(context);
        if(h.stream||h.node.IsDirectory())return STATUS_NOT_SUPPORTED;
        if(!s.GetMetadata(h.node.inode_id,h.node,s.error))return FusionStatus(s,false);
        if(append)offset=h.node.size;
        if(constrained){if(offset>=h.node.size)length=0;else length=static_cast<ULONG>((std::min<std::uint64_t>)(length,h.node.size-offset));}
        if(offset>FusionMaximumFileSize||length>FusionMaximumFileSize-offset)return STATUS_FILE_TOO_LARGE;
        while(*done<length){
            const auto count=(std::min)(length-*done,ULONG{256*1024});
            auto status=FusionMutationResult(s,s.writer->Overwrite(h.node.inode_id,offset+*done,std::span(static_cast<const std::byte*>(buffer)+*done,count),s.error));
            if(!NT_SUCCESS(status)){
                if(!*done||s.failed)return status;
                if(!s.GetMetadata(h.node.inode_id,h.node,s.error))return FusionStatus(s,false);
                FusionInfo(h,info);return STATUS_SUCCESS;
            }
            *done+=count;
        }
        if(!s.GetMetadata(h.node.inode_id,h.node,s.error))return FusionStatus(s,false);FusionInfo(h,info);*done=length;return STATUS_SUCCESS;
    });
}
NTSTATUS FusionSetBasic(FSP_FILE_SYSTEM* fs,PVOID context,UINT32 attrs,UINT64 create,UINT64 access,UINT64 write,UINT64 change,FSP_FSCTL_FILE_INFO* info) {
    if(!context||!info)return STATUS_INVALID_PARAMETER;
    return FusionCall(fs,"FusionSetBasicInfo",[&](MountContext&,fusion_mount::State& s){
        if(!s.Writable())return STATUS_MEDIA_WRITE_PROTECTED;auto& h=*static_cast<fusion_mount::Handle*>(context);
        if(h.stream||(attrs!=INVALID_FILE_ATTRIBUTES&&(attrs&~(FusionCopyAttributes|FILE_ATTRIBUTE_DIRECTORY))))return STATUS_NOT_SUPPORTED;
        if(!s.GetMetadata(h.node.inode_id,h.node,s.error))return FusionStatus(s,false);
        std::array<std::uint64_t,4> times={create,access,write,change},old={h.node.create_time,h.node.access_time,h.node.modification_time,h.node.change_time};
        bool changed=false;for(unsigned i=0;i<4;++i)changed|=times[i]&&times[i]!=UINT64_MAX&&times[i]!=old[i];
        if(changed){auto status=FusionMutationResult(s,s.writer->SetTimes(h.node.inode_id,times,s.error));if(!NT_SUCCESS(status))return status;}
        if(!s.GetMetadata(h.node.inode_id,h.node,s.error))return FusionStatus(s,false);FusionInfo(h,info);return STATUS_SUCCESS;
    });
}
NTSTATUS FusionCanDelete(FSP_FILE_SYSTEM* fs,PVOID context,PWSTR) {
    if(!context)return STATUS_INVALID_PARAMETER;
    return FusionCall(fs,"FusionCanDelete",[&](MountContext&,fusion_mount::State& s){
        if(!s.Writable())return STATUS_MEDIA_WRITE_PROTECTED;auto& h=*static_cast<fusion_mount::Handle*>(context);
        if(!s.GetMetadata(h.node.inode_id,h.node,s.error))return FusionStatus(s,false);
        if(h.stream||h.node.inode_id<=2||(!h.node.IsDirectory()&&h.node.children_or_links!=1))return STATUS_NOT_SUPPORTED;
        if(h.node.IsDirectory()&&h.node.children_or_links)return STATUS_DIRECTORY_NOT_EMPTY;
        return STATUS_SUCCESS; // The FSD enforces the actual handle share modes.
    });
}
NTSTATUS FusionSetDelete(FSP_FILE_SYSTEM* fs,PVOID context,PWSTR name,BOOLEAN deleting) {
    if(!context)return STATUS_INVALID_PARAMETER;
    return FusionCall(fs,"FusionSetDelete",[&](MountContext&,fusion_mount::State& s){
        if(!s.Writable())return STATUS_MEDIA_WRITE_PROTECTED;auto& h=*static_cast<fusion_mount::Handle*>(context);
        if(!s.GetMetadata(h.node.inode_id,h.node,s.error))return FusionStatus(s,false);
        if(h.stream||h.node.inode_id<=2||(!h.node.IsDirectory()&&h.node.children_or_links!=1))return STATUS_NOT_SUPPORTED;
        if(deleting&&h.node.IsDirectory()&&h.node.children_or_links)return STATUS_DIRECTORY_NOT_EMPTY;
        if(deleting&&h.node.IsDirectory()&&s.open_counts[h.node.inode_id]>1)return STATUS_SHARING_VIOLATION;
        return STATUS_SUCCESS;
    });
}
void FusionCleanup(FSP_FILE_SYSTEM* fs,PVOID context,PWSTR,ULONG flags) {
    if(!context)return;auto& h=*static_cast<fusion_mount::Handle*>(context);
    (void)FusionCall(fs,"FusionCleanupDelete",[&](MountContext&,fusion_mount::State& s){
        if(!h.cleaned){h.cleaned=true;auto it=s.open_counts.find(h.node.inode_id);
            if(it!=s.open_counts.end()&&!--it->second)s.open_counts.erase(it);}
        if(h.deleted)return STATUS_SUCCESS;
        const bool retained=s.writer&&s.writer->HasRetainedFile(h.node.inode_id);
        if(retained&&s.open_counts.contains(h.node.inode_id))return STATUS_SUCCESS;
        if(!retained&&!(flags&FspCleanupDelete))return STATUS_SUCCESS;
        if(!s.Writable()||h.stream){
            s.error="FusionCleanupDeleteBoundaryMismatch";s.failed=true;s.Cancel();return STATUS_IO_DEVICE_ERROR;}
        if(!s.GetMetadata(h.node.inode_id,h.node,s.error)){
            s.failed=true;s.Cancel();return STATUS_IO_DEVICE_ERROR;}
        const bool remaining=s.open_counts.contains(h.node.inode_id);
        auto status=FusionMutationResult(s,retained?s.writer->ReleaseRetainedFile(h.node.inode_id,s.error):
            remaining?s.writer->UnlinkRetainingFile(h.node.inode_id,s.error):s.writer->Unlink(h.node.inode_id,s.error));
        if(NT_SUCCESS(status))h.deleted=true;else{s.failed=true;s.Cancel();}return status;
    });
}
NTSTATUS FusionRename(FSP_FILE_SYSTEM* fs,PVOID context,PWSTR,PWSTR destination,BOOLEAN replace) {
    if(!context||!destination)return STATUS_INVALID_PARAMETER;
    return FusionCall(fs,"FusionRename",[&](MountContext&,fusion_mount::State& s){
        if(!s.Writable())return STATUS_MEDIA_WRITE_PROTECTED;auto& h=*static_cast<fusion_mount::Handle*>(context);
        if(h.stream||h.node.inode_id<=2||s.writer->HasRetainedFile(h.node.inode_id))return STATUS_NOT_SUPPORTED;
        std::uint64_t parent=0;std::string leaf;auto status=FusionParent(s,destination,parent,leaf);if(!NT_SUCCESS(status))return status;
        apfsaccess::rw::MetadataStore::DirectoryLink entry;const auto path=std::wstring_view(destination);const auto name=path.substr(path.rfind(L'\\')+1);
        std::uint64_t victim=0;
        if(s.LookupEntry(parent,name,entry,s.error)){
            if(entry.child_object_id!=h.node.inode_id){if(!replace)return STATUS_OBJECT_NAME_COLLISION;victim=entry.child_object_id;}
        } else if(s.LastStatus()!=apfsaccess::rw::FusionReadStatus::NotFound)return FusionStatus(s,false);
        const bool retain=victim&&s.open_counts.contains(victim);
        status=FusionMutationResult(s,retain?s.writer->RenameRetainingDestination(h.node.inode_id,parent,leaf,victim,s.error):
            victim?s.writer->RenameReplacing(h.node.inode_id,parent,leaf,victim,s.error):s.writer->Rename(h.node.inode_id,parent,leaf,s.error));
        if(NT_SUCCESS(status))h.entry_parent=parent;return status;
    });
}
