#pragma once

NTSTATUS FusionMutationResult(fusion_mount::State& s,bool ok) {
    const auto water=s.writer->Watermarks();s.accepted=water.accepted_sequence;s.durable=water.apfs_durable_sequence;s.cleaned=water.cleanup_sequence;
    if(ok){s.PublicationCompleted();return s.Cache(s.error)?STATUS_SUCCESS:STATUS_IO_DEVICE_ERROR;}
    if(water.accepted_sequence!=water.cleanup_sequence){s.failed=true;s.Cancel();return STATUS_IO_DEVICE_ERROR;}
    if(s.deadline_expired.load()||s.error.find("DeadlineExpired")!=s.error.npos)return STATUS_IO_TIMEOUT;
    if(s.cancelled->load()||s.error.find("Cancelled")!=s.error.npos)return STATUS_CANCELLED;
    if(s.error.find("ReadBudget")!=s.error.npos)return STATUS_INSUFFICIENT_RESOURCES;
    if(s.error.find("Admission")!=s.error.npos||s.error.find("Read")!=s.error.npos)return STATUS_IO_DEVICE_ERROR;
    // These exact runtime results describe namespace conflicts. Structural
    // collision labels can wrap a failed read or admission and are I/O failures.
    if(s.error=="FusionRuntimeNameCollision")return STATUS_OBJECT_NAME_COLLISION;
    if(s.error.find("DirectoryNotEmpty")!=s.error.npos)return STATUS_DIRECTORY_NOT_EMPTY;
    if(s.error.find("DirectoryCycle")!=s.error.npos||s.error.find("InvalidName")!=s.error.npos)return STATUS_INVALID_PARAMETER;
    if(s.error.find("Collision")!=s.error.npos||s.error.find("Duplicate")!=s.error.npos)return STATUS_IO_DEVICE_ERROR;
    if(s.error.find("Exhaust")!=s.error.npos||s.error.find("Capacity")!=s.error.npos)return STATUS_DISK_FULL;
    std::string e;if(!s.CheckAvailable(e))return FusionStatus(s,false);
    return STATUS_NOT_SUPPORTED;
}
