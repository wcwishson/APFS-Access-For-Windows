#pragma once
bool ParseSystemDataOption(const std::wstring& key,const std::wstring& value,system_data_mount::Options& out)
{
    if(key==L"--system-data-group") {if(!out.group.empty()||!IsValidContainerId(value))return false;out.group=value;return true;}
    if(!IsCanonicalNonzeroDecimal(value))return false;
    try {
        const auto number=std::stoull(value);
        if(std::to_wstring(number)!=value)return false;
        if(key==L"--system-data-data-oid"&&!out.data_oid){out.data_oid=number;return true;}
        if(key==L"--system-data-checkpoint-xid"&&!out.checkpoint_xid){out.checkpoint_xid=number;return true;}
    }catch(...){}
    return false;
}
bool ValidateSystemDataArguments(const Arguments& a)
{
    return a.system_data.enabled&&!a.encrypted.enabled&&!a.fusion.enabled&&a.readonly&&!a.readwrite&&
        !a.snapshot_xid&&a.snapshot_name.empty()&&!a.allow_raw_physical_write&&!a.enable_image_snapshots&&
        !a.enable_raw_snapshots&&!a.enable_retained_physical_snapshot_inventory&&
        IsWriteBackendMode(a.write_backend,L"Disabled")&&(a.recovery_identity.empty()||IsValidRecoveryIdentity(a.recovery_identity))&&
        a.container_manifest.empty()&&a.container_manifest_sha256.empty()&&a.container_control_file.empty()&&
        a.container_control_token.empty()&&!a.device_offset_bytes&&IsValidContainerId(a.container_id)&&
        IsValidContainerId(a.system_data.group)&&a.system_data.data_oid&&a.volume_object_id&&
        a.system_data.data_oid!=a.volume_object_id&&a.system_data.checkpoint_xid&&
        !a.device.empty()&&!IsRawPhysicalDevicePath(a.device)&&!a.mount.empty()&&a.parent_pid&&
        !a.lifetime_file.empty()&&!a.startup_gate_file.empty()&&!a.startup_gate_token.empty()&&!a.status_file.empty();
}
