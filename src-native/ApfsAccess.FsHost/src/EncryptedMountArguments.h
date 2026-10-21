#pragma once
bool ParseEncryptedOption(const std::wstring& key, const std::wstring& value, encrypted_mount::Options& o)
{
    if (key==L"--encrypted-source-id") { o.source_id=value; return !value.empty(); }
    if (key==L"--encrypted-volume-uuid") { o.volume_uuid=value; return IsValidContainerId(value); }
    if (key==L"--encrypted-user-uuid") { o.user_uuid=value; return IsValidContainerId(value); }
    if (key==L"--encrypted-bag-length") { o.bag_length=value; return value==L"includes-header" || value==L"entries-only"; }
    if (key==L"--encrypted-write-root") { o.write_root=value; return !value.empty(); }
    const bool bag_oid=key==L"--encrypted-container-bag-oid" || key==L"--encrypted-volume-bag-oid";
    if (!IsCanonicalNonzeroDecimal(value) && !(bag_oid && value==L"0")) return false;
    std::uint64_t number=0;
    try { number=std::stoull(value); } catch(...) { return false; }
    if(key==L"--encrypted-store-size") o.store_size=number;
    else if(key==L"--encrypted-checkpoint-xid") o.checkpoint=number;
    else if(key==L"--encrypted-container-bag-oid") {o.container_bag_oid=number;o.container_bag_oid_supplied=true;}
    else if(key==L"--encrypted-container-bag-xid") o.container_bag_xid=number;
    else if(key==L"--encrypted-volume-bag-oid") {o.volume_bag_oid=number;o.volume_bag_oid_supplied=true;}
    else if(key==L"--encrypted-volume-bag-xid") o.volume_bag_xid=number;
    else return false;
    return true;
}
bool ValidateEncryptedArguments(const Arguments& a)
{
    const auto& o=a.encrypted; const auto& p=a.device;
    return o.enabled && p.size()>3 && ((p[0]>=L'A' && p[0]<=L'Z') || (p[0]>=L'a' && p[0]<=L'z')) &&
        p[1]==L':' && (p[2]==L'\\' || p[2]==L'/') && p.find(L':',2)==p.npos &&
        (o.write_root.empty() ? (a.readonly && !a.readwrite) :
            (!a.readonly && a.readwrite && o.write_root.size()>3 &&
                ((o.write_root[0]>=L'A' && o.write_root[0]<=L'Z') || (o.write_root[0]>=L'a' && o.write_root[0]<=L'z')) &&
                o.write_root[1]==L':' && o.write_root[2]==L'\\' && o.write_root.find(L':',2)==o.write_root.npos)) &&
        !a.snapshot_xid && IsWriteBackendMode(a.write_backend,L"Disabled") &&
        a.recovery_identity.empty() && !a.allow_raw_physical_write && a.container_manifest.empty() &&
        a.container_manifest_sha256.empty() && a.container_control_file.empty() && a.container_control_token.empty() &&
        IsValidContainerId(a.container_id) && a.volume_object_id && !a.mount.empty() &&
        a.parent_pid && !a.lifetime_file.empty() && !a.startup_gate_file.empty() && !a.startup_gate_token.empty() &&
        !a.status_file.empty() && !o.source_id.empty() && o.source_id.size()<256 &&
        std::all_of(o.source_id.begin(),o.source_id.end(),[](wchar_t c){return c>=32 && c<=126;}) &&
        IsValidContainerId(o.volume_uuid) && IsValidContainerId(o.user_uuid) && o.store_size && o.checkpoint &&
        (o.container_bag_oid || o.container_bag_oid_supplied) && o.container_bag_xid &&
        (o.volume_bag_oid || o.volume_bag_oid_supplied) && o.volume_bag_xid &&
        (o.bag_length==L"includes-header" || o.bag_length==L"entries-only");
}
