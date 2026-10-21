#pragma once
bool ParseFusionOption(const std::wstring& key,const std::wstring& value,fusion_mount::Options& o) {
    if(key==L"--fusion-write-root") {if(value.empty()||!o.write_root.empty())return false;o.write_root=value;return true;}
    static const std::set<std::wstring> keys={L"uuid",L"volume-uuid",L"checkpoint-xid",L"role-convention",
        L"member-a",L"member-b",L"identity-a",L"identity-b",L"role-a",L"role-b",
        L"store-id-a",L"store-id-b",L"store-offset-a",L"store-offset-b",L"store-size-a",L"store-size-b"};
    auto name=key.substr(9);
    return keys.contains(name) && !value.empty() && o.selectors.emplace(name,value).second;
}
bool BuildFusionRequest(const Arguments& a,apfsaccess::catalog::FusionBindRequest& r,
    apfsaccess::rw::FusionVolumeSelection& selection) {
    using namespace apfsaccess;
    using namespace fusion_arguments;
    try {
        const auto& o=a.fusion.selectors;
        if(o.size()!=16) return false;
        const auto get=[&](const wchar_t* key)->const std::wstring& {return o.at(key);};
        const auto number=[&](const wchar_t* key) {const auto& v=get(key);auto n=Number(v);
            if(std::to_wstring(n)!=v) throw PublicFailure{"NonCanonicalNumber",2};return n;};
        if(!IsValidContainerId(get(L"uuid")) || !IsValidContainerId(get(L"volume-uuid")) ||
            get(L"role-convention")!=L"linux-apfs-last-byte-low-bit") return false;
        r={};r.container_uuid_hex=WideToUtf8(a.container_id);r.fusion_uuid_hex=Ascii(get(L"uuid"));
        r.checkpoint_xid=number(L"checkpoint-xid");if(!r.checkpoint_xid)return false;
        r.convention=catalog::FusionRoleConvention::LinuxApfsLastByteLowBit;
        selection={r.container_uuid_hex,Ascii(get(L"volume-uuid")),{},a.volume_object_id,r.checkpoint_xid};
        for(const std::wstring suffix:{L"-a",L"-b"}) {
            const auto val=[&](const wchar_t* key)->const std::wstring& {return o.at(key+suffix);};
            catalog::FusionImageMember m;m.path=val(L"member");m.exact_identity=ParseIdentity(val(L"identity"));
            if(Utf8ToWide(Identity(m.exact_identity))!=val(L"identity"))return false;
            m.stable_store_id=Ascii(val(L"store-id"));
            if(m.stable_store_id.empty() || m.stable_store_id.size()>256)return false;
            m.store_offset=number((L"store-offset"+suffix).c_str());m.store_size=number((L"store-size"+suffix).c_str());
            if(val(L"role")!=L"main" && val(L"role")!=L"tier2")return false;
            const auto index=val(L"role")==L"main"?0:1;
            if(!selection.member_store_ids[index].empty())return false;
            m.role=index?catalog::FusionMemberRole::Tier2:catalog::FusionMemberRole::Main;
            selection.member_store_ids[index]=m.stable_store_id;r.members.push_back(std::move(m));
        }
        if(selection.member_store_ids[0]==selection.member_store_ids[1])return false;
        const auto& x=r.members[0];const auto& y=r.members[1];
        return !(x.exact_identity.volume_serial==y.exact_identity.volume_serial && x.exact_identity.file_id==y.exact_identity.file_id);
    } catch(...) {return false;}
}
bool ValidateFusionArguments(const Arguments& a) {
    apfsaccess::catalog::FusionBindRequest r;apfsaccess::rw::FusionVolumeSelection selection;
    const bool mode=a.fusion.write_root.empty()?(a.readonly&&!a.readwrite):(a.readwrite&&!a.readonly);
    return a.fusion.enabled && !a.encrypted.enabled && mode && !a.snapshot_xid &&
        IsWriteBackendMode(a.write_backend,L"Disabled") && !a.allow_raw_physical_write && a.recovery_identity.empty() &&
        a.device.empty() && !a.device_offset_bytes && a.container_manifest.empty() && a.container_manifest_sha256.empty() &&
        a.container_control_file.empty() && a.container_control_token.empty() && IsValidContainerId(a.container_id) &&
        a.volume_object_id && !a.mount.empty() && a.parent_pid && !a.lifetime_file.empty() &&
        !a.startup_gate_file.empty() && !a.startup_gate_token.empty() && !a.status_file.empty() && BuildFusionRequest(a,r,selection);
}
