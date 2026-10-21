#pragma once
std::string EscapeJson(const std::string& value);
std::string FusionStatusJson(const MountContext& c)
{
    std::ostringstream out;
    const auto* s=c.fusion.get();const auto enabled=c.args.fusion.enabled;
    const auto missing=s?s->missing_members.load():0;
    const bool writable=s&&s->Writable();
    const char* health=writable?"ReadWrite":!enabled?"NotApplicable":!s?"NotAdmittedReadOnly":missing?"MissingMemberReadOnly":
        s->failed.load()?"ErrorReadOnly":s->cancelled->load()?"StoppedReadOnly":s->admitted.load()?"ReadOnly":"NotAdmittedReadOnly";
    out<<",\"immutableFusionImageSet\":"<<(enabled&&c.args.fusion.write_root.empty()?"true":"false")<<",\"fusionHealth\":\""<<health
        <<"\",\"fusionMissingMemberMask\":"<<missing<<",\"fusionWritable\":"<<(writable?"true":"false")
        <<",\"fusionCheckpointXid\":"<<(s?s->checkpoint.load():0)<<",\"fusionAcceptedSequence\":"<<(s?s->accepted.load():0)
        <<",\"fusionDurableSequence\":"<<(s?s->durable.load():0)<<",\"fusionCleanupSequence\":"<<(s?s->cleaned.load():0)
        <<",\"fusionLastFailure\":\""<<EscapeJson(s?s->LastFailure():std::string{})<<"\",\"fusionMembers\":[";
    bool comma=false;
    for(const std::wstring suffix:{L"-a",L"-b"}) {
        const auto& selectors=c.args.fusion.selectors;
        if(!selectors.contains(L"member"+suffix))continue;
        if(comma)out<<',';comma=true;out<<'{';bool field=false;
        for(const std::wstring key:{L"member",L"identity",L"role",L"store-id",L"store-offset",L"store-size"}) {
            auto it=selectors.find(key+suffix);if(it==selectors.end())continue;
            if(field)out<<',';field=true;out<<'"'<<WideToUtf8(key)<<"\":\""<<EscapeJson(WideToUtf8(it->second))<<'"';
        }
        const auto role=selectors.find(L"role"+suffix);
        const auto index=role!=selectors.end() && role->second==L"main"?0:1;
        out<<",\"state\":\""<<((missing&(1u<<index))?"Unavailable":!s?"NotAdmitted":
            s->admitted.load()?(s->write_mode?"HeldExclusive":"HeldReadOnly"):"ReleasedOrNotAdmitted")<<"\"}";
    }
    out<<"],\"fusionSelection\":{";bool comma2=false;
    for(const auto& [key,value]:c.args.fusion.selectors) if(key==L"uuid" || key==L"volume-uuid" || key==L"checkpoint-xid" || key==L"role-convention") {
        if(comma2)out<<',';comma2=true;out<<'"'<<WideToUtf8(key)<<"\":\""<<EscapeJson(WideToUtf8(value))<<'"';
    }
    out<<"},\"fusionContainerUuid\":\""<<EscapeJson(WideToUtf8(c.args.container_id))<<"\",\"fusionVolumeOid\":\""<<c.args.volume_object_id<<"\",\"fusionProfile\":\"clean-anchors-empty-caches-main-checkpoint\"";
    return out.str();
}
