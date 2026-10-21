#pragma once
std::string SystemDataStatusJson(const MountContext& c)
{
    const auto* s=c.system_data.get();
    const char* health=!c.args.system_data.enabled?"NotSelected":!s?"NotAdmitted":
        s->failed.load()?"FailedReadOnly":s->cancelled.load()?"StoppedReadOnly":s->admitted.load()?"ImageTableReadOnly":"NotAdmitted";
    std::ostringstream out;
    out<<",\"systemDataRoute\":\""<<health<<"\",\"systemDataWritable\":false"
        <<",\"systemDataAuthority\":\"CanonicalSystemTable\",\"systemDataGenuineMacCorpus\":\"Unverified\""
        <<",\"systemDataCheckpointXid\":\""<<c.args.system_data.checkpoint_xid
        <<"\",\"systemDataSystemOid\":\""<<c.args.volume_object_id<<"\",\"systemDataDataOid\":\""<<c.args.system_data.data_oid
        <<"\",\"systemDataGroup\":\""<<WideToUtf8(c.args.system_data.group)<<"\",\"systemDataPairs\":";
    out<<(s?s->pair_count.load():0);
    return out.str();
}
