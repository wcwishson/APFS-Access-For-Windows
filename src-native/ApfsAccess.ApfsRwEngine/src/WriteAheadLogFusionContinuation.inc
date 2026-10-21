bool WriteAheadLog::CaptureFusionOriginalForContinuation(FusionOriginalCapture& out) const
{
    std::lock_guard<std::recursive_mutex> operation_lock(WalOperationMutex(options_.path));
    if(options_.protected_persistence||!preserve_startup_evidence_||!ValidatedAppendLeaseGeneration(true))return false;
    auto reader=OpenWalFile(options_.path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(reader==INVALID_HANDLE_VALUE)return false;
    PhysicalFileIdentity identity{},held{};std::uint64_t size=0;
    bool valid=IsSafeWalPathHandle(reader)&&TryGetPhysicalFileIdentity(reader,identity)&&
        TryGetPhysicalFileIdentity(static_cast<HANDLE>(append_handle_),held)&&
        identity.volume_serial==held.volume_serial&&identity.file_id==held.file_id&&
        PathMatchesPhysicalFile(options_.path,identity,true)&&TryGetPhysicalFileSize(reader,size)&&size&&size<=(4ull<<20);
    std::vector<std::uint8_t> bytes;
    if(valid){bytes.resize(static_cast<std::size_t>(size));DWORD done=0;
        valid=ReadFile(reader,bytes.data(),static_cast<DWORD>(bytes.size()),&done,nullptr)&&done==bytes.size();}
    auto decoded=valid?DecodeWalBytes(bytes,options_.volume_identity,nullptr,{4ull<<20,4096},true):ReadResult{};
    valid=valid&&decoded.status==ReadStatus::Ok&&!decoded.recovered_torn_tail&&
        PathMatchesPhysicalFile(options_.path,identity,true)&&ValidatedAppendLeaseGeneration(true);
    valid=CloseHandle(reader)!=FALSE&&valid;
    if(!valid)return false;
    out.path=options_.path;out.identity=options_.volume_identity;out.volume_serial=identity.volume_serial;
    out.file_id=identity.file_id;out.writer_generation=writer_lease_generation_;
    out.bytes=std::move(bytes);out.records=std::move(decoded.records);return true;
}

bool WriteAheadLog::MatchesFusionOriginalForContinuation(const FusionOriginalCapture& expected) const
{
    FusionOriginalCapture actual;
    return CaptureFusionOriginalForContinuation(actual)&&actual.path==expected.path&&actual.identity==expected.identity&&
        actual.volume_serial==expected.volume_serial&&actual.file_id==expected.file_id&&
        actual.writer_generation==expected.writer_generation&&actual.bytes==expected.bytes;
}

WriteAheadLog::ReadResult WriteAheadLog::DecodeFusionOriginalForContinuation(
    const std::vector<std::uint8_t>& bytes,const std::string& identity)
{
    return DecodeWalBytes(bytes,identity,nullptr,{4ull<<20,4096},true);
}

bool WriteAheadLog::ValidateFusionReplacementReceipt(const FusionOriginalCapture& predecessor,
    const FusionOriginalCapture& current) const
{
    std::lock_guard<std::recursive_mutex> operation_lock(WalOperationMutex(options_.path));
    if(!MatchesFusionOriginalForContinuation(current)||predecessor.identity!=current.identity||
        predecessor.path!=current.path||predecessor.volume_serial!=current.volume_serial||
        predecessor.file_id==current.file_id)return false;
    auto receipt=OpenWalFile(CompactionIntentPath(options_.path),GENERIC_READ,FILE_SHARE_READ,nullptr,
        OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(receipt==INVALID_HANDLE_VALUE)return false;
    const auto read=ReadAllEvidenceFromHeldHandle(receipt,options_.volume_identity,{1ull<<20,8},8ull<<20);
    bool valid=read.status==ReadStatus::Ok&&!read.recovered_torn_tail&&
        IsStrictCompactionIntentHistory(read.records,options_.volume_identity);
    if(valid){const auto& last=read.records.back();valid=last.state==RecordState::Cleaned&&
        last.flags==kCompactionIntentNamespaceDurableFlag&&last.parent_object_id==predecessor.volume_serial&&
        last.object_id==predecessor.file_id&&last.logical_offset==current.file_id;}
    return CloseHandle(receipt)!=FALSE&&valid;
}

bool WriteAheadLog::InspectFusionCompactionRecovery(FusionOriginalCapture& out) const
{
    std::lock_guard<std::recursive_mutex> operation_lock(WalOperationMutex(options_.path));
    if(options_.protected_persistence||!preserve_startup_evidence_||!EnsureWriterLease())return false;
    auto receipt=OpenWalFile(CompactionIntentPath(options_.path),GENERIC_READ,FILE_SHARE_READ,nullptr,
        OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(receipt==INVALID_HANDLE_VALUE)return false;
    const auto read=ReadAllEvidenceFromHeldHandle(receipt,options_.volume_identity,{1ull<<20,8},8ull<<20);
    if(!CloseHandle(receipt)||read.status!=ReadStatus::Ok||read.recovered_torn_tail||
        !IsStrictCompactionIntentHistory(read.records,options_.volume_identity))return false;
    const auto& last=read.records.back();
    if(!last.object_id||!last.logical_offset||last.parent_object_id>UINT32_MAX)return false;
    for(const auto& path:{options_.path,CompactionPredecessorGuardPath(options_.path,last.object_id)}){
        auto file=OpenWalFile(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,
            OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        if(file==INVALID_HANDLE_VALUE)continue;
        PhysicalFileIdentity identity{};std::uint64_t size=0;std::vector<std::uint8_t> bytes;DWORD done=0;
        bool valid=IsRegularWalPathHandle(file)&&TryGetPhysicalFileIdentity(file,identity)&&
            identity.volume_serial==last.parent_object_id&&(identity.file_id==last.object_id||identity.file_id==last.logical_offset)&&
            TryGetPhysicalFileSize(file,size)&&size&&size<=(4ull<<20)&&PathMatchesPhysicalFile(path,identity,false);
        if(valid){bytes.resize(static_cast<std::size_t>(size));valid=ReadFile(file,bytes.data(),static_cast<DWORD>(bytes.size()),&done,nullptr)&&done==bytes.size();}
        valid=CloseHandle(file)!=FALSE&&valid;if(!valid)continue;
        auto decoded=DecodeWalBytes(bytes,options_.volume_identity,nullptr,{4ull<<20,4096},true);
        if(decoded.status!=ReadStatus::Ok||decoded.recovered_torn_tail)continue;
        out.path=options_.path;out.identity=options_.volume_identity;out.volume_serial=last.parent_object_id;
        out.file_id=last.object_id;out.writer_generation=writer_lease_generation_;out.floor=0;
        if(identity.file_id==last.object_id){
            for(const auto& row:decoded.records)if(row.operation==OperationKind::TransactionMarker&&row.state==RecordState::Accepted)
                out.accepted=row.sequence;
            for(const auto& row:decoded.records)if(row.sequence+1==out.accepted)out.floor=row.sequence;
            out.bytes=std::move(bytes);out.records=std::move(decoded.records);
        }else{
            for(const auto& row:decoded.records)if(row.operation==OperationKind::CompactionIndex){
                if(out.floor)return false;out.floor=row.sequence;}
        }
        if(out.floor)return true;
    }
    return false;
}

bool WriteAheadLog::RecoverFusionCompaction(const FusionCertifiedPredecessor& proof) const
{
    std::lock_guard<std::recursive_mutex> operation_lock(WalOperationMutex(options_.path));
    FusionOriginalCapture observed;
    if(!proof.original||!proof.revalidate||!InspectFusionCompactionRecovery(observed))return false;
    const auto& original=*proof.original;
    if(observed.path!=original.path||observed.identity!=original.identity||observed.volume_serial!=original.volume_serial||
        observed.file_id!=original.file_id||observed.floor!=original.floor||
        observed.writer_generation!=original.writer_generation||
        (!observed.bytes.empty()&&observed.bytes!=original.bytes)||!proof.revalidate())return false;
    std::vector<std::uint8_t> replacement;
    for(const auto& row:original.records)if(row.operation!=OperationKind::CompactionIndex&&row.sequence>=original.floor){
        auto bytes=EncodeForTest(row);replacement.insert(replacement.end(),bytes.begin(),bytes.end());}
    Record index;index.volume_identity=original.identity;index.sequence=original.floor;
    index.operation=OperationKind::CompactionIndex;index.state=RecordState::Cleaned;
    auto encoded=EncodeForTest(index);replacement.insert(replacement.end(),encoded.begin(),encoded.end());
    auto receipt=OpenWalFile(CompactionIntentPath(options_.path),GENERIC_READ,FILE_SHARE_READ,nullptr,
        OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(receipt==INVALID_HANDLE_VALUE)return false;
    auto history=ReadAllEvidenceFromHeldHandle(receipt,options_.volume_identity,{1ull<<20,8},8ull<<20);
    if(!CloseHandle(receipt)||history.status!=ReadStatus::Ok||history.recovered_torn_tail||
        !IsStrictCompactionIntentHistory(history.records,options_.volume_identity))return false;
    const auto intent=history.records.back();
    const auto verify=[&](const std::filesystem::path& path){
        auto file=OpenWalFile(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,
            OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        if(file==INVALID_HANDLE_VALUE)return false;
        PhysicalFileIdentity identity{};std::uint64_t size=0;DWORD done=0;std::vector<std::uint8_t> bytes;
        bool valid=IsRegularWalPathHandle(file)&&TryGetPhysicalFileIdentity(file,identity)&&
            identity.volume_serial==original.volume_serial&&TryGetPhysicalFileSize(file,size)&&size<=(4ull<<20);
        if(valid){bytes.resize(static_cast<std::size_t>(size));valid=ReadFile(file,bytes.data(),static_cast<DWORD>(bytes.size()),&done,nullptr)&&done==bytes.size();}
        valid=valid&&((identity.file_id==original.file_id&&(bytes==original.bytes||
            (bytes.empty()&&intent.state==RecordState::Cleaned)))||
            (identity.file_id==intent.logical_offset&&bytes==replacement));
        return CloseHandle(file)!=FALSE&&valid;
    };
    const auto attributes=WalFileAttributes(options_.path.c_str());
    if(attributes!=INVALID_FILE_ATTRIBUTES&&!verify(options_.path))return false;
    if(attributes==INVALID_FILE_ATTRIBUTES&&GetLastError()!=ERROR_FILE_NOT_FOUND)return false;
    WIN32_FIND_DATAW found{};auto search=FindFirstFileW(WalIoPath(options_.path.wstring()+L".compact*").c_str(),&found);
    if(search==INVALID_HANDLE_VALUE)return false;
    bool valid=true;unsigned count=0;
    do{const auto path=options_.path.parent_path()/found.cFileName;
        if(++count>4||(found.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))||
            (path!=CompactionIntentPath(options_.path)&&!verify(path))){valid=false;break;}
    }while(FindNextFileW(search,&found));
    const auto find_error=GetLastError();valid=FindClose(search)!=FALSE&&valid&&find_error==ERROR_NO_MORE_FILES;
    if(!valid||!proof.revalidate())return false;
    // The legacy native repair executes only after every extant member of its
    // namespace matches this exact protected old/replacement pair. No tail or
    // arbitrary incomplete stream can enter this branch.
    preserve_startup_evidence_=false;
    bool repaired=CloseAppendFileHandle()&&EnsureAppendHandle(true,false)&&ResolvePendingCompactionIntent();
    preserve_startup_evidence_=true;startup_journal_state_=StartupJournalState::Unobserved;
    startup_writer_lease_generation_=writer_lease_generation_;startup_evidence_valid_=false;
    if(!repaired)return false;
    const auto current=ReadStartupEvidence({4ull<<20,4096},32ull<<20);
    return current.status==ReadStatus::Ok&&!current.recovered_torn_tail&&
        writer_lease_generation_==original.writer_generation&&proof.revalidate();
}
