bool TransactionManager::CaptureFusionOriginalForContinuation(FusionOriginalCapture& capture, std::string& error)
{
    const auto fail=[&](const char* why){error=why;return false;};
    if(state_!=State::Idle||!recovery_state_valid_||!preserve_startup_evidence_||journal_protection_||continuation_seed_||
        current_transaction_id_||!pending_mutations_.empty()||!buffered_prepared_records_.empty()||journal_append_ambiguous_||
        !watermarks_.accepted_sequence||watermarks_.accepted_sequence!=watermarks_.apfs_durable_sequence||
        watermarks_.accepted_sequence!=watermarks_.cleanup_sequence||!JournalStateMatchesWriterLease())
        return fail("FusionContinuationOriginalNotClean");
    if(!journal_.FlushPendingAppends()||!journal_.CaptureFusionOriginalForContinuation(capture)||
        !ValidateWalSemantics(capture.records))return fail("FusionContinuationOriginalCapture");
    TransactionManager observer(L"Strict");
    if(!observer.SeedIdsFromJournalRecords(capture.records,0)||observer.next_transaction_id_!=next_transaction_id_||
        observer.next_sequence_!=next_sequence_||observer.watermarks_.accepted_sequence!=watermarks_.accepted_sequence||
        observer.watermarks_.apfs_durable_sequence!=watermarks_.apfs_durable_sequence||
        observer.watermarks_.cleanup_sequence!=watermarks_.cleanup_sequence)
        return fail("FusionContinuationOriginalCounters");
    RetainedAcceptedHistory history;
    if(!CollectRetainedAcceptedTransactions(capture.records,history,error)||!history.pending.empty()||history.cleaned.empty()||
        history.cleaned.back().accepted_sequence!=watermarks_.accepted_sequence||history.cleaned.back().mutations.empty())
        return fail("FusionContinuationOriginalBoundary");
    capture.next_transaction=next_transaction_id_;capture.next_sequence=next_sequence_;
    capture.accepted=watermarks_.accepted_sequence;capture.floor=history.cleaned.back().mutations.front().sequence;
    std::vector<WriteAheadLog::Record> kept;
    for(const auto& row:capture.records)
        if(row.operation!=WriteAheadLog::OperationKind::CompactionIndex&&row.sequence>=capture.floor)kept.push_back(row);
    auto index=WriteAheadLog::Record{};index.volume_identity=capture.identity;index.sequence=capture.floor;
    index.operation=WriteAheadLog::OperationKind::CompactionIndex;index.state=WriteAheadLog::RecordState::Cleaned;
    kept.push_back(index);
    TransactionManager replacement(L"Strict");
    if(!replacement.SeedIdsFromJournalRecords(kept,0)||replacement.next_transaction_id_!=next_transaction_id_||
        replacement.next_sequence_!=next_sequence_||replacement.watermarks_.accepted_sequence!=capture.accepted||
        replacement.watermarks_.apfs_durable_sequence!=capture.accepted||replacement.watermarks_.cleanup_sequence!=capture.accepted)
        return fail("FusionContinuationReplacementCounters");
    return JournalStateMatchesWriterLease()&&journal_.MatchesFusionOriginalForContinuation(capture);
}

bool TransactionManager::CompactFusionOriginalForContinuation(const FusionCertifiedPredecessor& proof, std::string& error)
{
    if(!proof.original||!proof.revalidate){error="FusionContinuationCertificateRequired";return false;}
    FusionOriginalCapture current;
    if(!CaptureFusionOriginalForContinuation(current,error))return false;
    const auto& expected=*proof.original;
    if(current.bytes!=expected.bytes||current.volume_serial!=expected.volume_serial||current.file_id!=expected.file_id||
        current.writer_generation!=expected.writer_generation||current.floor!=expected.floor||
        current.accepted!=expected.accepted||current.next_sequence!=expected.next_sequence||
        current.next_transaction!=expected.next_transaction||!proof.revalidate()){
        error="FusionContinuationOriginalChanged";return false;
    }
    const auto result=journal_.CompactOrdinaryWithResult(expected.floor,expected.writer_generation,&proof);
    if(result!=WriteAheadLog::CompactionResult::Succeeded){
        recovery_state_valid_=false;InvalidateFinalizationCoverage(true);
        error=result==WriteAheadLog::CompactionResult::BytesMayHavePersisted?
            "FusionContinuationCompactionDebt":"FusionContinuationCompactionRefused";
        error+=":"+std::to_string(GetLastError());return false;
    }
    const auto read=journal_.ReadStartupEvidence({4ull<<20,4096},32ull<<20);
    if(read.status!=WriteAheadLog::ReadStatus::Ok||read.recovered_torn_tail||
        journal_.ExclusiveWriterLeaseGeneration()!=expected.writer_generation||
        !SeedIdsFromJournalRecords(read.records,journal_.ExclusiveWriterLeaseGeneration())||
        next_sequence_!=expected.next_sequence||next_transaction_id_!=expected.next_transaction||
        watermarks_.accepted_sequence!=expected.accepted||watermarks_.apfs_durable_sequence!=expected.accepted||
        watermarks_.cleanup_sequence!=expected.accepted){
        recovery_state_valid_=false;InvalidateFinalizationCoverage(true);
        error="FusionContinuationReplacementEvidence";return false;
    }
    return true;
}
