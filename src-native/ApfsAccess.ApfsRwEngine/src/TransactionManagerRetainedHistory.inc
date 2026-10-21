bool TransactionManager::CollectRetainedAcceptedTransactions(
    const std::vector<WriteAheadLog::Record>& records,
    RetainedAcceptedHistory& history, std::string& error) const
{
    RetainedAcceptedHistory result;
    result.watermarks = watermarks_;
    bool complete = !continuation_seed_;
    std::uint64_t previous = 0, latest = 0;
    std::unordered_map<std::uint64_t, std::vector<WriteAheadLog::Record>> prepared;
    for (const auto& record : records)
    {
        if (record.operation == WriteAheadLog::OperationKind::CompactionIndex)
        {
            complete = false;
            continue;
        }
        if (record.sequence != previous + 1) complete = false;
        previous = record.sequence;
        if (record.operation == WriteAheadLog::OperationKind::DurabilityWatermark) continue;
        if (record.operation != WriteAheadLog::OperationKind::TransactionMarker)
        {
            prepared[record.transaction_id].push_back(record);
            continue;
        }
        auto found = prepared.find(record.transaction_id);
        const bool accepted = record.state == WriteAheadLog::RecordState::Accepted ||
            (record.state == WriteAheadLog::RecordState::Checkpointed && record.flags == kWalFlagCommitted);
        if (accepted)
        {
            latest = record.sequence;
            const bool empty_commit = found == prepared.end() && record.logical_length == 0 &&
                record.state == WriteAheadLog::RecordState::Checkpointed;
            const bool retained = empty_commit ||
                (found != prepared.end() && found->second.size() == record.logical_length);
            if (!retained)
            {
                if (record.sequence > watermarks_.cleanup_sequence)
                {
                    error = "RetainedHistoryPendingTransactionIncomplete";
                    return false;
                }
                complete = false;
            }
            else
            {
                AcceptedTransaction transaction{record.transaction_id, record.sequence,
                    empty_commit ? std::vector<WriteAheadLog::Record>{} : std::move(found->second), record.object_id};
                auto& destination = record.sequence <= watermarks_.cleanup_sequence ? result.cleaned : result.pending;
                destination.push_back(std::move(transaction));
            }
        }
        if (found != prepared.end()) prepared.erase(found);
    }
    if (watermarks_.accepted_sequence > watermarks_.cleanup_sequence &&
        (result.pending.empty() || result.pending.back().accepted_sequence != watermarks_.accepted_sequence))
    {
        error = "RetainedHistoryPendingBoundaryMissing";
        return false;
    }
    if (latest != watermarks_.accepted_sequence) complete = false;
    result.coverage = !complete ? RetainedHistoryCoverage::Unavailable :
        watermarks_.accepted_sequence ? RetainedHistoryCoverage::RetainedComplete : RetainedHistoryCoverage::NoAcceptedHistory;
    history = std::move(result);
    return true;
}

bool TransactionManager::LoadRetainedAcceptedHistory(
    RetainedAcceptedHistory& history, std::string& error, WalReadLimits limits)
{
    history = {};
    error.clear();
    const auto fail = [&](const char* reason) { history = {}; error = reason; return false; };
    if (state_ != State::Idle || !recovery_state_valid_ || !preserve_startup_evidence_ ||
        journal_path_.empty() || volume_identity_.empty() || !JournalStateMatchesWriterLease())
        return fail("RetainedHistoryOriginalOwnerRequired");
    const auto generation = journal_.ExclusiveWriterLeaseGeneration();
    const auto existing = journal_.ReadStartupEvidence(limits, 256ull << 20);
    if (existing.status == WriteAheadLog::ReadStatus::ResourceLimit)
        return fail("RetainedHistoryResourceLimit");
    if (existing.status != WriteAheadLog::ReadStatus::Ok || existing.recovered_torn_tail ||
        !ValidateWalSemantics(existing.records)) return fail("RetainedHistoryOriginalEvidenceInvalid");

    // Recompute on a separate observer so the held owner is never reseeded.
    TransactionManager observer(L"Strict");
    observer.continuation_seed_ = continuation_seed_;
    observer.journal_protection_ = journal_protection_;
    if (!observer.SeedIdsFromJournalRecords(existing.records, 0) ||
        observer.watermarks_.accepted_sequence != watermarks_.accepted_sequence ||
        observer.watermarks_.apfs_durable_sequence != watermarks_.apfs_durable_sequence ||
        observer.watermarks_.cleanup_sequence != watermarks_.cleanup_sequence)
        return fail("RetainedHistoryWatermarkMismatch");
    if (!CollectRetainedAcceptedTransactions(existing.records, history, error)) return false;
    if (!generation || generation != journal_.ExclusiveWriterLeaseGeneration() ||
        !JournalStateMatchesWriterLease() ||
        (!existing.records.empty() && journal_.ValidatedAppendLeaseGeneration(true) != generation))
        return fail("RetainedHistoryOriginalLeaseChanged");
    history.writer_lease_generation = generation;
    return true;
}
