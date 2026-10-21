namespace apfsaccess::rw
{
bool TransactionManager::MaterializeAbsentProtectedStartupJournal(
    const std::function<bool()>& census_current, std::string& error)
{
    error.clear();
    if (!journal_protection_ || !preserve_startup_evidence_ || !ProtectedSpoolOwnerValid() ||
        !census_current || current_transaction_id_ || next_transaction_id_ != 1 || next_sequence_ != 1 ||
        journal_.ValidatedAppendLeaseGeneration(true) || continuation_seed_ ||
        watermarks_.accepted_sequence || watermarks_.apfs_durable_sequence || watermarks_.cleanup_sequence ||
        last_committed_sequence_ || highest_checkpointed_marker_sequence_ || !accepted_boundaries_.empty())
    { error = "ProtectedAbsentStartupStateInvalid"; return false; }
    if (!journal_.MaterializeAbsentProtectedStartupJournal(census_current) || !SeedIdsFromExistingJournal(true))
    {
        recovery_state_valid_ = false;
        InvalidateFinalizationCoverage(true);
        error = "ProtectedAbsentStartupMaterializationRefused";
        return false;
    }
    return true;
}

bool TransactionManager::ProtectedBackupMutationCapacityAvailable(const MutationIntent& intent, std::string& error)
{
    std::lock_guard append_lock(deferred_wal_append_mutex_);
    error.clear();
    const auto fail = [&](const char* reason) { error = reason; return false; };
    const auto owner_current = [&] {
        if (state_ == State::Idle) return ProtectedSpoolOwnerValid();
        if (state_ != State::Active || !journal_protection_ || !recovery_state_valid_ ||
            !current_transaction_id_ || journal_path_.empty() || volume_identity_.empty() ||
            journal_append_ambiguous_ || !journal_.HasExclusiveWriterLease() || !JournalStateMatchesWriterLease() ||
            pending_mutations_.size() >= 64 || buffered_prepared_records_.size() != pending_mutations_.size()) return false;
        std::lock_guard state_lock(deferred_wal_state_mutex_);
        return !deferred_wal_flush_failed_ && !deferred_wal_flush_in_progress_;
    };
    if (!owner_current() || !next_sequence_ || next_sequence_ > UINT64_MAX - 9 ||
        !next_transaction_id_ || next_transaction_id_ == UINT64_MAX || intent.object_id <= 2 || !intent.generation ||
        (intent.wal_sequence && intent.wal_sequence != next_sequence_) || !journal_.ValidatedAppendLeaseGeneration(true))
        return fail("ProtectedBackupCapacityOwnerInvalid");
    const auto path = [](const std::wstring& value) {
        return !value.empty() && value.size() <= 4096 && value.front() == L'\\' &&
            value.find(L'\0') == value.npos && value.find(L'/') == value.npos &&
            (value.size() == 1 || value.back() != L'\\') && value.find(L"\\\\") == value.npos &&
            value.find(L"\\.\\") == value.npos && value.find(L"\\..\\") == value.npos &&
            !value.ends_with(L"\\.") && !value.ends_with(L"\\..");
    };
    const bool write = intent.kind == MutationKind::Write;
    const bool attribute = intent.kind == MutationKind::SetExtendedAttribute || intent.kind == MutationKind::RemoveExtendedAttribute;
    const bool patch = intent.kind == MutationKind::SetInodeMetadata, clone = intent.kind == MutationKind::CloneFile;
    const bool rename = intent.kind == MutationKind::Rename, basic = intent.kind == MutationKind::SetBasicInfo;
    const bool payload = write || patch || clone || intent.kind == MutationKind::SetExtendedAttribute;
    const bool sized = write || patch || clone || intent.kind == MutationKind::SetFileSize || intent.kind == MutationKind::SetAllocationSize;
    if (!path(intent.path) || (rename || clone ? !path(intent.secondary_path) :
            attribute ? (intent.secondary_path.empty() || intent.secondary_path.size() > 4096 || intent.secondary_path.find(L'\0') != intent.secondary_path.npos) :
                !intent.secondary_path.empty()) ||
        (intent.replace_if_exists && !rename) || (intent.unlink_outcome && intent.kind != MutationKind::Delete) ||
        (!write && intent.offset) || (!basic && intent.timestamp_utc) || (!sized && intent.length) ||
        (!payload && (intent.payload_length || intent.payload_spool_offset || !intent.inline_payload.empty() ||
            std::any_of(intent.payload_checksum.begin(), intent.payload_checksum.end(), [](auto b) { return b != 0; }))) ||
        (!write && intent.payload_spool_offset) ||
        (write && (!intent.payload_length || intent.payload_length > (256ull << 10) || intent.length != intent.payload_length ||
            intent.offset > (8ull << 20) - intent.length || intent.payload_spool_offset > UINT64_MAX - intent.payload_length - 80)) ||
        ((patch || clone) && (intent.length != intent.inline_payload.size() || intent.payload_length != intent.inline_payload.size())) ||
        (attribute && (intent.length || intent.payload_length != intent.inline_payload.size())))
        return fail("ProtectedBackupCapacityShapeInvalid");
    switch (intent.kind) {
    case MutationKind::Write: case MutationKind::CreateFile: case MutationKind::CreateDirectory:
    case MutationKind::Rename: case MutationKind::Delete: case MutationKind::SetFileSize: case MutationKind::SetAllocationSize:
    case MutationKind::SetBasicInfo: case MutationKind::SetInodeMetadata: case MutationKind::SetExtendedAttribute:
    case MutationKind::RemoveExtendedAttribute: case MutationKind::CloneFile: break;
    default: return fail("ProtectedBackupCapacityKindUnsupported");
    }
    if ((intent.kind == MutationKind::CreateFile || intent.kind == MutationKind::CreateDirectory) &&
        (intent.length || intent.offset || intent.payload_length || !intent.inline_payload.empty()))
        return fail("ProtectedBackupCapacityShapeInvalid");
    if ((intent.kind == MutationKind::SetFileSize || intent.kind == MutationKind::SetAllocationSize) && intent.length > (8ull << 20))
        return fail("ProtectedBackupCapacityShapeInvalid");
    try
    {
        WriteAheadLog::ProtectedHistoryHead head;
        if (!journal_.CaptureProtectedHistoryHead(head) || head.last_sequence > next_sequence_ - 1 ||
            next_sequence_ - 1 - head.last_sequence != buffered_prepared_records_.size())
            return fail("ProtectedBackupCapacityEvidenceUnavailable");
        const auto& protection = *journal_protection_;
        std::uint64_t bytes = head.bytes, count = head.records;
        const auto capacity = (std::min)({journal_max_bytes_, protection.read_limits.bytes, protection.max_allocation_bytes / 4});
        const auto account = [&](const WriteAheadLog::Record& record) {
            auto encoded = WriteAheadLog::EncodeForTest(record);
            const auto size = encoded.size(); if (size) SecureZeroMemory(encoded.data(), size);
            const auto framing = journal::kJournalRecordHeaderBytes + crypto::kGcmTagBytes;
            if (!size || size > journal::kMaxJournalPlaintextBytes || bytes > capacity || size + framing > capacity - bytes) return false;
            bytes += size + framing; ++count;
            return count <= protection.read_limits.records &&
                count <= (protection.max_allocation_bytes - bytes * 4) / (2 * sizeof(WriteAheadLog::Record) + 4);
        };
        for (std::size_t i = 0; i < buffered_prepared_records_.size(); ++i) {
            const auto& buffered = buffered_prepared_records_[i];
            if (buffered.sequence != head.last_sequence + i + 1 ||
                buffered.transaction_id != current_transaction_id_ || !account(buffered))
                return fail("ProtectedBackupCapacityPendingExceeded");
        }
        std::vector<WriteAheadLog::Record> projected(1); OriginalHistoryCleanup cleanup{projected};
        auto& record = projected.front();
        record.volume_identity = EffectiveVolumeIdentity(volume_identity_);
        record.transaction_id = state_ == State::Active ? current_transaction_id_ : next_transaction_id_;
        record.sequence = next_sequence_; record.state = WriteAheadLog::RecordState::Prepared; record.operation = ToWalOperation(intent.kind);
        record.object_id = intent.object_id; record.parent_object_id = intent.generation;
        record.logical_offset = basic ? intent.timestamp_utc : intent.offset; record.logical_length = patch || clone || attribute ? 0 : intent.length;
        record.payload_spool_id = write ? next_sequence_ : 0; record.payload_offset = intent.payload_spool_offset;
        record.payload_length = intent.payload_length; record.inline_payload = intent.inline_payload; record.payload_sha256 = intent.payload_checksum;
        record.path_utf8 = WideToUtf8(intent.path); record.secondary_path_utf8 = WideToUtf8(intent.secondary_path);
        record.flags = rename && intent.replace_if_exists ? kWalFlagReplaceIfExists : 0; record.unlink_outcome = intent.unlink_outcome;
        if (!WriteAheadLog::InlinePayloadIsConsistent(record) || !WriteAheadLog::UnlinkOutcomeIsConsistent(record) ||
            !WriteAheadLog::InodeMetadataMutationIsConsistent(record) || !WriteAheadLog::ExtendedAttributeMutationIsConsistent(record) ||
            !WriteAheadLog::AllocationSizeMutationIsConsistent(record) || !WriteAheadLog::NativeCloneIsConsistent(record) ||
            (intent.kind == MutationKind::Delete && !record.unlink_outcome))
            return fail("ProtectedBackupCapacityRecordInvalid");
        if (!account(record)) return fail("ProtectedBackupCapacityExceeded");
        cleanup.Clear(); projected.resize(1);
        auto& marker = projected.front(); marker.volume_identity = EffectiveVolumeIdentity(volume_identity_);
        marker.transaction_id = state_ == State::Active ? current_transaction_id_ : next_transaction_id_;
        marker.operation = WriteAheadLog::OperationKind::TransactionMarker;
        marker.state = WriteAheadLog::RecordState::Accepted; marker.flags = kWalFlagAccepted;
        marker.logical_length = buffered_prepared_records_.size() + 1;
        marker.path_utf8 = WideToUtf8(safety_level_);
        for (unsigned n = 0; n < 7; ++n) { marker.sequence = next_sequence_ + n + 1; if (!account(marker)) return fail("ProtectedBackupCapacityExceeded"); }
        return owner_current() || fail("ProtectedBackupCapacityEvidenceUnavailable");
    }
    catch (...) { return fail("ProtectedBackupCapacityEvidenceUnavailable"); }
}
}
