// Explicit backup-only counterpart of the ordinary retained-prefix proof.
// Both admission and each historical reconstruction use the complete backup
// profile; no ordinary or shared-container role is admitted through this entry.
bool MetadataStore::PrepareBackupRetainedWritePath(const BackupRetainedSource& source, std::string& error)
try
{
    error.clear();
    if (!device_ || !context_.allow_native_snapshot_runtime || context_.shared_container_session || !source.Current() ||
        (!AuthoritativeAppleCheckpointView() && !LoadContainerState()))
    { error = "BackupRetainedPreparationSourceUnavailable"; return false; }
    const auto* selected = AuthoritativeAppleCheckpointView();
    if (!selected || !source.Matches(*device_, context_.device_offset_bytes, *selected,
            context_.volume_object_id, source.RecoveryIdentity()) ||
        !ValidateBackupImageWriterProfile(source, *selected, context_.volume_object_id, error)) return false;
    BackupNoIoWriterScope scope(this, source);
    if (!PrepareNativeWritePath() || !source.Current())
    { error = "BackupRetainedCanonicalPreparationFailed"; return false; }
    return true;
}
catch (...) { error = "BackupRetainedPreparationFailed"; return false; }

MetadataStore::MutationStatus MetadataStore::StageBackupRetainedMutation(const BackupRetainedSource& source,
    const MutationRequest& request, PayloadIdentity* identity)
{
    const auto* selected = AuthoritativeAppleCheckpointView();
    if (identity) *identity = {};
    if (request.operation != MutationOperation::Write) return MutationStatus::UnsupportedOperation;
    if (!device_ || !selected || !context_.allow_native_snapshot_runtime || context_.shared_container_session ||
        !source.Matches(*device_, context_.device_offset_bytes, *selected, context_.volume_object_id, source.RecoveryIdentity()))
        return MutationStatus::NotReady;
    BackupNoIoWriterScope scope(this, source);
    const auto status = StageMutation(request, identity);
    return source.Current() ? status : MutationStatus::NotReady;
}

MetadataStore::MutationStatus MetadataStore::StageBackupRetainedTypedMutation(const BackupRetainedSource& source,
    const MutationRequest& request, PayloadIdentity* identity, std::optional<UnlinkOutcome>* unlink)
{
    if (identity) *identity = {};
    if (unlink) unlink->reset();
    if (!IsBackupRetainedMutation(request.operation)) return MutationStatus::UnsupportedOperation;
    const auto* selected = AuthoritativeAppleCheckpointView();
    if (!device_ || !selected || !context_.allow_native_snapshot_runtime || context_.shared_container_session ||
        !source.Matches(*device_, context_.device_offset_bytes, *selected, context_.volume_object_id, source.RecoveryIdentity()))
        return MutationStatus::NotReady;
    BackupNoIoWriterScope scope(this, source);
    const auto status = StageMutation(request, identity, unlink);
    return source.Current() ? status : MutationStatus::NotReady;
}

bool MetadataStore::PrepareBackupRetainedClone(const BackupRetainedSource& source,
    const std::wstring& from, const std::wstring& target, MutationRequest& request, std::string& error) const
{
    request = {}; error.clear();
    const auto* selected = AuthoritativeAppleCheckpointView();
    if (!device_ || !selected || !context_.allow_native_snapshot_runtime || context_.shared_container_session ||
        !source.Matches(*device_, context_.device_offset_bytes, *selected, context_.volume_object_id, source.RecoveryIdentity()))
    { error = "BackupRetainedCloneSourceUnavailable"; return false; }
    BackupNoIoWriterScope scope(this, source);
    if (!PrepareNativeClone(from, target, request) || !source.Current())
    { request = {}; error = "BackupRetainedCloneUnsupported"; return false; }
    return true;
}

MetadataStore::CloneAcceptance MetadataStore::AcceptBackupRetainedClone(const BackupRetainedSource& source,
    TransactionManager& original, const std::wstring& from, const std::wstring& target, CloneReceipt& receipt, std::string& error)
{
    receipt = {}; error.clear(); MutationRequest request;
    if (!source.JournalSourceBinding() || original.ProtectedSourceBinding() != source.JournalSourceBinding() ||
        !original.CanClearRecoveryState() || !PrepareBackupRetainedClone(source, from, target, request, error))
        return CloneAcceptance::Refused;
    TransactionManager::MutationIntent intent;
    intent.kind = TransactionManager::MutationKind::CloneFile; intent.path = request.path;
    intent.secondary_path = request.secondary_path; intent.object_id = request.object_id;
    intent.generation = request.generation; intent.length = intent.payload_length = request.inline_payload.size();
    intent.inline_payload = request.inline_payload;
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return CloneAcceptance::Refused;
    const auto hashed = BCryptHash(algorithm, nullptr, 0, reinterpret_cast<PUCHAR>(intent.inline_payload.data()),
        static_cast<ULONG>(intent.inline_payload.size()), intent.payload_checksum.data(), static_cast<ULONG>(intent.payload_checksum.size()));
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (hashed < 0 || !original.ProtectedBackupMutationCapacityAvailable(intent, error) || !source.Current())
        return CloneAcceptance::Refused;
    BackupNoIoWriterScope scope(this, source);
    const auto result = AcceptNativeClone(original, from, target, receipt);
    return source.Current() ? result : CloneAcceptance::RecoveryRequired;
}

MetadataStore::CloneReplay MetadataStore::ReplayBackupRetainedClone(const BackupRetainedSource& source,
    const WriteAheadLog::Record& accepted, std::uint64_t preimage)
{
    const auto* cp = AuthoritativeAppleCheckpointView();
    if (!device_ || !cp || !context_.allow_native_snapshot_runtime || context_.shared_container_session ||
        !source.Matches(*device_, context_.device_offset_bytes, *cp, context_.volume_object_id, source.RecoveryIdentity()))
        return CloneReplay::Refused;
    BackupNoIoWriterScope scope(this, source);
    const auto result = ReplayNativeClone(accepted, preimage);
    return source.Current() ? result : CloneReplay::Refused;
}

MetadataStore::MutationStatus MetadataStore::PreflightBackupRetainedCapacityMutations(const BackupRetainedSource& source,
    std::span<const MutationRequest> requests, const std::vector<std::uint64_t>& pins)
{
    const auto* selected = AuthoritativeAppleCheckpointView();
    if (requests.empty() || std::any_of(requests.begin(), requests.end(), [](const auto& r) { return !IsBackupRetainedMutation(r.operation); }))
        return MutationStatus::UnsupportedOperation;
    for (const auto& request : requests) {
        const bool write = request.operation == MutationOperation::Write;
        const bool sized = request.operation == MutationOperation::SetFileSize || request.operation == MutationOperation::SetAllocationSize;
        if ((write && (!request.length || request.length > (256ull << 10) ||
                request.offset > (8ull << 20) - request.length)) || (sized && request.length > (8ull << 20)))
            return MutationStatus::UnsupportedOperation;
    }
    if (!device_ || !selected || !context_.allow_native_snapshot_runtime || context_.shared_container_session ||
        !source.Matches(*device_, context_.device_offset_bytes, *selected, context_.volume_object_id, source.RecoveryIdentity()))
        return MutationStatus::NotReady;
    BackupNoIoWriterScope scope(this, source);
    const auto status = PreflightNativeCapacityMutations(requests, pins);
    return source.Current() ? status : MutationStatus::NotReady;
}

bool MetadataStore::PlanBackupRetainedPendingMutations(const BackupRetainedSource& source,
    const std::vector<std::uint64_t>& pins, AppleCheckpointPublicationPlan& publication, std::string& error)
try
{
    publication = {}; error.clear();
    if (std::any_of(pending_mutations_.begin(), pending_mutations_.end(),
            [](const auto& mutation) { return mutation.operation != MutationOperation::Write; }))
    { error = "BackupRetainedPlanningOperationUnsupported"; return false; }
    const auto* selected = AuthoritativeAppleCheckpointView();
    if (!device_ || !selected || !context_.allow_native_snapshot_runtime || context_.shared_container_session ||
        !source.Matches(*device_, context_.device_offset_bytes, *selected, context_.volume_object_id, source.RecoveryIdentity()))
    { error = "BackupRetainedPlanningSourceUnavailable"; return false; }
    BackupNoIoWriterScope scope(this, source);
    const auto observation = device_->CaptureExclusiveWriteSourceObservation();
    if (!observation) { error = "BackupRetainedPlanningSourceUnavailable"; return false; }
    if (CommitApplePendingMutations(pins, false, nullptr, {}, false, &publication, &source) != CommitStatus::NothingToCommit ||
        publication.superblock_write.bytes.empty() || !source.Current() ||
        !device_->IsExclusiveWriteSourceObservationCurrent(*observation))
    { publication = {}; error = "BackupRetainedPlanningFailed:" + LastCommitStage(); return false; }
    return true;
}
catch (...) { publication = {}; error = "BackupRetainedPlanningFailed"; return false; }

bool MetadataStore::PlanBackupRetainedTypedPendingMutations(const BackupRetainedSource& source,
    const std::vector<std::uint64_t>& pins, AppleCheckpointPublicationPlan& publication, std::string& error)
try
{
    publication = {}; error.clear();
    if (pending_mutations_.empty() || std::any_of(pending_mutations_.begin(), pending_mutations_.end(),
            [](const auto& mutation) { return !IsBackupRetainedMutation(mutation.operation); }))
    { error = "BackupRetainedTypedOperationUnsupported"; return false; }
    const auto* selected = AuthoritativeAppleCheckpointView();
    if (!device_ || !selected || !context_.allow_native_snapshot_runtime || context_.shared_container_session ||
        !source.Matches(*device_, context_.device_offset_bytes, *selected, context_.volume_object_id, source.RecoveryIdentity()))
    { error = "BackupRetainedTypedSourceUnavailable"; return false; }
    BackupNoIoWriterScope scope(this, source);
    const auto observation = device_->CaptureExclusiveWriteSourceObservation();
    if (!observation || CommitApplePendingMutations(pins, false, nullptr, {}, false, &publication, &source) != CommitStatus::NothingToCommit ||
        publication.superblock_write.bytes.empty() || !source.Current() ||
        !device_->IsExclusiveWriteSourceObservationCurrent(*observation))
    { publication = {}; error = "BackupRetainedTypedPlanningFailed:" + LastCommitStage(); return false; }
    return true;
}
catch (...) { publication = {}; error = "BackupRetainedTypedPlanningFailed"; return false; }

bool MetadataStore::PlanBackupRetainedAcceptedMutations(const BackupRetainedSource& source,
    TransactionManager& original, PayloadSpool& spool, AppleCheckpointPublicationPlan& publication, std::string& error)
try
{
    publication = {}; error.clear();
    const auto fail = [&](const char* reason) { publication = {}; if (error.empty()) error = reason; return false; };
    TransactionManager::RetainedAcceptedHistory history;
    const auto lease = original.ObservedJournalWriterLeaseGeneration();
    if (!source.IsPhysical() || !source.JournalSourceBinding() || original.ProtectedSourceBinding() != source.JournalSourceBinding() ||
        !original.ProtectedJournalIdentity() || !lease || original.ObservedJournalAppendLeaseGeneration() != lease ||
        TransactionManager::WideToUtf8(original.ConfiguredVolumeIdentity()) != source.RecoveryIdentity() || PendingMutationCount() ||
        !original.LoadRetainedAcceptedHistory(history, error, {16ull << 20, 4096}) ||
        history.coverage != TransactionManager::RetainedHistoryCoverage::RetainedComplete || history.pending.size() != 1 ||
        history.writer_lease_generation != lease) return fail("BackupAcceptedBatchOriginalUnavailable");
    const auto& batch = history.pending.front();
    if (batch.preimage_checkpoint_xid != CheckpointXid().value_or(0) || !batch.accepted_sequence ||
        batch.accepted_sequence != history.watermarks.accepted_sequence || batch.mutations.empty() || batch.mutations.size() > 64)
        return fail("BackupAcceptedBatchBoundaryUnsupported");
    if (!PrepareBackupRetainedWritePath(source, error)) return false;
    std::map<std::uint64_t, std::vector<std::byte>> payloads;
    constexpr std::uint64_t file_limit = 8ull << 20, total_limit = 32ull << 20;
    std::uint64_t materialized = 0;
    const auto resize = [&](std::vector<std::byte>& bytes, std::uint64_t size) {
        if (size > file_limit) return false;
        const auto growth = size > bytes.size() ? size - bytes.size() : 0;
        if (growth > total_limit - materialized) return false;
        materialized += growth; bytes.resize(static_cast<std::size_t>(size), std::byte{}); return true;
    };
    const auto hydrate = [&](std::uint64_t id) {
        if (payloads.contains(id)) return true;
        const auto old = committed_inodes_.find(id);
        if (old == committed_inodes_.end() || old->second.node_type != NodeType::RegularFile ||
            (old->second.bsd_flags & kAppleBsdCompressedFlag)) return false;
        auto& bytes = payloads[id];
        if (!resize(bytes, old->second.logical_size)) return false;
        if (bytes.empty()) return true;
        const auto extents = committed_read_extents_.find(id);
        if (extents == committed_read_extents_.end()) return false;
        std::uint64_t covered = 0;
        for (const auto& extent : extents->second) {
            if (extent.logical_offset >= bytes.size()) break;
            if (extent.logical_offset != covered || !extent.bytes || extent.bytes > UINT64_MAX - covered) return false;
            covered += extent.bytes;
            if (!extent.physical_address) continue;
            const auto count = static_cast<std::size_t>((std::min)(extent.bytes, bytes.size() - extent.logical_offset));
            std::vector<std::byte> chunk;
            if (!source.Read(extent.physical_address, count, chunk) || chunk.size() != count) return false;
            std::copy(chunk.begin(), chunk.end(), bytes.begin() + static_cast<std::size_t>(extent.logical_offset));
        }
        return covered >= bytes.size();
    };
    SetFilePayloadRangeProvider([&](const auto& path, auto identity, auto at, auto out) {
        const auto inode = LookupWorkingInodeByPath(path); const auto found = payloads.find(identity.object_id);
        if (!inode || inode->object_id != identity.object_id || inode->xid != identity.generation ||
            identity.generation != batch.preimage_checkpoint_xid + 1 || found == payloads.end() ||
            at > found->second.size() || out.size() > found->second.size() - at) return false;
        std::copy_n(found->second.begin() + at, out.size(), out.begin()); return true;
    });
    ScopeExit clear_provider{[&] { SetFilePayloadRangeProvider({}); }};
    for (const auto& record : batch.mutations) {
        MutationRequest request;
        if (record.volume_identity != source.RecoveryIdentity() || record.transaction_id != batch.transaction_id ||
            record.sequence >= batch.accepted_sequence || !DecodeBackupAcceptedMutation(record, request, error))
            return fail("BackupAcceptedBatchMutationInvalid");
        const auto old = committed_inodes_.find(request.object_id);
        if (old != committed_inodes_.end() && old->second.node_type == NodeType::RegularFile && !hydrate(request.object_id))
            return fail("BackupAcceptedBatchOldPayloadUnsupported");
        PayloadIdentity identity;
        if (StageBackupRetainedTypedMutation(source, request, &identity) != MutationStatus::Applied ||
            identity.object_id != request.object_id || identity.generation != request.generation)
            return fail("BackupAcceptedBatchStageMismatch");
        if (request.operation == MutationOperation::CreateFile) payloads[request.object_id].clear();
        if (request.operation == MutationOperation::Write || request.operation == MutationOperation::SetFileSize ||
            request.operation == MutationOperation::SetAllocationSize) {
            const auto inode = LookupWorkingInodeByPath(request.path);
            auto& bytes = payloads[request.object_id];
            if (!inode || !resize(bytes, inode->logical_size)) return fail("BackupAcceptedBatchPayloadLimit");
            if (request.operation == MutationOperation::Write) {
                std::vector<std::byte> replacement;
                if (!spool.ReadPersistedRange({record.volume_identity, record.object_id, record.parent_object_id, record.logical_offset,
                        record.payload_length, record.payload_offset, record.payload_spool_id, record.payload_sha256}, replacement) ||
                    (!record.inline_payload.empty() && record.inline_payload != replacement) ||
                    request.offset > bytes.size() || replacement.size() > bytes.size() - request.offset)
                    return fail("BackupAcceptedBatchOriginalPayloadInvalid");
                std::copy(replacement.begin(), replacement.end(), bytes.begin() + request.offset);
            }
        }
    }
    if (!PlanBackupRetainedTypedPendingMutations(source, {batch.preimage_checkpoint_xid}, publication, error)) return false;
    const auto marks = original.Watermarks();
    if (!(source.Current() && original.RecoveryStateValid() && original.ObservedJournalWriterLeaseGeneration() == lease &&
        original.ObservedJournalAppendLeaseGeneration() == lease && marks.accepted_sequence == history.watermarks.accepted_sequence &&
        marks.apfs_durable_sequence == history.watermarks.apfs_durable_sequence && marks.cleanup_sequence == history.watermarks.cleanup_sequence))
        return fail("BackupAcceptedBatchAuthorityChanged");
    return true;
}
catch (...) { publication = {}; error = "BackupAcceptedBatchPlanningFailed"; return false; }

bool MetadataStore::FlushBackupImageRecoveryEvidence()
try
{
    const auto* checkpoint = AuthoritativeAppleCheckpointView();
    if (!context_.allow_native_snapshot_runtime || context_.shared_container_session ||
        context_.device_offset_bytes || !device_ || !device_->IsRegularFile() || device_->BaseOffsetBytes() ||
        !checkpoint || checkpoint->volumes.size() != 1 ||
        checkpoint->volumes.front().superblock.role_raw != 0x0180 ||
        checkpoint->volumes.front().superblock.object_id != context_.volume_object_id ||
        PendingMutationCount()) return false;
    const auto observation = device_->CaptureExclusiveWriteSourceObservation();
    if (!observation) return false;
    BackupRecoverySource raw(*device_);
    std::string error;
    if (!ValidateBackupImageWriterProfile(raw, *checkpoint, context_.volume_object_id, error)) return false;
    return device_->Flush() && device_->IsExclusiveWriteSourceObservationCurrent(*observation);
}
catch (...) { return false; }

bool MetadataStore::ProveBackupRetainedAcceptedPrefix(TransactionManager& journal, PayloadSpool& spool,
    const std::filesystem::path& journal_path, const std::string& volume_identity,
    std::vector<std::uint64_t>& applied_sequences, std::string& error) const
try
{
    applied_sequences.clear();
    const auto* selected = AuthoritativeAppleCheckpointView();
    if (!selected) { error = "BackupRetainedAcceptedProfileUnsupported"; return false; }
    auto source = BackupRetainedSource::WholeImage(device_, *selected, context_.volume_object_id, error);
    if (!source) return false;
    return ProveBackupRetainedAcceptedPrefix(journal, spool, journal_path, volume_identity, *source, applied_sequences, error);
}
catch (const std::exception&) { applied_sequences.clear(); error = "BackupRetainedAcceptedSourceUnavailable"; return false; }

bool MetadataStore::FlushBackupRetainedRecoveryEvidence(const BackupRetainedSource& source)
try
{
    const auto* selected = AuthoritativeAppleCheckpointView();
    std::string error;
    return context_.allow_native_snapshot_runtime && !context_.shared_container_session && device_ && selected &&
        !PendingMutationCount() && source.Matches(*device_, context_.device_offset_bytes, *selected,
            context_.volume_object_id, source.RecoveryIdentity()) &&
        ValidateBackupImageWriterProfile(source, *selected, context_.volume_object_id, error) && source.Flush();
}
catch (...) { return false; }

bool MetadataStore::ProveBackupRetainedAcceptedPrefix(TransactionManager& journal, PayloadSpool& spool,
    const std::filesystem::path& journal_path, const std::string& volume_identity,
    const BackupRetainedSource& retained_source, std::vector<std::uint64_t>& applied_sequences, std::string& error) const
try
{
    applied_sequences.clear();
    error.clear();
    const auto fail = [&](const char* reason) { applied_sequences.clear(); error = reason; return false; };
    const auto* supplied = AuthoritativeAppleCheckpointView();
    if (!supplied || supplied->volumes.size() != 1 || !context_.allow_native_snapshot_runtime ||
        supplied->volumes.front().superblock.role_raw != 0x0180 ||
        context_.shared_container_session ||
        !device_ || !retained_source.Matches(*device_, context_.device_offset_bytes, *supplied,
            context_.volume_object_id, volume_identity) ||
        PendingMutationCount() || journal.CurrentState() != TransactionManager::State::Idle ||
        journal.PendingMutationCount() || !journal.RecoveryStateValid() || volume_identity.empty() ||
        supplied->container.superblock.block_size != 4096 || supplied->container.superblock.block_count > 65536)
        return fail("BackupRetainedAcceptedProfileUnsupported");
    // Retain the original image lease or the exact G08 held window throughout.
    const auto source_observation = device_->CaptureExclusiveWriteSourceObservation();
    if (!source_observation) return fail("BackupRetainedAcceptedSourceNotExclusive");
    const auto lease = journal.ObservedJournalWriterLeaseGeneration();
    const auto marks = journal.Watermarks();
    std::vector<TransactionManager::AcceptedTransaction> batches;
    TransactionManager::DurabilityWatermarks persisted_marks;
    const auto read_original = [&] {
        if (!retained_source.IsPhysical())
            return TransactionManager::InspectAcceptedTransactionsReadOnly(journal_path, volume_identity, batches, persisted_marks, error);
        if (!retained_source.JournalSourceBinding() || journal.ProtectedSourceBinding() != retained_source.JournalSourceBinding() ||
            !journal.ProtectedJournalIdentity())
        { error = "BackupPhysicalOriginalSourceBindingRequired"; return false; }
        TransactionManager::RetainedAcceptedHistory history;
        if (!journal.LoadRetainedAcceptedHistory(history, error, {16ull << 20, 4096}) ||
            history.coverage != TransactionManager::RetainedHistoryCoverage::RetainedComplete ||
            history.writer_lease_generation != lease) return false;
        batches = std::move(history.pending); persisted_marks = history.watermarks;
        return true;
    };
    std::error_code file_error;
    const auto journal_bytes = std::filesystem::file_size(journal_path, file_error);
    // A retained append handle denies other writers and authenticates the
    // original size/path. The existing read-only inspector never repairs tails,
    // creates a journal or reseeds the real owner.
    if (!lease || file_error || !journal_bytes || journal_bytes > (16ULL << 20) ||
        !journal_path.is_absolute() || journal.ObservedJournalAppendLeaseGeneration() != lease ||
        TransactionManager::WideToUtf8(journal.ConfiguredVolumeIdentity()) != volume_identity ||
        !journal.OwnsJournalForMaintenance(journal_path.wstring(), journal.ConfiguredVolumeIdentity()) ||
        !read_original() ||
        persisted_marks.accepted_sequence != marks.accepted_sequence ||
        persisted_marks.apfs_durable_sequence != marks.apfs_durable_sequence ||
        persisted_marks.cleanup_sequence != marks.cleanup_sequence ||
        batches.empty() || batches.size() > 16) return fail("BackupRetainedAcceptedJournalUnavailable");
    const auto budget = std::make_shared<catalog::ApfsReadBudget>(65536, 256ULL << 20, 262144, 256ULL << 20);
    catalog::BudgetedRandomAccessSource source(retained_source, budget);
    const auto current = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    if (!current || current->container.superblock_bytes != supplied->container.superblock_bytes ||
        current->container.superblock_physical_block != supplied->container.superblock_physical_block ||
        current->volumes.size() != 1 || current->volumes.front().superblock.object_id != context_.volume_object_id ||
        current->volumes.front().superblock.xid != supplied->volumes.front().superblock.xid ||
        current->volumes.front().superblock_object.physical_block != supplied->volumes.front().superblock_object.physical_block ||
        !ValidateBackupImageWriterProfile(source, *supplied, context_.volume_object_id, error))
        return fail("BackupRetainedAcceptedEndpointMismatch");
    const auto current_xid = current->container.superblock.xid;
    std::vector<std::uint64_t> pins;
    std::uint64_t previous_sequence = marks.cleanup_sequence;
    std::size_t mutation_count = 0;
    for (std::size_t i = 0; i < batches.size(); ++i)
    {
        const auto& batch = batches[i];
        if (retained_source.IsPhysical())
            for (const auto& record : batch.mutations) {
                MutationRequest checked;
                if (!DecodeBackupAcceptedMutation(record, checked, error)) return fail("BackupPhysicalAcceptedOperationUnsupported");
            }
        if (!batch.preimage_checkpoint_xid || batch.preimage_checkpoint_xid > current_xid ||
            batch.accepted_sequence <= previous_sequence || batch.accepted_sequence > marks.accepted_sequence ||
            batch.mutations.empty() || batch.mutations.size() > 64 ||
            batch.mutations.size() > 256 - mutation_count ||
            (i && batch.preimage_checkpoint_xid != batches[i - 1].preimage_checkpoint_xid + 1))
            return fail("BackupRetainedAcceptedOrderUnproven");
        previous_sequence = batch.accepted_sequence;
        mutation_count += batch.mutations.size();
        pins.push_back(batch.preimage_checkpoint_xid);
    }
    if (batches.front().preimage_checkpoint_xid >= current_xid ||
        (batches.back().preimage_checkpoint_xid != current_xid &&
            batches.back().preimage_checkpoint_xid + 1 != current_xid))
        return fail("BackupRetainedAcceptedPrefixUnavailable");
    std::vector<AppleRecoveryCheckpointView> history;
    if (!LoadAppleSnapshotRecoveryCheckpoints(source, *current, pins, history, error))
        return fail("BackupRetainedAcceptedHistoryUnavailable");
    const auto checkpoint = [&](std::uint64_t xid) -> const catalog::AppleCheckpointView* {
        if (xid == current_xid) return &*current;
        for (const auto& entry : history) if (entry.checkpoint.container.superblock.xid == xid) return &entry.checkpoint;
        return nullptr;
    };
    // Keep the original historical bytes, not a mutable projection or a caller's
    // claimed fingerprint, through reconstruction and the final readback.
    std::map<std::uint64_t, std::vector<std::byte>> historical_bytes;
    const auto retain = [&](std::uint64_t block) {
        if (historical_bytes.contains(block)) return true;
        if (historical_bytes.size() >= 8192) return false;
        std::vector<std::byte> bytes;
        if (!source.Read(block * 4096, 4096, bytes)) return false;
        historical_bytes.emplace(block, std::move(bytes));
        return true;
    };
    for (const auto& entry : history)
    {
        for (const auto block : entry.metadata_blocks) if (!retain(block)) return fail("BackupRetainedAcceptedHistoryLimit");
        for (const auto& extent : entry.payload_extents)
            for (std::uint64_t i = 0; i < extent.block_count; ++i)
                if (!retain(extent.physical_block + i)) return fail("BackupRetainedAcceptedHistoryLimit");
    }
    std::vector<std::uint64_t> publication_pins, proven;
    constexpr std::uint64_t file_limit = 8ULL << 20, payload_limit = 32ULL << 20;
    std::uint64_t payload_total = 0, materialized_total = 0;
    previous_sequence = marks.cleanup_sequence;
    for (const auto& batch : batches)
    {
        publication_pins.push_back(batch.preimage_checkpoint_xid);
        const auto* before = checkpoint(batch.preimage_checkpoint_xid);
        if (!before || before->volumes.size() != 1 ||
            before->volumes.front().superblock.uuid_hex != current->volumes.front().superblock.uuid_hex)
            return fail("BackupRetainedAcceptedOwnerMismatch");
        class HistoricalPlanningSource final : public catalog::RandomAccessSource
        {
        public:
            HistoricalPlanningSource(const catalog::RandomAccessSource& source,
                const catalog::AppleCheckpointView& before, const std::vector<AppleRecoveryCheckpointView>& history,
                const catalog::AppleCheckpointView& current) : source_(source), before_(before)
            {
                for (const auto& entry : history)
                    if (entry.checkpoint.container.superblock.xid > before.container.superblock.xid)
                        hidden_.push_back(entry.checkpoint.container.superblock_physical_block);
                if (current.container.superblock.xid > before.container.superblock.xid)
                    hidden_.push_back(current.container.superblock_physical_block);
            }
            std::uint64_t SizeBytes() const override { return source_.SizeBytes(); }
            std::shared_ptr<catalog::ApfsReadBudget> ReadBudget() const override { return source_.ReadBudget(); }
            bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& bytes) const override
            {
                if (!source_.Read(offset, size, bytes)) return false;
                const auto overlay = [&](std::uint64_t start, const std::vector<std::byte>* replacement) {
                    const auto begin = (std::max)(offset, start);
                    const auto end = (std::min)(offset + size, start + 4096);
                    if (begin >= end) return;
                    for (auto at = begin; at < end; ++at)
                        bytes[static_cast<std::size_t>(at - offset)] = replacement
                            ? (*replacement)[static_cast<std::size_t>(at - start)] : std::byte{0};
                };
                for (const auto block : hidden_) overlay(block * 4096, nullptr);
                overlay(0, &before_.container.superblock_bytes);
                return true;
            }
        private:
            const catalog::RandomAccessSource& source_;
            const catalog::AppleCheckpointView& before_;
            std::vector<std::uint64_t> hidden_;
        } historical_source(source, *before, history, *current);
        const bool pending_tail = batch.preimage_checkpoint_xid == current_xid;
        const catalog::RandomAccessSource& accepted_source = pending_tail ? static_cast<const catalog::RandomAccessSource&>(source) : historical_source;
        if (!ValidateBackupImageWriterProfile(accepted_source, *before, context_.volume_object_id, error))
            return fail("BackupRetainedAcceptedPreimageProfileUnsupported");
        std::vector<MutationRequest> requests;
        std::vector<std::vector<std::byte>> write_payloads;
        const auto decode_text = [&](const std::string& text, std::wstring& path) {
            if (text.empty() || text.size() > 4096 || text.find('\0') != std::string::npos) return false;
            const auto length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                static_cast<int>(text.size()), nullptr, 0);
            if (length <= 0) return false;
            path.resize(length);
            std::string roundtrip;
            return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                static_cast<int>(text.size()), path.data(), length) == length &&
                WideToUtf8Strict(path, roundtrip) && roundtrip == text;
        };
        const auto decode_path = [&](const std::string& text, std::wstring& path) {
            return decode_text(text, path) && NormalizePath(path) == path;
        };
        for (const auto& record : batch.mutations)
        {
            if (record.volume_identity != volume_identity || record.transaction_id != batch.transaction_id ||
                !record.transaction_id || record.sequence <= previous_sequence || record.sequence >= batch.accepted_sequence ||
                record.state != WriteAheadLog::RecordState::Prepared || record.object_id <= 2 || !record.parent_object_id ||
                !WriteAheadLog::UnlinkOutcomeIsConsistent(record))
                return fail("BackupRetainedAcceptedOriginalIdentityInvalid");
            previous_sequence = record.sequence;
            MutationRequest request;
            if (!decode_path(record.path_utf8, request.path)) return fail("BackupRetainedAcceptedPathInvalid");
            request.object_id = record.object_id; request.generation = record.parent_object_id;
            using Operation = WriteAheadLog::OperationKind;
            const bool write = record.operation == Operation::Write;
            const bool metadata = record.operation == Operation::SetInodeMetadata;
            const bool rename = record.operation == Operation::Rename;
            const bool attribute = record.operation == Operation::SetExtendedAttribute ||
                record.operation == Operation::RemoveExtendedAttribute;
            const bool link_target = record.operation == Operation::SetSymbolicLinkTarget;
            const bool clone = record.operation == Operation::CloneFile;
            if ((!rename && (record.flags ||
                    (!attribute && !link_target && !clone && !record.secondary_path_utf8.empty()))) ||
                (rename && ((record.flags & ~0x4u) || !decode_path(record.secondary_path_utf8, request.secondary_path))) ||
                (record.unlink_outcome && record.operation != Operation::Delete) ||
                (!write && !metadata && !attribute && !clone && (record.payload_length || record.payload_offset || record.payload_spool_id ||
                    !record.inline_payload.empty() || std::any_of(record.payload_sha256.begin(), record.payload_sha256.end(),
                        [](auto b) { return b != 0; }))) ||
                (record.operation != Operation::Write && record.operation != Operation::SetBasicInfo && record.logical_offset) ||
                (record.operation != Operation::Write && record.operation != Operation::SetFileSize &&
                    record.operation != Operation::SetAllocationSize && !clone && record.logical_length))
                return fail("BackupRetainedAcceptedMutationUnsupported");
            std::vector<std::byte> payload;
            switch (record.operation)
            {
            case Operation::CloneFile:
                if (!NativeCloneFromWal(record, request)) return fail("BackupRetainedAcceptedCloneInvalid");
                break;
            case Operation::CreateFile: request.operation = MutationOperation::CreateFile; break;
            case Operation::CreateDirectory: request.operation = MutationOperation::CreateDirectory; break;
            case Operation::Rename:
                request.operation = MutationOperation::Rename;
                request.replace_if_exists = (record.flags & 0x4u) != 0;
                break;
            case Operation::Delete:
                if (!record.unlink_outcome) return fail("BackupRetainedAcceptedUnlinkOutcomeMissing");
                request.operation = MutationOperation::Delete;
                request.expected_unlink_outcome = record.unlink_outcome;
                break;
            case Operation::SetBasicInfo:
                request.operation = MutationOperation::SetBasicInfo;
                request.timestamp_utc = record.logical_offset;
                break;
            case Operation::SetInodeMetadata:
                // The WAL codec validates the canonical patch, reserved fields
                // and SHA; staging applies that same codec to the old inode.
                if (!WriteAheadLog::InodeMetadataMutationIsConsistent(record))
                    return fail("BackupRetainedAcceptedMetadataInvalid");
                request.operation = MutationOperation::SetInodeMetadata;
                request.inline_payload = record.inline_payload;
                request.length = record.payload_length;
                break;
            case Operation::SetExtendedAttribute:
            case Operation::RemoveExtendedAttribute:
                if (!WriteAheadLog::ExtendedAttributeMutationIsConsistent(record) ||
                    !decode_text(record.secondary_path_utf8, request.secondary_path))
                    return fail("BackupRetainedAcceptedAttributeInvalid");
                if (record.payload_length > payload_limit - payload_total)
                    return fail("BackupRetainedAcceptedPayloadLimit");
                payload_total += record.payload_length;
                request.operation = record.operation == Operation::SetExtendedAttribute
                    ? MutationOperation::SetExtendedAttribute : MutationOperation::RemoveExtendedAttribute;
                request.inline_payload = record.inline_payload;
                request.length = record.payload_length;
                // Xattr timestamps are not persisted by this WAL operation.
                // Preserve the preimage time; any unlogged change must fail
                // complete publication readback, even if a later batch replaces it.
                break;
            case Operation::SetSymbolicLinkTarget:
                if (!decode_text(record.secondary_path_utf8, request.secondary_path))
                    return fail("BackupRetainedAcceptedSymbolicLinkInvalid");
                request.operation = MutationOperation::SetSymbolicLinkTarget;
                break;
            case Operation::RemoveSymbolicLinkTarget:
                request.operation = MutationOperation::RemoveSymbolicLinkTarget;
                break;
            case Operation::RestoreDirectoryFromSymbolicLink:
                if (!WriteAheadLog::DirectoryRestoreMutationIsConsistent(record))
                    return fail("BackupRetainedAcceptedSymbolicLinkInvalid");
                request.operation = MutationOperation::RestoreDirectoryFromSymbolicLink;
                break;
            case Operation::SetFileSize:
                if (record.logical_length > file_limit) return fail("BackupRetainedAcceptedPayloadLimit");
                request.operation = MutationOperation::SetFileSize;
                request.length = record.logical_length;
                break;
            case Operation::SetAllocationSize:
                if (!WriteAheadLog::AllocationSizeMutationIsConsistent(record) || record.logical_length > file_limit)
                    return fail("BackupRetainedAcceptedAllocationUnsupported");
                request.operation = MutationOperation::SetAllocationSize;
                request.length = record.logical_length;
                break;
            case Operation::Write:
                if (!record.payload_length || record.payload_length != record.logical_length ||
                    record.logical_offset > file_limit || record.payload_length > file_limit - record.logical_offset ||
                    record.payload_length > payload_limit - payload_total || record.payload_spool_id != record.sequence ||
                    !WriteAheadLog::InlinePayloadIsConsistent(record))
                    return fail("BackupRetainedAcceptedWriteUnsupported");
                payload_total += record.payload_length;
                if (!spool.ReadPersistedRange({volume_identity, record.object_id, record.parent_object_id,
                        record.logical_offset, record.payload_length, record.payload_offset,
                        record.payload_spool_id, record.payload_sha256}, payload) || payload.size() != record.payload_length ||
                    (!record.inline_payload.empty() && record.inline_payload != payload))
                    return fail("BackupRetainedAcceptedOriginalPayloadInvalid");
                request.operation = MutationOperation::Write;
                request.offset = record.logical_offset; request.length = record.logical_length;
                break;
            default: return fail("BackupRetainedAcceptedMutationUnsupported");
            }
            requests.push_back(std::move(request));
            write_payloads.push_back(std::move(payload));
        }
        previous_sequence = batch.accepted_sequence;
        const auto* after = pending_tail ? nullptr : checkpoint(batch.preimage_checkpoint_xid + 1);
        if (!pending_tail && (!after || before->container.superblock.next_xid != batch.preimage_checkpoint_xid + 1))
            return fail("BackupRetainedAcceptedSuccessorUnavailable");
        std::vector<catalog::BtreeRecord> records;
        NativeApfsVolumeProjection projection;
        if (before->volumes.front().superblock.fext_tree_oid || before->volumes.front().superblock.fext_tree_type ||
            !catalog::ReadAppleVolumeFileSystemRecords(source, before->container, before->volumes.front(), records, error) ||
            !NativeApfsReader::ProjectReadOnlyRecordsWithAdmission(records, before->container.superblock,
                before->volumes.front().superblock, before->container.superblock.block_count, budget, projection, error, false, true))
            return fail("BackupRetainedAcceptedSourceProjectionInvalid");
        MetadataStore candidate(context_, device_);
        candidate.context_.incompatible_features = projection.incompatible_features;
        candidate.authoritative_apple_checkpoint_view_ = *before;
        candidate.block_size_ = 4096; candidate.total_blocks_ = before->container.superblock.block_count;
        candidate.checkpoint_xid_ = candidate.loaded_superblock_checkpoint_xid_ = batch.preimage_checkpoint_xid;
        candidate.container_loaded_ = candidate.object_map_loaded_ = true;
        candidate.root_directory_object_id_ = projection.root_directory_inode;
        candidate.highest_committed_apple_file_system_object_id_ = projection.highest_file_system_object_id;
        if (!BuildNativeProjectionInodeGraph(projection, [&](const auto& path) {
                return candidate.CanonicalPathKeyFromNormalizedPath(path);
            }, candidate.committed_inodes_, candidate.committed_path_index_, candidate.committed_directory_links_))
            return fail("BackupRetainedAcceptedSourceGraphInvalid");
        candidate.committed_btree_records_ = std::move(projection.btree_records);
        candidate.committed_extended_attributes_ = std::move(projection.extended_attributes_by_inode);
        candidate.committed_attribute_stream_extents_ = std::move(projection.attribute_stream_extents);
        candidate.committed_read_extents_ = std::move(projection.read_extents_by_inode);
        for (const auto& [id, inode] : candidate.committed_inodes_)
            if (!inode.is_directory && inode.data_physical_address)
                candidate.committed_object_map_[id] = {id, inode.data_physical_address, inode.logical_size, projection.checkpoint_xid};
        std::vector<std::byte> spaceman;
        if (!source.Read(before->spaceman.object.physical_block * 4096, 4096, spaceman) ||
            !candidate.LoadSpacemanChunkInfoState(before->spaceman.object.physical_block, spaceman, &source) ||
            !candidate.RebuildCommittedBtreeIndex() || !candidate.EnsureRootState())
            return fail("BackupRetainedAcceptedSourceAllocatorInvalid");
        candidate.native_write_ready_ = candidate.spaceman_loaded_ = candidate.commit_path_ready_ = true;
        candidate.canonical_state_loaded_ = candidate.canonical_commit_ready_ = candidate.write_device_allowed_ = true;
        BackupNoIoWriterScope no_io_scope(&candidate, accepted_source);
        std::map<std::uint64_t, std::vector<std::byte>> payloads;
        const auto resize_payload = [&](std::vector<std::byte>& bytes, std::uint64_t size) {
            if (size > file_limit) return false;
            const auto growth = size > bytes.size() ? size - bytes.size() : 0;
            if (growth > payload_limit - materialized_total) return false;
            materialized_total += growth;
            bytes.resize(static_cast<std::size_t>(size), std::byte{0});
            return true;
        };
        const auto hydrate = [&](std::uint64_t id) {
            if (payloads.contains(id)) return true;
            const auto old = candidate.committed_inodes_.find(id);
            if (old == candidate.committed_inodes_.end() || old->second.node_type != NodeType::RegularFile ||
                (old->second.bsd_flags & kAppleBsdCompressedFlag)) return false;
            auto& bytes = payloads[id];
            if (!resize_payload(bytes, old->second.logical_size)) return false;
            if (bytes.empty()) return true;
            const auto extents = candidate.committed_read_extents_.find(id);
            // TryProjectOrdinaryFileSystemRecords validates native sparse-byte
            // and allocation accounting, and inserts explicit zero mappings for
            // authenticated implicit holes, including a fully sparse stream.
            // Never infer a hole from a missing or incomplete projected map.
            if (extents == candidate.committed_read_extents_.end()) return false;
            std::uint64_t covered = 0;
            for (const auto& extent : extents->second)
            {
                if (extent.logical_offset >= bytes.size()) break;
                if (extent.logical_offset != covered || !extent.bytes || extent.bytes > UINT64_MAX - covered)
                    return false;
                covered += extent.bytes;
                if (!extent.physical_address) continue;
                const auto count = static_cast<std::size_t>((std::min)(extent.bytes, bytes.size() - extent.logical_offset));
                std::vector<std::byte> original;
                if (!source.Read(extent.physical_address, count, original) || original.size() != count) return false;
                std::copy(original.begin(), original.end(), bytes.begin() + static_cast<std::size_t>(extent.logical_offset));
            }
            return covered >= bytes.size();
        };
        candidate.SetFilePayloadRangeProvider([&](const auto& path, auto identity, auto offset, auto destination) {
            const auto inode = candidate.LookupWorkingInodeByPath(path);
            const auto payload = payloads.find(identity.object_id);
            if (!inode || inode->object_id != identity.object_id || inode->xid != identity.generation ||
                identity.generation != batch.preimage_checkpoint_xid + 1 || payload == payloads.end() ||
                inode->logical_size != payload->second.size() || offset > payload->second.size() ||
                destination.size() > payload->second.size() - offset) return false;
            std::copy_n(payload->second.begin() + static_cast<std::size_t>(offset), destination.size(), destination.begin());
            return true;
        });
        for (std::size_t i = 0; i < requests.size(); ++i)
        {
            const auto& request = requests[i];
            const bool content = request.operation == MutationOperation::Write || request.operation == MutationOperation::SetFileSize ||
                request.operation == MutationOperation::SetAllocationSize;
            const auto old = candidate.committed_inodes_.find(request.object_id);
            const bool existing_file = old != candidate.committed_inodes_.end() && old->second.node_type == NodeType::RegularFile;
            if (existing_file && !hydrate(request.object_id)) return fail("BackupRetainedAcceptedSourcePayloadUnsupported");
            PayloadIdentity identity;
            if (candidate.StageMutation(request, &identity) != MutationStatus::Applied ||
                identity.object_id != request.object_id || identity.generation != request.generation)
                return fail("BackupRetainedAcceptedOriginalStageMismatch");
            if (request.operation == MutationOperation::CreateFile) payloads[request.object_id].clear();
            if (content)
            {
                const auto inode = candidate.LookupWorkingInodeByPath(request.path);
                auto& bytes = payloads.at(request.object_id);
                // Staging owns size/generation semantics. Resizing here also
                // forgets truncated bytes before a later extension in this batch.
                if (!inode || !resize_payload(bytes, inode->logical_size)) return fail("BackupRetainedAcceptedPayloadLimit");
                if (request.operation == MutationOperation::Write)
                {
                    const auto& payload = write_payloads[i];
                    if (request.offset > bytes.size() || payload.size() > bytes.size() - request.offset)
                        return fail("BackupRetainedAcceptedPayloadRangeInvalid");
                    std::copy(payload.begin(), payload.end(), bytes.begin() + static_cast<std::size_t>(request.offset));
                }
            }
        }
        // The original pending namespace, identity and reconstructed payload must stage
        // against the actual endpoint before any prefix can earn a receipt.
        if (pending_tail) continue;
        // Reconstruct only the descriptor selection at the historical boundary.
        // Authentic old roots/allocator/payload still come from the held source.
        // This view is private to no-I/O planning; the writer's latest-checkpoint
        // drift guard and every actual publication source remain unchanged.
        AppleCheckpointPublicationPlan publication;
        if (candidate.CommitApplePendingMutations(publication_pins, false, nullptr, {}, false, &publication, &historical_source) !=
                CommitStatus::NothingToCommit)
        {
            const auto detail = candidate.LastCommitFailureDetail();
            error = "BackupRetainedAcceptedPlanMismatch:" + candidate.LastCommitStage() + ":" +
                TransactionManager::WideToUtf8(detail);
            return false;
        }
        if (publication.transaction_xid != batch.preimage_checkpoint_xid + 1 ||
            publication.published_checkpoint.superblock_bytes != after->container.superblock_bytes ||
            publication.superblock_write.physical_block != after->container.superblock_physical_block)
            return fail("BackupRetainedAcceptedPublicationIdentityMismatch");
        const auto readback = [&](const auto& write) {
            std::vector<std::byte> bytes;
            return !write.bytes.empty() && write.bytes.size() % 4096 == 0 &&
                source.Read(write.physical_block * 4096, write.bytes.size(), bytes) && bytes == write.bytes;
        };
        if (!readback(publication.superblock_write) ||
            !std::all_of(publication.before_superblock_writes.begin(), publication.before_superblock_writes.end(), readback))
            return fail("BackupRetainedAcceptedPublicationReadbackMismatch");
        proven.push_back(batch.accepted_sequence);
    }
    for (const auto& [block, original] : historical_bytes)
    {
        std::vector<std::byte> fresh;
        if (!source.Read(block * 4096, 4096, fresh) || fresh != original) return fail("BackupRetainedAcceptedHistoryChanged");
    }
    const auto endpoint = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    const auto now = journal.Watermarks();
    if (!endpoint || endpoint->container.superblock_bytes != current->container.superblock_bytes ||
        endpoint->container.superblock_physical_block != current->container.superblock_physical_block || budget->Failed() ||
        !device_->IsExclusiveWriteSourceObservationCurrent(*source_observation) || !retained_source.Current() ||
        journal.ObservedJournalWriterLeaseGeneration() != lease || !journal.RecoveryStateValid() ||
        journal.ObservedJournalAppendLeaseGeneration() != lease ||
        now.accepted_sequence != marks.accepted_sequence || now.apfs_durable_sequence != marks.apfs_durable_sequence ||
        now.cleanup_sequence != marks.cleanup_sequence) return fail("BackupRetainedAcceptedAuthorityChanged");
    applied_sequences = std::move(proven);
    return !applied_sequences.empty();
}
catch (const std::bad_alloc&) { applied_sequences.clear(); error = "BackupRetainedAcceptedResourceLimit"; return false; }
catch (const std::length_error&) { applied_sequences.clear(); error = "BackupRetainedAcceptedResourceLimit"; return false; }

