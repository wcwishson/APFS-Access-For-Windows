namespace
{
// Only the no-I/O reconstruction below can select an authenticated historical
// source for its private candidate's staging checks. No class layout changes.
class BackupNoIoWriterScope final
{
public:
    BackupNoIoWriterScope(const MetadataStore* store, const catalog::RandomAccessSource& source)
        : previous_store_(store_), previous_source_(source_)
    { store_ = store; source_ = &source; }
    ~BackupNoIoWriterScope() { store_ = previous_store_; source_ = previous_source_; }
    BackupNoIoWriterScope(const BackupNoIoWriterScope&) = delete;
    BackupNoIoWriterScope& operator=(const BackupNoIoWriterScope&) = delete;
    static const catalog::RandomAccessSource* Find(const MetadataStore* store)
    { return store == store_ ? source_ : nullptr; }
private:
    inline static thread_local const MetadataStore* store_ = nullptr;
    inline static thread_local const catalog::RandomAccessSource* source_ = nullptr;
    const MetadataStore* previous_store_;
    const catalog::RandomAccessSource* previous_source_;
};

class BackupRecoverySource final : public catalog::RandomAccessSource
{
public:
    explicit BackupRecoverySource(const BlockDevice& device) : device_(device) {}
    std::uint64_t SizeBytes() const override { return device_.GetGeometry().total_bytes; }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& bytes) const override
    {
        bytes.clear();
        if (offset > SizeBytes() || size > SizeBytes() - offset) return false;
        if (!size) return true;
        const auto first = offset - offset % 4096;
        const auto prefix = static_cast<std::size_t>(offset - first);
        const auto count = (prefix + size + 4095) / 4096 * 4096;
        if (count > SizeBytes() - first || !device_.ReadForVerification(first, count, bytes)) return false;
        bytes.erase(bytes.begin(), bytes.begin() + prefix);
        bytes.resize(size);
        return true;
    }
private:
    const BlockDevice& device_;
};

class BackupHistoricalSource final : public catalog::RandomAccessSource
{
public:
    BackupHistoricalSource(const catalog::RandomAccessSource& source, const catalog::AppleCheckpointView& before,
        std::uint64_t successor_block) : source_(source), before_(before), successor_(successor_block) {}
    std::uint64_t SizeBytes() const override { return source_.SizeBytes(); }
    std::shared_ptr<catalog::ApfsReadBudget> ReadBudget() const override { return source_.ReadBudget(); }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& bytes) const override
    {
        if (!source_.Read(offset, size, bytes) || bytes.size() != size) return false;
        const auto overlay = [&](std::uint64_t start, const std::vector<std::byte>* replacement) {
            const auto first = (std::max)(offset, start), last = (std::min)(offset + size, start + 4096);
            for (auto at = first; at < last; ++at)
                bytes[static_cast<std::size_t>(at - offset)] = replacement
                    ? (*replacement)[static_cast<std::size_t>(at - start)] : std::byte{0};
        };
        overlay(successor_ * 4096, nullptr);
        overlay(0, &before_.container.superblock_bytes);
        return true;
    }
private:
    const catalog::RandomAccessSource& source_;
    const catalog::AppleCheckpointView& before_;
    std::uint64_t successor_;
};
}

bool MetadataStore::ProveBackupRetainedAcceptedWrite(TransactionManager& journal, PayloadSpool& spool,
    const std::filesystem::path& journal_path, const std::string& volume_identity,
    std::vector<std::uint64_t>& applied_sequences, std::string& error) const try
{
    applied_sequences.clear(); error.clear();
    const auto fail = [&](const char* why) { error = why; return false; };
    const auto* supplied = AuthoritativeAppleCheckpointView();
    if (!supplied || !context_.allow_native_snapshot_runtime || context_.shared_container_session || context_.device_offset_bytes ||
        supplied->volumes.size() != 1 || supplied->volumes.front().superblock.role_raw != 0x0180 ||
        supplied->container.superblock.block_size != 4096 || supplied->container.superblock.block_count > 65536 ||
        !device_ || !device_->IsRegularFile() || device_->BaseOffsetBytes() || PendingMutationCount() ||
        journal.CurrentState() != TransactionManager::State::Idle || journal.PendingMutationCount() ||
        !journal.RecoveryStateValid() || volume_identity.empty() || !journal_path.is_absolute())
        return fail("BackupAcceptedProfileUnsupported");
    const auto observation = device_->CaptureExclusiveWriteSourceObservation();
    if (!observation) return fail("BackupAcceptedSourceNotExclusive");
    const auto lease = journal.ObservedJournalWriterLeaseGeneration();
    const auto marks = journal.Watermarks();
    TransactionManager::DurabilityWatermarks persisted;
    std::vector<TransactionManager::AcceptedTransaction> accepted;
    std::error_code ec;
    const auto bytes = std::filesystem::file_size(journal_path, ec);
    if (!lease || ec || !bytes || bytes > (16ull << 20) ||
        journal.ObservedJournalAppendLeaseGeneration() != lease ||
        TransactionManager::WideToUtf8(journal.ConfiguredVolumeIdentity()) != volume_identity ||
        !journal.OwnsJournalForMaintenance(journal_path.wstring(), journal.ConfiguredVolumeIdentity()) ||
        !TransactionManager::InspectAcceptedTransactionsReadOnly(journal_path, volume_identity, accepted, persisted, error) ||
        persisted.accepted_sequence != marks.accepted_sequence || persisted.apfs_durable_sequence != marks.apfs_durable_sequence ||
        persisted.cleanup_sequence != marks.cleanup_sequence || accepted.size() != 1 || accepted[0].mutations.size() != 1)
        return fail("BackupAcceptedOriginalUnavailable");
    const auto& batch = accepted[0]; const auto& record = batch.mutations[0];
    if (!batch.preimage_checkpoint_xid || batch.preimage_checkpoint_xid == UINT64_MAX ||
        batch.accepted_sequence != marks.accepted_sequence || batch.accepted_sequence <= marks.cleanup_sequence ||
        record.sequence <= marks.cleanup_sequence || record.sequence >= batch.accepted_sequence ||
        !batch.transaction_id || record.transaction_id != batch.transaction_id || record.volume_identity != volume_identity ||
        record.operation != WriteAheadLog::OperationKind::Write || record.state != WriteAheadLog::RecordState::Prepared ||
        record.object_id <= 2 || record.parent_object_id != batch.preimage_checkpoint_xid + 1 || record.flags ||
        record.unlink_outcome || !record.secondary_path_utf8.empty() || record.payload_spool_id != record.sequence ||
        !record.payload_length || record.payload_length > (1ull << 20) || record.payload_length != record.logical_length ||
        !WriteAheadLog::InlinePayloadIsConsistent(record)) return fail("BackupAcceptedWriteUnsupported");
    MutationRequest request; request.operation = MutationOperation::Write;
    request.object_id = record.object_id; request.generation = record.parent_object_id;
    request.offset = record.logical_offset; request.length = record.logical_length;
    if (record.path_utf8.empty() || record.path_utf8.size() > 4096 || record.path_utf8.find('\0') != std::string::npos)
        return fail("BackupAcceptedPathInvalid");
    const auto length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, record.path_utf8.data(),
        static_cast<int>(record.path_utf8.size()), nullptr, 0);
    if (length <= 0) return fail("BackupAcceptedPathInvalid");
    request.path.resize(length); std::string roundtrip;
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, record.path_utf8.data(),
            static_cast<int>(record.path_utf8.size()), request.path.data(), length) != length ||
        !WideToUtf8Strict(request.path, roundtrip) || roundtrip != record.path_utf8 || NormalizePath(request.path) != request.path)
        return fail("BackupAcceptedPathInvalid");
    std::vector<std::byte> payload;
    if (!spool.ReadPersistedRange({volume_identity, record.object_id, record.parent_object_id, record.logical_offset,
            record.payload_length, record.payload_offset, record.payload_spool_id, record.payload_sha256}, payload) ||
        payload.size() != record.payload_length || (!record.inline_payload.empty() && record.inline_payload != payload))
        return fail("BackupAcceptedPayloadInvalid");
    BackupRecoverySource original(*device_);
    const auto budget = std::make_shared<catalog::ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
    catalog::BudgetedRandomAccessSource source(original, budget);
    const auto current = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    if (!current || current->container.superblock_bytes != supplied->container.superblock_bytes ||
        current->container.superblock_physical_block != supplied->container.superblock_physical_block ||
        current->container.superblock.xid != batch.preimage_checkpoint_xid + 1 || current->volumes.size() != 1 ||
        current->volumes.front().superblock.object_id != context_.volume_object_id ||
        current->volumes.front().superblock.xid != supplied->volumes.front().superblock.xid ||
        current->volumes.front().superblock_object.physical_block != supplied->volumes.front().superblock_object.physical_block ||
        !ValidateBackupImageWriterProfile(source, *supplied, context_.volume_object_id, error))
        return fail("BackupAcceptedEndpointUnproven");
    std::vector<AppleRecoveryCheckpointView> history;
    if (!LoadAppleSnapshotRecoveryCheckpoints(source, *current, {batch.preimage_checkpoint_xid}, history, error) || history.size() != 1)
        return fail("BackupAcceptedHistoryUnavailable");
    const auto& before = history[0].checkpoint;
    if (before.volumes.size() != 1 || before.container.superblock.xid != batch.preimage_checkpoint_xid ||
        before.volumes.front().superblock.uuid_hex != current->volumes.front().superblock.uuid_hex)
        return fail("BackupAcceptedOwnerMismatch");
    std::map<std::uint64_t, std::vector<std::byte>> retained;
    const auto retain = [&](std::uint64_t block) {
        if (retained.contains(block)) return true;
        if (retained.size() >= 8192) return false;
        std::vector<std::byte> bytes;
        if (!source.Read(block * 4096, 4096, bytes)) return false;
        retained.emplace(block, std::move(bytes)); return true;
    };
    for (const auto block : history[0].metadata_blocks) if (!retain(block)) return fail("BackupAcceptedHistoryLimit");
    for (const auto& extent : history[0].payload_extents)
        for (std::uint64_t i = 0; i < extent.block_count; ++i)
            if (!retain(extent.physical_block + i)) return fail("BackupAcceptedHistoryLimit");
    BackupHistoricalSource historical(source, before, current->container.superblock_physical_block);
    if (!ValidateBackupImageWriterProfile(historical, before, context_.volume_object_id, error))
        return fail("BackupAcceptedPreimageUnproven");
    std::vector<catalog::BtreeRecord> records; NativeApfsVolumeProjection projection;
    if (!catalog::ReadAppleVolumeFileSystemRecords(source, before.container, before.volumes.front(), records, error) ||
        !NativeApfsReader::ProjectReadOnlyRecordsWithAdmission(records, before.container.superblock,
            before.volumes.front().superblock, before.container.superblock.block_count, budget, projection, error, false, true))
        return fail("BackupAcceptedSourceProjectionInvalid");
    MetadataStore candidate(context_, device_);
    candidate.context_.incompatible_features = projection.incompatible_features;
    candidate.authoritative_apple_checkpoint_view_ = before;
    candidate.block_size_ = 4096; candidate.total_blocks_ = before.container.superblock.block_count;
    candidate.checkpoint_xid_ = candidate.loaded_superblock_checkpoint_xid_ = batch.preimage_checkpoint_xid;
    candidate.container_loaded_ = candidate.object_map_loaded_ = true;
    candidate.root_directory_object_id_ = projection.root_directory_inode;
    candidate.highest_committed_apple_file_system_object_id_ = projection.highest_file_system_object_id;
    if (!BuildNativeProjectionInodeGraph(projection, [&](const auto& path) { return candidate.CanonicalPathKeyFromNormalizedPath(path); },
            candidate.committed_inodes_, candidate.committed_path_index_, candidate.committed_directory_links_))
        return fail("BackupAcceptedSourceGraphInvalid");
    candidate.committed_btree_records_ = std::move(projection.btree_records);
    candidate.committed_extended_attributes_ = std::move(projection.extended_attributes_by_inode);
    candidate.committed_attribute_stream_extents_ = std::move(projection.attribute_stream_extents);
    candidate.committed_read_extents_ = std::move(projection.read_extents_by_inode);
    for (const auto& [id, inode] : candidate.committed_inodes_)
        if (!inode.is_directory && inode.data_physical_address)
            candidate.committed_object_map_[id] = {id, inode.data_physical_address, inode.logical_size, projection.checkpoint_xid};
    std::vector<std::byte> spaceman;
    if (!source.Read(before.spaceman.object.physical_block * 4096, 4096, spaceman) ||
        !candidate.LoadSpacemanChunkInfoState(before.spaceman.object.physical_block, spaceman, &historical) ||
        !candidate.RebuildCommittedBtreeIndex() || !candidate.EnsureRootState()) return fail("BackupAcceptedSourceAllocatorInvalid");
    candidate.native_write_ready_ = candidate.spaceman_loaded_ = candidate.commit_path_ready_ = true;
    candidate.canonical_state_loaded_ = candidate.canonical_commit_ready_ = candidate.write_device_allowed_ = true;
    const auto inode = candidate.LookupCommittedInodeByPath(request.path);
    if (!inode || inode->object_id != record.object_id || inode->node_type != NodeType::RegularFile ||
        inode->logical_size > (8ull << 20) || (inode->bsd_flags & kAppleBsdCompressedFlag) ||
        request.offset > inode->logical_size || request.length > inode->logical_size - request.offset)
        return fail("BackupAcceptedOverwriteScopeUnsupported");
    std::vector<std::byte> expected(static_cast<std::size_t>(inode->logical_size));
    const auto extents = candidate.committed_read_extents_.find(inode->object_id);
    if (extents == candidate.committed_read_extents_.end()) return fail("BackupAcceptedPayloadCoverageInvalid");
    std::uint64_t covered = 0;
    for (const auto& extent : extents->second)
    {
        if (extent.logical_offset != covered || !extent.bytes || extent.bytes > UINT64_MAX - covered)
            return fail("BackupAcceptedPayloadCoverageInvalid");
        covered += extent.bytes;
        if (!extent.physical_address || extent.logical_offset >= expected.size()) continue;
        const auto count = static_cast<std::size_t>((std::min)(extent.bytes, expected.size() - extent.logical_offset));
        std::vector<std::byte> old_extent_bytes;
        if (!source.Read(extent.physical_address, count, old_extent_bytes) || old_extent_bytes.size() != count) return fail("BackupAcceptedOldPayloadUnreadable");
        std::copy(old_extent_bytes.begin(), old_extent_bytes.end(), expected.begin() + static_cast<std::size_t>(extent.logical_offset));
    }
    if (covered < expected.size()) return fail("BackupAcceptedPayloadCoverageInvalid");
    std::copy(payload.begin(), payload.end(), expected.begin() + static_cast<std::size_t>(request.offset));
    candidate.SetFilePayloadRangeProvider([&](const auto& path, auto id, auto at, auto destination) {
        const auto working = candidate.LookupWorkingInodeByPath(path);
        if (!working || working->object_id != record.object_id || id.object_id != record.object_id ||
            id.generation != record.parent_object_id || at > expected.size() || destination.size() > expected.size() - at) return false;
        std::copy_n(expected.begin() + static_cast<std::size_t>(at), destination.size(), destination.begin()); return true;
    });
    AppleCheckpointPublicationPlan publication;
    {
        BackupNoIoWriterScope scope(&candidate, historical);
        PayloadIdentity staged;
        if (candidate.StageMutation(request, &staged) != MutationStatus::Applied || staged.object_id != record.object_id ||
            staged.generation != record.parent_object_id) return fail("BackupAcceptedOriginalStageMismatch");
        if (candidate.CommitApplePendingMutations({batch.preimage_checkpoint_xid}, false, nullptr, {}, false, &publication, &historical) != CommitStatus::NothingToCommit)
        { error = "BackupAcceptedPlanMismatch:" + candidate.LastCommitStage() + ":" + TransactionManager::WideToUtf8(candidate.LastCommitFailureDetail()); return false; }
    }
    if (publication.transaction_xid != current->container.superblock.xid ||
        publication.superblock_write.physical_block != current->container.superblock_physical_block ||
        publication.published_checkpoint.superblock_bytes != current->container.superblock_bytes)
        return fail("BackupAcceptedPublicationIdentityMismatch");
    const auto readback = [&](const auto& write) {
        std::vector<std::byte> bytes;
        return !write.bytes.empty() && write.bytes.size() % 4096 == 0 &&
            source.Read(write.physical_block * 4096, write.bytes.size(), bytes) && bytes == write.bytes;
    };
    if (!readback(publication.superblock_write) || !std::all_of(publication.before_superblock_writes.begin(),
            publication.before_superblock_writes.end(), readback)) return fail("BackupAcceptedPublicationReadbackMismatch");
    for (const auto& [block, retained_original_bytes] : retained)
    {
        std::vector<std::byte> retained_actual_bytes;
        if (!source.Read(block * 4096, 4096, retained_actual_bytes) || retained_actual_bytes != retained_original_bytes) return fail("BackupAcceptedHistoryChanged");
    }
    const auto endpoint = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    const auto now = journal.Watermarks();
    if (!endpoint || endpoint->container.superblock_bytes != current->container.superblock_bytes ||
        endpoint->container.superblock_physical_block != current->container.superblock_physical_block || budget->Failed() ||
        !device_->IsExclusiveWriteSourceObservationCurrent(*observation) || !journal.RecoveryStateValid() ||
        journal.ObservedJournalWriterLeaseGeneration() != lease || journal.ObservedJournalAppendLeaseGeneration() != lease ||
        now.accepted_sequence != marks.accepted_sequence || now.apfs_durable_sequence != marks.apfs_durable_sequence || now.cleanup_sequence != marks.cleanup_sequence)
        return fail("BackupAcceptedAuthorityChanged");
    applied_sequences.push_back(batch.accepted_sequence); return true;
}
catch (const std::bad_alloc&) { applied_sequences.clear(); error = "BackupAcceptedResourceLimit"; return false; }
catch (const std::length_error&) { applied_sequences.clear(); error = "BackupAcceptedResourceLimit"; return false; }
