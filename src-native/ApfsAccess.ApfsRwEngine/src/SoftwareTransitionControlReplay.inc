// Included inside apfsaccess::rw. This view reconstructs only certified old
// ring controls for deterministic replay; it never supplies a current bitmap.
namespace
{
class SoftwareTransitionControlReplaySource final : public catalog::ImmutableEncryptedReadSource
{
    const catalog::ImmutableEncryptedReadSource& source_;
    std::uint64_t preimage_ = 0;
    std::vector<AppleCheckpointGuardBlock> preimages_, changed_;
    explicit SoftwareTransitionControlReplaySource(const catalog::ImmutableEncryptedReadSource& source) : source_(source) {}
public:
    enum class Purpose { PendingPrefix, CompletedVerification };
    static bool Capture(TransactionManager& tx, const catalog::ImmutableEncryptedReadSource& source,
        const catalog::SoftwareVolumeRetainedOwners& owners,
        std::unique_ptr<SoftwareTransitionControlReplaySource>& result, std::string& error)
    { return CaptureFor(tx, source, owners, result, error, Purpose::PendingPrefix); }
    static bool CaptureForCompletedVerification(TransactionManager& tx, const catalog::ImmutableEncryptedReadSource& source,
        const catalog::SoftwareVolumeRetainedOwners& owners,
        std::unique_ptr<SoftwareTransitionControlReplaySource>& result, std::string& error)
    { return CaptureFor(tx, source, owners, result, error, Purpose::CompletedVerification); }
private:
    static bool CaptureFor(TransactionManager& tx, const catalog::ImmutableEncryptedReadSource& source,
        const catalog::SoftwareVolumeRetainedOwners& owners,
        std::unique_ptr<SoftwareTransitionControlReplaySource>& result, std::string& error, Purpose purpose)
    {
        result.reset();
        const auto fail = [&](const char* reason) { error = reason; return false; };
        if (!tx.RecoveryStateValid() || tx.ProtectedJournalIdentity() != std::optional{owners.OriginalJournalIdentity()} ||
            tx.ProtectedSourceBinding() != std::optional{owners.SourceBinding()} || source.SourceIdentity() != owners.SourceIdentity())
            return fail("AppleSoftwareTransitionControlReplayScopeMismatch");
        const auto marks = tx.Watermarks();
        if (marks.accepted_sequence == marks.cleanup_sequence && marks.apfs_durable_sequence == marks.cleanup_sequence)
            return true;
        std::vector<TransactionManager::AcceptedTransaction> pending;
        struct Wipe {
            decltype(pending)& rows;
            ~Wipe() { for (auto& group : rows) for (auto& row : group.mutations)
                std::fill(row.inline_payload.begin(), row.inline_payload.end(), std::byte{}); }
        } wipe{pending};
        if (tx.CurrentState() != TransactionManager::State::Idle ||
            !tx.LoadAcceptedTransactionsSinceCleanup(pending, &error) || pending.size() != 1 ||
            pending.front().mutations.size() != 1 || pending.front().accepted_sequence != marks.accepted_sequence ||
            marks.cleanup_sequence >= marks.accepted_sequence)
            return fail("AppleSoftwareTransitionControlReplayAcceptedWriteRequired");
        const auto& write = pending.front().mutations.front();
        if (write.operation != WriteAheadLog::OperationKind::Write || write.state != WriteAheadLog::RecordState::Prepared ||
            write.flags || write.unlink_outcome || !write.object_id || !write.parent_object_id || !write.logical_length ||
            write.logical_length > 4096 || !WriteAheadLog::InlinePayloadIsConsistent(write) || write.payload_offset ||
            write.payload_length != write.logical_length || write.inline_payload.size() != write.logical_length ||
            write.logical_offset > UINT64_MAX - write.logical_length || write.path_utf8.empty() || write.path_utf8.front() != '\\' ||
            write.path_utf8.starts_with("\\$apfs-") || !write.secondary_path_utf8.empty())
            return fail("AppleSoftwareTransitionControlReplayInlineWriteRequired");
        auto current = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        if (!current || current->volumes.size() != 1 ||
            current->volumes.front().superblock.object_id != owners.VolumeObjectId() ||
            current->volumes.front().superblock.uuid_hex != owners.VolumeUuid() ||
            current->volumes.front().superblock.fs_flags != catalog::kFsFlagUnencrypted)
            return fail("AppleSoftwareTransitionControlReplayCurrentPlainAllocatorRequired");
        const auto preimage = pending.front().preimage_checkpoint_xid;
        if (current->container.superblock.xid != preimage) {
            auto prior = catalog::LoadContainerCheckpointView(source, 0, source.SizeBytes(), error, preimage);
            if (!prior || prior->superblock.next_xid != current->container.superblock.xid)
                return fail("AppleSoftwareTransitionControlReplayCheckpointBoundaryMismatch");
            // A completed switch needs strict real-byte validation for reopen.
            // Keeping the old preimage below prevents another publication.
            if (purpose == Purpose::PendingPrefix) {
                auto completed = std::unique_ptr<SoftwareTransitionControlReplaySource>(new SoftwareTransitionControlReplaySource(source));
                completed->preimage_ = preimage; result = std::move(completed); return true;
            }
        } else if (purpose == Purpose::CompletedVerification) {
            return fail("AppleSoftwareTransitionCompletedSuccessorRequired");
        }
        std::vector<std::uint64_t> protected_blocks{0, current->container.superblock_physical_block,
            current->spaceman.object.physical_block};
        protected_blocks.insert(protected_blocks.end(), current->container.checkpoint_map_blocks.begin(), current->container.checkpoint_map_blocks.end());
        for (const auto& mapping : current->container.mappings)
            for (std::uint64_t i = 0; i < mapping.size_bytes / 4096; ++i) protected_blocks.push_back(mapping.physical_block + i);
        for (const auto& device : current->spaceman.devices) {
            for (const auto& cab : device.cabs) protected_blocks.push_back(cab.object.physical_block);
            for (const auto& cib : device.cibs) protected_blocks.push_back(cib.object.physical_block);
        }
        for (const auto& chunk : current->spaceman.chunks) protected_blocks.push_back(chunk.bitmap_block);
        for (const auto& bitmap : current->spaceman.internal_pool.active_bitmaps) protected_blocks.push_back(bitmap.physical_block);
        for (const auto& queue : current->spaceman.free_queues)
            protected_blocks.insert(protected_blocks.end(), queue.tree_blocks.begin(), queue.tree_blocks.end());
        // This separately named source is consumed only by no-I/O reconstruction.
        // The actual current allocator was fully loaded above and is rechecked
        // after every planned publication block has matched its real bytes.
        if (purpose == Purpose::CompletedVerification) protected_blocks = {0};
        for (const auto& generation : owners.Generations()) for (const auto& guard : generation.graph_guards)
            protected_blocks.push_back(guard.physical_block);
        auto view = std::unique_ptr<SoftwareTransitionControlReplaySource>(new SoftwareTransitionControlReplaySource(source));
        view->preimage_ = preimage;
        const auto& nx = current->container.superblock;
        const auto in_ring = [](std::uint64_t block, std::uint64_t base, std::uint64_t count) {
            return block >= base && block - base < count;
        };
        for (const auto& generation : owners.Generations()) {
            bool retired = false;
            if (!owners.VerifyGenerationRetirement(source, *tx.ProtectedJournalIdentity(),
                    generation.checkpoint.superblock.xid, retired, error)) return false;
            if (retired) continue;
            for (const auto& guard : generation.checkpoint_guards) {
            std::vector<std::byte> actual;
            if (guard.bytes.size() != 4096 || guard.physical_block > UINT64_MAX / 4096 ||
                !source.Read(guard.physical_block * 4096, 4096, actual))
                return fail("AppleSoftwareTransitionControlReplayGuardUnreadable");
            if (actual == guard.bytes) continue;
            if (std::find(protected_blocks.begin(), protected_blocks.end(), guard.physical_block) != protected_blocks.end() ||
                (!in_ring(guard.physical_block, nx.xp_desc_base_block, nx.xp_desc_block_count) &&
                 !in_ring(guard.physical_block, nx.xp_data_base_block, nx.xp_data_block_count)))
                return fail("AppleSoftwareTransitionControlReplayProtectedBytesChanged");
            const auto previous = std::find_if(view->preimages_.begin(), view->preimages_.end(),
                [&](const auto& row) { return row.physical_block == guard.physical_block; });
            if (previous != view->preimages_.end()) {
                if (previous->bytes != guard.bytes) return fail("AppleSoftwareTransitionControlReplayGuardConflict");
                continue;
            }
            if (!source.ReadBudget() || !source.ReadBudget()->Materialize(2, 2 * (sizeof(guard) + guard.bytes.size())))
                return fail("AppleSoftwareTransitionControlReplayBudgetExceeded");
            view->preimages_.push_back(guard); view->changed_.push_back({guard.physical_block, std::move(actual)});
            }
        }
        result = std::move(view); return true;
    }
public:
    bool MatchPlannedPrefix(const AppleCheckpointPublicationPlan& plan, std::string& error) const
    {
        if (plan.expected_checkpoint_xid != preimage_) { error = "AppleSoftwareTransitionControlReplayPlanMismatch"; return false; }
        for (const auto& actual : changed_) {
            if (actual.physical_block == plan.superblock_write.physical_block) {
                const auto before = std::find_if(preimages_.begin(), preimages_.end(),
                    [&](const auto& guard) { return guard.physical_block == actual.physical_block; });
                const auto& after = plan.superblock_write.bytes;
                if (before == preimages_.end() || actual.bytes.size() != 4096 || before->bytes.size() != 4096 || after.size() != 4096) {
                    error = "AppleSoftwareTransitionTornSwitchScopeMismatch"; return false;
                }
                std::size_t prefix = 0;
                while (prefix < after.size() && actual.bytes[prefix] == after[prefix]) ++prefix;
                if (prefix && prefix < after.size() && std::equal(actual.bytes.begin() + prefix, actual.bytes.end(), before->bytes.begin() + prefix))
                    continue;
                error = "AppleSoftwareTransitionTornSwitchBytesMismatch"; return false;
            }
            const auto found = std::find_if(plan.before_superblock_writes.begin(), plan.before_superblock_writes.end(),
                [&](const auto& write) { return write.physical_block == actual.physical_block && write.bytes == actual.bytes; });
            if (found == plan.before_superblock_writes.end()) { error = "AppleSoftwareTransitionControlReplayPrefixMismatch"; return false; }
        }
        return true;
    }
    bool MatchCompletedPublication(const AppleCheckpointPublicationPlan& plan, std::string& error) const
    {
        if (plan.expected_checkpoint_xid != preimage_) { error = "AppleSoftwareTransitionCompletedPlanMismatch"; return false; }
        for (const auto& actual : changed_) {
            if (actual.physical_block == plan.superblock_write.physical_block && actual.bytes == plan.superblock_write.bytes) continue;
            const auto found = std::find_if(plan.before_superblock_writes.begin(), plan.before_superblock_writes.end(),
                [&](const auto& write) { return write.physical_block == actual.physical_block && write.bytes == actual.bytes; });
            if (found == plan.before_superblock_writes.end()) { error = "AppleSoftwareTransitionCompletedControlMismatch"; return false; }
        }
        return true;
    }
    void Overlay(std::uint64_t at, std::span<std::byte> bytes) const
    {
        for (const auto& guard : preimages_) {
            const auto begin = guard.physical_block * 4096;
            const auto first = (std::max)(at, begin), last = (std::min)(at + bytes.size(), begin + 4096);
            if (first < last) std::copy(guard.bytes.begin() + (first - begin), guard.bytes.begin() + (last - begin), bytes.begin() + (first - at));
        }
    }
    std::uint64_t SizeBytes() const override { return source_.SizeBytes(); }
    std::string SourceIdentity() const override { return source_.SourceIdentity(); }
    std::uint64_t Revision() const override { return source_.Revision(); }
    std::shared_ptr<catalog::ApfsReadBudget> ReadBudget() const override { return source_.ReadBudget(); }
    bool Read(std::uint64_t at, std::size_t count, std::vector<std::byte>& bytes) const override
    {
        if (!source_.Read(at, count, bytes) || bytes.size() != count || at > SizeBytes() || count > SizeBytes() - at) return false;
        Overlay(at, bytes);
        return true;
    }
};
}
