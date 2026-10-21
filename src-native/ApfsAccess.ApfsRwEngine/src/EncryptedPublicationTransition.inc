// Included inside apfsaccess::rw after the common protected witness machinery.
#include "SoftwareTransitionControlReplay.inc"
namespace
{
struct TransitionBytesWipe
{
    std::vector<std::byte>& bytes;
    ~TransitionBytesWipe() { SecureZeroMemory(bytes.data(), bytes.size()); }
};
struct TransitionIntentsWipe
{
    std::vector<TransactionManager::MutationIntent>& rows;
    ~TransitionIntentsWipe() { for (auto& row : rows) SecureZeroMemory(row.inline_payload.data(), row.inline_payload.size()); }
};
struct TransitionOwnersDecoded
{
    std::string source, container, volume;
    std::uint64_t oid = 0, minted = 0, blocks = 0;
    std::array<std::byte, 32> binding{}, journal{}, allocator{};
    std::vector<catalog::SoftwareVolumeRetainedGeneration> generations;
    ~TransitionOwnersDecoded()
    {
        for (auto& generation : generations) {
            SecureZeroMemory(generation.checkpoint.superblock_bytes.data(), generation.checkpoint.superblock_bytes.size());
            for (auto* guards : {&generation.graph_guards, &generation.checkpoint_guards})
                for (auto& guard : *guards) SecureZeroMemory(guard.bytes.data(), guard.bytes.size());
        }
    }
};
std::vector<std::byte> EncodeTransitionOwners(const catalog::SoftwareVolumeRetainedOwners& owners)
{
    Encoder e;
    e.Number(1); e.Text(owners.SourceIdentity()); e.Text(owners.ContainerUuid()); e.Text(owners.VolumeUuid());
    e.Number(owners.VolumeObjectId()); e.Number(owners.MintedCheckpointXid()); e.Number(owners.ContainerBlockCount());
    e.Data(owners.SourceBinding()); e.Data(owners.OriginalJournalIdentity()); e.Data(owners.MintedAllocatorSha256());
    e.Number(owners.Generations().size());
    for (const auto& generation : owners.Generations()) {
        e.Number(generation.checkpoint.superblock_physical_block); e.Data(generation.checkpoint.superblock_bytes);
        e.Number(generation.ranges.size());
        for (const auto& range : generation.ranges) {
            e.Number(range.start_block); e.Number(range.block_count); e.Number(static_cast<unsigned>(range.kind));
        }
        for (const auto* guards : {&generation.checkpoint_guards, &generation.graph_guards}) {
            e.Number(guards->size());
            for (const auto& guard : *guards) { e.Number(guard.physical_block); e.Data(guard.bytes); }
        }
    }
    return std::move(e.bytes);
}
void DecodeTransitionOwners(std::span<const std::byte> bytes, TransitionOwnersDecoded& out)
{
    Decoder d{bytes};
    if (d.Number() != 1) throw std::runtime_error("TransitionOwnerVersion");
    out.source = d.Text(4096); out.container = d.Text(32); out.volume = d.Text(32);
    out.oid = d.Number(); out.minted = d.Number(); out.blocks = d.Number();
    for (auto* target : {&out.binding, &out.journal, &out.allocator}) {
        const auto value = d.Data(32);
        if (value.size() != 32) throw std::runtime_error("TransitionOwnerDigest");
        std::copy(value.begin(), value.end(), target->begin());
        if (!Nonzero(*target)) throw std::runtime_error("TransitionOwnerDigest");
    }
    if (out.source.empty() || out.container.size() != 32 || out.volume.size() != 32 || !out.oid || !out.minted ||
        !out.blocks || out.blocks > UINT64_MAX / 4096) throw std::runtime_error("TransitionOwnerScope");
    const auto count = d.Number();
    if (!count || count > 6) throw std::runtime_error("TransitionOwnerGenerationCount");
    std::set<std::uint64_t> xids;
    for (std::uint64_t i = 0; i < count; ++i) {
        catalog::SoftwareVolumeRetainedGeneration generation;
        generation.checkpoint.superblock_physical_block = d.Number();
        generation.checkpoint.superblock_bytes = d.Data(4096);
        auto nx = catalog::ParseNxSuperblock(generation.checkpoint.superblock_bytes);
        if (!nx || nx->block_size != 4096 || nx->block_count != out.blocks || nx->uuid_hex != out.container ||
            !nx->xid || nx->xid > out.minted || !xids.insert(nx->xid).second || generation.checkpoint.superblock_physical_block >= out.blocks)
            throw std::runtime_error("TransitionOwnerCheckpoint");
        generation.checkpoint.superblock = *nx;
        const auto ranges = d.Number();
        if (!ranges || ranges > 384) throw std::runtime_error("TransitionOwnerRanges");
        std::set<std::uint64_t> ranged;
        for (std::uint64_t n = 0; n < ranges; ++n) {
            catalog::SoftwareVolumeOwnedRange range;
            range.start_block = d.Number(); range.block_count = d.Number(); const auto kind = d.Number();
            if (!range.start_block || !range.block_count || range.block_count > 64 || range.start_block >= out.blocks ||
                range.block_count > out.blocks - range.start_block || kind > static_cast<unsigned>(catalog::SoftwareVolumeOwnerKind::Keybag))
                throw std::runtime_error("TransitionOwnerRange");
            range.kind = static_cast<catalog::SoftwareVolumeOwnerKind>(kind);
            for (std::uint64_t block = 0; block < range.block_count; ++block)
                if (!ranged.insert(range.start_block + block).second) throw std::runtime_error("TransitionOwnerRangeOverlap");
            generation.ranges.push_back(range);
        }
        for (auto* guards : {&generation.checkpoint_guards, &generation.graph_guards}) {
            const auto size = d.Number();
            if (!size || size > (guards == &generation.checkpoint_guards ? 64 : 384)) throw std::runtime_error("TransitionOwnerGuards");
            std::set<std::uint64_t> guarded;
            for (std::uint64_t n = 0; n < size; ++n) {
                AppleCheckpointGuardBlock guard; guard.physical_block = d.Number(); guard.bytes = d.Data(4096);
                if (guard.physical_block >= out.blocks || guard.bytes.size() != 4096 || !guarded.insert(guard.physical_block).second)
                    throw std::runtime_error("TransitionOwnerGuard");
                guards->push_back(std::move(guard));
            }
            if (guards == &generation.graph_guards && guarded != ranged) throw std::runtime_error("TransitionOwnerGuardCoverage");
        }
        const auto nx_guard = std::find_if(generation.checkpoint_guards.begin(), generation.checkpoint_guards.end(), [&](const auto& guard) {
            return guard.physical_block == generation.checkpoint.superblock_physical_block && guard.bytes == generation.checkpoint.superblock_bytes;
        });
        if (nx_guard == generation.checkpoint_guards.end()) throw std::runtime_error("TransitionOwnerCheckpointGuard");
        out.generations.push_back(std::move(generation));
    }
    if (!d.bytes.empty() || !xids.contains(out.minted)) throw std::runtime_error("TransitionOwnerTrailingOrMintedGeneration");
}
bool ValidateTransitionEnvelope(const Witness& w, const EncryptedPublicationJournal::Options& options, std::string& error)
{
    try {
        TransitionOwnersDecoded owners; DecodeTransitionOwners(w.transition_owners, owners);
        if (!ValidRetainedRewriteModes(w.version, w.transition_before, w.transition_after) ||
            w.inode != options.volume_object_id || w.volume_object_id != options.volume_object_id || w.volume_uuid != options.volume_uuid ||
            w.offset || w.parent || w.destination_parent || w.result_size || w.permissions || w.effective_mode ||
            w.kind != catalog::EncryptedMutationKind::Overwrite || w.name != Digest{} || w.destination_name != Digest{} ||
            owners.source != w.source || owners.container != options.container_uuid || owners.volume != w.volume_uuid ||
            owners.oid != w.volume_object_id || owners.minted != w.plan.expected_checkpoint_xid ||
            owners.blocks != options.container_bytes / 4096 || owners.journal != w.original_journal)
            return Fail(error, "EncryptedPublicationTransitionScopeMismatch");
        auto nx = catalog::ParseNxSuperblock(w.plan.superblock_write.bytes);
        if (!nx || nx->xid != w.plan.transaction_xid || nx->uuid_hex != options.container_uuid ||
            nx->block_count != owners.blocks || catalog::ReadU64LE(w.plan.superblock_write.bytes, 0x4F0) != (w.transition_after ? 4 : 0))
            return Fail(error, "EncryptedPublicationTransitionNxMismatch");
        std::size_t apsbs = 0;
        for (const auto& row : w.plan.before_superblock_writes) {
            if (catalog::ReadU32LE(row.bytes, 24) != catalog::kObjectTypeFs || catalog::ReadU64LE(row.bytes, 8) != owners.oid) continue;
            auto volume = catalog::ParseApsb(row.bytes);
            if (!volume || volume->xid != nx->xid || volume->uuid_hex != owners.volume ||
                volume->fs_flags != (w.transition_after ? catalog::kFsFlagOneKey : catalog::kFsFlagUnencrypted))
                return Fail(error, "EncryptedPublicationTransitionVolumeModeMismatch");
            ++apsbs;
        }
        return apsbs == 1 || Fail(error, "EncryptedPublicationTransitionVolumeMissing");
    } catch (...) { return Fail(error, "EncryptedPublicationTransitionOwnersInvalid"); }
}
bool MatchTransitionOriginal(const TransactionManager::AcceptedTransaction& original, const Witness& w,
    const EncryptedPublicationJournal::Options& options, std::string& error)
{
    auto bytes = MaintenanceTemplate(w, options); TransitionBytesWipe wipe{bytes}; Digest digest{};
    if (!IsRetainedRewrite(w.version) || original.accepted_sequence != w.accepted || original.transaction_id != w.transaction ||
        original.preimage_checkpoint_xid != w.plan.expected_checkpoint_xid || !Hash(bytes, digest) ||
        w.length != bytes.size() || w.replacement != digest || original.mutations.size() != (bytes.size() + chunk_bytes - 1) / chunk_bytes)
        return Fail(error, "EncryptedPublicationTransitionOriginalMismatch");
    std::size_t offset = 0;
    for (const auto& row : original.mutations) {
        const auto part = std::span(bytes).subspan(offset, (std::min)(chunk_bytes, bytes.size() - offset));
        if (row.operation != WriteAheadLog::OperationKind::Write || row.object_id != w.inode ||
            row.parent_object_id != w.plan.expected_checkpoint_xid || row.logical_offset != offset ||
            row.logical_length != part.size() || row.payload_length != part.size() || row.payload_offset || row.payload_spool_id != row.sequence ||
            row.flags || row.unlink_outcome ||
            row.path_utf8 != (w.version == 8 ? "\\$apfs-software-key-rotation-v1" : "\\$apfs-software-transition-v1") || !row.secondary_path_utf8.empty() ||
            row.inline_payload.size() != part.size() || !std::equal(row.inline_payload.begin(), row.inline_payload.end(), part.begin()) ||
            !Hash(part, digest) || digest != row.payload_sha256)
            return Fail(error, "EncryptedPublicationTransitionOriginalMismatch");
        offset += part.size();
    }
    return true;
}
bool TransitionWitness(const catalog::SoftwareVolumeTransitionPublication& prepared,
    const EncryptedPublicationJournal::Options& options, Witness& w, std::string& error)
{
    w.version = 6; w.inode = w.volume_object_id = prepared.VolumeObjectId(); w.volume_uuid = prepared.VolumeUuid();
    w.source = prepared.SourceIdentity(); w.original_journal = prepared.OriginalJournalIdentity(); w.plan = prepared.Publication();
    w.transition_before = static_cast<unsigned>(prepared.BeforeMode()); w.transition_after = static_cast<unsigned>(prepared.AfterMode());
    w.transition_owners = EncodeTransitionOwners(prepared.RetainedOwners());
    if (!Nonzero(w.original_journal) || w.original_journal != options.maintenance_original_journal_identity ||
        w.source != options.preimage_source_identity || prepared.SourceBinding() != options.witness.protected_persistence->source_binding ||
        w.plan.fusion_tier2_anchor_write || !Hash(w.transition_owners, w.transition_owners_sha256))
        return Fail(error, "EncryptedPublicationTransitionScopeMismatch");
    return ValidateTransitionEnvelope(w, options, error);
}
std::vector<TransactionManager::MutationIntent> TransitionOriginalRecords(const Witness& w, std::span<const std::byte> bytes)
{
    std::vector<TransactionManager::MutationIntent> output;
    for (std::size_t offset = 0; offset < bytes.size(); offset += chunk_bytes) {
        const auto part = bytes.subspan(offset, (std::min)(chunk_bytes, bytes.size() - offset));
        TransactionManager::MutationIntent row; row.kind = TransactionManager::MutationKind::Write;
        row.path = w.version == 8 ? EncryptedPublicationJournal::KeyRotationAcceptancePath : EncryptedPublicationJournal::TransitionAcceptancePath;
        row.object_id = w.inode;
        row.generation = w.plan.expected_checkpoint_xid; row.offset = offset; row.length = row.payload_length = part.size();
        row.inline_payload.assign(part.begin(), part.end());
        if (!Hash(part, row.payload_checksum)) throw std::runtime_error("TransitionOriginalHashFailed");
        output.push_back(std::move(row));
    }
    return output;
}
}

bool EncryptedPublicationJournal::AcceptTransition(TransactionManager& tx,
    const catalog::SoftwareVolumeTransitionPublication& prepared, std::uint64_t& accepted, std::string& error)
{
    accepted = 0; error.clear();
    try {
        Witness w;
        if (!TransitionWitness(prepared, options_, w, error)) return false;
        auto original = MaintenanceTemplate(w, options_); TransitionBytesWipe wipe{original};
        return AcceptRetainedRewrite(tx, original, accepted, error);
    } catch (...) { return Fail(error, "EncryptedPublicationTransitionAcceptInvalid"); }
}
bool EncryptedPublicationJournal::AcceptRetainedRewrite(TransactionManager& tx,
    std::span<const std::byte> original, std::uint64_t& accepted, std::string& error)
{
    accepted = 0; error.clear();
    if (poisoned_ || !tx.RecoveryStateValid() || tx.CurrentState() != TransactionManager::State::Idle ||
        tx.ProtectedJournalIdentity() != std::optional{options_.maintenance_original_journal_identity} ||
        tx.ProtectedSourceBinding() != std::optional{options_.witness.protected_persistence->source_binding})
        return Fail(error, "EncryptedPublicationTransitionOwnerInvalid");
    const auto abort = [&] { if (tx.CurrentState() == TransactionManager::State::Active) (void)tx.Abort(); };
    try {
        std::vector<TransactionManager::AcceptedTransaction> pending; AcceptedWipe pending_wipe{pending};
        const auto marks = tx.Watermarks();
        if (marks.accepted_sequence != marks.cleanup_sequence || marks.apfs_durable_sequence != marks.cleanup_sequence ||
            !tx.LoadAcceptedTransactionsSinceCleanup(pending, &error) || !pending.empty())
            return Fail(error, "EncryptedPublicationTransitionPriorBoundaryNotClean");
        auto w = Decode(original, options_, true);
        if (!IsRetainedRewrite(w.version) || w.source != options_.preimage_source_identity)
            return Fail(error, "EncryptedPublicationTransitionScopeMismatch");
        auto rows = TransitionOriginalRecords(w, original); TransitionIntentsWipe rows_wipe{rows};
        if (rows.empty() || !Hash(original, w.replacement) || !tx.ProtectedAcceptanceCapacityAvailable(rows, error)) return false;
        w.length = original.size();
        if (!tx.Begin()) return Fail(error, "EncryptedPublicationTransitionBeginFailed");
        const auto first = tx.NextMutationSequence();
        if (!first || rows.size() >= UINT64_MAX - first || !tx.CurrentTransactionId()) {
            abort(); return Fail(error, "EncryptedPublicationTransitionBoundaryOverflow");
        }
        w.accepted = first + rows.size(); w.transaction = tx.CurrentTransactionId();
        auto encoded = Encode(w, options_); TransitionBytesWipe encoded_wipe{encoded};
        if (!AppendWitness(w.accepted, encoded, error, false, &tx) || !ConfirmTransitionAuthorization(encoded, error)) { abort(); return false; }
        tx.NotifyStage("transition-after-private-authorization");
        for (const auto& row : rows) {
            if (!tx.RecordMutation(row) || !tx.FlushPreparedRecords()) {
                abort(); return Fail(error, "EncryptedPublicationTransitionPreparedFlushFailed");
            }
            tx.NotifyStage("transition-after-original-prepared-chunk");
        }
        if (!tx.Accept(w.plan.expected_checkpoint_xid)) { abort(); return Fail(error, "EncryptedPublicationTransitionAcceptFailed"); }
        if (tx.Watermarks().accepted_sequence != w.accepted) {
            poisoned_ = true; return Fail(error, "EncryptedPublicationTransitionAcceptedBoundaryMismatch");
        }
        if (!MatchAccepted(tx, w, options_, error)) { poisoned_ = true; return false; }
        accepted = w.accepted; return true;
    } catch (...) { abort(); return Fail(error, "EncryptedPublicationTransitionAcceptInvalid"); }
}
bool EncryptedPublicationJournal::ConfirmTransitionAuthorization(std::span<const std::byte> encoded, std::string& error)
{
    try {
        auto w = Decode(encoded, options_);
        if (!IsRetainedRewrite(w.version)) return Fail(error, "EncryptedPublicationTransitionAuthorizationMissing");
        auto records = witness_.ReadAllWithExclusiveWriterLease({64ull << 20, 4096}); Wipe wipe{records.records};
        std::vector<WitnessGroup> groups;
        if (records.status != WriteAheadLog::ReadStatus::Ok || !ReadGroups(records.records, groups, error) || groups.empty())
            return Fail(error, "EncryptedPublicationTransitionAuthorizationMissing");
        for (const auto& group : groups) {
            auto body = Decode(group.bytes, options_, false, OriginalJournalBinding::Historical);
            if (body.accepted != group.accepted || body.transaction != group.transaction || body.inode != group.inode)
                return Fail(error, "EncryptedPublicationTransitionAuthorizationBoundaryMismatch");
        }
        const auto& selected = groups.back();
        return (selected.accepted == w.accepted && selected.transaction == w.transaction && selected.inode == w.inode &&
            selected.bytes.size() == encoded.size() && std::equal(selected.bytes.begin(), selected.bytes.end(), encoded.begin())) ||
            Fail(error, "EncryptedPublicationTransitionAuthorizationMissing");
    } catch (...) { return Fail(error, "EncryptedPublicationTransitionAuthorizationMissing"); }
}
bool EncryptedPublicationJournal::StageTransition(TransactionManager& tx, std::uint64_t accepted,
    const catalog::SoftwareVolumeTransitionPublication& prepared, std::string& error)
{
    error.clear();
    try {
        Witness w;
        if (!TransitionWitness(prepared, options_, w, error)) return false;
        auto original = MaintenanceTemplate(w, options_); TransitionBytesWipe wipe{original};
        return StageRetainedRewrite(tx, accepted, original, error);
    } catch (...) { return Fail(error, "EncryptedPublicationTransitionStageInvalid"); }
}
bool EncryptedPublicationJournal::StageRetainedRewrite(TransactionManager& tx, std::uint64_t accepted,
    std::span<const std::byte> original, std::string& error)
{
    error.clear();
    if (poisoned_ || !tx.RecoveryStateValid() || tx.ProtectedJournalIdentity() != std::optional{options_.maintenance_original_journal_identity} ||
        tx.ProtectedSourceBinding() != std::optional{options_.witness.protected_persistence->source_binding})
        return Fail(error, "EncryptedPublicationTransitionOwnerInvalid");
    try {
        auto w = Decode(original, options_, true);
        if (!IsRetainedRewrite(w.version) || w.source != options_.preimage_source_identity)
            return Fail(error, "EncryptedPublicationTransitionScopeMismatch");
        std::vector<TransactionManager::AcceptedTransaction> pending; AcceptedWipe pending_wipe{pending};
        if (!tx.LoadAcceptedTransactionsSinceCleanup(pending, &error) || pending.size() != 1 || pending.front().accepted_sequence != accepted)
            return Fail(error, "EncryptedPublicationTransitionPendingBoundaryMismatch");
        w.accepted = accepted; w.transaction = pending.front().transaction_id; w.length = original.size();
        if (!Hash(original, w.replacement) || !MatchAccepted(tx, w, options_, error)) return false;
        auto encoded = Encode(w, options_); TransitionBytesWipe encoded_wipe{encoded};
        return ConfirmTransitionAuthorization(encoded, error) && witness_.FlushPendingAppends();
    } catch (...) { return Fail(error, "EncryptedPublicationTransitionStageInvalid"); }
}
bool EncryptedPublicationJournal::RestageTransition(TransactionManager& tx, std::uint64_t accepted, std::string& error)
{ return RestageRetainedRewrite(tx, accepted, 6, error); }
bool EncryptedPublicationJournal::RestageRetainedRewrite(TransactionManager& tx, std::uint64_t accepted,
    std::uint64_t expected_version, std::string& error)
{
    error.clear();
    if (poisoned_ || !tx.RecoveryStateValid() || tx.ProtectedJournalIdentity() != std::optional{options_.maintenance_original_journal_identity} ||
        tx.ProtectedSourceBinding() != std::optional{options_.witness.protected_persistence->source_binding})
        return Fail(error, "EncryptedPublicationTransitionOwnerInvalid");
    try {
        std::vector<TransactionManager::AcceptedTransaction> pending; AcceptedWipe pending_wipe{pending};
        if (!tx.LoadAcceptedTransactionsSinceCleanup(pending, &error) || pending.size() != 1 || pending.front().accepted_sequence != accepted)
            return Fail(error, "EncryptedPublicationTransitionPendingBoundaryMismatch");
        std::vector<std::byte> original; TransitionBytesWipe wipe{original};
        for (const auto& row : pending.front().mutations) {
            if (row.inline_payload.empty() || row.inline_payload.size() > chunk_bytes || row.logical_offset != original.size() ||
                row.inline_payload.size() > max_bytes - original.size()) return Fail(error, "EncryptedPublicationTransitionOriginalMismatch");
            original.insert(original.end(), row.inline_payload.begin(), row.inline_payload.end());
        }
        auto w = Decode(original, options_, true);
        if (!IsRetainedRewrite(expected_version) || w.version != expected_version || w.source != options_.preimage_source_identity)
            return Fail(error, "EncryptedPublicationTransitionScopeMismatch");
        w.accepted = accepted; w.transaction = pending.front().transaction_id; w.length = original.size();
        if (!Hash(original, w.replacement) || !MatchAccepted(tx, w, options_, error)) return false;
        auto encoded = Encode(w, options_); TransitionBytesWipe encoded_wipe{encoded};
        if (!ConfirmTransitionAuthorization(encoded, error)) {
            if (expected_version != 8 || !RebuildPrivateAuthorization(tx, encoded, 8, error) ||
                !ConfirmTransitionAuthorization(encoded, error)) return false;
        }
        if (!witness_.FlushPendingAppends()) { poisoned_ = true; return Fail(error, "EncryptedPublicationTransitionWitnessFlushFailed"); }
        return true;
    } catch (...) { return Fail(error, "EncryptedPublicationTransitionRestageInvalid"); }
}

bool EncryptedPublicationJournal::TryRestoreTransitionRetainedOwners(TransactionManager& tx,
    const catalog::ImmutableEncryptedReadSource& source, std::unique_ptr<const catalog::SoftwareVolumeRetainedOwners>& restored, std::string& error)
{ return TryRestoreTransitionRetainedOwnersImpl(tx, source, restored, error, 0); }

bool EncryptedPublicationJournal::TryRestoreTransitionRetainedOwnersImpl(TransactionManager& tx,
    const catalog::ImmutableEncryptedReadSource& source, std::unique_ptr<const catalog::SoftwareVolumeRetainedOwners>& restored,
    std::string& error, std::uint64_t accepted_replay_sequence, RetainedReplayPurpose purpose)
{
    restored.reset(); error.clear();
    const auto fail = [&](const char* reason) { error = reason; return false; };
    if (poisoned_ || !tx.RecoveryStateValid() || tx.CurrentState() != TransactionManager::State::Idle ||
        tx.ProtectedJournalIdentity() != std::optional{options_.maintenance_original_journal_identity} ||
        tx.ProtectedSourceBinding() != std::optional{options_.witness.protected_persistence->source_binding} ||
        source.SourceIdentity() != options_.preimage_source_identity)
        return fail("EncryptedPublicationTransitionRestoreScopeMismatch");
    try {
        const auto marks = tx.Watermarks();
        if (!accepted_replay_sequence) {
            if (marks.cleanup_sequence != marks.apfs_durable_sequence || marks.cleanup_sequence != marks.accepted_sequence)
                return fail("EncryptedPublicationTransitionRestoreRequiresCleanOriginal");
        } else {
            std::vector<TransactionManager::AcceptedTransaction> pending_write; AcceptedWipe pending_write_wipe{pending_write};
            if (marks.accepted_sequence != accepted_replay_sequence || marks.cleanup_sequence >= accepted_replay_sequence ||
                !tx.LoadAcceptedTransactionsSinceCleanup(pending_write, &error) || pending_write.size() != 1 ||
                pending_write.front().accepted_sequence != accepted_replay_sequence || !pending_write.front().preimage_checkpoint_xid ||
                pending_write.front().mutations.size() != 1)
                return fail("EncryptedPublicationTransitionPlainReplayBoundaryMismatch");
            if (purpose == RetainedReplayPurpose::EncryptedData) {
                AcceptedDataRecovery disposition;
                if (!InspectAcceptedDataRecovery(tx, accepted_replay_sequence, disposition, error) ||
                    disposition != AcceptedDataRecovery::TypedReprepareAllowed)
                    return fail("EncryptedPublicationTransitionEncryptedReplayTypedIntentRequired");
                auto checkpoint = catalog::LoadContainerCheckpointView(source, 0, source.SizeBytes(), error);
                auto volumes = checkpoint ? catalog::LoadAppleReadOnlyVolumeView(source, *checkpoint, error) : std::nullopt;
                if (!checkpoint || checkpoint->superblock.xid != pending_write.front().preimage_checkpoint_xid ||
                    !volumes || volumes->volumes.size() != 1 ||
                    volumes->volumes.front().superblock.object_id != options_.volume_object_id ||
                    volumes->volumes.front().superblock.uuid_hex != options_.volume_uuid ||
                    volumes->volumes.front().superblock.fs_flags != catalog::kFsFlagOneKey)
                    return fail("EncryptedPublicationTransitionEncryptedReplayEndpointRequired");
            } else {
            const auto& write = pending_write.front().mutations.front();
            if (write.operation != WriteAheadLog::OperationKind::Write || write.state != WriteAheadLog::RecordState::Prepared ||
                write.flags || write.unlink_outcome || !write.object_id || !write.parent_object_id || !write.logical_length ||
                write.logical_length > 65536 || write.payload_length != write.logical_length ||
                write.logical_offset > UINT64_MAX - write.logical_length || write.path_utf8.empty() || write.path_utf8.front() != '\\' ||
                write.path_utf8.starts_with("\\$apfs-") || !write.secondary_path_utf8.empty())
                return fail("EncryptedPublicationTransitionOrdinaryPlainWriteRequired");
            auto checkpoint = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
            if (!checkpoint || checkpoint->volumes.size() != 1 ||
                checkpoint->volumes.front().superblock.object_id != options_.volume_object_id ||
                checkpoint->volumes.front().superblock.uuid_hex != options_.volume_uuid ||
                checkpoint->volumes.front().superblock.fs_flags != catalog::kFsFlagUnencrypted ||
                pending_write.front().preimage_checkpoint_xid > checkpoint->container.superblock.xid)
                return fail("EncryptedPublicationTransitionPlainReplayEndpointRequired");
            }
        }
        const auto absent = [](const std::filesystem::path& path) {
            const auto attributes = GetFileAttributesW(path.c_str());
            return attributes == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND;
        };
        // A pristine stream has no ciphertext epoch at all. Hold the same key
        // directory lease used by epoch writers while proving that namespace.
        struct EmptyKeyLease {
            HANDLE handle = INVALID_HANDLE_VALUE;
            ~EmptyKeyLease() { if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
            bool Acquire(const std::filesystem::path& directory) {
                const auto path = directory / L"writer.lease";
                handle = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                    OPEN_ALWAYS, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr);
                BY_HANDLE_FILE_INFORMATION info{}; wchar_t resolved[512]{};
                const auto expected = L"\\\\?\\" + path.wstring();
                const auto length = handle == INVALID_HANDLE_VALUE ? 0 : GetFinalPathNameByHandleW(handle, resolved, 512, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
                if (handle == INVALID_HANDLE_VALUE || GetFileType(handle) != FILE_TYPE_DISK ||
                    !GetFileInformationByHandle(handle, &info) || info.nNumberOfLinks != 1 || info.nFileSizeHigh || info.nFileSizeLow ||
                    (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ||
                    !length || length >= 512 || CompareStringOrdinal(resolved, -1, expected.c_str(), -1, TRUE) != CSTR_EQUAL) return false;
                WIN32_FIND_DATAW entry{};
                const auto search = FindFirstFileW((directory / L"*").c_str(), &entry);
                if (search == INVALID_HANDLE_VALUE) return false;
                bool valid = true; unsigned count = 0;
                do {
                    if (!wcscmp(entry.cFileName, L".") || !wcscmp(entry.cFileName, L"..")) continue;
                    if (++count != 1 || wcscmp(entry.cFileName, L"writer.lease") || entry.nFileSizeHigh || entry.nFileSizeLow ||
                        (entry.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) { valid = false; break; }
                } while (FindNextFileW(search, &entry));
                const auto status = GetLastError(); FindClose(search);
                return valid && count == 1 && status == ERROR_NO_MORE_FILES;
            }
        } original_key_lease, witness_key_lease;
        struct PristineAncestry {
            std::vector<HANDLE> handles;
            ~PristineAncestry() { for (auto handle : handles) CloseHandle(handle); }
            bool Pin(const std::filesystem::path& directory) {
                const auto text = directory.wstring();
                if (text.size() < 3 || text.size() > 380 || text[1] != L':' || text[2] != L'\\') return false;
                for (std::size_t end = 2;;) {
                    const auto prefix = text.substr(0, end == 2 ? 3 : end);
                    const auto handle = CreateFileW(prefix.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
                    if (handle == INVALID_HANDLE_VALUE) return false;
                    handles.push_back(handle);
                    FILE_ATTRIBUTE_TAG_INFO info{}; wchar_t resolved[512]{};
                    const auto length = GetFinalPathNameByHandleW(handle, resolved, 512, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
                    const auto expected = L"\\\\?\\" + prefix;
                    if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &info, sizeof(info)) ||
                        !(info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
                        !length || length >= 512 || CompareStringOrdinal(resolved, -1, expected.c_str(), -1, TRUE) != CSTR_EQUAL) return false;
                    if (end == text.size()) return true;
                    end = text.find(L'\\', end + 1); if (end == text.npos) end = text.size();
                }
            }
        };
        if (!marks.accepted_sequence && !tx.continuation_seed_ && tx.next_sequence_ == 1 && tx.next_transaction_id_ == 1 &&
            tx.ProtectedSpoolOwnerValid() && absent(tx.journal_path_) && absent(options_.witness.path)) {
            auto ancestry = std::make_shared<PristineAncestry>();
            if (!ancestry->Pin(std::filesystem::path(tx.journal_path_).parent_path()) || !ancestry->Pin(options_.witness.path.parent_path()) ||
                !ancestry->Pin(tx.journal_protection_->key_directory) || !ancestry->Pin(options_.witness.protected_persistence->key_directory))
                return fail("EncryptedPublicationTransitionPristineAncestryUnproved");
            auto original_empty = tx.journal_.ReadAllWithExclusiveWriterLease(); Wipe original_empty_wipe{original_empty.records};
            auto witness_empty = witness_.ReadAllWithExclusiveWriterLease(); Wipe witness_empty_wipe{witness_empty.records};
            if (original_empty.status != WriteAheadLog::ReadStatus::Ok || original_empty.recovered_torn_tail || !original_empty.records.empty() ||
                witness_empty.status != WriteAheadLog::ReadStatus::Ok || witness_empty.recovered_torn_tail || !witness_empty.records.empty() ||
                !tx.journal_.HasExclusiveWriterLease() || !witness_.HasExclusiveWriterLease() ||
                !original_key_lease.Acquire(tx.journal_protection_->key_directory) ||
                !witness_key_lease.Acquire(options_.witness.protected_persistence->key_directory) ||
                !tx.journal_.ProtectedMaintenanceAbsent() || !witness_.ProtectedMaintenanceAbsent() ||
                !absent(tx.journal_path_) || !absent(options_.witness.path) || !tx.ProtectedSpoolOwnerValid())
                return fail("EncryptedPublicationTransitionPristineHistoryUnproved");
            transition_pristine_ancestry_ = std::move(ancestry);
            return true;
        }
        WriteAheadLog::ProtectedHistoryHead original_head, witness_head;
        std::vector<WriteAheadLog::Record> original; Wipe original_wipe{original};
        if (!tx.ReadProtectedOriginalHistory(original_head, original, error) || !witness_.CaptureProtectedHistoryHead(witness_head))
            return fail("EncryptedPublicationTransitionOriginalHistoryUnavailable");
        std::map<std::uint64_t, std::vector<WriteAheadLog::Record>> pending;
        std::map<std::uint64_t, TransactionManager::AcceptedTransaction> accepted;
        struct CleanAccepted {
            decltype(pending)& pending_rows; decltype(accepted)& accepted_rows;
            ~CleanAccepted() {
                for (auto& [id, rows] : pending_rows) { (void)id; Wipe wipe{rows}; }
                for (auto& [sequence, row] : accepted_rows) { (void)sequence; Wipe wipe{row.mutations}; }
            }
        } clear{pending, accepted};
        std::set<std::uint64_t> original_transition_transactions;
        for (const auto& row : original) {
            if (row.path_utf8.starts_with("\\$apfs-software-transition-") ||
                row.path_utf8.starts_with("\\$apfs-software-key-rotation-")) original_transition_transactions.insert(row.transaction_id);
            if (row.operation == WriteAheadLog::OperationKind::DurabilityWatermark) continue;
            if (row.operation != WriteAheadLog::OperationKind::TransactionMarker) { pending[row.transaction_id].push_back(row); continue; }
            const auto found = pending.find(row.transaction_id);
            if (row.state == WriteAheadLog::RecordState::Accepted && row.flags == 8) {
                if (found == pending.end() || found->second.size() != row.logical_length || !row.object_id || !row.transaction_id)
                    return fail("EncryptedPublicationTransitionOriginalBoundaryInvalid");
                TransactionManager::AcceptedTransaction group;
                group.transaction_id = row.transaction_id; group.accepted_sequence = row.sequence;
                group.preimage_checkpoint_xid = row.object_id; group.mutations = std::move(found->second);
                if (!accepted.emplace(group.accepted_sequence, std::move(group)).second)
                    return fail("EncryptedPublicationTransitionOriginalBoundaryDuplicate");
            } else if (row.state != WriteAheadLog::RecordState::Cleaned || row.flags != 2) {
                return fail("EncryptedPublicationTransitionOriginalTerminalUnsupported");
            }
            if (found != pending.end()) { { Wipe wipe{found->second}; } pending.erase(found); }
        }
        if (!pending.empty()) return fail("EncryptedPublicationTransitionOriginalIncomplete");
        auto records = witness_.ReadAllWithExclusiveWriterLease({64ull << 20, 4096}); Wipe wipe{records.records};
        std::vector<WitnessGroup> groups;
        if (records.status != WriteAheadLog::ReadStatus::Ok || !ReadGroups(records.records, groups, error))
            return fail("EncryptedPublicationTransitionAuthorizationMissing");
        std::vector<std::uint64_t> spent;
        if (!ValidateUnacceptedDispositions(tx, spent, error)) return false;
        std::optional<Witness> selected;
        for (const auto& group : groups) {
            auto body = Decode(group.bytes, options_, false, OriginalJournalBinding::Historical);
            if (body.accepted != group.accepted || body.transaction != group.transaction || body.inode != group.inode)
                return fail("EncryptedPublicationTransitionAuthorizationBoundaryMismatch");
            if (!IsRetainedRewrite(body.version)) continue;
            if (std::find(spent.begin(), spent.end(), body.accepted) != spent.end()) {
                original_transition_transactions.erase(body.transaction); continue;
            }
            const auto actual = accepted.find(body.accepted);
            TransactionManager::AcceptedTransaction certified; Wipe certified_wipe{certified.mutations}; bool found = false;
            if (actual == accepted.end() && !ReadCertifiedTransitionOriginal(tx, body.accepted, group.bytes, certified, found, error)) return false;
            if ((actual == accepted.end() && !found) || body.accepted > marks.cleanup_sequence ||
                body.original_journal != options_.maintenance_original_journal_identity ||
                !MatchTransitionOriginal(actual != accepted.end() ? actual->second : certified, body, options_, error))
                return fail("EncryptedPublicationTransitionAcceptedOwnerHistoryMissing");
            original_transition_transactions.erase(body.transaction);
            selected = std::move(body);
        }
        if (!original_transition_transactions.empty()) return fail("EncryptedPublicationTransitionRetainedAuthorizationMissing");
        if (tx.continuation_seed_) {
            ProtectedJournalContinuation::RecoveryEvidence carried;
            Wipe carried_original{carried.original.records}, carried_witness{carried.witness.records};
            if (!ProtectedJournalContinuation::CaptureEvidence(tx, witness_, carried, error) ||
                carried.original_head != original_head || carried.witness_head != witness_head)
                return fail("EncryptedPublicationTransitionCertifiedHistoryChanged");
            for (const auto& prior : carried.certificate_authority.retained_authorizations) {
                if (!IsRetainedRewrite(prior.version)) continue;
                const auto found = std::find_if(groups.begin(), groups.end(),
                    [&](const auto& group) { return group.accepted == prior.accepted && group.transaction == prior.transaction; });
                Digest digest{};
                if (found == groups.end() || !Hash(found->bytes, digest) || digest != prior.body_sha256 ||
                    prior.spent != std::binary_search(spent.begin(), spent.end(), prior.accepted))
                    return fail("EncryptedPublicationTransitionCertifiedAuthorizationMissing");
            }
        }
        if (!selected) {
            if (accepted_replay_sequence && purpose != RetainedReplayPurpose::EncryptedData)
                return fail("EncryptedPublicationTransitionRetainedAuthorizationMissing");
            WriteAheadLog::ProtectedHistoryHead original_after, witness_after;
            std::vector<WriteAheadLog::Record> rechecked; Wipe rechecked_wipe{rechecked};
            if (!tx.ReadProtectedOriginalHistory(original_after, rechecked, error) || original_head != original_after ||
                !witness_.CaptureProtectedHistoryHead(witness_after) || witness_after != witness_head)
                return fail("EncryptedPublicationTransitionRestoreHistoryChanged");
            return true;
        }
        if (selected->source != source.SourceIdentity()) return fail("EncryptedPublicationTransitionRetainedAuthorizationMissing");
        TransitionOwnersDecoded decoded; DecodeTransitionOwners(selected->transition_owners, decoded);
        if (decoded.binding != options_.witness.protected_persistence->source_binding || decoded.journal != options_.maintenance_original_journal_identity)
            return fail("EncryptedPublicationTransitionRetainedScopeMismatch");
        auto result = std::unique_ptr<catalog::SoftwareVolumeRetainedOwners>(new catalog::SoftwareVolumeRetainedOwners);
        result->identity_ = std::move(decoded.source); result->container_uuid_ = std::move(decoded.container); result->volume_uuid_ = std::move(decoded.volume);
        result->volume_oid_ = decoded.oid; result->minted_xid_ = decoded.minted; result->block_count_ = decoded.blocks;
        result->binding_ = decoded.binding; result->journal_identity_ = decoded.journal; result->allocator_sha256_ = decoded.allocator;
        result->generations_ = std::move(decoded.generations);
        // Internal replay needs the already matched private acceptance. The
        // candidate remains local until raw owners and both heads revalidate.
        result->restored_accepted_sequence_ = selected->accepted;
        std::transform(selected->replacement.begin(), selected->replacement.end(), result->restored_plan_sha256_.begin(),
            [](auto byte) { return static_cast<std::byte>(byte); });
        std::vector<catalog::SoftwareVolumeOwnedRange> exclusions;
        std::unique_ptr<SoftwareTransitionControlReplaySource> replay;
        if (accepted_replay_sequence && purpose != RetainedReplayPurpose::EncryptedData &&
            !SoftwareTransitionControlReplaySource::Capture(tx, source, *result, replay, error)) return false;
        if (!result->Revalidate(replay ? *replay : source, options_.maintenance_original_journal_identity, exclusions, error)) return false;
        WriteAheadLog::ProtectedHistoryHead original_after, witness_after;
        std::vector<WriteAheadLog::Record> rechecked; Wipe rechecked_wipe{rechecked};
        if (!tx.ReadProtectedOriginalHistory(original_after, rechecked, error) || original_head != original_after ||
            !witness_.CaptureProtectedHistoryHead(witness_after) || witness_after != witness_head)
            return fail("EncryptedPublicationTransitionRestoreHistoryChanged");
        restored = std::move(result); return true;
    } catch (...) { return fail("EncryptedPublicationTransitionRestoreInvalid"); }
}
std::unique_ptr<const catalog::SoftwareVolumeRetainedOwners> EncryptedPublicationJournal::RestoreTransitionRetainedOwners(
    TransactionManager& tx, const catalog::ImmutableEncryptedReadSource& source, std::string& error)
{
    std::unique_ptr<const catalog::SoftwareVolumeRetainedOwners> result;
    if (!TryRestoreTransitionRetainedOwners(tx, source, result, error)) return {};
    if (!result) error = "EncryptedPublicationTransitionRetainedAuthorizationMissing";
    return result;
}
std::unique_ptr<const catalog::SoftwareVolumeRetainedOwners> EncryptedPublicationJournal::RestoreTransitionRetainedOwnersForPlainReplay(
    TransactionManager& tx, const catalog::ImmutableEncryptedReadSource& source, std::uint64_t accepted, std::string& error)
{
    std::unique_ptr<const catalog::SoftwareVolumeRetainedOwners> result;
    if (!accepted) { error = "EncryptedPublicationTransitionPlainReplayBoundaryMismatch"; return {}; }
    if (!TryRestoreTransitionRetainedOwnersImpl(tx, source, result, error, accepted)) return {};
    return result;
}
std::unique_ptr<const catalog::SoftwareVolumeRetainedOwners> EncryptedPublicationJournal::RestoreTransitionRetainedOwnersForEncryptedReplay(
    TransactionManager& tx, const catalog::ImmutableEncryptedReadSource& source, std::uint64_t accepted, std::string& error)
{
    std::unique_ptr<const catalog::SoftwareVolumeRetainedOwners> result;
    if (!TryRestoreTransitionRetainedOwnersForEncryptedReplay(tx, source, accepted, result, error)) return {};
    if (!result) error = "EncryptedPublicationTransitionRetainedAuthorizationMissing";
    return result;
}
bool EncryptedPublicationJournal::TryRestoreTransitionRetainedOwnersForEncryptedReplay(TransactionManager& tx,
    const catalog::ImmutableEncryptedReadSource& source, std::uint64_t accepted,
    std::unique_ptr<const catalog::SoftwareVolumeRetainedOwners>& result, std::string& error)
{
    result.reset();
    if (!accepted) return Fail(error, "EncryptedPublicationTransitionEncryptedReplayBoundaryMismatch");
    return TryRestoreTransitionRetainedOwnersImpl(tx, source, result, error, accepted, RetainedReplayPurpose::EncryptedData);
}
