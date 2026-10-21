#include "BackupPhysicalWriteOwner.h"
#include "BackupMutationContract.h"
#include "VolumePhysicalMetadataOwner.h"
#include "VolumeFormatEvidence.h"
#include <algorithm>

namespace apfsaccess::rw
{
namespace
{
constexpr std::uint64_t MaxFile = 8ull << 20;
constexpr std::uint64_t MaxWrite = 256ull << 10;
std::wstring CanonicalBackupJournal(std::string_view container, std::uint64_t oid)
{ return L"apfs-vol:" + std::wstring(container.begin(), container.end()) + L":" + std::to_wstring(oid); }
}
BackupPhysicalWriteOwner::BackupPhysicalWriteOwner(std::shared_ptr<VolumePhysicalSource> held,
    TransactionManager& original, PayloadSpool& spool, std::filesystem::path path)
    : held_(std::move(held)), original_(original), spool_(spool), original_path_(std::move(path)) {}

std::unique_ptr<BackupPhysicalWriteOwner> BackupPhysicalWriteOwner::Bind(
    const std::shared_ptr<VolumePhysicalSource>& held, const RawSnapshotBinding& binding,
    std::wstring_view instance, const Selection& selected, TransactionManager& original,
    PayloadSpool& spool, const std::filesystem::path& path, std::string& error)
try
{
    error.clear();
    const auto device = VolumePhysicalSource::RetainMetadataDevice(held, binding, instance, error);
    if (!device || !path.is_absolute()) return {};
    const auto cp = catalog::LoadAppleCheckpointView(*held, 0, held->SizeBytes(), error);
    if (!cp || cp->volumes.size() != 1 || cp->container.superblock.uuid_hex != selected.container_uuid ||
        cp->container.superblock.xid != selected.checkpoint_xid ||
        cp->volumes.front().superblock.uuid_hex != selected.volume_uuid ||
        cp->volumes.front().superblock.object_id != selected.volume_oid ||
        original.EnrolledCanonicalJournalIdentity() != CanonicalBackupJournal(selected.container_uuid, selected.volume_oid))
    { error = "BackupPhysicalOwnerSelectionMismatch"; return {}; }
    auto owner = std::unique_ptr<BackupPhysicalWriteOwner>(new BackupPhysicalWriteOwner(held, original, spool, path));
    owner->source_ = BackupRetainedSource::HeldPhysical(held, binding, instance, *cp, selected.volume_oid, error);
    if (!owner->source_) return {};
    owner->context_.device_path = device->Path(); owner->context_.device_offset_bytes = binding.media.base_offset_bytes;
    owner->context_.volume_object_id = selected.volume_oid; owner->context_.allow_native_snapshot_runtime = true;
    owner->context_.allow_raw_device_canonical_commit = true; owner->context_.allow_legacy_scaffold_for_fixtures = false;
    if (!owner->Available(error) || !owner->Reload(error)) return {};
    TransactionManager::RetainedAcceptedHistory history;
    if (!original.LoadRetainedAcceptedHistory(history, error, {16ull << 20, 4096}) ||
        history.coverage == TransactionManager::RetainedHistoryCoverage::Unavailable ||
        (!history.cleaned.empty() && history.cleaned.back().preimage_checkpoint_xid >= selected.checkpoint_xid))
    { if (error.empty()) error = "BackupPhysicalOriginalHistoryUnavailable"; return {}; }
    return owner;
}
catch (...) { error = "BackupPhysicalOwnerAdmissionFailed"; return {}; }

bool BackupPhysicalWriteOwner::Available(std::string& error) const
{
    if (failed_ || !held_ || !source_ || !source_->Current() ||
        original_.CurrentState() != TransactionManager::State::Idle || !original_.RecoveryStateValid() ||
        !source_->JournalSourceBinding() || original_.ProtectedSourceBinding() != source_->JournalSourceBinding() ||
        !original_.ProtectedJournalIdentity() ||
        TransactionManager::WideToUtf8(original_.ConfiguredVolumeIdentity()) != source_->RecoveryIdentity() ||
        !original_.OwnsJournalForMaintenance(original_path_.wstring(), original_.ConfiguredVolumeIdentity()) ||
        !original_.ObservedJournalWriterLeaseGeneration() ||
        original_.ObservedJournalWriterLeaseGeneration() != original_.ObservedJournalAppendLeaseGeneration())
    { error = "BackupPhysicalOriginalOwnerUnavailable"; return false; }
    return true;
}
bool BackupPhysicalWriteOwner::Reload(std::string& error)
{
    auto fresh = CreateVolumePhysicalMetadataStore(held_, held_->Binding(), held_->InstanceId(), context_, error);
    if (!fresh || !fresh->PrepareBackupRetainedWritePath(*source_, error)) return false;
    store_ = std::move(fresh); return true;
}
bool BackupPhysicalWriteOwner::Fail(std::string& error, const char* reason)
{
    failed_ = true;
    if (error.empty()) error = reason;
    return false;
}
bool BackupPhysicalWriteOwner::RebuildSpool(const TransactionManager::RetainedAcceptedHistory& history, std::string& error)
{
    std::vector<PayloadSpool::PersistedRangeReference> live, discarded;
    const auto collect = [&](const auto& batches, auto& ranges) {
        for (const auto& batch : batches) for (const auto& r : batch.mutations) {
            MetadataStore::MutationRequest request;
            if (r.volume_identity != source_->RecoveryIdentity() ||
                !DecodeBackupAcceptedMutation(r, request, error)) return false;
            if (request.operation != MetadataStore::MutationOperation::Write) continue;
            if (ranges.size() >= 4096) return false;
            ranges.push_back({r.volume_identity, r.object_id, r.parent_object_id, r.logical_offset,
                r.payload_length, r.payload_offset, r.payload_spool_id, r.payload_sha256});
        }
        return true;
    };
    if (!collect(history.pending, live) || !collect(history.cleaned, discarded) ||
        !spool_.RebuildIndexFromReferences(live, history.watermarks.cleanup_sequence, discarded))
    { error = "BackupPhysicalOriginalSpoolUnavailable"; return false; }
    return true;
}
bool BackupPhysicalWriteOwner::Recover(std::string& error, const AppleCheckpointStageHook& hook)
{
    std::lock_guard lock(gate_);
    try { return RecoverLocked(error, hook); }
    catch (...) { return Fail(error, "BackupPhysicalRecoveryFailed"); }
}
bool BackupPhysicalWriteOwner::RecoverWithVerification(std::string& error, const PostpublicationVerifier& verify,
    const AppleCheckpointStageHook& hook)
{
    std::lock_guard lock(gate_);
    try { return RecoverLocked(error, hook, verify); }
    catch (...) { return Fail(error, "BackupPhysicalRecoveryVerificationFailed"); }
}
std::unique_ptr<MetadataStore> BackupPhysicalWriteOwner::TakeVerifiedStore(std::string& error)
{
    std::lock_guard lock(gate_);
    if (!Available(error) || !store_ || store_->PendingMutationCount() || !original_.CanClearRecoveryState() ||
        original_.Watermarks().accepted_sequence != original_.Watermarks().cleanup_sequence)
    { if (error.empty()) error = "BackupPhysicalStoreHandoffRefused"; return {}; }
    failed_ = true;
    return std::move(store_);
}
bool BackupPhysicalWriteOwner::RecoverLocked(std::string& error, const AppleCheckpointStageHook& hook,
    const PostpublicationVerifier& verify, bool cleanup)
{
    error.clear();
    if (!Available(error)) return Fail(error, "BackupPhysicalOwnerUnavailable");
    TransactionManager::RetainedAcceptedHistory history;
    if (!original_.LoadRetainedAcceptedHistory(history, error, {16ull << 20, 4096}) ||
        history.coverage == TransactionManager::RetainedHistoryCoverage::Unavailable ||
        history.pending.size() > 1) return Fail(error, "BackupPhysicalOriginalHistoryUnavailable");
    const bool no_accepted = history.coverage == TransactionManager::RetainedHistoryCoverage::NoAcceptedHistory &&
        history.pending.empty() && history.cleaned.empty() && !history.watermarks.accepted_sequence &&
        !history.watermarks.apfs_durable_sequence && !history.watermarks.cleanup_sequence;
    if ((!no_accepted && !original_.FlushRetainedOriginalEvidenceDurability()) || !RebuildSpool(history, error))
        return Fail(error, "BackupPhysicalOriginalBarrierFailed");
    if (!history.pending.empty()) {
        const auto& batch = history.pending.front();
        if (batch.mutations.empty() || batch.mutations.size() > 64) return Fail(error, "BackupPhysicalBatchLimit");
        if (store_->CheckpointXid().value_or(0) == batch.preimage_checkpoint_xid) {
            AppleCheckpointPublicationPlan plan;
            if (!store_->PlanBackupRetainedAcceptedMutations(*source_, original_, spool_, plan, error) ||
                !ExecuteAppleCheckpointPublication(*held_, plan, error, [&](auto stage) {
                    return source_->Current() && (!hook || hook(stage)); }) || !Reload(error))
                return Fail(error, "BackupPhysicalOriginalPublicationFailed");
        }
        std::vector<std::uint64_t> proven;
        if (!store_->ProveBackupRetainedAcceptedPrefix(original_, spool_, original_path_, source_->RecoveryIdentity(),
            *source_, proven, error) || proven != std::vector<std::uint64_t>{batch.accepted_sequence} ||
            !store_->FlushBackupRetainedRecoveryEvidence(*source_) ||
            (verify && !verify(*store_, error)) ||
            !original_.MarkApfsDurableThrough(batch.accepted_sequence) ||
            (cleanup && !original_.MarkCleanedThrough(batch.accepted_sequence)) ||
            !original_.FlushRetainedOriginalEvidenceDurability()) return Fail(error, "BackupPhysicalOriginalPostimageUnproven");
    } else if (history.watermarks.accepted_sequence != history.watermarks.apfs_durable_sequence ||
        history.watermarks.accepted_sequence != history.watermarks.cleanup_sequence ||
        !store_->FlushBackupRetainedRecoveryEvidence(*source_)) return Fail(error, "BackupPhysicalCleanedSourceUnproven");
    if ((cleanup && !spool_.CleanupThroughSequence(original_.Watermarks().cleanup_sequence)) || !source_->Current())
        return Fail(error, "BackupPhysicalOriginalCleanupFailed");
    return true;
}

std::unique_ptr<MetadataStore> BackupPhysicalWriteOwner::PublishAcceptedForHost(std::string& error,
    const PostpublicationVerifier& verify, const AppleCheckpointStageHook& hook)
{
    std::lock_guard lock(gate_);
    try {
        if (original_.Watermarks().accepted_sequence <= original_.Watermarks().cleanup_sequence ||
            !RecoverLocked(error, hook, verify, false) ||
            original_.Watermarks().accepted_sequence != original_.Watermarks().apfs_durable_sequence)
        { Fail(error, "BackupPhysicalHostPublicationUnproven"); return {}; }
        failed_ = true;
        return std::move(store_);
    } catch (...) { Fail(error, "BackupPhysicalHostPublicationFailed"); return {}; }
}

BackupPhysicalWriteOwner::WriteResult BackupPhysicalWriteOwner::Write(const std::wstring& path,
    std::uint64_t offset, std::span<const std::byte> bytes, std::string& error, const AppleCheckpointStageHook& hook)
{
    MetadataStore::MutationRequest request;
    request.path = path; request.offset = offset; request.length = bytes.size();
    return Apply(request, bytes, error, hook);
}

BackupPhysicalWriteOwner::WriteResult BackupPhysicalWriteOwner::Apply(const MetadataStore::MutationRequest& input,
    std::span<const std::byte> bytes, std::string& error, const AppleCheckpointStageHook& hook)
{
    std::lock_guard lock(gate_);
    try {
        if (!RecoverLocked(error, {})) return WriteResult::RecoveryRequired;
        using Op = MetadataStore::MutationOperation;
        const auto kind = BackupMutationJournalKind(input.operation);
        const bool writing = input.operation == Op::Write;
        const bool names = input.operation == Op::Rename || input.operation == Op::CloneFile ||
            input.operation == Op::SetExtendedAttribute || input.operation == Op::RemoveExtendedAttribute;
        const bool inline_metadata = input.operation == Op::SetExtendedAttribute || input.operation == Op::SetInodeMetadata;
        const bool sized = writing || inline_metadata || input.operation == Op::SetFileSize || input.operation == Op::SetAllocationSize;
        if (!kind || input.object_id || input.generation || input.expected_unlink_outcome ||
            input.deferred_payload_bound || !input.deferred_payload.empty() ||
            (!names && !input.secondary_path.empty()) || (!writing && input.offset) ||
            (!sized && input.length) || (input.replace_if_exists && input.operation != Op::Rename) ||
            (!inline_metadata && !input.inline_payload.empty()) ||
            (inline_metadata && input.length != input.inline_payload.size()) ||
            (input.operation != Op::SetBasicInfo && input.timestamp_utc) ||
            (writing ? (bytes.empty() || bytes.size() > MaxWrite || input.length != bytes.size() ||
                input.offset > MaxFile - bytes.size() || !input.inline_payload.empty() ||
                spool_.CheckAppendCapacity(bytes.size()) != PayloadSpool::AppendStatus::Succeeded) : !bytes.empty()))
        { error = "BackupPhysicalMutationBoundsOrAuthority"; return WriteResult::Refused; }
        auto candidate = CreateVolumePhysicalMetadataStore(held_, held_->Binding(), held_->InstanceId(), context_, error);
        if (!candidate || !candidate->PrepareBackupRetainedWritePath(*source_, error)) return WriteResult::Refused;
        auto request = input;
        if (input.operation == Op::CloneFile) {
            if (input.offset || input.length || input.replace_if_exists || !input.inline_payload.empty() ||
                !candidate->PrepareBackupRetainedClone(*source_, input.secondary_path, input.path, request, error))
                return WriteResult::Refused;
        }
        const auto inode = candidate->LookupCommittedInodeByPath(request.path);
        auto expected = std::make_shared<std::vector<std::byte>>();
        if (inode && inode->node_type == MetadataStore::NodeType::RegularFile) {
            if ((inode->bsd_flags & 0x20u) || inode->logical_size > MaxFile || (inode->logical_size &&
                !candidate->ReadCommittedFileRange(request.path, 0, static_cast<std::size_t>(inode->logical_size), *expected)))
            { error = "BackupPhysicalMutationFileUnsupported"; return WriteResult::Refused; }
        }
        MetadataStore::PayloadIdentity identity;
        std::optional<UnlinkOutcome> unlink;
        if (candidate->StageBackupRetainedTypedMutation(*source_, request, &identity, &unlink) != MetadataStore::MutationStatus::Applied)
        { error = "BackupPhysicalMutationStageRefused"; return WriteResult::Refused; }
        if (writing || input.operation == Op::SetFileSize || input.operation == Op::SetAllocationSize) {
            const auto changed = candidate->LookupWorkingInodeByPath(request.path);
            if (!changed || changed->logical_size > MaxFile) { error = "BackupPhysicalMutationSizeUnsupported"; return WriteResult::Refused; }
            expected->resize(static_cast<std::size_t>(changed->logical_size), std::byte{});
            if (writing) {
                if (request.offset > expected->size() || bytes.size() > expected->size() - request.offset)
                { error = "BackupPhysicalMutationRangeInvalid"; return WriteResult::Refused; }
                std::copy(bytes.begin(), bytes.end(), expected->begin() + request.offset);
            }
        }
        candidate->SetFilePayloadRangeProvider([expected, identity](const auto&, auto actual, auto at, std::span<std::byte> out) {
            if (actual.object_id != identity.object_id || actual.generation != identity.generation ||
                at > expected->size() || out.size() > expected->size() - at) return false;
            std::copy_n(expected->begin() + at, out.size(), out.begin()); return true;
        });
        const auto preimage = candidate->CheckpointXid().value_or(0);
        AppleCheckpointPublicationPlan plan;
        if (!candidate->PlanBackupRetainedTypedPendingMutations(*source_, {preimage}, plan, error)) return WriteResult::Refused;
        TransactionManager::MutationIntent intent;
        intent.kind = *kind; intent.path = request.path; intent.secondary_path = request.secondary_path;
        intent.object_id = identity.object_id; intent.generation = identity.generation;
        intent.offset = request.offset; intent.length = request.length;
        intent.replace_if_exists = request.replace_if_exists; intent.timestamp_utc = request.timestamp_utc;
        intent.unlink_outcome = unlink;
        if (writing) intent.wal_sequence = original_.NextMutationSequence();
        if (writing || inline_metadata || input.operation == Op::CloneFile) {
            const auto payload = writing ? bytes : std::span<const std::byte>(request.inline_payload);
            intent.payload_length = payload.size();
            const auto digest = format_evidence::Hash(payload);
            for (std::size_t i = 0; i < digest.size(); ++i) intent.payload_checksum[i] = std::to_integer<std::uint8_t>(digest[i]);
            if (!writing || bytes.size() <= 4096) intent.inline_payload.assign(payload.begin(), payload.end());
        }
        if (input.operation == Op::SetExtendedAttribute || input.operation == Op::RemoveExtendedAttribute) intent.length = 0;
        if (!original_.ProtectedBackupMutationCapacityAvailable(intent, error)) return WriteResult::Refused;
        if (!original_.Begin()) { Fail(error, "BackupPhysicalOriginalBeginFailed"); return WriteResult::RecoveryRequired; }
        if (writing) {
            PayloadSpool::AppendResult appended;
            if (!spool_.Append({source_->RecoveryIdentity(), identity.object_id, identity.generation, request.offset, intent.wal_sequence, bytes}, &appended) ||
                appended.payload_sha256 != intent.payload_checksum || !spool_.FlushDirtyState())
            { Fail(error, "BackupPhysicalOriginalSpoolFailed"); return WriteResult::RecoveryRequired; }
            intent.payload_spool_offset = appended.spool_offset;
        }
        if (!original_.RecordMutation(intent) || !original_.Accept(preimage) ||
            !original_.FlushAcceptedEvidenceDurability(original_.Watermarks().accepted_sequence))
        { Fail(error, "BackupPhysicalOriginalAcceptanceFailed"); return WriteResult::RecoveryRequired; }
        store_ = std::move(candidate);
        if (!ExecuteAppleCheckpointPublication(*held_, plan, error, [&](auto stage) {
            return source_->Current() && (!hook || hook(stage)); }) || !Reload(error) || !RecoverLocked(error, {}))
        { Fail(error, "BackupPhysicalWritePublicationFailed"); return WriteResult::RecoveryRequired; }
        return WriteResult::Committed;
    } catch (...) { Fail(error, "BackupPhysicalWriteFailed"); return WriteResult::RecoveryRequired; }
}
bool BackupPhysicalWriteOwner::Read(const std::wstring& path, std::uint64_t at, std::size_t count, std::vector<std::byte>& bytes)
{
    std::lock_guard lock(gate_); std::string error; bytes.clear();
    if (count > MaxFile || !Available(error) || original_.Watermarks().accepted_sequence != original_.Watermarks().cleanup_sequence ||
        !store_->ReadCommittedFileRange(path, at, count, bytes) || !source_->Current()) { bytes.clear(); return false; }
    return true;
}
std::optional<MetadataStore::InodeRecord> BackupPhysicalWriteOwner::Metadata(const std::wstring& path)
{
    std::lock_guard lock(gate_); std::string error;
    if (!Available(error) || original_.Watermarks().accepted_sequence != original_.Watermarks().cleanup_sequence) return {};
    const auto value = store_->LookupCommittedInodeByPath(path); return source_->Current() ? value : std::nullopt;
}
bool BackupPhysicalWriteOwner::RecoveryRequired() const
{ std::lock_guard lock(gate_); std::string error; return !Available(error) || !original_.CanClearRecoveryState(); }
std::uint64_t BackupPhysicalWriteOwner::CheckpointXid() const
{ std::lock_guard lock(gate_); return store_ ? store_->CheckpointXid().value_or(0) : 0; }
}
