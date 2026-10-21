#include "TransactionManager.h"
#include "FusionOriginalContinuation.h"
#include "NativeClone.h"
#include "NativeHardLink.h"
#include "NativeSparse.h"
#include "NativeSparseV2.h"
#include "NativeCloneRange.h"
#include "NativeVolumeRename.h"
#include "NativeSnapshotIntent.h"
#include "NativeCountRepair.h"

#include "WriteAheadLog.h"
#include "InodeMetadataPatch.h"
#include "ProtectedJournalEpoch.h"

#include <algorithm>
#include <chrono>
#include <cwchar>
#include <cstring>
#include <filesystem>
#include <limits>
#include <unordered_map>
#include <unordered_set>
#include <thread>
#include <utility>
#include <windows.h>
#ifdef CreateFile
#undef CreateFile
#endif
#ifdef CreateDirectory
#undef CreateDirectory
#endif

namespace apfsaccess::rw
{
namespace
{
constexpr std::uint64_t kWalFlagCommitted = 0x1;
constexpr std::uint64_t kWalFlagAborted = 0x2;
constexpr std::uint64_t kWalFlagReplaceIfExists = 0x4;
constexpr std::uint64_t kWalFlagAccepted = 0x8;
constexpr auto kDeferredWalGroupCommitWindow = std::chrono::milliseconds(8);
std::uint64_t ElapsedMicroseconds(const std::chrono::steady_clock::time_point& started)
{
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - started).count());
}

std::string EffectiveVolumeIdentity(const std::wstring& volume_identity)
{
    auto identity = volume_identity.empty()
        ? std::string("default")
        : TransactionManager::WideToUtf8(volume_identity);
    return identity.empty() ? std::string("default") : identity;
}

WriteAheadLog::OperationKind ToWalOperation(TransactionManager::MutationKind kind)
{
    switch (kind)
    {
    case TransactionManager::MutationKind::CreateFile:
        return WriteAheadLog::OperationKind::CreateFile;
    case TransactionManager::MutationKind::CreateDirectory:
        return WriteAheadLog::OperationKind::CreateDirectory;
    case TransactionManager::MutationKind::Write:
        return WriteAheadLog::OperationKind::Write;
    case TransactionManager::MutationKind::SetFileSize:
        return WriteAheadLog::OperationKind::SetFileSize;
    case TransactionManager::MutationKind::Rename:
        return WriteAheadLog::OperationKind::Rename;
    case TransactionManager::MutationKind::Delete:
        return WriteAheadLog::OperationKind::Delete;
    case TransactionManager::MutationKind::SetBasicInfo:
        return WriteAheadLog::OperationKind::SetBasicInfo;
    case TransactionManager::MutationKind::SetSymbolicLinkTarget:
        return WriteAheadLog::OperationKind::SetSymbolicLinkTarget;
    case TransactionManager::MutationKind::RemoveSymbolicLinkTarget:
        return WriteAheadLog::OperationKind::RemoveSymbolicLinkTarget;
    case TransactionManager::MutationKind::SetExtendedAttribute:
        return WriteAheadLog::OperationKind::SetExtendedAttribute;
    case TransactionManager::MutationKind::RemoveExtendedAttribute:
        return WriteAheadLog::OperationKind::RemoveExtendedAttribute;
    case TransactionManager::MutationKind::SetInodeMetadata:
        return WriteAheadLog::OperationKind::SetInodeMetadata;
    case TransactionManager::MutationKind::SetAllocationSize:
        return WriteAheadLog::OperationKind::SetAllocationSize;
    case TransactionManager::MutationKind::RestoreDirectoryFromSymbolicLink:
        return WriteAheadLog::OperationKind::RestoreDirectoryFromSymbolicLink;
    case TransactionManager::MutationKind::CloneFile:
        return WriteAheadLog::OperationKind::CloneFile;
    case TransactionManager::MutationKind::HardLink:
        return WriteAheadLog::OperationKind::HardLink;
    case TransactionManager::MutationKind::NativeSparse:
        return WriteAheadLog::OperationKind::NativeSparse;
    case TransactionManager::MutationKind::CloneRange:
        return WriteAheadLog::OperationKind::CloneRange;
    case TransactionManager::MutationKind::CreateSnapshot: return WriteAheadLog::OperationKind::CreateSnapshot;
    case TransactionManager::MutationKind::DeleteSnapshot: return WriteAheadLog::OperationKind::DeleteSnapshot;
    case TransactionManager::MutationKind::SetVolumeQuotaReserve:
        return WriteAheadLog::OperationKind::SetVolumeQuotaReserve;
    case TransactionManager::MutationKind::RenameVolume:
        return WriteAheadLog::OperationKind::RenameVolume;
    case TransactionManager::MutationKind::RepairVolumeFileCount:
        return WriteAheadLog::OperationKind::RepairVolumeFileCount;
    case TransactionManager::MutationKind::RewriteCompressedContent:
        return WriteAheadLog::OperationKind::RewriteCompressedContent;
    default:
        return WriteAheadLog::OperationKind::TransactionMarker;
    }
}

bool IsTransactionMarkerWithState(
    const WriteAheadLog::Record& record,
    WriteAheadLog::RecordState state,
    std::uint64_t flags)
{
    return record.state == state && record.flags == flags;
}

bool IsMutationOperation(WriteAheadLog::OperationKind operation)
{
    switch (operation)
    {
    case WriteAheadLog::OperationKind::CreateFile:
    case WriteAheadLog::OperationKind::CreateDirectory:
    case WriteAheadLog::OperationKind::Write:
    case WriteAheadLog::OperationKind::SetFileSize:
    case WriteAheadLog::OperationKind::Rename:
    case WriteAheadLog::OperationKind::Delete:
    case WriteAheadLog::OperationKind::SetBasicInfo:
    case WriteAheadLog::OperationKind::SetSymbolicLinkTarget:
    case WriteAheadLog::OperationKind::RemoveSymbolicLinkTarget:
    case WriteAheadLog::OperationKind::SetExtendedAttribute:
    case WriteAheadLog::OperationKind::RemoveExtendedAttribute:
    case WriteAheadLog::OperationKind::SetInodeMetadata:
    case WriteAheadLog::OperationKind::SetAllocationSize:
    case WriteAheadLog::OperationKind::RestoreDirectoryFromSymbolicLink:
    case WriteAheadLog::OperationKind::CloneFile:
    case WriteAheadLog::OperationKind::HardLink:
    case WriteAheadLog::OperationKind::NativeSparse:
    case WriteAheadLog::OperationKind::CloneRange:
    case WriteAheadLog::OperationKind::CreateSnapshot:
    case WriteAheadLog::OperationKind::DeleteSnapshot:
    case WriteAheadLog::OperationKind::SetVolumeQuotaReserve:
    case WriteAheadLog::OperationKind::RenameVolume:
    case WriteAheadLog::OperationKind::RepairVolumeFileCount:
    case WriteAheadLog::OperationKind::RewriteCompressedContent:
        return true;
    default:
        return false;
    }
}

bool RequiresPayloadSpoolFlushForRecovery(const std::vector<WriteAheadLog::Record>& records)
{
    return std::any_of(
        records.begin(),
        records.end(),
        [](const WriteAheadLog::Record& record)
        {
            return record.operation == WriteAheadLog::OperationKind::Write &&
                   (record.inline_payload.empty() ||
                    !WriteAheadLog::InlinePayloadIsConsistent(record));
        });
}

bool ValidateWalSemantics(const std::vector<WriteAheadLog::Record>& records)
{
    constexpr auto exhausted = (std::numeric_limits<std::uint64_t>::max)();
    std::unordered_map<std::uint64_t, std::size_t> prepared_counts;
    std::unordered_map<std::uint64_t,std::uint64_t> clone_checkpoints;
    std::unordered_set<std::uint64_t> terminal_transactions;
    std::uint64_t previous_sequence = 0;
    std::uint64_t compaction_floor = 0;
    std::uint64_t active_transaction_id = 0;

    for (const auto& record : records)
    {
        if (record.operation != WriteAheadLog::OperationKind::CompactionIndex)
        {
            continue;
        }
        if (record.transaction_id != 0 ||
            record.sequence == 0 ||
            record.sequence == exhausted ||
            record.state != WriteAheadLog::RecordState::Cleaned ||
            record.flags != 0)
        {
            return false;
        }
        compaction_floor = (std::max)(compaction_floor, record.sequence);
    }

    for (const auto& record : records)
    {
        if (record.operation == WriteAheadLog::OperationKind::CompactionIndex)
        {
            continue;
        }

        if (record.sequence == 0 ||
            record.sequence == exhausted ||
            record.sequence < compaction_floor ||
            record.sequence <= previous_sequence)
        {
            return false;
        }
        previous_sequence = record.sequence;

        if (record.operation == WriteAheadLog::OperationKind::TransactionMarker)
        {
            if (record.transaction_id == 0 ||
                record.transaction_id == exhausted ||
                (active_transaction_id != 0 && active_transaction_id != record.transaction_id) ||
                !terminal_transactions.insert(record.transaction_id).second)
            {
                return false;
            }

            const bool accepted = IsTransactionMarkerWithState(
                record,
                WriteAheadLog::RecordState::Accepted,
                kWalFlagAccepted);
            const bool committed = IsTransactionMarkerWithState(
                record,
                WriteAheadLog::RecordState::Checkpointed,
                kWalFlagCommitted);
            const bool aborted = IsTransactionMarkerWithState(
                record,
                WriteAheadLog::RecordState::Cleaned,
                kWalFlagAborted);
            if (!accepted && !committed && !aborted)
            {
                return false;
            }

            if (accepted || committed)
            {
                if(const auto clone=clone_checkpoints.find(record.transaction_id);clone!=clone_checkpoints.end())
                    if(record.object_id!=clone->second || record.logical_length!=1)return false;
                const auto prepared = prepared_counts.find(record.transaction_id);
                const bool compacted_before_this_boundary = record.sequence == compaction_floor;
                if (!compacted_before_this_boundary)
                {
                    if (prepared == prepared_counts.end())
                    {
                        if (!committed || record.logical_length != 0)
                        {
                            return false;
                        }
                    }
                    else if (prepared->second != record.logical_length)
                    {
                        return false;
                    }
                }
            }

            prepared_counts.erase(record.transaction_id);
            if (active_transaction_id == record.transaction_id)
            {
                active_transaction_id = 0;
            }
            continue;
        }

        if (record.operation == WriteAheadLog::OperationKind::DurabilityWatermark)
        {
            if (record.transaction_id != 0 ||
                active_transaction_id != 0 ||
                record.flags != 0 ||
                record.logical_offset == 0 ||
                (record.state != WriteAheadLog::RecordState::Checkpointed &&
                 record.state != WriteAheadLog::RecordState::Cleaned))
            {
                return false;
            }
            continue;
        }

        if (!IsMutationOperation(record.operation) ||
            record.state != WriteAheadLog::RecordState::Prepared ||
            record.transaction_id == 0 ||
            record.transaction_id == exhausted ||
            (active_transaction_id != 0 && active_transaction_id != record.transaction_id) ||
            terminal_transactions.contains(record.transaction_id))
        {
            return false;
        }
        if(record.operation==WriteAheadLog::OperationKind::CloneFile) {
            NativeCloneProof p;
            if(!WriteAheadLog::NativeCloneIsConsistent(record) || !DecodeNativeClone(record.inline_payload,p) ||
                !clone_checkpoints.emplace(record.transaction_id,p.checkpoint).second)return false;
        }
        if (record.operation == WriteAheadLog::OperationKind::HardLink) {
            NativeHardLinkProof proof;
            if (!WriteAheadLog::NativeHardLinkIsConsistent(record) ||
                !DecodeNativeHardLink(record.inline_payload, proof) ||
                !clone_checkpoints.emplace(record.transaction_id, proof.checkpoint).second) return false;
        }
        if (record.operation == WriteAheadLog::OperationKind::CloneRange) {
            NativeCloneRangeProof proof;
            if (!WriteAheadLog::NativeCloneRangeIsConsistent(record) || !DecodeNativeCloneRange(record.inline_payload, proof) ||
                !clone_checkpoints.emplace(record.transaction_id, proof.checkpoint).second) return false;
        }
        if (record.operation == WriteAheadLog::OperationKind::NativeSparse) {
            std::uint64_t checkpoint=0;
            if (!WriteAheadLog::NativeSparseIsConsistent(record) ||
                !DecodeNativeSparseOriginalCheckpoint(record.inline_payload, checkpoint) ||
                !clone_checkpoints.emplace(record.transaction_id, checkpoint).second) return false;
        }
        if (record.operation == WriteAheadLog::OperationKind::SetVolumeQuotaReserve) {
            NativeVolumeQuotaReserve rename;
            if (!WriteAheadLog::VolumeQuotaReserveIsConsistent(record) ||
                !DecodeNativeVolumeQuotaReserve(record.inline_payload, rename) ||
                !clone_checkpoints.emplace(record.transaction_id, rename.checkpoint).second) return false;
        }
        if (record.operation == WriteAheadLog::OperationKind::RenameVolume) {
            NativeVolumeRename rename;
            if (!WriteAheadLog::SnapshotIntentIsConsistent(record) || !WriteAheadLog::CountRepairIsConsistent(record) || !WriteAheadLog::VolumeQuotaReserveIsConsistent(record) || !WriteAheadLog::VolumeRenameIsConsistent(record) ||
                !DecodeNativeVolumeRename(record.inline_payload, rename) ||
                !clone_checkpoints.emplace(record.transaction_id, rename.checkpoint).second) return false;
        }
        if (record.operation == WriteAheadLog::OperationKind::CreateSnapshot || record.operation == WriteAheadLog::OperationKind::DeleteSnapshot) {
            NativeSnapshotIntent intent;
            if (!WriteAheadLog::SnapshotIntentIsConsistent(record) || !DecodeNativeSnapshotIntent(record.inline_payload,intent) ||
                !clone_checkpoints.emplace(record.transaction_id,intent.scope.checkpoint_xid).second) return false;
        }
        active_transaction_id = record.transaction_id;
        if (record.operation == WriteAheadLog::OperationKind::RepairVolumeFileCount) {
            NativeCountRepair repair;
            if (!WriteAheadLog::CountRepairIsConsistent(record) ||
                !DecodeNativeCountRepair(record.inline_payload, repair) ||
                !clone_checkpoints.emplace(record.transaction_id, repair.checkpoint).second) return false;
        }
        ++prepared_counts[record.transaction_id];
    }

    return active_transaction_id == 0 && prepared_counts.empty();
}

bool AppendSnapshotCheckpointPins(const WriteAheadLog::Record& record, std::vector<std::uint64_t>& pins)
{
    if (record.operation != WriteAheadLog::OperationKind::CreateSnapshot &&
        record.operation != WriteAheadLog::OperationKind::DeleteSnapshot) return true;
    NativeSnapshotIntent intent;
    if (!WriteAheadLog::SnapshotIntentIsConsistent(record) ||
        !DecodeNativeSnapshotIntent(record.inline_payload, intent) ||
        pins.size() > TransactionManager::MaxCachedCheckpointPinEntries() ||
        intent.pins.size() > TransactionManager::MaxCachedCheckpointPinEntries() - pins.size()) return false;
    pins.insert(pins.end(), intent.pins.begin(), intent.pins.end());
    return true;
}

struct OriginalHistoryCleanup
{
    std::vector<WriteAheadLog::Record>& records;
    void Clear()
    {
        for (auto& r : records) {
            for (auto* text : {&r.volume_identity, &r.path_utf8, &r.secondary_path_utf8})
                if (!text->empty()) SecureZeroMemory(text->data(), text->size());
            if (!r.inline_payload.empty()) SecureZeroMemory(r.inline_payload.data(), r.inline_payload.size());
            SecureZeroMemory(r.payload_sha256.data(), r.payload_sha256.size());
        }
        std::vector<WriteAheadLog::Record>().swap(records);
    }
    ~OriginalHistoryCleanup() { Clear(); }
};

bool HasOriginalProtectedAnchor(const std::filesystem::path& path, std::uint64_t expected_bytes)
{
    // The existing authenticated reader validates the anchor plaintext. This
    // header-only check refuses its larger retained-checkpoint variant, even
    // when compaction happened to retain sequences 1..N without any gaps.
    constexpr std::array<std::uint8_t, 40> normal{
        0xe4, 'A', 'P', 'F', 'S', 'W', 'A', 'L', 1, 0, 0, 0, 16, 0, 0, 0,
        'A', 'P', 'F', 'S', 'R', 'E', 'C', '1', 1, 0, 0, 0, 64, 0, 0, 0, 88, 0, 0, 0, 24, 0, 0, 0};
    struct Handle { HANDLE h; ~Handle() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); } } file{
        CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
    BY_HANDLE_FILE_INFORMATION info{}; LARGE_INTEGER size{}; wchar_t resolved[1024]{};
    if (file.h == INVALID_HANDLE_VALUE || !GetFileInformationByHandle(file.h, &info) || info.nNumberOfLinks != 1 ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ||
        !GetFileSizeEx(file.h, &size) || size.QuadPart < 0 || static_cast<std::uint64_t>(size.QuadPart) != expected_bytes) return false;
    const auto n = GetFinalPathNameByHandleW(file.h, resolved, 1024, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!n || n >= 1024 || CompareStringOrdinal(resolved, -1, (L"\\\\?\\" + path.wstring()).c_str(), -1, TRUE) != CSTR_EQUAL) return false;
    std::array<std::uint8_t, normal.size()> header{}; DWORD read = 0;
    return ReadFile(file.h, header.data(), static_cast<DWORD>(header.size()), &read, nullptr) && read == header.size() && header == normal;
}
}

TransactionManager::TransactionManager(std::wstring safety_level)
    : safety_level_(std::move(safety_level)),
      journal_(WriteAheadLog::Options{})
{
}

TransactionManager::State TransactionManager::CurrentState() const noexcept
{
    return state_;
}

bool TransactionManager::Begin()
{
    if (!recovery_state_valid_ ||
        state_ != State::Idle ||
        next_transaction_id_ == 0 ||
        next_transaction_id_ == (std::numeric_limits<std::uint64_t>::max)())
    {
        return false;
    }

    if (!journal_path_.empty() && !JournalStateMatchesWriterLease())
    {
        if (!SeedIdsFromExistingJournal(true) ||
            !recovery_state_valid_ ||
            !JournalStateMatchesWriterLease())
        {
            return false;
        }
    }

    if (preserve_startup_evidence_ && journal_.ValidatedAppendLeaseGeneration(true) == 0)
        return false;

    current_transaction_id_ = next_transaction_id_++;
    pending_mutations_.clear();
    ClearBufferedPreparedRecords();
    current_transaction_requires_payload_spool_flush_ = false;
    state_ = State::Active;
    NotifyStage("begin");
    return true;
}

bool TransactionManager::Commit(std::uint64_t preimage_checkpoint_xid)
{
    if (!recovery_state_valid_ || state_ != State::Active)
    {
        return false;
    }

    state_ = State::Committing;
    NotifyStage("commit-start");
    NotifyStage("prepare");
    NotifyStage("write-data");
    NotifyStage("write-metadata");
    if (!PersistTransactionBatchLocked(L"committed", true, preimage_checkpoint_xid))
    {
        state_ = State::Failed;
        NotifyStage("commit-failed");
        return false;
    }
    NotifyStage("flush-data");
    NotifyStage("switch-checkpoint");
    NotifyStage("finalize");
    NotifyStage("commit-finish");
    pending_mutations_.clear();
    ClearBufferedPreparedRecords();
    current_transaction_requires_payload_spool_flush_ = false;
    current_transaction_id_ = 0;
    state_ = State::Idle;
    return true;
}

bool TransactionManager::Accept(std::uint64_t preimage_checkpoint_xid)
{
    if (!recovery_state_valid_ || state_ != State::Active || pending_mutations_.empty())
    {
        return false;
    }

    state_ = State::Committing;
    NotifyStage("accept-start");
    if (!PersistTransactionBatchLocked(L"accepted", true, preimage_checkpoint_xid))
    {
        state_ = State::Failed;
        NotifyStage("accept-failed");
        return false;
    }

    NotifyStage("accept-finish");
    pending_mutations_.clear();
    ClearBufferedPreparedRecords();
    current_transaction_requires_payload_spool_flush_ = false;
    current_transaction_id_ = 0;
    state_ = State::Idle;
    return true;
}

bool TransactionManager::AcceptForDeferredCommit(
    std::uint64_t* accepted_sequence,
    std::uint64_t preimage_checkpoint_xid)
{
    if (accepted_sequence)
    {
        *accepted_sequence = 0;
    }
    if (!recovery_state_valid_ || state_ != State::Active || pending_mutations_.empty())
    {
        return false;
    }

    state_ = State::Committing;
    NotifyStage("accept-start");
    if (!PersistTransactionBatchLocked(L"accepted", false, preimage_checkpoint_xid))
    {
        state_ = State::Failed;
        NotifyStage("accept-failed");
        return false;
    }

    const auto accepted = watermarks_.accepted_sequence;
    pending_mutations_.clear();
    ClearBufferedPreparedRecords();
    current_transaction_requires_payload_spool_flush_ = false;
    current_transaction_id_ = 0;
    state_ = State::Idle;
    {
        std::lock_guard<std::mutex> lock(deferred_wal_state_mutex_);
        deferred_wal_pending_sequence_ =
            (std::max)(deferred_wal_pending_sequence_, accepted);
    }
    deferred_wal_state_cv_.notify_all();
    if (accepted_sequence)
    {
        *accepted_sequence = accepted;
    }
    NotifyStage("accept-finish");
    return true;
}

bool TransactionManager::WaitForDeferredAcceptanceDurability(std::uint64_t accepted_sequence)
{
    return EnsureDeferredAcceptanceDurability(accepted_sequence, true);
}

bool TransactionManager::FlushDeferredAcceptanceDurabilityNow(std::uint64_t accepted_sequence)
{
    return EnsureDeferredAcceptanceDurability(accepted_sequence, false);
}

bool TransactionManager::FlushAcceptedEvidenceDurability(std::uint64_t accepted_sequence)
{
    if (!recovery_state_valid_ || state_ != State::Idle || journal_path_.empty() ||
        !accepted_sequence || accepted_sequence > watermarks_.accepted_sequence ||
        accepted_sequence <= watermarks_.cleanup_sequence || !IsAcceptedBoundary(accepted_sequence) ||
        !JournalStateMatchesWriterLease()) return false;
    // The external journal gate prevents a new acceptance during this barrier.
    // The append mutex also excludes an already scheduled deferred flusher.
    bool flushed = false;
    {
        std::lock_guard append_lock(deferred_wal_append_mutex_);
        flushed = journal_.FlushPendingAppends();
        if (flushed) {
            std::lock_guard state_lock(deferred_wal_state_mutex_);
            deferred_wal_durable_sequence_ = (std::max)(deferred_wal_durable_sequence_, accepted_sequence);
        }
    }
    deferred_wal_state_cv_.notify_all();
    if (!flushed) MarkDeferredAcceptanceDurabilityFailure();
    return flushed;
}

bool TransactionManager::FlushRetainedOriginalEvidenceDurability()
try
{
    if (!recovery_state_valid_ || state_ != State::Idle || journal_path_.empty() || volume_identity_.empty() ||
        current_transaction_id_ || journal_append_ambiguous_ || !pending_mutations_.empty() ||
        !buffered_prepared_records_.empty() || !watermarks_.accepted_sequence ||
        watermarks_.cleanup_sequence > watermarks_.apfs_durable_sequence ||
        watermarks_.apfs_durable_sequence > watermarks_.accepted_sequence || !JournalStateMatchesWriterLease()) return false;
    const auto lease = journal_state_writer_generation_;
    bool flushed = false;
    {
        std::lock_guard append_lock(deferred_wal_append_mutex_);
        {
            std::lock_guard state_lock(deferred_wal_state_mutex_);
            if (deferred_wal_flush_failed_) return false;
        }
        // Validate the retained append handle without opening, repair or reseed.
        flushed = journal_.ValidatedAppendLeaseGeneration(true) == lease &&
            journal_.FlushPendingAppends() && journal_.ValidatedAppendLeaseGeneration(true) == lease &&
            JournalStateMatchesWriterLease();
        if (flushed) {
            std::lock_guard state_lock(deferred_wal_state_mutex_);
            deferred_wal_durable_sequence_ = (std::max)(deferred_wal_durable_sequence_, watermarks_.accepted_sequence);
        }
    }
    deferred_wal_state_cv_.notify_all();
    if (!flushed) MarkDeferredAcceptanceDurabilityFailure();
    return flushed;
}
catch (...) { MarkDeferredAcceptanceDurabilityFailure(); return false; }

bool TransactionManager::ProtectedSpoolOwnerValid() const
{
    if (!journal_protection_ || journal_path_.empty() || volume_identity_.empty() ||
        !recovery_state_valid_ || state_ != State::Idle || current_transaction_id_ || journal_append_ambiguous_ ||
        !pending_mutations_.empty() || !buffered_prepared_records_.empty() ||
        !journal_.HasExclusiveWriterLease() || !JournalStateMatchesWriterLease()) return false;
    std::lock_guard state_lock(deferred_wal_state_mutex_);
    return !deferred_wal_flush_failed_ && !deferred_wal_flush_in_progress_;
}

bool TransactionManager::ReadProtectedOriginalHistory(WriteAheadLog::ProtectedHistoryHead& head,
    std::vector<WriteAheadLog::Record>& records, std::string& error)
{
    head = {}; error.clear();
    const auto fail = [&](const char* reason) { head = {}; error = reason; return false; };
    if (!ProtectedSpoolOwnerValid()) return fail("ProtectedSpoolOriginalOwnerInvalid");
    const auto retired = continuation_seed_ ? continuation_seed_->last_sequence : 0;
    if (!journal_.CaptureProtectedHistoryHead(head) || head.records > 65536 ||
        head.records > UINT64_MAX - retired || head.last_sequence != retired + head.records ||
        (!continuation_seed_ && !HasOriginalProtectedAnchor(journal_path_, head.bytes))) return fail("ProtectedSpoolOriginalHistoryUnavailable");
    const auto budget = journal_protection_->max_allocation_bytes;
    if (head.bytes > budget / 8 || head.records > (budget - head.bytes * 8) / (3 * sizeof(WriteAheadLog::Record) + 256))
        return fail("ProtectedSpoolOriginalResourceLimit");
    auto read = journal_.ReadAllAtProtectedHead(head); OriginalHistoryCleanup cleanup{read.records};
    if (read.status != WriteAheadLog::ReadStatus::Ok || read.recovered_torn_tail || read.records.size() != head.records)
        return fail("ProtectedSpoolOriginalHistoryUnavailable");
    const auto identity = EffectiveVolumeIdentity(volume_identity_);
    for (std::size_t n = 0; n < read.records.size(); ++n)
        if (read.records[n].sequence != retired + n + 1 || read.records[n].volume_identity != identity ||
            read.records[n].operation == WriteAheadLog::OperationKind::CompactionIndex)
            return fail("ProtectedSpoolOriginalHistoryIncomplete");
    TransactionManager verifier(safety_level_);
    verifier.continuation_seed_ = continuation_seed_;
    if (continuation_seed_) verifier.journal_protection_ = journal_protection_;
    if (!verifier.SeedIdsFromJournalRecords(read.records, 0) || !verifier.RecoveryStateValid() ||
        verifier.watermarks_.accepted_sequence != watermarks_.accepted_sequence ||
        verifier.watermarks_.apfs_durable_sequence != watermarks_.apfs_durable_sequence ||
        verifier.watermarks_.cleanup_sequence != watermarks_.cleanup_sequence || next_sequence_ != head.last_sequence + 1 ||
        !ProtectedSpoolOwnerValid()) return fail("ProtectedSpoolOriginalStateMismatch");
    records = std::move(read.records);
    return true;
}

bool TransactionManager::ReadAuthorizationDispositionHistory(WriteAheadLog::ProtectedHistoryHead& head,
    std::vector<WriteAheadLog::Record>& records, std::string& error)
{
    records.clear(); head = {};
    const bool begun = recovery_state_valid_ && state_ == State::Active && current_transaction_id_ &&
        pending_mutations_.empty() && buffered_prepared_records_.empty() && !journal_append_ambiguous_ &&
        journal_protection_ && journal_.HasExclusiveWriterLease() && JournalStateMatchesWriterLease();
    const bool prepared_recovery = !recovery_state_valid_ && state_ == State::Idle && !current_transaction_id_ &&
        journal_protection_ && !journal_path_.empty() && !volume_identity_.empty() && journal_.HasExclusiveWriterLease() &&
        !journal_append_ambiguous_ && pending_mutations_.empty() && buffered_prepared_records_.empty();
    if (!begun && !prepared_recovery && !ProtectedSpoolOwnerValid()) { error = "AuthorizationDispositionOriginalOwnerInvalid"; return false; }
    if (begun || prepared_recovery) {
        std::lock_guard lock(deferred_wal_state_mutex_);
        if (deferred_wal_flush_failed_ || deferred_wal_flush_in_progress_) {
            error = "AuthorizationDispositionOriginalOwnerInvalid"; return false;
        }
    }
    const auto attributes = GetFileAttributesW(journal_path_.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        const auto code = GetLastError();
        if (code != ERROR_FILE_NOT_FOUND || continuation_seed_ || next_sequence_ != 1 ||
            (begun ? current_transaction_id_ != 1 : next_transaction_id_ != 1) ||
            watermarks_.accepted_sequence || watermarks_.apfs_durable_sequence || watermarks_.cleanup_sequence) {
            error = "AuthorizationDispositionOriginalMissing"; return false;
        }
        auto read = journal_.ReadAllWithExclusiveWriterLease(journal_protection_->read_limits);
        if (read.status != WriteAheadLog::ReadStatus::Ok || read.recovered_torn_tail || !read.records.empty()) {
            error = "AuthorizationDispositionOriginalUnreadable"; return false;
        }
        return true;
    }
    if (!begun && !prepared_recovery) return ReadProtectedOriginalHistory(head, records, error);
    if (!journal_.CaptureProtectedHistoryHead(head)) { error = "AuthorizationDispositionOriginalUnreadable"; return false; }
    const auto budget = journal_protection_->max_allocation_bytes;
    if (head.records > 65536 || head.bytes > budget / 8 ||
        head.records > (budget - head.bytes * 8) / (3 * sizeof(WriteAheadLog::Record) + 256)) {
        error = "AuthorizationDispositionOriginalResourceLimit"; return false;
    }
    auto read = journal_.ReadAllAtProtectedHead(head); OriginalHistoryCleanup clear{read.records};
    const auto retired = continuation_seed_ ? continuation_seed_->last_sequence : 0;
    if (read.status != WriteAheadLog::ReadStatus::Ok || read.recovered_torn_tail || head.records != read.records.size() ||
        head.last_sequence != retired + head.records ||
        (!continuation_seed_ && !HasOriginalProtectedAnchor(journal_path_, head.bytes))) {
        error = "AuthorizationDispositionOriginalIncomplete"; return false;
    }
    for (std::size_t n = 0; n < read.records.size(); ++n)
        if (read.records[n].sequence != retired + n + 1 || read.records[n].volume_identity != EffectiveVolumeIdentity(volume_identity_) ||
            read.records[n].operation == WriteAheadLog::OperationKind::CompactionIndex) {
            error = "AuthorizationDispositionOriginalIncomplete"; return false;
        }
    if (prepared_recovery) {
        if (!SeedAuthorizationPreparedPrefix(read.records, journal_.ExclusiveWriterLeaseGeneration())) {
            error = "AuthorizationDispositionPreparedPrefixInvalid"; return false;
        }
        records = std::move(read.records); return true;
    }
    TransactionManager verifier(safety_level_); verifier.continuation_seed_ = continuation_seed_;
    if (continuation_seed_) verifier.journal_protection_ = journal_protection_;
    if (!verifier.SeedIdsFromJournalRecords(read.records, 0) || current_transaction_id_ != verifier.next_transaction_id_ ||
        next_sequence_ != verifier.next_sequence_ || watermarks_.accepted_sequence != verifier.watermarks_.accepted_sequence ||
        watermarks_.apfs_durable_sequence != verifier.watermarks_.apfs_durable_sequence ||
        watermarks_.cleanup_sequence != verifier.watermarks_.cleanup_sequence) {
        error = "AuthorizationDispositionOriginalStateMismatch"; return false;
    }
    records = std::move(read.records); return true;
}

bool TransactionManager::SeedAuthorizationPreparedPrefix(
    const std::vector<WriteAheadLog::Record>& records, std::uint64_t writer_generation)
{
    if (state_ != State::Idle || records.empty() || records.back().sequence >= UINT64_MAX - 1 ||
        records.back().transaction_id >= UINT64_MAX - 1 || !records.back().transaction_id ||
        journal_append_ambiguous_ || !pending_mutations_.empty() || !buffered_prepared_records_.empty()) return false;
    const auto transaction = records.back().transaction_id;
    const auto& path = records.back().path_utf8;
    if (path != "\\$apfs-keybag-rewrap-v2" && path != "\\$apfs-software-transition-v1" &&
        path != "\\$apfs-software-key-rotation-v1") return false;
    std::uint64_t count = 0;
    for (auto it = records.rbegin(); it != records.rend() && it->transaction_id == transaction; ++it) {
        if (it->operation != WriteAheadLog::OperationKind::Write || it->state != WriteAheadLog::RecordState::Prepared ||
            it->path_utf8 != path || !WriteAheadLog::InlinePayloadIsConsistent(*it) || it->inline_payload.empty() ||
            it->inline_payload.size() > 4096) return false;
        ++count;
    }
    // Seed only the actual closed predecessor, without inventing a terminal
    // record for the prepared suffix. The suffix burns its own real IDs but
    // cannot make recovery valid until Journal appends its exact durable abort.
    std::vector<WriteAheadLog::Record> closed(records.begin(), records.end() - static_cast<std::ptrdiff_t>(count));
    OriginalHistoryCleanup clear{closed};
    TransactionManager verifier(safety_level_); verifier.continuation_seed_ = continuation_seed_;
    if (continuation_seed_) verifier.journal_protection_ = journal_protection_;
    if (!verifier.SeedIdsFromJournalRecords(closed, 0) || transaction != verifier.next_transaction_id_ ||
        records[closed.size()].sequence != verifier.next_sequence_ ||
        verifier.watermarks_.accepted_sequence != verifier.watermarks_.cleanup_sequence ||
        verifier.watermarks_.apfs_durable_sequence != verifier.watermarks_.cleanup_sequence) return false;
    next_sequence_ = records.back().sequence + 1; next_transaction_id_ = transaction + 1;
    watermarks_ = verifier.watermarks_; journal_state_writer_generation_ = writer_generation;
    recovery_state_valid_ = false;
    return true;
}

bool TransactionManager::AppendAuthorizationAbort(const WriteAheadLog::ProtectedHistoryHead& expected,
    const WriteAheadLog::Record& marker, std::string& error)
{
    std::unique_lock append_lock(deferred_wal_append_mutex_);
    WriteAheadLog::ProtectedHistoryHead head;
    std::vector<WriteAheadLog::Record> records; OriginalHistoryCleanup cleanup{records};
    if (!ReadAuthorizationDispositionHistory(head, records, error) || head != expected ||
        marker.sequence != next_sequence_ || marker.sequence == UINT64_MAX || !marker.transaction_id ||
        marker.transaction_id == UINT64_MAX || marker.operation != WriteAheadLog::OperationKind::TransactionMarker ||
        marker.state != WriteAheadLog::RecordState::Cleaned || marker.flags != kWalFlagAborted ||
        marker.object_id || marker.parent_object_id || marker.payload_spool_id || marker.payload_offset ||
        marker.payload_length || marker.logical_offset || marker.payload_sha256 != decltype(marker.payload_sha256){} ||
        !marker.inline_payload.empty() || marker.unlink_outcome || !marker.secondary_path_utf8.empty() ||
        marker.volume_identity != EffectiveVolumeIdentity(volume_identity_)) {
        error = "AuthorizationDispositionAbortMismatch"; return false;
    }
    records.push_back(marker);
    if (!ValidateWalSemantics(records) || (expected.bytes && !journal_.FlushPendingAppends())) {
        error = "AuthorizationDispositionOriginalBarrierFailed"; return false;
    }
    if (expected.bytes) {
        WriteAheadLog::ProtectedHistoryHead checked;
        if (!journal_.CaptureProtectedHistoryHead(checked) || checked != expected) {
            error = "AuthorizationDispositionOriginalChanged"; return false;
        }
    }
    const auto result = journal_.AppendWithResult(marker, true, journal_.ExclusiveWriterLeaseGeneration());
    if (result != WriteAheadLog::AppendResult::Succeeded) {
        if (result == WriteAheadLog::AppendResult::BytesMayHavePersisted) {
            recovery_state_valid_ = false; journal_append_ambiguous_ = true; state_ = State::Failed;
        }
        error = "AuthorizationDispositionAbortAppendFailed"; return false;
    }
    if (!SeedIdsFromJournalRecords(records, journal_.ExclusiveWriterLeaseGeneration())) {
        state_ = State::Failed; error = "AuthorizationDispositionAbortReseedFailed"; return false;
    }
    return true;
}

bool TransactionManager::CaptureProtectedOriginalHistoryHead(WriteAheadLog::ProtectedHistoryHead& head, std::string& error)
{
    std::lock_guard append_lock(deferred_wal_append_mutex_);
    std::vector<WriteAheadLog::Record> records; OriginalHistoryCleanup cleanup{records};
    try { return ReadProtectedOriginalHistory(head, records, error); }
    catch (...) { head = {}; error = "ProtectedSpoolOriginalHistoryUnavailable"; return false; }
}

PayloadSpool::ProtectedMaintenanceResult TransactionManager::ReconcileProtectedPayloadSpool(PayloadSpool& spool,
    const WriteAheadLog::ProtectedHistoryHead& expected, std::string& error)
{
    std::lock_guard append_lock(deferred_wal_append_mutex_);
    error.clear();
    const auto fail = [&](const char* reason) { error = reason; return PayloadSpool::ProtectedMaintenanceResult::RejectedBeforeWrite; };
    bool entered_spool = false;
    std::vector<WriteAheadLog::Record> records; OriginalHistoryCleanup cleanup{records};
    try {
        if (!ProtectedSpoolOwnerValid() || !spool.MatchesProtectedMaintenanceAuthority(journal_protection_->source_binding,
            EffectiveVolumeIdentity(volume_identity_), journal_protection_->key_directory)) return fail("ProtectedSpoolAuthorityMismatch");
        WriteAheadLog::ProtectedHistoryHead head;
        if (!ReadProtectedOriginalHistory(head, records, error)) return PayloadSpool::ProtectedMaintenanceResult::RejectedBeforeWrite;
        if (head != expected) return fail("ProtectedSpoolOriginalHeadMismatch");
        PayloadSpool::ProtectedCleanupProof proof;
        proof.source_binding = journal_protection_->source_binding; proof.wal_sha256 = head.sha256;
        proof.wal_bytes = head.bytes;
        // The private continuation baseline certifies the retired prefix. The
        // bounded active count must not be confused with a global sequence.
        proof.wal_records = head.records;
        proof.wal_last_sequence = head.last_sequence;
        proof.durable_sequence = watermarks_.apfs_durable_sequence; proof.cleanup_sequence = watermarks_.cleanup_sequence;
        std::vector<PayloadSpool::PersistedRangeReference> refs;
        std::vector<std::uint64_t> optional_inline_sequences;
        for (const auto& r : records) {
            if (r.operation != WriteAheadLog::OperationKind::Write &&
                r.operation != WriteAheadLog::OperationKind::CreateFile) continue;
            if (!r.payload_length) {
                if (r.payload_spool_id || r.payload_offset || !r.inline_payload.empty()) return fail("ProtectedSpoolOriginalReferenceInvalid");
                continue;
            }
            const bool complete_inline = !r.inline_payload.empty() && WriteAheadLog::InlinePayloadIsConsistent(r);
            if (!r.inline_payload.empty() && !complete_inline) return fail("ProtectedSpoolOriginalReferenceInvalid");
            if (complete_inline) {
                if (r.payload_spool_id && r.payload_spool_id != r.sequence) return fail("ProtectedSpoolOriginalReferenceInvalid");
                if (!r.parent_object_id) {
                    if (r.payload_offset) return fail("ProtectedSpoolOriginalReferenceInvalid");
                    continue; // A zero generation cannot authenticate a physical frame.
                }
                optional_inline_sequences.push_back(r.sequence);
            } else if (!r.parent_object_id) {
                return fail("ProtectedSpoolOriginalReferenceInvalid");
            }
            if (refs.size() >= 4096 || !r.object_id || !r.parent_object_id || r.payload_spool_id != r.sequence ||
                r.payload_length > journal::kMaxJournalPlaintextBytes || r.logical_length != r.payload_length ||
                r.logical_offset > UINT64_MAX - r.payload_length ||
                std::all_of(r.payload_sha256.begin(), r.payload_sha256.end(), [](auto b) { return b == 0; }) ||
                (!r.inline_payload.empty() && !WriteAheadLog::InlinePayloadIsConsistent(r))) return fail("ProtectedSpoolOriginalReferenceInvalid");
            refs.push_back({r.volume_identity, r.object_id, r.parent_object_id, r.logical_offset,
                r.payload_length, r.payload_offset, r.sequence, r.payload_sha256});
        }
        cleanup.Clear();
        const auto generation = journal_.ExclusiveWriterLeaseGeneration();
        NotifyStage("protected-spool-before-original-barrier");
        if (!ProtectedSpoolOwnerValid() || !journal_.FlushPendingAppends()) {
            MarkDeferredAcceptanceDurabilityFailure(); return fail("ProtectedSpoolOriginalFlushFailed");
        }
        NotifyStage("protected-spool-after-original-barrier");
        std::vector<WriteAheadLog::Record> rechecked; OriginalHistoryCleanup recheck_cleanup{rechecked};
        WriteAheadLog::ProtectedHistoryHead after;
        if (!ReadProtectedOriginalHistory(after, rechecked, error) || after != expected ||
            generation != journal_.ExclusiveWriterLeaseGeneration()) {
            MarkDeferredAcceptanceDurabilityFailure(); return fail("ProtectedSpoolOriginalChanged");
        }
        recheck_cleanup.Clear();
        {
            std::lock_guard state_lock(deferred_wal_state_mutex_);
            deferred_wal_durable_sequence_ = (std::max)(deferred_wal_durable_sequence_, watermarks_.accepted_sequence);
        }
        deferred_wal_state_cv_.notify_all();
        entered_spool = true;
        const auto result = spool.ReconcileProtectedOriginalHistory(proof, refs, optional_inline_sequences);
        if (result != PayloadSpool::ProtectedMaintenanceResult::Succeeded)
            error = result == PayloadSpool::ProtectedMaintenanceResult::RecoveryRequired ? "ProtectedSpoolRecoveryRequired" : "ProtectedSpoolReconciliationRefused";
        return result;
    } catch (...) {
        try { error = entered_spool ? "ProtectedSpoolRecoveryRequired" : "ProtectedSpoolOriginalHistoryUnavailable"; } catch (...) {}
        return entered_spool ? PayloadSpool::ProtectedMaintenanceResult::RecoveryRequired : PayloadSpool::ProtectedMaintenanceResult::RejectedBeforeWrite;
    }
}

void TransactionManager::MarkDeferredAcceptanceDurabilityFailure() noexcept
{
    {
        std::lock_guard<std::mutex> lock(deferred_wal_state_mutex_);
        deferred_wal_flush_failed_ = true;
        deferred_wal_flush_in_progress_ = false;
    }
    deferred_wal_state_cv_.notify_all();
    recovery_state_valid_ = false;
    journal_append_ambiguous_ = true;
    journal_state_writer_generation_ = 0;
    InvalidateFinalizationCoverage(true);
    state_ = State::Failed;
}

bool TransactionManager::EnsureDeferredAcceptanceDurability(
    std::uint64_t accepted_sequence,
    bool coalesce)
{
    if (accepted_sequence == 0 || journal_path_.empty())
    {
        return true;
    }

    for (;;)
    {
        bool become_flusher = false;
        {
            std::unique_lock<std::mutex> state_lock(deferred_wal_state_mutex_);
            if (deferred_wal_durable_sequence_ >= accepted_sequence ||
                deferred_wal_pending_sequence_ < accepted_sequence)
            {
                return true;
            }
            if (deferred_wal_flush_failed_)
            {
                return false;
            }
            if (!deferred_wal_flush_in_progress_)
            {
                deferred_wal_flush_in_progress_ = true;
                become_flusher = true;
            }
            else
            {
                deferred_wal_state_cv_.wait(state_lock, [&]()
                {
                    return deferred_wal_durable_sequence_ >= accepted_sequence ||
                           deferred_wal_flush_failed_ ||
                           !deferred_wal_flush_in_progress_;
                });
            }
        }

        if (!become_flusher)
        {
            continue;
        }

        if (coalesce)
        {
            std::this_thread::sleep_for(kDeferredWalGroupCommitWindow);
        }

        std::unique_lock<std::mutex> append_lock(deferred_wal_append_mutex_);
        std::uint64_t target_sequence = 0;
        {
            std::lock_guard<std::mutex> state_lock(deferred_wal_state_mutex_);
            target_sequence = deferred_wal_pending_sequence_;
        }

        const auto flush_started = std::chrono::steady_clock::now();
        const bool flushed = journal_.FlushPendingAppends();
        const auto flush_elapsed = ElapsedMicroseconds(flush_started);
        {
            std::lock_guard<std::mutex> state_lock(deferred_wal_state_mutex_);
            if (flushed)
            {
                deferred_wal_durable_sequence_ =
                    (std::max)(deferred_wal_durable_sequence_, target_sequence);
                ++deferred_wal_group_flush_count_;
                deferred_wal_group_flush_microseconds_ += flush_elapsed;
            }
            else
            {
                deferred_wal_flush_failed_ = true;
            }
            deferred_wal_flush_in_progress_ = false;
        }
        deferred_wal_state_cv_.notify_all();
        if (!flushed)
        {
            return false;
        }
    }
}

bool TransactionManager::CanAcceptWithoutPayloadSpoolFlush() const noexcept
{
    if (!recovery_state_valid_ ||
        state_ != State::Active ||
        pending_mutations_.empty() ||
        buffered_prepared_records_.size() != pending_mutations_.size() ||
        journal_path_.empty() ||
        volume_identity_.empty())
    {
        return false;
    }

    return !buffered_prepared_records_have_incomplete_inline_payload_;
}

bool TransactionManager::CanAddInlinePayload(std::size_t payload_bytes) const noexcept
{
    if (!recovery_state_valid_ ||
        state_ != State::Active ||
        payload_bytes == 0 ||
        payload_bytes > WriteAheadLog::MaxInlinePayloadBytes)
    {
        return false;
    }

    if (buffered_prepared_records_have_empty_write_payload_)
    {
        return false;
    }

    return payload_bytes <=
        WriteAheadLog::MaxInlinePayloadBytes - buffered_inline_payload_bytes_;
}

bool TransactionManager::CanFinalizeWithoutPayloadSpoolFlush(
    bool allow_process_local_coverage)
{
    if (!recovery_state_valid_ ||
        state_ == State::Failed ||
        state_ == State::Committing ||
        journal_path_.empty() ||
        volume_identity_.empty())
    {
        return false;
    }

    bool has_finalization_work = false;
    if (state_ == State::Active)
    {
        if (!CanAcceptWithoutPayloadSpoolFlush())
        {
            return false;
        }
        has_finalization_work = true;
    }

    const auto writer_generation = journal_.ExclusiveWriterLeaseGeneration();
    const bool trusted_process_local_coverage =
        finalization_coverage_trust_ == FinalizationCoverageTrust::Trusted &&
        writer_generation != 0 &&
        writer_generation == finalization_coverage_writer_generation_;
    if (allow_process_local_coverage && trusted_process_local_coverage)
    {
        ++finalization_coverage_cache_hit_count_;
        if (!accepted_boundaries_requiring_payload_spool_flush_.empty())
        {
            return false;
        }
        if (HasUnappliedAcceptedWork())
        {
            has_finalization_work = true;
        }
    }
    else
    {
        const auto scan_started = std::chrono::steady_clock::now();
        ++finalization_coverage_wal_scan_count_;
        std::vector<AcceptedTransaction> transactions;
        std::string failure_reason;
        const auto loaded = LoadUnappliedAcceptedTransactions(transactions, &failure_reason);
        finalization_coverage_wal_scan_microseconds_ += ElapsedMicroseconds(scan_started);
        if (!loaded)
        {
            InvalidateFinalizationCoverage(true);
            return false;
        }
        const auto validated_writer_generation = journal_.ExclusiveWriterLeaseGeneration();
        if (validated_writer_generation == 0 ||
            validated_writer_generation != journal_state_writer_generation_)
        {
            InvalidateFinalizationCoverage(true);
            return false;
        }
        for (const auto& transaction : transactions)
        {
            has_finalization_work = true;
            if (RequiresPayloadSpoolFlushForRecovery(transaction.mutations))
            {
                return false;
            }
        }
    }

    if (watermarks_.cleanup_sequence < watermarks_.apfs_durable_sequence)
    {
        has_finalization_work = true;
    }
    return has_finalization_work;
}

bool TransactionManager::Abort()
{
    if (!recovery_state_valid_)
    {
        state_ = State::Failed;
        NotifyStage("abort-failed");
        return false;
    }
    if (state_ == State::Idle)
    {
        return true;
    }

    if (journal_append_ambiguous_)
    {
        state_ = State::Failed;
        NotifyStage("abort-failed");
        return false;
    }

    state_ = State::Failed;
    NotifyStage("abort");
    if (!buffered_prepared_records_.empty())
    {
        next_sequence_ = buffered_prepared_records_.front().sequence;
    }
    ClearBufferedPreparedRecords();
    if (!PersistTransactionBatchLocked(L"aborted"))
    {
        NotifyStage("abort-failed");
        return false;
    }
    ClearBufferedPreparedRecords();
    pending_mutations_.clear();
    current_transaction_requires_payload_spool_flush_ = false;
    current_transaction_id_ = 0;
    state_ = State::Idle;
    return true;
}

bool TransactionManager::RecordMutation(const MutationIntent& mutation)
{
    if (!recovery_state_valid_ || state_ != State::Active)
    {
        return false;
    }
    if (!journal_path_.empty() && !JournalStateMatchesWriterLease())
    {
        recovery_state_valid_ = false;
        InvalidateFinalizationCoverage(true);
        return false;
    }

    auto prepared_mutation = mutation;
    if (!AppendPreparedMutationLocked(prepared_mutation))
    {
        return false;
    }

    pending_mutations_.push_back(std::move(prepared_mutation));
    NotifyStage("mutation-recorded");
    return true;
}

void TransactionManager::ClearBufferedPreparedRecords() noexcept
{
    buffered_prepared_records_.clear();
    buffered_inline_payload_bytes_ = 0;
    buffered_prepared_records_have_empty_write_payload_ = false;
    buffered_prepared_records_have_incomplete_inline_payload_ = false;
}

bool TransactionManager::OpenExistingRepairJournal(std::wstring path, std::wstring identity, std::string& error)
{
    if (state_ != State::Idle || !journal_path_.empty() || !volume_identity_.empty()) {
        error = "Fresh transaction owner required"; return false;
    }
    journal_path_ = std::move(path); volume_identity_ = std::move(identity);
    ConfigureJournal();
    if (!journal_.AcquireExistingRepairLease(error)) return false;
    // No second parser/collector: bytes are now protected by the actual writer lease.
    if (!SeedIdsFromExistingJournal(true)) {
        error = "Canonical journal semantic validation failed; evidence retained"; return false;
    }
    return true;
}

void TransactionManager::SetJournalPath(std::wstring journal_path, bool acquire_writer_lease)
{
    if (journal_protection_)
    {
        if (journal_path != journal_path_)
        {
            recovery_state_valid_ = false;
            InvalidateFinalizationCoverage(true);
        }
        return;
    }
    journal_path_ = std::move(journal_path);
    {
        std::lock_guard<std::mutex> lock(deferred_wal_state_mutex_);
        deferred_wal_pending_sequence_ = 0;
        deferred_wal_durable_sequence_ = 0;
        deferred_wal_flush_in_progress_ = false;
        deferred_wal_flush_failed_ = false;
    }
    ConfigureJournal();
    journal_state_writer_generation_ = 0;
    InvalidateFinalizationCoverage(false);
    if (!journal_path_.empty() && !volume_identity_.empty())
    {
        (void)SeedIdsFromExistingJournal(acquire_writer_lease);
    }
}

bool TransactionManager::OpenStartupJournal(std::wstring path, std::wstring identity, std::string& error)
{
    error.clear();
    if (state_ != State::Idle || !journal_path_.empty() || !volume_identity_.empty() ||
        path.empty() || identity.empty() || !std::filesystem::path(path).is_absolute())
    {
        error = "StartupJournalFreshOwnerRequired";
        return false;
    }
    journal_path_ = std::move(path);
    volume_identity_ = std::move(identity);
    preserve_startup_evidence_ = true;
    ConfigureJournal();
    if (!SeedIdsFromExistingJournal(true))
    {
        error = "StartupJournalEvidenceInvalid";
        return false;
    }
    return true;
}

bool TransactionManager::MaterializeAbsentStartupJournal(std::string& error)
{
    error.clear();
    if (!preserve_startup_evidence_ || !recovery_state_valid_ || state_ != State::Idle ||
        journal_path_.empty() || volume_identity_.empty() || !JournalStateMatchesWriterLease() ||
        current_transaction_id_ != 0 || next_transaction_id_ != 1 || next_sequence_ != 1 ||
        !pending_mutations_.empty() || !buffered_prepared_records_.empty() || journal_append_ambiguous_ ||
        watermarks_.accepted_sequence != 0 || watermarks_.apfs_durable_sequence != 0 ||
        watermarks_.cleanup_sequence != 0 || last_committed_sequence_ != 0 ||
        highest_checkpointed_marker_sequence_ != 0 || !accepted_boundaries_.empty())
    {
        error = "AbsentStartupJournalStateInvalid";
        return false;
    }
    if (!journal_.MaterializeAbsentStartupJournal())
    {
        error = "AbsentStartupJournalMaterializationRefused";
        return false;
    }
    if (!SeedIdsFromExistingJournal(true))
    {
        error = "MaterializedStartupJournalEvidenceInvalid";
        return false;
    }
    return true;
}

bool TransactionManager::SnapshotEvidenceCapacityAvailable(const MutationIntent& intent, std::string& error) const
{
    error.clear();
    if (state_ != State::Idle || !recovery_state_valid_ || !pending_mutations_.empty() ||
        watermarks_.accepted_sequence != watermarks_.apfs_durable_sequence ||
        watermarks_.accepted_sequence != watermarks_.cleanup_sequence ||
        (intent.kind != MutationKind::CreateSnapshot && intent.kind != MutationKind::DeleteSnapshot) ||
        intent.length != intent.inline_payload.size() || intent.payload_length != intent.inline_payload.size() ||
        intent.offset || intent.timestamp_utc || intent.replace_if_exists || !intent.secondary_path.empty() ||
        intent.payload_spool_offset || intent.unlink_outcome ||
        next_sequence_ > (std::numeric_limits<std::uint64_t>::max)() - 8)
    {
        error = "SnapshotRuntimeEvidenceCapacityAdmissionInvalid";
        return false;
    }
    WriteAheadLog::Record mutation{};
    mutation.volume_identity = EffectiveVolumeIdentity(volume_identity_);
    mutation.transaction_id = next_transaction_id_;
    mutation.sequence = next_sequence_;
    mutation.operation = ToWalOperation(intent.kind);
    mutation.object_id = intent.object_id;
    mutation.parent_object_id = intent.generation;
    mutation.payload_length = intent.payload_length;
    mutation.payload_sha256 = intent.payload_checksum;
    mutation.inline_payload = intent.inline_payload;
    mutation.path_utf8 = WideToUtf8(intent.path);
    if (!WriteAheadLog::SnapshotIntentIsConsistent(mutation))
    {
        error = "SnapshotRuntimeEvidenceCapacityAdmissionInvalid";
        return false;
    }
    std::vector<WriteAheadLog::Record> records{std::move(mutation)};
    // Include the actual acceptance label plus durability and terminal records
    // before accepting bytes. Extra fixed records conservatively cover cleanup.
    for (unsigned i = 0; i < 7; ++i)
    {
        WriteAheadLog::Record terminal{};
        terminal.volume_identity = EffectiveVolumeIdentity(volume_identity_);
        terminal.sequence = next_sequence_ + i;
        terminal.transaction_id = next_transaction_id_;
        terminal.operation = WriteAheadLog::OperationKind::TransactionMarker;
        terminal.state = WriteAheadLog::RecordState::Accepted;
        terminal.flags = kWalFlagAccepted;
        terminal.logical_length = 1;
        if (i == 0) terminal.path_utf8 = WideToUtf8(safety_level_);
        records.push_back(std::move(terminal));
    }
    if (!journal_.EvidenceAppendCapacityAvailable(records, {64ull << 20, 1000000}, 256ull << 20))
    {
        error = "SnapshotRuntimeEvidenceCapacityExceeded";
        return false;
    }
    return true;
}

bool TransactionManager::NativeSparseEvidenceCapacityAvailable(const MutationIntent& intent, std::string& error) const
{
    error.clear();
    const auto fail=[&](const char* text){error=text;return false;};
    if(journal_protection_ || state_!=State::Idle || !recovery_state_valid_ || !pending_mutations_.empty() ||
        !buffered_prepared_records_.empty() || watermarks_.accepted_sequence!=watermarks_.apfs_durable_sequence ||
        watermarks_.accepted_sequence!=watermarks_.cleanup_sequence || intent.kind!=MutationKind::NativeSparse ||
        intent.length!=intent.inline_payload.size() || intent.payload_length!=intent.inline_payload.size() ||
        intent.offset || intent.timestamp_utc || intent.replace_if_exists || !intent.secondary_path.empty() ||
        intent.payload_spool_offset || intent.unlink_outcome || next_sequence_>UINT64_MAX-8)
        return fail("SparseEvidenceCapacityAdmissionInvalid");
    WriteAheadLog::Record mutation{};mutation.volume_identity=EffectiveVolumeIdentity(volume_identity_);
    mutation.transaction_id=next_transaction_id_;mutation.sequence=next_sequence_;mutation.operation=WriteAheadLog::OperationKind::NativeSparse;
    mutation.object_id=intent.object_id;mutation.parent_object_id=intent.generation;
    mutation.logical_length=intent.length;mutation.payload_length=intent.payload_length;
    mutation.inline_payload=intent.inline_payload;mutation.payload_sha256=intent.payload_checksum;mutation.path_utf8=WideToUtf8(intent.path);
    if(!NativeSparseV2WalIsConsistent(mutation))return fail("SparseEvidenceCapacityAdmissionInvalid");
    std::vector<WriteAheadLog::Record> records{std::move(mutation)};
    for(unsigned i=0;i<7;++i){WriteAheadLog::Record marker{};
        marker.volume_identity=EffectiveVolumeIdentity(volume_identity_);marker.sequence=next_sequence_+i;marker.transaction_id=next_transaction_id_;
        marker.operation=WriteAheadLog::OperationKind::TransactionMarker;marker.state=WriteAheadLog::RecordState::Accepted;
        marker.flags=kWalFlagAccepted;marker.logical_length=1;if(!i)marker.path_utf8=WideToUtf8(safety_level_);records.push_back(std::move(marker));}
    if(!journal_.EvidenceAppendCapacityAvailable(records,{(std::min)(journal_max_bytes_,64ull<<20),1000000},256ull<<20))
        return fail("SparseEvidenceCapacityExceeded");
    return true;
}

bool TransactionManager::NativeCloneRangeEvidenceCapacityAvailable(const MutationIntent& intent, std::string& error) const
{
    error.clear(); const auto fail = [&](const char* text) { error = text; return false; };
    if (journal_protection_ || state_ != State::Idle || !recovery_state_valid_ || !pending_mutations_.empty() ||
        !buffered_prepared_records_.empty() || watermarks_.accepted_sequence != watermarks_.apfs_durable_sequence ||
        watermarks_.accepted_sequence != watermarks_.cleanup_sequence || intent.kind != MutationKind::CloneRange ||
        intent.length != intent.inline_payload.size() || intent.payload_length != intent.inline_payload.size() ||
        intent.offset || intent.timestamp_utc || intent.replace_if_exists || intent.payload_spool_offset ||
        intent.unlink_outcome || next_sequence_ > UINT64_MAX - 8) return fail("CloneRangeEvidenceCapacityAdmissionInvalid");
    WriteAheadLog::Record mutation{}; mutation.volume_identity = EffectiveVolumeIdentity(volume_identity_);
    mutation.transaction_id = next_transaction_id_; mutation.sequence = next_sequence_; mutation.operation = WriteAheadLog::OperationKind::CloneRange;
    mutation.object_id = intent.object_id; mutation.parent_object_id = intent.generation;
    mutation.logical_length = intent.length; mutation.payload_length = intent.payload_length; mutation.inline_payload = intent.inline_payload;
    mutation.payload_sha256 = intent.payload_checksum; mutation.path_utf8 = WideToUtf8(intent.path); mutation.secondary_path_utf8 = WideToUtf8(intent.secondary_path);
    if (!NativeCloneRangeWalIsConsistent(mutation)) return fail("CloneRangeEvidenceCapacityAdmissionInvalid");
    std::vector<WriteAheadLog::Record> records{std::move(mutation)};
    for (unsigned i = 0; i < 7; ++i) {
        WriteAheadLog::Record marker{}; marker.volume_identity = EffectiveVolumeIdentity(volume_identity_);
        marker.sequence = next_sequence_ + i; marker.transaction_id = next_transaction_id_;
        marker.operation = WriteAheadLog::OperationKind::TransactionMarker; marker.state = WriteAheadLog::RecordState::Accepted;
        marker.flags = kWalFlagAccepted; marker.logical_length = 1; if (!i) marker.path_utf8 = WideToUtf8(safety_level_);
        records.push_back(std::move(marker));
    }
    if (!journal_.EvidenceAppendCapacityAvailable(records, {(std::min)(journal_max_bytes_, 64ull << 20), 1000000}, 256ull << 20))
        return fail("CloneRangeEvidenceCapacityExceeded");
    return true;
}

bool TransactionManager::ProtectedAcceptanceCapacityAvailable(
    std::span<const MutationIntent> mutations, std::string& error) const
{
    error.clear();
    const auto fail = [&](const char* reason) { error = reason; return false; };
    if (!journal_protection_ || !recovery_state_valid_ || state_ != State::Idle ||
        !pending_mutations_.empty() || !buffered_prepared_records_.empty() || mutations.empty() ||
        mutations.size() > 256 || next_sequence_ > UINT64_MAX - mutations.size() - 8)
        return fail("ProtectedAcceptanceCapacityAdmissionInvalid");
    try {
        const auto& protection = *journal_protection_;
        WriteAheadLog::ProtectedHistoryHead head;
        std::error_code ec;
        const auto exists = std::filesystem::exists(journal_path_, ec);
        if (ec || (exists && !journal_.CaptureProtectedHistoryHead(head)))
            return fail("ProtectedAcceptanceCapacityEvidenceUnavailable");
        // The initial protected anchor is smaller than this reserve. Existing
        // files use their authenticated exact byte/record counts instead.
        std::uint64_t bytes = exists ? head.bytes : 512, count = exists ? head.records : 0;
        const auto capacity = (std::min)({journal_max_bytes_, protection.read_limits.bytes,
            protection.max_allocation_bytes / 4});
        const auto account = [&](const WriteAheadLog::Record& record) {
            const auto encoded = WriteAheadLog::EncodeForTest(record);
            const auto extra = encoded.size() + journal::kJournalRecordHeaderBytes + crypto::kGcmTagBytes;
            if (encoded.empty() || bytes > capacity || extra > capacity - bytes) return false;
            bytes += extra; ++count;
            return count <= protection.read_limits.records &&
                count <= (protection.max_allocation_bytes - bytes * 4) / (2 * sizeof(WriteAheadLog::Record) + 4);
        };
        const auto identity = EffectiveVolumeIdentity(volume_identity_);
        auto sequence = next_sequence_;
        for (const auto& intent : mutations) {
            if (intent.kind != MutationKind::Write || intent.inline_payload.empty() || intent.inline_payload.size() > 4096 ||
                intent.length != intent.inline_payload.size() || intent.payload_length != intent.inline_payload.size() ||
                intent.replace_if_exists || intent.unlink_outcome || !intent.secondary_path.empty() || intent.payload_spool_offset)
                return fail("ProtectedAcceptanceCapacityAdmissionInvalid");
            WriteAheadLog::Record record;
            record.volume_identity = identity; record.transaction_id = next_transaction_id_; record.sequence = sequence++;
            record.operation = WriteAheadLog::OperationKind::Write; record.state = WriteAheadLog::RecordState::Prepared;
            record.object_id = intent.object_id; record.parent_object_id = intent.generation;
            record.logical_offset = intent.offset; record.logical_length = intent.length;
            record.payload_length = intent.payload_length; record.payload_sha256 = intent.payload_checksum;
            record.inline_payload = intent.inline_payload; record.path_utf8 = WideToUtf8(intent.path);
            if (!account(record)) return fail("ProtectedAcceptanceCapacityExceeded");
        }
        for (unsigned index = 0; index < 7; ++index) {
            WriteAheadLog::Record marker;
            marker.volume_identity = identity; marker.transaction_id = next_transaction_id_; marker.sequence = sequence++;
            marker.operation = WriteAheadLog::OperationKind::TransactionMarker; marker.state = WriteAheadLog::RecordState::Accepted;
            marker.flags = kWalFlagAccepted; marker.logical_length = mutations.size(); marker.path_utf8 = WideToUtf8(safety_level_);
            if (!account(marker)) return fail("ProtectedAcceptanceCapacityExceeded");
        }
        return true;
    } catch (...) { return fail("ProtectedAcceptanceCapacityEvidenceUnavailable"); }
}

bool TransactionManager::ProtectedMutationCapacityAvailable(const MutationIntent& intent, std::string& error)
{
    std::lock_guard append_lock(deferred_wal_append_mutex_);
    error.clear();
    const auto fail = [&](const char* reason) { error = reason; return false; };
    const auto valid_path = [](const std::wstring& p) {
        return !p.empty() && p.size() <= 65536 && p.find(L'\0') == std::wstring::npos;
    };
    if (!ProtectedSpoolOwnerValid() || !next_sequence_ || next_sequence_ > UINT64_MAX - 9 ||
        !next_transaction_id_ || next_transaction_id_ == UINT64_MAX || !intent.object_id ||
        !valid_path(intent.path) || intent.secondary_path.size() > 65536 || intent.timestamp_utc ||
        (intent.unlink_outcome && intent.unlink_outcome->path_utf8.size() > 65536) ||
        (intent.wal_sequence && intent.wal_sequence != next_sequence_))
        return fail("ProtectedMutationCapacityAdmissionInvalid");
    const bool data = intent.kind == MutationKind::Write || intent.kind == MutationKind::CreateFile;
    const bool inode_metadata = intent.kind == MutationKind::SetInodeMetadata;
    const bool hard_link = intent.kind == MutationKind::HardLink;
    const bool attribute = intent.kind == MutationKind::SetExtendedAttribute ||
        intent.kind == MutationKind::RemoveExtendedAttribute;
    const bool zero_hash = std::all_of(intent.payload_checksum.begin(), intent.payload_checksum.end(), [](auto b) { return b == 0; });
    if (inode_metadata) {
        if ((intent.inline_payload.size() != InodeMetadataPatch::EncodedSize &&
                intent.inline_payload.size() != InodeMetadataPatch::BsdEncodedSize) ||
            intent.length != intent.inline_payload.size() || intent.payload_length != intent.inline_payload.size() ||
            intent.offset || intent.payload_spool_offset || !intent.secondary_path.empty() ||
            intent.replace_if_exists || intent.unlink_outcome)
            return fail("ProtectedMutationCapacityAdmissionInvalid");
    } else if (hard_link) {
        if (!intent.generation || intent.offset || intent.payload_spool_offset || intent.wal_sequence ||
            intent.replace_if_exists || intent.unlink_outcome || !valid_path(intent.secondary_path) ||
            intent.inline_payload.empty() || intent.inline_payload.size() > MaxNativeHardLinkProofBytes ||
            intent.length != intent.inline_payload.size() || intent.payload_length != intent.inline_payload.size())
            return fail("ProtectedMutationCapacityAdmissionInvalid");
    } else if (attribute) {
        const bool set = intent.kind == MutationKind::SetExtendedAttribute;
        if (!intent.generation || intent.offset || intent.length || intent.payload_spool_offset ||
            intent.wal_sequence || intent.replace_if_exists || intent.unlink_outcome ||
            intent.payload_length != intent.inline_payload.size() ||
            intent.inline_payload.size() > WriteAheadLog::MaxExtendedAttributePayloadBytes ||
            (!set && (intent.payload_length || !zero_hash)))
            return fail("ProtectedMutationCapacityAdmissionInvalid");
    } else if (data) {
        const auto limit = intent.kind == MutationKind::CreateFile ? 4096ull : 256ull * 1024;
        if (intent.length != intent.payload_length || intent.payload_length > limit ||
            intent.inline_payload.size() > limit || intent.offset > UINT64_MAX - intent.length ||
            !intent.secondary_path.empty() || intent.replace_if_exists || intent.unlink_outcome ||
            (!intent.payload_length && (intent.payload_spool_offset || !intent.inline_payload.empty())) ||
            (intent.payload_length && intent.inline_payload.empty() &&
                (!intent.generation || intent.wal_sequence != next_sequence_ || zero_hash ||
                    intent.payload_spool_offset > UINT64_MAX - intent.payload_length - 80)) ||
            (!intent.inline_payload.empty() && intent.payload_spool_offset))
            return fail("ProtectedMutationCapacityAdmissionInvalid");
    } else {
        if (intent.payload_length || intent.payload_spool_offset || !intent.inline_payload.empty() || !zero_hash)
            return fail("ProtectedMutationCapacityAdmissionInvalid");
        switch (intent.kind) {
        case MutationKind::CreateDirectory:
            if (!intent.generation || intent.length || !intent.secondary_path.empty() || intent.replace_if_exists || intent.unlink_outcome)
                return fail("ProtectedMutationCapacityAdmissionInvalid");
            break;
        case MutationKind::SetFileSize:
            if (intent.offset || !intent.secondary_path.empty() || intent.replace_if_exists || intent.unlink_outcome)
                return fail("ProtectedMutationCapacityAdmissionInvalid");
            break;
        case MutationKind::Rename:
            if (!valid_path(intent.secondary_path) || !intent.generation || !intent.offset || intent.length || intent.unlink_outcome)
                return fail("ProtectedMutationCapacityAdmissionInvalid");
            break;
        case MutationKind::Delete:
            if (!intent.secondary_path.empty() || intent.offset || intent.length || intent.replace_if_exists)
                return fail("ProtectedMutationCapacityAdmissionInvalid");
            break;
        default: return fail("ProtectedMutationCapacityAdmissionInvalid");
        }
    }
    try {
        const auto& protection = *journal_protection_;
        WriteAheadLog::ProtectedHistoryHead head;
        std::error_code ec;
        const auto exists = std::filesystem::exists(journal_path_, ec);
        if (ec) return fail("ProtectedMutationCapacityEvidenceUnavailable");
        if (exists) {
            if (!journal_.CaptureProtectedHistoryHead(head) || head.last_sequence != next_sequence_ - 1)
                return fail("ProtectedMutationCapacityEvidenceUnavailable");
        } else {
            auto read = journal_.ReadAllWithExclusiveWriterLease(protection.read_limits);
            OriginalHistoryCleanup cleanup{read.records};
            if (read.status != WriteAheadLog::ReadStatus::Ok || read.recovered_torn_tail ||
                !read.records.empty() || next_sequence_ != 1)
                return fail("ProtectedMutationCapacityEvidenceUnavailable");
        }
        std::uint64_t bytes = exists ? head.bytes : 512, count = exists ? head.records : 0;
        const auto capacity = (std::min)({journal_max_bytes_, protection.read_limits.bytes,
            protection.max_allocation_bytes / 4});
        const auto account = [&](const WriteAheadLog::Record& record) {
            auto encoded = WriteAheadLog::EncodeForTest(record);
            const auto size = encoded.size();
            if (size) SecureZeroMemory(encoded.data(), size);
            const auto extra = size + journal::kJournalRecordHeaderBytes + crypto::kGcmTagBytes;
            if (!size || size > journal::kMaxJournalPlaintextBytes || bytes > capacity || extra > capacity - bytes) return false;
            bytes += extra; ++count;
            return count <= protection.read_limits.records &&
                count <= (protection.max_allocation_bytes - bytes * 4) / (2 * sizeof(WriteAheadLog::Record) + 4);
        };
        std::vector<WriteAheadLog::Record> projected(1); OriginalHistoryCleanup cleanup{projected};
        auto& record = projected.front();
        record.volume_identity = EffectiveVolumeIdentity(volume_identity_);
        record.transaction_id = next_transaction_id_; record.sequence = next_sequence_;
        record.operation = ToWalOperation(intent.kind); record.state = WriteAheadLog::RecordState::Prepared;
        record.object_id = intent.object_id; record.parent_object_id = intent.generation;
        record.payload_spool_id = !inode_metadata && !attribute && !hard_link && intent.payload_length ? next_sequence_ : 0;
        record.payload_offset = intent.payload_spool_offset; record.payload_length = intent.payload_length;
        record.logical_offset = intent.offset; record.logical_length = inode_metadata || attribute ? 0 : intent.length;
        record.flags = intent.replace_if_exists ? kWalFlagReplaceIfExists : 0;
        record.path_utf8 = WideToUtf8(intent.path); record.secondary_path_utf8 = WideToUtf8(intent.secondary_path);
        record.payload_sha256 = intent.payload_checksum; record.inline_payload = intent.inline_payload;
        record.unlink_outcome = intent.unlink_outcome;
        if (record.path_utf8.size() > 65536 || record.secondary_path_utf8.size() > 65536 ||
            !WriteAheadLog::InlinePayloadIsConsistent(record) || !WriteAheadLog::UnlinkOutcomeIsConsistent(record) ||
            (hard_link && !WriteAheadLog::NativeHardLinkIsConsistent(record)) ||
            (inode_metadata && !WriteAheadLog::InodeMetadataMutationIsConsistent(record)) ||
            (attribute && !WriteAheadLog::ExtendedAttributeMutationIsConsistent(record)))
            return fail("ProtectedMutationCapacityAdmissionInvalid");
        if (!account(record)) return fail("ProtectedMutationCapacityExceeded");
        cleanup.Clear(); projected.resize(1);
        auto& marker = projected.front();
        marker.volume_identity = EffectiveVolumeIdentity(volume_identity_); marker.transaction_id = next_transaction_id_;
        marker.operation = WriteAheadLog::OperationKind::TransactionMarker; marker.state = WriteAheadLog::RecordState::Accepted;
        marker.flags = kWalFlagAccepted; marker.logical_length = 1; marker.path_utf8 = WideToUtf8(safety_level_);
        for (unsigned n = 0; n < 7; ++n) {
            marker.sequence = next_sequence_ + n + 1;
            if (!account(marker)) return fail("ProtectedMutationCapacityExceeded");
        }
        return ProtectedSpoolOwnerValid() || fail("ProtectedMutationCapacityEvidenceUnavailable");
    } catch (...) { return fail("ProtectedMutationCapacityEvidenceUnavailable"); }
}

void TransactionManager::SetVolumeIdentity(std::wstring volume_identity)
{
    if (journal_protection_)
    {
        if (volume_identity != volume_identity_)
        {
            recovery_state_valid_ = false;
            InvalidateFinalizationCoverage(true);
        }
        return;
    }
    volume_identity_ = std::move(volume_identity);
    {
        std::lock_guard<std::mutex> lock(deferred_wal_state_mutex_);
        deferred_wal_pending_sequence_ = 0;
        deferred_wal_durable_sequence_ = 0;
        deferred_wal_flush_in_progress_ = false;
        deferred_wal_flush_failed_ = false;
    }
    ConfigureJournal();
    journal_state_writer_generation_ = 0;
    InvalidateFinalizationCoverage(false);
    if (!journal_path_.empty())
    {
        (void)SeedIdsFromExistingJournal(true);
    }
}

bool TransactionManager::OpenProtectedJournal(std::wstring path, std::wstring identity,
    WriteAheadLog::ProtectedPersistence protection, std::string& error)
{
    return OpenProtectedJournalImpl(std::move(path), std::move(identity), std::move(protection), false, error);
}

bool TransactionManager::OpenProtectedStartupJournal(std::wstring path, std::wstring identity,
    WriteAheadLog::ProtectedPersistence protection, std::string& error)
{
    return OpenProtectedJournalImpl(std::move(path), std::move(identity), std::move(protection), true, error);
}

bool TransactionManager::OpenProtectedJournalImpl(std::wstring path, std::wstring identity,
    WriteAheadLog::ProtectedPersistence protection, bool preserve_evidence, std::string& error)
{
    error.clear();
    if (state_ != State::Idle || journal_protection_ || !journal_path_.empty() ||
        !volume_identity_.empty() || current_transaction_id_ || next_transaction_id_ != 1 ||
        next_sequence_ != 1 || !recovery_state_valid_ ||
        path.empty() || identity.empty() || !std::filesystem::path(path).is_absolute())
    {
        error = "ProtectedJournalFreshOwnerRequired";
        return false;
    }
    journal_protection_ = std::move(protection);
    journal_path_ = std::move(path);
    volume_identity_ = std::move(identity);
    preserve_startup_evidence_ = preserve_evidence;
    ConfigureJournal();
    if (!SeedIdsFromExistingJournal(true))
    {
        error = "ProtectedJournalEvidenceInvalid";
        return false;
    }
    return true;
}

bool TransactionManager::EnrollCanonicalJournalIdentity(std::wstring canonical_identity)
{
    if (canonical_identity.empty())
    {
        return false;
    }
    if (!canonical_journal_identity_.empty())
    {
        return canonical_journal_identity_ == canonical_identity;
    }
    canonical_journal_identity_ = std::move(canonical_identity);
    return true;
}

bool TransactionManager::AcquireJournalOwnership(std::string& error)
{
    if (journal_.HasExclusiveWriterLease())
    {
        return true;
    }
    if (journal_path_.empty())
    {
        error = "SnapshotJournalPathMissing";
        return false;
    }
    if (!journal_.AcquireWriterLeaseOnly())
    {
        error = "SnapshotJournalOwnerActive";
        return false;
    }
    return true;
}

void TransactionManager::SetJournalMaxBytesForTest(std::uint64_t max_bytes)
{
    if (journal_protection_)
    {
        if (max_bytes != journal_max_bytes_)
        {
            recovery_state_valid_ = false;
            InvalidateFinalizationCoverage(true);
        }
        return;
    }
    journal_max_bytes_ = max_bytes;
}

void TransactionManager::SetJournalFaultInjectionHook(WriteAheadLog::FaultInjectionHook hook)
{
    journal_.SetFaultInjectionHook(std::move(hook));
}

void TransactionManager::InvalidateJournalReadCacheForTest() noexcept
{
    // Exercise a real history read without changing the held journal or its owner.
    InvalidateFinalizationCoverage(false);
}

std::uint64_t TransactionManager::CurrentTransactionId() const noexcept
{
    return current_transaction_id_;
}

bool TransactionManager::RetainAcceptedSequenceProof(std::uint64_t transaction_id)
{
    if (transaction_id == 0 ||
        state_ != State::Active ||
        current_transaction_id_ != transaction_id)
    {
        return false;
    }

    const auto existing = accepted_transaction_sequences_.find(transaction_id);
    if (existing != accepted_transaction_sequences_.end())
    {
        if (existing->second.retain_count == (std::numeric_limits<std::size_t>::max)())
        {
            return false;
        }
        ++existing->second.retain_count;
        return true;
    }
    if (accepted_transaction_sequences_.size() >= MaxRetainedAcceptedSequenceProofs())
    {
        return false;
    }

    accepted_transaction_sequences_.emplace(
        transaction_id,
        AcceptedSequenceProof{0, 1});
    return true;
}

void TransactionManager::ReleaseAcceptedSequenceProof(std::uint64_t transaction_id) noexcept
{
    const auto existing = accepted_transaction_sequences_.find(transaction_id);
    if (existing == accepted_transaction_sequences_.end())
    {
        return;
    }
    if (existing->second.retain_count > 1)
    {
        --existing->second.retain_count;
        return;
    }
    accepted_transaction_sequences_.erase(existing);
}

std::optional<std::uint64_t> TransactionManager::AcceptedSequenceForTransaction(
    std::uint64_t transaction_id) const noexcept
{
    if (transaction_id == 0)
    {
        return std::nullopt;
    }

    const auto it = accepted_transaction_sequences_.find(transaction_id);
    if (it == accepted_transaction_sequences_.end())
    {
        return std::nullopt;
    }

    return it->second.accepted_sequence == 0
        ? std::nullopt
        : std::optional<std::uint64_t>{it->second.accepted_sequence};
}

std::size_t TransactionManager::RetainedAcceptedSequenceProofCount() const noexcept
{
    return accepted_transaction_sequences_.size();
}

std::size_t TransactionManager::TrackedAcceptedBoundaryCount() const noexcept
{
    return accepted_boundaries_.size();
}

std::uint64_t TransactionManager::NextMutationSequence() const noexcept
{
    return next_sequence_ == (std::numeric_limits<std::uint64_t>::max)()
        ? 0
        : next_sequence_;
}

std::uint64_t TransactionManager::LastCommittedSequence() const noexcept
{
    return last_committed_sequence_;
}

TransactionManager::DurabilityWatermarks TransactionManager::Watermarks() const noexcept
{
    return watermarks_;
}

bool TransactionManager::HasUnappliedAcceptedWork() const noexcept
{
    return watermarks_.accepted_sequence > watermarks_.apfs_durable_sequence;
}

bool TransactionManager::RecoveryStateValid() const noexcept
{
    return recovery_state_valid_;
}

bool TransactionManager::CanClearRecoveryState() const
{
    if (!recovery_state_valid_ || state_ != State::Idle)
    {
        return false;
    }
    if (!journal_path_.empty() && !JournalStateMatchesWriterLease())
    {
        return false;
    }
    return watermarks_.accepted_sequence <= watermarks_.apfs_durable_sequence &&
           watermarks_.apfs_durable_sequence <= watermarks_.cleanup_sequence;
}

std::uint64_t TransactionManager::ValidatedCleanJournalGeneration() const
{
    if (journal_path_.empty() || !recovery_state_valid_ || state_ != State::Idle ||
        !pending_mutations_.empty() || !accepted_boundaries_.empty() ||
        watermarks_.accepted_sequence != watermarks_.apfs_durable_sequence ||
        watermarks_.apfs_durable_sequence != watermarks_.cleanup_sequence ||
        last_committed_sequence_ > watermarks_.cleanup_sequence ||
        highest_checkpointed_marker_sequence_ > watermarks_.cleanup_sequence ||
        finalization_coverage_trust_ != FinalizationCoverageTrust::Trusted ||
        journal_state_writer_generation_ == 0 ||
        finalization_coverage_writer_generation_ != journal_state_writer_generation_)
    {
        return 0;
    }
    const auto generation = journal_.ValidatedAppendLeaseGeneration();
    return generation == journal_state_writer_generation_ ? generation : 0;
}

bool TransactionManager::LoadUnappliedAcceptedTransactions(
    std::vector<AcceptedTransaction>& transactions,
    std::string* failure_reason)
{
    return LoadAcceptedTransactionsAfter(
        false,
        transactions,
        failure_reason);
}

bool TransactionManager::LoadAcceptedTransactionsSinceCleanup(
    std::vector<AcceptedTransaction>& transactions,
    std::string* failure_reason,
    WalReadLimits limits)
{
    return LoadAcceptedTransactionsAfter(
        true,
        transactions,
        failure_reason, limits);
}

bool TransactionManager::LoadRequiredCheckpointXidsSinceCleanup(
    std::vector<std::uint64_t>& checkpoint_xids,
    std::string* failure_reason)
{
    checkpoint_xids.clear();
    if (failure_reason) failure_reason->clear();
    if (checkpoint_pin_census_trusted_ && recovery_state_valid_ &&
        (state_ == State::Idle || state_ == State::Active) &&
        watermarks_.cleanup_sequence <= watermarks_.apfs_durable_sequence &&
        watermarks_.apfs_durable_sequence <= watermarks_.accepted_sequence &&
        highest_checkpointed_marker_sequence_ <= watermarks_.cleanup_sequence &&
        finalization_coverage_trust_ == FinalizationCoverageTrust::Trusted &&
        accepted_checkpoint_pins_.size() == accepted_boundaries_.size())
    {
        const auto generation = journal_.ValidatedAppendLeaseGeneration();
        if (generation != 0 && generation == journal_state_writer_generation_ &&
            generation == finalization_coverage_writer_generation_ &&
            generation == checkpoint_pin_census_writer_generation_)
        {
            checkpoint_xids.reserve(cached_checkpoint_pin_entries_);
            for (const auto& [sequence, pins] : accepted_checkpoint_pins_)
                checkpoint_xids.insert(checkpoint_xids.end(), pins.begin(), pins.end());
            std::sort(checkpoint_xids.begin(), checkpoint_xids.end());
            checkpoint_xids.erase(std::unique(checkpoint_xids.begin(), checkpoint_xids.end()), checkpoint_xids.end());
            return true;
        }
    }
    InvalidateCheckpointPinCensus();
    if (recovery_state_valid_ && (state_ == State::Idle || state_ == State::Active) &&
        watermarks_.accepted_sequence == watermarks_.apfs_durable_sequence &&
        watermarks_.apfs_durable_sequence == watermarks_.cleanup_sequence &&
        last_committed_sequence_ <= watermarks_.cleanup_sequence &&
        highest_checkpointed_marker_sequence_ <= watermarks_.cleanup_sequence &&
        finalization_coverage_trust_ == FinalizationCoverageTrust::Trusted &&
        JournalStateMatchesWriterLease())
    {
        // The owner validated this history and durably cleaned every accepted boundary.
        // Retain that proof only while the same exclusive, unchanged file is still held.
        const auto generation = journal_.ValidatedAppendLeaseGeneration();
        if (generation != 0 && generation == journal_state_writer_generation_ &&
            generation == finalization_coverage_writer_generation_) return true;
    }
    std::vector<AcceptedTransaction> transactions;
    if (!LoadAcceptedTransactionsSinceCleanup(transactions, failure_reason))
    {
        return false;
    }

    checkpoint_xids.reserve(transactions.size());
    for (const auto& transaction : transactions)
    {
        if (transaction.preimage_checkpoint_xid == 0)
        {
            checkpoint_xids.clear();
            if (failure_reason)
            {
                *failure_reason = "Accepted WAL transaction has no preimage checkpoint XID";
            }
            return false;
        }
        checkpoint_xids.push_back(transaction.preimage_checkpoint_xid);
        for(const auto& record:transaction.mutations)if(record.operation==WriteAheadLog::OperationKind::CreateSnapshot||record.operation==WriteAheadLog::OperationKind::DeleteSnapshot){
            NativeSnapshotIntent intent;if(!DecodeNativeSnapshotIntent(record.inline_payload,intent)){checkpoint_xids.clear();if(failure_reason)*failure_reason="Snapshot WAL pin payload invalid";return false;}
            checkpoint_xids.insert(checkpoint_xids.end(),intent.pins.begin(),intent.pins.end());
        }
    }

    std::sort(checkpoint_xids.begin(), checkpoint_xids.end());
    checkpoint_xids.erase(
        std::unique(checkpoint_xids.begin(), checkpoint_xids.end()),
        checkpoint_xids.end());
    return true;
}

bool TransactionManager::LoadAcceptedTransactionsAfter(
    bool include_checkpointed_transactions,
    std::vector<AcceptedTransaction>& transactions,
    std::string* failure_reason,
    WalReadLimits limits)
{
    transactions.clear();
    if (failure_reason)
    {
        failure_reason->clear();
    }
    const auto fail = [&](const char* reason)
    {
        transactions.clear();
        if (failure_reason)
        {
            *failure_reason = reason;
        }
        return false;
    };
    if (!recovery_state_valid_)
    {
        return fail("WAL watermark state is invalid");
    }
    if (journal_path_.empty())
    {
        const auto lower_sequence_exclusive = include_checkpointed_transactions
            ? watermarks_.cleanup_sequence
            : watermarks_.apfs_durable_sequence;
        const auto has_work = include_checkpointed_transactions
            ? watermarks_.accepted_sequence > lower_sequence_exclusive
            : HasUnappliedAcceptedWork();
        return has_work
            ? fail("Accepted work has no WAL path")
            : true;
    }

    if (state_ != State::Idle && state_ != State::Active)
    {
        return fail("WAL cannot be read while a transaction is committing or failed");
    }
    if (state_ == State::Active && !JournalStateMatchesWriterLease())
    {
        recovery_state_valid_ = false;
        InvalidateFinalizationCoverage(true);
        return fail("Active transaction lost exclusive WAL ownership");
    }

    const auto existing = preserve_startup_evidence_
        ? journal_.ReadStartupEvidence(limits, 256ull << 20)
        : journal_.ReadAllWithExclusiveWriterLease(limits);
    if (existing.status == WriteAheadLog::ReadStatus::ResourceLimit)
        return fail("WAL read resource budget exceeded");
    if (existing.status != WriteAheadLog::ReadStatus::Ok)
    {
        recovery_state_valid_ = false;
        InvalidateFinalizationCoverage(true);
        return fail("WAL could not be read for replay");
    }
    if (!ValidateWalSemantics(existing.records))
    {
        recovery_state_valid_ = false;
        InvalidateFinalizationCoverage(true);
        return fail("WAL semantic validation failed");
    }
    const auto writer_generation = journal_.ExclusiveWriterLeaseGeneration();
    if (state_ == State::Idle)
    {
        if (!SeedIdsFromJournalRecords(existing.records, writer_generation))
        {
            return fail("WAL state could not be reseeded after lease acquisition");
        }
    }
    else if (writer_generation == 0 ||
             writer_generation != journal_state_writer_generation_)
    {
        recovery_state_valid_ = false;
        InvalidateFinalizationCoverage(true);
        return fail("Active transaction changed WAL ownership during validation");
    }

    return CollectAcceptedTransactions(existing.records, include_checkpointed_transactions, transactions, failure_reason);
}

bool TransactionManager::CollectAcceptedTransactions(const std::vector<WriteAheadLog::Record>& records,
    bool include_checkpointed_transactions, std::vector<AcceptedTransaction>& transactions, std::string* failure_reason)
{
    transactions.clear();
    if(failure_reason) failure_reason->clear();
    const auto fail=[&](const char* reason){transactions.clear();if(failure_reason)*failure_reason=reason;return false;};
    const auto lower_sequence_exclusive = include_checkpointed_transactions
        ? watermarks_.cleanup_sequence
        : watermarks_.apfs_durable_sequence;

    std::unordered_map<std::uint64_t, std::vector<WriteAheadLog::Record>> prepared_by_transaction;
    std::unordered_set<std::uint64_t> terminal_transactions;
    std::uint64_t previous_sequence = 0;
    for (const auto& record : records)
    {
        if (record.operation == WriteAheadLog::OperationKind::CompactionIndex)
        {
            continue;
        }
        if (record.sequence == 0 || record.sequence <= previous_sequence)
        {
            return fail("WAL sequence ordering is invalid");
        }
        previous_sequence = record.sequence;

        if (record.operation == WriteAheadLog::OperationKind::DurabilityWatermark)
        {
            continue;
        }
        if (record.operation == WriteAheadLog::OperationKind::TransactionMarker)
        {
            if (record.transaction_id == 0 || !terminal_transactions.insert(record.transaction_id).second)
            {
                return fail("WAL transaction terminal marker is invalid");
            }
            auto prepared = prepared_by_transaction.find(record.transaction_id);
            const auto is_accepted_marker =
                record.state == WriteAheadLog::RecordState::Accepted ||
                (include_checkpointed_transactions &&
                 record.state == WriteAheadLog::RecordState::Checkpointed &&
                 (record.flags & kWalFlagCommitted) != 0);
            if (is_accepted_marker)
            {
                if (record.sequence > watermarks_.accepted_sequence)
                {
                    return fail("Accepted WAL transaction exceeds its watermark");
                }
                if (record.sequence > lower_sequence_exclusive)
                {
                    const bool empty_committed = prepared == prepared_by_transaction.end() &&
                        record.logical_length == 0 && record.state == WriteAheadLog::RecordState::Checkpointed;
                    if (!empty_committed && (prepared == prepared_by_transaction.end() ||
                        prepared->second.size() != record.logical_length))
                    {
                        return fail("Accepted WAL transaction is incomplete");
                    }
                    transactions.push_back(AcceptedTransaction{
                        record.transaction_id,
                        record.sequence,
                        empty_committed ? std::vector<WriteAheadLog::Record>{} : std::move(prepared->second),
                        record.object_id,
                    });
                }
            }
            if (prepared != prepared_by_transaction.end())
            {
                prepared_by_transaction.erase(prepared);
            }
            continue;
        }

        if (record.state != WriteAheadLog::RecordState::Prepared ||
            record.transaction_id == 0 ||
            terminal_transactions.contains(record.transaction_id))
        {
            return fail("WAL mutation record is not replayable");
        }
        prepared_by_transaction[record.transaction_id].push_back(record);
    }

    const auto expected_latest_sequence = include_checkpointed_transactions
        ? watermarks_.accepted_sequence
        : (HasUnappliedAcceptedWork() ? watermarks_.accepted_sequence : 0);
    if (expected_latest_sequence > lower_sequence_exclusive &&
        (transactions.empty() || transactions.back().accepted_sequence != expected_latest_sequence))
    {
        return fail("Accepted WAL watermark has no complete transaction");
    }
    return true;
}

#include "TransactionManagerRetainedHistory.inc"
#include "TransactionManagerFusionContinuation.inc"

bool TransactionManager::InspectAcceptedTransactionsReadOnly(const std::filesystem::path& path,
    const std::string& identity, std::vector<AcceptedTransaction>& transactions,
    DurabilityWatermarks& watermarks, std::string& error)
{
    transactions.clear();watermarks={};error.clear();
    const auto existing=WriteAheadLog::ReadAll(path,identity);
    if(existing.status!=WriteAheadLog::ReadStatus::Ok || existing.recovered_torn_tail) {
        error="VolumeManagementWalReadOnlyInspectionFailed";return false;
    }
    TransactionManager inspector(L"Strict");
    if(!inspector.SeedIdsFromJournalRecords(existing.records,0) ||
        !inspector.CollectAcceptedTransactions(existing.records,true,transactions,&error)) {
        error="VolumeManagementWalSemanticsInvalid:"+error;return false;
    }
    watermarks=inspector.Watermarks();return true;
}

std::size_t TransactionManager::PendingMutationCount() const noexcept
{
    return pending_mutations_.size();
}

std::uint64_t TransactionManager::DurableJournalAppendCount() const noexcept
{
    return durable_journal_append_count_;
}

std::uint64_t TransactionManager::DurableJournalAppendMicroseconds() const noexcept
{
    return durable_journal_append_microseconds_;
}

std::uint64_t TransactionManager::DurableJournalAppendMaxMicroseconds() const noexcept
{
    return durable_journal_append_max_microseconds_;
}

std::uint64_t TransactionManager::DeferredWalGroupFlushCount() const noexcept
{
    std::lock_guard<std::mutex> lock(deferred_wal_state_mutex_);
    return deferred_wal_group_flush_count_;
}

std::uint64_t TransactionManager::DeferredWalGroupFlushMicroseconds() const noexcept
{
    std::lock_guard<std::mutex> lock(deferred_wal_state_mutex_);
    return deferred_wal_group_flush_microseconds_;
}

std::uint64_t TransactionManager::JournalAppendHandleOpenCount() const
{
    return journal_.SnapshotCounters().append_handle_open_count;
}

std::uint64_t TransactionManager::JournalAppendHandleFlushCount() const
{
    return journal_.SnapshotCounters().append_handle_flush_count;
}

std::uint64_t TransactionManager::FinalizationCoverageCacheHitCount() const noexcept
{
    return finalization_coverage_cache_hit_count_;
}

std::uint64_t TransactionManager::FinalizationCoverageWalScanCount() const noexcept
{
    return finalization_coverage_wal_scan_count_;
}

std::uint64_t TransactionManager::FinalizationCoverageWalScanMicroseconds() const noexcept
{
    return finalization_coverage_wal_scan_microseconds_;
}

bool TransactionManager::FlushPreparedRecords()
{
    if(std::any_of(pending_mutations_.begin(),pending_mutations_.end(),[](const auto& m){return m.kind==MutationKind::CloneFile || m.kind==MutationKind::HardLink || m.kind==MutationKind::NativeSparse || m.kind==MutationKind::CloneRange || m.kind==MutationKind::RenameVolume || m.kind==MutationKind::SetVolumeQuotaReserve || m.kind==MutationKind::CreateSnapshot || m.kind==MutationKind::DeleteSnapshot || m.kind==MutationKind::RepairVolumeFileCount;}))return false;
    if (!recovery_state_valid_)
    {
        return false;
    }
    if (buffered_prepared_records_.empty())
    {
        return true;
    }

    if (journal_path_.empty())
    {
        ClearBufferedPreparedRecords();
        return true;
    }
    if (!JournalStateMatchesWriterLease())
    {
        recovery_state_valid_ = false;
        InvalidateFinalizationCoverage(true);
        return false;
    }

    std::unique_lock<std::mutex> append_lock(deferred_wal_append_mutex_);

    const auto first_sequence_to_keep = pending_mutations_.empty()
        ? buffered_prepared_records_.front().sequence
        : pending_mutations_.front().wal_sequence;
    const auto effective_volume_identity = EffectiveVolumeIdentity(volume_identity_);

    std::vector<WriteAheadLog::Record> records;
    records.reserve(buffered_prepared_records_.size());
    for (auto& record : buffered_prepared_records_)
    {
        if (record.volume_identity.empty())
        {
            record.volume_identity = effective_volume_identity;
        }
        if (record.sequence == 0 || record.sequence >= next_sequence_)
        {
            return false;
        }
        records.push_back(record);
    }

    const auto coverage_generation_before_append = journal_state_writer_generation_;
    const bool coverage_trusted_before_append =
        finalization_coverage_trust_ == FinalizationCoverageTrust::Trusted &&
        coverage_generation_before_append != 0 &&
        coverage_generation_before_append == finalization_coverage_writer_generation_;
    bool compacted_for_retry = false;
    const auto append_started = std::chrono::steady_clock::now();
    const auto append_result = journal_.AppendBatchWithResult(
        records,
        true,
        coverage_generation_before_append);
    if (append_result == WriteAheadLog::AppendResult::BytesMayHavePersisted)
    {
        journal_append_ambiguous_ = true;
        recovery_state_valid_ = false;
        journal_state_writer_generation_ = 0;
        InvalidateFinalizationCoverage(true);
        return false;
    }
    if (append_result == WriteAheadLog::AppendResult::RejectedBeforeWrite)
    {
        const auto compaction_result = journal_.CompactWithResult(
            SafeCompactionFloor(first_sequence_to_keep),
            coverage_generation_before_append);
        if (compaction_result != WriteAheadLog::CompactionResult::Succeeded)
        {
            journal_append_ambiguous_ =
                compaction_result == WriteAheadLog::CompactionResult::BytesMayHavePersisted;
            recovery_state_valid_ = false;
            journal_state_writer_generation_ = 0;
            InvalidateFinalizationCoverage(true);
            return false;
        }
        compacted_for_retry = true;
        const auto retry_generation = journal_.ExclusiveWriterLeaseGeneration();
        if (retry_generation == 0)
        {
            recovery_state_valid_ = false;
            journal_state_writer_generation_ = 0;
            InvalidateFinalizationCoverage(true);
            return false;
        }
        journal_state_writer_generation_ = retry_generation;
        const auto retry_result = journal_.AppendBatchWithResult(
            records,
            true,
            retry_generation);
        if (retry_result == WriteAheadLog::AppendResult::BytesMayHavePersisted)
        {
            journal_append_ambiguous_ = true;
            recovery_state_valid_ = false;
            journal_state_writer_generation_ = 0;
            InvalidateFinalizationCoverage(true);
            return false;
        }
        if (retry_result != WriteAheadLog::AppendResult::Succeeded)
        {
            recovery_state_valid_ = false;
            journal_state_writer_generation_ = 0;
            InvalidateFinalizationCoverage(true);
            return false;
        }
    }
    const auto coverage_generation_after_append = journal_.ExclusiveWriterLeaseGeneration();
    if (coverage_generation_after_append == 0)
    {
        recovery_state_valid_ = false;
        journal_state_writer_generation_ = 0;
        InvalidateFinalizationCoverage(true);
        return false;
    }
    journal_state_writer_generation_ = coverage_generation_after_append;
    if (coverage_trusted_before_append &&
        (coverage_generation_after_append == coverage_generation_before_append ||
         compacted_for_retry))
    {
        finalization_coverage_trust_ = FinalizationCoverageTrust::Trusted;
        finalization_coverage_writer_generation_ = coverage_generation_after_append;
    }
    else
    {
        InvalidateFinalizationCoverage(false);
    }
    ObserveDurableJournalAppend(ElapsedMicroseconds(append_started));
    AdvanceCheckpointPinCensusGeneration(coverage_generation_before_append, coverage_generation_after_append, compacted_for_retry);
    ClearBufferedPreparedRecords();
    return true;
}

bool TransactionManager::MarkApfsDurableThrough(std::uint64_t accepted_sequence)
{
    if (!recovery_state_valid_ || state_ != State::Idle)
    {
        return false;
    }
    if (!journal_path_.empty() && !JournalStateMatchesWriterLease())
    {
        if (!SeedIdsFromExistingJournal(true) ||
            !recovery_state_valid_ ||
            !JournalStateMatchesWriterLease())
        {
            return false;
        }
    }
    if (accepted_sequence < watermarks_.apfs_durable_sequence ||
        accepted_sequence > watermarks_.accepted_sequence)
    {
        return false;
    }
    if (accepted_sequence == watermarks_.apfs_durable_sequence)
    {
        return true;
    }
    if (!IsAcceptedBoundary(accepted_sequence))
    {
        return false;
    }
    if (!FlushDeferredAcceptanceDurabilityNow(accepted_sequence))
    {
        MarkDeferredAcceptanceDurabilityFailure();
        return false;
    }
    if (!AppendWatermarkLocked(WriteAheadLog::RecordState::Checkpointed, accepted_sequence))
    {
        return false;
    }
    watermarks_.apfs_durable_sequence = accepted_sequence;
    last_committed_sequence_ = accepted_sequence;
    for (auto it = accepted_boundaries_requiring_payload_spool_flush_.begin();
         it != accepted_boundaries_requiring_payload_spool_flush_.end();)
    {
        if (*it <= accepted_sequence)
        {
            it = accepted_boundaries_requiring_payload_spool_flush_.erase(it);
        }
        else
        {
            ++it;
        }
    }
    if (watermarks_.apfs_durable_sequence == watermarks_.accepted_sequence)
    {
        accepted_boundaries_requiring_payload_spool_flush_.clear();
    }
    return true;
}

bool TransactionManager::MarkCleanedThrough(std::uint64_t durable_sequence)
{
    if (!recovery_state_valid_ || state_ != State::Idle)
    {
        return false;
    }
    if (!journal_path_.empty() && !JournalStateMatchesWriterLease())
    {
        if (!SeedIdsFromExistingJournal(true) ||
            !recovery_state_valid_ ||
            !JournalStateMatchesWriterLease())
        {
            return false;
        }
    }
    if (durable_sequence < watermarks_.cleanup_sequence ||
        durable_sequence > watermarks_.apfs_durable_sequence)
    {
        return false;
    }
    if (durable_sequence == watermarks_.cleanup_sequence)
    {
        return true;
    }
    if (!IsAcceptedBoundary(durable_sequence))
    {
        return false;
    }
    if (!FlushDeferredAcceptanceDurabilityNow(durable_sequence))
    {
        MarkDeferredAcceptanceDurabilityFailure();
        return false;
    }
    if (!AppendWatermarkLocked(WriteAheadLog::RecordState::Cleaned, durable_sequence))
    {
        return false;
    }
    watermarks_.cleanup_sequence = durable_sequence;
    PruneAcceptedBoundariesThrough(durable_sequence);
    return true;
}

void TransactionManager::SetFaultInjectionHook(std::function<void(const std::string& stage)> hook)
{
    fault_hook_ = std::move(hook);
}

void TransactionManager::NotifyStage(const std::string& stage)
{
    if (fault_hook_)
    {
        fault_hook_(stage);
    }
}

bool TransactionManager::PersistTransactionBatchLocked(
    const wchar_t* outcome,
    bool durable_flush,
    std::uint64_t preimage_checkpoint_xid)
{
    if (next_sequence_ == 0 ||
        next_sequence_ == (std::numeric_limits<std::uint64_t>::max)())
    {
        return false;
    }

    for (const auto& mutation : pending_mutations_) if (mutation.kind == MutationKind::CloneFile && outcome && wcscmp(outcome,L"aborted")!=0) {
        NativeCloneProof p;
        // Proof payload lives in the buffered record until the acceptance flush.
        const auto it=std::find_if(buffered_prepared_records_.begin(),buffered_prepared_records_.end(),[](const auto& r){return r.operation==WriteAheadLog::OperationKind::CloneFile;});
        if(journal_path_.empty() || pending_mutations_.size()!=1 || it==buffered_prepared_records_.end() ||
            !DecodeNativeClone(it->inline_payload,p) || p.checkpoint!=preimage_checkpoint_xid) return false;
    }
    for (const auto& mutation : pending_mutations_) if (mutation.kind == MutationKind::HardLink && outcome && wcscmp(outcome, L"aborted") != 0) {
        NativeHardLinkProof proof;
        const auto it = std::find_if(buffered_prepared_records_.begin(), buffered_prepared_records_.end(),
            [](const auto& record) { return record.operation == WriteAheadLog::OperationKind::HardLink; });
        if (journal_path_.empty() || pending_mutations_.size() != 1 || it == buffered_prepared_records_.end() ||
            !WriteAheadLog::NativeHardLinkIsConsistent(*it) || !DecodeNativeHardLink(it->inline_payload, proof) ||
            proof.checkpoint != preimage_checkpoint_xid) return false;
    }
    for (const auto& mutation : pending_mutations_) if (mutation.kind == MutationKind::CloneRange && outcome && wcscmp(outcome, L"aborted") != 0) {
        NativeCloneRangeProof proof;
        const auto it = std::find_if(buffered_prepared_records_.begin(), buffered_prepared_records_.end(),
            [](const auto& record) { return record.operation == WriteAheadLog::OperationKind::CloneRange; });
        if (journal_path_.empty() || pending_mutations_.size() != 1 || it == buffered_prepared_records_.end() ||
            !WriteAheadLog::NativeCloneRangeIsConsistent(*it) || !DecodeNativeCloneRange(it->inline_payload, proof) ||
            proof.checkpoint != preimage_checkpoint_xid) return false;
    }
    for (const auto& mutation : pending_mutations_) if (mutation.kind == MutationKind::NativeSparse && outcome && wcscmp(outcome, L"aborted") != 0) {
        std::uint64_t checkpoint=0;
        const auto it = std::find_if(buffered_prepared_records_.begin(), buffered_prepared_records_.end(),
            [](const auto& record) { return record.operation == WriteAheadLog::OperationKind::NativeSparse; });
        if (journal_path_.empty() || pending_mutations_.size() != 1 || it == buffered_prepared_records_.end() ||
            !WriteAheadLog::NativeSparseIsConsistent(*it) || !DecodeNativeSparseOriginalCheckpoint(it->inline_payload, checkpoint) ||
            checkpoint != preimage_checkpoint_xid) return false;
    }
    for (const auto& mutation : pending_mutations_) if (mutation.kind == MutationKind::SetVolumeQuotaReserve && outcome && wcscmp(outcome, L"aborted") != 0) {
        NativeVolumeQuotaReserve rename;
        const auto it = std::find_if(buffered_prepared_records_.begin(), buffered_prepared_records_.end(),
            [](const auto& r) { return r.operation == WriteAheadLog::OperationKind::SetVolumeQuotaReserve; });
        if (journal_path_.empty() || pending_mutations_.size() != 1 || it == buffered_prepared_records_.end() ||
            !DecodeNativeVolumeQuotaReserve(it->inline_payload, rename) || rename.checkpoint != preimage_checkpoint_xid) return false;
    }
    for (const auto& mutation : pending_mutations_) if ((mutation.kind == MutationKind::CreateSnapshot || mutation.kind == MutationKind::DeleteSnapshot) && outcome && wcscmp(outcome,L"aborted") != 0) {
        NativeSnapshotIntent intent;
        const auto it = std::find_if(buffered_prepared_records_.begin(),buffered_prepared_records_.end(),
            [](const auto& r){return r.operation == WriteAheadLog::OperationKind::CreateSnapshot || r.operation == WriteAheadLog::OperationKind::DeleteSnapshot;});
        if (journal_path_.empty() || pending_mutations_.size()!=1 || it==buffered_prepared_records_.end() ||
            !DecodeNativeSnapshotIntent(it->inline_payload,intent) || intent.scope.checkpoint_xid != preimage_checkpoint_xid) return false;
    }
    for (const auto& mutation : pending_mutations_) if (mutation.kind == MutationKind::RepairVolumeFileCount && outcome && wcscmp(outcome, L"aborted") != 0) {
        NativeCountRepair repair;
        const auto it = std::find_if(buffered_prepared_records_.begin(), buffered_prepared_records_.end(),
            [](const auto& r) { return r.operation == WriteAheadLog::OperationKind::RepairVolumeFileCount; });
        if (journal_path_.empty() || pending_mutations_.size() != 1 || it == buffered_prepared_records_.end() ||
            !DecodeNativeCountRepair(it->inline_payload, repair) || repair.checkpoint != preimage_checkpoint_xid) return false;
    }
    for (const auto& mutation : pending_mutations_) if (mutation.kind == MutationKind::RenameVolume && outcome && wcscmp(outcome, L"aborted") != 0) {
        NativeVolumeRename rename;
        const auto it = std::find_if(buffered_prepared_records_.begin(), buffered_prepared_records_.end(),
            [](const auto& r) { return r.operation == WriteAheadLog::OperationKind::RenameVolume; });
        if (journal_path_.empty() || pending_mutations_.size() != 1 || it == buffered_prepared_records_.end() ||
            !DecodeNativeVolumeRename(it->inline_payload, rename) || rename.checkpoint != preimage_checkpoint_xid) return false;
    }
    if (journal_path_.empty())
    {
        ClearBufferedPreparedRecords();
        if (outcome && wcscmp(outcome, L"committed") == 0 && !pending_mutations_.empty())
        {
            last_committed_sequence_ = pending_mutations_.back().wal_sequence;
        }
        if (outcome && wcscmp(outcome, L"accepted") == 0 && !pending_mutations_.empty())
        {
            watermarks_.accepted_sequence = pending_mutations_.back().wal_sequence;
            accepted_boundaries_.insert(watermarks_.accepted_sequence);
            const auto proof = accepted_transaction_sequences_.find(current_transaction_id_);
            if (proof != accepted_transaction_sequences_.end())
            {
                proof->second.accepted_sequence = watermarks_.accepted_sequence;
            }
        }
        return true;
    }
    if (!JournalStateMatchesWriterLease())
    {
        recovery_state_valid_ = false;
        InvalidateFinalizationCoverage(true);
        return false;
    }

    std::unique_lock<std::mutex> append_lock(deferred_wal_append_mutex_);

    const auto effective_volume_identity = EffectiveVolumeIdentity(volume_identity_);
    const bool accepted_outcome = outcome && wcscmp(outcome, L"accepted") == 0;
    const bool accepted_requires_payload_spool_flush =
        accepted_outcome && current_transaction_requires_payload_spool_flush_;
    const auto first_sequence_to_keep = pending_mutations_.empty()
        ? next_sequence_
        : pending_mutations_.front().wal_sequence;

    std::vector<WriteAheadLog::Record> records;
    records.reserve(buffered_prepared_records_.size() + 1);
    for (auto& record : buffered_prepared_records_)
    {
        if (record.volume_identity.empty())
        {
            record.volume_identity = effective_volume_identity;
        }
        if (record.sequence == 0 || record.sequence >= next_sequence_)
        {
            return false;
        }
        records.push_back(record);
    }

    auto marker = BuildTransactionMarkerLocked(
        outcome,
        effective_volume_identity,
        preimage_checkpoint_xid);
    marker.sequence = next_sequence_;
    records.push_back(marker);

    std::vector<std::uint64_t> accepted_pins;
    bool accepted_pins_valid = accepted_outcome && preimage_checkpoint_xid != 0;
    if (accepted_pins_valid)
    {
        accepted_pins.push_back(preimage_checkpoint_xid);
        for (const auto& record : records)
            if (!AppendSnapshotCheckpointPins(record, accepted_pins)) { accepted_pins_valid = false; break; }
    }

    const auto coverage_generation_before_append = journal_state_writer_generation_;
    const bool coverage_trusted_before_append =
        finalization_coverage_trust_ == FinalizationCoverageTrust::Trusted &&
        coverage_generation_before_append != 0 &&
        coverage_generation_before_append == finalization_coverage_writer_generation_;
    bool compacted_for_retry = false;
    const auto append_started = std::chrono::steady_clock::now();
    const auto append_result = journal_.AppendBatchWithResult(
        records,
        durable_flush,
        coverage_generation_before_append);
    if (append_result == WriteAheadLog::AppendResult::BytesMayHavePersisted)
    {
        journal_append_ambiguous_ = true;
        recovery_state_valid_ = false;
        journal_state_writer_generation_ = 0;
        InvalidateFinalizationCoverage(true);
        return false;
    }
    if (append_result == WriteAheadLog::AppendResult::RejectedBeforeWrite)
    {
        const auto compaction_result = journal_.CompactWithResult(
            SafeCompactionFloor(first_sequence_to_keep),
            coverage_generation_before_append);
        if (compaction_result != WriteAheadLog::CompactionResult::Succeeded)
        {
            journal_append_ambiguous_ =
                compaction_result == WriteAheadLog::CompactionResult::BytesMayHavePersisted;
            recovery_state_valid_ = false;
            journal_state_writer_generation_ = 0;
            InvalidateFinalizationCoverage(true);
            return false;
        }
        compacted_for_retry = true;
        const auto retry_generation = journal_.ExclusiveWriterLeaseGeneration();
        if (retry_generation == 0)
        {
            recovery_state_valid_ = false;
            journal_state_writer_generation_ = 0;
            InvalidateFinalizationCoverage(true);
            return false;
        }
        journal_state_writer_generation_ = retry_generation;
        const auto retry_result = journal_.AppendBatchWithResult(
            records,
            durable_flush,
            retry_generation);
        if (retry_result == WriteAheadLog::AppendResult::BytesMayHavePersisted)
        {
            journal_append_ambiguous_ = true;
            recovery_state_valid_ = false;
            journal_state_writer_generation_ = 0;
            InvalidateFinalizationCoverage(true);
            return false;
        }
        if (retry_result != WriteAheadLog::AppendResult::Succeeded)
        {
            recovery_state_valid_ = false;
            journal_state_writer_generation_ = 0;
            InvalidateFinalizationCoverage(true);
            return false;
        }
    }

    const auto coverage_generation_after_append = journal_.ExclusiveWriterLeaseGeneration();
    const bool coverage_remains_trusted =
        coverage_trusted_before_append &&
        coverage_generation_after_append != 0 &&
        (coverage_generation_after_append == coverage_generation_before_append ||
         compacted_for_retry);
    if (coverage_generation_after_append == 0)
    {
        recovery_state_valid_ = false;
        journal_state_writer_generation_ = 0;
        InvalidateFinalizationCoverage(true);
        return false;
    }
    journal_state_writer_generation_ = coverage_generation_after_append;
    if (coverage_remains_trusted)
    {
        finalization_coverage_trust_ = FinalizationCoverageTrust::Trusted;
        finalization_coverage_writer_generation_ = coverage_generation_after_append;
    }
    else
    {
        InvalidateFinalizationCoverage(false);
    }
    if (durable_flush)
    {
        ObserveDurableJournalAppend(ElapsedMicroseconds(append_started));
    }
    ++next_sequence_;
    AdvanceCheckpointPinCensusGeneration(coverage_generation_before_append, coverage_generation_after_append, compacted_for_retry);
    if (outcome && wcscmp(outcome, L"committed") == 0)
    {
        InvalidateCheckpointPinCensus();
        last_committed_sequence_ = marker.sequence;
        highest_checkpointed_marker_sequence_ = (std::max)(
            highest_checkpointed_marker_sequence_, marker.sequence);
    }
    else if (accepted_outcome)
    {
        watermarks_.accepted_sequence = marker.sequence;
        accepted_boundaries_.insert(marker.sequence);
        if (accepted_pins_valid) CacheAcceptedCheckpointPins(marker.sequence, std::move(accepted_pins));
        else InvalidateCheckpointPinCensus();
        if (coverage_remains_trusted &&
            accepted_requires_payload_spool_flush)
        {
            accepted_boundaries_requiring_payload_spool_flush_.insert(marker.sequence);
        }
        const auto proof = accepted_transaction_sequences_.find(current_transaction_id_);
        if (proof != accepted_transaction_sequences_.end())
        {
            proof->second.accepted_sequence = marker.sequence;
        }
    }
    ClearBufferedPreparedRecords();
    return true;
}

bool TransactionManager::AppendWatermarkLocked(
    WriteAheadLog::RecordState state,
    std::uint64_t target_sequence)
{
    WriteAheadLog::Record record{};
    record.volume_identity = EffectiveVolumeIdentity(volume_identity_);
    record.operation = WriteAheadLog::OperationKind::DurabilityWatermark;
    record.state = state;
    record.logical_offset = target_sequence;
    const auto first_sequence_to_keep = watermarks_.cleanup_sequence == (std::numeric_limits<std::uint64_t>::max)()
        ? watermarks_.cleanup_sequence
        : watermarks_.cleanup_sequence + 1;
    return AppendWalRecordWithCleanup(record, true, first_sequence_to_keep);
}

bool TransactionManager::AppendWalRecordWithCleanup(
    WriteAheadLog::Record& record,
    bool durable_flush,
    std::uint64_t first_sequence_to_keep)
{
    if (!recovery_state_valid_ ||
        next_sequence_ == 0 ||
        next_sequence_ == (std::numeric_limits<std::uint64_t>::max)())
    {
        return false;
    }

    if (journal_path_.empty())
    {
        return true;
    }
    if (!JournalStateMatchesWriterLease())
    {
        recovery_state_valid_ = false;
        InvalidateFinalizationCoverage(true);
        return false;
    }

    std::unique_lock<std::mutex> append_lock(deferred_wal_append_mutex_);

    if (record.sequence == 0)
    {
        record.sequence = next_sequence_;
    }
    if (record.sequence != next_sequence_)
    {
        return false;
    }

    const auto generation_before_append = journal_state_writer_generation_;
    const bool coverage_trusted_before_append =
        finalization_coverage_trust_ == FinalizationCoverageTrust::Trusted &&
        generation_before_append != 0 &&
        generation_before_append == finalization_coverage_writer_generation_;
    bool compacted_for_retry = false;
    const auto append_started = std::chrono::steady_clock::now();
    auto append_result = journal_.AppendWithResult(
        record,
        durable_flush,
        generation_before_append);

    if (append_result == WriteAheadLog::AppendResult::BytesMayHavePersisted)
    {
        journal_append_ambiguous_ = true;
        recovery_state_valid_ = false;
        journal_state_writer_generation_ = 0;
        InvalidateFinalizationCoverage(true);
        return false;
    }

    if (append_result == WriteAheadLog::AppendResult::RejectedBeforeWrite)
    {
        const auto compaction_result = journal_.CompactWithResult(
            SafeCompactionFloor(first_sequence_to_keep),
            generation_before_append);
        if (compaction_result != WriteAheadLog::CompactionResult::Succeeded)
        {
            journal_append_ambiguous_ =
                compaction_result == WriteAheadLog::CompactionResult::BytesMayHavePersisted;
            recovery_state_valid_ = false;
            journal_state_writer_generation_ = 0;
            InvalidateFinalizationCoverage(true);
            return false;
        }
        compacted_for_retry = true;
        const auto retry_generation = journal_.ExclusiveWriterLeaseGeneration();
        if (retry_generation == 0)
        {
            recovery_state_valid_ = false;
            journal_state_writer_generation_ = 0;
            InvalidateFinalizationCoverage(true);
            return false;
        }
        journal_state_writer_generation_ = retry_generation;
        append_result = journal_.AppendWithResult(
            record,
            durable_flush,
            retry_generation);
        if (append_result == WriteAheadLog::AppendResult::BytesMayHavePersisted)
        {
            journal_append_ambiguous_ = true;
            recovery_state_valid_ = false;
            journal_state_writer_generation_ = 0;
            InvalidateFinalizationCoverage(true);
            return false;
        }
        if (append_result != WriteAheadLog::AppendResult::Succeeded)
        {
            recovery_state_valid_ = false;
            journal_state_writer_generation_ = 0;
            InvalidateFinalizationCoverage(true);
            return false;
        }
    }

    const auto generation_after_append = journal_.ExclusiveWriterLeaseGeneration();
    if (generation_after_append == 0)
    {
        recovery_state_valid_ = false;
        journal_state_writer_generation_ = 0;
        InvalidateFinalizationCoverage(true);
        return false;
    }
    journal_state_writer_generation_ = generation_after_append;
    if (coverage_trusted_before_append &&
        (generation_after_append == generation_before_append || compacted_for_retry))
    {
        finalization_coverage_trust_ = FinalizationCoverageTrust::Trusted;
        finalization_coverage_writer_generation_ = generation_after_append;
    }
    else
    {
        InvalidateFinalizationCoverage(false);
    }
    ++next_sequence_;
    AdvanceCheckpointPinCensusGeneration(generation_before_append, generation_after_append, compacted_for_retry);
    if (durable_flush)
    {
        ObserveDurableJournalAppend(ElapsedMicroseconds(append_started));
    }
    return true;
}

void TransactionManager::ObserveDurableJournalAppend(std::uint64_t elapsed_microseconds) noexcept
{
    ++durable_journal_append_count_;
    durable_journal_append_microseconds_ += elapsed_microseconds;
    durable_journal_append_max_microseconds_ =
        (std::max)(durable_journal_append_max_microseconds_, elapsed_microseconds);
}

void TransactionManager::ConfigureJournal()
{
    journal_.Reconfigure({
        std::filesystem::path(journal_path_),
        EffectiveVolumeIdentity(volume_identity_),
        journal_max_bytes_,
        journal_protection_,
    });
}

WriteAheadLog::Record TransactionManager::BuildTransactionMarkerLocked(
    const wchar_t* outcome,
    const std::string& volume_identity,
    std::uint64_t preimage_checkpoint_xid) const
{
    const bool committed = outcome && wcscmp(outcome, L"committed") == 0;
    const bool aborted = outcome && wcscmp(outcome, L"aborted") == 0;
    const bool accepted = outcome && wcscmp(outcome, L"accepted") == 0;

    WriteAheadLog::Record marker{};
    marker.volume_identity = volume_identity;
    marker.transaction_id = current_transaction_id_;
    marker.operation = WriteAheadLog::OperationKind::TransactionMarker;
    marker.state = accepted
        ? WriteAheadLog::RecordState::Accepted
        : (committed ? WriteAheadLog::RecordState::Checkpointed : WriteAheadLog::RecordState::Cleaned);
    marker.flags = accepted
        ? kWalFlagAccepted
        : (committed ? kWalFlagCommitted : (aborted ? kWalFlagAborted : 0));
    marker.object_id = (accepted || committed) ? preimage_checkpoint_xid : 0;
    marker.logical_length = static_cast<std::uint64_t>(pending_mutations_.size());
    marker.path_utf8 = WideToUtf8(safety_level_);
    return marker;
}

bool TransactionManager::IsAcceptedBoundary(std::uint64_t sequence) const noexcept
{
    return accepted_boundaries_.contains(sequence);
}

std::uint64_t TransactionManager::SafeCompactionFloor(std::uint64_t preferred_floor) const noexcept
{
    // Direct Commit can precede watermark reseeding. Keep its whole mutation
    // group until cleanup proves the committed boundary is no longer needed.
    if (highest_checkpointed_marker_sequence_ > watermarks_.cleanup_sequence)
    {
        return 1;
    }
    if (watermarks_.accepted_sequence <= watermarks_.cleanup_sequence)
    {
        return preferred_floor;
    }
    if (watermarks_.cleanup_sequence == 0)
    {
        return 1;
    }
    return (std::min)(preferred_floor, watermarks_.cleanup_sequence);
}

bool TransactionManager::AppendPreparedMutationLocked(MutationIntent& mutation)
{
    if (next_sequence_ == 0 ||
        next_sequence_ == (std::numeric_limits<std::uint64_t>::max)())
    {
        return false;
    }

    const bool extended_attribute_mutation =
        mutation.kind == MutationKind::SetExtendedAttribute ||
        mutation.kind == MutationKind::RemoveExtendedAttribute;
    const bool hard_link_mutation = mutation.kind == MutationKind::HardLink || mutation.kind == MutationKind::NativeSparse || mutation.kind == MutationKind::CloneRange;
    const bool inode_metadata_mutation = mutation.kind == MutationKind::SetInodeMetadata ||
        mutation.kind == MutationKind::RewriteCompressedContent || mutation.kind == MutationKind::CloneFile ||
        mutation.kind == MutationKind::RenameVolume || mutation.kind == MutationKind::SetVolumeQuotaReserve || mutation.kind == MutationKind::CreateSnapshot || mutation.kind == MutationKind::DeleteSnapshot || mutation.kind == MutationKind::RepairVolumeFileCount;
    const bool allocation_size_mutation = mutation.kind == MutationKind::SetAllocationSize;
    const bool directory_restore_mutation = mutation.kind == MutationKind::RestoreDirectoryFromSymbolicLink;
    if (directory_restore_mutation && !mutation.secondary_path.empty())
    {
        return false;
    }
    if ((allocation_size_mutation || directory_restore_mutation) && mutation.timestamp_utc != 0)
    {
        return false;
    }
    if (inode_metadata_mutation &&
        (mutation.length != mutation.inline_payload.size() || mutation.timestamp_utc != 0 ||
            (mutation.kind != MutationKind::CloneFile && !mutation.secondary_path.empty())))
    {
        return false;
    }
    if (hard_link_mutation && (mutation.length != mutation.inline_payload.size() ||
        mutation.payload_length != mutation.inline_payload.size() || mutation.timestamp_utc || mutation.offset ||
        mutation.payload_spool_offset || mutation.replace_if_exists || mutation.unlink_outcome)) return false;
    if (extended_attribute_mutation || inode_metadata_mutation || hard_link_mutation || allocation_size_mutation || directory_restore_mutation)
    {
        WriteAheadLog::Record validation_record{};
        validation_record.volume_identity = EffectiveVolumeIdentity(volume_identity_);
        validation_record.operation = ToWalOperation(mutation.kind);
        validation_record.object_id = mutation.object_id;
        validation_record.parent_object_id = mutation.generation;
        validation_record.payload_offset = mutation.payload_spool_offset;
        validation_record.payload_length = mutation.payload_length;
        validation_record.logical_offset = mutation.offset;
        validation_record.logical_length = inode_metadata_mutation ? 0 : mutation.length;
        validation_record.flags = mutation.replace_if_exists ? kWalFlagReplaceIfExists : 0;
        validation_record.payload_sha256 = mutation.payload_checksum;
        validation_record.inline_payload = mutation.inline_payload;
        validation_record.path_utf8 = WideToUtf8(mutation.path);
        validation_record.secondary_path_utf8 = WideToUtf8(mutation.secondary_path);
        validation_record.unlink_outcome = mutation.unlink_outcome;
        if (!WriteAheadLog::NativeCloneRangeIsConsistent(validation_record) || !WriteAheadLog::NativeSparseIsConsistent(validation_record) || !WriteAheadLog::NativeHardLinkIsConsistent(validation_record) || !WriteAheadLog::SnapshotIntentIsConsistent(validation_record) || !WriteAheadLog::CountRepairIsConsistent(validation_record) || !WriteAheadLog::VolumeQuotaReserveIsConsistent(validation_record) || !WriteAheadLog::VolumeRenameIsConsistent(validation_record) || !WriteAheadLog::NativeCloneIsConsistent(validation_record) || !WriteAheadLog::CompressionRewriteIsConsistent(validation_record) ||
            !WriteAheadLog::ExtendedAttributeMutationIsConsistent(validation_record) ||
            !WriteAheadLog::AllocationSizeMutationIsConsistent(validation_record) ||
            !WriteAheadLog::DirectoryRestoreMutationIsConsistent(validation_record) ||
            !WriteAheadLog::InodeMetadataMutationIsConsistent(validation_record))
        {
            return false;
        }
    }

    if (journal_path_.empty())
    {
        if (mutation.wal_sequence == 0)
        {
            mutation.wal_sequence = next_sequence_;
        }
        if (mutation.wal_sequence != next_sequence_)
        {
            return false;
        }
        ++next_sequence_;
        return true;
    }

    const auto effective_volume_identity = EffectiveVolumeIdentity(volume_identity_);
    if (mutation.wal_sequence == 0)
    {
        mutation.wal_sequence = next_sequence_;
    }
    if (mutation.wal_sequence != next_sequence_)
    {
        return false;
    }

    WriteAheadLog::Record record{};
    record.volume_identity = effective_volume_identity;
    record.transaction_id = current_transaction_id_;
    record.sequence = mutation.wal_sequence;
    record.operation = ToWalOperation(mutation.kind);
    record.state = WriteAheadLog::RecordState::Prepared;
    record.object_id = mutation.object_id;
    record.parent_object_id = mutation.generation;
    record.payload_spool_id = extended_attribute_mutation || inode_metadata_mutation || hard_link_mutation || mutation.payload_length == 0
        ? 0
        : mutation.wal_sequence;
    record.payload_offset = mutation.payload_spool_offset;
    record.payload_length = mutation.payload_length;
    record.logical_offset = mutation.kind == MutationKind::SetBasicInfo
        ? mutation.timestamp_utc
        : mutation.offset;
    record.logical_length = inode_metadata_mutation ? 0 : mutation.length;
    record.flags = mutation.replace_if_exists ? kWalFlagReplaceIfExists : 0;
    record.path_utf8 = WideToUtf8(mutation.path);
    record.secondary_path_utf8 = WideToUtf8(mutation.secondary_path);
    record.payload_sha256 = mutation.payload_checksum;
    record.inline_payload = std::move(mutation.inline_payload);
    record.unlink_outcome = std::move(mutation.unlink_outcome);
    if (!WriteAheadLog::NativeCloneRangeIsConsistent(record) || !WriteAheadLog::NativeSparseIsConsistent(record) || !WriteAheadLog::NativeHardLinkIsConsistent(record) || !WriteAheadLog::SnapshotIntentIsConsistent(record) || !WriteAheadLog::CountRepairIsConsistent(record) || !WriteAheadLog::VolumeQuotaReserveIsConsistent(record) || !WriteAheadLog::VolumeRenameIsConsistent(record) || !WriteAheadLog::NativeCloneIsConsistent(record) || !WriteAheadLog::CompressionRewriteIsConsistent(record) ||
        !WriteAheadLog::ExtendedAttributeMutationIsConsistent(record) ||
        !WriteAheadLog::AllocationSizeMutationIsConsistent(record) ||
        !WriteAheadLog::DirectoryRestoreMutationIsConsistent(record) ||
        !WriteAheadLog::InodeMetadataMutationIsConsistent(record) ||
        !WriteAheadLog::UnlinkOutcomeIsConsistent(record))
    {
        return false;
    }

    if (record.operation == WriteAheadLog::OperationKind::Write &&
        (record.inline_payload.empty() ||
         !WriteAheadLog::InlinePayloadIsConsistent(record)))
    {
        current_transaction_requires_payload_spool_flush_ = true;
    }
    buffered_prepared_records_.push_back(std::move(record));
    const auto& buffered_record = buffered_prepared_records_.back();
    if (buffered_record.operation == WriteAheadLog::OperationKind::Write &&
        buffered_record.inline_payload.empty())
    {
        buffered_prepared_records_have_empty_write_payload_ = true;
    }
    const bool complete_inline_payload =
        buffered_record.operation == WriteAheadLog::OperationKind::Write
            ? !buffered_record.inline_payload.empty() &&
                WriteAheadLog::InlinePayloadIsConsistent(buffered_record)
            : (buffered_record.operation == WriteAheadLog::OperationKind::CreateSnapshot || buffered_record.operation == WriteAheadLog::OperationKind::DeleteSnapshot)
                ? WriteAheadLog::SnapshotIntentIsConsistent(buffered_record)
            : buffered_record.operation == WriteAheadLog::OperationKind::RepairVolumeFileCount
                ? WriteAheadLog::CountRepairIsConsistent(buffered_record)
            : buffered_record.operation == WriteAheadLog::OperationKind::SetVolumeQuotaReserve
                ? WriteAheadLog::VolumeQuotaReserveIsConsistent(buffered_record)
            : buffered_record.operation == WriteAheadLog::OperationKind::RenameVolume
                ? WriteAheadLog::VolumeRenameIsConsistent(buffered_record)
            : buffered_record.operation == WriteAheadLog::OperationKind::CloneFile
                ? WriteAheadLog::NativeCloneIsConsistent(buffered_record)
            : buffered_record.operation == WriteAheadLog::OperationKind::HardLink
                ? WriteAheadLog::NativeHardLinkIsConsistent(buffered_record)
            : buffered_record.operation == WriteAheadLog::OperationKind::NativeSparse
                ? WriteAheadLog::NativeSparseIsConsistent(buffered_record)
            : buffered_record.operation == WriteAheadLog::OperationKind::CloneRange
                ? WriteAheadLog::NativeCloneRangeIsConsistent(buffered_record)
            : buffered_record.operation == WriteAheadLog::OperationKind::RewriteCompressedContent
                ? WriteAheadLog::CompressionRewriteIsConsistent(buffered_record)
            : buffered_record.operation == WriteAheadLog::OperationKind::SetInodeMetadata
                ? WriteAheadLog::InodeMetadataMutationIsConsistent(buffered_record)
            : buffered_record.operation == WriteAheadLog::OperationKind::SetExtendedAttribute
                ? WriteAheadLog::ExtendedAttributeMutationIsConsistent(buffered_record)
                : buffered_record.inline_payload.empty();
    if (!complete_inline_payload)
    {
        buffered_prepared_records_have_incomplete_inline_payload_ = true;
    }
    if (buffered_inline_payload_bytes_ < WriteAheadLog::MaxInlinePayloadBytes)
    {
        const auto remaining =
            WriteAheadLog::MaxInlinePayloadBytes - buffered_inline_payload_bytes_;
        buffered_inline_payload_bytes_ +=
            (std::min)(remaining, buffered_record.inline_payload.size());
    }
    ++next_sequence_;
    return true;
}

bool TransactionManager::SeedIdsFromExistingJournal(bool acquire_writer_lease)
{
    if (state_ != State::Idle)
    {
        return false;
    }
    if (journal_path_.empty())
    {
        journal_state_writer_generation_ = 0;
        InvalidateFinalizationCoverage(false);
        return true;
    }

    const auto existing = preserve_startup_evidence_
        ? journal_.ReadStartupEvidence({64ull << 20, 1000000}, 256ull << 20)
        : acquire_writer_lease ? journal_.ReadAllWithExclusiveWriterLease() : journal_.ReadAll();
    if (existing.status != WriteAheadLog::ReadStatus::Ok ||
        !ValidateWalSemantics(existing.records))
    {
        // Keep the writer lease while this degraded owner is alive. Releasing
        // it would let a second process mutate evidence that this owner has
        // already classified as unsafe for recovery.
        recovery_state_valid_ = false;
        journal_state_writer_generation_ = 0;
        InvalidateFinalizationCoverage(true);
        return false;
    }

    const auto writer_generation = acquire_writer_lease
        ? journal_.ExclusiveWriterLeaseGeneration()
        : 0;
    return SeedIdsFromJournalRecords(existing.records, writer_generation);
}

bool TransactionManager::SeedIdsFromJournalRecords(
    const std::vector<WriteAheadLog::Record>& records,
    std::uint64_t writer_generation)
{
    if (state_ != State::Idle || !ValidateWalSemantics(records))
    {
        recovery_state_valid_ = false;
        journal_state_writer_generation_ = 0;
        InvalidateFinalizationCoverage(true);
        return false;
    }

    if (continuation_seed_)
    {
        const auto& seed = *continuation_seed_;
        if (!journal_protection_ || !seed.last_sequence || seed.last_sequence == UINT64_MAX ||
            !seed.next_transaction_id || seed.next_transaction_id == UINT64_MAX ||
            !seed.watermarks.accepted_sequence || seed.watermarks.accepted_sequence > seed.last_sequence ||
            seed.watermarks.accepted_sequence != seed.watermarks.apfs_durable_sequence ||
            seed.watermarks.accepted_sequence != seed.watermarks.cleanup_sequence ||
            std::any_of(records.begin(), records.end(), [&](const auto& record) {
                return record.sequence <= seed.last_sequence ||
                    (record.transaction_id && record.transaction_id < seed.next_transaction_id) ||
                    record.operation == WriteAheadLog::OperationKind::CompactionIndex;
            }))
        {
            recovery_state_valid_ = false; journal_state_writer_generation_ = 0;
            InvalidateFinalizationCoverage(true); return false;
        }
    }

    std::unordered_set<std::uint64_t> recovered_boundaries;
    std::unordered_map<std::uint64_t, std::uint64_t> recovered_transaction_sequences;
    std::unordered_map<std::uint64_t, bool> transaction_requires_spool_flush;
    std::vector<std::pair<std::uint64_t, bool>> accepted_recovery_requirements;
    std::uint64_t max_transaction_id = continuation_seed_ ? continuation_seed_->next_transaction_id - 1 : 0;
    std::uint64_t max_sequence = continuation_seed_ ? continuation_seed_->last_sequence : 0;
    std::uint64_t highest_checkpointed_marker = 0;
    DurabilityWatermarks recovered_watermarks = continuation_seed_ ? continuation_seed_->watermarks : DurabilityWatermarks{};
    if (continuation_seed_) recovered_boundaries.insert(recovered_watermarks.cleanup_sequence);
    bool recovered_state_valid = true;

    for (const auto& record : records)
    {
        max_transaction_id = (std::max)(max_transaction_id, record.transaction_id);
        max_sequence = (std::max)(max_sequence, record.sequence);

        if (record.state == WriteAheadLog::RecordState::Prepared &&
            IsMutationOperation(record.operation))
        {
            auto& requires_spool_flush = transaction_requires_spool_flush[record.transaction_id];
            if (record.operation == WriteAheadLog::OperationKind::Write &&
                (record.inline_payload.empty() ||
                 !WriteAheadLog::InlinePayloadIsConsistent(record)))
            {
                requires_spool_flush = true;
            }
            continue;
        }

        if (record.operation == WriteAheadLog::OperationKind::TransactionMarker)
        {
            const auto requirement = transaction_requires_spool_flush.find(record.transaction_id);
            const bool requires_spool_flush =
                requirement != transaction_requires_spool_flush.end() && requirement->second;
            transaction_requires_spool_flush.erase(record.transaction_id);

            if (record.state == WriteAheadLog::RecordState::Accepted)
            {
                recovered_boundaries.insert(record.sequence);
                recovered_transaction_sequences[record.transaction_id] = record.sequence;
                recovered_watermarks.accepted_sequence = (std::max)(
                    recovered_watermarks.accepted_sequence,
                    record.sequence);
                accepted_recovery_requirements.emplace_back(
                    record.sequence,
                    requires_spool_flush);
            }
            else if (record.state == WriteAheadLog::RecordState::Checkpointed &&
                      (record.flags & kWalFlagCommitted) != 0)
            {
                highest_checkpointed_marker = (std::max)(highest_checkpointed_marker, record.sequence);
                recovered_boundaries.insert(record.sequence);
                recovered_transaction_sequences[record.transaction_id] = record.sequence;
                recovered_watermarks.accepted_sequence = (std::max)(
                    recovered_watermarks.accepted_sequence,
                    record.sequence);
                recovered_watermarks.apfs_durable_sequence = (std::max)(
                    recovered_watermarks.apfs_durable_sequence,
                    record.sequence);
            }
            continue;
        }

        if (record.operation != WriteAheadLog::OperationKind::DurabilityWatermark)
        {
            continue;
        }

        const auto target_sequence = record.logical_offset;
        if (record.state == WriteAheadLog::RecordState::Checkpointed)
        {
            if (target_sequence < recovered_watermarks.apfs_durable_sequence ||
                target_sequence > recovered_watermarks.accepted_sequence ||
                !recovered_boundaries.contains(target_sequence))
            {
                recovered_state_valid = false;
            }
            recovered_watermarks.apfs_durable_sequence = (std::max)(
                recovered_watermarks.apfs_durable_sequence,
                target_sequence);
        }
        else if (record.state == WriteAheadLog::RecordState::Cleaned)
        {
            if (target_sequence < recovered_watermarks.cleanup_sequence ||
                target_sequence > recovered_watermarks.apfs_durable_sequence ||
                !recovered_boundaries.contains(target_sequence))
            {
                recovered_state_valid = false;
            }
            recovered_watermarks.cleanup_sequence = (std::max)(
                recovered_watermarks.cleanup_sequence,
                target_sequence);
        }
    }

    if (!transaction_requires_spool_flush.empty() ||
        recovered_watermarks.cleanup_sequence > recovered_watermarks.apfs_durable_sequence ||
        recovered_watermarks.apfs_durable_sequence > recovered_watermarks.accepted_sequence ||
        max_transaction_id == (std::numeric_limits<std::uint64_t>::max)() ||
        max_sequence == (std::numeric_limits<std::uint64_t>::max)())
    {
        recovered_state_valid = false;
    }

    accepted_boundaries_ = std::move(recovered_boundaries);
    accepted_boundaries_requiring_payload_spool_flush_.clear();
    for (const auto& [accepted_sequence, requires_spool_flush] : accepted_recovery_requirements)
    {
        if (requires_spool_flush &&
            accepted_sequence > recovered_watermarks.apfs_durable_sequence)
        {
            accepted_boundaries_requiring_payload_spool_flush_.insert(accepted_sequence);
        }
    }
    watermarks_ = recovered_watermarks;
    last_committed_sequence_ = recovered_watermarks.apfs_durable_sequence;
    highest_checkpointed_marker_sequence_ = highest_checkpointed_marker;
    recovery_state_valid_ = recovered_state_valid && !journal_append_ambiguous_;
    for (auto proof = accepted_transaction_sequences_.begin();
         proof != accepted_transaction_sequences_.end();)
    {
        const auto recovered = recovered_transaction_sequences.find(proof->first);
        if (recovered == recovered_transaction_sequences.end())
        {
            proof = accepted_transaction_sequences_.erase(proof);
            continue;
        }
        proof->second.accepted_sequence = recovered->second;
        ++proof;
    }
    PruneAcceptedBoundariesThrough(watermarks_.cleanup_sequence);

    if (next_transaction_id_ <= max_transaction_id)
    {
        next_transaction_id_ = max_transaction_id + 1;
    }
    if (next_sequence_ <= max_sequence)
    {
        next_sequence_ = max_sequence + 1;
    }
    if (!recovery_state_valid_ || (writer_generation == 0 && !journal_path_.empty()))
    {
        journal_state_writer_generation_ = 0;
        InvalidateFinalizationCoverage(!recovery_state_valid_);
        return recovery_state_valid_;
    }

    journal_state_writer_generation_ = writer_generation;
    if (writer_generation != 0)
    {
        finalization_coverage_trust_ = FinalizationCoverageTrust::Trusted;
        finalization_coverage_writer_generation_ = writer_generation;
    }
    else
    {
        InvalidateFinalizationCoverage(false);
    }
    SeedCheckpointPinCensus(records, writer_generation);
    return true;
}

bool TransactionManager::JournalStateMatchesWriterLease() const
{
    if (journal_path_.empty())
    {
        return true;
    }
    const auto writer_generation = journal_.ExclusiveWriterLeaseGeneration();
    return writer_generation != 0 && writer_generation == journal_state_writer_generation_;
}

void TransactionManager::InvalidateFinalizationCoverage(bool poison) noexcept
{
    InvalidateCheckpointPinCensus();
    if (poison)
    {
        finalization_coverage_trust_ = FinalizationCoverageTrust::Poisoned;
    }
    else if (finalization_coverage_trust_ != FinalizationCoverageTrust::Poisoned)
    {
        finalization_coverage_trust_ = FinalizationCoverageTrust::Unknown;
    }
    finalization_coverage_writer_generation_ = 0;
}

void TransactionManager::PruneAcceptedBoundariesThrough(
    std::uint64_t cleanup_sequence) noexcept
{
    for (auto it = accepted_checkpoint_pins_.begin(); it != accepted_checkpoint_pins_.end();)
    {
        if (it->first <= cleanup_sequence)
        {
            cached_checkpoint_pin_entries_ -= it->second.size();
            it = accepted_checkpoint_pins_.erase(it);
        }
        else ++it;
    }
    for (auto it = accepted_boundaries_.begin(); it != accepted_boundaries_.end();)
    {
        if (*it <= cleanup_sequence)
        {
            it = accepted_boundaries_.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

void TransactionManager::InvalidateCheckpointPinCensus() noexcept
{
    accepted_checkpoint_pins_.clear();
    cached_checkpoint_pin_entries_ = 0;
    checkpoint_pin_census_writer_generation_ = 0;
    checkpoint_pin_census_trusted_ = false;
}

void TransactionManager::AdvanceCheckpointPinCensusGeneration(
    std::uint64_t before, std::uint64_t after, bool compacted) noexcept
{
    if (!checkpoint_pin_census_trusted_ || before == 0 || after == 0 ||
        checkpoint_pin_census_writer_generation_ != before || (before != after && !compacted))
    {
        InvalidateCheckpointPinCensus();
        return;
    }
    checkpoint_pin_census_writer_generation_ = after;
}

void TransactionManager::CacheAcceptedCheckpointPins(std::uint64_t sequence, std::vector<std::uint64_t> pins)
{
    if (!checkpoint_pin_census_trusted_) return;
    std::sort(pins.begin(), pins.end());
    pins.erase(std::unique(pins.begin(), pins.end()), pins.end());
    if (pins.empty() || pins.front() == 0 || sequence <= watermarks_.cleanup_sequence ||
        accepted_checkpoint_pins_.size() >= MaxCachedCheckpointPinBoundaries() ||
        pins.size() > MaxCachedCheckpointPinEntries() - cached_checkpoint_pin_entries_ ||
        accepted_checkpoint_pins_.contains(sequence))
    {
        InvalidateCheckpointPinCensus();
        return;
    }
    cached_checkpoint_pin_entries_ += pins.size();
    accepted_checkpoint_pins_.emplace(sequence, std::move(pins));
}

void TransactionManager::SeedCheckpointPinCensus(
    const std::vector<WriteAheadLog::Record>& records, std::uint64_t writer_generation)
{
    InvalidateCheckpointPinCensus();
    if (!recovery_state_valid_ || writer_generation == 0 ||
        writer_generation != journal_state_writer_generation_ ||
        finalization_coverage_trust_ != FinalizationCoverageTrust::Trusted ||
        highest_checkpointed_marker_sequence_ > watermarks_.cleanup_sequence) return;
    checkpoint_pin_census_trusted_ = true;
    checkpoint_pin_census_writer_generation_ = writer_generation;
    std::vector<std::uint64_t> snapshot_pins;
    std::size_t prepared_count = 0;
    for (const auto& record : records)
    {
        if (record.state == WriteAheadLog::RecordState::Prepared)
        {
            ++prepared_count;
            if (!AppendSnapshotCheckpointPins(record, snapshot_pins))
            {
                InvalidateCheckpointPinCensus();
                return;
            }
        }
        else if (record.operation == WriteAheadLog::OperationKind::TransactionMarker)
        {
            if (record.state == WriteAheadLog::RecordState::Accepted && record.sequence > watermarks_.cleanup_sequence)
            {
                // A compaction floor may omit a cleaned group's preparation,
                // but unresolved pin evidence must still contain the whole group.
                if (prepared_count == 0 || prepared_count != record.logical_length)
                {
                    InvalidateCheckpointPinCensus();
                    return;
                }
                snapshot_pins.push_back(record.object_id);
                CacheAcceptedCheckpointPins(record.sequence, std::move(snapshot_pins));
                if (!checkpoint_pin_census_trusted_) return;
            }
            snapshot_pins.clear();
            prepared_count = 0;
        }
    }
    if (accepted_checkpoint_pins_.size() != accepted_boundaries_.size()) InvalidateCheckpointPinCensus();
}

std::string TransactionManager::WideToUtf8(const std::wstring& value)
{
    if (value.empty())
    {
        return {};
    }

    const int required = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (required <= 0)
    {
        return {};
    }

    std::string output(static_cast<std::size_t>(required), '\0');
    const int written = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        output.data(),
        required,
        nullptr,
        nullptr);
    if (written != required)
    {
        return {};
    }

    return output;
}

} // namespace apfsaccess::rw

#include "TransactionManagerBackup.inc"
