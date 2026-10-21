#include "EncryptedImageRuntime.h"
#include "MetadataStore.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <atomic>
#include <mutex>
#include <stdexcept>
#include <utility>
#undef CreateFile
#undef CreateDirectory

namespace apfsaccess::catalog
{
namespace
{
namespace r = apfsaccess::rw;
using Op = EncryptedMutationKind;
using Phase = EncryptedImageWritePhase;
struct Handle
{
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE h) : value(h) {}
    Handle(Handle&& other) noexcept : value(std::exchange(other.value, INVALID_HANDLE_VALUE)) {}
    ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
template<class T> void Wipe(T& value) noexcept
{ if (!value.empty()) SecureZeroMemory(value.data(), value.size() * sizeof(value[0])); value.clear(); }
struct IntentWipe
{
    r::TransactionManager::MutationIntent& intent;
    ~IntentWipe() { Wipe(intent.path); Wipe(intent.secondary_path); Wipe(intent.inline_payload); }
};
struct AcceptedWipe
{
    std::vector<r::TransactionManager::AcceptedTransaction>& accepted;
    ~AcceptedWipe()
    { for (auto& tx : accepted) for (auto& record : tx.mutations) { Wipe(record.path_utf8); Wipe(record.secondary_path_utf8); Wipe(record.inline_payload); } }
};
bool IsMaintenance(const r::TransactionManager::AcceptedTransaction& transaction)
{
    return std::any_of(transaction.mutations.begin(), transaction.mutations.end(), [](const auto& record) {
        return record.operation == r::WriteAheadLog::OperationKind::Write &&
            record.path_utf8.starts_with("\\$apfs-keybag-rewrap-");
    });
}
bool IsTransition(const r::TransactionManager::AcceptedTransaction& transaction)
{
    return std::any_of(transaction.mutations.begin(), transaction.mutations.end(), [](const auto& record) {
        return record.operation == r::WriteAheadLog::OperationKind::Write &&
            record.path_utf8 == "\\$apfs-software-transition-v1";
    });
}
bool IsKeyRotation(const r::TransactionManager::AcceptedTransaction& transaction)
{
    return std::any_of(transaction.mutations.begin(), transaction.mutations.end(), [](const auto& record) {
        return record.operation == r::WriteAheadLog::OperationKind::Write &&
            record.path_utf8 == "\\$apfs-software-key-rotation-v1";
    });
}
std::array<std::uint8_t, 32> Digest(std::span<const std::byte> bytes)
{
    std::array<std::uint8_t, 32> result{};
    if (bytes.size() > ULONG_MAX || BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())), static_cast<ULONG>(bytes.size()),
        result.data(), static_cast<ULONG>(result.size())) < 0)
        throw std::runtime_error("EncryptedRuntimeHashFailed");
    return result;
}
std::array<std::byte, 32> StreamIdentity(std::string_view domain)
{
    const auto digest = Digest(std::as_bytes(std::span(domain)));
    std::array<std::byte, 32> result{};
    std::transform(digest.begin(), digest.end(), result.begin(), [](auto byte) { return std::byte(byte); });
    return result;
}
std::wstring Wide(std::string_view value)
{
    if (value.empty()) return {};
    if (value.size() > INT_MAX) throw std::runtime_error("EncryptedRuntimeNameInvalid");
    const auto n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (n <= 0) throw std::runtime_error("EncryptedRuntimeNameInvalid");
    std::wstring result(static_cast<std::size_t>(n), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), n) != n)
        throw std::runtime_error("EncryptedRuntimeNameInvalid");
    return result;
}
// Pin every existing ancestor without delete sharing before creating a child.
// Protected persistence independently checks its own files and epoch key roots.
void PinDirectory(const std::filesystem::path& path, std::vector<Handle>& held)
{
    const auto text = path.wstring();
    const auto local_drive = text.size() >= 3 &&
        ((text[0] >= L'A' && text[0] <= L'Z') || (text[0] >= L'a' && text[0] <= L'z'));
    if (text.size() < 4 || text.size() > 140 || !local_drive ||
        text[1] != L':' || text[2] != L'\\' || text.back() == L'\\' ||
        text.find_first_of(L":*?\"<>|/", 3) != text.npos ||
        GetDriveTypeW(text.substr(0, 3).c_str()) != DRIVE_FIXED)
        throw std::runtime_error("EncryptedRuntimeRecoveryDirectoryInvalid");
    for (std::size_t end = 2;;) {
        const auto prefix = text.substr(0, end == 2 ? 3 : end);
        if (end > 2) {
            const auto start = text.rfind(L'\\', end - 1) + 1;
            const auto component = text.substr(start, end - start);
            if (component.empty() || component == L"." || component == L".." ||
                component.back() == L'.' || component.back() == L' ' ||
                std::any_of(component.begin(), component.end(), [](wchar_t ch) { return ch < 32; }))
                throw std::runtime_error("EncryptedRuntimeRecoveryDirectoryInvalid");
            if (!CreateDirectoryW(prefix.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
                throw std::runtime_error("EncryptedRuntimeRecoveryDirectoryCreateFailed");
        }
        Handle handle(CreateFileW(prefix.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        FILE_ATTRIBUTE_TAG_INFO info{};
        if (handle.value == INVALID_HANDLE_VALUE ||
            !GetFileInformationByHandleEx(handle.value, FileAttributeTagInfo, &info, sizeof(info)) ||
            !(info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
            throw std::runtime_error("EncryptedRuntimeRecoveryDirectoryReparseOrLease");
        held.push_back(std::move(handle));
        if (end == text.size()) break;
        end = text.find(L'\\', end + 1);
        if (end == text.npos) end = text.size();
    }
}
}

struct EncryptedImageRuntime::Impl
{
    Options options;
    std::unique_ptr<ApfsEncryptedImageWriteSession> image;
    std::unique_ptr<r::TransactionManager> transactions;
    std::unique_ptr<r::PayloadSpool> payload;
    std::unique_ptr<r::EncryptedPublicationJournal> witness;
    std::vector<Handle> directories;
    std::wstring volume_identity;
    std::string volume_utf8;
    std::uint64_t commits_since_continuation = 0;
    std::uint64_t apply_invocation = 0;
    bool transition_history_pinned = false;
    mutable std::mutex gate;
    mutable std::mutex status_gate;
    std::atomic<std::uint64_t> accepted{0}, durable{0}, cleaned{0};
    std::atomic<bool> recovery{false}, closed{false};
    std::atomic<bool> persistence_valid{false};
    bool owner_failed = false;
    bool ApplyPlainWrite(const EncryptedMutationRequest&, std::uint64_t&, std::string&,
        const r::AppleCheckpointStageHook&);
    bool RecoverPlainWrite(const r::TransactionManager::AcceptedTransaction&, std::string&,
        const r::AppleCheckpointStageHook&);
    void Observe() noexcept
    {
        const auto watermarks = transactions->Watermarks();
        const auto payload_recovery = payload->RecoveryRequired();
        const bool valid = !owner_failed && transactions->RecoveryStateValid() && !payload_recovery;
        std::lock_guard lock(status_gate);
        accepted.store(watermarks.accepted_sequence);
        durable.store(watermarks.apfs_durable_sequence);
        cleaned.store(watermarks.cleanup_sequence);
        persistence_valid.store(valid);
        recovery.store(owner_failed || !transactions->RecoveryStateValid() || payload_recovery ||
            watermarks.accepted_sequence > watermarks.cleanup_sequence);
    }
    bool Pending(std::vector<r::TransactionManager::AcceptedTransaction>& rows, std::string& error)
    {
        if (!transactions->LoadAcceptedTransactionsSinceCleanup(rows, &error)) { persistence_valid.store(false); recovery.store(true); return false; }
        if (rows.size() > 1) { error = "EncryptedRuntimeSinglePendingBoundaryRequired"; persistence_valid.store(false); recovery.store(true); return false; }
        return true;
    }
    bool MaintainPayload(std::string& error)
    {
        r::WriteAheadLog::ProtectedHistoryHead head;
        if (!transactions->CaptureProtectedOriginalHistoryHead(head, error)) return false;
        return transactions->ReconcileProtectedPayloadSpool(*payload, head, error) ==
            r::PayloadSpool::ProtectedMaintenanceResult::Succeeded;
    }
    bool ContinueCleanHistory(std::string& error, const r::AppleCheckpointStageHook& hook = {}, bool automatic = false,
        const r::ProtectedJournalContinuation::ProgressHook& progress = {})
    {
        const auto result = image->WithCleanJournalEndpoint([&](auto& endpoint, std::string& reason) {
            return witness->ContinueCleanGeneration(*transactions, *payload, endpoint, reason, hook, progress);
        }, error);
        if (result != r::ProtectedJournalContinuation::Result::Succeeded) {
            if (result == r::ProtectedJournalContinuation::Result::RejectedBeforeWrite &&
                (error == "ContinuationTransitionRetentionUnsupported" ||
                 error == "ContinuationKeyRotationOwnerCertificateRetentionUnproved" ||
                 error == "ContinuationTransitionOwnerCertificateRetentionUnproved")) {
                transition_history_pinned = true;
                if (automatic) { error.clear(); return true; }
                error = "EncryptedRuntimeTransitionHistoryCapacity"; return false;
            }
            owner_failed = true; Observe(); return false;
        }
        commits_since_continuation = 0; Observe(); return true;
    }
    bool Finish(std::uint64_t sequence, std::string& error)
    {
        Observe();
        if (durable.load() < sequence || !transactions->MarkCleanedThrough(sequence)) {
            error = "EncryptedRuntimeCleanupNotDurable"; recovery.store(true); return false;
        }
        Observe();
        if (!MaintainPayload(error)) { recovery.store(true); return false; }
        Observe();
        ++commits_since_continuation;
        return true;
    }
    bool TransitionVolume(SoftwareVolumeMode mode, const crypto::SecureBytes& password,
        PasswordUnlockBudget& budget, std::string& error, const r::AppleCheckpointStageHook& hook)
    {
        error.clear();
        if (closed.load()) { error = "EncryptedRuntimeReadyOwnerRequired"; return false; }
        if (recovery.load() && !Recover(error, hook)) return false;
        const auto status = image->CachedStatus();
        if (status.recovery_required || (status.phase != Phase::Ready && status.phase != Phase::Locked)) {
            error = "EncryptedRuntimeTransitionOwnerRequired"; return false;
        }
        try {
            if (!transition_history_pinned && commits_since_continuation >= 8 &&
                !ContinueCleanHistory(error, hook, true)) return false;
            std::uint64_t sequence = 0;
            const auto observed_hook = [&](std::string_view stage) { Observe(); return !hook || hook(stage); };
            const auto published = mode == SoftwareVolumeMode::Plain
                ? image->Decrypt(*transactions, *witness, status.checkpoint_xid, password, budget, sequence, error, observed_hook)
                : image->Encrypt(*transactions, *witness, status.checkpoint_xid, password, budget, sequence, error, observed_hook);
            if (sequence) transition_history_pinned = true;
            if (!published && image->CachedStatus().recovery_required) {
                const auto marks = transactions->Watermarks();
                if (marks.accepted_sequence == marks.cleanup_sequence) owner_failed = true;
            }
            Observe();
            if (!published) return false;
            return Finish(sequence, error);
        } catch (const std::exception& ex) {
            owner_failed = true; Observe(); error = ex.what(); return false;
        }
    }
    bool Recover(std::string& error, const r::AppleCheckpointStageHook& hook)
    {
        std::vector<r::TransactionManager::AcceptedTransaction> rows; AcceptedWipe wipe{rows};
        if (!Pending(rows, error)) return false;
        if (rows.empty()) {
            Observe();
            if (owner_failed) { error = "EncryptedRuntimeOriginalReopenRequired"; return false; }
            if ((accepted.load() || payload->RecoveryRequired()) && !MaintainPayload(error)) { recovery.store(true); return false; }
            Observe();
            return !recovery.load();
        }
        const auto sequence = rows.front().accepted_sequence;
        // Routing comes only from authenticated original rows. The journal
        // still requires the exact private authorization and full chunk set.
        if (IsKeyRotation(rows.front())) {
            transition_history_pinned = true;
            if (!image->RecoverAcceptedKeyRotation(*transactions, *witness, sequence, error, hook)) {
                recovery.store(true); return false;
            }
            return Finish(sequence, error);
        }
        if (IsTransition(rows.front())) {
            transition_history_pinned = true;
            if (!image->RecoverAcceptedTransition(*transactions, *witness, sequence, error, hook)) {
                recovery.store(true); return false;
            }
            return Finish(sequence, error);
        }
        if (IsMaintenance(rows.front())) {
            if (!image->RecoverAcceptedMaintenance(*transactions, *witness, sequence, error, hook)) {
                recovery.store(true); return false;
            }
            return Finish(sequence, error);
        }
        const auto& plain_rows = rows.front().mutations;
        if (plain_rows.size() == 1 && plain_rows.front().operation == r::WriteAheadLog::OperationKind::Write &&
            !plain_rows.front().path_utf8.empty() && plain_rows.front().path_utf8.front() == '\\' &&
            !plain_rows.front().path_utf8.starts_with("\\$apfs-"))
            return RecoverPlainWrite(rows.front(), error, hook);
        r::EncryptedPublicationJournal::AcceptedDataRecovery disposition;
        if (!witness->InspectAcceptedDataRecovery(*transactions, sequence, disposition, error)) {
            recovery.store(true); return false;
        }
        if (disposition == r::EncryptedPublicationJournal::AcceptedDataRecovery::CompleteWitness) {
            if (!image->RecoverAccepted(*transactions, *witness, sequence, error, hook)) {
                recovery.store(true); return false;
            }
        } else {
            if (image->CachedStatus().phase != Phase::Ready) {
                error = "EncryptedRuntimeRecoveryUnlockRequired"; recovery.store(true); return false;
            }
            const auto& record = rows.front().mutations.front();
            if (record.payload_length && record.inline_payload.empty()) {
                if (record.payload_length > MaxWriteBytes) {
                    error = "EncryptedRuntimeRecoveryPayloadProfileExceeded"; recovery.store(true); return false;
                }
                if (!MaintainPayload(error)) { recovery.store(true); return false; }
                r::PayloadSpool::PersistedRangeReference ref{record.volume_identity, record.object_id,
                    record.parent_object_id, record.logical_offset, record.payload_length,
                    record.payload_offset, record.sequence, record.payload_sha256};
                std::string consumer_error;
                const auto recovered = payload->WithProtectedPersistedRange(ref, MaxWriteBytes,
                    [&](std::span<const std::byte> exact) {
                        return image->RecoverAcceptedMutationWithTransitionRetention(*transactions, *witness, sequence, exact, consumer_error, {}, hook);
                    }, error);
                if (!recovered) {
                    if (!consumer_error.empty()) error = std::move(consumer_error);
                    recovery.store(true); return false;
                }
            } else if (!image->RecoverAcceptedMutationWithTransitionRetention(*transactions, *witness, sequence, {}, error, {}, hook)) {
                recovery.store(true); return false;
            }
        }
        return Finish(sequence, error);
    }
};

#include "EncryptedImagePlainRuntime.inc"

EncryptedImageRuntime::EncryptedImageRuntime(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
EncryptedImageRuntime::~EncryptedImageRuntime() { Close(); }
std::unique_ptr<EncryptedImageRuntime> EncryptedImageRuntime::Open(const Options& options, std::string& error)
{
    error.clear();
    try {
        if (options.journal_bytes < (1ull << 20) || options.journal_bytes > (64ull << 20) ||
            options.payload_bytes < (1ull << 20) || options.payload_bytes > (512ull << 20)) {
            error = "EncryptedRuntimeCapacityInvalid"; return {};
        }
        auto impl = std::make_unique<Impl>(); impl->options = options;
        impl->image = ApfsEncryptedImageWriteSession::Open(options.image, error);
        if (!impl->image) return {};
        PinDirectory(options.recovery_directory, impl->directories);
        const auto& root = options.recovery_directory;
        for (const auto& child : {L"original-keys", L"witness-keys", L"payload", L"payload-keys"})
            PinDirectory(root / child, impl->directories);
        impl->volume_utf8 = "apfs-vol:" + impl->image->ContainerUuid() + ":" + std::to_string(impl->image->VolumeObjectId());
        impl->volume_identity = Wide(impl->volume_utf8);
        const auto protection = [&](const wchar_t* keys, const char* domain) {
            return r::WriteAheadLog::ProtectedPersistence{root / keys, impl->image->SourceBinding(),
                StreamIdentity(domain), {options.journal_bytes, 65536}, 256ull << 20};
        };
        impl->transactions = std::make_unique<r::TransactionManager>(L"Conservative");
        const r::WriteAheadLog::Options original{root / L"original.wal", impl->volume_utf8,
            options.journal_bytes, protection(L"original-keys", "apfs-encrypted-runtime-original-v1")};
        r::PayloadSpool::Options spool;
        spool.root = root / L"payload"; spool.volume_identity = impl->volume_utf8;
        spool.max_bytes = options.payload_bytes; spool.protected_persistence = true;
        spool.protected_binding = impl->image->SourceBinding(); spool.protected_key_directory = root / L"payload-keys";
        spool.durable_flush_bytes = spool.durable_flush_appends = 0;
        spool.startup_index_max_bytes = 16ull << 20; spool.startup_payload_read_max_bytes = options.payload_bytes;
        impl->payload = std::make_unique<r::PayloadSpool>(spool);
        if (!impl->payload->MatchesProtectedMaintenanceAuthority(impl->image->SourceBinding(),
            impl->volume_utf8, root / L"original-keys")) {
            error = "EncryptedRuntimeProtectedStorageConfigurationInvalid"; return {};
        }
        r::EncryptedPublicationJournal::Options journal;
        journal.container_bytes = impl->image->CachedStatus().container_bytes;
        journal.container_uuid = impl->image->ContainerUuid(); journal.volume_uuid = impl->image->VolumeUuid();
        journal.volume_object_id = impl->image->VolumeObjectId(); journal.preimage_source_identity = impl->image->SourceIdentity();
        journal.witness = {root / L"witness.wal", impl->volume_utf8 + ":ciphertext-witness", options.journal_bytes,
            protection(L"witness-keys", "apfs-encrypted-runtime-witness-v2")};
        journal.maintenance_original_journal_identity = original.protected_persistence->journal_identity;
        impl->witness = std::make_unique<r::EncryptedPublicationJournal>(std::move(journal));
        const auto opened = impl->image->WithCleanJournalEndpoint([&](auto& endpoint, std::string& reason) {
            return impl->witness->OpenOrRecoverCleanGeneration(*impl->transactions, original, *impl->payload, endpoint, reason)
                ? r::ProtectedJournalContinuation::Result::Succeeded : r::ProtectedJournalContinuation::Result::RecoveryRequired;
        }, error);
        if (opened != r::ProtectedJournalContinuation::Result::Succeeded) return {};
        impl->Observe();
        std::vector<r::TransactionManager::AcceptedTransaction> rows; AcceptedWipe wipe{rows};
        if (!impl->Pending(rows, error)) return {};
        return std::unique_ptr<EncryptedImageRuntime>(new EncryptedImageRuntime(std::move(impl)));
    } catch (const std::exception& ex) { error = ex.what(); return {}; }
}
bool EncryptedImageRuntime::Unlock(const crypto::SecureBytes& password, PasswordUnlockBudget& budget, std::string& error)
{
    std::lock_guard lock(impl_->gate); error.clear();
    if (impl_->closed.load()) { error = "EncryptedRuntimeClosed"; return false; }
    // Replay complete ciphertext evidence before admitting a key for its final
    // checkpoint. Empty-witness recovery instead needs the original preimage key.
    if (impl_->recovery.load()) {
        std::vector<r::TransactionManager::AcceptedTransaction> rows; AcceptedWipe wipe{rows};
        if (!impl_->Pending(rows, error)) return false;
        if (!rows.empty()) {
            if (IsTransition(rows.front()) || IsKeyRotation(rows.front()) || IsMaintenance(rows.front())) {
                if (!impl_->Recover(error, {})) return false;
            } else {
                r::EncryptedPublicationJournal::AcceptedDataRecovery disposition;
                if (!impl_->witness->InspectAcceptedDataRecovery(*impl_->transactions, rows.front().accepted_sequence, disposition, error))
                    return false;
                if (disposition == r::EncryptedPublicationJournal::AcceptedDataRecovery::CompleteWitness && !impl_->Recover(error, {}))
                    return false;
            }
        }
    }
    if (!impl_->image->Unlock(password, budget, error)) return false;
    return !impl_->recovery.load() || impl_->Recover(error, {});
}
bool EncryptedImageRuntime::ChangePassword(const crypto::SecureBytes& old_password,
    const crypto::SecureBytes& new_password, PasswordUnlockBudget& budget, std::string& error,
    const r::AppleCheckpointStageHook& hook)
{
    std::lock_guard lock(impl_->gate); error.clear();
    if (impl_->closed.load() || impl_->recovery.load()) {
        error = "EncryptedRuntimeReadyOwnerRequired"; return false;
    }
    const auto status = impl_->image->CachedStatus();
    if (status.phase != Phase::Ready || status.recovery_required) {
        error = "EncryptedRuntimeReadyMaintenanceOwnerRequired"; return false;
    }
    std::uint64_t sequence = 0;
    try {
        if (!impl_->transition_history_pinned && impl_->commits_since_continuation >= 8 &&
            !impl_->ContinueCleanHistory(error, hook, true)) return false;
        const auto observed_hook = [&](std::string_view stage) {
            impl_->Observe();
            return !hook || hook(stage);
        };
        const bool published = impl_->image->ChangePassword(*impl_->transactions, *impl_->witness,
            status.checkpoint_xid, old_password, new_password, budget, sequence, error, observed_hook);
        if (!published && impl_->image->CachedStatus().recovery_required) {
            const auto watermarks = impl_->transactions->Watermarks();
            if (watermarks.accepted_sequence == watermarks.cleanup_sequence) impl_->owner_failed = true;
        }
        impl_->Observe();
        if (!published) return false;
        return impl_->Finish(sequence, error);
    }
    catch (const std::exception& ex) {
        impl_->owner_failed = true; impl_->Observe(); error = ex.what(); return false;
    }
}
bool EncryptedImageRuntime::Encrypt(const crypto::SecureBytes& password, PasswordUnlockBudget& budget,
    std::string& error, const r::AppleCheckpointStageHook& hook)
{
    std::lock_guard lock(impl_->gate);
    return impl_->TransitionVolume(SoftwareVolumeMode::OneKeyGenerationZero, password, budget, error, hook);
}
bool EncryptedImageRuntime::Decrypt(const crypto::SecureBytes& password, PasswordUnlockBudget& budget,
    std::string& error, const r::AppleCheckpointStageHook& hook)
{
    std::lock_guard lock(impl_->gate);
    return impl_->TransitionVolume(SoftwareVolumeMode::Plain, password, budget, error, hook);
}
bool EncryptedImageRuntime::Apply(const EncryptedMutationRequest& request, std::uint64_t& result_inode,
    std::string& error, const r::AppleCheckpointStageHook& hook)
{
    return Apply(request, result_inode, error, hook, {});
}

bool EncryptedImageRuntime::Apply(const EncryptedMutationRequest& request, std::uint64_t& result_inode,
    std::string& error, const r::AppleCheckpointStageHook& hook, const ProgressHook& progress)
{
    std::lock_guard lock(impl_->gate); error.clear(); result_inode = 0;
    if (!impl_->closed.load() && impl_->image->CachedStatus().phase == Phase::Locked) {
        try {
        if (impl_->apply_invocation == UINT64_MAX) { error = "EncryptedRuntimeInvocationExhausted"; return false; }
        const auto invocation = ++impl_->apply_invocation;
        if (!impl_->ApplyPlainWrite(request, result_inode, error, hook)) return false;
        if (progress) {
            const DurableProgress event(this, invocation, 1, 20, DurableBoundary::PublicationReconciled);
            if (!progress(event)) { error = "EncryptedRuntimeDurableObserverRefused"; return false; }
        }
        return true;
        } catch (const std::exception& ex) {
            if (impl_->transactions->CurrentState() == r::TransactionManager::State::Active)
                (void)impl_->transactions->Abort();
            impl_->owner_failed = true; impl_->Observe(); error = ex.what(); return false;
        }
    }
    if (impl_->closed.load() || impl_->recovery.load()) { error = "EncryptedRuntimeReadyOwnerRequired"; return false; }
    const auto status = impl_->image->CachedStatus();
    if (status.phase != Phase::Ready || request.data.size() > MaxWriteBytes ||
        (request.kind == Op::Create && request.data.size() > 4096)) {
        error = "EncryptedRuntimeReadyMutationProfileRequired"; return false;
    }
    try {
        if (impl_->apply_invocation == UINT64_MAX) { error = "EncryptedRuntimeInvocationExhausted"; return false; }
        const auto invocation = ++impl_->apply_invocation;
        const auto previous_accepted = impl_->accepted.load();
        std::uint64_t ordinal = 0;
        const auto observe_progress = [&](std::uint8_t slot, DurableBoundary boundary) {
            if (!progress) return true;
            const DurableProgress event(this, invocation, ++ordinal, slot, boundary);
            if (progress(event)) return true;
            error = "EncryptedRuntimeDurableObserverRefused"; return false;
        };
        const r::ProtectedJournalContinuation::ProgressHook continuation_progress = [&](const auto& event) {
            using Boundary = r::ProtectedJournalContinuation::DurableBoundary;
            std::optional<DurableBoundary> boundary;
            switch (event.Boundary()) {
            case Boundary::OriginalSpoolBarrier: boundary = DurableBoundary::OriginalSpoolBarrier; break;
            case Boundary::IntentFlushed: boundary = DurableBoundary::IntentFlushed; break;
            case Boundary::RecoveryBarrier: boundary = DurableBoundary::RecoveryBarrier; break;
            case Boundary::ControlRenamed: boundary = DurableBoundary::ControlRenamed; break;
            case Boundary::CertificatePromoted: boundary = DurableBoundary::CertificatePromoted; break;
            case Boundary::CandidateFlushed: boundary = DurableBoundary::CandidateFlushed; break;
            case Boundary::OldRenamed: boundary = DurableBoundary::OldRenamed; break;
            case Boundary::NewRenamed: boundary = DurableBoundary::NewRenamed; break;
            case Boundary::CompletionReceipt: boundary = DurableBoundary::CompletionReceipt; break;
            case Boundary::RetirementReceipt: boundary = DurableBoundary::RetirementReceipt; break;
            case Boundary::ReadyReceipt: boundary = DurableBoundary::ReadyReceipt; break;
            }
            if (!boundary || event.Slot() >= 20) { error = "EncryptedRuntimeDurableBoundaryInvalid"; return false; }
            return observe_progress(event.Slot(), *boundary);
        };
        bool continuation_attempted = false;
        const auto continue_history = [&](bool automatic) {
            if (continuation_attempted) { error = "EncryptedPublicationCapacityExceeded"; return false; }
            continuation_attempted = true;
            return impl_->ContinueCleanHistory(error, hook, automatic, continuation_progress);
        };
        const auto stage = [&](std::string_view name) {
            if (!hook || hook(name)) return true;
            error = "EncryptedRuntimeInterrupted:" + std::string(name); return false;
        };
        if (!impl_->transition_history_pinned && impl_->commits_since_continuation >= 8 &&
            !continue_history(true)) return false;
        if (!stage("before-encrypted-private-prepare")) return false;
        auto prepared = impl_->image->PrepareMutationWithTransitionRetention(
            *impl_->transactions, *impl_->witness, status.checkpoint_xid, request, error);
        if (!prepared) return false;
        if (!stage("after-encrypted-private-prepare")) return false;
        if (!impl_->witness->DataCapacityAvailable(*impl_->transactions, prepared->Intent(), error)) {
            if (error != "EncryptedPublicationCapacityExceeded" || !impl_->accepted.load() ||
                !continue_history(false) ||
                !impl_->witness->DataCapacityAvailable(*impl_->transactions, prepared->Intent(), error)) return false;
        }
        if (!stage("after-encrypted-witness-preflight")) return false;
        r::TransactionManager::MutationIntent intent; IntentWipe wipe{intent};
        intent.object_id = request.kind == Op::Create || request.kind == Op::MakeDirectory ? status.next_inode_id : request.inode;
        intent.path = L"encrypted-data";
        switch (request.kind) {
        case Op::Overwrite: case Op::Write:
            intent.kind = r::TransactionManager::MutationKind::Write; intent.offset = request.offset;
            intent.length = request.data.size(); break;
        case Op::Resize:
            intent.kind = r::TransactionManager::MutationKind::SetFileSize; intent.length = request.size; break;
        case Op::Create:
            intent.kind = r::TransactionManager::MutationKind::CreateFile; intent.path = Wide(request.name);
            intent.generation = request.parent; intent.offset = request.permissions; intent.length = request.data.size(); break;
        case Op::MakeDirectory:
            intent.kind = r::TransactionManager::MutationKind::CreateDirectory; intent.path = Wide(request.name);
            intent.generation = request.parent; intent.offset = request.permissions; break;
        case Op::SetInodeMetadata:
            intent.kind = r::TransactionManager::MutationKind::SetInodeMetadata;
            intent.generation = status.checkpoint_xid; intent.length = request.data.size(); break;
        case Op::SetExtendedAttribute:
        case Op::RemoveExtendedAttribute:
            intent.kind = request.kind == Op::SetExtendedAttribute
                ? r::TransactionManager::MutationKind::SetExtendedAttribute
                : r::TransactionManager::MutationKind::RemoveExtendedAttribute;
            intent.generation = status.checkpoint_xid; intent.secondary_path = Wide(request.name); break;
        case Op::Rename:
        case Op::ReplaceRename:
            intent.kind = r::TransactionManager::MutationKind::Rename; intent.path = Wide(request.name);
            intent.secondary_path = Wide(request.destination_name); intent.generation = request.parent;
            intent.offset = request.destination_parent;
            intent.replace_if_exists = request.kind == Op::ReplaceRename; break;
        case Op::Unlink:
            intent.kind = r::TransactionManager::MutationKind::Delete; intent.path = Wide(request.name);
            intent.generation = request.parent; break;
        default: error = "EncryptedRuntimeMutationUnsupported"; return false;
        }
        const bool data = request.kind == Op::Write || request.kind == Op::Overwrite || request.kind == Op::Create ||
            request.kind == Op::SetInodeMetadata || request.kind == Op::SetExtendedAttribute;
        const bool spooled = data && request.kind != Op::SetInodeMetadata && request.kind != Op::SetExtendedAttribute && !request.data.empty() &&
            (request.kind == Op::Create || request.data.size() > 4096);
        if (data) {
            intent.payload_length = request.data.size(); intent.payload_checksum = Digest(request.data);
            if (!spooled) intent.inline_payload.assign(request.data.begin(), request.data.end());
            else {
                if (request.kind != Op::Create) intent.generation = status.checkpoint_xid;
                intent.wal_sequence = impl_->transactions->NextMutationSequence();
                if (impl_->payload->CheckAppendCapacity(request.data.size()) != r::PayloadSpool::AppendStatus::Succeeded) {
                    error = "EncryptedRuntimePayloadCapacity"; return false;
                }
            }
        }
        if (!impl_->transactions->ProtectedMutationCapacityAvailable(intent, error)) return false;
        if (!stage("after-encrypted-original-preflight")) return false;
        if (!impl_->transactions->Begin()) { error = "EncryptedRuntimeBeginFailed"; return false; }
        if (spooled) {
            r::PayloadSpool::AppendResult ref;
            const auto append = impl_->payload->AppendWithStatus({impl_->volume_utf8, intent.object_id, intent.generation,
                intent.offset, impl_->transactions->NextMutationSequence(), request.data}, &ref);
            const auto flushed = append == r::PayloadSpool::AppendStatus::Succeeded && impl_->payload->FlushPayloadBytes();
            if (!flushed) {
                const auto aborted = impl_->transactions->Abort();
                impl_->owner_failed = true; impl_->recovery.store(true);
                error = !aborted ? "EncryptedRuntimeAbortFailed" : append != r::PayloadSpool::AppendStatus::Succeeded ?
                    "EncryptedRuntimePayloadAppendFailed" : "EncryptedRuntimePayloadFlushFailed";
                return false;
            }
            intent.wal_sequence = ref.wal_sequence; intent.payload_spool_offset = ref.spool_offset;
            intent.payload_checksum = ref.payload_sha256;
        }
        if (!impl_->transactions->RecordMutation(intent) || !impl_->transactions->Accept(status.checkpoint_xid)) {
            if (impl_->transactions->CurrentState() == r::TransactionManager::State::Active)
                (void)impl_->transactions->Abort();
            impl_->owner_failed = true; impl_->Observe(); error = "EncryptedRuntimeOriginalAcceptanceFailed"; return false;
        }
        impl_->Observe(); const auto sequence = impl_->accepted.load();
        if (hook && !hook("after-encrypted-original-accept")) {
            error = "EncryptedRuntimeInterruptedBeforeStage"; return false;
        }
        if (!impl_->image->CommitAcceptedPrepared(*impl_->transactions, *impl_->witness, sequence,
            status.checkpoint_xid, std::move(prepared), error, hook)) {
            impl_->recovery.store(true); return false;
        }
        impl_->Observe();
        if (!stage("before-encrypted-cleanup")) return false;
        if (!impl_->Finish(sequence, error)) return false;
        const auto final_marks = impl_->transactions->Watermarks();
        if (sequence <= previous_accepted || final_marks.accepted_sequence != sequence ||
            final_marks.apfs_durable_sequence != sequence || final_marks.cleanup_sequence != sequence ||
            !impl_->persistence_valid.load() || impl_->recovery.load()) {
            impl_->owner_failed = true; impl_->Observe(); error = "EncryptedRuntimeCompletedBoundaryInvalid"; return false;
        }
        if (!observe_progress(20, DurableBoundary::PublicationReconciled)) return false;
        result_inode = intent.object_id;
        return true;
    } catch (const std::exception& ex) {
        if (impl_->transactions->CurrentState() != r::TransactionManager::State::Idle) {
            if (impl_->transactions->CurrentState() == r::TransactionManager::State::Active)
                (void)impl_->transactions->Abort();
            impl_->owner_failed = true;
        }
        impl_->Observe(); error = ex.what();
        return false;
    }
}
bool EncryptedImageRuntime::Write(std::uint64_t inode, std::uint64_t offset,
    std::span<const std::byte> bytes, std::size_t& completed, std::string& error,
    const r::AppleCheckpointStageHook& hook)
{
    return Write(inode, offset, bytes, completed, error, hook, {});
}

bool EncryptedImageRuntime::Write(std::uint64_t inode, std::uint64_t offset,
    std::span<const std::byte> bytes, std::size_t& completed, std::string& error,
    const r::AppleCheckpointStageHook& hook, const ProgressHook& progress)
{
    completed = 0; error.clear();
    if (inode < 16 || offset > UINT64_MAX - bytes.size()) {
        error = "EncryptedRuntimeWriteRangeInvalid"; return false;
    }
    const auto status = CachedStatus();
    if (status.closed || (status.image.phase != Phase::Locked &&
            (status.recovery_required || status.image.phase != Phase::Ready))) {
        error = "EncryptedRuntimeReadyOwnerRequired"; return false;
    }
    while (completed < bytes.size()) {
        EncryptedMutationRequest request;
        request.kind = Op::Write; request.inode = inode; request.offset = offset + completed;
        request.data = bytes.subspan(completed, (std::min)(MaxWriteBytes, bytes.size() - completed));
        std::uint64_t result = 0;
        if (!Apply(request, result, error, hook, progress)) return false;
        completed += request.data.size();
    }
    return true;
}
bool EncryptedImageRuntime::Recover(std::string& error, const r::AppleCheckpointStageHook& hook)
{
    std::lock_guard lock(impl_->gate); error.clear();
    if (impl_->closed.load()) { error = "EncryptedRuntimeClosed"; return false; }
    return impl_->Recover(error, hook);
}
std::shared_ptr<ApfsEncryptedReadSession> EncryptedImageRuntime::OpenReadView(EncryptedReadError& error)
{
    std::lock_guard lock(impl_->gate);
    if (impl_->closed.load() || impl_->recovery.load()) { error = EncryptedReadError::Closed; return {}; }
    return impl_->image->OpenReadView(error);
}
std::shared_ptr<EncryptedImageRuntime::ReadInode> EncryptedImageRuntime::RetainReadInode(
    std::uint64_t inode, std::string& error)
{
    std::lock_guard lock(impl_->gate); error.clear();
    if (impl_->closed.load() || impl_->recovery.load()) {
        error = "EncryptedRuntimeReadyOwnerRequired"; return {};
    }
    return impl_->image->RetainReadInode(inode, error);
}
std::shared_ptr<ApfsEncryptedReadSession> EncryptedImageRuntime::OpenReadView(
    const ReadInode& inode, EncryptedReadError& error)
{
    std::lock_guard lock(impl_->gate);
    if (impl_->closed.load() || impl_->recovery.load()) { error = EncryptedReadError::Closed; return {}; }
    return impl_->image->OpenReadView(inode, error);
}
EncryptedImageRuntime::Status EncryptedImageRuntime::CachedStatus() const noexcept
{
    std::lock_guard lock(impl_->status_gate);
    return {impl_->image->CachedStatus(), impl_->accepted.load(), impl_->durable.load(), impl_->cleaned.load(),
        impl_->recovery.load(), impl_->closed.load()};
}
bool EncryptedImageRuntime::CachedPersistenceStateValid() const noexcept
{ return impl_->persistence_valid.load(); }
void EncryptedImageRuntime::Lock() noexcept
{ std::lock_guard lock(impl_->gate); if (!impl_->closed.load()) impl_->image->Lock(); }
const std::string& EncryptedImageRuntime::SourceIdentity() const noexcept { return impl_->image->SourceIdentity(); }
const std::string& EncryptedImageRuntime::ContainerUuid() const noexcept { return impl_->image->ContainerUuid(); }
const std::string& EncryptedImageRuntime::VolumeUuid() const noexcept { return impl_->image->VolumeUuid(); }
std::uint64_t EncryptedImageRuntime::VolumeObjectId() const noexcept { return impl_->image->VolumeObjectId(); }
std::optional<PasswordUnlockRequest> EncryptedImageRuntime::UnlockedSelection() const
{ std::lock_guard lock(impl_->gate); return impl_->image->UnlockedSelection(); }
bool EncryptedImageRuntime::ObserveKeyManagementEndpoint(ImageKeyManagementEndpoint& output, std::string& error)
{
    std::lock_guard lock(impl_->gate); output = {}; error.clear();
    if (impl_->closed.load()) { error = "EncryptedRuntimeClosed"; return false; }
    std::vector<r::TransactionManager::AcceptedTransaction> pending; AcceptedWipe wipe{pending};
    if (!impl_->Pending(pending, error)) return false;
    impl_->Observe();
    if (!pending.empty() || !impl_->persistence_valid.load() || impl_->recovery.load() ||
        impl_->accepted.load() != impl_->durable.load() || impl_->accepted.load() != impl_->cleaned.load() ||
        impl_->transactions->CurrentState() != r::TransactionManager::State::Idle) {
        error = "EncryptedRuntimeCleanEndpointRequired"; return false;
    }
    if (!impl_->witness->KeyManagementEndpointClean(*impl_->transactions, error)) return false;
    return impl_->image->ObserveKeyManagementEndpoint(output, error);
}
void EncryptedImageRuntime::Cancel() noexcept { impl_->image->Cancel(); }
void EncryptedImageRuntime::Close() noexcept
{
    std::lock_guard lock(impl_->gate);
    if (impl_->closed.exchange(true)) return;
    impl_->image->Close(); impl_->witness.reset(); impl_->payload.reset(); impl_->transactions.reset();
    impl_->directories.clear();
}
#include "EncryptedRuntimeKeyRotation.inc"
}
