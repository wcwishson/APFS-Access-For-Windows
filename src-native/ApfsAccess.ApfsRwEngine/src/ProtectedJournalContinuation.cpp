#include "ProtectedJournalContinuation.h"
#include "TransactionManager.h"

#include <algorithm>
#include <cstring>
#include <set>
#include <stdexcept>
#include <windows.h>
#include <bcrypt.h>

#undef CreateDirectory
#undef CreateFile

namespace apfsaccess::rw
{
#include "ProtectedJournalContinuationFiles.inc"
ProtectedJournalContinuation::Authority::RetainedAuthorization::~RetainedAuthorization()
{
    for (auto& row : original_records) SecureZeroMemory(row.data(), row.size());
}
void ProtectedJournalContinuation::Authority::RetainedAuthorization::Swap(RetainedAuthorization& other) noexcept
{
    using std::swap;
    swap(version, other.version); swap(accepted, other.accepted); swap(transaction, other.transaction); swap(spent, other.spent);
    swap(body_sha256, other.body_sha256); swap(intent_sha256, other.intent_sha256); swap(receipt_sha256, other.receipt_sha256);
    swap(original_records, other.original_records); swap(witness_sequences, other.witness_sequences);
}
auto ProtectedJournalContinuation::Authority::RetainedAuthorization::operator=(const RetainedAuthorization& other) -> RetainedAuthorization&
{ RetainedAuthorization copy(other); Swap(copy); return *this; }
auto ProtectedJournalContinuation::Authority::RetainedAuthorization::operator=(RetainedAuthorization&& other) noexcept -> RetainedAuthorization&
{ RetainedAuthorization moved(std::move(other)); Swap(moved); return *this; }

bool ProtectedJournalContinuation::ReadRetainedAuthorization(const TransactionManager& tm, std::uint64_t accepted,
    const Digest& body, std::optional<Authority::RetainedAuthorization>& out, std::string& error)
{
    out.reset();
    if (!tm.continuation_seed_) return true;
    if ((!tm.recovery_state_valid_ && tm.state_ != TransactionManager::State::Idle) ||
        tm.journal_append_ambiguous_ || !tm.journal_.HasExclusiveWriterLease() ||
        !tm.journal_.continuation_authority_ || !tm.journal_.continuation_admission_ ||
        !tm.journal_.continuation_admission_->validate_authority || !tm.journal_.continuation_admission_->validate_authority()) {
        error = "ContinuationRetainedAuthorizationUnavailable"; return false;
    }
    const auto op = std::static_pointer_cast<Operation>(tm.journal_.continuation_authority_);
    for (const auto& value : op->authority.retained_authorizations) if (value.accepted == accepted) {
        if (value.body_sha256 != body) { error = "ContinuationRetainedAuthorizationMismatch"; return false; }
        out = value; return true;
    }
    return true;
}
bool ProtectedJournalContinuation::FlushCleanOriginalEvidence(TransactionManager& original,
    const WriteAheadLog::ProtectedHistoryHead& expected, std::uint64_t cleanup, std::string& error)
{
    std::lock_guard append_lock(original.deferred_wal_append_mutex_);
    const auto fail = [&] { error = "ContinuationCleanOriginalBarrierFailed"; return false; };
    const auto marks = original.watermarks_;
    const auto generation = original.journal_.ExclusiveWriterLeaseGeneration();
    WriteAheadLog::ProtectedHistoryHead before, after;
    if (!original.ProtectedSpoolOwnerValid() || !cleanup || marks.accepted_sequence != cleanup ||
        marks.apfs_durable_sequence != cleanup || marks.cleanup_sequence != cleanup || !generation ||
        !original.journal_.CaptureProtectedHistoryHead(before) || before != expected) return fail();
    if (!original.journal_.FlushPendingAppends()) { original.MarkDeferredAcceptanceDurabilityFailure(); return fail(); }
    if (!original.journal_.CaptureProtectedHistoryHead(after) || after != expected ||
        original.journal_.ExclusiveWriterLeaseGeneration() != generation) {
        original.MarkDeferredAcceptanceDurabilityFailure(); return fail();
    }
    return true;
}

bool ProtectedJournalContinuation::CaptureOriginalSeed(const TransactionManager& original,
    Seed& seed, std::string& error)
{
    seed = {}; error.clear();
    const auto fail = [&]() { error = "ContinuationOriginalNotClean"; return false; };
    if (!original.ProtectedSpoolOwnerValid() || !original.next_sequence_ ||
        original.next_sequence_ == UINT64_MAX || !original.next_transaction_id_ ||
        original.next_transaction_id_ == UINT64_MAX) return fail();
    const auto marks = original.watermarks_;
    if (!marks.accepted_sequence || marks.accepted_sequence != marks.apfs_durable_sequence ||
        marks.accepted_sequence != marks.cleanup_sequence || marks.accepted_sequence >= original.next_sequence_)
        return fail();
    WriteAheadLog::ProtectedHistoryHead head;
    if (!original.journal_.CaptureProtectedHistoryHead(head) || head.last_sequence != original.next_sequence_ - 1)
        return fail();
    seed.last_sequence = head.last_sequence; seed.next_transaction_id = original.next_transaction_id_;
    seed.accepted_sequence = marks.accepted_sequence; seed.durable_sequence = marks.apfs_durable_sequence;
    seed.cleanup_sequence = marks.cleanup_sequence;
    return true;
}

bool ProtectedJournalContinuation::ValidateOriginalEvidence(const RecoveryEvidence& evidence,
    Seed& seed, std::string& error)
{
    seed = {}; error.clear();
    if (evidence.original.status != WriteAheadLog::ReadStatus::Ok || evidence.original.recovered_torn_tail ||
        evidence.original.records.size() != evidence.original_head.records) {
        error = "ContinuationOriginalEvidenceInvalid"; return false;
    }
    TransactionManager verifier(L"conservative");
    if (evidence.active_original_seed.last_sequence) {
        const auto& base = evidence.active_original_seed;
        verifier.journal_protection_ = WriteAheadLog::ProtectedPersistence{};
        verifier.continuation_seed_ = TransactionManager::ContinuationSeed{base.last_sequence, base.next_transaction_id,
            {base.accepted_sequence, base.durable_sequence, base.cleanup_sequence}};
    }
    std::uint64_t at = evidence.active_original_seed.last_sequence;
    for (const auto& record : evidence.original.records) {
        if (at == UINT64_MAX || record.sequence != ++at) { error = "ContinuationOriginalHistoryIncomplete"; return false; }
    }
    if (at != evidence.original_head.last_sequence) { error = "ContinuationOriginalSemanticsInvalid"; return false; }
    const bool closed = verifier.SeedIdsFromJournalRecords(evidence.original.records, 0) && verifier.RecoveryStateValid();
    if (!closed && (!evidence.admission_only ||
        !verifier.SeedAuthorizationPreparedPrefix(evidence.original.records, 0))) {
        error = "ContinuationOriginalSemanticsInvalid"; return false;
    }
    seed = {at, verifier.next_transaction_id_, verifier.watermarks_.accepted_sequence,
        verifier.watermarks_.apfs_durable_sequence, verifier.watermarks_.cleanup_sequence};
    return true;
}

bool ProtectedJournalContinuation::CaptureEvidence(TransactionManager& original, WriteAheadLog& witness,
    RecoveryEvidence& evidence, std::string& error)
{
    std::lock_guard append_lock(original.deferred_wal_append_mutex_);
    evidence = {}; error.clear();
    if (!original.ReadProtectedOriginalHistory(evidence.original_head, evidence.original.records, error)) return false;
    if (original.continuation_seed_) {
        if (!original.journal_.continuation_authority_ ||
            original.journal_.continuation_authority_ != witness.continuation_authority_) {
            error = "ContinuationCertificateCapabilityMissing"; return false;
        }
        const auto prior = std::static_pointer_cast<Operation>(original.journal_.continuation_authority_);
        evidence.certificate_authority = prior->authority;
        evidence.active_original_seed = prior->authority.original_seed;
        evidence.certified_endpoint = prior->endpoint;
        evidence.generation = prior->generation; evidence.certificate_sha256 = prior->certificate_hash;
    }
    if (!witness.options_.protected_persistence || !original.journal_protection_ ||
        witness.options_.protected_persistence->source_binding != original.journal_protection_->source_binding ||
        !witness.CaptureProtectedHistoryHead(evidence.witness_head)) {
        error = "ContinuationWitnessEvidenceInvalid"; return false;
    }
    evidence.certificate_authority.source_binding = original.journal_protection_->source_binding;
    evidence.certificate_authority.original_journal_identity = original.journal_protection_->journal_identity;
    evidence.certificate_authority.witness_journal_identity = witness.options_.protected_persistence->journal_identity;
    evidence.witness = witness.ReadAllAtProtectedHead(evidence.witness_head);
    if (evidence.witness.status != WriteAheadLog::ReadStatus::Ok || evidence.witness.recovered_torn_tail) {
        error = "ContinuationWitnessEvidenceInvalid"; return false;
    }
    return true;
}

ProtectedJournalContinuation::OriginalDescriptor ProtectedJournalContinuation::OriginalOptions(const TransactionManager& original)
{
    return original.journal_.options_;
}

ProtectedJournalContinuation::Result ProtectedJournalContinuation::Continue(TransactionManager& tm, PayloadSpool& spool,
    WriteAheadLog& witness, const Authority& authority, Endpoint& endpoint, std::string& error, const StageHook& hook)
{
    return Continue(tm, spool, witness, authority, endpoint, error, hook, {});
}

ProtectedJournalContinuation::Result ProtectedJournalContinuation::Continue(TransactionManager& tm, PayloadSpool& spool,
    WriteAheadLog& witness, const Authority& authority, Endpoint& endpoint, std::string& error, const StageHook& hook,
    const ProgressHook& progress)
{
    bool changed = false;
    const auto fail = [&] {
        if (changed) tm.MarkDeferredAcceptanceDurabilityFailure();
        if (error.empty()) error = "ContinuationPublicationFailed";
        return changed ? Result::RecoveryRequired : Result::RejectedBeforeWrite;
    };
    try {
        error.clear();
        auto op = std::make_shared<Operation>(); op->authority = authority; op->endpoint = endpoint.description_;
        if (!op->Bindings(tm.journal_.options_, witness, spool, error) || !authority.flush_and_recheck ||
            !endpoint.revalidate_ || !endpoint.read_guard_ || !endpoint.revalidate_(error) ||
            !authority.flush_and_recheck(error)) return fail();
        Seed seed;
        if (!CaptureOriginalSeed(tm, seed, error) || seed.last_sequence != authority.original_seed.last_sequence ||
            seed.next_transaction_id != authority.original_seed.next_transaction_id || seed.cleanup_sequence != authority.original_seed.cleanup_sequence)
            return fail();
        RecoveryEvidence evidence; CRecordsWipe ow{evidence.original.records}, ww{evidence.witness.records};
        if (!CaptureEvidence(tm, witness, evidence, error) || evidence.original_head != authority.original_head ||
            evidence.witness_head != authority.witness_head || !authority.witness_retained_first_sequence ||
            authority.witness_retained_first_sequence > authority.witness_last_sequence) return fail();
        std::shared_ptr<Operation> prior;
        if (tm.continuation_seed_) {
            prior = std::static_pointer_cast<Operation>(tm.journal_.continuation_authority_);
            op->generation = prior->generation + 1; op->predecessor_seed = prior->authority.original_seed;
            op->predecessor_publication = prior->authority.complete_publication_sha256;
            op->predecessor_original = prior->original; op->predecessor_witness = prior->witness;
        } else op->generation = 1;
        if (op->generation > 4095 || !op->Namespace(tm.journal_.options_, witness, spool)) {
            error = "ContinuationFiniteBudgetOrNamespaceRefused"; return fail();
        }
        changed = true;
        if (tm.ReconcileProtectedPayloadSpool(spool, authority.original_head, error) != PayloadSpool::ProtectedMaintenanceResult::Succeeded) return fail();
        PayloadSpool::ContinuationLease lease;
        if (!spool.CaptureContinuationSpool(lease, error) || lease.floor != seed.cleanup_sequence ||
            !authority.flush_and_recheck(error) || !op->Completed(DurableBoundary::OriginalSpoolBarrier, 0, progress, error) ||
            !Operation::Hook(hook, "continuation-after-original-spool-barrier", error)) return fail();
        op->spool.floor = lease.floor; op->spool.generation = op->generation; op->spool.tip = lease.tip;
        if (BCryptGenRandom(nullptr, op->spool.certificate.data(), static_cast<ULONG>(op->spool.certificate.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return fail();
        const auto anchor = [&](WriteAheadLog::ContinuationAdmission& admission, unsigned role, std::uint64_t sequence, const Digest& previous) {
            auto& b = admission.anchor; std::memcpy(b.data(), "WALCONT1", 8); CPut(b, 8, 6); CPut(b, 16, op->generation); CPut(b, 24, role);
            std::memcpy(b.data() + 32, authority.scope_binding.data(), 32); std::memcpy(b.data() + 64, op->spool.certificate.data(), 32);
            CPut(b, 96, sequence); CPut(b, 104, seed.next_transaction_id); CPut(b, 112, seed.accepted_sequence);
            CPut(b, 120, seed.durable_sequence); CPut(b, 128, seed.cleanup_sequence); std::memcpy(b.data() + 136, previous.data(), 32);
            CPut(b, 168, authority.checkpoint_xid); admission.last_sequence = sequence;
        };
        anchor(op->original, 1, seed.last_sequence, authority.original_head.sha256);
        anchor(op->witness, 2, authority.witness_retained_first_sequence - 1, authority.witness_head.sha256);
        // Keep the directory-wide writer leases throughout handle replacement.
        if (!tm.journal_.CloseAppendFileHandle() || !witness.CloseAppendFileHandle()) return fail();
        if (prior) {
            for (auto& pin : prior->retained) op->retained.push_back(std::move(pin));
            prior->retained.clear();
        }
        const auto options = tm.journal_.options_;
        auto* original_file = op->Open(options.path); auto* witness_file = op->Open(witness.options_.path);
        if (!original_file || !witness_file || !op->AddEntry(1, 0, *original_file) || !op->AddEntry(2, 0, *witness_file)) return fail();
        for (std::size_t n = 0; n < lease.receipts.size(); ++n)
            if (!op->AddReceiptEntry(lease, n)) return fail();
        if (!spool.SuspendContinuationSpool(lease, error)) return fail();
        auto* index = op->Open(spool.index_file_); if (!index || !op->AddEntry(3, 0, *index)) return fail();
        if (prior) for (std::uint64_t role = 5; role <= 8; ++role) {
            auto* f = op->Open(Operation::Side(options.path, Operation::Control(role)));
            if (!f || !op->AddEntry(role, 0, *f)) return fail();
        }
        auto original_epoch = journal::ProtectedJournalEpoch::AcquireWriter(options.protected_persistence->key_directory.wstring(), authority.source_binding);
        auto witness_epoch = journal::ProtectedJournalEpoch::AcquireWriter(witness.options_.protected_persistence->key_directory.wstring(), authority.source_binding);
        if (!original_epoch || !witness_epoch) return fail();
        std::vector<std::uint8_t> encrypted;
        if (!tm.journal_.SealContinuationAnchor(op->original, *original_epoch.epoch, encrypted)) return fail();
        op->candidates[0].assign(reinterpret_cast<const std::byte*>(encrypted.data()), reinterpret_cast<const std::byte*>(encrypted.data() + encrypted.size()));
        const auto first = std::find_if(evidence.witness.records.begin(), evidence.witness.records.end(),
            [&](const auto& r) { return r.sequence == authority.witness_retained_first_sequence; });
        std::set<std::uint64_t> retained_sequences;
        for (const auto& value : authority.retained_authorizations)
            retained_sequences.insert(value.witness_sequences.begin(), value.witness_sequences.end());
        std::vector<WriteAheadLog::Record> retained_records; CRecordsWipe retained_wipe{retained_records};
        if (first == evidence.witness.records.end()) return fail();
        // Retained authorization groups keep their exact record encodings and
        // global sequence positions. Only unrelated retired data groups leave.
        const auto tail_transaction = evidence.witness.records.back().transaction_id;
        for (const auto& row : evidence.witness.records)
            if (row.transaction_id == tail_transaction || retained_sequences.contains(row.sequence)) retained_records.push_back(row);
        if (authority.retained_authorizations.empty()) retained_records.assign(first, evidence.witness.records.end());
        if (retained_records.empty() || retained_records.front().sequence != authority.witness_retained_first_sequence ||
            retained_records.size() > 2048 || !witness.SealContinuationRecords(op->witness, retained_records, *witness_epoch.epoch, encrypted)) return fail();
        if (encrypted.size() > 2u * 1024u * 1024u) {
            error = "ContinuationRetainedAuthorizationCapacityExceeded"; return fail();
        }
        op->candidates[1].assign(reinterpret_cast<const std::byte*>(encrypted.data()), reinterpret_cast<const std::byte*>(encrypted.data() + encrypted.size()));
        witness_epoch.epoch.reset();
        if (!spool.SealContinuationSpool(op->spool, op->candidates[2], error)) return fail();
        // Release the new spool encryption lease; the next admitted writer must
        // acquire another fresh epoch, never resume a persisted key for sealing.
        if (!spool.SuspendContinuationSpool(lease, error)) return fail();
        auto metadata = op->Encode(); CBytesWipe metadata_wipe{metadata}; std::vector<std::byte> certificate;
        if (!Operation::Protect(options, *original_epoch.epoch, metadata, certificate) || !CHash(certificate, op->certificate_hash)) return fail();
        original_epoch.epoch.reset(); op->authority.flush_and_recheck = {};
        const auto pending = Operation::Side(options.path, L".jcont.pending");
        auto intent = std::make_unique<CFile>(); if (!intent->Open(pending, true)) return fail();
        auto* intent_ptr = intent.get(); op->retained.push_back(std::move(intent));
        if (!intent_ptr->Write(certificate) || !op->Completed(DurableBoundary::IntentFlushed, 0, progress, error) ||
            !Operation::Hook(hook, "continuation-after-intent-flush", error)) return fail();
        std::vector<std::byte> readback;
        if (!intent_ptr->Read(readback, continuation_limit + 128u * 1024u) || readback != certificate) return fail();
        const RecoveryAuthorizer retained_authority = [&](const RecoveryEvidence& actual, Authority& out, std::string& why) {
            if (actual.original_head != authority.original_head || actual.witness_head != authority.witness_head) { why = "ContinuationPinnedOriginalChanged"; return false; }
            out = authority; out.flush_and_recheck = [&](std::string& reason) { return endpoint.revalidate_(reason); };
            return true;
        };
        if (!op->Finish(op, tm, spool, witness, endpoint, retained_authority, false, lease, error, hook, progress)) return fail();
        return Result::Succeeded;
    } catch (...) { if (error.empty()) error = "ContinuationResourceOrProviderFailure"; return fail(); }
}

ProtectedJournalContinuation::Result ProtectedJournalContinuation::OpenOrRecover(TransactionManager& tm,
    const OriginalDescriptor& options, PayloadSpool& spool, WriteAheadLog& witness, Endpoint& endpoint,
    const RecoveryAuthorizer& authorize, std::string& error, const StageHook& hook)
{
    return OpenOrRecover(tm, options, spool, witness, endpoint, authorize, error, hook, {});
}

ProtectedJournalContinuation::Result ProtectedJournalContinuation::OpenOrRecover(TransactionManager& tm,
    const OriginalDescriptor& options, PayloadSpool& spool, WriteAheadLog& witness, Endpoint& endpoint,
    const RecoveryAuthorizer& authorize, std::string& error, const StageHook& hook, const ProgressHook& progress)
{
    error.clear(); bool debt = false;
    const auto fail = [&] { if (debt) tm.MarkDeferredAcceptanceDurabilityFailure();
        if (error.empty()) error = "ContinuationRecoveryRefused"; return debt ? Result::RecoveryRequired : Result::RejectedBeforeWrite; };
    try {
        if (!options.protected_persistence || !witness.options_.protected_persistence || !authorize ||
            !tm.journal_path_.empty() || tm.journal_protection_ || tm.state_ != TransactionManager::State::Idle ||
            tm.next_sequence_ != 1 || tm.next_transaction_id_ != 1 || !tm.recovery_state_valid_) {
            error = "ContinuationFreshConfiguredOwnerRequired"; return fail();
        }
        auto op = std::make_shared<Operation>();
        op->authority.source_binding = options.protected_persistence->source_binding;
        op->authority.original_journal_identity = options.protected_persistence->journal_identity;
        op->authority.witness_journal_identity = witness.options_.protected_persistence->journal_identity;
        if (op->authority.original_journal_identity == op->authority.witness_journal_identity ||
            !op->Bindings(options, witness, spool, error)) return fail();
        for (const auto& directory : {options.protected_persistence->key_directory,
            witness.options_.protected_persistence->key_directory, spool.options_.protected_key_directory}) {
            auto reader = journal::ProtectedJournalReadPass::Acquire(directory.wstring(), op->authority.source_binding);
            if (!reader) { error = "ContinuationKeyDirectoryAuthorityInvalid"; return fail(); }
        }
        for (const auto& path : {options.path, witness.options_.path, spool.index_file_}) if (!op->Pin(path)) return fail();
        const auto pending = Operation::Side(options.path, L".jcont.pending"), canonical = Operation::Side(options.path, L".jcont.certificate");
        const bool has_pending = !CAbsent(pending), has_certificate = !CAbsent(canonical);
        const auto decode_identity = [&]() {
            const auto count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, options.volume_identity.data(), static_cast<int>(options.volume_identity.size()), nullptr, 0);
            if (count <= 0) throw std::runtime_error("ContinuationVolumeIdentity");
            std::wstring identity(static_cast<std::size_t>(count), L'\0');
            if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, options.volume_identity.data(), static_cast<int>(options.volume_identity.size()), identity.data(), count) != count)
                throw std::runtime_error("ContinuationVolumeIdentity");
            return identity;
        };
        if (!has_pending && !has_certificate) {
            // Preserve existing startup and partial original/witness recovery.
            // No continuation authority is required for a never-continued log.
            for (const auto& base : {options.path, witness.options_.path, spool.index_file_}) {
                WIN32_FIND_DATAW found{}; const auto pattern = base.wstring() + L".jcont*";
                const auto find = FindFirstFileW(pattern.c_str(), &found);
                if (find != INVALID_HANDLE_VALUE) { FindClose(find); error = "ContinuationUnknownNamespace"; return fail(); }
                if (GetLastError() != ERROR_FILE_NOT_FOUND) return fail();
            }
            tm.journal_max_bytes_ = options.max_bytes;
            return tm.OpenProtectedJournal(options.path.wstring(), decode_identity(), *options.protected_persistence, error) ? Result::Succeeded : fail();
        }
        debt = true;
        auto* certificate = op->Open(has_pending ? pending : canonical); std::vector<std::byte> cipher, metadata;
        CBytesWipe metadata_wipe{metadata};
        if (!certificate || !certificate->Read(cipher, continuation_limit + 128u * 1024u) ||
            !Operation::Unprotect(options, cipher, metadata) || !CHash(cipher, op->certificate_hash)) return fail();
        op->Decode(metadata);
        if (!op->Bindings(options, witness, spool, error) || !op->Namespace(options, witness, spool)) return fail();
        tm.journal_path_ = options.path.wstring(); tm.volume_identity_ = decode_identity();
        tm.journal_protection_ = options.protected_persistence; tm.journal_max_bytes_ = options.max_bytes;
        tm.journal_.Reconfigure(options);
        if (!tm.journal_.EnsureWriterLease(true) || !witness.EnsureWriterLease(true) ||
            !tm.journal_.CloseAppendFileHandle() || !witness.CloseAppendFileHandle()) return fail();
        bool completed = false;
        if (!has_pending && !CAbsent(Operation::Side(options.path, L".jcont.done"))) {
            if (!op->Receipt(options, 1, false, error)) return fail(); completed = true;
        }
        PayloadSpool::ContinuationLease lease;
        if (!spool.SuspendContinuationSpool(lease, error, !completed) ||
            !op->Finish(op, tm, spool, witness, endpoint, authorize, completed, lease, error, hook, progress)) return fail();
        return Result::Succeeded;
    } catch (...) { if (error.empty()) error = "ContinuationMalformedOrUnavailableEvidence"; return fail(); }
}

ProtectedJournalContinuation::Result ProtectedJournalContinuation::Recover(TransactionManager& tm, const OriginalDescriptor& options, PayloadSpool& spool,
    WriteAheadLog& witness, const Authority& authority, Endpoint& endpoint, std::string& error, const StageHook& hook)
{
    return Recover(tm, options, spool, witness, authority, endpoint, error, hook, {});
}

ProtectedJournalContinuation::Result ProtectedJournalContinuation::Recover(TransactionManager& tm, const OriginalDescriptor& options, PayloadSpool& spool,
    WriteAheadLog& witness, const Authority& authority, Endpoint& endpoint, std::string& error, const StageHook& hook,
    const ProgressHook& progress)
{
    // The typed Journal normally uses OpenOrRecover with a fresh descriptor.
    // This private overload never reuses a failed/active original owner.
    const RecoveryAuthorizer authorize = [&](const RecoveryEvidence& evidence, Authority& checked, std::string& why) {
        if (!authority.flush_and_recheck || evidence.original_head != authority.original_head ||
            evidence.witness_head != authority.witness_head) { why = "ContinuationRecoveryAuthorityMismatch"; return false; }
        checked = authority; return true;
    };
    return OpenOrRecover(tm, options, spool, witness, endpoint, authorize, error, hook, progress);
}
} // namespace apfsaccess::rw
