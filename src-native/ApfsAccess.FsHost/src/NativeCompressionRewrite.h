#pragma once

#include "CompressionRewrite.h"
#include "InodeMetadataPatch.h"
#include "MetadataStore.h"
#include "TransactionManager.h"
#include <bcrypt.h>
#include <algorithm>
#include <limits>
#include <new>
#include <optional>
#include <stdexcept>
#include <utility>

namespace apfsaccess::fshost
{
// Preparation only: no Begin/Record/Stage/Accept/Commit, device writes, cache
// changes, recovery-marker changes or checkpoint-pin ownership live here.
// The caller holds its mutation serialization, committed-read/publication gate,
// metadata mutex and journal mutex in the existing host lock order. Keep those
// protections through revalidation and enqueue/staging. Never retain a plan
// across a drain, acceptance, sibling publication or transaction restart.
class NativeCompressionRewrite
{
public:
    using Store = rw::MetadataStore;
    using Tx = rw::TransactionManager;
    using Wal = rw::WriteAheadLog;

    enum class Failure
    {
        None, AdmissionClosed, ArchiveUpdateRequired, TransactionNotEmpty,
        IdentityMismatch, RangeUnsupported, BudgetExceeded, SourceUnsupported,
        SourceChanged, JournalCapacity, ResourceFailure,
    };

    struct Admission
    {
        // Populate from actual host state, never from a compression read candidate.
        bool native_writes_admitted = false;
        bool visibility_unresolved = true;
        // Manifest callers must be inside the coordinator's live-store builder,
        // after reload/census, with source-preserving WAL binding and immediate
        // publication verification wired. A borrowed session store is insufficient.
        bool manifest_session = true;
        bool container_commit_owned = false;
        bool windows_attributes_pending = true;
        std::size_t queued_requests = 0;
        std::uint64_t publication_budget_bytes = 0;
        std::uint64_t reserved_publication_bytes = 0;
    };

    // Charge the complete replacement allocation, even for a one-byte edit.
    // This is payload space/time accounting, not an allocator/free-space proof.
    [[nodiscard]] static bool PublicationBytes(std::uint64_t eof, std::uint32_t block_size,
        std::uint64_t& bytes) noexcept
    {
        bytes = 0;
        if (eof > rw::CompressionRewrite::MaxLogicalBytes || block_size == 0 ||
            (block_size & (block_size - 1)) != 0) return false;
        const auto remainder = eof % block_size;
        bytes = eof + (remainder ? block_size - remainder : 0);
        return true;
    }

    [[nodiscard]] static std::optional<NativeCompressionRewrite> Prepare(
        const Store& store, const Tx& tx, const Admission& admission,
        const std::wstring& path, Store::PayloadIdentity source_identity,
        std::uint64_t offset, std::uint64_t length, Failure& failure)
    {
        failure = Failure::None;
        const auto refuse = [&](Failure why) -> std::optional<NativeCompressionRewrite> {
            failure = why; return std::nullopt;
        };
        try
        {
            if (!admission.native_writes_admitted || admission.visibility_unresolved ||
                (admission.manifest_session && !admission.container_commit_owned) ||
                !store.Device().IsRegularFile() ||
                !store.IsCanonicalCommitReady() || store.IsRecoveryRequired() ||
                !tx.RecoveryStateValid() || tx.HasUnappliedAcceptedWork())
                return refuse(Failure::AdmissionClosed);
            if (admission.windows_attributes_pending) return refuse(Failure::ArchiveUpdateRequired);
            // The manifest builder remains read-only even with respect to WAL:
            // Begin is deferred to the identity binder after staging. Aborting
            // an empty begun transaction would itself append a WAL marker.
            const bool transaction_ready = admission.manifest_session && admission.container_commit_owned
                ? tx.CurrentState() == Tx::State::Idle && !tx.CurrentTransactionId()
                : tx.CurrentState() == Tx::State::Active && tx.CurrentTransactionId();
            if (admission.queued_requests || store.PendingMutationCount() ||
                !transaction_ready || tx.PendingMutationCount())
                return refuse(Failure::TransactionNotEmpty);
            if (path.empty() || path.front() != L'\\' || path.find(L'\0') != std::wstring::npos ||
                !source_identity.object_id || !source_identity.generation)
                return refuse(Failure::IdentityMismatch);
            const auto inode = store.LookupCommittedInodeByPath(path);
            if (!inode || inode->object_id != source_identity.object_id ||
                (inode->xid ? inode->xid : inode->object_id) != source_identity.generation)
                return refuse(Failure::IdentityMismatch);
            if (!length || offset > inode->logical_size || length > inode->logical_size - offset)
                return refuse(Failure::RangeUnsupported);
            NativeCompressionRewrite prepared;
            const auto block_size = store.BlockSizeBytes();
            if (!block_size || !PublicationBytes(inode->logical_size, *block_size, prepared.publication_bytes_) ||
                admission.reserved_publication_bytes > admission.publication_budget_bytes ||
                prepared.publication_bytes_ > admission.publication_budget_bytes - admission.reserved_publication_bytes)
                return refuse(Failure::BudgetExceeded);
            // The engine authenticates all blocks and owns CRW1/decmpfs parsing.
            if (!store.PrepareCompressionRewrite(path, prepared.request_))
                return refuse(Failure::SourceUnsupported);
            rw::CompressionRewrite proof;
            if (!rw::DecodeCompressionRewrite(prepared.request_.inline_payload, proof) ||
                proof.object != source_identity.object_id || proof.generation != source_identity.generation ||
                proof.size != inode->logical_size || proof.volume != store.Context().volume_object_id ||
                store.CheckpointXid() != proof.checkpoint || proof.checkpoint == UINT64_MAX)
                return refuse(Failure::SourceChanged);
            // Idle manifest preparation has no buffered transaction. Enforce
            // the WAL's hard bound here; RecordMutation remains authoritative
            // once the binder begins the empty transaction after staging.
            if (admission.manifest_session
                    ? prepared.request_.inline_payload.size() > Wal::MaxInlinePayloadBytes
                    : !tx.CanAddInlinePayload(prepared.request_.inline_payload.size()))
                return refuse(Failure::JournalCapacity);
            prepared.checkpoint_ = proof.checkpoint;
            prepared.volume_ = proof.volume;
            prepared.eof_ = proof.size;
            prepared.transaction_id_ = tx.CurrentTransactionId();
            prepared.store_ = &store;
            prepared.tx_ = &tx;
            prepared.offset_ = offset;
            prepared.length_ = length;
            auto& intent = prepared.intent_;
            intent.kind = Tx::MutationKind::RewriteCompressedContent;
            intent.path = prepared.request_.path;
            // CRW1 records the SOURCE incarnation. Subsequent data/times use the
            // identity returned by StageMutation, never this source generation.
            intent.object_id = prepared.request_.object_id;
            intent.generation = prepared.request_.generation;
            intent.inline_payload = prepared.request_.inline_payload;
            intent.length = intent.payload_length = intent.inline_payload.size();
            if (!Hash(intent.inline_payload, intent.payload_checksum)) return refuse(Failure::ResourceFailure);
            return prepared;
        }
        catch (const std::bad_alloc&) { return refuse(Failure::ResourceFailure); }
        catch (const std::length_error&) { return refuse(Failure::ResourceFailure); }
    }

    [[nodiscard]] const Store::MutationRequest& Request() const noexcept { return request_; }
    [[nodiscard]] const Tx::MutationIntent& JournalIntent() const noexcept { return intent_; }
    [[nodiscard]] std::uint64_t PreimageCheckpoint() const noexcept { return checkpoint_; }
    [[nodiscard]] std::uint64_t LogicalEof() const noexcept { return eof_; }
    [[nodiscard]] std::uint64_t PublicationByteReservation() const noexcept { return publication_bytes_; }

    // Invoke before the FIRST journal append/native mutation, with the same
    // protections as Prepare. Revalidation cannot repair or rebase a stale plan.
    [[nodiscard]] Failure Revalidate(const Store& store, const Tx& tx, const Admission& admission) const
    {
        if (&store != store_ || &tx != tx_ || tx.CurrentTransactionId() != transaction_id_)
            return Failure::SourceChanged;
        Failure failure;
        const auto current = Prepare(store, tx, admission, request_.path,
            {request_.object_id, request_.generation}, offset_, length_, failure);
        if (!current) return failure;
        return current->checkpoint_ == checkpoint_ && current->volume_ == volume_ &&
            current->request_.inline_payload == request_.inline_payload &&
            current->publication_bytes_ == publication_bytes_ ? Failure::None : Failure::SourceChanged;
    }

    // This is only request construction. The existing native staging guard is
    // still authoritative. Alias resolution binds to the working owner and the
    // actual conversion's returned identity, not a caller-supplied path fallback.
    [[nodiscard]] bool PrepareWrite(const Store& store, Store::PayloadIdentity staged_identity,
        const std::wstring& path, std::uint64_t offset, std::uint64_t length,
        Store::MutationRequest& out) const
    {
        out = {};
        try
        {
        if (&store != store_ || !tx_ || tx_->CurrentState() != Tx::State::Active ||
            tx_->CurrentTransactionId() != transaction_id_ || !tx_->PendingMutationCount() ||
            !length || offset > eof_ || length > eof_ - offset ||
            store.IsRecoveryRequired() || store.CheckpointXid() != checkpoint_ ||
            store.Context().volume_object_id != volume_ || !store.PendingMutationCount() ||
            staged_identity.object_id != request_.object_id || staged_identity.generation != checkpoint_ + 1 ||
            store.HasUnsupportedContentTransform(request_.object_id) ||
            path.empty() || path.front() != L'\\' || path.find(L'\0') != std::wstring::npos) return false;
        const auto identity = store.LookupWorkingPayloadIdentityByPath(path);
        if (!identity || identity->object_id != staged_identity.object_id ||
            identity->generation != staged_identity.generation) return false;
        out.operation = Store::MutationOperation::Write;
        out.path = path;
        out.object_id = staged_identity.object_id;
        out.generation = staged_identity.generation;
        out.offset = offset;
        out.length = length;
        return true;
        }
        catch (const std::bad_alloc&) { out = {}; return false; }
        catch (const std::length_error&) { out = {}; return false; }
    }

    // Dispatch only; not proof that an accepted transaction was applied. The
    // caller still runs retained-preimage, payload, publication and cleanup checks.
    [[nodiscard]] static bool ReplayRequest(const Wal::Record& record, Store::MutationRequest& out)
    {
        out = {};
        try
        {
        if (!Store::CompressionRewriteFromWal(record, out)) return false;
        if (out.path.empty() || out.path.front() != L'\\') { out = {}; return false; }
        return true;
        }
        catch (const std::bad_alloc&) { out = {}; return false; }
        catch (const std::length_error&) { out = {}; return false; }
    }

    // Additional admission for already-loaded accepted WAL. Ordinary transactions
    // pass through; their existing validators remain mandatory. CRW1 cannot be
    // translated to a sibling checkpoint by the generic history rebase path.
    [[nodiscard]] static bool AcceptedBatchIsConsistent(const Tx::AcceptedTransaction& transaction,
        std::uint64_t volume_object_id)
    {
        try
        {
        const auto& records = transaction.mutations;
        const auto conversion = std::find_if(records.begin(), records.end(), [](const auto& record) {
            return record.operation == Wal::OperationKind::RewriteCompressedContent;
        });
        if (conversion == records.end()) return true;
        Store::MutationRequest request;
        rw::CompressionRewrite proof;
        if (conversion != records.begin() || !ReplayRequest(*conversion, request) ||
            !rw::DecodeCompressionRewrite(request.inline_payload, proof) ||
            proof.volume != volume_object_id || proof.checkpoint == UINT64_MAX ||
            proof.checkpoint != transaction.preimage_checkpoint_xid ||
            !transaction.transaction_id || !transaction.accepted_sequence) return false;
        auto previous_sequence = std::uint64_t{0};
        bool has_write = false;
        for (const auto& record : records)
        {
            if (record.transaction_id != transaction.transaction_id || record.sequence <= previous_sequence ||
                record.sequence >= transaction.accepted_sequence || record.volume_identity.empty() ||
                record.volume_identity != conversion->volume_identity || record.state != Wal::RecordState::Prepared)
                return false;
            previous_sequence = record.sequence;
            if (&record == &*conversion) continue;
            if (record.object_id != proof.object || record.parent_object_id != proof.checkpoint + 1 ||
                !StrictAbsolutePath(record.path_utf8) || !record.secondary_path_utf8.empty() ||
                record.flags || record.unlink_outcome) return false;
            if (record.operation == Wal::OperationKind::Write)
            {
                if (!record.logical_length || record.logical_offset > proof.size ||
                    record.logical_length > proof.size - record.logical_offset ||
                    record.payload_length != record.logical_length ||
                    record.payload_offset > UINT64_MAX - record.payload_length ||
                    (record.inline_payload.empty() && !record.payload_spool_id) ||
                    !Wal::InlinePayloadIsConsistent(record)) return false;
                has_write = true;
            }
            else if (record.operation == Wal::OperationKind::SetInodeMetadata)
            {
                rw::InodeMetadataPatch patch;
                constexpr auto times = rw::InodeMetadataPatch::ModificationTime | rw::InodeMetadataPatch::ChangeTime;
                if (!Wal::InodeMetadataMutationIsConsistent(record) ||
                    !rw::DecodeInodeMetadataPatch(record.inline_payload, patch) || (patch.mask & ~times)) return false;
            }
            else return false;
        }
        return has_write;
        }
        catch (const std::bad_alloc&) { return false; }
        catch (const std::length_error&) { return false; }
    }

private:
    NativeCompressionRewrite() = default;
    [[nodiscard]] static bool StrictAbsolutePath(const std::string& path)
    {
        return !path.empty() && path.front() == '\\' && path.find('\0') == std::string::npos &&
            path.size() <= static_cast<std::size_t>((std::numeric_limits<int>::max)()) &&
            MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.data(),
                static_cast<int>(path.size()), nullptr, 0) > 0;
    }
    [[nodiscard]] static bool Hash(std::span<const std::byte> bytes,
        std::array<std::uint8_t, Wal::PayloadHashSize>& digest)
    {
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        if (bytes.size() > Wal::MaxInlinePayloadBytes ||
            BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return false;
        const auto status = BCryptHash(algorithm, nullptr, 0,
            reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())),
            static_cast<ULONG>(bytes.size()), digest.data(), static_cast<ULONG>(digest.size()));
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return status >= 0;
    }
    Store::MutationRequest request_;
    Tx::MutationIntent intent_;
    const Store* store_ = nullptr;
    const Tx* tx_ = nullptr;
    std::uint64_t checkpoint_ = 0, volume_ = 0, eof_ = 0, publication_bytes_ = 0;
    std::uint64_t transaction_id_ = 0, offset_ = 0, length_ = 0;
};
}
