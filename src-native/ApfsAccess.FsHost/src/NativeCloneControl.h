#pragma once
#include "NativeCloneProtocol.h"
#include "NativeSparseRangeControl.h"
// Deliberately unadvertised until the parent passes its consistent build and
// mounted gate. Software tests enable the exact same dispatcher body.
#ifndef APFSACCESS_ENABLE_NATIVE_CLONE_CONTROL
#define APFSACCESS_ENABLE_NATIVE_CLONE_CONTROL 0
#endif

#ifdef APFSACCESS_HAS_RW_ENGINE
#include "NativeCloneNamespace.h"
bool NativeCloneAncestrySupportedLocked(MountContext& c, std::wstring path)
{
    using Store = apfsaccess::rw::MetadataStore;
    for (unsigned depth = 0; depth < 1024; ++depth)
    {
        const auto inode = c.metadata_store->LookupCommittedInodeByPath(path);
        if (!inode || (inode->node_type != Store::NodeType::Directory &&
                      inode->node_type != Store::NodeType::RegularFile) ||
            c.metadata_store->LookupCommittedExtendedAttribute(inode->object_id, kWindowsSecurityName)) return false;
        if (path == L"\\") return true;
        path = ParentOfNormalizedPath(path);
    }
    return false;
}

bool NativeCloneOpenSupportedLocked(MountContext& c, OpenContext& o, bool source)
{
    if (!o.node || o.named_stream || o.native_xattr || o.cleanup_seen ||
        o.delete_on_close_requested || o.delete_on_cleanup || o.node->namespace_detached ||
        IsDeleteBlockedStateLocked(o.node) || TryGetNodeLockedNormalized(&c, o.node->path) != o.node)
        return false;
    if (source)
    {
        // Local sidecar streams are not APFS clone metadata.
        if (!c.named_stream_sizes.empty()) return false;
        return !o.node->is_directory && o.node->node_kind == NodeKind::RegularFile && o.allow_read_data;
    }
    return o.node->is_directory && o.node->node_kind == NodeKind::Directory &&
        (o.granted_access & FILE_ADD_FILE) != 0;
}
#include "NativeCloneManifest.h"
#endif
#include "NativeHardLinkControl.h"

NTSTATUS CB_Control(FSP_FILE_SYSTEM* fs, PVOID context, UINT32 code,
    PVOID input, ULONG input_size, PVOID output, ULONG output_size, PULONG transferred)
{
    using namespace apfsaccess::fshost::clone_control;
    auto* c = Ctx(fs);
    ScopedCallbackActivity callback(c, "Control");
    if (transferred) *transferred = 0;
    if (code == apfsaccess::fshost::hardlink_control::Export || code == apfsaccess::fshost::hardlink_control::Import)
        return DispatchNativeHardLinkControl(fs, context, code, input, input_size, output, output_size, transferred);
    if (code == apfsaccess::fshost::allocated_ranges_control::Query)
        return DispatchNativeAllocatedRangesControl(fs, context, input, input_size, output, output_size, transferred);
    if (code == apfsaccess::fshost::sparse_control::Query ||
        code == apfsaccess::fshost::sparse_control::Zero)
        return DispatchNativeSparseControl(fs, context, code, input, input_size, output, output_size, transferred);
    if (code != Export && code != Import) return STATUS_INVALID_DEVICE_REQUEST;
    if (!c || !context || !transferred) return STATUS_INVALID_PARAMETER;
    ExternalMutationRequestScope admission(c);
    if (!admission.Acquired()) return STATUS_VOLUME_DISMOUNTED;
    MutationCallbackScope mutation(c);
#if !defined(APFSACCESS_HAS_RW_ENGINE) || !APFSACCESS_ENABLE_NATIVE_CLONE_CONTROL
    return STATUS_NOT_SUPPORTED;
#else
    using Store = apfsaccess::rw::MetadataStore;
    auto& o = *static_cast<OpenContext*>(context);
    bool acceptance_started = false;
    try
    {
        if (HasBlockedRecoveryEvidence(*c) || c->recovery_active || c->write_degraded)
            return STATUS_MEDIA_WRITE_PROTECTED;
        if (!IsMutationWriteEnabled(c) || !IsNativeWriteEnabled(c) ||
            !c->metadata_store || !c->tx_manager) return STATUS_NOT_SUPPORTED;
        if (code == Export)
        {
            std::lock_guard authority(o.clone_authority_mutex);
            if (o.clone_authority_closed) return STATUS_INVALID_HANDLE;
            if (!input || input_size != sizeof(ExportRequest) || !output || output_size < sizeof(ExportReply))
                return STATUS_INVALID_PARAMETER;
            ExportRequest request; memcpy(&request, input, sizeof(request));
            if (request.version != Version || request.reserved) return STATUS_INVALID_PARAMETER;
            {
                std::lock_guard names(c->mutex);
                if (!NativeCloneOpenSupportedLocked(*c, o, true)) return STATUS_ACCESS_DENIED;
            }
            // Do not reissue a ticket or extend its authority on repeated exports.
            if (o.clone_ticket)
            {
                std::lock_guard ticket_lock(o.clone_ticket->mutex);
                if (o.clone_ticket->consumed) return STATUS_INVALID_HANDLE;
                ExportReply reply; reply.ticket = o.clone_ticket->ticket;
                memcpy(output, &reply, sizeof(reply)); *transferred = sizeof(reply); return STATUS_SUCCESS;
            }
            const auto drained = DrainNativeMutationsByPolicy(c, L"CloneExport", false, true);
            if (!NT_SUCCESS(drained)) return drained;
            if (!FinalizeMutationJournalBestEffort(c, L"CloneExport")) return STATUS_UNSUCCESSFUL;
            auto state = std::make_shared<NativeCloneTicketState>();
            {
                std::lock_guard metadata(c->metadata_mutex);
                std::uint64_t preimage = 0; std::string error;
                const auto inode = c->metadata_store->LookupCommittedInodeByPath(o.node->path);
                if ((!IsManifestSession(c) && (!GetDirectApplePreimageLocked(*c->metadata_store, preimage, error) || !preimage)) || !inode ||
                    !NativeCloneAncestrySupportedLocked(*c, o.node->path)) return STATUS_NOT_SUPPORTED;
                state->source = o.node; state->object_id = inode->object_id; state->generation = inode->xid;
            }
            auto& tickets = c->clone_tickets;
            tickets.erase(std::remove_if(tickets.begin(), tickets.end(), [](const auto& weak) { return weak.expired(); }), tickets.end());
            if (tickets.size() >= 1024) return STATUS_INSUFFICIENT_RESOURCES;
            if (BCryptGenRandom(nullptr, state->ticket.data(), static_cast<ULONG>(state->ticket.size()),
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return STATUS_INSUFFICIENT_RESOURCES;
            for (const auto& weak : tickets)
                if (const auto live = weak.lock(); live && live->ticket == state->ticket) return STATUS_INSUFFICIENT_RESOURCES;
            tickets.push_back(state); o.clone_ticket = state;
            ExportReply reply; reply.ticket = state->ticket;
            memcpy(output, &reply, sizeof(reply)); *transferred = sizeof(reply); return STATUS_SUCCESS;
        }
        if (!input || input_size != sizeof(ImportRequest) || output_size != 0) return STATUS_INVALID_PARAMETER;
        ImportRequest request; memcpy(&request, input, sizeof(request));
        if (request.version != Version || request.reserved || !request.leaf_chars || request.leaf_chars > request.leaf.size())
            return STATUS_INVALID_PARAMETER;
        std::wstring leaf;
        for (std::size_t i = 0; i < request.leaf.size(); ++i)
        {
            const auto ch = request.leaf[i];
            if (i >= request.leaf_chars) { if (ch) return STATUS_INVALID_PARAMETER; continue; }
            if (!ch || ch == '\\' || ch == '/' || ch == ':') return STATUS_OBJECT_NAME_INVALID;
            leaf.push_back(static_cast<wchar_t>(ch));
        }
        if (leaf == L"." || leaf == L".." || !IsValidNormalizedWin32PathForMutation(L"\\" + leaf))
            return STATUS_OBJECT_NAME_INVALID;
        std::shared_ptr<NativeCloneTicketState> ticket;
        for (const auto& weak : c->clone_tickets)
            if (auto live = weak.lock(); live && live->ticket == request.ticket) { ticket = std::move(live); break; }
        if (!ticket) return STATUS_INVALID_HANDLE;
        std::unique_lock ticket_lock(ticket->mutex);
        if (ticket->consumed || ticket->revoked) return STATUS_INVALID_HANDLE;
        std::wstring source, target;
        {
            std::lock_guard names(c->mutex);
            if (!NativeCloneOpenSupportedLocked(*c, o, false)) return STATUS_ACCESS_DENIED;
            if (!ticket->source || ticket->source->namespace_detached || IsDeleteBlockedStateLocked(ticket->source) ||
                TryGetNodeLockedNormalized(c, ticket->source->path) != ticket->source) return STATUS_INVALID_HANDLE;
            source = ticket->source->path;
            target = o.node->path == L"\\" ? L"\\" + leaf : o.node->path + L"\\" + leaf;
            if (TryGetNodeLockedNormalized(c, target)) return STATUS_OBJECT_NAME_COLLISION;
        }
        const auto drained = DrainNativeMutationsByPolicy(c, L"CloneImport", false, true);
        if (!NT_SUCCESS(drained)) return drained;
        if (!FinalizeMutationJournalBestEffort(c, L"CloneImport")) return STATUS_UNSUCCESSFUL;
        if (IsManifestSession(c))
            return ImportManifestNativeClone(*c, *ticket, source, target, o.node->path, acceptance_started);
        Store::CloneReceipt receipt;
        Store::CloneAcceptance accepted = Store::CloneAcceptance::Refused;
        {
            std::lock_guard commit(c->commit_mutex);
            std::unique_lock reads(c->committed_read_gate);
            std::lock_guard metadata(c->metadata_mutex);
            const auto inode = c->metadata_store->LookupCommittedInodeByPath(source);
            if (!inode || inode->object_id != ticket->object_id || inode->xid != ticket->generation)
                return STATUS_INVALID_HANDLE;
            if (!NativeCloneAncestrySupportedLocked(*c, source) || !NativeCloneAncestrySupportedLocked(*c, o.node->path))
                return STATUS_NOT_SUPPORTED;
            Store::MutationRequest preview;
            std::vector<std::uint64_t> pins; std::string error;
            const auto* held = c->backup_held ? c->backup_held->source.get() : nullptr;
            if (!LoadDirectCheckpointPinsLocked(*c, pins, error) || !(held
                ? c->metadata_store->PrepareBackupRetainedClone(*held, source, target, preview, error)
                : c->metadata_store->PrepareNativeClone(source, target, preview)))
                return STATUS_NOT_SUPPORTED;
            const auto capacity = held
                ? c->metadata_store->PreflightBackupRetainedCapacityMutations(*held, std::span(&preview, 1), pins)
                : c->metadata_store->PreflightNativeCapacityMutation(preview, pins);
            if (capacity != Store::MutationStatus::Applied)
                return capacity == Store::MutationStatus::CapacityBlocked ? STATUS_DISK_FULL : STATUS_NOT_SUPPORTED;
            std::lock_guard journal(c->tx_mutex);
            if (held && (!c->backup_held->census ||
                !c->backup_held->census->BeforeMutation(c->metadata_store->CheckpointXid().value_or(0), error)))
                return STATUS_IO_DEVICE_ERROR;
            acceptance_started = true;
            accepted = held ? c->metadata_store->AcceptBackupRetainedClone(*held, *c->tx_manager, source, target, receipt, error)
                : c->metadata_store->AcceptNativeClone(*c->tx_manager, source, target, receipt);
        }
        if (accepted == Store::CloneAcceptance::Refused) { acceptance_started = false; return STATUS_NOT_SUPPORTED; }
        if (accepted != Store::CloneAcceptance::Accepted)
            return BlockNativeCloneRecovery(*c, L"NativeCloneAcceptanceAmbiguous");
        ticket->consumed = true;
        if (!UpdateRecoveryMarkerBestEffort(c, true))
            return BlockNativeCloneRecovery(*c, L"NativeCloneMarkerFailed");
        const auto committed = CommitNativeMutationsBestEffort(c, L"CloneImport",
            {}, {}, {}, {}, nullptr, false,
            [&] { return PublishNativeCloneNamespace(*c, target, receipt.target); });
        if (!NT_SUCCESS(committed)) return BlockNativeCloneRecovery(*c, L"NativeClonePublicationFailed");
        bool verified = false;
        {
            std::lock_guard metadata(c->metadata_mutex);
            std::lock_guard journal(c->tx_mutex);
            std::vector<apfsaccess::rw::TransactionManager::AcceptedTransaction> transactions;
            verified = c->tx_manager->LoadAcceptedTransactionsSinceCleanup(transactions) && transactions.size() == 1 &&
                transactions.front().mutations.size() == 1 &&
                (c->backup_held && c->backup_held->source
                    ? c->metadata_store->ReplayBackupRetainedClone(*c->backup_held->source, transactions.front().mutations.front(), receipt.checkpoint)
                    : c->metadata_store->ReplayNativeClone(transactions.front().mutations.front(), receipt.checkpoint)) ==
                    Store::CloneReplay::AlreadyPublished;
#ifdef APFSACCESS_FSHOST_UNIT_TEST
            if (!verified) std::wcerr << L"[clone500] verification txs=" << transactions.size()
                << L" pending=" << c->metadata_store->PendingMutationCount() << L" recovery=" << c->metadata_store->IsRecoveryRequired()
                << L" checkpoint=" << c->metadata_store->CheckpointXid().value_or(0) << L" preimage=" << receipt.checkpoint
                << L" accepted=" << c->tx_manager->Watermarks().accepted_sequence
                << L" durable=" << c->tx_manager->Watermarks().apfs_durable_sequence
                << L" cleanup=" << c->tx_manager->Watermarks().cleanup_sequence << L'\n';
#endif
        }
        if (!verified) return BlockNativeCloneRecovery(*c, L"NativeClonePublicationUnproven");
        bool visible_target = false;
        {
            std::lock_guard names(c->mutex);
            const auto visible = TryGetNodeLockedNormalized(c, target);
            visible_target = visible && visible->object_id == receipt.target;
        }
        if (!visible_target) return BlockNativeCloneRecovery(*c, L"NativeCloneNamespacePublicationFailed");
        if (!FinalizeMutationJournalBestEffort(c, L"CloneImport"))
            return BlockNativeCloneRecovery(*c, L"NativeCloneCleanupFailed");
        bool cleanup_complete = false;
        {
            std::lock_guard journal(c->tx_mutex);
            cleanup_complete = c->tx_manager->Watermarks().cleanup_sequence >= receipt.sequence;
            if (cleanup_complete) c->tx_manager->ReleaseAcceptedSequenceProof(receipt.transaction_id);
        }
        if (!cleanup_complete) return BlockNativeCloneRecovery(*c, L"NativeCloneCleanupIncomplete");
        InvalidatePayloadIdentityCache(c);
        return STATUS_SUCCESS;
    }
    catch (...)
    {
        return acceptance_started ? BlockNativeCloneRecovery(*c, L"NativeCloneControlException") : STATUS_INSUFFICIENT_RESOURCES;
    }
#endif
}
