#pragma once
#include "NativeHardLinkProtocol.h"
#ifdef APFSACCESS_HAS_RW_ENGINE
#include "NativeHardLink.h"
#include "NativeHardLinkJournal.h"
#include "NativeHardLinkExecutor.h"
#endif

#ifndef APFSACCESS_ENABLE_NATIVE_HARD_LINK_CONTROL
#define APFSACCESS_ENABLE_NATIVE_HARD_LINK_CONTROL 0
#endif

#ifdef APFSACCESS_HAS_RW_ENGINE
bool NativeHardLinkOpenSupportedLocked(MountContext& c, OpenContext& open, bool source)
{
    if (!open.node || open.named_stream || open.native_xattr || open.cleanup_seen ||
        open.delete_on_close_requested || open.delete_on_cleanup || open.node->namespace_detached ||
        IsDeleteBlockedStateLocked(open.node) || TryGetNodeLockedNormalized(&c, open.node->path) != open.node)
        return false;
    if (source) return open.node->node_kind == NodeKind::RegularFile && !open.node->is_directory &&
        (open.granted_access & FILE_READ_DATA) != 0;
    return open.node->is_directory && open.node->node_kind == NodeKind::Directory &&
        (open.granted_access & FILE_ADD_FILE) != 0;
}

bool NativeHardLinkAncestrySupportedLocked(MountContext& c, std::wstring path)
{
    for (unsigned depth = 0; depth < 128; ++depth)
    {
        const auto inode = c.metadata_store->LookupCommittedInodeByPath(path);
        if (!inode || c.metadata_store->LookupCommittedExtendedAttribute(inode->object_id, kWindowsSecurityName)) return false;
        if (path == L"\\") return true;
        path = ParentOfNormalizedPath(path);
    }
    return false;
}
#endif

NTSTATUS DispatchNativeHardLinkControl(FSP_FILE_SYSTEM* fs, PVOID context, UINT32 code,
    PVOID input, ULONG input_size, PVOID output, ULONG output_size, PULONG transferred)
{
    using namespace apfsaccess::fshost::hardlink_control;
    auto* c = Ctx(fs);
    if (transferred) *transferred = 0;
    if (!c || !context || !transferred) return STATUS_INVALID_PARAMETER;
    // Encrypted and Fusion adapters use different open-context types.
    if (c->args.encrypted.enabled || c->args.fusion.enabled) return STATUS_NOT_SUPPORTED;
    ExternalMutationRequestScope admission(c);
    if (!admission.Acquired()) return STATUS_VOLUME_DISMOUNTED;
    MutationCallbackScope mutation(c);
#if !defined(APFSACCESS_HAS_RW_ENGINE) || !APFSACCESS_ENABLE_NATIVE_HARD_LINK_CONTROL
    (void)code; (void)input; (void)input_size; (void)output; (void)output_size;
    return STATUS_NOT_SUPPORTED;
#else
    auto& open = *static_cast<OpenContext*>(context);
    bool acceptance_started = false;
    const auto refuse = [&](const char* reason) {
        if (reason) c->hardlink_last_error = reason;
        {
            std::lock_guard<std::recursive_mutex> runtime(c->runtime_state_mutex);
            c->last_native_mutation_failure_operation = L"HardLink";
            c->last_native_mutation_failure_reason = Utf8ToWide(c->hardlink_last_error);
            c->last_native_mutation_failure_status = L"not-supported";
        }
        std::wcerr << L"[FsHost] Hard-link Control refused: " << Utf8ToWide(c->hardlink_last_error) << std::endl;
        return STATUS_NOT_SUPPORTED;
    };
    try
    {
        if (HasBlockedRecoveryEvidence(*c) || c->recovery_active || c->write_degraded) return STATUS_MEDIA_WRITE_PROTECTED;
        if (!IsMutationWriteEnabled(c) || !IsNativeWriteEnabled(c) || IsManifestSession(c) ||
            !c->metadata_store || !c->tx_manager) return STATUS_NOT_SUPPORTED;
        if (code == Export)
        {
            std::lock_guard authority(open.hardlink_authority_mutex);
            if (open.hardlink_authority_closed) return STATUS_INVALID_HANDLE;
            if (!input || input_size != sizeof(ExportRequest) || !output || output_size != sizeof(ExportReply)) return STATUS_INVALID_PARAMETER;
            ExportRequest request; memcpy(&request, input, sizeof(request));
            if (request.version != Version || request.reserved) return STATUS_INVALID_PARAMETER;
            { std::lock_guard names(c->mutex); if (!NativeHardLinkOpenSupportedLocked(*c, open, true)) return STATUS_ACCESS_DENIED; }
            if (open.hardlink_ticket)
            {
                std::lock_guard ticket(open.hardlink_ticket->mutex);
                if (open.hardlink_ticket->consumed || open.hardlink_ticket->revoked) return STATUS_INVALID_HANDLE;
                ExportReply reply; reply.ticket = open.hardlink_ticket->ticket;
                memcpy(output, &reply, sizeof(reply)); *transferred = sizeof(reply); return STATUS_SUCCESS;
            }
            const auto drained = DrainNativeMutationsByPolicy(c, L"HardLinkExport", false, true);
            if (!NT_SUCCESS(drained)) return drained;
            if (!FinalizeMutationJournalBestEffort(c, L"HardLinkExport")) return STATUS_UNSUCCESSFUL;
            auto ticket = std::make_shared<NativeHardLinkTicketState>();
            {
                std::lock_guard metadata(c->metadata_mutex); std::lock_guard journal(c->tx_mutex);
                apfsaccess::rw::NativeHardLinkOpenEntry entry;
                if (!EnrollNativeHardLinkJournalIdentity(*c)) return refuse("HardLinkCanonicalEnrollmentRefused");
                if (!CaptureNativeHardLinkOpenEntry(*c->metadata_store, open.node->path, entry) ||
                    !NativeHardLinkAncestrySupportedLocked(*c, open.node->path)) return STATUS_NOT_SUPPORTED;
                ticket->source = open.node; ticket->object_id = entry.object_id; ticket->generation = entry.generation;
                ticket->parent_object_id = entry.parent_object_id; ticket->sibling_id = entry.sibling_id; ticket->name_utf8 = entry.name_utf8;
            }
            auto& tickets = c->hardlink_tickets;
            tickets.erase(std::remove_if(tickets.begin(), tickets.end(), [](const auto& item) { return item.expired(); }), tickets.end());
            if (tickets.size() >= 1024 || BCryptGenRandom(nullptr, ticket->ticket.data(), static_cast<ULONG>(ticket->ticket.size()),
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return STATUS_INSUFFICIENT_RESOURCES;
            for (const auto& item : tickets) if (const auto live = item.lock(); live && live->ticket == ticket->ticket)
                return STATUS_INSUFFICIENT_RESOURCES;
            tickets.push_back(ticket); open.hardlink_ticket = ticket;
            ExportReply reply; reply.ticket = ticket->ticket;
            memcpy(output, &reply, sizeof(reply)); *transferred = sizeof(reply); return STATUS_SUCCESS;
        }
        if (code != Import || !input || input_size != sizeof(ImportRequest) || !output || output_size != sizeof(ImportReply))
            return STATUS_INVALID_PARAMETER;
        ImportRequest request; memcpy(&request, input, sizeof(request));
        if (request.version != Version || request.reserved || !request.leaf_chars || request.leaf_chars > request.leaf.size()) return STATUS_INVALID_PARAMETER;
        std::wstring leaf;
        for (std::size_t i = 0; i < request.leaf.size(); ++i)
        {
            const auto ch = request.leaf[i];
            if (i >= request.leaf_chars) { if (ch) return STATUS_INVALID_PARAMETER; continue; }
            if (!ch || ch == '\\' || ch == '/' || ch == ':') return STATUS_OBJECT_NAME_INVALID;
            leaf.push_back(static_cast<wchar_t>(ch));
        }
        if (leaf == L"." || leaf == L".." || !IsValidNormalizedWin32PathForMutation(L"\\" + leaf)) return STATUS_OBJECT_NAME_INVALID;
        std::shared_ptr<NativeHardLinkTicketState> ticket;
        for (const auto& item : c->hardlink_tickets) if (const auto live = item.lock(); live && live->ticket == request.ticket) { ticket = live; break; }
        if (!ticket) return STATUS_INVALID_HANDLE;
        std::unique_lock ticket_lock(ticket->mutex);
        if (ticket->consumed || ticket->revoked) return STATUS_INVALID_HANDLE;
        {
            std::lock_guard names(c->mutex);
            if (!NativeHardLinkOpenSupportedLocked(*c, open, false)) return STATUS_ACCESS_DENIED;
            if (!ticket->source || ticket->source->namespace_detached || IsDeleteBlockedStateLocked(ticket->source) ||
                TryGetNodeLockedNormalized(c, ticket->source->path) != ticket->source) return STATUS_INVALID_HANDLE;
        }
        apfsaccess::rw::NativeHardLinkOpenEntry destination;
        {
            std::lock_guard metadata(c->metadata_mutex); std::lock_guard journal(c->tx_mutex);
            if (!CaptureNativeHardLinkOpenEntry(*c->metadata_store, open.node->path, destination)) return STATUS_INVALID_HANDLE;
        }
        const apfsaccess::rw::NativeHardLinkOpenEntry source_entry{
            ticket->object_id, ticket->generation, ticket->parent_object_id, ticket->sibling_id, ticket->name_utf8};
        NativeHardLinkExecutionResult completed;
        const auto status = ExecuteNativeHardLinkUnderMutationGate(*c, ticket->source, source_entry,
            open.node, destination, leaf, completed,
            [](MountContext& context, const std::wstring& source, const std::wstring& parent) {
                return NativeHardLinkAncestrySupportedLocked(context, source) && NativeHardLinkAncestrySupportedLocked(context, parent);
            });
        acceptance_started = completed.acceptance_observed;
        if (acceptance_started) ticket->consumed = true;
        if (!NT_SUCCESS(status)) return status;
        ImportReply reply;
        reply.object_id = completed.object_id; reply.links = completed.links;
        reply.accepted_sequence = completed.accepted_sequence; reply.checkpoint_xid = completed.checkpoint_xid;
        memcpy(output, &reply, sizeof(reply)); *transferred = sizeof(reply); return STATUS_SUCCESS;
    }
    catch (...) { return acceptance_started ? BlockNativeCloneRecovery(*c, L"NativeHardLinkControlException") : STATUS_INSUFFICIENT_RESOURCES; }
#endif
}
